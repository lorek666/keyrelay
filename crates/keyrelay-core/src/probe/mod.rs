//! bazaarlink 模型检测（probe API，M15-S1）。
//!
//! 向 bazaarlink 发 probe 请求，检测目标模型端点是否真的是它声称的模型（防套壳/spoof）。
//! 复用 `site::HttpTransport` 调 bazaarlink.ai——不新加 transport trait、不新加依赖。
//!
//! # 安全边界
//!
//! - `apiKey` 来自 `Service::key_secret`（唯一明文出口 `vault_secret`，M8-S1 守卫），不新开 `vault.get`；
//! - `ProbeRequest` 手写 `Debug`，`api_key` 打印 `<已设置>`，不泄漏明文；
//! - 调用只 log 元数据（site_id / key_id / modelId），**不 log apiKey**；
//! - 响应里 `items[].response` / `responseHeaders` / `startedByIp` / `userKey` 视为敏感，
//!   `ProbeRun` 只取身份判定摘要，**不持久化**这些敏感字段。
//!
//! # 两条请求，一条主路径
//!
//! 1. [`run_probe`]：POST 提交。生产走 `sync=false`（B-160 起改为主路径）——秒级返回
//!    `{runId, claimToken}`，把「等服务端跑完」这件事从**一条长连接**挪到**轮询**上；
//! 2. [`poll_probe_run`]：`GET /api/probe/run/<runId>` 轮询到终态。best-effort、
//!    永不把一次成功的检测变成失败。
//!
//! # 为什么主路径要异步（B-160）
//!
//! 真机实测（2026-10-17，真实中转站 + 真实模型）：`sync=true` 的 POST
//! **单条连接要挂满全程 360.53s**，而薄壳注入的 probe 传输层 timeout 是 120s
//! ⇒ 重模型必然超时，用户看到「检测失败」，而服务端其实给出了高置信度判定。
//! 同一个模型改用 `sync=false` + 轮询：POST **0.75s** 返回，run 在服务端跑
//! **186.98s** 后 `completed`，拿到的判定与 `sync=true` 那次**逐字相同**
//! （`clean_match_submodel_mismatch` / `GPT-5.6 Luna` / `0.98`）。
//!
//! 异步不只是「绕开超时」：判定现在挂在**可重复查询的 runId** 上，单次轮询失败
//! 可以重试，而不是把已经跑出来的结论一起丢掉。

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::site::retry::Sleeper;
use crate::site::transport::{HttpRequest, HttpResponse, HttpTransport, Method};

/// bazaarlink probe 端点（POST 启动）。`sync=true` 时服务端等跑完再回。
const PROBE_ENDPOINT: &str = "https://bazaarlink.ai/api/probe/run";

/// bazaarlink run 状态查询端点前缀：`GET <prefix><runId>`（B-134 轮询兜底）。
///
/// 真机标定（2026-10-16）：
/// - `GET https://bazaarlink.ai/api/probe/run/kr-nonexistent-probe-id` ⇒ `404 {"error":"Run not found"}`
/// - `GET https://bazaarlink.ai/api/probe/run`（不带 runId）⇒ `405`
///
/// 即路由 `/api/probe/run/<runId>` 存在且接受 GET（集合路由只接受 POST）。
const PROBE_RUN_ENDPOINT_PREFIX: &str = "https://bazaarlink.ai/api/probe/run/";

/// 轮询参数（B-134 引入，B-160 重设计）。
///
/// 旧形状是「固定次数 × 固定间隔」（6 × 5s = 30s）。那是给 `sync=true` 的**兜底**设计的：
/// 主路径已经把结果等回来了，兜底只值 30s。B-160 起轮询是**主路径**——它要覆盖
/// 「服务端跑完一整轮多轮推理对比」的全部时间（真机实测 186.98s / 360.53s），
/// 所以换成**退避 + 总预算**：
///
/// - 退避让轻模型（真机 2–9s）也能被很快问到，而长跑不会把补查打得太密；
/// - 预算是**墙上时间**的上界，用尽即停，且**停下时仍然返回手上的 run**
///   （`run_id` 一定在；`report_url` 只有服务端收尾后才有，不承诺）。
///
/// ## 预算怎么算
///
/// `budget` 累计**两样**：计划睡眠时长 + **实测的请求耗时**。两样都计入，预算才是真的
/// 墙上时间上界——只算睡眠的话，「62 次补查 × 每次 GET 允许 120s」这种最坏情况会把
/// 900s 的预算拖成两小时（独立复审 P2-2 指出过这一点，修的就是这里）。
///
/// 测试友好性：请求耗时用 `Instant` 实测，而测试里的 `MockTransport` 往返只有微秒级，
/// 所以「预算 3.5s / 退避 1s ⇒ 问 3 次」这类断言仍然精确、不需要假时钟。
/// （写 3.5s 而不是 3s 是刻意的：`≈0` 不是 `0`，卡在整数边界上会因几微秒而少问一次——
/// 那等于把断言钉在「Mock 恰好不耗时」这个巧合上。）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollPolicy {
    /// 首次补查前的等待。刚提交的 run 立刻查大概率还是 `pending`。
    pub first_delay: Duration,
    /// 退避上限：`first_delay` 逐次翻倍，到此值后固定。
    pub max_interval: Duration,
    /// 预算（累计计划睡眠 + 实测请求耗时）。用尽 ⇒ [`PollStop::BudgetExhausted`]。
    pub budget: Duration,
    /// 连续补查失败的容忍次数。`0` = 一次都不容忍。
    ///
    /// 单次失败**不算失败**：判定挂在 runId 上，网络抖一下就放弃等于把 B-160 的收益还回去。
    /// 任意一次补查成功后连续计数归零。
    pub max_consecutive_errors: u32,
}

/// 轮询的**硬**尝试次数上限：防「预算不为零但退避为零」这类配置把人绕进死循环。
///
/// 真机形态下永远够用（默认预算 900s ÷ 平均 15s ≈ 60 次）。
pub const MAX_POLL_ATTEMPTS: u32 = 1000;

impl Default for PollPolicy {
    fn default() -> Self {
        Self {
            first_delay: Duration::from_secs(2),
            max_interval: Duration::from_secs(15),
            // 真机实测最长的两次：186.98s（async）与 360.53s（sync）。900s 留出充分余量，
            // 同时给界面一个「最多等多久」的确定上界。
            budget: Duration::from_secs(900),
            max_consecutive_errors: 5,
        }
    }
}

impl PollPolicy {
    /// 第 `attempt`（从 1 起）次补查前该睡多久：`min(first_delay * 2^(attempt-1), max_interval)`。
    fn delay_for(&self, attempt: u32) -> Duration {
        let shift = attempt.saturating_sub(1).min(32);
        let scaled = self
            .first_delay
            .checked_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX))
            .unwrap_or(self.max_interval);
        scaled.min(self.max_interval)
    }
}

/// 轮询为什么停下来。进事件流，便于线上判断「没拿到判定到底是谁的问题」。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PollStop {
    /// 一次都没补查：提交就带回了终态（或判定），或同步路径下服务端没说要等。
    NotNeeded,
    /// 追到了 run 级终态（`completed`/`failed`/`aborted`）。
    ///
    /// **不是**「拿到判定」：异步路径上判定会先于终态出现，但那是中间态
    /// （真机实测：70.26s 时 `trueModel=None`，187s 后才有子模型）——
    /// 所以异步路径只在终态停，见 [`needs_poll`] 的文档。
    Settled,
    /// 预算用尽——run 可能仍在跑（runId 仍然有效）。
    BudgetExhausted,
    /// 连续补查失败超过容忍次数（判定服务不可达）。
    TooManyErrors,
    /// 撞上 [`MAX_POLL_ATTEMPTS`] 硬上限（配置异常的自保）。
    AttemptsExhausted,
}

/// 轮询的完整结果。**不只是 run**：`stop` 决定上层怎么向用户交代。
#[derive(Clone, Debug)]
pub struct PollOutcome {
    pub run: ProbeRun,
    /// 成功的补查次数。
    pub polled: u32,
    /// 失败的补查次数（累计）。
    pub errors: u32,
    pub stop: PollStop,
}

/// probe 请求。`api_key` 是明文，手写 `Debug` 不泄漏。
///
/// `api_key` 用 `Zeroizing<String>` 包裹：drop 时清零堆上明文，与 `key_secret` 出口口径一致。
#[derive(Clone)]
pub struct ProbeRequest {
    pub base_url: String,
    pub api_key: Zeroizing<String>,
    pub model_id: String,
    /// 身份声明。`None` 时由调用方默认填 `model_id`（M15-S1 决策：claimedModel = modelId）。
    pub claimed_model: Option<String>,
    pub sync: bool,
}

impl std::fmt::Debug for ProbeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 手写 Debug：api_key 永不回显明文（证伪守卫：改 derive Debug ⇒ 测试断言红）。
        f.debug_struct("ProbeRequest")
            .field("base_url", &self.base_url)
            .field("api_key", &"<已设置>")
            .field("model_id", &self.model_id)
            .field("claimed_model", &self.claimed_model)
            .field("sync", &self.sync)
            .finish()
    }
}

impl ProbeRequest {
    /// 构造发往 bazaarlink 的 JSON 请求体。`apiKey` 在体里是设计要求（发给 bazaarlink）。
    fn to_json(&self) -> Value {
        let mut v = json!({
            "baseUrl": self.base_url,
            "apiKey": self.api_key.as_str(),
            "modelId": self.model_id,
            "sync": self.sync,
        });
        if let Some(cm) = &self.claimed_model {
            v["claimedModel"] = json!(cm);
        }
        v
    }
}

/// probe 结果摘要。
///
/// **只取身份判定摘要**——`items[].response` / `responseHeaders` / `startedByIp` / `userKey`
/// 等敏感字段不进本结构（M15-S1 安全边界）。持久化与 IPC 都只走本结构。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProbeRun {
    /// bazaarlink runId（轮询用；也作为本地历史的主键之一）。
    pub run_id: String,
    /// run 生命周期：running / completed / failed / aborted。
    pub status: String,
    /// `identityAssessment.status`：match / mismatch / uncertain / insufficient_data。
    pub identity_status: Option<String>,
    /// `identityAssessment.verdict.status`：clean_match / spoof_behavior_induced / plain_mismatch / ...
    pub verdict_status: Option<String>,
    pub true_family: Option<String>,
    pub true_model: Option<String>,
    pub spoof_method: Option<String>,
    pub confidence: Option<String>,
    pub warnings_count: u32,
    /// bazaarlink 报告路径（`/api/probe/report/<id>`）。半敏感：含 runId。
    pub report_url: Option<String>,
    pub created_at: Option<i64>,
    pub completed_at: Option<i64>,
}

/// 发 probe 请求（POST bazaarlink）并解析返回的 run。
///
/// **`sync` 由 [`ProbeRequest::sync`] 决定**：
/// - `sync=false`（生产主路径，B-160 起）：秒级返回 `{runId, claimToken}`，由
///   [`poll_probe_run`] 轮询到终态；
/// - `sync=true`（遗留路径 / 对照组）：服务端在**这条连接上**等到整轮跑完——
///   真机实测 360.53s，会撞上传输层 120s 超时，只在受控实验里用。
///
/// 复用传入的 `HttpTransport`——生产用 `ReqwestTransport`，测试用 `MockTransport`。
/// 限流（429）读 `Retry-After` 头；502/503/400/403 映射成可读错误。
///
/// `T: ?Sized` 是为了让调用方能把 `&dyn HttpTransport` 传进来（服务层要在
/// 「probe 专用 transport」与「默认 transport」之间二选一，见 `Service::probe_model`）。
pub async fn run_probe<T: HttpTransport + ?Sized>(
    transport: &T,
    req: &ProbeRequest,
) -> Result<ProbeRun> {
    let http = HttpRequest::new(Method::Post, PROBE_ENDPOINT).json_body(&req.to_json())?;
    let resp = transport.request(http).await?;
    parse_probe_response(resp)
}

/// `GET /api/probe/run/<runId>`：查一次 run 的当前状态（轮询兜底用）。
///
/// 状态码映射与 POST 同口径（429/502/503/400/403/其它非 2xx）。run 不存在或已过期时
/// bazaarlink 回 `404 {"error":"Run not found"}`，落进「其它非 2xx」那条分支。
pub async fn fetch_probe_run<T: HttpTransport + ?Sized>(
    transport: &T,
    run_id: &str,
) -> Result<ProbeRun> {
    let url = format!("{PROBE_RUN_ENDPOINT_PREFIX}{run_id}");
    let resp = transport
        .request(HttpRequest::new(Method::Get, url))
        .await?;
    parse_probe_response(resp)
}

/// run 仍在跑。只认**明说在跑**的词。
///
/// 词表来自真机观测：`sync=false` 提交后 run 级状态依次出现 `pending` → `running`，
/// `sync=true` 的终态是 `completed` / `failed`。
fn is_running_status(status: &str) -> bool {
    matches!(status, "running" | "queued" | "pending" | "in_progress")
}

/// run 已经收尾。**认不出来的一律当「没收尾」**——多问一次代价是 15s，
/// 少问一次代价是把结论判给一个还在跑的 run（B-160 的教训）。
fn is_terminal_status(status: &str) -> bool {
    matches!(status, "completed" | "failed" | "aborted")
}

/// 是否需要继续轮询。
///
/// `submitted_async = true`（B-160 起的主路径）：提交时**明确要了异步**、响应里带 runId，
/// 服务端已受理 ⇒ 只要它没明说终止，就继续等。
///
/// 这一条**不能**沿用同步路径的判据：`sync=false` 的响应体只有 `{runId, claimToken}`，
/// **压根没有 `status` 字段**（解析成 `"unknown"`）。同步路径把 `unknown` 当作「不补查」
/// 是有依据的（`sync=true` 的响应是服务端对这次请求的最终答复），而异步路径下同一个
/// `unknown` 的含义正好相反——它是「刚交出去，还没问过」。判据必须跟着**提交方式**走，
/// 而不是跟着**响应长什么样**走。
///
/// # 为什么异步路径**不等判定出现就收手**（真机教训，别改回去）
///
/// 2026-10-17 真机实测（`real_site_contract.rs` 的 B-160 用例）：把「已有判定 ⇒ 停」用在
/// 异步路径上，轮询会在 **70.26s** 收手，拿到的是
///
/// ```text
/// status="running"  verdict=Some("clean_match_family_only")  true_model=None
/// ```
///
/// ——**服务端还在跑**，此刻序列化出来的是一份**没定到子模型**的中间判定。同一把 key、
/// 同一模型的终版是 `clean_match_submodel_mismatch` / `trueModel="GPT-5.6 Luna"` / `0.98`。
/// 也就是说「早停」不是省时间，是**把结论换成了错的**。所以异步路径的唯一收手条件是
/// **run 级状态终止**（`completed` / `failed` / `aborted`），判定出现只是中间态。
///
/// `submitted_async = false`：M15-S1 遗留的同步路径，只在服务端**明说还在跑**且没判定时补查。
/// 两种「不该补查」都是实测过的真实形态：
/// - `completed` + 无判定：key 访问不了该模型时 POST 秒级（420–663ms）返回这个形态
///   ——**已是终态**，再问多少次都是同一个答案，补查只会白等（B-134 真机记录）；
/// - `status` 缺失（解析成 `"unknown"`）：同步响应的 `unknown` 没有依据认定它还会变。
pub fn needs_poll(run: &ProbeRun, submitted_async: bool) -> bool {
    if is_terminal_status(&run.status) {
        return false;
    }
    if submitted_async {
        // 异步提交：run 已经在服务端队列/执行中，只差时间。
        // **不看判定**——中间态也带判定，见上面的真机记录。
        true
    } else {
        run.verdict_status.is_none() && is_running_status(&run.status)
    }
}

/// 轮询到终态（best-effort），返回**最后一次**拿到的 run 与停下来原因。
///
/// 三条停止条件：拿到终态或判定、预算用尽（按计划睡眠时长计）、连续失败超限。
///
/// **永不返回 `Err`**：提交的结果才是判定来源，轮询只是把它取回来——轮询失败
/// 不能把一次可能成功的检测变成失败。
///
/// 与 B-134 旧实现的两点关键差异：
/// - 单次补查失败**不中止**（旧实现 `Err(_) => break`）；失败要连续到 `max_consecutive_errors`
///   才放弃，且中途成功一次即归零——判定挂在 runId 上，网络抖一下不该丢掉结论；
/// - 停下来时**一定**把 `run` 带回去（含 `run_id` / `report_url`），上层因此还能落一条
///   可追的历史与可点开的报告。旧实现在超时路径上会把 run 丢掉，等于换个方式丢结论。
pub async fn poll_probe_run<T: HttpTransport + ?Sized>(
    transport: &T,
    first: ProbeRun,
    submitted_async: bool,
    policy: PollPolicy,
    sleeper: &dyn Sleeper,
) -> PollOutcome {
    let mut run = first;
    let mut polled = 0u32;
    let mut errors = 0u32;
    let mut consecutive_errors = 0u32;
    // 已花掉的预算：**计划睡眠 + 实测请求耗时**（两样都算，预算才是墙上时间上界）。
    let mut spent = Duration::ZERO;
    let mut stop = PollStop::NotNeeded;

    if needs_poll(&run, submitted_async) {
        loop {
            let attempt = polled + errors + 1;
            if attempt > MAX_POLL_ATTEMPTS {
                stop = PollStop::AttemptsExhausted;
                break;
            }
            let delay = policy.delay_for(attempt);
            // 预算按「打算睡多少」先扣一次：先问下一次还睡得下吗，睡不下就不再问。
            if spent.saturating_add(delay) > policy.budget {
                stop = PollStop::BudgetExhausted;
                break;
            }
            sleeper.sleep(delay).await;
            spent = spent.saturating_add(delay);
            // 请求本身的往返也计入预算：否则 900s 的预算遇到慢响应会变成两小时。
            // 用 `Instant` 而不是注入时钟——测试里 `MockTransport` 往返≈0，
            // 「预算 3s / 退避 1s ⇒ 问 3 次」这类断言仍然精确。
            let requested_at = std::time::Instant::now();
            let fetched = fetch_probe_run(transport, &run.run_id).await;
            spent = spent.saturating_add(requested_at.elapsed());
            match fetched {
                Ok(next) => {
                    polled += 1;
                    consecutive_errors = 0;
                    run = next;
                }
                Err(_) => {
                    errors += 1;
                    consecutive_errors += 1;
                    if consecutive_errors >= policy.max_consecutive_errors {
                        stop = PollStop::TooManyErrors;
                        break;
                    }
                }
            }
            // 先判是否已收敛：真拿到终态就该报 `Settled`，哪怕这一发把预算吃穿了——
            // 「等超了」是没拿到结论时的说法，不是拿到结论后的说法。
            if !needs_poll(&run, submitted_async) {
                stop = PollStop::Settled;
                break;
            }
            // 预算可能在这次请求里就被吃掉（慢响应），这里补一次判：不再往下问。
            if spent > policy.budget {
                stop = PollStop::BudgetExhausted;
                break;
            }
        }
    }

    PollOutcome {
        run,
        polled,
        errors,
        stop,
    }
}

fn parse_probe_response(resp: HttpResponse) -> Result<ProbeRun> {
    if resp.status == 429 {
        let retry = resp.retry_after_secs().unwrap_or(60);
        return Err(Error::RateLimited {
            retry_after_secs: retry,
        });
    }
    if resp.status == 502 {
        return Err(Error::Transport("目标站点无法访问（DNS 解析失败）".into()));
    }
    if resp.status == 503 {
        return Err(Error::Transport("检测服务正在维护，请稍后重试".into()));
    }
    if resp.status == 400 {
        // M1（独立复审）：400 body 原样透传会回显请求字段——bazaarlink 未保证不回显 apiKey。
        // B-141：这里必须走**与三个出口同口径**的 `scrub_event_message`，不能只用 `scrub`——
        // `scrub` 对「整串没有 `://`」的形态不敏感（`password=hunter2`、`Bearer <token>` 这类），
        // 而这段文本会进错误信息、再进事件表。
        let body = crate::redact::scrub_event_message(&resp.text_lossy());
        return Err(Error::Transport(format!(
            "检测请求被拒（目标 URL 无效或私有 / 参数不合法）: {body}"
        )));
    }
    if resp.status == 403 {
        return Err(Error::Transport(
            "请求的检测功能（推理强度校验）未启用".into(),
        ));
    }
    if resp.status < 200 || resp.status >= 300 {
        return Err(Error::Transport(format!(
            "检测服务返回 HTTP {}",
            resp.status
        )));
    }
    let v: Value = resp.json_value()?;
    parse_probe_run(&v)
}

/// 从 bazaarlink 响应 JSON 取身份判定摘要。宽松反序列化：只强依赖 `runId`，
/// 其余字段缺失返回 `None`/默认（schema 可能演变，文档明说 "may evolve"）。
fn parse_probe_run(v: &Value) -> Result<ProbeRun> {
    // L3（独立复审）：bazaarlink schema 可能演变成 snake_case（文档自陈 may evolve），
    // 同时认 `runId` / `run_id`，避免 schema 一改就报「缺 runId」。
    let run_id = v
        .get("runId")
        .or_else(|| v.get("run_id"))
        .and_then(|x| x.as_str())
        .ok_or_else(|| Error::Transport("probe 响应缺 runId".into()))?
        .to_string();
    let status = v
        .get("status")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown")
        .to_string();
    let assessment = v.get("identityAssessment");
    let identity_status = assessment
        .and_then(|a| a.get("status"))
        .and_then(|x| x.as_str())
        .map(String::from);
    let verdict = assessment.and_then(|a| a.get("verdict"));
    let verdict_status = verdict
        .and_then(|v| v.get("status"))
        .and_then(|x| x.as_str())
        .map(String::from);
    let true_family = verdict
        .and_then(|v| v.get("trueFamily"))
        .and_then(|x| x.as_str())
        .map(String::from);
    let true_model = verdict
        .and_then(|v| v.get("trueModel"))
        .and_then(|x| x.as_str())
        .map(String::from);
    let spoof_method = verdict
        .and_then(|v| v.get("spoofMethod"))
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty() && *s != "null")
        .map(String::from);
    let confidence = verdict
        .and_then(|v| v.get("confidence"))
        .and_then(|x| x.as_str())
        .map(String::from);
    let warnings_count = v
        .get("warnings")
        .and_then(|w| w.as_array())
        .map(|a| a.len() as u32)
        .unwrap_or(0);
    let report_url = v
        .get("reportUrl")
        .and_then(|x| x.as_str())
        .map(String::from);
    let created_at = v.get("createdAt").and_then(|x| x.as_i64());
    let completed_at = v.get("completedAt").and_then(|x| x.as_i64());
    Ok(ProbeRun {
        run_id,
        status,
        identity_status,
        verdict_status,
        true_family,
        true_model,
        spoof_method,
        confidence,
        warnings_count,
        report_url,
        created_at,
        completed_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::retry::RecordingSleeper;
    use crate::site::transport::MockTransport;

    fn probe_req() -> ProbeRequest {
        ProbeRequest {
            base_url: "https://api.example.com/v1".into(),
            api_key: Zeroizing::new("sk-test-secret".into()),
            model_id: "vendor/model".into(),
            claimed_model: Some("vendor/model".into()),
            sync: true,
        }
    }

    /// 非终态响应：`sync=true` 的 POST 没等到跑完就返回（轮询兜底的触发形态）。
    fn running_response() -> HttpResponse {
        HttpResponse::json(200, json!({ "runId": "r-poll", "status": "running" })).unwrap()
    }

    /// 终态响应：跑完了，带判定。
    fn completed_with_verdict() -> HttpResponse {
        HttpResponse::json(
            200,
            json!({
                "runId": "r-poll",
                "status": "completed",
                "identityAssessment": {
                    "status": "mismatch",
                    "verdict": {
                        "status": "clean_match_submodel_mismatch",
                        "trueFamily": "zhipu",
                        "trueModel": "glm-5.2",
                        "confidence": "high"
                    }
                },
                "warnings": []
            }),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn run_probe_parses_completed_clean_match() {
        let mock = MockTransport::new(vec![HttpResponse::json(
            200,
            json!({
                "runId": "r1",
                "status": "completed",
                "identityAssessment": {
                    "status": "match",
                    "verdict": {
                        "status": "clean_match",
                        "trueFamily": "openai",
                        "trueModel": "gpt-4o",
                        "spoofMethod": null,
                        "confidence": "high"
                    }
                },
                "warnings": [],
                "reportUrl": "/api/probe/report/r1",
                "createdAt": 1700000000,
                "completedAt": 1700000060
            }),
        )
        .unwrap()]);
        let run = run_probe(&mock, &probe_req()).await.unwrap();
        assert_eq!(run.run_id, "r1");
        assert_eq!(run.status, "completed");
        assert_eq!(run.identity_status.as_deref(), Some("match"));
        assert_eq!(run.verdict_status.as_deref(), Some("clean_match"));
        assert_eq!(run.true_family.as_deref(), Some("openai"));
        assert_eq!(run.true_model.as_deref(), Some("gpt-4o"));
        assert_eq!(run.spoof_method, None);
        assert_eq!(run.confidence.as_deref(), Some("high"));
        assert_eq!(run.warnings_count, 0);
        assert_eq!(run.report_url.as_deref(), Some("/api/probe/report/r1"));
        assert_eq!(run.created_at, Some(1700000000));
        assert_eq!(run.completed_at, Some(1700000060));
    }

    #[tokio::test]
    async fn run_probe_parses_spoof_verdict() {
        let mock = MockTransport::new(vec![HttpResponse::json(
            200,
            json!({
                "runId": "r2",
                "status": "completed",
                "identityAssessment": {
                    "status": "mismatch",
                    "verdict": {
                        "status": "spoof_behavior_induced",
                        "trueFamily": "other",
                        "trueModel": null,
                        "spoofMethod": "behavior_induced",
                        "confidence": "medium"
                    }
                },
                "warnings": [{"id":"w1"},{"id":"w2"}]
            }),
        )
        .unwrap()]);
        let run = run_probe(&mock, &probe_req()).await.unwrap();
        assert_eq!(
            run.verdict_status.as_deref(),
            Some("spoof_behavior_induced")
        );
        assert_eq!(run.true_family.as_deref(), Some("other"));
        assert_eq!(run.true_model, None);
        assert_eq!(run.spoof_method.as_deref(), Some("behavior_induced"));
        assert_eq!(run.warnings_count, 2);
    }

    #[tokio::test]
    async fn run_probe_429_maps_to_rate_limited_with_retry_after() {
        let mock = MockTransport::new(vec![
            HttpResponse::new(429, b"rate limited".to_vec()).with_header("Retry-After", "120")
        ]);
        let err = run_probe(&mock, &probe_req()).await.unwrap_err();
        assert!(matches!(
            err,
            Error::RateLimited {
                retry_after_secs: 120
            }
        ));
    }

    #[tokio::test]
    async fn run_probe_502_reports_dns_failure() {
        let mock = MockTransport::new(vec![HttpResponse::new(502, b"bad gateway".to_vec())]);
        let err = run_probe(&mock, &probe_req()).await.unwrap_err();
        assert!(err.to_string().contains("DNS"));
    }

    #[tokio::test]
    async fn run_probe_400_reports_invalid_url() {
        let mock = MockTransport::new(vec![HttpResponse::new(400, b"invalid url".to_vec())]);
        let err = run_probe(&mock, &probe_req()).await.unwrap_err();
        assert!(err.to_string().contains("无效"));
    }

    #[tokio::test]
    async fn run_probe_503_reports_maintenance() {
        let mock = MockTransport::new(vec![HttpResponse::new(503, b"maintenance".to_vec())]);
        let err = run_probe(&mock, &probe_req()).await.unwrap_err();
        assert!(err.to_string().contains("维护"));
    }

    #[tokio::test]
    async fn run_probe_403_reports_feature_disabled() {
        let mock = MockTransport::new(vec![HttpResponse::new(403, b"disabled".to_vec())]);
        let err = run_probe(&mock, &probe_req()).await.unwrap_err();
        assert!(err.to_string().contains("未启用"));
    }

    #[tokio::test]
    async fn run_probe_incomplete_status_still_parses() {
        // running 状态（sync=false 场景，或未完成）——无 identityAssessment
        let mock = MockTransport::new(vec![HttpResponse::json(
            200,
            json!({ "runId": "r4", "status": "running" }),
        )
        .unwrap()]);
        let run = run_probe(&mock, &probe_req()).await.unwrap();
        assert_eq!(run.status, "running");
        assert_eq!(run.identity_status, None);
        assert_eq!(run.verdict_status, None);
    }

    #[tokio::test]
    async fn run_probe_missing_run_id_is_error() {
        let mock = MockTransport::new(vec![HttpResponse::json(
            200,
            json!({ "status": "completed" }),
        )
        .unwrap()]);
        let err = run_probe(&mock, &probe_req()).await.unwrap_err();
        assert!(err.to_string().contains("runId"));
    }

    #[tokio::test]
    async fn probe_request_debug_does_not_leak_api_key() {
        // 证伪守卫：Debug 输出不含 apiKey 明文。
        let req = probe_req();
        let dbg = format!("{:?}", req);
        assert!(!dbg.contains("sk-test-secret"));
        assert!(dbg.contains("<已设置>"));
    }

    #[tokio::test]
    async fn run_probe_sends_api_key_in_body_to_bazaarlink() {
        // 请求体含 apiKey（发给 bazaarlink，设计要求）；不是泄漏——是协议要求。
        let mock = MockTransport::new(vec![HttpResponse::json(
            200,
            json!({
                "runId": "r3", "status": "completed",
                "identityAssessment": {"status": "uncertain", "verdict": {"status": "ambiguous"}}
            }),
        )
        .unwrap()]);
        run_probe(&mock, &probe_req()).await.unwrap();
        let sent = mock.nth_request(0).unwrap();
        assert_eq!(sent.method, Method::Post);
        assert_eq!(sent.url, PROBE_ENDPOINT);
        let body: Value = serde_json::from_slice(&sent.body.unwrap()).unwrap();
        assert_eq!(body["apiKey"], "sk-test-secret");
        assert_eq!(body["baseUrl"], "https://api.example.com/v1");
        assert_eq!(body["modelId"], "vendor/model");
        assert_eq!(body["claimedModel"], "vendor/model");
        assert_eq!(body["sync"], true);
    }

    #[tokio::test]
    async fn run_probe_omits_claimed_model_when_none() {
        let mock = MockTransport::new(vec![HttpResponse::json(
            200,
            json!({ "runId": "r5", "status": "completed" }),
        )
        .unwrap()]);
        let mut req = probe_req();
        req.claimed_model = None;
        run_probe(&mock, &req).await.unwrap();
        let body: Value =
            serde_json::from_slice(&mock.nth_request(0).unwrap().body.unwrap()).unwrap();
        assert!(body.get("claimedModel").is_none() || body["claimedModel"].is_null());
    }

    #[tokio::test]
    async fn run_probe_400_body_does_not_leak_api_key() {
        // M1（独立复审）：400 body 若回显请求字段（含 apiKey），错误信息不得带明文。
        let mock = MockTransport::new(vec![HttpResponse::new(
            400,
            br#"{"error":"invalid baseUrl","echoedApiKey":"sk-test-secret-leak"}"#.to_vec(),
        )]);
        let err = run_probe(&mock, &probe_req()).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains("sk-test-secret-leak"),
            "400 body 不得回显 apiKey: {msg}"
        );
        assert!(msg.contains("检测请求被拒"));
    }

    #[tokio::test]
    async fn run_probe_accepts_snake_case_run_id() {
        // L3（独立复审）：schema 演变成 run_id（snake_case）也能解析。
        let mock = MockTransport::new(vec![HttpResponse::json(
            200,
            json!({ "run_id": "r6", "status": "completed" }),
        )
        .unwrap()]);
        let run = run_probe(&mock, &probe_req()).await.unwrap();
        assert_eq!(run.run_id, "r6");
    }

    // ---- B-134：轮询兜底 ----

    /// 轮询兜底的起点：POST 返回非终态、无判定。
    fn running_run() -> ProbeRun {
        ProbeRun {
            run_id: "r-poll".into(),
            status: "running".into(),
            identity_status: None,
            verdict_status: None,
            true_family: None,
            true_model: None,
            spoof_method: None,
            confidence: None,
            warnings_count: 0,
            report_url: None,
            created_at: None,
            completed_at: None,
        }
    }

    fn poll_policy(first_delay: u64, max_interval: u64, budget: u64) -> PollPolicy {
        PollPolicy {
            first_delay: Duration::from_secs(first_delay),
            max_interval: Duration::from_secs(max_interval),
            budget: Duration::from_secs(budget),
            ..PollPolicy::default()
        }
    }

    /// `sync=false` 提交响应的**真实形状**（真机标定）：只有 `runId` + `claimToken`，
    /// **没有 `status` 字段**。刻意走真正的解析器，而不是手搓一个 `ProbeRun`——
    /// 手搓的话 `status == "unknown"` 就成了「测试里顺便写死的前提」，而不是被测代码的产物。
    fn async_submit_run() -> ProbeRun {
        let run = parse_probe_run(&json!({
            "runId": "r-poll",
            "claimToken": "ct-not-echoed"
        }))
        .unwrap();
        assert_eq!(
            run.status, "unknown",
            "真机形态：sync=false 的响应没有 status，解析成 unknown"
        );
        assert!(run.verdict_status.is_none());
        run
    }

    #[tokio::test]
    async fn fetch_probe_run_gets_the_run_scoped_url() {
        // 真机标定过的路由形态：GET /api/probe/run/<runId>（集合路由只收 POST）。
        let mock = MockTransport::new(vec![completed_with_verdict()]);
        let run = fetch_probe_run(&mock, "r-poll").await.unwrap();
        assert_eq!(
            run.verdict_status.as_deref(),
            Some("clean_match_submodel_mismatch")
        );
        let sent = mock.nth_request(0).unwrap();
        assert_eq!(sent.method, Method::Get);
        assert_eq!(sent.url, "https://bazaarlink.ai/api/probe/run/r-poll");
    }

    #[test]
    fn needs_poll_sync_path_only_when_the_run_is_still_running_without_a_verdict() {
        let mut run = running_run();
        assert!(needs_poll(&run, false), "running 且无判定 ⇒ 补查");

        // 真机形态（B-134 实测 420–663ms）：已终态、无判定 ⇒ 不补查。
        run.status = "completed".into();
        assert!(
            !needs_poll(&run, false),
            "completed 无判定是终态，补查只会白等"
        );

        // status 缺失时解析成 "unknown" ⇒ 同步响应已是这次请求的最终答复，不赌。
        run.status = "unknown".into();
        assert!(!needs_poll(&run, false), "unknown 无依据认定还会变，不补查");

        // 有判定 ⇒ 无论什么状态都不补查。
        run.status = "running".into();
        run.verdict_status = Some("ambiguous".into());
        assert!(!needs_poll(&run, false), "已有判定 ⇒ 不补查");
    }

    /// **B-160 的核心**：同一个 `status == "unknown"`，判据必须跟着**提交方式**走。
    ///
    /// 证伪方式：把 `needs_poll` 的 `submitted_async` 分支删掉（退回 `is_running_status`），
    /// 本用例第一段立刻红——而那正是 B-160 的线上形态（异步提交后一次都不问，直接判「没结论」）。
    #[test]
    fn needs_poll_async_path_keeps_asking_even_when_the_response_had_no_status() {
        let run = async_submit_run();
        assert_eq!(run.status, "unknown");
        assert!(
            needs_poll(&run, true),
            "异步提交：响应没有 status 不等于它不在跑"
        );
        assert!(
            !needs_poll(&run, false),
            "同一个响应在同步语义下不补查（两种语义不能混）"
        );

        // 明说终止 ⇒ 两种语义都不再问。
        let mut done = async_submit_run();
        done.status = "completed".into();
        assert!(!needs_poll(&done, true));

        // **真机教训（2026-10-17）**：run 仍是 `running` 时服务端已经会吐出判定，
        // 但那是**中间判定**（`clean_match_family_only` / `trueModel=None`），
        // 终版是 `clean_match_submodel_mismatch` / `GPT-5.6 Luna`。
        // ⇒ 异步路径**不能**因为「看到判定」就收手，必须等 run 级状态终止。
        let mut early = async_submit_run();
        early.status = "running".into();
        early.verdict_status = Some("clean_match_family_only".into());
        assert!(
            needs_poll(&early, true),
            "异步路径上「有判定」只是中间态，必须继续等到终态"
        );
        // 同步语义下（遗留路径）「有判定」仍然收手——那里响应就是这次请求的最终答复。
        assert!(!needs_poll(&early, false));
    }

    /// 上面那条判据的**端到端**版本：run 先给出中间判定、之后才终止，
    /// 轮询必须把终版拿回来，而不是在第一个判定上停住。
    #[tokio::test]
    async fn poll_probe_run_does_not_stop_on_an_intermediate_verdict() {
        let intermediate = HttpResponse::json(
            200,
            json!({
                "runId": "r-poll",
                "status": "running",
                "identityAssessment": {
                    "status": "match",
                    "verdict": { "status": "clean_match_family_only", "confidence": "high" }
                }
            }),
        )
        .expect("构造中间态响应");
        let mock = MockTransport::new(vec![intermediate, completed_with_verdict()]);
        let sleeper = RecordingSleeper::default();
        let out = poll_probe_run(
            &mock,
            async_submit_run(),
            true,
            poll_policy(1, 1, 60),
            &sleeper,
        )
        .await;
        assert_eq!(out.stop, PollStop::Settled);
        assert_eq!(out.polled, 2, "中间判定之后还要再问一次");
        assert_eq!(out.run.status, "completed");
        assert_eq!(
            out.run.verdict_status.as_deref(),
            Some("clean_match_submodel_mismatch"),
            "必须拿到终版判定，不能停在中间态"
        );
        assert_eq!(out.run.true_model.as_deref(), Some("glm-5.2"));
    }

    #[test]
    fn poll_delay_backs_off_from_first_delay_then_caps() {
        let p = PollPolicy::default();
        let seq: Vec<u64> = (1..=7).map(|k| p.delay_for(k).as_secs()).collect();
        assert_eq!(seq, vec![2, 4, 8, 15, 15, 15, 15], "翻倍退避到上限后固定");
        // 极端 attempt 不 panic、不溢出。
        assert_eq!(p.delay_for(u32::MAX).as_secs(), 15);
        assert_eq!(p.delay_for(0).as_secs(), 2);
    }

    #[tokio::test]
    async fn poll_probe_run_settles_and_returns_the_verdict() {
        // 真机形态：pending → running → completed（+判定）。
        let mock = MockTransport::new(vec![
            HttpResponse::json(200, json!({ "runId": "r-poll", "status": "pending" })).unwrap(),
            running_response(),
            completed_with_verdict(),
        ]);
        let sleeper = RecordingSleeper::default();
        let out = poll_probe_run(
            &mock,
            async_submit_run(),
            true,
            poll_policy(1, 1, 60),
            &sleeper,
        )
        .await;
        assert_eq!(out.stop, PollStop::Settled);
        assert_eq!(out.polled, 3);
        assert_eq!(out.errors, 0);
        assert_eq!(out.run.status, "completed");
        assert_eq!(
            out.run.verdict_status.as_deref(),
            Some("clean_match_submodel_mismatch")
        );
        assert_eq!(out.run.true_model.as_deref(), Some("glm-5.2"));
        assert_eq!(sleeper.calls().len(), 3, "每次补查前退避一次");
        assert_eq!(mock.request_count(), 3, "拿到终态后不得再补查");
    }

    #[tokio::test]
    async fn poll_probe_run_stops_on_budget_and_still_returns_the_run() {
        // 预算 3s、退避 1s ⇒ 睡满 3 次后下一次「睡不下」⇒ 停。
        // 关键断言：停下时**最后一次问到的 run 原样带回去**——B-160 要的是「等不到结论也别把线索丢了」。
        //
        // 注意 `report_url` 不在这里断言：真机上 `reportUrl` 只随**终态**响应出现
        // （run 还在跑时顶层没有这个键），而本用例的 run 一直没跑完。把「没等到的 run
        // 也必须有报告链接」写成断言，就是拿一个服务端不承诺的东西当契约。
        let frame = || {
            HttpResponse::json(
                200,
                json!({ "runId": "r-poll", "status": "running", "modelId": "glm-5.3" }),
            )
            .expect("构造 running 响应")
        };
        let mock = MockTransport::new(vec![frame(), frame(), frame(), frame()]);
        let sleeper = RecordingSleeper::default();
        let out = poll_probe_run(
            &mock,
            async_submit_run(),
            true,
            // 预算 3.5s（不是 3s）：预算现在**把请求耗时也算进去**，任何非零耗时都会让
            // `spent + delay > budget` 提前一拍成立。留 0.5s 余量，断言才钉在
            // 「问了 3 次」这个语义上，而不是钉在「Mock 往返恰好为 0」这个巧合上。
            PollPolicy {
                budget: Duration::from_millis(3_500),
                ..poll_policy(1, 1, 60)
            },
            &sleeper,
        )
        .await;
        assert_eq!(out.stop, PollStop::BudgetExhausted);
        assert_eq!(out.polled, 3, "预算内问了 3 次");
        assert_eq!(sleeper.calls().len(), 3);
        assert_eq!(out.run.run_id, "r-poll", "run_id 必须带回去");
        assert_eq!(
            out.run.status, "running",
            "带回来的是**最后一次**问到的 run，不是提交时那个半成品"
        );
        assert_eq!(
            mock.request_count(),
            3,
            "预算用尽后不得再多打一次（第 4 帧没被消费）"
        );
    }

    #[tokio::test]
    async fn poll_probe_run_tolerates_a_transient_failure() {
        // 旧实现（B-134）在这里 `break`，等于网络抖一下就把已经跑出来的结论丢掉。
        let mock = MockTransport::new(vec![running_response()]);
        mock.push_error(Error::Transport("connection reset".into()));
        mock.push(completed_with_verdict());
        let sleeper = RecordingSleeper::default();
        let out = poll_probe_run(
            &mock,
            async_submit_run(),
            true,
            poll_policy(1, 1, 60),
            &sleeper,
        )
        .await;
        assert_eq!(out.stop, PollStop::Settled, "一次失败不该中止");
        assert_eq!(out.errors, 1);
        assert_eq!(out.polled, 2);
        assert_eq!(out.run.status, "completed");
        assert_eq!(mock.request_count(), 3, "失败那一次也真的打出去了");
    }

    /// **判别性用例**（独立复审 P2-4）：把「成功一次就归零连续失败计数」删掉，
    /// 这条必须红。
    ///
    /// 形态取「错-对-错-对-错-对」且容忍 2 次：只要连续计数**不**归零，
    /// 第二发失败后就会判 `TooManyErrors` 提前收手；归零了才能一直问到终态。
    /// 只注入一次失败的用例（上一条）对这件事**没有判别力**——容忍 5 次时删不删归零都过。
    #[tokio::test]
    async fn poll_probe_run_resets_the_consecutive_error_count_on_success() {
        let mock = MockTransport::new(vec![running_response()]);
        mock.push_error(Error::Transport("connection reset".into()));
        mock.push(running_response());
        mock.push_error(Error::Transport("connection reset".into()));
        mock.push(running_response());
        mock.push_error(Error::Transport("connection reset".into()));
        mock.push(completed_with_verdict());
        let sleeper = RecordingSleeper::default();
        let policy = PollPolicy {
            max_consecutive_errors: 2,
            ..poll_policy(1, 1, 600)
        };
        let out = poll_probe_run(&mock, async_submit_run(), true, policy, &sleeper).await;
        assert_eq!(
            out.stop,
            PollStop::Settled,
            "中途成功过就必须把连续失败计数归零，不能因为早先的失败而提前收手"
        );
        assert_eq!(out.errors, 3, "三次失败都记在累计数里");
        assert_eq!(out.polled, 4, "中间那三发成功都要真的问出去");
        assert_eq!(out.run.status, "completed");
    }

    #[tokio::test]
    async fn poll_probe_run_with_a_zero_budget_makes_no_request() {
        // 预算 0 ⇒ 一次都不问（「用尽即停」的最短形态）。
        let mock = MockTransport::new(vec![running_response()]);
        let sleeper = RecordingSleeper::default();
        let out = poll_probe_run(
            &mock,
            async_submit_run(),
            true,
            poll_policy(1, 1, 0),
            &sleeper,
        )
        .await;
        assert_eq!(out.stop, PollStop::BudgetExhausted);
        assert_eq!(out.polled, 0);
        assert_eq!(mock.request_count(), 0);
        assert!(sleeper.calls().is_empty());
        assert_eq!(out.run.run_id, "r-poll", "预算 0 也要把 run_id 带回去");
    }

    #[tokio::test]
    async fn poll_probe_run_caps_a_zero_backoff_configuration() {
        // 配置异常（退避 0 但预算 > 0）不能变成死循环：由 `MAX_POLL_ATTEMPTS` 兜住。
        // 这**不是**「立刻停」——退避 0 时预算永远花不完，只能靠硬上限。
        let frames: Vec<HttpResponse> =
            (0..MAX_POLL_ATTEMPTS).map(|_| running_response()).collect();
        let mock = MockTransport::new(frames);
        let sleeper = RecordingSleeper::default();
        let policy = PollPolicy {
            first_delay: Duration::ZERO,
            max_interval: Duration::ZERO,
            budget: Duration::from_secs(60),
            max_consecutive_errors: 5,
        };
        let out = poll_probe_run(&mock, async_submit_run(), true, policy, &sleeper).await;
        assert_eq!(out.stop, PollStop::AttemptsExhausted);
        assert_eq!(out.polled, MAX_POLL_ATTEMPTS);
        assert_eq!(out.run.run_id, "r-poll");
    }

    #[tokio::test]
    async fn poll_probe_run_gives_up_after_consecutive_errors() {
        // 空队列 ⇒ 每次补查都是 Err。
        let mock = MockTransport::new(Vec::new());
        let sleeper = RecordingSleeper::default();
        let out = poll_probe_run(
            &mock,
            async_submit_run(),
            true,
            poll_policy(1, 1, 600),
            &sleeper,
        )
        .await;
        assert_eq!(out.stop, PollStop::TooManyErrors);
        assert_eq!(out.polled, 0);
        assert_eq!(out.errors, 5, "默认容忍 5 次连续失败");
        assert_eq!(out.run.run_id, "r-poll");
    }

    #[tokio::test]
    async fn poll_probe_run_with_zero_error_tolerance_stops_on_the_first_failure() {
        let mock = MockTransport::new(Vec::new());
        let sleeper = RecordingSleeper::default();
        let policy = PollPolicy {
            max_consecutive_errors: 0,
            ..poll_policy(1, 1, 600)
        };
        let out = poll_probe_run(&mock, async_submit_run(), true, policy, &sleeper).await;
        assert_eq!(out.stop, PollStop::TooManyErrors);
        assert_eq!(out.errors, 1, "0 容忍 = 第一次失败就停");
        assert_eq!(mock.request_count(), 1);
    }

    #[tokio::test]
    async fn poll_probe_run_is_not_needed_when_a_verdict_is_already_there() {
        // 提交就带判定（轻模型 / 服务端忽略 async）⇒ 一次 GET 都不发。
        let mock = MockTransport::new(vec![]);
        let sleeper = RecordingSleeper::default();
        let mut settled = async_submit_run();
        settled.status = "completed".into();
        settled.verdict_status = Some("clean_match".into());
        let out = poll_probe_run(&mock, settled, true, poll_policy(1, 1, 600), &sleeper).await;
        assert_eq!(out.stop, PollStop::NotNeeded);
        assert_eq!(out.polled, 0);
        assert_eq!(mock.request_count(), 0);
        assert!(sleeper.calls().is_empty());
    }
}
