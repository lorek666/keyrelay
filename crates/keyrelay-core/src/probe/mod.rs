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
//! # 两条请求路径
//!
//! 1. [`run_probe`]：POST `sync=true`（M15-S1 主路径）；
//! 2. [`poll_probe_run`]：POST 返回**非终态**时的补查兜底（B-134），best-effort、
//!    永不把一次成功的检测变成失败。

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

/// 轮询兜底参数（B-134）。
///
/// `sync=true` 的 POST 若返回**非终态**（`running` 等），补查 `GET /api/probe/run/<runId>`
/// 直到拿到终态或次数用尽。默认 6 次 × 5s ⇒ 最多多等 30s：
/// 同步窗口内都没跑完的检测，再等 30s 是「值得多等」与「别把界面挂住」之间的折中。
/// `max_attempts = 0` ⇒ 关闭轮询兜底（回到 M15-S1 的一次性 POST 行为）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollPolicy {
    /// 补查次数上限（不含 POST 本身）。
    pub max_attempts: u32,
    /// 两次补查之间的等待。走注入的 [`Sleeper`]，测试里不真睡。
    pub interval: Duration,
}

impl Default for PollPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 6,
            interval: Duration::from_secs(5),
        }
    }
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

/// 发 probe 请求（POST bazaarlink，`sync=true` 等完成）。
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
/// 反向（终态）不写成一张表：`completed` / `failed` / `aborted` 与「词表外的任何值」
/// 对轮询决策是同一个答案——不补查。写成两张表反而会让人以为「终态」在别处有分支。
fn is_running_status(status: &str) -> bool {
    matches!(status, "running" | "queued" | "pending" | "in_progress")
}

/// 是否需要轮询补查：**只在 bazaarlink 明说还在跑**、且这次没拿到判定时才补查。
///
/// 两种「不该补查」都是实测过的真实形态，不能靠猜：
/// - `completed` + 无判定：key 访问不了该模型时 POST 秒级（420–663ms）返回这个形态
///   ——**已是终态**，再问多少次都是同一个答案，补查只会白等 30s（B-134 真机记录）；
/// - `status` 缺失（解析成 `"unknown"`）：没有依据认定它还会变，不拿 30s 赌。
pub fn needs_poll(run: &ProbeRun) -> bool {
    run.verdict_status.is_none() && is_running_status(&run.status)
}

/// 轮询兜底：把一个**非终态**的 run 追到终态（best-effort）。
///
/// 返回 `(最新一次拿到的 run, 成功补查次数)`。三条停止条件：拿到终态或判定、
/// 次数用尽、补查请求失败（保留上一次的结果）。
///
/// **永不返回 `Err`**：POST 的结果才是判定来源，补查只是多给一次机会——补查失败
/// 不能把一次成功的检测变成失败。失败原因在这里吞掉，调用方按 `polled` 记事件。
pub async fn poll_probe_run<T: HttpTransport + ?Sized>(
    transport: &T,
    first: ProbeRun,
    policy: PollPolicy,
    sleeper: &dyn Sleeper,
) -> (ProbeRun, u32) {
    let mut run = first;
    let mut polled = 0u32;
    // 先睡再查：POST 刚返回，立刻重查大概率还是同一个 `running`。
    while polled < policy.max_attempts && needs_poll(&run) {
        sleeper.sleep(policy.interval).await;
        match fetch_probe_run(transport, &run.run_id).await {
            Ok(next) => {
                polled += 1;
                run = next;
            }
            Err(_) => break,
        }
    }
    (run, polled)
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

    fn poll_policy(max_attempts: u32) -> PollPolicy {
        PollPolicy {
            max_attempts,
            interval: Duration::from_secs(1),
        }
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
    fn needs_poll_only_when_the_run_is_still_running_without_a_verdict() {
        let mut run = running_run();
        assert!(needs_poll(&run), "running 且无判定 ⇒ 补查");

        // 真机形态（B-134 实测 420–663ms）：已终态、无判定 ⇒ 不补查。
        run.status = "completed".into();
        assert!(!needs_poll(&run), "completed 无判定是终态，补查只会白等");

        // status 缺失时解析成 "unknown" ⇒ 不拿 30s 赌。
        run.status = "unknown".into();
        assert!(!needs_poll(&run), "unknown 无依据认定还会变，不补查");

        // 有判定 ⇒ 无论什么状态都不补查。
        run.status = "running".into();
        run.verdict_status = Some("ambiguous".into());
        assert!(!needs_poll(&run), "已有判定 ⇒ 不补查");
    }

    #[tokio::test]
    async fn poll_probe_run_stops_as_soon_as_the_run_finishes() {
        let mock = MockTransport::new(vec![completed_with_verdict()]);
        let sleeper = RecordingSleeper::default();
        let (run, polled) = poll_probe_run(&mock, running_run(), poll_policy(3), &sleeper).await;
        assert_eq!(polled, 1, "第一次补查就拿到终态");
        assert_eq!(run.status, "completed");
        assert_eq!(
            run.verdict_status.as_deref(),
            Some("clean_match_submodel_mismatch")
        );
        assert_eq!(run.true_model.as_deref(), Some("glm-5.2"));
        assert_eq!(sleeper.calls(), vec![Duration::from_secs(1)]);
        assert_eq!(mock.request_count(), 1, "拿到终态后不得再补查");
    }

    #[tokio::test]
    async fn poll_probe_run_gives_up_after_max_attempts() {
        let mock = MockTransport::new(vec![
            running_response(),
            running_response(),
            running_response(),
        ]);
        let sleeper = RecordingSleeper::default();
        let (run, polled) = poll_probe_run(&mock, running_run(), poll_policy(3), &sleeper).await;
        assert_eq!(polled, 3, "用满次数上限");
        assert_eq!(run.status, "running");
        assert_eq!(run.verdict_status, None);
        assert_eq!(sleeper.calls().len(), 3, "每次补查前都等一个 interval");
        assert_eq!(mock.request_count(), 3);
    }

    #[tokio::test]
    async fn poll_probe_run_keeps_the_post_result_when_a_poll_fails() {
        // 补查失败（404/5xx/传输错误）⇒ 保留 POST 的结果，且**不再打**第二次。
        let mock = MockTransport::new(vec![HttpResponse::new(500, b"boom".to_vec())]);
        let sleeper = RecordingSleeper::default();
        let (run, polled) = poll_probe_run(&mock, running_run(), poll_policy(3), &sleeper).await;
        assert_eq!(polled, 0, "失败的补查不计入成功次数");
        assert_eq!(run.status, "running", "保留 POST 结果");
        assert_eq!(run.run_id, "r-poll");
        assert_eq!(mock.request_count(), 1, "补查失败即停，不刷接口");
    }

    #[tokio::test]
    async fn poll_probe_run_with_zero_attempts_makes_no_request() {
        // `max_attempts = 0` ⇒ 关闭兜底，退回一次性 POST 行为。
        let mock = MockTransport::new(vec![]);
        let sleeper = RecordingSleeper::default();
        let (run, polled) = poll_probe_run(&mock, running_run(), poll_policy(0), &sleeper).await;
        assert_eq!(polled, 0);
        assert_eq!(run.status, "running");
        assert_eq!(mock.request_count(), 0);
        assert!(sleeper.calls().is_empty());
    }
}
