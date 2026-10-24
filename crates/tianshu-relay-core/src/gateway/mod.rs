//! 本地网关（PRD FR-5）：把 `127.0.0.1:<port>/v1/*` 转发到选定的中转站。
//!
//! 存在的意义：有些 agent 只能读环境变量里的 key，不想把密钥写进它们的配置文件时，
//! 让它们连本机网关即可——密钥始终只在钥匙串里。
//!
//! 安全约束（每一条都有测试）：
//! 1. **只绑 `127.0.0.1`**：`GatewayConfig` 里根本没有「绑定地址」这个参数；
//! 2. **必须带本地令牌**：令牌每次启动新生成、不持久化；不匹配就不转发；
//! 3. 转发给上游的是**站点密钥**，本地令牌**绝不**发给上游；
//! 4. 上游响应里的 `Set-Cookie` 等敏感头**不回传**；
//! 5. 请求体/响应体**不写日志**；
//! 6. **只转发 `/v1/*`，且路径里不许有「向上跳」的段**（见 [`path_is_safe`]）；
//! 7. 响应**流式回传**，且有大小上限（见 [`MAX_RESPONSE_BYTES`]）。
//!
//! 启停时序（B-64）：优雅停机是**异步**的，`shutdown()` 只是发信号。需要「停旧 → 立刻绑新」
//! 的调用方必须用 [`GatewayHandle::shutdown_and_wait`]；`start()` 另外对 bind 的
//! `AddrInUse` 做有界退避重试（见 [`BIND_RETRY_ATTEMPTS`] / [`BIND_RETRY_DELAY`]）。

pub mod translate;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use std::time::Duration;

use axum::routing::any;
use axum::Router;
use futures_util::{StreamExt, TryStreamExt};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::routing::{
    ewma_update, model_key, reorder_by_effective_latency, should_failover, site_key, weighted_pick,
    Breaker, BreakerKey, BreakerPolicy, BreakerState, Candidate, GuardOutcome, RoundRobinState,
    RouteTable, SiteGuard, SiteGuardPolicy, SiteLease, Upstream,
};

/// 回传上游响应体的大小上限。
///
/// 没有上限的流式转发等于把内存交给上游决定：一个（被攻陷的、或只是出错的）
/// 中转站可以一直吐字节，把这个桌面进程撑爆（M4-S2 复审 P1-2）。
/// 64 MiB 远大于任何正常的 completions 响应，又不至于吃掉整台机器。
pub const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

/// bind 失败时的重试次数上限（**只在 `AddrInUse` 时重试**，其余错误一次返回）。
///
/// 为什么需要它（B-64 / M4-S2 复审 P2-7）：`gateway_start` 是「先停旧、再绑新」，
/// 而优雅停机是异步的——监听套接字要等服务任务被调度到、drop 掉 listener 才释放
/// （实测 ≈1.3ms）。窗口内 bind 就会 `AddrInUse`，旧实现直接报「端口可能被占用」，
/// 而**旧网关其实已经被停掉了**，用户被引向错误的方向。
///
/// 20 × 50ms = 1000ms 的预算足够覆盖那个毫秒级窗口，又不会让「端口真被别的程序占用」
/// 的情况等太久。
pub const BIND_RETRY_ATTEMPTS: u32 = 20;

/// 两次 bind 尝试之间的间隔（配合 [`BIND_RETRY_ATTEMPTS`]，最坏 ≈1000ms）。
pub const BIND_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

/// 请求体上限的默认值（M42-S1：可由 Settings 覆盖，范围 1..=64 MiB）。
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;

/// 请求体上限的**硬上限**（M42-S1 §4.4）：Settings 只能配到 64 MiB。
pub const MAX_REQUEST_BYTES_LIMIT: usize = 64 * 1024 * 1024;

/// 上游响应里**不**回传给本地调用方的头。
///
/// 两道规则（M4-S2 复审 P2-1 补全）：精确黑名单 + 子串规则。
/// 只靠精确列举一定会漏——复审实测漏掉了 `X-Api-Key` / `X-Auth-Token` /
/// `X-Upstream-Key` 三个把上游凭证原样回传给本地调用方的头。
///
/// 例外：`x-ratelimit-*` 里的 `tokens` 指的是**词元数**而不是凭证，
/// 客户端要靠它做退避，必须放行。
fn should_strip_response_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("x-ratelimit-") {
        return false;
    }
    const EXACT: [&str; 12] = [
        "set-cookie",
        "cookie",
        "authorization",
        "www-authenticate",
        "proxy-authenticate",
        "proxy-authorization",
        // hop-by-hop：由我们这层的连接自己定帧，原样透传会和 hyper 的
        // 分块编码叠成双重分帧（`content-length` 例外，见下）
        "transfer-encoding",
        "connection",
        "keep-alive",
        "upgrade",
        "te",
        "trailer",
    ];
    if EXACT.contains(&lower.as_str()) {
        return true;
    }
    ["auth", "cookie", "secret", "token", "key", "session"]
        .iter()
        .any(|needle| lower.contains(needle))
}

/// 转发时**丢弃**的请求头。
///
/// `authorization` / `x-tianshu-relay-token` 是本地令牌的载体（换成站点密钥）；
/// 其余是 hop-by-hop 头，或调用方不该借我们的手送给上游的凭证类头
/// （M4-S2 复审 P2-2：`Cookie` / `Proxy-Authorization` 之前会被原样转发）。
fn should_strip_request_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    const STRIP: [&str; 13] = [
        // 令牌载体：必须换掉（旧名 `x-keyrelay-token` 仍兼容一个版本）
        "authorization",
        "x-tianshu-relay-token",
        "x-keyrelay-token",
        // 由我们重新计算 / 由连接层决定
        "host",
        "content-length",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
        "te",
        "trailer",
        // 凭证类：不该借网关的手转出去
        "cookie",
        "proxy-authorization",
    ];
    STRIP.contains(&lower.as_str())
}

/// 把 `%XX` 解成字节；非法转义原样保留（不报错）。
fn percent_decode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// 路径是否安全：**任何**编码层级下都不许出现 `.` / `..` 段，也不许有控制字符。
///
/// 为什么不能只看字面量（M4-S2 复审 P1-1）：我们把 `{base}{path}{query}` 拼成字符串
/// 交给 `reqwest`，而 `reqwest` 用 `url` 解析它 —— WHATWG URL 规范会把 `.` / `..`
/// 段规整掉，**并且把 `%2e` 也当成 `.`**。于是 `/v1/../../admin` 与 `/v1/%2e%2e/admin`
/// 到上游时都变成了 `/admin`，「只转发 `/v1/*`」这条约束被静默绕过。
///
/// 所以这里按 `url` 的语义校验：反复 percent-decode（有界），每一层都检查段名。
fn path_is_safe(path: &str) -> bool {
    let mut bytes = path.as_bytes().to_vec();
    for _ in 0..4 {
        if !decoded_path_has_no_traversal(&bytes) {
            return false;
        }
        let next = percent_decode(&bytes);
        if next == bytes {
            return true;
        }
        bytes = next;
    }
    decoded_path_has_no_traversal(&bytes)
}

fn decoded_path_has_no_traversal(bytes: &[u8]) -> bool {
    if bytes
        .iter()
        .any(|b| matches!(*b, 0 | b'\\' | b'\r' | b'\n' | b'\t'))
    {
        return false;
    }
    bytes
        .split(|b| *b == b'/')
        .all(|segment| segment != b"." && segment != b"..")
}

/// 从 JSON 响应体里提取 `usage` 字段（M13-S1）。
///
/// OpenAI 兼容的非流式响应：`{ "usage": { "prompt_tokens": 100, ... } }`。
/// 缺失或类型不对 → `None`。
fn extract_usage_from_json(body: &[u8]) -> Option<(i64, i64, i64)> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let usage = value.get("usage")?;
    let prompt = usage.get("prompt_tokens").and_then(|v| v.as_i64())?;
    let completion = usage.get("completion_tokens").and_then(|v| v.as_i64())?;
    let total = usage.get("total_tokens").and_then(|v| v.as_i64())?;
    Some((prompt, completion, total))
}

/// 一次**已命中上游**的元数据（M40-S1）：usage 归因所需的三项。
///
/// 单独成结构是为了让 `into_upstream_response` 的参数表保持在可读范围
/// （key/latency/attempts 是同一件事的三个面，一起传/一起忘）。
#[derive(Clone, Copy, Debug)]
pub(crate) struct AttemptMeta {
    /// 实际命中的上游 key（多站 = `Upstream.key_id`；legacy = `GatewayConfig.key_id`）。
    pub key_id: Option<i64>,
    /// send → 响应头（TTFB）。
    pub latency_ms: u64,
    /// 本次请求成功前的尝试次数（1 = 第一次就成功）。
    pub attempts: u32,
}

/// SSE carry 上限（M40-S1 §4.3）：单个未成行的片段最多 64 KiB；超限丢弃到下一个换行再继续。
pub(crate) const MAX_USAGE_CARRY_BYTES: usize = 64 * 1024;

/// 系统时钟（Unix 秒）——`UsageCapture` 的生产时钟实现。
///
/// 抽成函数是为了让 `UsageCapture::new` 能注入 `Arc<dyn Fn() -> i64>`：
/// 测试用固定/递增时钟可确定性地断言 `at`，不依赖墙上时间（M40-S1 §4.2）。
fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 一次响应的用量采集器（M40-S1）。
///
/// 职责：
/// 1. **SSE 跨 chunk 行缓冲**：chunk 边界与 SSE 事件边界无关，按 `\n` 拼行后再解析；
///    单行上限 [`MAX_USAGE_CARRY_BYTES`]，超限丢到下一个换行（防畸形流撑爆内存）。
/// 2. **幂等 flush**：正常结束 / 流错误 / 客户端断开（`Drop`）三路合计**恰好一次**，
///    由 `emitted: AtomicBool` 的 `swap(true)` 保证。
/// 3. 只把 [`GatewayUsage`] 交给 `sink`（内存 push，不做 IO、不 panic）。
pub(crate) struct UsageCapture {
    sink: Option<Arc<dyn Fn(GatewayUsage) + Send + Sync>>,
    /// 时钟注入：生产 = [`unix_now_secs`]；测试 = 固定/递增。
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
    site_id: i64,
    key_id: Option<i64>,
    /// M43-S1：认证身份（`None`/空 = legacy 单令牌，未归因）。
    token_id: Option<i64>,
    agent_label: String,
    model: String,
    status: u16,
    latency_ms: u64,
    attempts: u32,
    stream: bool,
    /// SSE 未成行的字节（不含已消费的完整行）。
    carry: Vec<u8>,
    /// 因超过 `MAX_USAGE_CARRY_BYTES` 进入「丢弃到下一个 \n」模式。
    discarding: bool,
    /// 已见到 `[DONE]`：之后不再解析任何 `data:` 行（仍允许 flush 已见的 `last_usage`）。
    done: bool,
    /// 最后一个含 usage 的 SSE 事件（后出现的覆盖前面的）。
    last_usage: Option<(i64, i64, i64)>,
    /// 非流式累积（受流层 `MAX_RESPONSE_BYTES` 约束）。
    body: Vec<u8>,
    /// 幂等闸：`swap(true)` 为 true 的那一次才真正 emit。
    emitted: std::sync::atomic::AtomicBool,
}

impl UsageCapture {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        sink: Option<Arc<dyn Fn(GatewayUsage) + Send + Sync>>,
        site_id: i64,
        key_id: Option<i64>,
        model: String,
        status: u16,
        latency_ms: u64,
        attempts: u32,
        stream: bool,
        now: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Self {
        Self {
            sink,
            now,
            site_id,
            key_id,
            token_id: None,
            agent_label: String::new(),
            model,
            status,
            latency_ms,
            attempts,
            stream,
            carry: Vec::new(),
            discarding: false,
            done: false,
            last_usage: None,
            body: Vec::new(),
            emitted: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// M43-S1：把认证身份挂到这次请求的用量上（`None` = legacy，未归因）。
    pub(crate) fn with_identity(mut self, token_id: Option<i64>, agent_label: String) -> Self {
        self.token_id = token_id;
        self.agent_label = agent_label;
        self
    }

    /// 每收到一个 chunk 调用一次：SSE 走行缓冲；非流式追加到 body。
    pub(crate) fn feed(&mut self, chunk: &[u8]) {
        if !self.stream {
            self.body.extend_from_slice(chunk);
            return;
        }
        self.carry.extend_from_slice(chunk);
        let mut start = 0usize;
        while let Some(rel) = self.carry[start..].iter().position(|b| *b == b'\n') {
            let end = start + rel;
            let line = String::from_utf8_lossy(&self.carry[start..end]).into_owned();
            start = end + 1;
            if self.discarding {
                // 超限后重同步：吃到第一个换行就恢复解析。
                self.discarding = false;
                continue;
            }
            if self.done {
                continue;
            }
            let line = line.strip_suffix('\r').unwrap_or(&line);
            let Some(rest) = line.strip_prefix("data:") else {
                continue;
            };
            let rest = rest.trim();
            if rest.is_empty() {
                continue;
            }
            if rest == "[DONE]" {
                self.done = true;
                continue;
            }
            if let Some(usage) = extract_usage_from_json(rest.as_bytes()) {
                // 后出现的覆盖前面的：OpenAI 兼容的 usage 在最后一个事件里。
                self.last_usage = Some(usage);
            }
        }
        if start > 0 {
            self.carry.drain(0..start);
        }
        if self.carry.len() > MAX_USAGE_CARRY_BYTES {
            // 不记日志、不落库：只丢数据并重同步。
            self.carry.clear();
            self.discarding = true;
        }
    }

    /// 幂等 flush：第一次调用（正常结束 / 流错误 / Drop）才 emit；之后是 no-op。
    pub(crate) fn flush(&mut self) {
        if self.emitted.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let usage = if self.stream {
            self.last_usage
        } else {
            extract_usage_from_json(&self.body)
        };
        let Some((prompt_tokens, completion_tokens, total_tokens)) = usage else {
            return;
        };
        if let Some(sink) = &self.sink {
            sink(GatewayUsage {
                at: (self.now)(),
                site_id: self.site_id,
                key_id: self.key_id,
                model: self.model.clone(),
                prompt_tokens,
                completion_tokens,
                total_tokens,
                status: self.status,
                latency_ms: self.latency_ms,
                attempts: self.attempts,
                stream: self.stream,
                token_id: self.token_id,
                agent_label: self.agent_label.clone(),
            });
        }
    }
}

impl Drop for UsageCapture {
    fn drop(&mut self) {
        // 客户端断开（响应体流被 drop）时走这里：把已经看到的 usage 补记上。
        self.flush();
    }
}

/// 判断响应是否为 SSE 流（`Content-Type: text/event-stream`）。
fn is_sse_response(resp: &reqwest::Response) -> bool {
    resp.headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/event-stream"))
        .unwrap_or(false)
}

/// 给上游字节流套一层**累计大小上限**：第 `limit + 1` 个字节让流以错误结束。
///
/// 单独抽出来是为了能直接测——不必真的让假上游吐 64 MiB。
fn cap_stream<S, E>(
    stream: S,
    limit: u64,
) -> impl futures_util::Stream<Item = std::result::Result<bytes::Bytes, std::io::Error>>
where
    S: futures_util::Stream<Item = std::result::Result<bytes::Bytes, E>> + Send + 'static,
    E: std::fmt::Display + 'static,
{
    futures_util::stream::try_unfold(
        (Box::pin(stream), 0u64),
        move |(mut stream, sent)| async move {
            match stream.try_next().await {
                Ok(None) => Ok(None),
                Ok(Some(chunk)) => {
                    let total = sent + chunk.len() as u64;
                    if total > limit {
                        return Err(std::io::Error::other(format!(
                            "上游响应体超过上限 {limit} 字节"
                        )));
                    }
                    Ok(Some((chunk, (stream, total))))
                }
                Err(e) => Err(std::io::Error::other(e.to_string())),
            }
        },
    )
}

/// 给上游字节流套一层**累计大小上限** + **chunk 收集**（M13-S1）。
///
/// 与 `cap_stream` 相同，但在流正常结束后把收集到的 chunk（最多最后 8 个）
/// 传给 `on_complete` 回调，用于提取 `usage`。
fn cap_stream_with_usage<S, E>(
    stream: S,
    limit: u64,
    capture: UsageCapture,
) -> impl futures_util::Stream<Item = std::result::Result<bytes::Bytes, std::io::Error>>
where
    S: futures_util::Stream<Item = std::result::Result<bytes::Bytes, E>> + Send + 'static,
    E: std::fmt::Display + 'static,
{
    // 正常结束 / 流错误两条路径显式 flush；流被客户端 drop（断开）时由
    // `UsageCapture::drop` 兜底。三条路径合计恰好一次（`emitted` 幂等闸）。
    futures_util::stream::try_unfold(
        (Box::pin(stream), 0u64, capture),
        move |(mut stream, sent, mut capture)| async move {
            match stream.try_next().await {
                Ok(None) => {
                    capture.flush();
                    Ok(None)
                }
                Ok(Some(chunk)) => {
                    let total = sent + chunk.len() as u64;
                    if total > limit {
                        capture.flush();
                        return Err(std::io::Error::other(format!(
                            "上游响应体超过上限 {limit} 字节"
                        )));
                    }
                    capture.feed(&chunk);
                    Ok(Some((chunk, (stream, total, capture))))
                }
                Err(e) => {
                    capture.flush();
                    Err(std::io::Error::other(e.to_string()))
                }
            }
        },
    )
}

/// M43-S1：认证集合里的一条（**只有 id 与 hash，装不下明文**）。
///
/// `grace_until` 是 M41-S2 的宽限期（运行态，不落库）：`None` = 立即失效。
/// `label` 是认证当时要带进用量归因的**快照**（每请求不再查库）。
#[derive(Clone, PartialEq, Eq)]
pub struct GatewayTokenEntry {
    pub id: i64,
    /// SHA-256(明文令牌) 的 64 位 hex（小写）。**明文永不入库**。
    pub token_hash: String,
    /// 归因标签快照（用户输入；展示前过 scrub）。
    pub label: String,
    /// M41-S2：宽限截止（运行态，不落库）。
    pub grace_until: Option<std::time::Instant>,
}

impl std::fmt::Debug for GatewayTokenEntry {
    /// 不打印 hash（它是凭据的等价物）。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayTokenEntry")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("grace_until", &self.grace_until)
            .finish_non_exhaustive()
    }
}

/// 认证结果：只有 id 与标签，**没有明文**。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthIdentity {
    /// `None` = 走的是 legacy 单令牌（未迁移 / 迁移未完成）。
    pub token_id: Option<i64>,
    /// 运行时从库里取（认证成功那一刻的快照）。
    pub label: Option<String>,
}

/// SHA-256(明文) 的 64 位小写 hex。令牌是**高熵随机串**，不需要慢哈希/加盐
/// （M43-S1 §4.1 的显式裁决：抗离线爆破的代价不该落在每请求的热路径上）。
pub fn sha256_hex(plaintext: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[derive(Clone)]
pub struct GatewayConfig {
    pub port: u16,
    /// M42-S1：请求体上限（字节）。`single_upstream` 用 [`DEFAULT_MAX_REQUEST_BYTES`]。
    pub max_request_bytes: usize,
    /// 本地令牌。**不是**站点密钥。
    pub token: String,
    /// 绑定的站点 id（M13-S1）：用于 token 用量出口的 `site_id`。
    /// `single_upstream` 默认 `0`（legacy 兼容）。
    pub site_id: i64,
    /// M40-S1：legacy 单上游路径使用的本地 key id（多站路由的 key 归因在 `Upstream.key_id`）。
    /// `single_upstream` 默认 `None`（行为与既有逐字相同）。
    pub key_id: Option<i64>,
    /// 转发目标（站点根，无尾斜杠）。`route` 为空时**只**用它。
    pub base_url: String,
    /// 站点密钥（从钥匙串取）。`route` 为空时**只**用它。
    ///
    /// `Zeroizing`：`GatewayConfig` 在每请求里被 clone（与 `keys_by_ref` 同一个理由）。
    /// M8-S1 章程 §3.5 第 13 行记的就是这里——`keys_by_ref` 那条路径已经是 `Zeroizing`，
    /// 而单上游这条还是裸 `String`，于是 `service.rs` 那一次 `.to_string()` 产生的副本
    /// 没有清零保护。M8-S4 收口：类型换成 `Zeroizing`，那个裸副本在类型上就不存在了。
    pub api_key: Zeroizing<String>,
    pub site_display_name: String,
    /// 多上游路由表（M7-S1）。**空表 ⇒ 转发行为与单上游时代逐字节相同**。
    pub route: RouteTable,
    /// 熔断策略（M7-S1）。熔断**状态**由 `start()` 建在 `AppState` 里（跨请求共享），
    /// 配置里只放策略——策略是纯数据、可 `Clone`，状态不是。
    pub breaker: BreakerPolicy,
    /// M39-S3 §4.1：参与加权轮转的候选数（`1` = 关掉负载均衡，回到确定性首选）。
    pub lb_top_n: usize,
    /// M46-S4：每请求最多尝试的候选数。`0` = 走全部候选（今天行为）；`>0` 则截断
    /// （只计实际发出去的上游尝试，本地保护拒绝的候选不计；见代理循环）。
    /// 下次启动网关生效（与 `lb_top_n` / `guard_policy` 同口径）。
    pub max_attempts: usize,
    /// M39-S3 §4.2：每站并发/限速策略。
    pub guard_policy: SiteGuardPolicy,
    /// `key_ref` → 明文。**仅进程内**；`Debug` 不打印（见下方手写 `Debug`）。
    ///
    /// 值是 [`Zeroizing<String>`]：`GatewayConfig` 在每请求里被 clone，
    /// 用 `Zeroizing` 让这些副本在 drop 时擦掉内存（M7-S1 章程 v1.1 的硬化要求）。
    pub keys_by_ref: HashMap<String, Zeroizing<String>>,
    /// 失败事件的出口。`None` = 不记（`single_upstream` 的默认 ⇒ 既有行为不变）。
    ///
    /// 用注入出口而不是直接依赖 `store`：网关不该为了记一条事件而拿到整个存储层。
    pub on_failure: Option<Arc<dyn Fn(GatewayFailure) + Send + Sync>>,
    /// 上游请求的两段超时（M8-S1 §3.5-2）。默认见 [`UpstreamTimeout::default`]。
    pub upstream_timeout: UpstreamTimeout,
    /// 共享的「已回收」视图（M8-S1 §3.5-5）：`key_ref` 命中 ⇒ 该上游**不再被选用**。
    ///
    /// `None` = 不做运行时校验（`single_upstream` 的默认 ⇒ 既有行为不变）。
    /// 为什么用共享集合而不是「网关自己去查」：`ensure_not_revoked` 建立的**唯一**取密钥路径
    /// 不能被绕过——网关不新开一条读路径，它只查一个由那条路径维护的集合。
    pub revoked_refs: Option<Arc<Mutex<std::collections::HashSet<String>>>>,
    /// 成功请求的 token 用量出口（M13-S1）。`None` = 不采集（`single_upstream` 默认）。
    /// 与 `on_failure` / `on_observation` 同形：注入出口，网关不直接依赖 store。
    pub on_usage: Option<Arc<dyn Fn(GatewayUsage) + Send + Sync>>,
    /// 每次上游尝试结束时的观测出口（M8-S1 §5.3）。`None` = 不采集。
    ///
    /// 与 `on_failure` 同形（注入出口），理由相同：网关不碰存储层。
    pub on_observation: Option<Arc<dyn Fn(UpstreamObservation) + Send + Sync>>,
    /// M46-S5：预算判定注入出口。`None` = 不拦（`single_upstream` 默认 ⇒ 既有行为不变）。
    ///
    /// 签名刻意只有 `(site_id, key_id)`：网关不把 store 类型推进请求路径，判定逻辑
    /// 活在 service 侧闭包里（读 `site_budgets` + 算已花）；网关只认返回的 breach。
    /// 闭包返回 `None` = 未超标（含「查询出错时 fail-open」，见 spec §4.2）。
    pub budget_check: Option<BudgetCheck>,
    /// M46-S5：超预算回调注入出口。网关只在循环里首次遇到某 breach 时调一次
    /// （同一请求内同一 breach 去重，见代理循环）；`None` = 不回调。
    pub on_budget_breach: Option<BudgetBreachSink>,
    /// 上游客户端走的代理（M10-S2）。`None` = 直连。
    ///
    /// 由 `service::gateway_config` 从 settings 解析后填入（与站点适配器 transport 同一份
    /// `proxy::resolve_proxy`）。网关每次 `start()` 都重读最新 settings，因此代理变更
    /// **重启网关即生效**（站点适配器 transport 仍需重启 app）。
    pub upstream_proxy: Option<String>,
    /// **legacy（空路由表）路径那把密钥的引用**（M16-S4 / P3-4）。
    ///
    /// 为什么需要它：legacy 路径只有 `api_key` 明文，没有引用 ⇒ 无法查 [`Self::revoked_refs`]
    /// （M8-S1 §12.4 的守卫只覆盖多上游路径）。填了之后 legacy 路径会拒绝使用已回收的密钥，
    /// 并把「为什么 / 怎么办」写进失败事件——这正是 P2-7（一键轮换后运行中的网关仍用旧密钥）
    /// 在网关侧的显式语义。
    ///
    /// `None` = 不校验（[`GatewayConfig::single_upstream`] 的默认 ⇒ 既有调用方行为逐字不变）。
    /// **由 `service.rs::gateway_config` 填充**（M16-S4 spec §12 W-3，道⑤/Lead 合并期打）。
    pub legacy_key_ref: Option<String>,
    /// **热更新句柄**（M39-S1）。`None` ⇒ 每个请求直接用本结构的 `route` / `keys_by_ref`
    /// （**与加这个字段之前逐字相同**：`single_upstream` 与所有既有测试都走这条）。
    ///
    /// `Some` ⇒ 请求在进入时**克隆一次**快照（[`RouteView`]），此后整条请求路径只读那份快照；
    /// `service.rs` 在模型目录变化时 `*runtime.write() = 新 Arc`，在途请求继续用它启动时
    /// 拿到的那一份，直到最后一个引用释放（换指针不撕裂）。
    ///
    /// 用 `std::sync::RwLock`（不是 tokio 的）：读侧只在**同步段**里 `read()` + `clone()` +
    /// 立刻放锁，**不跨 `await` 持锁**；写侧只做一次指针替换。
    pub runtime: Option<Arc<std::sync::RwLock<Arc<GatewaySnapshot>>>>,
}

/// 上游请求的两段超时。
///
/// **刻意不用 `reqwest::ClientBuilder::timeout`**：它的语义是「从开始连接直到 body 读完」的
/// **总 deadline**（依赖源码原文见 `docs/specs/M8-S1-路由数据源与跨站选路.md` §15 证据②），
/// 会把**合法的长流式补全**判成超时——而流式回传正是 `the_response_is_forwarded_as_a_stream_not_buffered`
/// 钉住的既有行为。
///
/// 用的是 `connect_timeout` + `read_timeout`：后者计的是「多久没有新字节」，成功读到就重置，
/// 它抓的是「接了连接却永远不回应」那种病态上游，不是「慢」。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UpstreamTimeout {
    /// 连接阶段（TCP + TLS）。
    pub connect: Duration,
    /// **每次读**的超时。
    pub read: Duration,
}

impl Default for UpstreamTimeout {
    fn default() -> Self {
        // connect 5s：覆盖 TCP+TLS 两段。真实站点实测（M9-S3 §3.2，NewAPI）：
        //   DNS   3.3–3.6 ms
        //   TCP   3.6–4.1 ms
        //   TLS  532–1145 ms   ← 主要成本
        //   TTFB 1.16–1.69 s（TLS 之后服务端另耗 0.6–1.1 s，不计入本段）
        // 上界约 1.15s，留约 4.3 倍余量。刻意取保守的一档而不是 2s：`connect_timeout`
        // 的代价只落在坏路径上（连接阶段真的卡死才等满它），正常站点 5s 远远够。
        //
        // read 240s：**M9-S5 用真实上游补全标定过**（B-124 关闭）。
        // 它的语义是「多久没有新字节」，抓的是「接了连接却永不回应」的病态上游，不是「慢」。
        //
        // 真实分布（M9-S5，两站充值后用 grok-4.7 / gpt-6-astra 实测）：
        //   - 流式 grok-4.7：首字节 ≤8.8s，字节间停顿最大 8.6s（推理间歇，有 SSE keepalive）。
        //   - 流式 gpt-6-astra：首字节 ≤14.6s（把推理全做完才吐第一个字节），字节间 ≤1.4s。
        //   - **非流式 gpt-6-astra 难题**：TTFB = 49/63/92/95/101s，另有 1 发 >120s（被 curl 砍）。
        // 非流式是 read 的真正约束——中转站等模型全做完才吐字节，合法「无字节期」观测最大
        // 100.7s、重尾 >120s。
        //
        // 240s = 2× 重尾(120s) = 约 2.4× 观测最大(100.7s)。刻意不取更小：
        //   - 风险不对称——偏低会**杀掉合法慢推理请求**（用户请求直接失败），
        //     偏高只是**卡死上游 failover 慢一点**（且卡死上游通常会先抛连接错，很少真等满）。
        //     前者比后者坏。
        //   - 180s（1.8× 观测最大）会把 >120s 重尾的合法请求判死。
        // 相对旧值 300s 砍掉 60s：failover 快 20%，仍在 2× 重尾之上。
        // 样本有限（非流式 6 发 / 流式 9 发），但取 2× 重尾而非 1.8× 观测最大，正是为了
        // 给未观测到的更慢推理留余量。证据 `docs/evidence/m9s5-read-timeout-calibration.md`。
        Self {
            connect: Duration::from_secs(5),
            read: Duration::from_secs(240),
        }
    }
}

/// M46-S4：分站超时解析（纯函数，与发送解耦）。
///
/// **替代，不是取 min**：分站值比全局大时全局不得提前掐断；分站值比全局小时
/// 分站值说了算。分站值同时作用于 connect 与 read 两维（见 `UpstreamTimeout` 的
/// 注释：没有 total 维，`RequestBuilder::timeout` 的总 deadline 语义会砍合法长流，
/// 故分站值绝不用它实现）。
///
/// `Some(0)` ≡ 未填：0 毫秒的超时永远不可能成功，把它当成配置值会直接 brick 掉
/// 该站点；且与本仓库「0 = 关/不限」的惯例一致。
pub fn effective_upstream_timeout(
    global: UpstreamTimeout,
    per_site_ms: Option<u64>,
) -> UpstreamTimeout {
    match per_site_ms {
        Some(ms) if ms > 0 => UpstreamTimeout {
            connect: Duration::from_millis(ms),
            read: Duration::from_millis(ms),
        },
        _ => global,
    }
}

/// 一次上游尝试的观测。**只有元数据**（不记请求 / 响应正文、不记密钥）。
///
/// 与 [`GatewayFailure`] 一样刻意保持字段极少：这是结构上的白名单。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamObservation {
    pub site_id: i64,
    /// 从「开始发这一次请求」到「拿到响应头」的毫秒数。**不含读 body**——
    /// 流式响应的 body 可能持续几分钟，算进去会让这个数失去比较意义。
    pub latency_ms: u64,
    pub ok: bool,
}

/// 一次网关请求的 token 用量（M13-S1）。恰好四个字段——结构上的白名单：
/// 装不下响应正文、密钥或本地令牌。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayUsage {
    /// 请求**完成**时刻（Unix 秒）。SSE：流结束或被客户端断开的那一刻；非流式：body 读完那一刻。
    /// 由 [`UsageCapture`] 构造时注入的时钟取值（生产 = 系统时钟；测试 = 固定/递增）。
    pub at: i64,
    pub site_id: i64,
    /// 本次请求**实际命中的上游**所用的本地 key 行（多站 = `Upstream.key_id`；legacy = `GatewayConfig.key_id`）。
    pub key_id: Option<i64>,
    /// 调用方自由文本，**脱敏在值被创造的地方完成**（与 `GatewayFailure.model` 同口径）。
    pub model: String,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
    /// 上游 HTTP 状态码（只有 2xx 才可能产生 usage）。
    pub status: u16,
    /// 从发起 send 到**收到响应头**的耗时（TTFB，首字节时间；不是总耗时）。
    pub latency_ms: u64,
    /// 本次请求成功前尝试过的上游次数（1 = 第一次就成功；失败切换后成功 = 命中的候选序号）。
    pub attempts: u32,
    /// 响应是否为 SSE。
    pub stream: bool,
    /// M43-S1：命中的令牌行 id；`None` = 走 legacy 单令牌（未迁移 / 迁移未完成）。
    pub token_id: Option<i64>,
    /// M43-S1：认证当时的 label 快照（`''` = 未归因）。
    pub agent_label: String,
}

/// 一次「因可切换状态而放弃当前上游」的元数据。
///
/// **恰好这三个字段**——这是结构上的白名单：装不下 prompt 正文、响应正文、
/// 密钥或本地令牌（FR-5:161 + FR-8 红线）。
///
/// `model` 是调用方自由文本，**脱敏在值被创造的地方完成**：即 [`report_failure`] 里
/// 先过一遍 [`crate::redact::scrub`]，再交给出口（M7-S1 复审 P1-1）。
///
/// 为什么不能把这个义务推给下游：出口是 `store.insert_event`，而它**原样入库**
/// （`store/mod.rs:706-721` 直接 `params![event.payload]`，不做任何脱敏）。
/// 「由出口负责」这个假设会让密钥形状的自由文本进事件表、再随导出与审计外流——
/// 与 B-75 是同一类咽喉。
/// M46-S5：预算周期（网关侧词汇；store 层只认同名字符串，见 store::budget_create）。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum BudgetPeriod {
    Day,
    Month,
}

impl BudgetPeriod {
    pub fn as_str(self) -> &'static str {
        match self {
            BudgetPeriod::Day => "day",
            BudgetPeriod::Month => "month",
        }
    }

    /// 解析周期名（`from_str` 之名会撞标准 trait 方法，clippy 会告警，故用 `parse`）。
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "day" => Some(BudgetPeriod::Day),
            "month" => Some(BudgetPeriod::Month),
            _ => None,
        }
    }
}

/// M46-S5：预算判定注入出口的类型（字段类型过长会触发 clippy type_complexity，
/// 故抽别名；`on_failure` 等回调同理只是本身较短）。
pub type BudgetCheck = Arc<dyn Fn(i64, Option<i64>) -> Option<BudgetBreach> + Send + Sync>;
/// M46-S5：超标回调注入出口的类型（同上，抽别名）。
pub type BudgetBreachSink = Arc<dyn Fn(BudgetBreach) + Send + Sync>;

/// M46-S5：一次预算超标事实（service 侧 `budget_check` 闭包构造，网关只认它）。
/// 不含任何密钥 / base_url / webhook 地址，可直接进事件与通知 payload。
#[derive(Clone, Debug, PartialEq)]
pub struct BudgetBreach {
    pub site_id: i64,
    /// 预算行的 key：`None` = 站级预算行超标；`Some(id)` = 该 key 的预算行超标。
    pub key_id: Option<i64>,
    pub period: BudgetPeriod,
    pub spent_usd: f64,
    pub limit_usd: f64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayFailure {
    pub site_id: i64,
    pub status: u16,
    pub model: String,
    /// P2-10 / P2-11（DEBUG-REPORT-v3 §2-10 / §2-11）：人话原因，让事件表能区分
    /// 「全部熔断」「缺明文」「已回收」三种 status=0，以及「传输层失败（超时 / 连不上）」
    /// 与「上游真回 502」两种 status=502。M7 冻结的三字段是结构白名单（装不下密钥），
    /// `reason` 是可显示的人话，不破坏白名单意图；调用方负责先 `scrub` 再传入。
    pub reason: String,
}

impl std::fmt::Debug for GatewayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 令牌与密钥都不打印。**新增字段刻意不进 field 列表**：
        // `keys_by_ref` 是明文密钥的 map，`on_failure` 是闭包（也没有有意义的 Debug 形态）。
        // `finish_non_exhaustive()` 会把未列出的字段显示成 `..`。
        f.debug_struct("GatewayConfig")
            .field("port", &self.port)
            .field("base_url", &self.base_url)
            .field("site_display_name", &self.site_display_name)
            .finish_non_exhaustive()
    }
}

impl GatewayConfig {
    /// 单一上游的构造器（M7-S0 引入）。
    ///
    /// 存在的理由：`service.rs` 是本文件**之外**的唯一生产构造点，而 M7-S1 会给本结构
    /// 增加多上游字段。只要构造走这个函数，S1 改字段就不会打断 `service.rs` 的编译——
    /// 「新增一个上游概念」不该要求改两个包的文件（同 M6-S0 §9.1 对 `relative_target` 的处置）。
    ///
    /// `service.rs::gateway_config` 的对外行为因此**逐字不变**：仍然是「一个站点、一把密钥」。
    /// 新字段一律取「空 / 默认 / 不记事件」，所以走这条构造器的调用方行为零变化。
    pub fn single_upstream(
        port: u16,
        token: String,
        base_url: String,
        api_key: Zeroizing<String>,
        site_display_name: String,
    ) -> Self {
        Self {
            port,
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            token,
            site_id: 0,
            key_id: None,
            base_url,
            api_key,
            site_display_name,
            route: RouteTable::default(),
            breaker: BreakerPolicy::default(),
            // M39-S3：单上游（legacy）路径保持 `top_n=1` 与默认 guard，
            // 行为与今天逐字相同（单候选不读轮转计数器）。
            lb_top_n: 1,
            // M46-S4：0 = 走全部候选；legacy 只有一个候选，预算恒不截断。
            max_attempts: 0,
            guard_policy: SiteGuardPolicy::default(),
            keys_by_ref: HashMap::new(),
            on_failure: None,
            upstream_timeout: UpstreamTimeout::default(),
            revoked_refs: None,
            on_observation: None,
            on_usage: None,
            // M46-S5：默认不拦、不回调（single_upstream 的调用方行为逐字不变；
            // 服务层的 gateway_config 在构造完再赋值）。
            budget_check: None,
            on_budget_breach: None,
            upstream_proxy: None,
            // P3-4：构造器不知道引用（签名逐字不变，M7-S0 §3.1 冻结）。
            // `None` ⇒ legacy 路径的已回收守卫不生效，行为与改动前逐字相同；
            // 服务层要启用它，就构造完再赋值（spec §12 W-3）。
            legacy_key_ref: None,
            // M39-S1：构造器不建热更新句柄（`None` ⇒ 请求直接用上面的 route / keys_by_ref，
            // 行为与加这个字段之前逐字相同）。服务层的 `gateway_config` 在构造完再赋值。
            runtime: None,
        }
    }
}

/// 一次「路由 + 密钥」的**不可变**快照（M39-S1）。
///
/// 为什么是不可变 + `Arc`：请求处理**每请求克隆一次** [`Arc<GatewaySnapshot>`] 就再也不碰锁，
/// 于是「热更新」只是换一个指针；在途请求继续用它启动时拿到的那一份，直到最后一个引用释放
/// （不会出现「一半请求按旧路由、一半按新路由读到同一个字段」的矛盾）。
///
/// **不含** `load_balance` / `guards`：那是 M39-S3 的字段，届时新增字段即可
/// （本结构的构造点只有 `service.rs` 与新测试，新增字段是源码兼容的变更）。
/// **不含** `aliases`：别名今天已经活在 [`RouteTable`] 里（`with_alias` / `resolve_model`），
/// 再拿一份等于把同一个事实存两处，必然分叉。
#[derive(Clone)]
pub struct GatewaySnapshot {
    /// 单调递增（同一运行态内）。首个快照 = 1；每次发布 +1。
    pub generation: u64,
    pub route: RouteTable,
    /// `key_ref` → 明文。与 [`GatewayConfig::keys_by_ref`] **同一类型**（`Zeroizing`），
    /// 这样请求路径的「取密钥」只有一种写法。
    pub keys_by_ref: HashMap<String, Zeroizing<String>>,
}

impl GatewaySnapshot {
    pub fn new(
        generation: u64,
        route: RouteTable,
        keys_by_ref: HashMap<String, Zeroizing<String>>,
    ) -> Self {
        Self {
            generation,
            route,
            keys_by_ref,
        }
    }
}

/// 手写 `Debug`：**不打印任何密钥**（与 `GatewayConfig` 同一条红线）。
impl std::fmt::Debug for GatewaySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewaySnapshot")
            .field("generation", &self.generation)
            .field("route_is_empty", &self.route.is_empty())
            .field("key_refs", &self.keys_by_ref.len())
            .finish()
    }
}

/// 一次请求看到的路由视图（M39-S1）：要么是静态配置（兼容路径），要么是一份快照。
///
/// 存在的理由：请求路径上有好几处要读 `route` / `keys_by_ref`；如果每处各写一次
/// 「有 runtime 就取快照、没有就用配置」，那一定会分叉（一半读新、一半读旧）。
/// 统一在这里取一次，之后只读 `view`。
pub enum RouteView<'a> {
    Static(&'a GatewayConfig),
    Snapshot(Arc<GatewaySnapshot>),
}

impl RouteView<'_> {
    pub fn route(&self) -> &RouteTable {
        match self {
            RouteView::Static(config) => &config.route,
            RouteView::Snapshot(snapshot) => &snapshot.route,
        }
    }

    pub fn keys(&self) -> &HashMap<String, Zeroizing<String>> {
        match self {
            RouteView::Static(config) => &config.keys_by_ref,
            RouteView::Snapshot(snapshot) => &snapshot.keys_by_ref,
        }
    }

    /// 静态路径返回 0（便于日志/测试区分「有没有热更新」）。
    pub fn generation(&self) -> u64 {
        match self {
            RouteView::Static(_) => 0,
            RouteView::Snapshot(snapshot) => snapshot.generation,
        }
    }
}

impl GatewayConfig {
    /// 取本请求的路由视图（M39-S1）：**克隆一次** `Arc` 就放锁，不跨 `await` 持锁。
    ///
    /// `runtime == None`（`single_upstream` / 既有测试）⇒ 借用静态配置，行为与今天逐字相同。
    /// 锁中毒时退回静态配置：可用性优先，而且「快照读不出来」不该让每个请求 500。
    pub fn view(&self) -> RouteView<'_> {
        match &self.runtime {
            Some(runtime) => match runtime.read() {
                Ok(guard) => RouteView::Snapshot(Arc::clone(&guard)),
                Err(_) => RouteView::Static(self),
            },
            None => RouteView::Static(self),
        }
    }
}

/// 网关任务结束的原因（M41-S1 §4.1.1）。只做**分类**，不含 payload / 不含上游信息。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayExitReason {
    /// 收到 `shutdown()` / `shutdown_and_wait()` 的停止信号，且任务正常结束。
    Requested,
    /// 服务任务 panic（`JoinError`）。
    Panicked,
    /// **没收到停止信号却正常结束**：任务自己返回了（最可疑的一类）。
    Unexpected,
}

impl GatewayExitReason {
    /// IPC DTO 用的稳定字符串：`requested` / `panicked` / `unexpected`。
    pub fn as_str(self) -> &'static str {
        match self {
            GatewayExitReason::Requested => "requested",
            GatewayExitReason::Panicked => "panicked",
            GatewayExitReason::Unexpected => "unexpected",
        }
    }
}

/// 任务结束记录（`alive() == false` 之后才有值）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatewayExit {
    /// 结束时刻（unix 秒，只用于展示）。
    pub at: i64,
    pub reason: GatewayExitReason,
}

/// 纯函数：`stop_requested` = 结束前是否收到过停止信号；`panicked` = 任务是否 panic。
///
/// 四格：`(true,false)=Requested`、`(true,true)=Panicked`、`(false,true)=Panicked`、
/// `(false,false)=Unexpected`。
pub fn classify_gateway_exit(stop_requested: bool, panicked: bool) -> GatewayExitReason {
    match (stop_requested, panicked) {
        (true, false) => GatewayExitReason::Requested,
        (_, true) => GatewayExitReason::Panicked,
        (false, false) => GatewayExitReason::Unexpected,
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 指标里的失败原因：**先剥掉 URL，再 scrub、截断**（M40-S2 复审 P1）。
///
/// `reqwest::Error` 的 Display 会带 `for url (https://站点域名/...)`；`redact::scrub`
/// 只掩 URL 里的 userinfo，不掩 host/path。`lastError` 会直接显示在网关卡片上，
/// 而 spec §6.2 的红线是「不含 URL/域名」。这里在指标入口做一次结构性剥离，
/// 不依赖调用方是否记得脱敏；事件路径不受影响（事件有自己的脱敏口径）。
fn sanitize_metric_error(reason: &str) -> String {
    let mut out = String::with_capacity(reason.len());
    let mut rest = reason;
    loop {
        let next = [rest.find("https://"), rest.find("http://")]
            .into_iter()
            .flatten()
            .min();
        let Some(start) = next else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..start]);
        out.push_str("<url>");
        let tail = &rest[start..];
        // URL 在 reqwest 的文案里通常以 `)` 收尾；空白、引号、逗号、分号、括号都算边界。
        let end = tail
            .find(|c: char| {
                c.is_whitespace() || matches!(c, ')' | ']' | '}' | ',' | ';' | '"' | '\'')
            })
            .unwrap_or(tail.len());
        rest = &tail[end..];
    }
    crate::redact::scrub(&out).chars().take(200).collect()
}

/// IPv6 降级原因的**结构化分类**（B-224 P2 修复）。
///
/// 分类必须在 v6 绑定失败的那一刻、按 `std::io::ErrorKind` 定下来，
/// 绝不能事后靠「原因文案里含不含『占用』」反推——OS 文案会随平台 /
/// 语言环境变化，反推一变就误分类。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6DegradedKind {
    /// v6 端口被占用。
    AddrInUse,
    /// v6 不可用（不支持 / 地址不可用等其他绑定失败）。
    Unavailable,
    /// port 0 测试路径：内核分配端口，主动跳过 v6。
    Skipped,
}

impl Ipv6DegradedKind {
    /// 事件 payload / 指标里用的稳定字符串（与任何 OS 文案无关）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Ipv6DegradedKind::AddrInUse => "addr_in_use",
            Ipv6DegradedKind::Unavailable => "unavailable",
            Ipv6DegradedKind::Skipped => "skipped",
        }
    }
}

/// IPv6 回环监听状态（M42-S1 §4.5）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ipv6State {
    /// `[::1]:port` 已监听。
    Listening,
    /// 未监听：`kind` 是结构化分类（调用方按它判，不解析文案）；
    /// `reason` 是**固定文案**，不含任何 OS 错误原文（事件表只留可判定事实）。
    Degraded {
        reason: String,
        kind: Ipv6DegradedKind,
    },
}

/// v6 绑定的测试注入模式（`#[doc(hidden)]`，只给集成测试用）。
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V6BindMode {
    /// 生产：真的绑 `[::1]:port`。
    Real,
    /// 测试：模拟一个指定 kind 的绑定错误（验证降级 / 端口占用两条路径）。
    Fail(std::io::ErrorKind),
}

// ============================================================ 内存指标（M40-S2）

/// 一个站点最近一次尝试的指标。**只有数字与已脱敏文本** —— 不含站点名 / 域名 / token / key_ref（红线）。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SiteMetrics {
    /// 打到这个站点的**尝试次数**（一次请求重放到两个站点 ⇒ 两边各 +1）。
    pub requests: u64,
    pub failovers: u64,
    /// 最近一次尝试的 TTFB（毫秒）。
    pub last_latency_ms: Option<u64>,
    /// M46-S2：成功请求的 TTFB 的 EWMA（毫秒，alpha 0.2）。
    /// `None` = 尚无成功样本（选路回退静态延迟；不是「实测 0ms」）。
    pub ewma_latency_ms: Option<f64>,
    pub last_status: Option<u16>,
    /// 已 `scrub` 且截断到 200 字符。
    pub last_error: Option<String>,
    pub last_error_at: Option<i64>,
}

/// 给 DTO / 测试用的冻结快照（不含原子类型与锁）。
#[derive(Debug, Clone, PartialEq)]
pub struct GatewayMetricsSnapshot {
    pub uptime_secs: u64,
    pub requests_total: u64,
    pub inflight: u64,
    pub by_status: std::collections::BTreeMap<u16, u64>,
    pub failovers_total: u64,
    /// 最近 60 秒的滑动 QPS；进程启动不足 3 秒时**恒为 0**（样本不足，见 M40-S2 §6.3）。
    pub qps: f64,
    pub per_site: std::collections::BTreeMap<i64, SiteMetrics>,
}

/// 60 个 1 秒槽的 QPS 环（真正的滑动窗口，M40-S2 P2-3 修复）。
#[derive(Debug)]
struct QpsRing {
    slots: [u64; 60],
    /// 样本窗口的起点：连续流量下**不重置**（只在空闲 ≥60s 后重置，见下）。
    started: Option<Instant>,
    /// 上次推进的时刻：槽位老化按「距上次推进」算，而不是「距起点」。
    last: Option<Instant>,
    current: usize,
}

impl Default for QpsRing {
    fn default() -> Self {
        Self {
            slots: [0; 60],
            started: None,
            last: None,
            current: 0,
        }
    }
}

impl QpsRing {
    /// 推进到 `now` 对应的槽（按 `Instant`，系统改墙钟不影响）。
    ///
    /// 此前实现按「距起点 elapsed」算目标槽，连续流量下每过 60s 就
    /// `elapsed / 60 > 0` ⇒ **整环清零**：QPS 在每分钟边界掉到 0，
    /// 所谓「滑动窗口」实际是翻滚窗口（M40-S2 复审 P2-3 属实）。
    /// 现在老化只清「上次推进以来经过的槽」：连续流量下每次推进
    /// 最多清 59 个槽，60s 前的旧槽逐个过期、新槽正常计入；
    /// 只有空闲 ≥60s（全部槽都已过期）时才整环清零并重置起点。
    fn advance(&mut self, now: Instant) {
        self.started.get_or_insert(now);
        let last = self.last.replace(now).unwrap_or(now);
        let elapsed = now.saturating_duration_since(last).as_secs() as usize;
        if elapsed >= 60 {
            self.slots = [0; 60];
            self.started = Some(now);
            return;
        }
        for _ in 0..elapsed {
            self.current = (self.current + 1) % 60;
            self.slots[self.current] = 0;
        }
    }
    fn bump(&mut self, now: Instant) {
        self.advance(now);
        self.slots[self.current] += 1;
    }
    fn qps(&self) -> f64 {
        self.qps_at(Instant::now())
    }
    /// 可注入时刻的版本（单测用真实 `Instant` 无法等 60s，故拆出来）。
    fn qps_at(&self, now: Instant) -> f64 {
        let sum: u64 = self.slots.iter().sum();
        let started = match self.started {
            Some(s) => s,
            None => return 0.0,
        };
        let uptime = now.saturating_duration_since(started).as_secs();
        if uptime < 3 {
            return 0.0;
        }
        sum as f64 / uptime.clamp(1, 60) as f64
    }
}

/// 网关实例的内存指标（M40-S2 §4.1）。
///
/// **红线**：只以 `site_id`（数字）为键；不含 token / key_ref / base_url / display_name。
/// **不写事件表**：本结构里没有任何 `log()` / 存储层调用。
#[derive(Debug)]
pub struct GatewayMetrics {
    started_at: Instant,
    requests_total: std::sync::atomic::AtomicU64,
    inflight: std::sync::atomic::AtomicI64,
    by_status: Mutex<std::collections::BTreeMap<u16, u64>>,
    failovers_total: std::sync::atomic::AtomicU64,
    per_site: Mutex<HashMap<i64, SiteMetrics>>,
    qps: Mutex<QpsRing>,
}

impl GatewayMetrics {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            started_at: Instant::now(),
            requests_total: std::sync::atomic::AtomicU64::new(0),
            inflight: std::sync::atomic::AtomicI64::new(0),
            by_status: Mutex::new(std::collections::BTreeMap::new()),
            failovers_total: std::sync::atomic::AtomicU64::new(0),
            per_site: Mutex::new(HashMap::new()),
            qps: Mutex::new(QpsRing::default()),
        })
    }

    fn on_request_started(self: &Arc<Self>) -> InflightGuard {
        self.requests_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inflight
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        InflightGuard {
            metrics: Arc::clone(self),
        }
    }

    fn on_request_finished(&self, status: u16) {
        if let Ok(mut map) = self.by_status.lock() {
            *map.entry(status).or_insert(0) += 1;
        }
        if let Ok(mut ring) = self.qps.lock() {
            ring.bump(Instant::now());
        }
    }

    /// 一次上游尝试（成功或失败都记）。`latency_ms` = TTFB。
    fn record_attempt(&self, site_id: i64, status: u16, latency_ms: u64) {
        if let Ok(mut map) = self.per_site.lock() {
            let e = map.entry(site_id).or_default();
            e.requests += 1;
            e.last_latency_ms = Some(latency_ms);
            e.last_status = Some(status);
        }
    }

    /// M46-S2：记一次成功请求的 TTFB 进 EWMA。**只由成功分支调用**——
    /// 失败路径（429 / 5xx / 传输失败）不调，失败不污染 EWMA。
    /// 锁中毒 ⇒ 跳过（可用性优先，与 `record_attempt` 同口径）。
    fn record_measured_latency(&self, site_id: i64, latency_ms: u64) {
        if let Ok(mut map) = self.per_site.lock() {
            let e = map.entry(site_id).or_default();
            e.ewma_latency_ms = Some(ewma_update(e.ewma_latency_ms, latency_ms));
        }
    }

    /// M46-S2：选路用的每站 EWMA 快照（只有 `Some` 的站进 map）。
    /// 锁中毒 ⇒ 空 map（选路退化为静态顺序）。
    fn ewma_latency_map(&self) -> std::collections::BTreeMap<i64, f64> {
        self.per_site
            .lock()
            .map(|map| {
                map.iter()
                    .filter_map(|(site_id, metrics)| metrics.ewma_latency_ms.map(|v| (*site_id, v)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 一次失败（原因先剥 URL，再 scrub + 截断；M40-S2 复审 P1）。
    ///
    /// **不加 `requests`**（B-224 P2 修复）：`requests` 的口径是「一次上游尝试」，
    /// 由 `record_attempt` 在尝试发生时记一次；失败路径若再 +1，一次失败尝试
    /// 会被计两遍。`record_failure` 只记失败元数据（状态 / 原因 / 时间），
    /// 未实际尝试的失败（熔断中、不可发送候选）因此也不虚增尝试数。
    fn record_failure(&self, site_id: i64, status: u16, reason: &str) {
        let cleaned = sanitize_metric_error(reason);
        if let Ok(mut map) = self.per_site.lock() {
            let e = map.entry(site_id).or_default();
            e.last_status = Some(status);
            e.last_error = Some(cleaned);
            e.last_error_at = Some(now_unix_secs());
        }
    }

    fn record_failover(&self, from_site_id: i64) {
        self.failovers_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut map) = self.per_site.lock() {
            map.entry(from_site_id).or_default().failovers += 1;
        }
    }

    fn snapshot(&self) -> GatewayMetricsSnapshot {
        let by_status = self.by_status.lock().map(|m| m.clone()).unwrap_or_default();
        let per_site = self.per_site.lock().map(|m| m.clone()).unwrap_or_default();
        let qps = self.qps.lock().map(|r| r.qps()).unwrap_or(0.0);
        GatewayMetricsSnapshot {
            uptime_secs: self.started_at.elapsed().as_secs(),
            requests_total: self
                .requests_total
                .load(std::sync::atomic::Ordering::Relaxed),
            inflight: self
                .inflight
                .load(std::sync::atomic::Ordering::SeqCst)
                .max(0) as u64,
            by_status: by_status.into_iter().collect(),
            failovers_total: self
                .failovers_total
                .load(std::sync::atomic::Ordering::Relaxed),
            qps,
            per_site: per_site.into_iter().collect(),
        }
    }
}

/// `inflight` 的 RAII guard：**panic 也会 dec**（M40-S2 §6.1）。
pub struct InflightGuard {
    metrics: Arc<GatewayMetrics>,
}
impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.metrics
            .inflight
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// 一个候选的**只读**视图（供 DTO 组装；health/breaker 都是字符串）。
#[derive(Debug, Clone, PartialEq)]
pub struct GatewayCandidateSnapshot {
    pub site_id: i64,
    pub key_id: Option<i64>,
    /// `healthy | unknown | exhausted`（只由 [`crate::routing::health_label`] 派生）
    pub health: &'static str,
    /// `closed | open | halfOpen`（只由 [`BreakerState`] 派生）
    pub breaker: &'static str,
}

pub struct GatewayHandle {
    pub addr: SocketAddr,
    /// M42-S1：实际监听的地址（v4 必有；v6 可能缺席）。
    pub addrs: Vec<SocketAddr>,
    /// M42-S1：IPv6 回环状态。
    pub ipv6: Ipv6State,
    pub token: String,
    pub site_display_name: String,
    /// M42-S1：两个 listener 共用一个停止信号（`oneshot` 只能 await 一次）。
    shutdown: tokio::sync::watch::Sender<bool>,
    /// 服务任务（v4 必有；v6 可能缺席）。`shutdown_and_wait` 等**全部**结束。
    finished: Vec<tokio::task::JoinHandle<()>>,
    /// 与 `AppState` 共享的「正在停止」标志（M16-S4 / P3-3）。
    stopping: Arc<std::sync::atomic::AtomicBool>,
    /// 任务结束记录（M41-S1）：任务体结束时回写，`alive()` 为假之后才可能有值。
    exit: Arc<std::sync::Mutex<Option<GatewayExit>>>,
    /// M40-S2：内存指标（与 `AppState` 共享同一个 Arc）。
    metrics: Arc<GatewayMetrics>,
    /// M40-S2：装配时的路由是否为空（`runtime` 为 `None` 时的 fallback）。
    initial_route_is_empty: bool,
    /// M39-S1 的运行时快照（热更新后会变）；`mode` 按它取**当前**真实路由。
    runtime: Option<Arc<std::sync::RwLock<Arc<GatewaySnapshot>>>>,
    /// M40-S2：候选列表要读熔断状态 ⇒ 与 `AppState` 共享同一个 `Breaker`。
    breaker: Arc<Mutex<Breaker>>,
    /// M40-S2：候选列表的来源（`runtime` 为 `None` 时用装配时的 route）。
    route: RouteTable,
    /// M40-S2：legacy 单上游的站点/密钥 id（`route` 为空时作为唯一候选）。
    legacy_site_id: i64,
    legacy_key_id: Option<i64>,

    /// M43-S1：认证集合的运行态句柄（与网关内部 `AppState` 共用同一份）。
    tokens: Arc<std::sync::RwLock<Vec<GatewayTokenEntry>>>,
}

impl std::fmt::Debug for GatewayHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayHandle")
            .field("addr", &self.addr)
            .field("site_display_name", &self.site_display_name)
            .finish_non_exhaustive()
    }
}

impl GatewayHandle {
    pub fn local_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.addr.port())
    }

    /// 服务任务是否还活着。**非阻塞**（`JoinHandle::is_finished`）。
    ///
    /// M41-S1：`gateway_status` 用这个而不是「`Option` 是不是 `Some`」——
    /// 一个已经 panic 的句柄绝不能继续被报成「运行中」。
    pub fn alive(&self) -> bool {
        self.finished.iter().any(|task| !task.is_finished())
    }

    /// M40-S2：一份当前指标快照。
    pub fn metrics(&self) -> GatewayMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// M40-S2：M39-S1 的运行时 generation（单上游 / 无 runtime ⇒ 0）。
    pub fn generation(&self) -> u64 {
        match &self.runtime {
            Some(rt) => match rt.read() {
                Ok(guard) => guard.generation,
                Err(_) => 0,
            },
            None => 0,
        }
    }

    /// M40-S2：`mode` 的**运行态**依据——`true` = 当前路由为空（走 legacy 单上游）。
    pub fn route_is_empty(&self) -> bool {
        match &self.runtime {
            Some(rt) => match rt.read() {
                Ok(guard) => guard.route.is_empty(),
                Err(_) => self.initial_route_is_empty,
            },
            None => self.initial_route_is_empty,
        }
    }

    /// M40-S2：候选列表（`health`/`breaker` 都从唯一出处派生；不含 display_name——那由壳层查 store）。
    pub fn candidates(&self) -> Vec<GatewayCandidateSnapshot> {
        let route = match &self.runtime {
            Some(rt) => match rt.read() {
                Ok(guard) => guard.route.clone(),
                Err(_) => self.route.clone(),
            },
            None => self.route.clone(),
        };
        let now = Instant::now();
        if route.is_empty() {
            // spec §6.4：**单上游 legacy ⇒ 恰好 1 条候选**（siteId/keyId 来自启动参数）。
            // health 无数据可依 ⇒ "unknown"（不编造「健康」）。
            return vec![GatewayCandidateSnapshot {
                site_id: self.legacy_site_id,
                key_id: self.legacy_key_id,
                health: "unknown",
                breaker: breaker_label(&self.breaker, self.legacy_site_id, now),
            }];
        }
        route
            .all_candidates()
            .into_iter()
            .map(|u| GatewayCandidateSnapshot {
                site_id: u.site_id,
                key_id: u.key_id,
                health: crate::routing::health_label(u.balance_usd),
                breaker: breaker_label(&self.breaker, u.site_id, now),
            })
            .collect()
    }

    /// 任务结束记录（还活着 ⇒ `None`）。
    pub fn last_exit(&self) -> Option<GatewayExit> {
        self.exit.lock().ok().and_then(|slot| *slot)
    }

    /// M43-S1：认证集合的运行态句柄——创建/吊销令牌**不重启网关**就生效。
    pub fn token_registry(&self) -> Arc<std::sync::RwLock<Vec<GatewayTokenEntry>>> {
        Arc::clone(&self.tokens)
    }

    /// M46-S1：把一站的巡检结论喂给运行中网关的 `Breaker`（与 `AppState`
    /// 共享的同一份，`eligible_candidates` 下一次选路即见效）。
    ///
    /// 锁中毒 ⇒ 静默丢弃：巡检结论丢了，下一轮还会再探；可用性优先，
    /// 不因此让巡检循环或网关请求失败。
    pub fn record_probe_outcome(
        &self,
        site_id: i64,
        models: &[String],
        verdict: crate::notify::KeyHealthVerdict,
        now: Instant,
    ) {
        if let Ok(mut guard) = self.breaker.lock() {
            crate::notify::apply_probe_outcome(&mut guard, site_id, models, verdict, now);
        }
    }

    /// M43-S1：把库里读出的集合播种进运行态（`start()` 之后由服务层调用）。
    pub fn set_tokens(&self, entries: Vec<GatewayTokenEntry>) {
        if let Ok(mut guard) = self.tokens.write() {
            *guard = entries;
        } else {
            // B-224 P3：此前锁中毒时静默保留旧集合、无任何日志——网关跑着
            // 旧令牌集，排障时没有任何线索。可用性仍优先（不因此停网关），
            // 但必须留下一行可查的记录。
            eprintln!("[tianshu-relay] 播种网关令牌集合失败：令牌锁已中毒，保留旧集合");
        }
    }

    /// 仅测试用：`shutdown_and_wait(self)` 会消费 token_registry 的克隆用于断言，
    /// 才能在停止之后断言 `last_exit`。
    #[cfg(test)]
    pub(crate) fn exit_slot(&self) -> Arc<std::sync::Mutex<Option<GatewayExit>>> {
        Arc::clone(&self.exit)
    }

    /// 停止网关并释放端口。幂等。
    ///
    /// **先置「正在停止」标志、再发信号**（M16-S4 / P3-3）：在途请求的下一次上游尝试
    /// 会看到标志并拒绝发起，不再把任何密钥发出去。
    pub fn shutdown(self) {
        self.stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = self.shutdown.send(true);
    }

    /// 停止网关并**等待监听套接字真正释放**。幂等。
    ///
    /// 「已释放」的判据是服务任务结束：axum 收到停止信号后先 break accept 循环、
    /// 立刻 `drop(listener)`，**然后**才等在途连接收尾（axum 0.8.9 `serve/mod.rs`）。
    /// 所以「任务结束」是「监听套接字已 drop」的充分条件（严格更强）。
    /// 这里**没有 sleep、没有轮询**——等的是任务本身。
    ///
    /// 幂等：服务已停时 oneshot 发送失败被忽略，已结束的 `JoinHandle` 立即返回；
    /// 任务 panic 时 `JoinError` 也被忽略。调用方不需要处理任何错误。
    ///
    /// 注意：在途连接会拖住这个 `await`（axum 先放掉端口、再等连接），但端口在
    /// 信号之后就已经能重新绑定了。
    pub async fn shutdown_and_wait(self) {
        let GatewayHandle {
            shutdown,
            finished,
            stopping,
            ..
        } = self;
        // P3-3：置位在信号之前——顺序反了的话，在途请求可能在这两步之间发起新尝试。
        stopping.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = shutdown.send(true);
        for task in finished {
            let _ = task.await;
        }
    }
}

/// 绑定 `127.0.0.1:port`，**只对 `AddrInUse` 退避重试**。
///
/// 首次尝试之外最多 [`BIND_RETRY_ATTEMPTS`] 次重试、每次间隔 [`BIND_RETRY_DELAY`]；
/// 其余错误（权限、地址不可用……）**一次**返回，不 sleep、不重试。
/// 重试耗尽后返回**最后一次**的错误（kind 仍是 `AddrInUse`），由调用方决定文案。
async fn bind_listener_with<F, Fut>(
    port: u16,
    mut bind: F,
) -> std::io::Result<tokio::net::TcpListener>
where
    F: FnMut(u16) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<tokio::net::TcpListener>>,
{
    let mut retries_left = BIND_RETRY_ATTEMPTS;
    loop {
        match bind(port).await {
            Ok(listener) => return Ok(listener),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && retries_left > 0 => {
                retries_left -= 1;
                tokio::time::sleep(BIND_RETRY_DELAY).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// 生产路径的绑定：**只绑 `127.0.0.1`**（地址写死，不接受任何参数）。
async fn bind_loopback(port: u16) -> std::io::Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(("127.0.0.1", port)).await
}

/// 绑 `[::1]:port`（M42-S1）。
///
/// 绑定的是**具体**的 `::1` 而不是通配 `::`：具体的 v6 地址天生不会接管 v4 的回环
/// （`IPV6_V6ONLY` 只对 `::` 有意义，tokio 的 `TcpSocket` 也没有暴露该开关），
/// 所以这里不需要额外的 only_v6 设置——语义与 spec §4.5 一致（不吞 v4）。
async fn bind_ipv6(port: u16) -> std::io::Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(("::1", port)).await
}

/// v6 失败一律降级（M42-S1 §4.5 / Lead 裁决 2）：**IPv6 永远不阻断 v4**。
///
/// 分类与文案都在此处一次定死：`kind` 按 `ErrorKind` 分，`reason` 用固定
/// 文案——**不把 `{error}` 的 OS 原文塞进 reason**（B-224 P2 修复；此前
/// 非占用分支的 reason 带 OS 原文，事件 message 因此与「不放原文」的
/// 注释自述矛盾，且调用方只能靠中文子串反推 kind）。
fn classify_ipv6_error(error: &std::io::Error) -> Ipv6State {
    if error.kind() == std::io::ErrorKind::AddrInUse {
        Ipv6State::Degraded {
            reason: "IPv6 回环端口被占用，仅监听 127.0.0.1".to_string(),
            kind: Ipv6DegradedKind::AddrInUse,
        }
    } else {
        Ipv6State::Degraded {
            reason: "IPv6 回环不可用，仅监听 127.0.0.1".to_string(),
            kind: Ipv6DegradedKind::Unavailable,
        }
    }
}

/// bind 失败的错误文案。
///
/// `AddrInUse` 单独一条：既要说清「端口 + 占用 + 实际端口号」，也要点明
/// 「可能是上一次网关还没释放」——旧文案写「端口可能被占用」，在 B-64 那个场景里
/// （旧实例其实已经被停掉）会把用户引向别的程序。
fn bind_error_message(port: u16, e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::AddrInUse {
        format!(
            "无法在 127.0.0.1:{port} 上启动网关：端口 {port} 被占用（可能是上一次网关尚未释放；\
             已重试 {BIND_RETRY_ATTEMPTS} 次、每次 {}ms 仍失败）: {e}",
            BIND_RETRY_DELAY.as_millis()
        )
    } else {
        format!("无法在 127.0.0.1:{port} 上启动网关: {e}")
    }
}

/// M46-S4：建一个上游客户端（全局主客户端与分站懒建客户端共用）。
///
/// 超时写在 `build()` 时：connect + read 两维，不用 `ClientBuilder::timeout`
///（总 deadline 会砍合法长流，见 `UpstreamTimeout` 的注释）。
/// 代理校验复用 `proxy::validate_proxy_url`——非法代理在这里就 Err，不静默直连（M10-S2）。
fn build_upstream_client(
    timeout: UpstreamTimeout,
    proxy_url: Option<&str>,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(timeout.connect)
        .read_timeout(timeout.read);
    if let Some(proxy_url) = proxy_url {
        crate::proxy::validate_proxy_url(proxy_url)?;
        let proxy = reqwest::Proxy::all(proxy_url.to_string()).map_err(|e| {
            Error::Transport(format!(
                "网关上游代理配置无效（{}），拒绝静默直连: {e}",
                crate::proxy::mask_proxy(proxy_url)
            ))
        })?;
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|e| Error::Transport(format!("构造网关的上游客户端失败: {e}")))
}

/// M46-S4：按生效超时取客户端。生效超时 == 全局超时 ⇒ 共享主客户端（今天路径）；
/// 否则按超时值缓存一个分站客户端（同值复用，不随请求膨胀）。
/// 懒建失败 ⇒ 回退共享客户端（只可能因非法代理失败，而代理在 `start()` 时已校验；
/// 回退时生效的是全局超时，与「没配分站值」一致，不产生新语义）。
fn client_for_timeout(state: &AppState, timeout: UpstreamTimeout) -> reqwest::Client {
    if timeout == state.config.upstream_timeout {
        return state.upstream.clone();
    }
    if let Ok(mut cache) = state.upstream_by_timeout.lock() {
        if let Some(client) = cache.get(&timeout) {
            return client.clone();
        }
        if let Ok(client) = build_upstream_client(timeout, state.config.upstream_proxy.as_deref()) {
            cache.insert(timeout, client.clone());
            return client;
        }
    }
    state.upstream.clone()
}

/// 启动网关（M42-S1：v4 必绑；v6 `[::1]` 同端口，失败降级）。
pub async fn start(config: GatewayConfig) -> Result<GatewayHandle> {
    start_with_v6(config, V6BindMode::Real).await
}

/// 启动网关（可注入 v6 绑定行为的测试入口；生产走 [`start`]）。
#[doc(hidden)]
pub async fn start_with_v6(config: GatewayConfig, v6_mode: V6BindMode) -> Result<GatewayHandle> {
    // 单上游（`route` 为空）时 `base_url` 是**唯一**的转发目标，必须非空——与既有行为一致。
    // 路由非空时 `base_url` 不再被使用（每个上游自带 `base_url`），因此不再强制。
    if config.route.is_empty() && config.base_url.trim().is_empty() {
        return Err(Error::Store("网关的上游地址为空".into()));
    }
    if config.token.trim().is_empty() {
        return Err(Error::Store("网关的本地令牌为空".into()));
    }
    // P3-9 / M8-S1 §10 第 3 条（W3 的集合不变式）：`route` 里的每个 `key_ref`
    // 都必须能落到一把**可用**的明文上——在 `keys_by_ref` 里，或者被显式标记为已回收
    // （已回收是合法状态：那正是「不再使用它」的表达）。
    //
    // 为什么放在 `start()` 而不是构造方：构造点不止一处（`single_upstream`、服务层的
    // `build_gateway_route`、测试、将来的调用方），把守卫放在**所有构造点的下游**才不会漏。
    // 不满足时的症状本来是「每个上游都跳过 → 502」，根因（忘填密钥映射）看不见。
    //
    // 文案**不打印 `key_ref` 原文**：引用本身是线索（M7-S0 §4.3 的红线），只说数量。
    {
        let revoked_set: std::collections::HashSet<String> = config
            .revoked_refs
            .as_ref()
            .and_then(|refs| refs.lock().ok().map(|set| set.clone()))
            .unwrap_or_default();
        // M39-S1：同一条不变式要覆盖**两套**路由——静态配置（兼容路径）与运行时快照
        // （热更新路径）。发布路径是本步新写的，若是它构造出「路由引用了不存在的明文」，
        // 症状与 M7 审计 D-2 一模一样（每个上游静默跳过 → 502），所以守卫放在 `start()`。
        let check = |label: &str,
                     route: &RouteTable,
                     keys: &HashMap<String, Zeroizing<String>>|
         -> Result<()> {
            let missing: Vec<&str> = route
                .key_refs()
                .into_iter()
                .filter(|r| !keys.contains_key(*r) && !revoked_set.contains(*r))
                .collect();
            if missing.is_empty() {
                return Ok(());
            }
            Err(Error::Store(format!(
                "网关启动被拒绝：{label}里有 {} 个上游的密钥既不在 keys_by_ref 里、\
                 也没有被标记为已回收——构造方忘了填密钥映射（在第一个请求上会表现成 502）",
                missing.len()
            )))
        };
        check("路由表", &config.route, &config.keys_by_ref)?;
        if let Some(runtime) = &config.runtime {
            if let Ok(guard) = runtime.read() {
                let snapshot = Arc::clone(&guard);
                drop(guard);
                check("运行时快照", &snapshot.route, &snapshot.keys_by_ref)?;
            }
        }
    }

    // §3.5-2：上游**必须**有超时。没有它，一个接了连接却不回应的上游会让请求永远挂着，
    // 既不切下一个候选，也不喂熔断（实测：卡 8.5s、下一个上游收到 0 次、失败事件 0 条）。
    // M46-S4：主客户端仍用全局超时建；分站客户端由 `client_for_timeout` 懒建，
    // 与这里共用同一个构造器（两处各写一份 builder 正是分叉的来源）。
    let upstream =
        build_upstream_client(config.upstream_timeout, config.upstream_proxy.as_deref())?;

    // P3-3：停止闸门。`AppState` 与 `GatewayHandle` 共享同一个标志——
    // 句柄置位（停止信号发出之前），请求路径读取。
    let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let metrics = GatewayMetrics::new();
    let breaker = Arc::new(Mutex::new(Breaker::new(config.breaker.clone())));
    let runtime_for_handle = config.runtime.clone();
    let route_for_handle = config.route.clone();
    let initial_route_is_empty = config.route.is_empty();

    // M43-S1：认证集合的共享句柄（handle 与 AppState 共用同一份）。
    let tokens: Arc<std::sync::RwLock<Vec<GatewayTokenEntry>>> =
        Arc::new(std::sync::RwLock::new(Vec::new()));
    let state = AppState {
        metrics: Arc::clone(&metrics),
        breaker: Arc::clone(&breaker),
        round_robin: Arc::new(Mutex::new(RoundRobinState::default())),
        guards: Arc::new(Mutex::new(HashMap::new())),
        local_rejects: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        config: config.clone(),
        upstream,
        // M46-S4：分站客户端缓存（空起步；生效超时 ≠ 全局时才懒建）。
        upstream_by_timeout: Arc::new(Mutex::new(HashMap::new())),
        stopping: Arc::clone(&stopping),
        // M43-S1：认证集合的运行态副本（创建/吊销**立即生效**，不重启网关）。
        // `start()` 从空集合起步（legacy 回退）；服务层随后用 `handle.set_tokens()` 播种。
        tokens: Arc::clone(&tokens),
    };
    let app = Router::new()
        .route("/health", any(health))
        .fallback(any(proxy))
        .with_state(state);

    // 只绑回环：这里写死，不接受任何参数。
    // bind 失败**只对 AddrInUse 退避重试**：调用方是「先停旧、再绑新」，而优雅停机是
    // 异步的，旧监听套接字可能还没被 drop（B-64 / M4-S2 复审 P2-7）。
    let listener = bind_listener_with(config.port, bind_loopback)
        .await
        .map_err(|e| Error::Store(bind_error_message(config.port, &e)))?;
    let addr = listener
        .local_addr()
        .map_err(|e| Error::Store(format!("读取网关地址失败: {e}")))?;
    if !addr.ip().is_loopback() {
        return Err(Error::Store(format!(
            "网关绑定到了非回环地址 {addr}，拒绝启动"
        )));
    }
    let port = addr.port();

    // M42-S1 §4.5：同端口再绑 `[::1]`。**任何 v6 失败都降级**（Lead 裁决 2）——
    // v4 已经是可用的，IPv6 只是兼容性增强，不能让它阻断启动。
    // 判**请求的**端口（`config.port`），不是内核分配出来的那个：
    // `port 0` 的语义是「测试路径不绑 v6」，而 `addr.port()` 此时已经是一个真实端口（永不为 0）。
    let (v6_listener, ipv6) = if config.port == 0 {
        (
            None,
            Ipv6State::Degraded {
                reason: "端口 0 由内核分配，跳过 IPv6 监听（仅测试路径）".to_string(),
                kind: Ipv6DegradedKind::Skipped,
            },
        )
    } else {
        match v6_mode {
            V6BindMode::Fail(kind) => (None, classify_ipv6_error(&std::io::Error::from(kind))),
            V6BindMode::Real => match bind_listener_with(port, bind_ipv6).await {
                Ok(listener6) => {
                    let addr6 = listener6
                        .local_addr()
                        .map_err(|e| Error::Store(format!("读取网关 IPv6 地址失败: {e}")))?;
                    if !addr6.ip().is_loopback() {
                        return Err(Error::Store(format!(
                            "网关 IPv6 绑定到了非回环地址 {addr6}，拒绝启动"
                        )));
                    }
                    (Some(listener6), Ipv6State::Listening)
                }
                Err(error) => (None, classify_ipv6_error(&error)),
            },
        }
    };
    let mut addrs = vec![addr];
    if let Some(listener6) = &v6_listener {
        if let Ok(addr6) = listener6.local_addr() {
            addrs.push(addr6);
        }
    }

    // M42-S1：两个 listener 共用一个停止信号（`oneshot` 只能 await 一次 ⇒ 改 `watch`）。
    let (tx, rx) = tokio::sync::watch::channel(false);
    let exit: Arc<std::sync::Mutex<Option<GatewayExit>>> = Arc::new(std::sync::Mutex::new(None));
    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // v4 是**主任务**：`GatewayExit` 由它记录（M41-S1 的 alive/last_exit 语义不变）。
    {
        let app_v4 = app.clone();
        let mut rx_v4 = rx.clone();
        let stopping_for_task = Arc::clone(&stopping);
        let exit_for_task = Arc::clone(&exit);
        tasks.push(tokio::spawn(async move {
            let served = tokio::spawn(async move {
                let _ = axum::serve(listener, app_v4)
                    .with_graceful_shutdown(async move {
                        let _ = rx_v4.changed().await;
                    })
                    .await;
            })
            .await;
            let reason = classify_gateway_exit(
                stopping_for_task.load(std::sync::atomic::Ordering::SeqCst),
                served.is_err(),
            );
            if let Ok(mut slot) = exit_for_task.lock() {
                *slot = Some(GatewayExit {
                    at: now_secs(),
                    reason,
                });
            }
        }));
    }

    // v6 是**尽力而为**：失败已在上面的绑定段降级，这里只负责跑起来与一起停。
    if let Some(listener6) = v6_listener {
        let app_v6 = app;
        let mut rx_v6 = rx.clone();
        tasks.push(tokio::spawn(async move {
            let _ = axum::serve(listener6, app_v6)
                .with_graceful_shutdown(async move {
                    let _ = rx_v6.changed().await;
                })
                .await;
        }));
    }

    Ok(GatewayHandle {
        addr,
        addrs,
        ipv6,
        token: config.token,
        site_display_name: config.site_display_name,
        shutdown: tx,
        finished: tasks,
        stopping,
        exit,
        metrics,
        initial_route_is_empty,
        runtime: runtime_for_handle,
        breaker,
        route: route_for_handle,
        legacy_site_id: config.site_id,
        legacy_key_id: config.key_id,

        tokens,
    })
}

#[derive(Clone)]
struct AppState {
    /// M40-S2：内存指标（与 `GatewayHandle` 共享同一个 Arc）。
    metrics: Arc<GatewayMetrics>,
    config: GatewayConfig,
    /// M43-S1：运行态认证集合。`tokens` 非空 ⇒ 只认集合（hash + 常量时间 + grace）；
    /// 空 ⇒ 回退 `config.token`（legacy 单令牌，行为与今天逐字相同）。
    tokens: Arc<std::sync::RwLock<Vec<GatewayTokenEntry>>>,
    upstream: reqwest::Client,
    /// M46-S4：按生效超时缓存的分站客户端（键 = 生效超时值本身，同值复用）。
    /// 共享主客户端（`upstream`）不在这里——生效超时 == 全局时直接用它。
    upstream_by_timeout: Arc<Mutex<HashMap<UpstreamTimeout, reqwest::Client>>>,
    /// M39-S3 §4.1：加权轮转计数器（跨请求共享；单候选时不读）。
    round_robin: Arc<Mutex<RoundRobinState>>,
    /// M39-S3 §4.2：每站 guard（信号量 + 令牌桶），按 `site_id` 索引。
    guards: Arc<Mutex<HashMap<i64, Arc<SiteGuard>>>>,
    /// 本地拒绝计数（不写事件，只做可观测兜底）。
    local_rejects: Arc<std::sync::atomic::AtomicU64>,
    /// 熔断**状态**：跨请求共享，所以是 `Arc<Mutex<_>>`。
    ///
    /// 不能放进 `config`：axum 的 `State` 每个请求 clone 一份，
    /// 裸值会变成「每个请求各有一份熔断历史」——熔断永远不生效。
    breaker: Arc<Mutex<Breaker>>,
    /// **正在停止**（M16-S4 / P3-3）：`shutdown()` / `shutdown_and_wait()` 在发出停止
    /// 信号**之前**置位；在途请求的下一次上游尝试看到它就不再发（不再带出任何密钥）。
    ///
    /// 为什么需要：axum 的优雅停机只保证「不再 accept 新连接 + 等连接收尾」——
    /// 已经进来的请求会继续跑完，包括**继续重放**到下一个上游。
    /// 用户按下停止（往往紧接着就要轮换/回收密钥）时，不该还有请求把密钥发出去。
    stopping: Arc<std::sync::atomic::AtomicBool>,
}

/// 取出请求里的本地令牌。支持 `Authorization: Bearer`、`X-Tianshu-Relay-Token`，
/// 以及旧版 `X-KeyRelay-Token`（兼容一个版本，避免已投递的本地网关客户端升级后 401）。
fn presented_token(headers: &HeaderMap) -> Option<String> {
    for name in ["x-tianshu-relay-token", "x-keyrelay-token"] {
        if let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) {
            // P3-6：两个令牌头都要 trim（与 Bearer 路径同口径）。
            return Some(value.trim().to_string());
        }
    }
    let auth = headers.get("authorization")?.to_str().ok()?;
    // P3-6：Bearer scheme 大小写不敏感（RFC 7235 scheme 是 case-insensitive），
    // 不只认 "Bearer"/"bearer" 两种。
    let (scheme, rest) = auth.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    Some(rest.trim().to_string())
}

/// P3-6：恒定时间比较令牌。`==` / `!=` 在第一个不匹配字节就提前返回，理论上能
/// 计时侧信道泄漏令牌前缀。本地令牌长期有效，值得用恒定时间比较：异或累积差异，
/// 最后判零。
///
/// 复审 F3：循环到 `max(len)` 并把超界字节按 0 处理——原实现只到 `min(len)`，
/// 长度不等时循环次数随较短方变化，可借计时推断「提交长度是否 ≤ 真实令牌长度」。
/// 改后循环次数恒为 `max(len)`，长度差异仍由预置的 `diff` 位捕获，只泄漏长度上限
/// （长度本身不是秘密，令牌内容才是）。
fn constant_time_eq(a: Option<&str>, b: &str) -> bool {
    match a {
        Some(a) => {
            let a = a.as_bytes();
            let b = b.as_bytes();
            let max = a.len().max(b.len());
            let mut diff: u8 = (a.len() != b.len()) as u8;
            for i in 0..max {
                let x = *a.get(i).unwrap_or(&0);
                let y = *b.get(i).unwrap_or(&0);
                diff |= x ^ y;
            }
            diff == 0
        }
        None => false,
    }
}

// ============================================================ M42-S1：本地错误信封

/// OpenAI 兼容的本地错误对象（M42-S1 §4.1）。**只用于网关自己生成的错误**；
/// 上游的响应体逐字节透传，不进这里。
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct GatewayErrorBody {
    pub message: String,
    /// `invalid_request_error` | `authentication_error` | `rate_limit_error` | `api_error`
    pub r#type: &'static str,
    /// 恒为 `None`（OpenAI 用它在字段级错误上指字段名；本地错误没有字段可指）。
    pub param: Option<String>,
    pub code: &'static str,
}

/// 线格式：`{"error": {message, type, param, code}}`。
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct GatewayErrorResponse {
    pub error: GatewayErrorBody,
}

/// 错误类型（决定 `type` 字段）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayErrorKind {
    InvalidRequest,
    Authentication,
    RateLimit,
    Api,
}

impl GatewayErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            GatewayErrorKind::InvalidRequest => "invalid_request_error",
            GatewayErrorKind::Authentication => "authentication_error",
            GatewayErrorKind::RateLimit => "rate_limit_error",
            GatewayErrorKind::Api => "api_error",
        }
    }
}

/// **全文件唯一**构造本地错误响应的地方（M42-S1 §4.1）。
///
/// 新增本地错误必须走这里；`rg 'json!\(\{\s*"error"\s*:\s*"' gateway.rs` 应为 0 命中。
pub(crate) fn local_error(
    status: StatusCode,
    kind: GatewayErrorKind,
    code: &'static str,
    message: impl Into<String>,
) -> Response {
    let body = GatewayErrorResponse {
        error: GatewayErrorBody {
            message: message.into(),
            r#type: kind.as_str(),
            param: None,
            code,
        },
    };
    (status, axum::Json(body)).into_response()
}

/// 本地 401（保留函数名，调用点不变；M42-S1 起走统一信封）。
fn unauthorized(message: &str) -> Response {
    local_error(
        StatusCode::UNAUTHORIZED,
        GatewayErrorKind::Authentication,
        "invalid_api_key",
        message,
    )
}

/// 网关**正在停止**时对「新的上游尝试」的统一拒绝（M16-S4 / P3-3）。
///
/// 为什么不是 502：这不是上游故障，是本地状态——文案必须说清，
/// 否则用户会去查一个没问题的上游。为什么是 503：请求此刻确实无法完成，
/// 但**重启网关后重试即可**（客户端按 5xx 处理即可）。
fn stopping_response() -> Response {
    local_error(
        StatusCode::SERVICE_UNAVAILABLE,
        GatewayErrorKind::Api,
        "gateway_stopping",
        "网关正在停止，不再向上游发起新请求；请重启网关后重试",
    )
}

/// 网关是否正在停止（P3-3）。
fn is_stopping(state: &AppState) -> bool {
    state.stopping.load(std::sync::atomic::Ordering::SeqCst)
}

/// M43-S1：认证入口——`/health` 与 `/proxy` **共用**（T3b）。
///
/// 顺序（逐字，见 spec §4.3）：
/// 1. 取 presented token（两种头 + 旧版头，trim + scheme 大小写不敏感）；取不到 ⇒ None；
/// 2. 与**运行态集合**逐条 `constant_time_eq`（**不早退**——不泄露命中的是第几条）；
///    `grace_until` 已过 ⇒ 该条不参与匹配；
/// 3. 集合为空 ⇒ 与 `config.token` 常量时间比较（legacy 回退，行为与今天逐字相同）；
/// 4. 其余 ⇒ None（401）。
fn authenticate(headers: &HeaderMap, state: &AppState) -> Option<AuthIdentity> {
    let presented = presented_token(headers)?;
    let presented_hash = sha256_hex(&presented);
    let entries = match state.tokens.read() {
        Ok(guard) => guard.clone(),
        Err(_) => {
            // 读锁中毒 ⇒ fail-closed（不放行），不 panic。
            return None;
        }
    };
    if !entries.is_empty() {
        let now = std::time::Instant::now();
        let mut matched: Option<AuthIdentity> = None;
        for entry in &entries {
            if let Some(deadline) = entry.grace_until {
                if now > deadline {
                    continue; // 宽限到期：等价于已失效
                }
            }
            if constant_time_eq(Some(presented_hash.as_str()), &entry.token_hash) {
                matched = Some(AuthIdentity {
                    token_id: Some(entry.id),
                    label: Some(entry.label.clone()),
                });
            }
            // **不早退**：走完整个集合（响应时间不泄露「命中的是第几条」）。
        }
        return matched;
    }
    // 集合为空 ⇒ legacy 单令牌回退。
    if constant_time_eq(Some(presented.as_str()), state.config.token.as_str()) {
        Some(AuthIdentity {
            token_id: None,
            label: None,
        })
    } else {
        None
    }
}

async fn health(State(state): State<AppState>, headers: HeaderMap) -> Response {
    // M43-S1：与 `proxy` 共用 `authenticate()`（同一口径，T3b 钉住）。
    if authenticate(&headers, &state).is_none() {
        return unauthorized("缺少或错误的本地令牌");
    }
    axum::Json(serde_json::json!({
        "ok": true,
        "site": state.config.site_display_name,
        "version": env!("CARGO_PKG_VERSION"),
    }))
    .into_response()
}

/// M39-S2：`GET /v1/models` 的本地聚合响应（标准 OpenAI list 形状）。
///
/// **只有** `id` / `object` / `created` / `owned_by` 四个键：
/// 不含站点 id、域名、显示名、倍率、余额、`key_ref`（安全红线，逐键断言在
/// `tests/gateway_models.rs::models_payload_has_only_id_object_created_owned_by`）。
/// `created: 0` = 未知（本产品不掌握模型的真实创建时间，**不编**时间戳）。
/// 不写事件、不打日志：模型目录不该成为可观测的拓扑面。
fn models_list_response(models: &[String]) -> axum::response::Response {
    let data: Vec<serde_json::Value> = models
        .iter()
        .map(|id| {
            serde_json::json!({
                "id": id,
                "object": "model",
                "created": 0,
                "owned_by": "tianshu-relay",
            })
        })
        .collect();
    axum::Json(serde_json::json!({ "object": "list", "data": data })).into_response()
}

async fn proxy(State(state): State<AppState>, request: Request) -> Response {
    // M40-S2：全局计数与「在途」在这里进出（status 取**最终返回给客户端**的那个）。
    let _inflight = state.metrics.on_request_started();
    let response = proxy_inner(State(state.clone()), request).await;
    state
        .metrics
        .on_request_finished(response.status().as_u16());
    response
}

async fn proxy_inner(State(state): State<AppState>, request: Request) -> Response {
    // ① 令牌校验：不通过就**不转发**。M43-S1：与 `/health` 共用 `authenticate()`。
    let Some(identity) = authenticate(request.headers(), &state) else {
        return unauthorized("缺少或错误的本地令牌");
    };

    let path = request.uri().path().to_string();
    let query = request
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();

    // ② 只转发 `/v1/*`，且路径里不许有「向上跳」的段
    // M42-S2a：Gemini 的路径是 `/v1beta/models/<model>:generateContent`，不在 `/v1/*` 下。
    // 只放行这一个**精确形态**（不是整个 `/v1beta` 前缀）——别把它变成任意路径的入口。
    // (4) Gemini 流式：`:streamGenerateContent` 与 `?alt=sse` 都必须 400 点名 S2b，
    //     不能掉到 404（那是「路径不存在」的语义，会误导用户去查地址）也不能静默当非流式。
    // M42-S2b：Gemini 的流式有**两种**入口——`:streamGenerateContent` 路径与 `?alt=sse` 查询。
    // 两者都走流式翻译（不再 400）。
    let gemini_stream = path.starts_with("/v1beta/models/")
        && (path.ends_with(":streamGenerateContent") || query.contains("alt=sse"));
    let gemini_path = path.starts_with("/v1beta/models/")
        && (path.ends_with(":generateContent") || path.ends_with(":streamGenerateContent"));
    if !path.starts_with("/v1/") && path != "/v1" && !gemini_path {
        return local_error(
            StatusCode::NOT_FOUND,
            GatewayErrorKind::InvalidRequest,
            "not_found",
            "网关只转发 /v1/*；健康检查用 /health",
        );
    }
    if !path_is_safe(&path) || query.contains(['\r', '\n', '\0']) {
        return local_error(
            StatusCode::BAD_REQUEST,
            GatewayErrorKind::InvalidRequest,
            "invalid_path",
            "路径里含「向上跳」的段或控制字符，拒绝转发",
        );
    }

    let method = request.method().clone();
    // 入站头先克隆一份：下面要按上游逐次重建（换 `Authorization`），
    // 但「丢掉带本地令牌的头」这条规则对每个上游都一样。
    let inbound = request.headers().clone();

    let max_request_bytes = state.config.max_request_bytes;
    let body = match axum::body::to_bytes(request.into_body(), max_request_bytes).await {
        Ok(bytes) => bytes,
        Err(e) => {
            // M42-S1 §4.2 #5：超限是 413，不是 400——判定用 `LengthLimitError` 精确区分，
            // 非超限的读取错误仍是 400。超限时不读完整 body、不连上游。
            // axum 0.8：`to_bytes` 的 Err 是 `axum::Error`，超限原因在 `source()` 链上
            // 的 `LengthLimitError`（axum 官方示例同口径：`source.is::<LengthLimitError>()`）。
            let too_large = std::error::Error::source(&e)
                .is_some_and(|source| source.is::<http_body_util::LengthLimitError>());
            if too_large {
                return local_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    GatewayErrorKind::InvalidRequest,
                    "request_too_large",
                    format!("请求体超过上限 {} MiB", max_request_bytes / (1024 * 1024)),
                );
            }
            return local_error(
                StatusCode::BAD_REQUEST,
                GatewayErrorKind::InvalidRequest,
                "invalid_request_body",
                format!("读取请求体失败: {e}"),
            );
        }
    };

    // ④′ M42-S2a：协议翻译（非流式 MVP）。
    //
    // Chat **零翻译**（不进本分支，body 逐字节不动）；其余三种先解析成 IR，
    // 再序列化成 OpenAI Chat body。**解析失败发生在发请求之前** ⇒ 不可能产生上游计费（ADR D5）。
    let mut translate_stream = false;
    let (body, translate_proto) = match translate::detect(&method, &path, &inbound) {
        Some(proto)
            if matches!(
                proto,
                translate::Protocol::OpenAiResponses
                    | translate::Protocol::AnthropicMessages
                    | translate::Protocol::GeminiGenerateContent
            ) =>
        {
            match translate::parse_request(proto, &body) {
                Ok(mut req) => {
                    // Gemini 的模型名在**路径**里，不在 body（spec §4.3）。
                    if req.model.is_empty() {
                        if let Some(model) = gemini_model_from_path(&path) {
                            req.model = model;
                        }
                    }
                    if req.model.is_empty() {
                        return local_error(
                            StatusCode::BAD_REQUEST,
                            GatewayErrorKind::InvalidRequest,
                            "invalid_request",
                            "无法确定模型名：Gemini 需要 /v1beta/models/<model>:generateContent",
                        );
                    }
                    // P1-1（复审）：**先**把流式意图写回 IR，再序列化——
                    // 否则 `to_upstream_json()` 读的还是 `req.stream`（false），
                    // 上游收到的是非流式请求，整个流式路径形同虚设。
                    req.stream = req.stream || gemini_stream;
                    translate_stream = req.stream;
                    let json = req.to_upstream_json().to_string();
                    (bytes::Bytes::from(json), Some(proto))
                }
                Err(e) => {
                    return local_error(
                        StatusCode::BAD_REQUEST,
                        GatewayErrorKind::InvalidRequest,
                        e.code,
                        e.message,
                    );
                }
            }
        }
        _ => (body, None),
    };

    // M39-S1：**每请求只取一次**路由视图（克隆一次 `Arc<GatewaySnapshot>` 就放锁）。
    // 之后所有 route / keys_by_ref 的读取都走 `view`——否则会分叉成「一半按新路由、
    // 一半按旧路由」。`runtime == None` 时它借用 `config`，与加这个字段之前逐字相同。
    let view = state.config.view();

    // ②′ M39-S2：`GET /v1/models` 在**非空路由 + 目录非空**时**本地聚合**（不向上游发请求）。
    //
    // 判定顺序（spec §4.2）：非该路径 → 空路由（走 legacy）→ 目录为空（回退到既有透传）→ 聚合。
    // 目录为空时的「旧透传」= 落到下面的 ④（`all_candidates()` 的第一个），与加本分支之前逐字一致。
    if method == axum::http::Method::GET && path == "/v1/models" && !view.route().is_empty() {
        let models = view.route().available_models();
        if !models.is_empty() {
            return models_list_response(&models);
        }
    }

    // ③ 空路由表 ⇒ 单上游时代的**逐字节相同**行为：不解析 body、不查 `keys_by_ref`、
    //    不查熔断、不写失败事件、只发一次请求。
    //
    //    M16-S4 / P3-3 的唯一增量：**停止信号已发出时一个字节都不发**。
    //    这不是「上游失败」，是本地状态 ⇒ 不写事件、不改响应形态（只在停止期间生效）。
    if view.route().is_empty() {
        if is_stopping(&state) {
            return stopping_response();
        }
        // P3-4 / P2-7 / B-111：legacy 路径手里是**启动那一刻的密钥快照**。
        // M8-S4 起密钥可以「一键轮换」，轮换后旧 key 在站点侧已删、在本地被标成
        // 已回收，而运行中的网关还在用它 —— 用户看到的是一个没有解释的 401/502。
        //
        // 所以：引用被标记为已回收 ⇒ **拒绝转发**，并留一条 `status = 0` 的事件，
        // 把「为什么」与「怎么办」写清楚（重启网关才会读到新密钥）。
        // 这是 D-1「空表路径不产生失败事件」的**唯一例外**，而且是**配置类**失败：
        // 上游失败那一维度仍然逐字节不变（见 `legacy_upstream_failures_still_write_no_event`）。
        //
        // `legacy_key_ref` 为 `None`（既有调用方 / `single_upstream`）⇒ 不校验，行为不变。
        if let Some(reference) = state.config.legacy_key_ref.as_deref() {
            let revoked = state
                .config
                .revoked_refs
                .as_ref()
                .map(|refs| {
                    refs.lock()
                        .map(|set| set.contains(reference))
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            if revoked {
                let model = model_from_body(&body).unwrap_or_default();
                report_event_only(
                    &state,
                    state.config.site_id,
                    0,
                    &model,
                    "该密钥已被回收（可能刚做过一键轮换）；网关需要重启才会用上新密钥",
                );
                return local_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    GatewayErrorKind::Api,
                    "key_revoked",
                    "这把密钥已被回收（可能刚做过一键轮换）；请重启网关，让它读到新密钥",
                );
            }
        }
        let url = format!("{}{}{}", state.config.base_url, path, query);
        let headers = upstream_headers(&state.config, &inbound, &state.config.api_key);
        return forward_to(
            &state,
            method,
            &url,
            headers,
            body,
            &identity,
            translate_proto,
            translate_stream,
        )
        .await;
    }

    // ④ 路由非空：选候选（首位即首选，顺序由 `RouteTable` 保证确定）
    let model = model_from_body(&body);
    let candidates: Vec<&Upstream> = match &model {
        Some(m) => view.route().candidates(m),
        // 没有 body（`GET /v1/models`）或 body 里没有 `model`：用**所有**上游的有序
        // 列表，而不是 `preferred()` 的单个——否则首选挂了就 502，不切别的上游
        // （B-98 / P2-9）。开了路由不该把一个 PRD 端点变成 404。
        None => view.route().all_candidates(),
    };
    if candidates.is_empty() {
        return local_error(
            StatusCode::NOT_FOUND,
            GatewayErrorKind::InvalidRequest,
            "model_not_found",
            format!(
                "没有可服务模型 {} 的上游",
                model.as_deref().unwrap_or("(请求里未指定)")
            ),
        );
    }

    let now = Instant::now();
    let eligible = eligible_candidates(&state.breaker, &candidates, model.as_deref(), now);
    if eligible.is_empty() {
        // §9 第 2 条：**「一个候选都没发出去」也必须可见**。
        //
        // `status = 0` 是哨兵值（HTTP 里不存在 0），表示「没有任何上游返回过状态码」。
        // **不编一个 503**：那会让事件说谎——读者会以为某个上游真的返回了 503。
        // 文案必须写明原因，否则 0 会被误读成真实状态码。
        let first_site = candidates[0].site_id;
        let key = match &model {
            Some(m) => model_key(first_site, m),
            None => site_key(first_site),
        };
        report_failure(
            &state,
            &key,
            first_site,
            0,
            &model.clone().unwrap_or_default(),
            "所有候选上游都在熔断冷却中",
            Instant::now(),
        );
        return local_error(
            StatusCode::SERVICE_UNAVAILABLE,
            GatewayErrorKind::Api,
            "breaker_open",
            "所有候选上游都在熔断冷却中，请稍后重试",
        );
    }

    // 别名命中时才改写 body 里的 `model`；未命中时 body 逐字节原样转发。
    let outbound = match &model {
        Some(m) => rewrite_model(&body, m, view.route()),
        None => body,
    };
    let event_model = model.unwrap_or_default();

    // §3.5-3 / §10：先把候选分成「发得出去」与「发不出去」两类。
    //
    // 修复前 `is_last` 用的是 `eligible.len()`——里面**含没有明文的候选**（它们会 `continue`）。
    // 于是「最后一个真的发得出去的候选」被误判成「不是最后一个」，它的响应被丢掉、
    // 继续往下走 → 最终 502。症状：唯一可用上游返回 `429 + Retry-After`，
    // 用户看到 502（而不是 429），`Retry-After` 被吞掉。
    let sendable: Vec<Candidate> = eligible
        .iter()
        .copied()
        .filter(|c| is_sendable(&state, view.keys(), c.upstream))
        .collect();

    // M46-S2：按实测 EWMA 重排（在 weighted_pick 之前；本行不读 round_robin，
    // 所以 cursor 消耗规则逐字不变；权重公式在 weighted_pick 内只由 rate 定，
    // 重排只改变组首次出现顺序与失败切换顺序）。
    let ewma = state.metrics.ewma_latency_map();
    let sendable = reorder_by_effective_latency(sendable, &|site_id| ewma.get(&site_id).copied());

    // M46-S5：请求级预算拦截表。sendable 里去重后的 (site_id, key_id) 对各查一次
    // budget_check，命中即记入映射（循环内按它跳过候选）。
    // 不在 eligible 阶段过滤：eligible 为空走的是熔断 503 尾巴，预算拦光不得报成熔断。
    let mut budget_blocked: std::collections::HashMap<(i64, Option<i64>), BudgetBreach> =
        std::collections::HashMap::new();
    if let Some(check) = &state.config.budget_check {
        for c in &sendable {
            let pair = (c.upstream.site_id, c.upstream.key_id);
            if let std::collections::hash_map::Entry::Vacant(entry) = budget_blocked.entry(pair) {
                if let Some(breach) = check(pair.0, pair.1) {
                    entry.insert(breach);
                }
            }
        }
    }
    // 同一请求内同一 breach 的回调去重集合（循环内首次遇到时才回调）。
    let mut budget_breach_fired: std::collections::HashSet<(i64, Option<i64>, BudgetPeriod)> =
        std::collections::HashSet::new();

    // M39-S3 §4.1：加权轮转只决定**第一个**尝试谁；失败切换仍按确定性顺序走其余候选。
    // 单候选 / 有探针时不读计数器（`weighted_pick` 内部保证）。
    let top_n = state.config.lb_top_n;
    let cursor = if sendable.len() > 1 && !sendable.iter().any(|c| c.probe) {
        state.round_robin.lock().map(|mut g| g.next()).unwrap_or(0)
    } else {
        0
    };
    let first = weighted_pick(&sendable, top_n, cursor);
    let mut order: Vec<&Upstream> = Vec::with_capacity(sendable.len());
    if let Some(f) = first {
        order.push(f);
    }
    for c in &sendable {
        if Some(c.upstream) != first {
            order.push(c.upstream);
        }
    }

    let mut last_error: Option<String> = None;
    // M46-S4：重试预算。cap = 0 ⇒ 走全部候选（今天行为）；>0 则每请求最多
    // 尝试 cap 个候选。attempts_made 只计实际发出去的上游尝试（见循环内递增点）：
    // 本地保护拒绝的候选不计（它没产生可返回的真实错误），探针被实际发出去时
    // 与普通候选一样占 1 个预算（计数代码里没有任何按 probe 旗标的分支）。
    let cap = state.config.max_attempts;
    let mut attempts_made = 0usize;
    // M39-S3 §4.5：本次请求里「被本地保护跳过」的候选数（与上游故障分开计）。
    let mut local_rejected = 0usize;
    // M46-S5：其中「因预算被拦」的候选数（全拦时文案区分用；kind 始终不变）。
    let mut budget_rejected = 0usize;
    // M39-S3（Lead P2）：先记下「可重放的真实响应」（目前只有 429）。若它之后的候选
    // 全被本地保护跳过，也要把它原样返回——不能把上游真的回过的 429 变成 502。
    // 元组里带着 lease：body 还没被读，站点并发要等这条响应真正结束才归还。
    // M40-S1：同时保留「这条响应对应的命中事实」（site/model/lease/key/latency/attempts），
    // 以便循环末尾统一走 `into_upstream_response` 时 usage 归因正确。
    struct PendingReplay {
        response: reqwest::Response,
        site_id: i64,
        model: String,
        lease: Option<SiteLease>,
        meta: AttemptMeta,
    }
    let mut pending_replay: Option<PendingReplay> = None;
    let order_len = order.len();
    for (index, upstream) in order.iter().enumerate() {
        // P3-3：**每一次上游尝试之前**都查停止闸门——信号可能在上一次尝试期间发出。
        // 在途请求允许跑完**当前**这一次（无法安全中断一个已发出的请求），
        // 但绝不再发起新的：那会把下一个站点的密钥也发出去，而用户按下停止
        // 往往紧接着就要轮换/回收密钥。
        if is_stopping(&state) {
            return stopping_response();
        }
        // M46-S4：is_last 的判定移到实际发送处（见 `attempts_made` 递增点之后）：
        // 预算是否耗尽只能在「本次发送计入之后」才知道，循环顶算不出来
        // （本地拒绝的候选不计，本次迭代可能根本不发送）。
        // M39-S3 §4.4：有 model 用 `(site, Some(model))`，无 model 用 `(site, None)`。
        let breaker_key = if event_model.is_empty() {
            site_key(upstream.site_id)
        } else {
            model_key(upstream.site_id, &event_model)
        };
        // 这里 `unwrap` 不会 panic：`sendable` 就是按同一个判据过滤出来的。
        // 但仍然写 `let Some(..) else` ——「过滤」与「取用」共用同一个函数
        // （`is_sendable`），所以两者不可能分叉。
        let Some(key) = view.keys().get(&upstream.key_ref) else {
            continue;
        };
        // M46-S5：预算拦截——本地拒绝的一种，但刻意与 guard 拒绝不同：
        // 不 record_failover（预算是策略拦停，不是失败切换）、不喂熔断、不写
        // GatewayFailure；continue 发生在 attempts_made 递增之前，故不占 M46-S4
        // 重试预算。回调只在同一请求内首次遇到该 breach 时发一次。
        if let Some(breach) = budget_blocked.get(&(upstream.site_id, upstream.key_id)) {
            state
                .local_rejects
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            local_rejected += 1;
            budget_rejected += 1;
            if budget_breach_fired.insert((breach.site_id, breach.key_id, breach.period)) {
                if let Some(sink) = &state.config.on_budget_breach {
                    sink(breach.clone());
                }
            }
            continue;
        }
        // M39-S3 §4.2 / §4.5：**本地保护在发请求之前**——`try_admit` 绝不等待，
        // 拿不到就切下一个候选。**本地拒绝不是上游故障**：不调 `report_failure`、
        // 不喂熔断、不写 `GatewayFailure`（否则一个本机限流就能把好站点熔断）。
        // guard 表锁中毒 ⇒ `None`：放行（可用性优先，行为与没有保护层时相同）。
        let lease: Option<SiteLease> = match site_guard(&state, upstream.site_id)
            .map(|guard| guard.try_admit(Instant::now()))
        {
            None => None,
            Some(GuardOutcome::Admitted(lease)) => Some(lease),
            Some(GuardOutcome::ConcurrencyLimited) | Some(GuardOutcome::RateLimited) => {
                state
                    .local_rejects
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                local_rejected += 1;
                // M40-S2：本地限流「切到下一个候选」也计一次失败切换（与 429 同口径）。
                state.metrics.record_failover(upstream.site_id);
                continue;
            }
        };
        let url = format!("{}{}{}", upstream.base_url, path, query);
        let headers = upstream_headers(&state.config, &inbound, key);

        // M46-S4：预算计数点——本地保护已放行，本次 `send_once` 就是一次真实
        // 上游尝试。本地拒绝的分支在上面 `continue` 了，根本到不了这里。
        attempts_made += 1;
        // 最后一个候选 = order 末位，或预算在本次发送后耗尽（cap > 0 时）。
        // 其余分支条件（`replayable && !is_last` / `!replayable || is_last`）逐字不动：
        // 预算截断复用既有的「最后一个候选」语义，不新写一套终止逻辑。
        // cap = 0 时右半恒假，退化为今天的 `index + 1 == order_len`。
        let is_last = index + 1 == order_len || (cap > 0 && attempts_made >= cap);
        let started = Instant::now();
        // M46-S4：本次发送的生效超时 = 全局超时被该候选的分站值替代
        // （替代不是取 min；未填 ⇒ 全局本身 ⇒ 共享主客户端）。
        let effective_timeout =
            effective_upstream_timeout(state.config.upstream_timeout, upstream.timeout_ms);
        match send_once(
            &state,
            method.clone(),
            &url,
            headers,
            outbound.clone(),
            effective_timeout,
        )
        .await
        {
            Ok(response) => {
                let latency_ms = started.elapsed().as_millis() as u64;
                let status = response.status().as_u16();
                observe(
                    &state,
                    upstream.site_id,
                    latency_ms,
                    !should_failover(status),
                );
                state
                    .metrics
                    .record_attempt(upstream.site_id, status, latency_ms);
                let replayable = status_allows_replay(status);
                if should_failover(status) {
                    // §3.5-1：`opened_at` 必须是**失败发生**的时刻，不是请求开始的时刻。
                    // 用请求开始时刻的话，一次比冷却期还慢的失败（524 ≈ 100s > 冷却 60s）
                    // 记下的那一刻冷却就已经「过期」⇒ 这个上游**永远熔断不了**；
                    // 即使不慢，有效冷却也被缩短了「本次请求耗时」那么多。
                    let reason = if replayable {
                        format!("上游返回 HTTP {status}（限流：未进入处理，已切下一个候选）")
                    } else {
                        format!("上游返回 HTTP {status}（可能已计费，按 P2-13 不重放）")
                    };
                    report_failure(
                        &state,
                        &breaker_key,
                        upstream.site_id,
                        status,
                        &event_model,
                        &reason,
                        Instant::now(),
                    );
                } else {
                    record_success(&state, &breaker_key, Instant::now());
                    // M46-S2：唯一 EWMA 更新点，与 record_success 同分支
                    // （成功定义同源；429 / 5xx / 传输失败不走到这里）。
                    state
                        .metrics
                        .record_measured_latency(upstream.site_id, latency_ms);
                }
                // M16-S4 / P2-13：**只有 429 才重放**（上游明确没处理这个请求）。
                // 其余状态码——含 5xx / 524 / 504 这类可能已经计费的——一律**原样返回**：
                // 重复计费不可逆，可用性由「熔断 → 下一个请求换上游」承接。
                // 不可切换的状态、或已经是最后一个候选 ⇒ 同样如实返回（不做 500 兜底）。
                if replayable && !is_last {
                    // M40-S2：真的切了候选 ⇒ 计一次失败切换（只数 429/连接层/本地限流）。
                    state.metrics.record_failover(upstream.site_id);
                    // 留着这条响应（含 lease），继续试下一个候选；若后面全军覆没，
                    // 循环末尾会把这条 429 原样返回，而不是编一个 502。
                    pending_replay = Some(PendingReplay {
                        response,
                        site_id: upstream.site_id,
                        model: event_model.clone(),
                        lease,
                        meta: AttemptMeta {
                            key_id: upstream.key_id,
                            latency_ms,
                            attempts: index as u32 + 1,
                        },
                    });
                    continue;
                }
                return maybe_translate_response(
                    &state,
                    translate_proto,
                    response,
                    upstream.site_id,
                    &event_model,
                    lease,
                    // M40-S1：key_id 取**实际命中的上游**（不是 config 那把）。
                    AttemptMeta {
                        key_id: upstream.key_id,
                        latency_ms,
                        attempts: index as u32 + 1,
                    },
                    &identity,
                    translate_stream,
                )
                .await;
            }
            Err(failure) => {
                let latency_ms = started.elapsed().as_millis() as u64;
                observe(&state, upstream.site_id, latency_ms, false);
                state
                    .metrics
                    .record_attempt(upstream.site_id, 502, latency_ms);
                let replayable = failure.is_replayable();
                let message = failure.message().to_string();
                // 传输层失败没有 HTTP 状态码：按 502 记（与 legacy 路径的错误码一致）。
                // 文案必须说清**为什么**这次能/不能重放——这是计费决策的现场记录（P2-13）。
                let reason = if replayable {
                    format!(
                        "传输层失败（连接层，请求未送达；已切下一个候选）: {}",
                        crate::redact::scrub(&message)
                    )
                } else {
                    format!(
                        "传输层失败（请求可能已送达，按 P2-13 不重放）: {}",
                        crate::redact::scrub(&message)
                    )
                };
                report_failure(
                    &state,
                    &breaker_key,
                    upstream.site_id,
                    502,
                    &event_model,
                    &reason,
                    Instant::now(),
                );
                last_error = Some(message);
                if !replayable || is_last {
                    break;
                }
                // M40-S2：连接层失败且还有候选 ⇒ 切下一个（计一次失败切换）。
                state.metrics.record_failover(upstream.site_id);
            }
        }
    }

    // M39-S3（Lead P2）：存在「可重放的真实响应」（429）⇒ 原样返回它。
    // 典型形态：第一候选回 429，其后的候选都被本地保护跳过。
    if let Some(pending) = pending_replay {
        return maybe_translate_response(
            &state,
            translate_proto,
            pending.response,
            pending.site_id,
            &pending.model,
            pending.lease,
            pending.meta,
            &identity,
            translate_stream,
        )
        .await;
    }

    // M39-S3 §4.5：**全部候选都被本地保护跳过** ⇒ 429（不是 502）。
    // 这里没有任何上游出过错：本地并发/限流拒绝不写事件、不喂熔断，
    // 客户端据 `kind == "local_rate_limited"` 就能把「本机限流」与「上游 429」分开。
    if local_rejected > 0 && local_rejected == order_len {
        // M46-S5：全是预算拦时文案点名预算（kind 始终是 local_rate_limited，
        // 客户端据 kind 分流，不据文案）；混拦时保持既有通用文案。
        let message = if budget_rejected == order_len {
            "本地保护：预算已超支"
        } else {
            "本地保护：所有候选均被限流"
        };
        return local_error(
            StatusCode::TOO_MANY_REQUESTS,
            GatewayErrorKind::RateLimit,
            "local_rate_limited",
            message,
        );
    }

    // §10 第 2 条：**发不出去**的候选也要产生事件。
    //
    // 修复前它们静默 `continue`：若构造方忘了填 `keys_by_ref`（M7 审计 D-2），
    // 表现是「每个上游都跳过 → 502」，看起来像「故障切换不工作」，
    // 根因却是密钥映射空着——**没有任何线索**。
    //
    // **只在失败路径上报**（即上面那个 `for` 没有 `return`）。理由不是省事：
    // 「某个候选被跳过」在请求**成功**时不是故障——若那时也上报，一个长期
    // 缺明文的候选会污染失败信号。且本循环走**不喂熔断**的版本（B-224 P2）：
    // 不可发送是配置问题，不是上游故障，绝不能因此把站点熔断。
    // 契约的原话是「不得静默 **502**」，指的正是这条路径。
    //
    // 文案区分两种原因（缺明文 / 已回收），但**都不写 `key_ref` 原文**：
    // 引用本身是线索（M7-S0 §4.3 的红线）。
    for cand in eligible
        .iter()
        .filter(|c| !is_sendable(&state, view.keys(), c.upstream))
    {
        let upstream = cand.upstream;
        let (status, reason) = if is_revoked(&state, upstream) {
            (0u16, "该密钥已被回收，不再使用")
        } else {
            (0u16, "密钥引用没有对应的明文")
        };
        // P3-5 / GW-18 / DEBUG-REPORT-v3 §3-5：不覆盖可发送循环已记下的真实失败原因
        //（传输错误 / 上游状态码）——不可发送的 reason 是配置问题，不是这次请求失败
        // 的主因，盖住它会让用户以为「密钥没明文」而其实是「上游连不上」。
        if last_error.is_none() {
            last_error = Some(format!("上游站点 {}: {reason}", upstream.site_id));
        }
        // B-224 P2：不可发送是**配置问题**（缺明文 / 已回收），不是上游故障，
        // 走不喂熔断的版本——否则一个长期缺明文的候选会把整个站点熔断。
        // （注意：这里不用 `report_event_only` 而是用带指标的版本，否则这类
        // 失败在 per_site 指标里连最后错误都看不到。）
        report_failure_without_breaker(&state, upstream.site_id, status, &event_model, reason);
    }

    local_error(
        StatusCode::BAD_GATEWAY,
        GatewayErrorKind::Api,
        "all_upstreams_failed",
        last_error.unwrap_or_else(|| "所有候选上游都失败了".to_string()),
    )
}

/// 取该站点的 guard（不存在就按 `config.guard_policy` 建一个）。
///
/// 按 **`site_id`** 索引 ⇒ 同站多 key **共享**一个 guard（M39-S3 §4.3）：
/// 若按 `key_ref` 建，两把 key 会各拿一份「每站 8 并发」，站点上限就翻倍了。
///
/// 返回 `None` 仅当 guard 表锁中毒：调用方按「无保护层」放行（可用性优先）。
fn site_guard(state: &AppState, site_id: i64) -> Option<Arc<SiteGuard>> {
    let mut guards = state.guards.lock().ok()?;
    if let Some(guard) = guards.get(&site_id) {
        return Some(Arc::clone(guard));
    }
    let guard = Arc::new(SiteGuard::new(state.config.guard_policy, Instant::now()));
    guards.insert(site_id, Arc::clone(&guard));
    Some(guard)
}

/// 这个上游**能不能真的发出去**：有明文，且该明文没被回收。
///
/// 「过滤」与「取用」共用这一个函数——两处各写一份判据正是 M7 那类分叉的来源。
fn is_sendable(
    state: &AppState,
    keys: &HashMap<String, Zeroizing<String>>,
    upstream: &Upstream,
) -> bool {
    !is_revoked(state, upstream) && keys.contains_key(&upstream.key_ref)
}

/// 该上游的密钥是否**已被回收**（§3.5-5）。
///
/// 回收只拦新启动是不够的：网关运行期间某把 key 被回收后，它仍在 `keys_by_ref` 里。
/// 服务侧在 `revoke_key` 成功后把 `secret_ref` 插进这个集合，网关只查它——
/// **不新开取密钥路径**。
fn is_revoked(state: &AppState, upstream: &Upstream) -> bool {
    let Some(refs) = &state.config.revoked_refs else {
        return false;
    };
    refs.lock()
        .map(|set| set.contains(&upstream.key_ref))
        // 锁中毒：**按「没被回收」处理**。可用性优先——一次 panic 不该让网关停止服务；
        // 而这里误判的代价是「多试一次注定 401 的上游」，由故障切换兜住。
        .unwrap_or(false)
}

/// 上报一次观测（§5.3）。失败尝试也上报，但服务侧**只把成功的记进 last-value**
/// （失败耗时没有比较意义）。
fn observe(state: &AppState, site_id: i64, latency_ms: u64, ok: bool) {
    if let Some(sink) = &state.config.on_observation {
        sink(UpstreamObservation {
            site_id,
            latency_ms,
            ok,
        });
    }
}

/// 构造发往上游的 `Authorization` 值。
///
/// **返回类型是 `Zeroizing<String>`**（M16-S4 / P3-32）：`format!` 出来的是一份
/// 不会被擦除的明文副本，而它每次请求都要造一次。用 `Zeroizing` 包住，
/// `HeaderValue::from_str` 复制完之后，临时串在 drop 时清零。
///
/// **边界（不得声称更多）**：`HeaderValue` 内部那一份拷贝属于 reqwest/hyper 的所有权，
/// 纯 Rust 层擦不掉——与 M7-S5 D-2「只覆盖我们持有的所有权」同口径。
/// 返回值刻意做成 `Zeroizing` 而不是 `String`：类型本身就是守卫，
/// 谁把它改回裸 `String`，`the_bearer_value_is_zeroizing` 会编译失败。
fn bearer_value(key: &str) -> Zeroizing<String> {
    Zeroizing::new(format!("Bearer {key}"))
}

/// 重建发往上游的请求头：**丢掉**调用方的 `Authorization`，换成该上游的站点密钥；
/// 另外把「值里带着本地令牌」的头也丢掉——不管它叫什么名字，本地令牌都不许发给上游
/// （M4-S2 复审 P2-2 的双头形态）。
fn upstream_headers(config: &GatewayConfig, inbound: &HeaderMap, key: &str) -> HeaderMap {
    let local_token = config.token.as_str();
    let mut headers = HeaderMap::new();
    for (name, value) in inbound.iter() {
        if should_strip_request_header(name.as_str()) {
            continue;
        }
        if value.to_str().is_ok_and(|text| text.contains(local_token)) {
            continue;
        }
        headers.insert(name.clone(), value.clone());
    }
    let bearer = bearer_value(key);
    headers.insert(
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(bearer.as_str())
            .unwrap_or_else(|_| HeaderValue::from_static("Bearer ")),
    );
    headers
}

/// 发一次请求。`Err` 表示失败，且**已经分类**成「可重放 / 不可重放」（P2-13）——
/// 分类必须在**这里**做：只有 `reqwest::Error` 才知道失败发生在连接阶段还是响应阶段，
/// 上层拿到的只是一个字符串。
async fn send_once(
    state: &AppState,
    method: axum::http::Method,
    url: &str,
    headers: HeaderMap,
    body: bytes::Bytes,
    // M46-S4：本次发送的生效超时。== 全局 ⇒ 共享主客户端；否则分站客户端
    // （见 `client_for_timeout`）。绝不用 `RequestBuilder::timeout`（总 deadline
    // 会砍合法长流，与全局两维语义不是同一维度）。
    timeout: UpstreamTimeout,
) -> std::result::Result<reqwest::Response, AttemptFailure> {
    client_for_timeout(state, timeout)
        .request(method, url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|e| classify_send_error(&e))
}

/// 单上游（legacy）转发：只发一次，错误按既有形态返回。
///
/// M16-S4：`send_once` 现在返回**分类后**的失败。legacy 路径**没有下一个候选**，
/// 所以分类不影响这里的行为（两个分支都返回 502 + 同一段文案），
/// 只是把错误消息取出来——**响应形态与改动前逐字节相同**。
#[allow(clippy::too_many_arguments)]
async fn forward_to(
    state: &AppState,
    method: axum::http::Method,
    url: &str,
    headers: HeaderMap,
    body: bytes::Bytes,
    identity: &AuthIdentity,
    translate_proto: Option<translate::Protocol>,
    translate_stream: bool,
) -> Response {
    let model = model_from_body(&body).unwrap_or_default();
    // B-224 长尾（M42-S2b §4.4）：legacy 单上游此前传 `lease: None`，流式翻译
    // 全程不受每站并发约束——与「流式请求同样受每站并发/令牌桶约束」矛盾。
    // 现与多上游路径同口径：发请求前 `try_admit`，拿不到即 429（不发上游、
    // 不喂熔断）；拿到的 lease 随响应 body 生命周期归还（流式泵内 `_lease`）。
    // 默认策略（8 并发、不限速）下对既有单上游部署的影响仅是 8 并发上限。
    // M46-S5：legacy 单上游预算拦截（无循环、无尾巴可复用，直接 429；
    // 不发上游、不喂熔断；回调语义与多上游路径相同）。
    if let Some(check) = &state.config.budget_check {
        if let Some(breach) = check(state.config.site_id, state.config.key_id) {
            if let Some(sink) = &state.config.on_budget_breach {
                sink(breach);
            }
            return local_error(
                StatusCode::TOO_MANY_REQUESTS,
                GatewayErrorKind::RateLimit,
                "local_rate_limited",
                "本地保护：预算已超支",
            );
        }
    }
    let lease: Option<SiteLease> = match site_guard(state, state.config.site_id)
        .map(|guard| guard.try_admit(Instant::now()))
    {
        None => None,
        Some(GuardOutcome::Admitted(lease)) => Some(lease),
        Some(GuardOutcome::ConcurrencyLimited) | Some(GuardOutcome::RateLimited) => {
            state
                .local_rejects
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return local_error(
                StatusCode::TOO_MANY_REQUESTS,
                GatewayErrorKind::RateLimit,
                "local_rate_limited",
                "本地保护：站点并发/限流拒绝",
            );
        }
    };
    let started = Instant::now();
    // M46-S4：legacy 单上游恒走全局超时 ⇒ 共享主客户端，今天路径逐字相同。
    match send_once(
        state,
        method,
        url,
        headers,
        body,
        state.config.upstream_timeout,
    )
    .await
    {
        Ok(response) => {
            let latency_ms = started.elapsed().as_millis() as u64;
            state.metrics.record_attempt(
                state.config.site_id,
                response.status().as_u16(),
                latency_ms,
            );
            // legacy 单上游：`key_id` 回退到启动参数（M40-S1 §4.1）。
            // M42-S2a：翻译协议在 legacy 单上游上同样生效（Chat 仍是零翻译直通）。
            maybe_translate_response(
                state,
                translate_proto,
                response,
                state.config.site_id,
                &model,
                lease,
                AttemptMeta {
                    key_id: state.config.key_id,
                    latency_ms,
                    attempts: 1,
                },
                identity,
                translate_stream,
            )
            .await
        }
        Err(failure) => local_error(
            StatusCode::BAD_GATEWAY,
            GatewayErrorKind::Api,
            "upstream_failed",
            failure.message(),
        ),
    }
}

/// 回传：过滤掉敏感响应头 + **流式**回传（带上限）。
///
/// 流式的理由（M4-S2 复审 P1-2）：整段缓冲会让客户端等上游吐完才见到第一个字节，
/// 而且响应体没有上限。超过 [`MAX_RESPONSE_BYTES`] 时让流以错误结束、连接随之断开——
/// 此时响应头已经发出去了，改不了状态码，只能如实断流，不静默截断。
/// 把 `SiteLease` 绑到响应 body 的生命周期上（M39-S3 §4.2 / Lead P1）。
///
/// **只放在 `proxy` 的栈上是不够的**：函数 `return` 时 lease 就被 drop，而 body 还在
/// 流式回传——站点并发提前减 1，等于「并发上限只覆盖到响应头」。把 lease 捕获进
/// `map` 的闭包 ⇒ 流结束 / 客户端断开 / 响应被丢弃时才归还。
fn hold_lease<S>(stream: S, lease: Option<SiteLease>) -> impl futures_util::Stream<Item = S::Item>
where
    S: futures_util::Stream + Send + 'static,
{
    stream.map(move |item| {
        let _ = &lease;
        item
    })
}

/// 从 `/v1beta/models/<model>:generateContent` 里取出模型名（Gemini 的模型名在路径里）。
fn gemini_model_from_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/v1beta/models/")?;
    // M42-S2b：流式入口是 `:streamGenerateContent`，非流式是 `:generateContent`
    let model = rest
        .strip_suffix(":streamGenerateContent")
        .or_else(|| rest.strip_suffix(":generateContent"))?;
    (!model.is_empty()).then(|| model.to_string())
}

/// M42-S2a：翻译协议的响应渲染。
///
/// - `proto == None`（Chat / 未识别）⇒ 完全走既有透传（**零翻译**）；
/// - 非 2xx ⇒ **原样透传**（不翻译上游错误语义，spec §4.5）；
/// - 2xx ⇒ 缓冲上游 Chat JSON（受 `MAX_RESPONSE_BYTES` 上限）→ IR → 渲染回入站协议。
///
/// **usage**：按上游 Chat 的 `usage` 记**一次**（`site_id` / `key_id` / 原始 prompt/completion），
/// 与被替换掉的 `into_upstream_response` 内部 `UsageCapture` 等价——**不重复计费**。
#[allow(clippy::too_many_arguments)]
async fn maybe_translate_response(
    state: &AppState,
    proto: Option<translate::Protocol>,
    upstream_response: reqwest::Response,
    site_id: i64,
    event_model: &str,
    lease: Option<SiteLease>,
    meta: AttemptMeta,
    identity: &AuthIdentity,
    stream: bool,
) -> Response {
    let Some(proto) = proto else {
        return into_upstream_response(
            state,
            upstream_response,
            site_id,
            event_model,
            lease,
            meta,
            identity,
        );
    };
    let status = upstream_response.status();
    if !status.is_success() {
        return into_upstream_response(
            state,
            upstream_response,
            site_id,
            event_model,
            lease,
            meta,
            identity,
        );
    }

    if stream {
        return streaming_translate_response(
            state,
            proto,
            upstream_response,
            site_id,
            event_model,
            meta,
            identity,
            lease,
        );
    }

    // (5) **带上限的流式收集**：超 64 MiB 立刻中止，不先整段进内存再判上限。
    let mut collected: Vec<u8> = Vec::new();
    let mut stream = upstream_response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => {
                return local_error(
                    StatusCode::BAD_GATEWAY,
                    GatewayErrorKind::Api,
                    "upstream_read_failed",
                    format!("读取上游响应失败: {e}"),
                )
            }
        };
        if collected.len() as u64 + chunk.len() as u64 > MAX_RESPONSE_BYTES {
            return local_error(
                StatusCode::BAD_GATEWAY,
                GatewayErrorKind::Api,
                "upstream_too_large",
                "上游响应超过网关上限，无法翻译",
            );
        }
        collected.extend_from_slice(&chunk);
    }
    let bytes = bytes::Bytes::from(collected);
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            return local_error(
                StatusCode::BAD_GATEWAY,
                GatewayErrorKind::Api,
                "render_failed",
                format!("上游响应不是 JSON，无法按 {:?} 渲染: {e}", proto),
            )
        }
    };
    let parsed = match translate::ChatResponse::from_upstream_json(&value) {
        Ok(p) => p,
        Err(e) => {
            return local_error(
                StatusCode::BAD_GATEWAY,
                GatewayErrorKind::Api,
                "render_failed",
                format!("上游响应无法按 {:?} 渲染: {e}", proto),
            )
        }
    };

    // usage：与既有 UsageCapture 同口径——只在 2xx 记一次
    if let (Some(sink), Some(u)) = (&state.config.on_usage, parsed.usage) {
        sink(GatewayUsage {
            at: unix_now_secs(),
            site_id,
            key_id: meta.key_id,
            model: event_model.to_string(),
            prompt_tokens: u.prompt_tokens,
            completion_tokens: u.completion_tokens,
            total_tokens: u.total_tokens,
            status: status.as_u16(),
            // 与既有 UsageCapture 同口径：翻译路径是「非流式、一次尝试成功」的形态，
            // 但 latency/attempts 仍取真实值（meta 里就是本次命中的那次尝试）。
            latency_ms: meta.latency_ms,
            attempts: meta.attempts,
            stream: false,
            token_id: identity.token_id,
            agent_label: identity.label.clone().unwrap_or_default(),
        });
    }
    drop(lease);
    let rendered = translate::render_response(proto, &parsed);
    (StatusCode::OK, axum::Json(rendered)).into_response()
}

/// M42-S2b：流式翻译。把上游 Chat SSE 增量渲染成入站协议的 SSE。
///
/// **行为契约**：
/// - 跨 chunk 由 [`translate::stream::SseDecoder`] 按空行缓冲（不假设事件整块到达）；
/// - `[DONE]` ⇒ `finish()`，**恰好一次**；
/// - 上游中途报错 ⇒ 发一个 `event: error` 再关闭（不静默当正常结束，也不挂死）；
/// - **客户端断开** ⇒ `tx.send` 失败 ⇒ 任务退出（不泄漏、不继续跑）；
/// - **usage 只记一次**（`include_usage` 的末帧）。
#[allow(clippy::too_many_arguments)]
/// 流式 usage 末帧口径（B-224 长尾）：与 [`UsageCapture`] 的 last-wins 一致——
/// 泵在整个流里只记**最后一次**见到的 usage，任务结束时（正常、错误、客户端断开）
/// 恰好发一行；无 usage 则不发。`Drop` 保证各返回点都不漏发、不多发；
/// `at` 取任务结束时刻（与 `GatewayUsage.at`「流结束或被客户端断开的那一刻」一致）。
struct StreamUsageFlush {
    sink: Option<std::sync::Arc<dyn Fn(GatewayUsage) + Send + Sync>>,
    site_id: i64,
    key_id: Option<i64>,
    model: String,
    status: u16,
    latency_ms: u64,
    attempts: u32,
    token_id: Option<i64>,
    label: String,
    pending: Option<(i64, i64, i64)>,
}

impl Drop for StreamUsageFlush {
    fn drop(&mut self) {
        if let (Some(sink), Some((p, c, t))) = (&self.sink, self.pending) {
            sink(GatewayUsage {
                at: unix_now_secs(),
                site_id: self.site_id,
                key_id: self.key_id,
                model: self.model.clone(),
                prompt_tokens: p,
                completion_tokens: c,
                total_tokens: t,
                status: self.status,
                latency_ms: self.latency_ms,
                attempts: self.attempts,
                stream: true,
                token_id: self.token_id,
                agent_label: self.label.clone(),
            });
        }
    }
}

fn streaming_translate_response(
    state: &AppState,
    proto: translate::Protocol,
    mut upstream: reqwest::Response,
    site_id: i64,
    event_model: &str,
    meta: AttemptMeta,
    identity: &AuthIdentity,
    lease: Option<SiteLease>,
) -> Response {
    use translate::stream::{ChatDelta, SseDecoder, StreamTranslator};

    let (tx, rx) =
        tokio::sync::mpsc::channel::<std::result::Result<bytes::Bytes, std::io::Error>>(16);
    let on_usage = state.config.on_usage.clone();
    let model = event_model.to_string();
    let token_id = identity.token_id;
    let label = identity.label.clone().unwrap_or_default();
    let status_code = upstream.status().as_u16();

    tokio::spawn(async move {
        // 许可跟着流走：流结束（或客户端断开）才归还（spec §4.4）
        let _lease = lease;
        let mut dec = SseDecoder::new();
        let mut tr = StreamTranslator::new(proto);
        // B-224 长尾：usage 取末帧（与 UsageCapture last-wins 同口径），
        // 任务结束时由 Drop 恰好发一行；首帧即发会在上游发多次 usage 时记少。
        let mut usage_flush = StreamUsageFlush {
            sink: on_usage.clone(),
            site_id,
            key_id: meta.key_id,
            model: model.clone(),
            status: status_code,
            latency_ms: meta.latency_ms,
            attempts: meta.attempts,
            token_id,
            label: label.clone(),
            pending: None,
        };
        let mut saw_done = false;

        loop {
            // B-224 P2：同时等客户端断开——上游停顿时不等 read_timeout，
            // 断开即退出、lease 随 `_lease` drop 归还。`tx.closed()` 在接收端
            // 全部 drop 时完成；下面各分支里 `tx.send` 失败才发现断开的
            // 旧路径仍保留（双重保障）。
            tokio::select! {
                _ = tx.closed() => {
                    return;
                }
                result = upstream.chunk() => {
                    match result {
                Ok(Some(chunk)) => {
                    let events = dec.push(&chunk);
                    // B-224 P2：单个 SSE 事件超 1 MiB ⇒ 畸形流，发 error 关闭，
                    // 不继续缓冲（否则上游永不发空行即可无界涨内存）。
                    if dec.is_overflowed() {
                        let frame = format!(
                            "event: error\ndata: {}\n\n",
                            serde_json::json!({
                                "type": "error",
                                "error": { "type": "upstream_error", "message": "上游 SSE 事件超过上限" }
                            })
                        );
                        let _ = tx.send(Ok(bytes::Bytes::from(frame))).await;
                        return;
                    }
                    for e in &events {
                        // P2（复审）：`[DONE]` 之外、解析不出增量的事件 ⇒ 明确报错并关闭，
                        // 不静默跳过（静默跳过 = 客户端拿到残缺回答却以为完整）。
                        let is_done = e.data.trim() == "[DONE]";
                        if is_done {
                            saw_done = true;
                        } else if ChatDelta::from_json(&e.data).is_none() {
                            let frame = format!(
                                "event: error\ndata: {}\n\n",
                                serde_json::json!({
                                    "type": "error",
                                    "error": { "type": "upstream_error", "message": "上游事件无法解析" }
                                })
                            );
                            let _ = tx.send(Ok(bytes::Bytes::from(frame))).await;
                            return;
                        }
                        // 末帧口径：每次见到的 usage 都覆盖 pending，结束时只发最后一次。
                        if let Some(d) = ChatDelta::from_json(&e.data) {
                            if d.usage.is_some() {
                                usage_flush.pending = d.usage;
                            }
                        }
                        let frames = tr.on_event(e);
                        if !frames.is_empty()
                            && tx
                                .send(Ok(bytes::Bytes::from(frames.concat())))
                                .await
                                .is_err()
                        {
                            return; // 客户端断开
                        }
                    }
                }
                Ok(None) => {
                    let (rest, truncated) = dec.finish();
                    for e in &rest {
                        for f in tr.on_event(e) {
                            let _ = tx.send(Ok(bytes::Bytes::from(f))).await;
                        }
                    }
                    // P2（复审）：**干净 EOF 但没收到 `[DONE]`**（或残留半截事件）⇒
                    // 发错误事件并**跳过正常收尾**。否则客户端会收到一个「看起来完整」的
                    // 收尾标记，而实际上回答被截断了。
                    if !saw_done || truncated {
                        let frame = format!(
                            "event: error\ndata: {}\n\n",
                            serde_json::json!({
                                "type": "error",
                                "error": { "type": "upstream_error", "message": "上游流未正常结束（缺少 [DONE]）" }
                            })
                        );
                        let _ = tx.send(Ok(bytes::Bytes::from(frame))).await;
                        return;
                    }
                    let tail = tr.finish();
                    if !tail.is_empty() {
                        let _ = tx.send(Ok(bytes::Bytes::from(tail.concat()))).await;
                    }
                    return;
                }
                Err(_) => {
                    let frame = format!(
                        "event: error\ndata: {}\n\n",
                        serde_json::json!({
                            "type": "error",
                            "error": { "type": "upstream_error", "message": "上游流中断" }
                        })
                    );
                    let _ = tx.send(Ok(bytes::Bytes::from(frame))).await;
                    return;
                }
                    }
                }
            }
        }
    });

    let body =
        axum::body::Body::from_stream(futures_util::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        }));
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn into_upstream_response(
    state: &AppState,
    upstream_response: reqwest::Response,
    site_id: i64,
    model: &str,
    lease: Option<SiteLease>,
    meta: AttemptMeta,
    identity: &AuthIdentity,
) -> Response {
    let status = upstream_response.status();
    let is_success = status.is_success();
    let is_sse = is_sse_response(&upstream_response);
    let mut builder = Response::builder().status(status);
    for (name, value) in upstream_response.headers().iter() {
        if should_strip_response_header(name.as_str()) {
            continue;
        }
        builder = builder.header(name, value);
    }

    if !is_success {
        // P1（M40-S1 复审）：**非 2xx 的 body 也必须 hold_lease**。M39-S3 的
        // `SiteLease` 要覆盖整个响应 body（5xx / 429 / pending_replay 都一样）；
        // 这里若直接 `Body::from_stream`，body 还没读完站点并发就提前归还，
        // 第二个请求会被错误放进来（本地 429 保护失效、上游并发超限）。
        let capped = hold_lease(
            cap_stream(upstream_response.bytes_stream(), MAX_RESPONSE_BYTES),
            lease,
        );
        return builder
            .body(Body::from_stream(capped))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    // M40-S1：2xx 用统一的 `UsageCapture`——SSE 走跨 chunk 行缓冲，非流式累积 body；
    // 正常结束 / 流错误 / 客户端断开（Drop）三路合计恰好 flush 一次。
    let capture = UsageCapture::new(
        state.config.on_usage.clone(),
        site_id,
        meta.key_id,
        crate::redact::scrub(model).to_string(),
        status.as_u16(),
        meta.latency_ms,
        meta.attempts,
        is_sse,
        Arc::new(unix_now_secs),
    )
    .with_identity(
        identity.token_id,
        identity.label.clone().unwrap_or_default(),
    );
    let capped = cap_stream_with_usage(
        upstream_response.bytes_stream(),
        MAX_RESPONSE_BYTES,
        capture,
    );
    let capped = hold_lease(capped, lease);
    builder
        .body(Body::from_stream(capped))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// 跳过 `Open` 的候选；`HalfOpen` 只放**一个探针**（P2-8：跨请求共享，不只是单次
/// 调用内——否则冷却一过所有并发请求都会拿到同一个 HalfOpen 探针涌向坏上游）。
fn eligible_candidates<'a>(
    breaker: &Arc<Mutex<Breaker>>,
    candidates: &[&'a Upstream],
    model: Option<&str>,
    now: Instant,
) -> Vec<Candidate<'a>> {
    let Ok(mut guard) = breaker.lock() else {
        // 锁中毒：放行全部候选。可用性优先——一次 panic 不该让网关永久 503。
        return candidates
            .iter()
            .map(|u| Candidate {
                upstream: u,
                probe: false,
            })
            .collect();
    };
    let mut out = Vec::with_capacity(candidates.len());
    for upstream in candidates {
        // M39-S3 §4.4：熔断键 `(site_id, Some(model))`；无 model ⇒ `(site_id, None)`。
        let key = match model {
            Some(m) => model_key(upstream.site_id, m),
            None => site_key(upstream.site_id),
        };
        match guard.state(&key, now) {
            BreakerState::Open => continue,
            BreakerState::HalfOpen => {
                // P2-8：第一个拿到探针的请求在 Breaker 里标记，其余并发请求看到标记
                // 即跳过。探针结果回来后由 record_success / record_failure 清除标记。
                if guard.try_take_half_open_probe(&key, now) {
                    // M39-S3 §4.1：探针**不参与加权轮转**，由 `weighted_pick` 优先返回。
                    out.push(Candidate {
                        upstream,
                        probe: true,
                    });
                }
            }
            BreakerState::Closed => out.push(Candidate {
                upstream,
                probe: false,
            }),
        }
    }
    out
}

/// M40-S2：`BreakerState` → DTO 字符串（唯一出处）。
fn breaker_label(breaker: &Arc<Mutex<Breaker>>, site_id: i64, now: Instant) -> &'static str {
    match breaker.lock().map(|g| g.worst_state_for_site(site_id, now)) {
        Ok(BreakerState::Closed) => "closed",
        Ok(BreakerState::Open) => "open",
        Ok(BreakerState::HalfOpen) => "halfOpen",
        Err(_) => "unknown",
    }
}

/// Unix 秒（墙钟；只用于「最近错误发生在什么时候」这类展示，不参与任何判定）。
fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn record_success(state: &AppState, key: &BreakerKey, now: Instant) {
    if let Ok(mut guard) = state.breaker.lock() {
        guard.record_success(key, now);
    }
}

/// 记一次失败：更新熔断，并通过注入出口上报**只有元数据**的事件。
///
/// 出口是 `Option<Arc<dyn Fn>>`：网关不该为了记一条事件而拿到整个存储层；
/// 也让测试能把事件捕获到 `Vec` 里**逐字段**断言白名单。
fn report_failure(
    state: &AppState,
    key: &BreakerKey,
    site_id: i64,
    status: u16,
    model: &str,
    reason: &str,
    now: Instant,
) {
    // M40-S2：失败原因落到内存指标（scrub + 截断在 `record_failure` 里）；
    // **事件表照旧只由 `on_failure` 出口写**，指标路径不写事件。
    state.metrics.record_failure(site_id, status, reason);
    if let Ok(mut guard) = state.breaker.lock() {
        guard.record_failure(key, now);
    }
    report_event_only(state, site_id, status, model, reason);
}

/// 记一次**配置类**失败：记指标 + 上报事件，**不喂熔断**（B-224 P2 修复）。
///
/// 与 [`report_failure`] 的唯一区别就是不碰熔断：缺明文 / 已回收这类本地
/// 配置问题不是上游故障，喂熔断会把站点熔断、进而影响后续正常请求。
/// 指标仍要记（`record_failure` 现在只记失败元数据、不加尝试数），
/// 否则这类失败在指标里完全不可见。
#[allow(clippy::too_many_arguments)]
fn report_failure_without_breaker(
    state: &AppState,
    site_id: i64,
    status: u16,
    model: &str,
    reason: &str,
) {
    state.metrics.record_failure(site_id, status, reason);
    report_event_only(state, site_id, status, model, reason);
}

/// 只上报事件，**不喂熔断**（M16-S4 / P3-4）。
///
/// 用于**配置类**失败（例如 legacy 路径的密钥已被回收）：它不是上游故障，
/// 喂熔断会让「熔断」这个信号失去意义（下一次启动的熔断状态会被一次本地配置问题污染）。
fn report_event_only(state: &AppState, site_id: i64, status: u16, model: &str, reason: &str) {
    if let Some(sink) = &state.config.on_failure {
        sink(GatewayFailure {
            site_id,
            status,
            // **在值被创造的地方脱敏**（M7-S1 复审 P1-1）：`model` 与 `reason` 都是调用方
            // 自由文本，可以是任何字符串——包括一把 `sk-…`。出口 `store.insert_event`
            // 原样入库，所以脱敏不能推给下游。
            //
            // 边界：模型名**整体**就是一把密钥时（`sk-…`），`scrub` 会把整条打掉，
            // 事件里只剩 `sk-…`——那是对的取舍（密钥绝不能外流；而那种情况下
            // 「这是哪个模型」本来也没有可用信息）。正常的模型名（`gpt-5.6`）原样通过。
            model: crate::redact::scrub(model),
            reason: crate::redact::scrub(reason),
        });
    }
}

/// 一次上游尝试的失败，按「上游是否**可能已经接受**了请求」分类（M16-S4 / P2-13）。
///
/// 这是**计费安全**的分类，不是错误类型的分类——它只回答一个问题：
/// 这次失败**能不能**把同一个请求再发给下一个上游而不产生重复计费。
///
/// - [`AttemptFailure::NotAccepted`]：连接层失败（DNS / TCP / TLS / 连接超时）。
///   请求连会话都没建立起来，上游不可能处理它 ⇒ **重放安全**。
/// - [`AttemptFailure::Ambiguous`]：其余（读超时、响应途中被重置、请求构造失败…）。
///   请求可能已经送达并被处理（上游超时后仍可能跑完计费）⇒ **不重放**。
enum AttemptFailure {
    NotAccepted(String),
    Ambiguous(String),
}

impl AttemptFailure {
    fn message(&self) -> &str {
        match self {
            AttemptFailure::NotAccepted(message) | AttemptFailure::Ambiguous(message) => message,
        }
    }

    /// 这次失败能不能重放到下一个上游。
    fn is_replayable(&self) -> bool {
        matches!(self, AttemptFailure::NotAccepted(_))
    }
}

/// 把 `reqwest` 的发送错误分成「上游没收到请求」与「无法判定」（P2-13）。
///
/// `is_connect()` 覆盖连接阶段的失败：DNS 解析、TCP 握手、TLS 握手，以及
/// `connect_timeout` 超时——这些情况下请求体一个字节都没进上游的处理流程。
/// 读超时（`read_timeout`，即「已连上但等不到响应头」）**不**算：那说明请求已经送出去了。
fn classify_send_error(e: &reqwest::Error) -> AttemptFailure {
    let message = format!("转发到上游失败: {e}");
    if e.is_connect() {
        AttemptFailure::NotAccepted(message)
    } else {
        AttemptFailure::Ambiguous(message)
    }
}

/// 收到响应码之后还能不能重放（M16-S4 / P2-13 的裁定）。
///
/// **只有 429** 算「上游明确没处理这个请求」：限流是在进入模型处理**之前**被拒的，
/// 重放不产生计费，也保住了 FR-5:160 的可见行为（用户看到换了站继续跑）。
///
/// 其余 5xx（含 524 / 504 这类**上游可能已经跑完并计费**的超时）一律不重放：
/// 重复计费不可逆，而可用性由「熔断 → 下一个请求换上游」承接。
/// 4xx 里除 429 外本来就 `should_failover == false`，走不到这里。
fn status_allows_replay(status: u16) -> bool {
    status == 429
}

/// 从请求体里**尽力**取出 `model`。取不到返回 `None`，不报错——
/// `GET /v1/models` 本来就没有 body，那不是一个错误。
fn model_from_body(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get("model")?.as_str().map(|s| s.to_string())
}

/// 别名命中时，**只**替换顶层 `"model"` 的字符串值，其余字节一个不动。
///
/// 为什么不整份重序列化：那会改掉无关字段的形态（`1.50` → `1.5`、转义规范化），
/// 与 BACKLOG B-45 的既有取舍同一理由。未命中别名时直接返回原 body。
fn rewrite_model(body: &[u8], model: &str, route: &RouteTable) -> bytes::Bytes {
    let real = route.resolve_model(model);
    if real == model {
        return bytes::Bytes::copy_from_slice(body);
    }
    let Some((start, end)) = top_level_model_span(body) else {
        return bytes::Bytes::copy_from_slice(body);
    };
    let mut out = Vec::with_capacity(body.len() + real.len());
    out.extend_from_slice(&body[..start]);
    // 用 JSON 字面量写回：`real` 里可能有需要转义的字符
    out.extend_from_slice(serde_json::Value::String(real).to_string().as_bytes());
    out.extend_from_slice(&body[end..]);
    bytes::Bytes::from(out)
}

/// 在**顶层**对象里找到 `"model"` 键的字符串值区间（含两侧引号）。
///
/// 只认顶层：嵌套对象里的 `model`（例如某个工具的参数 schema）不是我们要改的那个。
/// 键名不做转义解码——`"\u006dodel"` 这种写法不会被识别，但真实客户端不会那么写。
///
/// **重复键不保证**（M7-S1 复审 P2-2）：本函数取**第一个** `"model"`，而
/// [`model_from_body`] 走 serde、serde 对重复键**最后一个胜出**。于是
/// `{"model":"a","model":"b"}` 这种畸形 body 会出现「按 `b` 选路、却把第一个 `a` 改写」
/// 的不一致。**不改行为**：重复顶层键的 body 不是任何真实客户端会发出的东西，
/// 而为它引入一套「重复键感知」的改写逻辑，复杂度远大于收益。
/// 已知后果仅限「别名静默失效」（不改写、不损坏、不泄漏）。
fn top_level_model_span(body: &[u8]) -> Option<(usize, usize)> {
    let mut depth = 0i32;
    let mut i = 0usize;
    while i < body.len() {
        match body[i] {
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth -= 1;
                i += 1;
            }
            b'"' => {
                let end = scan_string_end(body, i)?;
                if depth == 1 && &body[i + 1..end - 1] == b"model" {
                    let mut j = end;
                    while j < body.len() && body[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if body.get(j) == Some(&b':') {
                        j += 1;
                        while j < body.len() && body[j].is_ascii_whitespace() {
                            j += 1;
                        }
                        if body.get(j) == Some(&b'"') {
                            return Some((j, scan_string_end(body, j)?));
                        }
                    }
                }
                i = end;
            }
            _ => i += 1,
        }
    }
    None
}

/// 读一个 JSON 字符串字面量的**结束下标**（`start` 处必须是 `"`）。
///
/// 只需要区间、不需要解码内容，所以转义一律按两字节跳过（`\uXXXX` 会多跳 4 字节）。
fn scan_string_end(body: &[u8], start: usize) -> Option<usize> {
    if body.get(start) != Some(&b'"') {
        return None;
    }
    let mut i = start + 1;
    while i < body.len() {
        match body[i] {
            b'\\' => {
                // `\uXXXX` 里的 4 个 hex 也走这条；`i += 2` 之后循环会继续正常推进
                i += 2;
            }
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// 生成一个本地网关令牌。
///
/// **P2-6**：用 OS 密码学随机源（`getrandom`），不是 `sha256(nanos+pid)`——
/// 后者在已知 pid 和大致时间时可在约 29ms 内离线算出（DEBUG-REPORT-v3 P2 #6）。
/// M8-S4 起令牌跨重启持久化（长期有效），可预测性风险被放大，必须不可预测。
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS 随机源不可用，无法生成安全网关令牌");
    let digest = crate::inject::sha256_hex(&bytes);
    format!("kr-gw-{}", &digest[..32])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M46-S2：成功样本喂 EWMA，且快照携带同一值；失败尝试不写 EWMA。
    #[test]
    fn measured_latency_feeds_ewma_and_snapshot() {
        let metrics = GatewayMetrics::new();
        assert!(metrics.ewma_latency_map().is_empty());
        metrics.record_measured_latency(7, 200);
        metrics.record_measured_latency(7, 200);
        metrics.record_measured_latency(7, 0);
        // 200 → 200 → 0.2×0 + 0.8×200 = 160。
        let map = metrics.ewma_latency_map();
        assert_eq!(map.len(), 1);
        assert!(
            (map[&7] - 160.0).abs() < 1e-9,
            "EWMA 应为 160，实测 {:?}",
            map.get(&7)
        );
        let snap = metrics.snapshot();
        assert_eq!(snap.per_site[&7].ewma_latency_ms, Some(160.0));
        // record_attempt 不写 EWMA：只被尝试过（失败）的站 EWMA 仍为 None。
        metrics.record_attempt(9, 200, 33);
        let snap = metrics.snapshot();
        assert_eq!(snap.per_site[&9].ewma_latency_ms, None);
        assert_eq!(snap.per_site[&9].last_latency_ms, Some(33));
    }

    /// M40-S2 复审 P1：`lastError` 不得带 URL/域名，且仍保留分类与状态码。
    #[test]
    fn metric_error_strips_urls_and_secrets() {
        let reason = "传输层失败（不可重放）: 转发到上游失败: error sending request for url (https://relay.example.com/v1/chat/completions?key=sk-secret-0123456789abcdef)";
        let cleaned = sanitize_metric_error(reason);
        assert!(!cleaned.contains("relay.example.com"), "{cleaned}");
        assert!(!cleaned.contains("https://"), "{cleaned}");
        assert!(cleaned.contains("<url>"), "{cleaned}");
        assert!(cleaned.contains("传输层失败"), "{cleaned}");
        assert!(!cleaned.contains("sk-secret"), "{cleaned}");
    }

    /// M40-S2 P2-3（B-224 待验证项，实测属实后修复）：QPS 环必须是
    /// 滑动窗口——连续流量跨过 60s 边界时，60s 内的样本不得被整环清零。
    #[test]
    fn qps_ring_is_sliding_not_tumbling_across_the_60s_boundary() {
        use std::time::Duration;
        let t0 = Instant::now();
        let mut ring = QpsRing::default();
        for _ in 0..10 {
            ring.bump(t0);
        }
        for _ in 0..10 {
            ring.bump(t0 + Duration::from_secs(30));
        }
        // 连续流量：t0 的 10 次在 t0+61 时已过期（>60s），但 t0+30 的
        // 10 次仍在窗口内 ⇒ 和为 10，分母 clamp 到 60。
        for _ in 0..10 {
            ring.bump(t0 + Duration::from_secs(61));
        }
        let qps = ring.qps_at(t0 + Duration::from_secs(61));
        assert!(
            (qps - 20.0 / 60.0).abs() < 1e-9,
            "滑动窗口下 t0+61 的 QPS 应为 20/60，实测 {qps}（翻滚实现会清零到 10/60 以下）"
        );
    }

    #[test]
    fn qps_ring_resets_after_a_full_idle_window() {
        use std::time::Duration;
        let t0 = Instant::now();
        let mut ring = QpsRing::default();
        ring.bump(t0);
        // 空闲 ≥60s 后再来：旧样本全部过期，起点重置，<3s 内仍按
        // 样本不足判 0（与 M40-S2 §6.3 的守则一致）。
        ring.bump(t0 + Duration::from_secs(120));
        assert_eq!(ring.qps_at(t0 + Duration::from_secs(120)), 0.0);
        ring.bump(t0 + Duration::from_secs(121));
        let qps = ring.qps_at(t0 + Duration::from_secs(124));
        assert!(
            (qps - 2.0 / 4.0).abs() < 1e-9,
            "空闲重置后窗口应只含新样本：2/4，实测 {qps}"
        );
    }

    /// 无 URL 的原因原样保留（除了 scrub 既有规则）。
    #[test]
    fn metric_error_keeps_plain_reason() {
        let cleaned = sanitize_metric_error("上游返回 HTTP 500（可能已计费）");
        assert_eq!(cleaned, "上游返回 HTTP 500（可能已计费）");
    }

    /// M9-S3 §5：`connect` 有真实站点标定，取值来自实测上界 1.15s + 约 4.3 倍余量。
    ///
    /// 等值断言之外再钉上下界与上界，让「无据的取值」自己撞上来。
    /// 下界守「不能低于实测上界，否则正常站点被判连接失败」；
    /// 上界守「不能大到失去连接卡死时快速切换的意义」。
    ///
    /// **上界取 5s 而不是 10s，是 M9-S3 复审 F-1 的直接后果**：先前的版本写的是
    /// `connect <= 10s`，而实测证明 `10s` 本身满足 `> 1150ms`——于是
    /// 「本步判定为无据、正要改掉的那个值」能两条边界全绿地通过，
    /// 这套边界因此没有独立价值，只是 `assert_eq!` 的复读。
    /// 上界收紧到与标定值同档后，边界才成为真守卫：反例由
    /// [`the_bounds_reject_the_very_value_this_step_replaced`] 固化。
    #[test]
    fn connect_timeout_is_calibrated_against_the_real_site_handshake() {
        let t = UpstreamTimeout::default();
        assert_eq!(
            t.connect,
            Duration::from_secs(5),
            "M9-S3 §3.2 实测 TCP 3.6–4.1ms + TLS 532–1145ms；\
             上界约 1.15s，取 5s 留约 4.3 倍余量"
        );
        assert!(
            t.connect > Duration::from_millis(1150),
            "connect 必须盖住实测 TLS 上界 1145ms，否则正常站点被判连接失败"
        );
        assert!(
            t.connect <= Duration::from_secs(5),
            "connect 上界与标定值同档；放大到 10s 会退回 M9-S3 判定的『无据』取值"
        );
    }

    /// M9-S3 复审 F-1：上界必须**自己**拦得住本步替换掉的那个值。
    ///
    /// 前一个版本的上界写成 `<= 10s`，于是 `10s`（本步判定无据并改掉的值）
    /// 同时满足 `> 1150ms` 与 `<= 10s`，两条边界全绿——边界形同复读 `assert_eq!`。
    /// 这条测试把那个反例固化成判据：**边界集合对 `10s` 必须为空**。
    ///
    /// 写的是「取样几个值逐个判定」而不是再抄一遍边界表达式：后者会跟着
    /// 实现一起改，永远绿；前者是独立重述「哪些取值可接受」。
    #[test]
    fn the_bounds_reject_the_very_value_this_step_replaced() {
        let t = UpstreamTimeout::default();
        // 逐个取值判定，与上面那条测试的边界表达式**故意不同形**，
        // 这样实现被改动时不会两条一起悄悄失效。
        let accepted = |c: Duration| c > Duration::from_millis(1150) && c <= Duration::from_secs(5);
        assert!(
            !accepted(Duration::from_secs(10)),
            "10s 正是 M9-S3 判定『无据』并替换掉的值，边界必须拒绝它"
        );
        assert!(
            !accepted(Duration::from_secs(6)),
            "超过标定值一档即视为失去『连接卡死时快速切换』的意义"
        );
        assert!(
            accepted(Duration::from_secs(5)) && accepted(t.connect),
            "标定值 5s 必须落在可接受区间内"
        );
    }

    /// M46-S4：分站超时解析——替代不是取 min；Some(0) ≡ 未填；两维同值。
    #[test]
    fn effective_upstream_timeout_replaces_both_dimensions_not_min() {
        let global = UpstreamTimeout {
            connect: Duration::from_secs(5),
            read: Duration::from_secs(240),
        };
        // 未填 ⇒ 全局本身（不是 0、不是默认值）。
        assert_eq!(effective_upstream_timeout(global, None), global);
        // Some(0) ≡ 未填（0 毫秒的超时永远不可能成功，见函数注释）。
        assert_eq!(effective_upstream_timeout(global, Some(0)), global);
        // 分站值同时作用于 connect 与 read 两维。
        let small = effective_upstream_timeout(global, Some(50));
        assert_eq!(small.connect, Duration::from_millis(50));
        assert_eq!(small.read, Duration::from_millis(50));
        // 分站值大于全局 ⇒ 全局不得提前掐断：两维均为分站值，不是 min(全局, 分站)。
        let big = effective_upstream_timeout(global, Some(30_000));
        assert_eq!(big.connect, Duration::from_secs(30));
        assert_eq!(big.read, Duration::from_secs(30));
        // 区分「替代」与「逐维取 min」的关键在 connect：取 min 会给出 5s
        // （全局 connect），替代给出 30s（分站值）。上面两条 assert_eq 已钉住 30s。
        assert_ne!(
            big.connect, global.connect,
            "分站值 30s > 全局 connect 5s 时，生效 connect 必须是 30s 而非全局的 5s"
        );
    }

    /// M9-S3 §5 判据 4：`read` 刻意比 `connect` 大至少一个数量级。
    ///
    /// 两者的语义不同，混用会让**合法的长流式补全被误杀**：
    /// `connect` 是握手容忍（TCP+TLS，实测约 1.15s 上界），
    /// `read` 是停顿容忍（多久没有新字节，实测同端点抖动到 6.30s 且仍属正常）。
    /// 若有人把 `read` 调到接近 `connect` 的量级，流式响应会在传输中途被判超时，
    /// 而网关随后切下一个上游重发——**同一个请求可能被计费两次**。
    #[test]
    fn read_timeout_stays_at_least_an_order_of_magnitude_above_connect() {
        let t = UpstreamTimeout::default();
        assert!(
            t.read >= t.connect * 10,
            "read({:?}) 必须远大于 connect({:?})：前者容停顿、后者容握手，\
             混用会杀死合法的长流式补全并导致重复计费",
            t.read,
            t.connect
        );
    }

    /// M9-S5：`read` 用真实上游补全标定过（B-124 关闭）。
    ///
    /// 非流式 gpt-6-astra 难题实测 TTFB = 49/63/92/95/101s + 1 发 >120s（curl 砍）。
    /// 这是 read 的真正约束——中转站等模型全做完才吐字节，合法「无字节期」最大 100.7s、
    /// 重尾 >120s。`read = 240s = 2× 重尾 = 约 2.4× 观测最大`。
    ///
    /// 边界集用命名常量表达实测上界，让「调小到杀合法请求」自己撞上来：
    /// 下界 `read >= 2 × OBSERVED_FIRST_BYTE_MAX`——低于它就把观测到的 100.7s 合法请求
    /// 判进 <2× 余量区，风险不对称里更坏的那一侧（杀合法请求 > 慢 failover）。
    /// 上界 `read <= 300s`——超过旧值没有数据支持，且让卡死上游 failover 更慢。
    /// `assert_eq!(240s)` 是主守卫；两条边界是它在「有人故意放松等值」时仍守住语义的反例。
    #[test]
    fn read_timeout_is_calibrated_against_real_upstream_first_byte() {
        // 非流式 gpt-6-astra 难题实测的最大成功 TTFB（M9-S5 §3）。
        // 100.7s 四舍五入到 101s，作为「已观测到的合法无字节期上界」。
        const OBSERVED_FIRST_BYTE_MAX: Duration = Duration::from_secs(101);
        let t = UpstreamTimeout::default();
        assert_eq!(
            t.read,
            Duration::from_secs(240),
            "M9-S5 实测：非流式首字节最大 100.7s、重尾 >120s；240s = 2× 重尾"
        );
        assert!(
            t.read >= OBSERVED_FIRST_BYTE_MAX * 2,
            "read({:?}) 必须 >= 2× 观测最大首字节({:?})：低于它就把 100.7s 的合法慢推理\
             判进 <2× 余量区——风险不对称里杀合法请求比慢 failover 更坏",
            t.read,
            OBSERVED_FIRST_BYTE_MAX * 2
        );
        assert!(
            t.read <= Duration::from_secs(300),
            "read({:?}) 不得超过旧值 300s：超过它没有数据支持，且让卡死上游 failover 更慢",
            t.read
        );
    }

    /// M9-S5 复审守卫（对应 M9-S3 的 F-1 教训）：边界必须**自己**拦得住「判它无据的取值」，
    /// 且必须**读实际值**——否则只是对一个内联闭包做算术，`read` 字段改成什么它都绿
    ///（M9-S5 复审 P2-1）。
    ///
    /// 180s 是本步判定「会把 >120s 重尾的合法请求判死」而**不**采用的取值
    ///（1.8× 观测最大，但只有 60s 余量给重尾）。360s 则是「超过旧值 300s、无数据支持」的一档。
    /// 两者都必须被区间排除。与上一条测试**故意不同形**（闭包逐值判定 + 读实际值，
    /// 而非 assert_eq!），避免实现被改时两条一起悄悄失效。
    #[test]
    fn read_timeout_bounds_reject_values_this_step_rejected() {
        let t = UpstreamTimeout::default();
        let accepted = |r: Duration| r >= Duration::from_secs(202) && r <= Duration::from_secs(300);
        // 钉住实际值落在数据支持区间内——这是它对 `read` 字段的独立守卫。
        // read=180s 或 360s 时这一条会红（accepted 返回 false），与 assert_eq!(240s) 互补。
        assert!(
            accepted(t.read),
            "read({:?}) 必须落在数据支持区间 [202s, 300s] 内：低于 202s 把观测到的 100.7s\
             合法请求判进 <2× 余量区，高于 300s 无数据支持",
            t.read
        );
        assert!(
            !accepted(Duration::from_secs(180)),
            "180s = 1.8× 观测最大，重尾余量不足，本步判定为『会杀合法请求』而不采用"
        );
        assert!(
            !accepted(Duration::from_secs(360)),
            "360s 超过旧值 300s、无数据支持，本步判定为『无据放大』而不采用"
        );
    }

    #[test]
    fn generated_tokens_are_unique_and_prefixed() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
        assert!(a.starts_with("kr-gw-"));
        assert_eq!(a.len(), "kr-gw-".len() + 32);
    }

    #[test]
    fn config_debug_hides_the_token_and_key() {
        let config = GatewayConfig::single_upstream(
            8787,
            "kr-gw-SECRET-TOKEN".into(),
            "https://relay.example.com".into(),
            Zeroizing::new("sk-SECRET-KEY".to_string()),
            "测试站".into(),
        );
        let text = format!("{config:?}");
        assert!(!text.contains("SECRET-TOKEN"), "{text}");
        assert!(!text.contains("SECRET-KEY"), "{text}");
        assert!(text.contains("8787"), "{text}");
    }

    /// M7-S1 章程 v1.1 的硬化要求：`keys_by_ref` 是**明文密钥的 map**，
    /// 手写 `Debug` 必须不打印它（先例：`site/mod.rs::session_debug_hides_secrets`）。
    #[test]
    fn config_debug_hides_the_key_map() {
        let mut config = GatewayConfig::single_upstream(
            8787,
            "kr-gw-token".into(),
            "https://relay.example.com".into(),
            Zeroizing::new("sk-legacy-key".to_string()),
            "测试站".into(),
        );
        config.keys_by_ref.insert(
            "kr/key/1/secret".to_string(),
            Zeroizing::new("sk-MAP-SECRET-0123456789".to_string()),
        );
        // 顺手把闭包出口也装上：它同样不该在 Debug 里出现
        config.on_failure = Some(Arc::new(|_| {}));

        let text = format!("{config:?}");
        assert!(!text.contains("MAP-SECRET"), "{text}");
        assert!(!text.contains("sk-"), "{text}");
        assert!(!text.contains("keys_by_ref"), "{text}");
        assert!(!text.contains("on_failure"), "{text}");
        // 有用的诊断信息仍在
        assert!(text.contains("8787"), "{text}");
    }

    #[test]
    fn presented_token_reads_both_headers() {
        let mut headers = HeaderMap::new();
        assert_eq!(presented_token(&headers), None);

        headers.insert("authorization", HeaderValue::from_static("Bearer abc"));
        assert_eq!(presented_token(&headers).as_deref(), Some("abc"));

        headers.insert("x-tianshu-relay-token", HeaderValue::from_static("xyz"));
        assert_eq!(
            presented_token(&headers).as_deref(),
            Some("xyz"),
            "专用头优先于 Authorization"
        );

        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Basic abc"));
        assert_eq!(presented_token(&headers), None, "非 Bearer 不认");

        // M35-S1：旧版专用头兼容一个版本（已投递的本地网关客户端不会升级后立刻 401）。
        let mut legacy = HeaderMap::new();
        legacy.insert("x-keyrelay-token", HeaderValue::from_static("old-xyz"));
        assert_eq!(presented_token(&legacy).as_deref(), Some("old-xyz"));
    }

    #[test]
    fn presented_token_accepts_bearer_case_insensitively_and_trims() {
        // P3-6：Bearer scheme 大小写不敏感（不只认 "Bearer"/"bearer"）；
        // x-tianshu-relay-token 也要 trim（与 Bearer 路径同口径）。
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("BEARER abc"));
        assert_eq!(presented_token(&headers).as_deref(), Some("abc"));

        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("BeArEr abc"));
        assert_eq!(presented_token(&headers).as_deref(), Some("abc"));

        // 令牌前后空白要 trim
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer  abc "));
        assert_eq!(presented_token(&headers).as_deref(), Some("abc"));

        // x-tianshu-relay-token 也 trim
        let mut headers = HeaderMap::new();
        headers.insert("x-tianshu-relay-token", HeaderValue::from_static("  xyz  "));
        assert_eq!(presented_token(&headers).as_deref(), Some("xyz"));
    }

    #[test]
    fn constant_time_eq_is_correct() {
        // P3-6：相等 ⇒ true；不等 ⇒ false；长度不同 ⇒ false。
        assert!(constant_time_eq(Some("abc"), "abc"));
        assert!(!constant_time_eq(Some("abc"), "abd"));
        assert!(!constant_time_eq(Some("abc"), "abcd"));
        assert!(!constant_time_eq(Some("abcd"), "abc"));
        assert!(!constant_time_eq(None, "abc"));
        assert!(!constant_time_eq(Some(""), "abc"));
        assert!(constant_time_eq(Some(""), ""));
    }

    #[test]
    fn path_traversal_forms_are_refused() {
        // M4-S2 复审 P1-1：这些形态到了上游都会被 `url` 规整成 `/admin`，
        // 从而绕过「只转发 /v1/*」
        for bad in [
            "/v1/../../admin",
            "/v1/a/../../admin",
            "/v1/%2e%2e/admin",
            "/v1/%2E%2E/admin",
            "/v1/..%2fadmin",
            "/v1/%252e%252e/admin",
            "/v1/./admin",
            "/v1/%2e/admin",
            "/v1/a%00b",
            "/v1/..\\admin",
        ] {
            assert!(!path_is_safe(bad), "「{bad}」必须被拒绝");
        }
    }

    #[test]
    fn normal_v1_paths_are_still_allowed() {
        for good in [
            "/v1",
            "/v1/",
            "/v1/chat/completions",
            "/v1/models",
            "/v1/a.b/c-d_e",
            "/v1/..hidden/ok",
            "/v1/embeddings?x=1",
        ] {
            assert!(path_is_safe(good), "「{good}」必须放行");
        }
    }

    #[test]
    fn credential_shaped_response_headers_are_stripped() {
        for name in [
            "set-cookie",
            "cookie",
            "authorization",
            "www-authenticate",
            "proxy-authenticate",
            "proxy-authorization",
            "X-Api-Key",
            "X-Auth-Token",
            "X-Upstream-Key",
            "x-session-id",
            // hop-by-hop：透传会和 hyper 的分帧叠成双重分帧
            "transfer-encoding",
            "connection",
            "keep-alive",
            "upgrade",
        ] {
            assert!(should_strip_response_header(name), "「{name}」必须被剥掉");
        }
        for name in [
            "content-type",
            "content-length",
            "x-request-id",
            "openai-processing-ms",
            // `tokens` 指的是词元数，不是凭证；客户端要靠它退避
            "x-ratelimit-limit-tokens",
            "x-ratelimit-remaining-requests",
        ] {
            assert!(!should_strip_response_header(name), "「{name}」不该被剥掉");
        }
    }

    #[test]
    fn credential_shaped_request_headers_are_not_forwarded() {
        for name in [
            "authorization",
            "X-Tianshu-Relay-Token",
            "X-KeyRelay-Token",
            "Cookie",
            "Proxy-Authorization",
            "Host",
            "Content-Length",
            "Connection",
            "Transfer-Encoding",
        ] {
            assert!(should_strip_request_header(name), "「{name}」不该转发");
        }
        for name in ["content-type", "accept", "user-agent", "x-request-id"] {
            assert!(!should_strip_request_header(name), "「{name}」该转发");
        }
    }

    #[tokio::test]
    async fn cap_stream_errors_on_the_byte_past_the_limit() {
        use futures_util::StreamExt as _;

        let chunk = |text: &'static str| {
            Ok::<_, std::io::Error>(bytes::Bytes::from_static(text.as_bytes()))
        };
        let stream = futures_util::stream::iter(vec![chunk("aaaa"), chunk("bbbb"), chunk("cccc")]);
        let mut capped = Box::pin(cap_stream(stream, 8));

        assert_eq!(
            capped.next().await.unwrap().unwrap(),
            bytes::Bytes::from_static(b"aaaa")
        );
        assert_eq!(
            capped.next().await.unwrap().unwrap(),
            bytes::Bytes::from_static(b"bbbb"),
            "正好用满上限仍然放行"
        );
        assert!(
            capped.next().await.unwrap().is_err(),
            "第 9 个字节必须让流报错，而不是继续吐"
        );
    }

    #[tokio::test]
    async fn cap_stream_passes_a_short_body_through_unchanged() {
        use futures_util::StreamExt as _;

        let stream = futures_util::stream::iter(vec![
            Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"hello ")),
            Ok(bytes::Bytes::from_static(b"world")),
        ]);
        let mut capped = Box::pin(cap_stream(stream, 1024));
        let mut collected = Vec::new();
        while let Some(item) = capped.next().await {
            collected.extend_from_slice(&item.unwrap());
        }
        assert_eq!(collected, b"hello world");
    }

    #[tokio::test]
    async fn refuses_an_empty_upstream_or_token() {
        let base = GatewayConfig::single_upstream(
            0,
            "t".into(),
            "https://x".into(),
            Zeroizing::new("k".to_string()),
            "s".into(),
        );
        assert!(start(GatewayConfig {
            base_url: "  ".into(),
            ..base.clone()
        })
        .await
        .is_err());
        assert!(start(GatewayConfig {
            token: "".into(),
            ..base
        })
        .await
        .is_err());
    }

    // ---- M5-S4：网关启停竞态（B-64）----

    /// 本组测试用的最小配置：不发任何请求，`base_url` 只要求非空。
    fn test_config(port: u16) -> GatewayConfig {
        GatewayConfig::single_upstream(
            port,
            "kr-gw-unit-test-token".into(),
            "http://127.0.0.1:1".into(),
            Zeroizing::new("sk-unit-test".to_string()),
            "单测站点".into(),
        )
    }

    /// 「真的等到监听套接字释放」的**确定性**证据。
    ///
    /// `#[tokio::test]` 默认是 `current_thread` 运行时：`shutdown_and_wait` 返回之后，
    /// 本测试里**没有任何 await**，所以服务任务只可能在 `shutdown_and_wait` 内部被推进。
    /// 若它只是「发个信号就返回」，服务任务在单线程运行时里根本没机会被调度、监听套接字
    /// 还开着，下面两条断言必红。
    /// M41-S1：四格分类（每一格都要有）。
    #[test]
    fn classify_gateway_exit_covers_all_four_cells() {
        assert_eq!(
            classify_gateway_exit(true, false),
            GatewayExitReason::Requested
        );
        assert_eq!(
            classify_gateway_exit(true, true),
            GatewayExitReason::Panicked,
            "停止过程中崩了仍按崩了算"
        );
        assert_eq!(
            classify_gateway_exit(false, true),
            GatewayExitReason::Panicked
        );
        assert_eq!(
            classify_gateway_exit(false, false),
            GatewayExitReason::Unexpected,
            "没让停却自己结束"
        );
        // DTO 字符串稳定
        assert_eq!(GatewayExitReason::Requested.as_str(), "requested");
        assert_eq!(GatewayExitReason::Panicked.as_str(), "panicked");
        assert_eq!(GatewayExitReason::Unexpected.as_str(), "unexpected");
    }

    /// M41-S1：`alive()` / `last_exit()` 跟踪任务生命周期（五格矩阵的 ①②）。
    #[tokio::test]
    async fn alive_and_last_exit_track_the_task_lifecycle() {
        let handle = start(test_config(0)).await.expect("网关应能启动");
        assert!(handle.alive(), "刚启动必须 alive");
        assert_eq!(handle.last_exit(), None, "活着时没有结束记录");
        let slot = handle.exit_slot();

        handle.shutdown_and_wait().await;

        let exit = slot
            .lock()
            .expect("结束记录槽可锁")
            .expect("停止后有结束记录");
        assert_eq!(exit.reason, GatewayExitReason::Requested);
        assert!(exit.at > 0, "结束时刻应为 unix 秒");
    }

    #[tokio::test]
    async fn shutdown_and_wait_releases_the_port_before_returning() {
        let handle = start(test_config(0)).await.expect("网关应能启动");
        let port = handle.addr.port();
        assert_ne!(port, 0, "内核应分配一个真实端口");

        handle.shutdown_and_wait().await;

        assert!(
            std::net::TcpStream::connect(("127.0.0.1", port)).is_err(),
            "shutdown_and_wait 返回后不该还有人在 {port} 上 accept"
        );
        let probe = std::net::TcpListener::bind(("127.0.0.1", port))
            .unwrap_or_else(|e| panic!("shutdown_and_wait 返回后端口 {port} 必须已可绑定: {e}"));
        drop(probe);
    }

    /// 对照组（同时也是「`shutdown()` 语义不变」的钉子）：在 `current_thread` 运行时里
    /// `shutdown()` 发完信号就返回，**此刻监听套接字还没释放**——这正是 B-64 的竞态窗口，
    /// 也正是 `shutdown_and_wait` 存在的理由。
    ///
    /// 与 `shutdown_and_wait_releases_the_port_before_returning` 合起来构成
    /// 「不等 vs 等」的确定性对照：两者只差一个 `await`，端口状态却相反。
    #[tokio::test]
    async fn shutdown_without_waiting_leaves_the_socket_bound_for_a_moment() {
        let handle = start(test_config(0)).await.expect("网关应能启动");
        let port = handle.addr.port();

        handle.shutdown(); // 只发信号，立即返回

        // 中间没有 await：单线程运行时里服务任务还没被调度到，端口仍被占着
        assert!(
            std::net::TcpListener::bind(("127.0.0.1", port)).is_err(),
            "shutdown() 返回时端口还没释放——这正是 B-64 的竞态窗口"
        );

        // 给服务任务机会跑完：端口最终必须释放（既有行为不变）
        let mut freed = false;
        for _ in 0..100 {
            if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
                freed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(freed, "shutdown() 之后端口 {port} 最终必须释放");
    }

    /// M42-S1 §7.1：信封形状（OpenAI 兼容）。
    #[test]
    fn local_error_shape_is_openai_compatible() {
        use axum::body::to_bytes;
        use axum::http::StatusCode;

        let response = local_error(
            StatusCode::UNAUTHORIZED,
            GatewayErrorKind::Authentication,
            "invalid_api_key",
            "缺少或错误的本地令牌",
        );
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let bytes = runtime
            .block_on(to_bytes(response.into_body(), 64 * 1024))
            .expect("读 body");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
        let err = value.get("error").expect("有 error");
        assert!(err.is_object(), "error 必须是对象，不是字符串: {value}");
        assert_eq!(err["type"], "authentication_error");
        assert_eq!(err["code"], "invalid_api_key");
        assert_eq!(err["message"], "缺少或错误的本地令牌");
        assert!(err["param"].is_null(), "param 必须是 null: {value}");
    }

    /// M42-S1 §7.1：四个 kind → OpenAI type 字符串。
    #[test]
    fn error_kind_maps_to_openai_types() {
        assert_eq!(
            GatewayErrorKind::InvalidRequest.as_str(),
            "invalid_request_error"
        );
        assert_eq!(
            GatewayErrorKind::Authentication.as_str(),
            "authentication_error"
        );
        assert_eq!(GatewayErrorKind::RateLimit.as_str(), "rate_limit_error");
        assert_eq!(GatewayErrorKind::Api.as_str(), "api_error");
    }

    /// 幂等：服务已经停了（接收端没了、任务已结束）时，
    /// `shutdown_and_wait` 必须立即返回，不 panic、不挂。
    ///
    /// M42-S1：停止信号从 `oneshot` 换成 `watch`（两个 listener 要共用一次停止），
    /// 所以这里按新的句柄形状构造。
    #[tokio::test]
    async fn shutdown_and_wait_on_an_already_stopped_server_returns() {
        let (tx, rx) = tokio::sync::watch::channel(false);
        drop(rx); // 接收端已消失：send 会失败，若实现里 unwrap 就会炸
        let finished = vec![tokio::spawn(async {})];
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("地址可解析");
        let handle = GatewayHandle {
            addr,
            addrs: vec![addr],
            ipv6: Ipv6State::Degraded {
                reason: "单测：未监听 v6".to_string(),
                kind: Ipv6DegradedKind::Unavailable,
            },
            token: "t".into(),
            site_display_name: "已停的站点".into(),
            shutdown: tx,
            finished,
            stopping: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            exit: Arc::new(std::sync::Mutex::new(None)),
            // M40-S2：测试用句柄的指标占位（不参与本用例断言）
            metrics: GatewayMetrics::new(),
            initial_route_is_empty: true,
            runtime: None,
            breaker: Arc::new(Mutex::new(Breaker::new(BreakerPolicy::default()))),
            route: RouteTable::default(),
            legacy_site_id: 0,
            legacy_key_id: None,

            tokens: Arc::new(std::sync::RwLock::new(Vec::new())),
        };
        handle.shutdown_and_wait().await;
    }

    /// 退避预算：首次 + `BIND_RETRY_ATTEMPTS` 次尝试，耗尽后返回**最后一次**的
    /// `AddrInUse` 错误，且实打实等满 `BIND_RETRY_ATTEMPTS × BIND_RETRY_DELAY`。
    #[tokio::test]
    async fn bind_retry_gives_up_after_the_budget_and_returns_the_last_error() {
        let mut calls = 0u32;
        let started = std::time::Instant::now();
        let err = bind_listener_with(12345, |_port| {
            calls += 1;
            async move {
                Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "Address already in use（单测注入）",
                ))
            }
        })
        .await
        .expect_err("一直 AddrInUse 时必须报错");
        let elapsed = started.elapsed();

        assert_eq!(
            calls,
            1 + BIND_RETRY_ATTEMPTS,
            "首次尝试 + {BIND_RETRY_ATTEMPTS} 次重试"
        );
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        assert!(
            elapsed >= BIND_RETRY_ATTEMPTS * BIND_RETRY_DELAY,
            "必须等满退避窗口（{BIND_RETRY_ATTEMPTS}×{BIND_RETRY_DELAY:?}，实测 {elapsed:?}）"
        );
    }

    /// 非 `AddrInUse`（这里是权限）：**一次**返回，不 sleep、不重试。
    ///
    /// 注入式闭包不会真的去绑 80 端口，所以这条测试与运行身份无关（root 下也成立）。
    #[tokio::test]
    async fn bind_retry_does_not_retry_a_non_addr_in_use_error() {
        let mut calls = 0u32;
        let started = std::time::Instant::now();
        let err = bind_listener_with(80, |_port| {
            calls += 1;
            async move {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "权限不足（单测注入）",
                ))
            }
        })
        .await
        .expect_err("非 AddrInUse 必须报错");
        let elapsed = started.elapsed();

        assert_eq!(calls, 1, "非 AddrInUse 不许重试");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            elapsed < BIND_RETRY_DELAY,
            "非 AddrInUse 不许 sleep（实测 {elapsed:?}）"
        );
    }

    /// 端口一释放就成功：失败两次 → 第三次拿到 listener，中间各退避一次。
    #[tokio::test]
    async fn bind_retry_succeeds_once_the_port_is_free() {
        let mut calls = 0u32;
        let started = std::time::Instant::now();
        let listener = bind_listener_with(0, |port| {
            calls += 1;
            let attempt = calls;
            async move {
                if attempt < 3 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        "还没释放（单测注入）",
                    ))
                } else {
                    tokio::net::TcpListener::bind(("127.0.0.1", port)).await
                }
            }
        })
        .await
        .expect("第三次必须成功");
        let elapsed = started.elapsed();

        assert_eq!(calls, 3, "前两次失败、第三次成功");
        assert!(listener.local_addr().expect("读到地址").ip().is_loopback());
        assert!(
            elapsed >= 2 * BIND_RETRY_DELAY,
            "两次失败之间各退避一次（实测 {elapsed:?}）"
        );
    }

    /// 文案：`AddrInUse` 要说清「端口 + 占用 + 实际端口号」并指出真实原因；
    /// **非** `AddrInUse` 不许再出现「占用」——旧实现那句「（端口可能被占用）」正是
    /// B-64 里误导用户的地方（旧实例其实已经停了）。
    #[test]
    fn bind_error_message_distinguishes_a_busy_port_from_other_failures() {
        let busy = std::io::Error::new(std::io::ErrorKind::AddrInUse, "Address already in use");
        let text = bind_error_message(8787, &busy);
        assert!(text.contains("端口"), "{text}");
        assert!(text.contains("占用"), "{text}");
        assert!(text.contains("8787"), "必须带实际端口号: {text}");
        assert!(
            text.contains("上一次网关"),
            "要指出真实原因（旧实例尚未释放），不能只说「可能被占用」: {text}"
        );

        let denied = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Permission denied");
        let text = bind_error_message(80, &denied);
        assert!(text.contains("80"), "非 AddrInUse 也要带端口号: {text}");
        assert!(
            !text.contains("占用"),
            "非 AddrInUse 不许说「被占用」（B-64 的误导文案就是它）: {text}"
        );
    }

    /// M16-S4 / P3-32（网关半）：`Bearer <key>` 的临时串必须是 `Zeroizing`。
    ///
    /// 这条测试的价值在**类型**：`bearer_value` 的返回类型一旦被改回裸 `String`，
    /// 下面的 `let value: Zeroizing<String>` 就编译不过——比 grep 源码更硬。
    #[test]
    fn the_bearer_value_is_zeroizing() {
        let value: Zeroizing<String> = bearer_value("sk-unit-test-0123456789");
        assert_eq!(value.as_str(), "Bearer sk-unit-test-0123456789");
    }

    /// 类型级检查：命令层（M5-S5）要在 `#[tauri::command] async fn` 里 await 它，
    /// 不是 `Send` 就编译不过。本测试不做任何运行期断言。
    #[test]
    fn shutdown_and_wait_future_is_send() {
        fn require_send<T: Send>(_: T) {}
        fn check(handle: GatewayHandle) {
            require_send(handle.shutdown_and_wait());
        }
        let _ = check as fn(GatewayHandle);
    }

    // ---- M13-S1：token 用量提取测试 ----

    #[test]
    fn extract_usage_from_json_finds_usage() {
        let body = br#"{"id":"chatcmpl-1","usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}"#;
        assert_eq!(extract_usage_from_json(body), Some((100, 50, 150)));
    }

    #[test]
    fn extract_usage_from_json_returns_none_when_missing() {
        let body = br#"{"id":"chatcmpl-1","choices":[]}"#;
        assert_eq!(extract_usage_from_json(body), None);
    }

    #[test]
    fn extract_usage_from_json_returns_none_on_invalid_json() {
        assert_eq!(extract_usage_from_json(b"not json"), None);
    }

    // ---------- M40-S1：用量采集（SSE 跨 chunk / Drop flush / 注入时钟） ----------

    use std::sync::atomic::{AtomicI64, Ordering as AtomicOrdering};

    /// 记录型 sink + 固定时钟的便捷构造。
    fn capture_for(
        stream: bool,
        now: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> (UsageCapture, Arc<Mutex<Vec<GatewayUsage>>>) {
        let log: Arc<Mutex<Vec<GatewayUsage>>> = Arc::new(Mutex::new(Vec::new()));
        let sink_log = Arc::clone(&log);
        let sink: Arc<dyn Fn(GatewayUsage) + Send + Sync> =
            Arc::new(move |usage| sink_log.lock().unwrap().push(usage));
        (
            UsageCapture::new(
                Some(sink),
                7,
                Some(42),
                "m".to_string(),
                200,
                123,
                2,
                stream,
                now,
            ),
            log,
        )
    }

    fn fixed_clock(at: i64) -> Arc<dyn Fn() -> i64 + Send + Sync> {
        Arc::new(move || at)
    }

    #[test]
    fn sse_usage_survives_chunk_split_mid_json() {
        let (mut capture, log) = capture_for(true, fixed_clock(1_700_000_000));
        capture.feed(b"data: {\"usa");
        assert!(log.lock().unwrap().is_empty(), "第一块还不成行，不能解析");
        capture
            .feed(b"ge\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\n");
        capture.flush();
        let log = log.lock().unwrap();
        assert_eq!(log.len(), 1, "跨包拼行后必须记一条");
        assert_eq!(
            (
                log[0].prompt_tokens,
                log[0].completion_tokens,
                log[0].total_tokens
            ),
            (10, 5, 15)
        );
        assert!(log[0].stream);
        assert_eq!(log[0].at, 1_700_000_000);
        assert_eq!(log[0].site_id, 7);
        assert_eq!(log[0].key_id, Some(42));
        assert_eq!(log[0].status, 200);
        assert_eq!(log[0].latency_ms, 123);
        assert_eq!(log[0].attempts, 2);
    }

    #[test]
    fn sse_usage_accepts_data_without_space_and_crlf() {
        let (mut capture, log) = capture_for(true, fixed_clock(1));
        capture.feed(b"data:{\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2,\"total_tokens\":3}}\r\n\r\n");
        capture.flush();
        let log = log.lock().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!((log[0].prompt_tokens, log[0].total_tokens), (1, 3));
    }

    #[test]
    fn sse_usage_takes_the_last_usage_and_ignores_done() {
        let (mut capture, log) = capture_for(true, fixed_clock(1));
        capture.feed(b"data: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}\n\n");
        capture.feed(b"data: {\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4,\"total_tokens\":7}}\n\n");
        capture.feed(b"data: [DONE]\n\n");
        capture.flush();
        let log = log.lock().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(
            (
                log[0].prompt_tokens,
                log[0].completion_tokens,
                log[0].total_tokens
            ),
            (3, 4, 7),
            "最后一个 usage 胜"
        );
    }

    #[test]
    fn sse_usage_after_done_is_ignored() {
        let (mut capture, log) = capture_for(true, fixed_clock(1));
        capture.feed(b"data: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}\n\n");
        capture.feed(b"data: [DONE]\n\n");
        // [DONE] 之后即便还有 usage 行，也不再解析（M40-S1 §4.3 规则 3）。
        capture.feed(b"data: {\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":9,\"total_tokens\":18}}\n\n");
        capture.flush();
        let log = log.lock().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].total_tokens, 2, "done 之后的 usage 必须被忽略");
    }

    #[test]
    fn sse_carry_drops_oversized_line_and_resyncs() {
        let (mut capture, log) = capture_for(true, fixed_clock(1));
        // 一条超长、无换行的片段 ⇒ carry 被清空并进入 discarding。
        capture.feed(&vec![b'x'; MAX_USAGE_CARRY_BYTES + 1]);
        assert!(log.lock().unwrap().is_empty(), "超限片段不得产生账目");
        // 下一个换行完成重同步；随后正常行仍能解析。
        capture.feed(b"\n");
        capture.feed(b"data: {\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":5,\"total_tokens\":9}}\n\n");
        capture.flush();
        let log = log.lock().unwrap();
        assert_eq!(log.len(), 1, "重同步后必须恢复解析");
        assert_eq!(log[0].total_tokens, 9);
    }

    #[tokio::test]
    async fn usage_capture_flushes_exactly_once_on_normal_end() {
        use futures_util::StreamExt;
        let (capture, log) = capture_for(true, fixed_clock(1));
        let chunks = vec![
            Ok::<_, std::io::Error>(bytes::Bytes::from_static(
                b"data: {\"usage\":{\"prompt_tokens\":2,",
            )),
            Ok(bytes::Bytes::from_static(
                b"\"completion_tokens\":3,\"total_tokens\":5}}\n\n",
            )),
        ];
        let capped = cap_stream_with_usage(futures_util::stream::iter(chunks), 1024, capture);
        let mut capped = Box::pin(capped);
        while capped.next().await.is_some() {}
        assert_eq!(log.lock().unwrap().len(), 1, "正常结束恰好 flush 一次");
    }

    #[tokio::test]
    async fn usage_capture_flushes_on_drop_mid_stream() {
        use futures_util::StreamExt;
        let (capture, log) = capture_for(true, fixed_clock(1));
        let chunks = vec![
            Ok::<_, std::io::Error>(bytes::Bytes::from_static(
                b"data: {\"usage\":{\"prompt_tokens\":2,",
            )),
            Ok(bytes::Bytes::from_static(
                b"\"completion_tokens\":3,\"total_tokens\":5}}\n\n",
            )),
            Ok(bytes::Bytes::from_static(b"data: {\"choices\":[]}\n\n")),
        ];
        let capped = cap_stream_with_usage(futures_util::stream::iter(chunks), 1024, capture);
        let mut capped = Box::pin(capped);
        // 读两块让 usage 成行（第二块带换行），随后 drop 模拟客户端断开。
        let _ = capped.next().await;
        let _ = capped.next().await;
        drop(capped);
        assert_eq!(
            log.lock().unwrap().len(),
            1,
            "断开时 Drop 必须 flush 已见 usage"
        );
    }

    #[test]
    fn usage_capture_never_double_flushes() {
        let (mut capture, log) = capture_for(false, fixed_clock(1));
        capture
            .feed(b"{\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2,\"total_tokens\":3}}");
        capture.flush();
        capture.flush();
        drop(capture);
        assert_eq!(log.lock().unwrap().len(), 1, "三路合计恰一次");
    }

    #[test]
    fn usage_capture_silent_when_no_usage_seen() {
        let (mut capture, log) = capture_for(true, fixed_clock(1));
        capture.feed(b"data: {\"choices\":[]}\n\n");
        capture.feed(b"data: [DONE]\n\n");
        capture.flush();
        drop(capture);
        assert!(log.lock().unwrap().is_empty(), "没有 usage 不得调用 sink");
    }

    #[test]
    fn usage_capture_uses_injected_clock() {
        let counter = Arc::new(AtomicI64::new(1_000));
        let c = Arc::clone(&counter);
        let now: Arc<dyn Fn() -> i64 + Send + Sync> =
            Arc::new(move || c.fetch_add(1, AtomicOrdering::SeqCst));
        let (mut capture, log) = capture_for(false, now);
        capture
            .feed(b"{\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}");
        capture.flush();
        assert_eq!(log.lock().unwrap()[0].at, 1_000, "at 必须来自注入时钟");
    }

    #[test]
    fn non_stream_usage_still_parses_from_body() {
        let (mut capture, log) = capture_for(false, fixed_clock(55));
        capture.feed(b"{\"id\":\"x\",\"usage\":{\"prompt_tokens\":7,");
        capture.feed(b"\"completion_tokens\":8,\"total_tokens\":15}}");
        capture.flush();
        let log = log.lock().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(
            (
                log[0].prompt_tokens,
                log[0].completion_tokens,
                log[0].total_tokens
            ),
            (7, 8, 15)
        );
        assert!(!log[0].stream);
        assert_eq!(log[0].at, 55);
    }

    // ---------- M16-S4 / P2-13：重放安全性的分类 ----------

    /// `status_allows_replay`：**只有 429** 算「上游没处理这个请求」。
    ///
    /// 这一格是计费决策的判据，逐值钉死：5xx（含 524 / 504 这类可能已经跑完计费的超时）
    /// 一律不许重放；429 是限流，发生在处理之前。
    #[test]
    fn only_429_allows_replay_after_a_status_code() {
        assert!(status_allows_replay(429), "429 = 限流，未进入处理 ⇒ 可重放");
        for status in [
            400u16, 401, 402, 403, 404, 408, 422, 499, 500, 502, 503, 504, 520, 524, 529,
        ] {
            assert!(
                !status_allows_replay(status),
                "{status} 可能已计费（或本就不该切换）⇒ 不许重放"
            );
        }
    }

    /// 连接被拒（端口没人听）⇒ `is_connect()` ⇒ **可重放**。
    ///
    /// 用 `127.0.0.1:1`：必然拒绝连接，不需要网络，也不会碰到任何真实站点。
    #[tokio::test]
    async fn a_refused_connection_is_classified_as_not_accepted() {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(500))
            .build()
            .expect("构造客户端");
        let err = client
            .get("http://127.0.0.1:1/v1/models")
            .send()
            .await
            .expect_err("127.0.0.1:1 上不该有服务");
        assert!(
            err.is_connect(),
            "前提：连接被拒时 reqwest 必须报 connect 错误（否则本分类的前提不成立）: {err:?}"
        );
        let failure = classify_send_error(&err);
        assert!(
            failure.is_replayable(),
            "连接层失败 ⇒ 请求未送达 ⇒ 必须可重放: {:?}",
            failure.message()
        );
    }

    /// 读超时（连上了、请求发出去了、等不到响应头）⇒ **不可重放**。
    ///
    /// 这是最容易写错的一格：`is_timeout()` 对连接超时与读超时**都为真**，
    /// 所以判据必须是 `is_connect()`，不是 `is_timeout()`。
    #[tokio::test]
    async fn a_read_timeout_is_classified_as_ambiguous() {
        // 一个只 accept、永不回包的假上游（本地回环，不联网）
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("绑定假上游");
        let addr = listener.local_addr().expect("读地址");
        let hold = tokio::spawn(async move {
            // 保持连接打开、不回任何字节；测试结束任务被 abort
            let mut sockets = Vec::new();
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                sockets.push(socket);
            }
        });

        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(500))
            .read_timeout(Duration::from_millis(150))
            .build()
            .expect("构造客户端");
        let err = client
            .get(format!("http://{addr}/v1/models"))
            .send()
            .await
            .expect_err("假上游不回包 ⇒ 必须读超时");
        assert!(err.is_timeout(), "前提：这一格必须是超时错误: {err:?}");
        assert!(
            !err.is_connect(),
            "前提：读超时**不是** connect 错误（否则这条用例证不到东西）: {err:?}"
        );
        let failure = classify_send_error(&err);
        assert!(
            !failure.is_replayable(),
            "请求可能已经送达并被处理 ⇒ 不许重放: {:?}",
            failure.message()
        );

        hold.abort();
    }
}
