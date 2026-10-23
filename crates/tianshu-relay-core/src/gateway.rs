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
use futures_util::TryStreamExt;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::routing::{should_failover, Breaker, BreakerPolicy, BreakerState, RouteTable, Upstream};

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

/// 请求体上限（与之前一致，只是抽成常量）。
const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;

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

/// 从一个 SSE chunk 的文本行里提取 `usage`（M13-S1）。
///
/// 扫描 chunk 里所有 `data:` 行，逐行尝试解析 JSON 并找 `usage`。
fn extract_usage_from_chunk(chunk: &[u8]) -> Option<(i64, i64, i64)> {
    let text = std::str::from_utf8(chunk).ok()?;
    for line in text.lines() {
        let line = match line.strip_prefix("data: ") {
            Some(s) => s,
            None => match line.strip_prefix("data:") {
                Some(s) => s,
                None => continue,
            },
        };
        if line.trim() == "[DONE]" {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(usage) = value.get("usage") {
                let prompt = usage.get("prompt_tokens").and_then(|v| v.as_i64());
                let completion = usage.get("completion_tokens").and_then(|v| v.as_i64());
                let total = usage.get("total_tokens").and_then(|v| v.as_i64());
                if let (Some(p), Some(c), Some(t)) = (prompt, completion, total) {
                    return Some((p, c, t));
                }
            }
        }
    }
    None
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
fn cap_stream_with_usage<S, E, F>(
    stream: S,
    limit: u64,
    on_complete: F,
) -> impl futures_util::Stream<Item = std::result::Result<bytes::Bytes, std::io::Error>>
where
    S: futures_util::Stream<Item = std::result::Result<bytes::Bytes, E>> + Send + 'static,
    E: std::fmt::Display + 'static,
    F: FnOnce(Vec<bytes::Bytes>) + Send + 'static,
{
    use std::sync::{Arc, Mutex};
    let collected: Arc<Mutex<Vec<bytes::Bytes>>> = Arc::new(Mutex::new(Vec::new()));
    let on_complete: Arc<Mutex<Option<F>>> = Arc::new(Mutex::new(Some(on_complete)));

    futures_util::stream::try_unfold(
        (Box::pin(stream), 0u64, collected, on_complete),
        move |(mut stream, sent, collected, on_complete)| async move {
            match stream.try_next().await {
                Ok(None) => {
                    let chunks = collected.lock().map(|g| g.clone()).unwrap_or_default();
                    if let Ok(mut guard) = on_complete.lock() {
                        if let Some(cb) = guard.take() {
                            cb(chunks);
                        }
                    }
                    Ok(None)
                }
                Ok(Some(chunk)) => {
                    let total = sent + chunk.len() as u64;
                    if total > limit {
                        return Err(std::io::Error::other(format!(
                            "上游响应体超过上限 {limit} 字节"
                        )));
                    }
                    if let Ok(mut guard) = collected.lock() {
                        if guard.len() >= 8 {
                            let drain_count = guard.len() - 7;
                            guard.drain(0..drain_count);
                        }
                        guard.push(chunk.clone());
                    }
                    Ok(Some((chunk, (stream, total, collected, on_complete))))
                }
                Err(e) => Err(std::io::Error::other(e.to_string())),
            }
        },
    )
}

#[derive(Clone)]
pub struct GatewayConfig {
    pub port: u16,
    /// 本地令牌。**不是**站点密钥。
    pub token: String,
    /// 绑定的站点 id（M13-S1）：用于 token 用量出口的 `site_id`。
    /// `single_upstream` 默认 `0`（legacy 兼容）。
    pub site_id: i64,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    pub site_id: i64,
    /// 调用方自由文本，**脱敏在值被创造的地方完成**（与 `GatewayFailure.model` 同口径）。
    pub model: String,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
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
            token,
            site_id: 0,
            base_url,
            api_key,
            site_display_name,
            route: RouteTable::default(),
            breaker: BreakerPolicy::default(),
            keys_by_ref: HashMap::new(),
            on_failure: None,
            upstream_timeout: UpstreamTimeout::default(),
            revoked_refs: None,
            on_observation: None,
            on_usage: None,
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

pub struct GatewayHandle {
    pub addr: SocketAddr,
    pub token: String,
    pub site_display_name: String,
    shutdown: oneshot::Sender<()>,
    /// 服务任务。`shutdown_and_wait` 等它结束；`shutdown()` 只是把它丢掉
    /// （drop 一个 `JoinHandle` 是 **detach**，不会 abort 任务——既有调用点的行为因此不变）。
    finished: tokio::task::JoinHandle<()>,
    /// 与 `AppState` 共享的「正在停止」标志（M16-S4 / P3-3）。
    stopping: Arc<std::sync::atomic::AtomicBool>,
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

    /// 停止网关并释放端口。幂等。
    ///
    /// **先置「正在停止」标志、再发信号**（M16-S4 / P3-3）：在途请求的下一次上游尝试
    /// 会看到标志并拒绝发起，不再把任何密钥发出去。
    pub fn shutdown(self) {
        self.stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = self.shutdown.send(());
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
        let _ = shutdown.send(());
        let _ = finished.await;
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

/// 启动网关。**只绑定 `127.0.0.1`**（配置里没有别的选项）。
pub async fn start(config: GatewayConfig) -> Result<GatewayHandle> {
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

    let mut builder = reqwest::Client::builder()
        // §3.5-2：上游**必须**有超时。没有它，一个接了连接却不回应的上游会让请求永远挂着，
        // 既不切下一个候选，也不喂熔断（实测：卡 8.5s、下一个上游收到 0 次、失败事件 0 条）。
        .connect_timeout(config.upstream_timeout.connect)
        .read_timeout(config.upstream_timeout.read);

    // M10-S2：上游客户端走解析后的代理（与站点适配器 transport 同一份 resolve_proxy）。
    // 校验复用 `proxy::validate_proxy_url`——非法代理在这里就 Err，不静默直连。
    if let Some(proxy_url) = config.upstream_proxy.as_deref() {
        crate::proxy::validate_proxy_url(proxy_url)?;
        let proxy = reqwest::Proxy::all(proxy_url.to_string()).map_err(|e| {
            Error::Transport(format!(
                "网关上游代理配置无效（{}），拒绝静默直连: {e}",
                crate::proxy::mask_proxy(proxy_url)
            ))
        })?;
        builder = builder.proxy(proxy);
    }

    let upstream = builder
        .build()
        .map_err(|e| Error::Transport(format!("构造网关的上游客户端失败: {e}")))?;

    // P3-3：停止闸门。`AppState` 与 `GatewayHandle` 共享同一个标志——
    // 句柄置位（停止信号发出之前），请求路径读取。
    let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let state = AppState {
        breaker: Arc::new(Mutex::new(Breaker::new(config.breaker.clone()))),
        config: config.clone(),
        upstream,
        stopping: Arc::clone(&stopping),
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

    let (tx, rx) = oneshot::channel::<()>();
    let finished = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await;
    });

    Ok(GatewayHandle {
        addr,
        token: config.token,
        site_display_name: config.site_display_name,
        shutdown: tx,
        finished,
        stopping,
    })
}

#[derive(Clone)]
struct AppState {
    config: GatewayConfig,
    upstream: reqwest::Client,
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

fn unauthorized(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({ "error": message })),
    )
        .into_response()
}

/// 网关**正在停止**时对「新的上游尝试」的统一拒绝（M16-S4 / P3-3）。
///
/// 为什么不是 502：这不是上游故障，是本地状态——文案必须说清，
/// 否则用户会去查一个没问题的上游。为什么是 503：请求此刻确实无法完成，
/// 但**重启网关后重试即可**（客户端按 5xx 处理即可）。
fn stopping_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(serde_json::json!({
            "error": "网关正在停止，不再向上游发起新请求；请重启网关后重试"
        })),
    )
        .into_response()
}

/// 网关是否正在停止（P3-3）。
fn is_stopping(state: &AppState) -> bool {
    state.stopping.load(std::sync::atomic::Ordering::SeqCst)
}

async fn health(State(state): State<AppState>, headers: HeaderMap) -> Response {
    // P3-6 / 复审 F1：与 `proxy` 同口径走 `constant_time_eq`——health 同样长期有效，
    // 同样可被计时侧信道探测令牌前缀，不该用 `!=` 提前返回。
    if !constant_time_eq(
        presented_token(&headers).as_deref(),
        state.config.token.as_str(),
    ) {
        return unauthorized("缺少或错误的本地令牌");
    }
    axum::Json(serde_json::json!({
        "ok": true,
        "site": state.config.site_display_name,
        "version": env!("CARGO_PKG_VERSION"),
    }))
    .into_response()
}

async fn proxy(State(state): State<AppState>, request: Request) -> Response {
    // ① 令牌校验：不通过就**不转发**
    if !constant_time_eq(
        presented_token(request.headers()).as_deref(),
        state.config.token.as_str(),
    ) {
        return unauthorized("缺少或错误的本地令牌");
    }

    let path = request.uri().path().to_string();
    let query = request
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();

    // ② 只转发 `/v1/*`，且路径里不许有「向上跳」的段
    if !path.starts_with("/v1/") && path != "/v1" {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "error": "网关只转发 /v1/*；健康检查用 /health"
            })),
        )
            .into_response();
    }
    if !path_is_safe(&path) || query.contains(['\r', '\n', '\0']) {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "error": "路径里含「向上跳」的段或控制字符，拒绝转发"
            })),
        )
            .into_response();
    }

    let method = request.method().clone();
    // 入站头先克隆一份：下面要按上游逐次重建（换 `Authorization`），
    // 但「丢掉带本地令牌的头」这条规则对每个上游都一样。
    let inbound = request.headers().clone();

    let body = match axum::body::to_bytes(request.into_body(), MAX_REQUEST_BYTES).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({ "error": format!("读取请求体失败: {e}") })),
            )
                .into_response()
        }
    };

    // M39-S1：**每请求只取一次**路由视图（克隆一次 `Arc<GatewaySnapshot>` 就放锁）。
    // 之后所有 route / keys_by_ref 的读取都走 `view`——否则会分叉成「一半按新路由、
    // 一半按旧路由」。`runtime == None` 时它借用 `config`，与加这个字段之前逐字相同。
    let view = state.config.view();

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
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    axum::Json(serde_json::json!({
                        "error": "这把密钥已被回收（可能刚做过一键轮换）；\
                                  请重启网关，让它读到新密钥"
                    })),
                )
                    .into_response();
            }
        }
        let url = format!("{}{}{}", state.config.base_url, path, query);
        let headers = upstream_headers(&state.config, &inbound, &state.config.api_key);
        return forward_to(&state, method, &url, headers, body).await;
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
        return (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "error": format!(
                    "没有可服务模型 {} 的上游",
                    model.as_deref().unwrap_or("(请求里未指定)")
                )
            })),
        )
            .into_response();
    }

    let now = Instant::now();
    let eligible = eligible_candidates(&state.breaker, &candidates, now);
    if eligible.is_empty() {
        // §9 第 2 条：**「一个候选都没发出去」也必须可见**。
        //
        // `status = 0` 是哨兵值（HTTP 里不存在 0），表示「没有任何上游返回过状态码」。
        // **不编一个 503**：那会让事件说谎——读者会以为某个上游真的返回了 503。
        // 文案必须写明原因，否则 0 会被误读成真实状态码。
        report_failure(
            &state,
            candidates[0].site_id,
            0,
            &model.clone().unwrap_or_default(),
            "所有候选上游都在熔断冷却中",
            Instant::now(),
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "error": "所有候选上游都在熔断冷却中，请稍后重试"
            })),
        )
            .into_response();
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
    let sendable: Vec<&Upstream> = eligible
        .iter()
        .copied()
        .filter(|u| is_sendable(&state, view.keys(), u))
        .collect();

    let mut last_error: Option<String> = None;
    let attempts = sendable.len();
    for (index, upstream) in sendable.iter().enumerate() {
        // P3-3：**每一次上游尝试之前**都查停止闸门——信号可能在上一次尝试期间发出。
        // 在途请求允许跑完**当前**这一次（无法安全中断一个已发出的请求），
        // 但绝不再发起新的：那会把下一个站点的密钥也发出去，而用户按下停止
        // 往往紧接着就要轮换/回收密钥。
        if is_stopping(&state) {
            return stopping_response();
        }
        let is_last = index + 1 == attempts;
        // 这里 `unwrap` 不会 panic：`sendable` 就是按同一个判据过滤出来的。
        // 但仍然写 `let Some(..) else` ——「过滤」与「取用」共用同一个函数
        // （`is_sendable`），所以两者不可能分叉。
        let Some(key) = view.keys().get(&upstream.key_ref) else {
            continue;
        };
        let url = format!("{}{}{}", upstream.base_url, path, query);
        let headers = upstream_headers(&state.config, &inbound, key);

        let started = Instant::now();
        match send_once(&state, method.clone(), &url, headers, outbound.clone()).await {
            Ok(response) => {
                let latency_ms = started.elapsed().as_millis() as u64;
                let status = response.status().as_u16();
                observe(
                    &state,
                    upstream.site_id,
                    latency_ms,
                    !should_failover(status),
                );
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
                        upstream.site_id,
                        status,
                        &event_model,
                        &reason,
                        Instant::now(),
                    );
                } else {
                    record_success(&state, upstream.site_id, Instant::now());
                }
                // M16-S4 / P2-13：**只有 429 才重放**（上游明确没处理这个请求）。
                // 其余状态码——含 5xx / 524 / 504 这类可能已经计费的——一律**原样返回**：
                // 重复计费不可逆，可用性由「熔断 → 下一个请求换上游」承接。
                // 不可切换的状态、或已经是最后一个候选 ⇒ 同样如实返回（不做 500 兜底）。
                if replayable && !is_last {
                    continue; // 丢掉这个 429，试下一个
                }
                return into_upstream_response(&state, response, upstream.site_id, &event_model);
            }
            Err(failure) => {
                let latency_ms = started.elapsed().as_millis() as u64;
                observe(&state, upstream.site_id, latency_ms, false);
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
            }
        }
    }

    // §10 第 2 条：**发不出去**的候选也要产生事件。
    //
    // 修复前它们静默 `continue`：若构造方忘了填 `keys_by_ref`（M7 审计 D-2），
    // 表现是「每个上游都跳过 → 502」，看起来像「故障切换不工作」，
    // 根因却是密钥映射空着——**没有任何线索**。
    //
    // **只在失败路径上报**（即上面那个 `for` 没有 `return`）。理由不是省事：
    // `report_failure` 同时**喂熔断**，而「某个候选被跳过」在请求**成功**时不是故障——
    // 若那时也上报，一个长期缺明文的候选会把熔断喂开，进而影响别的判断。
    // 契约的原话是「不得静默 **502**」，指的正是这条路径。
    //
    // 文案区分两种原因（缺明文 / 已回收），但**都不写 `key_ref` 原文**：
    // 引用本身是线索（M7-S0 §4.3 的红线）。
    for upstream in eligible
        .iter()
        .filter(|u| !is_sendable(&state, view.keys(), u))
    {
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
        report_failure(
            &state,
            upstream.site_id,
            status,
            &event_model,
            reason,
            Instant::now(),
        );
    }

    (
        StatusCode::BAD_GATEWAY,
        axum::Json(serde_json::json!({
            "error": last_error.unwrap_or_else(|| "所有候选上游都失败了".to_string())
        })),
    )
        .into_response()
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
) -> std::result::Result<reqwest::Response, AttemptFailure> {
    state
        .upstream
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
async fn forward_to(
    state: &AppState,
    method: axum::http::Method,
    url: &str,
    headers: HeaderMap,
    body: bytes::Bytes,
) -> Response {
    let model = model_from_body(&body).unwrap_or_default();
    match send_once(state, method, url, headers, body).await {
        Ok(response) => into_upstream_response(state, response, state.config.site_id, &model),
        Err(failure) => (
            StatusCode::BAD_GATEWAY,
            axum::Json(serde_json::json!({ "error": failure.message() })),
        )
            .into_response(),
    }
}

/// 回传：过滤掉敏感响应头 + **流式**回传（带上限）。
///
/// 流式的理由（M4-S2 复审 P1-2）：整段缓冲会让客户端等上游吐完才见到第一个字节，
/// 而且响应体没有上限。超过 [`MAX_RESPONSE_BYTES`] 时让流以错误结束、连接随之断开——
/// 此时响应头已经发出去了，改不了状态码，只能如实断流，不静默截断。
fn into_upstream_response(
    state: &AppState,
    upstream_response: reqwest::Response,
    site_id: i64,
    model: &str,
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
        let capped = cap_stream(upstream_response.bytes_stream(), MAX_RESPONSE_BYTES);
        return builder
            .body(Body::from_stream(capped))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    if !is_sse {
        // 非流式 2xx：读完 body，提取 usage，再回传
        let on_usage = state.config.on_usage.clone();
        let model_scrubbed = crate::redact::scrub(model).to_string();
        let capped = cap_stream_with_usage(
            upstream_response.bytes_stream(),
            MAX_RESPONSE_BYTES,
            move |chunks: Vec<bytes::Bytes>| {
                // 非流式：把所有 chunk 拼起来当 JSON 解析
                let combined: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
                if let Some((p, c, t)) = extract_usage_from_json(&combined) {
                    if let Some(sink) = &on_usage {
                        sink(GatewayUsage {
                            site_id,
                            model: model_scrubbed.clone(),
                            prompt_tokens: p,
                            completion_tokens: c,
                            total_tokens: t,
                        });
                    }
                }
            },
        );
        return builder
            .body(Body::from_stream(capped))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    // 流式 SSE 2xx：边转发边扫 chunk，流结束后提取最后的 usage
    let on_usage = state.config.on_usage.clone();
    let model_scrubbed = crate::redact::scrub(model).to_string();
    let capped = cap_stream_with_usage(
        upstream_response.bytes_stream(),
        MAX_RESPONSE_BYTES,
        move |chunks: Vec<bytes::Bytes>| {
            // 从最后一个 chunk 往前找
            for chunk in chunks.iter().rev() {
                if let Some((p, c, t)) = extract_usage_from_chunk(chunk) {
                    if let Some(sink) = &on_usage {
                        sink(GatewayUsage {
                            site_id,
                            model: model_scrubbed.clone(),
                            prompt_tokens: p,
                            completion_tokens: c,
                            total_tokens: t,
                        });
                    }
                    return;
                }
            }
        },
    );
    builder
        .body(Body::from_stream(capped))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// 跳过 `Open` 的候选；`HalfOpen` 只放**一个探针**（P2-8：跨请求共享，不只是单次
/// 调用内——否则冷却一过所有并发请求都会拿到同一个 HalfOpen 探针涌向坏上游）。
fn eligible_candidates<'a>(
    breaker: &Arc<Mutex<Breaker>>,
    candidates: &[&'a Upstream],
    now: Instant,
) -> Vec<&'a Upstream> {
    let Ok(mut guard) = breaker.lock() else {
        // 锁中毒：放行全部候选。可用性优先——一次 panic 不该让网关永久 503。
        return candidates.to_vec();
    };
    let mut out = Vec::with_capacity(candidates.len());
    for upstream in candidates {
        match guard.state(upstream.site_id, now) {
            BreakerState::Open => continue,
            BreakerState::HalfOpen => {
                // P2-8：第一个拿到探针的请求在 Breaker 里标记，其余并发请求看到标记
                // 即跳过。探针结果回来后由 record_success / record_failure 清除标记。
                if guard.try_take_half_open_probe(upstream.site_id, now) {
                    out.push(*upstream);
                }
            }
            BreakerState::Closed => out.push(*upstream),
        }
    }
    out
}

fn record_success(state: &AppState, site_id: i64, now: Instant) {
    if let Ok(mut guard) = state.breaker.lock() {
        guard.record_success(site_id, now);
    }
}

/// 记一次失败：更新熔断，并通过注入出口上报**只有元数据**的事件。
///
/// 出口是 `Option<Arc<dyn Fn>>`：网关不该为了记一条事件而拿到整个存储层；
/// 也让测试能把事件捕获到 `Vec` 里**逐字段**断言白名单。
fn report_failure(
    state: &AppState,
    site_id: i64,
    status: u16,
    model: &str,
    reason: &str,
    now: Instant,
) {
    if let Ok(mut guard) = state.breaker.lock() {
        guard.record_failure(site_id, now);
    }
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

    /// 幂等：服务已经停了（oneshot 接收端没了、任务已结束）时，
    /// `shutdown_and_wait` 必须立即返回，不 panic、不挂。
    #[tokio::test]
    async fn shutdown_and_wait_on_an_already_stopped_server_returns() {
        let (tx, rx) = oneshot::channel::<()>();
        drop(rx); // 接收端已消失：send 会失败，若实现里 unwrap 就会炸
        let finished = tokio::spawn(async {});
        let handle = GatewayHandle {
            addr: "127.0.0.1:0".parse().expect("地址可解析"),
            token: "t".into(),
            site_display_name: "已停的站点".into(),
            shutdown: tx,
            finished,
            stopping: Arc::new(std::sync::atomic::AtomicBool::new(false)),
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

    #[test]
    fn extract_usage_from_chunk_finds_usage_in_sse_data() {
        let chunk = b"data: {\"id\":\"x\",\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\ndata: [DONE]\n\n";
        assert_eq!(extract_usage_from_chunk(chunk), Some((10, 5, 15)));
    }

    #[test]
    fn extract_usage_from_chunk_returns_none_without_usage() {
        let chunk = b"data: {\"id\":\"x\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
        assert_eq!(extract_usage_from_chunk(chunk), None);
    }

    #[test]
    fn extract_usage_from_chunk_returns_none_on_non_utf8() {
        assert_eq!(extract_usage_from_chunk(b"\xff\xfe"), None);
    }

    #[tokio::test]
    async fn cap_stream_with_usage_collects_chunks_and_calls_callback() {
        use futures_util::StreamExt;
        let chunks = vec![
            Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"hello")),
            Ok(bytes::Bytes::from_static(b" ")),
            Ok(bytes::Bytes::from_static(b"world")),
        ];
        let stream = futures_util::stream::iter(chunks);
        let collected = Arc::new(Mutex::new(Vec::<bytes::Bytes>::new()));
        let cb_collected = Arc::clone(&collected);
        let capped = cap_stream_with_usage(stream, 1024, move |chs| {
            *cb_collected.lock().unwrap() = chs;
        });
        let mut capped = Box::pin(capped);
        let mut got = Vec::new();
        while let Some(item) = capped.next().await {
            got.extend_from_slice(&item.unwrap());
        }
        assert_eq!(&got, b"hello world");
        let collected = collected.lock().unwrap();
        assert_eq!(collected.len(), 3, "应收集全部 3 个 chunk");
        assert_eq!(collected[0], b"hello".as_slice());
        assert_eq!(collected[2], b"world".as_slice());
    }

    #[tokio::test]
    async fn cap_stream_with_usage_keeps_only_last_8_chunks() {
        use futures_util::StreamExt;
        let chunks: Vec<std::result::Result<bytes::Bytes, std::io::Error>> = (0..12)
            .map(|i| Ok(bytes::Bytes::from(format!("chunk{i}"))))
            .collect();
        let stream = futures_util::stream::iter(chunks);
        let collected = Arc::new(Mutex::new(Vec::<bytes::Bytes>::new()));
        let cb_collected = Arc::clone(&collected);
        let capped = cap_stream_with_usage(stream, 1024, move |chs| {
            *cb_collected.lock().unwrap() = chs;
        });
        let mut capped = Box::pin(capped);
        while capped.next().await.is_some() {}
        let collected = collected.lock().unwrap();
        assert_eq!(collected.len(), 8, "最多保留 8 个 chunk");
        assert_eq!(collected[0], b"chunk4".as_slice());
        assert_eq!(collected[7], b"chunk11".as_slice());
    }

    #[tokio::test]
    async fn cap_stream_with_usage_errors_on_limit_exceeded() {
        use futures_util::StreamExt;
        let chunks = vec![
            Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"hello")),
            Ok(bytes::Bytes::from_static(b"!!!")),
        ];
        let stream = futures_util::stream::iter(chunks);
        let capped = cap_stream_with_usage(stream, 5, |_| {});
        let mut capped = Box::pin(capped);
        // 第一个 chunk（5 字节）正好不超限
        let first = capped.next().await.unwrap().unwrap();
        assert_eq!(first.as_ref(), &b"hello"[..]);
        // 第二个 chunk 让累计超过 5 字节 ⇒ 错误
        let second = capped.next().await;
        assert!(second.is_some(), "第二个 chunk 超限应产生错误");
        assert!(second.unwrap().is_err());
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
