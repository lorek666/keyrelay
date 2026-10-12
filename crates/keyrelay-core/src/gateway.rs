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

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use futures_util::TryStreamExt;
use tokio::sync::oneshot;

use crate::error::{Error, Result};

/// 回传上游响应体的大小上限。
///
/// 没有上限的流式转发等于把内存交给上游决定：一个（被攻陷的、或只是出错的）
/// 中转站可以一直吐字节，把这个桌面进程撑爆（M4-S2 复审 P1-2）。
/// 64 MiB 远大于任何正常的 completions 响应，又不至于吃掉整台机器。
pub const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

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
/// `authorization` / `x-keyrelay-token` 是本地令牌的载体（换成站点密钥）；
/// 其余是 hop-by-hop 头，或调用方不该借我们的手送给上游的凭证类头
/// （M4-S2 复审 P2-2：`Cookie` / `Proxy-Authorization` 之前会被原样转发）。
fn should_strip_request_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    const STRIP: [&str; 12] = [
        // 令牌载体：必须换掉
        "authorization",
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

#[derive(Clone)]
pub struct GatewayConfig {
    pub port: u16,
    /// 本地令牌。**不是**站点密钥。
    pub token: String,
    /// 转发目标（站点根，无尾斜杠）
    pub base_url: String,
    /// 站点密钥（从钥匙串取）
    pub api_key: String,
    pub site_display_name: String,
}

impl std::fmt::Debug for GatewayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 令牌与密钥都不打印
        f.debug_struct("GatewayConfig")
            .field("port", &self.port)
            .field("base_url", &self.base_url)
            .field("site_display_name", &self.site_display_name)
            .finish_non_exhaustive()
    }
}

pub struct GatewayHandle {
    pub addr: SocketAddr,
    pub token: String,
    pub site_display_name: String,
    shutdown: oneshot::Sender<()>,
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
    pub fn shutdown(self) {
        let _ = self.shutdown.send(());
    }
}

/// 启动网关。**只绑定 `127.0.0.1`**（配置里没有别的选项）。
pub async fn start(config: GatewayConfig) -> Result<GatewayHandle> {
    if config.base_url.trim().is_empty() {
        return Err(Error::Store("网关的上游地址为空".into()));
    }
    if config.token.trim().is_empty() {
        return Err(Error::Store("网关的本地令牌为空".into()));
    }

    let upstream = reqwest::Client::builder()
        .build()
        .map_err(|e| Error::Transport(format!("构造网关的上游客户端失败: {e}")))?;

    let state = AppState {
        config: config.clone(),
        upstream,
    };
    let app = Router::new()
        .route("/health", any(health))
        .fallback(any(proxy))
        .with_state(state);

    // 只绑回环：这里写死，不接受任何参数
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", config.port))
        .await
        .map_err(|e| {
            Error::Store(format!(
                "无法在 127.0.0.1:{} 上启动网关（端口可能被占用）: {e}",
                config.port
            ))
        })?;
    let addr = listener
        .local_addr()
        .map_err(|e| Error::Store(format!("读取网关地址失败: {e}")))?;
    if !addr.ip().is_loopback() {
        return Err(Error::Store(format!(
            "网关绑定到了非回环地址 {addr}，拒绝启动"
        )));
    }

    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
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
    })
}

#[derive(Clone)]
struct AppState {
    config: GatewayConfig,
    upstream: reqwest::Client,
}

/// 取出请求里的本地令牌。支持 `Authorization: Bearer` 与 `X-KeyRelay-Token`。
fn presented_token(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers
        .get("x-keyrelay-token")
        .and_then(|v| v.to_str().ok())
    {
        return Some(value.to_string());
    }
    let auth = headers.get("authorization")?.to_str().ok()?;
    auth.strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .map(|s| s.trim().to_string())
}

fn unauthorized(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({ "error": message })),
    )
        .into_response()
}

async fn health(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if presented_token(&headers).as_deref() != Some(state.config.token.as_str()) {
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
    if presented_token(request.headers()).as_deref() != Some(state.config.token.as_str()) {
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

    let url = format!("{}{}{}", state.config.base_url, path, query);
    let method = request.method().clone();

    // ③ 逐条重建请求头：**丢掉**调用方的 Authorization，换成站点密钥。
    //    另外把「值里带着本地令牌」的头也丢掉——不管它叫什么名字，
    //    本地令牌都不许发给上游（M4-S2 复审 P2-2 的双头形态）。
    let local_token = state.config.token.as_str();
    let mut headers = HeaderMap::new();
    for (name, value) in request.headers().iter() {
        if should_strip_request_header(name.as_str()) {
            continue;
        }
        if value.to_str().is_ok_and(|text| text.contains(local_token)) {
            continue;
        }
        headers.insert(name.clone(), value.clone());
    }
    headers.insert(
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(&format!("Bearer {}", state.config.api_key))
            .unwrap_or_else(|_| HeaderValue::from_static("Bearer ")),
    );

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

    let upstream_request = state
        .upstream
        .request(method, &url)
        .headers(headers)
        .body(body);

    let upstream_response = match upstream_request.send().await {
        Ok(response) => response,
        Err(e) => {
            // 只记错误分类，不记请求体
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({
                    "error": format!("转发到上游失败: {e}")
                })),
            )
                .into_response();
        }
    };

    // ④ 回传：过滤掉敏感响应头
    let status = upstream_response.status();
    let mut builder = Response::builder().status(status);
    for (name, value) in upstream_response.headers().iter() {
        if should_strip_response_header(name.as_str()) {
            continue;
        }
        builder = builder.header(name, value);
    }

    // ⑤ **流式**回传，带上限：不整段缓冲，首字节到了就往下发
    //    （M4-S2 复审 P1-2：之前用 `.bytes()` 全缓冲，客户端要等上游吐完才见到第一个字节，
    //    而且响应体没有上限）。超过 `MAX_RESPONSE_BYTES` 时让流以错误结束、连接随之断开——
    //    此时响应头已经发出去了，改不了状态码，只能如实断流，不静默截断。
    let capped = cap_stream(upstream_response.bytes_stream(), MAX_RESPONSE_BYTES);

    builder
        .body(Body::from_stream(capped))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// 生成一个本地令牌。不是秘密级别的要求（只防同机其它程序误用），
/// 但仍然用足够长的随机串。
pub fn generate_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let digest = crate::inject::sha256_hex(format!("keyrelay-gateway-{nanos}-{pid}").as_bytes());
    format!("kr-gw-{}", &digest[..32])
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let config = GatewayConfig {
            port: 8787,
            token: "kr-gw-SECRET-TOKEN".into(),
            base_url: "https://relay.example.com".into(),
            api_key: "sk-SECRET-KEY".into(),
            site_display_name: "测试站".into(),
        };
        let text = format!("{config:?}");
        assert!(!text.contains("SECRET-TOKEN"), "{text}");
        assert!(!text.contains("SECRET-KEY"), "{text}");
        assert!(text.contains("8787"), "{text}");
    }

    #[test]
    fn presented_token_reads_both_headers() {
        let mut headers = HeaderMap::new();
        assert_eq!(presented_token(&headers), None);

        headers.insert("authorization", HeaderValue::from_static("Bearer abc"));
        assert_eq!(presented_token(&headers).as_deref(), Some("abc"));

        headers.insert("x-keyrelay-token", HeaderValue::from_static("xyz"));
        assert_eq!(
            presented_token(&headers).as_deref(),
            Some("xyz"),
            "专用头优先于 Authorization"
        );

        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Basic abc"));
        assert_eq!(presented_token(&headers), None, "非 Bearer 不认");
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
        let base = GatewayConfig {
            port: 0,
            token: "t".into(),
            base_url: "https://x".into(),
            api_key: "k".into(),
            site_display_name: "s".into(),
        };
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
}
