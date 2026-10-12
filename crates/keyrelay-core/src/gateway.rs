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
//! 5. 请求体/响应体**不写日志**。

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use tokio::sync::oneshot;

use crate::error::{Error, Result};

/// 上游响应里**不**回传给本地调用方的头。
const STRIPPED_RESPONSE_HEADERS: [&str; 4] = [
    "set-cookie",
    "authorization",
    "www-authenticate",
    "proxy-authenticate",
];

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

    // ② 只转发 `/v1/*`
    if !path.starts_with("/v1/") && path != "/v1" {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "error": "网关只转发 /v1/*；健康检查用 /health"
            })),
        )
            .into_response();
    }

    let url = format!("{}{}{}", state.config.base_url, path, query);
    let method = request.method().clone();

    // ③ 逐条重建请求头：**丢掉**调用方的 Authorization，换成站点密钥
    let mut headers = HeaderMap::new();
    for (name, value) in request.headers().iter() {
        if name.as_str().eq_ignore_ascii_case("authorization")
            || name.as_str().eq_ignore_ascii_case("x-keyrelay-token")
            || name.as_str().eq_ignore_ascii_case("host")
            || name.as_str().eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        headers.insert(name.clone(), value.clone());
    }
    headers.insert(
        HeaderName::from_static("authorization"),
        HeaderValue::from_str(&format!("Bearer {}", state.config.api_key))
            .unwrap_or_else(|_| HeaderValue::from_static("Bearer ")),
    );

    let body = match axum::body::to_bytes(request.into_body(), 16 * 1024 * 1024).await {
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
        if STRIPPED_RESPONSE_HEADERS
            .iter()
            .any(|blocked| name.as_str().eq_ignore_ascii_case(blocked))
        {
            continue;
        }
        builder = builder.header(name, value);
    }

    let bytes = match upstream_response.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({ "error": format!("读取上游响应失败: {e}") })),
            )
                .into_response()
        }
    };

    builder
        .body(Body::from(bytes))
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
