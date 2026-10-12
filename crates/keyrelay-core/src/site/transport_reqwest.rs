//! 真实 HTTP 传输层（reqwest + rustls）。
//!
//! 设计取舍：
//! - **默认不跟随重定向**：站点 API 出现 302 通常意味着会话失效或域名迁移，静默跟随会把
//!   凭据带到非预期主机上。
//! - **代理显式配置**：不读系统代理（M1-S0 范围外），配置非法时构造即失败，绝不静默直连。
//! - **User-Agent 固定**：站点侧便于识别与限流；不携带任何密钥信息。

use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, USER_AGENT};
use reqwest::{redirect, Method as HttpMethod, Proxy};

use super::transport::{HttpRequest, HttpResponse, HttpTransport, Method};
use crate::error::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportConfig {
    pub timeout: Duration,
    pub connect_timeout: Duration,
    /// `http://127.0.0.1:7897` / `socks5://127.0.0.1:1080`；`None` 表示直连
    pub proxy: Option<String>,
    pub user_agent: String,
    /// 允许跟随的重定向次数，默认 0
    pub follow_redirects: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(15),
            connect_timeout: Duration::from_secs(8),
            proxy: None,
            user_agent: format!("KeyRelay/{}", env!("CARGO_PKG_VERSION")),
            follow_redirects: 0,
        }
    }
}

#[derive(Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
    config: TransportConfig,
}

/// 手写 `Debug`：代理 URL 可能内嵌 `user:pass`，不能进日志。
impl std::fmt::Debug for ReqwestTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReqwestTransport")
            .field("timeout", &self.config.timeout)
            .field("connect_timeout", &self.config.connect_timeout)
            .field(
                "proxy",
                &self.config.proxy.as_ref().map(|_| "<已配置（内容脱敏）>"),
            )
            .field("user_agent", &self.config.user_agent)
            .field("follow_redirects", &self.config.follow_redirects)
            .finish()
    }
}

impl ReqwestTransport {
    pub fn new(config: TransportConfig) -> Result<Self> {
        let mut headers = HeaderMap::new();
        let user_agent = HeaderValue::from_str(&config.user_agent)
            .map_err(|e| Error::Transport(format!("User-Agent 非法: {e}")))?;
        headers.insert(USER_AGENT, user_agent);

        let mut builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout)
            .redirect(redirect::Policy::limited(config.follow_redirects))
            .default_headers(headers)
            .gzip(true);

        if let Some(proxy_url) = config.proxy.as_deref() {
            let proxy = Proxy::all(proxy_url.to_string()).map_err(|e| {
                Error::Transport(format!("代理配置无效（{proxy_url}），拒绝静默直连: {e}"))
            })?;
            builder = builder.proxy(proxy);
        }

        let client = builder
            .build()
            .map_err(|e| Error::Transport(format!("构建 HTTP 客户端失败: {e}")))?;

        Ok(Self { client, config })
    }

    pub fn config(&self) -> &TransportConfig {
        &self.config
    }
}

fn to_reqwest_method(method: Method) -> HttpMethod {
    match method {
        Method::Get => HttpMethod::GET,
        Method::Post => HttpMethod::POST,
        Method::Put => HttpMethod::PUT,
        Method::Patch => HttpMethod::PATCH,
        Method::Delete => HttpMethod::DELETE,
    }
}

fn describe(error: &reqwest::Error) -> Error {
    if error.is_timeout() {
        Error::Transport(format!("请求超时: {error}"))
    } else if error.is_connect() {
        Error::Transport(format!("连接失败: {error}"))
    } else {
        Error::Transport(format!("请求失败: {error}"))
    }
}

#[async_trait]
impl HttpTransport for ReqwestTransport {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse> {
        let mut builder = self.client.request(to_reqwest_method(req.method), &req.url);

        for (name, value) in &req.headers {
            let header_name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| Error::Transport(format!("请求头名非法（{name}）: {e}")))?;
            let header_value = HeaderValue::from_str(value)
                .map_err(|e| Error::Transport(format!("请求头值非法（{name}）: {e}")))?;
            builder = builder.header(header_name, header_value);
        }

        if let Some(body) = req.body {
            builder = builder.body(body);
        }

        let response = builder.send().await.map_err(|e| describe(&e))?;

        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            // 非 UTF-8 头直接丢弃，而不是塞入空串（避免下游把空值当成真实值）
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_string(), v.to_string()))
            })
            .collect();
        let body = response
            .bytes()
            .await
            .map_err(|e| Error::Transport(format!("读取响应体失败: {e}")))?;

        Ok(HttpResponse {
            status,
            headers,
            body: body.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_sane() {
        let config = TransportConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(15));
        assert_eq!(config.follow_redirects, 0, "默认不跟随重定向");
        assert!(config.proxy.is_none());
        assert!(config.user_agent.starts_with("KeyRelay/"));
    }

    #[test]
    fn invalid_proxy_is_rejected_at_construction() {
        let config = TransportConfig {
            proxy: Some("这不是一个 URL".to_string()),
            ..TransportConfig::default()
        };
        let err = ReqwestTransport::new(config).unwrap_err();
        assert!(matches!(err, Error::Transport(_)));
    }

    #[test]
    fn socks5_proxy_is_accepted() {
        let config = TransportConfig {
            proxy: Some("socks5://127.0.0.1:1080".to_string()),
            ..TransportConfig::default()
        };
        assert!(ReqwestTransport::new(config).is_ok());
    }
}
