//! 真实 HTTP 传输层（reqwest + rustls）。
//!
//! 设计取舍：
//! - **默认不跟随重定向**：站点 API 出现 302 通常意味着会话失效或域名迁移，静默跟随会把
//!   凭据带到非预期主机上。
//! - **代理显式配置**：校验与脱敏集中在 `crate::proxy`（M10-S2 起系统代理探测也复用同一份），
//!   配置非法时构造即失败，绝不静默直连。
//! - **User-Agent 固定**：站点侧便于识别与限流；不携带任何密钥信息。

use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, USER_AGENT};
use reqwest::{redirect, Method as HttpMethod, Proxy};

use super::transport::{HttpRequest, HttpResponse, HttpTransport, Method};
use crate::error::{Error, Result};
use crate::proxy::{mask_proxy, validate_proxy_url};

#[derive(Clone, PartialEq, Eq)]
pub struct TransportConfig {
    pub timeout: Duration,
    pub connect_timeout: Duration,
    /// `http://127.0.0.1:7897` / `socks5://127.0.0.1:1080`；`None` 表示直连
    pub proxy: Option<String>,
    pub user_agent: String,
    /// 允许跟随的重定向次数，默认 0
    pub follow_redirects: usize,
}

/// 手写 `Debug`：代理 URL 可能内嵌 `user:pass`，而 `config()` 是公开 API，
/// 用 derive 会让任何 `{:?}` 把凭据打进日志（M1-S0 复核 N-1 / BACKLOG B-22）。
impl std::fmt::Debug for TransportConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportConfig")
            .field("timeout", &self.timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field(
                "proxy",
                &self.proxy.as_ref().map(|_| "<已配置（内容脱敏）>"),
            )
            .field("user_agent", &self.user_agent)
            .field("follow_redirects", &self.follow_redirects)
            .finish()
    }
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

        // reqwest 0.13 的 `Policy::limited(0)` 会在**首个** 3xx 就报 TooManyRedirects，
        // 让适配器看不到 3xx（无法识别会话失效/域名迁移），且该错误会被重试层当作可重试错误。
        // 因此 0 必须用 `Policy::none()`：不跟随、把 30x 原样透传。
        let redirect_policy = if config.follow_redirects == 0 {
            redirect::Policy::none()
        } else {
            redirect::Policy::limited(config.follow_redirects)
        };

        let mut builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout)
            .redirect(redirect_policy)
            .default_headers(headers)
            .gzip(true);

        if let Some(proxy_url) = config.proxy.as_deref() {
            // scheme 白名单 + path/query/fragment 拒绝集中在 `proxy::validate_proxy_url`，
            // 与系统代理探测路径共用同一份校验（M10-S2）。非法 ⇒ Err，绝不静默直连。
            validate_proxy_url(proxy_url)?;

            let proxy = Proxy::all(proxy_url.to_string()).map_err(|e| {
                Error::Transport(format!(
                    "代理配置无效（{}），拒绝静默直连: {e}",
                    mask_proxy(proxy_url)
                ))
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

/// 代理背景下「读/总超时」的一条配置诊断（M21-S2 / B-164）。
///
/// **为什么只说 http(s)**：`http://` 代理要把域名交给代理解析，遇到 fake-IP（DNS 命中
/// 伪造地址）时代理会向一个不存在的地址发起连接，一路挂到超时——这正是 M18-S1 真机那次
/// 事故的成因（实测约 17s，`is_connect()` 两个谓词都不满足 ⇒ 既不能重放也判不出是否已送达）。
/// `socks5://` 由对端解析域名，正是那次事故的**正确替代方案**，提示它等于建议用户从对的改出去。
///
/// 只描述可能性与下一步，不断言因果：读超时也可能是服务端真的慢。
fn proxy_timeout_hint(proxy_url: &str) -> Option<&'static str> {
    let scheme = proxy_url
        .split_once("://")
        .map(|(s, _)| s.to_ascii_lowercase())
        .unwrap_or_default();
    (scheme == "http" || scheme == "https")
        .then_some("已配置 http(s) 代理：若目标主机被解析成保留地址（fake-IP），连接会挂到超时，可改用 socks5 代理")
}

fn describe(error: &reqwest::Error, proxy_url: Option<&str>) -> Error {
    // P2-19：reqwest 错误原文可能带完整 URL（含 userinfo），进文案前先 scrub。
    let msg = crate::redact::scrub(&error.to_string());
    // **顺序是载重逻辑，不是随手写的**（M19-S2 / 独立复审 P3-2）：
    // `is_timeout()` 必须排在 `is_connect()` 前面，因为「连接阶段挂到超时」在 reqwest 里
    // 表现为 `is_timeout()`，而**超时可能发生在读阶段**（请求已经送出去了）。
    // 两个谓词同时为真时往「可能已送达」那一侧判，是**保守**方向：
    // 代价是少重放一次（用户多等一轮），而不是重复计费（不可逆）。
    if error.is_timeout() {
        // M21-S2 / B-164：挂起式失败既不能重放、也判不出是否已送达，用户原先只拿到
        // 「请求超时」三个字。配了 http(s) 代理时补一条**条件**建议。
        let hint = proxy_url.and_then(proxy_timeout_hint);
        match hint {
            Some(hint) => Error::Transport(format!("请求超时: {msg}；{hint}")),
            None => Error::Transport(format!("请求超时: {msg}")),
        }
    } else if error.is_connect() {
        // M19-S2 / B-162：连接层失败的**类别**要活着走出 trait 边界。
        // 此前这里被压成 `Transport`，于是「能不能安全重放」这个判断在 probe 层
        // 只能靠猜文案——而猜错的代价是重复计费。
        //
        // 判据与网关侧 B-138 的 `classify_send_error` 同源（同一个 `is_connect()`），
        // 这样「上游没收到请求」在全仓只有**一个**定义。
        //
        // 这里**不加**「连接失败: 」前缀：变体自己的 Display 已经是
        // 「连接未建立（请求未送达）: …」，再套一层前缀只会得到一句叠词。
        Error::NotDelivered(msg)
    } else {
        Error::Transport(format!("请求失败: {msg}"))
    }
}

#[async_trait]
impl HttpTransport for ReqwestTransport {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse> {
        // P2-19 / DEBUG-REPORT-v3 §2-19：无 scheme 的 `user:pass@host` 会被 url crate
        // 解析成 scheme=user，reqwest 在 builder 里对非 http(s) scheme 报错，错误原文
        // 带完整 URL（含密码），进而在 detect_site / add_site 的文案里出现三次。先就地
        // 校验，失败时返回脱敏后的错误，不让密码进文案。
        let parsed = match reqwest::Url::parse(&req.url) {
            Ok(u) => u,
            Err(e) => {
                let safe = crate::redact::mask_authority_userinfo(&req.url);
                return Err(Error::Transport(format!(
                    "URL 非法（{}）: {safe}",
                    crate::redact::scrub(&e.to_string())
                )));
            }
        };
        if !matches!(parsed.scheme(), "http" | "https") {
            let safe = crate::redact::mask_authority_userinfo(&req.url);
            return Err(Error::Transport(format!(
                "URL 的 scheme 不是 http/https: {safe}"
            )));
        }
        let mut builder = self.client.request(to_reqwest_method(req.method), parsed);

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

        let response = builder
            .send()
            .await
            .map_err(|e| describe(&e, self.config.proxy.as_deref()))?;

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

    /// P2-19 / DEBUG-REPORT-v3 §2-19：无 scheme 的 `user:pass@host` 会被 url crate
    /// 解析成 scheme=user，reqwest builder 对非 http(s) scheme 报错，错误原文带完整
    /// URL（含密码），进而在 detect_site / add_site 的文案里出现三次。预校验在密码
    /// 进文案之前掩掉它（`mask_authority_userinfo`），仍点出主机名。
    #[tokio::test]
    async fn a_schemeless_url_with_userinfo_does_not_leak_the_password_in_the_error() {
        let transport = ReqwestTransport::new(TransportConfig::default()).unwrap();
        let req = HttpRequest::new(Method::Get, "carol:s3cr3t@host.example");
        let err = transport.request(req).await.unwrap_err();
        let text = err.to_string();
        assert!(!text.contains("s3cr3t"), "错误文案不得带 URL 密码: {text}");
        assert!(
            text.contains("host.example"),
            "错误文案仍要点出是哪个主机: {text}"
        );
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

    #[test]
    fn proxy_credentials_never_reach_error_message() {
        // 复审 P2-1：错误串里不得出现 user:pass
        let config = TransportConfig {
            proxy: Some("http://alice:s3cr3t-token@".to_string()),
            ..TransportConfig::default()
        };
        let err = ReqwestTransport::new(config).unwrap_err();
        let message = err.to_string();
        assert!(
            !message.contains("s3cr3t-token"),
            "错误串泄漏代理凭据: {message}"
        );
        assert!(
            !message.contains("alice"),
            "错误串泄漏代理用户名: {message}"
        );
    }

    #[test]
    fn proxy_scheme_whitelist_rejects_non_proxy_urls() {
        // 复核 P2-4：`Proxy::all` 会接受 `file:///...` 与无 scheme 的串，
        // 与「配置非法时构造即失败」的模块约定不符 → 由本层白名单收口
        for bad in [
            "file:///etc/passwd",
            "alice:s3cr3t-token@127.0.0.1:1080",
            "ftp://127.0.0.1:21",
            "",
        ] {
            let config = TransportConfig {
                proxy: Some(bad.to_string()),
                ..TransportConfig::default()
            };
            let err = ReqwestTransport::new(config)
                .err()
                .unwrap_or_else(|| panic!("{bad:?} 应被拒绝"));
            let message = err.to_string();
            assert!(message.contains("代理配置无效"), "{bad:?} → {message}");
            assert!(!message.contains("s3cr3t-token"), "{message}");
        }

        for good in [
            "http://127.0.0.1:7897",
            "https://proxy.example.com:8443",
            "socks5://127.0.0.1:1080",
            "socks5h://user:pw@127.0.0.1:1080",
        ] {
            let config = TransportConfig {
                proxy: Some(good.to_string()),
                ..TransportConfig::default()
            };
            assert!(ReqwestTransport::new(config).is_ok(), "{good} 应被接受");
        }
    }

    #[test]
    fn proxy_with_path_query_or_fragment_is_rejected() {
        // BACKLOG B-42：`Proxy::all` 会接受这些串，但 reqwest 只用 scheme/host/port，
        // 用户配的 path/query 被静默丢弃 → 与「配置非法时构造即失败」不符。
        for bad in [
            "socks5://127.0.0.1:1080/pac",
            "http://127.0.0.1:7897/pac?token=SECRET-VALUE",
            "http://127.0.0.1:7897#frag",
            "socks5://alice:pw@127.0.0.1:1080/pac?token=SECRET-VALUE#f",
        ] {
            let config = TransportConfig {
                proxy: Some(bad.to_string()),
                ..TransportConfig::default()
            };
            let err = ReqwestTransport::new(config)
                .err()
                .unwrap_or_else(|| panic!("{bad:?} 应被拒绝"));
            assert!(matches!(err, Error::Transport(_)), "{bad:?} → {err:?}");
            let message = err.to_string();
            assert!(message.contains("代理"), "{bad:?} → {message}");
            assert!(message.contains("非法片段"), "{bad:?} → {message}");
            // path/query 正文（可能含凭据）不得回显
            assert!(!message.contains("SECRET-VALUE"), "{message}");
            assert!(!message.contains("pac"), "{message}");
        }
    }

    #[test]
    fn proxy_authority_only_forms_are_accepted() {
        // 反例保护：正常形态不得被新校验拦死。
        // `scheme://host:port/` 是绝对 URL 的规范写法，path 实际为空，reqwest 处理一致。
        for good in [
            "http://127.0.0.1:7897",
            "http://127.0.0.1:7897/",
            "https://proxy.example.com:8443",
            "socks5://127.0.0.1:1080",
            "socks5h://user:pw@127.0.0.1:1080",
        ] {
            let config = TransportConfig {
                proxy: Some(good.to_string()),
                ..TransportConfig::default()
            };
            assert!(ReqwestTransport::new(config).is_ok(), "{good} 应被接受");
        }
    }

    #[test]
    fn illegal_proxy_tail_never_echoes_secrets() {
        // 复核 N-1 的延伸：错误串里连 path/query 正文都不能出现
        let config = TransportConfig {
            proxy: Some(
                "http://alice:s3cr3t-token@127.0.0.1:7897/x?token=s3cr3t-token#f".to_string(),
            ),
            ..TransportConfig::default()
        };
        let err = ReqwestTransport::new(config).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("非法片段"), "{message}");
        assert!(
            message.contains("127.0.0.1:7897"),
            "应保留可诊断的主机: {message}"
        );
        assert!(!message.contains("s3cr3t-token"), "泄漏了凭据: {message}");
        assert!(!message.contains("alice"), "泄漏了用户名: {message}");
    }

    // ============================================ M21-S2 / B-164：代理背景下的超时诊断

    /// http(s) 代理 + 超时 ⇒ 该给诊断。这是 M18-S1 真机那次事故的成因
    /// （fake-IP 让 `http://` 代理连到一个不存在的地址，一路挂到超时）。
    #[test]
    fn http_proxy_gets_the_timeout_hint() {
        assert!(proxy_timeout_hint("http://127.0.0.1:7897").is_some());
        assert!(proxy_timeout_hint("https://proxy.example.com:8080").is_some());
        // scheme 大小写不敏感
        assert!(proxy_timeout_hint("HTTP://127.0.0.1:7897").is_some());
    }

    /// socks5 是那次事故的**正确替代方案** ⇒ 提示它等于建议用户从对的改出去。
    #[test]
    fn socks_proxies_do_not_get_the_timeout_hint() {
        for url in [
            "socks5://127.0.0.1:1080",
            "socks5h://127.0.0.1:1080",
            "socks4://127.0.0.1:1080",
            "socks4a://127.0.0.1:1080",
        ] {
            assert!(
                proxy_timeout_hint(url).is_none(),
                "{url} 不该带诊断：socks 系由对端解析域名"
            );
        }
    }

    /// 没配代理 ⇒ 一个字都不加。没代理时的超时与代理无关。
    #[test]
    fn no_proxy_means_no_hint() {
        assert!(proxy_timeout_hint("").is_none());
        // 没有 scheme 的串（配置阶段就会被拒，但判据本身要能容错）
        assert!(proxy_timeout_hint("127.0.0.1:7897").is_none());
    }

    /// 诊断文案必须是**固定**的一段：不拼 host、不拼代理地址。
    ///
    /// 拼了就得为它再过一层 scrub（代理地址可带 userinfo），而诊断本身不需要这些信息。
    #[test]
    fn the_hint_carries_no_variable_data() {
        let a = proxy_timeout_hint("http://alice:s3cr3t@10.0.0.1:7897").expect("http 代理");
        let b = proxy_timeout_hint("http://other.example.com").expect("http 代理");
        assert_eq!(a, b, "文案必须与具体地址无关");
        assert!(!a.contains("alice"), "泄漏用户名: {a}");
        assert!(!a.contains("s3cr3t"), "泄漏凭据: {a}");
        assert!(!a.contains("10.0.0.1"), "不该拼 host: {a}");
        assert!(a.contains("socks5"), "要给出可执行的下一步: {a}");
    }

    #[test]
    fn debug_output_masks_proxy() {
        let transport = ReqwestTransport::new(TransportConfig {
            proxy: Some("http://alice:s3cr3t-token@127.0.0.1:7897".to_string()),
            ..TransportConfig::default()
        })
        .expect("合法代理应可构造");
        let debug = format!("{transport:?}");
        assert!(
            !debug.contains("s3cr3t-token"),
            "Debug 泄漏代理凭据: {debug}"
        );
        assert!(!debug.contains("alice"), "Debug 泄漏代理用户名: {debug}");
    }
}
