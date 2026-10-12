//! 站点适配器契约与共享类型。

pub mod newapi;
pub mod password_crypto;
pub mod registry;
pub mod retry;
pub mod sub2api;
pub mod transport;
pub mod transport_reqwest;

use async_trait::async_trait;
use serde_json::Value;

use crate::error::{Error, Result};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SiteKind {
    NewApi,
    Sub2Api,
}

impl SiteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SiteKind::NewApi => "newapi",
            SiteKind::Sub2Api => "sub2api",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "newapi" | "new-api" => Some(SiteKind::NewApi),
            "sub2api" | "sub2-api" => Some(SiteKind::Sub2Api),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteFingerprint {
    pub kind: SiteKind,
    pub display_name: String,
    pub version: Option<String>,
}

/// 会话凭证。**禁止** derive Debug 泄露 cookie/token，故手写 `Debug`。
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Session {
    pub cookies: Vec<(String, String)>,
    pub access_token: Option<String>,
    pub user_id: Option<String>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("cookies", &format!("<{} 项>", self.cookies.len()))
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<已设置>"),
            )
            .field("user_id", &self.user_id)
            .finish()
    }
}

impl Session {
    pub fn cookie_header(&self) -> Option<String> {
        if self.cookies.is_empty() {
            return None;
        }
        Some(
            self.cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyStatus {
    Enabled,
    Disabled,
    Exhausted,
    Unknown,
}

impl KeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyStatus::Enabled => "enabled",
            KeyStatus::Disabled => "disabled",
            KeyStatus::Exhausted => "exhausted",
            KeyStatus::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyMeta {
    pub remote_id: String,
    pub name: String,
    pub group: Option<String>,
    pub status: KeyStatus,
    pub created_at: Option<i64>,
    pub last_used_at: Option<i64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct KeySpec {
    pub name: String,
    pub group: Option<String>,
    /// 站点侧的额度上限（NewAPI 为 quota 单位，None 表示不限）
    pub quota_limit: Option<f64>,
    pub expires_at: Option<i64>,
}

impl KeySpec {
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            group: None,
            quota_limit: None,
            expires_at: None,
        }
    }
}

/// 密钥本体。手写 `Debug` 以免密钥进入日志。
#[derive(Clone, PartialEq, Eq)]
pub struct KeyMaterial {
    pub remote_id: String,
    pub secret: String,
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("remote_id", &self.remote_id)
            .field("secret", &"<已脱敏>")
            .finish()
    }
}

impl KeyMaterial {
    pub fn new(remote_id: impl Into<String>, secret: impl Into<String>) -> Self {
        Self {
            remote_id: remote_id.into(),
            secret: secret.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Balance {
    pub currency: String,
    pub remaining: f64,
    pub used: f64,
    pub raw_quota: Option<i64>,
    pub quota_per_unit: Option<i64>,
}

/// 站点的一个可选分组（M6-S4 / PRD FR-2）。
///
/// `rate` 是站点给出的**计费倍率**，站点没给或该用户没有专属覆盖倍率时为 `None`
/// ——`None` 与「倍率 1.0」是两件事，调用方不得把 `None` 当成 1.0 展示（M6-S4 spec §6.1）。
/// 本类型**不含任何凭证**。
#[derive(Clone, Debug, PartialEq)]
pub struct GroupInfo {
    pub name: String,
    pub rate: Option<f64>,
    pub description: Option<String>,
}

/// 登录凭证。手写 `Debug`，密码永不进入日志。
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub second_factor: Option<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"<已脱敏>")
            .field(
                "second_factor",
                &self.second_factor.as_ref().map(|_| "<已设置>"),
            )
            .finish()
    }
}

impl Credentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            second_factor: None,
        }
    }

    pub fn with_second_factor(mut self, code: impl Into<String>) -> Self {
        self.second_factor = Some(code.into());
        self
    }
}

#[async_trait]
pub trait SiteAdapter: Send + Sync {
    fn kind(&self) -> SiteKind;

    /// 指纹识别：判断该 base_url 是否属于本适配器
    async fn detect(&self, base_url: &str) -> Result<SiteFingerprint>;

    async fn login(&self, base_url: &str, cred: Credentials) -> Result<Session>;

    async fn list_keys(&self, base_url: &str, session: &Session) -> Result<Vec<KeyMeta>>;

    async fn create_key(
        &self,
        base_url: &str,
        session: &Session,
        spec: KeySpec,
    ) -> Result<KeyMaterial>;

    async fn reveal_key(
        &self,
        base_url: &str,
        session: &Session,
        remote_id: &str,
    ) -> Result<KeyMaterial>;

    async fn revoke_key(&self, base_url: &str, session: &Session, remote_id: &str) -> Result<()>;

    async fn balance(&self, base_url: &str, session: &Session) -> Result<Balance>;

    /// 拉取当前会话可见的分组（含站点给出的倍率，缺失为 `None`）。
    ///
    /// 站点契约：NewAPI `GET /api/token/auto-groups`；Sub2API `GET /api/v1/groups/available`
    /// 与 `GET /api/v1/groups/rates` 两次调用合并。
    ///
    /// 默认实现返回 [`Error::Unimplemented`]：`site/registry.rs` 的 `StubAdapter` 在 Lead 写域内，
    /// 若把本方法声明为必需，该文件会立刻编译失败。两个真实适配器都显式覆盖本方法。
    ///
    /// `base_url` 为首参（M6-S4 spec §4.3 接口异议 O-1）：适配器实例在 `SiteRegistry` 里按
    /// **站点类型**缓存（一个实例服务该类型下的所有站点），`Session` 又不含站点信息，
    /// 因此字面签名 `(&self, session)` 无法拼出请求 URL。
    async fn available_groups(&self, base_url: &str, session: &Session) -> Result<Vec<GroupInfo>> {
        let _ = (base_url, session);
        Err(Error::Unimplemented(
            "该适配器未实现 available_groups".into(),
        ))
    }

    /// 批量读取密钥明文。
    ///
    /// 返回值的长度与顺序**逐位对应**入参 `remote_ids`（含重复 id：重复几次就返回几条）。
    /// 空入参直接返回空 `Vec`，**不发任何请求**。
    ///
    /// 站点契约：NewAPI `POST /api/token/batch/keys`；Sub2API 无批量端点，逐个 `GET`
    /// （有界并发 `SUB2API_REVEAL_CONCURRENCY`）。
    ///
    /// 密钥红线：本方法的任何 `Err` 文案都不得包含密钥（实现侧负责在站点原文进错误前
    /// 过 [`scrub_error`]）。默认实现的理由同 [`SiteAdapter::available_groups`]。
    async fn reveal_keys(
        &self,
        base_url: &str,
        session: &Session,
        remote_ids: &[String],
    ) -> Result<Vec<(String, KeyMaterial)>> {
        let _ = (base_url, session, remote_ids);
        Err(Error::Unimplemented("该适配器未实现 reveal_keys".into()))
    }
}

/// 去掉尾部斜杠，避免拼出 `//api/...`
pub(crate) fn normalize_base_url(base_url: &str) -> String {
    base_url.trim().trim_end_matches('/').to_string()
}

/// 统一 HTTP 错误映射。适配器在拿到非 2xx 响应后必须调用本函数。
///
/// **密钥红线（M6-S6 / 关闭 B-75）**：站点返回的 `message` 是**外部输入**，可能回显密钥
/// （站点自己的日志文案、风控提示、回显请求体等）。它在被拼进 [`Error`] 之前一律过
/// [`crate::redact::scrub`]。
///
/// 为什么把脱敏放在这里而不是逐个调用点：本函数是**全部适配器**把非 2xx 响应变成
/// `Error` 的唯一咽喉，改一处即覆盖现存 14 个裸调用点与 4 个已包 `scrub_error` 的调用点，
/// 以及将来新增的每一个调用点；逐个改会把覆盖面变成一份需要手工维护的清单
/// （这正是 B-36 修完仍在别处残留的原因）。详见 `docs/specs/M6-S6-错误文案脱敏咽喉.md`。
pub fn map_http_error(status: u16, body: &[u8], retry_after_secs: Option<u64>) -> Error {
    let parsed: Option<Value> = serde_json::from_slice(body).ok();
    let code = parsed
        .as_ref()
        .and_then(|v| v.pointer("/error/code").or_else(|| v.get("code")))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    // 只对**站点原文**脱敏：下面的兜底文案是本产品自己的字面量，不经过这里，因此逐字不变。
    // `scrub` 幂等（`redact.rs` 文档），与调用点上的 `scrub_error` 叠加无副作用。
    let message = crate::redact::scrub(
        parsed
            .as_ref()
            .and_then(|v| {
                v.get("message")
                    .or_else(|| v.pointer("/error/message"))
                    .and_then(|m| m.as_str())
            })
            .unwrap_or_default(),
    );

    match status {
        401 | 403 if is_quota_code(&code) => Error::QuotaExhausted,
        401 => Error::AuthFailed(if message.is_empty() {
            "未授权（会话可能已失效）".into()
        } else {
            message
        }),
        403 => Error::AuthFailed(if message.is_empty() {
            "被站点拒绝（403）".into()
        } else {
            message
        }),
        404 => Error::NotFound(if message.is_empty() {
            "资源不存在".into()
        } else {
            message
        }),
        429 => Error::RateLimited {
            retry_after_secs: retry_after_secs.unwrap_or(60),
        },
        s if (500..600).contains(&s) => Error::Transport(format!("站点服务异常（{s}）")),
        s => Error::Transport(format!("未预期的状态码 {s}")),
    }
}

/// 把站点原文从错误文案里再脱敏一遍（M6-S4 引入）。
///
/// 只覆盖**带站点原文**的四个变体；`RateLimited` / `QuotaExhausted` / `CaptchaRequired` 等
/// 变体不含站点文本，原样透传。
///
/// **现状（M6-S6 之后）**：`map_http_error` 已经在**源头**对站点 `message` 脱敏，因此本函数
/// 对 `map_http_error` 产出的错误已是**冗余的第二层**（`scrub` 幂等，叠加无副作用）。
/// 保留它的理由：① 调用点上还有不经过 `map_http_error` 的错误来源（例如 Sub2API 的
/// `reveal_keys` 委托既有 `reveal_key`，其错误在方法边界被 `map_err(scrub_error)` 兜住）；
/// ② 纵深防御——将来若有人绕过咽喉点直接构造带站点文本的错误，这一层仍在。
pub(crate) fn scrub_error(err: Error) -> Error {
    match err {
        Error::AuthFailed(m) => Error::AuthFailed(crate::redact::scrub(&m)),
        Error::NotFound(m) => Error::NotFound(crate::redact::scrub(&m)),
        Error::Transport(m) => Error::Transport(crate::redact::scrub(&m)),
        Error::FingerprintMismatch(m) => Error::FingerprintMismatch(crate::redact::scrub(&m)),
        other => other,
    }
}

/// 额度不足的业务错误码（NewAPI / Sub2API 共用）
pub fn is_quota_code(code: &str) -> bool {
    matches!(
        code,
        "insufficient_user_quota" | "pre_consume_token_quota_failed" | "insufficient_quota"
    )
}

/// 从 JSON 里按路径取字符串
pub(crate) fn json_str<'a>(v: &'a Value, path: &str) -> Option<&'a str> {
    v.pointer(path).and_then(|x| x.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_debug_hides_secrets() {
        let s = Session {
            cookies: vec![("session".into(), "supersecret".into())],
            access_token: Some("deadbeef".into()),
            user_id: Some("7".into()),
        };
        let text = format!("{s:?}");
        assert!(!text.contains("supersecret"));
        assert!(!text.contains("deadbeef"));
    }

    #[test]
    fn credentials_debug_hides_password() {
        let c = Credentials::new("me@example.com", "hunter2");
        let text = format!("{c:?}");
        assert!(!text.contains("hunter2"));
        assert!(text.contains("me@example.com"));
    }

    #[test]
    fn key_material_debug_hides_secret() {
        let k = KeyMaterial::new("12", "sk-abcdefgh12345678");
        assert!(!format!("{k:?}").contains("sk-abcdefgh"));
    }

    #[test]
    fn maps_quota_exhausted() {
        let body = br#"{"error":{"code":"insufficient_user_quota","message":"quota"}}"#;
        assert_eq!(map_http_error(403, body, None), Error::QuotaExhausted);
    }

    #[test]
    fn maps_rate_limited_with_retry_after() {
        let e = map_http_error(429, b"{}", Some(42));
        assert_eq!(
            e,
            Error::RateLimited {
                retry_after_secs: 42
            }
        );
        assert!(e.is_retryable());
    }

    #[test]
    fn maps_401_to_auth_failed() {
        let body = br#"{"message":"bad credentials"}"#;
        assert_eq!(
            map_http_error(401, body, None),
            Error::AuthFailed("bad credentials".into())
        );
    }

    #[test]
    fn normalize_trims_trailing_slash() {
        assert_eq!(
            normalize_base_url("https://a.example.com/"),
            "https://a.example.com"
        );
        assert_eq!(
            normalize_base_url("  https://a.example.com  "),
            "https://a.example.com"
        );
    }

    // ============================================================ M6-S4

    #[test]
    fn scrub_error_masks_site_echoed_secrets() {
        let secret = "sk-0123456789abcdef0123456789abcdef";
        for err in [
            Error::AuthFailed(format!("站点回显 {secret}")),
            Error::NotFound(format!("没有 {secret}")),
            Error::Transport(format!("boom {secret}")),
            Error::FingerprintMismatch(format!("nope {secret}")),
        ] {
            let text = scrub_error(err).to_string();
            assert!(!text.contains(secret), "错误文案泄漏密钥: {text}");
            assert!(text.contains("***"), "应保留脱敏痕迹: {text}");
        }
    }

    #[test]
    fn scrub_error_passes_through_variants_without_site_text() {
        assert_eq!(scrub_error(Error::QuotaExhausted), Error::QuotaExhausted);
        assert_eq!(scrub_error(Error::CaptchaRequired), Error::CaptchaRequired);
        assert_eq!(
            scrub_error(Error::RateLimited {
                retry_after_secs: 7
            }),
            Error::RateLimited {
                retry_after_secs: 7
            }
        );
    }

    #[test]
    fn group_info_carries_no_secret() {
        let g = GroupInfo {
            name: "vip".into(),
            rate: Some(0.8),
            description: Some("高级分组".into()),
        };
        let text = format!("{g:?}");
        assert!(text.contains("vip"));
        assert!(!text.contains("sk-"));
    }

    // ============================================================ M6-S6 / B-75

    #[test]
    fn map_http_error_scrubs_site_echoed_secret_401() {
        let secret = "sk-SITE-ECHO-0123456789abcdef";
        let body = format!(r#"{{"message":"token {secret} rejected"}}"#);
        let err = map_http_error(401, body.as_bytes(), None);
        let text = err.to_string();
        assert!(!text.contains(secret), "错误文案泄漏密钥: {text}");
        assert!(!text.contains("SITE-ECHO"), "错误文案残留密钥片段: {text}");
        assert!(text.contains("sk-***"), "应留下脱敏痕迹: {text}");
        assert!(matches!(err, Error::AuthFailed(_)));
    }

    #[test]
    fn map_http_error_scrubs_32_hex_in_404() {
        let hex = "0123456789abcdef0123456789abcdef";
        let body = format!(r#"{{"message":"key {hex} not found"}}"#);
        let err = map_http_error(404, body.as_bytes(), None);
        let text = err.to_string();
        assert!(!text.contains(hex), "错误文案泄漏 32 位 hex: {text}");
        assert!(text.contains("***"), "应留下脱敏痕迹: {text}");
        assert!(matches!(err, Error::NotFound(_)), "{err:?}");
    }

    #[test]
    fn map_http_error_scrubs_nested_error_message() {
        let secret = "sk-NESTED-0123456789abcdef";
        let body = format!(r#"{{"error":{{"message":"bad {secret}"}}}}"#);
        let err = map_http_error(403, body.as_bytes(), None);
        let text = err.to_string();
        assert!(!text.contains(secret), "错误文案泄漏密钥: {text}");
        assert!(text.contains("sk-***"), "{text}");
    }

    #[test]
    fn map_http_error_scrubs_other_credential_shapes() {
        // `nap-`（NewAPI 应用开户密钥）与 `Bearer <token>`（站点回显请求头）两种形态
        let nap = "nap-0123456789abcdef";
        let bearer = "Bearer deadbeefdeadbeefdeadbeef";
        for (status, message, needle) in [
            (401u16, format!("app {nap} disabled"), nap),
            (403u16, format!("auth {bearer} denied"), bearer),
        ] {
            let body = format!(r#"{{"message":"{message}"}}"#);
            let err = map_http_error(status, body.as_bytes(), None);
            let text = err.to_string();
            assert!(!text.contains(needle), "错误文案泄漏凭证: {text}");
            assert!(text.contains("***"), "应留下脱敏痕迹: {text}");
        }
    }

    #[test]
    fn map_http_error_fallback_texts_are_byte_identical() {
        // 兜底文案是本产品自己的字面量，**不经过**脱敏（M6-S6 只对站点原文动手）。
        assert_eq!(
            map_http_error(401, b"{}", None),
            Error::AuthFailed("未授权（会话可能已失效）".into())
        );
        assert_eq!(
            map_http_error(401, b"", None),
            Error::AuthFailed("未授权（会话可能已失效）".into())
        );
        assert_eq!(
            map_http_error(401, br#"{"message":""}"#, None),
            Error::AuthFailed("未授权（会话可能已失效）".into())
        );
        assert_eq!(
            map_http_error(403, b"{}", None),
            Error::AuthFailed("被站点拒绝（403）".into())
        );
        assert_eq!(
            map_http_error(404, b"{}", None),
            Error::NotFound("资源不存在".into())
        );
        assert_eq!(
            map_http_error(500, b"{}", None),
            Error::Transport("站点服务异常（500）".into())
        );
        assert_eq!(
            map_http_error(418, b"{}", None),
            Error::Transport("未预期的状态码 418".into())
        );
        // 5xx 从不携带站点原文（只在兜底文案里带状态码）——站点回显的密钥自然进不来
        let body = br#"{"message":"token sk-5XX-0123456789abcdef"}"#;
        assert_eq!(
            map_http_error(503, body, None),
            Error::Transport("站点服务异常（503）".into())
        );
    }

    #[test]
    fn scrub_error_over_map_http_error_is_idempotent() {
        // 咽喉点 + 调用点上的 `scrub_error` 是两层；第二层必须是**空操作**。
        let secret = "sk-DOUBLE-0123456789abcdef";
        let body = format!(r#"{{"message":"{secret}"}}"#);
        let once = map_http_error(401, body.as_bytes(), None);
        assert_eq!(scrub_error(once.clone()), once);
    }

    /// M6-S6：**逐个真实调用点**验证 —— 从任意一个裸调用点触发，错误文案都不得含密钥。
    ///
    /// 每一行对应一个真实存在的 `map_http_error` 调用点（用**所在函数名**定位；行号会漂移，
    /// 只写在 spec 的清单里）。触发方式一律走公开的 [`SiteAdapter`] 方法，不直接调用私有函数。
    #[tokio::test]
    async fn every_map_http_error_call_site_scrubs_site_text() {
        use crate::site::newapi::NewApi;
        use crate::site::sub2api::Sub2Api;
        use crate::site::transport::{HttpResponse, MockTransport};
        use serde_json::json;

        const SECRET: &str = "sk-CALLSITE-0123456789abcdef";
        const BASE: &str = "https://probe.example.com";

        fn secret_err(status: u16) -> HttpResponse {
            HttpResponse::json(
                status,
                json!({"message": format!("站点回显 {SECRET} 拒绝")}),
            )
            .expect("构造响应")
        }
        fn ok(data: Value) -> HttpResponse {
            HttpResponse::json(200, json!({"code": 0, "message": "success", "data": data}))
                .expect("构造响应")
        }
        fn creds() -> Credentials {
            Credentials::new("probe@example.com", "pw-12345678")
        }
        fn bearer() -> Session {
            Session {
                cookies: Vec::new(),
                access_token: Some("tok-probe".to_string()),
                user_id: Some("7".to_string()),
            }
        }

        /// 断言：这次调用必须失败，且错误全文不含密钥、但看得到脱敏痕迹。
        async fn expect_scrubbed<T>(name: &str, fut: impl std::future::Future<Output = Result<T>>) {
            match fut.await {
                Ok(_) => panic!("{name}: 期望报错"),
                Err(err) => {
                    let text = err.to_string();
                    assert!(!text.contains(SECRET), "{name}: 错误文案泄漏密钥: {text}");
                    assert!(
                        !text.contains("CALLSITE"),
                        "{name}: 错误文案残留密钥片段: {text}"
                    );
                    assert!(text.contains("***"), "{name}: 未见脱敏痕迹: {text}");
                }
            }
        }

        // ---------- NewAPI 的 7 个裸调用点 ----------
        // ① newapi.rs::fetch_encryption_key（登录加密探测）
        expect_scrubbed(
            "newapi::fetch_encryption_key",
            NewApi::new(MockTransport::new(vec![secret_err(401)])).login(BASE, creds()),
        )
        .await;

        // ② newapi.rs::login（探测端点 404 = 未启用加密 → 登录 POST 报错）
        expect_scrubbed(
            "newapi::login",
            NewApi::new(MockTransport::new(vec![
                HttpResponse::new(404, b"".to_vec()),
                secret_err(401),
            ]))
            .login(BASE, creds()),
        )
        .await;

        // ③ newapi.rs::list_keys
        expect_scrubbed(
            "newapi::list_keys",
            NewApi::new(MockTransport::new(vec![secret_err(401)])).list_keys(BASE, &bearer()),
        )
        .await;

        // ④ newapi.rs::create_key
        expect_scrubbed(
            "newapi::create_key",
            NewApi::new(MockTransport::new(vec![secret_err(403)])).create_key(
                BASE,
                &bearer(),
                KeySpec::named("probe"),
            ),
        )
        .await;

        // ⑤ newapi.rs::reveal_key
        expect_scrubbed(
            "newapi::reveal_key",
            NewApi::new(MockTransport::new(vec![secret_err(404)])).reveal_key(BASE, &bearer(), "1"),
        )
        .await;

        // ⑥ newapi.rs::revoke_key
        expect_scrubbed(
            "newapi::revoke_key",
            NewApi::new(MockTransport::new(vec![secret_err(401)])).revoke_key(BASE, &bearer(), "1"),
        )
        .await;

        // ⑦ newapi.rs::balance
        expect_scrubbed(
            "newapi::balance",
            NewApi::new(MockTransport::new(vec![secret_err(401)])).balance(BASE, &bearer()),
        )
        .await;

        // ---------- Sub2API 的 7 个裸调用点 ----------
        // ⑧ sub2api.rs::post_login
        expect_scrubbed(
            "sub2api::post_login",
            Sub2Api::new(MockTransport::new(vec![secret_err(401)])).login(BASE, creds()),
        )
        .await;

        // ⑨ sub2api.rs::post_login_2fa（先拿 temp_token，再让 2FA 端点报错）
        expect_scrubbed(
            "sub2api::post_login_2fa",
            Sub2Api::new(MockTransport::new(vec![
                ok(json!({"requires_2fa": true, "temp_token": "tmp-1"})),
                secret_err(401),
            ]))
            .login(BASE, creds().with_second_factor("123456")),
        )
        .await;

        // ⑩ sub2api.rs::list_keys
        expect_scrubbed(
            "sub2api::list_keys",
            Sub2Api::new(MockTransport::new(vec![secret_err(401)])).list_keys(BASE, &bearer()),
        )
        .await;

        // ⑪ sub2api.rs::create_key
        expect_scrubbed(
            "sub2api::create_key",
            Sub2Api::new(MockTransport::new(vec![secret_err(401)])).create_key(
                BASE,
                &bearer(),
                KeySpec::named("probe"),
            ),
        )
        .await;

        // ⑫ sub2api.rs::reveal_key
        expect_scrubbed(
            "sub2api::reveal_key",
            Sub2Api::new(MockTransport::new(vec![secret_err(404)])).reveal_key(
                BASE,
                &bearer(),
                "1",
            ),
        )
        .await;

        // ⑬ sub2api.rs::revoke_key
        expect_scrubbed(
            "sub2api::revoke_key",
            Sub2Api::new(MockTransport::new(vec![secret_err(401)])).revoke_key(
                BASE,
                &bearer(),
                "1",
            ),
        )
        .await;

        // ⑭ sub2api.rs::balance
        expect_scrubbed(
            "sub2api::balance",
            Sub2Api::new(MockTransport::new(vec![secret_err(401)])).balance(BASE, &bearer()),
        )
        .await;

        // ---------- 另外 4 个已包 `scrub_error` 的调用点（M6-S4）----------
        // ⑮ newapi.rs::batch_keys_once
        expect_scrubbed(
            "newapi::batch_keys_once",
            NewApi::new(MockTransport::new(vec![secret_err(403)])).reveal_keys(
                BASE,
                &bearer(),
                &["1".to_string()],
            ),
        )
        .await;

        // ⑯ newapi.rs::available_groups
        expect_scrubbed(
            "newapi::available_groups",
            NewApi::new(MockTransport::new(vec![secret_err(401)]))
                .available_groups(BASE, &bearer()),
        )
        .await;

        // ⑰ sub2api.rs::available_groups（available 调用）
        expect_scrubbed(
            "sub2api::available_groups",
            Sub2Api::new(MockTransport::new(vec![secret_err(401)]))
                .available_groups(BASE, &bearer()),
        )
        .await;

        // ⑱ sub2api.rs::available_groups（rates 调用）
        expect_scrubbed(
            "sub2api::available_groups(rates)",
            Sub2Api::new(MockTransport::new(vec![
                ok(json!([{"id": 1, "name": "default"}])),
                secret_err(401),
            ]))
            .available_groups(BASE, &bearer()),
        )
        .await;
    }
}
