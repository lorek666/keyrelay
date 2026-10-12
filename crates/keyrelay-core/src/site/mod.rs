//! 站点适配器契约与共享类型。

pub mod newapi;
pub mod sub2api;
pub mod transport;

use async_trait::async_trait;
use serde_json::Value;

use crate::error::{Error, Result};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
}

/// 去掉尾部斜杠，避免拼出 `//api/...`
pub(crate) fn normalize_base_url(base_url: &str) -> String {
    base_url.trim().trim_end_matches('/').to_string()
}

/// 统一 HTTP 错误映射。适配器在拿到非 2xx 响应后必须调用本函数。
pub fn map_http_error(status: u16, body: &[u8], retry_after_secs: Option<u64>) -> Error {
    let parsed: Option<Value> = serde_json::from_slice(body).ok();
    let code = parsed
        .as_ref()
        .and_then(|v| v.pointer("/error/code").or_else(|| v.get("code")))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let message = parsed
        .as_ref()
        .and_then(|v| {
            v.get("message")
                .or_else(|| v.pointer("/error/message"))
                .and_then(|m| m.as_str())
        })
        .unwrap_or_default()
        .to_string();

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
}
