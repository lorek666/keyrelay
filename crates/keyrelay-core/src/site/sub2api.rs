//! Sub2API 适配器（含 TOTP 二次验证）。
//!
//! **契约全部来自本地源码实测**（`/Volumes/Date/mimimimi/sub2api/backend`：
//! `internal/handler/auth_handler.go`、`internal/handler/api_key_handler.go`、
//! `internal/handler/dto/types.go`、`internal/handler/setting_handler.go`、
//! `internal/pkg/response/response.go`、`internal/server/routes/{auth,user}.go`）。
//!
//! 与 NewAPI 的三处关键差异：
//! 1. 响应信封是 `{code: 0, message: "success", data: ...}`（NewAPI 是 `{success, message, data}`）；
//! 2. 登录字段名是 **`email`** 而不是 `username`，且**密码明文提交**（没有登录加密端点）；
//! 3. **列表接口直接返回明文 `key`** —— 适配器必须在边界处剥掉，
//!    否则明文会顺着 `KeyMeta` 流进 DTO 与事件表（红线）。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::{json, Value};

use super::transport::{HttpRequest, HttpTransport, Method};
use super::{
    json_str, map_http_error, normalize_base_url, Balance, Credentials, KeyMaterial, KeyMeta,
    KeySpec, KeyStatus, Session, SiteAdapter, SiteFingerprint, SiteKind,
};
use crate::error::{Error, Result, SecondFactorKind};

/// 2FA 临时会话的有效期。源码里的登录会话是短时效的；这里取一个保守值，
/// 过期就退回「重新用账号密码登录拿一个新的 temp_token」，而不是拿旧 token 硬试。
const TWO_FA_TTL: Duration = Duration::from_secs(5 * 60);

/// TOTP 码长度（源码 `binding:"required,len=6"`）。
const TOTP_LEN: usize = 6;

/// 一次登录尝试的中间态：需要 2FA 时暂存 `temp_token`。
struct PendingTwoFa {
    temp_token: String,
    expires_at: Instant,
}

pub struct Sub2Api<T: HttpTransport> {
    transport: T,
    /// `base_url` → 待完成的 2FA 会话。按站点隔离，避免多站点互相覆盖。
    pending: Mutex<HashMap<String, PendingTwoFa>>,
}

impl<T: HttpTransport> Sub2Api<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// 解包 Sub2API 信封 `{code, message, data}`。`code != 0` 一律视为业务失败。
    fn unwrap_data(resp: &super::transport::HttpResponse, op: &str) -> Result<Value> {
        let value = resp.json_value()?;
        let code = value.get("code").and_then(|v| v.as_i64()).unwrap_or(0);
        if code != 0 {
            let message = json_str(&value, "/message")
                .unwrap_or("站点返回失败")
                .to_string();
            return Err(classify_failure(op, &message));
        }
        Ok(value.get("data").cloned().unwrap_or(Value::Null))
    }

    fn auth_headers(session: &Session) -> Vec<(String, String)> {
        let mut headers = vec![("Accept".to_string(), "application/json".to_string())];
        if let Some(token) = &session.access_token {
            headers.push(("Authorization".to_string(), format!("Bearer {token}")));
        }
        if !session.cookies.is_empty() {
            let cookie = session
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            headers.push(("Cookie".to_string(), cookie));
        }
        headers
    }

    fn request(method: Method, url: String, session: &Session) -> HttpRequest {
        let mut req = HttpRequest::new(method, url);
        req.headers = Self::auth_headers(session);
        req
    }

    fn take_pending(&self, base_url: &str) -> Option<String> {
        let mut map = self.pending.lock().ok()?;
        let entry = map.get(base_url)?;
        if entry.expires_at <= Instant::now() {
            map.remove(base_url);
            return None;
        }
        Some(entry.temp_token.clone())
    }

    fn store_pending(&self, base_url: &str, temp_token: String) {
        if let Ok(mut map) = self.pending.lock() {
            map.insert(
                base_url.to_string(),
                PendingTwoFa {
                    temp_token,
                    expires_at: Instant::now() + TWO_FA_TTL,
                },
            );
        }
    }

    fn clear_pending(&self, base_url: &str) {
        if let Ok(mut map) = self.pending.lock() {
            map.remove(base_url);
        }
    }

    /// 只用账号密码换一次登录响应（可能返回 2FA 挑战）。
    async fn post_login(&self, base: &str, cred: &Credentials) -> Result<Value> {
        let body = json!({
            "email": cred.username,
            "password": cred.password,
        });
        let req =
            HttpRequest::new(Method::Post, format!("{base}/api/v1/auth/login")).json_body(&body)?;
        let resp = self.transport.request(req).await?;
        if resp.status != 200 {
            return Err(map_http_error(
                resp.status,
                &resp.body,
                resp.retry_after_secs(),
            ));
        }
        Self::unwrap_data(&resp, "登录")
    }

    /// 用 `temp_token` + TOTP 完成登录。
    async fn post_login_2fa(&self, base: &str, temp_token: &str, code: &str) -> Result<Value> {
        let body = json!({ "temp_token": temp_token, "totp_code": code });
        let req = HttpRequest::new(Method::Post, format!("{base}/api/v1/auth/login/2fa"))
            .json_body(&body)?;
        let resp = self.transport.request(req).await?;
        if resp.status != 200 {
            return Err(map_http_error(
                resp.status,
                &resp.body,
                resp.retry_after_secs(),
            ));
        }
        Self::unwrap_data(&resp, "二次验证")
    }
}

/// 带操作上下文的失败归类。站点原文先过 `scrub`（BACKLOG B-36）。
fn classify_failure(op: &str, message: &str) -> Error {
    let scrubbed = crate::redact::scrub(message);
    let lower = scrubbed.to_lowercase();
    if lower.contains("totp")
        || lower.contains("2fa")
        || scrubbed.contains("二次验证")
        || scrubbed.contains("验证码")
    {
        return Error::SecondFactorRequired {
            kind: SecondFactorKind::Totp,
        };
    }
    if lower.contains("turnstile") || lower.contains("captcha") {
        return Error::CaptchaRequired;
    }
    Error::AuthFailed(format!("{op}被站点拒绝（{scrubbed}）"))
}

/// 把 Sub2API 的 `status` 映射到本产品的 `KeyStatus`。
fn map_status(value: Option<&Value>) -> KeyStatus {
    match value.and_then(|v| v.as_str()).map(str::to_ascii_lowercase) {
        Some(s) if s == "active" || s == "enabled" => KeyStatus::Enabled,
        Some(s) if s == "inactive" || s == "disabled" => KeyStatus::Disabled,
        Some(s) if s == "expired" || s == "exhausted" => KeyStatus::Exhausted,
        _ => KeyStatus::Unknown,
    }
}

/// `created_at` / `last_used_at` 是 RFC 3339 字符串。这里只做粗解析（取 epoch 秒），
/// 解析不出来就返回 `None`——`KeyMeta` 的时间字段是可选的，不值得为它引入时间库。
fn parse_rfc3339_secs(value: Option<&Value>) -> Option<i64> {
    let raw = value.and_then(|v| v.as_str())?;
    let (date, rest) = raw.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = date_parts.next()?.parse().ok()?;
    let day: i64 = date_parts.next()?.parse().ok()?;
    let time = rest.trim_end_matches('Z');
    let mut time_parts = time.split(':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let minute: i64 = time_parts.next()?.parse().ok()?;
    let second: i64 = time_parts.next()?.split('.').next()?.parse().ok()?;
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Howard Hinnant 的 `days_from_civil`（公历 → Unix 天数）。避免为一个时间戳引入 chrono。
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// 从 `APIKey` 对象构造 `KeyMeta`。
///
/// **必须**只挑显式列出的字段：`APIKey` 里有 `key`（明文），
/// 任何「整体克隆再删字段」的写法都容易漏（红线）。
fn key_meta_from(item: &Value) -> Option<KeyMeta> {
    let remote_id = match item.get("id") {
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return None,
    };
    Some(KeyMeta {
        remote_id,
        name: json_str(item, "/name").unwrap_or_default().to_string(),
        group: item
            .get("group_id")
            .and_then(|v| v.as_i64())
            .map(|id| id.to_string()),
        status: map_status(item.get("status")),
        created_at: parse_rfc3339_secs(item.get("created_at")),
        last_used_at: parse_rfc3339_secs(item.get("last_used_at")),
    })
}

#[async_trait]
impl<T: HttpTransport + 'static> SiteAdapter for Sub2Api<T> {
    fn kind(&self) -> SiteKind {
        SiteKind::Sub2Api
    }

    async fn detect(&self, base_url: &str) -> Result<SiteFingerprint> {
        let base = normalize_base_url(base_url);
        let url = format!("{base}/api/v1/settings/public");
        let resp = self
            .transport
            .request(HttpRequest::new(Method::Get, url.clone()))
            .await?;

        if resp.status != 200 {
            return Err(Error::FingerprintMismatch(format!(
                "{url} 返回 {}",
                resp.status
            )));
        }
        let value = resp.json_value().map_err(|_| {
            Error::FingerprintMismatch(format!("{url} 不是 JSON，可能不是 Sub2API 站点"))
        })?;

        // 信封特征：`code` 必须是数字，`data` 必须是对象。
        // NewAPI 的信封是 `{success, message, data}`，没有 `code` —— 这条能把两者分开。
        let looks_like_sub2api = value.get("code").and_then(|v| v.as_i64()).is_some()
            && value.get("data").map(Value::is_object).unwrap_or(false);
        if !looks_like_sub2api {
            return Err(Error::FingerprintMismatch(
                "响应缺少 Sub2API 信封特征（code + data 对象）".into(),
            ));
        }

        let data = value.get("data").unwrap_or(&Value::Null);
        // 公开设置里的 Sub2API 专有字段：至少命中一个才认。
        let specific = [
            "site_name",
            "api_base_url",
            "totp_enabled",
            "table_default_page_size",
        ];
        if !specific.iter().any(|f| data.get(f).is_some()) {
            return Err(Error::FingerprintMismatch(
                "data 字段缺少 Sub2API 特征（site_name / api_base_url / totp_enabled）".into(),
            ));
        }

        Ok(SiteFingerprint {
            kind: SiteKind::Sub2Api,
            display_name: json_str(data, "/site_name")
                .unwrap_or("Sub2API")
                .to_string(),
            version: None,
        })
    }

    async fn login(&self, base_url: &str, cred: Credentials) -> Result<Session> {
        let base = normalize_base_url(base_url);

        match cred.second_factor.as_deref() {
            // 没有二次验证码 → 直接尝试密码登录
            None => {
                let data = self.post_login(&base, &cred).await?;
                if data
                    .get("requires_2fa")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    let temp_token = json_str(&data, "/temp_token")
                        .ok_or_else(|| {
                            Error::Transport("站点要求二次验证但未返回 temp_token".into())
                        })?
                        .to_string();
                    self.store_pending(&base, temp_token);
                    return Err(Error::SecondFactorRequired {
                        kind: SecondFactorKind::Totp,
                    });
                }
                session_from(&data)
            }
            // 有验证码 → 需要 temp_token；本地没有（或已过期）就重新登录拿一个
            Some(code) => {
                if code.len() != TOTP_LEN || !code.chars().all(|c| c.is_ascii_digit()) {
                    // 本机拦下：不发这个注定失败的请求，也避免把用户的手误当成站点错误
                    return Err(Error::AuthFailed(format!(
                        "二次验证码应为 {TOTP_LEN} 位数字"
                    )));
                }
                let temp_token = match self.take_pending(&base) {
                    Some(token) => token,
                    None => {
                        let data = self.post_login(&base, &cred).await?;
                        match json_str(&data, "/temp_token") {
                            Some(token) => token.to_string(),
                            // 站点这次直接给会话（例如 2FA 已被关掉）→ 直接用
                            None => return session_from(&data),
                        }
                    }
                };
                let data = self.post_login_2fa(&base, &temp_token, code).await?;
                self.clear_pending(&base);
                session_from(&data)
            }
        }
    }

    async fn list_keys(&self, base_url: &str, session: &Session) -> Result<Vec<KeyMeta>> {
        let base = normalize_base_url(base_url);
        let url = format!("{base}/api/v1/keys");
        let resp = self
            .transport
            .request(Self::request(Method::Get, url, session))
            .await?;
        if resp.status != 200 {
            return Err(map_http_error(
                resp.status,
                &resp.body,
                resp.retry_after_secs(),
            ));
        }
        let data = Self::unwrap_data(&resp, "列举密钥")?;
        let items = data.as_array().cloned().unwrap_or_default();
        // 逐项**只挑白名单字段**：响应里带明文 `key`，整体克隆会把密钥带出来
        Ok(items.iter().filter_map(key_meta_from).collect())
    }

    async fn create_key(
        &self,
        base_url: &str,
        session: &Session,
        spec: KeySpec,
    ) -> Result<KeyMaterial> {
        let base = normalize_base_url(base_url);
        let mut body = json!({ "name": spec.name });
        if let Some(group) = spec
            .group
            .as_deref()
            .filter(|g| !g.is_empty())
            .and_then(|g| g.parse::<i64>().ok())
        {
            body["group_id"] = json!(group);
        }
        if let Some(quota) = spec.quota_limit {
            body["quota"] = json!(quota);
        }

        let req =
            Self::request(Method::Post, format!("{base}/api/v1/keys"), session).json_body(&body)?;
        let resp = self.transport.request(req).await?;
        if resp.status != 200 && resp.status != 201 {
            return Err(map_http_error(
                resp.status,
                &resp.body,
                resp.retry_after_secs(),
            ));
        }
        let data = Self::unwrap_data(&resp, "创建密钥")?;
        let secret = json_str(&data, "/key")
            .ok_or_else(|| Error::Transport("创建密钥响应缺少 key 字段".into()))?
            .to_string();
        let remote_id = match data.get("id") {
            Some(Value::Number(n)) => n.to_string(),
            Some(Value::String(s)) => s.clone(),
            _ => String::new(),
        };
        Ok(KeyMaterial::new(remote_id, secret))
    }

    async fn reveal_key(
        &self,
        base_url: &str,
        session: &Session,
        remote_id: &str,
    ) -> Result<KeyMaterial> {
        let base = normalize_base_url(base_url);
        let id = safe_path_segment(remote_id)?;
        let url = format!("{base}/api/v1/keys/{id}");
        let resp = self
            .transport
            .request(Self::request(Method::Get, url, session))
            .await?;
        if resp.status != 200 {
            return Err(map_http_error(
                resp.status,
                &resp.body,
                resp.retry_after_secs(),
            ));
        }
        let data = Self::unwrap_data(&resp, "读取密钥")?;
        let secret = json_str(&data, "/key")
            .ok_or_else(|| Error::Transport("读取密钥响应缺少 key 字段".into()))?
            .to_string();
        Ok(KeyMaterial::new(remote_id, secret))
    }

    async fn revoke_key(&self, base_url: &str, session: &Session, remote_id: &str) -> Result<()> {
        let base = normalize_base_url(base_url);
        let id = safe_path_segment(remote_id)?;
        let url = format!("{base}/api/v1/keys/{id}");
        let resp = self
            .transport
            .request(Self::request(Method::Delete, url, session))
            .await?;
        if resp.status != 200 && resp.status != 204 {
            return Err(map_http_error(
                resp.status,
                &resp.body,
                resp.retry_after_secs(),
            ));
        }
        Ok(())
    }

    async fn balance(&self, base_url: &str, session: &Session) -> Result<Balance> {
        let base = normalize_base_url(base_url);
        let url = format!("{base}/api/v1/user/profile");
        let resp = self
            .transport
            .request(Self::request(Method::Get, url, session))
            .await?;
        if resp.status != 200 {
            return Err(map_http_error(
                resp.status,
                &resp.body,
                resp.retry_after_secs(),
            ));
        }
        let data = Self::unwrap_data(&resp, "查询余额")?;
        let remaining = data
            .get("balance")
            .and_then(|v| v.as_f64())
            .ok_or_else(|| Error::Transport("余额响应缺少 balance 字段".into()))?;
        // Sub2API 的 profile 只给 `balance` 与 `total_recharged`，没有「已用」字段。
        // 用「累计充值 - 当前余额」推导并夹到非负——这是**推导值**，用户拿过赠送额度时会偏大。
        let recharged = data
            .get("total_recharged")
            .and_then(|v| v.as_f64())
            .unwrap_or(remaining);
        let used = (recharged - remaining).max(0.0);

        Ok(Balance {
            currency: "USD".to_string(),
            remaining,
            used,
            raw_quota: None,
            quota_per_unit: None,
        })
    }
}

/// 从登录响应的 `data` 里取出会话。Sub2API 用 `Authorization: Bearer`，不用 Cookie。
fn session_from(data: &Value) -> Result<Session> {
    let access_token = json_str(data, "/access_token")
        .ok_or_else(|| Error::Transport("登录响应缺少 access_token".into()))?
        .to_string();
    let user_id = data
        .pointer("/user/id")
        .and_then(|v| v.as_i64())
        .map(|id| id.to_string());
    Ok(Session {
        cookies: Vec::new(),
        access_token: Some(access_token),
        user_id,
    })
}

/// 令牌 id 作为 URL 路径段前的校验（与 NewAPI 侧同规则，避免 `../` 逃逸）。
fn safe_path_segment(id: &str) -> Result<&str> {
    let ok = !id.is_empty()
        && id.len() <= 128
        && id != "."
        && !id.contains("..")
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if !ok {
        return Err(Error::Transport(format!(
            "站点返回的密钥 id 不是合法的路径段（长度 {}），已拒绝用它拼接请求",
            id.len()
        )));
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_from_civil_matches_known_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10957);
        assert_eq!(days_from_civil(2026, 7, 27), 20661);
    }

    #[test]
    fn parse_rfc3339_handles_fraction_and_z() {
        assert_eq!(
            parse_rfc3339_secs(Some(&json!("1970-01-01T00:00:00Z"))),
            Some(0)
        );
        assert_eq!(
            parse_rfc3339_secs(Some(&json!("1970-01-01T00:00:01.628Z"))),
            Some(1)
        );
        assert_eq!(parse_rfc3339_secs(Some(&json!("not a date"))), None);
        assert_eq!(parse_rfc3339_secs(None), None);
    }

    #[test]
    fn key_meta_never_carries_the_plaintext_key() {
        let item = json!({
            "id": 12,
            "key": "sk-SUB2API-PLAINTEXT-LEAK",
            "name": "codex/daily",
            "group_id": 3,
            "status": "active",
            "created_at": "2026-07-27T05:03:01.628Z",
            "last_used_at": null,
            "quota": 10.0,
        });
        let meta = key_meta_from(&item).expect("应能解析");
        assert_eq!(meta.remote_id, "12");
        assert_eq!(meta.name, "codex/daily");
        assert_eq!(meta.group.as_deref(), Some("3"));
        assert_eq!(meta.status, KeyStatus::Enabled);

        let text = format!("{meta:?}");
        assert!(!text.contains("sk-SUB2API"), "KeyMeta 泄漏明文: {text}");
        // 用「序列化等价物」代替：`KeyMeta` 本身不实现 Serialize（它不该出现在线上契约里），
        // 这里逐字段拼一遍，确认没有任何字段携带明文。
        let flattened = format!(
            "{}{}{:?}{:?}{:?}{:?}",
            meta.remote_id, meta.name, meta.group, meta.status, meta.created_at, meta.last_used_at
        );
        assert!(!flattened.contains("sk-SUB2API"), "{flattened}");
    }

    #[test]
    fn status_mapping() {
        assert_eq!(map_status(Some(&json!("active"))), KeyStatus::Enabled);
        assert_eq!(map_status(Some(&json!("inactive"))), KeyStatus::Disabled);
        assert_eq!(map_status(Some(&json!("expired"))), KeyStatus::Exhausted);
        assert_eq!(map_status(Some(&json!("weird"))), KeyStatus::Unknown);
        assert_eq!(map_status(None), KeyStatus::Unknown);
    }

    #[test]
    fn safe_path_segment_rejects_traversal() {
        for bad in ["../user/profile", "1/2", ".", "..", "", "1?x=2", "1#f"] {
            assert!(safe_path_segment(bad).is_err(), "{bad}");
        }
        assert_eq!(safe_path_segment("12").unwrap(), "12");
    }

    #[test]
    fn classify_failure_maps_2fa_and_captcha() {
        assert!(matches!(
            classify_failure("登录", "invalid totp code"),
            Error::SecondFactorRequired { .. }
        ));
        assert!(matches!(
            classify_failure("登录", "turnstile verification failed"),
            Error::CaptchaRequired
        ));
        assert!(matches!(
            classify_failure("登录", "invalid credentials"),
            Error::AuthFailed(_)
        ));
    }

    #[test]
    fn classify_failure_scrubs_site_text() {
        let err = classify_failure("登录", "token sk-0123456789abcdef rejected");
        assert!(!err.to_string().contains("sk-0123456789abcdef"), "{err}");
    }

    #[test]
    fn session_from_requires_access_token() {
        let session = session_from(&json!({"access_token": "t", "user": {"id": 7}})).unwrap();
        assert_eq!(session.access_token.as_deref(), Some("t"));
        assert_eq!(session.user_id.as_deref(), Some("7"));
        assert!(session.cookies.is_empty());
        assert!(session_from(&json!({"user": {"id": 7}})).is_err());
    }

    #[test]
    fn pending_2fa_is_scoped_by_base_url() {
        let adapter = Sub2Api::new(super::super::transport::MockTransport::default());
        adapter.store_pending("https://x", "tok".into());
        assert_eq!(adapter.take_pending("https://x").as_deref(), Some("tok"));
        assert_eq!(adapter.take_pending("https://other"), None);
        adapter.clear_pending("https://x");
        assert_eq!(adapter.take_pending("https://x"), None);
    }
}
