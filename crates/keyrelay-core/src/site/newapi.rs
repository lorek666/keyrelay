//! NewAPI（含 one-api / one-hub / veloera / donehub 等兼容系）适配器。
//!
//! 关键点（来自站点真实路由表）：
//! - `GET /api/status`：指纹识别
//! - `POST /api/user/login`：登录，可能被 `TurnstileCheck` 拦截
//! - `GET /api/user/self`：余额（`quota`，单位换算 `quota_per_unit`，默认 500000 = 1 USD）
//! - `GET/POST /api/token/`、`POST /api/token/:id/key`：令牌列表 / 新建 / 读明文
//!
//! **创建流程**：`POST /api/token/` 只返回成功与否，密钥本体需再 `POST /api/token/:id/key` 读取，
//! 因此 `create_key` 内部按「创建 → 列表定位 → 读明文」三步完成。

use async_trait::async_trait;
use serde_json::{json, Value};

use super::transport::{HttpRequest, HttpTransport, Method};
use super::{
    json_str, map_http_error, normalize_base_url, Balance, Credentials, KeyMaterial, KeyMeta,
    KeySpec, KeyStatus, Session, SiteAdapter, SiteFingerprint, SiteKind,
};
use crate::error::{Error, Result, SecondFactorKind};

pub const DEFAULT_QUOTA_PER_UNIT: i64 = 500_000;

pub struct NewApi<T: HttpTransport> {
    transport: T,
    quota_per_unit: i64,
}

impl<T: HttpTransport> NewApi<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            quota_per_unit: DEFAULT_QUOTA_PER_UNIT,
        }
    }

    pub fn with_quota_per_unit(transport: T, quota_per_unit: i64) -> Self {
        Self {
            transport,
            quota_per_unit: quota_per_unit.max(1),
        }
    }

    /// 暴露传输层，便于契约测试断言请求内容
    pub fn transport(&self) -> &T {
        &self.transport
    }

    fn auth_headers(&self, session: &Session) -> Vec<(String, String)> {
        let mut headers = vec![("Accept".to_string(), "application/json".to_string())];
        if let Some(cookie) = session.cookie_header() {
            headers.push(("Cookie".to_string(), cookie));
        }
        if let Some(token) = &session.access_token {
            headers.push(("Authorization".to_string(), format!("Bearer {token}")));
        }
        headers
    }

    fn request(&self, method: Method, url: String, session: &Session) -> HttpRequest {
        let mut req = HttpRequest::new(method, url);
        req.headers = self.auth_headers(session);
        req
    }

    /// 登录/业务响应统一解包：NewAPI 约定 `{success: bool, message: string, data: ...}`
    fn unwrap_success(resp: &super::transport::HttpResponse) -> Result<Value> {
        let value = resp.json_value()?;
        let ok = value
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if !ok {
            let message = json_str(&value, "/message")
                .unwrap_or("站点返回失败")
                .to_string();
            return Err(classify_login_message(&message));
        }
        Ok(value)
    }
}

/// 把站点返回的失败文案归类成可操作错误。
fn classify_login_message(message: &str) -> Error {
    let m = message.to_lowercase();
    let captcha = message.contains("验证码")
        || message.contains("人机")
        || m.contains("turnstile")
        || m.contains("captcha");
    if captcha {
        return Error::CaptchaRequired;
    }
    if message.contains("二次验证")
        || message.contains("两步")
        || m.contains("2fa")
        || m.contains("totp")
    {
        return Error::SecondFactorRequired {
            kind: SecondFactorKind::Totp,
        };
    }
    Error::AuthFailed(message.to_string())
}

fn map_key_status(value: Option<&Value>) -> KeyStatus {
    match value {
        Some(Value::Number(n)) => match n.as_i64() {
            Some(1) => KeyStatus::Enabled,
            Some(2) => KeyStatus::Disabled,
            Some(3) | Some(4) => KeyStatus::Exhausted,
            _ => KeyStatus::Unknown,
        },
        Some(Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "1" | "enabled" | "active" => KeyStatus::Enabled,
            "2" | "disabled" => KeyStatus::Disabled,
            "3" | "4" | "expired" | "exhausted" => KeyStatus::Exhausted,
            _ => KeyStatus::Unknown,
        },
        _ => KeyStatus::Unknown,
    }
}

/// 兼容 `data: [...]` 与 `data: {items: [...]}` 两种列表形态
fn extract_items(value: &Value) -> Vec<Value> {
    match value.get("data") {
        Some(Value::Array(items)) => items.clone(),
        Some(Value::Object(_)) => value
            .pointer("/data/items")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn parse_key_meta(item: &Value) -> Option<KeyMeta> {
    let remote_id = item.get("id").map(|v| match v {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => String::new(),
    })?;
    if remote_id.is_empty() {
        return None;
    }
    let name = json_str(item, "/name").unwrap_or_default().to_string();
    let group = json_str(item, "/group")
        .filter(|g| !g.is_empty())
        .map(|g| g.to_string());
    Some(KeyMeta {
        remote_id,
        name,
        group,
        status: map_key_status(item.get("status")),
        created_at: item
            .get("created_time")
            .or_else(|| item.get("created_at"))
            .and_then(|v| v.as_i64()),
        last_used_at: item
            .get("accessed_time")
            .or_else(|| item.get("last_used_at"))
            .and_then(|v| v.as_i64()),
    })
}

#[async_trait]
impl<T: HttpTransport + 'static> SiteAdapter for NewApi<T> {
    fn kind(&self) -> SiteKind {
        SiteKind::NewApi
    }

    async fn detect(&self, base_url: &str) -> Result<SiteFingerprint> {
        let url = format!("{}/api/status", normalize_base_url(base_url));
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
            Error::FingerprintMismatch(format!("{url} 不是 JSON，可能不是 NewAPI 站点"))
        })?;

        let data = value
            .get("data")
            .ok_or_else(|| Error::FingerprintMismatch("响应缺少 data 字段".into()))?;

        let looks_like_newapi = data.get("quota_per_unit").is_some()
            || data.get("version").is_some()
            || data.get("system_name").is_some()
            || data.get("start_time").is_some();
        if !looks_like_newapi {
            return Err(Error::FingerprintMismatch(
                "data 字段缺少 NewAPI 特征（version / quota_per_unit）".into(),
            ));
        }

        Ok(SiteFingerprint {
            kind: SiteKind::NewApi,
            display_name: json_str(data, "/system_name")
                .unwrap_or("NewAPI")
                .to_string(),
            version: json_str(data, "/version").map(|v| v.to_string()),
        })
    }

    async fn login(&self, base_url: &str, cred: Credentials) -> Result<Session> {
        let url = format!("{}/api/user/login", normalize_base_url(base_url));
        let body = json!({
            "username": cred.username,
            "password": cred.password,
        });
        let req = HttpRequest::new(Method::Post, url).json_body(&body)?;
        let resp = self.transport.request(req).await?;

        match resp.status {
            200 => {
                let value = Self::unwrap_success(&resp)?;
                let user_id = value
                    .pointer("/data/id")
                    .and_then(|v| v.as_i64())
                    .map(|id| id.to_string());
                Ok(Session {
                    cookies: resp.set_cookies(),
                    access_token: None,
                    user_id,
                })
            }
            429 => Err(Error::RateLimited {
                retry_after_secs: resp.retry_after_secs().unwrap_or(60),
            }),
            other => Err(map_http_error(other, &resp.body, resp.retry_after_secs())),
        }
    }

    async fn list_keys(&self, base_url: &str, session: &Session) -> Result<Vec<KeyMeta>> {
        let url = format!("{}/api/token/", normalize_base_url(base_url));
        let resp = self
            .transport
            .request(self.request(Method::Get, url, session))
            .await?;
        if resp.status != 200 {
            return Err(map_http_error(
                resp.status,
                &resp.body,
                resp.retry_after_secs(),
            ));
        }
        let value = Self::unwrap_success(&resp)?;
        Ok(extract_items(&value)
            .iter()
            .filter_map(parse_key_meta)
            .collect())
    }

    async fn create_key(
        &self,
        base_url: &str,
        session: &Session,
        spec: KeySpec,
    ) -> Result<KeyMaterial> {
        let base = normalize_base_url(base_url);
        let body = json!({
            "name": spec.name,
            "remain_quota": spec.quota_limit.map(|q| q as i64).unwrap_or(0),
            "unlimited_quota": spec.quota_limit.is_none(),
            "expired_time": spec.expires_at.unwrap_or(-1),
            "group": spec.group.clone().unwrap_or_default(),
        });
        let req = HttpRequest::new(Method::Post, format!("{base}/api/token/"))
            .header("Cookie", session.cookie_header().unwrap_or_default())
            .json_body(&body)?;
        let resp = self.transport.request(req).await?;
        if resp.status != 200 {
            return Err(map_http_error(
                resp.status,
                &resp.body,
                resp.retry_after_secs(),
            ));
        }
        let value = Self::unwrap_success(&resp)?;

        // 少数版本直接在响应里回明文
        if let Some(key) = json_str(&value, "/data/key") {
            let remote_id = value
                .pointer("/data/id")
                .map(|v| v.to_string())
                .unwrap_or_default();
            return Ok(KeyMaterial::new(remote_id, key));
        }

        // 常规路径：创建成功后按名字定位刚建好的令牌
        let keys = self.list_keys(base_url, session).await?;
        let target = keys
            .iter()
            .filter(|k| k.name == spec.name)
            .max_by_key(|k| k.created_at.unwrap_or_default())
            .ok_or_else(|| {
                Error::NotFound(format!("创建后未在令牌列表中找到名为 {} 的令牌", spec.name))
            })?;
        self.reveal_key(base_url, session, &target.remote_id).await
    }

    async fn reveal_key(
        &self,
        base_url: &str,
        session: &Session,
        remote_id: &str,
    ) -> Result<KeyMaterial> {
        let url = format!(
            "{}/api/token/{}/key",
            normalize_base_url(base_url),
            remote_id
        );
        let resp = self
            .transport
            .request(self.request(Method::Post, url, session))
            .await?;
        if resp.status != 200 {
            return Err(map_http_error(
                resp.status,
                &resp.body,
                resp.retry_after_secs(),
            ));
        }
        let value = Self::unwrap_success(&resp)?;
        let secret = json_str(&value, "/data/key")
            .or_else(|| value.get("data").and_then(|d| d.as_str()))
            .ok_or_else(|| Error::Transport("读令牌明文响应缺少 key 字段".into()))?;
        Ok(KeyMaterial::new(remote_id, secret))
    }

    async fn revoke_key(&self, base_url: &str, session: &Session, remote_id: &str) -> Result<()> {
        let url = format!("{}/api/token/{}", normalize_base_url(base_url), remote_id);
        let resp = self
            .transport
            .request(self.request(Method::Delete, url, session))
            .await?;
        if resp.status != 200 {
            return Err(map_http_error(
                resp.status,
                &resp.body,
                resp.retry_after_secs(),
            ));
        }
        Self::unwrap_success(&resp)?;
        Ok(())
    }

    async fn balance(&self, base_url: &str, session: &Session) -> Result<Balance> {
        let url = format!("{}/api/user/self", normalize_base_url(base_url));
        let resp = self
            .transport
            .request(self.request(Method::Get, url, session))
            .await?;
        if resp.status != 200 {
            return Err(map_http_error(
                resp.status,
                &resp.body,
                resp.retry_after_secs(),
            ));
        }
        let value = Self::unwrap_success(&resp)?;
        let raw_quota = value.pointer("/data/quota").and_then(|v| v.as_i64());
        let used_quota = value
            .pointer("/data/used_quota")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let unit = value
            .pointer("/data/quota_per_unit")
            .and_then(|v| v.as_i64())
            .unwrap_or(self.quota_per_unit)
            .max(1);

        Ok(Balance {
            currency: "USD".to_string(),
            remaining: raw_quota.unwrap_or(0) as f64 / unit as f64,
            used: used_quota as f64 / unit as f64,
            raw_quota,
            quota_per_unit: Some(unit),
        })
    }
}
