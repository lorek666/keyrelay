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
use std::collections::HashSet;

use super::password_crypto::{encrypt_password, PasswordEncryptionKey};
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

    /// 取站点密码加密公钥。站点未启用、端点不存在或响应不可解析时返回 `None`
    /// （按「未启用加密」处理，兼容旧版本 NewAPI）。
    async fn fetch_encryption_key(&self, base: &str) -> Result<Option<PasswordEncryptionKey>> {
        let url = format!("{base}/api/user/login/encryption-key");
        let resp = self
            .transport
            .request(HttpRequest::new(Method::Get, url))
            .await?;

        // 只有两种情形允许按「未启用加密」处理（fail-open）：
        // ① 端点不存在（404，旧版本 NewAPI）；② 响应不是 JSON（SPA 兜底页等）。
        // 其余一切异常都必须 fail-closed：站点已声明启用加密时，
        // 静默退回明文登录会把密码暴露给一个本应加密的通道（M1-S1 复审 P1-1）。
        if resp.status == 404 {
            return Ok(None);
        }
        if resp.status != 200 {
            return Err(map_http_error(
                resp.status,
                &resp.body,
                resp.retry_after_secs(),
            ));
        }
        let Ok(value) = resp.json_value() else {
            return Ok(None);
        };

        let enabled_field = value.pointer("/data/enabled");
        let enabled = match enabled_field {
            Some(Value::Bool(flag)) => *flag,
            // 端点存在、返回了 JSON 信封，却没有 `enabled` 字段 → 无法判定，fail-closed。
            // 与 `enabled: null` 同策略：把「读不懂」和「明确关闭」区分开（复核 N-2）。
            //
            // 站点常见的失败信封是 `{"success":false,"message":"Database error…"}`（HTTP 200）。
            // 方向（拒绝退回明文）是对的，但**必须把站点原文带出来**，否则用户无法排障（复核 P2）。
            None => {
                let site_message = json_str(&value, "/message").unwrap_or("(无 message)");
                return Err(Error::Transport(format!(
                    "登录加密探测响应缺少 enabled 字段，无法确认站点是否要求加密登录；站点返回: {}",
                    crate::redact::scrub(site_message)
                )));
            }
            Some(other) => {
                return Err(Error::Transport(format!(
                    "登录加密探测响应异常：enabled 字段类型不可识别（{}）",
                    json_kind(other)
                )))
            }
        };
        if !enabled {
            return Ok(None);
        }

        let kid = json_str(&value, "/data/kid")
            .unwrap_or_default()
            .to_string();
        let public_key_pem = json_str(&value, "/data/public_key")
            .unwrap_or_default()
            .to_string();
        if kid.is_empty() || public_key_pem.is_empty() {
            return Err(Error::Transport(
                "站点已启用登录加密，但响应缺少 kid / public_key；拒绝退回明文登录".to_string(),
            ));
        }
        Ok(Some(PasswordEncryptionKey {
            kid,
            public_key_pem,
        }))
    }

    /// 组装登录请求体：站点启用加密时发送密文（**不含明文 `password` 字段**），否则发送明文。
    async fn login_body(&self, base: &str, cred: &Credentials) -> Result<Value> {
        match self.fetch_encryption_key(base).await? {
            Some(key) => {
                let password_encrypted = encrypt_password(&cred.password, &key)?;
                Ok(json!({
                    "username": cred.username,
                    "password_encrypted": password_encrypted,
                    "encryption_key_id": key.kid,
                }))
            }
            None => Ok(json!({
                "username": cred.username,
                "password": cred.password,
            })),
        }
    }
}

/// JSON 值的类型名（用于错误信息，不回显内容）
fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// 令牌 id 归一化：数字与字符串统一成无引号字符串（复审 P2-3：`data.id` 为
/// `"99"` 时曾产出 `"\"99\""`，会污染 DTO 与后续落库定位）
fn normalize_id(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// 从同名候选中挑出「最新」的一把：优先按 `created_at`，缺失或平局时按数值 id 最大者。
///
/// 复审 P2-1：原实现 `max_by_key(created_at.unwrap_or_default())` 在时间戳缺失时会
/// 平局取**末位**元素，真实站点按 id 倒序返回时会静默交付**旧**令牌。
fn pick_newest_token<'a>(keys: &'a [KeyMeta], name: &str) -> Option<&'a KeyMeta> {
    keys.iter().filter(|k| k.name == name).max_by(|a, b| {
        a.created_at
            .unwrap_or(i64::MIN)
            .cmp(&b.created_at.unwrap_or(i64::MIN))
            .then_with(|| numeric_id(a).cmp(&numeric_id(b)))
    })
}

fn numeric_id(key: &KeyMeta) -> i64 {
    key.remote_id.parse().unwrap_or(0)
}

/// 把站点返回的令牌 id 当 URL 路径段使用前的校验。
///
/// 复核 N-4：`id` 是站点响应里的字符串，直接拼进路径可被构造成跨端点请求——
/// 实测 `id = "../user/self"` 会真的发出 `POST /api/user/self/key`（带会话 Cookie）。
/// 因此只接受单段安全字符，其余一律拒绝，不做「转义后照发」。
///
/// `"."` / `".."` 单独排除：`.` 虽然不含 `..`，但会被 URL 归一化抹掉，
/// 实测 `id = "."` 会退化成 `POST /api/token/key`（打到另一个资源，复核 P2）。
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
            "站点返回的令牌 id 不是合法的路径段（长度 {}），已拒绝用它拼接请求",
            id.len()
        )));
    }
    Ok(id)
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
    let remote_id = normalize_id(item.get("id"))?;
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
        let base = normalize_base_url(base_url);
        let body = self.login_body(&base, &cred).await?;
        let req =
            HttpRequest::new(Method::Post, format!("{base}/api/user/login")).json_body(&body)?;
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
        let base = normalize_base_url(base_url);
        let mut collected: Vec<KeyMeta> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut page: u32 = 1;
        // 每页请求 100 条；页数上限纯粹是「跑飞保护」，不承担「取全」的判断
        // —— 取全一律以站点声明的 `total` 为准（见下）。
        const PAGE_SIZE: u32 = 100;
        const MAX_PAGES: u32 = 100;

        loop {
            let url = format!("{base}/api/token/?p={page}&page_size={PAGE_SIZE}");
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
            let items = extract_items(&value);
            // `total` 缺失或非数字时不能当作「本页条数」，否则会在第一页就静默停住（复核 N-3）。
            let total = value.pointer("/data/total").and_then(|v| v.as_i64());
            let page_len = items.len();

            let parsed: Vec<KeyMeta> = items.iter().filter_map(parse_key_meta).collect();
            // 有条目却一条都解析不出 id：这是解析异常，不是「站点忽略分页」。
            // 若在这里当成「翻到底了」收工，会静默丢掉后面的页（第二轮复核 N-3 回归）。
            if page_len > 0 && parsed.is_empty() {
                return Err(Error::Transport(format!(
                    "站点返回的第 {page} 页有 {page_len} 条令牌，但都缺少可用的 id，无法安全分页"
                )));
            }

            let mut added = 0usize;
            for meta in parsed {
                if seen.insert(meta.remote_id.clone()) {
                    collected.push(meta);
                    added += 1;
                }
            }

            // 终止条件一（**权威**）：站点声明了总数，且已取够。
            //
            // 不能用「本页不满 PAGE_SIZE 即收工」——那等于假设站点按我们请求的
            // 每页条数返回。真实站点可能忽略 `page_size`（旧版读的是别的参数名，
            // 默认每页 10 条），于是「首页只有 10 条」会被误判成「只有 10 条令牌」，
            // 静默交付截断列表，并让 create_key 在令牌其实已创建时误报 NotFound
            // （第二轮复核 P1）。
            if let Some(total) = total {
                if (collected.len() as i64) >= total {
                    return Ok(collected);
                }
            }

            if page_len == 0 {
                return match total {
                    // 声明还有更多，却给了空页：矛盾，不能假装取全了。
                    Some(total) => Err(Error::Transport(format!(
                        "站点声明共有 {total} 条令牌，但第 {page} 页返回空列表，无法确认列表完整性"
                    ))),
                    // 没有 total 且本页为空 → 确实没有更多（含「一把令牌都没有」）。
                    None => Ok(collected),
                };
            }

            // 终止条件二：本页全是重复 id → 站点忽略了分页参数，再翻也是同一页。
            if added == 0 {
                return Ok(collected);
            }

            // 终止条件三：跑飞保护。宁可显式报错，也不交付被截断的列表。
            if page >= MAX_PAGES {
                return Err(Error::Transport(format!(
                    "已翻 {MAX_PAGES} 页仍未取全（已取 {} 条{}）；为避免交付不完整列表已中止，请先在站点端清理",
                    collected.len(),
                    total
                        .map(|t| format!("，站点声明共 {t} 条"))
                        .unwrap_or_default()
                )));
            }
            page += 1;
        }
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
        let req = self
            .request(Method::Post, format!("{base}/api/token/"), session)
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
            let remote_id = normalize_id(value.pointer("/data/id")).unwrap_or_default();
            return Ok(KeyMaterial::new(remote_id, key));
        }

        // 常规路径：创建成功后按名字定位刚建好的令牌（时间戳缺失/平局时取 id 最大者）
        let keys = self.list_keys(base_url, session).await?;
        let target = pick_newest_token(&keys, &spec.name).ok_or_else(|| {
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
            safe_path_segment(remote_id)?
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
        let url = format!(
            "{}/api/token/{}",
            normalize_base_url(base_url),
            safe_path_segment(remote_id)?
        );
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
