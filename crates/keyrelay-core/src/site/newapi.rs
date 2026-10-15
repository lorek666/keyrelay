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
use std::collections::{HashMap, HashSet};

use super::password_crypto::{encrypt_password, PasswordEncryptionKey};
use super::transport::{HttpRequest, HttpTransport, Method};
use super::{
    json_str, map_http_error, normalize_base_url, parse_rate, scrub_error, Balance, Credentials,
    GroupInfo, KeyMaterial, KeyMeta, KeySpec, KeyStatus, Session, SiteAdapter, SiteFingerprint,
    SiteKind,
};
use crate::error::{Error, Result, SecondFactorKind};

pub const DEFAULT_QUOTA_PER_UNIT: i64 = 500_000;

/// `POST /api/token/batch/keys` 单次可提交的 id 数上限（站点硬上限）。
///
/// 证据：`controller/token.go` 的 `GetTokenKeysBatch` 在 `len(ids) > 100` 时直接返回
/// `MsgBatchTooMany`（`Max: 100`）。超限时适配器**顺序**分块，不并发——该路由挂了
/// `middleware.CriticalRateLimit()`。
pub const NEWAPI_BATCH_KEYS_MAX_IDS: usize = 100;

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
    ///
    /// `op` 是操作名（「登录」/「列举令牌」/…），会进入错误文案——
    /// 站点对任何需要认证的操作都可能回 `success:false`，不带操作名会让用户误判（复核 P2-4）。
    fn unwrap_success(resp: &super::transport::HttpResponse, op: &str) -> Result<Value> {
        let value = resp.json_value()?;
        let ok = value
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if !ok {
            let message = json_str(&value, "/message")
                .unwrap_or("站点返回失败")
                .to_string();
            return Err(classify_failure(op, &message));
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
        // P3-21 / DEBUG-REPORT-v3 §3-21：username 前后空白会让上游 validator 必拒
        //（用户看到 Go 英文 400）——请求体里 trim 掉。预检（B-120）校验形态但不
        // trim，这里兜底。
        let username = cred.username.trim();
        match self.fetch_encryption_key(base).await? {
            Some(key) => {
                let password_encrypted = encrypt_password(&cred.password, &key)?;
                Ok(json!({
                    "username": username,
                    "password_encrypted": password_encrypted,
                    "encryption_key_id": key.kid,
                }))
            }
            None => Ok(json!({
                "username": username,
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
/// `"99"` 时曾产出 `"\"99\""`，会污染 DTO 与后续落库定位）。
///
/// BACKLOG B-35：**JSON number 形态必须是真正的整数且为正**——
/// - 非整数（`1.5`）会被 `to_string()` 成 `"1.5"` 塞进 DTO 与请求路径，而
///   `numeric_id()` 解析失败会退化为 0，让「同名取 id 最大者」在平局时选错令牌；
/// - `0`（与负数）在 `pick_newest_token` 里和「解析失败」不可区分，同样会选错。
///
/// 两种形态一律返回 `Err`（文案含「令牌 id」），由调用方决定整页失败还是中止操作。
///
/// 与 `parse_total` 的宽松口径**故意不对称**：`total` 只是个终止提示，多探一页也不会错；
/// 而 id 决定「读/吊销哪一把令牌」，只能严格。因此 `2.0` 这类整数值浮点在这里也被拒绝
/// （它 `to_string()` 成 `"2.0"`，同样会让 `numeric_id()` 退化）。
///
/// 返回 `Ok(None)` 表示站点**没给**可用 id（缺失 / `null` / 非标量）：
/// 沿用既有的「都缺少可用的 id」判定，不是本步要收紧的对象。
fn normalize_id(value: Option<&Value>) -> Result<Option<String>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => match n.as_i64() {
            Some(id) if id > 0 => Ok(Some(id.to_string())),
            Some(id) => Err(Error::Transport(format!(
                "站点返回的令牌 id 不是正整数（{id}），已拒绝用它定位令牌"
            ))),
            None => Err(Error::Transport(format!(
                "站点返回的令牌 id 不是整数（{n}），已拒绝用它定位令牌"
            ))),
        },
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        _ => Ok(None),
    }
}

/// 宽松解析站点声明的 `total`：接受整数、可解析为整数的字符串、以及整数值的浮点。
///
/// 返回 `None` 表示「站点没给可用的总数」——此时靠「空页 / 全重复页」判定到底。
fn parse_total(value: &Value) -> Option<i64> {
    let parsed = match value {
        Value::Number(n) => n.as_i64().or_else(|| {
            // 25.0 这类浮点：只在小数部分为 0 时接受，避免把 25.5 当成 25
            let f = n.as_f64()?;
            (f.fract() == 0.0).then_some(f as i64)
        }),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    };
    // 负数是无意义的声明。若照单全收，`collected.len() >= total` 会在第一页就成立，
    // 于是静默交付被截断的列表（M1-S3/S4 复审 P2-1 实测 `total:-5` 只发 1 次请求）。
    // 视为「站点没给可用总数」，退回「空页 / 全重复页」的终止判定。
    parsed.filter(|t| *t >= 0)
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

/// 带操作上下文的失败归类。
///
/// 站点原文先过 `redact::scrub`（BACKLOG B-36：`AuthFailed` 直接携带站点原文，
/// 若站点把密钥回显在错误文案里就会原样外流）。
fn classify_failure(op: &str, message: &str) -> Error {
    let scrubbed = crate::redact::scrub(message);
    match classify_login_message(&scrubbed) {
        Error::AuthFailed(detail) => Error::AuthFailed(format!("{op}被站点拒绝（{detail}）")),
        // 验证码 / 二次验证与操作无关，保持原样
        other => other,
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

/// 解析 `GET /api/user/self/groups` 的 `data` 对象（M12-S1）。
///
/// 站点契约（NewAPI 上游源码 `controller/group.go` `GetUserGroups`）：
/// `data = { "<分组名>": { "ratio": <number>, "desc": <string> } }`
///
/// - `ratio` 为正数 → `Some(rate)`；
/// - `ratio` 为 `"auto"` 或非数字 → `None`（倍率未知，不兜底 1×）；
/// - `desc` 为空字符串 → `None`。
///
/// 兼容 `rate` 与 `ratio` 两个字段名（不同 fork 可能用不同的名字）。
fn parse_user_groups(data: &Value) -> Result<Vec<GroupInfo>> {
    let obj = data
        .as_object()
        .ok_or_else(|| Error::Transport("分组响应 data 不是对象".into()))?;

    let mut out: Vec<GroupInfo> = Vec::with_capacity(obj.len());
    for (name, info) in obj {
        if name.is_empty() {
            continue;
        }
        let rate = info
            .get("ratio")
            .or_else(|| info.get("rate"))
            .and_then(parse_rate);
        let description = json_str(info, "/desc")
            .or_else(|| json_str(info, "/description"))
            .filter(|d| !d.is_empty())
            .map(|d| d.to_string());
        out.push(GroupInfo {
            name: name.clone(),
            rate,
            description,
        });
    }
    Ok(out)
}

fn parse_key_meta(item: &Value, quota_per_unit: i64) -> Result<Option<KeyMeta>> {
    // B-35：id 非法（非整数 / 0 / 负数）→ 整页失败，绝不静默跳过这一条
    // （静默跳过等于交付一份被悄悄截断的令牌列表）。
    let Some(remote_id) = normalize_id(item.get("id"))? else {
        return Ok(None);
    };
    let name = json_str(item, "/name").unwrap_or_default().to_string();
    let group = json_str(item, "/group")
        .filter(|g| !g.is_empty())
        .map(|g| g.to_string());
    // M14-S3：NewAPI `list_keys` 列表项含 `used_quota` / `remain_quota` / `unlimited_quota`
    //（M9-S6 §1）。整数 token 配额单位，`/ quota_per_unit` 换算成 USD（与 `balance()` 同口径）。
    // `quota_per_unit` 是 `/api/user/self` 字段、`list_keys` 响应不返回，这里用适配器持有的值
    //（`DEFAULT_QUOTA_PER_UNIT` 兜底，见 spec §11 差异⑤）。缺字段 ⇒ `None`（不写 0）。
    let unit = quota_per_unit.max(1) as f64;
    let quota_used = item
        .get("used_quota")
        .and_then(|v| v.as_i64())
        .map(|q| q as f64 / unit);
    let unlimited = item
        .get("unlimited_quota")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let quota_limit = if unlimited {
        None
    } else {
        item.get("remain_quota")
            .and_then(|v| v.as_i64())
            .map(|q| q as f64 / unit)
    };
    // 只在至少解析到一个用量字段时才标币种（避免给「全 None」的 key 一个误导性的 USD 标签）。
    let currency = if quota_used.is_some() || quota_limit.is_some() {
        Some("USD".to_string())
    } else {
        None
    };
    Ok(Some(KeyMeta {
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
        quota_used,
        quota_limit,
        currency,
    }))
}

impl<T: HttpTransport> NewApi<T> {
    /// 一次 `POST /api/token/batch/keys`，返回 `令牌 id → 明文` 的映射。
    ///
    /// 站点契约（M6-S4 spec §5.1）：请求体 `{"ids":[<int>, …]}`，
    /// 响应 `{"success":true,"data":{"keys":{"<id>":"<key>", …}}}`。
    /// 未命中的 id（已删除 / 不属于当前账号）**不会**出现在 `keys` 里，由调用方发现。
    async fn batch_keys_once(
        &self,
        base: &str,
        session: &Session,
        ids: &[i64],
    ) -> Result<HashMap<i64, String>> {
        let body = json!({ "ids": ids });
        let req = self
            .request(
                Method::Post,
                format!("{base}/api/token/batch/keys"),
                session,
            )
            .json_body(&body)?;
        let resp = self.transport.request(req).await?;
        if resp.status != 200 {
            return Err(scrub_error(map_http_error(
                resp.status,
                &resp.body,
                resp.retry_after_secs(),
            )));
        }
        let value = Self::unwrap_success(&resp, "批量读取令牌明文")?;
        let keys = value
            .pointer("/data/keys")
            .and_then(|v| v.as_object())
            .ok_or_else(|| Error::Transport("批量读明文响应缺少 data.keys 对象".into()))?;

        let mut out: HashMap<i64, String> = HashMap::with_capacity(keys.len());
        for (key, value) in keys {
            // JSON 对象键一定是字符串。解析不出 id / 值不是字符串的条目直接忽略：
            // 调用方只按自己请求的 id 取值，多余的键不影响结果。
            let (Ok(id), Some(secret)) = (key.parse::<i64>(), value.as_str()) else {
                continue;
            };
            out.insert(id, secret.to_string());
        }
        Ok(out)
    }
}

#[async_trait]
impl<T: HttpTransport + 'static> SiteAdapter for NewApi<T> {
    fn kind(&self) -> SiteKind {
        SiteKind::NewApi
    }

    async fn detect(&self, base_url: &str) -> Result<SiteFingerprint> {
        let url = format!("{}/api/status", normalize_base_url(base_url));
        // 复核 N-2：文案用掩过 userinfo 的形态，请求仍用 `url`（一字不改）。
        let shown = super::display_url(&url);
        let resp = self
            .transport
            .request(HttpRequest::new(Method::Get, url.clone()))
            .await?;

        if resp.status != 200 {
            return Err(Error::FingerprintMismatch(format!(
                "{shown} 返回 {}",
                resp.status
            )));
        }

        let value = resp.json_value().map_err(|_| {
            Error::FingerprintMismatch(format!("{shown} 不是 JSON，可能不是 NewAPI 站点"))
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
                let value = Self::unwrap_success(&resp, "登录")?;
                // `user_id` 有两个真实落点：旧版在 `data.id`，新版在 `data.user.id`
                // （`newapi.example.com` 实测只有后者）。只读一个会让另一个形态
                // 静默丢掉 user_id（M9-S1）。
                let user_id = value
                    .pointer("/data/id")
                    .or_else(|| value.pointer("/data/user/id"))
                    .and_then(|v| v.as_i64())
                    .map(|id| id.to_string());
                // 两个来源都要留（M9-S1，真实站点实测）：
                // ① 响应体 `data.access_token`（新版 NewAPI 主路径，走 `Authorization: Bearer`）；
                // ② `Set-Cookie`（旧版/仍依赖会话的端点）。
                // 早先的实现把 `access_token` 写死 `None`，于是在**不发 Set-Cookie、
                // 只回 body token** 的站点上，登录返回 200 却拿到一个空会话——
                // 随后每个带会话的请求都 401（`newapi.example.com` 实测复现）。
                let access_token = json_str(&value, "/data/access_token").map(str::to_string);
                let cookies = resp.set_cookies();
                if access_token.is_none() && cookies.is_empty() {
                    // 明确的失败。返回空会话会让「登录成功」和「什么都做不了」同时成立，
                    // 而用户看到的是下一跳的 401，排障时根本指不回登录这一步。
                    return Err(Error::AuthFailed(
                        "登录响应既没有 access_token 也没有 Set-Cookie，无法建立会话".into(),
                    ));
                }
                Ok(Session {
                    cookies,
                    access_token,
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
            let value = Self::unwrap_success(&resp, "列举令牌")?;
            let items = extract_items(&value);
            // `total` 缺失或不可解析时不能当作「本页条数」，否则会在第一页就静默停住（复核 N-3）。
            // 字符串 `"25"` / 浮点 `25.0` 也接受（复核 P2-5：真实站点理论上应回整数，
            // 但把它当成「缺失」会白白多探一页）。
            let total = value.pointer("/data/total").and_then(parse_total);
            let page_len = items.len();

            let mut parsed: Vec<KeyMeta> = Vec::with_capacity(items.len());
            for item in &items {
                // B-35：非法 id（非整数 / 0 / 负数）会让整页失败，只有「站点没给 id」
                // 才跳过——静默跳过非法 id 等于交付一份被悄悄截断的令牌列表。
                if let Some(meta) = parse_key_meta(item, self.quota_per_unit)? {
                    parsed.push(meta);
                }
            }
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

            // 终止条件三：跑飞保护。
            //
            // 判定用 `page > MAX_PAGES` 而不是 `>=`：第 `MAX_PAGES` 页**已取到的数据是有效的**，
            // 我们只是还需要**一次**探测请求才能确认到底（空页或全重复页）。若在这里就报错，
            // 「站点忽略 `page_size`（默认 10 条/页）+ 恰好 1000 把令牌 + 响应无 `total`」
            // 这个真实可达的形态会被误报为「取不全」（第三轮复核 P2-2）。
            if page > MAX_PAGES {
                return Err(Error::Transport(format!(
                    "已取满 {MAX_PAGES} 页仍未取全（已取 {} 条{}）；为避免交付不完整列表已中止，请先在站点端清理",
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
        let value = Self::unwrap_success(&resp, "创建令牌")?;

        // 少数版本直接在响应里回明文
        if let Some(key) = json_str(&value, "/data/key") {
            // B-35：id 非法时不再退回空 `remote_id`（那样产出的令牌既定位不了也吊销不了）
            let remote_id = normalize_id(value.pointer("/data/id"))?.unwrap_or_default();
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
        let value = Self::unwrap_success(&resp, "读取令牌明文")?;
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
        Self::unwrap_success(&resp, "删除令牌")?;
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
        let value = Self::unwrap_success(&resp, "查询余额")?;
        // 「不知道」不得被当成「余额 0」（DEBUG 报告 §1.7 / M7-S2 复审 S-2 的口径）。
        //
        // 修复前的形态是 `raw_quota.unwrap_or(0)` + 硬写 `known: true`：字段缺失或是浮点时
        // 余额被编成 0，而 `notify/rules.rs` 的 BalanceLow 照常触发——用户收到一条
        // 「余额不足」，去充值页却看到一个正常数字，**下一次他就不再相信这条告警了**。
        // 假告警的代价不是多一条通知，是整条通知链路失去信用。
        //
        // 判据只看 `quota`：它定义「这个站点的余额能不能观测」。
        // `used_quota` 缺失也走未知态——它与 `quota` 来自同一个响应体，读到一半就是没读到；
        // 而给它编一个 `0.0` 正是同一个「把不知道当成 0」的错误，只是换了个字段。
        let Some(raw_quota) = value.pointer("/data/quota").and_then(|v| v.as_i64()) else {
            return Ok(Balance::unknown("USD"));
        };
        let Some(used_quota) = value.pointer("/data/used_quota").and_then(|v| v.as_i64()) else {
            return Ok(Balance::unknown("USD"));
        };
        // `quota_per_unit` 缺失**不影响**可观测性：那是单位换算，不是余额本身。
        // 换算单位缺失时用适配器自己的常量兜底——那是已知的本地值，不是编造。
        let unit = value
            .pointer("/data/quota_per_unit")
            .and_then(|v| v.as_i64())
            .unwrap_or(self.quota_per_unit)
            .max(1);

        Ok(Balance {
            currency: "USD".to_string(),
            remaining: raw_quota as f64 / unit as f64,
            used: used_quota as f64 / unit as f64,
            raw_quota: Some(raw_quota),
            quota_per_unit: Some(unit),
            // NewAPI 有余额端点，且这一次真的读到了：可观测。
            known: true,
        })
    }

    /// M12-S1：`GET /api/user/self/groups`（替代旧的 `/api/token/auto-groups`）。
    ///
    /// 旧端点只返回分组名字符串数组、不含倍率；新端点返回用户可用的全部分组 + 倍率 + 描述。
    async fn available_groups(&self, base_url: &str, session: &Session) -> Result<Vec<GroupInfo>> {
        let url = format!("{}/api/user/self/groups", normalize_base_url(base_url));
        let resp = self
            .transport
            .request(self.request(Method::Get, url, session))
            .await?;
        if resp.status != 200 {
            return Err(scrub_error(map_http_error(
                resp.status,
                &resp.body,
                resp.retry_after_secs(),
            )));
        }
        let value = Self::unwrap_success(&resp, "拉取分组")?;
        parse_user_groups(value.get("data").unwrap_or(&Value::Null))
    }

    /// M6-S4 / PRD FR-2：`POST /api/token/batch/keys` 批量读明文。
    ///
    /// - 空入参 → 空 `Vec`，**0 请求**；
    /// - `n ≤ NEWAPI_BATCH_KEYS_MAX_IDS` → **恰好 1 次**请求（验收标准）；
    /// - `n > 100` → 顺序分块（站点硬上限，spec D-4）；
    /// - 返回顺序与入参**逐位一致**；站点少回任何一个 id → `NotFound`，不交付部分结果。
    async fn reveal_keys(
        &self,
        base_url: &str,
        session: &Session,
        remote_ids: &[String],
    ) -> Result<Vec<(String, KeyMaterial)>> {
        if remote_ids.is_empty() {
            return Ok(Vec::new());
        }
        let base = normalize_base_url(base_url);

        // 站点契约是 `ids: []int`：非正整数 id 在本地拦下，一个请求都不发。
        // 错误文案里的 id 过 scrub —— 调用方若误把密钥当 id 传进来，也不会被回显。
        let mut numeric: Vec<i64> = Vec::with_capacity(remote_ids.len());
        for id in remote_ids {
            let parsed = id.parse::<i64>().ok().filter(|v| *v > 0).ok_or_else(|| {
                Error::Transport(format!(
                    "NewAPI 批量读明文只接受正整数令牌 id（站点契约 ids: []int），收到 {}",
                    crate::redact::scrub(id)
                ))
            })?;
            numeric.push(parsed);
        }

        let mut secrets: HashMap<i64, String> = HashMap::with_capacity(numeric.len());
        for chunk in numeric.chunks(NEWAPI_BATCH_KEYS_MAX_IDS) {
            for (id, secret) in self.batch_keys_once(&base, session, chunk).await? {
                secrets.entry(id).or_insert(secret);
            }
        }

        let mut out: Vec<(String, KeyMaterial)> = Vec::with_capacity(remote_ids.len());
        let mut missing: Vec<&str> = Vec::new();
        for (raw, id) in remote_ids.iter().zip(&numeric) {
            match secrets.get(id) {
                Some(secret) => out.push((raw.clone(), KeyMaterial::new(raw.clone(), secret))),
                None => missing.push(raw),
            }
        }
        if !missing.is_empty() {
            // 站点对未命中的 id 静默丢弃（`GetTokenKeysByIds` 只回命中行）：
            // 必须由适配器发现，绝不交付「短一截」的结果。
            return Err(Error::NotFound(format!(
                "站点未返回以下令牌的明文（可能已被删除或不属于当前账号）：{}",
                crate::redact::scrub(&missing.join(", "))
            )));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_user_groups_normal() {
        let data = json!({
            "default": {"ratio": 1, "desc": "默认分组"},
            "vip": {"ratio": 0.5, "desc": "VIP 折扣"}
        });
        let groups = parse_user_groups(&data).unwrap();
        assert_eq!(groups.len(), 2);
        let default = groups.iter().find(|g| g.name == "default").unwrap();
        assert_eq!(default.rate, Some(1.0));
        assert_eq!(default.description.as_deref(), Some("默认分组"));
        let vip = groups.iter().find(|g| g.name == "vip").unwrap();
        assert_eq!(vip.rate, Some(0.5));
        assert_eq!(vip.description.as_deref(), Some("VIP 折扣"));
    }

    #[test]
    fn parse_user_groups_ratio_auto_is_none() {
        let data = json!({
            "auto": {"ratio": "auto", "desc": "自动分组"}
        });
        let groups = parse_user_groups(&data).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].rate, None);
    }

    #[test]
    fn parse_user_groups_ratio_missing_is_none() {
        let data = json!({
            "default": {"desc": "默认分组"}
        });
        let groups = parse_user_groups(&data).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].rate, None);
    }

    #[test]
    fn parse_user_groups_rate_field_fallback() {
        // 兼容用 `rate` 而非 `ratio` 的 fork
        let data = json!({
            "svip": {"rate": 0.3, "desc": "超级 VIP"}
        });
        let groups = parse_user_groups(&data).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].rate, Some(0.3));
    }

    #[test]
    fn parse_user_groups_desc_empty_is_none() {
        let data = json!({
            "default": {"ratio": 1, "desc": ""}
        });
        let groups = parse_user_groups(&data).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].description, None);
    }

    #[test]
    fn parse_user_groups_desc_missing_is_none() {
        let data = json!({
            "default": {"ratio": 1}
        });
        let groups = parse_user_groups(&data).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].description, None);
    }

    #[test]
    fn parse_user_groups_empty_object() {
        let data = json!({});
        let groups = parse_user_groups(&data).unwrap();
        assert!(groups.is_empty());
    }

    #[test]
    fn parse_user_groups_not_object_errors() {
        let data = json!(["default", "vip"]);
        assert!(parse_user_groups(&data).is_err());
    }

    #[test]
    fn parse_user_groups_free_group_keeps_zero() {
        let data = json!({
            "free": {"ratio": 0, "desc": "免费分组"}
        });
        let groups = parse_user_groups(&data).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].rate, Some(0.0));
    }
}
