//! Sub2API 适配器（含 TOTP 二次验证）。
//!
//! **契约全部来自本地源码实测**（Sub2API 本地源码实测：
//! `internal/handler/auth_handler.go`、`internal/handler/api_key_handler.go`、
//! `internal/handler/dto/types.go`、`internal/handler/setting_handler.go`、
//! `internal/pkg/response/response.go`、`internal/server/routes/{auth,user}.go`）。
//!
//! 与 NewAPI 的三处关键差异：
//! 1. 响应信封是 `{code: 0, message: "success", data: ...}`（NewAPI 是 `{success, message, data}`）；
//! 2. 登录字段名是 **`email`** 而不是 `username`，且**密码明文提交**（没有登录加密端点）；
//! 3. **列表接口直接返回明文 `key`** —— 适配器必须在边界处剥掉，
//!    否则明文会顺着 `KeyMeta` 流进 DTO 与事件表（红线）。

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures_util::stream::{self, StreamExt};
use serde_json::{json, Value};

use super::transport::{HttpRequest, HttpTransport, Method};
use super::{
    json_str, map_http_error, normalize_base_url, parse_rate, scrub_error, Balance, Credentials,
    GroupInfo, KeyDailyUsage, KeyMaterial, KeyMeta, KeySpec, KeyStatus, Session, SiteAdapter,
    SiteFingerprint, SiteKind,
};
use crate::error::{Error, Result, SecondFactorKind};

/// 2FA 临时会话的有效期。源码里的登录会话是短时效的；这里取一个保守值，
/// 过期就退回「重新用账号密码登录拿一个新的 temp_token」，而不是拿旧 token 硬试。
const TWO_FA_TTL: Duration = Duration::from_secs(5 * 60);

/// TOTP 码长度（源码 `binding:"required,len=6"`）。
const TOTP_LEN: usize = 6;

/// 批量读明文时的并发上限（章程 §4.4 冻结值）。
///
/// Sub2API **没有**批量端点，只能逐个 `GET /api/v1/keys/{id}`。用 `buffered(N)` 把同时在飞
/// 的请求数限制在 N，同时保持**返回顺序 = 入参顺序**（与完成先后无关）。
pub const SUB2API_REVEAL_CONCURRENCY: usize = 4;

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
        // M28-S1 / B-191：`cf_clearance` 与 UA 绑定（Cloudflare 机制）——不一同回放等于白拿。
        // `None` 时**不加**这个头：与加字段前逐字一致（老会话 / 密码登录路径不受影响）。
        if let Some(ua) = &session.user_agent {
            headers.push(("User-Agent".to_string(), ua.clone()));
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
        // M21-S3 / B-165：同 NewAPI 侧——登录是用户主动的一次操作、不产孤儿 ⇒ 保持可重发。
        let req =
            HttpRequest::new(Method::Post, format!("{base}/api/v1/auth/login")).json_body(&body)?;
        let resp = self.transport.request(req).await?;
        if resp.status != 200 {
            return Err(classify_non_200("登录", &resp));
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
            return Err(classify_non_200("二次验证", &resp));
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

/// 非 200 响应的错误归类：先尝试 `classify_failure`（识别 turnstile/TOTP），
/// 否则 `map_http_error`。
///
/// **P1-9**：Sub2API 的 turnstile/TOTP 失败回 HTTP 400（`infraerrors.BadRequest`），
/// 旧实现 `post_login`/`post_login_2fa` 非 200 一律 `map_http_error` ⇒ 400 → `Transport`，
/// `classify_failure` 只在 HTTP 200（`unwrap_data`）时走得到 ⇒ 人工兜底窗口永不弹出。
fn classify_non_200(op: &str, resp: &super::transport::HttpResponse) -> Error {
    let value = resp.json_value().ok();
    if let Some(msg) = value.as_ref().and_then(|v| json_str(v, "/message")) {
        let classified = classify_failure(op, msg);
        if matches!(
            classified,
            Error::CaptchaRequired | Error::SecondFactorRequired { .. }
        ) {
            return classified;
        }
    }
    map_http_error(resp.status, &resp.body, resp.retry_after_secs())
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

/// `created_at` / `last_used_at` 是 RFC 3339 字符串。手写解析，**不引入时间库**。
///
/// 严格校验每一段的取值范围，并处理时区偏移：
/// 早先的版本不校验范围也不看偏移，于是 `2026-13-45T25:61:61Z` 与
/// `+08:00` 都会**静默返回一个错的** epoch（后者差 8 小时）——比返回 `None` 更糟
/// （M2-S1 复审 P2）。现在任何无法确定的值一律 `None`。
fn parse_rfc3339_secs(value: Option<&Value>) -> Option<i64> {
    let raw = value.and_then(|v| v.as_str())?;
    let (date, rest) = raw.split_once('T')?;

    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = date_parts.next()?.parse().ok()?;
    let day: i64 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    // 时区：`Z` / `+HH:MM` / `-HH:MM` / 无
    let (time_part, offset_secs) = split_timezone(rest)?;

    let mut time_parts = time_part.split(':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let minute: i64 = time_parts.next()?.parse().ok()?;
    let second: i64 = time_parts.next()?.split('.').next()?.parse().ok()?;
    if time_parts.next().is_some()
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }

    Some(
        days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
            - offset_secs,
    )
}

/// 切出「时间部分」与「时区偏移秒数」。无法确定时返回 `None`。
fn split_timezone(rest: &str) -> Option<(&str, i64)> {
    if let Some(time) = rest.strip_suffix('Z') {
        return Some((time, 0));
    }
    if let Some(time) = rest.strip_suffix('z') {
        return Some((time, 0));
    }
    // 找最后一个 `+` / `-`（时间部分里不会有这两种符号）
    let pos = rest.rfind(['+', '-'])?;
    let (time, offset) = rest.split_at(pos);
    let sign = if offset.starts_with('+') { 1 } else { -1 };
    let mut parts = offset[1..].split(':');
    let hours: i64 = parts.next()?.parse().ok()?;
    let minutes: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || hours > 23 || minutes > 59 {
        return None;
    }
    Some((time, sign * (hours * 3600 + minutes * 60)))
}

/// 从 `data` 里取出密钥数组与总数。
///
/// 真实站点走的是 `response.Paginated` → `data = {items, total, page, page_size, pages}`
/// （`internal/pkg/response/response.go` 的 `PaginatedData`）。
/// 只认数组的实现会让**真实站点的列表恒为空**（M2-S1 复审 P1-1）。
/// 为了兼容老版本/异常部署，裸数组形态也接受，但**认不出的形态必须报错**，
/// 绝不能静默返回空列表。
fn extract_keys_page(data: &Value) -> Result<(Vec<Value>, Option<i64>)> {
    if let Some(items) = data.as_array() {
        return Ok((items.clone(), None));
    }
    if let Some(items) = data.get("items").and_then(|v| v.as_array()) {
        let total = data
            .get("total")
            .and_then(|v| v.as_i64())
            .filter(|t| *t >= 0);
        return Ok((items.clone(), total));
    }
    Err(Error::Transport(
        "列举密钥的响应形态无法识别（既不是数组，也没有 items 字段）".into(),
    ))
}

/// 每次创建请求一个唯一的幂等键。不是秘密，用时间戳 + 自增序号即可。
fn new_idempotency_key() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("tianshu-relay-{nanos:x}-{seq:x}")
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

/// `GET /api/v1/groups/available` 的中间形态。
///
/// `id` 只用于和 `/groups/rates` 的键合并，**不进** `GroupInfo`（`GroupInfo` 没有 id 字段）。
/// `rate_multiplier` 是分组的基准倍率，当 `/groups/rates` 里没有该用户的专属覆盖倍率时回落到此值（M12-S2）。
struct RawGroup {
    id: Option<i64>,
    name: String,
    description: Option<String>,
    rate_multiplier: Option<f64>,
}

/// 解析 `GET /api/v1/groups/available` 的 `data`（M6-S4 / PRD FR-2）。
///
/// **真实形态**（本机 Sub2API 源码实测，见 M6-S4 spec §5.2）：`data` 是数组，
/// 元素为 `dto.Group`：`{"id":1,"name":"vip","description":"…","rate_multiplier":1.0, …}`。
/// 兼容形态 `data = {items: [...]}`（与既有 `extract_keys_page` 同口径；真实站点未观察到）。
///
/// 逐条跳过取不出名字的条目；**数组非空却一条都取不出**时报错——静默返回空列表等于
/// 告诉用户「站点没有可选分组」。
fn parse_available_groups(data: &Value) -> Result<Vec<RawGroup>> {
    let items = if let Some(items) = data.as_array() {
        items.clone()
    } else if let Some(items) = data.get("items").and_then(|v| v.as_array()) {
        items.clone()
    } else {
        return Err(Error::Transport(
            "分组响应的形态无法识别（既不是数组，也没有 items 字段）".into(),
        ));
    };

    let mut out: Vec<RawGroup> = Vec::with_capacity(items.len());
    for item in &items {
        let Some(name) = json_str(item, "/name").filter(|n| !n.is_empty()) else {
            continue;
        };
        out.push(RawGroup {
            id: item.get("id").and_then(|v| v.as_i64()),
            name: name.to_string(),
            description: json_str(item, "/description")
                .filter(|d| !d.is_empty())
                .map(|d| d.to_string()),
            rate_multiplier: item.get("rate_multiplier").and_then(parse_rate),
        });
    }
    if !items.is_empty() && out.is_empty() {
        return Err(Error::Transport(format!(
            "分组响应有 {} 条，但都取不出可用的分组名",
            items.len()
        )));
    }
    Ok(out)
}

/// 解析 `GET /api/v1/groups/rates` 的 `data`。
///
/// **真实形态**：对象 `{"<group_id>": <倍率>}`（Go 的 `map[int64]float64`）。
/// 仓库未接线时源码直接 `return nil, nil` → `data: null` → `Ok(None)`，调用方把该轮
/// 全部 `rate` 置 `None`（章程 §4.4：「`rates` 缺失时 `rate = None`」）。
///
/// 既不是对象也不是 `null` 的形态 → 报错：静默当作「没有倍率」会把站点改版伪装成正常结果。
fn parse_group_rates(data: &Value) -> Result<Option<HashMap<i64, f64>>> {
    if data.is_null() {
        return Ok(None);
    }
    let Some(map) = data.as_object() else {
        return Err(Error::Transport(
            "分组倍率响应的形态无法识别（既不是对象，也不是 null）".into(),
        ));
    };
    let mut rates: HashMap<i64, f64> = HashMap::with_capacity(map.len());
    for (key, value) in map {
        // 倍率统一走 `parse_rate`（B-91）：负数 / NaN / ±inf / 非数字 ⇒ `None` ⇒ 该条目**忽略**
        // （与既有口径一致：匹配不上任何分组的条目直接忽略）；`0` ⇒ `Some(0.0)`，**保留**
        // （免费分组必须能显示成 0，不能被当成「没有倍率」丢掉）。
        let (Ok(id), Some(rate)) = (key.parse::<i64>(), parse_rate(value)) else {
            continue;
        };
        rates.insert(id, rate);
    }
    Ok(Some(rates))
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
    // M14-S3：Sub2API `list_keys` 列表项含 `quota`（限额）/ `quota_used`（已用）（M9-S6 §2）。
    // 单位 USD（与 `balance()` 实测一致）。缺字段 ⇒ `None`（不写 0）。
    let quota_used = item.get("quota_used").and_then(|v| v.as_f64());
    let quota_limit = item.get("quota").and_then(|v| v.as_f64());
    let currency = if quota_used.is_some() || quota_limit.is_some() {
        Some("USD".to_string())
    } else {
        None
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
        quota_used,
        quota_limit,
        currency,
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
            Error::FingerprintMismatch(format!("{shown} 不是 JSON，可能不是 Sub2API 站点"))
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
        let mut collected: Vec<KeyMeta> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut page: u32 = 1;
        // 源码里 `ParsePagination` 的默认每页 20，上限 1000
        const PAGE_SIZE: u32 = 100;
        const MAX_PAGES: u32 = 100;

        loop {
            let url = format!("{base}/api/v1/keys?page={page}&page_size={PAGE_SIZE}");
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
            let (items, total) = extract_keys_page(&data)?;
            let page_len = items.len();

            // 逐项**只挑白名单字段**：响应里带明文 `key`，整体克隆会把密钥带出来
            let parsed: Vec<KeyMeta> = items.iter().filter_map(key_meta_from).collect();
            if page_len > 0 && parsed.is_empty() {
                return Err(Error::Transport(format!(
                    "第 {page} 页有 {page_len} 条密钥但都缺少可用的 id，无法安全分页"
                )));
            }

            let mut added = 0usize;
            for meta in parsed {
                if seen.insert(meta.remote_id.clone()) {
                    collected.push(meta);
                    added += 1;
                }
            }

            // 站点声明了总数 → 以它为准
            if let Some(total) = total {
                if (collected.len() as i64) >= total {
                    return Ok(collected);
                }
            }
            if page_len == 0 {
                return match total {
                    Some(total) if (total as usize) > collected.len() => {
                        Err(Error::Transport(format!(
                            "站点声明共有 {total} 条密钥，但第 {page} 页返回空列表，无法确认列表完整性"
                        )))
                    }
                    _ => Ok(collected),
                };
            }
            if added == 0 {
                // 本页全是重复 id → 站点忽略了分页参数
                return Ok(collected);
            }
            if page >= MAX_PAGES {
                return Err(Error::Transport(format!(
                    "已取满 {MAX_PAGES} 页仍未取全（已取 {} 条{}）；为避免交付不完整列表已中止",
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
        let mut body = json!({ "name": spec.name });
        if let Some(group) = spec.group.as_deref().filter(|g| !g.is_empty()) {
            // M19-S1 / B-161：**不再静默丢弃**。此前的写法是
            // `.and_then(|g| g.parse::<i64>().ok())`——解析失败就什么都不做，
            // 于是界面传来的分组名（`"gpt plus"`）被悄悄扔掉，密钥建出来不带 `group_id`，
            // 用户要到 agent 收到 403 才知道。这里改成响亮失败：一个字节都不发，
            // 直接把「该传什么」告诉用户。
            //
            // 为什么错误类型是 `InvalidInput` 而不是 `Transport`：这不是网络问题，
            // 是**入参形态**不符合站点约定（见 `Error::InvalidInput` 的注释）。
            let id = group.parse::<i64>().map_err(|_| {
                Error::InvalidInput(format!(
                    "Sub2API 的分组要用数字 id（例如 \"2\"），收到的是 \"{group}\"；\
                     已拒绝创建——否则会建出一把没有绑定分组、调用时被站点 403 拒绝的密钥"
                ))
            })?;
            body["group_id"] = json!(id);
        }
        if let Some(quota) = spec.quota_limit {
            body["quota"] = json!(quota);
        }

        let mut req =
            Self::request(Method::Post, format!("{base}/api/v1/keys"), session).json_body(&body)?;
        // 服务端在 `idempotency.observe_only=false` 的部署下会**强制**要求这个头，
        // 缺失直接 400（`internal/service/idempotency.go:222`）。默认配置是观察期所以不报错，
        // 但我们不该依赖那个默认值——始终带一个唯一的键即可。
        req.headers
            .push(("Idempotency-Key".to_string(), new_idempotency_key()));
        // M21-S3 / B-165：这里**故意**不标 `retry_unsafe`。
        //
        // 与 NewAPI 的关键差异：NewAPI 的 `POST /api/token` 没有幂等键，读超时后重试
        // 会在站点上多留一把产品不知道的令牌；Sub2API 有这个 `Idempotency-Key`，
        // 而 `RetryingTransport` 重试时发的是 `req.clone()`——**同一个键**——
        // 服务端据此去重。所以读超时后重试不会多出一把密钥。
        // 键是在**本函数内**生成的（每次调用一个新键），所以只有传输层的重试
        // 才会复用同一个键；上层重调 `create_key` 会拿到新键、也就没有去重保护——
        // 这也是 `probe` / 本步都把重试放在传输层而不是上层的原因。
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
            .request(
                // M21-S3 / B-165：DELETE 终态幂等，但**不能安全重试**——读超时时那次删除
                // 可能已经成功，重试的 404 会让用户以为密钥从没存在过。
                Self::request(Method::Delete, url, session).retry_unsafe(),
            )
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
            // Sub2API 有余额端点：读到了就是可观测（M7-S2）。
            known: true,
        })
    }

    /// M6-S4 / PRD FR-2：`GET /api/v1/groups/available` + `GET /api/v1/groups/rates` 两次调用合并。
    ///
    /// - 顺序固定：先 `available`（决定分组集合与顺序），再 `rates`（决定倍率）；
    /// - `rates` 的 `data` 为 `null`（源码里仓库未接线）→ 全部回落到 `rate_multiplier`；
    /// - `rates` 里没有该分组 → 回落到 `available` 里的 `rate_multiplier`（M12-S2：
    ///   基准倍率比「倍率未知」有用；覆盖倍率优先，仅当 `rates` 里缺失时才回落）；
    /// - `rates` 调用本身失败（非 2xx / 信封失败）→ **传播错误**，不降级为全 `None`
    ///   （否则会话失效会被伪装成「倍率未知」，违反 M5-S2 的会话失效可见性）。
    async fn available_groups(&self, base_url: &str, session: &Session) -> Result<Vec<GroupInfo>> {
        let base = normalize_base_url(base_url);

        let resp = self
            .transport
            .request(Self::request(
                Method::Get,
                format!("{base}/api/v1/groups/available"),
                session,
            ))
            .await?;
        if resp.status != 200 {
            return Err(scrub_error(map_http_error(
                resp.status,
                &resp.body,
                resp.retry_after_secs(),
            )));
        }
        let groups = parse_available_groups(&Self::unwrap_data(&resp, "拉取分组")?)?;

        let resp = self
            .transport
            .request(Self::request(
                Method::Get,
                format!("{base}/api/v1/groups/rates"),
                session,
            ))
            .await?;
        if resp.status != 200 {
            return Err(scrub_error(map_http_error(
                resp.status,
                &resp.body,
                resp.retry_after_secs(),
            )));
        }
        let rates = parse_group_rates(&Self::unwrap_data(&resp, "拉取分组倍率")?)?;

        Ok(groups
            .into_iter()
            .map(|group| GroupInfo {
                // M19-S1 / B-161：`id` 必须传下去。Sub2API 建密钥要的是数字主键
                // （`group_id`），而 `name` 是给人看的（`"gpt plus"`）。此前这里把 id
                // 丢在适配器里，界面只能拿名字当标识往下传，`create_key` 解析成整数失败
                // 后**静默丢弃** ⇒ 用户选了分组，密钥建出来却不带分组。
                id: group.id.map(|id| id.to_string()),
                rate: group
                    .id
                    .and_then(|id| rates.as_ref().and_then(|map| map.get(&id).copied()))
                    .or(group.rate_multiplier),
                name: group.name,
                description: group.description,
            })
            .collect())
    }

    /// M6-S4 / PRD FR-2：无批量端点 → **有界并发**逐个 `GET /api/v1/keys/{id}`。
    ///
    /// - 空入参 → 空 `Vec`，**0 请求**；
    /// - 返回顺序与入参**逐位一致**（`buffered` 按流的顺序产出，与完成先后无关）；
    /// - 同时在飞 ≤ [`SUB2API_REVEAL_CONCURRENCY`]；
    /// - 按入参顺序的**首个**失败立即返回：流被丢弃 → 在飞请求取消，不再发新请求；
    /// - 单条的路径段校验 / 错误映射 / 脱敏沿用既有 [`SiteAdapter::reveal_key`]。
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

        // 先把每个 id 的 future 建出来（`async fn` 是惰性的：建出来不等于发请求），
        // 再交给 `buffered(N)` 驱动 —— 它同时保证「在飞 ≤ N」与「产出顺序 = 入参顺序」。
        let mut pending = Vec::with_capacity(remote_ids.len());
        for id in remote_ids {
            pending.push(self.reveal_key(&base, session, id));
        }
        let mut stream = Box::pin(stream::iter(pending).buffered(SUB2API_REVEAL_CONCURRENCY));
        let mut out: Vec<(String, KeyMaterial)> = Vec::with_capacity(remote_ids.len());
        while let Some(result) = stream.next().await {
            // 单条路径的错误文案来自 `map_http_error`，可能回显站点原文（含密钥）。
            // 既有 `reveal_key` 的行为不动（章程 §3），因此在**本方法**的边界上再脱一次敏
            // ——章程 §4.4 要求新增方法不得把密钥写进任何 `Error` 文案。
            let material = result.map_err(scrub_error)?;
            out.push((material.remote_id.clone(), material));
        }
        Ok(out)
    }

    /// M14-S3 / PRD FR-3：`GET /api/v1/user/api-keys/:id/usage/daily?days=30`。
    ///
    /// 返回 items 元素（`APIKeyDailyUsagePoint`，源码 `usage_log_types.go:210`）解析成的
    /// [`KeyDailyUsage`] 列表。`items` 为空（新建 key 无用量）⇒ 空 `Vec`，不报错。
    ///
    /// 节流：本方法只负责**单把 key 一次请求**；每轮调不调、并发上限、失败如何处理由
    /// `service::refresh_site` 决定（spec §7.4：每 key 每轮一次、并发 ≤ 2、失败静默）。
    async fn fetch_key_daily_usage(
        &self,
        base_url: &str,
        session: &Session,
        remote_id: &str,
    ) -> Result<Vec<KeyDailyUsage>> {
        let base = normalize_base_url(base_url);
        let id = safe_path_segment(remote_id)?;
        let url = format!("{base}/api/v1/user/api-keys/{id}/usage/daily?days=30");
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
        let data = Self::unwrap_data(&resp, "拉取 key 用量")?;
        // items 在 data 顶层（handler `response.Success(c, gin.H{"items": items, ...})`，
        // M9-S6 实测一致）。`items` 缺失或非数组 ⇒ 空 `Vec`（不报错：新建 key 本就无用量）。
        let items = data.get("items").and_then(|v| v.as_array());
        let mut out: Vec<KeyDailyUsage> = Vec::new();
        if let Some(items) = items {
            for item in items {
                // 字段名按 Sub2API 源码 `APIKeyDailyUsagePoint`：`input_tokens` / `output_tokens`
                //（非任务描述的 `tokens_in` / `tokens_out`——spec §11 差异②）。
                // 缺字段的条目用 0 兜底，不跳过（一条里缺 cost 不该丢掉它的 tokens）。
                out.push(KeyDailyUsage {
                    date: json_str(item, "/date").unwrap_or_default().to_string(),
                    requests: item.get("requests").and_then(|v| v.as_i64()).unwrap_or(0),
                    input_tokens: item
                        .get("input_tokens")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0),
                    output_tokens: item
                        .get("output_tokens")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0),
                    total_tokens: item
                        .get("total_tokens")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0),
                    cost: item.get("cost").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    // M43-S2：缺字段 ≠ 0 元。标记「有没有上报」，读侧据此显示「未知」。
                    cost_reported: item.get("cost").is_some_and(|v| !v.is_null()),
                });
            }
        }
        Ok(out)
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
        user_agent: None,
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
            "quota_used": 2.5,
        });
        let meta = key_meta_from(&item).expect("应能解析");
        assert_eq!(meta.remote_id, "12");
        assert_eq!(meta.name, "codex/daily");
        assert_eq!(meta.group.as_deref(), Some("3"));
        assert_eq!(meta.status, KeyStatus::Enabled);
        // M14-S3：quota / quota_used 解析进 KeyMeta（USD）。
        assert_eq!(meta.quota_used, Some(2.5));
        assert_eq!(meta.quota_limit, Some(10.0));
        assert_eq!(meta.currency.as_deref(), Some("USD"));

        let text = format!("{meta:?}");
        assert!(!text.contains("sk-SUB2API"), "KeyMeta 泄漏明文: {text}");
        // 用「序列化等价物」代替：`KeyMeta` 本身不实现 Serialize（它不该出现在线上契约里），
        // 这里逐字段拼一遍，确认没有任何字段携带明文（含 M14-S3 新增的用量字段）。
        let flattened = format!(
            "{}{}{:?}{:?}{:?}{:?}{:?}{:?}{:?}",
            meta.remote_id,
            meta.name,
            meta.group,
            meta.status,
            meta.created_at,
            meta.last_used_at,
            meta.quota_used,
            meta.quota_limit,
            meta.currency,
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
    fn classify_non_200_maps_turnstile_400_to_captcha_required() {
        // P1-9：Sub2API turnstile 失败回 HTTP 400，旧实现 map_http_error → Transport，
        // classify_failure 只在 200 时走得到 ⇒ 人工兜底窗口永不弹出。
        let resp = crate::site::transport::HttpResponse::new(
            400,
            br#"{"code":400,"message":"turnstile verification failed"}"#.to_vec(),
        );
        assert!(matches!(
            classify_non_200("登录", &resp),
            Error::CaptchaRequired
        ));
    }

    #[test]
    fn classify_non_200_maps_totp_400_to_second_factor() {
        let resp = crate::site::transport::HttpResponse::new(
            400,
            br#"{"code":400,"message":"invalid totp code"}"#.to_vec(),
        );
        assert!(matches!(
            classify_non_200("登录", &resp),
            Error::SecondFactorRequired { .. }
        ));
    }

    #[test]
    fn classify_non_200_falls_back_to_transport_for_plain_400() {
        let resp = crate::site::transport::HttpResponse::new(
            400,
            br#"{"code":400,"message":"bad request"}"#.to_vec(),
        );
        assert!(matches!(
            classify_non_200("登录", &resp),
            Error::Transport(_)
        ));
    }

    #[test]
    fn classify_non_200_handles_non_json_body() {
        let resp = crate::site::transport::HttpResponse::new(400, b"not json".to_vec());
        assert!(matches!(
            classify_non_200("登录", &resp),
            Error::Transport(_)
        ));
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
