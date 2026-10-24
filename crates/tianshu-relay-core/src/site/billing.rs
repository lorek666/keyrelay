//! M43-S2：站点账单的**只读**探测与导入（NewAPI `/api/log/self`）。
//!
//! 三条红线（spec §4.4，复审逐条核）：
//! 1. **只 GET**：全程只有 `GET`，不向站点写任何东西；
//! 2. **原始日志正文不入库**：只解析 `{day, quota/cost, requests}`，条目里可能有的
//!    prompt/response/payload 一律**不保留、不回传、不写日志**；
//! 3. **`partial` 如实报**：达到 `max_pages` 仍未取完 ⇒ `partial = true`。
//!
//! 本模块**不碰存储层**：解析出的按天账单通过 `sink` 交给调用方（命令层写 `site_bills`）。

use serde_json::Value;

use crate::error::{Error, Result};
use crate::site::transport::{HttpRequest, HttpResponse, HttpTransport, Method};
use crate::site::Session;

/// 一个站点的账单上下文。
pub struct SiteBilling<'a> {
    pub site_id: i64,
    pub base_url: &'a str,
    /// 站点配额单位（NewAPI 默认 500000 = 1 USD）。`quota / quota_per_unit` = 金额。
    pub quota_per_unit: i64,
}

/// 探测结论（五分类，spec §4.4）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BillProbe {
    /// 200 + JSON 信封 + 可识别的条目形状。`currency` 是站点自报币种（大多没有）。
    Supported { currency: Option<String> },
    /// 404 / 405 / 非 JSON（SPA 兜底页）。
    Unsupported,
    /// 401 / 403（或 200 的 `success:false` 且文案指向登录/权限）。
    NeedsLogin,
    /// 其余（网络 / 5xx / 解析失败）。`reason` 已 scrub。
    Failed { reason: String },
}

/// 导入结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportOutcome {
    /// 写入/更新的天数。
    pub imported: usize,
    /// 实际请求的页数。
    pub pages: usize,
    /// 达到 `max_pages` 仍未取完 ⇒ true（界面必须显示「只导入了最近 N 页」）。
    pub partial: bool,
    /// 站点自报的币种（站点没给 ⇒ `None`）。
    pub currency: Option<String>,
    /// 是否用上了调用方传入的 `currency`（只在站点没给币种时才可能为 true）。
    pub currency_override_used: bool,
}

/// 一天（或一页里的一天）的原始账单。
#[derive(Clone, Debug, PartialEq)]
pub struct RawBill {
    pub day: String,
    pub amount: Option<f64>,
    pub requests: Option<i64>,
}

/// 分页上限（spec §4.4：默认 10 / 上限 20）。
pub const DEFAULT_MAX_PAGES: usize = 10;
pub const HARD_MAX_PAGES: usize = 20;
const PAGE_SIZE: usize = 100;

fn auth_headers(session: &Session) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    if let Some(token) = session.access_token.as_deref().filter(|t| !t.is_empty()) {
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
    if let Some(ua) = session.user_agent.as_deref().filter(|u| !u.is_empty()) {
        headers.push(("User-Agent".to_string(), ua.to_string()));
    }
    headers
}

fn log_self_url(base_url: &str, page: usize, page_size: usize) -> String {
    let base = base_url.trim_end_matches('/');
    format!("{base}/api/log/self?p={page}&page_size={page_size}")
}

/// 从信封里取条目数组：`data: []` 或 `data.items: []`（与 NewAPI 的两种形态都兼容）。
fn extract_items(value: &Value) -> Option<Vec<Value>> {
    match value.get("data") {
        Some(Value::Array(items)) => Some(items.clone()),
        Some(Value::Object(_)) => value
            .pointer("/data/items")
            .and_then(|v| v.as_array())
            .cloned(),
        _ => None,
    }
}

fn site_currency(value: &Value) -> Option<String> {
    // 两种位置都收：信封里 `data.currency`，或顶层的 `currency`（不同站点/版本不一）。
    ["/data/currency", "/currency"]
        .iter()
        .find_map(|path| value.pointer(path).and_then(|v| v.as_str()))
        .map(|s| s.trim().to_ascii_uppercase())
        .filter(|s| !s.is_empty())
}

fn message_of(value: &Value) -> String {
    value
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn looks_like_auth_problem(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    m.contains("登录")
        || m.contains("login")
        || m.contains("未授权")
        || m.contains("unauthor")
        || m.contains("权限")
        || m.contains("forbidden")
        || m.contains("token")
}

/// 把一次响应分类成 `BillProbe`（探测与导入共用，避免两处判据分叉）。
fn classify(resp: &HttpResponse) -> BillProbe {
    match resp.status {
        401 | 403 => BillProbe::NeedsLogin,
        404 | 405 => BillProbe::Unsupported,
        200 => match resp.json_value() {
            Ok(value) => {
                if value.get("success").and_then(|v| v.as_bool()) == Some(false) {
                    let message = message_of(&value);
                    return if looks_like_auth_problem(&message) {
                        BillProbe::NeedsLogin
                    } else {
                        BillProbe::Failed {
                            reason: crate::redact::scrub(&message),
                        }
                    };
                }
                match extract_items(&value) {
                    Some(_) => BillProbe::Supported {
                        currency: site_currency(&value),
                    },
                    // 200 + JSON 但不是可识别的条目形状 ⇒ 当作不支持（不猜）。
                    None => BillProbe::Unsupported,
                }
            }
            // 非 JSON（SPA 兜底页）⇒ 不支持。
            Err(_) => BillProbe::Unsupported,
        },
        status => BillProbe::Failed {
            reason: format!("HTTP {status}"),
        },
    }
}

/// 只读探测：**一次** GET、`page_size=1`、不翻页、不写库。
pub async fn probe_bill_import(
    transport: &dyn HttpTransport,
    site: &SiteBilling<'_>,
    session: &Session,
) -> BillProbe {
    let mut req = HttpRequest::new(Method::Get, log_self_url(site.base_url, 1, 1));
    req.headers = auth_headers(session);
    match transport.request(req).await {
        Ok(resp) => classify(&resp),
        Err(err) => BillProbe::Failed {
            reason: crate::redact::scrub(&err.to_string()),
        },
    }
}

/// 只读导入：最多 `max_pages` 页（默认 10 / 上限 20）、每页 ≤ 100 条。
///
/// 每解析出一页就按天聚合，循环结束后**逐天**调 `sink`（调用方写库）。
pub async fn import_site_bills(
    transport: &dyn HttpTransport,
    site: &SiteBilling<'_>,
    session: &Session,
    max_pages: Option<usize>,
    currency: Option<&str>,
    // `+ Send`：Tauri 的异步命令要求 future `Send`，而 sink 被跨 `await` 持有。
    sink: &mut (dyn FnMut(RawBill) + Send),
) -> Result<ImportOutcome> {
    // 币种白名单（不做汇率）：只接受 USD / CNY。
    let override_currency = match currency.map(str::trim).filter(|s| !s.is_empty()) {
        None => None,
        Some(c) => {
            let upper = c.to_ascii_uppercase();
            if upper != "USD" && upper != "CNY" {
                return Err(Error::Store("站点币种只支持 USD / CNY".into()));
            }
            Some(upper)
        }
    };
    let pages_cap = max_pages
        .unwrap_or(DEFAULT_MAX_PAGES)
        .clamp(1, HARD_MAX_PAGES);

    let quota_per_unit = site.quota_per_unit.max(1) as f64;
    let mut per_day: std::collections::BTreeMap<String, (f64, i64, bool)> =
        std::collections::BTreeMap::new();
    let mut site_currency_value: Option<String> = None;
    let mut pages = 0usize;
    let mut complete = false;
    let mut total: Option<usize> = None;
    let mut collected = 0usize;

    for page in 1..=pages_cap {
        let mut req = HttpRequest::new(Method::Get, log_self_url(site.base_url, page, PAGE_SIZE));
        req.headers = auth_headers(session);
        let resp = transport.request(req).await.map_err(|e| {
            Error::Transport(format!(
                "账单导入失败：{}",
                crate::redact::scrub(&e.to_string())
            ))
        })?;
        pages += 1;
        match classify(&resp) {
            BillProbe::Supported { currency } => {
                if site_currency_value.is_none() {
                    site_currency_value = currency;
                }
            }
            BillProbe::Unsupported => {
                return Err(Error::Store(
                    "该站点不支持账单导入（/api/log/self 不可用）".into(),
                ))
            }
            BillProbe::NeedsLogin => return Err(Error::Store("需要先登录该站点".into())),
            BillProbe::Failed { reason } => {
                return Err(Error::Transport(format!("账单导入失败：{reason}")))
            }
        }
        let value = resp.json_value().unwrap_or(Value::Null);
        if total.is_none() {
            total = value
                .get("total")
                .and_then(|v| v.as_u64())
                .or_else(|| value.pointer("/data/total").and_then(|v| v.as_u64()))
                .map(|v| v as usize);
        }
        let items = extract_items(&value).unwrap_or_default();
        collected += items.len();
        for item in &items {
            let Some((day, amount, requests)) = parse_item(item, quota_per_unit) else {
                continue;
            };
            let entry = per_day.entry(day).or_insert((0.0, 0, true));
            *entry = (
                entry.0 + amount.unwrap_or(0.0),
                entry.1 + requests.unwrap_or(1),
                entry.2 && amount.is_some(),
            );
        }
        if items.is_empty() {
            complete = true;
            break;
        }
        if let Some(total) = total {
            if collected >= total {
                complete = true;
                break;
            }
        }
    }

    let currency_override_used = site_currency_value.is_none() && override_currency.is_some();
    let final_currency = site_currency_value.or(override_currency);
    let imported = per_day.len();
    for (day, (amount, requests, all_amounts_present)) in per_day {
        sink(RawBill {
            day,
            // 任一 item 缺金额 ⇒ 该日合计未知，不能把缺的部分当 0（spec §4.6）。
            amount: if all_amounts_present {
                Some(amount)
            } else {
                None
            },
            requests: Some(requests),
        });
    }
    Ok(ImportOutcome {
        imported,
        pages,
        partial: !complete,
        currency: final_currency,
        currency_override_used,
    })
}

/// 解析一条日志：返回 `(day, amount, requests)`。
///
/// **只取数字字段**：`day`/`date`/`created_on` 字符串优先；否则用 `created_at`（unix 秒）
/// 换算成 **UTC** 日期（站点没给日期时的兜底，不猜站点时区）。金额优先 `cost`（站点直接给），
/// 否则 `quota / quota_per_unit`。其他字段（content/payload/prompt…）**一律不读**。
fn parse_item(item: &Value, quota_per_unit: f64) -> Option<(String, Option<f64>, Option<i64>)> {
    let day = ["day", "date", "created_on"]
        .iter()
        .find_map(|k| item.get(k).and_then(|v| v.as_str()))
        .map(|s| s.trim().to_string())
        .filter(|s| s.len() >= 10)
        .map(|s| s[..10].to_string())
        .or_else(|| {
            item.get("created_at")
                .and_then(|v| v.as_i64())
                .map(utc_day_from_unix)
        })?;
    let amount = item.get("cost").and_then(|v| v.as_f64()).or_else(|| {
        item.get("quota")
            .and_then(|v| v.as_f64())
            .map(|q| q / quota_per_unit)
    });
    let requests = item.get("count").and_then(|v| v.as_i64()).or(Some(1));
    Some((day, amount, requests))
}

/// unix 秒 → `YYYY-MM-DD`（**UTC**）。Howard Hinnant 的 civil_from_days。
fn utc_day_from_unix(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::transport::MockTransport;

    fn session() -> Session {
        Session {
            cookies: vec![("session".into(), "s1".into())],
            access_token: None,
            user_id: None,
            user_agent: None,
        }
    }

    fn site() -> SiteBilling<'static> {
        SiteBilling {
            site_id: 7,
            base_url: "https://relay.example.com",
            quota_per_unit: 500_000,
        }
    }

    #[tokio::test]
    async fn probe_classifies_the_five_shapes() {
        let cases = [
            (
                r#"{"success":true,"data":[],"total":0}"#,
                BillProbe::Supported { currency: None },
            ),
            ("not json", BillProbe::Unsupported),
            (
                r#"{"success":false,"message":"未登录"}"#,
                BillProbe::NeedsLogin,
            ),
        ];
        for (body, expected) in cases {
            let t = MockTransport::new(vec![HttpResponse::new(200, body)]);
            assert_eq!(probe_bill_import(&t, &site(), &session()).await, expected);
        }
        let t = MockTransport::new(vec![HttpResponse::new(404, "")]);
        assert_eq!(
            probe_bill_import(&t, &site(), &session()).await,
            BillProbe::Unsupported
        );
        let t = MockTransport::new(vec![HttpResponse::new(401, "")]);
        assert_eq!(
            probe_bill_import(&t, &site(), &session()).await,
            BillProbe::NeedsLogin
        );
        let t = MockTransport::new(vec![HttpResponse::new(500, "")]);
        assert!(matches!(
            probe_bill_import(&t, &site(), &session()).await,
            BillProbe::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn import_aggregates_per_day_and_reports_partial() {
        let body = r#"{"success":true,"data":[
            {"created_at":1700000000,"quota":500000},
            {"created_at":1700000100,"quota":250000},
            {"day":"2026-10-23","quota":100000}
        ],"total":3}"#;
        let t = MockTransport::new(vec![HttpResponse::new(200, body)]);
        let mut rows: Vec<RawBill> = Vec::new();
        let out = import_site_bills(&t, &site(), &session(), None, None, &mut |b| rows.push(b))
            .await
            .expect("导入");
        assert_eq!(out.imported, 2, "两天");
        assert!(!out.partial);
        assert_eq!(out.pages, 1);
        assert_eq!(rows[0].requests, Some(2), "同一天两条");
        assert_eq!(rows[0].amount, Some(1.5), "500000+250000 配额 = 1.5 USD");
    }

    #[tokio::test]
    async fn import_respects_the_page_cap_and_marks_partial() {
        let page =
            r#"{"success":true,"data":[{"created_at":1700000000,"quota":1000}],"total":999}"#;
        let t = MockTransport::new(vec![
            HttpResponse::new(200, page),
            HttpResponse::new(200, page),
        ]);
        let mut rows: Vec<RawBill> = Vec::new();
        let out = import_site_bills(&t, &site(), &session(), Some(2), None, &mut |b| {
            rows.push(b)
        })
        .await
        .expect("导入");
        assert_eq!(out.pages, 2);
        assert!(out.partial, "没取完 ⇒ partial");
    }

    #[tokio::test]
    async fn currency_override_only_fills_the_gap() {
        // 站点没给币种 + 传 USD ⇒ 用 USD
        let t = MockTransport::new(vec![HttpResponse::new(
            200,
            r#"{"success":true,"data":[],"total":0}"#,
        )]);
        let out = import_site_bills(&t, &site(), &session(), None, Some("usd"), &mut |_| {})
            .await
            .expect("导入");
        assert_eq!(out.currency.as_deref(), Some("USD"));
        assert!(out.currency_override_used);
        // 站点给了 CNY + 传 USD ⇒ 站点为准
        let t = MockTransport::new(vec![HttpResponse::new(
            200,
            r#"{"success":true,"data":[],"total":0,"currency":"CNY"}"#,
        )]);
        let out = import_site_bills(&t, &site(), &session(), None, Some("USD"), &mut |_| {})
            .await
            .expect("导入");
        assert_eq!(out.currency.as_deref(), Some("CNY"));
        assert!(!out.currency_override_used);
        // 非白名单 ⇒ Err
        let t = MockTransport::new(vec![HttpResponse::new(
            200,
            r#"{"success":true,"data":[]}"#,
        )]);
        assert!(
            import_site_bills(&t, &site(), &session(), None, Some("EUR"), &mut |_| {})
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn auth_and_unsupported_report_the_right_error() {
        let t = MockTransport::new(vec![HttpResponse::new(401, "")]);
        let err = import_site_bills(&t, &site(), &session(), None, None, &mut |_| {})
            .await
            .expect_err("401");
        assert!(err.to_string().contains("需要先登录"), "{err}");
        let t = MockTransport::new(vec![HttpResponse::new(404, "")]);
        let err = import_site_bills(&t, &site(), &session(), None, None, &mut |_| {})
            .await
            .expect_err("404");
        assert!(err.to_string().contains("不支持账单导入"), "{err}");
    }

    #[tokio::test]
    async fn import_only_ever_issues_get_requests() {
        // M43-S2 T11：账单导入是只读探测——全程只能发 GET。MockTransport
        // 记录了每一次请求的方法与 body，断言「全部 GET 且无 body」，
        // 而不是只看导入结果（结果正确时也可能偷偷写过）。
        let page =
            r#"{"success":true,"data":[{"created_at":1700000000,"quota":1000}],"total":999}"#;
        let transport = MockTransport::new(vec![
            HttpResponse::new(200, page),
            HttpResponse::new(200, page),
        ]);
        let mut rows: Vec<RawBill> = Vec::new();
        let out = import_site_bills(&transport, &site(), &session(), Some(2), None, &mut |b| {
            rows.push(b)
        })
        .await
        .expect("导入");
        assert_eq!(out.pages, 2);
        let reqs = transport.requests();
        assert_eq!(reqs.len(), 2, "两页 ⇒ 恰好两次请求");
        for req in &reqs {
            assert_eq!(req.method, Method::Get, "账单导入不得发写请求: {req:?}");
            assert!(
                req.body.as_ref().map(|b| b.is_empty()).unwrap_or(true),
                "GET 不得带 body: {req:?}"
            );
        }
    }

    #[tokio::test]
    async fn import_drops_raw_entry_payloads_and_never_sinks_them() {
        // M43-S2 T13：条目里可能带 prompt / response / payload 等原始
        // 正文——导入后 sink 里只能有 {day, amount, requests}，canary
        // 字符串必须在任何 sink 行的 Debug 文本里都找不到（证明不是
        // 「RawBill 没字段所以没存」的形式主义，而是解析真的丢了它）。
        let canary = "CANARY-PROMPT-7f3a9c";
        let body = format!(
            r#"{{"success":true,"data":[{{"created_at":1700000000,"quota":500000,"prompt":"{canary}","response":"{canary}","payload":{{"text":"{canary}"}}}}],"total":1}}"#
        );
        // B-224 长尾 canary 先命中证明（与 M43-S1 T7 同标准）：先证明
        // 「Debug 拼串 + contains」这套扫描器在行里真有 canary 时能命中，
        // 否则下面的零命中可能是扫描器空转。RawBill 只有 day/amount/
        // requests 三个字段——把 canary 放进 day 字段即可证明扫描路径。
        let probe = vec![RawBill {
            day: canary.to_string(),
            amount: None,
            requests: None,
        }];
        assert!(
            format!("{probe:?}").contains(canary),
            "扫描器必须能命中故意放进 sink 行的 canary，否则零命中是空转"
        );

        let transport = MockTransport::new(vec![HttpResponse::new(200, body.as_str())]);
        let mut rows: Vec<RawBill> = Vec::new();
        let out = import_site_bills(&transport, &site(), &session(), None, None, &mut |b| {
            rows.push(b)
        })
        .await
        .expect("导入");
        assert_eq!(out.imported, 1);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].amount, Some(1.0));
        let haystack = format!("{rows:?}");
        assert!(
            !haystack.contains(canary),
            "原始条目正文不得进入 sink 行: {haystack}"
        );
    }

    #[test]
    fn utc_day_conversion_matches_known_dates() {
        assert_eq!(utc_day_from_unix(0), "1970-01-01");
        assert_eq!(utc_day_from_unix(1_700_000_000), "2023-11-14");
        assert_eq!(utc_day_from_unix(1_800_000_000), "2027-01-15");
    }
}
