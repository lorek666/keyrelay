//! M14-S3：Sub2API `fetch_key_daily_usage` + NewAPI/Sub2API `list_keys` 用量解析测试（spec §12）。
//!
//! 字段名用 Sub2API 源码真实名（`input_tokens`/`output_tokens`，非任务描述的 `tokens_in`/`tokens_out`——
//! spec §11 差异②）。

use serde_json::json;
use tianshu_relay_core::gateway::quota::{KeyQuotaSnapshot, QuotaRank};
use tianshu_relay_core::site::newapi::NewApi;
use tianshu_relay_core::site::sub2api::Sub2Api;
use tianshu_relay_core::site::transport::{HttpResponse, MockTransport};
use tianshu_relay_core::site::{Session, SiteAdapter};

fn bearer() -> Session {
    Session {
        cookies: Vec::new(),
        access_token: Some("tok-probe".to_string()),
        user_id: Some("7".to_string()),
        user_agent: None,
    }
}

const BASE: &str = "https://probe.example.com";

// ---------- Sub2API fetch_key_daily_usage ----------

#[tokio::test]
async fn sub2api_fetch_daily_usage_parses_items() {
    let resp = HttpResponse::json(
        200,
        json!({
            "code": 0, "message": "success",
            "data": {
                "items": [{
                    "date": "2026-10-15",
                    "requests": 5,
                    "input_tokens": 1000,
                    "output_tokens": 500,
                    "cache_read_tokens": 0,
                    "cache_write_tokens": 0,
                    "total_tokens": 1500,
                    "cost": 0.12,
                    "actual_cost": 0.10
                }],
                "days": 30,
                "start_date": "2026-09-16",
                "end_date": "2026-10-15"
            }
        }),
    )
    .expect("构造响应");
    let adapter = Sub2Api::new(MockTransport::new(vec![resp]));
    let points = adapter
        .fetch_key_daily_usage(BASE, &bearer(), "158")
        .await
        .unwrap();
    assert_eq!(points.len(), 1);
    let p = &points[0];
    assert_eq!(p.date, "2026-10-15");
    assert_eq!(p.requests, 5);
    assert_eq!(
        p.input_tokens, 1000,
        "字段名用源码 input_tokens（非 tokens_in）"
    );
    assert_eq!(
        p.output_tokens, 500,
        "字段名用源码 output_tokens（非 tokens_out）"
    );
    assert_eq!(p.total_tokens, 1500);
    assert_eq!(p.cost, 0.12);
}

#[tokio::test]
async fn sub2api_fetch_daily_usage_empty_items_is_empty_vec() {
    // M9-S6 实测：新建 key 无用量，items 为空 ⇒ 空 Vec，不报错。
    let resp = HttpResponse::json(
        200,
        json!({"code":0,"message":"success","data":{"items":[],"days":30,"start_date":"2026-09-16","end_date":"2026-10-15"}}),
    )
    .expect("构造响应");
    let adapter = Sub2Api::new(MockTransport::new(vec![resp]));
    let points = adapter
        .fetch_key_daily_usage(BASE, &bearer(), "158")
        .await
        .unwrap();
    assert!(points.is_empty());
}

#[tokio::test]
async fn sub2api_fetch_daily_usage_items_missing_is_empty() {
    // items 字段缺失 ⇒ 空 Vec（容错，不报错）。
    let resp = HttpResponse::json(
        200,
        json!({"code":0,"message":"success","data":{"days":30}}),
    )
    .expect("构造响应");
    let adapter = Sub2Api::new(MockTransport::new(vec![resp]));
    let points = adapter
        .fetch_key_daily_usage(BASE, &bearer(), "158")
        .await
        .unwrap();
    assert!(points.is_empty());
}

#[tokio::test]
async fn sub2api_fetch_daily_usage_code_nonzero_is_err() {
    let resp = HttpResponse::json(
        200,
        json!({"code":1,"message":"invalid api key","data":null}),
    )
    .expect("构造响应");
    let adapter = Sub2Api::new(MockTransport::new(vec![resp]));
    assert!(adapter
        .fetch_key_daily_usage(BASE, &bearer(), "158")
        .await
        .is_err());
}

#[tokio::test]
async fn sub2api_fetch_daily_usage_401_is_auth_failed() {
    let resp = HttpResponse::new(
        401,
        br#"{"code":"INVALID_TOKEN","message":"Invalid token"}"#.to_vec(),
    );
    let adapter = Sub2Api::new(MockTransport::new(vec![resp]));
    let err = adapter
        .fetch_key_daily_usage(BASE, &bearer(), "158")
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        tianshu_relay_core::error::Error::AuthFailed(_)
    ));
}

// ---------- NewAPI list_keys quota 解析 ----------

#[tokio::test]
async fn newapi_list_keys_parses_used_quota_into_usd() {
    // used_quota=500_000, quota_per_unit=500_000 (DEFAULT) ⇒ quota_used=1.0 USD
    // remain_quota=4_500_000 ⇒ 总额 = used + remaining = 5_000_000 ⇒ 10.0 USD
    let resp = HttpResponse::json(
        200,
        json!({
            "success": true,
            "data": {
                "items": [{
                    "id": 12, "name": "codex/daily", "status": 1,
                    "used_quota": 500_000, "remain_quota": 4_500_000, "unlimited_quota": false
                }],
                "total": 1
            }
        }),
    )
    .expect("构造响应");
    let adapter = NewApi::new(MockTransport::new(vec![resp]));
    let keys = adapter.list_keys(BASE, &bearer()).await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(
        keys[0].quota_used,
        Some(1.0),
        "used_quota / quota_per_unit = 1.0 USD"
    );
    assert_eq!(
        keys[0].quota_limit,
        Some(10.0),
        "quota_limit 必须是 used + remain = 10.0 USD，不能把 remain 当总额"
    );
    assert_eq!(keys[0].currency.as_deref(), Some("USD"));
}

#[tokio::test]
async fn newapi_half_used_key_ranks_healthy_not_exhausted() {
    // 复审 H2 回归：used=5, remain=5 是「用了一半」，不是「额度耗尽」。
    // 旧实现把 remain 当 limit，ratio=5/5=1.0 ⇒ Exhausted，完全反过来。
    let resp = HttpResponse::json(
        200,
        json!({
            "success": true,
            "data": {
                "items": [{
                    "id": 15, "name": "half-used", "status": 1,
                    "used_quota": 2_500_000, "remain_quota": 2_500_000,
                    "unlimited_quota": false
                }],
                "total": 1
            }
        }),
    )
    .expect("构造响应");
    let adapter = NewApi::new(MockTransport::new(vec![resp]));
    let keys = adapter.list_keys(BASE, &bearer()).await.unwrap();
    assert_eq!(keys[0].quota_used, Some(5.0));
    assert_eq!(keys[0].quota_limit, Some(10.0));
    let snapshot = KeyQuotaSnapshot::from_stored(
        keys[0].quota_used,
        keys[0].quota_limit,
        Some(1_000),
        "newapi_list_keys",
    );
    assert_eq!(snapshot.rank_at(1_000), QuotaRank::Healthy);
    assert_ne!(snapshot.rank_at(1_000), QuotaRank::Exhausted);
}

#[tokio::test]
async fn newapi_list_keys_unlimited_quota_means_no_limit() {
    let resp = HttpResponse::json(
        200,
        json!({
            "success": true,
            "data": {
                "items": [{
                    "id": 13, "name": "unlimited", "status": 1,
                    "used_quota": 100_000, "remain_quota": 0, "unlimited_quota": true
                }],
                "total": 1
            }
        }),
    )
    .expect("构造响应");
    let adapter = NewApi::new(MockTransport::new(vec![resp]));
    let keys = adapter.list_keys(BASE, &bearer()).await.unwrap();
    assert_eq!(keys[0].quota_used, Some(0.2), "100_000 / 500_000 = 0.2");
    assert_eq!(
        keys[0].quota_limit, None,
        "unlimited_quota=true ⇒ quota_limit=None"
    );
}

#[tokio::test]
async fn newapi_list_keys_missing_quota_is_none() {
    // 缺 used_quota/remain_quota ⇒ None（不写 0）；全 None 时不标币种。
    let resp = HttpResponse::json(
        200,
        json!({
            "success": true,
            "data": {
                "items": [{"id": 14, "name": "noquota", "status": 1}],
                "total": 1
            }
        }),
    )
    .expect("构造响应");
    let adapter = NewApi::new(MockTransport::new(vec![resp]));
    let keys = adapter.list_keys(BASE, &bearer()).await.unwrap();
    assert_eq!(keys[0].quota_used, None);
    assert_eq!(keys[0].quota_limit, None);
    assert_eq!(keys[0].currency, None, "全 None 时不标币种");
}

// ---------- Sub2API list_keys quota 解析 ----------

#[tokio::test]
async fn sub2api_list_keys_parses_quota_fields() {
    let resp = HttpResponse::json(
        200,
        json!({
            "code": 0, "message": "success",
            "data": {
                "items": [{
                    "id": 158, "name": "codex/daily", "group_id": 3, "status": "active",
                    "quota": 10.0, "quota_used": 2.5
                }],
                "total": 1
            }
        }),
    )
    .expect("构造响应");
    let adapter = Sub2Api::new(MockTransport::new(vec![resp]));
    let keys = adapter.list_keys(BASE, &bearer()).await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].quota_used, Some(2.5));
    assert_eq!(keys[0].quota_limit, Some(10.0));
    assert_eq!(keys[0].currency.as_deref(), Some("USD"));
}

#[tokio::test]
async fn newapi_default_fetch_daily_usage_is_empty_no_request() {
    // NewAPI 不覆盖 fetch_key_daily_usage（默认返回空 Vec，零请求）——
    // spec §11 差异③：NewAPI 无 per-key 日趋势端点。
    let mock = MockTransport::new(vec![]);
    let adapter = NewApi::new(mock.clone());
    let points = adapter
        .fetch_key_daily_usage(BASE, &bearer(), "12")
        .await
        .unwrap();
    assert!(points.is_empty());
    assert_eq!(mock.request_count(), 0, "NewAPI 默认实现不发请求");
}
