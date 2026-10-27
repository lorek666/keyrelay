//! M14-S3：service `collect_key_usage` 编排测试（spec §12）。
//!
//! 覆盖：Sub2API refresh 写 usage_samples + keys.quota_used；fetch 失败静默不阻塞；
//! NewAPI refresh 写 keys.quota_used 但不写 usage_samples（无日趋势端点）。

use serde_json::json;
use tianshu_relay_core::service::{ServiceConfig, TianshuRelayService};
use tianshu_relay_core::site::transport::{HttpResponse, MockTransport};
use tianshu_relay_core::site::Credentials;
use tianshu_relay_core::store::Store;

// ---------- Sub2API 响应夹具 ----------

fn sub2api_settings() -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"code":0,"message":"success","data":{"site_name":"测试","totp_enabled":false}}),
    )
    .expect("构造响应")
}
fn sub2api_login() -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"code":0,"message":"success","data":{"access_token":"tok","user":{"id":7}}}),
    )
    .expect("构造响应")
}
fn sub2api_profile() -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"code":0,"message":"success","data":{"balance":10.0,"total_recharged":20.0}}),
    )
    .expect("构造响应")
}
fn sub2api_keys(quota: f64, used: f64) -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"code":0,"message":"success","data":{"items":[{
            "id":158,"name":"k","group_id":3,"status":"active",
            "quota":quota,"quota_used":used
        }],"total":1}}),
    )
    .expect("构造响应")
}
fn sub2api_usage() -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"code":0,"message":"success","data":{
            "items":[{"date":"2026-10-15","requests":5,"input_tokens":1000,
                      "output_tokens":500,"total_tokens":1500,"cost":0.12}],
            "days":30,"start_date":"2026-09-16","end_date":"2026-10-15"
        }}),
    )
    .expect("构造响应")
}

async fn new_service(
    responses: Vec<HttpResponse>,
) -> (TianshuRelayService<MockTransport>, tempfile::TempDir) {
    let store = Store::open_in_memory().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let service = TianshuRelayService::new(
        store,
        MockTransport::new(responses),
        ServiceConfig::in_memory(dir.path().to_path_buf()),
    );
    (service, dir)
}

#[tokio::test]
async fn sub2api_refresh_writes_usage_samples_and_key_quota() {
    // mock 序列：① NewAPI detect 消费（失败：data 无 version/quota_per_unit）
    // ② Sub2API detect 消费（成功）③ login ④ balance ⑤ list_keys ⑥ fetch_key_daily_usage
    let (service, _dir) = new_service(vec![
        sub2api_settings(),
        sub2api_settings(),
        sub2api_login(),
        sub2api_profile(),
        sub2api_keys(10.0, 2.5),
        sub2api_usage(),
    ])
    .await;

    let site = service.add_site("https://api.example.com").await.unwrap();
    service
        .login(site.id, Credentials::new("me@example.com", "pw"))
        .await
        .unwrap();

    // 本地登记一把 key（remote_id=158，与站点侧 list_keys 的 id 对应）
    let key_id = service
        .store()
        .insert_key(site.id, "k", "kr/s/i/f", Some("158"), None)
        .unwrap();

    let summary = service.refresh_all().await.unwrap();
    assert_eq!(summary.sites_ok, 1, "Sub2API 站点应刷新成功");

    // keys.quota_used 从 list_keys 的 quota_used=2.5 写入
    let row = service.store().get_key(key_id).unwrap().unwrap();
    assert_eq!(row.quota_used, Some(2.5));
    assert_eq!(row.quota_limit, Some(10.0));
    assert_eq!(row.currency.as_deref(), Some("USD"));

    // usage_samples 有数据（fetch_key_daily_usage 返回 1 条）
    let samples = service.store().recent_key_usage(key_id, 30).unwrap();
    assert_eq!(samples.len(), 1, "应写入 1 条日用量采样");
    assert_eq!(samples[0].cost, 0.12);
    assert_eq!(samples[0].input_tokens, 1000, "字段名 input_tokens");
}

#[tokio::test]
async fn sub2api_fetch_failure_does_not_block_refresh() {
    // 节流静默（spec §7.4）：fetch_key_daily_usage 返回 500 ⇒ refresh_all 仍 Ok，
    // sites_failed 不增（fetch 失败静默记 event，不让 refresh 失败）。
    // keys.quota_used 仍更新（来自 list_keys，与 fetch 无关）。
    let (service, _dir) = new_service(vec![
        sub2api_settings(), // NewAPI detect 消费（失败）
        sub2api_settings(), // Sub2API detect 消费（成功）
        sub2api_login(),
        sub2api_profile(),
        sub2api_keys(10.0, 2.5),
        // 第 6 个响应：usage/daily 返回 500（fetch 失败）
        HttpResponse::new(500, b"boom".to_vec()),
    ])
    .await;

    let site = service.add_site("https://api.example.com").await.unwrap();
    service
        .login(site.id, Credentials::new("me@example.com", "pw"))
        .await
        .unwrap();
    let key_id = service
        .store()
        .insert_key(site.id, "k", "kr/s/i/f", Some("158"), None)
        .unwrap();

    let summary = service.refresh_all().await.unwrap();
    assert_eq!(summary.sites_ok, 1, "fetch 失败不应让站点计入失败");
    assert_eq!(summary.sites_failed, 0, "fetch 失败静默，sites_failed=0");

    // keys.quota_used 仍更新（来自 list_keys，fetch 失败不影响）
    let row = service.store().get_key(key_id).unwrap().unwrap();
    assert_eq!(row.quota_used, Some(2.5));

    // usage_samples 为空（fetch 失败，没写入）
    let samples = service.store().recent_key_usage(key_id, 30).unwrap();
    assert!(samples.is_empty(), "fetch 失败 ⇒ usage_samples 为空");
}

// ---------- NewAPI ----------

fn newapi_status() -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"success":true,"data":{"version":"v0.9.1","quota_per_unit":500000}}),
    )
    .expect("构造响应")
}
fn newapi_encryption_disabled() -> HttpResponse {
    HttpResponse::json(200, json!({"success":true,"data":{"enabled":false}})).expect("构造响应")
}
fn newapi_login() -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"success":true,"data":{"access_token":"tok","user":{"id":7}}}),
    )
    .expect("构造响应")
}
fn newapi_self() -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"success":true,"data":{"quota":5000000,"used_quota":500000,"quota_per_unit":500000}}),
    )
    .expect("构造响应")
}
fn newapi_tokens(used_quota: i64, remain_quota: i64, unlimited: bool) -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"success":true,"data":{"items":[{
            "id":12,"name":"k","status":1,
            "used_quota":used_quota,"remain_quota":remain_quota,"unlimited_quota":unlimited
        }],"total":1}}),
    )
    .expect("构造响应")
}

#[tokio::test]
async fn newapi_refresh_writes_key_quota_without_usage_samples() {
    // NewAPI 无 per-key 日趋势端点：refresh 写 keys.quota_used（来自 list_keys used_quota），
    // 不写 usage_samples（fetch_key_daily_usage 默认返回空 Vec，零请求）。
    // mock 序列：① status ② encryption-key ③ login ④ user/self(balance) ⑤ token(list_keys)
    let (service, _dir) = new_service(vec![
        newapi_status(),
        newapi_encryption_disabled(),
        newapi_login(),
        newapi_self(),
        newapi_tokens(500_000, 4_500_000, false),
    ])
    .await;

    let site = service.add_site("https://relay.example.com").await.unwrap();
    service
        .login(site.id, Credentials::new("me", "pw"))
        .await
        .unwrap();
    let key_id = service
        .store()
        .insert_key(site.id, "k", "kr/s/i/f", Some("12"), None)
        .unwrap();

    let summary = service.refresh_all().await.unwrap();
    assert_eq!(summary.sites_ok, 1);

    // keys.quota_used = used_quota / quota_per_unit = 500000/500000 = 1.0 USD
    // quota_limit = (used_quota + remain_quota) / quota_per_unit = 10.0 USD
    let row = service.store().get_key(key_id).unwrap().unwrap();
    assert_eq!(row.quota_used, Some(1.0));
    assert_eq!(row.quota_limit, Some(10.0));

    // NewAPI 不写 usage_samples（无日趋势端点）
    let samples = service.store().recent_key_usage(key_id, 30).unwrap();
    assert!(samples.is_empty(), "NewAPI 无日趋势，usage_samples 应为空");
}
