//! 模型清单采集测试（M14-S1 / B-99 ①）。
//!
//! M1-M4：`site::fetch_models` 纯函数层（解析 `data[].id` / Bearer key / 错误形态 / HTTP 错误）。
//! M5-M8：采集接线（开关 / 节流 / 失败静默）。
//!
//! **M39-S1 适配**：采集已从 `refresh_all` 移到 `refresh_model_catalog_once()`
//! （独立 60s 循环驱动，与刷新定时器解耦；见 `docs/specs/M39-S1-模型目录持久化与热更新.md`）。
//! 因此 M5-M8 的调用点从 `refresh_all()` 换成 `refresh_model_catalog_once()`；
//! 其中 M7 的语义**有意改变**：旧实现「每轮最多采 1 站」是为了不在一次刷新里打出一串
//! 带密钥请求，新实现用**有界并发 2** 达成同一目的 ⇒ 3 个站一轮内都会采到。

use std::sync::Arc;

use serde_json::json;
use tianshu_relay_core::service::{ServiceConfig, TianshuRelayService};
use tianshu_relay_core::site::{
    self,
    transport::{HttpResponse, MockTransport},
};
use tianshu_relay_core::store::Store;
use tianshu_relay_core::vault::{secret_ref, MemoryVault, Vault};

const KEY: &str = "sk-models-0123456789abcdef";
const BASE: &str = "https://relay.example.com";

fn models_response(ids: &[&str]) -> HttpResponse {
    let data: Vec<_> = ids.iter().map(|id| json!({"id": id})).collect();
    HttpResponse::json(200, json!({ "data": data })).expect("构造响应")
}

fn count_models_requests(transport: &MockTransport) -> usize {
    transport
        .requests()
        .iter()
        .filter(|r| r.url.contains("/v1/models"))
        .count()
}

// ============================================================ M1-M4：fetch_models 纯函数层

/// M1：解析 `data[].id` 列表（OpenAI 形态）。
#[tokio::test]
async fn fetch_models_parses_data_ids() {
    let transport = MockTransport::new(vec![models_response(&["gpt-4", "gpt-4o"])]);
    let models = site::fetch_models(&transport, BASE, KEY).await.unwrap();
    assert_eq!(models, vec!["gpt-4".to_string(), "gpt-4o".to_string()]);
}

/// M2：带 `Authorization: Bearer <key>`，且 URL 拼了 `/v1/models`。
#[tokio::test]
async fn fetch_models_sends_bearer_key() {
    let transport = MockTransport::new(vec![models_response(&[])]);
    let _ = site::fetch_models(&transport, BASE, KEY).await.unwrap();
    let reqs = transport.requests();
    assert_eq!(reqs.len(), 1);
    let auth = reqs[0]
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"));
    assert!(auth.is_some(), "请求必须带 Authorization 头");
    assert_eq!(
        auth.unwrap().1,
        format!("Bearer {KEY}"),
        "带的是站点 key，Bearer 前缀"
    );
    assert!(
        reqs[0].url.ends_with("/v1/models"),
        "URL 拼了 /v1/models: {}",
        reqs[0].url
    );
}

/// M3：非 OpenAI 形态（无 `data` 数组）⇒ `Err`。
#[tokio::test]
async fn fetch_models_rejects_non_openai_shape() {
    let transport = MockTransport::new(vec![
        HttpResponse::json(200, json!({"not_data": []})).unwrap()
    ]);
    let err = site::fetch_models(&transport, BASE, KEY).await.unwrap_err();
    assert!(err.to_string().contains("data"), "{err}");
}

/// M4：401 ⇒ `Err`，文案过 `scrub`（不回显 key）。
#[tokio::test]
async fn fetch_models_maps_http_errors() {
    let transport = MockTransport::new(vec![HttpResponse::json(
        401,
        json!({"message": format!("bad {KEY}")}),
    )
    .unwrap()]);
    let err = site::fetch_models(&transport, BASE, KEY).await.unwrap_err();
    let text = err.to_string();
    assert!(!text.contains(KEY), "失败文案不得含密钥: {text}");
}

// ============================================================ M5-M8：refresh_all 采集接线

struct Svc {
    _dir: tempfile::TempDir,
    service: TianshuRelayService<MockTransport>,
    transport: MockTransport,
}

/// 建 `site_count` 个站点（各带一把 key + 明文），不 login（无 session）。
/// `refresh_all` 对无 session 的站点跳过 balance/keys，于是 `/v1/models` 是唯一的网络请求。
fn setup_with_sites(site_count: usize) -> Svc {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let store = Store::open(&dir.path().join("tianshu-relay.db")).unwrap();
    let vault = Arc::new(MemoryVault::new());
    for i in 1..=site_count {
        let site_id = store
            .upsert_site("newapi", &format!("{BASE}/s{i}"), &format!("站{i}"))
            .unwrap();
        let reference = secret_ref("key", i, "secret");
        store
            .insert_key(
                site_id,
                &format!("k{i}"),
                &reference,
                Some(&i.to_string()),
                None,
            )
            .unwrap();
        vault.put(&reference, KEY).unwrap();
    }
    let transport = MockTransport::new(vec![]);
    let service = TianshuRelayService::new(
        store,
        transport.clone(),
        ServiceConfig {
            vault,
            home,
            backup_dir: dir.path().join("backups"),
        },
    );
    Svc {
        _dir: dir,
        service,
        transport,
    }
}

/// M5：`collect_models == false`（默认）⇒ 不采集（零 `/v1/models` 请求）。
#[tokio::test]
async fn disabled_collection_never_fetches() {
    let svc = setup_with_sites(2);
    // collect_models 默认 false，不 push 任何响应
    svc.service.refresh_model_catalog_once().await.unwrap();
    assert_eq!(
        count_models_requests(&svc.transport),
        0,
        "collect_models=false 时不发 /v1/models"
    );
}

/// M6：节流——第一次采（`last=None`），第二次在 `min_interval` 内不采。
#[tokio::test]
async fn throttle_respects_min_interval() {
    let svc = setup_with_sites(1);
    svc.service
        .store()
        .set_setting("collect_models", "true")
        .unwrap();
    // 默认 models_min_interval_secs = 1800
    svc.transport.push(models_response(&["gpt-4"]));
    svc.service.refresh_model_catalog_once().await.unwrap();
    assert_eq!(
        count_models_requests(&svc.transport),
        1,
        "第一次采（last=None ⇒ should_collect=true）"
    );

    // 第二次立即跑（interval 内）⇒ 不采（节流锚点 = last_attempt_at）
    svc.transport.push(models_response(&["gpt-4o"]));
    svc.service.refresh_model_catalog_once().await.unwrap();
    assert_eq!(
        count_models_requests(&svc.transport),
        1,
        "min_interval 内不重复采"
    );
}

/// M7（M39-S1 改写）：3 个站点都到期 ⇒ **一趟内都采**（有界并发 2），不是「每轮 1 个」。
///
/// 旧断言（每轮恰好 1 站）钉的是「别一次打出一串带密钥请求」这个**目的**；
/// 新实现用有界并发 2 达成同一目的，3 个站就该都采到（否则节流期内永远轮不到后两个）。
#[tokio::test]
async fn all_due_sites_are_collected_in_one_pass() {
    let svc = setup_with_sites(3);
    svc.service
        .store()
        .set_setting("collect_models", "true")
        .unwrap();
    for _ in 0..3 {
        svc.transport.push(models_response(&["gpt-4"]));
    }
    svc.service.refresh_model_catalog_once().await.unwrap();
    assert_eq!(
        count_models_requests(&svc.transport),
        3,
        "一趟内 3 个到期站点都要采（有界并发 2）"
    );
}

/// M8：采集失败（500）⇒ `refresh_all` 仍 `Ok`（不阻塞），且留 Debug 事件。
#[tokio::test]
async fn failed_fetch_keeps_previous_models() {
    let svc = setup_with_sites(1);
    svc.service
        .store()
        .set_setting("collect_models", "true")
        .unwrap();
    // 第一次成功
    svc.transport.push(models_response(&["gpt-4"]));
    svc.service.refresh_model_catalog_once().await.unwrap();

    // 第二次失败（500）
    svc.transport
        .push(HttpResponse::json(500, json!({})).unwrap());
    // 需要让节流放行：把 min_interval 设成 0（不节流）
    svc.service
        .store()
        .set_setting("models_min_interval_secs", "0")
        .unwrap();
    let summary = svc.service.refresh_model_catalog_once().await;
    assert!(summary.is_ok(), "采集失败不阻塞采集（返回摘要）");
    // 失败不清空已有目录（旧断言只查事件，这里补上目录本身）
    let site = svc.service.store().list_sites().unwrap()[0].id;
    assert_eq!(
        svc.service.store().site_models(site).unwrap(),
        vec!["gpt-4".to_string()],
        "失败不得清空已采到的目录"
    );

    // 失败静默留痕：Debug 事件含「模型清单采集失败」
    let events = svc.service.store().list_events(50).unwrap();
    assert!(
        events
            .iter()
            .any(|e| e.level == "debug" && e.message.contains("模型清单采集失败")),
        "失败静默但必须留痕：{:?}",
        events
            .iter()
            .map(|e| (&e.level, &e.message))
            .collect::<Vec<_>>()
    );
}
