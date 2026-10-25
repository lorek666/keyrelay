//! KeyRelay debug 波次第 1 组：P0-1 预算 drain + P1-6 预算 fail-open 静默。
//!
//! 与 `m46s5_budget.rs` 的关键区别：那里的用例直接 `insert_gateway_usage`
//! 写库，绕过了 drain 时滞；这里走生产链路——`gateway_config` 装配出的
//! `on_usage` 回调进缓冲 → `budget_check` 闭包判定，全程不调 `refresh_all`、
//! 不调 `drain_gateway_usage`，且定时刷新保持默认关闭。

use std::sync::Arc;

use tianshu_relay_core::gateway::GatewayUsage;
use tianshu_relay_core::service::{ServiceConfig, TianshuRelayService};
use tianshu_relay_core::site::transport::MockTransport;
use tianshu_relay_core::store::Store;
use tianshu_relay_core::vault::{secret_ref, MemoryVault, Vault};

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("时钟")
        .as_secs() as i64
}

struct Fixture {
    _dir: tempfile::TempDir,
    db_path: std::path::PathBuf,
    service: TianshuRelayService<MockTransport>,
    site_id: i64,
    key_id: i64,
}

fn fixture(limit_usd: f64) -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let db_path = dir.path().join("t.db");
    let store = Store::open(&db_path).expect("文件库");
    let site_id = store
        .upsert_site("newapi", "https://relay.example.com", "预算站")
        .expect("写站点");
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "k1", &reference, Some("1"), None)
        .expect("写 key");
    let vault = Arc::new(MemoryVault::new());
    vault.put(&reference, "<redacted>").expect("钥匙串");
    // USD 价：1M prompt = 2.0，1M completion = 4.0；价行生效时间远早于用量。
    store
        .model_price_upsert("usd-model", 2.0, 4.0, "USD", now() - 40 * 86_400)
        .expect("写价格");
    store
        .budget_create(site_id, Some(key_id), "day", limit_usd)
        .expect("建预算");
    let service = TianshuRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault,
            home,
            backup_dir: dir.path().join("backups"),
        },
    );
    Fixture {
        _dir: dir,
        db_path,
        service,
        site_id,
        key_id,
    }
}

fn usage(site_id: i64, key_id: i64, prompt: i64) -> GatewayUsage {
    GatewayUsage {
        at: now(),
        site_id,
        key_id: Some(key_id),
        model: "usd-model".to_string(),
        prompt_tokens: prompt,
        completion_tokens: 0,
        total_tokens: prompt,
        status: 200,
        latency_ms: 10,
        attempts: 1,
        stream: false,
        token_id: None,
        agent_label: String::new(),
    }
}

/// P0-1：小预算 + 关刷新 + 只走 on_usage 缓冲，budget_check 必须 breach，
/// 且判定本身把缓冲落库（第二次判定已花不变，证明没有重复计入）。
#[test]
fn buffered_usage_triggers_breach_without_refresh() {
    let f = fixture(1.0);
    // 前置：定时刷新默认关闭——这正是生产里预算失效的配置。
    let settings = f.service.settings().expect("读设置");
    assert_eq!(settings.refresh_interval_secs, 0, "默认不开启定时刷新");
    assert!(!settings.scheduler_enabled(), "默认调度器关闭");

    let config = f
        .service
        .gateway_config(f.site_id, f.key_id, 0)
        .expect("装配网关配置");
    let check = config.budget_check.as_ref().expect("应有预算判定");
    let on_usage = config.on_usage.as_ref().expect("应用量回调");

    assert!(
        check(f.site_id, Some(f.key_id)).is_none(),
        "无用量时不 breach"
    );

    // 一次请求产生 1M prompt = 2.0 美元，已超 1.0 上限；只进缓冲。
    on_usage(usage(f.site_id, f.key_id, 1_000_000));
    assert!(
        f.service
            .store()
            .recent_gateway_usage(24 * 365 * 100)
            .expect("查库")
            .is_empty(),
        "前置：判定前库里仍为空，证明用量只在缓冲里"
    );

    // 不调 refresh_all、不调 drain：判定本身必须看到缓冲里的用量。
    let breach = check(f.site_id, Some(f.key_id)).expect("缓冲用量已超预算，必须 breach");
    assert_eq!(breach.spent_usd, 2.0, "已花 = 缓冲里 1M prompt 的 USD 价");
    assert_eq!(breach.limit_usd, 1.0);
    assert_eq!(
        f.service
            .store()
            .recent_gateway_usage(24 * 365 * 100)
            .expect("查库")
            .len(),
        1,
        "判定应把缓冲落库，而不是只在内存里算一次"
    );
    let again = check(f.site_id, Some(f.key_id)).expect("落库后仍 breach");
    assert_eq!(
        again.spent_usd, 2.0,
        "第二次判定已花不变：缓冲已排空，不得重复计入"
    );
}

/// P0-1 反向：未超限的缓冲用量不得误拦。
#[test]
fn under_limit_buffered_usage_does_not_breach() {
    let f = fixture(10.0);
    let config = f
        .service
        .gateway_config(f.site_id, f.key_id, 0)
        .expect("装配网关配置");
    let check = config.budget_check.as_ref().expect("应有预算判定");
    let on_usage = config.on_usage.as_ref().expect("应用量回调");

    on_usage(usage(f.site_id, f.key_id, 1_000_000));
    assert!(
        check(f.site_id, Some(f.key_id)).is_none(),
        "2.0 未超 10.0 上限，不得 breach"
    );
}

/// P1-6：store 出错时预算照常放行，但必须留下一条 Warn 事件。
#[test]
fn budget_check_store_error_fails_open_with_warn_event() {
    let f = fixture(1.0);
    // 先装配（装配本身要读库），再弄坏用量表——与 m46s5 的造 Err 手段相同。
    let config = f
        .service
        .gateway_config(f.site_id, f.key_id, 0)
        .expect("装配网关配置");
    let check = config.budget_check.as_ref().expect("应有预算判定");
    let conn = rusqlite::Connection::open(&f.db_path).expect("直连");
    conn.execute_batch("DROP TABLE gateway_usage_log;")
        .expect("删表");

    assert!(
        check(f.site_id, Some(f.key_id)).is_none(),
        "fail-open 本身不变：读库失败时放行"
    );

    let events = f.service.recent_events(100).expect("读事件");
    let warn = events
        .iter()
        .find(|e| e.level == "warn" && e.source == "gateway" && e.message.contains("fail-open"));
    assert!(
        warn.is_some(),
        "fail-open 必须留下一条 Warn 事件，现有事件：{:?}",
        events
            .iter()
            .map(|e| (e.level.as_str(), e.source.as_str(), e.message.as_str()))
            .collect::<Vec<_>>()
    );
}
