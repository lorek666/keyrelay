//! 事件表零明文守护（BACKLOG B-11 / B-31 / B-36）。
//!
//! 本文件的意义在于：`events` 表在 M1-S3 之前**零写入点**，
//! 「密钥不进事件表」是一条**空断言**（无可验证的防护路径）。
//! 现在有了写入方，这条断言才第一次可以被真正测到。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use keyrelay_core::delivery::DeliveryChannel;
use keyrelay_core::observability::{self, Event, Level};
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::transport::MockTransport;
use keyrelay_core::store::Store;
use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};

const SECRET: &str = "sk-0123456789abcdefSECRET";

struct Fixture {
    _dir: tempfile::TempDir,
    db_path: PathBuf,
    service: KeyRelayService<MockTransport>,
    key_id: i64,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let db_path = dir.path().join("keyrelay.db");

    let store = Store::open(&db_path).expect("文件库");
    let site_id = store
        .upsert_site("newapi", "https://relay.example.com", "测试站")
        .expect("写站点");
    let secret_ref = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &secret_ref, Some("1"))
        .expect("写密钥记录");

    let vault = Arc::new(MemoryVault::new());
    vault.put(&secret_ref, SECRET).expect("写钥匙串");

    let service = KeyRelayService::new(
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
        key_id,
    }
}

/// 另开一个连接扫同一份文件库（WAL 下并发读没问题）。
fn secret_hits(db_path: &Path) -> i64 {
    Store::open(db_path)
        .expect("复开库")
        .count_events_with_secrets()
        .expect("扫描事件表")
}

#[test]
fn full_delivery_flow_leaves_no_plaintext_in_events() {
    let f = setup();

    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    let _ = f
        .service
        .delivery_plan(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    let outcome = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    f.service.rollback_delivery(&outcome.journal_id).unwrap();

    let events = f.service.recent_events(200).unwrap();
    assert!(
        !events.is_empty(),
        "走完整个流程后事件表必须非空（否则「密钥不进事件表」仍是空断言）"
    );

    for row in &events {
        assert!(
            !row.message.contains(SECRET),
            "事件 message 泄漏密钥: {}",
            row.message
        );
        if let Some(payload) = &row.payload {
            assert!(
                !payload.contains(SECRET),
                "事件 payload 泄漏密钥: {payload}"
            );
            assert!(
                !payload.contains("0123456789"),
                "事件 payload 含密钥片段: {payload}"
            );
        }
    }

    assert_eq!(secret_hits(&f.db_path), 0, "事件表存在疑似未脱敏行");

    // 诊断导出同样不得带出密钥
    let exported = f.service.export_diagnostics(200).unwrap();
    assert!(!exported.contains(SECRET), "{exported}");
}

#[test]
fn event_table_scan_is_not_a_no_op() {
    let f = setup();

    // 负对照：**绕过** `observability::event()`，手工构造一个含明文的 Event 直接落库。
    // （`Event` 的字段是公开的，这正是扫描要抓的「绕过路径」。）
    let raw = Event {
        ts: 0,
        level: Level::Info,
        source: "app".to_string(),
        message: format!("手工明文 {SECRET}"),
        payload: None,
    };
    Store::open(&f.db_path)
        .expect("复开库")
        .insert_event(&raw)
        .expect("写入人为明文");

    assert_eq!(
        secret_hits(&f.db_path),
        1,
        "扫描发现不了人为明文 → 门禁无效（空跑）"
    );
}

#[test]
fn event_table_scan_catches_plaintext_in_payload_too() {
    let f = setup();
    let raw = Event {
        ts: 0,
        level: Level::Info,
        source: "app".to_string(),
        message: "看起来没问题".to_string(),
        payload: Some(format!(r#"{{"token":"{SECRET}"}}"#)),
    };
    Store::open(&f.db_path)
        .expect("复开库")
        .insert_event(&raw)
        .expect("写入人为明文");

    assert_eq!(secret_hits(&f.db_path), 1, "载荷里的明文也必须被发现");
}

#[test]
fn constructed_event_scrubs_even_when_caller_passes_raw_secret() {
    let e = observability::event(Level::Warn, "site", format!("站点回了 {SECRET}"));
    assert!(!e.message.contains(SECRET), "{}", e.message);
    assert!(e.message.contains("sk-***"), "{}", e.message);
}

#[test]
fn nested_payload_is_scrubbed_at_every_depth() {
    let e = observability::event_with_payload(
        Level::Error,
        "delivery",
        "投递失败",
        serde_json::json!({
            "a": { "b": { "c": { "key": SECRET } } },
            "arr": [ { "deep": [SECRET] } ],
        }),
    );
    let payload = e.payload.expect("有载荷");
    assert!(!payload.contains(SECRET), "{payload}");
    assert!(!payload.contains("0123456789"), "{payload}");
}

#[test]
fn events_table_has_writers_after_a_site_operation() {
    // 「零写入点」的回归：任何一次业务操作都应留下事件
    let f = setup();
    let before = f.service.recent_events(1000).unwrap().len();

    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();

    let after = f.service.recent_events(1000).unwrap().len();
    assert!(after > before, "授予同意必须留下事件记录");
}

#[test]
fn diagnostic_export_includes_vault_backend_for_support() {
    let f = setup();
    let exported = f.service.export_diagnostics(10).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&exported).expect("导出应是 JSON");
    assert_eq!(parsed["vault_backend"], "memory");
    assert!(parsed["home"].is_string());
}
