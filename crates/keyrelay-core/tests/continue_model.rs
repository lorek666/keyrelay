//! Continue 通道的模型名：**服务层接线**（生产路径）。
//!
//! 写入器早就支持 `model`，但生产路径 `prepare_delivery → resolve_for` 固定传 `None`，
//! 于是按生产路径投递出来的条目没有 `model`——Continue 的 schema 把它定为必填，
//! 整份配置拒绝加载（`models.0: Invalid input`），用户原有的模型也跟着失效。
//! 写入器层的测试都是直接构造 `ContinueWriter(..., Some(model))`，看不见这条接线缺口（P-5）。

use std::fs;
use std::sync::Arc;

use keyrelay_core::delivery::DeliveryChannel;
use keyrelay_core::service::{KeyRelayService, RevokeOutcome, ServiceConfig};
use keyrelay_core::site::transport::{HttpResponse, MockTransport};
use keyrelay_core::site::{Credentials, KeySpec};
use keyrelay_core::store::Store;
use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};
use serde_json::json;

const SECRET: &str = "sk-continue-svc-0123456789abcdef";
const NEW_SECRET: &str = "sk-continue-svc-ROTATED-0123456789";
const BASE: &str = "https://relay.example.com";
const MODEL: &str = "gpt-4o";

struct Fixture {
    _dir: tempfile::TempDir,
    service: KeyRelayService<MockTransport>,
    mock: MockTransport,
    key_id: i64,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let store = Store::open(&dir.path().join("keyrelay.db")).unwrap();
    let site_id = store.upsert_site("newapi", BASE, "测试站").unwrap();
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "continue/daily", &reference, Some("1"))
        .unwrap();
    let vault = Arc::new(MemoryVault::new());
    vault.put(&reference, SECRET).unwrap();
    let mock = MockTransport::new(vec![]);
    let service = KeyRelayService::new(
        store,
        mock.clone(),
        ServiceConfig {
            vault,
            home,
            backup_dir: dir.path().join("backups"),
        },
    );
    Fixture {
        _dir: dir,
        service,
        mock,
        key_id,
    }
}

fn target(f: &Fixture) -> std::path::PathBuf {
    f.service
        .home()
        .join(DeliveryChannel::Continue.relative_target())
}

#[test]
fn continue_delivery_without_a_model_is_refused_with_a_reason() {
    let f = setup();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::Continue)
        .unwrap();

    let err = f
        .service
        .delivery_plan(f.key_id, DeliveryChannel::Continue)
        .unwrap_err();
    assert!(err.to_string().contains("模型名"), "{err}");
    let err = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::Continue)
        .unwrap_err();
    assert!(err.to_string().contains("模型名"), "{err}");
    assert!(!err.to_string().contains(SECRET), "{err}");
    assert!(!target(&f).exists(), "拒绝时不得落盘");
}

#[test]
fn continue_delivery_with_a_model_writes_it() {
    let f = setup();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::Continue)
        .unwrap();

    let plan = f
        .service
        .delivery_plan_with_model(f.key_id, DeliveryChannel::Continue, Some(MODEL))
        .unwrap();
    assert!(!plan.preview.contains(SECRET), "预览不得含明文");
    assert!(
        plan.fields
            .iter()
            .any(|field| field.key == "model" && field.masked == MODEL),
        "{:?}",
        plan.fields
    );

    f.service
        .apply_delivery_with_model(f.key_id, DeliveryChannel::Continue, Some(MODEL))
        .unwrap();
    let written = fs::read_to_string(target(&f)).unwrap();
    assert!(written.starts_with("name: "), "{written}");
    assert!(written.contains("\nversion: "), "{written}");
    assert!(written.contains("    model: \"gpt-4o\"\n"), "{written}");
}

/// 轮换第②步走的是不带模型名的 `apply_delivery`：Continue 必须沿用块里已有的模型名，
/// 否则新 key 建好之后轮换就停在第②步。
#[tokio::test]
async fn rotation_reinjects_continue_with_the_model_already_in_the_block() {
    let f = setup();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::Continue)
        .unwrap();
    f.service
        .apply_delivery_with_model(f.key_id, DeliveryChannel::Continue, Some(MODEL))
        .unwrap();

    f.mock.push(
        HttpResponse::json(200, json!({"success": true, "data": {"enabled": false}})).unwrap(),
    );
    f.mock.push(
        HttpResponse::json(200, json!({"success": true, "data": {"id": 7}}))
            .unwrap()
            .with_header("Set-Cookie", "session=abc; Path=/"),
    );
    f.service
        .login(1, Credentials::new("me", "pw"))
        .await
        .unwrap();
    f.mock.push(
        HttpResponse::json(
            200,
            json!({"success": true, "data": {"key": NEW_SECRET, "id": 2}}),
        )
        .unwrap(),
    );
    f.mock
        .push(HttpResponse::json(200, json!({"success": true, "message": ""})).unwrap());

    let run = f
        .service
        .rotate_key(f.key_id, KeySpec::named("continue/rotated"))
        .await
        .unwrap();
    assert!(run.completed(), "轮换应三步走完: {:?}", run.stop_reason);
    assert_eq!(run.reinjected, vec!["continue".to_string()]);
    assert_eq!(run.revoke, RevokeOutcome::Revoked);

    let written = fs::read_to_string(target(&f)).unwrap();
    assert!(written.contains(NEW_SECRET), "新 key 必须已注入");
    assert!(!written.contains(SECRET), "旧 key 必须被替换");
    assert!(written.contains("    model: \"gpt-4o\"\n"), "{written}");
}
