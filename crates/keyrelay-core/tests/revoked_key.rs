//! 「已回收」（`keys.status = revoked`）必须有读者（M7-S4 写入、无人读取的缺口）。
//!
//! M7-S4 让 `revoke_key` 把本地行标成 `revoked`，但服务层没有任何一处读它：
//! 回收后这把 key 仍被判「该轮换」、仍能投递、仍能组装网关；对它点「轮换」会先在站点上
//! **新建**一把，再去 DELETE 一个早已不存在的 id。这里逐条钉住「已回收 ⇒ 不再被使用」。

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use keyrelay_core::delivery::DeliveryChannel;
use keyrelay_core::service::{KeyRelayService, RevokeOutcome, ServiceConfig};
use keyrelay_core::site::transport::{HttpResponse, MockTransport};
use keyrelay_core::site::{Credentials, KeySpec};
use keyrelay_core::store::{Store, KEY_STATUS_REVOKED};
use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};
use serde_json::json;

const OLD_SECRET: &str = "sk-old-0123456789abcdef";
const NEW_SECRET: &str = "sk-rot-newkey0123456789";
const BASE: &str = "https://relay.example.com";
const DAY: i64 = 86_400;

struct Fixture {
    _dir: tempfile::TempDir,
    db: PathBuf,
    service: KeyRelayService<MockTransport>,
    mock: MockTransport,
    site_id: i64,
    key_id: i64,
}

fn encryption_disabled() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": {"enabled": false}})).unwrap()
}

fn login_ok() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": {"id": 7}}))
        .unwrap()
        .with_header("Set-Cookie", "session=abc; Path=/")
}

fn delete_ok() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "message": ""})).unwrap()
}

fn create_key_ok() -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"success": true, "data": {"key": NEW_SECRET, "id": 2}}),
    )
    .unwrap()
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let db = dir.path().join("keyrelay.db");
    let store = Store::open(&db).unwrap();
    let site_id = store.upsert_site("newapi", BASE, "测试站").unwrap();
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &reference, Some("1"))
        .unwrap();
    let vault = Arc::new(MemoryVault::new());
    vault.put(&reference, OLD_SECRET).unwrap();
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
    mock.push(encryption_disabled());
    mock.push(login_ok());
    service
        .login(site_id, Credentials::new("me", "pw"))
        .await
        .unwrap();
    Fixture {
        _dir: dir,
        db,
        service,
        mock,
        site_id,
        key_id,
    }
}

/// 把 key 的创建时间往前拨，让它进入轮换窗口（默认 30 天）。
fn backdate(f: &Fixture, key_id: i64, days: i64) {
    let conn = rusqlite::Connection::open(&f.db).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    conn.execute(
        "UPDATE keys SET created_at = ?1 WHERE id = ?2",
        rusqlite::params![now - days * DAY, key_id],
    )
    .unwrap();
}

async fn revoke(f: &Fixture) {
    f.mock.push(delete_ok());
    f.service.revoke_key(f.site_id, "1").await.expect("回收");
    assert_eq!(
        f.service.store().key_status(f.key_id).unwrap().as_deref(),
        Some(KEY_STATUS_REVOKED),
        "前提：本地状态已写成 revoked"
    );
}

fn due_ids(f: &Fixture) -> Vec<i64> {
    f.service
        .rotation_due()
        .unwrap()
        .into_iter()
        .map(|d| d.key_id)
        .collect()
}

#[tokio::test]
async fn revoked_key_is_not_reported_as_rotation_due() {
    let f = setup().await;
    backdate(&f, f.key_id, 40);
    assert_eq!(due_ids(&f), vec![f.key_id], "前提：回收前已到期");

    revoke(&f).await;

    assert!(
        due_ids(&f).is_empty(),
        "已回收的 key 不该再被提醒轮换: {:?}",
        due_ids(&f)
    );
}

#[tokio::test]
async fn successful_rotation_clears_the_old_key_from_rotation_due() {
    let f = setup().await;
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    f.service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    backdate(&f, f.key_id, 40);

    f.mock.push(create_key_ok());
    f.mock.push(delete_ok());
    let run = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/rotated"))
        .await
        .unwrap();
    assert!(run.completed(), "前提：三步全部走完 {:?}", run.stop_reason);
    assert_eq!(run.revoke, RevokeOutcome::Revoked);

    assert!(
        !due_ids(&f).contains(&f.key_id),
        "轮换成功后旧 key 不该还在「该轮换」列表: {:?}",
        due_ids(&f)
    );
}

#[tokio::test]
async fn revoked_key_cannot_be_delivered() {
    let f = setup().await;
    revoke(&f).await;
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();

    let preview = f
        .service
        .delivery_plan(f.key_id, DeliveryChannel::CodexAuthJson);
    assert!(preview.is_err(), "已回收的 key 不该出投递预览");
    let err = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap_err();
    assert!(err.to_string().contains("已回收"), "{err}");
    let target = f
        .service
        .home()
        .join(DeliveryChannel::CodexAuthJson.relative_target());
    assert!(!target.exists(), "拒绝时不得落盘");
}

#[tokio::test]
async fn revoked_key_cannot_back_the_gateway() {
    let f = setup().await;
    revoke(&f).await;

    let err = f
        .service
        .gateway_config(f.site_id, f.key_id, 0)
        .unwrap_err();
    assert!(err.to_string().contains("已回收"), "{err}");
}

#[tokio::test]
async fn rotating_a_revoked_key_is_refused_before_any_site_request() {
    let f = setup().await;
    revoke(&f).await;
    let before = f.mock.request_count();

    let err = f.service.rotation_plan(f.key_id).unwrap_err();
    assert!(err.to_string().contains("已回收"), "{err}");

    // 若不在动手前拒绝：站点上会**先建一把新 key**，再去 DELETE 一个早已不存在的 id
    f.mock.push(create_key_ok());
    let err = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/rotated"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("已回收"), "{err}");
    assert_eq!(
        f.mock.request_count(),
        before,
        "对已回收的 key 发起轮换不得发出任何站点请求"
    );
}
