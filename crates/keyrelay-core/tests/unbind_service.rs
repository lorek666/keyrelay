//! 解绑的**服务层**语义（M8-S4 §5 / §5.5 / §7）。
//!
//! `tests/unbind.rs` 钉的是存储层（`unbind_agent` / `unbind_target` 的行级语义与迁移）。
//! 本文件钉的是 Lead 接线的那一层：`service.unbind(agent, also_revoke)`。
//!
//! 三条最容易被实现成「看起来对」的地方：
//! ① `also_revoke == false` 必须是**零站点请求**（解绑是本地动作）；
//! ② 同一把 key 投到多个目标时只回收一次（重复请求会让「回收了几把」这个数字失去意义）；
//! ③ 单条回收失败**不**回滚解绑、也不冒泡——把两者绑成一个事务会让「站点挂了就解不了绑」。

use std::fs;
use std::sync::Arc;

use keyrelay_core::delivery::DeliveryChannel;
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::transport::{HttpResponse, MockTransport};
use keyrelay_core::site::Credentials;
use keyrelay_core::store::{Store, KEY_STATUS_REVOKED};
use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};
use serde_json::json;

const SECRET: &str = "sk-unbind-0123456789abcdef";
const BASE: &str = "https://relay.example.com";

struct Fixture {
    _dir: tempfile::TempDir,
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

fn delete_fails() -> HttpResponse {
    HttpResponse::json(400, json!({"success": false, "message": "无权删除"})).unwrap()
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let store = Store::open(&dir.path().join("keyrelay.db")).unwrap();
    let site_id = store.upsert_site("newapi", BASE, "测试站").unwrap();
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &reference, Some("1"), None)
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
    mock.push(encryption_disabled());
    mock.push(login_ok());
    service
        .login(site_id, Credentials::new("me", "pw"))
        .await
        .unwrap();
    Fixture {
        _dir: dir,
        service,
        mock,
        site_id,
        key_id,
    }
}

/// 投递一次，产生一条绑定（这是解绑的前提）。
fn deliver(f: &Fixture, channel: DeliveryChannel) {
    f.service.grant_consent(f.key_id, channel).unwrap();
    f.service.apply_delivery(f.key_id, channel).unwrap();
}

fn agent_of(channel: DeliveryChannel) -> &'static str {
    channel.agent_id()
}

#[tokio::test]
async fn unbind_without_revoke_sends_no_site_request() {
    let f = setup().await;
    deliver(&f, DeliveryChannel::CodexAuthJson);
    let before = f.mock.request_count();
    let status_before = f.service.store().key_status(f.key_id).unwrap();

    let outcome = f
        .service
        .unbind(agent_of(DeliveryChannel::CodexAuthJson), false)
        .await
        .unwrap();

    assert_eq!(outcome.unbound, 1, "本次应新解开 1 条");
    assert_eq!(outcome.already_unbound, 0);
    assert!(outcome.revoked.is_empty(), "默认路径不回收：{:?}", outcome);
    assert_eq!(
        f.mock.request_count(),
        before,
        "解绑是本地动作：`also_revoke == false` 时一个站点请求都不该发"
    );
    assert_ne!(
        status_before.as_deref(),
        Some(KEY_STATUS_REVOKED),
        "前提：解绑前这把 key 不是已回收状态"
    );
    assert_eq!(
        f.service.store().key_status(f.key_id).unwrap(),
        status_before,
        "解绑 ≠ 回收：`keys.status` 一个字都不动"
    );
}

#[tokio::test]
async fn unbind_with_revoke_reports_both_worlds() {
    let f = setup().await;
    deliver(&f, DeliveryChannel::CodexAuthJson);
    f.mock.push(delete_ok());

    let outcome = f
        .service
        .unbind(agent_of(DeliveryChannel::CodexAuthJson), true)
        .await
        .unwrap();

    assert_eq!(outcome.unbound, 1);
    assert_eq!(outcome.revoked.len(), 1, "一把 key 一条回报");
    let report = &outcome.revoked[0];
    assert!(report.revoked, "站点侧确认删除");
    assert!(report.local_status_updated, "本地状态写上了");
    assert_eq!(report.site_id, f.site_id);
    assert_eq!(report.remote_id.as_deref(), Some("1"));
    assert!(report.note.is_none(), "{:?}", report.note);
    assert_eq!(
        f.service.store().key_status(f.key_id).unwrap().as_deref(),
        Some(KEY_STATUS_REVOKED)
    );
}

#[tokio::test]
async fn a_failed_revoke_does_not_undo_the_unbind() {
    let f = setup().await;
    deliver(&f, DeliveryChannel::CodexAuthJson);
    f.mock.push(delete_fails());

    let outcome = f
        .service
        .unbind(agent_of(DeliveryChannel::CodexAuthJson), true)
        .await
        .expect("单条回收失败不该让解绑失败——否则站点一挂就解不了绑");

    assert_eq!(outcome.unbound, 1, "解绑照常完成");
    assert_eq!(outcome.revoked.len(), 1);
    assert!(!outcome.revoked[0].revoked, "站点侧没删成功");
    assert!(
        outcome.revoked[0].note.is_some(),
        "失败原因必须能念给用户听"
    );
    // 绑定确实被解开了（行还在、标记已写）
    let rows = f
        .service
        .store()
        .bindings_of_agent(agent_of(DeliveryChannel::CodexAuthJson))
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].unbound_at.is_some());
}

#[tokio::test]
async fn one_key_bound_to_two_targets_is_revoked_once() {
    let f = setup().await;
    // 同一个 agent 的两个落点：`opencode` 与 `opencode-jsonc` 都算 `opencode` 吗？
    // 不是——它们是两个 agent id（M7-S3 的通道表）。这里用**同一把 key**投两个通道，
    // 它们各自的 agent 不同，但 key 是同一把：解绑其中一个 agent 时只该发一次回收。
    deliver(&f, DeliveryChannel::OpenCode);
    deliver(&f, DeliveryChannel::OpenCodeJsonc);
    f.mock.push(delete_ok());
    let before = f.mock.request_count();

    let outcome = f
        .service
        .unbind(agent_of(DeliveryChannel::OpenCode), true)
        .await
        .unwrap();

    assert_eq!(outcome.revoked.len(), 1, "同一把 key 只回收一次");
    assert_eq!(
        f.mock.request_count() - before,
        1,
        "回收只发一个请求（重复请求会让「回收了几把」失去意义）"
    );
}

#[tokio::test]
async fn unbind_on_an_unknown_agent_is_a_zero_report() {
    let f = setup().await;
    let before = f.mock.request_count();

    let outcome = f.service.unbind("不存在的-agent", false).await.unwrap();

    assert_eq!((outcome.unbound, outcome.already_unbound), (0, 0));
    assert!(outcome.revoked.is_empty());
    assert_eq!(f.mock.request_count(), before, "零报告也不发请求");
}

#[tokio::test]
async fn a_binding_without_a_remote_id_is_skipped_with_a_note() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let store = Store::open(&dir.path().join("keyrelay.db")).unwrap();
    let site_id = store.upsert_site("newapi", BASE, "测试站").unwrap();
    let reference = secret_ref("key", 1, "secret");
    // `remote_id = None`：老库 / 手工导入的形态（站点侧没有记录）。
    let key_id = store
        .insert_key(site_id, "codex/daily", &reference, None, None)
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
    service
        .grant_consent(key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    service
        .apply_delivery(key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    let before = mock.request_count();

    let outcome = service.unbind("codex", true).await.unwrap();

    assert_eq!(outcome.unbound, 1, "解绑照常");
    assert!(outcome.revoked.is_empty(), "没有站点侧 id ⇒ 没有可回收的");
    assert_eq!(mock.request_count(), before, "也不该发请求");
    let note = outcome.note.expect("必须说明「跳过了回收」");
    assert!(note.contains("站点侧"), "{note}");
}

#[tokio::test]
async fn unbind_is_idempotent_through_the_service_too() {
    let f = setup().await;
    deliver(&f, DeliveryChannel::CodexAuthJson);

    let first = f.service.unbind("codex", false).await.unwrap();
    let second = f.service.unbind("codex", false).await.unwrap();

    assert_eq!((first.unbound, first.already_unbound), (1, 0));
    assert_eq!(
        (second.unbound, second.already_unbound),
        (0, 1),
        "二次调用：只报「本来就是解绑状态」"
    );
}

#[tokio::test]
async fn unbind_keeps_the_key_usable_elsewhere() {
    let f = setup().await;
    deliver(&f, DeliveryChannel::CodexAuthJson);
    f.service.unbind("codex", false).await.unwrap();

    // 解绑之后这把 key 仍然可以投递到**别的**通道（默认语义是「只解除关系」）。
    f.service
        .grant_consent(f.key_id, DeliveryChannel::ClaudeCodeSettings)
        .unwrap();
    let outcome = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::ClaudeCodeSettings)
        .unwrap();
    assert!(outcome.journal_id.starts_with('j'), "{outcome:?}");
}
