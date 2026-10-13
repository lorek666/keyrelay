//! 网关本地令牌的生命周期（M8-S4 §6.4 / §6.5）。
//!
//! 这一条是 FR-5:158「换站零改动」的**全部技术前提**：令牌跨重启稳定 ⇒
//! 换站（`stop → start`）之后 agent 配置里的 `api_key` 仍然有效 ⇒ agent 侧不用改。
//! 不稳定的令牌会让每次换站都作废 agent 配置，而那正是这条需求声称要消灭的一步。
//!
//! 覆盖：
//! ① 两次 `gateway_config` 拿到**逐字相同**的令牌（跨重启稳定）；
//! ② 显式轮换 ⇒ 换掉、且新令牌**也持久化**；
//! ③ 钥匙串不可用 ⇒ 降级为临时令牌，但**说出来**（`token_persistent() == false`）；
//! ④ 「一键清理钥匙串」必须连网关令牌一起清（FR-8:191），否则它永远留在系统钥匙串里。

use std::fs;
use std::sync::Arc;

use keyrelay_core::service::{KeyRelayService, ServiceConfig, GATEWAY_TOKEN_REF};
use keyrelay_core::site::transport::{HttpResponse, MockTransport};
use keyrelay_core::site::Credentials;
use keyrelay_core::store::Store;
use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};
use serde_json::json;

const SECRET: &str = "sk-gw-0123456789abcdef";
const BASE: &str = "https://relay.example.com";

struct Fixture {
    _dir: tempfile::TempDir,
    service: KeyRelayService<MockTransport>,
    vault: Arc<MemoryVault>,
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
            vault: vault.clone(),
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
        vault,
        site_id,
        key_id,
    }
}

#[tokio::test]
async fn the_token_survives_a_restart() {
    let f = setup().await;

    let first = f.service.gateway_config(f.site_id, f.key_id, 0).unwrap();
    // 模拟「换站」：停掉再启一次（`gateway_config` 就是 `gateway_start` 的第一步）
    let second = f.service.gateway_config(f.site_id, f.key_id, 0).unwrap();

    assert_eq!(
        first.token, second.token,
        "令牌必须跨重启稳定——否则每次换站都会作废 agent 配置（FR-5:158 的承诺就不成立）"
    );
    assert!(first.token.starts_with("kr-gw-"), "{}", first.token);
    assert!(f.service.gateway_token_persistent(), "写进钥匙串了");
    assert_eq!(
        f.vault.get(GATEWAY_TOKEN_REF).unwrap().as_deref(),
        Some(first.token.as_str()),
        "钥匙串里那一份就是网关用的那一份"
    );
}

#[tokio::test]
async fn rotating_the_token_changes_it_and_keeps_it_persisted() {
    let f = setup().await;
    let before = f.service.gateway_config(f.site_id, f.key_id, 0).unwrap();

    f.service.rotate_gateway_token().unwrap();
    let after = f.service.gateway_config(f.site_id, f.key_id, 0).unwrap();

    assert_ne!(before.token, after.token, "轮换必须真的换掉");
    assert!(f.service.gateway_token_persistent(), "新令牌也是持久化的");
    assert_eq!(
        f.vault.get(GATEWAY_TOKEN_REF).unwrap().as_deref(),
        Some(after.token.as_str())
    );
    // 再启一次仍然稳定（轮换只换一次）
    let again = f.service.gateway_config(f.site_id, f.key_id, 0).unwrap();
    assert_eq!(again.token, after.token);
}

#[tokio::test]
async fn a_missing_vault_degrades_to_a_temporary_token_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let store = Store::open(&dir.path().join("keyrelay.db")).unwrap();
    let site_id = store.upsert_site("newapi", BASE, "测试站").unwrap();
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &reference, Some("1"), None)
        .unwrap();
    // 只读钥匙串：站点密钥读得到（否则连 `gateway_config` 都走不到令牌那一步），
    // 但 `put` 必然失败（模拟「钥匙串不可用 / ACL 拒绝」）。
    let vault = Arc::new(ReadOnlyVault {
        site_secret_ref: reference.clone(),
    });
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

    let config = service
        .gateway_config(site_id, key_id, 0)
        .expect("钥匙串写不了也要能启动网关（降级，不是拒绝）");
    assert!(config.token.starts_with("kr-gw-"));
    assert!(
        !service.gateway_token_persistent(),
        "降级必须**说出来**：状态里要能看到「临时令牌」（§6.4 第 5 条）"
    );
    // 留痕：事件表里有一条 Warn 说明为什么是临时的
    let events = service.store().list_events(50).unwrap();
    assert!(
        events
            .iter()
            .any(|e| e.level == "warn" && e.message.contains("临时令牌")),
        "降级必须留痕：{:?}",
        events
            .iter()
            .map(|e| (&e.level, &e.message))
            .collect::<Vec<_>>()
    );

    // 显式轮换在钥匙串写不了时**必须报错**（用户按下的按钮不能静默失败）
    assert!(
        service.rotate_gateway_token().is_err(),
        "轮换写不进钥匙串 ⇒ 报错，而不是让用户以为换掉了"
    );
}

#[tokio::test]
async fn the_token_reference_is_a_valid_vault_ref() {
    assert!(
        keyrelay_core::vault::is_valid_secret_ref(GATEWAY_TOKEN_REF),
        "引用形状由 ADR-0002 钉死：{GATEWAY_TOKEN_REF}"
    );
}

#[tokio::test]
async fn purge_keychain_also_removes_the_gateway_token() {
    let f = setup().await;
    f.service.gateway_config(f.site_id, f.key_id, 0).unwrap();
    assert!(f.vault.get(GATEWAY_TOKEN_REF).unwrap().is_some());

    let report = f.service.purge_keychain().unwrap();

    assert_eq!(report.failed, 0, "{:?}", report.first_error);
    assert!(
        f.vault.get(GATEWAY_TOKEN_REF).unwrap().is_none(),
        "一键清理钥匙串必须连网关令牌一起清（FR-8:191），否则它永远留在系统钥匙串里"
    );
    assert!(
        f.vault
            .get(&secret_ref("key", 1, "secret"))
            .unwrap()
            .is_none(),
        "站点密钥也清了"
    );
    assert_eq!(report.removed, 2, "两条：站点密钥 + 网关令牌");
}

/// 只读钥匙串：`get` 只认得站点密钥那一条，`put` / `delete` 一律失败。
struct ReadOnlyVault {
    site_secret_ref: String,
}

impl Vault for ReadOnlyVault {
    fn backend_name(&self) -> &'static str {
        "memory"
    }

    fn probe(&self) -> keyrelay_core::error::Result<()> {
        Ok(())
    }

    fn put(&self, _key: &str, _secret: &str) -> keyrelay_core::error::Result<()> {
        Err(keyrelay_core::error::Error::Vault(
            "钥匙串不可用（测试夹具）".to_string(),
        ))
    }

    fn get(&self, key: &str) -> keyrelay_core::error::Result<Option<String>> {
        Ok((key == self.site_secret_ref).then(|| SECRET.to_string()))
    }

    fn delete(&self, _key: &str) -> keyrelay_core::error::Result<()> {
        Err(keyrelay_core::error::Error::Vault(
            "钥匙串不可用（测试夹具）".to_string(),
        ))
    }
}
