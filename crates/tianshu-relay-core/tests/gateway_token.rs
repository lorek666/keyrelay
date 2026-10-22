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

use serde_json::json;
use tianshu_relay_core::service::{ServiceConfig, TianshuRelayService, GATEWAY_TOKEN_REF};
use tianshu_relay_core::site::transport::{HttpResponse, MockTransport};
use tianshu_relay_core::site::Credentials;
use tianshu_relay_core::store::Store;
use tianshu_relay_core::vault::{secret_ref, MemoryVault, Vault};

const SECRET: &str = "sk-gw-0123456789abcdef";
const BASE: &str = "https://relay.example.com";

struct Fixture {
    _dir: tempfile::TempDir,
    service: TianshuRelayService<MockTransport>,
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
    let store = Store::open(&dir.path().join("tianshu-relay.db")).unwrap();
    let site_id = store.upsert_site("newapi", BASE, "测试站").unwrap();
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &reference, Some("1"), None)
        .unwrap();
    let vault = Arc::new(MemoryVault::new());
    vault.put(&reference, SECRET).unwrap();
    let mock = MockTransport::new(vec![]);
    let service = TianshuRelayService::new(
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
    let store = Store::open(&dir.path().join("tianshu-relay.db")).unwrap();
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
    let service = TianshuRelayService::new(
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
        tianshu_relay_core::vault::is_valid_secret_ref(GATEWAY_TOKEN_REF),
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
    assert!(
        f.vault
            .get(&secret_ref("site", f.site_id, "session"))
            .unwrap()
            .is_none(),
        "持久化会话也清了（M13-S1：login 写入的 session_ref 必须一并清理）"
    );
    assert_eq!(report.removed, 3, "三条：站点密钥 + 网关令牌 + 持久化会话");
}

/// 只读钥匙串：`get` 只认得站点密钥那一条，`put` / `delete` 一律失败。
struct ReadOnlyVault {
    site_secret_ref: String,
}

impl Vault for ReadOnlyVault {
    fn backend_name(&self) -> &'static str {
        "memory"
    }

    fn probe(&self) -> tianshu_relay_core::error::Result<()> {
        Ok(())
    }

    fn put(&self, _key: &str, _secret: &str) -> tianshu_relay_core::error::Result<()> {
        Err(tianshu_relay_core::error::Error::Vault(
            "钥匙串不可用（测试夹具）".to_string(),
        ))
    }

    fn get(&self, key: &str) -> tianshu_relay_core::error::Result<Option<String>> {
        Ok((key == self.site_secret_ref).then(|| SECRET.to_string()))
    }

    fn delete(&self, _key: &str) -> tianshu_relay_core::error::Result<()> {
        Err(tianshu_relay_core::error::Error::Vault(
            "钥匙串不可用（测试夹具）".to_string(),
        ))
    }
}

/// 钥匙串读**瞬时失败**夹具（P2-4 / DEBUG-REPORT-v3 §2-4）：`get(GATEWAY_TOKEN_REF)`
/// 在 `gateway_read_fails` 为真时返回 `Err`，其余读写委托内部 `MemoryVault`——模拟
/// 「锁屏 / ACL 拒绝」那次读失败，但钥匙串里已有一把仍有效的持久令牌。
struct FlakyReadVault {
    inner: MemoryVault,
    gateway_read_fails: std::sync::atomic::AtomicBool,
}

impl FlakyReadVault {
    fn new() -> Self {
        Self {
            inner: MemoryVault::new(),
            gateway_read_fails: std::sync::atomic::AtomicBool::new(false),
        }
    }
    fn set_gateway_read_fails(&self, fails: bool) {
        self.gateway_read_fails
            .store(fails, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Vault for FlakyReadVault {
    fn backend_name(&self) -> &'static str {
        "memory"
    }
    fn probe(&self) -> tianshu_relay_core::error::Result<()> {
        Ok(())
    }
    fn put(&self, key: &str, secret: &str) -> tianshu_relay_core::error::Result<()> {
        self.inner.put(key, secret)
    }
    fn get(&self, key: &str) -> tianshu_relay_core::error::Result<Option<String>> {
        if key == GATEWAY_TOKEN_REF
            && self
                .gateway_read_fails
                .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(tianshu_relay_core::error::Error::Vault(
                "钥匙串读失败（测试夹具：模拟锁屏 / ACL 拒绝）".to_string(),
            ));
        }
        self.inner.get(key)
    }
    fn delete(&self, key: &str) -> tianshu_relay_core::error::Result<()> {
        self.inner.delete(key)
    }
}

/// P2-4：钥匙串**读**瞬时失败（锁屏 / ACL 拒绝）时，`gateway_token` 不得生成新令牌
/// 覆盖已持久化的那把——否则所有指向网关的 agent 配置会永久 401。降级为临时令牌
/// （`token_persistent = false`）+ Warn 事件，且钥匙串里那把原样保留；读恢复后仍用它。
#[tokio::test]
async fn a_flaky_read_does_not_overwrite_the_persisted_gateway_token() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let store = Store::open(&dir.path().join("tianshu-relay.db")).unwrap();
    let site_id = store.upsert_site("newapi", BASE, "测试站").unwrap();
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &reference, Some("1"), None)
        .unwrap();
    let vault = Arc::new(FlakyReadVault::new());
    vault.put(&reference, SECRET).unwrap();
    let mock = MockTransport::new(vec![]);
    let service = TianshuRelayService::new(
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

    // 第一次装配：读正常 ⇒ 生成 + 持久化令牌 T1
    let first = service.gateway_config(site_id, key_id, 0).unwrap();
    let t1 = first.token.clone();
    assert!(service.gateway_token_persistent(), "T1 持久化");
    assert_eq!(
        vault.get(GATEWAY_TOKEN_REF).unwrap().as_deref(),
        Some(t1.as_str())
    );

    // 模拟钥匙串读瞬时失败（锁屏 / ACL 拒绝）
    vault.set_gateway_read_fails(true);
    let degraded = service.gateway_config(site_id, key_id, 0).unwrap();
    assert!(
        !service.gateway_token_persistent(),
        "读失败 ⇒ 临时令牌，状态必须明示（不报 token_persistent=true）"
    );
    assert_ne!(
        degraded.token, t1,
        "临时令牌是新生成的一把，不是钥匙串里那把"
    );
    // 关键：钥匙串里那把 T1 没被覆盖——读恢复后仍能拿到它
    vault.set_gateway_read_fails(false);
    assert_eq!(
        vault.get(GATEWAY_TOKEN_REF).unwrap().as_deref(),
        Some(t1.as_str()),
        "读失败不得覆盖钥匙串里已持久化的令牌（P2-4）"
    );
    // 留痕：Warn 事件说明为什么是临时的
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

    // 读恢复后仍用 T1（没被临时那把顶掉）
    let again = service.gateway_config(site_id, key_id, 0).unwrap();
    assert_eq!(
        again.token, t1,
        "读恢复 ⇒ 仍用钥匙串里那把 T1，临时令牌不持久"
    );
    assert!(service.gateway_token_persistent());
}

/// E1：换站零改动——site A → site B 切换，令牌逐字相同（B-105 端到端守卫）。
///
/// `the_token_survives_a_restart` 测的是**同站点** stop→start；本条测**异站点**切换，
/// 钉住「换站」而不只是「重启」——这是 FR-5:158 的核心承诺。
/// M14-S1 复核：token 持久化（M8-S4 §6.4）+ 网关投递（M8-S4 §6.2）已关闭 B-105，
/// 本条是对「换站零改动」链路的端到端守卫。
#[tokio::test]
async fn token_survives_a_site_switch() {
    let f = setup().await;
    // 再建第二个站点 + key（同 service，同钥匙串）
    let site_b = f
        .service
        .store()
        .upsert_site("newapi", "https://relay-b.example.com", "B 站")
        .unwrap();
    let ref_b = secret_ref("key", 2, "secret");
    let key_b = f
        .service
        .store()
        .insert_key(site_b, "codex/b", &ref_b, Some("2"), None)
        .unwrap();
    f.vault.put(&ref_b, "sk-site-B-0123456789").unwrap();

    // site A 启动网关
    let first = f.service.gateway_config(f.site_id, f.key_id, 0).unwrap();
    // 换站：site B 启动网关（令牌仍从同一把钥匙串读出）
    let second = f.service.gateway_config(site_b, key_b, 0).unwrap();

    assert_eq!(
        first.token, second.token,
        "换站（A → B）令牌必须逐字相同——FR-5:158 换站零改动"
    );
    assert!(
        f.service.gateway_token_persistent(),
        "令牌仍持久化（换站不触发重新生成）"
    );
}
