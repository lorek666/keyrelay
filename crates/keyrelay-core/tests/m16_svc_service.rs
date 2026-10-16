//! M16-S5 服务层欠账收口的测试（service.rs）。
//!
//! 每条测试对应 spec `docs/specs/M16-S5-服务层欠账收口.md` §6 的一行；§10 列出的变异点
//! 就是「把这条断言改坏 ⇒ 必须变红」的地方。

use std::sync::Arc;

use keyrelay_core::error::{Error, Result};
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::transport::{HttpResponse, MockTransport};
use keyrelay_core::site::Credentials;
use keyrelay_core::store::Store;
use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};
use serde_json::json;

// ============================================================ 夹具

struct Fixture {
    _dir: tempfile::TempDir,
    db_path: std::path::PathBuf,
    home: std::path::PathBuf,
    service: KeyRelayService<MockTransport>,
    site_id: i64,
    key_id: i64,
}

fn json_ok(value: serde_json::Value) -> HttpResponse {
    HttpResponse::json(200, value).expect("构造响应")
}

fn sub2api_ok(data: serde_json::Value) -> HttpResponse {
    json_ok(json!({"code": 0, "message": "success", "data": data}))
}

/// 一个可用的 Sub2API 站点 + 一把带分组的 key。
fn fixture(responses: Vec<HttpResponse>) -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let db_path = dir.path().join("keyrelay.db");
    let store = Store::open(&db_path).expect("文件库");
    let site_id = store
        .upsert_site("sub2api", "https://sub.example.com", "探针站")
        .expect("站点");
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "m16/daily", &reference, Some("1"), Some("vip"))
        .expect("密钥行");
    let vault = Arc::new(MemoryVault::new());
    vault
        .put(&reference, "sk-m16-0123456789abcdef")
        .expect("钥匙串");
    let service = KeyRelayService::new(
        store,
        MockTransport::new(responses),
        ServiceConfig {
            vault,
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
        },
    );
    Fixture {
        _dir: dir,
        db_path,
        home,
        service,
        site_id,
        key_id,
    }
}

fn login_response(token: &str) -> HttpResponse {
    sub2api_ok(json!({"access_token": token, "token_type": "Bearer", "user": {"id": 7}}))
}

/// 造一个合法 JWT（只有 `exp` 有意义；**不校验签名**，见 `jwt_exp` 的口径）。
fn jwt_with_exp(exp: i64) -> String {
    use base64::Engine as _;
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(format!(r#"{{"sub":"7","exp":{exp}}}"#).as_bytes());
    format!("{header}.{payload}.signature-not-checked")
}

fn events_of(f: &Fixture) -> Vec<keyrelay_core::store::EventRow> {
    Store::open(&f.db_path)
        .expect("二次开库")
        .list_events(200)
        .expect("读事件")
}

// ============================================================ P3-8

#[tokio::test]
async fn rotate_gateway_token_event_has_no_secret_ref() {
    let f = fixture(vec![]);
    f.service.rotate_gateway_token().expect("轮换令牌");

    let events = events_of(&f);
    let event = events
        .iter()
        .find(|e| e.message.contains("已轮换网关本地令牌"))
        .expect("应有轮换事件");
    let payload = event.payload.clone().unwrap_or_default();
    assert!(
        !payload.contains("secret_ref"),
        "P3-8：事件 payload 不得写钥匙串条目名：{payload}"
    );
    assert!(
        !payload.contains("kr/"),
        "P3-8：事件 payload 不得出现任何 `kr/...` 引用：{payload}"
    );
    assert!(
        payload.contains("persistent"),
        "应报「已持久化」这个事实：{payload}"
    );
}

// ============================================================ P2-12

/// 真正的断言（上面那条只跑通链路）：倍率必须来自 key 的分组。
#[tokio::test]
async fn available_groups_records_the_rate_of_the_keys_group() {
    // 站点有 3 个分组，key 的分组是 `vip`（第二个）。
    // `available` 两次调用：① 分组列表 ② rates 映射。
    let f = fixture(vec![
        login_response(&jwt_with_exp(9_999_999_999)),
        sub2api_ok(json!([
            {"id": 1, "name": "default", "description": ""},
            {"id": 2, "name": "vip", "description": ""},
            {"id": 3, "name": "svip", "description": ""},
        ])),
        sub2api_ok(json!({"1": 0.5, "2": 2.0, "3": 9.0})),
    ]);
    f.service
        .login(f.site_id, Credentials::new("me@example.com", "pw-12345678"))
        .await
        .expect("登录");
    let groups = f.service.available_groups(f.site_id).await.expect("拉分组");
    assert_eq!(groups.len(), 3);
    // 断言观测值：key 的分组是 `vip` ⇒ 2.0（**不是**第一个分组的 0.5，也不是 9.0）
    let observed = f.service.site_rate_for_test(f.site_id);
    assert_eq!(
        observed,
        Some(2.0),
        "P2-12：倍率必须取当前出网 key 所在分组（vip=2.0）"
    );
}

#[tokio::test]
async fn rate_is_none_when_the_keys_group_has_no_rate() {
    // key 的分组是 `vip`，但 rates 映射里没有它 ⇒ 观测置 `None`（未知），不回落第一个分组。
    let f = fixture(vec![
        login_response(&jwt_with_exp(9_999_999_999)),
        sub2api_ok(json!([
            {"id": 1, "name": "default", "description": ""},
            {"id": 2, "name": "vip", "description": ""},
        ])),
        sub2api_ok(json!({"1": 0.5})),
    ]);
    f.service
        .login(f.site_id, Credentials::new("me@example.com", "pw-12345678"))
        .await
        .expect("登录");
    f.service.available_groups(f.site_id).await.expect("拉分组");
    assert_eq!(
        f.service.site_rate_for_test(f.site_id),
        None,
        "P2-12：key 的分组没有倍率 ⇒ None（不得回落 default 的 0.5）"
    );
}

// ============================================================ P3-28

#[tokio::test]
async fn needs_login_is_reported_when_balance_fails_and_keys_401() {
    // 余额 503（非认证类，**排在前**）+ 令牌列表 401（认证类）。
    // 旧实现只取第一个错误 ⇒ 汇总的 needs_login 为空（P3-28）。
    let f = fixture(vec![
        login_response(&jwt_with_exp(9_999_999_999)),
        HttpResponse::new(503, b"upstream down".to_vec()),
        HttpResponse::new(401, br#"{"code":401,"message":"invalid token"}"#.to_vec()),
    ]);
    f.service
        .login(f.site_id, Credentials::new("me@example.com", "pw-12345678"))
        .await
        .expect("登录");

    let summary = f.service.refresh_all().await.expect("刷新");
    assert_eq!(summary.sites_failed, 1);
    assert_eq!(
        summary.needs_login,
        vec![f.site_id],
        "P3-28：余额 503 不得掩盖令牌列表的 401"
    );
}

// ============================================================ P2-22

#[tokio::test]
async fn balance_alert_skips_unknown_balance() {
    // `custom-openai-compatible` 站点的余额**不可观测**（known == false，remaining 占位 0.0）。
    // 阈值 > 0 时**不得**产生余额告警（否则界面显示「余额低于阈值: 0 USD < 15」）。
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let store = Store::open(&dir.path().join("k.db")).expect("库");
    let site_id = store
        .upsert_site(
            "custom-openai-compatible",
            "https://plain.example.com",
            "兼容端点",
        )
        .expect("站点");
    // `custom-openai-compatible` 的能力位是 `login: false`（能力门会拒登录）⇒
    // 这里走**持久化会话 + restore** 拿会话（顺带覆盖 B-113 的恢复路径）。
    let vault = Arc::new(MemoryVault::new());
    vault
        .put(
            &keyrelay_core::vault::secret_ref("site", site_id, "session"),
            &format!(
                r#"{{"cookies":[],"access_token":"{}","user_id":"1"}}"#,
                jwt_with_exp(9_999_999_999)
            ),
        )
        .expect("写会话");
    let service = KeyRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault: Arc::clone(&vault) as Arc<dyn Vault>,
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
        },
    );
    service.restore_sessions();
    let mut settings = service.settings().expect("设置");
    settings.balance_alert_threshold = 15.0;
    service.update_settings(&settings).expect("写设置");

    let summary = service.refresh_all().await.expect("刷新");
    assert!(
        summary.balance_alerts.is_empty(),
        "P2-22：未知余额不得当 0（实际 {:?}）",
        summary.balance_alerts
    );
    let events = Store::open(&dir.path().join("k.db"))
        .expect("开库")
        .list_events(200)
        .expect("事件");
    assert!(
        !events.iter().any(|e| e.message.contains("余额低于阈值")),
        "P2-22：未知余额不得写「余额低于阈值」事件"
    );
}

// ============================================================ P2-4

/// 读失败一次、之后正常的钥匙串（模拟锁屏 / ACL 拒绝）。
struct FlakyVault {
    inner: MemoryVault,
    fail_next_get: std::sync::atomic::AtomicBool,
}

impl FlakyVault {
    fn new() -> Self {
        Self {
            inner: MemoryVault::new(),
            fail_next_get: std::sync::atomic::AtomicBool::new(false),
        }
    }
    /// 只让**网关令牌**那一条的下一次读失败：其它读（站点密钥等）不受影响。
    fn arm(&self) {
        self.fail_next_get
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    const GATEWAY_REF: &'static str = "kr/gateway/local/token";
}

impl Vault for FlakyVault {
    fn backend_name(&self) -> &'static str {
        "memory"
    }
    fn probe(&self) -> Result<()> {
        Ok(())
    }
    fn put(&self, key: &str, secret: &str) -> Result<()> {
        self.inner.put(key, secret)
    }
    fn get(&self, key: &str) -> Result<Option<String>> {
        if key == Self::GATEWAY_REF
            && self
                .fail_next_get
                .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(Error::Vault("读失败（探针注入）".to_string()));
        }
        self.inner.get(key)
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key)
    }
}

#[tokio::test]
async fn gateway_token_read_failure_keeps_the_persisted_token() {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let store = Store::open(&dir.path().join("k.db")).expect("库");
    let site_id = store
        .upsert_site("sub2api", "https://sub.example.com", "站")
        .expect("站点");
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "k", &reference, Some("1"), None)
        .expect("key");
    let vault = Arc::new(FlakyVault::new());
    vault
        .put(&reference, "sk-m16-0123456789abcdef")
        .expect("密钥");
    let service = KeyRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault: Arc::clone(&vault) as Arc<dyn Vault>,
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
        },
    );

    // 第一次装配：钥匙串里没有网关令牌 ⇒ 生成并写进去。
    service
        .gateway_config(site_id, key_id, 39001)
        .expect("装配 1");
    let persisted = vault
        .get("kr/gateway/local/token")
        .expect("读")
        .expect("应有持久令牌");

    // 第二次装配：钥匙串**读**失败一次 ⇒ 必须用临时令牌，且**不覆盖**已持久化的那把。
    vault.arm();
    let config = service
        .gateway_config(site_id, key_id, 39001)
        .expect("装配 2");
    assert_ne!(
        config.token, persisted,
        "读失败时应当用临时令牌（本次会话有效）"
    );
    assert_eq!(
        vault.get("kr/gateway/local/token").expect("读").as_deref(),
        Some(persisted.as_str()),
        "P2-4：读失败**不得**覆盖已持久化的令牌"
    );
    assert!(
        !service.gateway_token_persistent(),
        "P2-4：本次用的是临时令牌 ⇒ 状态位应为 false（与事件文案一致）"
    );
}

// ============================================================ B-113 / B-121

#[tokio::test]
async fn logout_deletes_the_persisted_session() {
    let f = fixture(vec![login_response(&jwt_with_exp(9_999_999_999))]);
    f.service
        .login(f.site_id, Credentials::new("me@example.com", "pw-12345678"))
        .await
        .expect("登录");
    let reference = keyrelay_core::vault::secret_ref("site", f.site_id, "session");
    assert!(
        f.service.vault_has_for_test(&reference).expect("查钥匙串"),
        "B-113：登录后会话应已持久化到钥匙串"
    );

    f.service.logout(f.site_id).expect("退出登录");
    assert!(
        !f.service.vault_has_for_test(&reference).expect("查钥匙串"),
        "B-113：退出登录必须删掉钥匙串条目"
    );
    // 新实例不该恢复出会话（缓存已清 + 条目已删）
    let fresh = KeyRelayService::new(
        Store::open(&f.db_path).expect("开库"),
        MockTransport::new(vec![]),
        ServiceConfig {
            vault: Arc::new(MemoryVault::new()),
            home: f.home.clone(),
            backup_dir: f.home.join("backups"),
        },
    );
    fresh.restore_sessions();
    assert!(
        fresh.session_expiry(f.site_id).is_none(),
        "退出后不该恢复出任何会话"
    );
}

#[tokio::test]
async fn session_expiry_reads_jwt_exp() {
    let exp = 9_999_999_999_i64;
    let f = fixture(vec![login_response(&jwt_with_exp(exp))]);
    f.service
        .login(f.site_id, Credentials::new("me@example.com", "pw-12345678"))
        .await
        .expect("登录");

    let expiry = f.service.session_expiry(f.site_id).expect("应有过期信息");
    assert_eq!(expiry.expires_at, exp);
    assert!(expiry.seconds_left > 0, "未来时间戳 ⇒ 剩余为正");
}

#[tokio::test]
async fn session_expiry_is_none_for_tokens_without_exp() {
    for token in [
        "not-a-jwt",
        "only-one-segment",
        "a.b.c",
        // 合法 base64 但不是 JSON
        "a.bm90LWpzb24.c",
    ] {
        let f = fixture(vec![login_response(token)]);
        f.service
            .login(f.site_id, Credentials::new("me@example.com", "pw-12345678"))
            .await
            .expect("登录");
        assert!(
            f.service.session_expiry(f.site_id).is_none(),
            "B-121：无法解析的 token ⇒ None（不得 panic）：{token}"
        );
    }
}

#[tokio::test]
async fn restore_sessions_skips_expired_jwt() {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let db_path = dir.path().join("k.db");
    let vault = Arc::new(MemoryVault::new());
    let store = Store::open(&db_path).expect("库");
    let site_id = store
        .upsert_site("sub2api", "https://sub.example.com", "站")
        .expect("站点");
    // 直接写一条**已过期**的会话进钥匙串（模拟上次运行留下的旧会话）。
    let expired = format!(
        r#"{{"cookies":[],"access_token":"{}","user_id":"7"}}"#,
        jwt_with_exp(1_000_000)
    );
    vault
        .put(
            &keyrelay_core::vault::secret_ref("site", site_id, "session"),
            &expired,
        )
        .expect("写会话");
    let service = KeyRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault: Arc::clone(&vault) as Arc<dyn Vault>,
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
        },
    );
    service.restore_sessions();
    assert!(
        service.session_expiry(site_id).is_none(),
        "B-121：过期会话不得恢复"
    );
    assert!(
        !vault
            .has(&keyrelay_core::vault::secret_ref(
                "site", site_id, "session"
            ))
            .expect("查"),
        "B-121：过期会话应被删掉（否则每次启动都要再吃一次 401）"
    );
}

// ============================================================ B-81

#[tokio::test]
async fn notify_baseline_is_persisted_after_a_refresh() {
    let f = fixture(vec![
        login_response(&jwt_with_exp(9_999_999_999)),
        sub2api_ok(json!({"balance": 100.0, "total_recharged": 100.0})),
        sub2api_ok(json!([])),
    ]);
    f.service
        .login(f.site_id, Credentials::new("me@example.com", "pw-12345678"))
        .await
        .expect("登录");
    let service = f.service.with_notify(keyrelay_core::notify::NotifyConfig {
        system_enabled: false,
        webhook_url: None,
        balance_threshold: 0.0,
        timeout: std::time::Duration::from_secs(5),
    });
    assert!(!service.notify_baseline_present(), "首轮之前不该有基线");
    service.refresh_all().await.expect("刷新");
    assert!(
        service.notify_baseline_present(),
        "B-81：刷新后应把基线落库（跨重启可用）"
    );
}

// ============================================================ B-80

#[tokio::test]
async fn snapshot_models_come_from_the_collection() {
    // `collect_models` 开 + 该站有可用 key ⇒ 刷新时采集一次 `/v1/models`；
    // 采集结果必须进 `SiteSnapshot.models`（此前恒 `None` ⇒ `ModelsChanged` 永不触发）。
    let f = fixture(vec![
        login_response(&jwt_with_exp(9_999_999_999)),
        sub2api_ok(json!({"balance": 100.0, "total_recharged": 100.0})),
        sub2api_ok(json!([])),
        // `/v1/models`（采集）：Sub2API 的兼容响应形态
        json_ok(json!({"object": "list", "data": [{"id": "gpt-5.6"}]})),
    ]);
    f.service
        .login(f.site_id, Credentials::new("me@example.com", "pw-12345678"))
        .await
        .expect("登录");
    let mut settings = f.service.settings().expect("设置");
    settings.collect_models = true;
    settings.models_min_interval_secs = 0; // 本轮就采
    f.service.update_settings(&settings).expect("写设置");

    let service = f.service.with_notify(keyrelay_core::notify::NotifyConfig {
        system_enabled: false,
        webhook_url: None,
        balance_threshold: 0.0,
        timeout: std::time::Duration::from_secs(5),
    });
    let _ = &f.key_id;
    service.refresh_all().await.expect("刷新");

    let snapshot = service.notify_last_snapshot_for_test().expect("应有快照");
    let site = snapshot
        .sites
        .iter()
        .find(|s| s.site_id == f.site_id)
        .expect("快照里应有该站点");
    assert_eq!(
        site.models,
        Some(vec!["gpt-5.6".to_string()]),
        "B-80：快照的 models 必须来自采集结果（不是 None）"
    );
}
