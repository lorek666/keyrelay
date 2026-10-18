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
    fixture_with_group(responses, Some("vip"), None)
}

/// 同上，但分组两列由调用方给（M22-S2 / B-171：倍率按 `group_id` 认定要用）。
///
/// 走 `insert_key_with_group`——与生产 `create_key` 同一条写入口径，两列同一条 INSERT。
fn fixture_with_group(
    responses: Vec<HttpResponse>,
    group_name: Option<&str>,
    group_id: Option<&str>,
) -> Fixture {
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
        .insert_key_with_group(
            site_id,
            "m16/daily",
            &reference,
            Some("1"),
            group_name,
            group_id,
        )
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

// ============================================================ 倍率按 id 认定（M22-S2 / B-171）

/// **站点侧改了名**：本地记的是「gpt plus」+ 主键 2，站点上 id 2 现在叫「gpt plus v2」。
///
/// 轮换早已按 id 认定（M22-S1），倍率这里却还在只按名字 ⇒ 改名后倍率变「未知」，
/// 网关按倍率排序的依据静默消失，直到下一次轮换把新名字写回。id 是主键，改名不改它。
#[tokio::test]
async fn rate_follows_the_group_id_after_the_site_renames_it() {
    let f = fixture_with_group(
        vec![
            login_response(&jwt_with_exp(9_999_999_999)),
            sub2api_ok(json!([
                {"id": 1, "name": "default", "description": ""},
                {"id": 2, "name": "gpt plus v2", "description": ""},
            ])),
            sub2api_ok(json!({"1": 0.5, "2": 2.0})),
        ],
        // 本地记的是**旧名**，但主键还是 2
        Some("gpt plus"),
        Some("2"),
    );
    f.service
        .login(f.site_id, Credentials::new("me@example.com", "pw-12345678"))
        .await
        .expect("登录");
    f.service.available_groups(f.site_id).await.expect("拉分组");

    assert_eq!(
        f.service.site_rate_for_test(f.site_id),
        Some(2.0),
        "B-171：站点改名后倍率必须仍按 group_id 取到（按名字会落空 ⇒ 未知）"
    );
}

/// 有 `group_id` 而站点列表里没有该 id ⇒ `None`，**不**回落到按名字找。
///
/// 这条防的是"回落"这一诱人的修法：名字分支会把另一个分组的倍率记到这把 key 上，
/// 而排序看起来照常有依据——正是 P2-12 要防的那种"看起来对、其实是错"。
#[tokio::test]
async fn rate_is_none_when_the_stored_group_id_is_gone_even_if_the_name_matches() {
    let f = fixture_with_group(
        vec![
            login_response(&jwt_with_exp(9_999_999_999)),
            // 站点上有个**同名**的 `vip`（id 1），但本地记的主键是 9
            sub2api_ok(json!([{"id": 1, "name": "vip", "description": ""}])),
            sub2api_ok(json!({"1": 0.5})),
        ],
        Some("vip"),
        Some("9"),
    );
    f.service
        .login(f.site_id, Credentials::new("me@example.com", "pw-12345678"))
        .await
        .expect("登录");
    f.service.available_groups(f.site_id).await.expect("拉分组");

    assert_eq!(
        f.service.site_rate_for_test(f.site_id),
        None,
        "B-171：主键不在列表里 ⇒ 未知；按名字回落会把 id=1 的 0.5 记到这把 key 上"
    );
}

/// id **命中**但该分组没有倍率 ⇒ `None`（M22-S2 复审 §6-2：id 分支的覆盖闭环）。
///
/// 既有那条 `rate_is_none_when_the_keys_group_has_no_rate` 走的是**名字**分支；
/// 两个分支共用末尾的 `.and_then(|group| group.rate)`，但只覆盖一侧时，将来若把
/// id 分支改成「命中就给个默认倍率」，没有任何用例会红。
#[tokio::test]
async fn rate_is_none_when_the_id_matches_but_the_group_has_no_rate() {
    let f = fixture_with_group(
        vec![
            login_response(&jwt_with_exp(9_999_999_999)),
            // 站点上有 id=2，但既没有 rate_multiplier，rates 里也没有 "2"
            sub2api_ok(json!([{"id": 2, "name": "gpt plus", "description": ""}])),
            sub2api_ok(json!({"1": 0.5})),
        ],
        Some("gpt plus"),
        Some("2"),
    );
    f.service
        .login(f.site_id, Credentials::new("me@example.com", "pw-12345678"))
        .await
        .expect("登录");
    f.service.available_groups(f.site_id).await.expect("拉分组");

    assert_eq!(
        f.service.site_rate_for_test(f.site_id),
        None,
        "B-171：id 命中但该分组没有倍率 ⇒ 未知（不得借用别的分组的 0.5）"
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
async fn jwt_exp_handles_malformed_tokens() {
    for token in [
        "not-a-jwt",
        "only-one-segment",
        "a.b.c",
        // 合法 base64 但不是 JSON
        "a.bm90LWpzb24.c",
        // 空串 / 两段 / 段内非法 base64 / JSON 里没有 exp / exp 不是整数
        "",
        "a.b",
        "a.!!!not-base64!!!.c",
        "a.eyJzdWIiOiI3In0.c",
        "a.eyJleHAiOiJub3QtYS1udW1iZXIifQ.c",
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

/// B-81 的**可见降级**路径：基线编码失败（fail-closed）时不得静默 ——
/// 必须有 Warn 事件，且基线状态仍是「没有」。
///
/// 触发器必须是**真的密钥形态**（词边界处的 `sk-` + 32 位十六进制）；
/// `task-scheduler` 这类「词中间的 sk-」已被 P2-26 的边界规则修好，不再触发（道② 的改动已在本基线）。
#[tokio::test]
async fn notify_baseline_refusal_is_visible_not_silent() {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let store = Store::open(&dir.path().join("k.db")).expect("库");
    let secret_shaped_name = format!("站点 sk-{}", "0123456789abcdef0123456789abcdef");
    let site_id = store
        .upsert_site("sub2api", "https://sub.example.com", &secret_shaped_name)
        .expect("站点");
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
        MockTransport::new(vec![
            sub2api_ok(json!({"balance": 100.0, "total_recharged": 100.0})),
            sub2api_ok(json!([])),
        ]),
        ServiceConfig {
            vault: Arc::clone(&vault) as Arc<dyn Vault>,
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
        },
    );
    service.restore_sessions();
    let service = service.with_notify(keyrelay_core::notify::NotifyConfig {
        system_enabled: false,
        webhook_url: None,
        balance_threshold: 0.0,
        timeout: std::time::Duration::from_secs(5),
    });
    service.refresh_all().await.expect("刷新");

    assert!(
        !service.notify_baseline_present(),
        "编码被拒 ⇒ 不该有基线（fail-closed）"
    );
    let events = Store::open(&dir.path().join("k.db"))
        .expect("开库")
        .list_events(200)
        .expect("事件");
    assert!(
        events
            .iter()
            .any(|e| e.message.contains("通知基线未能保存")),
        "B-81：编码失败必须**可见**（Warn 事件），不得静默关闭"
    );
}

// ============================================================ 复审 P1-2 补的测试（把已有行为钉住）

/// P2-16 服务半：同 `(agent_id, key_id, target_path)` 的重投只留**最新一行**。
#[tokio::test]
async fn channel_bindings_dedups_reapplied_targets() {
    let f = fixture(vec![]);
    let store = Store::open(&f.db_path).expect("开库");
    for journal in ["j-1", "j-2", "j-3"] {
        store
            .record_binding(
                "claude-code",
                f.key_id,
                "/home/u/.claude/settings.json",
                journal,
                "site",
            )
            .expect("记绑定");
    }
    let rows = f.service.channel_bindings().expect("绑定列表");
    assert_eq!(
        rows.len(),
        1,
        "P2-16：同一目标的重复投递只应留一行（实际 {rows:?}）"
    );
}

/// P3-26：一轮刷新里的事件必须按 **site_id 升序** 落库（不是按完成顺序）。
#[tokio::test]
async fn refresh_events_are_ordered_by_site_id() {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let db_path = dir.path().join("k.db");
    let vault = Arc::new(MemoryVault::new());
    let store = Store::open(&db_path).expect("库");
    let mut ids = Vec::new();
    for n in 0..3 {
        let id = store
            .upsert_site("sub2api", &format!("https://s{n}.example.com"), "站")
            .expect("站点");
        vault
            .put(
                &keyrelay_core::vault::secret_ref("site", id, "session"),
                &format!(
                    r#"{{"cookies":[],"access_token":"{}","user_id":"1"}}"#,
                    jwt_with_exp(9_999_999_999)
                ),
            )
            .expect("会话");
        ids.push(id);
    }
    // 三个站点全部失败（余额 503）⇒ 每站一条「刷新站点失败」事件，用来验顺序。
    let service = KeyRelayService::new(
        store,
        MockTransport::new(vec![
            HttpResponse::new(503, b"down".to_vec()),
            HttpResponse::new(503, b"down".to_vec()),
            HttpResponse::new(503, b"down".to_vec()),
        ]),
        ServiceConfig {
            vault: Arc::clone(&vault) as Arc<dyn Vault>,
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
        },
    );
    service.restore_sessions();
    service.refresh_all().await.expect("刷新");

    let events = Store::open(&db_path)
        .expect("开库")
        .list_events(200)
        .expect("事件");
    let seen: Vec<i64> = events
        .iter()
        .filter(|e| e.message.starts_with("刷新站点失败"))
        .filter_map(|e| e.payload.as_deref())
        .filter_map(|p| serde_json::from_str::<serde_json::Value>(p).ok())
        .filter_map(|v| v.get("site_id").and_then(|s| s.as_i64()))
        .collect();
    // `list_events` 是 **id 降序**（最新在前）⇒ 反转后才是「落库顺序」。
    let written: Vec<i64> = seen.iter().rev().copied().collect();
    let mut sorted = written.clone();
    sorted.sort_unstable();
    assert_eq!(
        written, sorted,
        "P3-26：事件必须按 site_id 升序落库（落库顺序 = list_events 的反转）"
    );
    assert_eq!(written.len(), 3, "三个站点各一条失败事件");
}

/// 自定义传输层：记录**并发在途峰值**，每次请求停留一小会儿（让重叠真的发生）。
#[derive(Clone)]
struct CountingTransport {
    inflight: Arc<std::sync::atomic::AtomicUsize>,
    peak: Arc<std::sync::atomic::AtomicUsize>,
}

impl CountingTransport {
    fn new() -> Self {
        Self {
            inflight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            peak: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

#[async_trait::async_trait]
impl keyrelay_core::site::transport::HttpTransport for CountingTransport {
    async fn request(
        &self,
        req: keyrelay_core::site::transport::HttpRequest,
    ) -> Result<HttpResponse> {
        use std::sync::atomic::Ordering;
        let now = self.inflight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        self.inflight.fetch_sub(1, Ordering::SeqCst);
        if req.url.contains("/keys") {
            Ok(json_ok(json!({"code": 0, "data": []})))
        } else {
            Ok(json_ok(
                json!({"code": 0, "data": {"balance": 100.0, "total_recharged": 100.0}}),
            ))
        }
    }
}

/// P3-27：两次 `refresh_all` 重叠时，在途峰值**不得**超过 `MAX_REFRESH_CONCURRENCY`。
#[tokio::test]
async fn overlapping_refresh_all_calls_serialize() {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let db_path = dir.path().join("k.db");
    let vault = Arc::new(MemoryVault::new());
    let store = Store::open(&db_path).expect("库");
    // 8 个站点：不加互斥时两次重叠调用会把在途推到 8。
    for n in 0..8 {
        let id = store
            .upsert_site("sub2api", &format!("https://s{n}.example.com"), "站")
            .expect("站点");
        vault
            .put(
                &keyrelay_core::vault::secret_ref("site", id, "session"),
                &format!(
                    r#"{{"cookies":[],"access_token":"{}","user_id":"1"}}"#,
                    jwt_with_exp(9_999_999_999)
                ),
            )
            .expect("会话");
    }
    let transport = CountingTransport::new();
    let service = KeyRelayService::new(
        store,
        transport.clone(),
        ServiceConfig {
            vault: Arc::clone(&vault) as Arc<dyn Vault>,
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
        },
    );
    service.restore_sessions();
    let (a, b) = tokio::join!(service.refresh_all(), service.refresh_all());
    a.expect("第一轮");
    b.expect("第二轮");

    let peak = transport.peak.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        peak <= keyrelay_core::service::MAX_REFRESH_CONCURRENCY,
        "P3-27：在途峰值 {peak} 不得超过 {}",
        keyrelay_core::service::MAX_REFRESH_CONCURRENCY
    );
}

/// B-81：基线**跨实例**（同库新实例）可见 —— 即已落库，不是只在内存里。
#[tokio::test]
async fn notify_baseline_persists_across_instances() {
    let f = fixture(vec![
        login_response(&jwt_with_exp(9_999_999_999)),
        sub2api_ok(json!({"balance": 100.0, "total_recharged": 100.0})),
        sub2api_ok(json!([])),
    ]);
    f.service
        .login(f.site_id, Credentials::new("me@example.com", "pw-12345678"))
        .await
        .expect("登录");
    let first = f.service.with_notify(keyrelay_core::notify::NotifyConfig {
        system_enabled: false,
        webhook_url: None,
        balance_threshold: 0.0,
        timeout: std::time::Duration::from_secs(5),
    });
    first.refresh_all().await.expect("第一实例刷新");

    let second = KeyRelayService::new(
        Store::open(&f.db_path).expect("开库"),
        MockTransport::new(vec![]),
        ServiceConfig {
            vault: Arc::new(MemoryVault::new()),
            home: f.home.clone(),
            backup_dir: f.home.join("backups"),
        },
    );
    assert!(
        second.notify_baseline_present(),
        "B-81：新实例（同库）应当能看到已落库的基线"
    );
}

/// B-113 红线：会话凭证**只**进钥匙串 —— 库文件字节 / 事件 / 诊断导出都不得出现它。
#[tokio::test]
async fn session_is_persisted_to_the_vault_only() {
    const MARKER: &str = "TOKEN-MARKER-M16S5-DO-NOT-PERSIST";
    let f = fixture(vec![login_response(MARKER)]);
    f.service
        .login(f.site_id, Credentials::new("me@example.com", "pw-12345678"))
        .await
        .expect("登录");
    let reference = keyrelay_core::vault::secret_ref("site", f.site_id, "session");
    assert!(
        f.service.vault_has_for_test(&reference).expect("查钥匙串"),
        "B-113：会话应当在钥匙串里"
    );

    // ① 库文件字节（含 WAL / SHM）
    for suffix in ["", "-wal", "-shm"] {
        let path = std::path::PathBuf::from(format!("{}{suffix}", f.db_path.display()));
        if let Ok(bytes) = std::fs::read(&path) {
            assert!(
                !bytes.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()),
                "B-113 红线：{} 里出现了会话凭证",
                path.display()
            );
        }
    }
    // ② 事件表
    let events = events_of(&f);
    for event in &events {
        let text = format!(
            "{}{}",
            event.message,
            event.payload.clone().unwrap_or_default()
        );
        assert!(!text.contains(MARKER), "B-113 红线：事件里出现了会话凭证");
    }
    // ③ 诊断导出
    if let Ok(dump) = f.service.export_diagnostics(200) {
        assert!(
            !format!("{dump:?}").contains(MARKER),
            "B-113 红线：诊断导出里出现了会话凭证"
        );
    }
}

/// B-113：认证失败（站点 401）⇒ 删掉钥匙串里的持久化会话（下次启动不再恢复一个坏会话）。
#[tokio::test]
async fn auth_failure_deletes_the_persisted_session() {
    let f = fixture(vec![
        login_response(&jwt_with_exp(9_999_999_999)),
        HttpResponse::new(401, br#"{"code":401,"message":"invalid token"}"#.to_vec()),
        HttpResponse::new(401, br#"{"code":401,"message":"invalid token"}"#.to_vec()),
    ]);
    f.service
        .login(f.site_id, Credentials::new("me@example.com", "pw-12345678"))
        .await
        .expect("登录");
    let reference = keyrelay_core::vault::secret_ref("site", f.site_id, "session");
    assert!(f.service.vault_has_for_test(&reference).expect("查"));

    f.service.refresh_all().await.expect("刷新");
    assert!(
        !f.service.vault_has_for_test(&reference).expect("查"),
        "B-113：站点侧失效后必须删掉持久化会话"
    );
}

// ============================================================ B-155（M16-S10 ②）

/// **B-155 ②**（原 §7 名 `rotation_reports_local_status_not_updated`，本增量**改名**）：
/// 站点侧删成功、**本地 `keys.status` 写失败** ⇒ `revoked == true` 且
/// `local_status_updated == false`。轮换收尾据此报「站点侧已删、本地未写成 revoked」，
/// 而不是纯「已回收」（否则用户以为本地也清了）。
///
/// **为什么改名**：拥有 `local_status_updated` 字段、能被确定断言的是 `revoke_key`；
/// 轮换层只是把它转述成文案（那句文案仍由读码覆盖，见 spec §11）。原名会把断言引向
/// 快乐路径（`true`），与名字不符。
///
/// **诱导方式（确定性，不靠概率/时序）**：SQLite 触发器只让 `keys` 表的 UPDATE 失败
/// （`RAISE(ABORT, …)`）——`journals` / `bindings` / `events` 照常可写 ⇒ 精确命中该分支。
#[tokio::test]
async fn revoke_key_reports_local_status_not_updated_when_the_keys_update_fails() {
    let f = fixture(vec![
        login_response(&jwt_with_exp(9_999_999_999)),
        HttpResponse::new(204, Vec::new()), // 第一次 DELETE /api/v1/keys/1
        HttpResponse::new(204, Vec::new()), // 第二次（去掉触发器后的反向验证）
    ]);
    f.service
        .login(f.site_id, Credentials::new("me@example.com", "pw-12345678"))
        .await
        .expect("登录");

    // 只挡 keys 表的 UPDATE（其它表照常可写）
    let conn = rusqlite::Connection::open(&f.db_path).expect("注入连接");
    conn.execute_batch(
        "CREATE TRIGGER block_key_status BEFORE UPDATE ON keys
         BEGIN SELECT RAISE(ABORT, 'blocked by M16-S10 test'); END;",
    )
    .expect("建触发器");
    drop(conn);

    let report = f
        .service
        .revoke_key(f.site_id, "1")
        .await
        .expect("站点侧已删 ⇒ 整体仍是 Ok（本地没记上不改变「站点上那把已经没了」）");
    assert!(report.revoked, "站点侧必须确认删除: {report:?}");
    assert!(
        !report.local_status_updated,
        "本地写状态被挡住 ⇒ 必须如实报 false（调用方据此提示「本地未写成 revoked」）: {report:?}"
    );

    // 反向：去掉触发器后同一条路必须能写上 ⇒ 证明上面的 false 是触发器造成的
    let conn = rusqlite::Connection::open(&f.db_path).expect("再开");
    conn.execute_batch("DROP TRIGGER block_key_status")
        .expect("删触发器");
    drop(conn);
    let report = f
        .service
        .revoke_key(f.site_id, "1")
        .await
        .expect("第二次回收");
    assert!(
        report.local_status_updated,
        "没有触发器时必须写上 revoked: {report:?}"
    );
}
