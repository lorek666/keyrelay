//! 通知快照装配的**接线**验证（M6-S5 / 关闭 W-1）。
//!
//! 为什么单独一个文件：M6-S5 的两处快照装配曾经写死 `drift: Vec::new()` 与
//! `rotation_due: Vec::new()`，导致 `NotifyKind::Drift` 与 `RotationDue` 在生产上
//! **没有任何出口**，而 M6-S3 的包内测试全部照过——它们喂的是手工构造的快照，
//! 装配那一步不在覆盖范围内。本文件钉住的正是那一步：
//! **真实库里的事实（投递绑定 / 密钥创建时间）有没有走到规则判定的输入上**。
//!
//! 本文件**不**验证发送（那是 M6-S3 的覆盖范围，且发送侧要真弹通知）。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use keyrelay_core::delivery::DeliveryChannel;
use keyrelay_core::notify::NotifyConfig;
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::settings::Settings;
use keyrelay_core::site::transport::{HttpResponse, MockTransport};
use keyrelay_core::site::Credentials;
use keyrelay_core::store::Store;
use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};
use serde_json::json;

const SECRET: &str = "sk-wiring-0123456789abcdef";
const QUOTA_PER_UNIT: i64 = 500_000;
const DAY: i64 = 86_400;

struct Fixture {
    _dir: tempfile::TempDir,
    db: PathBuf,
    service: KeyRelayService<MockTransport>,
    mock: MockTransport,
    #[allow(dead_code, reason = "登录态用例之外用不到，但夹具统一返回")]
    site_id: i64,
    key_id: i64,
}

/// 两个发送出口**都关掉**：本文件验证的是「事实有没有走到规则」，不是发送。
/// 开着系统通知会让测试真的弹窗（macOS 上会把 `osascript` 叫起来）。
fn silent_notify() -> NotifyConfig {
    NotifyConfig {
        system_enabled: false,
        webhook_url: None,
        balance_threshold: 0.0,
        timeout: std::time::Duration::from_secs(10),
    }
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let db = dir.path().join("keyrelay.db");

    let store = Store::open(&db).expect("文件库");
    let site_id = store
        .upsert_site("newapi", "https://relay.example.com", "测试站")
        .expect("写站点");
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &reference, Some("1"), None)
        .expect("写密钥记录");

    let vault = Arc::new(MemoryVault::new());
    vault.put(&reference, SECRET).expect("写钥匙串");

    let mock = MockTransport::new(vec![]);
    let service = KeyRelayService::new(
        store,
        mock.clone(),
        ServiceConfig {
            vault,
            home,
            backup_dir: dir.path().join("backups"),
        },
    )
    .with_notify(silent_notify());

    Fixture {
        _dir: dir,
        db,
        service,
        mock,
        site_id,
        key_id,
    }
}

/// 真投递一次并返回目标文件路径（`tests/drift.rs` 同款夹具）。
fn deliver(f: &Fixture, key_id: i64, channel: DeliveryChannel) -> PathBuf {
    f.service.grant_consent(key_id, channel).expect("授权");
    f.service.apply_delivery(key_id, channel).expect("投递");
    f.service
        .delivery_plan(key_id, channel)
        .expect("取计划")
        .target_path
}

/// 把密钥的创建时间往前拨。
///
/// 为什么直接开库改：`Store::insert_key` 一律拿「现在」当 `created_at`，产品里没有
/// 「让一把钥匙变旧」的入口——那是测试需求，不是用户需求，为它开一个生产 API
/// 只会多一条能被误用的路径。`rusqlite` 已在 `[dev-dependencies]` 里（其注释写明
/// 「集成测试直接开库制造故障」），这是既有约定。
fn backdate_key(db: &Path, key_id: i64, age_secs: i64) {
    let conn = rusqlite::Connection::open(db).expect("开库");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("时钟")
        .as_secs() as i64;
    let changed = conn
        .execute(
            "UPDATE keys SET created_at = ?1 WHERE id = ?2",
            rusqlite::params![now - age_secs, key_id],
        )
        .expect("改创建时间");
    assert_eq!(changed, 1, "必须恰好命中一行：命不中说明夹具与库不一致");
}

/// 本轮**真的产出**的通知标题（按**判定顺序**）。
///
/// 取的是事件而不是通知本身：事件是装配 + 判定走完全程的产物，
/// 而当两个发送出口都关掉时，事件就是唯一的外部可观测点。
///
/// **必须反转一次**：`recent_events` 底层的 `query_events` 是 `ORDER BY id DESC`
/// （最新在最前，那是事件面板要的顺序），拿到的是逆序。只做 count 断言的测试感觉不到
/// 这件事，但「哪条先报」本身是有语义的（事实型与边沿型的相对位置），不能靠偶然——
/// 写这条测试时就踩过一次：断言写的是规则序，取到的却是倒序。
fn notification_titles(service: &KeyRelayService<MockTransport>) -> Vec<String> {
    let mut titles: Vec<String> = service
        .recent_events(500)
        .expect("读事件")
        .into_iter()
        .filter(|event| event.message.starts_with("通知: "))
        .map(|event| event.message.trim_start_matches("通知: ").to_string())
        .collect();
    titles.reverse();
    titles
}

fn with_rotation(max_age_days: u32, warn_before_days: u32) -> Settings {
    Settings {
        rotation_max_age_days: max_age_days,
        rotation_warn_before_days: warn_before_days,
        ..Settings::default()
    }
}

// ============================================================ 漂移（FR-3）

/// W-1 的修前形态：这里恒为空（`drift` 永远是空 `Vec`），且**没有任何测试会红**。
#[tokio::test]
async fn a_tampered_target_reaches_the_drift_rule() {
    let f = setup();
    let target = deliver(&f, f.key_id, DeliveryChannel::CodexAuthJson);
    fs::write(&target, "{\"tampered\":true}\n").expect("外部改动");

    f.service.refresh_all().await.expect("刷新");

    assert_eq!(
        notification_titles(&f.service),
        vec!["配置漂移"],
        "首轮有中性基线（unix_now_secs 上方的 neutral_baseline），漂移必须当轮就报出来"
    );
}

#[tokio::test]
async fn drift_is_reported_once_per_state_not_once_per_round() {
    let f = setup();
    let target = deliver(&f, f.key_id, DeliveryChannel::CodexAuthJson);
    fs::write(&target, "{\"tampered\":true}\n").expect("外部改动");

    f.service.refresh_all().await.expect("刷新");
    assert_eq!(notification_titles(&f.service), vec!["配置漂移"]);

    // 第二轮：文件内容没再变 → 同一条事实（agent, channel, path, state 四元组）→ 不重复报
    f.service.refresh_all().await.expect("刷新");
    assert_eq!(
        notification_titles(&f.service),
        vec!["配置漂移"],
        "状态没变不得重复告警（每轮一条会让用户把通知关掉）"
    );

    // 第三轮：文件再被改一次**但状态还是** `Modified` → 四元组没变 → 仍然不报。
    //
    // 这是 M6-S3 定稿的去重口径（`rules.rs::same_fact` 的键是**状态**，不是内容哈希），
    // 不是漏报：目标应用每次启动都重写自己的配置是常态，按内容哈希去重会变成每轮一条。
    fs::write(&target, "{\"tampered\":\"again\"}\n").expect("再改一次");
    f.service.refresh_all().await.expect("刷新");
    assert_eq!(
        notification_titles(&f.service),
        vec!["配置漂移"],
        "同一状态下的再次改动不重报（去重键是状态，不是内容）"
    );

    // 第四轮：状态**变了**（`Modified` → `Missing`）→ 新的四元组 → 必须再报。
    // 少了这一段，上面两条断言在「规则退化成只报第一次」时也会通过。
    fs::remove_file(&target).expect("删掉目标");
    f.service.refresh_all().await.expect("刷新");
    assert_eq!(
        notification_titles(&f.service),
        vec!["配置漂移", "配置漂移"],
        "状态变化（被改动 → 被删除）是新事实，必须再报"
    );
}

#[tokio::test]
async fn an_intact_target_produces_no_drift_notification() {
    let f = setup();
    let _target = deliver(&f, f.key_id, DeliveryChannel::CodexAuthJson);

    f.service.refresh_all().await.expect("刷新");
    f.service.refresh_all().await.expect("刷新");

    assert_eq!(
        notification_titles(&f.service),
        Vec::<String>::new(),
        "没被动过的目标不得进入告警——事实是采集了，但 Intact 不是「需要注意」"
    );
}

// ============================================================ 轮换（FR-7）

#[tokio::test]
async fn a_due_key_reaches_the_rotation_rule() {
    let f = setup();
    f.service
        .update_settings(&with_rotation(30, 7))
        .expect("写设置");
    backdate_key(&f.db, f.key_id, 40 * DAY);

    f.service.refresh_all().await.expect("刷新");

    assert_eq!(
        notification_titles(&f.service),
        vec!["密钥到期"],
        "到期的密钥必须报出来（W-1 的修前形态：这里恒为空）"
    );

    f.service.refresh_all().await.expect("刷新");
    assert_eq!(
        notification_titles(&f.service),
        vec!["密钥到期"],
        "同一把钥匙不得每轮重报（它每轮都会出现在到期列表里）"
    );
}

/// 反例保护：`rotation_max_age_days == 0` 必须真的关掉，而不是「碰巧没有到期的钥匙」。
///
/// 关键在于两段之间的对照——先证明「关掉时不报」，再证明「同一把钥匙在打开时**确实**
/// 被判为到期」。少了后半段，这条测试在「钥匙根本没变旧」时也会通过。
#[tokio::test]
async fn rotation_disabled_really_suppresses_a_key_that_is_due() {
    let f = setup();
    f.service
        .update_settings(&with_rotation(0, 7))
        .expect("写设置");
    backdate_key(&f.db, f.key_id, 40 * DAY);

    f.service.refresh_all().await.expect("刷新");
    f.service.refresh_all().await.expect("刷新");
    assert_eq!(
        notification_titles(&f.service),
        Vec::<String>::new(),
        "轮换关掉时不得有任何到期提醒"
    );

    f.service
        .update_settings(&with_rotation(30, 7))
        .expect("写设置");
    let due = f.service.rotation_due().expect("判定到期");
    assert_eq!(
        due.len(),
        1,
        "同一把钥匙在打开轮换后确实被判为到期 —— 前半段的空结果来自开关，不是来自数据"
    );
    assert_eq!(due[0].key_id, f.key_id);

    f.service.refresh_all().await.expect("刷新");
    assert_eq!(
        notification_titles(&f.service),
        vec!["密钥到期"],
        "打开之后要能立刻报出来"
    );
}

// ============================================================ 运行期新加的站点

/// W-1 的近亲，触发窗口窄得多但后果一样：**站点在运行期被加进来**时，它相对上一轮快照
/// 是「不存在」的。若基线只按 `prev` 取（不给缺失的站点补中性值），`evaluate` 里按站点取的
/// `before` 同样是 `None` → 漂移规则整条不评估；而这一轮的事实**已经写进了快照**，
/// 下一轮的 `same_fact` 会把它当成「报过了」→ **那条漂移永远不会被报出来**。
///
/// 这条测试只有在「缺口真的存在过」时才有意义：把它对着「基线只补首轮」的实现跑，
/// 会以「一条通知都没有」的形式变红（不是顺序或数量差一个，是彻底为 0）。
#[tokio::test]
async fn a_newly_added_site_reports_its_drift_on_the_very_round_it_appears() {
    let f = setup();

    // 第一轮：只有 `setup()` 建的那个站点，而它没有任何事实 → 不该有通知。
    f.service.refresh_all().await.expect("第一轮");
    assert_eq!(
        notification_titles(&f.service),
        Vec::<String>::new(),
        "第一个站点既没投递过也没登录过，第一轮不该有通知"
    );

    // 运行期加第二个站点：它不在第一轮快照里。
    let second = f
        .service
        .store()
        .upsert_site("newapi", "https://second.example.com", "后加的站")
        .expect("写站点");
    let second_key = f
        .service
        .store_key_material(
            second,
            "gemini/second",
            Some("9"),
            None,
            "sk-second-0123456789abcdef",
        )
        .expect("写第二把密钥")
        .id;

    // 用**另一个通道**（不同的目标文件），这样两个站点各有各的目标，不互相覆盖绑定。
    let target = deliver(&f, second_key, DeliveryChannel::GeminiCli);
    fs::write(&target, "GEMINI_API_KEY=sk-tampered\n").expect("外部改动");

    f.service.refresh_all().await.expect("第二轮");

    assert_eq!(
        notification_titles(&f.service),
        vec!["配置漂移"],
        "新站点在**它出现的这一轮**就要报出漂移；变成空 Vec 就是这个缺口又回来了"
    );
}

// ============================================================ 另一条装配分支
/// `refresh_all` 有两条推快照的分支（有会话 / 无会话）。上面所有用例走的都是**无会话**
/// 那条（夹具从不登录，也不会为它准备任何响应）。这条走有会话的那条，钉住两条分支
/// 装配出的事实一致——W-1 的形状正是「某一条分支里写死了空 `Vec`」。
///
/// 两类事实都断言：只测一类的话，另一类在**这条分支**上的写死仍会漏过。
#[tokio::test]
async fn a_logged_in_site_carries_drift_and_rotation_facts_too() {
    let f = setup();
    f.service
        .update_settings(&with_rotation(30, 7))
        .expect("写设置");
    backdate_key(&f.db, f.key_id, 40 * DAY);

    // 漂移事实也在这条分支上造一份：投递一个目标，再从外部改掉它。
    let target = deliver(&f, f.key_id, DeliveryChannel::CodexAuthJson);
    fs::write(&target, "{\"tampered\":true}\n").expect("外部改动");

    f.mock.push(encryption_disabled());
    f.mock.push(login_ok());
    f.service
        .login(f.site_id, Credentials::new("me", "pw"))
        .await
        .expect("登录");

    // 有会话的站点每轮两次请求：① 余额 ② 令牌列表（顺序与 refresh_all 的实现一致）
    f.mock.push(balance_ok(9_000_000));
    f.mock.push(keys_ok());

    f.service.refresh_all().await.expect("刷新");

    assert_eq!(
        notification_titles(&f.service),
        vec!["配置漂移", "密钥到期"],
        "有会话的分支同样要带上两类事实；顺序是规则的固定序（Drift 在 RotationDue 之前）"
    );
}

// ============================================================ 夹具（照 refresh_isolation.rs）

/// 站点未启用登录加密（`fetch_encryption_key` 的 fail-open 分支）
fn encryption_disabled() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": {"enabled": false}})).expect("构造响应")
}

fn login_ok() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": {"id": 7}}))
        .expect("构造响应")
        .with_header("Set-Cookie", "session=abc; Path=/")
}

/// 余额 = quota / quota_per_unit（USD）
fn balance_ok(quota: i64) -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"success": true, "data": {"quota": quota, "used_quota": 0, "quota_per_unit": QUOTA_PER_UNIT}}),
    )
    .expect("构造响应")
}

fn keys_ok() -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"success": true, "data": {"items": [], "total": 0}}),
    )
    .expect("构造响应")
}
