//! 漂移检测的端到端验证（M3-S1 spec §7）。

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use tianshu_relay_core::delivery::DeliveryChannel;
use tianshu_relay_core::drift::DriftState;
use tianshu_relay_core::service::{ServiceConfig, TianshuRelayService};
use tianshu_relay_core::site::transport::MockTransport;
use tianshu_relay_core::store::Store;
use tianshu_relay_core::vault::{secret_ref, MemoryVault, Vault};

const SECRET: &str = "sk-drift-0123456789abcdef";

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    service: TianshuRelayService<MockTransport>,
    key_id: i64,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");

    let store = Store::open(&dir.path().join("tianshu-relay.db")).expect("文件库");
    let site_id = store
        .upsert_site("newapi", "https://relay.example.com", "测试站")
        .expect("写站点");
    let secret_ref = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &secret_ref, Some("1"), None)
        .expect("写密钥记录");

    let vault = Arc::new(MemoryVault::new());
    vault.put(&secret_ref, SECRET).expect("写钥匙串");

    let service = TianshuRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault,
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
        },
    );

    Fixture {
        _dir: dir,
        home,
        service,
        key_id,
    }
}

/// Continue 的条目必须有模型名（Continue 的 schema 必填；TianshuRelay 不编造默认模型），
/// 其余通道不需要。对 `ALL` 循环的用例统一从这里取。
fn model_for(channel: DeliveryChannel) -> Option<&'static str> {
    (channel == DeliveryChannel::OpenClaw).then_some("gpt-4o")
}

fn deliver(f: &Fixture, channel: DeliveryChannel) -> PathBuf {
    f.service.grant_consent(f.key_id, channel).unwrap();
    f.service
        .apply_delivery_with_model(f.key_id, channel, model_for(channel))
        .unwrap();
    f.service
        .delivery_plan(f.key_id, channel)
        .unwrap()
        .target_path
}

/// 两把 key 的夹具（M16-S1 / B-126 的「回退到上一次投递」用例）：
/// 同一个站点下的 A / B，用于「同一目标先投 A、再投 B、回滚 B」。
/// 返回的 `Fixture.key_id` 是 **A**。
fn setup_two_keys() -> (Fixture, i64) {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");

    let store = Store::open(&dir.path().join("tianshu-relay.db")).expect("文件库");
    let site_id = store
        .upsert_site("newapi", "https://relay.example.com", "测试站")
        .expect("写站点");
    let ref_a = secret_ref("key", 1, "secret");
    let key_a = store
        .insert_key(site_id, "codex/a", &ref_a, Some("1"), None)
        .expect("写密钥记录 A");
    let ref_b = secret_ref("key", 2, "secret");
    let key_b = store
        .insert_key(site_id, "codex/b", &ref_b, Some("2"), None)
        .expect("写密钥记录 B");

    let vault = Arc::new(MemoryVault::new());
    vault.put(&ref_a, SECRET).expect("写钥匙串 A");
    vault
        .put(&ref_b, "sk-drift-b-0123456789abcdef")
        .expect("写钥匙串 B");

    let service = TianshuRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault,
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
        },
    );

    (
        Fixture {
            _dir: dir,
            home,
            service,
            key_id: key_a,
        },
        key_b,
    )
}

#[test]
fn empty_state_reports_nothing() {
    let f = setup();
    assert!(f.service.drift_report().unwrap().is_empty());
}

#[test]
fn intact_after_delivery() {
    let f = setup();
    let target = deliver(&f, DeliveryChannel::CodexAuthJson);

    let reports = f.service.drift_report().unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].state, DriftState::Intact);
    assert_eq!(reports[0].target_path, target);
    assert_eq!(reports[0].agent_id, "codex");
    assert_eq!(reports[0].channel, "codex-auth-json");
    assert!(reports[0].expected_sha256.is_some());
    assert_eq!(
        reports[0].current_sha256, reports[0].expected_sha256,
        "完好时两个哈希应相同"
    );
}

#[test]
fn modified_after_external_edit() {
    let f = setup();
    let target = deliver(&f, DeliveryChannel::CodexAuthJson);

    // 模拟别的工具改了这个文件
    let mut content = fs::read_to_string(&target).unwrap();
    content.push('\n');
    fs::write(&target, content).unwrap();

    let reports = f.service.drift_report().unwrap();
    assert_eq!(reports[0].state, DriftState::Modified);
    assert_ne!(reports[0].current_sha256, reports[0].expected_sha256);

    // 应留下一条 warn 事件
    let warnings: Vec<_> = f
        .service
        .recent_events(100)
        .unwrap()
        .into_iter()
        .filter(|e| e.level == "warn" && e.message.contains("外部改动"))
        .collect();
    assert_eq!(warnings.len(), 1, "被改动时应有一条告警事件");
    // 事件里只能出现哈希前 8 位，不得出现完整哈希之外的敏感内容
    let payload = warnings[0].payload.clone().unwrap_or_default();
    assert!(payload.contains("agent_id"), "{payload}");
}

#[test]
fn missing_after_deletion() {
    let f = setup();
    let target = deliver(&f, DeliveryChannel::CodexAuthJson);
    fs::remove_file(&target).unwrap();

    let reports = f.service.drift_report().unwrap();
    assert_eq!(reports[0].state, DriftState::Missing);
    assert!(reports[0].current_sha256.is_none());
}

#[test]
fn rolled_back_delivery_leaves_drift_and_rotation() {
    // **M16-S1 / B-126 选项①**：回滚过的绑定不再是「现状」——
    // 该目标唯一一次投递被回滚 ⇒ 它**整条退出**漂移报告与轮换目标。
    //
    // 旧口径（本用例的前身 `missing_after_rollback`）断言「回滚后 → Missing」：
    // 那是拿一个已经被撤销的投递的 `after_sha256` 当期望值，与历史页的 `superseded`
    // 自相矛盾（同一个「已回滚」在历史页被标掉、在漂移页却仍算数）。
    // `Missing` 这条状态**没有消失**：文件被外部删除且没有回滚时仍是 `Missing`
    // （上一条 `drifted_file_that_was_deleted_reports_missing` 原样保留）。
    let f = setup();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    let outcome = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    f.service.rollback_delivery(&outcome.journal_id).unwrap();

    let reports = f.service.drift_report().unwrap();
    assert!(
        reports.is_empty(),
        "回滚后该目标应退出漂移报告: {reports:?}"
    );

    let plan = f.service.rotation_plan(f.key_id).unwrap();
    assert!(
        !plan
            .channels
            .contains(&DeliveryChannel::CodexAuthJson.as_str().to_string()),
        "回滚后这把 key 不该再被算作该文件的服务者: {:?}",
        plan.channels
    );
}

#[test]
fn rollback_falls_back_to_the_previous_delivery() {
    // **M16-S1 / B-126 选项①** 的另一面：同一目标先投 A、再投 B，回滚 B ⇒ 现状落回 A
    // （漂移 Intact、期望哈希来自 A 的那次投递；A 仍被算作该文件的服务者，B 不再是）。
    let (f, key_b) = setup_two_keys();
    let channel = DeliveryChannel::CodexAuthJson;

    // A 投递，记下它写下的字节
    let target = deliver(&f, channel);
    let after_a = fs::read(&target).unwrap();

    // B 投递到同一个目标（同 agent / 同通道 ⇒ 同一落点）
    f.service.grant_consent(key_b, channel).unwrap();
    let outcome_b = f
        .service
        .apply_delivery_with_model(key_b, channel, model_for(channel))
        .unwrap();

    // 回滚 B：文件应回到 A 的内容（journal 的 backup 就是 B 之前的字节）
    f.service.rollback_delivery(&outcome_b.journal_id).unwrap();
    assert_eq!(
        fs::read(&target).unwrap(),
        after_a,
        "回滚 B 应把文件还原成 A 写下的内容"
    );

    // 漂移：由 A 主导 ⇒ Intact（不是 Missing、也不是 B 的哈希）
    let reports = f.service.drift_report().unwrap();
    assert_eq!(reports.len(), 1, "该目标仍应有一条报告: {reports:?}");
    assert_eq!(reports[0].state, DriftState::Intact);
    assert_eq!(reports[0].target_path, target);

    // 轮换：A 仍带上该文件（一个通道 ↔ 一个落点），B 不再
    let plan_a = f.service.rotation_plan(f.key_id).unwrap();
    assert!(
        plan_a.channels.contains(&channel.as_str().to_string()),
        "A 应仍被算作该文件的服务者: {:?}",
        plan_a.channels
    );
    let plan_b = f.service.rotation_plan(key_b).unwrap();
    assert!(
        !plan_b.channels.contains(&channel.as_str().to_string()),
        "B 已回滚，不该再被算作该文件的服务者: {:?}",
        plan_b.channels
    );
}

#[test]
fn tracks_every_channel_independently() {
    let f = setup();
    for channel in DeliveryChannel::ALL {
        deliver(&f, channel);
    }

    let reports = f.service.drift_report().unwrap();
    // 期望值从 `ALL` 推导，而不是写死 3 或写死那三个字符串。
    // M6-S1 把 `ALL` 从 3 扩到 5 时，这个测试的两处硬编码会**同时**变红，
    // 而它要断言的其实是「每条通道各一条报告」这个关系，不是通道总数本身。
    assert_eq!(
        reports.len(),
        DeliveryChannel::ALL.len(),
        "每条通道各一条报告"
    );
    let mut channels: Vec<&str> = reports.iter().map(|r| r.channel.as_str()).collect();
    channels.sort_unstable();
    let mut expected: Vec<&str> = DeliveryChannel::ALL.iter().map(|c| c.as_str()).collect();
    expected.sort_unstable();
    assert_eq!(channels, expected);
    assert!(reports.iter().all(|r| r.state == DriftState::Intact));
}

#[test]
fn only_the_latest_delivery_per_target_is_reported() {
    let f = setup();
    deliver(&f, DeliveryChannel::CodexAuthJson);
    deliver(&f, DeliveryChannel::CodexAuthJson); // 同一目标再投一次

    let reports = f.service.drift_report().unwrap();
    assert_eq!(reports.len(), 1, "同一目标只应有一条报告");
    assert_eq!(reports[0].state, DriftState::Intact);
}

#[test]
fn old_rows_without_a_hash_are_unknown_not_modified() {
    // 模拟老库：删掉 journals 里的哈希，再检测
    let f = setup();
    deliver(&f, DeliveryChannel::CodexAuthJson);

    let conn =
        rusqlite::Connection::open(f.home.parent().unwrap().join("tianshu-relay.db")).unwrap();
    conn.execute_batch("UPDATE journals SET after_sha256 = NULL;")
        .unwrap();

    let reports = f.service.drift_report().unwrap();
    assert_eq!(
        reports[0].state,
        DriftState::Unknown,
        "缺哈希必须报 Unknown，不能猜成 Modified"
    );
    // Unknown 不该触发告警事件
    let warnings = f
        .service
        .recent_events(100)
        .unwrap()
        .into_iter()
        .filter(|e| e.level == "warn" && e.message.contains("外部改动"))
        .count();
    assert_eq!(warnings, 0, "Unknown 不该告警");
}

#[test]
fn drift_report_never_leaks_the_secret() {
    let f = setup();
    let target = deliver(&f, DeliveryChannel::CodexAuthJson);

    let reports = f.service.drift_report().unwrap();
    let debug = format!("{reports:?}");
    assert!(!debug.contains(SECRET), "报告泄漏密钥: {debug}");
    assert!(!debug.contains("sk-"), "报告出现密钥形态: {debug}");

    for row in f.service.recent_events(200).unwrap() {
        assert!(!row.message.contains(SECRET));
        if let Some(p) = row.payload {
            assert!(!p.contains(SECRET));
        }
    }

    // 目标文件本身当然含密钥（那是投递的目的）
    assert!(fs::read_to_string(&target).unwrap().contains(SECRET));
}
