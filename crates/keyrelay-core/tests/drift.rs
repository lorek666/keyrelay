//! 漂移检测的端到端验证（M3-S1 spec §7）。

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use keyrelay_core::delivery::DeliveryChannel;
use keyrelay_core::drift::DriftState;
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::transport::MockTransport;
use keyrelay_core::store::Store;
use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};

const SECRET: &str = "sk-drift-0123456789abcdef";

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    service: KeyRelayService<MockTransport>,
    key_id: i64,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");

    let store = Store::open(&dir.path().join("keyrelay.db")).expect("文件库");
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

/// Continue 的条目必须有模型名（Continue 的 schema 必填；KeyRelay 不编造默认模型），
/// 其余通道不需要。对 `ALL` 循环的用例统一从这里取。
fn model_for(channel: DeliveryChannel) -> Option<&'static str> {
    (channel == DeliveryChannel::Continue).then_some("gpt-4o")
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
fn missing_after_rollback() {
    // 回滚会把「投递时新建的文件」删掉 → 之后检测应是 Missing（而不是 Intact）
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
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].state, DriftState::Missing);
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

    let conn = rusqlite::Connection::open(f.home.parent().unwrap().join("keyrelay.db")).unwrap();
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
