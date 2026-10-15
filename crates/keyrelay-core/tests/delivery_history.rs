//! 投递历史的端到端验证（M9-S4 spec §7 H1–H12）。
//!
//! 这一批测试守的是「变更历史页能不能真的回滚」这件事的两半：
//! ① 每次投递在界面上有一行（含已解绑的）；
//! ② 那一行上写的状态（可回滚 / 已被覆盖 / 已回滚）与**真实回滚的结果**一致——
//! 所以 H4 断言的不只是标志位，还真的去回滚旧那一次并比对文件字节。

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use keyrelay_core::delivery::{DeliveryChannel, DeliveryOutcome};
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::transport::MockTransport;
use keyrelay_core::store::{DeliveryHistoryRow, Store};
use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};

const AGENT: &str = "codex";

struct Fixture {
    _dir: tempfile::TempDir,
    db_path: PathBuf,
    service: KeyRelayService<MockTransport>,
    site_id: i64,
    keys: Vec<i64>,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");

    let db_path = dir.path().join("keyrelay.db");
    let store = Store::open(&db_path).expect("文件库");
    // 先占掉站点 id 1：否则 site = key = 1，`site_id` 与 `key_id` 互换也照样通过（复审 P2-3）
    store
        .upsert_site("newapi", "https://placeholder.example.com", "占位站")
        .expect("写占位站点");
    let site_id = store
        .upsert_site("newapi", "https://relay.example.com", "测试站")
        .expect("写站点");

    let vault = Arc::new(MemoryVault::new());
    let mut keys = Vec::new();
    // 两把（第三把留给 H7）：不同的明文 ⇒ 同一个目标文件上会真的产生不同内容，
    // 于是「第二次覆盖了第一次」是文件系统里的事实，不只是记录里的一行。
    for n in 1..=3 {
        let reference = secret_ref("key", n, "secret");
        vault
            .put(&reference, &format!("sk-history-{n:04}0123456789abcdef"))
            .expect("写钥匙串");
        keys.push(
            store
                .insert_key(
                    site_id,
                    &format!("codex/daily-{n}"),
                    &reference,
                    Some(&n.to_string()),
                    None,
                )
                .expect("写密钥记录"),
        );
    }

    let service = KeyRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault,
            home,
            backup_dir: dir.path().join("backups"),
        },
    );

    Fixture {
        _dir: dir,
        db_path,
        service,
        site_id,
        keys,
    }
}

fn target_path(f: &Fixture, channel: DeliveryChannel) -> PathBuf {
    f.service
        .delivery_plan(f.keys[0], channel)
        .unwrap()
        .target_path
}

/// 投递一次并返回结果。Continue 之外没有通道需要模型名（Continue 的 schema 必填）。
fn deliver(f: &Fixture, key_id: i64, channel: DeliveryChannel) -> DeliveryOutcome {
    f.service.grant_consent(key_id, channel).unwrap();
    let model = (channel == DeliveryChannel::OpenClaw).then_some("gpt-4o");
    f.service
        .apply_delivery_with_model(key_id, channel, model)
        .unwrap()
}

#[test]
fn empty_state_has_no_deliveries() {
    let f = setup();
    assert!(f.service.delivery_history(100).unwrap().is_empty());
}

#[test]
fn one_delivery_is_listed_with_its_journal() {
    let f = setup();
    let outcome = deliver(&f, f.keys[0], DeliveryChannel::CodexAuthJson);

    let rows = f.service.delivery_history(100).unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.journal_id, outcome.journal_id);
    assert_eq!(row.agent_id, AGENT);
    assert_ne!(f.site_id, f.keys[0], "两个 id 必须不同，否则互换抓不到");
    assert_eq!(row.key_id, f.keys[0]);
    assert_eq!(row.site_id, f.site_id);
    assert_eq!(
        row.target_path,
        target_path(&f, DeliveryChannel::CodexAuthJson)
            .display()
            .to_string()
    );
    assert_eq!(
        row.backup_path,
        outcome.backup_path.map(|p| p.display().to_string())
    );
    assert!(row.has_journal, "有变更记录");
    assert!(!row.rolled_back, "还没回滚过");
    assert!(!row.superseded, "这是这个目标上最新的一次投递");
    assert_eq!(row.unbound_at, None, "还绑着");
}

#[test]
fn later_delivery_to_the_same_target_supersedes_the_earlier_one() {
    let f = setup();
    let first = deliver(&f, f.keys[0], DeliveryChannel::CodexAuthJson);
    let second = deliver(&f, f.keys[1], DeliveryChannel::CodexAuthJson);

    let rows = f.service.delivery_history(100).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].journal_id, second.journal_id, "最新的在前");
    assert_eq!(rows[1].journal_id, first.journal_id);
    assert!(rows[1].superseded, "被之后的投递覆盖了");
    assert!(!rows[0].superseded);
}

#[test]
fn rolling_back_the_newer_delivery_restores_the_earlier_one() {
    let f = setup();
    let target = target_path(&f, DeliveryChannel::CodexAuthJson);
    // 投递之前文件就在：这样每次投递都留有备份，回滚是「还原」而不是「删除」
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&target, "{\n  \"auth_mode\": \"apikey\"\n}").unwrap();
    let before_first = fs::read(&target).unwrap();

    let first = deliver(&f, f.keys[0], DeliveryChannel::CodexAuthJson);
    let after_first = fs::read(&target).unwrap();
    let second = deliver(&f, f.keys[1], DeliveryChannel::CodexAuthJson);

    f.service.rollback_delivery(&second.journal_id).unwrap();
    assert_eq!(
        fs::read(&target).unwrap(),
        after_first,
        "回到第一次投递之后"
    );

    let rows = f.service.delivery_history(100).unwrap();
    let newer = rows
        .iter()
        .find(|r| r.journal_id == second.journal_id)
        .unwrap();
    let older = rows
        .iter()
        .find(|r| r.journal_id == first.journal_id)
        .unwrap();
    assert!(newer.rolled_back, "刚回滚的那次记为已回滚");
    assert!(
        !older.superseded,
        "覆盖它的那次已被回滚 ⇒ 它又成了当前生效的那次"
    );

    // 判据与真实结果一致：这一次**真的**能回滚
    f.service.rollback_delivery(&first.journal_id).unwrap();
    assert_eq!(fs::read(&target).unwrap(), before_first, "一路回到投递之前");
}

#[test]
fn superseded_delivery_cannot_be_rolled_back() {
    let f = setup();
    let target = target_path(&f, DeliveryChannel::CodexAuthJson);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&target, "{\n  \"auth_mode\": \"apikey\"\n}").unwrap();

    let first = deliver(&f, f.keys[0], DeliveryChannel::CodexAuthJson);
    deliver(&f, f.keys[1], DeliveryChannel::CodexAuthJson);

    let err = f.service.rollback_delivery(&first.journal_id).unwrap_err();
    assert!(
        matches!(err, keyrelay_core::error::Error::Inject { .. }),
        "被覆盖的那次回滚必须被拒（界面据此灰显）: {err:?}"
    );

    // 被拒 ⇒ 什么都没发生：不得记成「已回滚」（spec §6「回滚失败不记状态」，复审 P2-3）
    let rows = f.service.delivery_history(100).unwrap();
    let older = rows
        .iter()
        .find(|r| r.journal_id == first.journal_id)
        .unwrap();
    assert!(!older.rolled_back, "回滚被拒，状态不能变");
    assert!(older.superseded, "仍被之后那次覆盖着");
}

#[tokio::test]
async fn unbound_delivery_stays_listed_and_can_still_be_rolled_back() {
    let f = setup();
    let target = target_path(&f, DeliveryChannel::CodexAuthJson);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&target, "{\n  \"auth_mode\": \"apikey\"\n}").unwrap();
    let before = fs::read(&target).unwrap();

    let outcome = deliver(&f, f.keys[0], DeliveryChannel::CodexAuthJson);
    f.service.unbind(AGENT, false).await.unwrap();

    let rows = f.service.delivery_history(100).unwrap();
    let row = rows
        .iter()
        .find(|r| r.journal_id == outcome.journal_id)
        .expect("解绑不删行，投递记录仍在");
    assert!(row.unbound_at.is_some(), "标成已解绑");
    assert!(!row.superseded, "解绑不改文件内容，不构成覆盖");

    f.service.rollback_delivery(&outcome.journal_id).unwrap();
    assert_eq!(fs::read(&target).unwrap(), before, "解绑后仍能回滚");
}

#[tokio::test]
async fn an_unbound_newer_delivery_still_supersedes_the_older_one() {
    // spec §5：解绑不改文件，文件里仍是之后那次写下的内容 ⇒ 旧那次仍是「被覆盖」，回滚仍会被拒
    let f = setup();
    let target = target_path(&f, DeliveryChannel::CodexAuthJson);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&target, "{\n  \"auth_mode\": \"apikey\"\n}").unwrap();

    let first = deliver(&f, f.keys[0], DeliveryChannel::CodexAuthJson);
    let second = deliver(&f, f.keys[1], DeliveryChannel::CodexAuthJson);
    f.service.unbind(AGENT, false).await.unwrap();

    let rows = f.service.delivery_history(100).unwrap();
    let older = rows
        .iter()
        .find(|r| r.journal_id == first.journal_id)
        .unwrap();
    let newer = rows
        .iter()
        .find(|r| r.journal_id == second.journal_id)
        .unwrap();
    assert!(
        older.unbound_at.is_some() && newer.unbound_at.is_some(),
        "两行都解绑了"
    );
    assert!(older.superseded, "已解绑的那次更新投递仍然覆盖着它");
    assert!(!newer.superseded);

    // 判据与真实结果一致
    let err = f.service.rollback_delivery(&first.journal_id).unwrap_err();
    assert!(
        matches!(err, keyrelay_core::error::Error::Inject { .. }),
        "文件里是之后那次的内容，旧那次的回滚必须被拒: {err:?}"
    );
}

#[test]
fn limit_keeps_the_newest_deliveries() {
    let f = setup();
    deliver(&f, f.keys[0], DeliveryChannel::CodexAuthJson);
    deliver(&f, f.keys[1], DeliveryChannel::CodexAuthJson);
    let third = deliver(&f, f.keys[2], DeliveryChannel::CodexAuthJson);

    let rows = f.service.delivery_history(2).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].journal_id, third.journal_id);
}

#[test]
fn limit_never_hides_a_delivery_that_can_still_be_rolled_back() {
    // 历史页承诺「当前生效的投递都能在这里回滚」：limit 只能截掉旧的**历史**，
    // 不能把一个仍然生效、只是比较早的投递挤出页面（复审 P2-4）。
    let f = setup();
    let early_but_live = deliver(&f, f.keys[0], DeliveryChannel::Hermes);
    let superseded = deliver(&f, f.keys[0], DeliveryChannel::CodexAuthJson);
    let newest = deliver(&f, f.keys[1], DeliveryChannel::CodexAuthJson);

    let rows = f.service.delivery_history(1).unwrap();
    let ids: Vec<&str> = rows.iter().map(|r| r.journal_id.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            newest.journal_id.as_str(),
            early_but_live.journal_id.as_str()
        ],
        "最新的 1 行 + 更早但仍可回滚的那行；被覆盖的 {} 照常被 limit 截掉",
        superseded.journal_id
    );
}

#[test]
fn limit_never_hides_a_rolled_back_delivery_that_is_still_the_targets_state() {
    // 回滚过、之后再没投递过的目标：总览要靠这一行认出「这是你自己回滚的」，不能被 limit 挤掉
    let f = setup();
    let rolled = deliver(&f, f.keys[0], DeliveryChannel::CodexAuthJson);
    f.service.rollback_delivery(&rolled.journal_id).unwrap();
    deliver(&f, f.keys[0], DeliveryChannel::Hermes);
    let newest = deliver(&f, f.keys[1], DeliveryChannel::Hermes);

    let rows = f.service.delivery_history(1).unwrap();
    let ids: Vec<&str> = rows.iter().map(|r| r.journal_id.as_str()).collect();
    assert_eq!(
        ids,
        vec![newest.journal_id.as_str(), rolled.journal_id.as_str()],
        "最新的 1 行 + 那个目标的现状（已回滚）；被覆盖的第一次 shell 投递照常被截掉"
    );
    assert!(rows[1].rolled_back);
}

#[test]
fn different_targets_do_not_supersede_each_other() {
    let f = setup();
    let auth = deliver(&f, f.keys[0], DeliveryChannel::CodexAuthJson);
    let shell = deliver(&f, f.keys[0], DeliveryChannel::Hermes);
    assert_ne!(
        target_path(&f, DeliveryChannel::CodexAuthJson),
        target_path(&f, DeliveryChannel::Hermes),
        "两个不同的目标文件"
    );

    let rows: Vec<DeliveryHistoryRow> = f.service.delivery_history(100).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter().all(|r| !r.superseded),
        "目标是另一条路径，不算覆盖"
    );
    for expected in [auth.journal_id, shell.journal_id] {
        assert!(rows.iter().any(|r| r.journal_id == expected));
    }
}

#[test]
fn rollback_still_succeeds_when_the_status_cannot_be_recorded() {
    // 文件已经还原了：记状态失败不能把这次回滚报成失败（spec §6，与 B-100 同口径）。
    // 制造方式：直连库挂一个拒绝 UPDATE journals 的触发器——回滚要读的 SELECT 不受影响。
    let f = setup();
    let target = target_path(&f, DeliveryChannel::CodexAuthJson);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&target, "{\n  \"auth_mode\": \"apikey\"\n}").unwrap();
    let before = fs::read(&target).unwrap();
    let outcome = deliver(&f, f.keys[0], DeliveryChannel::CodexAuthJson);

    let conn = rusqlite::Connection::open(&f.db_path).expect("直连库");
    conn.execute_batch(
        "CREATE TRIGGER no_journal_updates BEFORE UPDATE ON journals
         BEGIN SELECT RAISE(ABORT, 'journals 只读（测试制造的故障）'); END;",
    )
    .expect("挂触发器");

    f.service
        .rollback_delivery(&outcome.journal_id)
        .expect("文件已还原，回滚必须报成功");
    assert_eq!(fs::read(&target).unwrap(), before, "文件确实还原了");

    let warned = f
        .service
        .recent_events(50)
        .unwrap()
        .into_iter()
        .any(|e| e.level == "warn" && e.message.contains("本地状态没记上"));
    assert!(warned, "没记上必须留下一条 warn 事件，不能静默");

    let rows = f.service.delivery_history(100).unwrap();
    assert!(
        !rows[0].rolled_back,
        "状态确实没记上（这条断言防止触发器没生效、测试空转）"
    );
}
