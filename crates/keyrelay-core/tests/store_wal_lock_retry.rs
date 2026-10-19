//! M16-S10 ① / B-140：`Store::open` 的 WAL 切换重试循环的**确定性**用例。
//!
//! 背景：`store/mod.rs::concurrent_first_upgrade_of_an_old_database_all_succeed` 是**概率型**
//! （旧实现 1/10 红，作者报 8/40；修复后 0/20 绿）。概率型守卫在更快 / 更少争用的机器上会
//! **静默失效**，长期退化成装饰（S1 复审 P3-1 = BACKLOG B-140）。
//!
//! 这里把竞态窗口变成**确定性**的：另一个连接用 `BEGIN EXCLUSIVE` **显式**持锁
//! （不依赖线程调度），而「从 rollback journal 切到 WAL」需要独占锁
//! ⇒ 第一次尝试必然撞锁 ⇒ 只有重试循环能救。
//!
//! **M24-S1（B-156）之后**：重试预算改成可注入的（私有 `Store::open_with_budget`），
//! 于是「按预算放弃 + 报出真实重试次数」那一半从 `#[ignore]` 的 3.5 分钟用例
//! 搬进了 `store/mod.rs` 的单元测试（`open_gives_up_immediately_when_the_budget_is_zero`
//! 与 `open_gives_up_after_the_budget_and_says_how_many_retries`），跑一次约 0.1s。
//! 本文件只保留**必须用真实默认预算**的那条：锁在窗口内释放 ⇒ 必须熬过去。

use std::path::Path;
use std::time::{Duration, Instant};

use keyrelay_core::store::Store;
use rusqlite::Connection;

fn journal_mode(conn: &Connection) -> String {
    conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
        .expect("读 journal_mode")
}

/// 造一个**非 WAL** 的库文件。
///
/// 关键：只有「从 rollback journal 切到 WAL」才需要独占锁。若夹具本来就是 WAL，
/// 这条用例会变成空跑 ⇒ 夹具自己断言初始模式是 `delete`。
fn make_rollback_journal_db(path: &Path) {
    let conn = Connection::open(path).expect("建库");
    conn.execute_batch(
        "CREATE TABLE probe(id INTEGER PRIMARY KEY, note TEXT);
         INSERT INTO probe(id, note) VALUES (1, 'fixture');",
    )
    .expect("建表");
    assert_eq!(
        journal_mode(&conn),
        "delete",
        "夹具必须是非 WAL 库（否则切 WAL 不需要独占锁，用例会变成空跑）"
    );
}

/// 拿一把排他锁：`BEGIN EXCLUSIVE` 立刻拿锁，不依赖调度。
fn hold_exclusive_lock(path: &Path) -> Connection {
    let conn = Connection::open(path).expect("锁连接");
    conn.execute_batch("BEGIN EXCLUSIVE").expect("拿排他锁");
    conn
}

#[test]
fn open_waits_for_a_held_exclusive_lock_and_then_succeeds() {
    let dir = tempfile::tempdir().expect("临时目录");
    let db = dir.path().join("keyrelay.db");
    make_rollback_journal_db(&db);

    // 持锁 **6s**：必须大于 `busy_timeout(5s)`（M16-S10 实测：这条 pragma 会走忙等，
    // 所以短于 5s 的争用**光靠忙等就能扛过去**，那样这条用例就抓不到「重试循环没了」）。
    // M24-S1 之后忙等被**刻意关掉**、改由 `WAL_LOCK_BUDGET`(10s) 控制 —— 6s 仍在预算内，
    // 所以这条判据不变：只有「等到锁释放」才能成功。
    const HOLD_MS: u64 = 6_000;
    let blocker = hold_exclusive_lock(&db);
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(HOLD_MS));
        // 连接关闭 ⇒ 未提交的事务回滚 ⇒ 锁释放
        drop(blocker);
    });

    let started = Instant::now();
    let _store = Store::open(&db).expect(
        "重试循环必须等到锁释放后成功——旧实现会在忙等超时（5s）后报 `database is locked`（B-140 的确定性判据）",
    );
    let elapsed = started.elapsed();
    releaser.join().expect("放锁线程");

    assert!(
        elapsed >= Duration::from_millis(5_500),
        "必须熬过忙等超时（实测 {elapsed:?}，持锁 {HOLD_MS}ms）：没熬过去就说明重试循环没了"
    );
    // 重试成功后必须真的切到 WAL（模式是持久化在文件头里的）
    let probe = Connection::open(&db).expect("复开");
    assert_eq!(journal_mode(&probe), "wal", "重试成功后必须切到 WAL");
}
