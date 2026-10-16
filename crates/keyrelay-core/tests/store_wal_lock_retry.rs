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
//! 快速用例（进常规门禁）：锁在窗口内释放 ⇒ **必须等到**锁释放后成功。
//! 慢用例（`#[ignore]`）：锁一直不放 ⇒ 按预算放弃 + 报出真实重试次数（见该函数文档的实测说明）。

use std::path::Path;
use std::time::{Duration, Instant};

use keyrelay_core::store::Store;
use rusqlite::Connection;

/// 与 `store/mod.rs::Store::open` 的重试预算保持一致（改那边时这里要跟着改）。
const RETRY_ATTEMPTS: u64 = 40;
const RETRY_DELAY_MS: u64 = 25;

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

    // 持锁 **6s**：比 `busy_timeout(5s)` 长（M16-S10 实测：这条 pragma 会走忙等，
    // 所以短于 5s 的争用**光靠忙等就能扛过去**，那样这条用例就抓不到「重试循环没了」）。
    // 只有重试循环能让它熬过 5s 之后的那一段。
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

/// **慢用例（`#[ignore]`，跑一次 ≈3.5 分钟）**：钉住「按预算放弃 + 报出真实重试次数」。
///
/// 为什么这么慢（M16-S10 实测，已回报 Lead）：`Store::open` 在 `PRAGMA journal_mode = WAL`
/// 之前设了 `busy_timeout(5s)`，而**这条 pragma 在这台机器上确实会走忙等**——锁一直被持有时，
/// 每次尝试要等满 5s 才拿到 `SQLITE_BUSY`，于是最坏总耗时 ≈ 41 × (5s + 25ms) ≈ **206s**
/// （实测 213.6s）。这与 `store/mod.rs` 里「SQLite 在这条路径上不调用忙等处理器 ⇒
/// `busy_timeout` 对它无效」的注释**不符**：预算实际上不是 ≈1s 而是 ≈3.5 分钟。
///
/// 快速的那一半（「锁会在窗口内释放 ⇒ 必须等到它」）在
/// [`open_waits_for_a_held_exclusive_lock_and_then_succeeds`] 里，进常规门禁。
#[test]
#[ignore = "≈3.5 分钟：钉住重试预算的上界与真实重试次数（详见函数文档的实测说明）"]
fn open_gives_up_after_the_retry_budget_and_says_how_many_retries() {
    let dir = tempfile::tempdir().expect("临时目录");
    let db = dir.path().join("keyrelay.db");
    make_rollback_journal_db(&db);

    // 锁一直不放：超过整个预算
    let blocker = hold_exclusive_lock(&db);
    let started = Instant::now();
    let err = match Store::open(&db) {
        Ok(_) => panic!("锁一直不放时必须按预算放弃，而不是无限等"),
        Err(err) => err,
    };
    let elapsed = started.elapsed();
    drop(blocker);

    let text = err.to_string();
    assert!(
        text.contains("切换 WAL 模式失败"),
        "错误文案应说清是切 WAL 失败: {text}"
    );
    assert!(
        text.contains(&format!("重试 {RETRY_ATTEMPTS} 次")),
        "必须报出真实的重试次数（旧实现是 0 次）: {text}"
    );
    // 有界：每次尝试受 busy_timeout(5s) 限制 ⇒ 总耗时落在 [预算, 41×5s + 余量] 内。
    let budget = Duration::from_millis(RETRY_ATTEMPTS * RETRY_DELAY_MS);
    let busy_bound = Duration::from_secs(5) * (RETRY_ATTEMPTS as u32 + 1);
    assert!(
        elapsed >= budget / 2,
        "至少要等掉半个预算（实测 {elapsed:?}，预算 {budget:?}）"
    );
    assert!(
        elapsed < busy_bound + Duration::from_secs(10),
        "不许无界等待（实测 {elapsed:?}，busy_timeout 上界 {busy_bound:?}）"
    );
}
