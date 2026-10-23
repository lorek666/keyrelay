//! M8-S4：解绑（FR-2:115 / B-104）与显示名迁移（DEBUG §1.3 的历史数据那一半）。
//!
//! 这一层此前**完全不存在**：全仓 `解绑` / `unbind` 零命中，`bindings` 表只有
//! `record_binding`（写）与 `binding_drift_rows`（读），没有任何入口能表达
//! 「这个 agent 不再用这把 key」。于是 PRD 那句「默认只解绑不回收（可恢复）」
//! 在数据模型里**没有承载物**。

use std::fs;

use rusqlite::Connection;
use tianshu_relay_core::store::{Store, KEY_STATUS_REVOKED};

fn store_with_one_binding() -> (tempfile::TempDir, Store, i64, i64) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("tianshu-relay.db")).unwrap();
    let site = store
        .upsert_site("newapi", "https://relay.example.com", "测试站")
        .unwrap();
    let key = store
        .insert_key(site, "codex/daily", "kr/key/1/secret", Some("1"), None)
        .unwrap();
    store
        .record_binding("codex", key, "/home/u/.codex/auth.json", "j1", "site")
        .unwrap();
    (dir, store, site, key)
}

#[test]
fn unbinding_marks_the_row_instead_of_deleting_it() {
    // §5.1：**解绑不是删除**。删行会连带丢掉 `managed_json` / `journal_id`
    // （回滚要靠它），而 `keys.id` 是漂移追溯链的起点——与 B-82 同一条纪律。
    let (_dir, store, _site, key) = store_with_one_binding();

    let report = store.unbind_agent("codex").unwrap();
    assert_eq!(report.unbound, 1);
    assert_eq!(report.already_unbound, 0);

    let rows = store.bindings_of_agent("codex").unwrap();
    assert_eq!(rows.len(), 1, "行必须**保留**（历史只增不改）");
    assert!(rows[0].unbound_at.is_some(), "标记写上了");
    assert_eq!(rows[0].key_id, key);
    assert_eq!(rows[0].target_path, "/home/u/.codex/auth.json");
}

#[test]
fn unbinding_is_idempotent_and_does_not_refresh_the_timestamp() {
    // 幂等：二次调用 `unbound == 0`，且**不刷新**时间戳——
    // 刷新会让「什么时候解绑的」随着重复点击漂移。
    let (_dir, store, _site, _key) = store_with_one_binding();

    store.unbind_agent("codex").unwrap();
    let first = store.bindings_of_agent("codex").unwrap()[0].unbound_at;

    let again = store.unbind_agent("codex").unwrap();
    assert_eq!(again.unbound, 0, "幂等：二次调用不该再标记");
    assert_eq!(again.already_unbound, 1, "但要如实报「本来就已解绑」");
    assert_eq!(
        store.bindings_of_agent("codex").unwrap()[0].unbound_at,
        first,
        "时间戳不得被刷新"
    );
}

#[test]
fn unbinding_something_that_does_not_exist_is_not_an_error() {
    // §4.3：一行都没命中 ⇒ `{0, 0}`。解绑是幂等的收尾动作，不是「必须命中」的操作。
    let (_dir, store, _site, _key) = store_with_one_binding();
    let report = store.unbind_agent("不存在的 agent").unwrap();
    assert_eq!((report.unbound, report.already_unbound), (0, 0));
}

#[test]
fn unbinding_one_target_leaves_the_others_alone() {
    // 同一 agent 可能有多个落点；`unbind_target` 只解绑**那一个文件**。
    let (_dir, store, site, key) = store_with_one_binding();
    store
        .record_binding(
            "codex",
            key,
            "/home/u/.config/opencode/opencode.json",
            "j2",
            "site",
        )
        .unwrap();

    let report = store.unbind_target("/home/u/.codex/auth.json").unwrap();
    assert_eq!(report.unbound, 1);

    let rows = store.bindings_of_agent("codex").unwrap();
    assert_eq!(rows.len(), 2, "两行都还在");
    let unbound: Vec<&str> = rows
        .iter()
        .filter(|r| r.unbound_at.is_some())
        .map(|r| r.target_path.as_str())
        .collect();
    assert_eq!(unbound, vec!["/home/u/.codex/auth.json"]);
    let _ = site;
}

#[test]
fn an_unbound_target_disappears_from_the_drift_report() {
    // §5.3：文件已经不属于我们；继续报「配置已漂移」等于指挥用户去修一个
    // 我们不该管的文件。
    let (_dir, store, _site, _key) = store_with_one_binding();
    assert_eq!(
        store.binding_drift_rows().unwrap().len(),
        1,
        "前提：本来在报告里"
    );

    store.unbind_agent("codex").unwrap();
    assert!(
        store.binding_drift_rows().unwrap().is_empty(),
        "解绑后不得再出现在漂移报告里"
    );
}

#[test]
fn re_delivering_after_unbinding_inserts_a_new_row() {
    // §5.3：再投递**允许**，且**新插一行**（旧行保持已解绑）。
    // 历史只增不改 ⇒ `binding_drift_rows` 取 `MAX(id)` 时新行自然成为最新。
    let (_dir, store, _site, key) = store_with_one_binding();
    store.unbind_agent("codex").unwrap();

    store
        .record_binding("codex", key, "/home/u/.codex/auth.json", "j3", "site")
        .unwrap();

    let rows = store.bindings_of_agent("codex").unwrap();
    assert_eq!(rows.len(), 2, "旧行保留 + 新行插入");
    assert!(rows[0].unbound_at.is_some(), "旧行仍然是已解绑");
    assert!(rows[1].unbound_at.is_none(), "新行是绑定的");
    assert_eq!(
        store.binding_drift_rows().unwrap().len(),
        1,
        "漂移报告里只应出现最新那一行（未解绑的）"
    );
}

#[test]
fn unbinding_does_not_touch_the_key_status() {
    // §5.3：解绑 ≠ 回收。站点侧那把 key 仍然有效、仍可在别处使用。
    let (_dir, store, _site, key) = store_with_one_binding();
    store.unbind_agent("codex").unwrap();

    let status = store.key_status(key).unwrap();
    assert_ne!(
        status.as_deref(),
        Some(KEY_STATUS_REVOKED),
        "解绑不得把 key 标成已回收（那是另一个动作，且不可逆）"
    );
}

// ============================================================ schema 迁移

/// 造一个 **v2** 的库：老 DDL（`bindings` 没有 `unbound_at`）+ 一条真实数据。
fn make_v2_database(path: &std::path::Path) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        r#"
        CREATE TABLE sites(
          id INTEGER PRIMARY KEY, kind TEXT NOT NULL, base_url TEXT NOT NULL UNIQUE,
          display_name TEXT NOT NULL, health TEXT NOT NULL DEFAULT 'unknown',
          created_at INTEGER NOT NULL
        );
        CREATE TABLE keys(
          id INTEGER PRIMARY KEY, site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
          account_id INTEGER, remote_id TEXT, name TEXT NOT NULL, group_id TEXT, group_name TEXT,
          secret_ref TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'unknown',
          created_at INTEGER NOT NULL, last_used_at INTEGER, quota_used REAL,
          quota_limit REAL, currency TEXT
        );
        CREATE TABLE bindings(
          id INTEGER PRIMARY KEY, agent_id TEXT NOT NULL,
          key_id INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
          target_path TEXT NOT NULL, managed_json TEXT, applied_at INTEGER NOT NULL,
          journal_id TEXT
        );
        INSERT INTO sites(id, kind, base_url, display_name, health, created_at)
          VALUES (1, 'newapi', 'https://relay.example.com', '老站', 'ok', 1700000000);
        INSERT INTO keys(id, site_id, remote_id, name, secret_ref, status, created_at)
          VALUES (1, 1, '1', 'codex/daily', 'kr/key/1/secret', 'unknown', 1700000000);
        INSERT INTO bindings(id, agent_id, key_id, target_path, managed_json, applied_at, journal_id)
          VALUES (1, 'codex', 1, '/home/u/.codex/auth.json', '{}', 1700000000, 'j1');
        PRAGMA user_version = 2;
        "#,
    )
    .unwrap();
}

#[test]
fn opening_a_v2_database_adds_the_unbound_column_without_losing_data() {
    // §5.2 的第三条：**必须**有一条「v2 老库（含数据）打开 → 列出现、老行 NULL、
    // 数据零丢失」的用例。这一条是本包最容易踩的坑：
    // DDL 是 `CREATE TABLE IF NOT EXISTS` ⇒ 加列**不会**自动生效。
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tianshu-relay.db");
    make_v2_database(&path);

    let store = Store::open(&path).unwrap();

    assert_eq!(
        store.schema_version().unwrap(),
        9,
        "版本号升到 9（M39-S1 是 7，M40-S1 是 8，M43-S1 新增 gateway_tokens 与 usage token 归因）"
    );
    let rows = store.bindings_of_agent("codex").unwrap();
    assert_eq!(rows.len(), 1, "老数据必须还在");
    assert_eq!(rows[0].target_path, "/home/u/.codex/auth.json");
    assert_eq!(rows[0].unbound_at, None, "老行默认「仍然绑定」");

    // 迁移之后解绑要真的能写进去（列存在）。
    let report = store.unbind_agent("codex").unwrap();
    assert_eq!(report.unbound, 1);
}

#[test]
fn reopening_a_migrated_database_is_idempotent() {
    // 不判存在就直接 `ALTER TABLE` 的话，**第二次打开**会因 `duplicate column name`
    // 直接失败——而 `migrate()` 是每次打开都跑的。
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tianshu-relay.db");
    make_v2_database(&path);

    for round in 1..=3 {
        let store = Store::open(&path).unwrap_or_else(|e| panic!("第 {round} 次打开失败: {e}"));
        assert_eq!(store.schema_version().unwrap(), 9);
    }
}

// ============================================================ 显示名迁移

#[test]
fn migrating_display_names_strips_only_the_exact_userinfo() {
    // DEBUG 报告 §1.3 的历史数据那一半：M7 版本录入 `https://alice:pw@host` 时，
    // `display_name` 被写成 `alice:pw@host`，文本级脱敏没有 `://` 抓不到它，
    // 于是通知与 webhook 正文会持续带出密码。
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("tianshu-relay.db")).unwrap();

    // ① 要修的形态：显示名逐字等于 userinfo
    let bad = store
        .upsert_site(
            "custom-openai-compatible",
            "https://alice:pw@host.example",
            "alice:pw@host.example",
        )
        .unwrap();
    // ② 对照组：正常的显示名，一个字都不该动
    let good = store
        .upsert_site("newapi", "https://relay.example.com", "我的中转站")
        .unwrap();
    // ③ 对照组：base_url 没有 userinfo
    let plain = store
        .upsert_site("newapi", "https://plain.example.com", "plain.example.com")
        .unwrap();

    let changed = store.migrate_display_names_stripping_userinfo().unwrap();
    assert_eq!(changed, 1, "只应改写那一行");

    let sites = store.list_sites().unwrap();
    let name_of = |id: i64| {
        sites
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.display_name.clone())
            .unwrap()
    };
    assert_eq!(name_of(bad), "host.example", "userinfo 被剥掉，剩下 host");
    assert!(!name_of(bad).contains("pw"), "密码不得残留");
    assert_eq!(name_of(good), "我的中转站", "正常显示名零误伤");
    assert_eq!(
        name_of(plain),
        "plain.example.com",
        "没有 userinfo 的行零误伤"
    );
}

#[test]
fn the_display_name_migration_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("tianshu-relay.db")).unwrap();
    store
        .upsert_site(
            "custom-openai-compatible",
            "https://alice:pw@host.example",
            "alice:pw@host.example",
        )
        .unwrap();

    assert_eq!(store.migrate_display_names_stripping_userinfo().unwrap(), 1);
    assert_eq!(
        store.migrate_display_names_stripping_userinfo().unwrap(),
        0,
        "第二次没有可改的行（否则每次启动都会写一次库）"
    );
}

#[test]
fn the_old_database_file_still_opens_after_migration() {
    // 顺带：迁移只改数据，不改文件权限 / 不重建文件。
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tianshu-relay.db");
    make_v2_database(&path);
    let before = fs::metadata(&path).unwrap().len();

    let store = Store::open(&path).unwrap();
    store.migrate_display_names_stripping_userinfo().unwrap();
    drop(store);

    assert!(path.exists());
    assert!(fs::metadata(&path).unwrap().len() >= before);
}

#[test]
fn open_strips_userinfo_from_legacy_display_names_automatically() {
    // P2-1（DEBUG-REPORT-v3 P2 #1）：Store::open 自动跑 migrate_display_names_stripping_userinfo。
    // M7 老库里 display_name 带 `user:pw@host` ⇒ 重新 open 后自动剥掉，无需手动调。
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tianshu-relay.db");

    // 建库 + 写一条带 userinfo 的显示名（模拟 M7 老库）。
    {
        let store = Store::open(&path).unwrap();
        store
            .upsert_site(
                "custom-openai-compatible",
                "https://alice:pw@host.example",
                "alice:pw@host.example",
            )
            .unwrap();
    }

    // 重新打开：open 应自动跑迁移。
    let store = Store::open(&path).unwrap();
    let sites = store.list_sites().unwrap();
    let name = sites
        .iter()
        .find(|s| s.base_url == "https://alice:pw@host.example")
        .map(|s| s.display_name.clone())
        .unwrap();
    assert_eq!(name, "host.example", "open 应自动剥掉 userinfo");
    assert!(!name.contains("pw"), "密码不得残留");
}
