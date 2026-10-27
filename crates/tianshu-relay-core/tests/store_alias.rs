//! 模型别名映射的存储层测试（M14-S1 / B-110）。
//!
//! 覆盖：建表迁移（v3 → v4）、CRUD 语义（后者胜 / 幂等删除）、输入校验（空 / 超长）。
//! 不测路由消费（那在 `routing_wiring.rs` 的 W10/W11）。

use tianshu_relay_core::store::Store;

fn fresh() -> Store {
    Store::open_in_memory().expect("内存库")
}

/// S1：v3 库打开后 `model_aliases` 表存在、老数据零丢失、`schema_version() == 6`、二次 `open` 不报错。
#[test]
fn v3_database_gets_alias_table_and_keeps_rows() {
    let dir = tempfile::tempdir().expect("临时目录");
    let path = dir.path().join("tianshu-relay.db");

    // 用 v3 的 DDL + user_version = 3 造库：model_aliases 还不存在（v4 才加）。
    // sites 表结构与生产 v3 一致（含 health / fingerprint_json），否则 list_sites 报缺列。
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE sites(
               id INTEGER PRIMARY KEY, kind TEXT, base_url TEXT, display_name TEXT,
               fingerprint_json TEXT, health TEXT NOT NULL DEFAULT 'unknown', created_at INTEGER
             );
             INSERT INTO sites(id, kind, base_url, display_name, health, created_at)
               VALUES (1, 'newapi', 'https://relay.example.com', '测试站', 'unknown', 0);
             PRAGMA user_version = 3;",
        )
        .unwrap();
    }

    // open 触发 migrate：补建 model_aliases + 升版本到 4。
    let store = Store::open(&path).expect("open v3");
    // M39-S1：schema 6 → 7（新增 site_model_catalog / site_model_sync）；
    // M40-S1：7 → 8（gateway_usage_log 六列）；M43-S1：8 → 9（gateway_tokens + usage token 归因）；M43-S2：9 → 10（model_prices / site_bills）。
    assert_eq!(store.schema_version().unwrap(), 12, "迁移到当前 v12");
    // 老数据零丢失
    let sites = store.list_sites().expect("list_sites");
    assert_eq!(sites.len(), 1, "老数据零丢失");
    assert_eq!(sites[0].id, 1);
    // model_aliases 表存在且为空
    assert!(
        store.list_alias_map().unwrap().is_empty(),
        "新表为空（v3 库里没有 alias 行）"
    );

    // 二次 open 幂等：不报 duplicate / 不丢数据
    drop(store);
    let again = Store::open(&path).expect("二次 open");
    assert_eq!(again.schema_version().unwrap(), 12, "当前版本 v12");
    assert_eq!(again.list_sites().unwrap().len(), 1);
}

/// S2：upsert 插入 + list 读回（按 alias 升序）；入参前后空格被 trim。
#[test]
fn upsert_and_list_alias_map() {
    let store = fresh();
    store.upsert_alias("gpt-5", "gpt-5-real").unwrap();
    store.upsert_alias("claude", "claude-3-opus").unwrap();
    // 前后空格 trim：存的是 "gemini" / "gemini-pro"
    store.upsert_alias("  gemini  ", "  gemini-pro  ").unwrap();

    let map = store.list_alias_map().unwrap();
    // 按 alias 升序
    assert_eq!(
        map,
        vec![
            ("claude".to_string(), "claude-3-opus".to_string()),
            ("gemini".to_string(), "gemini-pro".to_string()),
            ("gpt-5".to_string(), "gpt-5-real".to_string()),
        ]
    );
}

/// S3：重复 alias 后者胜（与 `alias_map` 的 `BTreeMap::insert` 语义一致）。
#[test]
fn upsert_alias_last_write_wins() {
    let store = fresh();
    store.upsert_alias("gpt-5", "gpt-5-a").unwrap();
    store.upsert_alias("gpt-5", "gpt-5-b").unwrap();

    let map = store.list_alias_map().unwrap();
    assert_eq!(map.len(), 1, "重复 alias 不新增行");
    assert_eq!(
        map[0],
        ("gpt-5".to_string(), "gpt-5-b".to_string()),
        "后者胜"
    );
}

/// S4：delete 后不含；删不存在的 alias 幂等返回 Ok。
#[test]
fn delete_alias_is_idempotent() {
    let store = fresh();
    store.upsert_alias("gpt-5", "gpt-5-real").unwrap();
    store.upsert_alias("claude", "claude-3").unwrap();

    store.delete_alias("gpt-5").unwrap();
    let map = store.list_alias_map().unwrap();
    assert_eq!(map.len(), 1);
    assert_eq!(map[0].0, "claude");

    // 删不存在的 alias 幂等返回 Ok（不报错）
    store.delete_alias("gpt-5").unwrap();
    store.delete_alias("never-existed").unwrap();
    // 带空格的删法也能命中（trim 后 = "claude"）
    store.delete_alias("  claude  ").unwrap();
    assert!(store.list_alias_map().unwrap().is_empty());
}

/// S5：空 / 空白 / 超长入参在 store 层就拒绝；128 刚好通过。
#[test]
fn upsert_alias_rejects_empty_and_overlong() {
    let store = fresh();
    // 空 / 空白（alias 与 real_model 任一为空都拒绝）
    assert!(store.upsert_alias("", "real").is_err());
    assert!(store.upsert_alias("   ", "real").is_err());
    assert!(store.upsert_alias("alias", "").is_err());
    assert!(store.upsert_alias("alias", "   ").is_err());
    // 超长（>128）
    let long = "x".repeat(129);
    assert!(store.upsert_alias(&long, "real").is_err());
    assert!(store.upsert_alias("alias", &long).is_err());
    // 拒绝的不写入
    assert!(store.list_alias_map().unwrap().is_empty());
    // 128 刚好通过
    let exact = "y".repeat(128);
    assert!(store.upsert_alias(&exact, "real").is_ok());
    assert_eq!(store.list_alias_map().unwrap().len(), 1);
}
