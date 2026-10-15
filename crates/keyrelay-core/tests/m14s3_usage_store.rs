//! M14-S3：`usage_samples` 表与 `keys.quota_used` 写入的 CRUD 测试（spec §12）。
//!
//! 隔离：全部用 `Store::open_in_memory()`（内存库），不碰文件库。

use keyrelay_core::site::KeyDailyUsage;
use keyrelay_core::store::Store;

fn sample(date: &str, cost: f64) -> KeyDailyUsage {
    KeyDailyUsage {
        date: date.to_string(),
        requests: 10,
        input_tokens: 100,
        output_tokens: 50,
        total_tokens: 150,
        cost,
    }
}

fn fresh_site_with_key(store: &Store) -> (i64, i64) {
    let site_id = store
        .upsert_site("newapi", "https://x.example.com", "x")
        .unwrap();
    let key_id = store
        .insert_key(site_id, "k", "kr/s/i/f", Some("r1"), None)
        .unwrap();
    (site_id, key_id)
}

#[test]
fn usage_samples_table_created_by_migrate() {
    // 建表幂等：open_in_memory 调 migrate 建出 usage_samples，upsert 不报 no such table。
    let store = Store::open_in_memory().unwrap();
    let (site_id, key_id) = fresh_site_with_key(&store);
    store
        .upsert_usage_sample(key_id, site_id, &sample("2026-10-01", 0.1))
        .unwrap();
}

#[test]
fn upsert_usage_sample_overwrites_same_day() {
    // UNIQUE(key_id, date) + INSERT OR REPLACE：同日覆盖，不堆积。
    let store = Store::open_in_memory().unwrap();
    let (site_id, key_id) = fresh_site_with_key(&store);
    store
        .upsert_usage_sample(key_id, site_id, &sample("2026-10-01", 0.1))
        .unwrap();
    store
        .upsert_usage_sample(key_id, site_id, &sample("2026-10-01", 0.5))
        .unwrap();
    let rows = store.recent_key_usage(key_id, 30).unwrap();
    assert_eq!(rows.len(), 1, "同日应覆盖，不堆积");
    assert_eq!(rows[0].cost, 0.5, "后者胜");
}

#[test]
fn recent_key_usage_orders_by_date_asc() {
    let store = Store::open_in_memory().unwrap();
    let (site_id, key_id) = fresh_site_with_key(&store);
    store
        .upsert_usage_sample(key_id, site_id, &sample("2026-10-03", 0.3))
        .unwrap();
    store
        .upsert_usage_sample(key_id, site_id, &sample("2026-10-01", 0.1))
        .unwrap();
    store
        .upsert_usage_sample(key_id, site_id, &sample("2026-10-02", 0.2))
        .unwrap();
    let rows = store.recent_key_usage(key_id, 30).unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].date, "2026-10-01");
    assert_eq!(rows[1].date, "2026-10-02");
    assert_eq!(rows[2].date, "2026-10-03");
}

#[test]
fn recent_key_usage_scoped_to_key() {
    // 不同 key 的采样不串。
    let store = Store::open_in_memory().unwrap();
    let site_id = store
        .upsert_site("newapi", "https://x.example.com", "x")
        .unwrap();
    let k1 = store
        .insert_key(site_id, "k1", "kr/s/i/f", Some("r1"), None)
        .unwrap();
    let k2 = store
        .insert_key(site_id, "k2", "kr/s/i/g", Some("r2"), None)
        .unwrap();
    store
        .upsert_usage_sample(k1, site_id, &sample("2026-10-01", 0.1))
        .unwrap();
    store
        .upsert_usage_sample(k2, site_id, &sample("2026-10-01", 0.2))
        .unwrap();
    assert_eq!(store.recent_key_usage(k1, 30).unwrap().len(), 1);
    assert_eq!(store.recent_key_usage(k2, 30).unwrap().len(), 1);
}

#[test]
fn update_key_usage_none_writes_null_not_zero() {
    // 「不知道」≠「用 0」：None 写 NULL（与 Balance::known 同纪律）。
    let store = Store::open_in_memory().unwrap();
    let (_site_id, key_id) = fresh_site_with_key(&store);
    store
        .update_key_usage(key_id, Some(1.5), Some(10.0), Some("USD"))
        .unwrap();
    // 覆盖回 None
    store.update_key_usage(key_id, None, None, None).unwrap();
    let row = store
        .list_keys()
        .unwrap()
        .into_iter()
        .find(|r| r.id == key_id)
        .unwrap();
    assert_eq!(row.quota_used, None);
    assert_eq!(row.quota_limit, None);
    assert_eq!(row.currency, None);
}

#[test]
fn update_key_usage_values_readable_from_list_keys() {
    // list_keys 的 SELECT 含 quota_used/quota_limit/currency（M14-S3 加列）。
    let store = Store::open_in_memory().unwrap();
    let (_site_id, key_id) = fresh_site_with_key(&store);
    store
        .update_key_usage(key_id, Some(1.5), Some(10.0), Some("USD"))
        .unwrap();
    let row = store
        .list_keys()
        .unwrap()
        .into_iter()
        .find(|r| r.id == key_id)
        .unwrap();
    assert_eq!(row.quota_used, Some(1.5));
    assert_eq!(row.quota_limit, Some(10.0));
    assert_eq!(row.currency.as_deref(), Some("USD"));
}

#[test]
fn update_key_usage_values_readable_from_get_key() {
    // get_key 的 SELECT 也含用量字段（投递路径 get_key 不该丢用量）。
    let store = Store::open_in_memory().unwrap();
    let (_site_id, key_id) = fresh_site_with_key(&store);
    store
        .update_key_usage(key_id, Some(2.0), Some(20.0), Some("USD"))
        .unwrap();
    let row = store.get_key(key_id).unwrap().unwrap();
    assert_eq!(row.quota_used, Some(2.0));
    assert_eq!(row.quota_limit, Some(20.0));
    assert_eq!(row.currency.as_deref(), Some("USD"));
}

#[test]
fn prune_usage_samples_keeps_recent() {
    // prune(90) 保留最近 90 天：刚写的采样（sampled_at=now）不删（`sampled_at < cutoff` 不含 ==）。
    // 删旧逻辑与 `prune_gateway_usage_log` / `prune_usage_snapshots` 同构，已有同构测试覆盖。
    let store = Store::open_in_memory().unwrap();
    let (site_id, key_id) = fresh_site_with_key(&store);
    store
        .upsert_usage_sample(key_id, site_id, &sample("2026-10-01", 0.1))
        .unwrap();
    let n = store.prune_usage_samples(90).unwrap();
    assert_eq!(n, 0, "最近 90 天的不该删");
    assert_eq!(store.recent_key_usage(key_id, 30).unwrap().len(), 1);
}

#[test]
fn prune_usage_samples_deletes_old_rows() {
    // 删旧：用 `prune_usage_samples(0)` cutoff=now，但 sampled_at==now 不满足 `<now`。
    // 改用负天数让 cutoff 落在未来，验证 DELETE 真的能删行（与 prune_gateway_usage_log 同构）。
    let store = Store::open_in_memory().unwrap();
    let (site_id, key_id) = fresh_site_with_key(&store);
    store
        .upsert_usage_sample(key_id, site_id, &sample("2026-10-01", 0.1))
        .unwrap();
    // cutoff = now - (-1)*86400 = now + 86400（未来），sampled_at=now < now+86400 ⇒ 删。
    let n = store.prune_usage_samples(-1).unwrap();
    assert!(n >= 1, "应至少删一条");
    assert!(store.recent_key_usage(key_id, 30).unwrap().is_empty());
}

#[test]
fn delete_site_cascades_usage_samples() {
    // ON DELETE CASCADE：删站点连带删 usage_samples（与 gateway_usage_log / usage_snapshots 同口径）。
    let store = Store::open_in_memory().unwrap();
    let site_id = store
        .upsert_site("newapi", "https://x.example.com", "x")
        .unwrap();
    let key_id = store
        .insert_key(site_id, "k", "kr/s/i/f", Some("r1"), None)
        .unwrap();
    store
        .upsert_usage_sample(key_id, site_id, &sample("2026-10-01", 0.1))
        .unwrap();
    store.delete_site(site_id).unwrap();
    // key 已级联删，recent_key_usage(key_id) 应空（不报错：行不在也不 panic）。
    assert!(store.recent_key_usage(key_id, 30).unwrap().is_empty());
}
