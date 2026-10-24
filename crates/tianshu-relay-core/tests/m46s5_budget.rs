//! M46-S5：按站 / 按 key 硬预算（store 层 + service 判定层）。
//!
//! 网关准入的端到端行为（拦截、429 尾巴、回调、legacy 路径）由
//! `gateway_balance.rs` 的固定桩用例覆盖；这里只覆盖需要真实 store 的部分：
//! 预算 CRUD 校验、已花口径（USD 价行 / CNY 排除 / 无价排除 / legacy 行归因）、
//! 周期窗口（本地日界、旧 at 行）、service 判定（key 级优先、fail-open 的 Err 可区分）。

use tianshu_relay_core::gateway::{BudgetPeriod, GatewayUsage};
use tianshu_relay_core::service::budget_breach_for;
use tianshu_relay_core::store::Store;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("时钟")
        .as_secs() as i64
}

fn store_with_site() -> (tempfile::TempDir, Store, i64) {
    let dir = tempfile::tempdir().expect("临时目录");
    let store = Store::open(&dir.path().join("t.db")).expect("建库");
    let site = store
        .upsert_site("newapi", "https://relay.example.com", "站")
        .expect("写站点");
    (dir, store, site)
}

fn usage(
    at: i64,
    site_id: i64,
    key_id: Option<i64>,
    model: &str,
    prompt: i64,
    completion: i64,
) -> GatewayUsage {
    GatewayUsage {
        at,
        site_id,
        key_id,
        model: model.to_string(),
        prompt_tokens: prompt,
        completion_tokens: completion,
        total_tokens: prompt + completion,
        status: 200,
        latency_ms: 10,
        attempts: 1,
        stream: false,
        token_id: None,
        agent_label: String::new(),
    }
}

fn price(store: &Store, model: &str, input: f64, output: f64, currency: &str, from: i64) {
    store
        .model_price_upsert(model, input, output, currency, from)
        .expect("写价格");
}

#[test]
fn budget_period_round_trips_through_store_strings() {
    assert_eq!(BudgetPeriod::parse("day"), Some(BudgetPeriod::Day));
    assert_eq!(BudgetPeriod::parse("month"), Some(BudgetPeriod::Month));
    assert_eq!(BudgetPeriod::parse("week"), None);
    assert_eq!(BudgetPeriod::parse(""), None);
    assert_eq!(BudgetPeriod::Day.as_str(), "day");
    assert_eq!(BudgetPeriod::Month.as_str(), "month");
}

#[test]
fn budget_create_validates_before_write() {
    let (_dir, store, site) = store_with_site();
    let other = store
        .upsert_site("newapi", "https://other.example.com", "别站")
        .expect("写别站");
    let key = store
        .insert_key(site, "k1", "kr/key/1/secret", None, None)
        .expect("写 key");

    // 上限非法
    assert!(store.budget_create(site, None, "day", 0.0).is_err());
    assert!(store.budget_create(site, None, "day", -5.0).is_err());
    assert!(store.budget_create(site, None, "day", f64::NAN).is_err());
    assert!(store
        .budget_create(site, None, "day", f64::INFINITY)
        .is_err());
    // 周期非法
    assert!(store.budget_create(site, None, "week", 10.0).is_err());
    assert!(store.budget_create(site, None, "", 10.0).is_err());
    // 站点 / key 不存在、key 属别站
    assert!(store.budget_create(9999, None, "day", 10.0).is_err());
    assert!(store.budget_create(site, Some(9999), "day", 10.0).is_err());
    let foreign_key = store
        .insert_key(other, "k2", "kr/key/2/secret", None, None)
        .expect("写别站 key");
    assert!(store
        .budget_create(site, Some(foreign_key), "day", 10.0)
        .is_err());
    // 全部拒绝后表仍为空
    assert!(store.budget_list().expect("列表").is_empty());

    // 合法行写进
    let id = store
        .budget_create(site, Some(key), "day", 10.0)
        .expect("合法建预算");
    let rows = store.budget_list().expect("列表");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, id);
    assert_eq!(rows[0].site_id, site);
    assert_eq!(rows[0].key_id, Some(key));
    assert_eq!(rows[0].period, "day");
    assert_eq!(rows[0].limit_usd, 10.0);
}

#[test]
fn budget_create_rejects_duplicate_scope_but_allows_site_and_key_rows() {
    let (_dir, store, site) = store_with_site();
    let key = store
        .insert_key(site, "k1", "kr/key/1/secret", None, None)
        .expect("写 key");

    store
        .budget_create(site, None, "day", 10.0)
        .expect("站级 day");
    assert!(
        store.budget_create(site, None, "day", 20.0).is_err(),
        "同站同周期站级行第二次应被拒"
    );
    store
        .budget_create(site, None, "month", 20.0)
        .expect("站级 month 是不同行");
    store
        .budget_create(site, Some(key), "day", 5.0)
        .expect("key 级 day 与站级 day 并存");
    assert!(
        store.budget_create(site, Some(key), "day", 6.0).is_err(),
        "同 key 同周期第二次应被拒"
    );
    assert_eq!(store.budget_list().expect("列表").len(), 3);
}

#[test]
fn budget_delete_missing_returns_false() {
    let (_dir, store, site) = store_with_site();
    assert!(!store.budget_delete(9999).expect("删不存在"));
    let id = store
        .budget_create(site, None, "day", 10.0)
        .expect("建预算");
    assert!(store.budget_delete(id).expect("删存在"));
    assert!(store.budget_list().expect("列表").is_empty());
    assert!(!store.budget_delete(id).expect("再删"));
}

#[test]
fn budget_spent_sums_usd_priced_rows_only() {
    let (_dir, store, site) = store_with_site();
    let key = store
        .insert_key(site, "k1", "kr/key/1/secret", None, None)
        .expect("写 key");
    let base = now() - 40 * 86_400;
    price(&store, "usd-model", 2.0, 4.0, "USD", base);
    price(&store, "cny-model", 2.0, 4.0, "CNY", base);
    // 注意：free-model 故意不配价。
    let t = now();
    // key 的 USD 行：1M prompt × 2.0 + 0.5M completion × 4.0 = 4.0
    store
        .insert_gateway_usage(&usage(t, site, Some(key), "usd-model", 1_000_000, 500_000))
        .expect("写用量");
    // legacy 行（key 为空）：1M prompt × 2.0 = 2.0，计站级不计 key 级
    store
        .insert_gateway_usage(&usage(t, site, None, "usd-model", 1_000_000, 0))
        .expect("写 legacy 用量");
    // CNY 价行与无价行：都不计入
    store
        .insert_gateway_usage(&usage(t, site, Some(key), "cny-model", 1_000_000, 500_000))
        .expect("写 CNY 用量");
    store
        .insert_gateway_usage(&usage(t, site, Some(key), "free-model", 1_000_000, 500_000))
        .expect("写无价用量");

    assert_eq!(
        store.budget_spent_usd(site, None, "day").expect("站级已花"),
        6.0,
        "站级 = key 的 USD 行 4.0 + legacy 行 2.0"
    );
    assert_eq!(
        store
            .budget_spent_usd(site, Some(key), "day")
            .expect("key 级已花"),
        4.0,
        "key 级只含该 key 的 USD 行"
    );
    assert_eq!(
        store
            .budget_spent_usd(site, Some(key + 1000), "day")
            .expect("无关 key 已花"),
        0.0
    );
}

#[test]
fn budget_spent_respects_day_and_month_windows() {
    let (dir, store, site) = store_with_site();
    let base = now() - 40 * 86_400;
    price(&store, "usd-model", 2.0, 4.0, "USD", base);
    let t = now();
    // 本周期行：1M prompt = 2.0
    store
        .insert_gateway_usage(&usage(t, site, None, "usd-model", 1_000_000, 0))
        .expect("写本周期用量");
    // 昨日行：40M prompt = 80.0（day 窗口外）
    store
        .insert_gateway_usage(&usage(t - 86_400, site, None, "usd-model", 40_000_000, 0))
        .expect("写昨日用量");
    // 40 天前行：40M prompt = 80.0（month 窗口外）
    store
        .insert_gateway_usage(&usage(
            t - 40 * 86_400,
            site,
            None,
            "usd-model",
            40_000_000,
            0,
        ))
        .expect("写上月用量");

    assert_eq!(
        store.budget_spent_usd(site, None, "day").expect("day 已花"),
        2.0,
        "昨日超支行不应计入本日"
    );
    // month 期望值按窗口起点动态算：昨日在本月内则含 80.0（82.0），
    // 若今日是 1 号则昨日属上月（2.0）——两种都是正确的本地月口径，测试不得写死。
    let (mstart, _) = store.budget_period_bounds("month").expect("month 窗口");
    let expected_month = if t - 86_400 >= mstart { 82.0 } else { 2.0 };
    assert_eq!(
        store
            .budget_spent_usd(site, None, "month")
            .expect("month 已花"),
        expected_month,
        "month 应含本周期行、排除 40 天前行；昨日行按是否在本月内决定"
    );

    // 周期窗口本身是本地日界：直接对同一文件开 rusqlite 连接核对。
    let path = dir.path().join("t.db");
    let conn = rusqlite::Connection::open(&path).expect("直连");
    let (start, end) = store.budget_period_bounds("day").expect("day 窗口");
    let local_today: String = conn
        .query_row(
            "SELECT date(?1, 'unixepoch', 'localtime')",
            rusqlite::params![start],
            |row| row.get(0),
        )
        .expect("查窗口起点本地日");
    let today: String = conn
        .query_row("SELECT date('now', 'localtime')", [], |row| row.get(0))
        .expect("查今天");
    assert_eq!(local_today, today, "day 窗口起点必须是本地今天零点");
    assert!(start <= t && t < end, "当前时刻必须落在 day 窗口内");
    assert!(
        (82_800..=90_000).contains(&(end - start)),
        "day 窗口长应为一天（DST 日 23/25 小时）: {}",
        end - start
    );
    let (mstart, mend) = store.budget_period_bounds("month").expect("month 窗口");
    assert!(mstart <= t && t < mend, "当前时刻必须落在 month 窗口内");
    assert!(
        (28 * 86_400..=31 * 86_400).contains(&(mend - mstart)),
        "month 窗口长应为 28–31 天: {}",
        mend - mstart
    );
}

#[test]
fn budget_breach_for_prefers_key_level_and_returns_none_when_under() {
    let (_dir, store, site) = store_with_site();
    let key = store
        .insert_key(site, "k1", "kr/key/1/secret", None, None)
        .expect("写 key");
    let base = now() - 40 * 86_400;
    price(&store, "usd-model", 2.0, 4.0, "USD", base);
    let t = now();
    // key 的 USD 行 = 4.0；站级预算 3.0（超）、key 级预算 5.0（未超）⇒ 站级 breach
    store
        .insert_gateway_usage(&usage(t, site, Some(key), "usd-model", 1_000_000, 500_000))
        .expect("写用量");
    store
        .budget_create(site, None, "day", 3.0)
        .expect("站级预算");
    store
        .budget_create(site, Some(key), "day", 5.0)
        .expect("key 级预算");
    let breach = budget_breach_for(&store, site, Some(key))
        .expect("判定")
        .expect("站级超了应有 breach");
    assert_eq!(breach.key_id, None, "仅站级超时返回站级行");
    assert_eq!(breach.spent_usd, 4.0);
    assert_eq!(breach.limit_usd, 3.0);

    // key 级预算改成 4.0（含等于即拦）⇒ 两行都超，返回 key 级行
    store
        .budget_delete(
            store
                .budget_list()
                .expect("列表")
                .into_iter()
                .find(|r| r.key_id == Some(key))
                .expect("key 级行")
                .id,
        )
        .expect("删 key 级行");
    store
        .budget_create(site, Some(key), "day", 4.0)
        .expect("key 级预算等于已花");
    let breach = budget_breach_for(&store, site, Some(key))
        .expect("判定")
        .expect("两行都超应有 breach");
    assert_eq!(breach.key_id, Some(key), "两行都超时 key 级行优先");
    assert_eq!(breach.limit_usd, 4.0);

    // 另一站无预算 ⇒ None；本站无 key 的请求只看站级行
    let other = store
        .upsert_site("newapi", "https://other.example.com", "别站")
        .expect("写别站");
    assert!(budget_breach_for(&store, other, None)
        .expect("判定")
        .is_none());
}

/// M46-S5 复审 P0-1：他 key 的 key 级预算行不得误拦本 key。
/// 旧 bug：`budget_breach_for` 里 (Some, Some-不同) 只把 is_key_row 置 false
/// 就继续往下算，K2 的超标行落入站级回落，K1 的请求也被拦。
#[test]
fn budget_breach_for_ignores_other_keys_key_level_rows() {
    let (_dir, store, site) = store_with_site();
    let k1 = store
        .insert_key(site, "k1", "kr/key/1/secret", None, None)
        .expect("写 key1");
    let k2 = store
        .insert_key(site, "k2", "kr/key/2/secret", None, None)
        .expect("写 key2");
    let base = now() - 40 * 86_400;
    price(&store, "usd-model", 2.0, 4.0, "USD", base);
    let t = now();
    // K2 已花 4.0（1M prompt + 500K completion），K1 无用量。
    store
        .insert_gateway_usage(&usage(t, site, Some(k2), "usd-model", 1_000_000, 500_000))
        .expect("写用量");
    store
        .budget_create(site, Some(k2), "day", 3.0)
        .expect("K2 key 级预算（超）");
    store
        .budget_create(site, None, "day", 100.0)
        .expect("站级预算（未超）");
    // K1 的请求：K2 的行与未超的站级行均不得拦它。
    assert!(
        budget_breach_for(&store, site, Some(k1))
            .expect("判定")
            .is_none(),
        "他 key 的超标行不得误拦本 key"
    );
    // 对照：K2 自己的请求仍应被 K2 的行拦住（防矫枉过正把 key 级行全忽略）。
    let breach = budget_breach_for(&store, site, Some(k2))
        .expect("判定")
        .expect("K2 应被拦");
    assert_eq!(breach.key_id, Some(k2));
    assert_eq!(breach.limit_usd, 3.0);
}

#[test]
fn budget_breach_for_propagates_store_error() {
    // fail-open 契约的前提：判定函数在 store 坏掉时返回 Err（而不是静默 None），
    // 调用方闭包据此 .ok().flatten() 放行。直接对同一文件删用量表来造 Err。
    let (dir, store, site) = store_with_site();
    store
        .budget_create(site, None, "day", 10.0)
        .expect("建预算");
    let path = dir.path().join("t.db");
    let conn = rusqlite::Connection::open(&path).expect("直连");
    conn.execute_batch("DROP TABLE gateway_usage_log;")
        .expect("删表");
    assert!(
        budget_breach_for(&store, site, None).is_err(),
        "用量表没了时判定必须 Err（闭包才能据此 fail-open），不能静默当成未超"
    );
}
