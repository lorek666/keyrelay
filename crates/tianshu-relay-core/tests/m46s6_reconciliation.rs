//! M46-S6：多源账单对账（service 层自由函数 + store 层窗口函数）。
//!
//! 网关侧成本口径与 S5 的 `budget_spent_usd` 同源（共享窗口函数）；账单侧直接写
//! `site_bills` 行。桩形态沿用 `m46s5_budget.rs`（临时库 + 直接插用量行、价格行、
//! 账单行），不连真实站点、不走导入器。

use tianshu_relay_core::gateway::GatewayUsage;
use tianshu_relay_core::service::{reconcile_bills, BillReconciliationKind};
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

fn bill(
    store: &Store,
    site: i64,
    day: &str,
    amount: Option<f64>,
    currency: Option<&str>,
    source: &str,
) {
    store
        .site_bill_upsert(site, day, amount, currency, None, source)
        .expect("写账单");
}

/// 直接 SQL 取本地日期（与被测代码同一 localtime 口径，测试不依赖运行机时区假设）。
fn local_date_of(dir: &tempfile::TempDir, ts: i64) -> String {
    let conn = rusqlite::Connection::open(dir.path().join("t.db")).expect("直连");
    conn.query_row(
        "SELECT date(?1, 'unixepoch', 'localtime')",
        rusqlite::params![ts],
        |row| row.get(0),
    )
    .expect("算本地日")
}

fn local_today(dir: &tempfile::TempDir) -> String {
    let conn = rusqlite::Connection::open(dir.path().join("t.db")).expect("直连");
    conn.query_row("SELECT date('now', 'localtime')", [], |row| row.get(0))
        .expect("查今天")
}

/// 站级 USD 用量行：prompt  token 数 × 2.0（usd-model input 价）= 成本。
fn gateway_cost(store: &Store, site: i64, prompt: i64, at: i64) {
    store
        .insert_gateway_usage(&usage(at, site, None, "usd-model", prompt, 0))
        .expect("写用量");
}

fn setup_usd_price(store: &Store) {
    price(store, "usd-model", 2.0, 4.0, "USD", now() - 40 * 86_400);
}

#[test]
fn window_cost_agrees_with_budget_spent() {
    let (dir, store, site) = store_with_site();
    let key = store
        .insert_key(site, "k1", "kr/key/1/secret", None, None)
        .expect("写 key");
    let base = now() - 40 * 86_400;
    // 用「本地当天起点」而不是 `now()-2h` 造两个价格时段：后者在凌晨 0–2 点
    // 会把旧价行落到前一天，日窗口只剩 10.0 而稳定失败（跨午夜时间依赖）。
    let today = local_today(&dir);
    let (start, end) = store.local_day_bounds(&today).expect("当日窗口");
    let old_at = start + 10;
    let new_price_at = start + 20;
    let new_at = start + 30;
    // 价格版本更替：旧价 2.0（40 天前生效）、新价 10.0（当天第二秒生效）。
    price(&store, "usd-model", 2.0, 4.0, "USD", base);
    price(&store, "usd-model", 10.0, 4.0, "USD", new_price_at);
    // 旧价时段行：1M prompt × 2.0 = 2.0；新价时段行：1M prompt × 10.0 = 10.0。
    store
        .insert_gateway_usage(&usage(old_at, site, Some(key), "usd-model", 1_000_000, 0))
        .expect("写旧价用量");
    store
        .insert_gateway_usage(&usage(new_at, site, Some(key), "usd-model", 1_000_000, 0))
        .expect("写新价用量");
    assert_eq!(
        store
            .gateway_cost_usd_in_window(site, None, start, end)
            .expect("窗口成本"),
        store.budget_spent_usd(site, None, "day").expect("站级已花"),
        "站级窗口函数必须等于 budget_spent_usd（委托无回归）"
    );
    assert_eq!(
        store
            .gateway_cost_usd_in_window(site, Some(key), start, end)
            .expect("key 窗口成本"),
        store
            .budget_spent_usd(site, Some(key), "day")
            .expect("key 级已花"),
        "key 级窗口函数必须等于 budget_spent_usd（委托无回归）"
    );
    assert_eq!(
        store.budget_spent_usd(site, None, "day").expect("站级已花"),
        12.0,
        "旧价行 2.0 + 新价行 10.0 = 12.0（行级最新价版本）"
    );
}

#[test]
fn reconciliation_matched_within_threshold_not_flagged() {
    let (dir, store, site) = store_with_site();
    setup_usd_price(&store);
    gateway_cost(&store, site, 5_000_000, now()); // 5M × 2.0 = 10.0
    let today = local_today(&dir);
    bill(
        &store,
        site,
        &today,
        Some(10.4),
        Some("USD"),
        "newapi-log-self",
    );
    let rows = reconcile_bills(&store, Some(site), 30).expect("对账");
    assert_eq!(rows.len(), 1, "应恰好一行");
    let row = &rows[0];
    assert_eq!(row.kind, BillReconciliationKind::Matched);
    assert_eq!(row.gateway_usd, 10.0);
    assert_eq!(row.bill_usd, Some(10.4));
    assert_eq!(row.diff_usd, Some(-0.4));
    assert!(!row.flagged, "差额 0.4 < 阈值 max(0.52, 1) = 1，不标");
    assert_eq!(row.source.as_deref(), Some("newapi-log-self"));
}

#[test]
fn reconciliation_matched_over_threshold_flagged() {
    let (dir, store, site_a) = store_with_site();
    let site_b = store
        .upsert_site("newapi", "https://other.example.com", "别站")
        .expect("写别站");
    setup_usd_price(&store);
    let t = now();
    let today = local_today(&dir);
    // A：网关 100、账单 90 ⇒ diff 10 > max(5, 1) = 5 ⇒ 标。
    gateway_cost(&store, site_a, 50_000_000, t);
    bill(
        &store,
        site_a,
        &today,
        Some(90.0),
        Some("USD"),
        "newapi-log-self",
    );
    // B：网关 100、账单 96 ⇒ diff 4 < 5 ⇒ 不标（相对分支生效、$1 下限不越俎）。
    gateway_cost(&store, site_b, 50_000_000, t);
    bill(
        &store,
        site_b,
        &today,
        Some(96.0),
        Some("USD"),
        "newapi-log-self",
    );
    let rows_a = reconcile_bills(&store, Some(site_a), 30).expect("对账 A");
    assert_eq!(rows_a.len(), 1);
    assert_eq!(rows_a[0].kind, BillReconciliationKind::Matched);
    assert_eq!(rows_a[0].diff_usd, Some(10.0));
    assert!(rows_a[0].flagged, "差额 10 > 阈值 5，应标");
    let rows_b = reconcile_bills(&store, Some(site_b), 30).expect("对账 B");
    assert_eq!(rows_b.len(), 1);
    assert_eq!(rows_b[0].diff_usd, Some(4.0));
    assert!(!rows_b[0].flagged, "差额 4 < 阈值 5，不标");
}

#[test]
fn reconciliation_threshold_boundary_equal_not_flagged() {
    let (dir, store, site_a) = store_with_site();
    let site_b = store
        .upsert_site("newapi", "https://other.example.com", "别站")
        .expect("写别站");
    setup_usd_price(&store);
    let t = now();
    let today = local_today(&dir);
    // $1 分支边界：网关 20、账单 19 ⇒ diff 1，阈值 max(1, 1) = 1，等于不标。
    gateway_cost(&store, site_a, 10_000_000, t);
    bill(
        &store,
        site_a,
        &today,
        Some(19.0),
        Some("USD"),
        "newapi-log-self",
    );
    // 5% 分支边界：网关 40、账单 38 ⇒ diff 2，阈值 max(2, 1) = 2，等于不标。
    gateway_cost(&store, site_b, 20_000_000, t);
    bill(
        &store,
        site_b,
        &today,
        Some(38.0),
        Some("USD"),
        "newapi-log-self",
    );
    let rows_a = reconcile_bills(&store, Some(site_a), 30).expect("对账 A");
    assert_eq!(rows_a[0].diff_usd, Some(1.0));
    assert!(!rows_a[0].flagged, "差额恰等于阈值 1，严格大于才标");
    let rows_b = reconcile_bills(&store, Some(site_b), 30).expect("对账 B");
    assert_eq!(rows_b[0].diff_usd, Some(2.0));
    assert!(!rows_b[0].flagged, "差额恰等于阈值 2，严格大于才标");
}

#[test]
fn reconciliation_zero_sides() {
    let (dir, store, site_a) = store_with_site();
    let site_b = store
        .upsert_site("newapi", "https://other.example.com", "别站")
        .expect("写别站");
    setup_usd_price(&store);
    let t = now();
    let today = local_today(&dir);
    // A：账单 0 + 网关成本 0（无价模型用量行）⇒ bill-only、diff 0、不标。
    store
        .insert_gateway_usage(&usage(t, site_a, None, "free-model", 1_000_000, 0))
        .expect("写无价用量");
    bill(
        &store,
        site_a,
        &today,
        Some(0.0),
        Some("USD"),
        "newapi-log-self",
    );
    // B：账单 0、网关 5 ⇒ matched、diff 5、标（任务书示例）。
    gateway_cost(&store, site_b, 2_500_000, t);
    bill(
        &store,
        site_b,
        &today,
        Some(0.0),
        Some("USD"),
        "newapi-log-self",
    );
    let rows_a = reconcile_bills(&store, Some(site_a), 30).expect("对账 A");
    assert_eq!(rows_a.len(), 1);
    assert_eq!(rows_a[0].kind, BillReconciliationKind::BillOnly);
    assert_eq!(rows_a[0].gateway_usd, 0.0);
    assert_eq!(rows_a[0].diff_usd, Some(0.0));
    assert!(!rows_a[0].flagged, "两边都为 0，diff 0 < 阈值 1，不标");
    let rows_b = reconcile_bills(&store, Some(site_b), 30).expect("对账 B");
    assert_eq!(rows_b[0].kind, BillReconciliationKind::Matched);
    assert_eq!(rows_b[0].diff_usd, Some(5.0));
    assert!(
        rows_b[0].flagged,
        "账单 0、网关 5，diff 5 > max(0.25, 1) = 1，应标"
    );
}

#[test]
fn reconciliation_gateway_only_and_bill_only() {
    let (dir, store, site_a) = store_with_site();
    let site_b = store
        .upsert_site("newapi", "https://other.example.com", "别站")
        .expect("写别站");
    let site_c = store
        .upsert_site("newapi", "https://third.example.com", "空站")
        .expect("写空站");
    setup_usd_price(&store);
    let t = now();
    let today = local_today(&dir);
    // A：网关 10、无账单 ⇒ gateway-only。
    gateway_cost(&store, site_a, 5_000_000, t);
    // B：账单 5、无网关 ⇒ bill-only。
    bill(
        &store,
        site_b,
        &today,
        Some(5.0),
        Some("USD"),
        "newapi-log-self",
    );
    let rows = reconcile_bills(&store, None, 30).expect("对账全部");
    assert_eq!(rows.len(), 2, "空站不出行，两边都空无行");
    let row_a = rows.iter().find(|r| r.site_id == site_a).expect("A 行");
    assert_eq!(row_a.kind, BillReconciliationKind::GatewayOnly);
    assert_eq!(row_a.gateway_usd, 10.0);
    assert_eq!(row_a.bill_usd, Some(0.0), "缺失侧按 0 计");
    assert_eq!(row_a.diff_usd, Some(10.0));
    assert!(row_a.flagged);
    assert_eq!(row_a.source, None, "gateway-only 行无来源");
    let row_b = rows.iter().find(|r| r.site_id == site_b).expect("B 行");
    assert_eq!(row_b.kind, BillReconciliationKind::BillOnly);
    assert_eq!(row_b.gateway_usd, 0.0);
    assert_eq!(row_b.diff_usd, Some(-5.0));
    assert!(row_b.flagged);
    assert!(rows.iter().all(|r| r.site_id != site_c), "空站无行");
}

#[test]
fn reconciliation_non_usd_and_missing_amount_are_incomparable() {
    let (dir, store, site_a) = store_with_site();
    let site_b = store
        .upsert_site("newapi", "https://other.example.com", "别站")
        .expect("写别站");
    let site_c = store
        .upsert_site("newapi", "https://third.example.com", "三站")
        .expect("写三站");
    let site_d = store
        .upsert_site("newapi", "https://fourth.example.com", "四站")
        .expect("写四站");
    let site_e = store
        .upsert_site("newapi", "https://fifth.example.com", "五站")
        .expect("写五站");
    setup_usd_price(&store);
    price(&store, "cny-model", 2.0, 4.0, "CNY", now() - 40 * 86_400);
    let t = now();
    let today = local_today(&dir);
    // A：CNY 账单 + 网关 10 ⇒ matched 但不可比。
    gateway_cost(&store, site_a, 5_000_000, t);
    bill(
        &store,
        site_a,
        &today,
        Some(10.0),
        Some("CNY"),
        "newapi-log-self",
    );
    // B：currency 为空账单 + 网关 10 ⇒ 不可比（未知币种不能默认 USD）。
    gateway_cost(&store, site_b, 5_000_000, t);
    bill(&store, site_b, &today, Some(10.0), None, "newapi-log-self");
    // C：amount 为空账单 + 网关 10 ⇒ 不可比。
    gateway_cost(&store, site_c, 5_000_000, t);
    bill(&store, site_c, &today, None, Some("USD"), "newapi-log-self");
    // D：USD 账单对照组 ⇒ 可比、diff 0、不标。
    gateway_cost(&store, site_d, 5_000_000, t);
    bill(
        &store,
        site_d,
        &today,
        Some(10.0),
        Some("usd"),
        "newapi-log-self",
    );
    // E：CNY 账单、无网关 ⇒ bill-only 但不可比。
    bill(
        &store,
        site_e,
        &today,
        Some(5.0),
        Some("CNY"),
        "newapi-log-self",
    );
    for (site, kind) in [
        (site_a, BillReconciliationKind::Matched),
        (site_b, BillReconciliationKind::Matched),
        (site_c, BillReconciliationKind::Matched),
        (site_e, BillReconciliationKind::BillOnly),
    ] {
        let rows = reconcile_bills(&store, Some(site), 30).expect("对账");
        assert_eq!(rows.len(), 1, "站 {site} 应恰好一行");
        assert_eq!(rows[0].kind, kind, "站 {site} kind 按存在分区");
        assert_eq!(rows[0].bill_usd, None, "站 {site} 不可比行 bill 为空");
        assert_eq!(rows[0].diff_usd, None, "站 {site} 不可比行 diff 为空");
        assert!(rows[0].flagged, "站 {site} 不可比行恒标");
    }
    let rows_d = reconcile_bills(&store, Some(site_d), 30).expect("对账 D");
    assert_eq!(
        rows_d[0].bill_usd,
        Some(10.0),
        "小写 usd 应大小写不敏感可比"
    );
    assert_eq!(rows_d[0].diff_usd, Some(0.0));
    assert!(!rows_d[0].flagged);
}

#[test]
fn reconciliation_groups_by_local_day_boundary() {
    let (dir, store, site) = store_with_site();
    setup_usd_price(&store);
    let today = local_today(&dir);
    let (start, end) = store.local_day_bounds(&today).expect("当日窗口");
    // 窗口本身是本地日界（与 S5 的窗口断言同式）。
    assert_eq!(
        local_date_of(&dir, start),
        today,
        "窗口起点必须是本地今天零点"
    );
    assert!(start <= now() && now() < end, "当前时刻必须落在当日窗口内");
    assert!(
        (82_800..=90_000).contains(&(end - start)),
        "当日窗口长应为一天（DST 日 23/25 小时）: {}",
        end - start
    );
    // 零点前 1 秒 ⇒ 前一日；零点本身 ⇒ 当日。
    gateway_cost(&store, site, 1_000_000, start - 1); // 前一日 2.0
    gateway_cost(&store, site, 1_000_000, start); // 当日 2.0
    let yesterday = local_date_of(&dir, start - 1);
    bill(
        &store,
        site,
        &yesterday,
        Some(2.0),
        Some("USD"),
        "newapi-log-self",
    );
    let rows = reconcile_bills(&store, Some(site), 2).expect("对账");
    assert_eq!(rows.len(), 2, "前一日 matched + 当日 gateway-only");
    let row_yesterday = rows.iter().find(|r| r.day == yesterday).expect("前一日行");
    assert_eq!(row_yesterday.kind, BillReconciliationKind::Matched);
    assert_eq!(row_yesterday.gateway_usd, 2.0);
    assert_eq!(row_yesterday.diff_usd, Some(0.0));
    assert!(!row_yesterday.flagged);
    let row_today = rows.iter().find(|r| r.day == today).expect("当日行");
    assert_eq!(row_today.kind, BillReconciliationKind::GatewayOnly);
    assert_eq!(row_today.gateway_usd, 2.0);
    assert_eq!(row_today.diff_usd, Some(2.0));
    assert!(row_today.flagged, "网关 2、无账单，diff 2 > 阈值 1，应标");
}

#[test]
fn reconciliation_multiple_sources_share_gateway_cost() {
    let (dir, store, site) = store_with_site();
    setup_usd_price(&store);
    let today = local_today(&dir);
    gateway_cost(&store, site, 5_000_000, now()); // 10.0
    bill(
        &store,
        site,
        &today,
        Some(10.0),
        Some("USD"),
        "newapi-log-self",
    );
    bill(&store, site, &today, Some(8.0), Some("USD"), "manual-x");
    let rows = reconcile_bills(&store, Some(site), 30).expect("对账");
    assert_eq!(rows.len(), 2, "两来源各出一行，不出 gateway-only 行");
    assert!(
        rows.iter()
            .all(|r| r.kind == BillReconciliationKind::Matched),
        "两行都应为 matched"
    );
    assert!(
        rows.iter().all(|r| r.gateway_usd == 10.0),
        "两行共用同一网关成本"
    );
    let row_newapi = rows
        .iter()
        .find(|r| r.source.as_deref() == Some("newapi-log-self"))
        .expect("来源行");
    assert_eq!(row_newapi.diff_usd, Some(0.0));
    assert!(!row_newapi.flagged);
    let row_manual = rows
        .iter()
        .find(|r| r.source.as_deref() == Some("manual-x"))
        .expect("手工来源行");
    assert_eq!(row_manual.diff_usd, Some(2.0));
    assert!(row_manual.flagged, "diff 2 > 阈值 1，应标");
}

#[test]
fn reconciliation_site_filter_and_days_window() {
    let (dir, store, site_a) = store_with_site();
    let site_b = store
        .upsert_site("newapi", "https://other.example.com", "别站")
        .expect("写别站");
    setup_usd_price(&store);
    let t = now();
    let today = local_today(&dir);
    let (start, _) = store.local_day_bounds(&today).expect("当日窗口");
    let yesterday = local_date_of(&dir, start - 3600);
    for site in [site_a, site_b] {
        gateway_cost(&store, site, 5_000_000, t);
        bill(
            &store,
            site,
            &today,
            Some(10.0),
            Some("USD"),
            "newapi-log-self",
        );
    }
    // A 站昨日也有账单与网关（昨日 23:00 前后各一笔，归属昨日无歧义）。
    gateway_cost(&store, site_a, 5_000_000, start - 3600);
    bill(
        &store,
        site_a,
        &yesterday,
        Some(10.0),
        Some("USD"),
        "newapi-log-self",
    );
    let rows_a = reconcile_bills(&store, Some(site_a), 30).expect("对账 A");
    assert_eq!(rows_a.len(), 2, "A 站今日 + 昨日各一行");
    assert!(
        rows_a.iter().all(|r| r.site_id == site_a),
        "site 过滤只回该站"
    );
    let rows_all = reconcile_bills(&store, None, 30).expect("对账全部");
    assert_eq!(rows_all.len(), 3, "A 站 2 行 + B 站 1 行");
    let rows_1day = reconcile_bills(&store, Some(site_a), 1).expect("对账近 1 天");
    assert_eq!(rows_1day.len(), 1, "days=1 时昨日行不出");
    assert_eq!(rows_1day[0].day, today);
    let rows_2day = reconcile_bills(&store, Some(site_a), 2).expect("对账近 2 天");
    assert_eq!(rows_2day.len(), 2, "days=2 时昨日行应出现");
    assert!(
        rows_2day.iter().any(|r| r.day == yesterday),
        "昨日行应在 2 天窗口内"
    );
}

#[test]
fn reconciliation_output_order() {
    let (dir, store, site_a) = store_with_site();
    let site_b = store
        .upsert_site("newapi", "https://other.example.com", "别站")
        .expect("写别站");
    setup_usd_price(&store);
    let t = now();
    let today = local_today(&dir);
    let (start, _) = store.local_day_bounds(&today).expect("当日窗口");
    let yesterday = local_date_of(&dir, start - 3600);
    for site in [site_a, site_b] {
        gateway_cost(&store, site, 5_000_000, t); // 当日用量
        gateway_cost(&store, site, 5_000_000, start - 3600); // 昨日用量
        bill(
            &store,
            site,
            &today,
            Some(10.0),
            Some("USD"),
            "newapi-log-self",
        );
        bill(
            &store,
            site,
            &yesterday,
            Some(10.0),
            Some("USD"),
            "newapi-log-self",
        );
    }
    let rows = reconcile_bills(&store, None, 2).expect("对账");
    assert_eq!(rows.len(), 4, "两站 × 两天各一行");
    let order: Vec<(String, i64)> = rows.iter().map(|r| (r.day.clone(), r.site_id)).collect();
    assert_eq!(
        order,
        vec![
            (today.clone(), site_a),
            (today.clone(), site_b),
            (yesterday.clone(), site_a),
            (yesterday.clone(), site_b),
        ],
        "day 倒序、site_id 升序"
    );
}

#[test]
fn reconciliation_illegal_bill_day_errors() {
    let (_dir, store, site) = store_with_site();
    bill(
        &store,
        site,
        "not-a-date",
        Some(10.0),
        Some("USD"),
        "newapi-log-self",
    );
    assert!(
        reconcile_bills(&store, Some(site), 30).is_err(),
        "非法 day 应整条报错，不静默跳行"
    );
}

#[test]
fn reconciliation_unpriced_usage_gets_explicit_row_not_silently_skipped() {
    // DEBUG-G5 P1-9：有用量、无账单、无 USD 价 ⇒ 出 gateway_unpriced 显性行，
    // 而不是旧实现的静默 continue；当天无用量的空站仍不出行，两者可区分。
    let (dir, store, site_a) = store_with_site();
    let site_empty = store
        .upsert_site("newapi", "https://empty.example.com", "空站")
        .expect("写空站");
    // 只有 CNY 价：USD 口径 JOIN 不命中，网关成本恒为 0，但用量行真实存在。
    price(&store, "cny-model", 2.0, 4.0, "CNY", now() - 40 * 86_400);
    store
        .insert_gateway_usage(&usage(now(), site_a, None, "cny-model", 1_000_000, 0))
        .expect("写 CNY 用量");
    let rows = reconcile_bills(&store, None, 30).expect("对账全部");
    assert_eq!(rows.len(), 1, "只应有 unpriced 这一行，空站不出行");
    let row = &rows[0];
    assert_eq!(row.site_id, site_a);
    assert_eq!(row.kind, BillReconciliationKind::GatewayUnpriced);
    assert_eq!(row.gateway_usd, 0.0, "0 在此表示不可定价，不是花了 0");
    assert_eq!(row.bill_usd, Some(0.0), "无账单，缺失侧按 0 计");
    assert_eq!(row.diff_usd, None, "网关侧未知，无法比较");
    assert!(row.flagged, "不可比行恒 flagged，需人工看");
    assert_eq!(row.source, None, "无账单行无来源");
    assert!(
        rows.iter().all(|r| r.site_id != site_empty),
        "当天无用量的空站必须不出行，否则与 unpriced 无法区分"
    );
    let _ = dir;
}

#[test]
fn site_bills_excludes_future_days() {
    // DEBUG-G7 补齐 P3-K3：site_bills 窗口有上界——未来日账单行不得出现
    // （此前只有下界，未来行会以 bill_only 混进对账）。
    let (dir, store, site) = store_with_site();
    let today = local_today(&dir);
    bill(
        &store,
        site,
        &today,
        Some(10.0),
        Some("USD"),
        "newapi-log-self",
    );
    bill(
        &store,
        site,
        "2999-01-01",
        Some(10.0),
        Some("USD"),
        "newapi-log-self",
    );
    let rows = store.site_bills(90).expect("读账单");
    assert!(rows.iter().any(|r| r.day == today), "当日行应在窗口内");
    assert!(
        rows.iter().all(|r| r.day != "2999-01-01"),
        "未来日行不得进入窗口，实测 {:?}",
        rows.iter().map(|r| r.day.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn reconciliation_rows_carry_import_partial_flag() {
    // DEBUG-G7 补齐 P3-K3：对账行带站级导入覆盖信号——最近一次导入
    // partial 的站，其账单行与网关行都挂 import_partial=true；无记录的站
    // 为 false（不是“覆盖完整”，只是“没导入过/取完了”，见字段语义）。
    let (dir, store, site_partial) = store_with_site();
    let site_clean = store
        .upsert_site("newapi", "https://clean.example.com", "干净站")
        .expect("写干净站");
    setup_usd_price(&store);
    let t = now();
    let today = local_today(&dir);
    // partial 站：当日账单（bill-only 侧）+ 当日网关用量（另一天无账单侧
    // 为 gateway-only——为避免两天混淆，用量写当日、账单写昨日）。
    let (start, _) = store.local_day_bounds(&today).expect("当日窗口");
    let yesterday = local_date_of(&dir, start - 3600);
    bill(
        &store,
        site_partial,
        &yesterday,
        Some(5.0),
        Some("USD"),
        "newapi-log-self",
    );
    gateway_cost(&store, site_partial, 5_000_000, t);
    bill(
        &store,
        site_clean,
        &today,
        Some(5.0),
        Some("USD"),
        "newapi-log-self",
    );
    store
        .record_site_bill_import(site_partial, true, 10, 3)
        .expect("记覆盖");
    store
        .record_site_bill_import(site_clean, false, 10, 3)
        .expect("记覆盖");
    let rows = reconcile_bills(&store, None, 30).expect("对账全部");
    let partial_rows: Vec<_> = rows.iter().filter(|r| r.site_id == site_partial).collect();
    assert!(!partial_rows.is_empty(), "partial 站应有行");
    assert!(
        partial_rows.iter().all(|r| r.import_partial),
        "partial 站的全部行都应挂旗，实测 {:?}",
        partial_rows
            .iter()
            .map(|r| (r.day.clone(), r.kind))
            .collect::<Vec<_>>()
    );
    let clean_rows: Vec<_> = rows.iter().filter(|r| r.site_id == site_clean).collect();
    assert!(!clean_rows.is_empty(), "干净站应有行");
    assert!(
        clean_rows.iter().all(|r| !r.import_partial),
        "取完的站不得挂旗"
    );
    // 最新一次为准：partial 站再记一次取完，旗应翻回 false。
    store
        .record_site_bill_import(site_partial, false, 10, 30)
        .expect("记覆盖");
    let rows = reconcile_bills(&store, None, 30).expect("对账全部");
    assert!(
        rows.iter()
            .filter(|r| r.site_id == site_partial)
            .all(|r| !r.import_partial),
        "最新一次取完后，旧 partial 旗不得残留"
    );
}
