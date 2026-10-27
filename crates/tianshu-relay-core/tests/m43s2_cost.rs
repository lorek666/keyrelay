//! M43-S2：成本估算与站点账单（schema v10 + 单价表 + 账单表 + 成本聚合）。
//!
//! 红线（spec §4.6 / §6）：无价格 / 旧行 / 币种不符 ⇒ **未知（None）**，绝不显示 0；
//! USD / CNY 分开；`usage_samples.cost` 的「没上报」与「真的 0」必须可区分。

use tianshu_relay_core::gateway::GatewayUsage;
use tianshu_relay_core::store::Store;

fn usage(at: i64, model: &str, prompt: i64, completion: i64, label: &str) -> GatewayUsage {
    GatewayUsage {
        at,
        site_id: 1,
        key_id: None,
        model: model.to_string(),
        prompt_tokens: prompt,
        completion_tokens: completion,
        total_tokens: prompt + completion,
        status: 200,
        latency_ms: 10,
        attempts: 1,
        stream: false,
        token_id: None,
        agent_label: label.to_string(),
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("时钟")
        .as_secs() as i64
}

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().expect("临时目录");
    let store = Store::open(&dir.path().join("t.db")).expect("建库");
    store
        .upsert_site("newapi", "https://relay.example.com", "站")
        .expect("写站点");
    (dir, store)
}

#[test]
fn schema_v9_to_v10_adds_cost_tables_and_flag() {
    let dir = tempfile::tempdir().expect("临时目录");
    let path = dir.path().join("old.db");
    {
        let store = Store::open(&path).expect("建库");
        assert_eq!(store.schema_version().unwrap(), 12);
    }
    // 把库降级成「v9 的形态」：删掉两张新表、去掉 cost_reported、版本号回退。
    {
        let conn = rusqlite::Connection::open(&path).expect("打开");
        conn.execute_batch(
            "DROP TABLE model_prices; DROP TABLE site_bills; \
             ALTER TABLE usage_samples DROP COLUMN cost_reported; \
             PRAGMA user_version = 9;",
        )
        .expect("降级");
    }
    // 重新打开 ⇒ 迁移补齐
    let store = Store::open(&path).expect("重开");
    assert_eq!(store.schema_version().unwrap(), 12);
    assert!(store.model_price_list().is_ok(), "model_prices 必须存在");
    assert!(store.site_bills(30).is_ok(), "site_bills 必须存在");
    // cost_reported 列存在且老行取 0
    let rows = store.key_usage_totals(30, None).expect("查询");
    assert!(rows.is_empty(), "没有采样行");
}

#[test]
fn price_upsert_is_idempotent_per_version_and_validated() {
    let (_dir, store) = store();
    let base = now() - 40 * 86_400;
    let id = store
        .model_price_upsert("gpt-4o", 2.5, 10.0, "USD", base)
        .expect("写入");
    // 同一版本再写 ⇒ 覆盖价格而不是新增一行
    let id2 = store
        .model_price_upsert("gpt-4o", 3.0, 12.0, "USD", base)
        .expect("覆盖");
    assert_eq!(id, id2);
    let rows = store.model_price_list().expect("列出");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].input_per_mtok, 3.0);
    assert_eq!(rows[0].currency, "USD");

    // 新版本（不同 effective_from）⇒ 多一行
    let id3 = store
        .model_price_upsert("gpt-4o", 4.0, 16.0, "USD", now() - 20 * 86_400)
        .expect("新版本");
    assert_eq!(store.model_price_list().unwrap().len(), 2);

    // 校验：空模型 / 0 价 / NaN / 非白名单币种
    assert!(store.model_price_upsert("  ", 1.0, 1.0, "USD", 1).is_err());
    assert!(store.model_price_upsert("m", 0.0, 1.0, "USD", 1).is_err());
    assert!(store
        .model_price_upsert("m", f64::NAN, 1.0, "USD", 1)
        .is_err());
    assert!(store.model_price_upsert("m", 1.0, 1.0, "EUR", 1).is_err());

    // 删除：两个版本各删一次才清空
    assert!(store.model_price_delete(id).unwrap());
    assert_eq!(store.model_price_list().unwrap().len(), 1);
    assert!(store.model_price_delete(id3).unwrap());
    assert!(store.model_price_list().unwrap().is_empty());
}

#[test]
fn usage_daily_prices_by_effective_time_and_splits_currencies() {
    let (_dir, store) = store();
    // 1 月：USD 1 元/1M；2 月：USD 2 元/1M；CNY 版本（同日不同币种示例）
    let old_price_at = now() - 40 * 86_400;
    let new_price_at = now() - 86_400;
    store
        .model_price_upsert("gpt-4o", 1.0, 1.0, "USD", old_price_at)
        .expect("旧价");
    store
        .model_price_upsert("gpt-4o", 2.0, 2.0, "USD", new_price_at)
        .expect("新价");
    // 旧价时期的一条：1M prompt + 1M completion ⇒ 1 + 1 = 2 USD
    store
        .insert_gateway_usage(&usage(
            old_price_at + 3600,
            "gpt-4o",
            1_000_000,
            1_000_000,
            "codex",
        ))
        .expect("写用量");
    // 新价时期的一条：1M prompt ⇒ 2 USD
    store
        .insert_gateway_usage(&usage(new_price_at + 3600, "gpt-4o", 1_000_000, 0, "codex"))
        .expect("写用量");

    let rows = store.usage_daily(90, None).expect("聚合");
    let usd: Vec<_> = rows
        .iter()
        .filter(|r| r.currency.as_deref() == Some("USD"))
        .collect();
    assert_eq!(usd.len(), 2, "两个不同日期各一行：{rows:?}");
    let total: f64 = usd.iter().map(|r| r.estimated_cost.unwrap_or(0.0)).sum();
    assert!((total - 4.0).abs() < 1e-9, "1 月 2 + 2 月 2 = 4: {total}");
    assert!(rows.iter().all(|r| r.unpriced_requests == 0));
}

#[test]
fn future_price_does_not_price_earlier_usage() {
    let (_dir, store) = store();
    // 价格从**明天**起生效 ⇒ 今天的用量不可定价（不是 0）
    store
        .model_price_upsert("gpt-4o", 1.0, 1.0, "USD", now() + 86_400)
        .expect("价格");
    store
        .insert_gateway_usage(&usage(now() - 60, "gpt-4o", 1_000_000, 0, ""))
        .expect("用量");
    let rows = store.usage_daily(90, None).expect("聚合");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].estimated_cost, None, "价格尚未生效 ⇒ 未知");
    assert_eq!(rows[0].unpriced_requests, 1);
    assert_eq!(rows[0].unpriced_tokens, 1_000_000);
}

#[test]
fn unpriced_rows_are_counted_but_not_priced() {
    let (_dir, store) = store();
    // 只给 gpt-4o 配价；另一条用没有价格的模型
    store
        .model_price_upsert("gpt-4o", 1.0, 1.0, "USD", now() - 90 * 86_400)
        .expect("价格");
    store
        .insert_gateway_usage(&usage(now() - 3600, "gpt-4o", 0, 0, ""))
        .expect("有价");
    store
        .insert_gateway_usage(&usage(now() - 3500, "o3", 500, 500, ""))
        .expect("无价");
    let rows = store.usage_daily(90, None).expect("聚合");
    let priced = rows.iter().find(|r| r.model == "gpt-4o").expect("有价行");
    assert_eq!(priced.currency.as_deref(), Some("USD"));
    let unpriced = rows.iter().find(|r| r.model == "o3").expect("无价行");
    assert_eq!(unpriced.currency, None);
    assert_eq!(unpriced.estimated_cost, None, "无价 ⇒ 未知，不是 0");
    assert_eq!(unpriced.unpriced_requests, 1);
}

#[test]
fn usage_by_agent_groups_by_label_and_currency() {
    let (_dir, store) = store();
    store
        .model_price_upsert("gpt-4o", 1.0, 1.0, "USD", now() - 90 * 86_400)
        .expect("价格");
    store
        .insert_gateway_usage(&usage(now() - 7200, "gpt-4o", 1_000_000, 0, "codex"))
        .expect("A");
    store
        .insert_gateway_usage(&usage(now() - 7100, "gpt-4o", 2_000_000, 0, "codex"))
        .expect("B");
    store
        .insert_gateway_usage(&usage(now() - 7000, "gpt-4o", 1_000_000, 0, ""))
        .expect("未归因");
    let rows = store.usage_by_agent(90).expect("聚合");
    let codex = rows
        .iter()
        .find(|r| r.agent_label == "codex")
        .expect("codex");
    assert_eq!(codex.requests, 2);
    assert_eq!(codex.currency.as_deref(), Some("USD"));
    assert!((codex.estimated_cost.unwrap_or(0.0) - 3.0).abs() < 1e-9);
    let unattributed = rows
        .iter()
        .find(|r| r.agent_label.is_empty())
        .expect("空标签");
    assert_eq!(unattributed.requests, 1);
}

#[test]
fn site_bills_overwrite_the_same_day() {
    let (_dir, store) = store();
    store
        .site_bill_upsert(
            1,
            "2026-10-01",
            Some(3.5),
            Some("USD"),
            Some(10),
            "newapi-log-self",
        )
        .expect("写");
    store
        .site_bill_upsert(
            1,
            "2026-10-01",
            Some(4.5),
            Some("USD"),
            Some(12),
            "newapi-log-self",
        )
        .expect("覆盖");
    let rows = store.site_bills(30).expect("列");
    assert_eq!(rows.len(), 1, "同一天只留最新一份");
    assert_eq!(rows[0].amount, Some(4.5));
    assert_eq!(rows[0].requests, Some(12));
    // 站点没给金额 ⇒ NULL（不是 0）
    store
        .site_bill_upsert(1, "2026-10-02", None, None, None, "newapi-log-self")
        .expect("写空");
    let rows = store.site_bills(30).expect("列");
    let missing = rows.iter().find(|r| r.day == "2026-10-02").expect("缺失日");
    assert_eq!(missing.amount, None);
    assert_eq!(missing.currency, None);
}

#[test]
fn key_usage_totals_distinguishes_unreported_cost() {
    let (_dir, store) = store();
    let key = store
        .insert_key(1, "key-a", "kr/key/1/secret", None, None)
        .expect("建 key");
    // 没上报 cost ⇒ 未知
    store
        .upsert_usage_sample(
            key,
            1,
            &tianshu_relay_core::site::KeyDailyUsage {
                date: "2026-10-01".into(),
                requests: 1,
                input_tokens: 10,
                output_tokens: 5,
                total_tokens: 15,
                cost: 0.0,
                cost_reported: false,
            },
        )
        .expect("采样");
    let rows = store.key_usage_totals(30, None).expect("汇总");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].cost, None, "没上报 ⇒ 未知（不是 0）");
    // 上报了 0 ⇒ 真的 0
    store
        .upsert_usage_sample(
            key,
            1,
            &tianshu_relay_core::site::KeyDailyUsage {
                date: "2026-10-02".into(),
                requests: 1,
                input_tokens: 1,
                output_tokens: 1,
                total_tokens: 2,
                cost: 0.0,
                cost_reported: true,
            },
        )
        .expect("采样");
    let rows = store.key_usage_totals(30, None).expect("汇总");
    assert_eq!(rows[0].cost, Some(0.0), "上报的 0 是 0");
}
