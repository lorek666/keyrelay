//! M8-S1 装配层测试：**数据源 → 路由表 → 网关配置**。
//!
//! 这一层是 M7 缺的那一层。M7-S1 把 `RouteTable` / `Breaker` / `should_failover` 都写好、
//! 也测了，但**生产构造点**（`service.rs::gateway_config`）一直走 `single_upstream`
//! ⇒ `route` 恒为空表 ⇒ 排序、故障切换、失败事件**在生产上全部不可达**
//! （M7-S7 审计的 D-2 / D-3 / D-4）。
//!
//! 所以这里的断言不是「纯函数算得对」（那在 `gateway_route.rs` 里已经钉过），
//! 而是**「事实到路由表的那一步真的接上了」**。

use keyrelay_core::routing::{alias_map, build_route_table, SiteFacts};

fn facts(site_id: i64, balance: Option<f64>, rate: Option<f64>, latency: Option<u64>) -> SiteFacts {
    SiteFacts {
        site_id,
        base_url: format!("https://site-{site_id}.example.com"),
        models: vec!["gpt-5.6".to_string()],
        rate,
        balance_usd: balance,
        latency_ms: latency,
        key_ref: format!("kr/key/{site_id}/secret"),
    }
}

#[test]
fn build_route_table_maps_every_field() {
    // W1：七个字段一个不漏。漏一个的后果不是编译错，而是**静默地按默认值排序**。
    let f = SiteFacts {
        site_id: 42,
        base_url: "https://relay.example.com".to_string(),
        models: vec!["a".to_string(), "b".to_string()],
        rate: Some(0.5),
        balance_usd: Some(12.5),
        latency_ms: Some(180),
        key_ref: "kr/key/42/secret".to_string(),
    };
    let table = build_route_table(&[f.clone()]);
    let up = table.preferred().expect("非空表应有首选");

    assert_eq!(up.site_id, f.site_id);
    assert_eq!(up.base_url, f.base_url);
    assert_eq!(up.models, f.models);
    assert_eq!(up.rate, f.rate);
    assert_eq!(up.balance_usd, f.balance_usd);
    assert_eq!(up.latency_ms, f.latency_ms);
    assert_eq!(up.key_ref, f.key_ref);
}

#[test]
fn unknown_balance_sorts_between_healthy_and_exhausted_not_last() {
    // W2：**本包最重要的一条**。「不知道」既不等于「有钱」也不等于「没钱」——
    // 它排在两者之间。修复前（`unwrap_or(0.0)`）它会掉进「已耗尽」档，排到最后。
    let table = build_route_table(&[
        facts(1, Some(0.0), None, None),      // 已耗尽
        facts(2, None, None, None),           // 不知道
        facts(3, Some(10.0), None, None),     // 有余额
        facts(4, Some(f64::NAN), None, None), // 算不出来 ⇒ 也算「不知道」
    ]);

    let order: Vec<i64> = table
        .candidates("gpt-5.6")
        .iter()
        .map(|u| u.site_id)
        .collect();

    assert_eq!(
        order,
        vec![3, 2, 4, 1],
        "档位必须是 [有余额, 不知道, 不知道, 已耗尽]；\
         修复前（把 None 当 0）会得到 [3, 1, 2, 4] —— 「不知道」被排到最后"
    );
}

#[test]
fn no_unwrap_or_degradation_on_balance_in_the_builder() {
    // W2 的结构面：上面那条测的是行为，这条测的是**实现里没有那条降级路径**。
    // 行为断言会被「恰好没构造出触发条件的输入」骗过；这条不会。
    let source = include_str!("../src/routing.rs");
    let builder_start = source
        .find("pub fn build_route_table")
        .expect("有 build_route_table");
    let builder_end = source[builder_start..]
        .find("\n}\n")
        .map(|i| builder_start + i)
        .expect("函数有结尾");
    // **必须先剥掉注释行**：函数体里的注释就写着「不做任何 `unwrap_or` 降级」，
    // 不剥的话守卫会被自己的说明文字骗到（这个坑在 capability_gate.rs 里已经踩过一次）。
    let body: String = source[builder_start..builder_end]
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    for banned in ["unwrap_or", "unwrap_or_default", "unwrap_or_else"] {
        assert!(
            !body.contains(banned),
            "`build_route_table` 里出现了 `{banned}`：任何对 `balance_usd` 的降级都会\
             把「不知道」变成「已耗尽」，直接改变候选顺序"
        );
    }
    assert!(
        body.contains("balance_usd: f.balance_usd"),
        "余额必须**原样**搬进 `Upstream`（Option 一路走到排序键）"
    );
}

#[test]
fn empty_model_list_means_wildcard() {
    // W4：采集默认关 ⇒ 所有站点 `models` 都是空的。若把空解释成「谁都不服务」，
    // 路由在**默认配置下完全不可用**（每个请求 404）。
    let mut f = facts(1, Some(1.0), None, None);
    f.models = Vec::new();
    let table = build_route_table(&[f]);

    for model in ["gpt-5.6", "claude-4.7", "完全没听说过的模型"] {
        assert_eq!(
            table.candidates(model).len(),
            1,
            "空清单 = 未知 ⇒ 对任何模型都是候选（{model}）"
        );
    }
}

#[test]
fn non_empty_model_list_filters_strictly() {
    // W5：清单非空时必须**精确**匹配——通配只对「未知」生效，不是对所有上游生效。
    let table = build_route_table(&[facts(1, Some(1.0), None, None)]);

    assert_eq!(table.candidates("gpt-5.6").len(), 1);
    assert!(
        table.candidates("gpt-5.6-turbo").is_empty(),
        "非空清单不做前缀 / 模糊匹配"
    );
}

#[test]
fn alias_map_last_write_wins_and_is_identity_by_default() {
    // W6：别名映射的纯函数面。
    let map = alias_map(&[("gpt-5.6", "gpt-5.6-2026"), ("gpt-5.6", "gpt-5.6-real")]);
    assert_eq!(
        map.get("gpt-5.6").map(String::as_str),
        Some("gpt-5.6-real"),
        "重复 alias 后者胜（配置来自用户，不该让应用起不来）"
    );

    // 顺序确定（BTreeMap），不是「碰巧」。
    let ordered = alias_map(&[("b", "2"), ("a", "1")]);
    let keys: Vec<&str> = ordered.keys().map(String::as_str).collect();
    assert_eq!(keys, vec!["a", "b"]);

    // 未登记 ⇒ 恒等：与 `RouteTable::resolve_model` 同源。
    let table = build_route_table(&[facts(1, Some(1.0), None, None)]);
    assert_eq!(table.resolve_model("没登记的"), "没登记的");
}

#[test]
fn build_route_table_keeps_the_input_order() {
    // 稳定排序的性质依赖「`RouteTable` 存的是入参顺序」：同分（连 site_id 都相同）时
    // 输出必须保持入参顺序，否则「确定性」这条论证就断了。
    let table = build_route_table(&[
        facts(9, Some(1.0), None, None),
        facts(1, Some(1.0), None, None),
    ]);
    let order: Vec<i64> = table
        .candidates("gpt-5.6")
        .iter()
        .map(|u| u.site_id)
        .collect();
    assert_eq!(order, vec![1, 9], "同分按 site_id 升序（排序键的最后一段）");
}
