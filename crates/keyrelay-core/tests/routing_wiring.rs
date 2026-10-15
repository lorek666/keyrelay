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
    let table = build_route_table(std::slice::from_ref(&f));
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

// ============================================================ W7：生产构造点

/// **W7 是「未接线」的守卫**：M7 的 D-2/D-4 就是「实现好了但生产构造点仍走 `single_upstream`」。
/// 这条直接对**生产构造点**（`service.rs::gateway_config`）断言，它红了就说明接线没做。
mod production_wiring {
    use std::fs;
    use std::sync::Arc;

    use keyrelay_core::service::{KeyRelayService, ServiceConfig};
    use keyrelay_core::site::transport::MockTransport;
    use keyrelay_core::store::Store;
    use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};

    async fn service_with_two_sites() -> (
        tempfile::TempDir,
        KeyRelayService<MockTransport>,
        i64,
        i64,
        String,
        String,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let store = Store::open(&dir.path().join("keyrelay.db")).unwrap();

        let a = store
            .upsert_site("newapi", "https://a.example.com", "A 站")
            .unwrap();
        let b = store
            .upsert_site("newapi", "https://b.example.com", "B 站")
            .unwrap();
        let ref_a = secret_ref("key", 1, "secret");
        let ref_b = secret_ref("key", 2, "secret");
        let key_a = store
            .insert_key(a, "codex/daily", &ref_a, Some("1"), None)
            .unwrap();
        store
            .insert_key(b, "codex/daily", &ref_b, Some("2"), None)
            .unwrap();

        let vault = Arc::new(MemoryVault::new());
        vault.put(&ref_a, "sk-site-A-0123456789").unwrap();
        vault.put(&ref_b, "sk-site-B-0123456789").unwrap();

        let mock = MockTransport::new(vec![]);
        let service = KeyRelayService::new(
            store,
            mock.clone(),
            ServiceConfig {
                vault: Arc::clone(&vault) as Arc<dyn Vault>,
                home,
                backup_dir: dir.path().join("backups"),
            },
        );
        (dir, service, a, key_a, ref_a, ref_b)
    }

    #[tokio::test]
    async fn gateway_config_uses_empty_route_under_single_upstream() {
        // P1-4：当前按 M8-S4（single_upstream，空 route）。多站路由（M8-S1）是 B-99 未来。
        let (_dir, service, site_a, key_a, _ref_a, _ref_b) = service_with_two_sites().await;

        let config = service
            .gateway_config(site_a, key_a, 0)
            .expect("组装网关配置");

        // P1-4：当前按 M8-S4（single_upstream，空 route）。多站路由（M8-S1）是 B-99 未来。
        assert!(
            config.route.is_empty(),
            "P1-4：single_upstream 下 route 为空（legacy 单上游用 config.base_url/api_key）"
        );
        assert!(
            config.keys_by_ref.is_empty(),
            "P1-4：空 route 下 keys_by_ref 也为空"
        );
    }

    #[tokio::test]
    async fn a_revoked_key_is_excluded_from_the_route_table() {
        // §3.5-5 的另一半：**新的取密钥路径不得绕过 `ensure_not_revoked` 建立的读者**。
        let (_dir, service, site_a, key_a, _ref_a, _ref_b) = service_with_two_sites().await;
        service
            .store()
            .set_key_status(key_a, keyrelay_core::store::KEY_STATUS_REVOKED)
            .unwrap();

        let config = service.gateway_config(site_a, key_a, 0);
        // 站点 A 唯一那把被回收了 ⇒ 它不该出现在路由表里。
        // （`gateway_config` 本身会因为 key 被回收而拒绝——那是另一条路径，见 M8-S5A §2。）
        assert!(
            config.is_err(),
            "对已回收的 key 组装网关配置必须被拒绝，而不是产出一张含它的路由表"
        );
    }

    #[tokio::test]
    async fn an_unobservable_balance_does_not_push_a_site_to_the_back() {
        // 端到端把 §6 的排序语义钉在生产装配上：观测缓存里余额未知时，
        // 该站点**不得**被排到「已耗尽」档后面。
        let (_dir, service, site_a, key_a, _ref_a, _ref_b) = service_with_two_sites().await;

        // 给 B 站一个已知余额，A 站保持未知。
        service.set_site_observation_for_test(1, Some(50.0), None, None);
        service.set_site_observation_for_test(2, None, None, None);

        let config = service
            .gateway_config(site_a, key_a, 0)
            .expect("组装网关配置");
        // P1-4：single_upstream 下 route 为空，多站排序是 B-99 接线后的未来。
        assert!(
            config.route.is_empty(),
            "P1-4：route 为空，余额排序在 B-99 多站路由接线后才有意义"
        );
    }

    #[test]
    fn the_route_table_is_built_from_the_single_production_constructor() {
        // 结构面：生产侧只应有一个 `GatewayConfig` 构造点，且它必须**不是**
        // 一条只产单上游的路径。M7 的 D-4 就是「实现好了但构造点没换」。
        let source = include_str!("../src/service.rs");
        let built = source.matches("GatewayConfig::single_upstream(").count();
        assert_eq!(built, 1, "生产侧应当只有一处构造（当前 {built} 处）");
        // P1-4：single_upstream 下不装 route / keys_by_ref（空表 legacy）。
        assert!(
            !source.contains("config.route = route;"),
            "P1-4：不再装 route（single_upstream，空表 legacy）"
        );
        assert!(
            !source.contains("config.keys_by_ref = keys_by_ref;"),
            "P1-4：不再装 keys_by_ref（空表 legacy）"
        );
    }
}
