//! M7-S1 路由与熔断的**纯函数**层（无网络、无网关）。
//!
//! 测试名即契约，与 `docs/specs/M7-S1-网关路由与故障切换.md` §7.1 一一对应。

use std::time::{Duration, Instant};

use tianshu_relay_core::routing::{
    should_failover, site_key, Breaker, BreakerPolicy, BreakerState, RouteTable, Upstream,
};

const MODEL: &str = "gpt-5.6";

fn up(site_id: i64, rate: Option<f64>, balance: Option<f64>, latency: Option<u64>) -> Upstream {
    Upstream {
        site_id,
        key_id: None,
        base_url: format!("http://site{site_id}.example.com"),
        key_ref: format!("kr/key/{site_id}/secret"),
        models: vec![MODEL.to_string()],
        rate,
        balance_usd: balance,
        latency_ms: latency,
        timeout_ms: None,
    }
}

fn ids(candidates: &[&Upstream]) -> Vec<i64> {
    candidates.iter().map(|u| u.site_id).collect()
}

// ============================================================ M16-S4 / P3-9：key_refs

/// `RouteTable::key_refs()`：去重 + 保持首次出现顺序。
///
/// 用途是 `gateway::start()` 的集合不变式（route ⊆ keys_by_ref ∪ revoked_refs）——
/// 重复的引用不该被数两次（报错文案里的「几个上游」得是真数）。
#[test]
fn key_refs_is_deduped_and_ordered() {
    let mut a = up(1, Some(1.0), Some(1.0), None);
    let mut b = up(2, Some(2.0), Some(1.0), None);
    let c = up(3, Some(3.0), Some(1.0), None);
    // 三个上游、两个不同的 key_ref（A 与 B 共用一个）
    a.key_ref = "kr/key/shared/secret".to_string();
    b.key_ref = "kr/key/shared/secret".to_string();

    let table = RouteTable::new(vec![a, b, c]);
    assert_eq!(
        table.key_refs(),
        vec!["kr/key/shared/secret", "kr/key/3/secret"],
        "去重且保持首次出现顺序"
    );
    assert!(RouteTable::default().key_refs().is_empty(), "空表 ⇒ 空列表");
}

// ============================================================ 排序

#[test]
fn empty_table_is_empty() {
    let table = RouteTable::new(vec![]);
    assert!(table.is_empty());
    assert!(table.candidates(MODEL).is_empty());
    assert!(table.preferred().is_none());

    let table = RouteTable::new(vec![up(1, None, None, None)]);
    assert!(!table.is_empty());
}

#[test]
fn candidates_order_is_balance_then_rate_then_latency_then_site_id() {
    // 逐段构造：每一段都让「更该被选中的」排在后面输入，验证排序真的按规则而不是按入参
    let table = RouteTable::new(vec![
        up(1, Some(2.0), Some(0.0), Some(10)), // 已耗尽 → 最后
        up(2, Some(1.0), Some(5.0), Some(50)), // 有余额、倍率 1.0 → 第一
        up(3, Some(0.5), Some(5.0), Some(90)), // 有余额、倍率更低 → 应当更前
        up(4, None, Some(5.0), None),          // 有余额、倍率未知 → 排在有倍率之后
    ]);
    assert_eq!(ids(&table.candidates(MODEL)), vec![3, 2, 4, 1]);
}

#[test]
fn unknown_balance_sorts_between_healthy_and_exhausted() {
    let table = RouteTable::new(vec![
        up(1, Some(1.0), Some(0.0), None), // 已耗尽
        up(2, Some(1.0), None, None),      // 未知
        up(3, Some(1.0), Some(9.9), None), // 有余额
    ]);
    assert_eq!(ids(&table.candidates(MODEL)), vec![3, 2, 1]);
}

#[test]
fn negative_rate_sorts_by_value_and_nan_is_safe() {
    // 这条原本叫 `nan_and_negative_rate_sort_last_without_panicking`，但它自己的断言是
    // 「**负倍率按数值升序、排最前**（`[2,3,1]`）」——名字与断言矛盾，会误导下一个人
    // （M7-S1 复审 P2-1）。行为是对的，只改名。
    let table = RouteTable::new(vec![
        up(1, Some(f64::NAN), Some(1.0), None),
        up(2, Some(-1.0), Some(1.0), None),
        up(3, Some(0.5), Some(1.0), None),
    ]);
    assert_eq!(ids(&table.candidates(MODEL)), vec![2, 3, 1]);
}

#[test]
fn latency_breaks_ties_before_site_id() {
    let table = RouteTable::new(vec![
        up(1, Some(1.0), Some(1.0), Some(300)),
        up(2, Some(1.0), Some(1.0), None), // 未观测 → 最后
        up(3, Some(1.0), Some(1.0), Some(20)),
    ]);
    assert_eq!(ids(&table.candidates(MODEL)), vec![3, 1, 2]);
}

#[test]
fn two_fully_tied_upstreams_fall_back_to_site_id_ascending() {
    // 除 site_id 外全同 ⇒ 必须按 site_id 升序（确定性论证的最小守卫）
    let table = RouteTable::new(vec![
        up(9, Some(1.0), Some(1.0), Some(10)),
        up(2, Some(1.0), Some(1.0), Some(10)),
        up(5, Some(1.0), Some(1.0), Some(10)),
    ]);
    assert_eq!(ids(&table.candidates(MODEL)), vec![2, 5, 9]);
}

#[test]
fn input_order_does_not_change_the_result() {
    // **本包最重要的一条**：把入参打乱，输出必须逐项相同。
    // 若排序键不是全序（例如少了 site_id 决胜），这条会以「顺序抖动」的形式变红。
    let base = vec![
        up(7, Some(1.0), Some(1.0), Some(10)),
        up(3, Some(1.0), Some(1.0), Some(10)),
        up(5, Some(0.5), Some(1.0), None),
        up(1, None, Some(1.0), Some(99)),
        up(4, Some(1.0), Some(0.0), Some(1)),
    ];
    let expected = ids(&RouteTable::new(base.clone()).candidates(MODEL));

    let permutations = [
        vec![4, 3, 2, 1, 0],
        vec![2, 0, 4, 1, 3],
        vec![1, 4, 0, 3, 2],
        vec![3, 2, 1, 0, 4],
    ];
    for order in permutations {
        let shuffled: Vec<Upstream> = order.iter().map(|i| base[*i].clone()).collect();
        assert_eq!(
            ids(&RouteTable::new(shuffled).candidates(MODEL)),
            expected,
            "入参顺序 {order:?} 改变了候选顺序"
        );
    }
}

#[test]
fn candidates_are_deterministic_across_calls() {
    let table = RouteTable::new(vec![
        up(7, Some(1.0), Some(1.0), Some(10)),
        up(3, Some(1.0), Some(1.0), Some(10)),
        up(5, None, None, None),
    ]);
    let first = ids(&table.candidates(MODEL));
    for _ in 0..10 {
        assert_eq!(ids(&table.candidates(MODEL)), first);
    }
}

// ============================================================ 别名

#[test]
fn alias_is_applied_before_matching() {
    let mut real = up(1, Some(1.0), Some(1.0), None);
    real.models = vec!["gpt-4o-real".to_string()];
    let table = RouteTable::new(vec![real]).with_alias(MODEL, "gpt-4o-real");

    assert_eq!(table.resolve_model(MODEL), "gpt-4o-real");
    assert_eq!(ids(&table.candidates(MODEL)), vec![1]);
    // 用真实名直接查也应当命中（别名只做一层映射）
    assert_eq!(ids(&table.candidates("gpt-4o-real")), vec![1]);
}

#[test]
fn unregistered_model_is_identity() {
    let table = RouteTable::new(vec![up(1, None, None, None)]).with_alias("a", "b");
    assert_eq!(
        table.resolve_model("nothing-registered"),
        "nothing-registered"
    );
    assert_eq!(table.resolve_model("a"), "b");
}

#[test]
fn unknown_model_yields_no_candidates() {
    let table = RouteTable::new(vec![up(1, None, None, None)]);
    assert!(table.candidates("no-such-model").is_empty());
}

// ============================================================ preferred

#[test]
fn preferred_uses_the_same_key_without_model_filter() {
    // 路由表里有别的模型，但 `preferred()` 不做 model 过滤 ⇒ 仍返回排序首位
    let mut other = up(2, Some(9.0), Some(1.0), None);
    other.models = vec!["some-other-model".to_string()];
    let table = RouteTable::new(vec![other, up(1, Some(1.0), Some(1.0), None)]);

    assert_eq!(table.preferred().map(|u| u.site_id), Some(1));
    // 而同表按一个没人登记的模型选路时是空的 —— 两条路的语义确实不同
    assert!(table.candidates("not-registered").is_empty());
}

// ============================================================ should_failover

#[test]
fn should_failover_boundary_table() {
    // 该切的
    for status in [429u16, 500, 502, 503, 504, 599] {
        assert!(should_failover(status), "{status} 应当切换");
    }
    // **不该切的**：401/403 是凭证问题，切换会把「密钥无效」误报成「上游故障」
    for status in [200u16, 301, 302, 400, 401, 403, 404, 405, 409, 418, 422] {
        assert!(!should_failover(status), "{status} 不该切换");
    }
    // 边界：499 不是 5xx，500 是
    assert!(!should_failover(499));
    assert!(should_failover(500));
    assert!(should_failover(599));
    assert!(!should_failover(600));
}

// ============================================================ 熔断

fn policy(threshold: u32, cooldown_secs: u64) -> BreakerPolicy {
    BreakerPolicy {
        threshold,
        cooldown: Duration::from_secs(cooldown_secs),
    }
}

#[test]
fn breaker_opens_at_threshold() {
    let now = Instant::now();
    let mut breaker = Breaker::new(policy(3, 60));

    assert_eq!(
        breaker.record_failure(&site_key(1), now),
        BreakerState::Closed
    );
    assert_eq!(
        breaker.record_failure(&site_key(1), now),
        BreakerState::Closed
    );
    assert_eq!(
        breaker.record_failure(&site_key(1), now),
        BreakerState::Open
    );
    assert_eq!(breaker.state(&site_key(1), now), BreakerState::Open);
}

#[test]
fn half_opens_after_cooldown() {
    let now = Instant::now();
    let mut breaker = Breaker::new(policy(1, 60));
    assert_eq!(
        breaker.record_failure(&site_key(1), now),
        BreakerState::Open
    );

    // 冷却未到
    assert_eq!(
        breaker.state(&site_key(1), now + Duration::from_secs(59)),
        BreakerState::Open
    );
    // 冷却已到 ⇒ HalfOpen（允许一个探活）
    assert_eq!(
        breaker.state(&site_key(1), now + Duration::from_secs(60)),
        BreakerState::HalfOpen
    );
    assert_eq!(
        breaker.state(&site_key(1), now + Duration::from_secs(600)),
        BreakerState::HalfOpen
    );
}

#[test]
fn success_resets_to_closed() {
    let now = Instant::now();
    let mut breaker = Breaker::new(policy(2, 60));
    breaker.record_failure(&site_key(1), now);
    breaker.record_failure(&site_key(1), now);
    assert_eq!(breaker.state(&site_key(1), now), BreakerState::Open);

    breaker.record_success(&site_key(1), now);
    assert_eq!(breaker.state(&site_key(1), now), BreakerState::Closed);
    // 清零：再失败一次不足以重新打开
    assert_eq!(
        breaker.record_failure(&site_key(1), now),
        BreakerState::Closed
    );
}

#[test]
fn breaker_state_is_read_only() {
    let now = Instant::now();
    let mut breaker = Breaker::new(policy(1, 60));
    breaker.record_failure(&site_key(1), now);

    // 连查两次（其中一次已过冷却）不得改变状态：
    // 如果 `state()` 顺手把 HalfOpen「用掉」了，第二次查询就会与第一次不同
    let first = breaker.state(&site_key(1), now + Duration::from_secs(120));
    let second = breaker.state(&site_key(1), now + Duration::from_secs(120));
    assert_eq!(first, BreakerState::HalfOpen);
    assert_eq!(second, BreakerState::HalfOpen);
    // 冷却内的站点也不受影响
    assert_eq!(breaker.state(&site_key(2), now), BreakerState::Closed);
}

#[test]
fn breaker_is_per_site() {
    let now = Instant::now();
    let mut breaker = Breaker::new(policy(2, 60));
    breaker.record_failure(&site_key(1), now);
    breaker.record_failure(&site_key(1), now);
    assert_eq!(breaker.state(&site_key(1), now), BreakerState::Open);

    // 另一个站点不受影响
    assert_eq!(breaker.state(&site_key(2), now), BreakerState::Closed);
    assert_eq!(
        breaker.record_failure(&site_key(2), now),
        BreakerState::Closed
    );
}

#[test]
fn unknown_site_is_closed() {
    let breaker = Breaker::new(BreakerPolicy::default());
    assert_eq!(
        breaker.state(&site_key(42), Instant::now()),
        BreakerState::Closed
    );
}
