//! M46-S1：巡检结论喂给运行中网关的 `Breaker`，候选随之标红 / 恢复。
//!
//! 只测注入点本身（`GatewayHandle::record_probe_outcome` → `candidates()` 的
//! `breaker` 字段），不发用户请求、不碰上游：网关只绑回环端口 0。

use std::time::{Duration, Instant};

use tianshu_relay_core::gateway::{self, GatewayConfig};
use tianshu_relay_core::notify::KeyHealthVerdict;
use tianshu_relay_core::routing::{BreakerPolicy, RouteTable, SiteGuardPolicy, Upstream};

fn upstream(site_id: i64, key_ref: &str) -> Upstream {
    Upstream {
        site_id,
        base_url: "http://127.0.0.1:9".to_string(),
        key_ref: key_ref.to_string(),
        key_id: Some(site_id),
        models: vec!["gpt-4o".to_string()],
        rate: Some(1.0),
        balance_usd: Some(100.0),
        latency_ms: None,
        timeout_ms: None,
    }
}

fn config() -> GatewayConfig {
    let mut map = std::collections::HashMap::new();
    map.insert(
        "r1".to_string(),
        zeroize::Zeroizing::new("sk-test-health-1".to_string()),
    );
    map.insert(
        "r2".to_string(),
        zeroize::Zeroizing::new("sk-test-health-2".to_string()),
    );
    GatewayConfig {
        port: 0,
        token: "kr-gw-health".to_string(),
        key_id: None,
        site_id: 0,
        base_url: String::new(),
        api_key: zeroize::Zeroizing::new(String::new()),
        site_display_name: "relay.example.com".to_string(),
        route: RouteTable::new(vec![upstream(1, "r1"), upstream(2, "r2")]),
        breaker: BreakerPolicy {
            threshold: 3,
            cooldown: Duration::from_secs(60),
        },
        keys_by_ref: map,
        upstream_timeout: gateway::UpstreamTimeout {
            connect: Duration::from_millis(300),
            read: Duration::from_millis(300),
        },
        revoked_refs: None,
        on_observation: None,
        upstream_proxy: None,
        legacy_key_ref: None,
        lb_top_n: 3,
        max_attempts: 0,
        guard_policy: SiteGuardPolicy::default(),
        runtime: None,
        on_failure: None,
        on_usage: None,
        budget_check: None,
        on_budget_breach: None,
        routing_rules: Vec::new(),
        max_request_bytes: gateway::DEFAULT_MAX_REQUEST_BYTES,
    }
}

fn breaker_of(handle: &gateway::GatewayHandle, site_id: i64) -> &'static str {
    handle
        .candidates()
        .into_iter()
        .find(|c| c.site_id == site_id)
        .expect("候选里应有该站")
        .breaker
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_outcome_opens_and_closes_gateway_candidate() {
    let handle = gateway::start(config()).await.expect("网关应能启动");
    let now = Instant::now();
    let models = vec!["gpt-4o".to_string()];
    assert_eq!(breaker_of(&handle, 1), "closed");
    assert_eq!(breaker_of(&handle, 2), "closed");

    // 2 轮故障仍 Closed（阈值 3），第 3 轮才 Open；另一站不受影响。
    // 触发源是站点级故障：DEBUG-G5 P1-8 起 DeadKey 不再喂熔断（单 key 事实
    // 不得株连全站），此处改用 UpstreamFault，阈值语义本身未放宽。
    handle.record_probe_outcome(1, &models, KeyHealthVerdict::UpstreamFault, now);
    handle.record_probe_outcome(1, &models, KeyHealthVerdict::UpstreamFault, now);
    assert_eq!(breaker_of(&handle, 1), "closed");
    handle.record_probe_outcome(1, &models, KeyHealthVerdict::UpstreamFault, now);
    assert_eq!(breaker_of(&handle, 1), "open");
    assert_eq!(breaker_of(&handle, 2), "closed");

    // 成功一轮 ⇒ 立即回 Closed（正证据复活）。
    handle.record_probe_outcome(1, &models, KeyHealthVerdict::Healthy, now);
    assert_eq!(breaker_of(&handle, 1), "closed");

    // DEBUG-G5 P1-8：死 key / 额度空连续 3 轮也不得打开本站候选（其它 key 不被跳过）。
    handle.record_probe_outcome(1, &models, KeyHealthVerdict::DeadKey, now);
    handle.record_probe_outcome(1, &models, KeyHealthVerdict::DeadKey, now);
    handle.record_probe_outcome(1, &models, KeyHealthVerdict::DeadKey, now);
    assert_eq!(breaker_of(&handle, 1), "closed");
    handle.record_probe_outcome(1, &models, KeyHealthVerdict::QuotaExhausted, now);
    handle.record_probe_outcome(1, &models, KeyHealthVerdict::QuotaExhausted, now);
    handle.record_probe_outcome(1, &models, KeyHealthVerdict::QuotaExhausted, now);
    assert_eq!(breaker_of(&handle, 1), "closed");

    handle.shutdown();
}
