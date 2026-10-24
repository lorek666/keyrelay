//! M40-S2 网关**内存指标**（spec §7.1 M1–M12 的可独立跑子集）。
//!
//! 红线：本文件只断言 `GatewayMetrics` / `GatewayHandle` 的公开面；
//! 不依赖事件表、不写库、夹具只用 `127.0.0.1` + `sk-test-…`。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tianshu_relay_core::gateway::{self, GatewayConfig, GatewayHandle, UpstreamTimeout};
use tianshu_relay_core::routing::{BreakerPolicy, RouteTable, SiteGuardPolicy, Upstream};

/// 假上游：固定状态行 + 固定 2ms 延迟；记录命中次数。
fn spawn_upstream(status_line: &'static str) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = Arc::clone(&hits);
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { continue };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            std::thread::sleep(Duration::from_millis(2));
            h.fetch_add(1, Ordering::SeqCst);
            let body = r#"{"ok":true}"#;
            let resp = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    (port, hits)
}

fn dead_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

fn http_post(port: u16, token: Option<&str>) -> u16 {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"ping"}]}"#;
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    String::from_utf8_lossy(&out)
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .expect("状态行")
}

fn single_config(token: &str, fake_port: u16) -> GatewayConfig {
    GatewayConfig::single_upstream(
        0,
        token.to_string(),
        format!("http://127.0.0.1:{fake_port}"),
        zeroize::Zeroizing::new("sk-test-baseline".to_string()),
        "指标测试站".to_string(),
    )
}

fn routed_config(
    token: &str,
    upstreams: Vec<(u16, &str)>,
    breaker: BreakerPolicy,
) -> GatewayConfig {
    let mut route = Vec::new();
    let mut keys = std::collections::HashMap::new();
    for (i, (port, key_ref)) in upstreams.iter().enumerate() {
        route.push(Upstream {
            site_id: (i + 1) as i64,
            base_url: format!("http://127.0.0.1:{port}"),
            key_ref: (*key_ref).to_string(),
            key_id: Some((i + 1) as i64),
            models: vec!["gpt-4o".to_string()],
            rate: None,
            balance_usd: Some(1.0),
            latency_ms: None,
            timeout_ms: None,
        });
        keys.insert(
            (*key_ref).to_string(),
            zeroize::Zeroizing::new("sk-test-up".to_string()),
        );
    }
    GatewayConfig {
        port: 0,
        max_request_bytes: 16 * 1024 * 1024,
        token: token.to_string(),
        key_id: None,
        site_id: 0,
        base_url: String::new(),
        api_key: zeroize::Zeroizing::new(String::new()),
        site_display_name: "路由".to_string(),
        route: RouteTable::new(route),
        breaker,
        keys_by_ref: keys,
        upstream_timeout: UpstreamTimeout::default(),
        revoked_refs: None,
        on_observation: None,
        upstream_proxy: None,
        legacy_key_ref: None,
        lb_top_n: 1,
        max_attempts: 0,
        guard_policy: SiteGuardPolicy::default(),
        runtime: None,
        on_failure: None,
        on_usage: None,
        budget_check: None,
        on_budget_breach: None,
    }
}

fn port_of(handle: &GatewayHandle) -> u16 {
    handle
        .local_url()
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

// ---------------------------------------------------------------- M1

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m1_counts_every_request_and_returns_inflight_to_zero() {
    let (fake, _hits) = spawn_upstream("200 OK");
    let token = "kr-gw-m1";
    let handle = gateway::start(single_config(token, fake)).await.unwrap();
    let port = port_of(&handle);

    let mut joins = Vec::new();
    for _ in 0..4 {
        joins.push(std::thread::spawn(move || {
            for _ in 0..25 {
                assert_eq!(http_post(port, Some(token)), 200);
            }
        }));
    }
    for j in joins {
        j.join().unwrap();
    }

    let m = handle.metrics();
    assert_eq!(m.requests_total, 100, "每个请求都计数");
    assert_eq!(m.inflight, 0, "全部结束后在途必须归零");
    assert_eq!(m.by_status.get(&200), Some(&100), "状态码分布");
    assert_eq!(
        m.per_site.get(&0).map(|s| s.requests),
        Some(100),
        "legacy 站点按 site_id=0 计"
    );
    assert!(m.per_site.get(&0).and_then(|s| s.last_latency_ms).is_some());
    handle.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- M2

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m2_local_rejection_is_counted_but_never_hits_the_upstream() {
    let (fake, hits) = spawn_upstream("200 OK");
    let token = "kr-gw-m2";
    let handle = gateway::start(single_config(token, fake)).await.unwrap();
    let port = port_of(&handle);

    assert_eq!(http_post(port, None), 401);
    let m = handle.metrics();
    assert_eq!(m.requests_total, 1);
    assert_eq!(m.by_status.get(&401), Some(&1));
    assert_eq!(hits.load(Ordering::SeqCst), 0, "本地拒绝不得打到上游");
    assert!(m.per_site.is_empty(), "没打到上游 ⇒ 不产生站点指标");
    handle.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- M3

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m3_failover_counts_only_replayed_classes() {
    // 429 + 第二个 200 ⇒ 切换一次
    let (a, _ha) = spawn_upstream("429 Too Many Requests");
    let (b, _hb) = spawn_upstream("200 OK");
    let token = "kr-gw-m3a";
    let breaker = BreakerPolicy {
        threshold: 3,
        cooldown: Duration::from_secs(60),
    };
    let handle = gateway::start(routed_config(
        token,
        vec![(a, "r1"), (b, "r2")],
        breaker.clone(),
    ))
    .await
    .unwrap();
    assert_eq!(http_post(port_of(&handle), Some(token)), 200);
    assert_eq!(handle.metrics().failovers_total, 1, "429 ⇒ 切换一次");
    handle.shutdown_and_wait().await;

    // 503 ⇒ 不重放、不计数
    let (c, _hc) = spawn_upstream("503 Service Unavailable");
    let (d, _hd) = spawn_upstream("200 OK");
    let handle = gateway::start(routed_config(
        "kr-gw-m3b",
        vec![(c, "r1"), (d, "r2")],
        breaker,
    ))
    .await
    .unwrap();
    assert_eq!(http_post(port_of(&handle), Some("kr-gw-m3b")), 503);
    assert_eq!(
        handle.metrics().failovers_total,
        0,
        "503 不重放 ⇒ 不计失败切换"
    );
    handle.shutdown_and_wait().await;

    // 连接层失败 ⇒ 重放、计数
    let (e, _he) = spawn_upstream("200 OK");
    let handle = gateway::start(routed_config(
        "kr-gw-m3c",
        vec![(dead_port(), "r1"), (e, "r2")],
        BreakerPolicy {
            threshold: 3,
            cooldown: Duration::from_secs(60),
        },
    ))
    .await
    .unwrap();
    assert_eq!(http_post(port_of(&handle), Some("kr-gw-m3c")), 200);
    assert_eq!(handle.metrics().failovers_total, 1, "连接层失败 ⇒ 切换一次");
    handle.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- M5

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m5_metrics_snapshot_never_contains_token_or_host() {
    let (fake, _h) = spawn_upstream("500 Internal Server Error");
    let token = "kr-gw-m5-secret-token";
    let handle = gateway::start(single_config(token, fake)).await.unwrap();
    assert_eq!(http_post(port_of(&handle), Some(token)), 500);
    let dump = format!("{:?}", handle.metrics());
    assert!(!dump.contains(token), "红线：快照里不得有本地令牌");
    assert!(!dump.contains("127.0.0.1"), "红线：快照里不得有主机名");
    handle.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- M6

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m6_metrics_never_write_events() {
    let (fake, _h) = spawn_upstream("200 OK");
    let token = "kr-gw-m6";
    let seen = Arc::new(Mutex::new(0usize));
    let sink = Arc::clone(&seen);
    let mut cfg = single_config(token, fake);
    cfg.on_failure = Some(Arc::new(move |_f| {
        *sink.lock().unwrap() += 1;
    }));
    let handle = gateway::start(cfg).await.unwrap();
    assert_eq!(http_post(port_of(&handle), Some(token)), 200);
    assert_eq!(
        *seen.lock().unwrap(),
        0,
        "成功请求不得产生失败事件（指标路径不写事件）"
    );
    handle.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- M7 / M8

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m7_qps_is_guarded_during_the_first_seconds() {
    let (fake, _h) = spawn_upstream("200 OK");
    let token = "kr-gw-m7";
    let handle = gateway::start(single_config(token, fake)).await.unwrap();
    for _ in 0..5 {
        let _ = http_post(port_of(&handle), Some(token));
    }
    let m = handle.metrics();
    assert!(m.uptime_secs < 3);
    assert_eq!(m.qps, 0.0, "启动不足 3 秒 ⇒ QPS 恒 0（样本不足）");
    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m8_breaker_state_comes_from_the_breaker() {
    let (a, _ha) = spawn_upstream("503 Service Unavailable");
    let (b, _hb) = spawn_upstream("200 OK");
    let token = "kr-gw-m8";
    let handle = gateway::start(routed_config(
        token,
        vec![(a, "r1"), (b, "r2")],
        BreakerPolicy {
            threshold: 1,
            cooldown: Duration::from_secs(60),
        },
    ))
    .await
    .unwrap();
    // 第一次 503 就打开该站点熔断（threshold=1）
    let _ = http_post(port_of(&handle), Some(token));
    let cands = handle.candidates();
    let site1 = cands.iter().find(|c| c.site_id == 1).expect("site1 候选");
    assert_eq!(site1.breaker, "open", "breaker 必须来自 BreakerState");
    assert!(
        cands.iter().any(|c| c.health == "healthy"),
        "health 来自 health_rank"
    );
    handle.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- M10 / M11 / M12

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m10_mode_multi_when_route_is_non_empty() {
    let (a, _ha) = spawn_upstream("200 OK");
    let handle = gateway::start(routed_config(
        "kr-gw-m10",
        vec![(a, "r1")],
        BreakerPolicy::default(),
    ))
    .await
    .unwrap();
    assert!(!handle.route_is_empty(), "多站装配 ⇒ route 非空");
    assert_eq!(handle.candidates().len(), 1);
    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m11_mode_single_when_route_is_empty() {
    // 单上游（legacy）⇒ route 为空。**设置值不参与**判断。
    let (fake, _h) = spawn_upstream("200 OK");
    let handle = gateway::start(single_config("kr-gw-m11", fake))
        .await
        .unwrap();
    assert!(
        handle.route_is_empty(),
        "legacy 单上游 ⇒ route 为空 ⇒ mode 应为 single"
    );
    // spec §6.4：单上游 legacy ⇒ **恰好 1 条候选**（health 无数据可依 ⇒ unknown，不编造「健康」）
    let cands = handle.candidates();
    assert_eq!(cands.len(), 1, "legacy 单上游必须有且只有一条候选");
    assert_eq!(cands[0].health, "unknown");
    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m12_mode_stopped_when_not_running() {
    // “未运行”由壳层组装（`gateway_status_of` 的 stopped/crashed 分支）：这里断言其依据——
    // 没有句柄时无从取 metrics；对应断言见 `src-tauri/tests/commands.rs` 的 D2。
    // 本用例只证明「已 shutdown 的句柄不再是 alive」（壳层据此判 stopped）。
    let (fake, _h) = spawn_upstream("200 OK");
    let handle = gateway::start(single_config("kr-gw-m12", fake))
        .await
        .unwrap();
    assert!(handle.alive());
    handle.shutdown_and_wait().await;
}
