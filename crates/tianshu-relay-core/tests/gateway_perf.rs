//! M44-S1 F 组：性能基线（**`#[ignore]`**，release 构建下手动跑）。
//!
//! 判据（Lead 裁决）：延迟/吞吐走**相对回归**（基线见 `docs/evidence/m44s1-baseline.md`，
//! HEAD `080a1b5`：p95@1/4/16/32 = 3.03 / 2.99 / 3.75 / **5.11** ms；吞吐 **12,905 req/s**），
//! 资源/启停保留**绝对护栏**。
//!
//! 跑法：
//! ```text
//! CARGO_TARGET_DIR=… cargo test -p tianshu-relay-core --release --test gateway_perf -- --ignored --nocapture
//! ```

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tianshu_relay_core::gateway::{self, GatewayConfig};
use tianshu_relay_core::routing::{BreakerPolicy, RouteTable, SiteGuardPolicy};

const TOKEN: &str = "kr-gw-perf";
const BODY: &str = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"ping"}]}"#;

// 基线（docs/evidence/m44s1-baseline.md §3/§4）
const BASE_P50: [f64; 4] = [2.46, 2.47, 3.13, 4.12];
const BASE_P95: [f64; 4] = [3.03, 2.99, 3.75, 5.11];
const BASE_RPS: f64 = 12_905.0;
const CONCURRENCY: [usize; 4] = [1, 4, 16, 32];

fn fake(delay_ms: u64) -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = Arc::clone(&hits);
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(mut s) = conn else { continue };
            let mut buf = vec![0u8; 8192];
            let _ = s.read(&mut buf);
            if delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(delay_ms));
            }
            h.fetch_add(1, Ordering::SeqCst);
            let body = r#"{"ok":true}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    (port, hits)
}

fn cfg(port: u16) -> GatewayConfig {
    GatewayConfig {
        catalog: None,
        port: 0,
        token: TOKEN.to_string(),
        key_id: Some(1),
        site_id: 1,
        base_url: format!("http://127.0.0.1:{port}"),
        api_key: zeroize::Zeroizing::new("sk-test-perf".to_string()),
        site_display_name: "relay.example.com".to_string(),
        route: RouteTable::new(vec![]),
        breaker: BreakerPolicy::default(),
        keys_by_ref: Default::default(),
        upstream_timeout: Default::default(),
        revoked_refs: None,
        on_observation: None,
        upstream_proxy: None,
        legacy_key_ref: None,
        lb_top_n: 1,
        max_attempts: 0,
        session_affinity: false,
        guard_policy: SiteGuardPolicy::default(),
        runtime: None,
        on_failure: None,
        on_usage: None,
        budget_check: None,
        on_budget_breach: None,
        routing_rules: Vec::new(),
        max_request_bytes: tianshu_relay_core::gateway::DEFAULT_MAX_REQUEST_BYTES,
    }
}

fn once(port: u16) -> f64 {
    let t0 = Instant::now();
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(30))).ok();
    let req = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
        BODY.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    t0.elapsed().as_secs_f64() * 1000.0
}

fn load(port: u16, c: usize, n: usize) -> Vec<f64> {
    let lat = Arc::new(std::sync::Mutex::new(Vec::new()));
    let next = Arc::new(AtomicUsize::new(0));
    let mut js = Vec::new();
    for _ in 0..c {
        let lat = Arc::clone(&lat);
        let next = Arc::clone(&next);
        js.push(std::thread::spawn(move || loop {
            let i = next.fetch_add(1, Ordering::SeqCst);
            if i >= n {
                break;
            }
            let ms = once(port);
            lat.lock().unwrap().push(ms);
        }));
    }
    for j in js {
        j.join().unwrap();
    }
    let v = lat.lock().unwrap().clone();
    v
}

fn pct(mut v: Vec<f64>, p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if v.is_empty() {
        return f64::NAN;
    }
    v[((v.len() as f64 - 1.0) * p).round() as usize]
}

fn port_of(h: &tianshu_relay_core::gateway::GatewayHandle) -> u16 {
    h.local_url().rsplit(':').next().unwrap().parse().unwrap()
}

/// F1：每档 p95 ≤ 基线 × 1.20、p50 ≤ 基线 × 1.20。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "性能：release 下手动跑（相对基线，见 docs/evidence/m44s1-baseline.md）"]
async fn m44_f1_latency_regression() {
    let (up, _h) = fake(2);
    let h = gateway::start(cfg(up)).await.unwrap();
    let p = port_of(&h);
    for (i, c) in CONCURRENCY.iter().enumerate() {
        let _ = load(p, *c, 50); // 预热
        let v = load(p, *c, 200);
        let p50 = pct(v.clone(), 0.50);
        let p95 = pct(v, 0.95);
        println!("c={c} p50={p50:.2}ms（基线 {:.2}，上限 {:.2}） p95={p95:.2}ms（基线 {:.2}，上限 {:.2}）",
            BASE_P50[i], BASE_P50[i] * 1.20, BASE_P95[i], BASE_P95[i] * 1.20);
        assert!(p50 <= BASE_P50[i] * 1.20, "p50 退化超 20%（c={c}）");
        assert!(p95 <= BASE_P95[i] * 1.20, "p95 退化超 20%（c={c}）");
    }
    h.shutdown_and_wait().await;
}

/// F2：吞吐 ≥ 基线 × 0.90。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "性能：release 下手动跑"]
async fn m44_f2_throughput_regression() {
    let (up, _h) = fake(0);
    let h = gateway::start(cfg(up)).await.unwrap();
    let p = port_of(&h);
    let _ = load(p, 32, 200); // 预热
    let t0 = Instant::now();
    let mut done = 0usize;
    while t0.elapsed() < Duration::from_secs(5) {
        done += load(p, 32, 320).len();
    }
    let rps = done as f64 / t0.elapsed().as_secs_f64();
    println!(
        "吞吐 {rps:.0} req/s（基线 {BASE_RPS:.0}，下限 {:.0}）",
        BASE_RPS * 0.90
    );
    assert!(rps >= BASE_RPS * 0.90, "吞吐低于基线 90%");
    h.shutdown_and_wait().await;
}

/// F3：RSS 增量 ≤ 30 MiB（绝对护栏）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "性能：release 下手动跑"]
async fn m44_f3_memory_growth() {
    let (up, _h) = fake(2);
    let h = gateway::start(cfg(up)).await.unwrap();
    let p = port_of(&h);
    let rss = || -> u64 {
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .expect("ps");
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .unwrap_or(0)
    };
    let before = rss();
    let _ = load(p, 32, 10_000);
    let after = rss();
    let delta = (after as f64 - before as f64) / 1024.0;
    println!("RSS {before} → {after} KiB（增量 {delta:.1} MiB，上限 30）");
    assert!(delta <= 30.0, "RSS 增量超 30 MiB");
    h.shutdown_and_wait().await;
}

/// F4：start ≤ 500ms（n=5 中位）、stop ≤ 2s。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "性能：release 下手动跑"]
async fn m44_f4_start_stop_time() {
    let mut starts = Vec::new();
    for _ in 0..5 {
        let (up, _h) = fake(0);
        let t0 = Instant::now();
        let h = gateway::start(cfg(up)).await.unwrap();
        let _ = once(port_of(&h)); // 首次成功请求（/health 需 token；这里用转发路径证明已就绪）
        starts.push(t0.elapsed().as_secs_f64() * 1000.0);
        let t1 = Instant::now();
        h.shutdown_and_wait().await;
        let stop = t1.elapsed().as_secs_f64() * 1000.0;
        assert!(stop <= 2000.0, "stop 超 2s: {stop:.1}ms");
        println!("start={:.1}ms stop={:.1}ms", starts.last().unwrap(), stop);
    }
    let med = pct(starts, 0.5);
    println!("start 中位 {med:.1}ms（上限 500）");
    assert!(med <= 500.0, "start 中位超 500ms");
}

/// F5：核心层冷启动 ≤ 1.5s（沿用 M8-S3 B1 口径）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "性能：release 下手动跑"]
async fn m44_f5_core_cold_start() {
    let mut v = Vec::new();
    for _ in 0..5 {
        let dir = std::env::temp_dir().join(format!("m44-perf-cold-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t0 = Instant::now();
        let store = tianshu_relay_core::store::Store::open(&dir.join("tianshu-relay.db")).unwrap();
        let svc = tianshu_relay_core::service::TianshuRelayService::new(
            store,
            tianshu_relay_core::site::transport::MockTransport::new(vec![]),
            tianshu_relay_core::service::ServiceConfig {
                vault: Arc::new(tianshu_relay_core::vault::MemoryVault::new()),
                home: dir.clone(),
                backup_dir: dir.join("backups"),
                data_dir: None,
            },
        );
        let _ = svc.sites().unwrap();
        v.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    let med = pct(v.clone(), 0.5);
    println!("冷启动样本 {v:?} 中位 {med:.2}ms（上限 1500）");
    assert!(med <= 1500.0);
}
