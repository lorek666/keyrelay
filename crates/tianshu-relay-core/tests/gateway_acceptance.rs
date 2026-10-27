//! M44-S1 验收矩阵 A–E 组（端到端，多站 mock）。
//!
//! 行号与 `docs/specs/M44-S1-网关验收矩阵与打包.md` §7 **一一对应**；
//! 本文件只覆盖**能在核心层可靠构造**的行，其余行在同名 `#[ignore]` 占位里写明原因
//! （spec §8.9：未接线必须显式，不得跳过即绿）。
//!
//! 夹具红线：只用 `relay.example.com` / `sk-test-…` / `127.0.0.1`，不出现真实域名与账号。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tianshu_relay_core::gateway::{
    self, GatewayConfig, GatewayHandle, GatewaySnapshot, UpstreamTimeout,
};
use tianshu_relay_core::routing::{BreakerPolicy, RouteTable, SiteGuardPolicy, Upstream};

const TOKEN: &str = "kr-gw-acc";
const BODY: &str = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"ping"}]}"#;

// ---------------------------------------------------------------- 夹具

struct Upstream_ {
    port: u16,
    hits: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<String>>>,
}

/// 假上游：按 `script`（每次请求依次取一个）返回；用完后重复最后一个。
fn fake(script: Vec<&'static str>, delay_ms: u64) -> Upstream_ {
    fake_with_body(script, delay_ms, r#"{"ok":true}"#)
}

/// 同上，但可指定响应体（D1 需要带 `usage` 的 body）。
fn fake_with_body(script: Vec<&'static str>, delay_ms: u64, body: &'static str) -> Upstream_ {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let h = Arc::clone(&hits);
    let s = Arc::clone(&seen);
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { continue };
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let raw = String::from_utf8_lossy(&buf[..n]).to_string();
            let idx = h.fetch_add(1, Ordering::SeqCst);
            let line = *script.get(idx).unwrap_or(script.last().unwrap());
            if let Ok(mut log) = s.lock() {
                log.push(raw);
            }
            if delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(delay_ms));
            }
            let resp = format!(
                "HTTP/1.1 {line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    Upstream_ { port, hits, seen }
}

fn dead_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

fn upstream(site_id: i64, port: u16, key_ref: &str, models: Vec<&str>, rate: f64) -> Upstream {
    Upstream {
        site_id,
        base_url: format!("http://127.0.0.1:{port}"),
        key_ref: key_ref.to_string(),
        key_id: Some(site_id),
        models: models.into_iter().map(str::to_string).collect(),
        rate: Some(rate),
        balance_usd: Some(100.0),
        latency_ms: None,
        timeout_ms: None,
    }
}

fn config(route: Vec<Upstream>, keys: Vec<(&str, &str)>) -> GatewayConfig {
    let mut map = std::collections::HashMap::new();
    for (k, v) in keys {
        map.insert(k.to_string(), zeroize::Zeroizing::new(v.to_string()));
    }
    GatewayConfig {
        catalog: None,
        port: 0,
        token: TOKEN.to_string(),
        key_id: None,
        site_id: 0,
        base_url: String::new(),
        api_key: zeroize::Zeroizing::new(String::new()),
        site_display_name: "relay.example.com".to_string(),
        route: RouteTable::new(route),
        breaker: BreakerPolicy {
            threshold: 3,
            cooldown: Duration::from_secs(60),
        },
        keys_by_ref: map,
        upstream_timeout: UpstreamTimeout {
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
        max_request_bytes: tianshu_relay_core::gateway::DEFAULT_MAX_REQUEST_BYTES,
    }
}

fn request(port: u16, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    request_with_timeout(port, method, path, body, Duration::from_secs(15))
}

/// 同上，但客户端读超时可调：仅供 `m44_c4` 使用（见该用例注释）。
fn request_with_timeout(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    read_timeout: Duration,
) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(read_timeout)).ok();
    let body = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    let text = String::from_utf8_lossy(&out).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .expect("状态行");
    (status, text)
}

fn port_of(h: &GatewayHandle) -> u16 {
    h.local_url().rsplit(':').next().unwrap().parse().unwrap()
}

// ---------------------------------------------------------------- A 组

/// A1：`/v1/models` 是多站并集 + 别名，且**零上游 `/v1/models` 命中**。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m44_a1_models_is_the_union_with_aliases() {
    let a = fake(vec!["200 OK"], 0);
    let b = fake(vec!["200 OK"], 0);
    let mut cfg = config(
        vec![
            upstream(1, a.port, "r1", vec!["gpt-4o", "claude-3"], 1.0),
            upstream(2, b.port, "r2", vec!["gpt-4o", "deepseek-chat"], 1.0),
        ],
        vec![("r1", "sk-test-1"), ("r2", "sk-test-2")],
    );
    cfg.route = cfg.route.with_alias("gpt4", "gpt-4o");
    let h = gateway::start(cfg).await.unwrap();
    let (status, text) = request(port_of(&h), "GET", "/v1/models", None);
    assert_eq!(status, 200);
    for want in ["gpt-4o", "claude-3", "deepseek-chat", "gpt4"] {
        assert!(text.contains(want), "并集缺 {want}: {text}");
    }
    assert_eq!(
        a.hits.load(Ordering::SeqCst),
        0,
        "聚合不得打到上游 /v1/models（A 站）"
    );
    assert_eq!(
        b.hits.load(Ordering::SeqCst),
        0,
        "聚合不得打到上游 /v1/models（B 站）"
    );
    h.shutdown_and_wait().await;
}

/// A5：未知模型 ⇒ 本地 404，且**所有上游零请求**。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m44_a5_unknown_model_is_a_local_404() {
    let a = fake(vec!["200 OK"], 0);
    let h = gateway::start(config(
        vec![upstream(1, a.port, "r1", vec!["gpt-4o"], 1.0)],
        vec![("r1", "sk-test-1")],
    ))
    .await
    .unwrap();
    let unknown = r#"{"model":"not-in-catalog","messages":[]}"#;
    let (status, _) = request(port_of(&h), "POST", "/v1/chat/completions", Some(unknown));
    assert_eq!(status, 404);
    assert_eq!(a.hits.load(Ordering::SeqCst), 0, "未知模型不得打到任何上游");
    h.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- B 组

/// B1：等倍率两站，100 次请求分布 40–60。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m44_b1_weighted_round_robin_spreads_load() {
    let a = fake(vec!["200 OK"], 0);
    let b = fake(vec!["200 OK"], 0);
    let h = gateway::start(config(
        vec![
            upstream(1, a.port, "r1", vec!["gpt-4o"], 1.0),
            upstream(2, b.port, "r2", vec!["gpt-4o"], 1.0),
        ],
        vec![("r1", "sk-test-1"), ("r2", "sk-test-2")],
    ))
    .await
    .unwrap();
    let p = port_of(&h);
    for _ in 0..100 {
        assert_eq!(
            request(p, "POST", "/v1/chat/completions", Some(BODY)).0,
            200
        );
    }
    let (ca, cb) = (a.hits.load(Ordering::SeqCst), b.hits.load(Ordering::SeqCst));
    assert_eq!(ca + cb, 100);
    assert!(
        (40..=60).contains(&ca),
        "A 站命中 {ca}，应落在 40–60（加权轮转）"
    );
    h.shutdown_and_wait().await;
}

/// B2：单候选行为不变（10/10 落该站）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m44_b2_single_candidate_is_unchanged() {
    let a = fake(vec!["200 OK"], 0);
    let h = gateway::start(config(
        vec![upstream(1, a.port, "r1", vec!["gpt-4o"], 1.0)],
        vec![("r1", "sk-test-1")],
    ))
    .await
    .unwrap();
    for _ in 0..10 {
        assert_eq!(
            request(port_of(&h), "POST", "/v1/chat/completions", Some(BODY)).0,
            200
        );
    }
    assert_eq!(a.hits.load(Ordering::SeqCst), 10);
    h.shutdown_and_wait().await;
}

/// B3：模型只存在于 site2 ⇒ 10/10 落 site2，site1 零请求。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m44_b3_model_aware_routing() {
    let a = fake(vec!["200 OK"], 0);
    let b = fake(vec!["200 OK"], 0);
    let h = gateway::start(config(
        vec![
            upstream(1, a.port, "r1", vec!["claude-3"], 1.0),
            upstream(2, b.port, "r2", vec!["gpt-4o"], 1.0),
        ],
        vec![("r1", "sk-test-1"), ("r2", "sk-test-2")],
    ))
    .await
    .unwrap();
    for _ in 0..10 {
        assert_eq!(
            request(port_of(&h), "POST", "/v1/chat/completions", Some(BODY)).0,
            200
        );
    }
    assert_eq!(a.hits.load(Ordering::SeqCst), 0, "site1 不服务 gpt-4o");
    assert_eq!(b.hits.load(Ordering::SeqCst), 10);
    h.shutdown_and_wait().await;
}

/// B4：别名先解析再选路；上游收到的 `model` 是解析后的值。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m44_b4_alias_resolves_before_routing() {
    let b = fake(vec!["200 OK"], 0);
    let mut cfg = config(
        vec![upstream(2, b.port, "r2", vec!["gpt-4o"], 1.0)],
        vec![("r2", "sk-test-2")],
    );
    cfg.route = cfg.route.with_alias("gpt4", "gpt-4o");
    let h = gateway::start(cfg).await.unwrap();
    let alias_body = r#"{"model":"gpt4","messages":[]}"#;
    assert_eq!(
        request(
            port_of(&h),
            "POST",
            "/v1/chat/completions",
            Some(alias_body)
        )
        .0,
        200
    );
    let seen = b.seen.lock().unwrap().clone();
    assert!(
        seen.iter().any(|r| r.contains("\"model\":\"gpt-4o\"")),
        "上游应收到解析后的 model: {seen:?}"
    );
    h.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- C 组

async fn start_two(a: &Upstream_, b: &Upstream_, breaker: BreakerPolicy) -> GatewayHandle {
    let mut cfg = config(
        vec![
            upstream(1, a.port, "r1", vec!["gpt-4o"], 1.0),
            upstream(2, b.port, "r2", vec!["gpt-4o"], 1.0),
        ],
        vec![("r1", "sk-test-1"), ("r2", "sk-test-2")],
    );
    cfg.breaker = breaker;
    gateway::start(cfg).await.unwrap()
}

/// C1：429 ⇒ 重放到下一上游；B 收到 1 次。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m44_c1_429_is_replayed() {
    let a = fake(vec!["429 Too Many Requests"], 0);
    let b = fake(vec!["200 OK"], 0);
    let h = start_two(&a, &b, BreakerPolicy::default()).await;
    assert_eq!(
        request(port_of(&h), "POST", "/v1/chat/completions", Some(BODY)).0,
        200
    );
    assert_eq!(b.hits.load(Ordering::SeqCst), 1);
    h.shutdown_and_wait().await;
}

/// C2：503 ⇒ 不重放；B 零请求。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m44_c2_5xx_is_not_replayed() {
    let a = fake(vec!["503 Service Unavailable"], 0);
    let b = fake(vec!["200 OK"], 0);
    let h = start_two(&a, &b, BreakerPolicy::default()).await;
    assert_eq!(
        request(port_of(&h), "POST", "/v1/chat/completions", Some(BODY)).0,
        503
    );
    assert_eq!(b.hits.load(Ordering::SeqCst), 0, "5xx 不得重放");
    h.shutdown_and_wait().await;
}

/// C3：读超时 ⇒ 502、不重放、B 零请求。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m44_c3_read_timeout_is_not_replayed() {
    // 假上游：接连接但不回（用 400ms 延迟 + 300ms read 超时模拟「挂起」）
    let a = fake(vec!["200 OK"], 5_000);
    let b = fake(vec!["200 OK"], 0);
    let h = start_two(&a, &b, BreakerPolicy::default()).await;
    let t0 = Instant::now();
    let (status, _) = request(port_of(&h), "POST", "/v1/chat/completions", Some(BODY));
    assert_eq!(status, 502, "读超时按 502 如实返回");
    assert!(
        t0.elapsed() < Duration::from_secs(3),
        "必须在超时上界内返回"
    );
    assert_eq!(b.hits.load(Ordering::SeqCst), 0, "读超时不得重放");
    h.shutdown_and_wait().await;
}

/// C4：连接失败 ⇒ 重放；B 收到 1 次。
///
/// Windows 注意（CI 40225644513 实测 502）：Windows 的 Winsock 收到未监听端口的
/// RST 后**不立即失败**，而是按 base 超时重发 SYN 直到最大重试（默认 3 次，见微软
/// KB 175523；Unix 是首个 RST 即失败）。`config()` 默认的 300ms connect/read
/// 超时会在 Winsock 真正报出拒绝之前先触发——其中 read 超时报的是非 connect
/// 错误 ⇒ `classify_send_error` 判 Ambiguous ⇒ 不重放 ⇒ 502。Linux 上 RST 瞬到，
/// 两维超时值从不触发，行为与断言都不变。
///
/// 修法（只动本用例的超时，不动分类与断言）：connect/read 各放宽到 30s，让
/// Winsock 的 SYN 重试先走完、真正报拒（`is_connect`）后再分类、重放到 B；
/// 客户端读超时同步放宽到 60s（Winsock 等待 + B 响应），避免客户端先于网关超时。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m44_c4_connection_failure_is_replayed() {
    let b = fake(vec!["200 OK"], 0);
    let mut cfg = config(
        vec![
            upstream(1, dead_port(), "r1", vec!["gpt-4o"], 1.0),
            upstream(2, b.port, "r2", vec!["gpt-4o"], 1.0),
        ],
        vec![("r1", "sk-test-1"), ("r2", "sk-test-2")],
    );
    cfg.breaker = BreakerPolicy::default();
    cfg.upstream_timeout = UpstreamTimeout {
        connect: Duration::from_secs(30),
        read: Duration::from_secs(30),
    };
    let h = gateway::start(cfg).await.unwrap();
    assert_eq!(
        request_with_timeout(
            port_of(&h),
            "POST",
            "/v1/chat/completions",
            Some(BODY),
            Duration::from_secs(60),
        )
        .0,
        200
    );
    assert_eq!(b.hits.load(Ordering::SeqCst), 1);
    h.shutdown_and_wait().await;
}

/// C5：熔断按 (site, model)：A 站 m1 连败 3 次后第 4 次不碰 A；同一时刻 m2 仍能落 A。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m44_c5_breaker_opens_per_site_and_model() {
    // 单站两模型（m1 坏、m2 好）——**必须是两个不同的假上游**，否则 m2 也会拿到 503
    let a = fake(vec!["503 Service Unavailable"], 0);
    let good = fake(vec!["200 OK"], 0);
    let mut cfg = config(
        vec![
            upstream(1, a.port, "r1", vec!["m1"], 1.0),
            upstream(1, good.port, "r2", vec!["m2"], 1.0),
        ],
        vec![("r1", "sk-test-1"), ("r2", "sk-test-2")],
    );
    cfg.breaker = BreakerPolicy {
        threshold: 3,
        cooldown: Duration::from_secs(60),
    };
    let h = gateway::start(cfg).await.unwrap();
    let p = port_of(&h);
    let m1 = r#"{"model":"m1","messages":[]}"#;
    let m2 = r#"{"model":"m2","messages":[]}"#;
    for _ in 0..3 {
        assert_eq!(request(p, "POST", "/v1/chat/completions", Some(m1)).0, 503);
    }
    let a_before = a.hits.load(Ordering::SeqCst);
    // 第 4 次 m1：候选都在熔断 ⇒ 不再碰上游（本地 404/503 均可，核心是不新增上游请求）
    let _ = request(p, "POST", "/v1/chat/completions", Some(m1));
    assert_eq!(
        a.hits.load(Ordering::SeqCst),
        a_before,
        "熔断后不得再碰该 (site,model)"
    );
    // m2 不受影响
    assert_eq!(request(p, "POST", "/v1/chat/completions", Some(m2)).0, 200);
    h.shutdown_and_wait().await;
}

/// C6：每站并发上限（默认 8）——32 并发时每站上游实测峰值 == 8。
///
/// B-224 P3 修复：此前本用例只断言 `ok > 0`，并发上限等于没被守住。
/// 现在假上游本身按连接记并发峰值（每连接一线程 + 200ms 延迟，保证
/// 32 个请求在同一窗口内重叠）：上限若被打破，峰值会冲到 16 左右；
/// 若测试本身没压出并发（调度问题），`peak == 8` 的精确断言会让它显形，
/// 而不是在串行执行下悄悄变绿。
/// B-224 长尾：补齐 spec §7 C6 的三条判据——峰值 == 8（不是 ≤ 8 且 ≥ 4）、
/// 被拒请求是本地 429（body `error.code == "local_rate_limited"`，即代码
/// 注释里说的 kind 口径）、A 满后切到 B（双站峰值都到 8 即证明）。
struct ConcurrentFake {
    port: u16,
    current: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

fn concurrent_fake(delay_ms: u64) -> ConcurrentFake {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let current = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let cur = Arc::clone(&current);
    let pk = Arc::clone(&peak);
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { continue };
            let cur = Arc::clone(&cur);
            let pk = Arc::clone(&pk);
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 8192];
                let Ok(n) = stream.read(&mut buf) else { return };
                if n == 0 {
                    return;
                }
                let now = cur.fetch_add(1, Ordering::SeqCst) + 1;
                // 峰值 = 见过的最大 current（CAS 循环，避免 fetch_max 的旧版本问题）
                loop {
                    let old = pk.load(Ordering::SeqCst);
                    if now <= old
                        || pk
                            .compare_exchange(old, now, Ordering::SeqCst, Ordering::SeqCst)
                            .is_ok()
                    {
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(delay_ms));
                let body = r#"{"ok":true}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                cur.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    ConcurrentFake {
        port,
        current,
        peak,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m44_c6_per_site_concurrency_cap() {
    let a = concurrent_fake(200);
    let b = concurrent_fake(200);
    let mut cfg = config(
        vec![
            upstream(1, a.port, "r1", vec!["gpt-4o"], 1.0),
            upstream(2, b.port, "r2", vec!["gpt-4o"], 1.0),
        ],
        vec![("r1", "sk-test-1"), ("r2", "sk-test-2")],
    );
    cfg.guard_policy = SiteGuardPolicy {
        max_concurrency: 8,
        rate_limit_per_sec: 0,
        rate_burst: 0, // M46-S3：机械补字段，行为不变
    };
    // 本用例测的是并发上限，不是超时：共享 config() 的 300ms 读超时只比假上游
    // 的 200ms 延迟多 100ms 裕量。CI 负载下首字节延迟一旦越过 300ms，读超时
    // 即 Ambiguous——不重试下一个候选（直接 502）还要喂熔断，3 次即开闸，
    // 剩下请求连上游都不碰就 503，最终 ok == 0（72602bc 的 macOS CI 实测）。
    // 故本用例单独把上游超时放宽到 2s：200ms 延迟的 overlap 保证不动，
    // 峰值 == 8 的判据也不动；5s 的单请求耗时上限仍在下面守着。
    cfg.upstream_timeout = UpstreamTimeout {
        connect: Duration::from_secs(2),
        read: Duration::from_secs(2),
    };
    let h = gateway::start(cfg).await.unwrap();
    let p = port_of(&h);
    let results = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut joins = Vec::new();
    for _ in 0..32 {
        let results = Arc::clone(&results);
        joins.push(std::thread::spawn(move || {
            // B-224 长尾（C6「无请求 > 5s」）：逐请求计时——本地保护不排队，
            // 200 靠 200ms 上游延迟、429 靠立即拒绝，两者都应远小于 5s。
            let started = Instant::now();
            let (status, text) = request(p, "POST", "/v1/chat/completions", Some(BODY));
            let elapsed = started.elapsed();
            results.lock().unwrap().push((status, text, elapsed));
        }));
    }
    for j in joins {
        j.join().unwrap();
    }
    // 在途归零必须等排空，不是 join 后立刻读：fake 的计数在 write_all 之后、
    // 连接关闭之前才 fetch_sub，而网关按 Content-Length 转发、不等上游 FIN 就能
    // 关掉客户端连接——客户端 join 完成时，fake 处理线程可能还没被调度到
    // fetch_sub 那一行（CI 负载下实测残留 4）。因此这里轮询到双站归零为止
    // （上限 5s）；超时仍不归零才是真泄漏，断言照样红，不是放水。
    let drain_deadline = Instant::now() + Duration::from_secs(5);
    while (a.current.load(Ordering::SeqCst) != 0 || b.current.load(Ordering::SeqCst) != 0)
        && Instant::now() < drain_deadline
    {
        std::thread::sleep(Duration::from_millis(5));
    }
    // 锁只在断言段持有：先在块内读完 results 做断言、块结束即放锁，
    // 再 await 关停（clippy::await_holding_lock；join 已全部回收，块内无并发写）。
    {
        let results = results.lock().unwrap();
        let ok = results.iter().filter(|(s, _, _)| *s == 200).count();
        assert!(
            ok > 0,
            "至少要有成功的，实测各状态：{:?}",
            results.iter().map(|(s, _, _)| s).collect::<Vec<_>>()
        );
        // 被拒的必须是本地 429（不是上游 429）：body error.code 为 local_rate_limited。
        let local_429 = results
            .iter()
            .filter(|(s, text, _)| *s == 429 && text.contains(r#""code":"local_rate_limited""#))
            .count();
        assert!(
            local_429 > 0,
            "32 并发、双站各 8 上限 ⇒ 必然有请求在双站都满时被本地拒掉（429 local_rate_limited），实测各状态：{:?}",
            results.iter().map(|(s, _, _)| s).collect::<Vec<_>>()
        );
        let max_latency = results
            .iter()
            .map(|(_, _, elapsed)| *elapsed)
            .max()
            .expect("至少一条请求");
        assert!(
            max_latency < Duration::from_secs(5),
            "无请求耗时可超过 5s，实测最慢 {max_latency:?}"
        );
    }
    assert_eq!(
        a.current.load(Ordering::SeqCst),
        0,
        "A 站在途必须归零（无泄漏）"
    );
    assert_eq!(
        b.current.load(Ordering::SeqCst),
        0,
        "B 站在途必须归零（无泄漏）"
    );
    let peak_a = a.peak.load(Ordering::SeqCst);
    let peak_b = b.peak.load(Ordering::SeqCst);
    assert_eq!(peak_a, 8, "A 站并发峰值必须压满上限 8，实测 {peak_a}");
    assert_eq!(
        peak_b, 8,
        "B 站并发峰值必须压满上限 8（A 满后切到 B 的证明），实测 {peak_b}"
    );
    h.shutdown_and_wait().await;
}

/// C7：多站模式下同站两把 key 共享熔断（k1 连败 3 次 ⇒ 第 4 次 A 站零请求）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m44_c7_multi_key_shares_breaker() {
    let a = fake(vec!["503 Service Unavailable"], 0);
    let cfg = GatewayConfig {
        catalog: None,
        route: RouteTable::new(vec![
            upstream(1, a.port, "r1a", vec!["gpt-4o"], 1.0),
            upstream(1, a.port, "r1b", vec!["gpt-4o"], 1.0),
        ]),
        keys_by_ref: [("r1a", "sk-test-1a"), ("r1b", "sk-test-1b")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), zeroize::Zeroizing::new(v.to_string())))
            .collect(),
        ..config(vec![], vec![])
    };
    let h = gateway::start(cfg).await.unwrap();
    let p = port_of(&h);
    for _ in 0..3 {
        let _ = request(p, "POST", "/v1/chat/completions", Some(BODY));
    }
    let before = a.hits.load(Ordering::SeqCst);
    let _ = request(p, "POST", "/v1/chat/completions", Some(BODY));
    assert_eq!(
        a.hits.load(Ordering::SeqCst),
        before,
        "同站共享熔断 ⇒ k1/k2 都不再试"
    );
    h.shutdown_and_wait().await;
}

/// C9：热更新——换 runtime 快照后**下一个**请求用新路由，且不重启端口。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m44_c9_hot_reload_takes_effect_on_next_request() {
    let a = fake(vec!["200 OK"], 0);
    let b = fake(vec!["200 OK"], 0);
    let mut cfg = config(
        vec![upstream(1, a.port, "r1", vec!["gpt-4o"], 1.0)],
        vec![("r1", "sk-test-1"), ("r2", "sk-test-2")],
    );
    let runtime = Arc::new(std::sync::RwLock::new(Arc::new(GatewaySnapshot {
        generation: 1,
        route: RouteTable::new(vec![upstream(1, a.port, "r1", vec!["gpt-4o"], 1.0)]),
        keys_by_ref: cfg.keys_by_ref.clone(),
    })));
    cfg.runtime = Some(Arc::clone(&runtime));
    let h = gateway::start(cfg).await.unwrap();
    let p = port_of(&h);
    assert_eq!(
        request(p, "POST", "/v1/chat/completions", Some(BODY)).0,
        200
    );
    assert_eq!(a.hits.load(Ordering::SeqCst), 1);
    // 换快照：只留 site2（**先**读 keys 再拿写锁——否则同一把 RwLock 会自锁）
    let keys = runtime.read().unwrap().keys_by_ref.clone();
    *runtime.write().unwrap() = Arc::new(GatewaySnapshot {
        generation: 2,
        route: RouteTable::new(vec![upstream(2, b.port, "r2", vec!["gpt-4o"], 1.0)]),
        keys_by_ref: keys,
    });
    assert_eq!(
        request(p, "POST", "/v1/chat/completions", Some(BODY)).0,
        200
    );
    assert_eq!(b.hits.load(Ordering::SeqCst), 1, "下一个请求应用新快照");
    assert_eq!(h.generation(), 2, "generation 必须更到 2");
    h.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- D 组

/// D1：usage 的 `latency_ms` 是 TTFB；`attempts == 1`；`status == 200`。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m44_d1_usage_records_ttfb_and_attempts() {
    let a = fake_with_body(
        vec!["200 OK"],
        120,
        r#"{"id":"x","usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}"#,
    );
    let seen: Arc<Mutex<Vec<tianshu_relay_core::gateway::GatewayUsage>>> =
        Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let mut cfg = config(
        vec![upstream(1, a.port, "r1", vec!["gpt-4o"], 1.0)],
        vec![("r1", "sk-test-1")],
    );
    cfg.on_usage = Some(Arc::new(
        move |u: tianshu_relay_core::gateway::GatewayUsage| {
            sink.lock().unwrap().push(u);
        },
    ));
    let h = gateway::start(cfg).await.unwrap();
    assert_eq!(
        request(port_of(&h), "POST", "/v1/chat/completions", Some(BODY)).0,
        200
    );
    let log = seen.lock().unwrap().clone();
    assert_eq!(log.len(), 1, "一条请求一条 usage");
    assert_eq!(log[0].status, 200);
    assert_eq!(log[0].attempts, 1);
    assert!(
        log[0].latency_ms >= 100,
        "latency 应 >= 上游延迟 120ms 量级: {}",
        log[0].latency_ms
    );
    assert!(log[0].at > 0, "at 必须是完成时刻（非 0）");
    h.shutdown_and_wait().await;
}

/// D4：状态面——多站 + A 熔断 ⇒ `candidates` 有真值、breaker 为 open。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m44_d4_status_reports_real_candidates() {
    let a = fake(vec!["503 Service Unavailable"], 0);
    let mut cfg = config(
        vec![
            upstream(1, a.port, "r1", vec!["m1"], 1.0),
            upstream(1, a.port, "r2", vec!["m2"], 1.0),
        ],
        vec![("r1", "sk-test-1"), ("r2", "sk-test-2")],
    );
    cfg.breaker = BreakerPolicy {
        threshold: 3,
        cooldown: Duration::from_secs(60),
    };
    let h = gateway::start(cfg).await.unwrap();
    let m1 = r#"{"model":"m1","messages":[]}"#;
    for _ in 0..3 {
        let _ = request(port_of(&h), "POST", "/v1/chat/completions", Some(m1));
    }
    let cands = h.candidates();
    assert_eq!(
        cands.len(),
        2,
        "两个 upstream 各一条候选（同一站点、两个 key）"
    );
    assert!(cands.iter().any(|c| c.site_id == 1 && c.breaker == "open"));
    assert_eq!(
        h.generation(),
        0,
        "无 runtime ⇒ generation 0（单/静态路由）"
    );
    h.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- 未覆盖行（显式）

/// A2/A3/A4：模型目录持久化与采集语义（`site_model_catalog` / `empty_streak`）——
/// 属 **service 层采集接线**，本文件只做网关 HTTP 面；未覆盖，留给 M44-S1 的实现补充或用
/// `docs/specs/M39-S1` 的采集单测承接。
#[tokio::test]
#[ignore = "未覆盖：A2/A3/A4 需要 service 层采集接线（本文件只测网关 HTTP 面）"]
async fn m44_a2_a3_a4_catalog_rows_are_not_covered_here() {}

/// C8：令牌宽限属**壳层**（`commands.rs` 的 token registry，M41-S2），核心层无此概念。
#[tokio::test]
#[ignore = "未覆盖：C8 令牌宽限在 src-tauri 壳层（M41-S2），不在核心层矩阵"]
async fn m44_c8_token_grace_is_not_covered_here() {}

/// D2/D3：SSE 跨包 usage / 断开 flush 属 M40-S1 的 usage 解析路径，已在 `gateway_usage*` 覆盖。
#[tokio::test]
#[ignore = "未覆盖：D2/D3 由 M40-S1 的 usage 测试承接（本矩阵不重复）"]
async fn m44_d2_d3_sse_rows_are_not_covered_here() {}

/// E1/E2：关开关停监听 / 改端口自动重启属**壳层 supervisor**（M41-S1）。
#[tokio::test]
#[ignore = "未覆盖：E1/E2 在 src-tauri 壳层（M41-S1 supervisor）"]
async fn m44_e1_e2_lifecycle_rows_are_not_covered_here() {}

/// B-224 P2：不可发送候选（已回收）不得喂熔断。
/// 阈值 3 的熔断下连发 5 次「已回收」请求：若喂熔断，第 4 次起会
/// 变成熔断中 503 且候选 breaker 显示 open；正确行为是每次都 502
///（all_upstreams_failed），且 breaker 始终 closed。
/// 注：启动期会校验「密钥映射缺失 ⇒ 拒绝启动」，所以不可发送的
/// 真实形态是「映射在、运行中被回收」——用 `revoked_refs` 构造它，
/// 而不是留空 keys（那条是启动校验的职责，与本用例无关）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsendable_candidates_do_not_feed_the_breaker() {
    let a = fake(vec!["200 OK"], 0);
    let mut cfg = config(
        vec![upstream(1, a.port, "r1", vec!["gpt-4o"], 1.0)],
        vec![("r1", "sk-test-1")],
    );
    cfg.revoked_refs = Some(Arc::new(Mutex::new(
        ["r1".to_string()].into_iter().collect(),
    )));
    let h = gateway::start(cfg).await.unwrap();
    let p = port_of(&h);
    for i in 0..5 {
        let (status, _) = request(p, "POST", "/v1/chat/completions", Some(BODY));
        assert_eq!(
            status, 502,
            "第 {i} 次不可发送请求应为 502（熔断中会变成 503）"
        );
    }
    assert_eq!(a.hits.load(Ordering::SeqCst), 0, "不可发送不得打到上游");
    let cand = h
        .candidates()
        .into_iter()
        .find(|c| c.site_id == 1)
        .expect("site1 候选");
    assert_eq!(cand.breaker, "closed", "不可发送失败不得打开熔断: {cand:?}");
    h.shutdown_and_wait().await;
}

/// B-224 P2：per_site.requests 口径——一次失败尝试只计一次。
/// 上游恒 503（可切换状态但只有一个候选 ⇒ 原样返回）：record_attempt
/// 记 1 次后，record_failure 不得再 +1，否则 requests 会是 attempts 的两倍。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_attempt_counts_requests_exactly_once() {
    let a = fake(vec!["503 Service Unavailable"], 0);
    let cfg = config(
        vec![upstream(1, a.port, "r1", vec!["gpt-4o"], 1.0)],
        vec![("r1", "sk-test-1")],
    );
    let h = gateway::start(cfg).await.unwrap();
    let p = port_of(&h);
    for _ in 0..3 {
        let (status, _) = request(p, "POST", "/v1/chat/completions", Some(BODY));
        assert_eq!(status, 503);
    }
    let m = h.metrics();
    let per_site = m.per_site.get(&1).expect("site1 指标");
    assert_eq!(
        per_site.requests, 3,
        "3 次失败尝试 ⇒ requests 必须为 3（此前为 6）: {per_site:?}"
    );
    assert!(per_site.last_error.is_some(), "失败原因仍要记");
    h.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- DEBUG P1-3

/// DEBUG P1-3：走别名的请求，用量行模型名必须是改写后的真实名（不是别名）。
/// 别名 `gpt4` → 真实 `gpt-4o-real`：上游收到的 body 已改写、用量行也必须
/// 是真实名，否则价格 JOIN（按真实名）命中不了价格行、预算 spent 记 0。
/// 未命中别名时两者恒等（既有 D1 用例覆盖，不在此重复）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn debug_p1_3_alias_usage_uses_the_rewritten_real_model() {
    let a = fake_with_body(
        vec!["200 OK"],
        0,
        r#"{"id":"x","usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}"#,
    );
    let seen: Arc<Mutex<Vec<tianshu_relay_core::gateway::GatewayUsage>>> =
        Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let mut cfg = config(
        vec![upstream(1, a.port, "r1", vec!["gpt-4o-real"], 1.0)],
        vec![("r1", "sk-test-1")],
    );
    cfg.route = cfg.route.with_alias("gpt4", "gpt-4o-real");
    cfg.on_usage = Some(Arc::new(
        move |u: tianshu_relay_core::gateway::GatewayUsage| {
            sink.lock().unwrap().push(u);
        },
    ));
    let h = gateway::start(cfg).await.unwrap();
    let alias_body = r#"{"model":"gpt4","messages":[]}"#;
    let (status, _) = request(
        port_of(&h),
        "POST",
        "/v1/chat/completions",
        Some(alias_body),
    );
    assert_eq!(status, 200, "别名请求应经改写后成功");
    // 上游收到的 body 已改写成真实名（出站改写本身无问题，问题只在用量口径）。
    let upstream_seen = a.seen.lock().unwrap().clone();
    assert_eq!(upstream_seen.len(), 1, "上游应恰好收到一次请求");
    assert!(
        upstream_seen[0].contains(r#""model":"gpt-4o-real""#),
        "上游应收到改写后的真实名: {}",
        upstream_seen[0]
    );
    let log = seen.lock().unwrap().clone();
    assert_eq!(log.len(), 1, "一条请求一条 usage");
    assert_eq!(
        log[0].model, "gpt-4o-real",
        "用量行模型名必须是真实名（修前记别名 gpt4，价格 JOIN 命中不了）"
    );
    h.shutdown_and_wait().await;
}
