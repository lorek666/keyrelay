//! M39-S3：负载均衡与上游保护（spec §7 的 T1–T16）。
//!
//! 分三层：
//! - **纯函数**（T1–T4、T11、T12）：`weighted_pick` 的确定性序列、`top_n`、单候选、熔断键；
//! - **网关端到端**（T5–T8、T10、T15、T16）：本地并发/限流拒绝、共享 guard、探针优先；
//! - **服务/设置**（T9、T13）：多 key 展开、设置校验不落库。
//!
//! 假上游是本地 `TcpListener`（不联网）。

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tianshu_relay_core::gateway::{
    start, GatewayConfig, GatewayFailure, GatewayHandle, UpstreamTimeout,
};
use tianshu_relay_core::routing::{
    model_key, site_key, weighted_pick, Breaker, BreakerPolicy, BreakerState, Candidate,
    RoundRobinState, RouteTable, SiteGuard, SiteGuardPolicy, Upstream,
};
use zeroize::Zeroizing;

const MODEL: &str = "m39-model";
const REF_A: &str = "kr/key/1/secret";
const REF_B: &str = "kr/key/2/secret";
const KEY_A: &str = "sk-a-0123456789abcdef";
const KEY_B: &str = "sk-b-0123456789abcdef";

// ============================================================ 假上游 / HTTP 客户端

fn read_request(stream: &mut TcpStream) -> String {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf).to_string();
                if let Some(head_end) = text.find("\r\n\r\n") {
                    let content_length = text[..head_end]
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            if name.eq_ignore_ascii_case("content-length") {
                                value.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    if buf.len() >= head_end + 4 + content_length {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

/// 假上游：按 `statuses` 顺序回放状态行（用完后重复最后一个），可延迟、可计数。
struct FakeUpstream {
    base_url: String,
    seen: Arc<AtomicUsize>,
}

impl FakeUpstream {
    fn count(&self) -> usize {
        self.seen.load(Ordering::SeqCst)
    }
}

fn spawn_upstream(site_id: i64, statuses: &[&str], delay: Duration) -> FakeUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取地址");
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    // 转成 `String`：状态行要活到后台线程里（`&str` 借不出去）。
    let statuses: Vec<String> = statuses.iter().map(|s| (*s).to_string()).collect();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = read_request(&mut stream);
            counter.fetch_add(1, Ordering::SeqCst);
            if !delay.is_zero() {
                thread::sleep(delay);
            }
            let idx = counter.load(Ordering::SeqCst).saturating_sub(1);
            let status = statuses
                .get(idx)
                .or_else(|| statuses.last())
                .map(|s| s.as_str())
                .unwrap_or("200 OK");
            let body = format!(r#"{{"from":"site{site_id}"}}"#);
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    FakeUpstream {
        base_url: format!("http://{addr}"),
        seen,
    }
}

/// 慢 body 上游（Lead P1 的夹具）：响应头先发，body 分两段写、中间睡一会儿。
///
/// 用来证明「并发许可覆盖整条响应流」：body 没读完，站点的并发就不该归还。
fn spawn_slow_body_upstream(site_id: i64, delay: Duration) -> FakeUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取地址");
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = read_request(&mut stream);
            counter.fetch_add(1, Ordering::SeqCst);
            // body = `{"from":"site<N>","pad":"xxxxxxx"}`，分两段写：头 + 前半段先发，
            // 睡 `delay` 之后才发后半段（Content-Length 按实际长度算）。
            let tail = format!("{site_id}\",\"pad\":\"xxxxxxx\"}}");
            let total = "{\"from\":\"site".len() + tail.len();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {total}\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(b"{\"from\":\"site");
            let _ = stream.flush();
            thread::sleep(delay);
            let _ = stream.write_all(tail.as_bytes());
            let _ = stream.flush();
        }
    });
    FakeUpstream {
        base_url: format!("http://{addr}"),
        seen,
    }
}

fn http_post(url: &str, token: &str, path: &str, body: &str) -> (u16, String) {
    let without_scheme = url.trim_start_matches("http://");
    let mut stream = TcpStream::connect(without_scheme).expect("连接网关");
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {without_scheme}\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("发送请求");
    stream.flush().ok();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("读响应");
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let (_, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    (status, body.to_string())
}

/// 与 [`post`] 相同，但接受拥有所有权的参数（便于 `tokio::spawn`）。
async fn post_owned(url: String, token: String) -> (u16, String) {
    let body = format!(r#"{{"model":"{MODEL}","messages":[]}}"#);
    tokio::task::spawn_blocking(move || http_post(&url, &token, "/v1/chat/completions", &body))
        .await
        .expect("阻塞任务")
}

async fn post(handle: &GatewayHandle, token: &str) -> (u16, String) {
    let url = handle.local_url();
    let token = token.to_string();
    let body = format!(r#"{{"model":"{MODEL}","messages":[]}}"#);
    tokio::task::spawn_blocking(move || http_post(&url, &token, "/v1/chat/completions", &body))
        .await
        .expect("阻塞任务")
}

// ============================================================ 配置构造

type Failures = Arc<Mutex<Vec<GatewayFailure>>>;

fn upstream(site_id: i64, base_url: &str, key_ref: &str, rate: f64) -> Upstream {
    Upstream {
        site_id,
        key_id: None,
        base_url: base_url.to_string(),
        key_ref: key_ref.to_string(),
        models: vec![MODEL.to_string()],
        rate: Some(rate),
        balance_usd: Some(10.0),
        latency_ms: Some(10),
    }
}

fn keys(pairs: &[(&str, &str)]) -> HashMap<String, Zeroizing<String>> {
    let mut map = HashMap::new();
    for (reference, plain) in pairs {
        map.insert(reference.to_string(), Zeroizing::new(plain.to_string()));
    }
    map
}

fn config(
    route: Vec<Upstream>,
    keys_by_ref: HashMap<String, Zeroizing<String>>,
    top_n: usize,
    guard: SiteGuardPolicy,
    breaker: BreakerPolicy,
) -> (GatewayConfig, Failures) {
    let failures: Failures = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&failures);
    let config = GatewayConfig {
        port: 0,
        token: "local-token-for-balance-tests".to_string(),
        key_id: None,
        site_id: 0,
        base_url: String::new(),
        api_key: Zeroizing::new(String::new()),
        site_display_name: "负载测试".to_string(),
        route: RouteTable::new(route),
        breaker,
        lb_top_n: top_n,
        guard_policy: guard,
        keys_by_ref,
        upstream_timeout: UpstreamTimeout::default(),
        revoked_refs: None,
        on_failure: Some(Arc::new(move |failure| {
            if let Ok(mut log) = sink.lock() {
                log.push(failure);
            }
        })),
        on_observation: None,
        on_usage: None,
        upstream_proxy: None,
        legacy_key_ref: None,
        // M42-S1：请求体上限（既有用例用默认 16 MiB）
        max_request_bytes: tianshu_relay_core::gateway::DEFAULT_MAX_REQUEST_BYTES,
        runtime: None,
    };
    (config, failures)
}

fn open_breaker() -> BreakerPolicy {
    BreakerPolicy {
        threshold: 3,
        cooldown: Duration::from_secs(3600),
    }
}

fn no_guard() -> SiteGuardPolicy {
    SiteGuardPolicy {
        max_concurrency: 0, // 0 = 不限
        rate_limit_per_sec: 0,
    }
}

// ============================================================ T1–T4：weighted_pick（纯函数）

fn cand<'a>(up: &'a Upstream, probe: bool) -> Candidate<'a> {
    Candidate {
        upstream: up,
        probe,
    }
}

/// T1：权重 100:1 的精确槽位序列（显式 cursor，不靠统计）。
#[test]
fn weighted_pick_follows_weights_exactly() {
    let cheap = upstream(1, "http://127.0.0.1:1", REF_A, 0.01); // unit 100
    let pricey = upstream(2, "http://127.0.0.1:2", REF_B, 1.0); // unit 1
    let candidates = vec![cand(&cheap, false), cand(&pricey, false)];

    // 槽位表 = [1]×100 + [2]×1，长度 101
    for cursor in 0..100u64 {
        let picked = weighted_pick(&candidates, 3, cursor).expect("有候选");
        assert_eq!(picked.site_id, 1, "cursor={cursor} 应当选便宜的站点");
    }
    assert_eq!(
        weighted_pick(&candidates, 3, 100).expect("有候选").site_id,
        2,
        "第 101 个槽位才是贵的站点"
    );
    assert_eq!(
        weighted_pick(&candidates, 3, 101).expect("有候选").site_id,
        1,
        "槽位表循环：101 % 101 == 0"
    );
}

/// T2：`top_n` 只取前 N；`n < top_n` 不补齐；`top_n == 0` 视为 1。
#[test]
fn weighted_pick_respects_top_n() {
    let a = upstream(1, "http://127.0.0.1:1", REF_A, 1.0);
    let b = upstream(2, "http://127.0.0.1:2", REF_B, 1.0);
    let c = upstream(3, "http://127.0.0.1:3", "kr/key/3/secret", 1.0);
    let all = vec![cand(&a, false), cand(&b, false), cand(&c, false)];

    // top_n = 2 ⇒ 第三个永远轮不到
    for cursor in 0..50u64 {
        let picked = weighted_pick(&all, 2, cursor).expect("有候选");
        assert_ne!(picked.site_id, 3, "top_n=2 时第 3 个候选不该被选中");
    }
    // 两个候选 + top_n=5 ⇒ 用实际数量，不补齐
    let two = vec![cand(&a, false), cand(&b, false)];
    let seen: std::collections::BTreeSet<i64> = (0..10)
        .map(|cursor| weighted_pick(&two, 5, cursor).unwrap().site_id)
        .collect();
    assert_eq!(seen, [1, 2].into_iter().collect());
    // top_n = 0 ⇒ 视为 1 ⇒ 永远第一个
    for cursor in 0..5u64 {
        assert_eq!(weighted_pick(&all, 0, cursor).unwrap().site_id, 1);
    }
}

/// T3：单候选**不读 cursor**——任意 cursor（含 u64::MAX）结果都一样。
#[test]
fn single_candidate_does_not_touch_the_cursor() {
    let only = upstream(7, "http://127.0.0.1:7", REF_A, 1.0);
    let candidates = vec![cand(&only, false)];
    for cursor in [0u64, 1, 42, u64::MAX] {
        assert_eq!(
            weighted_pick(&candidates, 3, cursor).map(|u| u.site_id),
            Some(7),
            "单候选必须与 cursor 无关（cursor={cursor}）"
        );
    }
    // 反向保护：`RoundRobinState` 自增本身是确定的（生产侧只在多候选时才调 `next()`）
    let mut state = RoundRobinState::default();
    assert_eq!(state.next(), 0);
    assert_eq!(state.next(), 1);
}

/// T4：统计补充——1000 次里便宜站点至少是贵站点的 50 倍（不替代 T1 的精确序列）。
#[test]
fn cheap_site_dominates_the_distribution() {
    let cheap = upstream(1, "http://127.0.0.1:1", REF_A, 0.01);
    let pricey = upstream(2, "http://127.0.0.1:2", REF_B, 1.0);
    let candidates = vec![cand(&cheap, false), cand(&pricey, false)];
    let mut cheap_hits = 0usize;
    let mut pricey_hits = 0usize;
    for cursor in 0..1000u64 {
        match weighted_pick(&candidates, 3, cursor).unwrap().site_id {
            1 => cheap_hits += 1,
            2 => pricey_hits += 1,
            other => panic!("意外站点 {other}"),
        }
    }
    assert!(
        cheap_hits >= pricey_hits * 50,
        "便宜站点应当占绝对多数：cheap={cheap_hits} pricey={pricey_hits}"
    );
}

// ============================================================ T11 / T12：熔断键（纯函数）

/// T11：`(站点, 模型)` 的失败不熔断同站其它模型。
#[test]
fn breaker_is_per_site_and_model() {
    let now = std::time::Instant::now();
    let mut breaker = Breaker::new(BreakerPolicy {
        threshold: 3,
        cooldown: Duration::from_secs(60),
    });
    let x = model_key(1, "x");
    let y = model_key(1, "y");
    for _ in 0..3 {
        breaker.record_failure(&x, now);
    }
    assert_eq!(
        breaker.state(&x, now),
        BreakerState::Open,
        "模型 x 应当熔断"
    );
    assert_eq!(
        breaker.state(&y, now),
        BreakerState::Closed,
        "同站模型 y 不受影响"
    );
    // 另一个站点的同名模型也不受影响
    assert_eq!(breaker.state(&model_key(2, "x"), now), BreakerState::Closed);
}

/// T12：无 model 的请求按 `(site, None)` 熔断，与 M39-S3 之前逐字相同。
#[test]
fn bodyless_requests_breaker_is_site_level() {
    let now = std::time::Instant::now();
    let mut breaker = Breaker::new(BreakerPolicy {
        threshold: 3,
        cooldown: Duration::from_secs(60),
    });
    let site = site_key(1);
    for _ in 0..3 {
        breaker.record_failure(&site, now);
    }
    assert_eq!(breaker.state(&site, now), BreakerState::Open);
    // 站点级熔断**不**顺带熔断具体模型键（两者是独立的键）
    assert_eq!(
        breaker.state(&model_key(1, "x"), now),
        BreakerState::Closed,
        "站点级键与模型级键不串"
    );
}

// ============================================================ T5–T8、T10：本地保护（端到端）

/// T5：`max_concurrency = 2` 时第 3 个并发请求拿到本地 429，且**没有** `GatewayFailure`。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_site_concurrency_caps_in_flight_requests() {
    let slow = spawn_upstream(1, &["200 OK"], Duration::from_millis(250));
    let (config, failures) = config(
        vec![upstream(1, &slow.base_url, REF_A, 0.1)],
        keys(&[(REF_A, KEY_A)]),
        3,
        SiteGuardPolicy {
            max_concurrency: 2,
            rate_limit_per_sec: 0,
        },
        open_breaker(),
    );
    let handle = start(config).await.expect("网关应能启动");
    let token = handle.token.clone();

    let (r1, r2, r3) = tokio::join!(
        post(&handle, &token),
        post(&handle, &token),
        post(&handle, &token)
    );
    let mut statuses = vec![r1.0, r2.0, r3.0];
    statuses.sort_unstable();
    assert_eq!(
        statuses,
        vec![200, 200, 429],
        "并发上限 2 ⇒ 第三个被本地拒绝"
    );

    let rejected = [&r1, &r2, &r3]
        .into_iter()
        .find(|(status, _)| *status == 429)
        .expect("有一个 429");
    assert!(
        rejected.1.contains("local_rate_limited"),
        "本地拒绝必须可判定：{}",
        rejected.1
    );
    assert!(
        failures.lock().expect("锁").is_empty(),
        "本地拒绝不得写 GatewayFailure（那是上游故障）"
    );
    handle.shutdown_and_wait().await;
}

/// T6：令牌桶按**每秒**计——同一秒第 3 个被拒，下一秒恢复。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn token_bucket_boundary_is_per_second() {
    let fast = spawn_upstream(1, &["200 OK"], Duration::ZERO);
    let (config, failures) = config(
        vec![upstream(1, &fast.base_url, REF_A, 0.1)],
        keys(&[(REF_A, KEY_A)]),
        3,
        SiteGuardPolicy {
            max_concurrency: 0,
            rate_limit_per_sec: 2,
        },
        open_breaker(),
    );
    let handle = start(config).await.expect("网关应能启动");
    let token = handle.token.clone();

    assert_eq!(post(&handle, &token).await.0, 200);
    assert_eq!(post(&handle, &token).await.0, 200);
    let (status, body) = post(&handle, &token).await;
    assert_eq!(status, 429, "同一秒第 3 个必须被令牌桶拒绝: {body}");
    assert!(body.contains("local_rate_limited"), "{body}");
    assert!(failures.lock().expect("锁").is_empty(), "限流不是上游故障");

    // 下一秒恢复（容量 = rate = 2，1.1s 后至少回 2 个令牌）
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(post(&handle, &token).await.0, 200, "下一秒应恢复");
    handle.shutdown_and_wait().await;
}

/// T7：连续本地拒绝**不喂熔断**——之后正常请求仍然是 200（熔断仍 Closed）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_rejects_never_trip_the_breaker() {
    let slow = spawn_upstream(1, &["200 OK"], Duration::from_millis(120));
    let (config, failures) = config(
        vec![upstream(1, &slow.base_url, REF_A, 0.1)],
        keys(&[(REF_A, KEY_A)]),
        3,
        SiteGuardPolicy {
            max_concurrency: 1,
            rate_limit_per_sec: 0,
        },
        // 阈值 1：只要本地拒绝被误算成一次失败，熔断立刻打开，下一条就会 503
        BreakerPolicy {
            threshold: 1,
            cooldown: Duration::from_secs(3600),
        },
    );
    let handle = start(config).await.expect("网关应能启动");
    let token = handle.token.clone();

    // 10 个并发：1 个拿到许可、9 个本地拒绝
    let url = handle.local_url();
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let url = url.clone();
        let token = token.clone();
        tasks.push(tokio::spawn(post_owned(url, token)));
    }
    let mut statuses = Vec::new();
    for task in tasks {
        statuses.push(task.await.expect("任务不应 panic").0);
    }
    let rejected = statuses.iter().filter(|s| **s == 429).count();
    assert!(rejected >= 8, "绝大多数应当被本地拒绝：{statuses:?}");

    assert!(
        failures.lock().expect("锁").is_empty(),
        "本地拒绝不得产生 GatewayFailure"
    );
    // 熔断仍 Closed：下一条请求必须是 200（若被喂开，这里会是 503）
    assert_eq!(post(&handle, &token).await.0, 200, "本地拒绝不得熔断该站点");
    handle.shutdown_and_wait().await;
}

/// T8：**所有**候选被本地拒绝 ⇒ 429 + `kind=local_rate_limited`（不是 502）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_candidates_locally_rejected_returns_429() {
    let slow = spawn_upstream(1, &["200 OK"], Duration::from_millis(250));
    let (config, _failures) = config(
        vec![upstream(1, &slow.base_url, REF_A, 0.1)],
        keys(&[(REF_A, KEY_A)]),
        3,
        SiteGuardPolicy {
            max_concurrency: 1,
            rate_limit_per_sec: 0,
        },
        open_breaker(),
    );
    let handle = start(config).await.expect("网关应能启动");
    let token = handle.token.clone();

    // 唯一候选 + 并发 1 ⇒ 3 个并发里 2 个被本地拒绝 ⇒ 那是「全部候选都被本地拒绝」的形态
    let (r1, r2, r3) = tokio::join!(
        post(&handle, &token),
        post(&handle, &token),
        post(&handle, &token)
    );
    let mut statuses = vec![r1.0, r2.0, r3.0];
    statuses.sort_unstable();
    assert_eq!(statuses, vec![200, 429, 429], "并发 1 ⇒ 其余两个本地拒绝");

    let rejected = [&r1, &r2, &r3]
        .into_iter()
        .find(|(status, _)| *status == 429)
        .expect("有 429");
    assert!(
        rejected.1.contains("\"code\":\"local_rate_limited\""),
        "错误体必须可判定（不是 502）: {}",
        rejected.1
    );
    assert!(rejected.1.contains("本地保护"), "{}", rejected.1);
    handle.shutdown_and_wait().await;
}

/// T10：同站两把 key **共享**一个并发上限（不是每 key 一份）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_site_keys_share_one_guard() {
    let slow_a = spawn_upstream(1, &["200 OK"], Duration::from_millis(250));
    let slow_b = spawn_upstream(1, &["200 OK"], Duration::from_millis(250));
    let mut a = upstream(1, &slow_a.base_url, REF_A, 0.1);
    a.key_id = Some(1);
    let mut b = upstream(1, &slow_b.base_url, REF_B, 1.0);
    b.key_id = Some(2);
    let (config, failures) = config(
        vec![a, b],
        keys(&[(REF_A, KEY_A), (REF_B, KEY_B)]),
        3,
        SiteGuardPolicy {
            max_concurrency: 1,
            rate_limit_per_sec: 0,
        },
        open_breaker(),
    );
    let handle = start(config).await.expect("网关应能启动");
    let token = handle.token.clone();

    let (r1, r2) = tokio::join!(post(&handle, &token), post(&handle, &token));
    let mut statuses = vec![r1.0, r2.0];
    statuses.sort_unstable();
    assert_eq!(
        statuses,
        vec![200, 429],
        "两把 key 必须共享「每站 1 个并发」：若各算一份，两个都会 200"
    );
    assert_eq!(
        slow_a.count() + slow_b.count(),
        1,
        "只有一个上游请求真的发出去"
    );
    assert!(failures.lock().expect("锁").is_empty());
    handle.shutdown_and_wait().await;
}

// ============================================================ T15 / T16：探针优先

/// T15（纯函数部分）：探针**不在首位**时也必须优先——这是「探针优先」的真正判别点。
///
/// 若只测「探针恰好是第一个候选」，去掉探针优先的变异依然会绿（cursor 0 本来就选第一个）。
#[test]
fn probe_priority_is_independent_of_candidate_order() {
    let pricey = upstream(1, "http://127.0.0.1:1", REF_A, 10.0);
    let cheap = upstream(2, "http://127.0.0.1:2", REF_B, 0.01);
    // 便宜站点排在前面；探针（贵站点）排在**第二位**
    let list = vec![cand(&cheap, false), cand(&pricey, true)];
    for cursor in [0u64, 1, 7, 100, 99_999] {
        assert_eq!(
            weighted_pick(&list, 3, cursor).map(|u| u.site_id),
            Some(1),
            "探针必须优先（cursor={cursor} 时也不能被轮转跳过）"
        );
    }
}

/// T15（端到端）：HalfOpen 探针**优先于**加权轮转。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn half_open_probe_is_tried_before_the_rotated_candidates() {
    // 两站同倍率（权重 1:1），排序后 A(site 1) 在前 ⇒ slots = [A, B]，cursor 0 打 A。
    // 让 A 先失败一次（阈值 1、冷却 50ms）：冷却后 A 成为 HalfOpen 探针，
    // 而「不探针」的轮转下一条（cursor 1）本该是 B —— 探针优先必须让 A 先上。
    let a = spawn_upstream(1, &["503 Service Unavailable", "200 OK"], Duration::ZERO);
    let b = spawn_upstream(2, &["200 OK"], Duration::ZERO);
    let (config, _failures) = config(
        vec![
            upstream(1, &a.base_url, REF_A, 1.0),
            upstream(2, &b.base_url, REF_B, 1.0),
        ],
        keys(&[(REF_A, KEY_A), (REF_B, KEY_B)]),
        3,
        no_guard(),
        BreakerPolicy {
            threshold: 1,
            cooldown: Duration::from_millis(50),
        },
    );
    let handle = start(config).await.expect("网关应能启动");
    let token = handle.token.clone();

    // 第 1 条：cursor 0 ⇒ 槽位表 [A]×1 + [B]×100 的第 0 位是 A ⇒ A 收到 503 并熔断
    let (status, _) = post(&handle, &token).await;
    assert_eq!(status, 503);
    assert_eq!(a.count(), 1, "首条应当先打 A（槽位 0）");

    // 冷却后：A 是 HalfOpen ⇒ 探针优先（B 再便宜也让位）
    tokio::time::sleep(Duration::from_millis(80)).await;
    let (status, body) = post(&handle, &token).await;
    assert_eq!(status, 200, "探针成功应当返回 200: {body}");
    assert_eq!(a.count(), 2, "**探针必须优先**：第二次请求先打 A");
    assert_eq!(b.count(), 0, "B 一次都不该被请求（探针优先于轮转）");
    handle.shutdown_and_wait().await;
}

/// T16：探针成功后 A 回到 Closed ⇒ 轮转恢复（B 占绝对多数）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_a_successful_probe_rotation_resumes() {
    let a = spawn_upstream(1, &["503 Service Unavailable", "200 OK"], Duration::ZERO);
    let b = spawn_upstream(2, &["200 OK"], Duration::ZERO);
    let (config, _failures) = config(
        vec![
            upstream(1, &a.base_url, REF_A, 1.0),
            upstream(2, &b.base_url, REF_B, 1.0),
        ],
        keys(&[(REF_A, KEY_A), (REF_B, KEY_B)]),
        3,
        no_guard(),
        BreakerPolicy {
            threshold: 1,
            cooldown: Duration::from_millis(50),
        },
    );
    let handle = start(config).await.expect("网关应能启动");
    let token = handle.token.clone();

    assert_eq!(post(&handle, &token).await.0, 503, "第一条第 A 失败");
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(post(&handle, &token).await.0, 200, "第二条是成功的探针");
    assert_eq!(a.count(), 2);
    assert_eq!(b.count(), 0);

    // 探针不消耗 cursor ⇒ 下一条从 cursor 1 继续 ⇒ **两站交替**（1:1 权重）。
    // 断言「两个站点都真的被轮到」= 轮转恢复（而不是永远压在探针那一站上）。
    let a_before = a.count();
    let b_before = b.count();
    for _ in 0..6 {
        assert_eq!(post(&handle, &token).await.0, 200, "A 已恢复，后续都应 200");
    }
    let a_extra = a.count() - a_before;
    let b_extra = b.count() - b_before;
    assert!(
        a_extra >= 2 && b_extra >= 2,
        "轮转必须恢复：6 条里两站都该被轮到（A +{a_extra} / B +{b_extra}）"
    );
    handle.shutdown_and_wait().await;
}

// ============================================================ T13：设置校验

#[test]
fn gateway_guard_settings_are_validated() {
    use tianshu_relay_core::settings::Settings;

    let mut s = Settings::default();
    assert_eq!(s.gateway_lb_top_n, 3, "默认 3");
    assert_eq!(s.gateway_per_site_concurrency, 8, "默认 8");
    assert_eq!(s.gateway_per_site_rate_limit, 0, "默认 0 = 不限速");
    assert!(s.validate().is_ok(), "默认值必须合法");

    for bad in [0usize, 21] {
        s.gateway_lb_top_n = bad;
        assert!(s.validate().is_err(), "top_n={bad} 必须被拒");
    }
    s.gateway_lb_top_n = 20;
    assert!(s.validate().is_ok(), "20 是合法上界");

    s.gateway_per_site_concurrency = 0;
    assert!(
        s.validate().is_err(),
        "并发 0 必须被拒（0 只在 guard 内部表示不限）"
    );
    s.gateway_per_site_concurrency = 129;
    assert!(s.validate().is_err());
    s.gateway_per_site_concurrency = 128;
    assert!(s.validate().is_ok(), "128 是合法上界");

    s.gateway_per_site_rate_limit = 10_001;
    assert!(s.validate().is_err(), "每秒上限超过 10000 必须被拒");
    s.gateway_per_site_rate_limit = 10_000;
    assert!(s.validate().is_ok());

    // KV 往返：三个字段都要出现且能被读回
    let pairs = s.to_pairs();
    for key in [
        "gateway_lb_top_n",
        "gateway_per_site_concurrency",
        "gateway_per_site_rate_limit",
    ] {
        assert!(
            pairs.iter().any(|(k, _)| *k == key),
            "{key} 必须在 to_pairs 里"
        );
    }
    let back = Settings::from_pairs(pairs.iter().map(|(k, v)| (*k, v.as_str())));
    assert_eq!(back.gateway_lb_top_n, s.gateway_lb_top_n);
    assert_eq!(
        back.gateway_per_site_concurrency,
        s.gateway_per_site_concurrency
    );
    assert_eq!(
        back.gateway_per_site_rate_limit,
        s.gateway_per_site_rate_limit
    );
}

// ============================================================ T9：多 key（服务层）

/// T9：同站两把可用 key ⇒ 两个 `Upstream`（同 `site_id`、不同 `key_id`/`key_ref`）。
#[test]
fn multiple_keys_per_site_expand_into_multiple_upstreams() {
    use tianshu_relay_core::service::{ServiceConfig, TianshuRelayService};
    use tianshu_relay_core::site::transport::MockTransport;
    use tianshu_relay_core::vault::{secret_ref, MemoryVault, Vault};

    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let store = tianshu_relay_core::store::Store::open(&dir.path().join("t.db")).expect("建库");
    let vault = Arc::new(MemoryVault::new());
    let site = store
        .upsert_site("newapi", "https://relay.example.com", "多 key 站")
        .expect("写站点");
    let mut key_ids = Vec::new();
    for i in 1..=2 {
        let reference = secret_ref("key", i, "secret");
        let id = store
            .insert_key(
                site,
                &format!("k{i}"),
                &reference,
                Some(&i.to_string()),
                None,
            )
            .expect("写 key");
        vault.put(&reference, KEY_A).expect("写明文");
        key_ids.push(id);
    }
    store
        .set_setting("gateway_multi_site", "true")
        .expect("多站");
    let service = TianshuRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault,
            home,
            backup_dir: dir.path().join("backups"),
        },
    );

    let config = service
        .gateway_config(site, key_ids[0], 0)
        .expect("装配网关配置");
    let ups: Vec<_> = config
        .route
        .candidates(MODEL)
        .into_iter()
        .filter(|u| u.site_id == site)
        .collect();
    assert_eq!(ups.len(), 2, "同站两把 key ⇒ 两个候选");
    let ids: std::collections::BTreeSet<i64> = ups.iter().filter_map(|u| u.key_id).collect();
    assert_eq!(
        ids,
        key_ids.iter().copied().collect(),
        "两个候选的 key_id 必须是那两把 key"
    );
    assert!(
        ups.iter().any(|u| u.key_ref != ups[0].key_ref),
        "两个候选的 key_ref 必须不同（否则同 key 展开两次）"
    );
}

// ============================================================ 附加：guard 单测

/// 纯单测：`try_admit` 非阻塞、并发满即拒、`SiteLease` 归还后能再拿。
#[test]
fn site_guard_is_non_blocking_and_returns_the_lease() {
    let guard = SiteGuard::new(
        SiteGuardPolicy {
            max_concurrency: 1,
            rate_limit_per_sec: 0,
        },
        std::time::Instant::now(),
    );
    let lease = match guard.try_admit(std::time::Instant::now()) {
        tianshu_relay_core::routing::GuardOutcome::Admitted(lease) => lease,
        _ => panic!("第一个必须放行"),
    };
    assert!(matches!(
        guard.try_admit(std::time::Instant::now()),
        tianshu_relay_core::routing::GuardOutcome::ConcurrencyLimited
    ));
    drop(lease);
    assert!(matches!(
        guard.try_admit(std::time::Instant::now()),
        tianshu_relay_core::routing::GuardOutcome::Admitted(_)
    ));
}

// ============================================================ Lead P1 / P2 的回归用例

/// **P1**：并发许可必须覆盖**整条响应 body**，不是只到响应头。
///
/// 夹具：慢 body 上游（先发头、300ms 后才把 body 写完）+ `max_concurrency = 1`。
/// 第一条请求还在读 body 时，第二条必须被本地拒绝；第一条结束后第二条能成功。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_concurrency_lease_is_held_for_the_whole_body_stream() {
    let slow = spawn_slow_body_upstream(1, Duration::from_millis(300));
    let (config, failures) = config(
        vec![upstream(1, &slow.base_url, REF_A, 0.1)],
        keys(&[(REF_A, KEY_A)]),
        3,
        SiteGuardPolicy {
            max_concurrency: 1,
            rate_limit_per_sec: 0,
        },
        open_breaker(),
    );
    let handle = start(config).await.expect("网关应能启动");
    let token = handle.token.clone();

    // 第一条：后台读完整条慢 body（约 300ms）
    let url = handle.local_url();
    let token1 = token.clone();
    let first = tokio::spawn(post_owned(url, token1));

    // 头 + 第一段 body 已经发出、body 还在流式回传 ⇒ 许可仍被占用
    tokio::time::sleep(Duration::from_millis(120)).await;
    let (status, body) = post(&handle, &token).await;
    assert_eq!(
        status, 429,
        "body 还没读完时第二次请求必须被本地拒绝（许可覆盖整条响应流）: {body}"
    );
    assert!(body.contains("local_rate_limited"), "{body}");

    // 第一条读完后，许可归还 ⇒ 下一条成功
    let (first_status, first_body) = first.await.expect("任务不应 panic");
    assert_eq!(
        first_status, 200,
        "慢 body 的请求本身应当成功: {first_body}"
    );
    assert!(first_body.contains("site1"), "{first_body}");
    assert_eq!(post(&handle, &token).await.0, 200, "许可必须已归还");
    assert!(
        failures.lock().expect("锁").is_empty(),
        "本地拒绝不是上游故障"
    );
    handle.shutdown_and_wait().await;
}

/// **P2**：第一候选回 429（可重放）、第二候选被本地保护跳过 ⇒ 客户端看到那个 429，**不是 502**。
///
/// 夹具：A 便宜（cursor 0 打 A）且只服务 `m39-model`，恒回 429；
/// B 服务 `other-model`（用来占用它的并发许可）。两条请求交错：
/// 后台请求打 B（慢，占住 1 个许可）→ 测试请求打 `m39-model`：A 429 → B 本地拒绝 → 返回 A 的 429。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayable_429_survives_a_locally_rejected_candidate() {
    let a = spawn_upstream(1, &["429 Too Many Requests"], Duration::ZERO);
    let b = spawn_upstream(2, &["200 OK"], Duration::from_millis(300));

    let mut up_a = upstream(1, &a.base_url, REF_A, 0.01);
    up_a.models = vec![MODEL.to_string()];
    let mut up_b = upstream(2, &b.base_url, REF_B, 1.0);
    up_b.models = vec![MODEL.to_string(), "other-model".to_string()];

    let (config, _failures) = config(
        vec![up_a, up_b],
        keys(&[(REF_A, KEY_A), (REF_B, KEY_B)]),
        3,
        SiteGuardPolicy {
            max_concurrency: 1,
            rate_limit_per_sec: 0,
        },
        open_breaker(),
    );
    let handle = start(config).await.expect("网关应能启动");
    let token = handle.token.clone();

    // 后台请求：只服务 other-model 的 B（慢）⇒ 占住 B 的唯一许可
    let url = handle.local_url();
    let token_bg = token.clone();
    let background =
        tokio::spawn(async move { post_model_owned(url, token_bg, "other-model").await });
    tokio::time::sleep(Duration::from_millis(120)).await;

    // 测试请求：A 429（可重放）→ B 被本地保护跳过 → 必须返回 A 的 429
    let (status, body) = post(&handle, &token).await;
    assert_eq!(
        status, 429,
        "上游真的回过 429，不能因为后面的候选被本地拒绝就变成 502: {body}"
    );
    assert!(
        !body.contains("local_rate_limited"),
        "这里应当返回**上游的** 429（A），不是本地 429: {body}"
    );
    assert!(body.contains("site1"), "响应体应当来自 A: {body}");

    assert_eq!(background.await.expect("任务不应 panic").0, 200);
    handle.shutdown_and_wait().await;
}

async fn post_model_owned(url: String, token: String, model: &str) -> (u16, String) {
    let body = format!(r#"{{"model":"{model}","messages":[]}}"#);
    tokio::task::spawn_blocking(move || http_post(&url, &token, "/v1/chat/completions", &body))
        .await
        .expect("阻塞任务")
}
