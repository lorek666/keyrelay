//! M7-S1 端到端失败切换：**真起网关 + 两个假上游**。
//!
//! 与 `tests/gateway.rs` 的分工：那个文件覆盖单上游时代的既有约束（本步必须保持它们全绿），
//! 这个文件只覆盖「路由非空」的新行为。
//!
//! 为什么自带一份假上游脚手架而不是共享 `tests/gateway.rs` 的：Rust 的 `tests/*.rs`
//! 各自是独立 crate，共享代码要放 `tests/common/mod.rs`，而那条路径不在本包写域
//! （M7-S0 §2）。既有 `spawn_fake_upstream()` 的行为是**按路径硬编码**的，
//! 而失败切换需要「A 恒 503、B 恒 200」两个**由参数决定**行为的上游。
//!
//! 所有断言都看**上游实际收到的原始请求**，不看代码顺序——「没有切换」这件事只能由
//! 「第二个上游一次都没被请求」证明。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tianshu_relay_core::gateway::{
    generate_token, sha256_hex, start, GatewayConfig, GatewayFailure, GatewayHandle,
    GatewayTokenEntry, UpstreamTimeout,
};
use tianshu_relay_core::routing::{BreakerPolicy, RouteTable, RoutingRule, Upstream};
use zeroize::Zeroizing;

const MODEL: &str = "gpt-5.6";
const KEY_A: &str = "sk-upstream-A-0123456789abcdef";
const KEY_B: &str = "sk-upstream-B-0123456789abcdef";
const KEY_C: &str = "sk-upstream-C-0123456789abcdef";
const REF_A: &str = "kr/key/1/secret";
const REF_B: &str = "kr/key/2/secret";
const REF_C: &str = "kr/key/3/secret";

// ============================================================ 脚手架

/// 一个行为固定（永远回同一个状态码）的假上游，并记录收到的**原始请求**。
struct FakeUpstream {
    site_id: i64,
    base_url: String,
    key_ref: String,
    seen: Arc<Mutex<Vec<String>>>,
}

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

/// 起一个「永远回 `status_line`」的假上游。`seen` 记录它收到的每一个原始请求。
fn spawn_upstream_always(site_id: i64, key_ref: &str, status_line: &str) -> FakeUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取地址");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    let status_line = status_line.to_string();

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let raw = read_request(&mut stream);
            if let Ok(mut log) = recorder.lock() {
                log.push(raw);
            }
            let body = format!(r#"{{"from":"site{site_id}"}}"#);
            let response = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    FakeUpstream {
        site_id,
        base_url: format!("http://{addr}"),
        key_ref: key_ref.to_string(),
        seen,
    }
}

impl FakeUpstream {
    fn request_count(&self) -> usize {
        self.seen.lock().map(|s| s.len()).unwrap_or(0)
    }

    fn upstream(&self, rate: f64) -> Upstream {
        Upstream {
            site_id: self.site_id,
            key_id: None,
            base_url: self.base_url.clone(),
            key_ref: self.key_ref.clone(),
            models: vec![MODEL.to_string()],
            rate: Some(rate),
            balance_usd: Some(10.0),
            latency_ms: Some(10),
            timeout_ms: None,
        }
    }
}

type Failures = Arc<Mutex<Vec<GatewayFailure>>>;
type UsageLog = Arc<Mutex<Vec<tianshu_relay_core::gateway::GatewayUsage>>>;
type Observations = Arc<Mutex<Vec<tianshu_relay_core::gateway::UpstreamObservation>>>;

/// 起一个**路由模式**的网关。`rate` 决定排序：小的排前面（首选）。
async fn start_routed(
    upstreams: &[(&FakeUpstream, f64)],
    breaker: BreakerPolicy,
) -> (GatewayHandle, String, Failures) {
    let ups: Vec<Upstream> = upstreams
        .iter()
        .map(|(u, rate)| u.upstream(*rate))
        .collect();
    let keys: Vec<(&str, &str)> = upstreams
        .iter()
        .map(|(u, _)| {
            let plain = if u.key_ref == REF_A { KEY_A } else { KEY_B };
            (u.key_ref.as_str(), plain)
        })
        .collect();
    let (handle, token, failures, _) = start_routed_full(
        ups,
        breaker,
        UpstreamTimeout::default(),
        None,
        keys,
        tianshu_relay_core::routing::SiteGuardPolicy::default(),
        None,
    )
    .await;
    (handle, token, failures)
}

/// 唯一的配置构造点：候选由调用方直接给（`Upstream` 值），其余参数显式传入。
///
/// 为什么要有它（M16-S4 / P2-13）：**「连接层失败」的候选没有假上游进程**——
/// 它就是一个没人听的端口，用 `&FakeUpstream` 表达不出来。
async fn start_routed_full(
    upstreams: Vec<Upstream>,
    breaker: BreakerPolicy,
    timeout: UpstreamTimeout,
    revoked: Option<Vec<String>>,
    keys: Vec<(&str, &str)>,
    guard: tianshu_relay_core::routing::SiteGuardPolicy,
    usage: Option<UsageLog>,
) -> (GatewayHandle, String, Failures, Observations) {
    let route = RouteTable::new(upstreams);
    let mut map = std::collections::HashMap::new();
    for (r, plain) in keys {
        map.insert(r.to_string(), Zeroizing::new(plain.to_string()));
    }
    let failures: Failures = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&failures);
    let observations: Observations = Arc::new(Mutex::new(Vec::new()));
    let obs_sink = Arc::clone(&observations);

    let handle = start(GatewayConfig {
        catalog: None,
        port: 0,
        token: generate_token(),
        key_id: None,
        site_id: 0,
        // 路由非空时 `base_url` 不被使用；留空正好证明这一点（`start()` 只在空表时要求它非空）
        base_url: String::new(),
        api_key: zeroize::Zeroizing::new(String::new()),
        site_display_name: "路由模式".to_string(),
        route,
        breaker,
        keys_by_ref: map,
        upstream_timeout: timeout,
        revoked_refs: revoked.map(|refs| {
            Arc::new(Mutex::new(
                refs.into_iter().collect::<std::collections::HashSet<_>>(),
            ))
        }),
        on_observation: Some(Arc::new(move |o| {
            if let Ok(mut log) = obs_sink.lock() {
                log.push(o);
            }
        })),
        upstream_proxy: None,
        legacy_key_ref: None,
        // M42-S1：请求体上限（既有用例用默认 16 MiB）
        max_request_bytes: tianshu_relay_core::gateway::DEFAULT_MAX_REQUEST_BYTES,
        // M39-S3：既有用例保持单候选（top_n=1）+ 默认 guard ⇒ 行为逐字不变
        lb_top_n: 1,
        max_attempts: 0,
        session_affinity: false,
        guard_policy: guard,
        runtime: None,
        on_failure: Some(Arc::new(move |f| {
            if let Ok(mut log) = sink.lock() {
                log.push(f);
            }
        })),
        on_usage: usage.map(|log| {
            Arc::new(move |u: tianshu_relay_core::gateway::GatewayUsage| {
                if let Ok(mut log) = log.lock() {
                    log.push(u);
                }
            }) as Arc<dyn Fn(tianshu_relay_core::gateway::GatewayUsage) + Send + Sync>
        }),
        // M46-S5：既有用例默认不拦、不回调。
        budget_check: None,
        on_budget_breach: None,
        routing_rules: Vec::new(),
    })
    .await
    .expect("网关应能启动");

    let token = handle.token.clone();
    (handle, token, failures, observations)
}

/// 一个**没人听**的端口：连接必然被拒（`is_connect()` ⇒ P2-13 里「可重放」的那一类）。
///
/// 用一个刚释放的临时端口而不是固定端口号（`127.0.0.1:1` 在不同平台/沙箱里行为不一）。
fn dead_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("占一个临时端口");
    let port = listener.local_addr().expect("读端口").port();
    drop(listener);
    port
}

/// 「连不上」的上游：候选里有它，但它不会收到任何请求。
fn dead_upstream(site_id: i64, key_ref: &str, rate: f64) -> Upstream {
    Upstream {
        site_id,
        key_id: None,
        base_url: format!("http://127.0.0.1:{}", dead_port()),
        key_ref: key_ref.to_string(),
        models: vec![MODEL.to_string()],
        rate: Some(rate),
        balance_usd: Some(10.0),
        latency_ms: Some(10),
        timeout_ms: None,
    }
}

/// P3-9 / M8-S1 §10 第 3 条（W3 的集合不变式）：`route` 里的每个 `key_ref`
/// 必须落在 `keys_by_ref`（有可用明文）或 `revoked_refs`（显式标记不用）里。
/// 缺一个就**在 `start()` 报错**，而不是等到第一个请求变成 502。
#[tokio::test]
async fn route_and_keys_by_ref_must_agree() {
    /// 按「keys 里填哪些引用 / revoked 里标哪些」构造一份路由配置。
    fn config_with(keys: &[&str], revoked: &[&str]) -> GatewayConfig {
        let mut map = std::collections::HashMap::new();
        for r in keys {
            let plain = if *r == REF_A { KEY_A } else { KEY_B };
            map.insert((*r).to_string(), Zeroizing::new(plain.to_string()));
        }
        GatewayConfig {
            catalog: None,
            port: 0,
            token: generate_token(),
            key_id: None,
            site_id: 0,
            base_url: String::new(),
            api_key: Zeroizing::new(String::new()),
            site_display_name: "路由模式".to_string(),
            route: RouteTable::new(vec![dead_upstream(1, REF_A, 0.1)]),
            breaker: long_cooldown(),
            keys_by_ref: map,
            upstream_timeout: UpstreamTimeout::default(),
            revoked_refs: if revoked.is_empty() {
                None
            } else {
                Some(Arc::new(Mutex::new(
                    revoked.iter().map(|r| (*r).to_string()).collect(),
                )))
            },
            on_observation: None,
            on_usage: None,
            budget_check: None,
            on_budget_breach: None,
            routing_rules: Vec::new(),
            upstream_proxy: None,
            legacy_key_ref: None,
            // M42-S1：请求体上限（既有用例用默认 16 MiB）
            max_request_bytes: tianshu_relay_core::gateway::DEFAULT_MAX_REQUEST_BYTES,
            // M39-S3：既有用例保持单候选（top_n=1）+ 默认 guard ⇒ 行为逐字不变
            lb_top_n: 1,
            max_attempts: 0,
            session_affinity: false,
            guard_policy: tianshu_relay_core::routing::SiteGuardPolicy::default(),
            runtime: None,
            on_failure: None,
        }
    }

    // ① 路由里有 REF_A，但既没明文也没标已回收 ⇒ 拒绝启动
    let err = start(config_with(&[], &[]))
        .await
        .expect_err("缺明文的 key_ref 必须让启动失败（否则第一个请求才 502）");
    let text = err.to_string();
    assert!(
        text.contains("密钥映射"),
        "文案要说清根因是构造方忘了填密钥映射: {text}"
    );
    assert!(
        !text.contains(REF_A),
        "**不得**打印 key_ref 原文（引用本身是线索，M7-S0 §4.3）: {text}"
    );

    // ② 有明文 ⇒ 允许启动
    let handle = start(config_with(&[REF_A], &[]))
        .await
        .expect("填齐明文的 route 必须能启动");
    handle.shutdown_and_wait().await;

    // ③ 没明文但被标成已回收 ⇒ 合法（「不再使用它」的显式表达）
    let handle = start(config_with(&[], &[REF_A]))
        .await
        .expect("已回收的 key_ref 是合法状态（网关会跳过它并记事件）");
    handle.shutdown_and_wait().await;
}

/// 极简 HTTP 客户端：POST + JSON body。
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

/// 极简 HTTP 客户端：GET，无 body（P2-9 / B-98：GET /v1/models 等无 body 请求也要故障切换）。
fn http_get(url: &str, token: &str, path: &str) -> (u16, String) {
    let without_scheme = url.trim_start_matches("http://");
    let mut stream = TcpStream::connect(without_scheme).expect("连接网关");
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {without_scheme}\r\nAuthorization: Bearer {token}\r\n\
         Connection: close\r\n\r\n"
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

async fn get(handle: &GatewayHandle, token: &str, path: &str) -> (u16, String) {
    let url = format!("http://{}", handle.addr);
    let token = token.to_string();
    let path = path.to_string();
    tokio::task::spawn_blocking(move || http_get(&url, &token, &path))
        .await
        .expect("阻塞任务")
}

async fn post(handle: &GatewayHandle, token: &str, body: &str) -> (u16, String) {
    let url = format!("http://{}", handle.addr);
    let token = token.to_string();
    let body = body.to_string();
    tokio::task::spawn_blocking(move || http_post(&url, &token, "/v1/chat/completions", &body))
        .await
        .expect("阻塞任务")
}

fn chat_body() -> String {
    format!(r#"{{"model":"{MODEL}","messages":[{{"role":"user","content":"hi"}}]}}"#)
}

fn long_cooldown() -> BreakerPolicy {
    BreakerPolicy {
        threshold: 100,
        cooldown: Duration::from_secs(3600),
    }
}

// ============================================================ 用例

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_503_response_is_not_replayed() {
    // M16-S4 / P2-13（旧用例 `failover_on_503_reaches_the_second_upstream`）：
    //   旧断言：A 恒 503 ⇒ 切到 B，客户端拿到 200，A/B 各被请求 1 次。
    //   新断言：503 **原样返回**，B **一次都不被请求**，仍记一条失败事件。
    //   为什么：5xx 是「上游已开始处理但失败」的区间（524/504 明确是超时类），
    //   重放到另一个站点会让用户在两处各付一次钱，而重复计费不可逆。
    //   可用性由熔断承接：下一个请求会跳过被熔断的 A（见 breaker 那条用例）。
    let a = spawn_upstream_always(1, REF_A, "503 Service Unavailable");
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let (handle, token, failures) = start_routed(&[(&a, 0.1), (&b, 1.0)], long_cooldown()).await;

    let (status, _) = post(&handle, &token, &chat_body()).await;

    assert_eq!(status, 503, "503 必须原样返回（不再重放到第二个上游）");
    assert_eq!(a.request_count(), 1, "首选上游应当被试过一次");
    assert_eq!(
        b.request_count(),
        0,
        "**第二个上游一次都不该被请求**（P2-13）"
    );
    {
        let events = failures.lock().unwrap();
        assert_eq!(events.len(), 1, "仍要记一条失败事件（可观测性不变）");
        assert_eq!(events[0].site_id, 1);
        assert_eq!(events[0].status, 503);
        assert!(
            events[0].reason.contains("不重放"),
            "reason 要写明计费口径: {}",
            events[0].reason
        );
    }

    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_429_is_replayed_to_the_next_upstream() {
    // Lead 2026-10-16 的最终口径：429 是**限流**——上游在进入模型处理之前就拒了，
    // 重放不产生计费，所以它和连接层失败一样允许同请求内切换（FR-5:160 的可见行为不变）。
    let a = spawn_upstream_always(1, REF_A, "429 Too Many Requests");
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let (handle, token, failures) = start_routed(&[(&a, 0.1), (&b, 1.0)], long_cooldown()).await;

    let (status, body) = post(&handle, &token, &chat_body()).await;

    assert_eq!(status, 200, "429 应当切到第二个上游: {body}");
    assert!(body.contains("site2"), "{body}");
    assert_eq!(a.request_count(), 1);
    assert_eq!(b.request_count(), 1);
    {
        let events = failures.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].status, 429);
        assert!(
            events[0].reason.contains("限流"),
            "reason 要写明 429 是限流（未进入处理）: {}",
            events[0].reason
        );
    }

    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connect_failure_is_replayed_to_the_next_upstream() {
    // P2-13 允许重放的**另一类**：连接层失败。请求连会话都没建立 ⇒ 上游不可能处理它。
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let (handle, token, failures, _observations) = start_routed_full(
        vec![dead_upstream(1, REF_A, 0.1), b.upstream(1.0)],
        long_cooldown(),
        UpstreamTimeout::default(),
        None,
        vec![(REF_A, KEY_A), (REF_B, KEY_B)],
        tianshu_relay_core::routing::SiteGuardPolicy::default(),
        None,
    )
    .await;

    let (status, body) = post(&handle, &token, &chat_body()).await;

    assert_eq!(status, 200, "连接层失败必须切到第二个上游: {body}");
    assert!(body.contains("site2"), "{body}");
    assert_eq!(b.request_count(), 1, "第二个上游应当被请求一次");
    {
        let events = failures.lock().unwrap();
        assert_eq!(events.len(), 1, "切走的那次失败也要记事件");
        assert_eq!(events[0].site_id, 1);
        assert_eq!(events[0].status, 502, "连接层失败没有状态码 ⇒ 按 502 记");
        assert!(
            events[0].reason.contains("连接层"),
            "reason 要说明这是可重放的那一类: {}",
            events[0].reason
        );
    }

    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_timeout_is_not_replayed() {
    // 最容易写错的一格：读超时（连上了、请求发出去了、等不到响应头）**不是** connect 错误，
    // 所以判据必须是 `is_connect()` 而不是 `is_timeout()`。上游可能已经跑完并计费 ⇒ 不重放。
    let stalled = spawn_stalled_upstream(1, REF_A);
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let timeout = UpstreamTimeout {
        connect: Duration::from_millis(500),
        read: Duration::from_millis(200),
    };
    let (handle, token, failures, _observations) = start_routed_full(
        vec![stalled.upstream(0.1), b.upstream(1.0)],
        long_cooldown(),
        timeout,
        None,
        vec![(REF_A, KEY_A), (REF_B, KEY_B)],
        tianshu_relay_core::routing::SiteGuardPolicy::default(),
        None,
    )
    .await;

    let (status, _) = post(&handle, &token, &chat_body()).await;

    assert_eq!(status, 502, "读超时按 502 如实返回");
    assert_eq!(
        b.request_count(),
        0,
        "**第二个上游一次都不该被请求**（读超时可能已计费 ⇒ 不重放）"
    );
    {
        let events = failures.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert!(
            events[0].reason.contains("不重放"),
            "reason 要写明「可能已送达」: {}",
            events[0].reason
        );
    }

    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bodyless_get_request_also_fails_over() {
    // P2-9 / B-98 / DEBUG-REPORT-v3 §2-9：无 body 的 GET，旧实现只用 preferred() 的
    // 单个候选——首选挂了就 502，不切别的上游。现在用 all_candidates()，无 body 请求
    // 也走故障切换循环。
    //
    // M16-S4 / P2-13 之后能触发切换的只剩「连接层失败」与 429，所以本用例的故障源
    // 从「503」换成「连不上的端口」——**测的东西没变**（无 body 也走切换循环），
    // 只是换了一个在计费口径下合法的触发方式。
    //
    // **M39-S2 适配**：样本从 `GET /v1/models` 换成 `GET /v1/files`。
    // `/v1/models` 在非空路由 + 目录非空时已改为**本地聚合**（上游零命中，见
    // `tests/gateway_models_aggregate.rs`），它不再是一条「会走到上游」的无 body 请求；
    // `GET /v1/files` 同为无 body 的 GET、`model_from_body` 为 None、网关无特殊处理，
    // 因此仍能覆盖「无 body 也走切换循环」。**断言不变**。
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let (handle, token, _failures, _observations) = start_routed_full(
        vec![dead_upstream(1, REF_A, 0.1), b.upstream(1.0)],
        long_cooldown(),
        UpstreamTimeout::default(),
        None,
        vec![(REF_A, KEY_A), (REF_B, KEY_B)],
        tianshu_relay_core::routing::SiteGuardPolicy::default(),
        None,
    )
    .await;

    let (status, body) = get(&handle, &token, "/v1/files").await;

    assert_eq!(status, 200, "无 body 请求也应当切到第二个上游: {body}");
    assert!(body.contains("site2"), "响应应当来自第二个上游: {body}");
    assert_eq!(b.request_count(), 1, "第二个上游应当被请求一次");

    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_failover_on_401_so_an_invalid_key_is_not_masked_as_an_upstream_fault() {
    // **本包最重的一条**：401 是凭证问题。切换会把「密钥无效」误报成「上游故障」，
    // 还会把**其它站点的密钥**也拿去试一遍。
    let a = spawn_upstream_always(1, REF_A, "401 Unauthorized");
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let (handle, token, failures) = start_routed(&[(&a, 0.1), (&b, 1.0)], long_cooldown()).await;

    let (status, _) = post(&handle, &token, &chat_body()).await;

    assert_eq!(status, 401, "401 必须原样返回给客户端");
    assert_eq!(a.request_count(), 1);
    assert_eq!(
        b.request_count(),
        0,
        "**401 时第二个上游一次都不该被请求**（否则等于拿别的站点的密钥去试）"
    );
    assert!(
        failures.lock().unwrap().is_empty(),
        "401 不是「上游故障」，不该产生失败事件"
    );

    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn breaker_opens_after_threshold_and_skips_the_upstream() {
    // M16-S4 / P2-13 之后「同一个请求内」不再因 503 切换，所以喂熔断改成
    // **N 个独立请求**：每个请求都如实返回 503（旧断言是前两次返回 200，因为当时会切到 B）。
    // 第 3 个请求时 A 已 Open ⇒ 被跳过、直接走 B——这正是 P2-13 承诺的可用性替代路径。
    let a = spawn_upstream_always(1, REF_A, "503 Service Unavailable");
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let policy = BreakerPolicy {
        threshold: 2,
        cooldown: Duration::from_secs(3600), // 冷却很长，本轮不会 HalfOpen
    };
    let (handle, token, _failures) = start_routed(&[(&a, 0.1), (&b, 1.0)], policy).await;

    // 第 1、2 次：A 是首选且未熔断 ⇒ 每次都试 A，503 原样返回（不重放）
    assert_eq!(post(&handle, &token, &chat_body()).await.0, 503);
    assert_eq!(post(&handle, &token, &chat_body()).await.0, 503);
    assert_eq!(a.request_count(), 2, "阈值内应当每次都试 A");
    assert_eq!(b.request_count(), 0, "503 不重放 ⇒ B 一次都不该被请求");

    // 第 3 次：A 已 Open ⇒ 应当**跳过**它，直接走 B
    assert_eq!(post(&handle, &token, &chat_body()).await.0, 200);
    assert_eq!(a.request_count(), 2, "熔断打开后不该再打 A");
    assert_eq!(b.request_count(), 1, "第 3 个请求由 B 承接");

    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failure_event_carries_only_metadata() {
    // M16-S4 / P2-13：故障源从「503」换成「连不上的端口」——这条用例测的是**事件形状**
    // （只有元数据、不带密钥/prompt），与故障种类无关；换成连接层失败后它仍然测同一件事，
    // 而且这是新口径下**唯一**会「切走并记事件」的那一类。
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let (handle, token, failures, _observations) = start_routed_full(
        vec![dead_upstream(1, REF_A, 0.1), b.upstream(1.0)],
        long_cooldown(),
        UpstreamTimeout::default(),
        None,
        vec![(REF_A, KEY_A), (REF_B, KEY_B)],
        tianshu_relay_core::routing::SiteGuardPolicy::default(),
        None,
    )
    .await;

    assert_eq!(
        post(&handle, &token, &chat_body()).await.0,
        200,
        "连接层失败应当切到第二个上游"
    );

    // 断言全部在**同步块**里做完：`std::sync::MutexGuard` 绝不跨 `.await` 持有。
    // 跨 await 持锁在单线程 runtime 上会自锁，在多线程 runtime 上只是**碰巧**能过——
    // 一条会随调度变化的假绿（`clippy::await_holding_lock`）。
    {
        let events = failures.lock().unwrap();
        assert_eq!(events.len(), 1, "一次失败切换应当只写一条事件");
        let event = &events[0];
        assert_eq!(event.site_id, 1);
        assert_eq!(event.status, 502, "连接层失败没有状态码 ⇒ 按 502 记");
        assert_eq!(event.model, MODEL, "记的是**调用方请求的那个**模型名");

        // 结构上装不下别的东西（`GatewayFailure` 的字段是白名单），内容上也不许混进密钥
        let text = format!("{event:?}");
        assert!(!text.contains(KEY_A), "{text}");
        assert!(!text.contains(KEY_B), "{text}");
        assert!(!text.contains(&token), "{text}");
        assert!(!text.contains("Bearer"), "{text}");
        assert!(!text.contains("messages"), "不得带 prompt 正文: {text}");
    }

    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_response_wins_and_is_returned_as_is() {
    // M16-S4 / P2-13（旧用例 `exhausted_candidates_return_the_last_status`）：
    //   旧断言：两个上游都 503 ⇒ 「切到最后一个候选」再返回它的 503（B 被请求 1 次、两条事件）。
    //   新断言：**第一个响应就是终局** ⇒ 返回首选 A 的 503，B 不被请求，只记一条事件。
    //   为什么：503 可能已经计费；「候选耗尽」这个状态在新口径下只可能由**连接层失败**造成。
    let a = spawn_upstream_always(1, REF_A, "503 Service Unavailable");
    let b = spawn_upstream_always(2, REF_B, "503 Service Unavailable");
    let (handle, token, failures) = start_routed(&[(&a, 0.1), (&b, 1.0)], long_cooldown()).await;

    let (status, body) = post(&handle, &token, &chat_body()).await;

    assert_eq!(status, 503, "如实返回首选上游的状态码（不做 500/502 兜底）");
    assert!(
        body.contains("site1"),
        "返回的应当是**第一个**上游的响应: {body}"
    );
    assert_eq!(a.request_count(), 1);
    assert_eq!(b.request_count(), 0, "第二个上游不该被请求（P2-13）");
    assert_eq!(failures.lock().unwrap().len(), 1, "只记一条事件");

    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_connect_failures_still_return_502_with_the_last_reason() {
    // 「候选耗尽」在新口径下只剩这一条路径：**所有候选都是连接层失败**。
    // 客户端拿到 502 + 最后一次的真实原因（P3-5 的既有保证）。
    let (handle, token, failures, _observations) = start_routed_full(
        vec![dead_upstream(1, REF_A, 0.1), dead_upstream(2, REF_B, 1.0)],
        long_cooldown(),
        UpstreamTimeout::default(),
        None,
        vec![(REF_A, KEY_A), (REF_B, KEY_B)],
        tianshu_relay_core::routing::SiteGuardPolicy::default(),
        None,
    )
    .await;

    let (status, body) = post(&handle, &token, &chat_body()).await;

    assert_eq!(status, 502, "两个候选都连不上 ⇒ 502");
    assert!(
        body.contains("转发到上游失败"),
        "文案要带真实原因（不是空错误）: {body}"
    );
    assert_eq!(failures.lock().unwrap().len(), 2, "两次失败各记一条事件");

    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_model_404s_instead_of_falling_back() {
    // 路由非空但没有任何上游登记这个模型 ⇒ 404，且**不**回落 legacy 单上游
    // （回落会用一把用户没有路由过的密钥）
    let a = spawn_upstream_always(1, REF_A, "200 OK");
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let (handle, token, _failures) = start_routed(&[(&a, 0.1), (&b, 1.0)], long_cooldown()).await;

    let body = r#"{"model":"no-such-model","messages":[]}"#;
    let (status, resp) = post(&handle, &token, body).await;

    assert_eq!(status, 404);
    assert!(resp.contains("no-such-model"), "{resp}");
    assert_eq!(a.request_count(), 0, "不该请求任何上游");
    assert_eq!(b.request_count(), 0);

    handle.shutdown_and_wait().await;
}

/// **M7-S1 复审 P1-1 的回归**：`model` 是调用方自由文本，**可以是密钥形状**。
///
/// 出口 `store.insert_event` 原样入库（不做脱敏），所以脱敏必须在**值被创造的地方**完成——
/// 即 `report_failure` 里先过 `redact::scrub`。若把义务推给下游，密钥形状的自由文本
/// 会进事件表并随导出与审计外流（B-75 同类）。
///
/// 同时断言**另一半**：正常的模型名不得被整条吃掉（否则事件就失去了「这是哪个模型」的信息）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failure_event_scrubs_a_key_shaped_model() {
    const KEY_SHAPED: &str = "sk-PROBE-LEAK-0123456789abcdef";

    /// 起一个「只服务 `models` 里那些名字」的两上游网关
    /// （A = 连不上的端口、B 恒 200 —— M16-S4 / P2-13 之后「切走」只能由连接层失败触发）。
    async fn start_with_models(
        models: Vec<String>,
    ) -> (GatewayHandle, String, Failures, FakeUpstream) {
        let b = spawn_upstream_always(2, REF_B, "200 OK");
        let mut up_a = dead_upstream(1, REF_A, 0.1);
        up_a.models = models.clone();
        let mut up_b = b.upstream(1.0);
        up_b.models = models;

        let failures: Failures = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&failures);
        let mut keys = std::collections::HashMap::new();
        keys.insert(REF_A.to_string(), Zeroizing::new(KEY_A.to_string()));
        keys.insert(REF_B.to_string(), Zeroizing::new(KEY_B.to_string()));

        let handle = start(GatewayConfig {
            catalog: None,
            port: 0,
            token: generate_token(),
            key_id: None,
            site_id: 0,
            base_url: String::new(),
            api_key: zeroize::Zeroizing::new(String::new()),
            site_display_name: "路由模式".to_string(),
            route: RouteTable::new(vec![up_a, up_b]),
            breaker: long_cooldown(),
            keys_by_ref: keys,
            // M8-S1 新增的三个字段：这里都用默认 / 不启用，让既有用例的语义不变。
            upstream_timeout: UpstreamTimeout::default(),
            revoked_refs: None,
            on_observation: None,
            on_usage: None,
            budget_check: None,
            on_budget_breach: None,
            routing_rules: Vec::new(),
            upstream_proxy: None,
            legacy_key_ref: None,
            // M42-S1：请求体上限（既有用例用默认 16 MiB）
            max_request_bytes: tianshu_relay_core::gateway::DEFAULT_MAX_REQUEST_BYTES,
            // M39-S3：既有用例保持单候选（top_n=1）+ 默认 guard ⇒ 行为逐字不变
            lb_top_n: 1,
            max_attempts: 0,
            session_affinity: false,
            guard_policy: tianshu_relay_core::routing::SiteGuardPolicy::default(),
            runtime: None,
            on_failure: Some(Arc::new(move |f| {
                if let Ok(mut log) = sink.lock() {
                    log.push(f);
                }
            })),
        })
        .await
        .expect("网关应能启动");
        let token = handle.token.clone();
        (handle, token, failures, b)
    }

    // ---- ① 密钥形状的模型名：必须被打码 ----
    let (handle, token, failures, _b) = start_with_models(vec![KEY_SHAPED.to_string()]).await;
    let body = format!(r#"{{"model":"{KEY_SHAPED}","messages":[]}}"#);
    assert_eq!(
        post(&handle, &token, &body).await.0,
        200,
        "应当切到第二个上游"
    );

    {
        let events = failures.lock().unwrap();
        assert_eq!(events.len(), 1, "一次失败切换写一条事件");
        let model = &events[0].model;
        assert!(
            !model.contains("PROBE-LEAK"),
            "密钥形状的模型名必须被打码，实际: {model}"
        );
        assert!(!model.contains("0123456789abcdef"), "实际: {model}");
        assert_eq!(model, "sk-***", "打码形态应当是 scrub 的标准掩码");
        // 事件里其余字段不受影响
        assert_eq!(events[0].site_id, 1);
        assert_eq!(events[0].status, 502, "连接层失败没有状态码 ⇒ 按 502 记");
    }
    handle.shutdown_and_wait().await;

    // ---- ② 正常模型名：逐字保留，可用信息没被整条吃掉 ----
    let (handle, token, failures, _b) = start_with_models(vec![MODEL.to_string()]).await;
    assert_eq!(post(&handle, &token, &chat_body()).await.0, 200);
    {
        let events = failures.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].model, MODEL,
            "正常模型名必须逐字保留（否则事件读不出「这是哪个模型」）"
        );
    }
    handle.shutdown_and_wait().await;
}

// ============================================================ M8-S1：§3.5 的调试余项

/// 起一个**延迟 `delay` 之后**才回 `status_line` 的假上游。
///
/// 用途：制造「失败本身比冷却期还慢」的形态——§3.5-1 的缺陷只在这种输入下显形。
fn spawn_upstream_delayed(
    site_id: i64,
    key_ref: &str,
    status_line: &str,
    delay: Duration,
) -> FakeUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取地址");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    let status_line = status_line.to_string();

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let raw = read_request(&mut stream);
            if let Ok(mut log) = recorder.lock() {
                log.push(raw);
            }
            thread::sleep(delay);
            let body = format!(r#"{{"from":"site{site_id}"}}"#);
            let response = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    FakeUpstream {
        site_id,
        base_url: format!("http://{addr}"),
        key_ref: key_ref.to_string(),
        seen,
    }
}

/// 起一个**接了连接但永不回应**的假上游：§3.5-2 要抓的就是这种病态形态。
fn spawn_stalled_upstream(site_id: i64, key_ref: &str) -> FakeUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取地址");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);

    thread::spawn(move || {
        let mut held: Vec<TcpStream> = Vec::new();
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let raw = read_request(&mut stream);
            if let Ok(mut log) = recorder.lock() {
                log.push(raw);
            }
            // **不回任何字节**，把连接攥在手里。连接不断，上游就没有「错误」——
            // 只有超时才能把它判成故障。
            held.push(stream);
        }
    });

    FakeUpstream {
        site_id,
        base_url: format!("http://{addr}"),
        key_ref: key_ref.to_string(),
        seen,
    }
}

/// 与 [`start_routed`] 同形，但可以调超时 / 给已回收集合 / 收集观测。
async fn start_routed_with(
    upstreams: &[(&FakeUpstream, f64)],
    breaker: BreakerPolicy,
    timeout: UpstreamTimeout,
    revoked: Option<Vec<String>>,
    keys: Vec<(&str, &str)>,
) -> (GatewayHandle, String, Failures, Observations) {
    let ups: Vec<Upstream> = upstreams
        .iter()
        .map(|(u, rate)| u.upstream(*rate))
        .collect();
    start_routed_full(
        ups,
        breaker,
        timeout,
        revoked,
        keys,
        tianshu_relay_core::routing::SiteGuardPolicy::default(),
        None,
    )
    .await
}

fn body_with_model() -> String {
    format!(r#"{{"model":"{MODEL}","messages":[]}}"#)
}

#[tokio::test]
async fn breaker_opens_even_when_the_failure_is_slower_than_the_cooldown() {
    // §3.5-1（DEBUG 报告 §2.1）：`opened_at` 用的是**请求开始**时刻时，
    // 一次比冷却期还慢的失败（真实形态：Cloudflare 524 ≈ 100s > 冷却 60s）记下的那一刻
    // 冷却就已经「过期」⇒ 这个上游**永远熔断不了**。
    //
    // 判据（章程 §3.5-1 原文）：打 5 次，A 只应被调用 **3** 次（threshold = 3）。
    let cooldown = Duration::from_millis(50);
    let slow = Duration::from_millis(150); // > cooldown ⇒ 失败本身就跨过了冷却期
    let a = spawn_upstream_delayed(1, REF_A, "503 Service Unavailable", slow);
    let b = spawn_upstream_always(2, REF_B, "200 OK");

    let (handle, token, _failures, _obs) = start_routed_with(
        &[(&a, 1.0), (&b, 2.0)],
        BreakerPolicy {
            threshold: 3,
            cooldown,
        },
        UpstreamTimeout::default(),
        None,
        vec![(REF_A, KEY_A), (REF_B, KEY_B)],
    )
    .await;

    for (index, expected) in [503u16, 503, 503, 200, 200].into_iter().enumerate() {
        let (status, _) = post(&handle, &token, &body_with_model()).await;
        // M16-S4 / P2-13：前 3 次 A 是首选且未熔断 ⇒ 503 **原样返回**（旧断言是 200，
        // 因为当时 503 会切到 B）；第 4、5 次 A 已 Open ⇒ 被跳过、由 B 接住（200）。
        assert_eq!(status, expected, "第 {} 次请求的状态码", index + 1);
    }
    handle.shutdown_and_wait().await;

    assert_eq!(
        a.request_count(),
        3,
        "A 应当在第 3 次失败后熔断住；修复前（opened_at = 请求开始）它会被调用 5 次——\
         因为每次失败的耗时都超过了冷却期，冷却在记下的那一刻就已过期"
    );
}

#[tokio::test]
async fn the_last_sendable_candidate_returns_its_own_status() {
    // §3.5-3（DEBUG 报告 §2.3）：`is_last` 把**发不出去**的候选也计进去，
    // 于是「最后一个真的发得出去的候选」被误判成「不是最后一个」，它的响应被丢掉、
    // 继续往下走 → 502。症状：唯一可用上游返回 429，用户看到 502，`Retry-After` 被吞掉。
    //
    // M16-S4 / P3-9：让 B「发不出去」的方式从**缺明文**改成**已回收**——
    // 缺明文的 route 现在会在 `start()` 就被拒（`route_and_keys_by_ref_must_agree`），
    // 而「已回收」是合法状态。被测性质不变：A 仍然是最后一个**发得出去**的候选。
    let a = spawn_upstream_always(1, REF_A, "429 Too Many Requests");
    let b = spawn_upstream_always(2, REF_B, "200 OK");

    let (handle, token, _failures, _obs) = start_routed_with(
        &[(&a, 1.0), (&b, 2.0)],
        BreakerPolicy {
            threshold: 3,
            cooldown: Duration::from_secs(60),
        },
        UpstreamTimeout::default(),
        // **B 标记为已回收**：它进不了 sendable，因此 A 就是最后一个发得出去的候选。
        Some(vec![REF_B.to_string()]),
        vec![(REF_A, KEY_A), (REF_B, KEY_B)],
    )
    .await;

    let (status, _) = post(&handle, &token, &body_with_model()).await;
    handle.shutdown_and_wait().await;

    assert_eq!(
        status, 429,
        "A 是最后一个发得出去的候选 ⇒ 必须如实返回它的 429；\
         修复前会继续往下走，最终 502（B 发不出去）"
    );
    assert_eq!(b.request_count(), 0, "B 已回收，不该被请求");
}

#[tokio::test]
async fn a_missing_plaintext_is_refused_at_startup() {
    // §10（M7 审计 D-2）+ M16-S4 / P3-9：缺明文的候选原来**静默** `continue`，
    // 症状是「每个上游都跳过 → 502」，根因（构造方忘填密钥映射）看不见。
    // 现在前移到 `start()`：**这种配置根本起不来**，错误文案直接说根因。
    //
    // 旧用例（`a_missing_plaintext_is_visible_not_silent`）断言的是运行期 502 + status=0 事件；
    // 那条路径保留为**纵深防御**（`is_sendable` 仍然同时查明文与回收），
    // 但既然启动就拒绝，运行期就构造不出这种状态了。
    let a = spawn_upstream_always(1, REF_A, "200 OK");

    let err = start(GatewayConfig {
        catalog: None,
        port: 0,
        token: generate_token(),
        key_id: None,
        site_id: 0,
        base_url: String::new(),
        api_key: Zeroizing::new(String::new()),
        site_display_name: "路由模式".to_string(),
        route: RouteTable::new(vec![a.upstream(1.0)]),
        breaker: BreakerPolicy {
            threshold: 3,
            cooldown: Duration::from_secs(60),
        },
        // 故意不给任何明文。
        keys_by_ref: std::collections::HashMap::new(),
        upstream_timeout: UpstreamTimeout::default(),
        revoked_refs: None,
        on_observation: None,
        on_usage: None,
        budget_check: None,
        on_budget_breach: None,
        routing_rules: Vec::new(),
        upstream_proxy: None,
        legacy_key_ref: None,
        // M42-S1：请求体上限（既有用例用默认 16 MiB）
        max_request_bytes: tianshu_relay_core::gateway::DEFAULT_MAX_REQUEST_BYTES,
        // M39-S3：既有用例保持单候选（top_n=1）+ 默认 guard ⇒ 行为逐字不变
        lb_top_n: 1,
        max_attempts: 0,
        session_affinity: false,
        guard_policy: tianshu_relay_core::routing::SiteGuardPolicy::default(),
        runtime: None,
        on_failure: None,
    })
    .await
    .expect_err("缺明文的 route 必须在 start() 就被拒（P3-9）");

    let text = err.to_string();
    assert!(text.contains("密钥映射"), "文案要说清根因: {text}");
    assert!(
        !text.contains(REF_A) && !text.contains("kr/key"),
        "文案里不得出现 key_ref 原文（引用本身是线索）: {text}"
    );
    assert_eq!(a.request_count(), 0, "拒绝启动 ⇒ 一个请求都不会发出去");
}

#[tokio::test]
async fn all_candidates_open_still_produces_an_event() {
    // §9 第 2 条：`eligible.is_empty()` 是一次**没有发出任何请求**的失败，
    // 它也必须可见——否则用户看到 503 而事件表里什么都没有。
    let a = spawn_upstream_always(1, REF_A, "503 Service Unavailable");

    let (handle, token, failures, _obs) = start_routed_with(
        &[(&a, 1.0)],
        BreakerPolicy {
            threshold: 1, // 一次失败就熔断
            cooldown: Duration::from_secs(60),
        },
        UpstreamTimeout::default(),
        None,
        vec![(REF_A, KEY_A)],
    )
    .await;

    let (first, _) = post(&handle, &token, &body_with_model()).await;
    assert_eq!(first, 503, "第一次是上游真的返回了 503");
    let after_first = failures.lock().expect("锁").len();

    let (second, _) = post(&handle, &token, &body_with_model()).await;
    handle.shutdown_and_wait().await;

    assert_eq!(second, 503, "候选全被熔断 ⇒ 503");
    let log = failures.lock().expect("锁").clone();
    assert!(
        log.len() > after_first,
        "「一个候选都没发出去」也必须产生事件（修复前这里静默）"
    );
    assert_eq!(a.request_count(), 1, "第二次不该再打到 A");
    assert!(
        log.iter().any(|f| f.status == 0),
        "全熔断的失败没有状态码，用 0 哨兵: {log:?}"
    );
}

#[tokio::test]
async fn a_revoked_key_ref_is_never_used() {
    // §3.5-5 / DEBUG §1.2 残留：`ensure_not_revoked` 只拦**新启动**。
    // 网关运行期间某把 key 被回收后，它仍在 `keys_by_ref` 里 ⇒ 继续被使用，
    // agent 收到的是 401。
    let a = spawn_upstream_always(1, REF_A, "200 OK");
    let b = spawn_upstream_always(2, REF_B, "200 OK");

    let (handle, token, failures, _obs) = start_routed_with(
        &[(&a, 1.0), (&b, 2.0)],
        BreakerPolicy {
            threshold: 3,
            cooldown: Duration::from_secs(60),
        },
        UpstreamTimeout::default(),
        Some(vec![REF_A.to_string()]),
        vec![(REF_A, KEY_A), (REF_B, KEY_B)],
    )
    .await;

    let (status, _) = post(&handle, &token, &body_with_model()).await;
    handle.shutdown_and_wait().await;

    assert_eq!(status, 200, "应当切到 B");
    assert_eq!(a.request_count(), 0, "已回收的 key 一次都不该被使用");
    assert_eq!(b.request_count(), 1);
    // **请求成功时不上报**：`report_failure` 同时喂熔断，而「某个候选被跳过」
    // 在请求成功时不是故障——那时也上报，一个长期缺明文/已回收的候选会把熔断喂开。
    assert!(
        failures.lock().expect("锁").is_empty(),
        "请求成功了就不该产生失败事件（否则会误喂熔断）"
    );
}

#[tokio::test]
async fn a_revoked_only_candidate_reports_why_it_was_skipped() {
    // 与上一条互补：**没有别的候选可去**时，跳过原因必须可见。
    // 契约的原话是「不得静默 **502**」——指的就是这条路径。
    let a = spawn_upstream_always(1, REF_A, "200 OK");

    let (handle, token, failures, _obs) = start_routed_with(
        &[(&a, 1.0)],
        BreakerPolicy {
            threshold: 3,
            cooldown: Duration::from_secs(60),
        },
        UpstreamTimeout::default(),
        Some(vec![REF_A.to_string()]),
        vec![(REF_A, KEY_A)],
    )
    .await;

    let (status, _) = post(&handle, &token, &body_with_model()).await;
    handle.shutdown_and_wait().await;

    assert_eq!(status, 502);
    assert_eq!(a.request_count(), 0);
    let log = failures.lock().expect("锁").clone();
    assert!(
        log.iter().any(|f| f.site_id == 1 && f.status == 0),
        "被跳过的原因要可见（与「缺明文」文案不同）: {log:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_in_flight_during_stop_never_reaches_the_next_upstream() {
    // P3-3 / DEBUG-REPORT-v3 §3-3：stop 返回后，在途请求的下一次尝试**仍然**会把
    // 下一个站点的密钥发出去。修法：句柄在发停止信号**之前**置「正在停止」标志，
    // 请求路径在**每次上游尝试之前**查它。
    //
    // 构造：A 延迟 300ms 才回 429（429 是可重放的那一类，所以「没有闸门」时它一定会
    // 切到 B——这正是这条用例能红的原因）；B 恒 200。等 A 真的收到请求之后再 stop，
    // 于是停止信号落在「A 已收到、B 还没发」的窗口里。
    let a = spawn_upstream_delayed(
        1,
        REF_A,
        "429 Too Many Requests",
        Duration::from_millis(300),
    );
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let (handle, token, _failures, _observations) = start_routed_with(
        &[(&a, 1.0), (&b, 2.0)],
        long_cooldown(),
        UpstreamTimeout::default(),
        None,
        vec![(REF_A, KEY_A), (REF_B, KEY_B)],
    )
    .await;

    let url = format!("http://{}", handle.addr);
    let token_for_task = token.clone();
    let request = tokio::spawn(async move {
        tokio::task::spawn_blocking(move || {
            http_post(
                &url,
                &token_for_task,
                "/v1/chat/completions",
                &body_with_model(),
            )
        })
        .await
        .expect("阻塞任务")
    });

    // 等 A 真的收到请求（不要用固定 sleep 猜时序）
    for _ in 0..200 {
        if a.request_count() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(a.request_count(), 1, "前提：首选上游必须先收到这次请求");

    // 停止（`shutdown()` 只发信号、不等——正是最容易漏的那条路径）
    handle.shutdown();

    let (status, body) = request.await.expect("请求任务");
    assert_eq!(
        status, 503,
        "停止期间的下一次尝试必须被闸门拒绝（而不是把 429 重放给 B）: {body}"
    );
    assert!(
        body.contains("网关正在停止"),
        "文案要说清是本地状态、不是上游故障: {body}"
    );
    assert_eq!(
        b.request_count(),
        0,
        "**第二个上游一次都不该被请求**——停止之后不许再带出任何密钥（P3-3）"
    );
}

#[tokio::test]
async fn a_stalled_upstream_times_out_and_is_not_replayed() {
    // §3.5-2（DEBUG 报告 §2.2）：上游客户端原来**没有任何超时**——上游接了连接却不回应时，
    // 请求永远挂着，既不判死也不喂熔断（实测：卡 8.5s、失败事件 0 条）。
    //
    // M16-S4 / P2-13：读超时**不重放**（请求已经送出去了，上游可能已经跑完并计费），
    // 所以这条用例的期望从「切到 B 拿到 200」改成「按 502 如实返回、B 一次都不被请求」；
    // 「超时判死」这个被测性质没变——判死的证据是「请求在上界内返回 + 事件 + 熔断 + 观测」。
    let stalled = spawn_stalled_upstream(1, REF_A);
    let b = spawn_upstream_always(2, REF_B, "200 OK");

    let (handle, token, failures, obs) = start_routed_with(
        &[(&stalled, 1.0), (&b, 2.0)],
        BreakerPolicy {
            threshold: 3,
            cooldown: Duration::from_secs(60),
        },
        // 测试把 read 调小到 200ms 来复现判据。**这不代表生产上切换很快**：
        // 生产默认是 240s（M9-S5 用真实上游标定过，见 `UpstreamTimeout::default`）。
        UpstreamTimeout {
            connect: Duration::from_millis(200),
            read: Duration::from_millis(200),
        },
        None,
        vec![(REF_A, KEY_A), (REF_B, KEY_B)],
    )
    .await;

    let started = std::time::Instant::now();
    let (status, _) = post(&handle, &token, &body_with_model()).await;
    let elapsed = started.elapsed();
    handle.shutdown_and_wait().await;

    assert_eq!(status, 502, "读超时按 502 如实返回（不再重放到 B）");
    assert!(
        elapsed < Duration::from_secs(2),
        "卡住的上游必须被 read 超时判死，而不是让请求挂着（实测 {elapsed:?}）"
    );
    assert_eq!(
        b.request_count(),
        0,
        "**第二个上游一次都不该被请求**（读超时可能已计费 ⇒ 不重放）"
    );
    let log = failures.lock().expect("锁").clone();
    assert!(
        log.iter()
            .any(|f| f.site_id == 1 && f.reason.contains("不重放")),
        "超时也是一次失败，必须喂熔断并产生事件，且写明不重放的理由: {log:?}"
    );

    // §5.3：观测出口只把**成功**的延迟记进 last-value，但失败的尝试也要上报。
    let seen = obs.lock().expect("锁").clone();
    assert!(
        seen.iter().any(|o| o.site_id == 1 && !o.ok),
        "失败尝试也要上报观测（由服务侧决定不采信）: {seen:?}"
    );
    assert!(
        !seen.iter().any(|o| o.site_id == 2),
        "B 没被请求过，就不该有它的观测（P2-13 之后这里不再有成功观测）: {seen:?}"
    );
}

// ============================================================ /health 端点（复审 F1）

/// 极简 HTTP 客户端：GET /health，令牌可选（测「缺失」「错误」「正确」三态）。
///
/// 不用 `read_to_end`：`/health` 由 axum 直接回，不走假上游，keep-alive 下连接不会 EOF，
/// `read_to_end` 会一直阻塞。按 `Content-Length` 读够即返回，外加读超时兜底。
fn http_get_health(url: &str, token: Option<&str>) -> (u16, String) {
    let without_scheme = url.trim_start_matches("http://");
    let mut stream = TcpStream::connect(without_scheme).expect("连接网关");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("设读超时");
    let auth = match token {
        Some(t) => format!("Authorization: Bearer {t}\r\n"),
        None => String::new(),
    };
    let request = format!(
        "GET /health HTTP/1.1\r\nHost: {without_scheme}\r\n{auth}Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).expect("发送请求");
    stream.flush().ok();
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf).to_string();
                if let Some(head_end) = text.find("\r\n\r\n") {
                    let cl = text[..head_end]
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    if buf.len() >= head_end + 4 + cl {
                        break;
                    }
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(_) => break,
        }
    }
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

/// `http_get_health` 的 async 包装：网关与测试共享 tokio runtime，阻塞读必须丢到
/// `spawn_blocking`，否则 current_thread 下会把 axum 卡死（网关等线程让出、测试等响应）。
async fn health_get(handle: &GatewayHandle, token: Option<&str>) -> (u16, String) {
    let url = format!("http://{}", handle.addr);
    let token = token.map(|t| t.to_string());
    tokio::task::spawn_blocking(move || http_get_health(&url, token.as_deref()))
        .await
        .expect("阻塞任务")
}

/// 复审 F1 / P3-6：`/health` 端点也走 `constant_time_eq`，与 `/proxy` 同口径。
/// 正确令牌放行（200 + `ok:true`），错误或缺失令牌一律 401——行为与 proxy 一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_endpoint_checks_token_like_proxy() {
    let up = spawn_upstream_always(1, REF_A, "200 OK");
    let (handle, token, _failures) = start_routed(&[(&up, 1.0)], BreakerPolicy::default()).await;

    let (ok_status, ok_body) = health_get(&handle, Some(&token)).await;
    assert_eq!(ok_status, 200, "正确令牌应放行 /health: {ok_body}");
    assert!(
        ok_body.contains("\"ok\":true"),
        "body 应含 ok=true: {ok_body}"
    );

    let (wrong_status, _) = health_get(&handle, Some("wrong-token-shape")).await;
    assert_eq!(wrong_status, 401, "错误令牌应拒 /health");

    let (none_status, _) = health_get(&handle, None).await;
    assert_eq!(none_status, 401, "缺失令牌应拒 /health");

    handle.shutdown_and_wait().await;
}

/// 起一个回**自定义 body** 的假上游（M40-S1：验证 usage 归因时 body 里必须带 usage）。
fn spawn_upstream_with_body(
    site_id: i64,
    key_ref: &str,
    status_line: &str,
    body: String,
) -> FakeUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取地址");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    let status_line = status_line.to_string();

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let raw = read_request(&mut stream);
            if let Ok(mut log) = recorder.lock() {
                log.push(raw);
            }
            let response = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    FakeUpstream {
        site_id,
        base_url: format!("http://{addr}"),
        key_ref: key_ref.to_string(),
        seen,
    }
}

/// M40-S1：`key_id` 必须来自**实际命中的上游**，而不是启动参数里的 config 那把。
///
/// 场景：首选 A（`Upstream.key_id = 101`）回 429 被重放；真正命中的是 B
/// （`Upstream.key_id = 202`）⇒ usage 的 `key_id` 必须是 202，`attempts = 2`。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn usage_key_id_comes_from_the_hit_upstream() {
    let a = spawn_upstream_always(1, REF_A, "429 Too Many Requests");
    let b = spawn_upstream_with_body(
        2,
        REF_B,
        "200 OK",
        r#"{"usage":{"prompt_tokens":5,"completion_tokens":6,"total_tokens":11}}"#.to_string(),
    );
    let mut up_a = a.upstream(0.1);
    up_a.key_id = Some(101);
    let mut up_b = b.upstream(1.0);
    up_b.key_id = Some(202);

    let usage: UsageLog = Arc::new(Mutex::new(Vec::new()));
    let (handle, token, _failures, _observations) = start_routed_full(
        vec![up_a, up_b],
        long_cooldown(),
        UpstreamTimeout::default(),
        None,
        vec![(REF_A, KEY_A), (REF_B, KEY_B)],
        tianshu_relay_core::routing::SiteGuardPolicy::default(),
        Some(Arc::clone(&usage)),
    )
    .await;

    let (status, body) = post(&handle, &token, &chat_body()).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(a.request_count(), 1, "首选应当先被尝试");
    assert_eq!(b.request_count(), 1, "429 之后应当重放到第二站");

    // flush 发生在网关读完上游 body 时；客户端读完后最多等 1 秒。
    for _ in 0..50 {
        if !usage.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    {
        let log = usage.lock().unwrap();
        assert_eq!(log.len(), 1, "必须恰好一条 usage");
        assert_eq!(
            log[0].key_id,
            Some(202),
            "必须是**实际命中的第二站**的 key（不是 config 的 101）"
        );
        assert_eq!(log[0].site_id, 2);
        assert_eq!(log[0].attempts, 2, "命中的是第二个候选");
        assert_eq!(log[0].status, 200);
        assert!(!log[0].stream);
        assert!(log[0].at > 0, "at 必须由系统时钟填入");
    }
    handle.shutdown_and_wait().await;
}

/// 脚本化假上游（M40-S1 P1 回归测试）：**第一个**连接回 `first_status`，
/// 但 body 延迟 `delay` 后才写；之后的连接一律 200 + `{"from":"siteN"}`。
///
/// 用途：让「非 2xx 的响应 body 还没读完」这个状态可以被确定性地观察到，
/// 从而验证 lease 是否覆盖了整个 body（M39-S3 的并发保护）。
fn spawn_upstream_slow_first(
    site_id: i64,
    key_ref: &str,
    first_status: &str,
    delay: Duration,
) -> FakeUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取地址");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    let first_status = first_status.to_string();

    thread::spawn(move || {
        for (index, stream) in listener.incoming().enumerate() {
            let Ok(mut stream) = stream else { continue };
            let raw = read_request(&mut stream);
            if let Ok(mut log) = recorder.lock() {
                log.push(raw);
            }
            if index == 0 {
                let body = b"slow-500-body";
                let head = format!(
                    "HTTP/1.1 {first_status}\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.flush();
                // 头已发出、body 还在路上：此刻 lease 必须仍被占用。
                thread::sleep(delay);
                let _ = stream.write_all(body);
                let _ = stream.flush();
            } else {
                let body = format!(r#"{{"from":"site{site_id}"}}"#);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        }
    });

    FakeUpstream {
        site_id,
        base_url: format!("http://{addr}"),
        key_ref: key_ref.to_string(),
        seen,
    }
}

/// 发请求并**只读到响应头**，返回（仍打开的连接, 状态码）。
fn open_and_read_headers(url: &str, token: &str, path: &str, body: &str) -> (TcpStream, u16) {
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
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) => buf.push(byte[0]),
        }
    }
    let head = String::from_utf8_lossy(&buf).to_string();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    (stream, status)
}

/// M40-S1 复审 P1：**非 2xx 的 body 也必须占着站点 lease**，直到 body 读完。
///
/// 场景：`max_concurrency = 1`，上游第一次回「慢 500」（头发完、body 延迟 800ms）。
/// - 第一请求只读头不读 body ⇒ 第二请求必须被本地保护拒绝（429 `local_rate_limited`）；
/// - 读完第一请求的 body ⇒ lease 归还，第三请求必须被放行（脚本化上游回 200）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_success_body_holds_the_site_lease_until_read() {
    let a = spawn_upstream_slow_first(
        1,
        REF_A,
        "500 Internal Server Error",
        Duration::from_millis(800),
    );
    let (handle, token, _failures, _obs) = start_routed_full(
        vec![a.upstream(1.0)],
        long_cooldown(),
        UpstreamTimeout::default(),
        None,
        vec![(REF_A, KEY_A)],
        tianshu_relay_core::routing::SiteGuardPolicy {
            max_concurrency: 1,
            rate_limit_per_sec: 0,
            rate_burst: 0, // M46-S3：机械补字段，行为不变
        },
        None,
    )
    .await;

    let url = format!("http://{}", handle.addr);
    let (mut first, status1) =
        open_and_read_headers(&url, &token, "/v1/chat/completions", &chat_body());
    assert_eq!(status1, 500, "第一请求应拿到上游的 500");

    // body 还没读完 ⇒ lease 必须仍被占用 ⇒ 第二请求被本地并发保护拒绝。
    let (status2, body2) = post(&handle, &token, &chat_body()).await;
    assert_eq!(
        status2, 429,
        "body 未读完时第二请求必须被本地保护拒绝: {body2}"
    );
    assert!(
        body2.contains("local_rate_limited"),
        "必须是本地限流而不是上游 429: {body2}"
    );

    // 读完第一条 body（lease 归还）。
    let mut rest = Vec::new();
    first.read_to_end(&mut rest).expect("读完 body");
    drop(first);

    // lease 已归还 ⇒ 第三请求放行（脚本化上游第二次起回 200）。
    let (status3, body3) = post(&handle, &token, &chat_body()).await;
    assert_eq!(status3, 200, "lease 归还后应放行: {body3}");
    assert!(body3.contains("site1"), "{body3}");

    handle.shutdown_and_wait().await;
}

// ============================================================ DELIVERY-P2-10：优先级备用顺序
//
// 语义（见 spec）：命中路由规则时，备用尝试顺序按规则 `siteIds` 数组顺序；
// 首选仍由加权轮转定出（本文件用 lb_top_n=1 + 倍率拉开派生顺序，使首选确定为 1 号站）。
// 触发切换的仍是既有可重放类（429 / 连接层失败）；401 / 5xx / 读超时不切换，
// 优先级不得推翻这些口径——下面每条否定用例都钉住一条。
//
// 假上游与既有用例同款（本地 TcpListener，不联网、不用真实密钥与真实站点）。

const PRIORITY_TOKEN: &str = "kr-gw-p10-labeled-token-0123456789abcdef";

fn seed_priority_token(handle: &GatewayHandle) {
    handle.set_tokens(vec![GatewayTokenEntry {
        id: 1,
        token_hash: sha256_hex(PRIORITY_TOKEN),
        label: "codex".to_string(),
        grace_until: None,
    }]);
}

/// P2-10 专用构造点：既有 `start_routed_full` 的 `routing_rules` 恒为空、`lb_top_n` 恒为 1、
/// `max_attempts` 恒为 0，改它会牵动全文件调用点；这里单独立一份，只给本节用例用。
/// 派生顺序由倍率拉开：1 号站 0.1、2 号站 0.5、3 号站 1.0 ⇒ 派生顺序恒为 [1, 2, 3]，
/// lb_top_n=1 ⇒ 首选恒为 1 号站；规则顺序 [3, 2, 1] 与派生顺序完全相反，
/// 于是「备用先打谁」一眼可辨。
async fn start_priority_routed(
    ups: Vec<Upstream>,
    rules: Vec<RoutingRule>,
    max_attempts: usize,
    timeout: UpstreamTimeout,
    breaker: BreakerPolicy,
) -> GatewayHandle {
    let mut map = std::collections::HashMap::new();
    map.insert(REF_A.to_string(), Zeroizing::new(KEY_A.to_string()));
    map.insert(REF_B.to_string(), Zeroizing::new(KEY_B.to_string()));
    map.insert(REF_C.to_string(), Zeroizing::new(KEY_C.to_string()));
    start(GatewayConfig {
        catalog: None,
        port: 0,
        token: generate_token(),
        key_id: None,
        site_id: 0,
        base_url: String::new(),
        api_key: Zeroizing::new(String::new()),
        site_display_name: "优先级备用".to_string(),
        route: RouteTable::new(ups),
        breaker,
        keys_by_ref: map,
        upstream_timeout: timeout,
        revoked_refs: None,
        on_observation: None,
        on_usage: None,
        budget_check: None,
        on_budget_breach: None,
        routing_rules: rules,
        upstream_proxy: None,
        legacy_key_ref: None,
        max_request_bytes: tianshu_relay_core::gateway::DEFAULT_MAX_REQUEST_BYTES,
        lb_top_n: 1,
        max_attempts,
        session_affinity: false,
        guard_policy: tianshu_relay_core::routing::SiteGuardPolicy::default(),
        runtime: None,
        on_failure: None,
    })
    .await
    .expect("网关应能启动")
}

fn priority_rule() -> Vec<RoutingRule> {
    vec![RoutingRule {
        agent_label: "codex".to_string(),
        site_ids: vec![3, 2, 1],
    }]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn priority_rule_orders_backup_attempts_after_a_429() {
    // 派生备用顺序是 [2, 3]，规则备用顺序是 [3, 2]：1 号站 429 之后必须先打 3 号站。
    let a = spawn_upstream_always(1, REF_A, "429 Too Many Requests");
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let c = spawn_upstream_always(3, REF_C, "200 OK");
    let handle = start_priority_routed(
        vec![a.upstream(0.1), b.upstream(0.5), c.upstream(1.0)],
        priority_rule(),
        0,
        UpstreamTimeout::default(),
        long_cooldown(),
    )
    .await;
    seed_priority_token(&handle);

    let (status, body) = post(&handle, PRIORITY_TOKEN, &chat_body()).await;
    handle.shutdown_and_wait().await;

    assert_eq!(status, 200, "备用应当接住: {body}");
    assert!(
        body.contains("site3"),
        "备用首选应是规则第一位的 3 号站: {body}"
    );
    assert_eq!(a.request_count(), 1, "首选 1 号站应被试过一次");
    assert_eq!(c.request_count(), 1, "规则备用第一位 3 号站应被试过一次");
    assert_eq!(b.request_count(), 0, "派生顺序的下一位 2 号站不该被抢先");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn priority_chain_continues_in_priority_order() {
    // 1 号站 429 → 3 号站 429 → 2 号站 200：整条链都按规则顺序走。
    let a = spawn_upstream_always(1, REF_A, "429 Too Many Requests");
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let c = spawn_upstream_always(3, REF_C, "429 Too Many Requests");
    let handle = start_priority_routed(
        vec![a.upstream(0.1), b.upstream(0.5), c.upstream(1.0)],
        priority_rule(),
        0,
        UpstreamTimeout::default(),
        long_cooldown(),
    )
    .await;
    seed_priority_token(&handle);

    let (status, body) = post(&handle, PRIORITY_TOKEN, &chat_body()).await;
    handle.shutdown_and_wait().await;

    assert_eq!(status, 200, "链尾应当接住: {body}");
    assert!(body.contains("site2"), "链尾应是 2 号站: {body}");
    assert_eq!(a.request_count(), 1);
    assert_eq!(c.request_count(), 1);
    assert_eq!(b.request_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn priority_does_not_apply_without_a_matching_rule() {
    // 对照：不播种带 label 的令牌 ⇒ legacy 路径恒不命中规则，备用顺序仍是派生顺序 [2, 3]。
    let a = spawn_upstream_always(1, REF_A, "429 Too Many Requests");
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let c = spawn_upstream_always(3, REF_C, "200 OK");
    let handle = start_priority_routed(
        vec![a.upstream(0.1), b.upstream(0.5), c.upstream(1.0)],
        priority_rule(),
        0,
        UpstreamTimeout::default(),
        long_cooldown(),
    )
    .await;
    let legacy = handle.token.clone();

    let (status, body) = post(&handle, &legacy, &chat_body()).await;
    handle.shutdown_and_wait().await;

    assert_eq!(status, 200, "备用应当接住: {body}");
    assert!(
        body.contains("site2"),
        "未命中规则时备用应是派生下一位 2 号站: {body}"
    );
    assert_eq!(a.request_count(), 1);
    assert_eq!(b.request_count(), 1);
    assert_eq!(c.request_count(), 0, "规则顺序在未命中时不得生效");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn priority_never_overrides_a_401() {
    // 401 是凭证问题：优先级再高也不得拿别的站点的密钥去试（既有红线，本项不碰）。
    let a = spawn_upstream_always(1, REF_A, "401 Unauthorized");
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let c = spawn_upstream_always(3, REF_C, "200 OK");
    let handle = start_priority_routed(
        vec![a.upstream(0.1), b.upstream(0.5), c.upstream(1.0)],
        priority_rule(),
        0,
        UpstreamTimeout::default(),
        long_cooldown(),
    )
    .await;
    seed_priority_token(&handle);

    let (status, _) = post(&handle, PRIORITY_TOKEN, &chat_body()).await;
    handle.shutdown_and_wait().await;

    assert_eq!(status, 401, "401 必须原样返回");
    assert_eq!(a.request_count(), 1);
    assert_eq!(
        c.request_count(),
        0,
        "401 时规则第一位 3 号站一次都不该被请求"
    );
    assert_eq!(b.request_count(), 0, "401 时 2 号站也不该被请求");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn priority_stops_at_max_attempts() {
    // 预算：max_attempts=2 ⇒ 链 1→3→2 只走到 3，2 号站不被试，返回第二条 429。
    let a = spawn_upstream_always(1, REF_A, "429 Too Many Requests");
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let c = spawn_upstream_always(3, REF_C, "429 Too Many Requests");
    let handle = start_priority_routed(
        vec![a.upstream(0.1), b.upstream(0.5), c.upstream(1.0)],
        priority_rule(),
        2,
        UpstreamTimeout::default(),
        long_cooldown(),
    )
    .await;
    seed_priority_token(&handle);

    let (status, body) = post(&handle, PRIORITY_TOKEN, &chat_body()).await;
    handle.shutdown_and_wait().await;

    assert_eq!(status, 429, "预算耗尽时应返回最后一条真实 429: {body}");
    assert_eq!(a.request_count(), 1);
    assert_eq!(c.request_count(), 1);
    assert_eq!(b.request_count(), 0, "预算耗尽后不得再试下一个备用");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_failed_error_lists_attempted_sites() {
    // 全部连接失败 ⇒ 502 尾巴必须列出实际尝试过的站点，且不带任何密钥材料。
    let handle = start_priority_routed(
        vec![dead_upstream(1, REF_A, 0.1), dead_upstream(2, REF_B, 1.0)],
        priority_rule(),
        0,
        UpstreamTimeout::default(),
        long_cooldown(),
    )
    .await;
    seed_priority_token(&handle);

    let (status, body) = post(&handle, PRIORITY_TOKEN, &chat_body()).await;
    handle.shutdown_and_wait().await;

    assert_eq!(status, 502, "两个候选都连不上 ⇒ 502: {body}");
    assert!(
        body.contains("已尝试站点：1（连接失败）、2（连接失败）"),
        "全失败错误必须按实际尝试顺序列出档位: {body}"
    );
    assert!(!body.contains(KEY_A) && !body.contains(KEY_B), "{body}");
    assert!(
        !body.contains("kr/key"),
        "错误里不得出现密钥引用原文: {body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_500_is_not_replayed_even_with_a_priority_rule() {
    // P2-13 红线（本项不推翻）：5xx 单请求内不重放——规则再优先也不得让 503 去试备用。
    // 5xx 的可用性由熔断承接（见下一条跨请求用例），不在本请求内发生。
    let a = spawn_upstream_always(1, REF_A, "503 Service Unavailable");
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let c = spawn_upstream_always(3, REF_C, "200 OK");
    let handle = start_priority_routed(
        vec![a.upstream(0.1), b.upstream(0.5), c.upstream(1.0)],
        priority_rule(),
        0,
        UpstreamTimeout::default(),
        long_cooldown(),
    )
    .await;
    seed_priority_token(&handle);

    let (status, body) = post(&handle, PRIORITY_TOKEN, &chat_body()).await;
    handle.shutdown_and_wait().await;

    assert_eq!(status, 503, "503 必须原样返回: {body}");
    assert!(
        body.contains("site1"),
        "返回的应是首选 1 号站的响应: {body}"
    );
    assert_eq!(a.request_count(), 1);
    assert_eq!(
        c.request_count(),
        0,
        "503 时规则第一位 3 号站一次都不该被请求"
    );
    assert_eq!(b.request_count(), 0, "503 时 2 号站也不该被请求");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn breaker_skips_the_failed_primary_on_the_next_request() {
    // 5xx 的跨请求承接：阈值 1 ⇒ 第一次 503 即熔断 1 号站；第二次请求跳过它，
    // 由剩余候选承接。这里如实钉住一个边界：第二次的首选仍是派生顺序的 2 号站，
    // 而不是规则第一位的 3 号站——本项的优先级只排备用顺序，不改首选；
    // 把优先级提升为主用选择是拆分项（见 spec），不得由本用例假装已实现。
    let a = spawn_upstream_always(1, REF_A, "503 Service Unavailable");
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let c = spawn_upstream_always(3, REF_C, "200 OK");
    let handle = start_priority_routed(
        vec![a.upstream(0.1), b.upstream(0.5), c.upstream(1.0)],
        priority_rule(),
        0,
        UpstreamTimeout::default(),
        BreakerPolicy {
            threshold: 1,
            cooldown: Duration::from_secs(3600),
        },
    )
    .await;
    seed_priority_token(&handle);

    let (first, _) = post(&handle, PRIORITY_TOKEN, &chat_body()).await;
    assert_eq!(first, 503, "第一次应如实返回 503");
    let (second, body) = post(&handle, PRIORITY_TOKEN, &chat_body()).await;
    handle.shutdown_and_wait().await;

    assert_eq!(second, 200, "第二次应由备用承接: {body}");
    assert!(
        body.contains("site2"),
        "第二次首选仍是派生顺序的 2 号站: {body}"
    );
    assert_eq!(a.request_count(), 1, "熔断后不该再打 1 号站");
    assert_eq!(b.request_count(), 1);
    assert_eq!(c.request_count(), 0, "第二次首选成功，3 号站无需被试");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_timeout_is_not_replayed_even_with_a_priority_rule() {
    // 读超时（已送达、可能已计费）同样不切换：停滞的 1 号站超时后直接 502，
    // 规则第一位的 3 号站一次都不该被请求。超时分两类：连接阶段超时属可重放类
    // （与连接拒绝同类，见 classify），读超时属不可重放类——本用例钉住后者。
    let stalled = spawn_stalled_upstream(1, REF_A);
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let c = spawn_upstream_always(3, REF_C, "200 OK");
    let handle = start_priority_routed(
        vec![stalled.upstream(0.1), b.upstream(0.5), c.upstream(1.0)],
        priority_rule(),
        0,
        UpstreamTimeout {
            connect: Duration::from_millis(500),
            read: Duration::from_millis(200),
        },
        long_cooldown(),
    )
    .await;
    seed_priority_token(&handle);

    let (status, _) = post(&handle, PRIORITY_TOKEN, &chat_body()).await;
    handle.shutdown_and_wait().await;

    assert_eq!(status, 502, "读超时按 502 如实返回");
    assert_eq!(
        c.request_count(),
        0,
        "读超时时规则第一位 3 号站一次都不该被请求"
    );
    assert_eq!(b.request_count(), 0, "读超时时 2 号站也不该被请求");
}
