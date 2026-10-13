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

use keyrelay_core::gateway::{generate_token, start, GatewayConfig, GatewayFailure, GatewayHandle};
use keyrelay_core::routing::{BreakerPolicy, RouteTable, Upstream};
use zeroize::Zeroizing;

const MODEL: &str = "gpt-5.6";
const KEY_A: &str = "sk-upstream-A-0123456789abcdef";
const KEY_B: &str = "sk-upstream-B-0123456789abcdef";
const REF_A: &str = "kr/key/1/secret";
const REF_B: &str = "kr/key/2/secret";

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
            base_url: self.base_url.clone(),
            key_ref: self.key_ref.clone(),
            models: vec![MODEL.to_string()],
            rate: Some(rate),
            balance_usd: Some(10.0),
            latency_ms: Some(10),
        }
    }
}

type Failures = Arc<Mutex<Vec<GatewayFailure>>>;

/// 起一个**路由模式**的网关。`rate` 决定排序：小的排前面（首选）。
async fn start_routed(
    upstreams: &[(&FakeUpstream, f64)],
    breaker: BreakerPolicy,
) -> (GatewayHandle, String, Failures) {
    let route = RouteTable::new(
        upstreams
            .iter()
            .map(|(u, rate)| u.upstream(*rate))
            .collect(),
    );
    let mut keys = std::collections::HashMap::new();
    for (u, _) in upstreams {
        let plain = if u.key_ref == REF_A { KEY_A } else { KEY_B };
        keys.insert(u.key_ref.clone(), Zeroizing::new(plain.to_string()));
    }
    let failures: Failures = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&failures);

    let handle = start(GatewayConfig {
        port: 0,
        token: generate_token(),
        // 路由非空时 `base_url` 不被使用；留空正好证明这一点（`start()` 只在空表时要求它非空）
        base_url: String::new(),
        api_key: String::new(),
        site_display_name: "路由模式".to_string(),
        route,
        breaker,
        keys_by_ref: keys,
        on_failure: Some(Arc::new(move |f| {
            if let Ok(mut log) = sink.lock() {
                log.push(f);
            }
        })),
    })
    .await
    .expect("网关应能启动");

    let token = handle.token.clone();
    (handle, token, failures)
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
async fn failover_on_503_reaches_the_second_upstream() {
    // A 恒 503（倍率更低 ⇒ 首选），B 恒 200
    let a = spawn_upstream_always(1, REF_A, "503 Service Unavailable");
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let (handle, token, _failures) = start_routed(&[(&a, 0.1), (&b, 1.0)], long_cooldown()).await;

    let (status, body) = post(&handle, &token, &chat_body()).await;

    assert_eq!(status, 200, "应当切到第二个上游并拿到 200");
    assert!(body.contains("site2"), "响应应当来自第二个上游: {body}");
    assert_eq!(a.request_count(), 1, "首选上游应当被试过一次");
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
    let a = spawn_upstream_always(1, REF_A, "503 Service Unavailable");
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let policy = BreakerPolicy {
        threshold: 2,
        cooldown: Duration::from_secs(3600), // 冷却很长，本轮不会 HalfOpen
    };
    let (handle, token, _failures) = start_routed(&[(&a, 0.1), (&b, 1.0)], policy).await;

    // 第 1、2 次：A 失败 → 切换（第 2 次之后 A 达到阈值进入 Open）
    assert_eq!(post(&handle, &token, &chat_body()).await.0, 200);
    assert_eq!(post(&handle, &token, &chat_body()).await.0, 200);
    assert_eq!(a.request_count(), 2, "阈值内应当每次都试 A");

    // 第 3 次：A 已 Open ⇒ 应当**跳过**它，直接走 B
    assert_eq!(post(&handle, &token, &chat_body()).await.0, 200);
    assert_eq!(a.request_count(), 2, "熔断打开后不该再打 A");
    assert_eq!(b.request_count(), 3);

    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failure_event_carries_only_metadata() {
    let a = spawn_upstream_always(1, REF_A, "503 Service Unavailable");
    let b = spawn_upstream_always(2, REF_B, "200 OK");
    let (handle, token, failures) = start_routed(&[(&a, 0.1), (&b, 1.0)], long_cooldown()).await;

    assert_eq!(post(&handle, &token, &chat_body()).await.0, 200);

    // 断言全部在**同步块**里做完：`std::sync::MutexGuard` 绝不跨 `.await` 持有。
    // 跨 await 持锁在单线程 runtime 上会自锁，在多线程 runtime 上只是**碰巧**能过——
    // 一条会随调度变化的假绿（`clippy::await_holding_lock`）。
    {
        let events = failures.lock().unwrap();
        assert_eq!(events.len(), 1, "一次失败切换应当只写一条事件");
        let event = &events[0];
        assert_eq!(event.site_id, 1);
        assert_eq!(event.status, 503);
        assert_eq!(event.model, MODEL, "记的是**调用方请求的那个**模型名");

        // 结构上装不下别的东西（`GatewayFailure` 恰好三个公开字段），内容上也不许混进密钥
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
async fn exhausted_candidates_return_the_last_status() {
    // 两个上游都 503 ⇒ 客户端拿到 503（不是 500/502 兜底）
    let a = spawn_upstream_always(1, REF_A, "503 Service Unavailable");
    let b = spawn_upstream_always(2, REF_B, "503 Service Unavailable");
    let (handle, token, failures) = start_routed(&[(&a, 0.1), (&b, 1.0)], long_cooldown()).await;

    let (status, body) = post(&handle, &token, &chat_body()).await;

    assert_eq!(status, 503, "候选耗尽时应当如实返回最后一个上游的状态码");
    assert!(
        body.contains("site2"),
        "返回的应当是**最后一个**上游的响应: {body}"
    );
    assert_eq!(a.request_count(), 1);
    assert_eq!(b.request_count(), 1);
    assert_eq!(failures.lock().unwrap().len(), 2, "两次失败各记一条");

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

    /// 起一个「只服务 `models` 里那些名字」的两上游网关（A 恒 503、B 恒 200）。
    async fn start_with_models(
        models: Vec<String>,
    ) -> (GatewayHandle, String, Failures, FakeUpstream, FakeUpstream) {
        let a = spawn_upstream_always(1, REF_A, "503 Service Unavailable");
        let b = spawn_upstream_always(2, REF_B, "200 OK");
        let mut up_a = a.upstream(0.1);
        up_a.models = models.clone();
        let mut up_b = b.upstream(1.0);
        up_b.models = models;

        let failures: Failures = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&failures);
        let mut keys = std::collections::HashMap::new();
        keys.insert(REF_A.to_string(), Zeroizing::new(KEY_A.to_string()));
        keys.insert(REF_B.to_string(), Zeroizing::new(KEY_B.to_string()));

        let handle = start(GatewayConfig {
            port: 0,
            token: generate_token(),
            base_url: String::new(),
            api_key: String::new(),
            site_display_name: "路由模式".to_string(),
            route: RouteTable::new(vec![up_a, up_b]),
            breaker: long_cooldown(),
            keys_by_ref: keys,
            on_failure: Some(Arc::new(move |f| {
                if let Ok(mut log) = sink.lock() {
                    log.push(f);
                }
            })),
        })
        .await
        .expect("网关应能启动");
        let token = handle.token.clone();
        (handle, token, failures, a, b)
    }

    // ---- ① 密钥形状的模型名：必须被打码 ----
    let (handle, token, failures, a, _b) = start_with_models(vec![KEY_SHAPED.to_string()]).await;
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
        assert_eq!(events[0].site_id, a.site_id);
        assert_eq!(events[0].status, 503);
    }
    handle.shutdown_and_wait().await;

    // ---- ② 正常模型名：逐字保留，可用信息没被整条吃掉 ----
    let (handle, token, failures, _a, _b) = start_with_models(vec![MODEL.to_string()]).await;
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
