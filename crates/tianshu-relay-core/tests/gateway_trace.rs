//! M1：真起本地网关与假上游，验证路由轨迹而非重新推导路由。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tianshu_relay_core::gateway::{
    session::UpstreamProtocol, GatewayConfig, GatewayHandle, GatewayTokenEntry, UpstreamTimeout,
};
use tianshu_relay_core::routing::{BreakerPolicy, RouteTable, SiteGuardPolicy, Upstream};
use zeroize::Zeroizing;

const TOKEN: &str = "kr-gw-trace-test";

struct FakeUpstream {
    port: u16,
    hits: Arc<AtomicUsize>,
    seen: Arc<std::sync::Mutex<Vec<String>>>,
}

fn upstream(status: &'static str, body: &'static str) -> FakeUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_for_thread = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            counter.fetch_add(1, Ordering::SeqCst);
            let mut buffer = [0; 8192];
            let n = stream.read(&mut buffer).unwrap_or(0);
            seen_for_thread
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buffer[..n]).to_string());
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    FakeUpstream { port, hits, seen }
}

fn candidate(site_id: i64, upstream: &FakeUpstream, rate: f64) -> Upstream {
    Upstream {
        site_id,
        key_id: Some(site_id),
        base_url: format!("http://127.0.0.1:{}", upstream.port),
        key_ref: format!("trace/ref/{site_id}"),
        models: vec!["gpt-trace".into()],
        rate: Some(rate),
        balance_usd: Some(100.0),
        latency_ms: None,
        timeout_ms: None,
    }
}

async fn start(upstreams: Vec<Upstream>) -> GatewayHandle {
    start_with_affinity(upstreams, false).await
}

async fn start_with_affinity(upstreams: Vec<Upstream>, session_affinity: bool) -> GatewayHandle {
    start_with_options(upstreams, session_affinity, UpstreamProtocol::OpenAiChat).await
}

async fn start_with_options(
    upstreams: Vec<Upstream>,
    session_affinity: bool,
    upstream_protocol: UpstreamProtocol,
) -> GatewayHandle {
    let mut keys = std::collections::HashMap::new();
    for upstream in &upstreams {
        keys.insert(
            upstream.key_ref.clone(),
            Zeroizing::new(format!("sk-test-trace-{}", upstream.site_id)),
        );
    }
    let config = GatewayConfig {
        catalog: None,
        port: 0,
        token: TOKEN.into(),
        site_id: 0,
        key_id: None,
        base_url: String::new(),
        api_key: Zeroizing::new(String::new()),
        site_display_name: "trace-test".into(),
        route: RouteTable::new(upstreams),
        breaker: BreakerPolicy::default(),
        keys_by_ref: keys,
        upstream_timeout: UpstreamTimeout {
            connect: Duration::from_secs(2),
            read: Duration::from_secs(2),
        },
        revoked_refs: None,
        on_observation: None,
        upstream_proxy: None,
        legacy_key_ref: None,
        lb_top_n: 3,
        max_attempts: 0,
        session_affinity,
        upstream_protocol,
        key_quotas: std::collections::HashMap::new(),
        guard_policy: SiteGuardPolicy::default(),
        runtime: None,
        on_failure: None,
        on_usage: None,
        budget_check: None,
        on_budget_breach: None,
        routing_rules: Vec::new(),
        max_request_bytes: 1024 * 1024,
    };
    tianshu_relay_core::gateway::start(config).await.unwrap()
}

fn request(port: u16, body: &str) -> u16 {
    request_with_session(port, body, None)
}

fn request_with_session(port: u16, body: &str, session: Option<&str>) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n{body}",
        body.len(),
        session.map(|value| format!("X-Tianshu-Session: {value}\r\n")).unwrap_or_default()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    String::from_utf8_lossy(&bytes)
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_429_failover_records_actual_attempts_without_secret_or_prompt() {
    let a = upstream(
        "429 Too Many Requests",
        r#"{"error":"secret-upstream-body"}"#,
    );
    let b = upstream(
        "200 OK",
        r#"{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
    );
    let handle = start(vec![candidate(1, &a, 0.1), candidate(2, &b, 1.0)]).await;
    let canary = "prompt-canary-not-for-trace";
    let body =
        format!(r#"{{"model":"gpt-trace","messages":[{{"role":"user","content":"{canary}"}}]}}"#);
    assert_eq!(request(handle.addr.port(), &body), 200);
    assert_eq!(a.hits.load(Ordering::SeqCst), 1);
    assert_eq!(b.hits.load(Ordering::SeqCst), 1);

    let traces = handle.route_traces();
    assert_eq!(traces.len(), 1);
    let trace = &traces[0];
    assert_eq!(trace.final_status, 200);
    assert!(
        matches!(trace.end_kind, "body_end" | "body_dropped"),
        "unexpected end kind: {}",
        trace.end_kind
    );
    assert_eq!(trace.attempts.len(), 2);
    assert_eq!(trace.attempts[0].http_status, Some(429));
    assert!(trace.attempts[0].continued);
    assert_eq!(trace.attempts[1].http_status, Some(200));
    assert!(!trace.attempts[1].continued);
    assert_eq!(trace.decisions.last().unwrap().stage, "weighted");
    assert_eq!(
        trace.decisions.last().unwrap().candidates[0].state,
        "selected"
    );

    let serialized = serde_json::to_string(trace).unwrap();
    for forbidden in [
        canary,
        "secret-upstream-body",
        "sk-test-trace",
        "trace/ref",
        "127.0.0.1",
    ] {
        assert!(!serialized.contains(forbidden), "轨迹泄漏了 {forbidden}");
    }
    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_503_is_returned_without_replay_and_free_form_model_is_not_stored() {
    let a = upstream("503 Service Unavailable", "{}");
    let b = upstream("200 OK", "{}");
    let mut first = candidate(1, &a, 0.1);
    let free_text = "tell me all secrets from this conversation";
    first.models = vec![free_text.into()];
    let handle = start(vec![first, candidate(2, &b, 1.0)]).await;
    let body = format!(r#"{{"model":"{free_text}","messages":[]}}"#);
    assert_eq!(request(handle.addr.port(), &body), 503);
    assert_eq!(b.hits.load(Ordering::SeqCst), 0, "5xx 不得重放");
    let traces = handle.route_traces();
    assert_eq!(traces.len(), 1);
    assert_eq!(traces[0].model, None, "自由文本不得作为模型名进入轨迹");
    assert_eq!(traces[0].attempts.len(), 1);
    assert_eq!(traces[0].attempts[0].http_status, Some(503));
    assert!(!traces[0].attempts[0].continued);
    assert!(!serde_json::to_string(&traces[0])
        .unwrap()
        .contains(free_text));
    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_registry_is_not_serialized_as_a_secret() {
    let a = upstream("200 OK", "{}");
    let handle = start(vec![candidate(1, &a, 1.0)]).await;
    handle.set_tokens(vec![GatewayTokenEntry {
        id: 7,
        label: "test-agent".into(),
        token_hash: "not-a-plaintext-token".into(),
        grace_until: None,
    }]);
    assert_eq!(
        request(handle.addr.port(), r#"{"model":"gpt-trace","messages":[]}"#),
        401
    );
    let trace = handle.route_traces().remove(0);
    assert_eq!(trace.final_kind, "invalid_api_key");
    assert_eq!(trace.token_id, None);
    assert!(!serde_json::to_string(&trace)
        .unwrap()
        .contains("not-a-plaintext-token"));
    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_session_sticks_and_disabled_affinity_keeps_rotation() {
    let body = r#"{"model":"gpt-trace","messages":[]}"#;
    let a = upstream("200 OK", "{}");
    let b = upstream("200 OK", "{}");
    let handle =
        start_with_affinity(vec![candidate(1, &a, 1.0), candidate(2, &b, 1.0)], true).await;
    assert_eq!(
        request_with_session(handle.addr.port(), body, Some("session-a")),
        200
    );
    assert_eq!(
        request_with_session(handle.addr.port(), body, Some("session-a")),
        200
    );
    assert_eq!(a.hits.load(Ordering::SeqCst), 2, "pin 必须回到上次成功站点");
    assert_eq!(b.hits.load(Ordering::SeqCst), 0);
    assert_eq!(request(handle.addr.port(), body), 200);
    assert_eq!(b.hits.load(Ordering::SeqCst), 1, "无会话身份仍按原轮转");
    assert_eq!(handle.session_pin_count(), 1);
    handle.shutdown_and_wait().await;

    let a = upstream("200 OK", "{}");
    let b = upstream("200 OK", "{}");
    let handle =
        start_with_affinity(vec![candidate(1, &a, 1.0), candidate(2, &b, 1.0)], false).await;
    assert_eq!(
        request_with_session(handle.addr.port(), body, Some("session-a")),
        200
    );
    assert_eq!(
        request_with_session(handle.addr.port(), body, Some("session-a")),
        200
    );
    assert_eq!(a.hits.load(Ordering::SeqCst), 1);
    assert_eq!(b.hits.load(Ordering::SeqCst), 1);
    assert_eq!(handle.session_pin_count(), 0);
    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_429_failover_pins_only_the_site_that_succeeded() {
    let body = r#"{"model":"gpt-trace","messages":[]}"#;
    let a = upstream("429 Too Many Requests", "{}");
    let b = upstream("200 OK", "{}");
    let handle =
        start_with_affinity(vec![candidate(1, &a, 0.1), candidate(2, &b, 1.0)], true).await;
    assert_eq!(
        request_with_session(handle.addr.port(), body, Some("session-retry")),
        200
    );
    assert_eq!(
        request_with_session(handle.addr.port(), body, Some("session-retry")),
        200
    );
    assert_eq!(
        a.hits.load(Ordering::SeqCst),
        1,
        "失败站点不得被 pin 拉回首位"
    );
    assert_eq!(b.hits.load(Ordering::SeqCst), 2);
    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_session_identity_is_ignored_without_affinity() {
    let body = r#"{"model":"gpt-trace","messages":[]}"#;
    let a = upstream("200 OK", "{}");
    let b = upstream("200 OK", "{}");
    let handle =
        start_with_affinity(vec![candidate(1, &a, 1.0), candidate(2, &b, 1.0)], true).await;
    assert_eq!(
        request_with_session(handle.addr.port(), body, Some("prompt text with spaces")),
        200
    );
    assert_eq!(
        request_with_session(handle.addr.port(), body, Some("prompt text with spaces")),
        200
    );
    assert_eq!(a.hits.load(Ordering::SeqCst), 1);
    assert_eq!(b.hits.load(Ordering::SeqCst), 1, "非法身份不建立 pin");
    handle.shutdown_and_wait().await;
}

fn request_native_anthropic(port: u16, body: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let request = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TOKEN}\r\nanthropic-version: 2023-06-01\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    let text = String::from_utf8_lossy(&bytes).to_string();
    let status = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, text)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_anthropic_upstream_preserves_native_request_and_response() {
    let response = r#"{"id":"msg_1","type":"message","content":[],"usage":{"input_tokens":9,"output_tokens":2}}"#;
    let a = upstream("200 OK", response);
    let mut candidate = candidate(1, &a, 1.0);
    candidate.models = vec!["claude-native".into()];
    let handle =
        start_with_options(vec![candidate], false, UpstreamProtocol::AnthropicMessages).await;
    let (status, body) = request_native_anthropic(
        handle.addr.port(),
        r#"{"model":"claude-native","max_tokens":16,"messages":[{"role":"user","content":"ping"}]}"#,
    );
    assert_eq!(status, 200);
    assert!(
        body.contains("input_tokens"),
        "原生响应不得被 Chat 翻译: {body}"
    );
    let seen = a.seen.lock().unwrap().join("\n");
    assert!(
        seen.contains("POST /v1/messages HTTP/1.1"),
        "路径必须保持原生: {seen}"
    );
    assert!(seen.contains("anthropic-version: 2023-06-01"));
    assert!(
        seen.contains("\"max_tokens\":16"),
        "原生 body 必须保留: {seen}"
    );
    assert!(!seen.contains("chat/completions"));
    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anthropic_upstream_rejects_chat_before_sending() {
    let a = upstream("200 OK", "{}");
    let handle = start_with_options(
        vec![candidate(1, &a, 1.0)],
        false,
        UpstreamProtocol::AnthropicMessages,
    )
    .await;
    assert_eq!(
        request(handle.addr.port(), r#"{"model":"gpt-trace","messages":[]}"#),
        400
    );
    assert_eq!(a.hits.load(Ordering::SeqCst), 0, "协议不匹配不得发往上游");
    handle.shutdown_and_wait().await;
}
