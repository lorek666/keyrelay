//! M1：真起本地网关与假上游，验证路由轨迹而非重新推导路由。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tianshu_relay_core::gateway::{
    session::UpstreamProtocol, GatewayConfig, GatewayHandle, GatewayTokenEntry, GatewayUsage,
    UpstreamTimeout,
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
    upstream_with_headers(status, body, "")
}

fn upstream_with_headers(
    status: &'static str,
    body: &'static str,
    extra_headers: &'static str,
) -> FakeUpstream {
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
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
    start_with_options_and_usage(upstreams, session_affinity, upstream_protocol, None).await
}

async fn start_with_options_and_usage(
    upstreams: Vec<Upstream>,
    session_affinity: bool,
    upstream_protocol: UpstreamProtocol,
    on_usage: Option<Arc<dyn Fn(GatewayUsage) + Send + Sync>>,
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
        routing_preset: tianshu_relay_core::routing::RoutingPreset::Balanced,
        key_quotas: std::collections::HashMap::new(),
        guard_policy: SiteGuardPolicy::default(),
        runtime: None,
        on_failure: None,
        on_usage,
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
async fn key_cooldown_can_be_cleared_on_lifecycle_change() {
    let a = upstream_with_headers(
        "429 Too Many Requests",
        r#"{"error":"rate limited"}"#,
        "Retry-After: 60\r\n",
    );
    let handle = start(vec![candidate(1, &a, 1.0)]).await;
    let body = r#"{"model":"gpt-trace","messages":[]}"#;
    assert_eq!(request(handle.addr.port(), body), 429);
    assert_eq!(
        handle.key_cooldown_count(),
        1,
        "Retry-After 应建立 key 级冷却"
    );
    assert_eq!(handle.clear_key_cooldowns(), 1);
    assert_eq!(handle.key_cooldown_count(), 0);
    assert_eq!(request(handle.addr.port(), body), 429);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_upstream_response_is_recorded_as_complete_not_dropped() {
    let a = upstream("204 No Content", "");
    let handle = start(vec![candidate(1, &a, 1.0)]).await;
    assert_eq!(
        request(handle.addr.port(), r#"{"model":"gpt-trace","messages":[]}"#,),
        204
    );
    let traces = handle.route_traces();
    assert_eq!(traces.len(), 1);
    assert_eq!(
        traces[0].end_kind, "body_end",
        "正常空响应不能被误报为 body_dropped"
    );
    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_redirects_are_not_followed_with_credentials() {
    let target = upstream("200 OK", "{}");
    let location =
        Box::leak(format!("Location: http://127.0.0.1:{}/steal\r\n", target.port).into_boxed_str());
    let redirect = upstream_with_headers("302 Found", "", location);
    let handle = start(vec![candidate(1, &redirect, 1.0)]).await;
    assert_eq!(
        request(handle.addr.port(), r#"{"model":"gpt-trace","messages":[]}"#,),
        302,
        "3xx 必须原样返回，不能带着站点密钥跟随到另一个主机"
    );
    assert_eq!(
        target.hits.load(Ordering::SeqCst),
        0,
        "重定向目标绝不能收到带站点密钥的请求"
    );
    handle.shutdown_and_wait().await;
}

fn request_native_anthropic(port: u16, body: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let request = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nx-api-key: {TOKEN}\r\nX-Tianshu-Session: local-only-session\r\nanthropic-version: 2023-06-01\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
    let response = r#"{"id":"msg_1","type":"message","content":[],"usage":{"input_tokens":9,"cache_creation_input_tokens":100,"cache_read_input_tokens":50,"output_tokens":2}}"#;
    let a = upstream("200 OK", response);
    let mut candidate = candidate(1, &a, 1.0);
    candidate.models = vec!["claude-native".into()];
    let usage: Arc<std::sync::Mutex<Vec<GatewayUsage>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let usage_sink = Arc::clone(&usage);
    let handle = start_with_options_and_usage(
        vec![candidate],
        false,
        UpstreamProtocol::AnthropicMessages,
        Some(Arc::new(move |usage_row| {
            usage_sink.lock().unwrap().push(usage_row);
        })),
    )
    .await;
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
    let seen_lower = seen.to_ascii_lowercase();
    assert!(
        seen_lower.contains("x-api-key: sk-test-trace-1"),
        "上游必须收到站点 key: {seen}"
    );
    assert!(
        !seen.contains(TOKEN),
        "本地网关 token 绝不能作为 x-api-key 发给上游: {seen}"
    );
    assert!(
        !seen.contains("local-only-session"),
        "本地会话标识不得跨站转发: {seen}"
    );
    let usage = usage.lock().unwrap().clone();
    assert_eq!(usage.len(), 1, "原生 Anthropic 也必须记一条用量");
    assert_eq!(
        (
            usage[0].prompt_tokens,
            usage[0].completion_tokens,
            usage[0].total_tokens
        ),
        (159, 2, 161),
        "缓存创建/读取 token 都是计费输入，不能漏记"
    );
    handle.shutdown_and_wait().await;
}

fn request_native_anthropic_dual_headers(port: u16, body: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let request = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nx-api-key: real-anthropic-key-canary\r\nAuthorization: Bearer {TOKEN}\r\nanthropic-version: 2023-06-01\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
async fn anthropic_dual_auth_prefers_local_bearer_and_never_leaks_real_key() {
    let a = upstream("200 OK", r#"{"type":"message","content":[]}"#);
    let mut candidate = candidate(1, &a, 1.0);
    candidate.models = vec!["claude-native".into()];
    let handle =
        start_with_options(vec![candidate], false, UpstreamProtocol::AnthropicMessages).await;
    let (status, body) = request_native_anthropic_dual_headers(
        handle.addr.port(),
        r#"{"model":"claude-native","max_tokens":16,"messages":[{"role":"user","content":"ping"}]}"#,
    );
    assert_eq!(status, 200, "{body}");
    let seen = a.seen.lock().unwrap().join("\n");
    assert!(
        !seen.contains("real-anthropic-key-canary"),
        "客户端的真实 x-api-key 绝不能转发: {seen}"
    );
    assert!(
        seen.to_ascii_lowercase()
            .contains("x-api-key: sk-test-trace-1"),
        "上游应收到站点 key: {seen}"
    );
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
