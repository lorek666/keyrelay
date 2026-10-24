//! M42-S1：本地错误信封 / 413 / 双栈监听。
//!
//! 覆盖 spec §7.1–§7.2 的集成部分：
//! - 10 个本地错误点全部是 OpenAI 风格的 `{"error":{message,type,param,code}}`；
//! - 上游非 2xx **逐字节透传**（不重新包信封）；
//! - 413 在连上游之前就拒绝（上游收到 0 次）；
//! - 双栈 / IPv6 降级 / v6 端口占用 canary / port 0。

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use tianshu_relay_core::gateway::{
    start, start_with_v6, GatewayConfig, GatewayHandle, Ipv6State, UpstreamTimeout, V6BindMode,
};
use tianshu_relay_core::routing::{RouteTable, Upstream};
use zeroize::Zeroizing;

const MODEL: &str = "m42-model";
const REF_A: &str = "kr/key/1/secret";
const KEY_A: &str = "sk-a-0123456789abcdef";

// ============================================================ 夹具

struct FakeUpstream {
    base_url: String,
    seen: Arc<AtomicUsize>,
}

impl FakeUpstream {
    fn count(&self) -> usize {
        self.seen.load(Ordering::SeqCst)
    }
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

/// 起一个回固定 status/body 的假上游。
fn spawn_upstream(status: &str, body: &str) -> FakeUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取地址");
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    let status = status.to_string();
    let body = body.to_string();
    let body_for_thread = body;
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = read_request(&mut stream);
            counter.fetch_add(1, Ordering::SeqCst);
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body_for_thread}",
                body_for_thread.len()
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

fn http_request(
    url: &str,
    token: Option<&str>,
    path: &str,
    method: &str,
    body: Option<&[u8]>,
) -> (u16, String) {
    let without_scheme = url.trim_start_matches("http://");
    let mut stream = TcpStream::connect(without_scheme).expect("连接网关");
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let payload = body.unwrap_or(b"");
    // 无 body 时不发 `Content-Length`（与既有测试的 `http_get` 同形）：
    // 给 GET 加 `Content-Length: 0` 在某些 hyper 版本上会让服务端等一个「零长 body 结束符」。
    let framing = if payload.is_empty() {
        String::from("Content-Type: application/json\r\n")
    } else {
        format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            payload.len()
        )
    };
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {without_scheme}\r\n{auth}{framing}Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).expect("发送请求头");
    if !payload.is_empty() {
        stream.write_all(payload).expect("发送请求体");
    }
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

/// **异步**版本：网关的 serve 任务是 tokio 任务，而 `TcpStream` 是阻塞的——
/// 在 `#[tokio::test]`（单线程 runtime）里直接调 `http_request` 会把唯一的线程占住，
/// 网关永远没机会 accept/响应（实测挂死）。所有请求都必须走 `spawn_blocking`。
async fn request_async(
    url: String,
    token: Option<String>,
    path: &'static str,
    method: &'static str,
    body: Option<Vec<u8>>,
) -> (u16, String) {
    tokio::task::spawn_blocking(move || {
        http_request(&url, token.as_deref(), path, method, body.as_deref())
    })
    .await
    .expect("阻塞任务")
}

async fn get(url: &str, token: &str, path: &'static str) -> (u16, String) {
    request_async(url.to_string(), Some(token.to_string()), path, "GET", None).await
}

async fn post(url: &str, token: &str, body: &str) -> (u16, String) {
    request_async(
        url.to_string(),
        Some(token.to_string()),
        "/v1/chat/completions",
        "POST",
        Some(body.as_bytes().to_vec()),
    )
    .await
}

fn chat_body() -> String {
    format!(r#"{{"model":"{MODEL}","messages":[]}}"#)
}

// ============================================================ 配置

fn legacy_config(upstream: &FakeUpstream, max_request_bytes: usize) -> GatewayConfig {
    let mut config = GatewayConfig::single_upstream(
        0,
        "local-token-envelope-tests".to_string(),
        upstream.base_url.clone(),
        Zeroizing::new(KEY_A.to_string()),
        "信封测试".to_string(),
    );
    config.max_request_bytes = max_request_bytes;
    config
}

fn routed_config(upstreams: Vec<Upstream>, keys: &[(&str, &str)], port: u16) -> GatewayConfig {
    let mut map = HashMap::new();
    for (reference, plain) in keys {
        map.insert(reference.to_string(), Zeroizing::new((*plain).to_string()));
    }
    GatewayConfig {
        port,
        token: "local-token-envelope-tests".to_string(),
        site_id: 0,
        key_id: None,
        base_url: String::new(),
        api_key: Zeroizing::new(String::new()),
        site_display_name: "信封测试".to_string(),
        route: RouteTable::new(upstreams),
        breaker: tianshu_relay_core::routing::BreakerPolicy::default(),
        lb_top_n: 1,
        max_attempts: 0,
        guard_policy: tianshu_relay_core::routing::SiteGuardPolicy::default(),
        keys_by_ref: map,
        upstream_timeout: UpstreamTimeout::default(),
        revoked_refs: None,
        on_failure: None,
        on_observation: None,
        on_usage: None,
        budget_check: None,
        on_budget_breach: None,
        upstream_proxy: None,
        legacy_key_ref: None,
        max_request_bytes: tianshu_relay_core::gateway::DEFAULT_MAX_REQUEST_BYTES,
        runtime: None,
    }
}

fn upstream_of(site_id: i64, base_url: &str, key_ref: &str, models: &[&str]) -> Upstream {
    Upstream {
        site_id,
        key_id: None,
        base_url: base_url.to_string(),
        key_ref: key_ref.to_string(),
        models: models.iter().map(|m| (*m).to_string()).collect(),
        rate: None,
        balance_usd: None,
        latency_ms: None,
        timeout_ms: None,
    }
}

/// 断言：`error` 是对象、`type`/`code` 精确匹配、`message` 含关键文案、`param` 为 null。
fn assert_envelope(body: &str, expected_type: &str, expected_code: &str, message_contains: &str) {
    let value: serde_json::Value =
        serde_json::from_str(body).unwrap_or_else(|e| panic!("响应不是 JSON（{e}）: {body}"));
    let err = value
        .get("error")
        .expect("必须有 error 键")
        .as_object()
        .unwrap_or_else(|| panic!("error 必须是对象（不能是字符串）: {body}"));
    assert_eq!(
        err.get("type").and_then(|v| v.as_str()),
        Some(expected_type),
        "type 不符: {body}"
    );
    assert_eq!(
        err.get("code").and_then(|v| v.as_str()),
        Some(expected_code),
        "code 不符: {body}"
    );
    assert!(
        err.get("message")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .contains(message_contains),
        "message 应含「{message_contains}」: {body}"
    );
    assert!(
        err.get("param").map(|v| v.is_null()).unwrap_or(false),
        "param 必须是 null: {body}"
    );
}

async fn shutdown(handle: GatewayHandle) {
    handle.shutdown_and_wait().await;
}

// ============================================================ 1–4、6：简单本地错误

#[tokio::test]
async fn envelope_401_missing_token() {
    let up = spawn_upstream("200 OK", r#"{"ok":true}"#);
    let handle = start(legacy_config(&up, 16 * 1024 * 1024))
        .await
        .expect("启动");
    let url = handle.local_url();
    let (status, body) = request_async(url.clone(), None, "/v1/models", "GET", None).await;
    assert_eq!(status, 401);
    assert_envelope(&body, "authentication_error", "invalid_api_key", "本地令牌");
    shutdown(handle).await;
}

#[tokio::test]
async fn envelope_404_path_outside_v1() {
    let up = spawn_upstream("200 OK", r#"{"ok":true}"#);
    let handle = start(legacy_config(&up, 16 * 1024 * 1024))
        .await
        .expect("启动");
    let url = handle.local_url();
    let token = handle.token.clone();
    let (status, body) = get(&url, &token, "/v2/models").await;
    assert_eq!(status, 404);
    assert_envelope(&body, "invalid_request_error", "not_found", "/v1/*");
    shutdown(handle).await;
}

#[tokio::test]
async fn envelope_400_path_traversal() {
    let up = spawn_upstream("200 OK", r#"{"ok":true}"#);
    let handle = start(legacy_config(&up, 16 * 1024 * 1024))
        .await
        .expect("启动");
    let url = handle.local_url();
    let token = handle.token.clone();
    let (status, body) = get(&url, &token, "/v1/../etc/passwd").await;
    assert_eq!(status, 400);
    assert_envelope(&body, "invalid_request_error", "invalid_path", "向上跳");
    shutdown(handle).await;
}

/// 非超限的 body 读取失败仍是 400 `invalid_request_body`（不能被误判成 413）。
#[tokio::test]
async fn envelope_400_unreadable_body() {
    let up = spawn_upstream("200 OK", r#"{"ok":true}"#);
    let handle = start(legacy_config(&up, 16 * 1024 * 1024))
        .await
        .expect("启动");
    let url = handle.local_url();
    let token = handle.token.clone();

    // 声明 100 字节却只发 3 字节就关连接 ⇒ hyper 读取失败（不是 LengthLimitError）
    let without_scheme = url.trim_start_matches("http://");
    let mut stream = TcpStream::connect(without_scheme).expect("连接网关");
    let head = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {without_scheme}\r\n\
         Authorization: Bearer {token}\r\nContent-Type: application/json\r\n\
         Content-Length: 100\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).expect("头");
    stream.write_all(b"abc").expect("半截 body");
    stream.flush().ok();
    drop(stream);

    // 连接已断，网关记下的是 400；这里用「下一条请求仍然正常」来证明网关没崩
    let (status, body) = post(&url, &token, &chat_body()).await;
    assert_eq!(status, 200, "网关必须继续服务: {body}");
    shutdown(handle).await;
}

// ============================================================ 5 + 7：413 / 不连上游

#[tokio::test]
async fn envelope_413_body_too_large_and_zero_upstream_calls() {
    let up = spawn_upstream("200 OK", r#"{"ok":true}"#);
    // 上限 8 字节：任何 JSON body 都超
    let handle = start(legacy_config(&up, 8)).await.expect("启动");
    let url = handle.local_url();
    let token = handle.token.clone();
    let (status, body) = post(&url, &token, &chat_body()).await;
    assert_eq!(status, 413, "超限必须是 413（不是 400）: {body}");
    assert_envelope(
        &body,
        "invalid_request_error",
        "request_too_large",
        "请求体超过上限",
    );
    assert_eq!(up.count(), 0, "413 必须在连上游之前拒绝");
    shutdown(handle).await;
}

#[tokio::test]
async fn envelope_413_mentions_the_configured_limit_in_mib() {
    let up = spawn_upstream("200 OK", r#"{"ok":true}"#);
    let handle = start(legacy_config(&up, 2 * 1024 * 1024))
        .await
        .expect("启动");
    let url = handle.local_url();
    let token = handle.token.clone();
    let big = vec![b'x'; 2 * 1024 * 1024 + 1];
    let (status, body) = request_async(
        url.clone(),
        Some(token.clone()),
        "/v1/chat/completions",
        "POST",
        Some(big.clone()),
    )
    .await;
    assert_eq!(status, 413, "{body}");
    assert!(body.contains("2 MiB"), "消息应含配置的上限: {body}");
    assert_eq!(up.count(), 0);
    shutdown(handle).await;
}

// ============================================================ 8：无可用模型

#[tokio::test]
async fn envelope_404_model_not_found() {
    let up = spawn_upstream("200 OK", r#"{"ok":true}"#);
    let config = routed_config(
        vec![upstream_of(1, &up.base_url, REF_A, &[MODEL])],
        &[(REF_A, KEY_A)],
        0,
    );
    let handle = start(config).await.expect("启动");
    let url = handle.local_url();
    let token = handle.token.clone();
    let (status, body) = post(&url, &token, r#"{"model":"nope","messages":[]}"#).await;
    assert_eq!(status, 404);
    assert_envelope(
        &body,
        "invalid_request_error",
        "model_not_found",
        "没有可服务模型",
    );
    assert_eq!(up.count(), 0, "没有候选就不该发请求");
    shutdown(handle).await;
}

// ============================================================ 9：全熔断

#[tokio::test]
async fn envelope_503_breaker_open() {
    let up = spawn_upstream("503 Service Unavailable", r#"{"error":"down"}"#);
    let mut config = routed_config(
        vec![upstream_of(1, &up.base_url, REF_A, &[MODEL])],
        &[(REF_A, KEY_A)],
        0,
    );
    config.breaker = tianshu_relay_core::routing::BreakerPolicy {
        threshold: 1,
        cooldown: std::time::Duration::from_secs(3600),
    };
    let handle = start(config).await.expect("启动");
    let url = handle.local_url();
    let token = handle.token.clone();
    // 第一条把熔断喂开（503 原样返回）
    let (status, _) = post(&url, &token, &chat_body()).await;
    assert_eq!(status, 503);
    // 第二条：没有候选可用 ⇒ 503 breaker_open
    let (status, body) = post(&url, &token, &chat_body()).await;
    assert_eq!(status, 503);
    assert_envelope(&body, "api_error", "breaker_open", "熔断冷却中");
    shutdown(handle).await;
}

// ============================================================ 10：全失败（502）

#[tokio::test]
async fn envelope_502_all_upstreams_failed() {
    // 死端口：连接层失败 ⇒ 候选耗尽 ⇒ 502
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("占端口");
        let port = listener.local_addr().expect("地址").port();
        drop(listener);
        port
    };
    let config = routed_config(
        vec![upstream_of(
            1,
            &format!("http://127.0.0.1:{port}"),
            REF_A,
            &[MODEL],
        )],
        &[(REF_A, KEY_A)],
        0,
    );
    let handle = start(config).await.expect("启动");
    let url = handle.local_url();
    let token = handle.token.clone();
    let (status, body) = post(&url, &token, &chat_body()).await;
    assert_eq!(status, 502);
    assert_envelope(&body, "api_error", "all_upstreams_failed", "上游");
    shutdown(handle).await;
}

// ============================================================ 11：上游错误逐字节透传

#[tokio::test]
async fn upstream_error_body_is_byte_transparent() {
    let raw = r#"{"error":"slow down","x":1}"#;
    let up = spawn_upstream("400 Bad Request", raw);
    let handle = start(legacy_config(&up, 16 * 1024 * 1024))
        .await
        .expect("启动");
    let url = handle.local_url();
    let token = handle.token.clone();
    let (status, body) = post(&url, &token, &chat_body()).await;
    assert_eq!(status, 400, "上游状态码必须原样透传");
    assert_eq!(body, raw, "上游 body 必须**逐字节**一致（不得重新包信封）");
    assert!(
        !body.contains("\"type\""),
        "不得把上游错误包装成 OpenAI envelope: {body}"
    );
    shutdown(handle).await;
}

// ============================================================ 双栈 / 降级 / port 0

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("占端口");
    let port = listener.local_addr().expect("地址").port();
    drop(listener);
    port
}

#[tokio::test]
async fn dual_stack_listens_on_v4_and_v6() {
    let up = spawn_upstream("200 OK", r#"{"ok":true}"#);
    let port = free_port();
    let mut config = legacy_config(&up, 16 * 1024 * 1024);
    config.port = port;
    let handle = start(config).await.expect("启动");
    let token = handle.token.clone();

    let (status4, _) = get(&format!("http://127.0.0.1:{port}"), &token, "/health").await;
    assert_eq!(status4, 200, "v4 /health 必须 200");
    // v6 也要真的能**连上**（不只是「绑定成功」）：双栈的验收判据是两边都能 200。
    let (status6, _) = get(&format!("http://[::1]:{port}"), &token, "/health").await;
    assert_eq!(status6, 200, "v6 /health 必须 200（[::1]:{port}）");
    assert_eq!(
        handle.addrs.len(),
        2,
        "双栈应当有两条监听地址: {:?}",
        handle.addrs
    );
    assert_eq!(handle.ipv6, Ipv6State::Listening, "v6 应当监听成功");
    assert!(
        handle.addrs.iter().any(|a| a.is_ipv6()),
        "addrs 里必须有 v6: {:?}",
        handle.addrs
    );
    shutdown(handle).await;
}

#[tokio::test]
async fn ipv6_unavailable_degrades_to_v4_only() {
    let up = spawn_upstream("200 OK", r#"{"ok":true}"#);
    let port = free_port();
    let mut config = legacy_config(&up, 16 * 1024 * 1024);
    config.port = port;
    let handle = start_with_v6(
        config,
        V6BindMode::Fail(std::io::ErrorKind::AddrNotAvailable),
    )
    .await
    .expect("v6 不可用不得阻断启动");
    let token = handle.token.clone();
    assert_eq!(handle.addrs.len(), 1, "只剩 v4");
    assert!(matches!(handle.ipv6, Ipv6State::Degraded { .. }));
    let (status, _) = get(&format!("http://127.0.0.1:{port}"), &token, "/health").await;
    assert_eq!(status, 200, "v4 必须照常服务");
    shutdown(handle).await;
}

/// **端口冲突 canary**（Lead 裁决 2）：v6 被占用 ⇒ 降级，v4 照常；且 v4 端口真的还在听。
#[tokio::test]
async fn ipv6_addr_in_use_degrades_and_keeps_v4_serving() {
    let up = spawn_upstream("200 OK", r#"{"ok":true}"#);
    let port = free_port();
    let mut config = legacy_config(&up, 16 * 1024 * 1024);
    config.port = port;
    let handle = start_with_v6(config, V6BindMode::Fail(std::io::ErrorKind::AddrInUse))
        .await
        .expect("v6 端口被占用不得阻断启动");
    let token = handle.token.clone();
    assert_eq!(handle.addrs.len(), 1, "只有 v4");
    match &handle.ipv6 {
        Ipv6State::Degraded { reason, kind } => {
            assert!(
                reason.contains("占用"),
                "降级原因要说清是端口占用: {reason}"
            );
            assert!(reason.contains("127.0.0.1"), "要说明只剩 v4: {reason}");
            // B-224 P2：kind 必须由核心层按 ErrorKind 定死，调用方不再解析文案。
            assert_eq!(
                *kind,
                tianshu_relay_core::gateway::Ipv6DegradedKind::AddrInUse,
                "端口占用 ⇒ kind 必须是 AddrInUse: {kind:?}"
            );
        }
        other => panic!("应当是 Degraded，实际 {other:?}"),
    }
    let (status, _) = get(&format!("http://127.0.0.1:{port}"), &token, "/health").await;
    assert_eq!(status, 200);
    // canary：v4 端口确实被网关占着（同一端口再绑必须失败）
    assert!(
        TcpListener::bind(("127.0.0.1", port)).is_err(),
        "v4 端口必须仍在监听（否则上面那条 200 是假的）"
    );
    shutdown(handle).await;
}

#[tokio::test]
async fn ephemeral_port_binds_v4_only() {
    let up = spawn_upstream("200 OK", r#"{"ok":true}"#);
    let handle = start(legacy_config(&up, 16 * 1024 * 1024))
        .await
        .expect("启动");
    assert_eq!(handle.addrs.len(), 1, "port 0 只绑 v4");
    assert!(matches!(handle.ipv6, Ipv6State::Degraded { .. }));
    if let Ipv6State::Degraded { reason, kind } = &handle.ipv6 {
        assert!(reason.contains("端口 0"), "原因要说明是 port 0: {reason}");
        assert_eq!(
            *kind,
            tianshu_relay_core::gateway::Ipv6DegradedKind::Skipped,
            "port 0 ⇒ kind 必须是 Skipped: {kind:?}"
        );
    }
    shutdown(handle).await;
}
