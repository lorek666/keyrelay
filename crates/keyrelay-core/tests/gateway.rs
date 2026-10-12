//! 本地网关的真实 loopback 往返（M4-S2 spec §7）。
//!
//! 用一个**假上游站点**记录收到的请求，逐条验证安全约束：
//! 无令牌不转发、转发的是站点密钥而不是本地令牌、敏感响应头不回传。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use keyrelay_core::gateway::{generate_token, start, GatewayConfig};

const SITE_KEY: &str = "sk-upstream-0123456789abcdef";

struct FakeUpstream {
    base_url: String,
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

fn respond(stream: &mut TcpStream, status: &str, body: &str, extra: &[(&str, &str)]) {
    let mut headers = String::new();
    for (name, value) in extra {
        headers.push_str(&format!("{name}: {value}\r\n"));
    }
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn spawn_fake_upstream() -> FakeUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取地址");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let raw = read_request(&mut stream);
            if let Ok(mut log) = recorder.lock() {
                log.push(raw.clone());
            }
            let first_line = raw.lines().next().unwrap_or_default().to_string();
            if first_line.contains("/v1/chat/completions") {
                respond(
                    &mut stream,
                    "200 OK",
                    r#"{"ok":true,"from":"upstream"}"#,
                    // 故意塞一个敏感头，验证网关会过滤掉
                    &[("Set-Cookie", "session=upstream-secret; Path=/")],
                );
            } else if first_line.contains("/v1/boom") {
                respond(
                    &mut stream,
                    "429 Too Many Requests",
                    r#"{"error":"slow down"}"#,
                    &[],
                );
            } else if first_line.contains("/v1/stream") {
                // 先发第一个分片，**停 1.5 秒**，再发第二个。
                // 整段缓冲的实现会让客户端在 1.5 秒后才见到第一个字节。
                let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                            Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(b"6\r\nfirst\n\r\n");
                let _ = stream.flush();
                thread::sleep(std::time::Duration::from_millis(1500));
                let _ = stream.write_all(b"7\r\nsecond\n\r\n0\r\n\r\n");
                let _ = stream.flush();
            } else {
                respond(&mut stream, "404 Not Found", r#"{"error":"no route"}"#, &[]);
            }
        }
    });

    FakeUpstream {
        base_url: format!("http://{addr}"),
        seen,
    }
}

/// 极简的 HTTP 客户端（不引入额外依赖，也不需要 reqwest 的重试层）。
fn http_request(url: &str, token: Option<&str>, path: &str, method: &str) -> (u16, String, String) {
    let without_scheme = url.trim_start_matches("http://");
    let mut stream = TcpStream::connect(without_scheme).expect("连接网关");
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {without_scheme}\r\n{auth}Content-Length: 0\r\nConnection: close\r\n\r\n"
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
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    (status, head.to_string(), body.to_string())
}

/// 与 [`http_request`] 相同，但可以带任意额外请求头（用来验证「本地令牌不管放在
/// 哪个头里都不会被转发出去」）。
fn http_request_with_headers(
    url: &str,
    path: &str,
    extra: &[(&str, &str)],
) -> (u16, String, String) {
    let without_scheme = url.trim_start_matches("http://");
    let mut stream = TcpStream::connect(without_scheme).expect("连接网关");
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: {without_scheme}\r\n");
    for (name, value) in extra {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
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
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    (status, head.to_string(), body.to_string())
}

/// 读到「响应头之后的第一批 body 字节」就返回——用来证明网关**没有**把整段响应缓冲下来。
/// 整段缓冲的实现会在上游吐完（本例 1.5 秒）之后才有第一批字节。
fn read_first_body_bytes(url: &str, token: &str, path: &str) -> String {
    let without_scheme = url.trim_start_matches("http://");
    let mut stream = TcpStream::connect(without_scheme).expect("连接网关");
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {without_scheme}\r\nAuthorization: Bearer {token}\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).expect("发送请求");
    stream.flush().ok();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf).to_string();
                if let Some(head_end) = text.find("\r\n\r\n") {
                    if text.len() > head_end + 4 {
                        return text[head_end + 4..].to_string();
                    }
                }
            }
            Err(_) => break,
        }
    }
    String::new()
}

async fn start_gateway(upstream: &FakeUpstream) -> (keyrelay_core::gateway::GatewayHandle, String) {
    let token = generate_token();
    let handle = start(GatewayConfig {
        port: 0, // 让内核分配
        token: token.clone(),
        base_url: upstream.base_url.clone(),
        api_key: SITE_KEY.to_string(),
        site_display_name: "假站点".to_string(),
    })
    .await
    .expect("网关应能启动");
    (handle, token)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_binds_loopback_only_and_serves_health() {
    let upstream = spawn_fake_upstream();
    let (handle, token) = start_gateway(&upstream).await;

    assert!(handle.addr.ip().is_loopback(), "必须只绑回环");
    assert_eq!(handle.addr.ip().to_string(), "127.0.0.1");

    let url = handle.local_url();
    let (status, _, body) = tokio::task::spawn_blocking({
        let url = url.clone();
        let token = token.clone();
        move || http_request(&url, Some(&token), "/health", "GET")
    })
    .await
    .unwrap();
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("假站点"), "{body}");

    handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_without_a_token_are_rejected_and_not_forwarded() {
    let upstream = spawn_fake_upstream();
    let (handle, token) = start_gateway(&upstream).await;
    let url = handle.local_url();

    // ① 完全没有令牌
    let (status, _, body) = tokio::task::spawn_blocking({
        let url = url.clone();
        move || http_request(&url, None, "/v1/chat/completions", "POST")
    })
    .await
    .unwrap();
    assert_eq!(status, 401, "{body}");

    // ② 错误的令牌
    let (status, _, _) = tokio::task::spawn_blocking({
        let url = url.clone();
        move || http_request(&url, Some("kr-gw-wrong"), "/v1/chat/completions", "POST")
    })
    .await
    .unwrap();
    assert_eq!(status, 401);

    // ③ `/health` 也要令牌
    let (status, _, _) = tokio::task::spawn_blocking({
        let url = url.clone();
        move || http_request(&url, None, "/health", "GET")
    })
    .await
    .unwrap();
    assert_eq!(status, 401, "/health 也必须带令牌");

    // **关键**：上游一次都没被打到
    assert!(
        upstream.seen.lock().unwrap().is_empty(),
        "未授权的请求绝不能转发到上游"
    );

    handle.shutdown();
    let _ = token;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authorized_requests_forward_with_the_site_key_not_the_local_token() {
    let upstream = spawn_fake_upstream();
    let (handle, token) = start_gateway(&upstream).await;
    let url = handle.local_url();

    let (status, head, body) = tokio::task::spawn_blocking({
        let url = url.clone();
        let token = token.clone();
        move || http_request(&url, Some(&token), "/v1/chat/completions", "POST")
    })
    .await
    .unwrap();
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("upstream"), "{body}");

    // 上游收到的是**站点密钥**
    let seen = upstream.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "应恰好转发一次");
    assert!(
        seen[0].contains(&format!("Bearer {SITE_KEY}")),
        "上游应收到站点密钥: {}",
        seen[0]
    );
    // **本地令牌绝不能出现在上游请求里**
    assert!(
        !seen[0].contains(&token),
        "本地令牌泄漏到了上游: {}",
        seen[0]
    );
    // 上游的敏感响应头不回传
    assert!(
        !head.to_ascii_lowercase().contains("set-cookie"),
        "Set-Cookie 不该回传给调用方: {head}"
    );

    handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn traversal_paths_are_refused_and_never_reach_the_upstream() {
    // M4-S2 复审 P1-1 的回归：这些形态在旧实现里会被 `url` 规整成 `/admin` 转发出去
    let upstream = spawn_fake_upstream();
    let (handle, token) = start_gateway(&upstream).await;
    let url = handle.local_url();

    for path in [
        "/v1/../../admin",
        "/v1/a/../../admin",
        "/v1/%2e%2e/admin",
        "/v1/../..%2fadmin",
    ] {
        let (status, _, body) = tokio::task::spawn_blocking({
            let url = url.clone();
            let token = token.clone();
            let path = path.to_string();
            move || http_request(&url, Some(&token), &path, "GET")
        })
        .await
        .unwrap();
        assert_eq!(status, 400, "「{path}」必须被拒: {body}");
    }

    assert_eq!(
        upstream.seen.lock().unwrap().len(),
        0,
        "被拒的路径一个字节都不该打到上游"
    );

    // 对照：正常路径照旧放行（否则「全拒」也能让上面通过）
    let (status, _, _) = tokio::task::spawn_blocking({
        let url = url.clone();
        let token = token.clone();
        move || http_request(&url, Some(&token), "/v1/chat/completions", "POST")
    })
    .await
    .unwrap();
    assert_eq!(status, 200);
    assert_eq!(upstream.seen.lock().unwrap().len(), 1);

    handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_response_is_forwarded_as_a_stream_not_buffered() {
    // M4-S2 复审 P1-2 的回归：假上游先发 `first`、停 1.5 秒、再发 `second`。
    // 整段缓冲的实现要等 1.5 秒才让客户端见到第一个字节。
    let upstream = spawn_fake_upstream();
    let (handle, token) = start_gateway(&upstream).await;
    let url = handle.local_url();

    let started = std::time::Instant::now();
    let first = tokio::task::spawn_blocking({
        let url = url.clone();
        let token = token.clone();
        move || read_first_body_bytes(&url, &token, "/v1/stream")
    })
    .await
    .unwrap();
    let elapsed = started.elapsed();

    assert!(first.contains("first"), "应读到第一个分片: {first:?}");
    assert!(
        elapsed < std::time::Duration::from_millis(1000),
        "第一个分片应远早于上游那 1.5 秒的停顿到达（实测 {elapsed:?}）——\
         超过就说明响应被整段缓冲了"
    );

    handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_local_token_never_reaches_the_upstream_in_any_header() {
    // 复审 P2-2：本地令牌可能被调用方塞进**任意**头名里；
    // 不管叫什么名字，只要值里带着本地令牌就不许转发。
    let upstream = spawn_fake_upstream();
    let (handle, token) = start_gateway(&upstream).await;
    let url = handle.local_url();

    let (status, _, _) = tokio::task::spawn_blocking({
        let url = url.clone();
        let token = token.clone();
        move || {
            http_request_with_headers(
                &url,
                "/v1/chat/completions",
                &[
                    ("Authorization", &format!("Bearer {token}")),
                    ("X-Custom-Auth", &format!("token={token}")),
                    ("Cookie", "session=local-cookie-value"),
                    ("Proxy-Authorization", "Basic bG9jYWw6c2VjcmV0"),
                ],
            )
        }
    })
    .await
    .unwrap();
    assert_eq!(status, 200);

    let seen = upstream.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    let raw = &seen[0];
    assert!(!raw.contains(&token), "本地令牌从某个头里漏到了上游: {raw}");
    assert!(
        !raw.to_ascii_lowercase().contains("local-cookie-value"),
        "Cookie 不该被转发: {raw}"
    );
    assert!(
        !raw.to_ascii_lowercase().contains("proxy-authorization"),
        "Proxy-Authorization 不该被转发: {raw}"
    );
    assert!(
        raw.contains(&format!("Bearer {SITE_KEY}")),
        "应换成站点密钥: {raw}"
    );

    handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_status_codes_pass_through_and_unknown_paths_404() {
    let upstream = spawn_fake_upstream();
    let (handle, token) = start_gateway(&upstream).await;
    let url = handle.local_url();

    let (status, _, body) = tokio::task::spawn_blocking({
        let url = url.clone();
        let token = token.clone();
        move || http_request(&url, Some(&token), "/v1/boom", "POST")
    })
    .await
    .unwrap();
    assert_eq!(status, 429, "上游状态码应原样透传: {body}");

    let (status, _, body) = tokio::task::spawn_blocking({
        let url = url.clone();
        let token = token.clone();
        move || http_request(&url, Some(&token), "/not-v1", "GET")
    })
    .await
    .unwrap();
    assert_eq!(status, 404, "非 /v1 路径应 404: {body}");

    handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_releases_the_port() {
    let upstream = spawn_fake_upstream();
    let (handle, _token) = start_gateway(&upstream).await;
    let port = handle.addr.port();
    handle.shutdown();

    // 给优雅停机一点时间，然后确认端口能重新绑定
    let mut bound = false;
    for _ in 0..50 {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            bound = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(bound, "shutdown 之后端口 {port} 应能被重新绑定");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_busy_port_is_reported_clearly() {
    let upstream = spawn_fake_upstream();
    let occupied = TcpListener::bind("127.0.0.1:0").expect("占住一个端口");
    let port = occupied.local_addr().unwrap().port();

    let err = start(GatewayConfig {
        port,
        token: generate_token(),
        base_url: upstream.base_url.clone(),
        api_key: SITE_KEY.to_string(),
        site_display_name: "假站点".to_string(),
    })
    .await
    .expect_err("端口被占用时必须报错");
    assert!(err.to_string().contains("端口"), "{err}");
}
