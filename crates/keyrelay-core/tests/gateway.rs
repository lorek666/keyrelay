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
