//! 本地网关的真实 loopback 往返（M4-S2 spec §7）。
//!
//! 用一个**假上游站点**记录收到的请求，逐条验证安全约束：
//! 无令牌不转发、转发的是站点密钥而不是本地令牌、敏感响应头不回传。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use keyrelay_core::gateway::{
    generate_token, start, GatewayConfig, GatewayHandle, BIND_RETRY_ATTEMPTS, BIND_RETRY_DELAY,
};

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
    let handle = start(GatewayConfig::single_upstream(
        0, // 让内核分配
        token.clone(),
        upstream.base_url.clone(),
        zeroize::Zeroizing::new(SITE_KEY.to_string()),
        "假站点".to_string(),
    ))
    .await
    .expect("网关应能启动");
    (handle, token)
}

/// 在**指定端口**上起网关（`port = 0` 时由内核分配）。M5-S4 的重启用例要能指定端口。
async fn start_gateway_on(
    upstream: &FakeUpstream,
    port: u16,
) -> keyrelay_core::Result<GatewayHandle> {
    start(GatewayConfig::single_upstream(
        port,
        generate_token(),
        upstream.base_url.clone(),
        zeroize::Zeroizing::new(SITE_KEY.to_string()),
        "假站点".to_string(),
    ))
    .await
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

    let err = start(GatewayConfig::single_upstream(
        port,
        generate_token(),
        upstream.base_url.clone(),
        zeroize::Zeroizing::new(SITE_KEY.to_string()),
        "假站点".to_string(),
    ))
    .await
    .expect_err("端口被占用时必须报错");
    assert!(err.to_string().contains("端口"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restarting_on_the_same_port_after_shutdown_and_wait_succeeds() {
    // B-64 的正面用例：`shutdown_and_wait().await` 返回时监听套接字必须已经释放，
    // 于是「停旧 → 立刻绑新同一端口」必然成功（旧实现要碰运气）。
    // 端口用 0 拿内核分配的实际端口，避免与 CI / 队友的固定端口冲突；跑 3 轮提高敏感度。
    let upstream = spawn_fake_upstream();

    for round in 0..3 {
        let first = start_gateway_on(&upstream, 0).await.expect("网关应能启动");
        let port = first.addr.port();
        assert_ne!(port, 0, "内核应分配真实端口");

        first.shutdown_and_wait().await;

        // ① 立刻（中间没有 sleep）连一下：不该还有人在 accept
        assert!(
            TcpStream::connect(("127.0.0.1", port)).is_err(),
            "第 {round} 轮：shutdown_and_wait 返回后 {port} 上不该还有监听者"
        );

        // ② 立刻用 OS 层直接 bind：端口必须已经可绑定
        let probe = TcpListener::bind(("127.0.0.1", port)).unwrap_or_else(|e| {
            panic!("第 {round} 轮：shutdown_and_wait 返回后端口 {port} 必须已可绑定: {e}")
        });
        drop(probe);

        // ③ 立刻 start 同端口：必须成功，端口号一致。
        //    这条耗时断言只是**粗界**（重启不该烧掉退避预算）；「有没有真的等」由单测
        //    `shutdown_and_wait_releases_the_port_before_returning` 确定性钉住。
        let started = std::time::Instant::now();
        let second = start_gateway_on(&upstream, port)
            .await
            .unwrap_or_else(|e| panic!("第 {round} 轮：同端口立刻重启必须成功: {e}"));
        let elapsed = started.elapsed();
        assert_eq!(second.addr.port(), port);
        assert!(
            elapsed < BIND_RETRY_ATTEMPTS * BIND_RETRY_DELAY / 2,
            "第 {round} 轮：重启不该烧掉退避预算（实测 {elapsed:?}）"
        );

        second.shutdown_and_wait().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_start_without_shutdown_fails_after_the_full_retry_budget() {
    // B-64 的负面用例：旧网关**不**关，第二个网关绑同一端口必须明确报错。
    // 有了退避重试之后，报错会先等满 20 × 50ms 的预算——把这段耗时也断言进去：
    // 既钉住「确实重试过」，也钉住「没有无限重试」。
    let upstream = spawn_fake_upstream();
    let first = start_gateway_on(&upstream, 0).await.expect("网关应能启动");
    let port = first.addr.port();

    let started = std::time::Instant::now();
    let err = start_gateway_on(&upstream, port)
        .await
        .expect_err("同一端口上的第二个网关必须报错");
    let elapsed = started.elapsed();
    let text = err.to_string();

    assert!(text.contains("端口"), "文案要提端口: {text}");
    assert!(text.contains("占用"), "文案要说清是被占用: {text}");
    assert!(
        text.contains(&port.to_string()),
        "文案要带实际端口号 {port}: {text}"
    );
    assert!(
        elapsed >= BIND_RETRY_ATTEMPTS * BIND_RETRY_DELAY,
        "必须等满退避预算 {}×{:?}（实测 {elapsed:?}）",
        BIND_RETRY_ATTEMPTS,
        BIND_RETRY_DELAY
    );
    assert!(
        elapsed < BIND_RETRY_ATTEMPTS * BIND_RETRY_DELAY * 5,
        "不许无界重试（实测 {elapsed:?}）"
    );

    first.shutdown_and_wait().await;
}

// ==================================================== M7-S1：空路由表的 legacy 等价

/// 带 body 的 POST（既有 `http_request` 固定 `Content-Length: 0`，用来验证空路由表时
/// **请求体逐字节原样转发**需要能发 body）。
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

/// **章程 §3.1 点名的测试**：`route.is_empty()` 时转发行为必须与单上游时代**逐字节相同**。
///
/// 四条断言分别对应「不引入新行为」的四个面：目标、凭证、请求体、请求次数。
/// 若将来有人在空表路径上也接了 body 解析 / 别名改写 / 熔断，这条会红。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_route_table_keeps_legacy_behaviour() {
    let upstream = spawn_fake_upstream();
    let (handle, token) = start_gateway(&upstream).await;
    let url = format!("http://{}", handle.addr);

    // 这个 body 里**故意**放一个 `model`：若空表路径也做了别名/路由处理，它就有机会被改写。
    let body =
        r#"{"model":"gpt-5.6","messages":[{"role":"user","content":"hi"}],"temperature":0.50}"#;
    let (status, resp_body) = tokio::task::spawn_blocking({
        let url = url.clone();
        let token = token.clone();
        let body = body.to_string();
        move || http_post(&url, &token, "/v1/chat/completions", &body)
    })
    .await
    .expect("阻塞任务");

    assert_eq!(status, 200);
    assert!(resp_body.contains("upstream"), "{resp_body}");

    let seen = upstream.seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "空路由表必须只发一次请求");

    let raw = &seen[0];
    // ① 转发目标是 config.base_url 对应的那个上游（就是这个假上游）
    assert!(raw.starts_with("POST /v1/chat/completions"), "{raw}");
    // ② 凭证是站点密钥，不是本地令牌
    assert!(
        raw.contains(&format!("authorization: Bearer {SITE_KEY}")),
        "{raw}"
    );
    assert!(!raw.contains(&token), "本地令牌不得出现在上游请求里: {raw}");
    // ③ 请求体**逐字节**原样（`0.50` 没有被规范化成 `0.5`）
    assert!(
        raw.ends_with(body),
        "空路由表时请求体必须逐字节原样转发:\n{raw}"
    );
    assert!(raw.contains("0.50"), "数值形态不得被重序列化改写: {raw}");
}

// ============================================================ M16-S4：legacy 路径的已回收守卫

/// 起一个 legacy（空路由表）网关，并可控地设置「已回收集合」与失败事件出口。
async fn start_legacy_with_guard(
    upstream: &FakeUpstream,
    legacy_key_ref: Option<&str>,
    revoked: Option<&[&str]>,
) -> (
    GatewayHandle,
    String,
    Arc<Mutex<Vec<keyrelay_core::gateway::GatewayFailure>>>,
) {
    let token = generate_token();
    let failures = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&failures);
    let mut config = GatewayConfig::single_upstream(
        0,
        token.clone(),
        upstream.base_url.clone(),
        zeroize::Zeroizing::new(SITE_KEY.to_string()),
        "假站点".to_string(),
    );
    config.site_id = 7;
    config.legacy_key_ref = legacy_key_ref.map(str::to_string);
    config.revoked_refs = revoked.map(|refs| {
        Arc::new(Mutex::new(refs.iter().map(|r| (*r).to_string()).collect()))
    });
    config.on_failure = Some(Arc::new(move |f| {
        if let Ok(mut log) = sink.lock() {
            log.push(f);
        }
    }));
    let handle = start(config).await.expect("网关应能启动");
    (handle, token, failures)
}

/// P3-4 + P2-7 + B-111：legacy 路径的密钥**已被回收**时，拒绝转发并留一条事件。
///
/// 为什么必须有这条：M8-S4 起密钥可以「一键轮换」，而运行中的网关手里是旧密钥的**快照**；
/// 轮换后旧 key 在站点侧已删、本地被标成已回收，网关却还在用它 —— 用户看到的
/// 是一个没有解释的 401/502。事件把「为什么」与「怎么办」写清楚。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_legacy_key_is_refused_and_reported() {
    let upstream = spawn_fake_upstream();
    let (handle, token, failures) = start_legacy_with_guard(
        &upstream,
        Some("kr/key/9/secret"),
        Some(&["kr/key/9/secret"]),
    )
    .await;
    let url = handle.local_url();

    let (status, body) = tokio::task::spawn_blocking({
        let url = url.clone();
        let token = token.clone();
        move || http_post(&url, &token, "/v1/chat/completions", "{}")
    })
    .await
    .unwrap();

    assert_eq!(status, 503, "已回收的密钥必须被拒绝（不再发出去）: {body}");
    assert!(
        body.contains("已被回收"),
        "文案要说清原因与出路（重启网关）: {body}"
    );
    assert_eq!(
        upstream.seen.lock().unwrap().len(),
        0,
        "**一个字节都不该发给上游**（旧实现会继续用那把已回收的密钥）"
    );

    let log = failures.lock().unwrap().clone();
    assert_eq!(log.len(), 1, "必须留一条事件（B-111 的唯一例外）: {log:?}");
    assert_eq!(log[0].site_id, 7, "事件带 site_id");
    assert_eq!(
        log[0].status, 0,
        "「没发出去」没有 HTTP 状态码 ⇒ 用 0 这个哨兵（编 503 会让事件说谎）"
    );
    assert!(
        log[0].reason.contains("已被回收") && log[0].reason.contains("重启"),
        "reason 要同时给出原因与出路: {}",
        log[0].reason
    );

    handle.shutdown_and_wait().await;
}

/// B-111 的反向对照：legacy 路径的**上游失败**仍然不产生事件（M7 D-1 保持）。
///
/// 与上一条合起来才是完整口径：**配置类**失败（密钥已回收）写事件，
/// **上游类**失败（状态码 / 传输错误）不写——空表路径在这一维度上逐字节不变。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_upstream_failures_still_write_no_event() {
    let upstream = spawn_fake_upstream();
    // `legacy_key_ref` 给一个**没有**被回收的引用 ⇒ 守卫不触发，走原路径
    let (handle, token, failures) =
        start_legacy_with_guard(&upstream, Some("kr/key/9/secret"), None).await;
    let url = handle.local_url();

    // `/v1/boom` 在假上游里恒回 429（上游类失败）
    let (status, _) = tokio::task::spawn_blocking({
        let url = url.clone();
        let token = token.clone();
        move || http_post(&url, &token, "/v1/boom", "{}")
    })
    .await
    .unwrap();

    assert_eq!(status, 429, "上游状态码原样透传");
    assert_eq!(upstream.seen.lock().unwrap().len(), 1, "应当发出去一次");
    assert!(
        failures.lock().unwrap().is_empty(),
        "legacy 路径的上游失败**不得**产生事件（M7 D-1：空表路径与单上游时代逐字节相同）"
    );

    handle.shutdown_and_wait().await;
}
