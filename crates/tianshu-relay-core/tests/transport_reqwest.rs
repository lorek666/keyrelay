//! `ReqwestTransport` 端到端测试：全部走 `127.0.0.1` 上的极简假服务器，**不依赖外网**。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tianshu_relay_core::error::Error;
use tianshu_relay_core::site::transport::{HttpRequest, HttpTransport, Method};
use tianshu_relay_core::site::transport_reqwest::{ReqwestTransport, TransportConfig};

struct FakeServer {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
}

fn http_response(status_line: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
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

fn spawn_server(responses: Vec<String>) -> FakeServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取本地地址");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&requests);

    thread::spawn(move || {
        for response in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let raw = read_request(&mut stream);
            if let Ok(mut recorded) = recorder.lock() {
                recorded.push(raw);
            }
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    FakeServer {
        base_url: format!("http://{addr}"),
        requests,
    }
}

/// 接受连接但永不响应，用于验证超时映射
fn spawn_silent_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取本地地址");
    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            thread::sleep(Duration::from_secs(2));
            drop(stream);
        }
    });
    format!("http://{addr}")
}

fn transport(timeout: Duration) -> ReqwestTransport {
    ReqwestTransport::new(TransportConfig {
        timeout,
        ..TransportConfig::default()
    })
    .expect("构造传输层")
}

#[tokio::test]
async fn get_sends_method_path_and_user_agent() {
    let server = spawn_server(vec![http_response(
        "200 OK",
        "application/json",
        r#"{"success":true}"#,
    )]);
    let transport = transport(Duration::from_secs(5));

    let response = transport
        .request(HttpRequest::new(
            Method::Get,
            format!("{}/api/status", server.base_url),
        ))
        .await
        .expect("请求成功");

    assert_eq!(response.status, 200);
    assert_eq!(response.json_value().unwrap()["success"], true);

    let raw = server.requests.lock().unwrap()[0].clone();
    assert!(
        raw.starts_with("GET /api/status HTTP/1.1"),
        "实际请求: {raw}"
    );
    let lower = raw.to_lowercase();
    assert!(
        lower.contains("user-agent: tianshu-relay/"),
        "缺少 UA: {raw}"
    );
}

#[tokio::test]
async fn post_sends_json_body_and_headers() {
    let server = spawn_server(vec![http_response("200 OK", "application/json", "{}")]);
    let transport = transport(Duration::from_secs(5));

    transport
        .request(
            HttpRequest::new(Method::Post, format!("{}/api/user/login", server.base_url))
                .header("X-Test", "yes")
                .json_body(&serde_json::json!({"username": "me", "password": "pw"}))
                .unwrap(),
        )
        .await
        .expect("请求成功");

    let raw = server.requests.lock().unwrap()[0].clone();
    assert!(
        raw.starts_with("POST /api/user/login HTTP/1.1"),
        "实际请求: {raw}"
    );
    assert!(raw
        .to_lowercase()
        .contains("content-type: application/json"));
    assert!(raw.contains("x-test: yes") || raw.contains("X-Test: yes"));
    assert!(raw.contains(r#""username":"me""#), "请求体缺失: {raw}");
}

#[tokio::test]
async fn non_2xx_status_and_body_are_passed_through() {
    let server = spawn_server(vec![http_response(
        "403 Forbidden",
        "application/json",
        r#"{"error":{"code":"insufficient_user_quota"}}"#,
    )]);
    let transport = transport(Duration::from_secs(5));

    let response = transport
        .request(HttpRequest::new(
            Method::Get,
            format!("{}/v1/models", server.base_url),
        ))
        .await
        .expect("传输层不把 4xx 当错误");

    assert_eq!(response.status, 403);
    assert_eq!(
        response.json_value().unwrap()["error"]["code"],
        "insufficient_user_quota"
    );
}

#[tokio::test]
async fn retry_after_header_is_parsed() {
    let server = spawn_server(vec![http_response(
        "429 Too Many Requests",
        "application/json",
        "{}",
    )
    .replace("Connection: close", "Connection: close\r\nRetry-After: 7")]);
    let transport = transport(Duration::from_secs(5));

    let response = transport
        .request(HttpRequest::new(
            Method::Get,
            format!("{}/api/status", server.base_url),
        ))
        .await
        .expect("请求成功");

    assert_eq!(response.status, 429);
    assert_eq!(response.retry_after_secs(), Some(7));
}

#[tokio::test]
async fn timeout_maps_to_transport_error() {
    let base_url = spawn_silent_server();
    let transport = transport(Duration::from_millis(300));

    let err = transport
        .request(HttpRequest::new(
            Method::Get,
            format!("{base_url}/api/status"),
        ))
        .await
        .unwrap_err();

    match err {
        Error::Transport(message) => assert!(message.contains("超时"), "错误信息: {message}"),
        other => panic!("期望 Transport 错误，实际: {other:?}"),
    }
}

#[tokio::test]
async fn redirect_is_passed_through_not_followed() {
    // 复审 P2-2：默认必须把 3xx 原样交给适配器（用于识别会话失效/域名迁移），
    // 而不是变成 TooManyRedirects 错误。
    let server = spawn_server(vec![
        "HTTP/1.1 302 Found\r\nLocation: https://login.example.com/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
    ]);
    let transport = transport(Duration::from_secs(5));

    let response = transport
        .request(HttpRequest::new(
            Method::Get,
            format!("{}/api/status", server.base_url),
        ))
        .await
        .expect("3xx 不应变成传输错误");

    assert_eq!(response.status, 302);
    assert_eq!(
        response.header("Location"),
        Some("https://login.example.com/")
    );
    assert_eq!(server.requests.lock().unwrap().len(), 1, "不得跟随重定向");
}

#[tokio::test]
async fn real_stack_retries_429_with_retry_after() {
    // 复审 P1-1 的**真实栈**回归测试：ReqwestTransport（429 作为 Ok 返回）
    // 叠加重试装饰器后必须真的重试，而不是一次即返。
    use std::sync::Arc;
    use tianshu_relay_core::site::retry::{RecordingSleeper, RetryPolicy, RetryingTransport};

    let server = spawn_server(vec![
        http_response("429 Too Many Requests", "application/json", "{}")
            .replace("Connection: close", "Connection: close\r\nRetry-After: 2"),
        http_response("200 OK", "application/json", r#"{"success":true}"#),
    ]);

    let inner = transport(Duration::from_secs(5));
    let sleeper = Arc::new(RecordingSleeper::default());
    let retrying = RetryingTransport::with_sleeper(inner, RetryPolicy::default(), sleeper.clone());

    let response = retrying
        .request(HttpRequest::new(
            Method::Get,
            format!("{}/api/status", server.base_url),
        ))
        .await
        .expect("请求成功");

    assert_eq!(response.status, 200, "重试后应拿到 200");
    assert_eq!(
        server.requests.lock().unwrap().len(),
        2,
        "服务端应收到两次请求（429 后重试一次）"
    );
    assert_eq!(
        sleeper.calls(),
        vec![Duration::from_secs(2)],
        "等待时长应取 Retry-After"
    );
}

/// M19-S2 / B-162：连接层失败必须**带着类别**走出 trait 边界。
///
/// 判据是 `reqwest::Error::is_connect()`——DNS / TCP / TLS 握手阶段就失败，请求体
/// 一个字节都没进对端。只有这一类可以安全重放（对端没看到请求，不可能计费）。
///
/// 这条用例同时是 `describe()` 分类的**真实 socket 证据**：`127.0.0.1:1` 上没有监听者，
/// TCP 直接 RST。用 mock 是证明不了的——mock 里的错误是我们自己造的形状。
#[tokio::test]
async fn refused_connection_is_classified_as_not_delivered() {
    let transport = transport(Duration::from_secs(2));
    let err = transport
        .request(HttpRequest::new(
            Method::Post,
            "http://127.0.0.1:1/api/probe/run",
        ))
        .await
        .unwrap_err();

    assert!(
        matches!(err, Error::NotDelivered(_)),
        "连接被拒 ⇒ 请求未送达 ⇒ 必须可重放；实际: {err:?}"
    );
    assert!(err.is_not_delivered());
    assert!(err.is_retryable(), "站点侧重试策略不得因加变体而退化");
    assert!(
        err.to_string().contains("连接未建立"),
        "文案要说清「没连上、请求没送达」: {err}"
    );
}

/// 对照：超时**不是**「未送达」。
///
/// 已连上但等不到响应头（读超时）说明请求已经送出去了，可能已被处理并计费 ⇒ 不可重放。
/// 这条与上一条一起，钉死 `describe()` 里两个分支的边界。
/// M21-S1 / B-164：配了 `http://` 代理时，超时错误要带一条**配置诊断**。
///
/// 用的是本地假代理（接受连接后沉默），所以这里复现的是「代理那头挂住」这一**形状**，
/// 与 M18-S1 真机那次（`http://` 代理 + fake-IP，约 17s，两个谓词都不满足）同源。
/// 真机那个 fake-IP 场景在 CI 里不可移植，所以用本地等价物承载判据。
#[tokio::test]
async fn a_timeout_through_an_http_proxy_carries_a_diagnosis() {
    // 假代理：收下连接就沉默，让客户端超时
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定代理端口");
    let proxy_addr = listener.local_addr().expect("读取代理地址");
    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            thread::sleep(Duration::from_secs(5));
            drop(stream);
        }
    });

    let silent = spawn_silent_server();
    // 代理地址里带 userinfo：诊断不得把它拼进去（代理商 + 凭据都要脱敏）
    let transport = ReqwestTransport::new(TransportConfig {
        timeout: Duration::from_millis(300),
        proxy: Some(format!("http://alice:s3cr3t-token@{proxy_addr}")),
        ..TransportConfig::default()
    })
    .expect("合法代理应可构造");

    let err = transport
        .request(HttpRequest::new(
            Method::Get,
            format!("{silent}/api/status"),
        ))
        .await
        .expect_err("代理挂住必须超时");

    assert!(matches!(err, Error::Transport(_)), "{err:?}");
    let message = err.to_string();
    assert!(
        message.contains("请求超时"),
        "主错误必须仍是超时: {message}"
    );
    assert!(message.contains("fake-IP"), "应附上代理诊断: {message}");
    assert!(
        message.contains("socks5"),
        "诊断要给出可执行的下一步: {message}"
    );
    assert!(!message.contains("s3cr3t-token"), "泄漏代理凭据: {message}");
    assert!(!message.contains("alice"), "泄漏代理用户名: {message}");
}

/// 配 `socks5://` 代理时的失败**不**带诊断。
///
/// 说明（别被用例名误导）：这里指向一个没人听的 socks5 端口，实测拿到的是
/// `连接未建立（NotDelivered）`——**不是**超时，所以它走不到 `describe()` 的超时分支。
/// 「socks5 + 真超时不带诊断」由同文件的单测 `socks_proxies_do_not_get_the_timeout_hint`
/// 直接钉住（那条不需要真的跑通 socks 握手）。本条负责的是**另一件事**：
/// 即使请求真的失败了，也绝不允许把「建议改用 socks5」这句话塞给一个已经在用 socks 的用户。
#[tokio::test]
async fn a_socks5_proxy_failure_carries_no_proxy_diagnosis() {
    let silent = spawn_silent_server();
    let transport = ReqwestTransport::new(TransportConfig {
        timeout: Duration::from_millis(300),
        proxy: Some("socks5://127.0.0.1:1".to_string()),
        ..TransportConfig::default()
    })
    .expect("socks5 代理合法");

    let err = transport
        .request(HttpRequest::new(
            Method::Get,
            format!("{silent}/api/status"),
        ))
        .await
        .expect_err("应失败");

    let message = err.to_string();
    assert!(
        !message.contains("fake-IP"),
        "socks 代理不该被建议改走 socks5: {message}"
    );
}

#[tokio::test]
async fn timeout_is_not_classified_as_not_delivered() {
    let base_url = spawn_silent_server();
    let transport = transport(Duration::from_millis(300));

    let err = transport
        .request(HttpRequest::new(
            Method::Get,
            format!("{base_url}/api/status"),
        ))
        .await
        .unwrap_err();

    assert!(
        !err.is_not_delivered(),
        "超时可能已送达 ⇒ 不得判为未送达；实际: {err:?}"
    );
    assert!(matches!(err, Error::Transport(_)), "{err:?}");
}
