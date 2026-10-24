//! M39-S1：`GatewaySnapshot` 热更新。
//!
//! 覆盖：新请求用新快照 / 旧快照对在途请求仍然完整（不可变 + Arc）/ `runtime: None` 的兼容路径 /
//! `start()` 的集合不变式覆盖快照 / `Debug` 不打印密钥。
//!
//! 假上游是本地 `TcpListener`（**不联网**）。

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use tianshu_relay_core::gateway::{
    start, GatewayConfig, GatewayHandle, GatewaySnapshot, UpstreamTimeout,
};
use tianshu_relay_core::routing::{BreakerPolicy, RouteTable, Upstream};
use zeroize::Zeroizing;

const MODEL: &str = "m39-model";
const REF_A: &str = "kr/key/1/secret";
const REF_B: &str = "kr/key/2/secret";
const KEY_A: &str = "sk-a-0123456789abcdef";
const KEY_B: &str = "sk-b-0123456789abcdef";

/// 读一个完整的 HTTP 请求（按 `Content-Length` 等 body），失败时返回已读到的部分。
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

/// 起一个永远回 `200 OK` + `{"from":"site<N>"}` 的假上游；返回 `(base_url, 命中计数)`。
fn spawn_tagged(site_id: i64) -> (String, Arc<Mutex<usize>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取地址");
    let hits = Arc::new(Mutex::new(0usize));
    let counter = Arc::clone(&hits);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = read_request(&mut stream);
            if let Ok(mut n) = counter.lock() {
                *n += 1;
            }
            let body = format!(r#"{{"from":"site{site_id}"}}"#);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    (format!("http://{addr}"), hits)
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

async fn post(handle: &GatewayHandle, token: &str) -> (u16, String) {
    let url = handle.local_url();
    let token = token.to_string();
    let body = format!(r#"{{"model":"{MODEL}","messages":[]}}"#);
    tokio::task::spawn_blocking(move || http_post(&url, &token, "/v1/chat/completions", &body))
        .await
        .expect("阻塞任务")
}

fn upstream(site_id: i64, base_url: &str, key_ref: &str) -> Upstream {
    Upstream {
        site_id,
        key_id: None,
        base_url: base_url.to_string(),
        key_ref: key_ref.to_string(),
        models: vec![MODEL.to_string()],
        rate: None,
        balance_usd: None,
        latency_ms: None,
        timeout_ms: None,
    }
}

fn keys(pairs: &[(&str, &str)]) -> HashMap<String, Zeroizing<String>> {
    let mut map = HashMap::new();
    for (reference, plain) in pairs {
        map.insert(reference.to_string(), Zeroizing::new(plain.to_string()));
    }
    map
}

/// 唯一的配置构造点（`runtime` 由调用方决定）。
fn base_config(
    route: RouteTable,
    keys_by_ref: HashMap<String, Zeroizing<String>>,
) -> GatewayConfig {
    GatewayConfig {
        port: 0,
        token: "local-token-for-snapshot-tests".to_string(),
        key_id: None,
        site_id: 0,
        // 路由非空时不被使用；置空正好证明这一点。
        base_url: String::new(),
        api_key: Zeroizing::new(String::new()),
        site_display_name: "快照测试".to_string(),
        route,
        breaker: BreakerPolicy::default(),
        keys_by_ref,
        upstream_timeout: UpstreamTimeout::default(),
        revoked_refs: None,
        on_failure: None,
        on_observation: None,
        on_usage: None,
        upstream_proxy: None,
        legacy_key_ref: None,
        // M42-S1：请求体上限（既有用例用默认 16 MiB）
        max_request_bytes: tianshu_relay_core::gateway::DEFAULT_MAX_REQUEST_BYTES,
        // M39-S3：单候选 + 默认 guard（快照测试与负载均衡无关）
        lb_top_n: 1,
        // M46-S4：机械补字段，行为不变（0 = 走全部候选）
        max_attempts: 0,
        guard_policy: tianshu_relay_core::routing::SiteGuardPolicy::default(),
        runtime: None,
    }
}

// ============================================================ 用例

/// 发布新快照后，**新请求**使用新路由（旧上游不再被请求）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_request_uses_the_published_snapshot() {
    let (url_a, hits_a) = spawn_tagged(1);
    let (url_b, hits_b) = spawn_tagged(2);

    let route_a = RouteTable::new(vec![upstream(1, &url_a, REF_A)]);
    let runtime = Arc::new(std::sync::RwLock::new(Arc::new(GatewaySnapshot::new(
        1,
        route_a.clone(),
        keys(&[(REF_A, KEY_A)]),
    ))));
    let mut config = base_config(route_a, keys(&[(REF_A, KEY_A)]));
    config.runtime = Some(Arc::clone(&runtime));

    let handle = start(config).await.expect("网关应能启动");
    let token = handle.token.clone();

    let (status, body) = post(&handle, &token).await;
    assert_eq!(status, 200, "首个请求应当成功: {body}");
    assert!(body.contains("site1"), "首个请求走快照里的上游 A: {body}");

    // 发布一份把候选换成 B 的快照（不可变整体替换）
    *runtime.write().expect("写锁") = Arc::new(GatewaySnapshot::new(
        2,
        RouteTable::new(vec![upstream(2, &url_b, REF_B)]),
        keys(&[(REF_B, KEY_B)]),
    ));

    let (status, body) = post(&handle, &token).await;
    assert_eq!(status, 200, "发布后的请求应当成功: {body}");
    assert!(
        body.contains("site2"),
        "**新请求必须用新快照**（热更新生效）: {body}"
    );
    assert_eq!(*hits_a.lock().expect("锁"), 1, "旧上游不再被请求");
    assert_eq!(*hits_b.lock().expect("锁"), 1);

    handle.shutdown_and_wait().await;
}

/// 旧快照对象在发布之后**仍然完整可用**（不可变 + `Arc`：换指针不撕裂）。
#[tokio::test]
async fn an_in_flight_request_keeps_the_snapshot_it_started_with() {
    let route_a = RouteTable::new(vec![upstream(1, "http://127.0.0.1:1", REF_A)]);
    let runtime = Arc::new(std::sync::RwLock::new(Arc::new(GatewaySnapshot::new(
        1,
        route_a,
        keys(&[(REF_A, KEY_A)]),
    ))));

    // 「在途请求」先克隆一份并持有
    let in_flight = Arc::clone(&runtime.read().expect("读锁"));

    *runtime.write().expect("写锁") = Arc::new(GatewaySnapshot::new(
        2,
        RouteTable::new(vec![upstream(2, "http://127.0.0.1:2", REF_B)]),
        keys(&[(REF_B, KEY_B)]),
    ));

    assert_eq!(in_flight.generation, 1, "手里的快照不会被改写");
    assert_eq!(in_flight.route.candidates(MODEL)[0].site_id, 1);
    assert_eq!(
        in_flight.keys_by_ref.get(REF_A).map(|k| k.as_str()),
        Some(KEY_A)
    );
    assert_eq!(runtime.read().expect("读锁").generation, 2, "容器里是新的");
}

/// `runtime: None` ⇒ 行为与加这个字段之前**逐字相同**（用静态 `route`）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_static_config_without_runtime_behaves_exactly_as_before() {
    let (url_a, hits_a) = spawn_tagged(1);
    let config = base_config(
        RouteTable::new(vec![upstream(1, &url_a, REF_A)]),
        keys(&[(REF_A, KEY_A)]),
    );
    assert!(config.runtime.is_none());

    let handle = start(config).await.expect("网关应能启动");
    let token = handle.token.clone();
    let (status, body) = post(&handle, &token).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("site1"));
    assert_eq!(*hits_a.lock().expect("锁"), 1);
    handle.shutdown_and_wait().await;
}

/// `start()` 的集合不变式也覆盖**快照**：路由引用的引用没有明文 ⇒ 拒绝启动，且不打印引用原文。
#[tokio::test]
async fn start_rejects_a_snapshot_whose_route_references_unknown_keys() {
    let mut config = base_config(RouteTable::default(), HashMap::new());
    // 静态路由为空 ⇒ 先过「base_url 非空」那道检查（否则测的就是另一条错误）
    config.base_url = "http://127.0.0.1:1".to_string();
    config.runtime = Some(Arc::new(std::sync::RwLock::new(Arc::new(
        GatewaySnapshot::new(
            1,
            RouteTable::new(vec![upstream(1, "http://127.0.0.1:1", REF_A)]),
            HashMap::new(), // 有路由、没明文 ⇒ 必须被拒
        ),
    ))));

    let err = start(config)
        .await
        .expect_err("快照里的未知引用必须拒绝启动");
    let text = err.to_string();
    assert!(text.contains("密钥映射"), "文案要说清根因: {text}");
    assert!(!text.contains(REF_A), "**不得**打印 key_ref 原文: {text}");
}

/// `Debug` 不打印任何密钥（红线）。
#[test]
fn the_snapshot_debug_does_not_print_keys() {
    let snapshot = GatewaySnapshot::new(
        7,
        RouteTable::new(vec![upstream(1, "http://127.0.0.1:1", REF_A)]),
        keys(&[(REF_A, KEY_A)]),
    );
    let text = format!("{snapshot:?}");
    assert!(text.contains("generation"), "至少能看出是哪个代号: {text}");
    assert!(!text.contains(KEY_A), "**不得**打印明文: {text}");
    assert!(!text.contains(REF_A), "也不打印引用: {text}");
}
