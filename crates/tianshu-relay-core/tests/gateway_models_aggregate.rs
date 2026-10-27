//! M39-S2：`GET /v1/models` 的本地聚合 + 模型不存在的 404 判据。
//!
//! 假上游是本地 `TcpListener`（**不联网**）；核心判据是「聚合时上游 `/v1/models` 命中 0 次」。
//!
//! 关键语义（spec §4.1/§4.3）：**空 `models` = 未知 ⇒ 通配（fail-open）**。
//! 空目录站点不贡献模型名，但它让任何模型都「可能可服务」⇒ **不能本地 404**。

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::Value;
use tianshu_relay_core::gateway::{start, GatewayConfig, GatewayHandle, UpstreamTimeout};
use tianshu_relay_core::routing::{BreakerPolicy, RouteTable, Upstream};
use zeroize::Zeroizing;

const TOKEN: &str = "local-token-for-models-tests";
const REF_A: &str = "kr/key/1/secret";
const REF_B: &str = "kr/key/2/secret";
const KEY_A: &str = "sk-a-0123456789abcdef";
const KEY_B: &str = "sk-b-0123456789abcdef";

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

/// 假上游句柄：`(base_url, 命中计数, 收到的请求体)`。
type UpstreamHandle = (String, Arc<Mutex<usize>>, Arc<Mutex<Vec<String>>>);

/// 起一个假上游：记录命中次数与收到的请求体，回 `200 {"from":"site<N>"}`。
fn spawn_upstream(site_id: i64) -> UpstreamHandle {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取地址");
    let hits = Arc::new(Mutex::new(0usize));
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let counter = Arc::clone(&hits);
    let recorded = Arc::clone(&bodies);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let request = read_request(&mut stream);
            if let Ok(mut n) = counter.lock() {
                *n += 1;
            }
            if let Some((_, body)) = request.split_once("\r\n\r\n") {
                if let Ok(mut list) = recorded.lock() {
                    list.push(body.to_string());
                }
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
    (format!("http://{addr}"), hits, bodies)
}

/// 发一个请求（`GET` 时 `body` 传 `None`）。
fn http_call(
    url: &str,
    token: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> (u16, String) {
    let without_scheme = url.trim_start_matches("http://");
    let mut stream = TcpStream::connect(without_scheme).expect("连接网关");
    let body = body.unwrap_or("");
    let headers = if body.is_empty() {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: {without_scheme}\r\n\
             Authorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        )
    } else {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: {without_scheme}\r\n\
             Authorization: Bearer {token}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    };
    stream.write_all(headers.as_bytes()).expect("发送请求");
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

async fn call(
    handle: &GatewayHandle,
    method: &str,
    path: &str,
    body: Option<String>,
) -> (u16, String) {
    let url = handle.local_url();
    let method = method.to_string();
    let path = path.to_string();
    tokio::task::spawn_blocking(move || http_call(&url, TOKEN, &method, &path, body.as_deref()))
        .await
        .expect("阻塞任务")
}

fn upstream(site_id: i64, base_url: &str, key_ref: &str, models: &[&str]) -> Upstream {
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

fn keys() -> HashMap<String, Zeroizing<String>> {
    let mut map = HashMap::new();
    map.insert(REF_A.to_string(), Zeroizing::new(KEY_A.to_string()));
    map.insert(REF_B.to_string(), Zeroizing::new(KEY_B.to_string()));
    map
}

fn base_config(
    route: RouteTable,
    keys_by_ref: HashMap<String, Zeroizing<String>>,
) -> GatewayConfig {
    GatewayConfig {
        catalog: None,
        port: 0,
        token: TOKEN.to_string(),
        key_id: None,
        site_id: 0,
        base_url: String::new(),
        api_key: Zeroizing::new(String::new()),
        site_display_name: "模型聚合测试".to_string(),
        route,
        breaker: BreakerPolicy::default(),
        keys_by_ref,
        upstream_timeout: UpstreamTimeout::default(),
        revoked_refs: None,
        on_failure: None,
        on_observation: None,
        on_usage: None,
        budget_check: None,
        on_budget_breach: None,
        routing_rules: Vec::new(),
        upstream_proxy: None,
        legacy_key_ref: None,
        // M42-S1：请求体上限（既有用例用默认 16 MiB）
        max_request_bytes: tianshu_relay_core::gateway::DEFAULT_MAX_REQUEST_BYTES,
        // M39-S3：单候选 + 默认 guard（聚合测试与负载均衡无关）
        lb_top_n: 1,
        max_attempts: 0,
        guard_policy: tianshu_relay_core::routing::SiteGuardPolicy::default(),
        runtime: None,
    }
}

fn parse(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or(Value::Null)
}

fn hit_count(hits: &Arc<Mutex<usize>>) -> usize {
    *hits.lock().expect("计数锁")
}

// ============================================================ 1) 本地聚合，上游零命中

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn models_endpoint_is_served_locally_and_never_hits_an_upstream() {
    let (base_a, hits_a, _) = spawn_upstream(1);
    let (base_b, hits_b, _) = spawn_upstream(2);
    let route = RouteTable::new(vec![
        upstream(1, &base_a, REF_A, &["b-model", "a-model"]),
        upstream(2, &base_b, REF_B, &["c-model"]),
    ]);
    let handle = start(base_config(route, keys())).await.expect("启动网关");

    let (status, body) = call(&handle, "GET", "/v1/models", None).await;
    assert_eq!(status, 200, "{body}");
    let value = parse(&body);
    assert_eq!(value["object"], "list");
    let ids: Vec<&str> = value["data"]
        .as_array()
        .expect("data 数组")
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect();
    assert_eq!(ids, vec!["a-model", "b-model", "c-model"], "并集 + 升序");
    assert_eq!(hit_count(&hits_a), 0, "聚合不得请求上游 A 的 /v1/models");
    assert_eq!(hit_count(&hits_b), 0, "聚合不得请求上游 B 的 /v1/models");
    handle.shutdown_and_wait().await;
}

// ============================================================ 2) 响应键集合（安全）

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn models_payload_has_only_id_object_created_owned_by() {
    let (base_a, _, _) = spawn_upstream(1);
    let route = RouteTable::new(vec![upstream(1, &base_a, REF_A, &["only-model"])]);
    let handle = start(base_config(route, keys())).await.expect("启动网关");

    let (status, body) = call(&handle, "GET", "/v1/models", None).await;
    assert_eq!(status, 200);
    let value = parse(&body);

    // 顶层只有 object / data
    let mut top: Vec<&str> = value
        .as_object()
        .expect("顶层对象")
        .keys()
        .map(String::as_str)
        .collect();
    top.sort_unstable();
    assert_eq!(top, vec!["data", "object"], "顶层键集合：{value}");

    // 每一项只有 id / object / created / owned_by —— 多一个键就红
    for item in value["data"].as_array().expect("data 数组") {
        let mut keys: Vec<&str> = item
            .as_object()
            .expect("模型项对象")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["created", "id", "object", "owned_by"],
            "模型项键集合：{item}"
        );
        assert_eq!(item["object"], "model");
        assert_eq!(item["created"], 0);
        assert_eq!(item["owned_by"], "tianshu-relay");
    }

    // 安全：响应文本不得出现站点标识 / 密钥引用 / 域名 / 显示名
    let text = body.clone();
    for forbidden in [
        base_a.as_str(),
        REF_A,
        KEY_A,
        "模型聚合测试",
        "site_id",
        "key_ref",
    ] {
        assert!(
            !text.contains(forbidden),
            "响应里不得出现 {forbidden:?}：{text}"
        );
    }
    handle.shutdown_and_wait().await;
}

// ============================================================ 3) 目录为空 ⇒ 旧透传

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn models_endpoint_falls_back_to_upstream_when_the_route_has_no_models() {
    let (base_a, hits_a, _) = spawn_upstream(1);
    // 非空路由，但每个上游的 models 都是空的（= 目录未知）
    let route = RouteTable::new(vec![
        upstream(1, &base_a, REF_A, &[]),
        upstream(2, &base_a, REF_B, &[]),
    ]);
    let handle = start(base_config(route, keys())).await.expect("启动网关");

    let (status, body) = call(&handle, "GET", "/v1/models", None).await;
    assert_eq!(status, 200);
    assert_eq!(
        hit_count(&hits_a),
        1,
        "目录为空时必须回退到旧透传（上游收到 1 次）：{body}"
    );
    assert_eq!(parse(&body)["from"], "site1", "回退打的是第一个候选");
    handle.shutdown_and_wait().await;
}

// ============================================================ 4) legacy（空路由）不变

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_route_models_endpoint_is_unchanged() {
    let (base_a, hits_a, _) = spawn_upstream(7);
    let mut config = base_config(RouteTable::new(vec![]), HashMap::new());
    config.base_url = base_a.clone();
    config.api_key = Zeroizing::new(KEY_A.to_string());
    let handle = start(config).await.expect("启动网关");

    let (status, body) = call(&handle, "GET", "/v1/models", None).await;
    assert_eq!(status, 200);
    assert_eq!(hit_count(&hits_a), 1, "legacy 必须逐字保留旧透传");
    assert_eq!(parse(&body)["from"], "site7");
    handle.shutdown_and_wait().await;
}

// ============================================================ 5) 别名

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alias_appears_in_the_list_and_is_routable() {
    let (base_a, _, bodies) = spawn_upstream(1);
    let route = RouteTable::new(vec![upstream(1, &base_a, REF_A, &["real-model"])])
        .with_alias("fast", "real-model");
    let handle = start(base_config(route, keys())).await.expect("启动网关");

    let (status, body) = call(&handle, "GET", "/v1/models", None).await;
    assert_eq!(status, 200);
    let ids: Vec<String> = parse(&body)["data"]
        .as_array()
        .expect("data")
        .iter()
        .filter_map(|item| item["id"].as_str().map(str::to_string))
        .collect();
    assert_eq!(ids, vec!["fast", "real-model"], "别名与真实名都要列出");

    let (status, _) = call(
        &handle,
        "POST",
        "/v1/chat/completions",
        Some(r#"{"model":"fast","messages":[]}"#.to_string()),
    )
    .await;
    assert_eq!(status, 200);
    let sent = bodies
        .lock()
        .expect("体记录")
        .last()
        .cloned()
        .unwrap_or_default();
    let sent: Value = serde_json::from_str(&sent).unwrap_or(Value::Null);
    assert_eq!(
        sent["model"], "real-model",
        "上游收到的 body 必须是改写后的真实模型名：{sent}"
    );
    handle.shutdown_and_wait().await;
}

// ============================================================ 6) 404 只在全部目录明确时

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_model_returns_404_only_when_every_catalog_is_known() {
    let (base_a, hits_a, _) = spawn_upstream(1);
    let (base_b, hits_b, _) = spawn_upstream(2);
    let route = RouteTable::new(vec![
        upstream(1, &base_a, REF_A, &["a-model"]),
        upstream(2, &base_b, REF_B, &["b-model"]),
    ]);
    let handle = start(base_config(route, keys())).await.expect("启动网关");

    let (status, body) = call(
        &handle,
        "POST",
        "/v1/chat/completions",
        Some(r#"{"model":"not-exist","messages":[]}"#.to_string()),
    )
    .await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(hit_count(&hits_a), 0, "404 不得打到任何上游");
    assert_eq!(hit_count(&hits_b), 0, "404 不得打到任何上游");
    handle.shutdown_and_wait().await;
}

// ============================================================ 7) 有未知目录上游 ⇒ 不本地 404

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn known_catalog_without_the_model_plus_an_unknown_upstream_is_not_a_local_404() {
    let (base_a, hits_a, _) = spawn_upstream(1);
    let (base_b, hits_b, _) = spawn_upstream(2);
    let route = RouteTable::new(vec![
        upstream(1, &base_a, REF_A, &["a-model"]),
        // 目录未知（空 models = 通配）
        upstream(2, &base_b, REF_B, &[]),
    ]);
    let handle = start(base_config(route, keys())).await.expect("启动网关");

    let (status, _) = call(
        &handle,
        "POST",
        "/v1/chat/completions",
        Some(r#"{"model":"not-in-a-catalog","messages":[]}"#.to_string()),
    )
    .await;
    assert_eq!(status, 200, "有未知目录上游 ⇒ 必须照常转发，不得本地 404");
    assert_eq!(hit_count(&hits_a), 0, "明确目录不含 ⇒ 不打它");
    assert_eq!(hit_count(&hits_b), 1, "请求必须打到那个未知目录站点");
    handle.shutdown_and_wait().await;
}

// ============================================================ 8) 空目录站点仍是候选

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upstream_with_empty_models_is_still_a_last_resort_candidate() {
    let (base_a, hits_a, _) = spawn_upstream(1);
    let (base_b, hits_b, _) = spawn_upstream(2);
    let route = RouteTable::new(vec![
        upstream(1, &base_a, REF_A, &["a-model"]),
        upstream(2, &base_b, REF_B, &[]),
    ]);
    let handle = start(base_config(route, keys())).await.expect("启动网关");

    // 与 7 同样的路由，但断言集中看「候选集里确实有这个空目录站点」
    let (status, _) = call(
        &handle,
        "POST",
        "/v1/chat/completions",
        Some(r#"{"model":"zzz","messages":[]}"#.to_string()),
    )
    .await;
    assert_eq!(status, 200, "空目录站点必须仍被当作候选");
    assert_eq!(hit_count(&hits_b), 1, "空目录站点收到了请求");
    assert_eq!(hit_count(&hits_a), 0, "有明确目录且不含 ⇒ 不该被打");
    handle.shutdown_and_wait().await;
}
