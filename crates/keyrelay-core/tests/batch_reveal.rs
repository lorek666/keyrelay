//! M6-S4 契约测试：**批量读明文**（`SiteAdapter::reveal_keys`）。
//!
//! 这里用的是**按 URL 路由的假 transport**（不是 `MockTransport` 的响应队列）：
//!
//! 1. 每条响应与它对应的请求严格绑定（按 URL / 请求体生成），因此「id 与明文错配」必被发现；
//! 2. 每条请求可以注入**不同的延迟**，把完成顺序**故意打反**——若实现按完成顺序收集结果，
//!    20-id 保序断言必然变红（这是复审的第一号探针，见 M6-S4 spec §13）；
//! 3. 记录**同时在飞**的请求数峰值，用来钉住 `SUB2API_REVEAL_CONCURRENCY`。
//!
//! 假 transport ≠ 真实站点已验证（spec §9）。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use keyrelay_core::error::{Error, Result};
use keyrelay_core::site::newapi::NewApi;
use keyrelay_core::site::sub2api::{Sub2Api, SUB2API_REVEAL_CONCURRENCY};
use keyrelay_core::site::transport::{HttpRequest, HttpResponse, HttpTransport, Method};
use keyrelay_core::site::{KeyMaterial, Session, SiteAdapter};
use serde_json::{json, Value};

const NEWAPI_BASE: &str = "https://newapi.example.com/";
const SUB2API_BASE: &str = "https://sub.example.com/";
const SECRET: &str = "sk-LEAK0000000000000000000000000000";

fn json_resp(status: u16, value: Value) -> HttpResponse {
    HttpResponse::json(status, value).expect("构造响应")
}

fn newapi_ok(data: Value) -> HttpResponse {
    json_resp(200, json!({"success": true, "message": "", "data": data}))
}

fn sub2api_ok(data: Value) -> HttpResponse {
    json_resp(200, json!({"code": 0, "message": "success", "data": data}))
}

fn session() -> Session {
    Session {
        cookies: Vec::new(),
        access_token: Some("tok-abc".to_string()),
        user_id: Some("7".to_string()),
    }
}

fn body_of(req: &HttpRequest) -> Value {
    serde_json::from_slice(req.body.as_ref().expect("有请求体")).unwrap_or(Value::Null)
}

fn ids_of(n: usize) -> Vec<String> {
    (1..=n).map(|i| i.to_string()).collect()
}

/// 请求 URL 的最后一个路径段（`/api/v1/keys/12` → `12`）
fn last_segment(url: &str) -> String {
    url.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_string()
}

/// 按请求路由响应的假 transport：`handler` 决定「延迟 + 响应」。
#[derive(Clone)]
struct Router<F> {
    seen: Arc<Mutex<Vec<HttpRequest>>>,
    in_flight: Arc<AtomicUsize>,
    max_in_flight: Arc<AtomicUsize>,
    handler: F,
}

impl<F> Router<F>
where
    F: Fn(&HttpRequest) -> (u64, HttpResponse) + Send + Sync,
{
    fn new(handler: F) -> Self {
        Self {
            seen: Arc::new(Mutex::new(Vec::new())),
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight: Arc::new(AtomicUsize::new(0)),
            handler,
        }
    }

    fn requests(&self) -> Vec<HttpRequest> {
        self.seen.lock().expect("锁").clone()
    }

    fn request_count(&self) -> usize {
        self.seen.lock().expect("锁").len()
    }

    fn urls(&self) -> Vec<String> {
        self.requests().into_iter().map(|r| r.url).collect()
    }

    fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl<F> HttpTransport for Router<F>
where
    F: Fn(&HttpRequest) -> (u64, HttpResponse) + Send + Sync,
{
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse> {
        let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(current, Ordering::SeqCst);
        self.seen.lock().expect("锁").push(req.clone());

        let (delay_ms, response) = (self.handler)(&req);
        if delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        Ok(response)
    }
}

/// Sub2API 的单条读明文响应（`reveal_key` 读 `data.key`）
fn sub2api_key_response(id: i64) -> HttpResponse {
    sub2api_ok(json!({"id": id, "key": format!("sk-sub2api-key-{id}")}))
}

// ============================================================ NewAPI：批量端点

#[tokio::test]
async fn newapi_reveal_keys_posts_batch_endpoint_once() {
    let transport = Router::new(|req: &HttpRequest| {
        let ids: Vec<i64> = body_of(req)["ids"]
            .as_array()
            .expect("请求体应有 ids 数组")
            .iter()
            .filter_map(Value::as_i64)
            .collect();
        let keys: serde_json::Map<String, Value> = ids
            .iter()
            .map(|id| (id.to_string(), json!(format!("sk-newapi-key-{id}"))))
            .collect();
        (0, newapi_ok(json!({ "keys": keys })))
    });
    let adapter = NewApi::new(transport.clone());

    let ids = vec!["1".to_string(), "2".to_string(), "3".to_string()];
    let revealed = adapter
        .reveal_keys(NEWAPI_BASE, &session(), &ids)
        .await
        .unwrap();

    assert_eq!(revealed.len(), 3);
    for (i, (remote_id, material)) in revealed.iter().enumerate() {
        assert_eq!(remote_id, &ids[i], "返回顺序 = 入参顺序");
        assert_eq!(material.remote_id, ids[i]);
        assert_eq!(material.secret, format!("sk-newapi-key-{}", ids[i]));
    }

    assert_eq!(transport.request_count(), 1, "n ≤ 100 时恰好一次调用");
    let request = &transport.requests()[0];
    assert_eq!(
        request.url,
        "https://newapi.example.com/api/token/batch/keys"
    );
    assert_eq!(request.method, Method::Post);
    assert_eq!(body_of(request)["ids"], json!([1, 2, 3]));
    assert!(
        request
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("authorization") && v == "Bearer tok-abc"),
        "{:?}",
        request.headers
    );
}

#[tokio::test]
async fn newapi_reveal_keys_empty_input_sends_no_request() {
    let transport = Router::new(|_req: &HttpRequest| (0, newapi_ok(json!({"keys": {}}))));
    let adapter = NewApi::new(transport.clone());

    assert!(adapter
        .reveal_keys(NEWAPI_BASE, &session(), &[])
        .await
        .unwrap()
        .is_empty());
    assert_eq!(transport.request_count(), 0, "空入参不得发请求");
}

#[tokio::test]
async fn newapi_reveal_keys_chunks_at_the_site_limit() {
    let transport = Router::new(|req: &HttpRequest| {
        let ids: Vec<i64> = body_of(req)["ids"]
            .as_array()
            .expect("请求体应有 ids 数组")
            .iter()
            .filter_map(Value::as_i64)
            .collect();
        let keys: serde_json::Map<String, Value> = ids
            .iter()
            .map(|id| (id.to_string(), json!(format!("sk-newapi-key-{id}"))))
            .collect();
        (0, newapi_ok(json!({ "keys": keys })))
    });
    let adapter = NewApi::new(transport.clone());

    let ids = ids_of(101);
    let revealed = adapter
        .reveal_keys(NEWAPI_BASE, &session(), &ids)
        .await
        .unwrap();
    assert_eq!(revealed.len(), 101);
    assert_eq!(revealed[0].0, "1");
    assert_eq!(revealed[100].0, "101");
    assert_eq!(revealed[100].1.secret, "sk-newapi-key-101");

    assert_eq!(transport.request_count(), 2, "站点硬上限 100 → 分两块");
    let chunks: Vec<usize> = transport
        .requests()
        .iter()
        .map(|r| body_of(r)["ids"].as_array().map(Vec::len).unwrap_or(0))
        .collect();
    assert_eq!(chunks, vec![100, 1]);
}

#[tokio::test]
async fn newapi_reveal_keys_rejects_non_numeric_ids_without_request() {
    let transport = Router::new(|_req: &HttpRequest| (0, newapi_ok(json!({"keys": {}}))));
    let adapter = NewApi::new(transport.clone());

    for hostile in [
        vec!["abc".to_string()],
        vec!["0".to_string()],
        vec!["-1".to_string()],
        vec!["1.5".to_string()],
        vec!["".to_string()],
        vec!["1".to_string(), "2/x".to_string()],
    ] {
        let err = adapter
            .reveal_keys(NEWAPI_BASE, &session(), &hostile)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Transport(ref m) if m.contains("正整数")),
            "{hostile:?} → {err:?}"
        );
    }
    assert_eq!(transport.request_count(), 0, "本地校验失败不得发请求");
}

#[tokio::test]
async fn newapi_reveal_keys_reports_missing_ids_without_partial_result() {
    // 站点对未命中的 id 静默丢弃（`GetTokenKeysByIds` 只回命中行）→ 适配器必须发现。
    let transport = Router::new(|req: &HttpRequest| {
        let ids: Vec<i64> = body_of(req)["ids"]
            .as_array()
            .expect("ids")
            .iter()
            .filter_map(Value::as_i64)
            .filter(|id| *id != 2)
            .collect();
        let keys: serde_json::Map<String, Value> = ids
            .iter()
            .map(|id| (id.to_string(), json!(format!("sk-newapi-key-{id}"))))
            .collect();
        (0, newapi_ok(json!({ "keys": keys })))
    });
    let adapter = NewApi::new(transport.clone());

    let ids = vec!["1".to_string(), "2".to_string(), "3".to_string()];
    let err = adapter
        .reveal_keys(NEWAPI_BASE, &session(), &ids)
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(matches!(err, Error::NotFound(_)), "{err:?}");
    assert!(text.contains('2'), "错误里应点名缺失的 id: {text}");
    assert!(!text.contains("sk-"), "错误里不得出现明文: {text}");
    assert_eq!(transport.request_count(), 1, "不因缺一条而重试");
}

#[tokio::test]
async fn newapi_reveal_keys_keeps_input_order_with_duplicates() {
    let transport = Router::new(|req: &HttpRequest| {
        let ids: Vec<i64> = body_of(req)["ids"]
            .as_array()
            .expect("ids")
            .iter()
            .filter_map(Value::as_i64)
            .collect();
        let keys: serde_json::Map<String, Value> = ids
            .iter()
            .map(|id| (id.to_string(), json!(format!("sk-newapi-key-{id}"))))
            .collect();
        (0, newapi_ok(json!({ "keys": keys })))
    });
    let adapter = NewApi::new(transport.clone());

    let ids = vec!["2".to_string(), "1".to_string(), "2".to_string()];
    let revealed = adapter
        .reveal_keys(NEWAPI_BASE, &session(), &ids)
        .await
        .unwrap();
    let got: Vec<String> = revealed.iter().map(|(id, _)| id.clone()).collect();
    assert_eq!(got, ids, "逐位对应（含重复 id）");
    assert_eq!(revealed[0].1.secret, "sk-newapi-key-2");
    assert_eq!(revealed[1].1.secret, "sk-newapi-key-1");
    assert_eq!(revealed[2].1.secret, "sk-newapi-key-2");
}

// ============================================================ Sub2API：有界并发 + 保序

/// 20 个 id 的并发探针：延迟随 id 增大而**减小** → 完成顺序被故意打反。
#[tokio::test]
async fn sub2api_reveal_keys_preserves_input_order_under_concurrency() {
    let completed: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let completed_in_transport = Arc::clone(&completed);
    let transport = Router::new(move |req: &HttpRequest| {
        let id: i64 = last_segment(&req.url).parse().expect("URL 末段应是 id");
        let delay = (21 - id).max(1) as u64 * 3;
        let response = sub2api_key_response(id);
        // 记录「完成顺序」：延迟结束后才算完成
        let log = Arc::clone(&completed_in_transport);
        let url = req.url.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay)).await;
            if let Ok(mut log) = log.lock() {
                log.push(last_segment(&url));
            }
        });
        (delay, response)
    });
    let adapter = Sub2Api::new(transport.clone());

    let ids = ids_of(20);
    let revealed = adapter
        .reveal_keys(SUB2API_BASE, &session(), &ids)
        .await
        .unwrap();

    assert_eq!(revealed.len(), 20);
    for (i, (remote_id, material)) in revealed.iter().enumerate() {
        assert_eq!(
            remote_id, &ids[i],
            "第 {i} 位必须是入参第 {i} 位（并发乱序实现会在这里红）"
        );
        assert_eq!(material.remote_id, ids[i]);
        assert_eq!(material.secret, format!("sk-sub2api-key-{}", ids[i]));
    }

    // 每个 id 恰好一次 GET
    assert_eq!(transport.request_count(), 20);
    let urls = transport.urls();
    for id in &ids {
        assert_eq!(
            urls.iter()
                .filter(|u| u.ends_with(&format!("/api/v1/keys/{id}")))
                .count(),
            1,
            "id {id} 应恰好请求一次"
        );
    }

    // 反证测试本身有效：完成顺序确实被打反了（否则这个探针证明不了保序）
    tokio::time::sleep(Duration::from_millis(50)).await;
    let finished = completed.lock().expect("锁").clone();
    assert_eq!(finished.len(), 20, "所有请求都应完成: {finished:?}");
    assert_ne!(
        finished, ids,
        "完成顺序必须与入参顺序不同，否则保序断言没有鉴别力"
    );
}

#[tokio::test]
async fn sub2api_reveal_keys_bounds_in_flight_requests() {
    let transport = Router::new(|req: &HttpRequest| {
        let id: i64 = last_segment(&req.url).parse().expect("URL 末段应是 id");
        let delay = (21 - id).max(1) as u64 * 3;
        (delay, sub2api_key_response(id))
    });
    let adapter = Sub2Api::new(transport.clone());

    let ids = ids_of(20);
    let revealed = adapter
        .reveal_keys(SUB2API_BASE, &session(), &ids)
        .await
        .unwrap();

    assert_eq!(revealed.len(), 20);
    assert_eq!(SUB2API_REVEAL_CONCURRENCY, 4, "章程冻结值");
    assert_eq!(
        transport.max_in_flight(),
        SUB2API_REVEAL_CONCURRENCY,
        "在飞请求峰值必须恰好等于上限（证明真的并发、且没有超发）"
    );
}

#[tokio::test]
async fn sub2api_reveal_keys_stops_at_first_failure_in_input_order() {
    // 第 3 个 id 失败；id ≥ 7 的请求被注入 10s 延迟——若实现「收集全部再报错」，
    // 这次调用会被 2s 的超时打断（测试红）。
    let transport = Router::new(|req: &HttpRequest| {
        let id: i64 = last_segment(&req.url).parse().expect("URL 末段应是 id");
        if id == 3 {
            return (
                0,
                json_resp(401, json!({"code": 401, "message": "invalid token"})),
            );
        }
        let delay = if id >= 7 { 10_000 } else { 0 };
        (delay, sub2api_key_response(id))
    });
    let adapter = Sub2Api::new(transport.clone());

    let ids = ids_of(8);
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        adapter.reveal_keys(SUB2API_BASE, &session(), &ids),
    )
    .await
    .expect("首个失败必须立即返回，不得等后面的请求");

    let err = outcome.unwrap_err();
    assert!(matches!(err, Error::AuthFailed(_)), "{err:?}");

    let urls = transport.urls();
    assert!(
        !urls.iter().any(|u| u.ends_with("/api/v1/keys/7")),
        "报错后不得再发新请求: {urls:?}"
    );
    assert!(
        !urls.iter().any(|u| u.ends_with("/api/v1/keys/8")),
        "报错后不得再发新请求: {urls:?}"
    );
}

#[tokio::test]
async fn sub2api_reveal_keys_empty_input_sends_no_request() {
    let transport = Router::new(|_req: &HttpRequest| (0, sub2api_key_response(1)));
    let adapter = Sub2Api::new(transport.clone());

    assert!(adapter
        .reveal_keys(SUB2API_BASE, &session(), &[])
        .await
        .unwrap()
        .is_empty());
    assert_eq!(transport.request_count(), 0, "空入参不得发请求");
}

#[tokio::test]
async fn sub2api_reveal_keys_rejects_path_traversal_ids() {
    let transport = Router::new(|_req: &HttpRequest| (0, sub2api_key_response(1)));
    let adapter = Sub2Api::new(transport.clone());

    for hostile in ["../user/profile", "1/2", "."] {
        let err = adapter
            .reveal_keys(SUB2API_BASE, &session(), &[hostile.to_string()])
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Transport(ref m) if m.contains("路径段")),
            "{hostile:?} → {err:?}"
        );
    }
    assert_eq!(transport.request_count(), 0, "非法路径段不得发请求");
}

// ============================================================ 红线：错误文案

#[tokio::test]
async fn reveal_keys_errors_never_carry_site_echoed_secret() {
    // ① NewAPI：非 2xx 且 body 回显密钥
    let transport = Router::new(|_req: &HttpRequest| {
        (
            0,
            json_resp(403, json!({"message": format!("token {SECRET} forbidden")})),
        )
    });
    let adapter = NewApi::new(transport.clone());
    let err = adapter
        .reveal_keys(NEWAPI_BASE, &session(), &["1".to_string()])
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(!text.contains(SECRET), "错误文案泄漏密钥: {text}");
    assert!(!text.contains("LEAK0000"), "错误文案残留密钥片段: {text}");

    // ② NewAPI：HTTP 200 + success:false 且 message 回显密钥
    let transport = Router::new(|_req: &HttpRequest| {
        (
            0,
            json_resp(
                200,
                json!({"success": false, "message": format!("bad {SECRET}")}),
            ),
        )
    });
    let adapter = NewApi::new(transport.clone());
    let err = adapter
        .reveal_keys(NEWAPI_BASE, &session(), &["1".to_string()])
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(!text.contains(SECRET), "错误文案泄漏密钥: {text}");
    assert!(!text.contains("LEAK0000"), "错误文案残留密钥片段: {text}");

    // ③ Sub2API：401 且 message 回显密钥
    let transport = Router::new(|_req: &HttpRequest| {
        (
            0,
            json_resp(
                401,
                json!({"code": 401, "message": format!("{SECRET} 已失效")}),
            ),
        )
    });
    let adapter = Sub2Api::new(transport.clone());
    let err = adapter
        .reveal_keys(SUB2API_BASE, &session(), &["1".to_string()])
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(!text.contains(SECRET), "错误文案泄漏密钥: {text}");
    assert!(!text.contains("LEAK0000"), "错误文案残留密钥片段: {text}");

    // ④ 返回值本身是密钥的唯一出口：`KeyMaterial` 的 Debug 必须脱敏
    let material = KeyMaterial::new("1", SECRET);
    assert!(!format!("{material:?}").contains(SECRET));
}
