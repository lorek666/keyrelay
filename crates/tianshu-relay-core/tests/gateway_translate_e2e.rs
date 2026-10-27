//! M42-S2a 端到端：假上游 → 网关 → 三种协议的非流式翻译。
//!
//! 每个用例都断言**上游实际收到的原始请求**（不只是客户端看到的响应）——
//! 「翻译了没有」只能由上游 body 证明。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};
use tianshu_relay_core::gateway::{start, GatewayConfig, GatewayHandle};
use tianshu_relay_core::routing::{BreakerPolicy, RouteTable, Upstream};
use zeroize::Zeroizing;

const KEY_A: &str = "sk-e2e-0123456789abcdef";
const REF_A: &str = "kr/key/1/secret";

struct FakeUpstream {
    base_url: String,
    seen: Arc<Mutex<Vec<String>>>,
}

fn spawn_upstream(status: &str, body: &str) -> FakeUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定");
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let rec = Arc::clone(&seen);
    let status = status.to_string();
    let body = body.to_string();
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match s.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&buf).to_string();
                        if let Some(he) = text.find("\r\n\r\n") {
                            let cl = text[..he]
                                .lines()
                                .find_map(|l| {
                                    let (k, v) = l.split_once(':')?;
                                    k.eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse::<usize>().ok())?
                                })
                                .unwrap_or(0);
                            if buf.len() >= he + 4 + cl {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            rec.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf).to_string());
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    FakeUpstream {
        base_url: format!("http://{addr}"),
        seen,
    }
}

impl FakeUpstream {
    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
    fn last_body(&self) -> Value {
        let raw = self
            .seen
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_default();
        let body = raw.split("\r\n\r\n").nth(1).unwrap_or("");
        serde_json::from_str(body).unwrap_or(Value::Null)
    }
}

fn http_post(url: &str, token: &str, path: &str, body: &str) -> (u16, String) {
    let bare = url.trim_start_matches("http://");
    let mut s = TcpStream::connect(bare).expect("连接网关");
    // Anthropic 的检测需要版本头；路径是 /v1/messages 时带上（与真实客户端一致）
    let anthropic = if path == "/v1/messages" {
        "anthropic-version: 2023-06-01\r\n"
    } else {
        ""
    };
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {bare}\r\nAuthorization: Bearer {token}\r\n{anthropic}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (
        status,
        text.split("\r\n\r\n").nth(1).unwrap_or("").to_string(),
    )
}

async fn start_legacy(up: &FakeUpstream) -> GatewayHandle {
    start(GatewayConfig::single_upstream(
        0,
        "local-token-e2e".to_string(),
        up.base_url.clone(),
        Zeroizing::new(KEY_A.to_string()),
        "e2e".to_string(),
    ))
    .await
    .expect("启动")
}

async fn start_routed(up: &FakeUpstream) -> GatewayHandle {
    let mut keys = std::collections::HashMap::new();
    keys.insert(REF_A.to_string(), Zeroizing::new(KEY_A.to_string()));
    let mut config = GatewayConfig::single_upstream(
        0,
        "local-token-e2e".to_string(),
        String::new(),
        Zeroizing::new(String::new()),
        "e2e".to_string(),
    );
    config.route = RouteTable::new(vec![Upstream {
        site_id: 1,
        key_id: None,
        base_url: up.base_url.clone(),
        key_ref: REF_A.to_string(),
        models: vec![],
        rate: Some(1.0),
        balance_usd: Some(10.0),
        latency_ms: Some(1),
        timeout_ms: None,
    }]);
    config.keys_by_ref = keys;
    config.breaker = BreakerPolicy {
        threshold: 100,
        cooldown: Duration::from_secs(3600),
    };
    start(config).await.expect("启动")
}

fn chat_response_text(text: &str) -> String {
    json!({
        "id": "chatcmpl-e2e", "object": "chat.completion", "model": "gpt-5.6",
        "choices": [{ "index": 0, "message": { "role": "assistant", "content": text }, "finish_reason": "stop" }],
        "usage": { "prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10 }
    })
    .to_string()
}

// ---------------------------------------------------------------- 1 Responses（legacy）

#[tokio::test]
async fn responses_e2e_on_the_legacy_path() {
    let up = spawn_upstream("200 OK", &chat_response_text("你好"));
    let h = start_legacy(&up).await;
    let token = h.token.clone();
    let url = format!("http://{}", h.addr);
    let body = json!({
        "model": "gpt-5.6",
        "instructions": "系统",
        "input": [{ "role": "user", "content": [{ "type": "input_text", "text": "问" }] }]
    })
    .to_string();

    let (status, resp) =
        tokio::task::spawn_blocking(move || http_post(&url, &token, "/v1/responses", &body))
            .await
            .unwrap();
    assert_eq!(status, 200, "{resp}");
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["object"], "response", "{v}");
    assert_eq!(v["output"][0]["content"][0]["text"], "你好");

    // 上游收到的是 **Chat** 形状（翻译生效）
    let sent = up.last_body();
    assert_eq!(sent["messages"][0]["role"], "system");
    assert_eq!(sent["messages"][1]["content"], "问");
    assert!(
        sent.get("input").is_none(),
        "上游不该收到 Responses 的 input: {sent}"
    );

    h.shutdown_and_wait().await;
}

#[tokio::test]
async fn responses_reasoning_reaches_chat_as_reasoning_effort() {
    let up = spawn_upstream("200 OK", &chat_response_text("好"));
    let h = start_legacy(&up).await;
    let token = h.token.clone();
    let url = format!("http://{}", h.addr);
    let body = json!({
        "model": "o3",
        "reasoning": {"effort": "high"},
        "input": [{ "role": "user", "content": [{ "type": "input_text", "text": "问" }] }]
    })
    .to_string();
    let (status, resp) =
        tokio::task::spawn_blocking(move || http_post(&url, &token, "/v1/responses", &body))
            .await
            .unwrap();
    assert_eq!(
        status, 200,
        "Codex 自己写出的 reasoning 不能在本地 400: {resp}"
    );
    let sent = up.last_body();
    assert_eq!(sent["reasoning_effort"], "high");
    assert!(sent.get("reasoning").is_none());
    h.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- 2 Anthropic（路由）

#[tokio::test]
async fn anthropic_e2e_on_the_routed_path() {
    let up = spawn_upstream("200 OK", &chat_response_text("好"));
    let h = start_routed(&up).await;
    let token = h.token.clone();
    let url = format!("http://{}", h.addr);
    let body = json!({
        "model": "claude-x", "max_tokens": 64, "system": "规则",
        "messages": [{ "role": "user", "content": [{ "type": "text", "text": "嗨" }] }]
    })
    .to_string();

    let (status, resp) =
        tokio::task::spawn_blocking(move || http_post(&url, &token, "/v1/messages", &body))
            .await
            .unwrap();
    assert_eq!(status, 200, "{resp}");
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["type"], "message", "{v}");
    assert_eq!(v["content"][0]["text"], "好");

    let sent = up.last_body();
    assert_eq!(sent["messages"][0]["role"], "system");
    assert_eq!(sent["max_tokens"], 64);

    h.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- 3 Gemini（legacy，model 来自 path）

#[tokio::test]
async fn gemini_e2e_takes_the_model_from_the_path() {
    let up = spawn_upstream("200 OK", &chat_response_text("答"));
    let h = start_legacy(&up).await;
    let token = h.token.clone();
    let url = format!("http://{}", h.addr);
    let body = json!({
        "contents": [{ "role": "user", "parts": [{ "text": "问" }] }],
        "generationConfig": { "maxOutputTokens": 32 }
    })
    .to_string();

    let (status, resp) = tokio::task::spawn_blocking(move || {
        http_post(
            &url,
            &token,
            "/v1beta/models/gemini-2.5-pro:generateContent",
            &body,
        )
    })
    .await
    .unwrap();
    assert_eq!(status, 200, "{resp}");
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["candidates"][0]["content"]["parts"][0]["text"], "答");

    let sent = up.last_body();
    // **model 必须从 path 填进来**（不能是空串）
    assert_eq!(sent["model"], "gemini-2.5-pro", "上游收到的 body: {sent}");

    h.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- 4 工具调用

#[tokio::test]
async fn tool_calls_e2e_keep_both_calls() {
    let upstream_body = json!({
        "id": "c1", "model": "gpt-5.6",
        "choices": [{
            "index": 0,
            "message": { "content": null, "tool_calls": [
                { "id": "t1", "type": "function", "function": { "name": "f1", "arguments": "{\"a\":1}" } },
                { "id": "t2", "type": "function", "function": { "name": "f2", "arguments": "{\"b\":2}" } }
            ]},
            "finish_reason": "tool_calls"
        }]
    })
    .to_string();
    let up = spawn_upstream("200 OK", &upstream_body);
    let h = start_legacy(&up).await;
    let token = h.token.clone();
    let url = format!("http://{}", h.addr);
    let body = json!({ "model": "gpt-5.6", "max_tokens": 8, "messages": [{ "role": "user", "content": "用工具" }] })
        .to_string();

    let (status, resp) =
        tokio::task::spawn_blocking(move || http_post(&url, &token, "/v1/messages", &body))
            .await
            .unwrap();
    assert_eq!(status, 200, "{resp}");
    let v: Value = serde_json::from_str(&resp).unwrap();
    let uses: Vec<&Value> = v["content"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["type"] == "tool_use")
        .collect();
    assert_eq!(uses.len(), 2, "两个 tool_calls 都要在: {v}");

    h.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- 5 上游 400 原样

#[tokio::test]
async fn upstream_400_is_passed_through_verbatim() {
    let raw = r#"{"error":{"message":"上游说不行","type":"invalid_request_error"}}"#;
    let up = spawn_upstream("400 Bad Request", raw);
    let h = start_legacy(&up).await;
    let token = h.token.clone();
    let url = format!("http://{}", h.addr);
    let body = json!({ "model": "m", "input": [] }).to_string();

    let (status, resp) =
        tokio::task::spawn_blocking(move || http_post(&url, &token, "/v1/responses", &body))
            .await
            .unwrap();
    assert_eq!(status, 400);
    assert_eq!(resp, raw, "上游非 2xx 必须逐字节透传（不翻译）");

    h.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- 6 解析失败 / stream ⇒ 上游 0 次

#[tokio::test]
async fn parse_failure_and_stream_never_touch_the_upstream() {
    let up = spawn_upstream("200 OK", &chat_response_text("不该被调用"));
    let h = start_legacy(&up).await;
    let token = h.token.clone();
    let url = format!("http://{}", h.addr);

    // ① 不支持字段
    let body = json!({ "model": "m", "input": [], "reasoning": {} }).to_string();
    let (status, resp) = tokio::task::spawn_blocking({
        let (url, token) = (url.clone(), token.clone());
        move || http_post(&url, &token, "/v1/responses", &body)
    })
    .await
    .unwrap();
    assert_eq!(status, 400, "{resp}");
    assert!(resp.contains("reasoning"), "必须点名: {resp}");

    // ② 另一个不支持字段（流式已由 M42-S2b 支持，不再是拒绝理由）
    let body = json!({ "model": "m", "max_tokens": 1, "messages": [], "top_k": 5 }).to_string();
    let (status, resp) = tokio::task::spawn_blocking({
        let (url, token) = (url.clone(), token.clone());
        move || http_post(&url, &token, "/v1/messages", &body)
    })
    .await
    .unwrap();
    assert_eq!(status, 400, "{resp}");
    assert!(resp.contains("top_k"), "必须点名: {resp}");

    assert_eq!(
        up.count(),
        0,
        "解析失败/流式拒绝**一次都不能碰上游**（计费红线）"
    );

    h.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- 7 Chat 逐字节直通

#[tokio::test]
async fn chat_body_is_forwarded_byte_for_byte() {
    let up = spawn_upstream("200 OK", &chat_response_text("ok"));
    let h = start_legacy(&up).await;
    let token = h.token.clone();
    let url = format!("http://{}", h.addr);
    // 刻意保留空格与数字形态：任何重序列化都会改掉它们
    let body =
        r#"{"model":"gpt-5.6", "messages":[{"role":"user","content":"hi"}], "temperature":0.50}"#;

    let (status, _) = tokio::task::spawn_blocking({
        let (url, token) = (url.clone(), token.clone());
        let body = body.to_string();
        move || http_post(&url, &token, "/v1/chat/completions", &body)
    })
    .await
    .unwrap();
    assert_eq!(status, 200);

    let raw = up.seen.lock().unwrap().last().cloned().unwrap_or_default();
    assert!(raw.ends_with(body), "Chat body 必须逐字节直通:\n{raw}");
    assert!(raw.contains("0.50"), "数值形态不得被改写: {raw}");

    h.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- 8 usage 等价性

/// M42-S2a §3：翻译路径的 usage 行必须与 `UsageCapture` 同字段、且**不丢 token_id/agent_label**。
#[tokio::test]
async fn translated_usage_keeps_token_id_and_agent_label() {
    use std::sync::Mutex as StdMutex;
    use tianshu_relay_core::gateway::{sha256_hex, GatewayTokenEntry, GatewayUsage};

    let up = spawn_upstream("200 OK", &chat_response_text("好"));
    let captured: Arc<StdMutex<Vec<GatewayUsage>>> = Arc::new(StdMutex::new(Vec::new()));
    let sink = Arc::clone(&captured);

    let mut config = GatewayConfig::single_upstream(
        0,
        "local-token-e2e".to_string(),
        up.base_url.clone(),
        Zeroizing::new(KEY_A.to_string()),
        "e2e".to_string(),
    );
    config.on_usage = Some(Arc::new(move |u| sink.lock().unwrap().push(u)));
    let h = start(config).await.expect("启动");

    // 让认证走**具名令牌**（token_id / agent_label 才会被填）
    h.set_tokens(vec![GatewayTokenEntry {
        id: 42,
        token_hash: sha256_hex("local-token-e2e"),
        label: "e2e-agent".to_string(),
        grace_until: None,
    }]);

    let url = format!("http://{}", h.addr);
    let body = json!({ "model": "m", "input": [{ "role": "user", "content": [{ "type": "input_text", "text": "问" }] }] }).to_string();
    let (status, resp) = tokio::task::spawn_blocking(move || {
        http_post(&url, "local-token-e2e", "/v1/responses", &body)
    })
    .await
    .unwrap();
    assert_eq!(status, 200, "{resp}");

    {
        let rows = captured.lock().unwrap();
        assert_eq!(
            rows.len(),
            1,
            "翻译路径必须**恰好记一次** usage（不重复计费）"
        );
        let u = &rows[0];
        assert_eq!(u.prompt_tokens, 7);
        assert_eq!(u.completion_tokens, 3);
        assert_eq!(u.total_tokens, 10);
        assert_eq!(u.status, 200);
        assert!(!u.stream, "非流式翻译路径应记 stream=false");
        assert_eq!(u.model, "m", "记的是**请求里**的模型名");
        // 关键：这两项不能丢
        assert_eq!(u.token_id, Some(42), "token_id 不能丢: {u:?}");
        assert_eq!(u.agent_label, "e2e-agent", "agent_label 不能丢: {u:?}");
        assert!(u.attempts >= 1);
    }

    h.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- 复审 P1-1：Gemini 工具往返

#[tokio::test]
async fn gemini_tool_result_reaches_the_upstream_as_a_tool_message() {
    let up = spawn_upstream("200 OK", &chat_response_text("好"));
    let h = start_legacy(&up).await;
    let token = h.token.clone();
    let url = format!("http://{}", h.addr);
    let body = json!({
        "contents": [
            { "role": "user", "parts": [{ "text": "查天气" }] },
            { "role": "model", "parts": [{ "functionCall": { "name": "get_weather", "args": {"city":"SH"} } }] },
            { "role": "user", "parts": [{ "functionResponse": { "name": "get_weather", "response": { "temp": 21 } } }] }
        ]
    })
    .to_string();

    let (status, resp) = tokio::task::spawn_blocking(move || {
        http_post(
            &url,
            &token,
            "/v1beta/models/gemini-2.5-pro:generateContent",
            &body,
        )
    })
    .await
    .unwrap();
    assert_eq!(status, 200, "{resp}");

    // 上游必须收到一条 role=tool 的消息，且内容是展开后的文本
    let sent = up.last_body();
    let msgs = sent["messages"].as_array().expect("messages");
    let tool = msgs
        .iter()
        .find(|m| m["role"] == "tool")
        .unwrap_or_else(|| panic!("上游没收到 tool 消息: {sent}"));
    let content = tool["content"].as_str().unwrap_or("");
    assert!(
        content.contains("temp: 21"),
        "工具结果要展开成文本: {content}"
    );

    h.shutdown_and_wait().await;
}

// ---------------------------------------------------------------- 复审 P2-4：Gemini 流式 ⇒ 400（不是 404）

// （`?alt=sse` 的 400 断言已由 M42-S2b 取代：现在真的走流式，见 gateway_translate_stream_e2e.rs）

// ---------------------------------------------------------------- B-224 P3：翻译 usage 与 UsageCapture 逐字段等价

/// M42-S2a P2：同一上游响应、同一模型名，走 Chat 直通（`UsageCapture`）
/// 与走 Responses 翻译（手工组 `GatewayUsage`）时，记下的用量行除
/// `at`（完成时刻）与 `latency_ms`（真实耗时）外必须逐字段相同。
/// 此前翻译路径只断言了自身字段（token_id / agent_label 不丢），两条
/// 路径漂移时没有任何用例会红。
#[tokio::test]
async fn translated_usage_matches_passthrough_usage_field_by_field() {
    use std::sync::Mutex as StdMutex;
    use tianshu_relay_core::gateway::{sha256_hex, GatewayTokenEntry, GatewayUsage};

    let up = spawn_upstream("200 OK", &chat_response_text("好"));
    let captured: Arc<StdMutex<Vec<GatewayUsage>>> = Arc::new(StdMutex::new(Vec::new()));
    let sink = Arc::clone(&captured);
    let mut config = GatewayConfig::single_upstream(
        0,
        "local-token-e2e".to_string(),
        up.base_url.clone(),
        Zeroizing::new(KEY_A.to_string()),
        "e2e".to_string(),
    );
    config.on_usage = Some(Arc::new(move |u| sink.lock().unwrap().push(u)));
    let h = start(config).await.expect("启动");
    h.set_tokens(vec![GatewayTokenEntry {
        id: 42,
        token_hash: sha256_hex("local-token-e2e"),
        label: "e2e-agent".to_string(),
        grace_until: None,
    }]);

    let url = format!("http://{}", h.addr);
    // 直通：Chat 请求，模型名与翻译请求相同，消除模型名差异。
    let chat_body = json!({
        "model": "m",
        "messages": [{ "role": "user", "content": "问" }]
    })
    .to_string();
    let (status, _) = tokio::task::spawn_blocking({
        let url = url.clone();
        move || http_post(&url, "local-token-e2e", "/v1/chat/completions", &chat_body)
    })
    .await
    .unwrap();
    assert_eq!(status, 200);
    // 翻译：Responses 请求，同一模型名、同一上游响应。
    let resp_body = json!({
        "model": "m",
        "input": [{ "role": "user", "content": [{ "type": "input_text", "text": "问" }] }]
    })
    .to_string();
    let (status, _) = tokio::task::spawn_blocking({
        let url = url.clone();
        move || http_post(&url, "local-token-e2e", "/v1/responses", &resp_body)
    })
    .await
    .unwrap();
    assert_eq!(status, 200);

    // 先 clone 出来再断言：直接抱着 MutexGuard 跨 shutdown await 会
    // 触发 clippy::await_holding_lock（且关停本身可能再回调 on_usage）。
    let rows = captured.lock().unwrap().clone();
    assert_eq!(rows.len(), 2, "两条路径各记一次，合计恰好两行: {rows:?}");
    let (a, b) = (&rows[0], &rows[1]);
    for (name, va, vb) in [
        ("site_id", a.site_id.to_string(), b.site_id.to_string()),
        (
            "key_id",
            format!("{:?}", a.key_id),
            format!("{:?}", b.key_id),
        ),
        ("model", a.model.clone(), b.model.clone()),
        (
            "prompt_tokens",
            a.prompt_tokens.to_string(),
            b.prompt_tokens.to_string(),
        ),
        (
            "completion_tokens",
            a.completion_tokens.to_string(),
            b.completion_tokens.to_string(),
        ),
        (
            "total_tokens",
            a.total_tokens.to_string(),
            b.total_tokens.to_string(),
        ),
        ("status", a.status.to_string(), b.status.to_string()),
        ("attempts", a.attempts.to_string(), b.attempts.to_string()),
        ("stream", a.stream.to_string(), b.stream.to_string()),
        (
            "token_id",
            format!("{:?}", a.token_id),
            format!("{:?}", b.token_id),
        ),
        ("agent_label", a.agent_label.clone(), b.agent_label.clone()),
    ] {
        assert_eq!(
            va, vb,
            "翻译与直通的用量字段 {name} 必须一致: {a:?} vs {b:?}"
        );
    }
    assert_eq!(a.prompt_tokens, 7);
    assert_eq!(a.completion_tokens, 3);
    assert_eq!(a.total_tokens, 10);
    h.shutdown_and_wait().await;
}
