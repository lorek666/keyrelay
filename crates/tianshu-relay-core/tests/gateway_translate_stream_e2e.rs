//! M42-S2b 流式端到端：假上游按 chunk + 短延迟发 SSE，网关真 socket 逐块读。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};
use tianshu_relay_core::gateway::{start, GatewayConfig, GatewayHandle, GatewayUsage};
use zeroize::Zeroizing;

const KEY_A: &str = "sk-e2e-stream-0123456789";
const TOKEN: &str = "local-token-e2e";

struct SseUpstream {
    base_url: String,
    seen: Arc<Mutex<Vec<String>>>,
}

/// 假上游：按 chunk 发 SSE，每帧之间延迟 `delay_ms`；`abort_after` 给了就在第 n 帧后**直接断 TCP**。
fn spawn_sse(frames: Vec<String>, delay_ms: u64, abort_after: Option<usize>) -> SseUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let rec = Arc::clone(&seen);
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

            let _ = s.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            );
            for (i, frame) in frames.iter().enumerate() {
                if let Some(n) = abort_after {
                    if i >= n {
                        // 半截断：不发终止 chunk，直接关 socket
                        let _ = s.flush();
                        drop(s);
                        return;
                    }
                }
                let body = frame.as_bytes();
                let head = format!("{:x}\r\n", body.len());
                if s.write_all(head.as_bytes()).is_err()
                    || s.write_all(body).is_err()
                    || s.write_all(b"\r\n").is_err()
                {
                    break;
                }
                let _ = s.flush();
                thread::sleep(Duration::from_millis(delay_ms));
            }
            let _ = s.write_all(b"0\r\n\r\n");
        }
    });
    SseUpstream {
        base_url: format!("http://{addr}"),
        seen,
    }
}

impl SseUpstream {
    fn body(&self) -> Value {
        let raw = self
            .seen
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_default();
        serde_json::from_str(raw.split("\r\n\r\n").nth(1).unwrap_or("")).unwrap_or(Value::Null)
    }
}

fn chat_sse(text: &str, finish: bool) -> String {
    let mut s = format!(
        "data: {}\n\n",
        json!({"choices":[{"index":0,"delta":{"content":text}}]})
    );
    if finish {
        s.push_str(&format!(
            "data: {}\n\n",
            json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]})
        ));
        s.push_str(&format!(
            "data: {}\n\n",
            json!({"choices":[],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}})
        ));
        s.push_str("data: [DONE]\n\n");
    }
    s
}

async fn start_gw(up: &SseUpstream) -> GatewayHandle {
    let mut config = GatewayConfig::single_upstream(
        0,
        TOKEN.to_string(),
        up.base_url.clone(),
        Zeroizing::new(KEY_A.to_string()),
        "s2b".to_string(),
    );
    config.upstream_timeout = Default::default();
    start(config).await.expect("启动")
}

/// 逐块读响应体（chunked），返回完整文本。用于验证「增量到达」与「断开」。
fn stream_read(
    addr: &str,
    token: &str,
    path: &str,
    body: &str,
    stop_after: Option<usize>,
) -> String {
    let mut s = TcpStream::connect(addr).expect("连接");
    let anthropic = if path.starts_with("/v1/messages") {
        "anthropic-version: 2023-06-01\r\n"
    } else {
        ""
    };
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\n{anthropic}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    let mut reads = 0;
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                reads += 1;
                if let Some(limit) = stop_after {
                    if reads >= limit {
                        break; // 客户端断开
                    }
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn body_of(raw: &str) -> String {
    // 从 chunked 响应里剥出实际负载（只取 `data:` / `event:` 行，够断言用）
    raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn responses_streaming_e2e() {
    let up = spawn_sse(vec![chat_sse("你", false), chat_sse("好", true)], 5, None);
    let h = start_gw(&up).await;
    let addr = h.addr.to_string();
    let body = json!({"model":"gpt-5.6","input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}],"stream":true}).to_string();
    let raw = tokio::task::spawn_blocking(move || {
        stream_read(&addr, TOKEN, "/v1/responses", &body, None)
    })
    .await
    .unwrap();
    let text = body_of(&raw);
    assert!(text.contains("response.output_text.delta"), "{text}");
    assert!(text.contains("\"delta\":\"你\""), "{text}");
    assert!(text.contains("\"delta\":\"好\""), "{text}");
    assert!(text.contains("response.completed"), "{text}");
    assert_eq!(up.body()["stream"], true, "上游必须收到 stream:true");
    h.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn anthropic_streaming_e2e() {
    let up = spawn_sse(vec![chat_sse("好", true)], 5, None);
    let h = start_gw(&up).await;
    let addr = h.addr.to_string();
    let body = json!({"model":"claude-x","max_tokens":8,"messages":[{"role":"user","content":"hi"}],"stream":true}).to_string();
    let raw =
        tokio::task::spawn_blocking(move || stream_read(&addr, TOKEN, "/v1/messages", &body, None))
            .await
            .unwrap();
    let text = body_of(&raw);
    assert!(text.contains("message_start"), "{text}");
    assert!(text.contains("content_block_delta"), "{text}");
    assert!(text.contains("\"text\":\"好\""), "{text}");
    assert!(text.contains("message_stop"), "{text}");
    h.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn gemini_streaming_e2e_via_alt_sse() {
    let up = spawn_sse(vec![chat_sse("答", true)], 5, None);
    let h = start_gw(&up).await;
    let addr = h.addr.to_string();
    // **没有** body 的 stream:true —— 靠路径 + ?alt=sse 判定（M42-S2b）
    let body = json!({"contents":[{"role":"user","parts":[{"text":"问"}]}]}).to_string();
    let raw = tokio::task::spawn_blocking(move || {
        stream_read(
            &addr,
            TOKEN,
            "/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse",
            &body,
            None,
        )
    })
    .await
    .unwrap();
    let text = body_of(&raw);
    assert!(text.contains("candidates"), "{text}");
    assert!(text.contains("\"text\":\"答\""), "{text}");
    assert!(!text.contains("[DONE]"), "Gemini 不该有 [DONE]: {text}");
    assert_eq!(up.body()["model"], "gemini-2.5-pro");
    // P1-1（复审）：`alt=sse` 入站也必须在**上游请求**里带 stream:true，
    // 否则上游回的是普通 JSON，整个流式路径形同虚设。
    assert_eq!(
        up.body()["stream"],
        true,
        "上游必须收到 stream:true: {}",
        up.body()
    );
    h.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cross_chunk_boundary_e2e() {
    // 把**一个** data 事件切成两帧发：第一帧没有空行结尾
    let full = chat_sse("好", true);
    let (a, b) = full.split_at(full.len() / 2);
    let up = spawn_sse(vec![a.to_string(), b.to_string()], 10, None);
    let h = start_gw(&up).await;
    let addr = h.addr.to_string();
    let body = json!({"model":"gpt-5.6","input":[],"stream":true}).to_string();
    let raw = tokio::task::spawn_blocking(move || {
        stream_read(&addr, TOKEN, "/v1/responses", &body, None)
    })
    .await
    .unwrap();
    let text = body_of(&raw);
    assert!(
        text.contains("\"delta\":\"好\""),
        "跨包事件必须被拼出来: {text}"
    );
    h.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn tool_calls_streaming_e2e() {
    let frame = format!(
        "data: {}\n\ndata: [DONE]\n\n",
        json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"f1","arguments":"{\"a\":1}"}}]}}]})
    );
    let up = spawn_sse(vec![frame], 5, None);
    let h = start_gw(&up).await;
    let addr = h.addr.to_string();
    let body = json!({"model":"claude-x","max_tokens":8,"messages":[],"stream":true}).to_string();
    let raw =
        tokio::task::spawn_blocking(move || stream_read(&addr, TOKEN, "/v1/messages", &body, None))
            .await
            .unwrap();
    let text = body_of(&raw);
    assert!(text.contains("tool_use"), "tool_use 块要在: {text}");
    assert!(text.contains("input_json_delta"), "{text}");
    h.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_midstream_error_emits_an_error_event() {
    // 发 1 帧后直接断 TCP（没有终止 chunk）
    let up = spawn_sse(
        vec![chat_sse("半", false), chat_sse("截", false)],
        5,
        Some(1),
    );
    let h = start_gw(&up).await;
    let addr = h.addr.to_string();
    let body = json!({"model":"gpt-5.6","input":[],"stream":true}).to_string();
    let raw = tokio::task::spawn_blocking(move || {
        stream_read(&addr, TOKEN, "/v1/responses", &body, None)
    })
    .await
    .unwrap();
    let text = body_of(&raw);
    assert!(
        text.contains("event: error"),
        "中途断流必须发错误事件（不静默）: {text}"
    );
    h.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn client_disconnect_and_usage_is_recorded_once() {
    let up = spawn_sse(
        vec![
            chat_sse("一", false),
            chat_sse("二", false),
            chat_sse("三", true),
        ],
        20,
        None,
    );
    let captured: Arc<Mutex<Vec<GatewayUsage>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);
    let mut config = GatewayConfig::single_upstream(
        0,
        TOKEN.to_string(),
        up.base_url.clone(),
        Zeroizing::new(KEY_A.to_string()),
        "s2b".to_string(),
    );
    config.on_usage = Some(Arc::new(move |u| sink.lock().unwrap().push(u)));
    let h = start(config).await.expect("启动");
    let addr = h.addr.to_string();

    // 读完第一块就断开（模拟客户端取消）
    let body = json!({"model":"gpt-5.6","input":[],"stream":true}).to_string();
    let _ = tokio::task::spawn_blocking(move || {
        stream_read(&addr, TOKEN, "/v1/responses", &body, Some(1))
    })
    .await
    .unwrap();

    // 不挂死：shutdown 必须在合理时间内返回
    let done =
        tokio::time::timeout(std::time::Duration::from_secs(10), h.shutdown_and_wait()).await;
    assert!(done.is_ok(), "客户端断开后网关不得挂死");

    // usage 至多一次（断开时可能还没收到末帧 usage ⇒ 0 或 1 都合法，绝不重复）
    let n = captured.lock().unwrap().len();
    assert!(n <= 1, "usage 重复记录了 {n} 次");
}
