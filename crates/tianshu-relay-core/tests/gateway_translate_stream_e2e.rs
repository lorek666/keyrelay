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

// ---------------------------------------------------------------- B-224 长尾：干净 EOF / 泵级溢出 / 停顿断开 / lease / 流式用量等价

/// 假上游：发一帧后**一直占着连接不发**（模拟上游停顿），供断开与 lease 用例用。
/// 每个连接独立占 30s，测试结束前由网关侧断开/进程退出收尾。
fn spawn_holding_sse(frame: String) -> SseUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let rec = Arc::clone(&seen);
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            let rec = Arc::clone(&rec);
            let frame = frame.clone();
            // 每连接一个线程：占着的连接不能挡住后续连接的 accept。
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    match s.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if String::from_utf8_lossy(&buf).contains("\r\n\r\n") {
                                break;
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
                let body = frame.as_bytes();
                let _ = s.write_all(format!("{:x}\r\n", body.len()).as_bytes());
                let _ = s.write_all(body);
                let _ = s.write_all(b"\r\n");
                let _ = s.flush();
                // 占着不发、不关：泵必须靠 tx.closed() 在客户端断开时退出，而不是等 read 超时。
                thread::sleep(Duration::from_secs(30));
            });
        }
    });
    SseUpstream {
        base_url: format!("http://{addr}"),
        seen,
    }
}

/// 只读响应头（流式 body 还没到也不等），返回状态行。
fn read_status_line(addr: &str, tok: &str, path: &str, body: &str) -> String {
    let mut s = TcpStream::connect(addr).expect("连接");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {tok}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if String::from_utf8_lossy(&out).contains("\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn clean_eof_without_done_emits_error_and_no_completed() {
    // 完整事件流（正文 + finish_reason + usage），唯独没有 [DONE]，随后正常结束 chunked。
    let frames = chat_sse("好", true).replace("data: [DONE]\n\n", "");
    let up = spawn_sse(vec![frames], 5, None);
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
        "干净 EOF 无 [DONE] 必须发错误事件: {text}"
    );
    assert!(
        !text.contains("response.completed"),
        "错误路径必须跳过正常收尾（否则客户端以为回答完整）: {text}"
    );
    h.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pump_level_sse_overflow_emits_error_and_closes() {
    // 一个永不发空行的超大事件（>1 MiB）：泵级必须发 error 并关闭，不继续缓冲。
    let big = format!("data: {}", "x".repeat(1024 * 1024 + 1));
    let up = spawn_sse(vec![big], 5, None);
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
        "超限事件必须发错误事件: {text}"
    );
    assert!(text.contains("超过上限"), "错误信息应点明上限: {text}");
    assert!(
        !text.contains("response.completed"),
        "溢出后不得再发正常收尾: {text}"
    );
    h.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_stall_and_client_disconnect_exits_without_read_timeout() {
    // 上游发一帧后停顿（默认 read 超时 240s）；客户端断开后泵必须立即退出，
    // shutdown 在 10s 内返回——不等读超时是 tx.closed() select 的唯一证明。
    let up = spawn_holding_sse(chat_sse("一", false));
    let h = start_gw(&up).await;
    let addr = h.addr.to_string();
    let body = json!({"model":"gpt-5.6","input":[],"stream":true}).to_string();
    let _ = tokio::task::spawn_blocking(move || {
        stream_read(&addr, TOKEN, "/v1/responses", &body, Some(1))
    })
    .await
    .unwrap();
    let done =
        tokio::time::timeout(std::time::Duration::from_secs(10), h.shutdown_and_wait()).await;
    assert!(
        done.is_ok(),
        "上游停顿 + 客户端断开后，网关必须立即退出而不是等 240s 读超时"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn streaming_translation_holds_the_concurrency_lease() {
    use tianshu_relay_core::routing::SiteGuardPolicy;
    let up = spawn_holding_sse(chat_sse("一", false));
    let mut config = GatewayConfig::single_upstream(
        0,
        TOKEN.to_string(),
        up.base_url.clone(),
        Zeroizing::new(KEY_A.to_string()),
        "s2b".to_string(),
    );
    config.guard_policy = SiteGuardPolicy {
        max_concurrency: 1,
        rate_limit_per_sec: 0,
    };
    let h = start(config).await.expect("启动");
    let addr = h.addr.to_string();
    let body = json!({"model":"gpt-5.6","input":[],"stream":true}).to_string();

    // 第一条流式请求：读到首帧后占着连接不放（流未结束 ⇒ lease 未归还）。
    let addr1 = addr.clone();
    let body1 = body.clone();
    let first_conn = tokio::task::spawn_blocking(move || {
        let mut s = TcpStream::connect(&addr1).expect("连接");
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let req = format!(
            "POST /v1/responses HTTP/1.1\r\nHost: {addr1}\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body1}",
            body1.len()
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut buf = [0u8; 1024];
        let mut out = Vec::new();
        loop {
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if String::from_utf8_lossy(&out).contains("output_text.delta") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        s // 占着不 drop
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 第二条：lease 被占 ⇒ 本地 429。
    let status2 = read_status_line(&addr, TOKEN, "/v1/responses", &body);
    assert!(
        status2.contains("429"),
        "流未结束时第二条必须被本地拒绝（lease 覆盖整条流式响应）: {status2}"
    );
    assert!(status2.contains("local_rate_limited"), "{status2}");

    // 放掉第一条（客户端断开 ⇒ 泵退出 ⇒ lease 归还），第三条不再 429。
    drop(first_conn);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let status3 = read_status_line(&addr, TOKEN, "/v1/responses", &body);
    assert!(
        status3.contains("200"),
        "第一条结束后 lease 必须已归还: {status3}"
    );
    h.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn streaming_translated_usage_matches_passthrough_usage_field_by_field() {
    // 同一上游流、两个 usage 帧（先 4/2/6、后 10/5/15）：末帧口径下翻译与直通必须同为 10/5/15。
    // （旧首帧口径会使翻译行记成 4/2/6，与直通的末帧行不等——本用例即判别点。）
    let frames = format!(
        "data: {}\n\ndata: {}\n\ndata: {}\n\ndata: [DONE]\n\n",
        json!({"choices":[{"delta":{"content":"好"}}]}),
        json!({"choices":[],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}),
        json!({"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}),
    );
    let up = spawn_sse(vec![frames], 5, None);
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

    // 直通：Chat 流式。
    let chat_body =
        json!({"model":"m","messages":[{"role":"user","content":"问"}],"stream":true}).to_string();
    let addr_c = addr.clone();
    let _ = tokio::task::spawn_blocking(move || {
        stream_read(&addr_c, TOKEN, "/v1/chat/completions", &chat_body, None)
    })
    .await
    .unwrap();
    // 翻译：Responses 流式，同一模型名。
    let resp_body = json!({"model":"m","input":[],"stream":true}).to_string();
    let _ = tokio::task::spawn_blocking(move || {
        stream_read(&addr, TOKEN, "/v1/responses", &resp_body, None)
    })
    .await
    .unwrap();

    let rows = captured.lock().unwrap().clone();
    assert_eq!(rows.len(), 2, "直通与翻译应各记一行: {rows:?}");
    let (a, b) = (&rows[0], &rows[1]);
    for (f, av, bv) in [
        ("site_id", a.site_id, b.site_id),
        ("prompt_tokens", a.prompt_tokens, b.prompt_tokens),
        (
            "completion_tokens",
            a.completion_tokens,
            b.completion_tokens,
        ),
        ("total_tokens", a.total_tokens, b.total_tokens),
    ] {
        assert_eq!(av, bv, "{f} 两路必须相等: {a:?} vs {b:?}");
    }
    assert_eq!(a.stream, b.stream, "stream 标志两路必须相等");
    assert_eq!(a.model, b.model, "模型名两路必须相等");
    assert_eq!(
        a.prompt_tokens, 10,
        "末帧口径：应记后一次 usage，不是首帧的 4: {a:?}"
    );
    assert_eq!(a.total_tokens, 15, "{a:?}");
    h.shutdown_and_wait().await;
}
