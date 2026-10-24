//! M42-S2b §7：SSE 拆包与三协议增量渲染（纯函数层）。

use tianshu_relay_core::gateway::translate::stream::{ChatDelta, SseDecoder, StreamTranslator};
use tianshu_relay_core::gateway::translate::Protocol;

// ---------------------------------------------------------------- T1 跨包

#[test]
fn sse_split_across_packets_is_reassembled() {
    let mut d = SseDecoder::new();
    // 一个完整事件被切成两块：第一块连 `data:` 都没写完
    assert!(d.push(br#"data: {"choices":[{"delta":{"con"#).is_empty());
    let evs = d.push(b"tent\":\"hi\"}}]}\n\n");
    assert_eq!(evs.len(), 1, "跨包必须拼出一个事件");
    assert_eq!(evs[0].data, r#"{"choices":[{"delta":{"content":"hi"}}]}"#);
}

#[test]
fn crlf_and_bare_data_prefix_are_accepted() {
    let mut d = SseDecoder::new();
    let evs = d.push(b"data:{\"a\":1}\r\n\r\n");
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].data, r#"{"a":1}"#, "`data:` 后无空格也要认");

    let mut d2 = SseDecoder::new();
    let evs2 = d2.push(b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
    assert_eq!(evs2[0].event.as_deref(), Some("message_stop"));
}

#[test]
fn multi_line_data_is_joined_with_newline() {
    let mut d = SseDecoder::new();
    let evs = d.push(b"data: a\ndata: b\n\n");
    assert_eq!(evs[0].data, "a\nb");
}

#[test]
fn comment_lines_are_ignored() {
    let mut d = SseDecoder::new();
    let evs = d.push(b": keep-alive\ndata: x\n\n");
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].data, "x");
}

// ---------------------------------------------------------------- T2 恰好一次

#[test]
fn stream_terminates_exactly_once() {
    for proto in [Protocol::OpenAiResponses, Protocol::AnthropicMessages] {
        let mut t = StreamTranslator::new(proto);
        let first = t.finish();
        assert!(!first.is_empty(), "{proto:?} 应产出收尾帧");
        let second = t.finish();
        assert!(second.is_empty(), "{proto:?} 收尾必须恰好一次");
    }
}

#[test]
fn done_marker_triggers_finish_and_is_idempotent() {
    let mut t = StreamTranslator::new(Protocol::AnthropicMessages);
    let ev = tianshu_relay_core::gateway::translate::stream::SseEvent {
        event: None,
        data: "[DONE]".to_string(),
    };
    let a = t.on_event(&ev);
    assert!(a.iter().any(|f| f.contains("message_stop")));
    let b = t.on_event(&ev);
    assert!(b.is_empty(), "[DONE] 之后不得再发收尾");
}

// ---------------------------------------------------------------- T4 Gemini 无 [DONE]

#[test]
fn gemini_stream_closes_without_done_marker() {
    let mut t = StreamTranslator::new(Protocol::GeminiGenerateContent);
    let ev = tianshu_relay_core::gateway::translate::stream::SseEvent {
        event: None,
        data: r#"{"choices":[{"delta":{"content":"你"}}]}"#.to_string(),
    };
    let frames = t.on_event(&ev);
    assert_eq!(frames.len(), 1);
    assert!(frames[0].contains("\"text\":\"你\""));
    // Gemini **没有 [DONE]**：收尾不额外发帧
    assert!(t.finish().is_empty(), "Gemini 不该发 [DONE] 或额外结束帧");
}

// ---------------------------------------------------------------- T5 三协议增量

#[test]
fn responses_delta_maps_to_output_text_delta() {
    let mut t = StreamTranslator::new(Protocol::OpenAiResponses);
    let ev = tianshu_relay_core::gateway::translate::stream::SseEvent {
        event: None,
        data: r#"{"choices":[{"delta":{"content":"好"}}]}"#.to_string(),
    };
    let frames = t.on_event(&ev);
    assert!(frames
        .iter()
        .any(|f| f.contains("response.output_text.delta")));
    assert!(frames.iter().any(|f| f.contains("\"delta\":\"好\"")));
}

#[test]
fn anthropic_delta_maps_to_content_block_delta() {
    let mut t = StreamTranslator::new(Protocol::AnthropicMessages);
    let ev = tianshu_relay_core::gateway::translate::stream::SseEvent {
        event: None,
        data: r#"{"choices":[{"delta":{"content":"好"}}]}"#.to_string(),
    };
    let frames = t.on_event(&ev);
    assert!(
        frames.iter().any(|f| f.contains("message_start")),
        "首个 delta 前要有 message_start"
    );
    assert!(frames.iter().any(|f| f.contains("content_block_start")));
    assert!(frames.iter().any(|f| f.contains("content_block_delta")));
}

// ---------------------------------------------------------------- T5 tool_calls 增量

#[test]
fn tool_call_delta_is_rendered_per_protocol() {
    let payload = r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"f1","arguments":"{\"a\":"}}]}}]}"#;

    let ev = || tianshu_relay_core::gateway::translate::stream::SseEvent {
        event: None,
        data: payload.to_string(),
    };

    let mut r = StreamTranslator::new(Protocol::OpenAiResponses);
    let f = r.on_event(&ev());
    assert!(f.iter().any(|x| x.contains("response.output_item.added")));
    assert!(f
        .iter()
        .any(|x| x.contains("function_call_arguments.delta")));

    let mut a = StreamTranslator::new(Protocol::AnthropicMessages);
    let f = a.on_event(&ev());
    assert!(f.iter().any(|x| x.contains("tool_use")));
    assert!(f.iter().any(|x| x.contains("input_json_delta")));

    // P1-2：Gemini 的 arguments 是累积的，on_event 不发、finish 时一次性发完整 functionCall
    let mut g = StreamTranslator::new(Protocol::GeminiGenerateContent);
    let f = g.on_event(&ev());
    assert!(
        !f.iter().any(|x| x.contains("functionCall")),
        "不该边收边发: {f:?}"
    );
    let fin = g.finish();
    assert!(fin.iter().any(|x| x.contains("functionCall")), "{fin:?}");
}

// ---------------------------------------------------------------- usage 解析

#[test]
fn usage_is_read_from_the_final_chunk() {
    let d = ChatDelta::from_json(
        r#"{"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}"#,
    )
    .unwrap();
    assert_eq!(d.usage, Some((5, 2, 7)));
}

// ---------------------------------------------------------------- P1-2 状态机：两个 tool_calls 跨多个 delta

#[test]
fn two_tool_calls_across_multiple_deltas_start_once_each() {
    use tianshu_relay_core::gateway::translate::stream::SseEvent;
    let mk = |data: &str| SseEvent {
        event: None,
        data: data.to_string(),
    };

    // 3 个 delta：第 1 个开两个块（各带首段 args），第 2/3 个只补 args
    let d1 = r#"{"choices":[{"delta":{"tool_calls":[
        {"index":0,"id":"c1","function":{"name":"f1","arguments":"{\"a\":"}},
        {"index":1,"id":"c2","function":{"name":"f2","arguments":"{\"b\":"}}]}}]}"#;
    let d2 =
        r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"1}"}}]}}]}"#;
    let d3 =
        r#"{"choices":[{"delta":{"tool_calls":[{"index":1,"function":{"arguments":"2}"}}]}}]}"#;

    // Anthropic：两个 content_block_start 只出现一次，后面只有 delta，finish 两个 stop
    let mut a = StreamTranslator::new(Protocol::AnthropicMessages);
    let mut starts = 0;
    let mut deltas = 0;
    for d in [d1, d2, d3] {
        for f in a.on_event(&mk(d)) {
            if f.contains("content_block_start") && f.contains("tool_use") {
                starts += 1;
            }
            if f.contains("input_json_delta") {
                deltas += 1;
            }
        }
    }
    assert_eq!(starts, 2, "每个 index 只开一次");
    assert_eq!(deltas, 4, "d1 有 2 个带 args 的 call + d2/d3 各 1 ⇒ 4");
    let fin = a.finish();
    let stops = fin
        .iter()
        .filter(|f| f.contains("content_block_stop"))
        .count();
    assert_eq!(stops, 2, "两个 tool 块都要收尾: {fin:?}");

    // Responses：added 只出现一次
    let mut r = StreamTranslator::new(Protocol::OpenAiResponses);
    let mut added = 0;
    for d in [d1, d2, d3] {
        for f in r.on_event(&mk(d)) {
            if f.contains("response.output_item.added") {
                added += 1;
            }
        }
    }
    assert_eq!(added, 2, "每个 index 只 added 一次");

    // Gemini：finish 时两个 functionCall 且 args 完整
    let mut g = StreamTranslator::new(Protocol::GeminiGenerateContent);
    for d in [d1, d2, d3] {
        let _ = g.on_event(&mk(d));
    }
    let fin = g.finish();
    let joined = fin.concat();
    assert!(joined.contains("functionCall"), "{joined}");
    let v: serde_json::Value = serde_json::from_str(
        joined
            .lines()
            .find_map(|l| l.strip_prefix("data: "))
            .expect("data 行"),
    )
    .expect("JSON");
    let parts = v["candidates"][0]["content"]["parts"].as_array().unwrap();
    assert_eq!(parts.len(), 2, "{v}");
    assert_eq!(
        parts[0]["functionCall"]["args"]["a"], 1,
        "args 必须累积完整: {v}"
    );
    assert_eq!(parts[1]["functionCall"]["args"]["b"], 2, "{v}");
}

// ---------------------------------------------------------------- B-224 P2：SSE 缓冲上限

#[test]
fn sse_decoder_flags_overflow_instead_of_growing_unbounded() {
    use tianshu_relay_core::gateway::translate::stream::MAX_SSE_EVENT_BYTES;
    let mut d = SseDecoder::new();
    // 正常小事件不受影响
    let evs = d.push(b"data: hi\n\n");
    assert_eq!(evs.len(), 1);
    assert!(!d.is_overflowed());
    // 一个永不发空行的超大事件：分两次喂，跨过上限即溢出，缓冲被清空
    let big = vec![b'x'; MAX_SSE_EVENT_BYTES + 1];
    let evs = d.push(&big);
    assert!(evs.is_empty(), "超限事件不应产出半截事件");
    assert!(
        d.is_overflowed(),
        "超 1 MiB 且无空行 ⇒ 必须记溢出（调用方据此发 error 关闭）"
    );
    // 溢出后仍可继续解新事件（缓冲已清空，不会把旧垃圾拼进来）
    let evs = d.push(b"data: ok\n\n");
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].data, "ok");
}
