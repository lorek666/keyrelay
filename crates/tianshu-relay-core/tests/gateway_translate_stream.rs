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

    let mut g = StreamTranslator::new(Protocol::GeminiGenerateContent);
    let f = g.on_event(&ev());
    assert!(f.iter().any(|x| x.contains("functionCall")), "{f:?}");
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
