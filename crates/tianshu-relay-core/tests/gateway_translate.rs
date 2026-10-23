//! M42-S2a §7：协议翻译的纯函数层（detect / 解析 / 渲染）。
//!
//! 翻译层是纯函数，所以这些用例**不启网关、不连上游**——它们直接断言「输入 → IR → 输出」。
//! 端到端（wire-in）用例在 `gateway_envelope.rs`/`gateway_failover.rs` 的家族里另算。

use axum::http::{HeaderMap, HeaderValue, Method};
use serde_json::{json, Value};
use tianshu_relay_core::gateway::translate::{
    detect, parse_request, render_response, ChatResponse, ContentPart, Protocol,
};

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.insert(
            axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    h
}

// ---------------------------------------------------------------- T1 detect

#[test]
fn detect_maps_method_and_path_only() {
    let h = headers(&[]);
    assert_eq!(
        detect(&Method::POST, "/v1/chat/completions", &h),
        Some(Protocol::OpenAiChat)
    );
    assert_eq!(
        detect(&Method::POST, "/v1/responses", &h),
        Some(Protocol::OpenAiResponses)
    );
    assert_eq!(
        detect(
            &Method::POST,
            "/v1beta/models/gemini-2.5-pro:generateContent",
            &h
        ),
        Some(Protocol::GeminiGenerateContent)
    );
    // Anthropic 必须有版本头
    assert_eq!(detect(&Method::POST, "/v1/messages", &h), None);
    assert_eq!(
        detect(
            &Method::POST,
            "/v1/messages",
            &headers(&[("anthropic-version", "2023-06-01")])
        ),
        Some(Protocol::AnthropicMessages)
    );
    // 未知路径 / 非 POST ⇒ None（走透传）
    assert_eq!(detect(&Method::POST, "/v1/embeddings", &h), None);
    assert_eq!(detect(&Method::GET, "/v1/models", &h), None);
}

// ---------------------------------------------------------------- T3 Responses

#[test]
fn responses_request_and_response_roundtrip() {
    let body = json!({
        "model": "gpt-5.6",
        "instructions": "你是助手",
        "input": [
            { "role": "user", "content": [{ "type": "input_text", "text": "你好" }] }
        ],
        "max_output_tokens": 256,
        "temperature": 0.2
    });
    let req = parse_request(Protocol::OpenAiResponses, body.to_string().as_bytes()).unwrap();
    assert_eq!(req.model, "gpt-5.6");
    assert_eq!(req.system.as_deref(), Some("你是助手"));
    assert_eq!(req.max_tokens, Some(256));
    assert_eq!(req.temperature, Some(0.2));
    let up = req.to_upstream_json();
    assert_eq!(up["messages"][0]["role"], "system");
    assert_eq!(up["messages"][1]["content"], "你好");

    let resp = ChatResponse::from_upstream_json(&json!({
        "id": "chatcmpl-1", "model": "gpt-5.6",
        "choices": [{ "index": 0, "message": { "content": "在" }, "finish_reason": "stop" }],
        "usage": { "prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4 }
    }))
    .unwrap();
    let out = render_response(Protocol::OpenAiResponses, &resp);
    assert_eq!(out["object"], "response");
    assert_eq!(out["output"][0]["content"][0]["text"], "在");
    assert_eq!(out["usage"]["input_tokens"], 3);
}

// ---------------------------------------------------------------- T4 Anthropic

#[test]
fn anthropic_request_and_response_roundtrip() {
    let body = json!({
        "model": "claude-x",
        "system": "规则",
        "max_tokens": 128,
        "messages": [{ "role": "user", "content": [{ "type": "text", "text": "嗨" }] }]
    });
    let req = parse_request(Protocol::AnthropicMessages, body.to_string().as_bytes()).unwrap();
    assert_eq!(req.system.as_deref(), Some("规则"));
    assert_eq!(req.max_tokens, Some(128));

    let resp = ChatResponse::from_upstream_json(&json!({
        "id": "c1", "model": "claude-x",
        "choices": [{ "index": 0, "message": { "content": "好" }, "finish_reason": "stop" }]
    }))
    .unwrap();
    let out = render_response(Protocol::AnthropicMessages, &resp);
    assert_eq!(out["type"], "message");
    assert_eq!(out["content"][0]["text"], "好");
    assert_eq!(out["stop_reason"], "end_turn");
    // max_tokens 必填
    let bad = json!({ "model": "x", "messages": [] });
    assert!(parse_request(Protocol::AnthropicMessages, bad.to_string().as_bytes()).is_err());
}

// ---------------------------------------------------------------- T5 Gemini

#[test]
fn gemini_request_and_response_roundtrip() {
    let body = json!({
        "systemInstruction": { "parts": [{ "text": "系统" }] },
        "contents": [{ "role": "user", "parts": [{ "text": "问" }] }],
        "generationConfig": { "temperature": 0.5, "maxOutputTokens": 64 }
    });
    let req = parse_request(Protocol::GeminiGenerateContent, body.to_string().as_bytes()).unwrap();
    assert_eq!(req.system.as_deref(), Some("系统"));
    assert_eq!(req.max_tokens, Some(64));
    assert_eq!(req.temperature, Some(0.5));

    let resp = ChatResponse::from_upstream_json(&json!({
        "id": "g1", "model": "gemini",
        "choices": [{ "index": 0, "message": { "content": "答" }, "finish_reason": "stop" }]
    }))
    .unwrap();
    let out = render_response(Protocol::GeminiGenerateContent, &resp);
    assert_eq!(out["candidates"][0]["content"]["parts"][0]["text"], "答");
    assert_eq!(out["candidates"][0]["content"]["role"], "model");
}

// ---------------------------------------------------------------- T6/T7 工具调用 N 个

fn two_calls_response() -> ChatResponse {
    ChatResponse::from_upstream_json(&json!({
        "id": "t1", "model": "m",
        "choices": [{
            "index": 0,
            "message": {
                "content": null,
                "tool_calls": [
                    { "id": "c1", "type": "function", "function": { "name": "f1", "arguments": "{\"a\":1}" } },
                    { "id": "c2", "type": "function", "function": { "name": "f2", "arguments": "{\"b\":2}" } }
                ]
            },
            "finish_reason": "tool_calls"
        }]
    }))
    .unwrap()
}

#[test]
fn two_tool_calls_survive_the_roundtrip_responses() {
    let out = render_response(Protocol::OpenAiResponses, &two_calls_response());
    let calls: Vec<&Value> = out["output"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["type"] == "function_call")
        .collect();
    assert_eq!(calls.len(), 2, "两个 tool_calls 必须都渲染: {out}");
    assert_eq!(calls[0]["name"], "f1");
    assert_eq!(calls[1]["name"], "f2");
}

#[test]
fn two_tool_calls_survive_the_roundtrip_anthropic() {
    let out = render_response(Protocol::AnthropicMessages, &two_calls_response());
    let uses: Vec<&Value> = out["content"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["type"] == "tool_use")
        .collect();
    assert_eq!(uses.len(), 2, "{out}");
    assert_eq!(uses[0]["name"], "f1");
    assert_eq!(uses[1]["name"], "f2");
}

#[test]
fn two_tool_calls_survive_the_roundtrip_gemini() {
    let out = render_response(Protocol::GeminiGenerateContent, &two_calls_response());
    let calls: Vec<&Value> = out["candidates"][0]["content"]["parts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x.get("functionCall").is_some())
        .collect();
    assert_eq!(calls.len(), 2, "{out}");
    assert_eq!(calls[0]["functionCall"]["name"], "f1");
}

// ---------------------------------------------------------------- T8 图片

#[test]
fn images_map_to_image_part() {
    let resp = json!({
        "model": "m",
        "input": [{ "role": "user", "content": [
            { "type": "input_text", "text": "看图" },
            { "type": "input_image", "image_url": "https://x/y.png" }
        ]}]
    });
    let req = parse_request(Protocol::OpenAiResponses, resp.to_string().as_bytes()).unwrap();
    let up = req.to_upstream_json();
    let parts = up["messages"][0]["content"].as_array().unwrap();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[1]["type"], "image_url");
    assert_eq!(parts[1]["image_url"]["url"], "https://x/y.png");

    // Gemini inlineData → data URI
    let g = json!({
        "contents": [{ "role": "user", "parts": [
            { "text": "看" },
            { "inlineData": { "mimeType": "image/png", "data": "AAA" } }
        ]}]
    });
    let req = parse_request(Protocol::GeminiGenerateContent, g.to_string().as_bytes()).unwrap();
    let imgs: Vec<_> = req
        .messages
        .iter()
        .flat_map(|m| match m {
            tianshu_relay_core::gateway::translate::ChatMessage::User(p) => p.clone(),
            _ => vec![],
        })
        .filter(|p| matches!(p, ContentPart::ImageUrl(_)))
        .collect();
    assert_eq!(imgs.len(), 1);
}

// ---------------------------------------------------------------- T9 不支持字段

#[test]
fn unsupported_fields_are_named_not_dropped() {
    for (proto, body, field) in [
        (
            Protocol::OpenAiResponses,
            json!({"model":"m","input":[],"reasoning":{}}),
            "reasoning",
        ),
        (
            Protocol::AnthropicMessages,
            json!({"model":"m","max_tokens":1,"messages":[],"thinking":{}}),
            "thinking",
        ),
        (
            Protocol::GeminiGenerateContent,
            json!({"contents":[],"safetySettings":[]}),
            "safetySettings",
        ),
    ] {
        let err = parse_request(proto, body.to_string().as_bytes()).unwrap_err();
        assert_eq!(err.code, "unsupported_field");
        assert!(
            err.message.contains(field),
            "必须点名 {field}: {}",
            err.message
        );
    }
}

// ---------------------------------------------------------------- T11 stream 400

#[test]
fn streaming_is_rejected_with_the_s2b_hint() {
    for proto in [
        Protocol::OpenAiResponses,
        Protocol::AnthropicMessages,
        Protocol::GeminiGenerateContent,
    ] {
        let v = match proto {
            Protocol::AnthropicMessages => {
                json!({"model":"m","max_tokens":1,"messages":[],"stream":true})
            }
            _ => json!({"model":"m","input":[],"contents":[],"stream":true}),
        };
        let err = parse_request(proto, v.to_string().as_bytes()).unwrap_err();
        assert_eq!(err.code, "streaming_not_supported", "{proto:?}");
        assert!(
            err.message.contains("M42-S2b"),
            "必须点名 M42-S2b: {}",
            err.message
        );
    }
}

// ---------------------------------------------------------------- 复审 P1-1：Gemini functionResponse

#[test]
fn gemini_function_response_becomes_a_tool_message() {
    let body = json!({
        "contents": [
            { "role": "user", "parts": [{ "text": "查天气" }] },
            { "role": "model", "parts": [{ "functionCall": { "name": "get_weather", "args": {"city":"SH"} } }] },
            { "role": "user", "parts": [{ "functionResponse": {
                "name": "get_weather",
                "response": { "temp": 21, "sky": "晴" }
            }}] }
        ]
    });
    let req = parse_request(Protocol::GeminiGenerateContent, body.to_string().as_bytes()).unwrap();
    let up = req.to_upstream_json();
    let msgs = up["messages"].as_array().unwrap();
    // system? 没有；user / assistant(tool_call) / tool
    let tool = msgs
        .iter()
        .find(|m| m["role"] == "tool")
        .expect("必须有 tool 消息");
    let content = tool["content"].as_str().unwrap();
    assert!(
        content.contains("temp: 21"),
        "对象要展开成 k: v，不是整段 JSON: {content}"
    );
    assert!(content.contains("sky: 晴"), "{content}");
    assert!(!content.starts_with('{'), "不得整段 JSON 引号: {content}");
    // 空 parts 的 model 轮次不该产生空 assistant
    assert!(msgs
        .iter()
        .all(|m| m["role"] != "assistant" || m.get("tool_calls").is_some()));
}

// ---------------------------------------------------------------- 复审 P1-2：Anthropic base64 图片

#[test]
fn anthropic_base64_image_becomes_a_data_uri() {
    let body = json!({
        "model": "claude-x", "max_tokens": 8,
        "messages": [{ "role": "user", "content": [
            { "type": "text", "text": "看图" },
            { "type": "image", "source": { "type": "base64", "media_type": "image/jpeg", "data": "QUJD" } }
        ]}]
    });
    let req = parse_request(Protocol::AnthropicMessages, body.to_string().as_bytes()).unwrap();
    let up = req.to_upstream_json();
    let parts = up["messages"][0]["content"].as_array().unwrap();
    assert_eq!(parts[1]["type"], "image_url");
    assert_eq!(parts[1]["image_url"]["url"], "data:image/jpeg;base64,QUJD");

    // url 形态仍在
    let body2 = json!({
        "model": "claude-x", "max_tokens": 8,
        "messages": [{ "role": "user", "content": [
            { "type": "image", "source": { "type": "url", "url": "https://x/y.png" } }
        ]}]
    });
    let req2 = parse_request(Protocol::AnthropicMessages, body2.to_string().as_bytes()).unwrap();
    let up2 = req2.to_upstream_json();
    assert_eq!(
        up2["messages"][0]["content"][0]["image_url"]["url"],
        "https://x/y.png"
    );
}

// ---------------------------------------------------------------- 复审 P1-3：tool_choice 对象

#[test]
fn tool_choice_objects_are_accepted_for_auto_and_none_only() {
    // Anthropic：对象形态 auto/none 放行
    for ok in ["auto", "none"] {
        let body = json!({
            "model": "m", "max_tokens": 8, "messages": [],
            "tool_choice": { "type": ok }
        });
        assert!(
            parse_request(Protocol::AnthropicMessages, body.to_string().as_bytes()).is_ok(),
            "Anthropic tool_choice.type={ok} 应放行"
        );
    }
    // Anthropic：any / tool / 未知 ⇒ 400 点名
    for bad in ["any", "tool", "weird"] {
        let body = json!({
            "model": "m", "max_tokens": 8, "messages": [],
            "tool_choice": { "type": bad }
        });
        let err =
            parse_request(Protocol::AnthropicMessages, body.to_string().as_bytes()).unwrap_err();
        assert_eq!(err.code, "unsupported_field");
        assert!(err.message.contains(bad), "必须点名 {bad}: {}", err.message);
    }
    // Responses：对象形态同样处理
    let ok = json!({ "model": "m", "input": [], "tool_choice": { "type": "auto" } });
    assert!(parse_request(Protocol::OpenAiResponses, ok.to_string().as_bytes()).is_ok());
    let bad = json!({ "model": "m", "input": [], "tool_choice": { "type": "tool" } });
    let err = parse_request(Protocol::OpenAiResponses, bad.to_string().as_bytes()).unwrap_err();
    assert!(err.message.contains("tool"), "{}", err.message);
}
