//! Anthropic Messages ⇄ IR（M42-S2a §4.3）。

use super::ir::*;
use super::{reject_unknown, TranslateError};
use serde_json::{json, Value};

/// 入站白名单（与 M42-S2a spec §4.2 白名单表同源；改表必须同步改 spec）。
const ALLOWED: &[&str] = &[
    "model",
    "system",
    "messages",
    "max_tokens",
    "temperature",
    "top_p",
    "stop_sequences",
    "tools",
    "tool_choice",
    "stream",
    "metadata",
    // M47-S2：`thinking` 现在**放行**——是否真的生效由网关按内置模型名单决定
    // （名单说支持 ⇒ 折算成上游 Chat 的 `reasoning_effort`，否则丢弃）。
    // 这里仍保留「点名拒绝未知字段」的纪律：只有这个字段被显式加进白名单。
    "thinking",
];

pub fn parse_request(v: &Value) -> Result<ChatRequest, TranslateError> {
    reject_unknown(v, ALLOWED, "Anthropic")?;
    // (3) tool_choice：`{"type":"auto"|"none"}` 放行；`any`/`tool`/未知 ⇒ 400 点名
    if let Some(tc) = v.get("tool_choice") {
        let kind = tc
            .get("type")
            .and_then(|x| x.as_str())
            .unwrap_or("<无 type>");
        if kind != "auto" && kind != "none" {
            return Err(TranslateError::new(
                "unsupported_field",
                format!("Anthropic: 不支持字段 `tool_choice.type: {kind}`（只支持 auto/none）"),
            ));
        }
    }
    let model = v
        .get("model")
        .and_then(|x| x.as_str())
        .ok_or_else(|| TranslateError::new("invalid_request", "Anthropic: 缺少 model"))?
        .to_string();
    // Anthropic 语义里 max_tokens **必填**
    let max_tokens = v
        .get("max_tokens")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| TranslateError::new("invalid_request", "Anthropic: 缺少 max_tokens"))?
        as u32;

    let system = match v.get("system") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Array(arr)) => {
            let mut out = String::new();
            for b in arr {
                match b.get("type").and_then(|x| x.as_str()) {
                    Some("text") => {
                        if let Some(t) = b.get("text").and_then(|x| x.as_str()) {
                            out.push_str(t);
                        }
                    }
                    Some(other) => {
                        return Err(TranslateError::new(
                            "unsupported_field",
                            format!("Anthropic: system 里不支持块 `{other}`"),
                        ))
                    }
                    None => {}
                }
            }
            (!out.is_empty()).then_some(out)
        }
        _ => None,
    };

    let mut messages = Vec::new();
    if let Some(arr) = v.get("messages").and_then(|x| x.as_array()) {
        for m in arr {
            let role = m.get("role").and_then(|x| x.as_str()).unwrap_or("user");
            let mut parts = Vec::new();
            let mut calls = Vec::new();
            let mut results = Vec::new();
            match m.get("content") {
                Some(Value::String(s)) => parts.push(ContentPart::Text(s.clone())),
                Some(Value::Array(blocks)) => {
                    for b in blocks {
                        match b.get("type").and_then(|x| x.as_str()) {
                            Some("text") => {
                                if let Some(t) = b.get("text").and_then(|x| x.as_str()) {
                                    parts.push(ContentPart::Text(t.to_string()));
                                }
                            }
                            Some("image") => {
                                // (2) 两种形态：base64（data URI）与 url
                                let src = b.get("source");
                                match src.and_then(|s| s.get("type")).and_then(|x| x.as_str()) {
                                    Some("base64") => {
                                        let media = src
                                            .and_then(|s| s.get("media_type"))
                                            .and_then(|x| x.as_str())
                                            .unwrap_or("image/png");
                                        let data = src
                                            .and_then(|s| s.get("data"))
                                            .and_then(|x| x.as_str())
                                            .unwrap_or("");
                                        parts.push(ContentPart::ImageUrl(format!(
                                            "data:{media};base64,{data}"
                                        )));
                                    }
                                    _ => {
                                        if let Some(u) =
                                            src.and_then(|s| s.get("url")).and_then(|x| x.as_str())
                                        {
                                            parts.push(ContentPart::ImageUrl(u.to_string()));
                                        }
                                    }
                                }
                            }
                            Some("tool_use") => calls.push(ToolCall {
                                id: b
                                    .get("id")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("call")
                                    .to_string(),
                                name: b
                                    .get("name")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                arguments: b.get("input").cloned().unwrap_or(json!({})),
                            }),
                            Some("tool_result") => results.push(ToolResult {
                                tool_call_id: b
                                    .get("tool_use_id")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("call")
                                    .to_string(),
                                content: b
                                    .get("content")
                                    .map(|c| c.to_string())
                                    .unwrap_or_default(),
                            }),
                            Some(other) => {
                                return Err(TranslateError::new(
                                    "unsupported_field",
                                    format!("Anthropic: 不支持内容块 `{other}`"),
                                ))
                            }
                            None => {}
                        }
                    }
                }
                _ => {}
            }
            for r in results {
                messages.push(ChatMessage::Tool(r));
            }
            if role == "assistant" {
                let text = parts.iter().find_map(|p| match p {
                    ContentPart::Text(t) => Some(t.clone()),
                    _ => None,
                });
                messages.push(ChatMessage::Assistant(AssistantTurn {
                    text,
                    tool_calls: calls,
                }));
            } else if !parts.is_empty() {
                messages.push(ChatMessage::User(parts));
            }
        }
    }

    let tools = v
        .get("tools")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| {
                    Some(ToolSpec {
                        name: t.get("name")?.as_str()?.to_string(),
                        description: t
                            .get("description")
                            .and_then(|x| x.as_str())
                            .map(str::to_string),
                        parameters: t.get("input_schema").cloned().unwrap_or(json!({})),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(ChatRequest {
        model,
        messages,
        system,
        temperature: v.get("temperature").and_then(|x| x.as_f64()),
        top_p: v.get("top_p").and_then(|x| x.as_f64()),
        max_tokens: Some(max_tokens),
        stop: v
            .get("stop_sequences")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        tools,
        reasoning_effort: None,
        stream: false,
    })
}

pub fn render_response(resp: &ChatResponse) -> Value {
    let choice = resp.choices.first();
    let mut content: Vec<Value> = Vec::new();
    if let Some(c) = choice {
        if let Some(t) = &c.message.text {
            content.push(json!({ "type": "text", "text": t }));
        }
        // N 个 tool_use
        for call in &c.message.tool_calls {
            content.push(json!({
                "type": "tool_use",
                "id": call.id,
                "name": call.name,
                "input": call.arguments,
            }));
        }
    }
    let stop_reason = choice
        .and_then(|c| c.finish_reason.clone())
        .map(|r| match r.as_str() {
            "length" => "max_tokens",
            "tool_calls" => "tool_use",
            _ => "end_turn",
        });
    let mut out = json!({
        "id": resp.id,
        "type": "message",
        "role": "assistant",
        "model": resp.model,
        "content": content,
        "stop_reason": stop_reason,
    });
    if let Some(u) = resp.usage {
        out["usage"] =
            json!({ "input_tokens": u.prompt_tokens, "output_tokens": u.completion_tokens });
    }
    out
}
