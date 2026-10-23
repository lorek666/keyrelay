//! OpenAI Responses ⇄ IR（M42-S2a §4.3）。

use super::ir::*;
use super::{reject_unknown, TranslateError};
use serde_json::{json, Value};

const ALLOWED: &[&str] = &[
    "model",
    "instructions",
    "input",
    "max_output_tokens",
    "temperature",
    "top_p",
    "tools",
    "tool_choice",
    "stream",
];

pub fn parse_request(v: &Value) -> Result<ChatRequest, TranslateError> {
    reject_unknown(v, ALLOWED, "Responses")?;
    // (3) tool_choice：字符串 `auto`/`none` 与对象 `{"type":"auto"|"none"}` 都放行；其余 400 点名
    if let Some(tc) = v.get("tool_choice") {
        let kind = tc
            .as_str()
            .or_else(|| tc.get("type").and_then(|x| x.as_str()))
            .unwrap_or("<未知>");
        if kind != "auto" && kind != "none" {
            return Err(TranslateError::new(
                "unsupported_field",
                format!("Responses: 不支持字段 `tool_choice: {kind}`（只支持 auto/none）"),
            ));
        }
    }
    let model = v
        .get("model")
        .and_then(|x| x.as_str())
        .ok_or_else(|| TranslateError::new("invalid_request", "Responses: 缺少 model"))?
        .to_string();
    let system = v
        .get("instructions")
        .and_then(|x| x.as_str())
        .map(str::to_string);

    let mut messages = Vec::new();
    match v.get("input") {
        Some(Value::String(s)) => {
            messages.push(ChatMessage::User(vec![ContentPart::Text(s.clone())]))
        }
        Some(Value::Array(items)) => {
            for item in items {
                let role = item.get("role").and_then(|x| x.as_str()).unwrap_or("user");
                let mut parts = Vec::new();
                let mut text = None;
                if let Some(c) = item.get("content") {
                    match c {
                        Value::String(s) => text = Some(s.clone()),
                        Value::Array(arr) => {
                            for p in arr {
                                match p.get("type").and_then(|x| x.as_str()) {
                                    Some("input_text") => {
                                        if let Some(t) = p.get("text").and_then(|x| x.as_str()) {
                                            parts.push(ContentPart::Text(t.to_string()));
                                        }
                                    }
                                    Some("input_image") => {
                                        if let Some(u) = p.get("image_url").and_then(|x| x.as_str())
                                        {
                                            parts.push(ContentPart::ImageUrl(u.to_string()));
                                        }
                                    }
                                    Some(other) => {
                                        return Err(TranslateError::new(
                                            "unsupported_field",
                                            format!("Responses: 不支持内容块 `{other}`"),
                                        ))
                                    }
                                    None => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(t) = text {
                    parts.push(ContentPart::Text(t));
                }
                if role == "assistant" {
                    messages.push(ChatMessage::Assistant(AssistantTurn {
                        text: first_text(&parts),
                        tool_calls: vec![],
                    }));
                } else {
                    messages.push(ChatMessage::User(parts));
                }
            }
        }
        _ => {
            return Err(TranslateError::new(
                "invalid_request",
                "Responses: 缺少 input",
            ))
        }
    }

    let tools = v
        .get("tools")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| {
                    let f = t.get("function")?;
                    Some(ToolSpec {
                        name: f.get("name")?.as_str()?.to_string(),
                        description: f
                            .get("description")
                            .and_then(|x| x.as_str())
                            .map(str::to_string),
                        parameters: f.get("parameters").cloned().unwrap_or(json!({})),
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
        max_tokens: v
            .get("max_output_tokens")
            .and_then(|x| x.as_u64())
            .map(|n| n as u32),
        stop: vec![],
        tools,
        stream: false,
    })
}

fn first_text(parts: &[ContentPart]) -> Option<String> {
    parts.iter().find_map(|p| match p {
        ContentPart::Text(t) => Some(t.clone()),
        _ => None,
    })
}

pub fn render_response(resp: &ChatResponse) -> Value {
    let choice = resp.choices.first();
    let mut output: Vec<Value> = Vec::new();
    if let Some(c) = choice {
        if let Some(t) = &c.message.text {
            output.push(json!({
                "type": "message",
                "role": "assistant",
                "content": [{ "type": "output_text", "text": t }],
            }));
        }
        // M42-S2a：**N 个** tool_calls 逐个渲染（不截断、不合并）
        for call in &c.message.tool_calls {
            output.push(json!({
                "type": "function_call",
                "call_id": call.id,
                "name": call.name,
                "arguments": call.arguments.to_string(),
            }));
        }
    }
    let mut out = json!({
        "id": resp.id,
        "object": "response",
        "model": resp.model,
        "status": "completed",
        "output": output,
    });
    if let Some(u) = resp.usage {
        out["usage"] = json!({
            "input_tokens": u.prompt_tokens,
            "output_tokens": u.completion_tokens,
            "total_tokens": u.total_tokens,
        });
    }
    out
}
