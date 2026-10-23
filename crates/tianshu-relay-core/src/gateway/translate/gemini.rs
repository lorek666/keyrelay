//! Gemini generateContent ⇄ IR（M42-S2a §4.3）。

use super::ir::*;
use super::{reject_unknown, TranslateError};
use serde_json::{json, Value};

const ALLOWED: &[&str] = &[
    "contents",
    "systemInstruction",
    "generationConfig",
    "tools",
    "stream",
];

pub fn parse_request(v: &Value) -> Result<ChatRequest, TranslateError> {
    reject_unknown(v, ALLOWED, "Gemini")?;
    // Gemini 的模型名在**路径**里，不在 body 里 ⇒ 由调用方填。这里先取 body 的可选 model。
    let model = v
        .get("model")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let system = v
        .get("systemInstruction")
        .and_then(|s| s.get("parts"))
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.get("text").and_then(|x| x.as_str()))
                .collect::<Vec<_>>()
                .join("")
        })
        .filter(|s| !s.is_empty());

    let mut messages = Vec::new();
    if let Some(arr) = v.get("contents").and_then(|x| x.as_array()) {
        for c in arr {
            let role = c.get("role").and_then(|x| x.as_str()).unwrap_or("user");
            let mut parts = Vec::new();
            let mut calls = Vec::new();
            if let Some(ps) = c.get("parts").and_then(|x| x.as_array()) {
                for p in ps {
                    if let Some(t) = p.get("text").and_then(|x| x.as_str()) {
                        parts.push(ContentPart::Text(t.to_string()));
                    }
                    if let Some(d) = p.get("inlineData") {
                        if let (Some(m), Some(data)) = (
                            d.get("mimeType").and_then(|x| x.as_str()),
                            d.get("data").and_then(|x| x.as_str()),
                        ) {
                            parts.push(ContentPart::ImageUrl(format!("data:{m};base64,{data}")));
                        }
                    }
                    if let Some(fc) = p.get("functionCall") {
                        calls.push(ToolCall {
                            id: fc
                                .get("id")
                                .and_then(|x| x.as_str())
                                .unwrap_or("call")
                                .to_string(),
                            name: fc
                                .get("name")
                                .and_then(|x| x.as_str())
                                .unwrap_or("")
                                .to_string(),
                            arguments: fc.get("args").cloned().unwrap_or(json!({})),
                        });
                    }
                }
            }
            if role == "model" {
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

    let gc = v.get("generationConfig").cloned().unwrap_or(json!({}));
    let tools = v
        .get("tools")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .flat_map(|t| {
                    t.get("functionDeclarations")
                        .and_then(|x| x.as_array())
                        .cloned()
                        .unwrap_or_default()
                })
                .filter_map(|f| {
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
        temperature: gc.get("temperature").and_then(|x| x.as_f64()),
        top_p: gc.get("topP").and_then(|x| x.as_f64()),
        max_tokens: gc
            .get("maxOutputTokens")
            .and_then(|x| x.as_u64())
            .map(|n| n as u32),
        stop: gc
            .get("stopSequences")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        tools,
    })
}

pub fn render_response(resp: &ChatResponse) -> Value {
    let choice = resp.choices.first();
    let mut parts: Vec<Value> = Vec::new();
    if let Some(c) = choice {
        if let Some(t) = &c.message.text {
            parts.push(json!({ "text": t }));
        }
        // N 个 functionCall
        for call in &c.message.tool_calls {
            parts.push(json!({ "functionCall": { "name": call.name, "args": call.arguments } }));
        }
    }
    let finish = choice
        .and_then(|c| c.finish_reason.clone())
        .map(|r| match r.as_str() {
            "length" => "MAX_TOKENS",
            "tool_calls" => "STOP",
            _ => "STOP",
        });
    let mut out = json!({
        "candidates": [{
            "content": { "role": "model", "parts": parts },
            "finishReason": finish,
            "index": 0,
        }],
    });
    if let Some(u) = resp.usage {
        out["usageMetadata"] = json!({
            "promptTokenCount": u.prompt_tokens,
            "candidatesTokenCount": u.completion_tokens,
            "totalTokenCount": u.total_tokens,
        });
    }
    out
}
