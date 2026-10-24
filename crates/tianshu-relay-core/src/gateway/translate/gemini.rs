//! Gemini generateContent ⇄ IR（M42-S2a §4.3）。

use super::ir::*;
use super::{reject_unknown, TranslateError};
use serde_json::{json, Value};

/// 入站白名单（与 M42-S2a spec §4.2 白名单表同源；改表必须同步改 spec；模型名只认路径）。
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
            let mut results = Vec::new();
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
                    // (1) Gemini 的工具**结果**（多轮工具调用里的一环）
                    if let Some(fr) = p.get("functionResponse") {
                        let name = fr.get("name").and_then(|x| x.as_str()).unwrap_or("call");
                        let text = fr.get("response").map(flatten_text).unwrap_or_default();
                        results.push(ToolResult {
                            tool_call_id: name.to_string(),
                            content: text,
                        });
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
            // 工具结果先入（它属于上一轮的 assistant tool_call）
            for r in results {
                messages.push(ChatMessage::Tool(r));
            }
            if role == "model" {
                let text = parts.iter().find_map(|p| match p {
                    ContentPart::Text(t) => Some(t.clone()),
                    _ => None,
                });
                // 全空的 model 轮次不 push（否则会塞一条空 assistant）
                if text.is_some() || !calls.is_empty() {
                    messages.push(ChatMessage::Assistant(AssistantTurn {
                        text,
                        tool_calls: calls,
                    }));
                }
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
        stream: false,
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

/// 把 Gemini `functionResponse.response`（对象/数组/字符串）展开成**纯文本**。
///
/// 不整段 `JSON.stringify` 加引号：那会把值变成 `"{\"a\":1}"` 这种带转义的串，
/// 上游模型读起来是噪音。数组按行拼、对象按键值拼、标量原样。
fn flatten_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        Value::Array(items) => items
            .iter()
            .map(flatten_text)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        Value::Object(map) => map
            .iter()
            .map(|(k, val)| format!("{k}: {}", flatten_text(val)))
            .collect::<Vec<_>>()
            .join("\n"),
    }
}
