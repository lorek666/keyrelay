//! 内部表示（IR）= **OpenAI Chat 形状**（ADR-0005 D2）。
//!
//! 上游固定 Chat，所以不引入「第四种中立 IR」：各协议解析成它、它也直接序列化成上游 body。

use serde_json::{json, Value};

#[derive(Clone, Debug, PartialEq)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub system: Option<String>,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub max_tokens: Option<u32>,
    pub stop: Vec<String>,
    pub tools: Vec<ToolSpec>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ChatMessage {
    User(Vec<ContentPart>),
    Assistant(AssistantTurn),
    Tool(ToolResult),
}

#[derive(Clone, Debug, PartialEq)]
pub enum ContentPart {
    Text(String),
    ImageUrl(String),
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct AssistantTurn {
    pub text: Option<String>,
    /// M42-S2a：**允许 N 个**（Lead 裁决 2）。
    pub tool_calls: Vec<ToolCall>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ToolResult {
    pub tool_call_id: String,
    pub content: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ToolSpec {
    pub name: String,
    pub description: Option<String>,
    pub parameters: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChatResponse {
    pub id: String,
    pub model: String,
    pub choices: Vec<Choice>,
    pub usage: Option<Usage>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Choice {
    pub index: u32,
    pub message: AssistantTurn,
    pub finish_reason: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Usage {
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
}

impl ChatRequest {
    /// 序列化成**上游 OpenAI Chat** 的请求体。
    pub fn to_upstream_json(&self) -> Value {
        let mut messages: Vec<Value> = Vec::new();
        if let Some(system) = &self.system {
            messages.push(json!({ "role": "system", "content": system }));
        }
        for m in &self.messages {
            match m {
                ChatMessage::User(parts) => {
                    // 纯文本时用字符串形态（最常见的形态，别把简单请求复杂化）
                    if parts.len() == 1 {
                        if let ContentPart::Text(t) = &parts[0] {
                            messages.push(json!({ "role": "user", "content": t }));
                            continue;
                        }
                    }
                    let content: Vec<Value> = parts
                        .iter()
                        .map(|p| match p {
                            ContentPart::Text(t) => json!({ "type": "text", "text": t }),
                            ContentPart::ImageUrl(u) => {
                                json!({ "type": "image_url", "image_url": { "url": u } })
                            }
                        })
                        .collect();
                    messages.push(json!({ "role": "user", "content": content }));
                }
                ChatMessage::Assistant(turn) => {
                    let mut obj = json!({ "role": "assistant" });
                    if let Some(t) = &turn.text {
                        obj["content"] = json!(t);
                    }
                    if !turn.tool_calls.is_empty() {
                        let calls: Vec<Value> = turn
                            .tool_calls
                            .iter()
                            .map(|c| {
                                json!({
                                    "id": c.id,
                                    "type": "function",
                                    "function": {
                                        "name": c.name,
                                        "arguments": c.arguments.to_string(),
                                    }
                                })
                            })
                            .collect();
                        obj["tool_calls"] = Value::Array(calls);
                    }
                    messages.push(obj);
                }
                ChatMessage::Tool(r) => messages.push(json!({
                    "role": "tool",
                    "tool_call_id": r.tool_call_id,
                    "content": r.content,
                })),
            }
        }

        let mut body = json!({ "model": self.model, "messages": messages });
        if let Some(t) = self.temperature {
            body["temperature"] = json!(t);
        }
        if let Some(p) = self.top_p {
            body["top_p"] = json!(p);
        }
        if let Some(m) = self.max_tokens {
            body["max_tokens"] = json!(m);
        }
        if !self.stop.is_empty() {
            body["stop"] = json!(self.stop);
        }
        if !self.tools.is_empty() {
            body["tools"] = Value::Array(
                self.tools
                    .iter()
                    .map(|t| {
                        json!({
                            "type": "function",
                            "function": {
                                "name": t.name,
                                "description": t.description,
                                "parameters": t.parameters,
                            }
                        })
                    })
                    .collect(),
            );
        }
        body
    }
}

impl ChatResponse {
    /// 解析上游 OpenAI Chat 的响应体。
    pub fn from_upstream_json(v: &Value) -> Result<Self, String> {
        let id = v
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or("chatcmpl")
            .to_string();
        let model = v
            .get("model")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let choices = v
            .get("choices")
            .and_then(|x| x.as_array())
            .ok_or_else(|| "上游响应缺少 choices".to_string())?
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let msg = c.get("message").cloned().unwrap_or(Value::Null);
                let text = msg
                    .get("content")
                    .and_then(|x| x.as_str())
                    .map(str::to_string);
                let tool_calls = msg
                    .get("tool_calls")
                    .and_then(|x| x.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|tc| {
                                let id = tc.get("id")?.as_str()?.to_string();
                                let f = tc.get("function")?;
                                let name = f.get("name")?.as_str()?.to_string();
                                let args = f
                                    .get("arguments")
                                    .and_then(|a| a.as_str())
                                    .and_then(|s| serde_json::from_str(s).ok())
                                    .unwrap_or(Value::Null);
                                Some(ToolCall {
                                    id,
                                    name,
                                    arguments: args,
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Choice {
                    index: i as u32,
                    message: AssistantTurn { text, tool_calls },
                    finish_reason: c
                        .get("finish_reason")
                        .and_then(|x| x.as_str())
                        .map(str::to_string),
                }
            })
            .collect();
        let usage = v.get("usage").and_then(|u| {
            Some(Usage {
                prompt_tokens: u.get("prompt_tokens")?.as_i64()?,
                completion_tokens: u.get("completion_tokens")?.as_i64()?,
                total_tokens: u.get("total_tokens")?.as_i64()?,
            })
        });
        Ok(Self {
            id,
            model,
            choices,
            usage,
        })
    }
}
