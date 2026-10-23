//! 流式：SSE 拆包 + 把 OpenAI Chat 的增量渲染回入站协议（M42-S2b）。
//!
//! **两个独立的难点，各自可测**：
//! 1. **拆包**（[`SseDecoder`]）——`data:` 事件可能被 TCP 切成任意碎片，必须按行缓冲；
//! 2. **渲染**（[`StreamTranslator`]）——Chat 的 `delta` 要翻译成各协议自己的事件形态，
//!    并且**结束标记恰好一次**。

use serde_json::{json, Value};

/// 一个 SSE 事件。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
}

/// 增量 SSE 拆包器：喂字节、吐事件。
///
/// **必须能处理事件跨 TCP 包**——这是流式翻译最容易写错的地方（假设"一次 read 一个事件"，
/// 在慢网络 + 大 chunk 下必然出错）。
#[derive(Debug, Default)]
pub struct SseDecoder {
    buf: Vec<u8>,
}

impl SseDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// 喂一块字节，返回**本次能完整解出**的事件。
    ///
    /// 切事件的依据是空行（`\n\n`，兼容 `\r\n\r\n`）——不是单行、不是字节数。
    pub fn push(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some((end, sep_len)) = find_event_boundary(&self.buf) {
            let raw = self.buf[..end].to_vec();
            self.buf.drain(..end + sep_len);
            if let Some(ev) = parse_event(&raw) {
                out.push(ev);
            }
        }
        out
    }

    /// 流结束：吐出残留的不完整事件（`truncated = true` 表示上游没发完就断了）。
    pub fn finish(self) -> (Vec<SseEvent>, bool) {
        if self.buf.iter().all(|b| b.is_ascii_whitespace()) {
            return (Vec::new(), false);
        }
        let ev = parse_event(&self.buf);
        (ev.into_iter().collect(), true)
    }
}

/// 找空行边界，返回 (事件内容结束位置, 分隔符长度)。
fn find_event_boundary(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < buf.len() {
        // `\r\n\r\n`（CRLF 形态）：分隔符从 `\r` 开始
        if buf[i] == b'\r'
            && i + 3 < buf.len()
            && buf[i + 1] == b'\n'
            && buf[i + 2] == b'\r'
            && buf[i + 3] == b'\n'
        {
            return Some((i, 4));
        }
        // `\n\n`（LF 形态）
        if buf[i] == b'\n' && i + 1 < buf.len() && buf[i + 1] == b'\n' {
            return Some((i, 2));
        }
        i += 1;
    }
    None
}

fn parse_event(raw: &[u8]) -> Option<SseEvent> {
    let text = String::from_utf8_lossy(raw);
    let mut event = None;
    let mut data_lines: Vec<&str> = Vec::new();
    for line in text.lines() {
        if line.starts_with(':') {
            continue; // 注释行
        }
        if let Some(v) = line.strip_prefix("event:") {
            event = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("data:") {
            // 规范：`data:` 后的**一个**空格是分隔符（有就剥、没有也行）
            data_lines.push(v.strip_prefix(' ').unwrap_or(v));
        }
    }
    if event.is_none() && data_lines.is_empty() {
        return None;
    }
    Some(SseEvent {
        event,
        data: data_lines.join("\n"),
    })
}

/// Chat SSE 的一个 delta 里我们关心的部分。
#[derive(Clone, Debug, PartialEq, Default)]
pub struct ChatDelta {
    pub text: Option<String>,
    /// (index, id, name, arguments 片段)
    pub tool_calls: Vec<(u32, String, String, String)>,
    pub finish_reason: Option<String>,
    pub usage: Option<(i64, i64, i64)>,
}

impl ChatDelta {
    /// 从 Chat 的 `data:` JSON 解析；`[DONE]` ⇒ `None`（由调用方处理结束）。
    pub fn from_json(data: &str) -> Option<Self> {
        let v: Value = serde_json::from_str(data).ok()?;
        let mut d = ChatDelta::default();
        if let Some(u) = v.get("usage").filter(|u| !u.is_null()) {
            d.usage = Some((
                u.get("prompt_tokens").and_then(|x| x.as_i64()).unwrap_or(0),
                u.get("completion_tokens")
                    .and_then(|x| x.as_i64())
                    .unwrap_or(0),
                u.get("total_tokens").and_then(|x| x.as_i64()).unwrap_or(0),
            ));
        }
        let choice = v
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|a| a.first());
        if let Some(c) = choice {
            let delta = c.get("delta");
            d.text = delta
                .and_then(|x| x.get("content"))
                .and_then(|x| x.as_str())
                .map(str::to_string);
            if let Some(calls) = delta
                .and_then(|x| x.get("tool_calls"))
                .and_then(|x| x.as_array())
            {
                for (i, tc) in calls.iter().enumerate() {
                    let idx = tc.get("index").and_then(|x| x.as_u64()).unwrap_or(i as u64) as u32;
                    let f = tc.get("function");
                    d.tool_calls.push((
                        idx,
                        tc.get("id")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string(),
                        f.and_then(|x| x.get("name"))
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string(),
                        f.and_then(|x| x.get("arguments"))
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string(),
                    ));
                }
            }
            d.finish_reason = c
                .get("finish_reason")
                .and_then(|x| x.as_str())
                .map(str::to_string);
        }
        Some(d)
    }
}

/// 把 Chat 增量渲染成**入站协议**的 SSE 帧。
///
/// 结束标记**恰好一次**：`finish()` 只会产出一次收尾帧，之后 `finish()` 再被调用返回空。
pub struct StreamTranslator {
    proto: super::Protocol,
    started: bool,
    finished: bool,
    /// Anthropic 需要 `content_block` 的 index 递进
    block_index: u32,
    /// 已经开过 text block（Anthropic）
    text_block_open: bool,
    /// 已开过的 tool 块：`index → 累积的 arguments 字符串`（P1-2 状态机）。
    /// start 只发一次；后续只发增量；Gemini 在 finish 时一次性发完整 functionCall。
    tool_blocks: std::collections::BTreeMap<u32, String>,
}

impl StreamTranslator {
    pub fn new(proto: super::Protocol) -> Self {
        Self {
            proto,
            started: false,
            finished: false,
            block_index: 0,
            text_block_open: false,
            tool_blocks: std::collections::BTreeMap::new(),
        }
    }

    /// 处理一个 Chat SSE 事件，产出若干帧（已含 `data:`/`event:` 行与空行）。
    pub fn on_event(&mut self, ev: &SseEvent) -> Vec<String> {
        if self.finished {
            return Vec::new();
        }
        if ev.data.trim() == "[DONE]" {
            return self.finish();
        }
        let Some(d) = ChatDelta::from_json(&ev.data) else {
            return Vec::new();
        };
        let mut frames = Vec::new();
        self.ensure_started(&mut frames);
        match self.proto {
            super::Protocol::OpenAiResponses => {
                if let Some(t) = &d.text {
                    frames.push(sse_data(&json!({
                        "type": "response.output_text.delta", "delta": t
                    })));
                }
                for (idx, id, name, args) in &d.tool_calls {
                    // P1-2：start 只发**一次**（同一个 index 的后续 delta 只发增量）
                    let fresh = !self.tool_blocks.contains_key(idx);
                    if fresh {
                        self.tool_blocks.insert(*idx, String::new());
                        frames.push(sse_data(&json!({
                            "type": "response.output_item.added",
                            "output_index": idx,
                            "item": { "type": "function_call", "call_id": id, "name": name },
                        })));
                    }
                    if !args.is_empty() {
                        self.tool_blocks.entry(*idx).or_default().push_str(args);
                        frames.push(sse_data(&json!({
                            "type": "response.function_call_arguments.delta",
                            "output_index": idx, "delta": args,
                        })));
                    }
                }
            }
            super::Protocol::AnthropicMessages => {
                if let Some(t) = &d.text {
                    if !self.text_block_open {
                        frames.push(sse_data(&json!({
                            "type": "content_block_start", "index": self.block_index,
                            "content_block": { "type": "text", "text": "" },
                        })));
                        self.text_block_open = true;
                    }
                    frames.push(sse_data(&json!({
                        "type": "content_block_delta", "index": self.block_index,
                        "delta": { "type": "text_delta", "text": t },
                    })));
                }
                for (idx, id, name, args) in &d.tool_calls {
                    let fresh = !self.tool_blocks.contains_key(idx);
                    if fresh {
                        self.tool_blocks.insert(*idx, String::new());
                        frames.push(sse_data(&json!({
                            "type": "content_block_start", "index": idx + 1,
                            "content_block": { "type": "tool_use", "id": id, "name": name, "input": {} },
                        })));
                    }
                    if !args.is_empty() {
                        self.tool_blocks.entry(*idx).or_default().push_str(args);
                        frames.push(sse_data(&json!({
                            "type": "content_block_delta", "index": idx + 1,
                            "delta": { "type": "input_json_delta", "partial_json": args },
                        })));
                    }
                }
            }
            super::Protocol::GeminiGenerateContent => {
                let mut parts: Vec<Value> = Vec::new();
                if let Some(t) = &d.text {
                    parts.push(json!({ "text": t }));
                }
                // P1-2：Gemini 的 arguments 是**累积**的，finish 时一次性发完整 functionCall
                for (idx, _, _, args) in &d.tool_calls {
                    self.tool_blocks.entry(*idx).or_default().push_str(args);
                }
                if !parts.is_empty() {
                    frames.push(sse_data(&json!({
                        "candidates": [{ "content": { "role": "model", "parts": parts }, "index": 0 }]
                    })));
                }
            }
            super::Protocol::OpenAiChat => {}
        }
        frames
    }

    /// 收尾：**恰好一次**。Gemini 没有 `[DONE]`，所以三种协议在这里都产出明确收尾。
    pub fn finish(&mut self) -> Vec<String> {
        if self.finished {
            return Vec::new();
        }
        self.finished = true;
        let mut frames = Vec::new();
        self.ensure_started(&mut frames);
        match self.proto {
            super::Protocol::OpenAiResponses => {
                frames.push(sse_data(&json!({ "type": "response.completed" })));
            }
            super::Protocol::AnthropicMessages => {
                if self.text_block_open {
                    frames.push(sse_data(&json!({
                        "type": "content_block_stop", "index": self.block_index
                    })));
                }
                // P1-2：每个已开的 tool 块都要收尾（否则客户端挂住）
                for idx in self.tool_blocks.keys() {
                    frames.push(sse_data(&json!({
                        "type": "content_block_stop", "index": idx + 1
                    })));
                }
                frames.push(sse_data(&json!({ "type": "message_stop" })));
            }
            super::Protocol::GeminiGenerateContent => {
                // P1-2：累积的 arguments 在这里一次性发完整 functionCall
                let parts: Vec<Value> = self
                    .tool_blocks
                    .values()
                    .map(|args| {
                        let parsed: Value = serde_json::from_str(args).unwrap_or(json!({}));
                        json!({ "functionCall": { "args": parsed } })
                    })
                    .collect();
                if !parts.is_empty() {
                    frames.push(sse_data(&json!({
                        "candidates": [{ "content": { "role": "model", "parts": parts }, "index": 0 }]
                    })));
                }
                // Gemini **没有 [DONE]**：靠流关闭本身表示结束，不额外发结束帧
            }
            super::Protocol::OpenAiChat => frames.push(sse_data_raw("[DONE]")),
        }
        frames
    }

    fn ensure_started(&mut self, frames: &mut Vec<String>) {
        if self.started {
            return;
        }
        self.started = true;
        match self.proto {
            super::Protocol::AnthropicMessages => {
                frames.push(sse_event(
                    "message_start",
                    &json!({ "type": "message_start", "message": { "role": "assistant", "content": [] } }),
                ));
            }
            super::Protocol::OpenAiResponses => {
                frames.push(sse_event(
                    "response.created",
                    &json!({ "type": "response.created" }),
                ));
            }
            _ => {}
        }
    }
}

fn sse_data(v: &Value) -> String {
    sse_data_raw(&v.to_string())
}

fn sse_data_raw(data: &str) -> String {
    format!("data: {data}\n\n")
}

fn sse_event(name: &str, v: &Value) -> String {
    format!("event: {name}\ndata: {}\n\n", v)
}
