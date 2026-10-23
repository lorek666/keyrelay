//! 协议翻译层（M42-S2a / ADR-0005）。
//!
//! 上游固定 **OpenAI Chat**（ADR D2/D7）；本模块把三种入站协议**非流式**地翻译成 Chat，
//! 再把响应渲染回去。Chat 自身零翻译直通——它根本不进本模块。
//!
//! **计费红线（ADR D5）**：翻译发生在 `send_once` 之前/之后，**不参与候选循环**；
//! 解析失败（400）发生在发请求之前 ⇒ 不可能产生上游计费。

pub mod anthropic;
pub mod detect;
pub mod gemini;
pub mod ir;
pub mod responses;

pub use detect::{detect, Protocol};
pub use ir::*;

/// 翻译层错误 → 由调用方映射成 `local_error`（400）。
#[derive(Clone, Debug, PartialEq)]
pub struct TranslateError {
    pub code: &'static str,
    pub message: String,
}

impl TranslateError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// 拒绝不支持的字段：**点名**第一个，不静默丢（ADR D3/D6）。
pub(crate) fn reject_unknown(
    value: &serde_json::Value,
    allowed: &[&str],
    proto: &str,
) -> Result<(), TranslateError> {
    if let Some(obj) = value.as_object() {
        for key in obj.keys() {
            if !allowed.contains(&key.as_str()) {
                return Err(TranslateError::new(
                    "unsupported_field",
                    format!("{proto}: 不支持字段 `{key}`"),
                ));
            }
        }
    }
    Ok(())
}

/// 解析入站请求 → IR。`stream: true` 一律 400 并点名 M42-S2b。
pub fn parse_request(protocol: Protocol, body: &[u8]) -> Result<ChatRequest, TranslateError> {
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| TranslateError::new("invalid_json", format!("请求体不是 JSON: {e}")))?;
    if v.get("stream").and_then(|x| x.as_bool()) == Some(true) {
        return Err(TranslateError::new(
            "streaming_not_supported",
            "流式尚未支持（M42-S2b）；请先以 stream:false 调用",
        ));
    }
    match protocol {
        Protocol::OpenAiResponses => responses::parse_request(&v),
        Protocol::AnthropicMessages => anthropic::parse_request(&v),
        Protocol::GeminiGenerateContent => gemini::parse_request(&v),
        // Chat 不进本模块；真进来了就按「无需翻译」处理
        Protocol::OpenAiChat => Err(TranslateError::new("internal", "Chat 请求不应进入翻译层")),
    }
}

/// IR → 入站协议的响应 JSON。
pub fn render_response(protocol: Protocol, resp: &ChatResponse) -> serde_json::Value {
    match protocol {
        Protocol::OpenAiResponses => responses::render_response(resp),
        Protocol::AnthropicMessages => anthropic::render_response(resp),
        Protocol::GeminiGenerateContent => gemini::render_response(resp),
        Protocol::OpenAiChat => serde_json::Value::Null,
    }
}
