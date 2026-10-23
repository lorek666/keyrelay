//! 协议检测（M42-S2a §4.1）：**只按方法 + 路径**（+ Anthropic 的版本头），不猜 body 形状。
//!
//! 猜错会把一个合法的 Chat 请求按 Responses 解析，用户拿到一堆莫名其妙的 400。
//! 路径是唯一的强信号；认不出 ⇒ `None` ⇒ 调用方走今天的透传。

use axum::http::{HeaderMap, Method};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// `POST /v1/chat/completions`（**零翻译**，与今天逐字相同）
    OpenAiChat,
    /// `POST /v1/responses`
    OpenAiResponses,
    /// `POST /v1/messages`（需 `anthropic-version` 头）
    AnthropicMessages,
    /// `POST /v1beta/models/{model}:generateContent`
    GeminiGenerateContent,
}

pub fn detect(method: &Method, path: &str, headers: &HeaderMap) -> Option<Protocol> {
    if method != Method::POST {
        return None;
    }
    if path == "/v1/chat/completions" {
        return Some(Protocol::OpenAiChat);
    }
    if path == "/v1/responses" {
        return Some(Protocol::OpenAiResponses);
    }
    if path == "/v1/messages" {
        // Anthropic 的强信号是版本头；没有它就不认（宁可透传，也不误判）
        return headers
            .contains_key("anthropic-version")
            .then_some(Protocol::AnthropicMessages);
    }
    // /v1beta/models/<model>:generateContent
    if let Some(rest) = path.strip_prefix("/v1beta/models/") {
        // M42-S2b：`:streamGenerateContent`（`?alt=sse`）也是 Gemini 协议，
        // 由调用方按流式处理；这里只负责认出它。
        if rest.ends_with(":generateContent") || rest.ends_with(":streamGenerateContent") {
            return Some(Protocol::GeminiGenerateContent);
        }
    }
    None
}
