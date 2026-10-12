//! HTTP 传输层抽象。
//!
//! 适配器只依赖 [`HttpTransport`]，因此契约测试可以用 [`MockTransport`] 精确断言请求内容，
//! 生产实现（`reqwest`，含代理支持）在 M1-S1 接入。

use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use serde_json::Value;

use crate::error::{Error, Result};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

impl HttpRequest {
    pub fn new(method: Method, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn json_body(mut self, value: &Value) -> Result<Self> {
        let bytes = serde_json::to_vec(value)
            .map_err(|e| Error::Transport(format!("请求体序列化失败: {e}")))?;
        self.body = Some(bytes);
        self.headers
            .push(("Content-Type".to_string(), "application/json".to_string()));
        Ok(self)
    }

    /// 便于断言与脱敏日志：只描述方法与 URL，不回显请求体。
    pub fn summary(&self) -> String {
        format!("{} {}", self.method.as_str(), self.url)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    pub fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: serde_json::to_vec(&value).unwrap_or_default(),
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn json_value(&self) -> Result<Value> {
        serde_json::from_slice(&self.body)
            .map_err(|e| Error::Transport(format!("响应不是合法 JSON: {e}")))
    }

    pub fn text_lossy(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    /// 解析 `Retry-After`（秒）
    pub fn retry_after_secs(&self) -> Option<u64> {
        self.header("Retry-After")
            .and_then(|v| v.trim().parse().ok())
    }

    /// 解析所有 `Set-Cookie`，返回 `(name, value)` 列表
    pub fn set_cookies(&self) -> Vec<(String, String)> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Set-Cookie"))
            .filter_map(|(_, v)| {
                let first = v.split(';').next()?.trim();
                let (name, value) = first.split_once('=')?;
                Some((name.trim().to_string(), value.trim().to_string()))
            })
            .collect()
    }
}

#[async_trait]
pub trait HttpTransport: Send + Sync {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse>;
}

/// 测试用传输层：按队列顺序返回预置响应，并记录收到的请求。
#[derive(Default)]
pub struct MockTransport {
    queue: Mutex<VecDeque<HttpResponse>>,
    seen: Mutex<Vec<HttpRequest>>,
}

impl MockTransport {
    pub fn new(responses: Vec<HttpResponse>) -> Self {
        Self {
            queue: Mutex::new(responses.into()),
            seen: Mutex::new(Vec::new()),
        }
    }

    pub fn push(&self, response: HttpResponse) {
        if let Ok(mut q) = self.queue.lock() {
            q.push_back(response);
        }
    }

    pub fn requests(&self) -> Vec<HttpRequest> {
        self.seen.lock().map(|s| s.clone()).unwrap_or_default()
    }

    pub fn request_count(&self) -> usize {
        self.seen.lock().map(|s| s.len()).unwrap_or(0)
    }

    pub fn nth_request(&self, n: usize) -> Option<HttpRequest> {
        self.seen.lock().ok().and_then(|s| s.get(n).cloned())
    }
}

#[async_trait]
impl HttpTransport for MockTransport {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse> {
        self.seen
            .lock()
            .map_err(|_| Error::Transport("mock 请求记录锁已中毒".into()))?
            .push(req);
        self.queue
            .lock()
            .map_err(|_| Error::Transport("mock 响应队列锁已中毒".into()))?
            .pop_front()
            .ok_or_else(|| Error::Transport("mock 响应队列已空".into()))
    }
}
