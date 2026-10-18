//! HTTP 传输层抽象。
//!
//! 适配器只依赖 [`HttpTransport`]，因此契约测试可以用 [`MockTransport`] 精确断言请求内容，
//! 生产实现（`reqwest`，含代理支持）在 M1-S1 接入。

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

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
    /// 重复发送同一请求是否**安全**（M21-S3 / B-165）。
    ///
    /// `true`（默认）= GET/列举/登录探测这类天然幂等的请求，重复发没有副作用。
    /// `false` = 「重复发一次就多一个对象」的写：建令牌、回收令牌，以及登录三连
    /// （登录不产孤儿，但重发会短时间内翻倍登录尝试，正是风控计数喜欢的形状）。
    ///
    /// `false` 只影响 `RetryingTransport` 对**可能已送达**失败的处理：`Error::NotDelivered`
    /// （连接层失败，对端根本没看到这个请求）仍然重试；读超时、连接建立后中断
    /// **一次都不重试**。判据与网关 B-138、probe M19-S2 同源。
    ///
    /// **默认 `true` 是有意选的**：漏标一个新写点 ⇒ 保持旧行为（多重试一次），
    /// 不会把「本来安全的」误判成「不能重试」而白白损失可用性。
    pub retry_safe: bool,
}

impl HttpRequest {
    pub fn new(method: Method, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            headers: Vec::new(),
            body: None,
            retry_safe: true,
        }
    }

    /// 标记「重复发送不安全」（非幂等写 / 风控敏感）。
    pub fn retry_unsafe(mut self) -> Self {
        self.retry_safe = false;
        self
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

    /// 构造 JSON 响应。
    ///
    /// 序列化失败（例如 `Value` 里含 NaN/Infinity）返回错误，**不再静默降级为空 body**
    /// （BACKLOG B-13）。
    pub fn json(status: u16, value: Value) -> Result<Self> {
        let body = serde_json::to_vec(&value)
            .map_err(|e| Error::Transport(format!("响应体序列化失败: {e}")))?;
        Ok(Self {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body,
        })
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

/// 测试用传输层：按队列顺序返回预置响应或预置错误，并记录收到的请求。
///
/// 内部用 `Arc` 包裹，`clone()` 后共享同一队列与记录（契约测试里 `mock.clone()` 交给
/// 被测适配器、原句柄用来断言请求，是常见用法）。
#[derive(Default, Clone)]
pub struct MockTransport {
    queue: Arc<Mutex<VecDeque<Result<HttpResponse>>>>,
    seen: Arc<Mutex<Vec<HttpRequest>>>,
}

impl MockTransport {
    pub fn new(responses: Vec<HttpResponse>) -> Self {
        Self {
            queue: Arc::new(Mutex::new(responses.into_iter().map(Ok).collect())),
            seen: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn push(&self, response: HttpResponse) {
        if let Ok(mut q) = self.queue.lock() {
            q.push_back(Ok(response));
        }
    }

    /// 注入一个传输层错误（用于测试重试与错误路径）
    pub fn push_error(&self, error: Error) {
        if let Ok(mut q) = self.queue.lock() {
            q.push_back(Err(error));
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
            .unwrap_or_else(|| Err(Error::Transport("mock 响应队列已空".into())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(n: usize) -> HttpRequest {
        HttpRequest::new(Method::Get, format!("https://x.example.com/{n}"))
    }

    #[tokio::test]
    async fn queue_preserves_order_of_responses_and_errors() {
        let mock = MockTransport::new(vec![]);
        mock.push_error(Error::Transport("E1".into()));
        mock.push(HttpResponse::new(200, "R2".as_bytes().to_vec()));
        mock.push_error(Error::QuotaExhausted);

        assert_eq!(
            mock.request(req(0)).await.unwrap_err(),
            Error::Transport("E1".into())
        );
        assert_eq!(mock.request(req(1)).await.unwrap().status, 200);
        assert_eq!(
            mock.request(req(2)).await.unwrap_err(),
            Error::QuotaExhausted
        );
    }

    #[tokio::test]
    async fn clone_shares_queue_and_request_log() {
        let mock = MockTransport::new(vec![]);
        let clone = mock.clone();
        clone.push(HttpResponse::new(204, Vec::new()));

        // 通过原句柄消费克隆句柄压入的响应
        assert_eq!(mock.request(req(0)).await.unwrap().status, 204);
        // 记录跨句柄可见
        assert_eq!(clone.request_count(), 1);
        assert_eq!(clone.nth_request(0).unwrap().url, "https://x.example.com/0");
    }

    #[tokio::test]
    async fn empty_queue_reports_transport_error() {
        let mock = MockTransport::new(vec![]);
        assert!(matches!(
            mock.request(req(0)).await.unwrap_err(),
            Error::Transport(_)
        ));
    }

    #[test]
    fn json_constructor_is_infallible_for_valid_values() {
        // 事实核对：`Value` 总能序列化（NaN 在 `Value::from` 阶段就退化为 Null），
        // 所以返回 `Result` 属**防御性**设计——把「序列化失败」显式化，而不是静默产出空 body。
        let response = HttpResponse::json(200, Value::from(f64::NAN)).expect("构造成功");
        assert_eq!(response.text_lossy(), "null");
    }
}
