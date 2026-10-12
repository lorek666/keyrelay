//! 重试装饰器：指数退避 + 尊重 `Retry-After`。
//!
//! 只重试 [`Error::is_retryable`] 为真的错误（传输失败、限流）；
//! 认证失败、额度不足、需要验证码、资源不存在一律**立即返回**，避免把风控撞成封号。

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use super::transport::{HttpRequest, HttpResponse, HttpTransport};
use crate::error::{Error, Result};

/// 退避等待抽象。测试注入 [`RecordingSleeper`]，生产用 [`TokioSleeper`]。
#[async_trait]
pub trait Sleeper: Send + Sync {
    async fn sleep(&self, duration: Duration);
}

/// 生产实现：交给 tokio 计时器，不阻塞执行线程。
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioSleeper;

#[async_trait]
impl Sleeper for TokioSleeper {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

/// 测试实现：记录每次等待时长，不真的睡。
#[derive(Debug, Default)]
pub struct RecordingSleeper {
    calls: std::sync::Mutex<Vec<Duration>>,
}

impl RecordingSleeper {
    pub fn calls(&self) -> Vec<Duration> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }

    pub fn total(&self) -> Duration {
        self.calls().iter().copied().sum()
    }
}

#[async_trait]
impl Sleeper for RecordingSleeper {
    async fn sleep(&self, duration: Duration) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(duration);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    /// 含首次在内的总尝试次数
    pub max_attempts: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(300),
            max_delay: Duration::from_secs(5),
        }
    }
}

impl RetryPolicy {
    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts.max(1);
        self
    }

    /// 第 `attempt` 次失败后的退避时长：`base * 2^(attempt-1)`，封顶 `max_delay`
    pub fn delay_for(&self, attempt: u32) -> Duration {
        let factor = 2u32.saturating_pow(attempt.saturating_sub(1));
        self.base_delay.saturating_mul(factor).min(self.max_delay)
    }
}

#[derive(Clone)]
pub struct RetryingTransport<T: HttpTransport> {
    inner: T,
    policy: RetryPolicy,
    sleeper: Arc<dyn Sleeper>,
}

impl<T: HttpTransport> RetryingTransport<T> {
    pub fn new(inner: T, policy: RetryPolicy) -> Self {
        Self {
            inner,
            policy,
            sleeper: Arc::new(TokioSleeper),
        }
    }

    pub fn with_sleeper(inner: T, policy: RetryPolicy, sleeper: Arc<dyn Sleeper>) -> Self {
        Self {
            inner,
            policy,
            sleeper,
        }
    }

    pub fn policy(&self) -> RetryPolicy {
        self.policy
    }
}

/// 传输层可重试的状态码。
///
/// 只放 429：限流意味着**服务端未处理**该请求，重试安全。
/// 5xx **不重试**——`create_key` 这类 POST 非幂等，服务端可能已处理却返回 5xx，
/// 重试会凭空多出一把令牌。
pub fn is_retryable_status(status: u16) -> bool {
    status == 429
}

#[async_trait]
impl<T: HttpTransport> HttpTransport for RetryingTransport<T> {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse> {
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            let can_retry = attempt < self.policy.max_attempts;

            match self.inner.request(req.clone()).await {
                // 传输层把 429 当正常响应返回（状态码→错误的映射在适配器层，位于本装饰器**之上**），
                // 所以这里必须自己识别状态码，否则「429 等待后重试」在真实装配下永不发生。
                Ok(response) if can_retry && is_retryable_status(response.status) => {
                    let delay = response
                        .retry_after_secs()
                        .map(|secs| Duration::from_secs(secs).min(self.policy.max_delay))
                        .unwrap_or_else(|| self.policy.delay_for(attempt));
                    self.sleeper.sleep(delay).await;
                }
                Ok(response) => return Ok(response),
                Err(err) if can_retry && err.is_retryable() => {
                    let delay = match err {
                        Error::RateLimited { retry_after_secs } => {
                            Duration::from_secs(retry_after_secs).min(self.policy.max_delay)
                        }
                        _ => self.policy.delay_for(attempt),
                    };
                    self.sleeper.sleep(delay).await;
                }
                Err(err) => return Err(err),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::transport::MockTransport;

    fn request() -> HttpRequest {
        HttpRequest::new(
            super::super::transport::Method::Get,
            "https://x.example.com",
        )
    }

    #[tokio::test]
    async fn retries_transport_error_then_succeeds() {
        let mock = MockTransport::new(vec![]);
        mock.push_error(Error::Transport("连接被重置".into()));
        mock.push(HttpResponse::new(200, "ok".as_bytes().to_vec()));

        let sleeper = Arc::new(RecordingSleeper::default());
        let transport =
            RetryingTransport::with_sleeper(mock.clone(), RetryPolicy::default(), sleeper.clone());

        let resp = transport.request(request()).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(mock.request_count(), 2);
        assert_eq!(sleeper.calls(), vec![Duration::from_millis(300)]);
    }

    #[tokio::test]
    async fn honors_retry_after_on_429() {
        let mock = MockTransport::new(vec![]);
        mock.push_error(Error::RateLimited {
            retry_after_secs: 2,
        });
        mock.push(HttpResponse::new(200, "ok".as_bytes().to_vec()));

        let sleeper = Arc::new(RecordingSleeper::default());
        let transport =
            RetryingTransport::with_sleeper(mock.clone(), RetryPolicy::default(), sleeper.clone());

        transport.request(request()).await.unwrap();
        assert_eq!(sleeper.calls(), vec![Duration::from_secs(2)]);
    }

    #[tokio::test]
    async fn retry_after_is_capped_by_max_delay() {
        let mock = MockTransport::new(vec![]);
        mock.push_error(Error::RateLimited {
            retry_after_secs: 600,
        });
        mock.push(HttpResponse::new(200, "ok".as_bytes().to_vec()));

        let sleeper = Arc::new(RecordingSleeper::default());
        let transport =
            RetryingTransport::with_sleeper(mock.clone(), RetryPolicy::default(), sleeper.clone());

        transport.request(request()).await.unwrap();
        assert_eq!(sleeper.calls(), vec![Duration::from_secs(5)]);
    }

    #[tokio::test]
    async fn does_not_retry_auth_failure() {
        let mock = MockTransport::new(vec![]);
        mock.push_error(Error::AuthFailed("密码错误".into()));

        let sleeper = Arc::new(RecordingSleeper::default());
        let transport =
            RetryingTransport::with_sleeper(mock.clone(), RetryPolicy::default(), sleeper.clone());

        let err = transport.request(request()).await.unwrap_err();
        assert_eq!(err, Error::AuthFailed("密码错误".into()));
        assert_eq!(mock.request_count(), 1, "认证失败不得重试");
        assert!(sleeper.calls().is_empty());
    }

    #[tokio::test]
    async fn does_not_retry_quota_or_captcha() {
        for err in [
            Error::QuotaExhausted,
            Error::CaptchaRequired,
            Error::NotFound("key".into()),
        ] {
            let mock = MockTransport::new(vec![]);
            mock.push_error(err.clone());
            let transport = RetryingTransport::with_sleeper(
                mock.clone(),
                RetryPolicy::default(),
                Arc::new(RecordingSleeper::default()),
            );
            assert_eq!(transport.request(request()).await.unwrap_err(), err);
            assert_eq!(mock.request_count(), 1);
        }
    }

    #[tokio::test]
    async fn gives_up_after_max_attempts() {
        let mock = MockTransport::new(vec![]);
        for _ in 0..5 {
            mock.push_error(Error::Transport("超时".into()));
        }

        let sleeper = Arc::new(RecordingSleeper::default());
        let transport =
            RetryingTransport::with_sleeper(mock.clone(), RetryPolicy::default(), sleeper.clone());

        let err = transport.request(request()).await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)));
        assert_eq!(mock.request_count(), 3, "默认 3 次尝试");
        assert_eq!(
            sleeper.calls(),
            vec![Duration::from_millis(300), Duration::from_millis(600)],
            "退避应为 base、2×base"
        );
    }

    #[test]
    fn delay_sequence_is_exponential_and_capped() {
        let policy = RetryPolicy {
            max_attempts: 6,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(700),
        };
        let seq: Vec<u128> = (1..=5).map(|a| policy.delay_for(a).as_millis()).collect();
        assert_eq!(seq, vec![100, 200, 400, 700, 700]);
    }

    #[tokio::test]
    async fn retries_429_response_not_only_rate_limited_error() {
        // 真实传输层把 429 作为 Ok 响应返回（状态码→错误的映射在适配器层），
        // 重试层必须自己识别状态码——复审 P1-1 的回归测试。
        let mock = MockTransport::new(vec![
            HttpResponse::new(429, "{}".as_bytes().to_vec()).with_header("Retry-After", "2"),
            HttpResponse::new(200, "ok".as_bytes().to_vec()),
        ]);

        let sleeper = Arc::new(RecordingSleeper::default());
        let transport =
            RetryingTransport::with_sleeper(mock.clone(), RetryPolicy::default(), sleeper.clone());

        let response = transport.request(request()).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(mock.request_count(), 2, "429 必须触发重试");
        assert_eq!(sleeper.calls(), vec![Duration::from_secs(2)]);
    }

    #[tokio::test]
    async fn exhausted_429_is_returned_as_response_not_error() {
        // 尝试次数用尽后保持「传输层返回响应」的契约，由适配器层映射为 RateLimited
        let mock = MockTransport::new(vec![]);
        for _ in 0..5 {
            mock.push(
                HttpResponse::new(429, "{}".as_bytes().to_vec()).with_header("Retry-After", "1"),
            );
        }

        let sleeper = Arc::new(RecordingSleeper::default());
        let transport =
            RetryingTransport::with_sleeper(mock.clone(), RetryPolicy::default(), sleeper.clone());

        let response = transport.request(request()).await.unwrap();
        assert_eq!(response.status, 429);
        assert_eq!(response.retry_after_secs(), Some(1));
        assert_eq!(mock.request_count(), 3);
        assert_eq!(sleeper.calls().len(), 2);
    }

    #[tokio::test]
    async fn does_not_retry_5xx_because_posts_are_not_idempotent() {
        let mock = MockTransport::new(vec![
            HttpResponse::new(500, "boom".as_bytes().to_vec()),
            HttpResponse::new(200, "ok".as_bytes().to_vec()),
        ]);

        let sleeper = Arc::new(RecordingSleeper::default());
        let transport =
            RetryingTransport::with_sleeper(mock.clone(), RetryPolicy::default(), sleeper.clone());

        let response = transport.request(request()).await.unwrap();
        assert_eq!(response.status, 500);
        assert_eq!(mock.request_count(), 1, "5xx 不得重试（非幂等 POST 风险）");
        assert!(sleeper.calls().is_empty());
    }

    #[tokio::test]
    async fn non_retryable_status_passes_through_immediately() {
        for status in [200u16, 302, 401, 403, 404] {
            let mock = MockTransport::new(vec![
                HttpResponse::new(status, "x".as_bytes().to_vec()),
                HttpResponse::new(200, "should-not-be-used".as_bytes().to_vec()),
            ]);
            let transport = RetryingTransport::with_sleeper(
                mock.clone(),
                RetryPolicy::default(),
                Arc::new(RecordingSleeper::default()),
            );
            assert_eq!(transport.request(request()).await.unwrap().status, status);
            assert_eq!(mock.request_count(), 1, "{status} 不应重试");
        }
    }
}
