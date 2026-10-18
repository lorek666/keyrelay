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
                // M21-S3 / B-165：重试判据 = `is_retryable()` **且**（本请求可安全重发
                // **或** 这次失败可证明未送达 **或** 服务端明确说「没处理」）。
                //
                // 改动前这里是 `err.is_retryable()`，而它覆盖**全部** `Error::Transport`
                // ——读超时也在内。读超时意味着请求**可能已送达**，于是 `create_key`
                // 多重试一次就会在站点上多留一把产品不知道的令牌（NewAPI 的
                // `POST /api/token` 没有幂等键）。
                //
                // `is_retryable()` 必须留在最前面：它是「这类错误值不值得再试」的总门
                // （认证失败、额度不足、验证码、NotFound 一律原地返回，避免把风控撞成封号）。
                // 后面的括号只负责**再收窄一层**——「值得试」不等于「可以重复发」。
                // （第一版把 `retry_safe` 写在最前面，于是 `retry_safe = true` 时连
                // `AuthFailed` 都会被重试，`does_not_retry_auth_failure` 立刻红。）
                //
                // 三项豁免：
                // - `retry_safe`：GET/列举这类天然幂等，重复发没有副作用；
                // - `NotDelivered`：连接层失败，对端根本没看到这个请求，重放安全
                //   （判据与网关 B-138、probe M19-S2 同源）；
                // - `RateLimited`：服务端**明说**没处理，退避后重试是协议的一部分，
                //   与请求是否幂等无关。
                Err(err)
                    if can_retry
                        && err.is_retryable()
                        && (req.retry_safe
                            || err.is_not_delivered()
                            || matches!(err, Error::RateLimited { .. })) =>
                {
                    let delay = match err {
                        Error::RateLimited { retry_after_secs } => {
                            Duration::from_secs(retry_after_secs).min(self.policy.max_delay)
                        }
                        _ => self.policy.delay_for(attempt),
                    };
                    self.sleeper.sleep(delay).await;
                }
                // M21-S3 / B-165：非幂等写撞上「可能已送达」的失败 ⇒ 不重试，并把
                // 「服务端可能已经处理了」这件事说清楚（用户得知道自己该去站点上核对，
                // 而不是当成一次普通失败再点一次「重试」——那一下才真的会多出一把密钥）。
                Err(err) if !req.retry_safe && err.is_retryable() => {
                    return Err(err.note_maybe_delivered("提交非幂等请求"));
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

    // ============================================ M21-S3 / B-165

    fn unsafe_request() -> HttpRequest {
        HttpRequest::new(
            super::super::transport::Method::Post,
            "https://x.example.com/v1/keys",
        )
        .retry_unsafe()
    }

    /// 非幂等写 + 读超时 ⇒ **恰好 1 次**请求（读超时可能已送达）。
    ///
    /// 这是 B-165 的核心判据。改动前这里是 `err.is_retryable()`，而它覆盖全部
    /// `Transport`，于是建令牌会发 3 次——NewAPI 没有幂等键，站点上会多出两把
    /// 产品不知道的令牌。
    #[tokio::test]
    async fn an_unsafe_request_is_not_retried_on_an_ambiguous_failure() {
        let mock = MockTransport::new(vec![]);
        mock.push_error(Error::Transport("请求超时".into()));

        let sleeper = Arc::new(RecordingSleeper::default());
        let transport =
            RetryingTransport::with_sleeper(mock.clone(), RetryPolicy::default(), sleeper.clone());

        let err = transport.request(unsafe_request()).await.unwrap_err();
        assert_eq!(mock.request_count(), 1, "读超时不得重试非幂等写");
        assert!(sleeper.calls().is_empty(), "不重试就不该退避等待");
        let message = err.to_string();
        assert!(
            message.contains("无法确认服务端是否已处理"),
            "必须把「可能已处理」说清楚: {message}"
        );
    }

    /// 同一类非幂等写，但失败是**可证明未送达** ⇒ 仍然重试。
    ///
    /// 收窄不能收过头：连接层失败时对端根本没看到这个请求，重放是安全的，
    /// 砍掉它等于把站点侧瞬时连接故障从「重试 3 次」降级成「一次就放弃」。
    #[tokio::test]
    async fn an_unsafe_request_is_still_retried_when_not_delivered() {
        let mock = MockTransport::new(vec![]);
        // 默认 max_attempts = 3，所以要让三次都失败才看得出「重试真的发生了」。
        for _ in 0..3 {
            mock.push_error(Error::NotDelivered("连接被拒".into()));
        }

        let sleeper = Arc::new(RecordingSleeper::default());
        let transport =
            RetryingTransport::with_sleeper(mock.clone(), RetryPolicy::default(), sleeper.clone());

        let err = transport.request(unsafe_request()).await.unwrap_err();
        assert_eq!(
            mock.request_count(),
            3,
            "NotDelivered 可证明未送达，应重试到 max_attempts"
        );
        assert!(matches!(err, Error::NotDelivered(_)), "{err:?}");
    }

    /// 非幂等写 + 429 ⇒ 仍然重试。429 意味着服务端**未处理**，重试安全。
    #[tokio::test]
    async fn an_unsafe_request_is_still_retried_on_429() {
        let mock = MockTransport::new(vec![]);
        mock.push_error(Error::RateLimited {
            retry_after_secs: 1,
        });
        mock.push(HttpResponse::new(201, "created".as_bytes().to_vec()));

        let sleeper = Arc::new(RecordingSleeper::default());
        let transport =
            RetryingTransport::with_sleeper(mock.clone(), RetryPolicy::default(), sleeper.clone());

        let resp = transport.request(unsafe_request()).await.unwrap();
        assert_eq!(resp.status, 201);
        assert_eq!(mock.request_count(), 2, "429 与请求是否幂等无关");
    }

    /// 回归防线：`is_retryable()` 必须留在判据**最前面**。
    ///
    /// 第一版的写法是 `can_retry && (req.retry_safe || err.is_not_delivered())`——
    /// `retry_safe` 短路在前，于是默认 `true` 的 GET 请求连 `AuthFailed` 都会被重试，
    /// `does_not_retry_auth_failure` 当场红。认证失败重试正是 `retry.rs` 模块注释里
    /// 「避免把风控撞成封号」要防的那件事，所以这条用例钉住顺序。
    #[tokio::test]
    async fn retry_safe_does_not_bypass_the_retryable_gate() {
        for err in [
            Error::AuthFailed("密码错误".into()),
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
            assert_eq!(mock.request_count(), 1, "{err:?} 不得被重试");
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
