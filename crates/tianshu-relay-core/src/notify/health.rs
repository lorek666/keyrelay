//! 密钥健康巡检的纯决策（M46-S1）。
//!
//! 两件事，都不读时钟、不读环境、不碰网络、不碰存储：
//!
//! 1. [`classify_probe_result`]：一次 `GET /v1/models` 探活（既有
//!    [`crate::site::fetch_models`]）的结果 → 结论。按 `Error` 变体分类，
//!    不解析错误文案——唯独 `Transport` 变体要区分 5xx 与其它（见函数文档的锚点）。
//! 2. [`apply_probe_outcome`]：结论 → 既有 [`crate::routing::Breaker`]。
//!    本模块**不**持有任何熔断状态：计数、阈值、冷却全是 `Breaker` 既有的，
//!    这里只是「巡检结论怎么翻译成 `record_failure` / `record_success`」。
//!
//! # 为什么结论分五档，而不是「活 / 死」两档
//!
//! - `QuotaExhausted` 与 `DeadKey` 现阶段同样不可用、同样喂熔断，
//!   但事件里必须区分：前者靠充值恢复，后者要换 key；混成一档会误导处置。
//! - `Unknown` 是「无法判定」的安全档：其它 4xx / 响应形态异常时，
//!   喂熔断等于用一次猜测摘除一把可能活着的 key，所以只记事件、不碰熔断。
//! - `UpstreamFault`（429 / 5xx / 连接失败 / 超时）是站点侧故障：
//!   单轮只记一次失败，连续 3 轮（既有阈值）才 Open，单轮抖动不摘除。

use crate::error::{Error, Result};
use crate::routing::{model_key, site_key, Breaker, BreakerKey};

/// 一次探活的结论。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyHealthVerdict {
    /// 2xx 且 `data` 数组可解析（含空数组：认证通过即活）。
    Healthy,
    /// 401 / 403（非额度码）：key 已死。
    DeadKey,
    /// 401 / 403 + 额度码：key 活着但额度已空。
    QuotaExhausted,
    /// 429 / 5xx / 连接层失败 / 探活超时：站点侧故障。
    UpstreamFault,
    /// 其余 4xx / 响应形态异常：无法判定，不喂熔断。
    Unknown,
}

impl KeyHealthVerdict {
    /// 事件 payload 里的取值（snake_case，与 `NotifyKind::as_str` 同口径）。
    pub fn as_str(self) -> &'static str {
        match self {
            KeyHealthVerdict::Healthy => "healthy",
            KeyHealthVerdict::DeadKey => "dead_key",
            KeyHealthVerdict::QuotaExhausted => "quota_exhausted",
            KeyHealthVerdict::UpstreamFault => "upstream_fault",
            KeyHealthVerdict::Unknown => "unknown",
        }
    }

    /// 该结论是否喂熔断（失败档）。`Unknown` 与 `Healthy` 之外的三档都喂：
    /// 现阶段不可用的 key（死 / 额度空）与持续故障的站点，都不该继续接用户请求。
    fn feeds_breaker(self) -> bool {
        matches!(
            self,
            KeyHealthVerdict::DeadKey
                | KeyHealthVerdict::QuotaExhausted
                | KeyHealthVerdict::UpstreamFault
        )
    }
}

/// `fetch_models` 的结果 → 结论。
///
/// 按 `Error` 变体分类：
/// - `Ok` ⇒ `Healthy`（空数组也是活：认证通过了，目录空是另一回事）；
/// - `AuthFailed` ⇒ `DeadKey`（`map_http_error` 已把 401 / 403 非额度码归到这里）；
/// - `QuotaExhausted` ⇒ `QuotaExhausted`（401 / 403 + 额度码）；
/// - `RateLimited`（429）/ `NotDelivered`（连接层失败）⇒ `UpstreamFault`；
/// - `Transport`：只有 `map_http_error` 的 5xx 字面量（`"站点服务异常（{s}）"`）
///   ⇒ `UpstreamFault`；其余（400、形态异常、未预期状态码）⇒ `Unknown`。
///   字面量锚点由用例钉住：5xx mock 必须得 `UpstreamFault`，字面量一变用例即红。
/// - 其余变体（`NotFound` 等）⇒ `Unknown`。
pub fn classify_probe_result(result: &Result<Vec<String>>) -> KeyHealthVerdict {
    match result {
        Ok(_) => KeyHealthVerdict::Healthy,
        Err(Error::AuthFailed(_)) => KeyHealthVerdict::DeadKey,
        Err(Error::QuotaExhausted) => KeyHealthVerdict::QuotaExhausted,
        Err(Error::RateLimited { .. }) | Err(Error::NotDelivered(_)) => {
            KeyHealthVerdict::UpstreamFault
        }
        Err(Error::Transport(message)) => {
            if message.starts_with("站点服务异常") {
                KeyHealthVerdict::UpstreamFault
            } else {
                KeyHealthVerdict::Unknown
            }
        }
        Err(_) => KeyHealthVerdict::Unknown,
    }
}

/// 结论 → `Breaker`。
///
/// - `Healthy` ⇒ 对每个键记 `record_success`（回 Closed、清零；Open 期间的成功
///   是正证据复活，不等冷却——见 M46-S1 spec §4.2）。
/// - 失败档 ⇒ 对每个键记一次 `record_failure`（连续 3 轮即 Open，阈值是 `Breaker`
///   既有的；Open 冷却未过时 `record_failure` 不刷新 `opened_at`，巡检不会续期冷却）。
/// - `Unknown` ⇒ 不碰 `Breaker`（无法判定，宁可不摘）。
///
/// 键集合：`site_key(site_id)` + `models` 中每个模型的 `model_key`。
/// 只喂 `site_key` 是不够的：用户请求带模型时选路查的是 `model_key`，
/// `site_key` 的 Open 不会跳过它（见 spec §6.3 / §6.6）。
pub fn apply_probe_outcome(
    breaker: &mut Breaker,
    site_id: i64,
    models: &[String],
    verdict: KeyHealthVerdict,
    now: std::time::Instant,
) {
    if verdict == KeyHealthVerdict::Unknown {
        return;
    }
    let mut keys: Vec<BreakerKey> = Vec::with_capacity(models.len() + 1);
    keys.push(site_key(site_id));
    for model in models {
        let key = model_key(site_id, model);
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    if verdict == KeyHealthVerdict::Healthy {
        for key in &keys {
            breaker.record_success(key, now);
        }
    } else {
        // 失败档（feeds_breaker 为真时才到这里；Unknown 已在上面返回）。
        debug_assert!(verdict.feeds_breaker());
        for key in &keys {
            breaker.record_failure(key, now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{BreakerPolicy, BreakerState};

    fn breaker() -> Breaker {
        Breaker::new(BreakerPolicy::default())
    }

    fn ok(models: &[&str]) -> Result<Vec<String>> {
        Ok(models.iter().map(|m| m.to_string()).collect())
    }

    #[test]
    fn classify_probe_result_maps_status_to_verdict() {
        // 成功（含空数组）⇒ Healthy：认证通过即活。
        assert_eq!(
            classify_probe_result(&ok(&["gpt-4o"])),
            KeyHealthVerdict::Healthy
        );
        assert_eq!(classify_probe_result(&ok(&[])), KeyHealthVerdict::Healthy);
        // 401 / 403 非额度码 ⇒ DeadKey。
        assert_eq!(
            classify_probe_result(&Err(Error::AuthFailed("未授权".into()))),
            KeyHealthVerdict::DeadKey
        );
        // 额度码 ⇒ QuotaExhausted（与死 key 区分）。
        assert_eq!(
            classify_probe_result(&Err(Error::QuotaExhausted)),
            KeyHealthVerdict::QuotaExhausted
        );
        // 429 / 连接失败 ⇒ UpstreamFault。
        assert_eq!(
            classify_probe_result(&Err(Error::RateLimited {
                retry_after_secs: 60
            })),
            KeyHealthVerdict::UpstreamFault
        );
        assert_eq!(
            classify_probe_result(&Err(Error::NotDelivered("dns".into()))),
            KeyHealthVerdict::UpstreamFault
        );
        // 5xx 字面量 ⇒ UpstreamFault（锚点：字面量一变这条即红）。
        assert_eq!(
            classify_probe_result(&Err(Error::Transport("站点服务异常（503）".into()))),
            KeyHealthVerdict::UpstreamFault
        );
        // 其余 Transport / 其它变体 ⇒ Unknown，不喂熔断。
        assert_eq!(
            classify_probe_result(&Err(Error::Transport("请求被站点拒绝（400）".into()))),
            KeyHealthVerdict::Unknown
        );
        assert_eq!(
            classify_probe_result(&Err(Error::Transport("未预期的状态码 418".into()))),
            KeyHealthVerdict::Unknown
        );
        assert_eq!(
            classify_probe_result(&Err(Error::NotFound("资源不存在".into()))),
            KeyHealthVerdict::Unknown
        );
    }

    #[test]
    fn apply_probe_outcome_opens_after_three_failed_rounds() {
        let mut b = breaker();
        let now = std::time::Instant::now();
        let models = vec!["gpt-4o".to_string(), "claude-x".to_string()];
        let site = site_key(7);
        let model = model_key(7, "gpt-4o");
        // 第 1、2 轮仍 Closed（阈值 3，单轮抖动不摘除）。
        apply_probe_outcome(&mut b, 7, &models, KeyHealthVerdict::DeadKey, now);
        assert_eq!(b.state(&site, now), BreakerState::Closed);
        assert_eq!(b.state(&model, now), BreakerState::Closed);
        apply_probe_outcome(&mut b, 7, &models, KeyHealthVerdict::DeadKey, now);
        assert_eq!(b.state(&site, now), BreakerState::Closed);
        // 第 3 轮 ⇒ site_key 与各 model_key 同时 Open。
        apply_probe_outcome(&mut b, 7, &models, KeyHealthVerdict::DeadKey, now);
        assert_eq!(b.state(&site, now), BreakerState::Open);
        assert_eq!(b.state(&model, now), BreakerState::Open);
        assert_eq!(b.state(&model_key(7, "claude-x"), now), BreakerState::Open);
        // 其它站点不受影响。
        assert_eq!(b.state(&site_key(8), now), BreakerState::Closed);
    }

    #[test]
    fn apply_probe_outcome_success_closes_and_unknown_is_noop() {
        let mut b = breaker();
        let now = std::time::Instant::now();
        let models = vec!["gpt-4o".to_string()];
        for _ in 0..3 {
            apply_probe_outcome(&mut b, 7, &models, KeyHealthVerdict::DeadKey, now);
        }
        assert_eq!(b.state(&site_key(7), now), BreakerState::Open);
        // Unknown 不改变任何状态（Open 仍在）。
        apply_probe_outcome(&mut b, 7, &models, KeyHealthVerdict::Unknown, now);
        assert_eq!(b.state(&site_key(7), now), BreakerState::Open);
        // 成功 ⇒ 立即回 Closed（正证据复活，不等冷却）。
        apply_probe_outcome(&mut b, 7, &models, KeyHealthVerdict::Healthy, now);
        assert_eq!(b.state(&site_key(7), now), BreakerState::Closed);
        assert_eq!(b.state(&model_key(7, "gpt-4o"), now), BreakerState::Closed);
        // 计数已清零：此后 1 轮失败仍是 Closed（不是「2 轮就 Open」的残留计数）。
        apply_probe_outcome(&mut b, 7, &models, KeyHealthVerdict::DeadKey, now);
        assert_eq!(b.state(&site_key(7), now), BreakerState::Closed);
    }

    #[test]
    fn apply_probe_outcome_quota_and_fault_feed_like_dead() {
        for verdict in [
            KeyHealthVerdict::QuotaExhausted,
            KeyHealthVerdict::UpstreamFault,
        ] {
            let mut b = breaker();
            let now = std::time::Instant::now();
            let models = vec!["gpt-4o".to_string()];
            for _ in 0..3 {
                apply_probe_outcome(&mut b, 7, &models, verdict, now);
            }
            assert_eq!(
                b.state(&site_key(7), now),
                BreakerState::Open,
                "{verdict:?} 连续 3 轮也应 Open"
            );
        }
    }

    #[test]
    fn apply_probe_outcome_dedupes_model_keys() {
        let mut b = breaker();
        let now = std::time::Instant::now();
        // 重复模型名只喂一次：3 轮仍是恰好 Open（重复计数会让 2 轮就 Open）。
        let models = vec!["gpt-4o".to_string(), "gpt-4o".to_string()];
        apply_probe_outcome(&mut b, 7, &models, KeyHealthVerdict::DeadKey, now);
        apply_probe_outcome(&mut b, 7, &models, KeyHealthVerdict::DeadKey, now);
        assert_eq!(b.state(&site_key(7), now), BreakerState::Closed);
    }
}
