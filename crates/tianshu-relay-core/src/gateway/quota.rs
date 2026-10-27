//! M3：key 额度事实模型。
//!
//! 累计用量 ≠ 周期额度；未知 ≠ 0 ≠ 不限量。当前存储只有逐 key 的
//! `quota_used / quota_limit` 快照，没有可信窗口或 reset 时间，因此这里
//! 只提供**软排序**，不硬排除候选；真正窗口耗尽需要适配器明确给出窗口事实。

pub const QUOTA_SNAPSHOT_MAX_AGE_SECS: i64 = 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum QuotaLimitState {
    Unknown,
    Unlimited,
    Limited { used: f64, limit: f64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotaRank {
    Unknown,
    Unlimited,
    Healthy,
    NearLimit,
    Exhausted,
    /// 快照超过 [`QUOTA_SNAPSHOT_MAX_AGE_SECS`]：仍可展示，但不参与排序 / pin，
    /// 更不能等同当前耗尽（计划 M3：过期快照只做提示）。
    Stale,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KeyQuotaSnapshot {
    pub limit: QuotaLimitState,
    /// 读取该快照的本地时刻；`None` = 来源没提供可证明的观测时间。
    pub observed_at: Option<i64>,
    /// 受控来源标签，不能塞 URL / 错误正文。
    pub source: &'static str,
}

impl KeyQuotaSnapshot {
    pub fn unknown() -> Self {
        Self {
            limit: QuotaLimitState::Unknown,
            observed_at: None,
            source: "unknown",
        }
    }

    pub fn unlimited(observed_at: Option<i64>, source: &'static str) -> Self {
        Self {
            limit: QuotaLimitState::Unlimited,
            observed_at,
            source,
        }
    }

    pub fn limited(used: f64, limit: f64, observed_at: Option<i64>, source: &'static str) -> Self {
        // `limit == 0` 在历史数据里混合了「没有额度」与「字段缺失被写成 0」，
        // 不能安全地判成 Exhausted；负用量同理。两者都保持 Unknown，宁可不排序。
        if !used.is_finite() || used < 0.0 || !limit.is_finite() || limit <= 0.0 {
            return Self::unknown();
        }
        Self {
            limit: QuotaLimitState::Limited { used, limit },
            observed_at,
            source,
        }
    }

    /// 存储层只有 `Option` 时：`None` 必须保持未知，不能猜「不限量」。
    pub fn from_stored(
        used: Option<f64>,
        limit: Option<f64>,
        observed_at: Option<i64>,
        source: &'static str,
    ) -> Self {
        match (used, limit) {
            (Some(used), Some(limit)) => Self::limited(used, limit, observed_at, source),
            _ => Self {
                limit: QuotaLimitState::Unknown,
                observed_at,
                source,
            },
        }
    }

    pub fn rank(self) -> QuotaRank {
        match self.limit {
            QuotaLimitState::Unknown => QuotaRank::Unknown,
            QuotaLimitState::Unlimited => QuotaRank::Unlimited,
            QuotaLimitState::Limited { used, limit }
                if !used.is_finite() || used < 0.0 || !limit.is_finite() || limit <= 0.0 =>
            {
                QuotaRank::Unknown
            }
            QuotaLimitState::Limited { used, limit } => {
                let ratio = (used / limit).clamp(0.0, 10.0);
                if ratio >= 1.0 {
                    QuotaRank::Exhausted
                } else if ratio >= 0.9 {
                    QuotaRank::NearLimit
                } else {
                    QuotaRank::Healthy
                }
            }
        }
    }

    /// 与 [`Self::rank`] 相同，但超过 freshness 上限的**已知**快照降为 `Stale`。
    /// `Unknown` 保持 `Unknown`；不知道不能因为时间流逝变成另一个不知道。
    pub fn rank_at(self, now: i64) -> QuotaRank {
        if matches!(
            self.limit,
            QuotaLimitState::Limited { .. } | QuotaLimitState::Unlimited
        ) {
            if let Some(observed_at) = self.observed_at {
                if now.saturating_sub(observed_at) > QUOTA_SNAPSHOT_MAX_AGE_SECS {
                    return QuotaRank::Stale;
                }
            }
        }
        self.rank()
    }

    /// 仅用于排序：越小越先。Unknown / Stale / Unlimited 不因缺少或被时间淘汰的数据被罚。
    pub fn sort_key(self) -> u8 {
        match self.rank() {
            QuotaRank::Healthy => 0,
            QuotaRank::Unknown | QuotaRank::Unlimited | QuotaRank::Stale => 1,
            QuotaRank::NearLimit => 1,
            QuotaRank::Exhausted => 2,
        }
    }

    /// 排序用：带 freshness 判定。过期快照回到中性档，不会被误排为耗尽。
    pub fn sort_key_at(self, now: i64) -> u8 {
        match self.rank_at(now) {
            QuotaRank::Healthy => 0,
            QuotaRank::Unknown | QuotaRank::Unlimited | QuotaRank::Stale => 1,
            QuotaRank::NearLimit => 1,
            QuotaRank::Exhausted => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_data_is_unknown_not_unlimited_or_zero() {
        let q = KeyQuotaSnapshot::from_stored(Some(3.0), None, Some(10), "key_store");
        assert_eq!(q.limit, QuotaLimitState::Unknown);
        assert_eq!(q.rank(), QuotaRank::Unknown);
        assert_eq!(q.sort_key(), 1);
        let q = KeyQuotaSnapshot::from_stored(None, Some(10.0), Some(10), "key_store");
        assert_eq!(q.limit, QuotaLimitState::Unknown);
    }

    #[test]
    fn limited_rating_is_soft_and_rejects_invalid_numbers() {
        assert_eq!(
            KeyQuotaSnapshot::limited(1.0, 10.0, None, "x").rank(),
            QuotaRank::Healthy
        );
        assert_eq!(
            KeyQuotaSnapshot::limited(9.5, 10.0, None, "x").rank(),
            QuotaRank::NearLimit
        );
        assert_eq!(
            KeyQuotaSnapshot::limited(10.0, 10.0, None, "x").rank(),
            QuotaRank::Exhausted
        );
        assert_eq!(
            KeyQuotaSnapshot::limited(f64::NAN, 10.0, None, "x").limit,
            QuotaLimitState::Unknown
        );
        assert_eq!(
            KeyQuotaSnapshot::limited(1.0, -1.0, None, "x").limit,
            QuotaLimitState::Unknown
        );
        assert_eq!(
            KeyQuotaSnapshot::limited(-1.0, 10.0, None, "x").limit,
            QuotaLimitState::Unknown,
            "negative used must not rank as healthy"
        );
        assert_eq!(
            KeyQuotaSnapshot::limited(0.0, 0.0, None, "x").limit,
            QuotaLimitState::Unknown,
            "zero limit is ambiguous legacy data, not unlimited or exhausted"
        );
    }

    #[test]
    fn unlimited_is_distinct_from_unknown() {
        let q = KeyQuotaSnapshot::unlimited(Some(100), "adapter");
        assert_eq!(q.limit, QuotaLimitState::Unlimited);
        assert_eq!(q.rank(), QuotaRank::Unlimited);
        assert_ne!(q, KeyQuotaSnapshot::unknown());
    }

    #[test]
    fn stale_snapshots_leave_ranking_neutral_without_becoming_exhausted() {
        let observed = 1_000;
        let q = KeyQuotaSnapshot::from_stored(Some(1.0), Some(10.0), Some(observed), "store");
        assert_eq!(q.rank_at(observed + 3_600), QuotaRank::Healthy);
        assert_eq!(
            q.rank_at(observed + QUOTA_SNAPSHOT_MAX_AGE_SECS + 1),
            QuotaRank::Stale
        );
        assert_eq!(
            q.sort_key_at(observed + QUOTA_SNAPSHOT_MAX_AGE_SECS + 1),
            1,
            "stale quota must neither outrank healthy nor fall into exhausted"
        );
        let unknown = KeyQuotaSnapshot::from_stored(None, None, Some(observed), "store");
        assert_eq!(
            unknown.rank_at(observed + QUOTA_SNAPSHOT_MAX_AGE_SECS + 1),
            QuotaRank::Unknown
        );
    }
}
