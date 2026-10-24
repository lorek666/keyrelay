//! 通知渠道（M6-S3 实现）：告警判定 + 系统通知 + Webhook。
//!
//! 三件事，各有明确的边界：
//!
//! 1. [`rules::evaluate`]：把「上一轮快照 + 本轮快照 + 配置」判定成 [`Notification`]。
//!    **纯函数**——不读时钟（`now` 由参数传入）、不读环境、不访问网络。
//! 2. [`SystemNotifier`]：macOS / Windows 系统通知。命令拼装是纯函数（`argv` 可逐字断言），
//!    执行走注入式 [`CommandRunner`]，因此测试里**不会**真的弹通知。
//! 3. [`WebhookNotifier`]：`POST` JSON，非 2xx 返回 `Err`、**不重试**、超时取
//!    [`NotifyConfig::timeout`]。
//!
//! # 脱敏是双层的
//!
//! - **构造侧**：[`Notification::new`] 对 `title` / `body` 过 [`crate::redact::scrub`]，
//!   [`rules::evaluate`] 走的就是这条路径；
//! - **发送侧**：[`Notifier::send`] 里再走一次 [`Notification::scrubbed`]（幂等），
//!   兜住「别人手工拼出来的 `Notification`」。
//!
//! 只有一层都不够：构造侧保证正常路径不产生密钥，发送侧保证异常路径也发不出去。
//!
//! # 本模块不接线
//!
//! `evaluate` 与派发由 M6-S5 挂进 `refresh_all`（章程 §4.5）。本模块不依赖 `store` /
//! `service` / `settings`：通知渠道不该有落库能力，也不该被设置模型绑住（章程 §5.2 的中间态）。

pub mod baseline;
pub mod health;
pub mod models;
pub mod rules;
pub mod system;
pub mod webhook;

pub use baseline::{decode_snapshot, encode_snapshot, BASELINE_MAX_AGE_SECS, BASELINE_SETTING_KEY};
pub use health::{apply_probe_outcome, classify_probe_result, KeyHealthVerdict};
pub use models::{merge_models, should_collect_models, ModelsPolicy};
pub use rules::{
    evaluate, BalanceSnapshot, DriftFact, RotationDueFact, SiteSnapshot, Snapshot,
    USAGE_SPIKE_MIN_DELTA, USAGE_SPIKE_RATIO,
};
pub use system::{system_command, NotifyPlatform, StdCommandRunner, SystemNotifier};
pub use webhook::{webhook_payload, ReqwestWebhookTransport, WebhookNotifier, WebhookTransport};

use std::time::Duration;

use crate::error::Result;
use crate::redact::scrub;

/// 告警类型。`as_str` 的取值进 Webhook 报文的 `kind` 字段（snake_case，冻结）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NotifyKind {
    BalanceLow,
    UsageSpike,
    NeedsLogin,
    ModelsChanged,
    QuotaExceeded,
    Drift,
    RotationDue,
    /// M46-S5：本地硬预算超标（网关拦停候选）。与 `QuotaExceeded`（站点侧额度）
    /// 不同：这是本地预算，不是上游报的额度；与 `BalanceLow`（余额阈值告警）
    /// 不同：这是「已超且已拦停」的事实，不是阈值提醒。
    /// 只由 service 的预算 drain 路径直接构造，不走 `rules::evaluate`（见 spec §4.3）。
    BudgetExceeded,
}

impl NotifyKind {
    /// 全部变体。存在的理由：测试要对「8 类都有覆盖」做穷举断言，
    /// 而 `ALL` 与 `as_str` 一旦不同步，穷举就会静默漏掉新变体。
    pub const ALL: [NotifyKind; 8] = [
        NotifyKind::BalanceLow,
        NotifyKind::UsageSpike,
        NotifyKind::NeedsLogin,
        NotifyKind::ModelsChanged,
        NotifyKind::QuotaExceeded,
        NotifyKind::Drift,
        NotifyKind::RotationDue,
        NotifyKind::BudgetExceeded,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            NotifyKind::BalanceLow => "balance_low",
            NotifyKind::UsageSpike => "usage_spike",
            NotifyKind::NeedsLogin => "needs_login",
            NotifyKind::ModelsChanged => "models_changed",
            NotifyKind::QuotaExceeded => "quota_exceeded",
            NotifyKind::Drift => "drift",
            NotifyKind::RotationDue => "rotation_due",
            NotifyKind::BudgetExceeded => "budget_exceeded",
        }
    }
}

/// 通知配置（章程 §4.3 冻结）。
///
/// 注意字段的**归属**：`balance_threshold` 归 [`rules::evaluate`]；
/// `system_enabled` / `webhook_url` / `timeout` 归**派发侧**（[`SystemNotifier`] 的冻结
/// 构造函数拿不到本结构体，所以 `system_enabled` 必须由调用方判定）。
#[derive(Clone, PartialEq, Debug)]
pub struct NotifyConfig {
    pub system_enabled: bool,
    pub webhook_url: Option<String>,
    /// 余额低于该值时告警（USD）。`0` / 负数 / `NaN` = **关闭**。
    pub balance_threshold: f64,
    pub timeout: Duration,
}

impl Default for NotifyConfig {
    /// 与 `Settings::default()` 的口径一致：系统通知开、无 webhook、阈值 0（关）。
    /// 超时 10s（S5 的 `notify_timeout_secs` 默认值与上限 60 见 `M6-S5-接线与运行时.md` §2.1）。
    fn default() -> Self {
        Self {
            system_enabled: true,
            webhook_url: None,
            balance_threshold: 0.0,
            timeout: Duration::from_secs(10),
        }
    }
}

/// 一条待发出的通知。`title` / `body` **必须**已脱敏（见 [`Notification::new`]）。
#[derive(Clone, PartialEq, Debug)]
pub struct Notification {
    pub kind: NotifyKind,
    pub site_id: Option<i64>,
    pub title: String,
    pub body: String,
    pub ts: i64,
}

impl Notification {
    /// 构造侧脱敏：`title` / `body` 都过 [`scrub`]。
    ///
    /// 生产路径（[`rules::evaluate`]）走这里；字段是 `pub`，所以手工拼结构体字面量可以绕过，
    /// 那种情况由发送侧的 [`Notification::scrubbed`] 兜住。
    pub fn new(
        kind: NotifyKind,
        site_id: Option<i64>,
        title: impl Into<String>,
        body: impl Into<String>,
        ts: i64,
    ) -> Self {
        Self {
            kind,
            site_id,
            title: title.into(),
            body: body.into(),
            ts,
        }
        .scrubbed()
    }

    /// 发送侧兜底脱敏。幂等（`scrub` 幂等，见 `redact::scrub` 的文档）。
    pub fn scrubbed(&self) -> Notification {
        Notification {
            kind: self.kind,
            site_id: self.site_id,
            title: scrub(&self.title),
            body: scrub(&self.body),
            ts: self.ts,
        }
    }
}

/// 通知渠道（章程 §4.3 冻结）。
pub trait Notifier: Send + Sync {
    fn send(&self, n: &Notification) -> Result<()>;
}

/// 执行外部命令的抽象，便于注入式测试（本机不弹真实通知）。
pub trait CommandRunner: Send + Sync {
    fn run(&self, program: &str, args: &[String]) -> Result<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-0123456789abcdef";

    #[test]
    fn kind_all_covers_every_variant_with_distinct_names() {
        assert_eq!(NotifyKind::ALL.len(), 8);
        let mut names: Vec<&str> = NotifyKind::ALL.iter().map(|k| k.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 8, "as_str 有重名: {names:?}");

        // 逐个钉住字面量：`kind` 是 Webhook 报文的一部分，改名等于改线上契约
        assert_eq!(NotifyKind::BalanceLow.as_str(), "balance_low");
        assert_eq!(NotifyKind::UsageSpike.as_str(), "usage_spike");
        assert_eq!(NotifyKind::NeedsLogin.as_str(), "needs_login");
        assert_eq!(NotifyKind::ModelsChanged.as_str(), "models_changed");
        assert_eq!(NotifyKind::QuotaExceeded.as_str(), "quota_exceeded");
        assert_eq!(NotifyKind::Drift.as_str(), "drift");
        assert_eq!(NotifyKind::RotationDue.as_str(), "rotation_due");
        assert_eq!(NotifyKind::BudgetExceeded.as_str(), "budget_exceeded");
    }

    #[test]
    fn default_config_is_conservative() {
        let config = NotifyConfig::default();
        assert!(config.system_enabled, "PRD FR-3：系统通知是默认渠道");
        assert_eq!(config.webhook_url, None, "webhook 是可选渠道，默认不开");
        assert_eq!(
            config.balance_threshold, 0.0,
            "阈值 0 = 关闭，与 Settings::default 一致"
        );
        assert_eq!(config.timeout, Duration::from_secs(10));
    }

    #[test]
    fn notification_new_scrubs_both_fields() {
        let n = Notification::new(
            NotifyKind::BalanceLow,
            Some(1),
            format!("标题 {SECRET}"),
            format!("正文 nap-0123456789abcdef 与 {}", "a".repeat(32)),
            7,
        );
        assert_eq!(n.title, "标题 sk-***");
        assert_eq!(n.body, "正文 nap-*** 与 ***");
        assert_eq!(n.ts, 7);
        assert_eq!(n.kind, NotifyKind::BalanceLow);
        assert_eq!(n.site_id, Some(1));
    }

    #[test]
    fn scrubbed_is_idempotent_and_keeps_other_fields() {
        let raw = Notification {
            kind: NotifyKind::Drift,
            site_id: None,
            title: format!("t {SECRET}"),
            body: format!("b {SECRET}"),
            ts: 42,
        };
        let once = raw.scrubbed();
        assert_eq!(once.title, "t sk-***");
        assert_eq!(once, once.scrubbed(), "发送侧脱敏必须幂等");
        assert_eq!(once.ts, 42);
        assert_eq!(once.site_id, None);
    }

    #[test]
    fn plain_text_survives_untouched() {
        let n = Notification::new(
            NotifyKind::NeedsLogin,
            Some(3),
            "登录态失效",
            "测试站点: 会话已失效，需要重新登录",
            1,
        );
        assert_eq!(n.title, "登录态失效");
        assert_eq!(n.body, "测试站点: 会话已失效，需要重新登录");
    }
}
