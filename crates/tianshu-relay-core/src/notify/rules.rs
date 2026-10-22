//! 告警判定：纯函数 [`evaluate`]。
//!
//! 输入是「上一轮快照 + 本轮快照 + 配置」，输出 `Vec<Notification>`；
//! **不读时钟**（`now` 由参数传入）、不读环境变量、不读文件、不访问网络、无内部状态。
//! 同一输入必出同一输出。
//!
//! 规则表与阈值边界见 `docs/specs/M6-S3-通知渠道.md` §6.1；这里只写实现上容易踩的点：
//!
//! - 比较一律写成 `!(a < b)` 这种**否定式**，让 `NaN` 走「不触发」分支而不是意外命中；
//! - 「事实型」规则（余额、轮换到期）首轮也发；「边沿型」规则需要基线，没有基线就**不发**
//!   （否则每次启动都会重放一轮通知）；
//! - 快照类型里**没有**承载上游错误文案的字段：正文只能由「站点显示名 + 数值 + 枚举化原因」拼出来。

use std::collections::BTreeSet;

use crate::drift::DriftState;

use super::{Notification, NotifyConfig, NotifyKind};

/// 用量跳变：相对倍数阈值。
pub const USAGE_SPIKE_RATIO: f64 = 2.0;
/// 用量跳变：绝对增量下限。没有它，`0.01 → 0.02` 这种抖动也会被倍数放大成告警。
pub const USAGE_SPIKE_MIN_DELTA: f64 = 1.0;

/// 一天的秒数。到期文案的三段式分界（见 [`due_phrase`]）。
const SECONDS_PER_DAY: i64 = 86_400;

/// 一轮观测的快照。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Snapshot {
    pub sites: Vec<SiteSnapshot>,
}

impl Snapshot {
    /// 按 `site_id` 取**第一个**匹配项。
    ///
    /// `site_id` 重复时不做合并（`evaluate` 会各自判定一次）——去重是装配快照那侧的职责，
    /// 判定函数不替调用方猜「哪一条才算数」。
    pub fn site(&self, site_id: i64) -> Option<&SiteSnapshot> {
        self.sites.iter().find(|s| s.site_id == site_id)
    }
}

/// 单个站点的一轮观测事实。**不含密钥，也没有承载上游自由文本的字段**。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SiteSnapshot {
    pub site_id: i64,
    /// 站点显示名（TianshuRelay 自己的展示名），允许进入通知正文
    pub display_name: String,
    /// 本轮余额；`None` = 本轮没取到（站点失败 / 未登录）
    pub balance: Option<BalanceSnapshot>,
    /// 本轮登录态：`true` = 会话失效、需要重新登录
    pub needs_login: bool,
    /// 本轮是否命中额度错误码（`Error::QuotaExhausted`）
    pub quota_exceeded: bool,
    /// 本轮模型列表；`None` = 没取到，`Some(vec![])` = 站点返回了空列表（两者不同）
    pub models: Option<Vec<String>>,
    pub drift: Vec<DriftFact>,
    pub rotation_due: Vec<RotationDueFact>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct BalanceSnapshot {
    pub remaining: f64,
    pub used: f64,
    pub currency: String,
}

/// 一条投递产物的漂移事实。`target_path` / `agent_id` / `channel` 都是 TianshuRelay 自己的
/// 取值（不是上游文本）。
#[derive(Clone, Debug, PartialEq)]
pub struct DriftFact {
    pub target_path: String,
    pub agent_id: String,
    pub channel: String,
    pub state: DriftState,
}

/// 一把进入轮换窗口的密钥。字段与 M6-S4 的 `rotation::RotationDue` 对齐（子集）。
///
/// `name` 是**上游自由文本**（用户在站点侧给令牌起的名字），保留它只为对齐与追溯；
/// **不得**进入通知正文——见 [`rotation_due`] 的实现与 `rotation_due_body_omits_upstream_free_text`。
#[derive(Clone, Debug, PartialEq)]
pub struct RotationDueFact {
    pub key_id: i64,
    pub name: String,
    pub due_at: i64,
}

/// 告警判定（**本包定稿的签名**，章程 §5.3 回填项）。
///
/// `prev = None` 表示没有上一轮快照（首轮 / 刚建库）：只发**事实型**规则
/// （[`NotifyKind::BalanceLow`]、[`NotifyKind::RotationDue`]），边沿型规则一律不发。
///
/// 输出顺序 = `curr.sites` 的输入顺序 × 站点内固定规则序
/// （`BalanceLow` → `UsageSpike` → `NeedsLogin` → `ModelsChanged` → `QuotaExceeded` →
/// `Drift`* → `RotationDue`*）；`drift` / `rotation_due` 内部按输入顺序。
pub fn evaluate(
    prev: Option<&Snapshot>,
    curr: &Snapshot,
    config: &NotifyConfig,
    now: i64,
) -> Vec<Notification> {
    let mut out: Vec<Notification> = Vec::new();

    for site in &curr.sites {
        // `prev` 里没有这个站点 = 新站点：边沿型规则没有基线，但事实型规则照发。
        let before = prev.and_then(|snapshot| snapshot.site(site.site_id));

        if let Some(n) = balance_low(before, site, config, now) {
            out.push(n);
        }
        if let Some(before) = before {
            if let Some(n) = usage_spike(before, site, now) {
                out.push(n);
            }
            if let Some(n) = needs_login(before, site, now) {
                out.push(n);
            }
            if let Some(n) = models_changed(before, site, now) {
                out.push(n);
            }
            if let Some(n) = quota_exceeded(before, site, now) {
                out.push(n);
            }
            out.extend(drift(before, site, now));
        }
        out.extend(rotation_due(before, site, now));
    }

    out
}

/// 余额低于阈值。**事实型**：首轮也发。
///
/// 边界（逐条有测试）：
/// - 阈值 `<= 0`（含 `NaN`）= **关闭**：这是「阈值 0 表示不告警」的既有口径（`settings.rs` / `service.rs`）；
/// - `remaining == threshold` **不**告警（严格小于）；
/// - 上一轮同站点也已低于阈值 → 已经在告警中，不重复发；回升后再次跌破会重新发。
fn balance_low(
    before: Option<&SiteSnapshot>,
    site: &SiteSnapshot,
    config: &NotifyConfig,
    now: i64,
) -> Option<Notification> {
    let threshold = config.balance_threshold;
    // 阈值 0 / 负数 / NaN = 关闭
    if !is_positive(threshold) {
        return None;
    }
    let balance = site.balance.as_ref()?;
    // 严格小于；`remaining` 是 NaN 时不触发
    if !is_less(balance.remaining, threshold) {
        return None;
    }
    let already_alerting = before
        .and_then(|s| s.balance.as_ref())
        .is_some_and(|prev| is_less(prev.remaining, threshold));
    if already_alerting {
        return None;
    }

    Some(Notification::new(
        NotifyKind::BalanceLow,
        Some(site.site_id),
        "余额不足",
        format!(
            "{}: 剩余 {} {}，低于阈值 {}",
            site.display_name, balance.remaining, balance.currency, threshold
        ),
        now,
    ))
}

/// 用量相对跳变。**边沿型**：需要基线。
///
/// `prev.used <= 0` 视为无基线（「从 0 开始用」不是跳变，无法与「刚启用额度」区分）；
/// 倍数与绝对增量**都要**满足。
fn usage_spike(before: &SiteSnapshot, site: &SiteSnapshot, now: i64) -> Option<Notification> {
    let prev = before.balance.as_ref()?;
    let curr = site.balance.as_ref()?;
    if !is_positive(prev.used) {
        return None;
    }
    if !is_at_least(curr.used, prev.used * USAGE_SPIKE_RATIO) {
        return None;
    }
    if !is_at_least(curr.used - prev.used, USAGE_SPIKE_MIN_DELTA) {
        return None;
    }

    Some(Notification::new(
        NotifyKind::UsageSpike,
        Some(site.site_id),
        "用量异常跳变",
        format!(
            "{}: 用量从 {} 跳到 {}（阈值 {} 倍）",
            site.display_name, prev.used, curr.used, USAGE_SPIKE_RATIO
        ),
        now,
    ))
}

/// 登录态失效（`false → true` 的边沿）。
fn needs_login(before: &SiteSnapshot, site: &SiteSnapshot, now: i64) -> Option<Notification> {
    if !site.needs_login || before.needs_login {
        return None;
    }
    Some(Notification::new(
        NotifyKind::NeedsLogin,
        Some(site.site_id),
        "登录态失效",
        format!("{}: 会话已失效，需要重新登录", site.display_name),
        now,
    ))
}

/// 模型列表变化。**边沿型**，且按**集合**比较（顺序、重复元素都不算变化）。
///
/// 正文只报**数量**：模型名是上游自由文本，不进通知（见 spec §6.3 D-4）。
fn models_changed(before: &SiteSnapshot, site: &SiteSnapshot, now: i64) -> Option<Notification> {
    let prev = before.models.as_ref()?;
    let curr = site.models.as_ref()?;
    let prev_set: BTreeSet<&str> = prev.iter().map(String::as_str).collect();
    let curr_set: BTreeSet<&str> = curr.iter().map(String::as_str).collect();
    if prev_set == curr_set {
        return None;
    }

    let added = curr_set.difference(&prev_set).count();
    let removed = prev_set.difference(&curr_set).count();
    Some(Notification::new(
        NotifyKind::ModelsChanged,
        Some(site.site_id),
        "模型列表变化",
        format!(
            "{}: 新增 {} 个，移除 {} 个",
            site.display_name, added, removed
        ),
        now,
    ))
}

/// 额度不足错误码（`false → true` 的边沿）。连续多轮只报第一轮。
fn quota_exceeded(before: &SiteSnapshot, site: &SiteSnapshot, now: i64) -> Option<Notification> {
    if !site.quota_exceeded || before.quota_exceeded {
        return None;
    }
    Some(Notification::new(
        NotifyKind::QuotaExceeded,
        Some(site.site_id),
        "额度不足",
        format!("{}: 站点返回额度不足错误", site.display_name),
        now,
    ))
}

/// 配置漂移。只对 `state.needs_attention()` 为真的 fact 判定——
/// `Intact` 是正常态，`Unknown` 是「判定不了」，把它俩报成告警就是误报
/// （`drift.rs` 对 `Unknown` 也明确 `needs_attention() == false`）。
///
/// 去重键是四元组 `(agent_id, channel, target_path, state)`：同一处只报一次，
/// 状态变化（`Modified` → `Missing`）算新事实。
fn drift(before: &SiteSnapshot, site: &SiteSnapshot, now: i64) -> Vec<Notification> {
    let mut out = Vec::new();
    for fact in &site.drift {
        if !fact.state.needs_attention() {
            continue;
        }
        if before.drift.iter().any(|prev| same_fact(prev, fact)) {
            continue;
        }
        out.push(Notification::new(
            NotifyKind::Drift,
            Some(site.site_id),
            "配置漂移",
            format!(
                "{} 的 {} 配置{}: {}",
                fact.agent_id,
                fact.channel,
                drift_label(fact.state),
                fact.target_path
            ),
            now,
        ));
    }
    out
}

fn same_fact(a: &DriftFact, b: &DriftFact) -> bool {
    a.agent_id == b.agent_id
        && a.channel == b.channel
        && a.target_path == b.target_path
        && a.state == b.state
}

/// 漂移状态的枚举化文案。`Intact` / `Unknown` 不会触发规则，兜底文案只为让 match 完备。
fn drift_label(state: DriftState) -> &'static str {
    match state {
        DriftState::Modified => "内容被改动",
        DriftState::Missing => "文件被删除",
        DriftState::Unreadable => "存在但读不到",
        DriftState::Intact | DriftState::Unknown => "状态异常",
    }
}

/// 密钥进入轮换窗口。**事实型**：首轮也发。
///
/// 「哪些密钥算进入窗口」由**调用方**判定：`SiteSnapshot::rotation_due` 的语义就是
/// 「已经进入提醒窗口的密钥」，S5 用 M6-S4 的 `rotation::due_keys(rows, policy, now)`
/// （按 `RotationPolicy::warn_before_days`）过滤后装配进来。`evaluate` **不二次过滤**：
/// 冻结签名里没有窗口宽度参数，自己猜一个宽度只会把「还没到期」的钥匙也报出来。
///
/// 去重：上一轮同 `key_id` 也在列表里 → 不重复发（`due_keys` 每轮都会把同一把钥匙带出来，
/// 不去重就是每轮一条）。「进窗口」这个边沿由列表本身表达。
///
/// 正文只带 `key_id`：密钥名是上游自由文本（见 [`RotationDueFact`] 的说明）。
fn rotation_due(before: Option<&SiteSnapshot>, site: &SiteSnapshot, now: i64) -> Vec<Notification> {
    let mut out = Vec::new();
    for fact in &site.rotation_due {
        let already =
            before.is_some_and(|prev| prev.rotation_due.iter().any(|p| p.key_id == fact.key_id));
        if already {
            continue;
        }
        out.push(Notification::new(
            NotifyKind::RotationDue,
            Some(site.site_id),
            "密钥到期",
            format!(
                "{}: 密钥 #{} {}",
                site.display_name,
                fact.key_id,
                due_phrase(fact.due_at, now)
            ),
            now,
        ));
    }
    out
}

/// 到期文案。**只看 `due_at` 与 `now` 的差**（无日期库、无时区、不读时钟）。
///
/// 三段式（复审 P2-2 处置，spec §6.1 与差异登记 D-15）：
///
/// | `due_at - now` | 文案 | 理由 |
/// |---|---|---|
/// | `<= 0` | `已到期` | 过期语义，**必须**与「不足一天」可区分 |
/// | `0 < x < 86400` | `还有不到 1 天到期` | 旧口径写成 `还有 0 天到期`：用户实际还有最多 23:59:59，而「0 天」读起来像「今天必须换」或「已经过期」 |
/// | `>= 86400` | `还有 {x / 86400} 天到期` | 天数口径不变（向下取整）；**不**换算成小时 |
///
/// 不用「小时数」修中间那段的理由：`(0, 86400)` 里最后一次向下取整会重新造出
/// 「0 小时」，等于把同一个缺陷换个单位。定性措辞没有可截断的数。
fn due_phrase(due_at: i64, now: i64) -> String {
    let remaining = due_at - now;
    if remaining <= 0 {
        "已到期".to_string()
    } else if remaining < SECONDS_PER_DAY {
        "还有不到 1 天到期".to_string()
    } else {
        format!("还有 {} 天到期", remaining / SECONDS_PER_DAY)
    }
}

// ---------------------------------------------------------------- 浮点比较
//
// 这三个小函数存在的理由：比较的**边界**（`NaN` 走哪条分支）是契约的一部分
// （spec §6.1「阈值 0 / 负数 / NaN = 关闭」），而 `!(a < b)` 这种写法既读不出来，
// 也会被 `clippy::neg_cmp_op_on_partial_ord` 拦下。用 `partial_cmp` 把
// 「`NaN` 一律不触发」写成显式结果，测试按这个语义钉边界。

/// `a > 0`。`0` / 负数 / `NaN` 都是 `false`。
fn is_positive(a: f64) -> bool {
    matches!(a.partial_cmp(&0.0), Some(std::cmp::Ordering::Greater))
}

/// `a < b`（严格小于）。`NaN` 参与比较时为 `false`。
fn is_less(a: f64, b: f64) -> bool {
    matches!(a.partial_cmp(&b), Some(std::cmp::Ordering::Less))
}

/// `a >= b`。任一侧是 `NaN` 时为 `false`。
fn is_at_least(a: f64, b: f64) -> bool {
    matches!(
        a.partial_cmp(&b),
        Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-0123456789abcdef";
    const NOW: i64 = 1_700_000_000;

    fn site(id: i64, name: &str) -> SiteSnapshot {
        SiteSnapshot {
            site_id: id,
            display_name: name.to_string(),
            ..SiteSnapshot::default()
        }
    }

    fn balance(remaining: f64, used: f64, currency: &str) -> Option<BalanceSnapshot> {
        Some(BalanceSnapshot {
            remaining,
            used,
            currency: currency.to_string(),
        })
    }

    fn config(threshold: f64) -> NotifyConfig {
        NotifyConfig {
            balance_threshold: threshold,
            ..NotifyConfig::default()
        }
    }

    fn snapshot(sites: Vec<SiteSnapshot>) -> Snapshot {
        Snapshot { sites }
    }

    fn kinds(notes: &[Notification]) -> Vec<NotifyKind> {
        notes.iter().map(|n| n.kind).collect()
    }

    // ---------- 规则 1：BalanceLow ----------

    #[test]
    fn balance_low_fires_below_threshold() {
        let curr = snapshot(vec![SiteSnapshot {
            balance: balance(3.5, 1.0, "USD"),
            ..site(1, "测试站点")
        }]);
        let notes = evaluate(None, &curr, &config(15.0), NOW);
        assert_eq!(kinds(&notes), vec![NotifyKind::BalanceLow]);
        assert_eq!(notes[0].title, "余额不足");
        assert_eq!(notes[0].body, "测试站点: 剩余 3.5 USD，低于阈值 15");
        assert_eq!(notes[0].site_id, Some(1));
        assert_eq!(notes[0].ts, NOW);
    }

    #[test]
    fn balance_low_at_exactly_the_threshold_does_not_fire() {
        // 边界①：恰好等于阈值 → 不报（严格小于）
        let curr = snapshot(vec![SiteSnapshot {
            balance: balance(15.0, 1.0, "USD"),
            ..site(1, "测试站点")
        }]);
        assert!(evaluate(None, &curr, &config(15.0), NOW).is_empty());

        // 边界另一侧：低一分就报
        let curr = snapshot(vec![SiteSnapshot {
            balance: balance(14.99, 1.0, "USD"),
            ..site(1, "测试站点")
        }]);
        assert_eq!(evaluate(None, &curr, &config(15.0), NOW).len(), 1);
    }

    #[test]
    fn balance_low_threshold_zero_means_disabled() {
        // 边界②：阈值 0 = 关闭（连负余额也不报）
        let curr = snapshot(vec![SiteSnapshot {
            balance: balance(-5.0, 1.0, "USD"),
            ..site(1, "测试站点")
        }]);
        assert!(evaluate(None, &curr, &config(0.0), NOW).is_empty());
        // 负阈值与 NaN 同样关闭（NaN 的比较恒为假，若写成 `threshold < 0.0` 就会漏掉）
        assert!(evaluate(None, &curr, &config(-1.0), NOW).is_empty());
        assert!(evaluate(None, &curr, &config(f64::NAN), NOW).is_empty());
    }

    #[test]
    fn balance_low_dedupes_until_it_recovers() {
        let below = snapshot(vec![SiteSnapshot {
            balance: balance(3.0, 1.0, "USD"),
            ..site(1, "测试站点")
        }]);
        let above = snapshot(vec![SiteSnapshot {
            balance: balance(30.0, 1.0, "USD"),
            ..site(1, "测试站点")
        }]);
        let cfg = config(15.0);

        // 上一轮已低于阈值 → 本轮不重复报
        assert!(evaluate(Some(&below), &below, &cfg, NOW).is_empty());
        // 从正常跌破 → 报
        assert_eq!(evaluate(Some(&above), &below, &cfg, NOW).len(), 1);
        // 回升 → 不报（枚举里没有「恢复」类，见 spec D-6）
        assert!(evaluate(Some(&below), &above, &cfg, NOW).is_empty());
        // 回升后再次跌破 → 重新报
        assert_eq!(evaluate(Some(&above), &below, &cfg, NOW).len(), 1);
    }

    #[test]
    fn balance_low_without_balance_never_fires() {
        // 本轮没取到余额（站点失败）→ 不报；上一轮没取到也不算「已在告警中」
        let no_balance = snapshot(vec![site(1, "测试站点")]);
        assert!(evaluate(None, &no_balance, &config(15.0), NOW).is_empty());

        let below = snapshot(vec![SiteSnapshot {
            balance: balance(3.0, 1.0, "USD"),
            ..site(1, "测试站点")
        }]);
        assert_eq!(
            evaluate(Some(&no_balance), &below, &config(15.0), NOW).len(),
            1
        );
    }

    // ---------- 规则 2：UsageSpike ----------

    fn used(prev_used: f64, curr_used: f64) -> (Snapshot, Snapshot) {
        (
            snapshot(vec![SiteSnapshot {
                balance: balance(100.0, prev_used, "USD"),
                ..site(1, "测试站点")
            }]),
            snapshot(vec![SiteSnapshot {
                balance: balance(100.0, curr_used, "USD"),
                ..site(1, "测试站点")
            }]),
        )
    }

    #[test]
    fn usage_spike_fires_at_exactly_the_ratio() {
        let (prev, curr) = used(10.0, 20.0);
        let notes = evaluate(Some(&prev), &curr, &config(0.0), NOW);
        assert_eq!(kinds(&notes), vec![NotifyKind::UsageSpike]);
        assert_eq!(notes[0].title, "用量异常跳变");
        assert_eq!(notes[0].body, "测试站点: 用量从 10 跳到 20（阈值 2 倍）");
    }

    #[test]
    fn usage_spike_below_the_ratio_does_not_fire() {
        let (prev, curr) = used(10.0, 19.99);
        assert!(evaluate(Some(&prev), &curr, &config(0.0), NOW).is_empty());
        // 用量不涨（甚至回落）也不报
        let (prev, curr) = used(10.0, 9.0);
        assert!(evaluate(Some(&prev), &curr, &config(0.0), NOW).is_empty());
    }

    #[test]
    fn usage_spike_needs_the_absolute_delta_too() {
        // 倍数够了（0.2 → 0.4），但绝对增量 0.2 < 1.0 → 不报
        let (prev, curr) = used(0.2, 0.4);
        assert!(evaluate(Some(&prev), &curr, &config(0.0), NOW).is_empty());
        // 增量刚好 1.0 且倍数刚好 2 倍 → 报
        let (prev, curr) = used(1.0, 2.0);
        assert_eq!(evaluate(Some(&prev), &curr, &config(0.0), NOW).len(), 1);
    }

    #[test]
    fn usage_spike_needs_a_baseline() {
        // 首轮不报
        let (_, curr) = used(0.0, 100.0);
        assert!(evaluate(None, &curr, &config(0.0), NOW).is_empty());
        // 上一轮用量为 0 → 无基线（无法与「刚启用额度」区分）
        let (prev, curr) = used(0.0, 100.0);
        assert!(evaluate(Some(&prev), &curr, &config(0.0), NOW).is_empty());
        // 任一轮没有余额数据 → 不报
        let prev = snapshot(vec![site(1, "测试站点")]);
        let (_, curr) = used(1.0, 100.0);
        assert!(evaluate(Some(&prev), &curr, &config(0.0), NOW).is_empty());
    }

    #[test]
    fn usage_spike_ignores_nan_usage() {
        // `NaN` 参与比较一律为假：不触发（否则 `NaN >= x` 的写法会把告警发出去）
        let (prev, curr) = used(10.0, f64::NAN);
        assert!(evaluate(Some(&prev), &curr, &config(0.0), NOW).is_empty());
        let (prev, curr) = used(f64::NAN, 100.0);
        assert!(evaluate(Some(&prev), &curr, &config(0.0), NOW).is_empty());
        let (prev, curr) = used(f64::INFINITY, f64::INFINITY);
        assert!(evaluate(Some(&prev), &curr, &config(0.0), NOW).is_empty());
    }

    #[test]
    fn balance_low_ignores_nan_remaining() {
        let curr = snapshot(vec![SiteSnapshot {
            balance: balance(f64::NAN, 0.0, "USD"),
            ..site(1, "测试站点")
        }]);
        assert!(evaluate(None, &curr, &config(15.0), NOW).is_empty());
    }

    #[test]
    fn float_helpers_treat_nan_as_no_trigger() {
        assert!(is_positive(1.0));
        assert!(!is_positive(0.0));
        assert!(!is_positive(-1.0));
        assert!(!is_positive(f64::NAN));

        assert!(is_less(1.0, 2.0));
        assert!(!is_less(2.0, 2.0), "严格小于：相等不成立");
        assert!(!is_less(f64::NAN, 2.0));
        assert!(!is_less(1.0, f64::NAN));

        assert!(is_at_least(2.0, 2.0), "恰好等于阈值成立");
        assert!(is_at_least(3.0, 2.0));
        assert!(!is_at_least(1.0, 2.0));
        assert!(!is_at_least(f64::NAN, 2.0));
        assert!(!is_at_least(2.0, f64::NAN));
    }

    #[test]
    fn usage_spike_does_not_repeat_while_usage_is_flat() {
        let (_, curr) = used(10.0, 20.0);
        // 下一轮：用量停在 20，与上一轮相同 → 不报
        assert!(evaluate(Some(&curr), &curr, &config(0.0), NOW).is_empty());
        // 再翻一倍 → 又报
        let (_, curr2) = used(20.0, 40.0);
        assert_eq!(evaluate(Some(&curr), &curr2, &config(0.0), NOW).len(), 1);
    }

    // ---------- 规则 3：NeedsLogin ----------

    fn login(state: bool) -> Snapshot {
        snapshot(vec![SiteSnapshot {
            needs_login: state,
            ..site(1, "测试站点")
        }])
    }

    #[test]
    fn needs_login_fires_on_the_edge_only() {
        assert_eq!(
            kinds(&evaluate(
                Some(&login(false)),
                &login(true),
                &config(0.0),
                NOW
            )),
            vec![NotifyKind::NeedsLogin]
        );
        // 连续两轮都失效 → 只报第一轮
        assert!(evaluate(Some(&login(true)), &login(true), &config(0.0), NOW).is_empty());
        // 恢复登录 → 不报（没有「恢复」类）
        assert!(evaluate(Some(&login(true)), &login(false), &config(0.0), NOW).is_empty());
        // 首轮不报：启动瞬间窗口是开着的，正是通知最不需要的时刻
        assert!(evaluate(None, &login(true), &config(0.0), NOW).is_empty());
    }

    #[test]
    fn a_site_added_in_a_later_round_has_no_baseline() {
        let prev = snapshot(vec![site(1, "甲")]);
        let curr = snapshot(vec![
            site(1, "甲"),
            SiteSnapshot {
                needs_login: true,
                quota_exceeded: true,
                models: Some(vec!["gpt-4".into()]),
                ..site(2, "乙")
            },
        ]);
        assert!(evaluate(Some(&prev), &curr, &config(0.0), NOW).is_empty());
    }

    // ---------- 规则 4：ModelsChanged ----------

    fn models(list: Option<Vec<&str>>) -> Snapshot {
        snapshot(vec![SiteSnapshot {
            models: list.map(|v| v.into_iter().map(str::to_string).collect()),
            ..site(1, "测试站点")
        }])
    }

    #[test]
    fn models_changed_compares_sets_not_sequences() {
        // 顺序变化不算变化
        assert!(evaluate(
            Some(&models(Some(vec!["a", "b"]))),
            &models(Some(vec!["b", "a"])),
            &config(0.0),
            NOW
        )
        .is_empty());
        // 重复元素也不算变化
        assert!(evaluate(
            Some(&models(Some(vec!["a", "a"]))),
            &models(Some(vec!["a"])),
            &config(0.0),
            NOW
        )
        .is_empty());
        // 空 → 空不算变化
        assert!(evaluate(
            Some(&models(Some(vec![]))),
            &models(Some(vec![])),
            &config(0.0),
            NOW
        )
        .is_empty());
    }

    #[test]
    fn models_changed_reports_counts_only() {
        let notes = evaluate(
            Some(&models(Some(vec!["a", "b", "c"]))),
            &models(Some(vec!["b", "c", "d", "e"])),
            &config(0.0),
            NOW,
        );
        assert_eq!(kinds(&notes), vec![NotifyKind::ModelsChanged]);
        assert_eq!(notes[0].body, "测试站点: 新增 2 个，移除 1 个");
    }

    #[test]
    fn models_changed_needs_both_rounds_to_have_a_list() {
        assert!(evaluate(
            Some(&models(None)),
            &models(Some(vec!["a"])),
            &config(0.0),
            NOW
        )
        .is_empty());
        assert!(evaluate(
            Some(&models(Some(vec!["a"]))),
            &models(None),
            &config(0.0),
            NOW
        )
        .is_empty());
        assert!(evaluate(None, &models(Some(vec!["a"])), &config(0.0), NOW).is_empty());
    }

    #[test]
    fn models_changed_body_carries_counts_not_names() {
        // 模型名是上游自由文本：即使它长得像密钥，正文里也只能出现数量
        let notes = evaluate(
            Some(&models(Some(vec!["gpt-4"]))),
            &models(Some(vec![SECRET, "gpt-4"])),
            &config(0.0),
            NOW,
        );
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].body, "测试站点: 新增 1 个，移除 0 个");
        assert!(!notes[0].body.contains("gpt-4"), "{}", notes[0].body);
        assert!(!notes[0].body.contains("sk-"), "{}", notes[0].body);
    }

    // ---------- 规则 5：QuotaExceeded ----------

    fn quota(state: bool) -> Snapshot {
        snapshot(vec![SiteSnapshot {
            quota_exceeded: state,
            ..site(1, "测试站点")
        }])
    }

    #[test]
    fn quota_exceeded_fires_on_the_edge_only() {
        let notes = evaluate(Some(&quota(false)), &quota(true), &config(0.0), NOW);
        assert_eq!(kinds(&notes), vec![NotifyKind::QuotaExceeded]);
        assert_eq!(notes[0].body, "测试站点: 站点返回额度不足错误");
        assert!(evaluate(Some(&quota(true)), &quota(true), &config(0.0), NOW).is_empty());
        assert!(evaluate(Some(&quota(true)), &quota(false), &config(0.0), NOW).is_empty());
        assert!(evaluate(None, &quota(true), &config(0.0), NOW).is_empty());
    }

    // ---------- 规则 6：Drift ----------

    fn drift_fact(path: &str, state: DriftState) -> DriftFact {
        DriftFact {
            target_path: path.to_string(),
            agent_id: "codex".to_string(),
            channel: "codex-auth-json".to_string(),
            state,
        }
    }

    fn drifted(facts: Vec<DriftFact>) -> Snapshot {
        snapshot(vec![SiteSnapshot {
            drift: facts,
            ..site(1, "测试站点")
        }])
    }

    #[test]
    fn drift_fires_once_per_new_fact() {
        let fact = drift_fact("/Users/me/.codex/auth.json", DriftState::Modified);
        let notes = evaluate(
            Some(&drifted(vec![])),
            &drifted(vec![fact.clone()]),
            &config(0.0),
            NOW,
        );
        assert_eq!(kinds(&notes), vec![NotifyKind::Drift]);
        assert_eq!(
            notes[0].body,
            "codex 的 codex-auth-json 配置内容被改动: /Users/me/.codex/auth.json"
        );
        // 同一 fact 再来一轮 → 不重复报
        assert!(evaluate(
            Some(&drifted(vec![fact.clone()])),
            &drifted(vec![fact]),
            &config(0.0),
            NOW
        )
        .is_empty());
    }

    #[test]
    fn drift_state_change_is_a_new_fact() {
        let modified = drift_fact("/Users/me/.codex/auth.json", DriftState::Modified);
        let missing = drift_fact("/Users/me/.codex/auth.json", DriftState::Missing);
        let notes = evaluate(
            Some(&drifted(vec![modified])),
            &drifted(vec![missing]),
            &config(0.0),
            NOW,
        );
        assert_eq!(notes.len(), 1);
        assert_eq!(
            notes[0].body,
            "codex 的 codex-auth-json 配置文件被删除: /Users/me/.codex/auth.json"
        );
    }

    #[test]
    fn drift_ignores_states_that_do_not_need_attention() {
        // `Intact` 是正常态，`Unknown` 是「判定不了」：都不该报（spec D-3）
        let notes = evaluate(
            Some(&drifted(vec![])),
            &drifted(vec![
                drift_fact("/a", DriftState::Intact),
                drift_fact("/b", DriftState::Unknown),
            ]),
            &config(0.0),
            NOW,
        );
        assert!(notes.is_empty(), "{notes:?}");
    }

    #[test]
    fn drift_needs_a_baseline() {
        let notes = evaluate(
            None,
            &drifted(vec![drift_fact("/a", DriftState::Missing)]),
            &config(0.0),
            NOW,
        );
        assert!(notes.is_empty());
    }

    #[test]
    fn drift_reports_unreadable_with_its_own_wording() {
        let notes = evaluate(
            Some(&drifted(vec![])),
            &drifted(vec![drift_fact("/a", DriftState::Unreadable)]),
            &config(0.0),
            NOW,
        );
        assert_eq!(notes.len(), 1);
        assert!(notes[0].body.contains("存在但读不到"), "{}", notes[0].body);
    }

    // ---------- 规则 7：RotationDue ----------

    fn rotation(facts: Vec<(i64, &str, i64)>) -> Snapshot {
        snapshot(vec![SiteSnapshot {
            rotation_due: facts
                .into_iter()
                .map(|(key_id, name, due_at)| RotationDueFact {
                    key_id,
                    name: name.to_string(),
                    due_at,
                })
                .collect(),
            ..site(1, "测试站点")
        }])
    }

    #[test]
    fn rotation_due_fires_on_the_first_round() {
        // 事实型：首轮也报
        let notes = evaluate(
            None,
            &rotation(vec![(7, "daily", NOW - 10)]),
            &config(0.0),
            NOW,
        );
        assert_eq!(kinds(&notes), vec![NotifyKind::RotationDue]);
        assert_eq!(notes[0].body, "测试站点: 密钥 #7 已到期");
    }

    #[test]
    fn rotation_due_counts_down_in_days_without_a_date_library() {
        let notes = evaluate(
            None,
            &rotation(vec![(7, "daily", NOW + 3 * 86_400)]),
            &config(0.0),
            NOW,
        );
        assert_eq!(notes[0].body, "测试站点: 密钥 #7 还有 3 天到期");
        // 向下取整：3.9 天算 3 天
        let notes = evaluate(
            None,
            &rotation(vec![(7, "daily", NOW + 3 * 86_400 + 100)]),
            &config(0.0),
            NOW,
        );
        assert_eq!(notes[0].body, "测试站点: 密钥 #7 还有 3 天到期");
    }

    /// 复审 P2-2 的五点边界（**逐字**）。三段式的分界必须是
    /// `<= 0` → 已到期 / `(0, 86400)` → 不足 1 天 / `>= 86400` → 整除天数。
    #[test]
    fn rotation_due_phrase_boundaries_are_verbatim() {
        let now = 1_000_000_i64;
        let cases: [(i64, &str); 6] = [
            (86_400, "还有 1 天到期"),     // 恰好一天
            (86_401, "还有 1 天到期"),     // 向下取整仍是 1
            (86_399, "还有不到 1 天到期"), // 差一秒不足一天 → 不得说「0 天」
            (1, "还有不到 1 天到期"),      // 还差一秒
            (0, "已到期"),                 // 恰好到点
            (-1, "已到期"),                // 已过期一秒
        ];
        for (remaining, expected) in cases {
            let notes = evaluate(
                None,
                &rotation(vec![(7, "daily", now + remaining)]),
                &config(0.0),
                now,
            );
            assert_eq!(notes.len(), 1, "remaining={remaining} 应恰好一条");
            assert_eq!(
                notes[0].body,
                format!("测试站点: 密钥 #7 {expected}"),
                "remaining={remaining} 的文案不符（复审 P2-2）"
            );
        }
    }

    /// 复审 P2-2 报告过的**原始输入**：`now=100, due_at=86400`（还剩 23.99 小时）。
    #[test]
    fn rotation_due_reported_case_no_longer_says_zero_days() {
        let notes = evaluate(
            None,
            &rotation(vec![(42, "daily", 86_400)]),
            &config(0.0),
            100,
        );
        assert_eq!(notes[0].body, "测试站点: 密钥 #42 还有不到 1 天到期");
        assert!(
            !notes[0].body.contains("0 天"),
            "不足一天时不得出现「0 天」（读起来像已过期）: {}",
            notes[0].body
        );
    }

    /// 反向守护：把 `(0, 86400)` 全档拉一遍，任何取值都不得出现「0 天」或「已经过期」的措辞。
    #[test]
    fn rotation_due_never_says_zero_days_before_the_deadline() {
        let now = 7_000_000_i64;
        for remaining in [1_i64, 2, 59, 3_599, 3_600, 43_200, 86_399] {
            let notes = evaluate(
                None,
                &rotation(vec![(7, "daily", now + remaining)]),
                &config(0.0),
                now,
            );
            let body = &notes[0].body;
            assert!(
                !body.contains("0 天") && !body.contains("已到期"),
                "remaining={remaining} 的文案误导（应为「不足 1 天」）: {body}"
            );
        }
    }

    #[test]
    fn rotation_due_does_not_repeat_while_the_key_stays_in_the_window() {
        let due = rotation(vec![(7, "daily", NOW - 10)]);
        assert!(evaluate(Some(&due), &due, &config(0.0), NOW).is_empty());
        // 新进窗口的 key（上一轮不在列表里）→ 报
        let empty = snapshot(vec![site(1, "测试站点")]);
        assert_eq!(evaluate(Some(&empty), &due, &config(0.0), NOW).len(), 1);
        // 全新的 key → 报
        assert_eq!(
            evaluate(
                Some(&due),
                &rotation(vec![(9, "new", NOW - 1)]),
                &config(0.0),
                NOW
            )
            .len(),
            1
        );
        // 上一轮在、这一轮还在 → 不报；另一把钥匙同时进来 → 只报新的那把
        assert_eq!(
            evaluate(
                Some(&due),
                &rotation(vec![(7, "daily", NOW - 10), (9, "new", NOW - 1)]),
                &config(0.0),
                NOW
            )
            .len(),
            1
        );
    }

    #[test]
    fn rotation_due_reports_every_key_in_the_list_in_input_order() {
        let notes = evaluate(
            None,
            &rotation(vec![(7, "a", NOW - 1), (9, "b", NOW + 86_400)]),
            &config(0.0),
            NOW,
        );
        assert_eq!(
            kinds(&notes),
            vec![NotifyKind::RotationDue, NotifyKind::RotationDue]
        );
        assert_eq!(notes[0].body, "测试站点: 密钥 #7 已到期");
        assert_eq!(notes[1].body, "测试站点: 密钥 #9 还有 1 天到期");
    }

    #[test]
    fn rotation_due_trusts_the_callers_window() {
        // 刻意不做二次过滤（spec D-12）：快照里出现 = 调用方已按 `warn_before_days` 判过窗口。
        // 若在这里再猜一个宽度，就会与 S4 的 `RotationPolicy` 打架。
        let notes = evaluate(
            None,
            &rotation(vec![(7, "daily", NOW + 100 * 86_400)]),
            &config(0.0),
            NOW,
        );
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].body, "测试站点: 密钥 #7 还有 100 天到期");
        // 空列表（没到窗口）→ 一条都没有
        assert!(evaluate(None, &rotation(vec![]), &config(0.0), NOW).is_empty());
    }

    #[test]
    fn rotation_due_body_omits_upstream_free_text() {
        // 密钥名是上游自由文本（可能被上游回显成密钥形态）→ 正文只带 key_id
        let notes = evaluate(
            None,
            &rotation(vec![(7, SECRET, NOW - 1)]),
            &config(0.0),
            NOW,
        );
        assert_eq!(notes[0].body, "测试站点: 密钥 #7 已到期");
        assert!(!notes[0].body.contains("sk-"), "{}", notes[0].body);
        assert!(!notes[0].body.contains(SECRET), "{}", notes[0].body);
    }

    // ---------- 纯函数性 ----------

    #[test]
    fn evaluate_is_deterministic_for_the_same_input() {
        let prev = snapshot(vec![SiteSnapshot {
            balance: balance(30.0, 5.0, "USD"),
            needs_login: false,
            quota_exceeded: false,
            models: Some(vec!["a".into()]),
            drift: vec![],
            ..site(1, "测试站点")
        }]);
        let curr = snapshot(vec![SiteSnapshot {
            balance: balance(3.0, 20.0, "USD"),
            needs_login: true,
            quota_exceeded: true,
            models: Some(vec!["a".into(), "b".into()]),
            drift: vec![drift_fact("/x", DriftState::Modified)],
            rotation_due: vec![RotationDueFact {
                key_id: 1,
                name: "k".into(),
                due_at: NOW - 1,
            }],
            ..site(1, "测试站点")
        }]);
        let cfg = config(15.0);
        let a = evaluate(Some(&prev), &curr, &cfg, NOW);
        let b = evaluate(Some(&prev), &curr, &cfg, NOW);
        assert_eq!(a, b);
        assert_eq!(a.len(), 7, "7 条规则各命中一次: {:?}", kinds(&a));
    }

    #[test]
    fn evaluate_does_not_read_the_clock() {
        // 反证法：`now` 只影响 `ts` 与到期文案。若实现偷偷读了真实时钟，
        // 第一条断言（now=0 时 due_at=86400 必须说「还有 1 天」）就会红。
        let curr = rotation(vec![(7, "daily", 86_400)]);
        let with_zero = evaluate(None, &curr, &config(0.0), 0);
        assert_eq!(with_zero[0].body, "测试站点: 密钥 #7 还有 1 天到期");
        assert_eq!(with_zero[0].ts, 0);

        let with_real = evaluate(None, &curr, &config(0.0), 1_700_000_000);
        assert_eq!(with_real[0].body, "测试站点: 密钥 #7 已到期");
        assert_eq!(with_real[0].ts, 1_700_000_000);
    }

    #[test]
    fn evaluate_only_ts_follows_the_now_argument() {
        let curr = snapshot(vec![SiteSnapshot {
            balance: balance(1.0, 0.0, "USD"),
            needs_login: true,
            ..site(1, "测试站点")
        }]);
        let cfg = config(15.0);
        let a = evaluate(None, &curr, &cfg, 1_700_000_000);
        let b = evaluate(None, &curr, &cfg, 0);
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.ts, 1_700_000_000);
            assert_eq!(y.ts, 0);
            assert_eq!(x.kind, y.kind);
            assert_eq!(x.title, y.title);
            assert_eq!(x.body, y.body, "除 ts 外不得随 now 变化");
            assert_eq!(x.site_id, y.site_id);
        }
    }

    // ---------- 输出顺序与结构 ----------

    #[test]
    fn output_order_is_input_order_times_rule_order() {
        let prev = snapshot(vec![
            SiteSnapshot {
                balance: balance(30.0, 5.0, "USD"),
                models: Some(vec!["a".into()]),
                ..site(1, "甲")
            },
            SiteSnapshot {
                balance: balance(30.0, 5.0, "USD"),
                models: Some(vec!["a".into()]),
                ..site(2, "乙")
            },
        ]);
        let curr = snapshot(vec![
            SiteSnapshot {
                balance: balance(1.0, 20.0, "USD"),
                needs_login: true,
                quota_exceeded: true,
                models: Some(vec!["a".into(), "b".into()]),
                drift: vec![drift_fact("/x", DriftState::Modified)],
                rotation_due: vec![RotationDueFact {
                    key_id: 1,
                    name: "k".into(),
                    due_at: NOW - 1,
                }],
                ..site(1, "甲")
            },
            SiteSnapshot {
                balance: balance(1.0, 20.0, "USD"),
                ..site(2, "乙")
            },
        ]);
        let notes = evaluate(Some(&prev), &curr, &config(15.0), NOW);
        assert_eq!(
            kinds(&notes),
            vec![
                NotifyKind::BalanceLow,
                NotifyKind::UsageSpike,
                NotifyKind::NeedsLogin,
                NotifyKind::ModelsChanged,
                NotifyKind::QuotaExceeded,
                NotifyKind::Drift,
                NotifyKind::RotationDue,
                // 第二个站点：它的上一轮也有余额 → 也有跳变；没有其它变化
                NotifyKind::BalanceLow,
                NotifyKind::UsageSpike,
            ]
        );
        assert_eq!(notes[0].site_id, Some(1));
        assert_eq!(notes[7].site_id, Some(2));
    }

    #[test]
    fn empty_and_no_prev_inputs_are_safe() {
        let empty = Snapshot::default();
        assert!(evaluate(None, &empty, &config(15.0), NOW).is_empty());
        assert!(evaluate(Some(&empty), &empty, &config(15.0), NOW).is_empty());
    }

    #[test]
    fn duplicated_site_ids_are_evaluated_independently() {
        // 去重是装配快照那侧的职责；`evaluate` 不替调用方猜哪条才算数
        let curr = snapshot(vec![
            SiteSnapshot {
                balance: balance(1.0, 0.0, "USD"),
                ..site(1, "甲")
            },
            SiteSnapshot {
                balance: balance(2.0, 0.0, "USD"),
                ..site(1, "甲")
            },
        ]);
        let notes = evaluate(None, &curr, &config(15.0), NOW);
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].body, "甲: 剩余 1 USD，低于阈值 15");
        assert_eq!(notes[1].body, "甲: 剩余 2 USD，低于阈值 15");
        assert_eq!(
            curr.site(1).unwrap().balance.as_ref().unwrap().remaining,
            1.0
        );
    }

    // ---------- 脱敏与「不携带上游自由文本」 ----------

    #[test]
    fn evaluate_scrubs_secret_shaped_fields_at_construction() {
        // 站点显示名与货币字段都是受限字段，但仍要过 scrub：
        // 上游把密钥塞进显示名时，通知里不能出现明文
        let prev = snapshot(vec![SiteSnapshot {
            balance: balance(30.0, 0.0, "USD"),
            ..site(1, SECRET)
        }]);
        let curr = snapshot(vec![SiteSnapshot {
            balance: balance(1.0, 0.0, SECRET),
            drift: vec![DriftFact {
                target_path: format!("/tmp/{SECRET}"),
                agent_id: "codex".into(),
                channel: "codex-auth-json".into(),
                state: DriftState::Modified,
            }],
            ..site(1, SECRET)
        }]);
        let notes = evaluate(Some(&prev), &curr, &config(15.0), NOW);
        assert_eq!(notes.len(), 2);
        for n in &notes {
            assert!(!n.title.contains(SECRET), "{:?}", n.title);
            assert!(!n.body.contains(SECRET), "{:?}", n.body);
            assert!(!n.body.contains("sk-0123"), "{:?}", n.body);
        }
        assert_eq!(notes[0].body, "sk-***: 剩余 1 sk-***，低于阈值 15");
    }

    #[test]
    fn site_snapshot_field_set_is_pinned() {
        // 结构性保证（spec §6.3）：快照类型里**没有**承载上游错误文案的字段。
        // 这里写一个**不带 `..Default::default()`** 的完整字面量：新增字段时它编译失败，
        // 逼人回来确认「新字段是不是上游自由文本」——纪律做成编译期检查才有约束力。
        let s = SiteSnapshot {
            site_id: 1,
            display_name: "测试站点".to_string(),
            balance: None,
            needs_login: false,
            quota_exceeded: false,
            models: None,
            drift: Vec::new(),
            rotation_due: Vec::new(),
        };
        assert_eq!(s, site(1, "测试站点"));
    }
}
