//! 上游路由与熔断（M7-S1 / PRD FR-5 路由表、FR-6 多站聚合与故障切换）。
//!
//! 两件事：
//! - [`RouteTable`]：按模型选路，并给出**确定**的候选顺序（首位即首选）；
//! - [`Breaker`]：按站点计数的连续失败熔断，冷却后放行一个探针。
//!
//! 边界：
//! - **不碰钥匙串、不含密钥**：`Upstream::key_ref` 是引用，明文只在网关进程内（见 `gateway.rs`）；
//! - **不做 IO**：本模块是纯数据与纯函数，网络行为在 `gateway.rs`；
//! - 排序**必须确定**：`candidates()` 的首位就是实际被使用的上游，排序不确定会让同一个请求
//!   两次走不同上游（不可复现、成本漂移、测试失去钉住能力、熔断被绕过），详见
//!   `docs/specs/M7-S1-网关路由与故障切换.md` §5.1。

use std::cmp::Ordering;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// 一个可被路由到的上游。
#[derive(Clone, Debug, PartialEq)]
pub struct Upstream {
    pub site_id: i64,
    pub base_url: String,
    pub key_ref: String,          // 钥匙串引用，**不是**密钥明文
    pub models: Vec<String>,      // 该上游可服务的模型名（精确匹配）
    pub rate: Option<f64>,        // 站点倍率；None = 未知
    pub balance_usd: Option<f64>, // 余额；None = 未知
    pub latency_ms: Option<u64>,  // 最近一次观测延迟；None = 未观测
}

/// 路由表：一组上游 + 别名映射。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RouteTable {
    upstreams: Vec<Upstream>,
    /// agent 侧模型名 → 真实模型名
    aliases: HashMap<String, String>,
}

impl RouteTable {
    pub fn new(upstreams: Vec<Upstream>) -> Self {
        Self {
            upstreams,
            aliases: HashMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.upstreams.is_empty()
    }

    /// 别名映射：agent 侧模型名 → 真实模型名。未登记的模型名按**恒等**处理。
    pub fn with_alias(mut self, alias: &str, real: &str) -> Self {
        self.aliases.insert(alias.to_string(), real.to_string());
        self
    }

    /// 别名解析：未登记则**恒等**返回。`candidates` 内部用的是同一个函数
    /// （两者同源，否则「选路用的名字」与「发上游的名字」会分叉）。
    pub fn resolve_model(&self, model: &str) -> String {
        match self.aliases.get(model) {
            Some(real) => real.clone(),
            None => model.to_string(),
        }
    }

    /// 按 `model` 选路，返回**已排序**的候选（首位即首选）。
    ///
    /// 排序键（PRD FR-6）：余额健康度（有余额 > 未知 > 已耗尽）→ 倍率升序（`None` 排最后）
    /// → 延迟升序（`None` 排最后）→ `site_id` 升序。**同分按 `site_id` 升序**。
    ///
    /// `model` 先过 [`Self::resolve_model`]（别名映射）再与 `Upstream::models` **精确**匹配。
    pub fn candidates(&self, model: &str) -> Vec<&Upstream> {
        let real = self.resolve_model(model);
        ordered(
            self.upstreams
                .iter()
                .filter(|u| u.models.iter().any(|m| m == &real)),
        )
    }

    /// 不做 model 过滤、只用**同一个**排序键选首选。
    ///
    /// 存在的理由：`GET /v1/models` 这类请求**没有 body**，开了路由不能凭空 404 掉一个 PRD 端点。
    /// 它返回的仍然是确定性排序的第一项，不是「随便挑一个」。
    pub fn preferred(&self) -> Option<&Upstream> {
        ordered(self.upstreams.iter()).into_iter().next()
    }
}

/// 候选排序：`sort_by` 是**稳定排序**，所以「连 `site_id` 都相同」的重复条目会保持入参顺序——
/// 于是输出是输入的确定性函数（见模块文档的确定性论证）。
fn ordered<'a>(upstreams: impl Iterator<Item = &'a Upstream>) -> Vec<&'a Upstream> {
    let mut keyed: Vec<(SortKey, &Upstream)> = upstreams.map(|u| (SortKey::of(u), u)).collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    keyed.into_iter().map(|(_, u)| u).collect()
}

/// 余额健康度档位：0 = 有余额，1 = 未知（`None` 或 `NaN`），2 = 已耗尽。
///
/// `NaN` 归入「未知」而不是「已耗尽」：`NaN` 表示**算不出来**，不是「没钱了」。
fn health_rank(balance: Option<f64>) -> u8 {
    match balance {
        Some(x) if x.is_nan() => 1,
        Some(x) if x > 0.0 => 0,
        Some(_) => 2,
        None => 1,
    }
}

/// 排序键：`f64` 不是 `Ord`，这里手工实现全序。
///
/// `NaN` 已被 `health_rank` / `SortKey::of` 归一化成「缺失」，所以 `rate` 字段里
/// 永远不会出现 `NaN`；`partial_cmp` 的 `unwrap_or(Equal)` 只是不 panic 的兜底。
#[derive(Debug)]
struct SortKey {
    health: u8,
    rate_missing: bool,
    rate: f64,
    latency_missing: bool,
    latency: u64,
    site_id: i64,
}

impl SortKey {
    fn of(u: &Upstream) -> Self {
        let (rate_missing, rate) = match u.rate {
            Some(x) if !x.is_nan() => (false, x),
            _ => (true, 0.0),
        };
        let (latency_missing, latency) = match u.latency_ms {
            Some(x) => (false, x),
            None => (true, 0),
        };
        Self {
            health: health_rank(u.balance_usd),
            rate_missing,
            rate,
            latency_missing,
            latency,
            site_id: u.site_id,
        }
    }
}

impl PartialEq for SortKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for SortKey {}
impl PartialOrd for SortKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SortKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.health
            .cmp(&other.health)
            .then_with(|| self.rate_missing.cmp(&other.rate_missing))
            .then_with(|| {
                self.rate
                    .partial_cmp(&other.rate)
                    .unwrap_or(Ordering::Equal)
            })
            .then_with(|| self.latency_missing.cmp(&other.latency_missing))
            .then_with(|| self.latency.cmp(&other.latency))
            .then_with(|| self.site_id.cmp(&other.site_id))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Clone, Debug)]
pub struct BreakerPolicy {
    pub threshold: u32,
    pub cooldown: Duration,
}

impl Default for BreakerPolicy {
    fn default() -> Self {
        Self {
            threshold: 3,
            cooldown: Duration::from_secs(60),
        }
    }
}

/// 按 `site_id` 计数的连续失败熔断。
#[derive(Clone, Debug, Default)]
pub struct Breaker {
    policy: BreakerPolicy,
    sites: HashMap<i64, Entry>,
}

#[derive(Clone, Debug, Default)]
struct Entry {
    consecutive_failures: u32,
    /// `Some(t)` = 最近一次进入 `Open` 的时刻（用于算冷却）
    opened_at: Option<Instant>,
}

impl Breaker {
    pub fn new(policy: BreakerPolicy) -> Self {
        Self {
            policy,
            sites: HashMap::new(),
        }
    }

    /// 记一次失败。返回**本次调用之后**的状态：达到阈值即 `Open`。
    ///
    /// 调用方**只应**在 `should_failover(status)` 为真时调用——否则一个 400 就能把健康上游打成 `Open`。
    ///
    /// `policy.threshold == 0` 的含义是「首次失败即打开」（`0 >= 0`），它不是一个「关闭熔断」的开关。
    pub fn record_failure(&mut self, site_id: i64, now: Instant) -> BreakerState {
        let entry = self.sites.entry(site_id).or_default();
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        if entry.consecutive_failures >= self.policy.threshold {
            // 刷新冷却：`Open` 期间再次失败（探针失败）应从**这一次**重新计时。
            entry.opened_at = Some(now);
            BreakerState::Open
        } else {
            BreakerState::Closed
        }
    }

    /// 记一次成功：无论此前什么状态，一律回 `Closed` 并清零计数。
    pub fn record_success(&mut self, site_id: i64, _now: Instant) {
        self.sites.remove(&site_id);
    }

    /// 只读查询，**不**改状态。`Open` 且冷却已过 ⇒ `HalfOpen`（允许一个探活请求）。
    pub fn state(&self, site_id: i64, now: Instant) -> BreakerState {
        let Some(entry) = self.sites.get(&site_id) else {
            return BreakerState::Closed;
        };
        match entry.opened_at {
            // `saturating_duration_since`：`now` 早于 `opened_at` 时得 0，不 panic。
            Some(opened_at) if now.saturating_duration_since(opened_at) >= self.policy.cooldown => {
                BreakerState::HalfOpen
            }
            Some(_) => BreakerState::Open,
            None => BreakerState::Closed,
        }
    }
}

/// 纯函数：该 HTTP 状态是否应当切下一个上游。
///
/// `429` 与 `5xx` ⇒ `true`；其余（含 `400`/`401`/`403`/`404`/`422`）⇒ `false`。
///
/// 理由：400 类是**请求本身**的问题，换上游只会把同一个错误再犯一次；
/// 401/403 是凭证问题，重试别的上游等于把「密钥无效」误报成「上游故障」，
/// 而且会把**其它站点的密钥**也拿去试一遍。
///
/// **额度耗尽的 403 也落在 `false` 里**——这是**决策**不是遗漏：
/// 上游回「额度不足」是**一个答案**，不是**一次故障**；静默切到另一个站点等于花用户没指定的那份钱。
/// 缓解在**选路时**做（`balance_usd` 把余额耗尽的站点排到最后），见 M7-S0 §3.1 的 D-2 裁决。
pub fn should_failover(status: u16) -> bool {
    status == 429 || (500..=599).contains(&status)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn up(site_id: i64, rate: Option<f64>, balance: Option<f64>, latency: Option<u64>) -> Upstream {
        Upstream {
            site_id,
            base_url: format!("http://site{site_id}.example.com"),
            key_ref: format!("kr/key/{site_id}/secret"),
            models: vec!["gpt-5.6".to_string()],
            rate,
            balance_usd: balance,
            latency_ms: latency,
        }
    }

    #[test]
    fn health_rank_normalises_nan_to_unknown() {
        assert_eq!(health_rank(Some(1.0)), 0);
        assert_eq!(health_rank(None), 1);
        assert_eq!(health_rank(Some(f64::NAN)), 1);
        assert_eq!(health_rank(Some(0.0)), 2);
        assert_eq!(health_rank(Some(-1.0)), 2);
    }

    #[test]
    fn sort_key_is_a_total_order_for_distinct_sites() {
        // 同分时 site_id 必须决出胜负（确定性论证的最小守卫）
        let a = SortKey::of(&up(2, Some(1.0), Some(1.0), Some(1)));
        let b = SortKey::of(&up(1, Some(1.0), Some(1.0), Some(1)));
        assert_eq!(b.cmp(&a), Ordering::Less);
        assert_ne!(a, b);
    }

    #[test]
    fn breaker_default_is_three_failures_and_sixty_seconds() {
        let policy = BreakerPolicy::default();
        assert_eq!(policy.threshold, 3);
        assert_eq!(policy.cooldown, Duration::from_secs(60));
    }
}
