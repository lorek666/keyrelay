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
use std::collections::{HashMap, HashSet};
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
    ///
    /// **空 `models` = 未知 ⇒ 通配**（M8-S1 §4.2）：模型清单采集**默认关**，关着的时候
    /// 每个上游的 `models` 都是空的。若把空列表解释成「谁都不服务」，路由在默认配置下
    /// **完全不可用**（每个请求都 404）。fail-open 在这里是对的：最坏是多一次注定失败的
    /// 尝试，由故障切换兜住；而 fail-closed 会把一个本来可用的站点从候选里摘掉。
    /// 残差（与「该站点真的一把模型都不服务」不可区分）见 BACKLOG 与 spec 的 D-1。
    pub fn candidates(&self, model: &str) -> Vec<&Upstream> {
        let real = self.resolve_model(model);
        ordered(
            self.upstreams
                .iter()
                .filter(|u| u.models.is_empty() || u.models.iter().any(|m| m == &real)),
        )
    }

    /// 不做 model 过滤、只用**同一个**排序键选首选。
    ///
    /// 存在的理由：`GET /v1/models` 这类请求**没有 body**，开了路由不能凭空 404 掉一个 PRD 端点。
    /// 它返回的仍然是确定性排序的第一项，不是「随便挑一个」。
    pub fn preferred(&self) -> Option<&Upstream> {
        ordered(self.upstreams.iter()).into_iter().next()
    }

    /// 所有上游按排序键的有序列表（不过滤 model）。无 body 请求（`GET /v1/models`）
    /// 用它而不是 [`Self::preferred`] 的单个——故障切换仍要工作（B-98 / P2-9）：
    /// 只给首选一个候选，它挂了就 502，不会切到别的上游。
    pub fn all_candidates(&self) -> Vec<&Upstream> {
        ordered(self.upstreams.iter())
    }
}

/// 一个站点能服务哪些模型 + 它的成本 / 健康度（**路由表的输入**）。
///
/// 与 [`Upstream`] 的区别：`Upstream` 是「一次请求可用的上游」，本结构是「从站点事实推导上游」
/// 的中间层——分开的理由是**推导要能单测**，而 `Upstream` 的构造要读钥匙串。
///
/// 七个字段里 `site_id` / `base_url` / `key_ref` 是**事实**（库里有），
/// 另外四个是**观测**（`models` 来自可选的采集，`rate` / `balance_usd` / `latency_ms`
/// 来自最近一次成功观测）。四项观测都**不落库**：重启后回到「全未知」，
/// 排序退化成按 `site_id`（M8-S1 spec §5.1 / D-4）。
#[derive(Clone, Debug, PartialEq)]
pub struct SiteFacts {
    pub site_id: i64,
    pub base_url: String,
    /// 站点侧模型清单（可选采集的结果）。**空 = 未知**，语义见 [`RouteTable::candidates`]。
    pub models: Vec<String>,
    /// 站点倍率（`parse_rate` 的口径）。`None` = 未知，**不是** 1.0。
    pub rate: Option<f64>,
    /// 余额；`known == false` ⇒ `None`（**不是** `Some(0.0)`）。
    pub balance_usd: Option<f64>,
    /// 最近一次成功观测的延迟（到响应头为止）。`None` = 未观测。
    pub latency_ms: Option<u64>,
    /// 钥匙串引用。**不是**密钥明文。
    pub key_ref: String,
}

/// 从站点事实推导路由表。**纯函数**（不读钥匙串、不联网、不读时钟）。
///
/// 余额未知（`None`）的站点**不得**被当成「余额为 0」而排到最后——那是把「不知道」
/// 当成「最差」，与 `Balance.known` 的口径冲突（M7-S2 复审 S-2 花了一整条测试禁止
/// 「未知余额被当成 0 渲染 / 告警」，路由层再犯一次就是同一件事在另一层复活）。
///
/// 排序**不在这里做**：`RouteTable` 只在 [`RouteTable::candidates`] / [`RouteTable::preferred`]
/// 里排序，本函数只做映射，且**保持入参顺序**（稳定排序的性质依赖它）。
pub fn build_route_table(facts: &[SiteFacts]) -> RouteTable {
    RouteTable::new(
        facts
            .iter()
            .map(|f| Upstream {
                site_id: f.site_id,
                base_url: f.base_url.clone(),
                key_ref: f.key_ref.clone(),
                models: f.models.clone(),
                // **原样搬过去，不做任何 `unwrap_or` 降级**：`Option` 一路走到排序键，
                // 由 `health_rank` 把 `None` 归进「未知」档。任何 `unwrap_or(0.0)`
                // 都会把「不知道」变成「已耗尽」，直接改变候选顺序。
                rate: f.rate,
                balance_usd: f.balance_usd,
                latency_ms: f.latency_ms,
            })
            .collect(),
    )
}

/// 模型别名：agent 侧名 → 真实模型名（PRD FR-6 的「模型别名映射」）。
///
/// 用 `BTreeMap` 而不是 `HashMap`：遍历顺序确定（与排序的确定性同一条理由）。
/// 重复的 alias **后者胜**（与 `BTreeMap::insert` 一致）——配置来自用户，
/// 不该让应用因为一个重复键起不来。
///
/// **未接线（去向 B-110）**：别名表的**数据来源**还没有定论（用户手填？从站点模型表推导？），
/// 所以生产上 `pairs` 恒为空。本函数已实现、已测，但**没有生产调用点**。
pub fn alias_map(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    for (alias, real) in pairs {
        map.insert((*alias).to_string(), (*real).to_string());
    }
    map
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
    /// P2-8 / DEBUG-REPORT-v3 §2-8：HalfOpen 探针已放出的站点。冷却一过所有并发
    /// 请求都会看到 HalfOpen（`state` 只读不改），不限流就全部去试坏上游。第一个
    /// 放进探针的请求在这里标记，其余看到标记即跳过，等探针结果回来
    /// （`record_success` / `record_failure` 清除）。
    probe_in_flight: HashSet<i64>,
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
            probe_in_flight: HashSet::new(),
        }
    }

    /// 记一次失败。返回**本次调用之后**的状态：达到阈值即 `Open`。
    ///
    /// 调用方**只应**在 `should_failover(status)` 为真时调用——否则一个 400 就能把健康上游打成 `Open`。
    ///
    /// `policy.threshold == 0` 的含义是「首次失败即打开」（`0 >= 0`），它不是一个「关闭熔断」的开关。
    pub fn record_failure(&mut self, site_id: i64, now: Instant) -> BreakerState {
        // P2-8：探针结果回来（失败），清除「探针在飞」标记。
        self.probe_in_flight.remove(&site_id);
        let entry = self.sites.entry(site_id).or_default();
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        if entry.consecutive_failures >= self.policy.threshold {
            // 只在「首次打开」或「冷却已过（HalfOpen 探针失败）」时设 `opened_at`。
            // 已 `Open` 且冷却未过时**不**刷新 —— 否则请求间隔 < 冷却期时 `opened_at`
            // 每次失败都被续期，冷却永远到不了期，网关永久 503（P1-3）。
            let cooldown_passed = entry
                .opened_at
                .map(|t| now.saturating_duration_since(t) >= self.policy.cooldown)
                .unwrap_or(true);
            if cooldown_passed {
                entry.opened_at = Some(now);
            }
            BreakerState::Open
        } else {
            BreakerState::Closed
        }
    }

    /// 记一次成功：无论此前什么状态，一律回 `Closed` 并清零计数。
    pub fn record_success(&mut self, site_id: i64, _now: Instant) {
        self.sites.remove(&site_id);
        // P2-8：探针成功，清除「探针在飞」标记。
        self.probe_in_flight.remove(&site_id);
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

    /// P2-8 / DEBUG-REPORT-v3 §2-8：HalfOpen 且本站点尚无探针在飞 ⇒ 标记并返回
    /// `true`（本次调用方就是那个唯一的探针）；否则 `false`（已有探针在飞，或非
    /// HalfOpen）。**会改状态**——与 [`Self::state`] 的只读不同：`state` 谁调都看到
    /// HalfOpen，本方法只有第一个调用者拿到探针，其余并发请求看到标记即跳过，
    /// 不会全部涌向坏上游。探针结果回来后由 `record_success` / `record_failure` 清除。
    pub fn try_take_half_open_probe(&mut self, site_id: i64, now: Instant) -> bool {
        if self.state(site_id, now) == BreakerState::HalfOpen {
            self.probe_in_flight.insert(site_id)
        } else {
            false
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

    #[test]
    fn record_failure_opens_after_threshold() {
        let mut b = Breaker::new(BreakerPolicy::default());
        let t0 = Instant::now();
        assert_eq!(b.record_failure(1, t0), BreakerState::Closed);
        assert_eq!(b.record_failure(1, t0), BreakerState::Closed);
        // 第三次达阈值 → Open，opened_at 设为 t0
        assert_eq!(b.record_failure(1, t0), BreakerState::Open);
        assert_eq!(b.state(1, t0), BreakerState::Open);
    }

    #[test]
    fn record_failure_during_cooldown_does_not_refresh_opened_at() {
        // P1-3 核心：Open 后冷却未过时再次失败，opened_at 不得续期。
        // 旧实现每次失败都 opened_at=Some(now)，请求间隔 < 冷却期时冷却永不到期。
        let mut b = Breaker::new(BreakerPolicy::default());
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure(1, t0);
        }
        // 冷却期内（t0+30s）再失败 —— opened_at 应保持 t0，不刷成 t0+30s
        let t1 = t0 + Duration::from_secs(30);
        b.record_failure(1, t1);
        assert_eq!(b.state(1, t1), BreakerState::Open);
        // t0+61s 冷却应到期 → HalfOpen。
        // 若 opened_at 被续到 t1（旧 bug），则 t1+61s 才到期，t0+61s 仍 Open。
        let t2 = t0 + Duration::from_secs(61);
        assert_eq!(
            b.state(1, t2),
            BreakerState::HalfOpen,
            "冷却应从首次打开算起，不被冷却期内的失败续期"
        );
    }

    #[test]
    fn state_transitions_to_half_open_after_cooldown() {
        let mut b = Breaker::new(BreakerPolicy::default());
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure(1, t0);
        }
        assert_eq!(b.state(1, t0), BreakerState::Open);
        assert_eq!(
            b.state(1, t0 + Duration::from_secs(61)),
            BreakerState::HalfOpen
        );
    }

    #[test]
    fn record_failure_after_cooldown_refreshes_opened_at() {
        // HalfOpen 探针失败 → opened_at 重置（探针失败重新冷却，这是合理意图）
        let mut b = Breaker::new(BreakerPolicy::default());
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure(1, t0);
        }
        let t1 = t0 + Duration::from_secs(61);
        assert_eq!(b.state(1, t1), BreakerState::HalfOpen);
        // 探针失败 —— opened_at 应刷到 t1
        b.record_failure(1, t1);
        let t2 = t1 + Duration::from_secs(30);
        assert_eq!(b.state(1, t2), BreakerState::Open);
        let t3 = t1 + Duration::from_secs(61);
        assert_eq!(b.state(1, t3), BreakerState::HalfOpen);
    }

    #[test]
    fn record_success_closes_breaker() {
        let mut b = Breaker::new(BreakerPolicy::default());
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure(1, t0);
        }
        assert_eq!(b.state(1, t0), BreakerState::Open);
        b.record_success(1, t0);
        assert_eq!(b.state(1, t0), BreakerState::Closed);
    }

    #[test]
    fn try_take_half_open_probe_lets_only_one_probe_through() {
        // P2-8 / DEBUG-REPORT-v3 §2-8：冷却一过所有并发请求都看到 HalfOpen（`state`
        // 只读不改），不限流就全部涌向坏上游。`try_take_half_open_probe` 只让第一个
        // 拿到探针，其余看到标记即跳过；探针结果回来后清除标记。
        let mut b = Breaker::new(BreakerPolicy::default());
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure(1, t0);
        }
        let t1 = t0 + Duration::from_secs(61);
        assert_eq!(b.state(1, t1), BreakerState::HalfOpen);

        assert!(
            b.try_take_half_open_probe(1, t1),
            "第一个 HalfOpen 探针应被放行"
        );
        assert!(
            !b.try_take_half_open_probe(1, t1),
            "探针在飞时，第二个并发请求不得再放探针（P2-8）"
        );

        // 探针失败 ⇒ 清除标记 + 重新冷却；冷却过后可再放探针（标记已清）
        b.record_failure(1, t1);
        let t2 = t1 + Duration::from_secs(61);
        assert_eq!(b.state(1, t2), BreakerState::HalfOpen);
        assert!(
            b.try_take_half_open_probe(1, t2),
            "探针结果回来后标记清除，冷却过后可再放探针"
        );
    }

    #[test]
    fn try_take_half_open_probe_is_no_op_for_non_half_open() {
        let mut b = Breaker::new(BreakerPolicy::default());
        let t0 = Instant::now();
        assert!(!b.try_take_half_open_probe(1, t0), "Closed 不放探针");
        for _ in 0..3 {
            b.record_failure(1, t0);
        }
        assert!(
            !b.try_take_half_open_probe(1, t0),
            "Open（冷却未过）不放探针"
        );
    }
}
