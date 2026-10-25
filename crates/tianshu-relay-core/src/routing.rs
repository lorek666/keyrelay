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
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 一个可被路由到的上游。
#[derive(Clone, Debug, PartialEq)]
pub struct Upstream {
    pub site_id: i64,
    /// 该上游使用的**本地 key id**（M39-S3 §4.3）。
    ///
    /// `None` = 旧单 key 路径（`single_upstream` / legacy `gateway_config`）——
    /// 那条路径的签名与行为逐字不变；多 key 展开只在 `service::build_gateway_route` 的
    /// 多站路径里发生（每站每把可用 key 一个 `Upstream`，同站共享 guard 与熔断键）。
    pub key_id: Option<i64>,
    pub base_url: String,
    pub key_ref: String,          // 钥匙串引用，**不是**密钥明文
    pub models: Vec<String>,      // 该上游可服务的模型名（精确匹配）
    pub rate: Option<f64>,        // 站点倍率；None = 未知
    pub balance_usd: Option<f64>, // 余额；None = 未知
    pub latency_ms: Option<u64>,  // 最近一次观测延迟；None = 未观测
    /// M46-S4：该上游的分站超时（毫秒）。None = 回退全局 UpstreamTimeout；
    /// Some(0) 在网关解析时同样视为未填（见 `effective_upstream_timeout`）。
    pub timeout_ms: Option<u64>,
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

    /// 该路由表**能枚举出来**的模型名（升序、去重）。M39-S2 §4.1。
    ///
    /// **这是「枚举」而不是「可达性判据」**：`models` 为空的站点（= 目录未知，M8-S1 §4.2 的
    /// fail-open）不贡献任何模型名，但它**依然是候选**——所以「列表里没有 `m`」不等于
    /// 「`m` 会 404」。可达性判据只看 [`Self::supports_model`]。
    ///
    /// DEBUG-G7 P2-G4：[`Self::available_models_for_sites`] 是本函数的规则过滤版。
    pub fn available_models(&self) -> Vec<String> {
        self.available_models_for_sites(None)
    }

    /// `available_models` 的规则过滤版（DEBUG-G7 P2-G4）。
    ///
    /// `None` = 不过滤（与 `available_models` 逐字相同）；`Some(allowed)` = 只算
    /// 允许站点上游的并集，别名可服务性判定也只看允许站点。`GET /v1/models`
    /// 本地聚合分支用它按请求令牌的 label 过滤，否则聚合分支会在规则过滤之前
    /// 返回，把规则外站点的模型名泄露给受限 agent（泄露面仅模型名字符串，
    /// 但规则的存在意义就是隔离，名字也不应漏）。
    pub fn available_models_for_sites(&self, allowed: Option<&[i64]>) -> Vec<String> {
        let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let in_scope = |site_id: i64| allowed.map_or(true, |list| list.contains(&site_id));
        for upstream in &self.upstreams {
            if in_scope(upstream.site_id) {
                out.extend(upstream.models.iter().cloned());
            }
        }
        for (alias, real) in &self.aliases {
            // 别名与它的真实名都只在**可服务**时列出：指向不存在模型的别名列出来
            // 就是伪造候选（M39-S2 §6）。过滤版里“可服务”只看允许站点。
            let serviceable = self.upstreams.iter().any(|u| {
                in_scope(u.site_id) && (u.models.is_empty() || u.models.iter().any(|m| m == real))
            });
            if !serviceable {
                continue;
            }
            out.insert(alias.clone());
            // 真实名只为「有明确目录」的上游列出：通配（空 models）站点没有可枚举的名字。
            if self
                .upstreams
                .iter()
                .any(|u| in_scope(u.site_id) && u.models.iter().any(|m| m == real))
            {
                out.insert(real.clone());
            }
        }
        out.into_iter().collect()
    }

    /// 该模型**是否可能**被服务（M39-S2 §4.1）：**与 [`Self::candidates`] 同源**。
    ///
    /// `true` ⇒ 至少一个上游可能服务它（含**目录未知**的上游——fail-open）；
    /// `false` ⇒ 每个上游都有明确目录且都不含它（这时调用方才可以 404）。
    pub fn supports_model(&self, model: &str) -> bool {
        !self.candidates(model).is_empty()
    }

    /// 表里出现过的全部 `key_ref`（**去重**，按首次出现顺序）。
    ///
    /// 用途（M16-S4 / P3-9）：`gateway::start()` 的集合不变式——
    /// 「`route` 里的每个 `key_ref` 都必须在 `keys_by_ref` 或 `revoked_refs` 里」。
    /// 不满足时构造方多半是忘了填密钥映射，症状却是「每个上游都跳过 → 502」，
    /// 根因看不见（M7 审计 D-2）。在启动时就报错比等到第一个请求好。
    pub fn key_refs(&self) -> Vec<&str> {
        let mut seen = std::collections::HashSet::new();
        self.upstreams
            .iter()
            .map(|u| u.key_ref.as_str())
            .filter(|r| seen.insert(*r))
            .collect()
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
    /// 该事实使用的**本地 key id**（M39-S3 §4.3）。
    ///
    /// `None` = 旧单 key 路径（`build_route_table` 之外的历史构造点）；
    /// 多站路径里 `service::build_gateway_route` 会给每把可用 key 各产出一条事实。
    pub key_id: Option<i64>,
    /// M46-S4：分站超时（毫秒），与 [`Upstream::timeout_ms`] 同口径；
    /// `build_route_table` 原样搬运，不做任何 `unwrap_or` 降级。
    /// 生产来源缺口见 M46-S4 spec §4.4：`build_gateway_route` 目前恒填 `None`。
    pub timeout_ms: Option<u64>,
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
                key_id: f.key_id,
                base_url: f.base_url.clone(),
                key_ref: f.key_ref.clone(),
                models: f.models.clone(),
                // **原样搬过去，不做任何 `unwrap_or` 降级**：`Option` 一路走到排序键，
                // 由 `health_rank` 把 `None` 归进「未知」档。任何 `unwrap_or(0.0)`
                // 都会把「不知道」变成「已耗尽」，直接改变候选顺序。
                rate: f.rate,
                balance_usd: f.balance_usd,
                latency_ms: f.latency_ms,
                // M46-S4：原样搬运（None = 回退全局，不降级成任何数值）。
                timeout_ms: f.timeout_ms,
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

/// M46-S2：EWMA 平滑系数（固定值，不可配——可配会让两台网关的选路行为不可复现）。
pub const EWMA_ALPHA: f64 = 0.2;

/// M46-S2：一次成功样本后的 EWMA。首次样本直接作为初值（不是 `alpha × 样本`）：
/// `None ⇒ 样本`；`Some(prev) ⇒ alpha × 样本 + (1 − alpha) × prev`。
/// 纯函数：只算数，不判定「成功」——调用方（网关成功分支）负责只喂成功样本。
///
/// DEBUG-G7 P2-G1（异常值截断，先于衰减做）：样本先截断到上一值的 5 倍再
/// 平滑——单次离群样本最多让 EWMA 上涨 80%（`0.2 × 5 + 0.8 × 1`），而不是无界
/// 抬升。下跌不截断（样本可以任意小）：一次极快样本最多让 EWMA 下跌 20%，本身有界。
///
/// DEBUG-G7 补齐 P2-G1（时间衰减，取 TTL 路线而非连续加权）：EWMA 值本身
/// 不带时间加权——陈旧值由网关层 `SiteMetrics::ewma_latency_at_secs` +
/// `EWMA_STALE_AFTER_SECS`（600 秒）兜底：超期未更新的 EWMA 在选路 map
/// 与快照里一律视为无 EWMA，回退静态延迟。取 TTL 而非按（站点，模型）
/// 分键，是改动最小的选择（分键要改快照键类型与选路闭包签名，另立项）；
/// 残留：EWMA 仍按站聚合（不同模型延迟差异仍被抹平）；被挤出窗口的站
/// 若静态延迟也慢，TTL 过期后仍进不了窗口、拿不到新样本，自纠正只闭合
/// “过期快值占优”一半，窗口轮换/探针需另立项。
///
/// 语义（不得谎称 EWMA 决定首选）：EWMA 只改变候选进入 `lb_top_n` 窗口的集合
/// 与失败切换尾巴的顺序；首选的加权分布由 `weighted_pick` 的 rate 定。
/// `lb_top_n >=` 候选数时 EWMA 对首选分布**零影响**；只有 `top_n = 1` 时
/// EWMA 才决定同档首选。另：EWMA 按站聚合（不按模型），见上段残留。
pub fn ewma_update(previous: Option<f64>, sample_ms: u64) -> f64 {
    match previous {
        None => sample_ms as f64,
        Some(prev) => {
            // prev == 0（曾采到 0ms 样本）时不截断：否则 0 × 5 = 0 会把 EWMA
            // 永远钉在 0；0 本身不是“离群高值”，放行即恢复。
            let capped = if prev > 0.0 {
                (sample_ms as f64).min(prev * 5.0)
            } else {
                sample_ms as f64
            };
            EWMA_ALPHA * capped + (1.0 - EWMA_ALPHA) * prev
        }
    }
}

/// M46-S2：按有效延迟重排候选（网关 handler 在 `weighted_pick` 前调用）。
///
/// 排序键与 [`SortKey`] 逐字同一套（余额档位 → 倍率 → 延迟 → `site_id`），
/// 只把延迟一项换成有效延迟：`ewma_ms(site)` 有值（且有限）⇒ `round()` 到毫秒
/// （静态延迟本就是 `u64` 毫秒，排序粒度即毫秒）；否则回退 `Upstream.latency_ms`。
/// 输入输出都是 `Vec<Candidate>`：`probe` 旗标跟着候选走，不增不减；
/// 权重公式不在这里（`weighted_pick` 的槽位份额只由 `rate` 定），
/// 本函数只改变组首次出现顺序与失败切换顺序。
/// 全序（末位 `site_id` 兜底），输出与输入顺序无关。
pub fn reorder_by_effective_latency<'a>(
    candidates: Vec<Candidate<'a>>,
    ewma_ms: &dyn Fn(i64) -> Option<f64>,
) -> Vec<Candidate<'a>> {
    let mut keyed: Vec<(SortKey, Candidate<'a>)> = candidates
        .into_iter()
        .map(|c| {
            let effective = ewma_ms(c.upstream.site_id)
                .filter(|v| v.is_finite())
                .map(|v| v.round().max(0.0) as u64)
                .or(c.upstream.latency_ms);
            (SortKey::of_with_latency(c.upstream, effective), c)
        })
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    keyed.into_iter().map(|(_, c)| c).collect()
}

/// M46-S7：一条按 agent 路由规则。
///
/// `agent_label` 是网关令牌的 label（M43-S1 的认证快照）；匹配时精确相等、
/// 大小写敏感。`site_ids` 是该 agent 只允许走的站点 id（解析时按序去重）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutingRule {
    pub agent_label: String,
    pub site_ids: Vec<i64>,
}

/// M46-S7：规则 JSON 文本上限（字符数）。65536 远高于真实规模
/// （agent 数与站点数都是个位数到两位数），只拦病态大串。
pub const MAX_ROUTING_RULES_JSON_LEN: usize = 65_536;
/// M46-S7：规则条数上限（同上，只拦病态值）。
pub const MAX_ROUTING_RULES: usize = 64;
/// M46-S7：单条规则的站点数上限（去重后计）。
pub const MAX_ROUTING_RULE_SITES: usize = 128;

/// M46-S7：解析规则 JSON（纯函数，不读库、不读时钟）。
///
/// 空串 / 纯空白 ⇒ 空规则（等价于 `[]`）；顶层必须是数组，条目必须是对象，
/// 字段为 camelCase（`agentLabel` / `siteIds`，与 DTO 命名同惯例）。
/// `agentLabel` 解析时 trim，trim 后为空 ⇒ 非法；`siteIds` 非空、每项为正整数、
/// 按序去重；同一 `agentLabel`（trim 后比较）出现两次 ⇒ 非法；
/// 未知字段忽略（前向兼容）。任一条目非法 ⇒ 整串 Err，不做部分解析
/// （部分解析会让用户以为规则全生效，实则部分生效，比整单拒更危险）。
/// Err 文本是中文原因，不回显规则全文。
pub fn parse_routing_rules(text: &str) -> Result<Vec<RoutingRule>, String> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    if text.chars().count() > MAX_ROUTING_RULES_JSON_LEN {
        return Err(format!(
            "路由规则文本超过 {MAX_ROUTING_RULES_JSON_LEN} 字符上限"
        ));
    }
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("路由规则 JSON 解析失败：{e}"))?;
    let items = match value.as_array() {
        Some(items) => items,
        None => return Err("路由规则顶层必须是数组".to_string()),
    };
    if items.len() > MAX_ROUTING_RULES {
        return Err(format!("路由规则超过 {MAX_ROUTING_RULES} 条上限"));
    }
    let mut rules: Vec<RoutingRule> = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let rule_no = index + 1;
        let obj = match item.as_object() {
            Some(obj) => obj,
            None => return Err(format!("第 {rule_no} 条路由规则必须是对象")),
        };
        let label = match obj.get("agentLabel").and_then(|v| v.as_str()) {
            Some(label) => label.trim().to_string(),
            None => {
                return Err(format!("第 {rule_no} 条路由规则的 agentLabel 必须是字符串"));
            }
        };
        if label.is_empty() {
            return Err(format!("第 {rule_no} 条路由规则的 agentLabel 不能为空"));
        }
        if rules.iter().any(|r: &RoutingRule| r.agent_label == label) {
            return Err(format!("路由规则的 agentLabel「{label}」重复"));
        }
        let raw_sites = match obj.get("siteIds").and_then(|v| v.as_array()) {
            Some(sites) => sites,
            None => {
                return Err(format!(
                    "第 {rule_no} 条路由规则的 siteIds 必须是非空整数数组"
                ));
            }
        };
        if raw_sites.is_empty() {
            return Err(format!("第 {rule_no} 条路由规则的 siteIds 不能为空"));
        }
        let mut site_ids: Vec<i64> = Vec::new();
        for site in raw_sites {
            let id = match site.as_i64() {
                Some(id) if id > 0 => id,
                _ => {
                    return Err(format!("第 {rule_no} 条路由规则的 siteIds 必须全为正整数"));
                }
            };
            if !site_ids.contains(&id) {
                site_ids.push(id);
            }
        }
        if site_ids.len() > MAX_ROUTING_RULE_SITES {
            return Err(format!(
                "第 {rule_no} 条路由规则的站点数超过 {MAX_ROUTING_RULE_SITES} 上限"
            ));
        }
        rules.push(RoutingRule {
            agent_label: label,
            site_ids,
        });
    }
    Ok(rules)
}

/// M46-S7：查某 agent 命中的规则限定站点。
///
/// `Some(sites)` = 命中（`sites` 可能为空 allowlist：规则引用的站点全被剥离后
/// 仍保留，见 `resolve_routing_rules`）；`None` = 未命中，走全局加权。
/// 空 label（legacy 无 label 请求）恒为 `None`——没有身份就无法被按身份限制。
///
/// DEBUG-G7 P2-G3（显性声明，不得静默）：空 label 即 legacy 单令牌（无 label 的
/// 旧令牌）**永远不命中任何规则**，返回 `None` = 全局加权——这是有意的兼容
/// 行为，不是“规则没配好”：legacy 令牌不受任何规则限制。
pub fn routing_allowed_sites<'a>(rules: &'a [RoutingRule], agent_label: &str) -> Option<&'a [i64]> {
    if agent_label.is_empty() {
        return None;
    }
    rules
        .iter()
        .find(|r| r.agent_label == agent_label)
        .map(|r| r.site_ids.as_slice())
}

/// M46-S7：剥离不存在站点（纯函数）。
///
/// 「不存在」= 不在调用方给的已知站点 id 集合里（网关启动时由 sites 表算出，
/// 不是路由表缺席——路由表缺席可能是暂无可用 key 的运行态）。
/// 返回（有效规则，未知条目 `[(agentLabel, siteId)]`）；未知条目按规则顺序、
/// 站序输出（事件顺序确定）。剥离后 `site_ids` 为空的规则**保留**为空
/// allowlist（命中后候选恒空 ⇒ 404），不静默消失成「未命中」。
pub fn resolve_routing_rules(
    rules: Vec<RoutingRule>,
    known_site_ids: &HashSet<i64>,
) -> (Vec<RoutingRule>, Vec<(String, i64)>) {
    let mut effective: Vec<RoutingRule> = Vec::with_capacity(rules.len());
    let mut unknown: Vec<(String, i64)> = Vec::new();
    for rule in rules {
        let mut kept: Vec<i64> = Vec::new();
        for site_id in rule.site_ids {
            if known_site_ids.contains(&site_id) {
                kept.push(site_id);
            } else {
                unknown.push((rule.agent_label.clone(), site_id));
            }
        }
        effective.push(RoutingRule {
            agent_label: rule.agent_label,
            site_ids: kept,
        });
    }
    (effective, unknown)
}

/// M46-S7：按站点集合过滤候选（纯函数，保持输入顺序）。
///
/// `allowed` 为 `None` ⇒ 原样返回（未命中规则，全局加权）。
/// 只操作 handler 传来的 `Vec<&Upstream>`，不碰 `RouteTable` 的任何函数。
pub fn filter_upstreams_by_sites<'a>(
    candidates: Vec<&'a Upstream>,
    allowed: Option<&[i64]>,
) -> Vec<&'a Upstream> {
    let Some(allowed) = allowed else {
        return candidates;
    };
    candidates
        .into_iter()
        .filter(|u| allowed.contains(&u.site_id))
        .collect()
}

/// DELIVERY-P2-10：按用户配置的优先级排备用顺序（纯函数）。
///
/// DEBUG-G7 P2-G2（语义澄清，不改首选行为）：`priority`（规则 `siteIds` 顺序）
/// **只排备用尾巴**——首选仍由加权轮转 / EWMA / 探针定出，本函数不动它。界面
/// 上“优先级”一词不得被理解成“首选顺序”：把某站排在 `siteIds` 首位，不会让它
/// 成为首选，只会让它在首选失败后第一个被尝试。
///
/// `rest` 是「首选之后」的候选：首选已由加权轮转 / EWMA / 探针定出，本函数不动它，
/// 只排它之后的备用尝试顺序。`priority` 是用户配置的站点顺序——当前唯一来源是
/// 命中 agent 的路由规则 `siteIds` 数组顺序（网关 handler 在过滤后调用本函数；
/// 未命中规则时 handler 根本不调用，顺序与今天相同）。
///
/// 排序：`priority` 里出现过的站点按其在数组里的下标升序；未出现的站点排在已出现
/// 之后，且彼此保持输入顺序；同站多 key（同一 `site_id` 的多个候选）同 rank，
/// 彼此顺序不变（站内 key 轮换顺序不被打乱）。
///
/// 只重排、不增删：`priority` 里有但候选里没有的站点不会凭空出现；候选里有但
/// `priority` 里没有的站点不会被丢弃（只排后面）。于是「切换不得去用户没配过的档位」
/// 在本层由调用方（规则过滤）与本函数共同保证：过滤限定集合，本函数限定顺序。
/// 注意与 [`filter_upstreams_by_sites`] 的分工：过滤保持输入顺序（不按规则重排），
/// 优先级只在网关的尝试顺序层生效，不改变候选集本身。
pub fn reorder_failover_tail<'a>(rest: Vec<&'a Upstream>, priority: &[i64]) -> Vec<&'a Upstream> {
    if priority.is_empty() || rest.len() < 2 {
        return rest;
    }
    let mut keyed: Vec<(usize, usize, &'a Upstream)> = rest
        .into_iter()
        .enumerate()
        .map(|(index, upstream)| {
            let rank = priority
                .iter()
                .position(|id| *id == upstream.site_id)
                .unwrap_or(usize::MAX);
            (rank, index, upstream)
        })
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    keyed.into_iter().map(|(_, _, upstream)| upstream).collect()
}

/// 余额健康度档位：0 = 有余额，1 = 未知（`None` 或 `NaN`），2 = 已耗尽。
///
/// `NaN` 归入「未知」而不是「已耗尽」：`NaN` 表示**算不出来**，不是「没钱了」。
/// M40-S2：健康档位的**字符串**视图（DTO 用）。
///
/// **唯一出处**：与 `health_rank` 同一个判据——三档 `healthy(0) / unknown(1) / exhausted(2)`。
/// 禁止在 DTO 里复制判据（否则排序与展示会分叉）。
pub(crate) fn health_label(balance: Option<f64>) -> &'static str {
    match health_rank(balance) {
        0 => "healthy",
        1 => "unknown",
        _ => "exhausted",
    }
}

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
        Self::of_with_latency(u, u.latency_ms)
    }

    /// M46-S2：与 `of` 同一套键，只把延迟一项换成调用方给的有效延迟
    /// （实测 EWMA 或回退后的静态值）。`None` = 延迟缺失（排最后），
    /// 与 `of` 的 `latency_missing` 语义逐字一致。
    fn of_with_latency(u: &Upstream, latency_ms: Option<u64>) -> Self {
        let (rate_missing, rate) = match u.rate {
            Some(x) if !x.is_nan() => (false, x),
            _ => (true, 0.0),
        };
        let (latency_missing, latency) = match latency_ms {
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

/// DEBUG P1-2：HalfOpen 探针「在飞」标记的过期时限（见 `Breaker::probe_in_flight`）。
/// 正常探针在响应头到达时即清除（秒级）：2xx / failover 结果经 `record_*`，
/// 非 failover 非 2xx 结果（DEBUG P2-1）经 `release_half_open_probe`；
/// 时限只给「取走后没走到发送」的泄漏标记一个自愈上界，不参与 Closed/Open 判定。
const PROBE_IN_FLIGHT_TTL: Duration = Duration::from_secs(600);

/// 按 `site_id` 计数的连续失败熔断。
#[derive(Clone, Debug, Default)]
pub struct Breaker {
    policy: BreakerPolicy,
    entries: HashMap<BreakerKey, Entry>,
    /// P2-8 / DEBUG-REPORT-v3 §2-8：HalfOpen 探针已放出的站点。冷却一过所有并发
    /// 请求都会看到 HalfOpen（`state` 只读不改），不限流就全部去试坏上游。第一个
    /// 放进探针的请求在这里标记，其余看到标记即跳过，等探针结果回来
    /// （`record_success` / `record_failure` 清除）。
    ///
    /// DEBUG P1-2：标记带时间戳、过期自愈。探针被取走后若请求没走到真实发送
    /// （预算/限流跳过、首候选成功提前返回、cap 截断……），没有任何
    /// `record_*` 会回来清标记，旧的 `HashSet` 会让该键永久报 HalfOpen 却再也
    /// 取不到探针。过期只放宽「在飞」互斥的**时限**，不改 Closed/Open 判定：
    /// 过期后下一次 `try_take_half_open_probe` 可再放一个探针；迟到的旧探针结果
    /// 回来时按结果分流清除：2xx / failover 经 `record_*`，非 failover 非 2xx
    /// 经 `release_half_open_probe`（`remove` 对过期/未过期一视同仁）。
    /// 时限取 10 分钟：探针在飞的合法上限是「响应头耗时」——全局默认
    /// connect 5s + read 240s ≈ 245s，10 分钟留有余量，正常探针（秒级）不受影响。
    probe_in_flight: HashMap<BreakerKey, Instant>,
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
            entries: HashMap::new(),
            probe_in_flight: HashMap::new(),
        }
    }

    /// 记一次失败。返回**本次调用之后**的状态：达到阈值即 `Open`。
    ///
    /// 调用方**只应**在 `should_failover(status)` 为真时调用——否则一个 400 就能把健康上游打成 `Open`。
    ///
    /// `policy.threshold == 0` 的含义是「首次失败即打开」（`0 >= 0`），它不是一个「关闭熔断」的开关。
    pub fn record_failure(&mut self, key: &BreakerKey, now: Instant) -> BreakerState {
        // P2-8：探针结果回来（失败），清除「探针在飞」标记。
        self.probe_in_flight.remove(key);
        let entry = self.entries.entry(key.clone()).or_default();
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
    pub fn record_success(&mut self, key: &BreakerKey, _now: Instant) {
        self.entries.remove(key);
        // P2-8：探针成功，清除「探针在飞」标记。
        self.probe_in_flight.remove(key);
    }

    /// DEBUG P2-1：只释放 HalfOpen 探针标记，**不动 `entries`**。
    ///
    /// 供主循环「非 failover 且非 2xx」分支调用：这类结果按 P1-1 的三段互斥
    /// 既不喂失败也不记成功，故不能走 `record_*`，但探针本身已经回来，
    /// 标记再留着就会等到 TTL（最长 600s）才可再探。对非探针键是无害 no-op
    /// （`remove` 一个不存在的键），且与 `record_*` 的 remove 共享同一竞态
    /// 模型（迟到结果删掉后来探针的标记这一竞态本来就存在，不新引入）。
    pub fn release_half_open_probe(&mut self, key: &BreakerKey) {
        self.probe_in_flight.remove(key);
    }

    /// 只读查询，**不**改状态。`Open` 且冷却已过 ⇒ `HalfOpen`（允许一个探活请求）。
    /// M40-S2：该站点**任意模型**上最坏的那个熔断态（`Open > HalfOpen > Closed`）。
    ///
    /// 为什么需要聚合：熔断是 `(site, model)` 粒度，而状态面板的候选**没有**模型维度；
    /// 用户看到「这个站点被跳过」时，关心的是「有没有模型在熔断」，不是某一个模型。
    /// **只读**：不推进冷却、不放出探针（与 [`Self::state`] 同语义）。
    pub(crate) fn worst_state_for_site(&self, site_id: i64, now: Instant) -> BreakerState {
        let mut worst = BreakerState::Closed;
        for key in self.entries.keys().filter(|k| k.0 == site_id) {
            match self.state(key, now) {
                BreakerState::Open => return BreakerState::Open,
                BreakerState::HalfOpen => worst = BreakerState::HalfOpen,
                BreakerState::Closed => {}
            }
        }
        worst
    }

    pub fn state(&self, key: &BreakerKey, now: Instant) -> BreakerState {
        let Some(entry) = self.entries.get(key) else {
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
    /// 不会全部涌向坏上游。探针结果回来后按结果分流清除：2xx / failover 由
    /// `record_success` / `record_failure`，非 failover 非 2xx 由
    /// `release_half_open_probe`（只清标记，不动熔断计数）。
    ///
    /// DEBUG P1-2：标记过期自愈（见 `probe_in_flight` 字段注释）。过期标记先被
    /// 清掉再放新探针，因此「探针被取走却没走到发送」不再永久卡死；时限内
    /// 的互斥语义与旧 `HashSet` 逐字相同（第二并发请求仍为 `false`）。
    pub fn try_take_half_open_probe(&mut self, key: &BreakerKey, now: Instant) -> bool {
        if self.state(key, now) != BreakerState::HalfOpen {
            return false;
        }
        // 先清过期标记：不然一个泄漏的旧标记会挡住所有后续探针。
        self.probe_in_flight
            .retain(|_, taken| now.saturating_duration_since(*taken) < PROBE_IN_FLIGHT_TTL);
        if self.probe_in_flight.contains_key(key) {
            return false;
        }
        self.probe_in_flight.insert(key.clone(), now);
        true
    }
}

/// 每站保护策略（M39-S3 §4.2）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SiteGuardPolicy {
    /// 每站同时在飞的上游请求上限。`0` ⇒ 不限（不推荐）。
    pub max_concurrency: usize,
    /// 每站每秒允许的新请求数。`0` ⇒ 不限速。
    pub rate_limit_per_sec: u32,
    /// 令牌桶的额外容量（M46-S3）。`0` ⇒ 关（与今天逐字相同）。
    /// 桶容量 = `rate_limit_per_sec + rate_burst`；每秒补充仍是
    /// `rate_limit_per_sec`，burst 只抬高上限、不提高补充速率。
    pub rate_burst: u32,
}

impl Default for SiteGuardPolicy {
    fn default() -> Self {
        Self {
            max_concurrency: 8,
            rate_limit_per_sec: 0,
            rate_burst: 0,
        }
    }
}

#[derive(Debug)]
pub enum GuardOutcome {
    /// 拿到并发许可（可能还拿了令牌）；`lease` 必须被 drop 归还。
    Admitted(SiteLease),
    /// 并发满了 ⇒ 本地拒绝。
    ConcurrencyLimited,
    /// 令牌桶空了 ⇒ 本地拒绝。
    RateLimited,
}

/// 每站一个：并发计数 + 令牌桶（多 key **共享**，见 §4.3）。
#[derive(Debug)]
pub struct SiteGuard {
    policy: SiteGuardPolicy,
    in_flight: Arc<AtomicUsize>,
    bucket: Mutex<TokenBucket>,
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last: Instant,
}

/// 一次并发许可。`Drop` 时归还（panic 也归还）。
#[derive(Debug)]
pub struct SiteLease {
    in_flight: Arc<AtomicUsize>,
}

impl Drop for SiteLease {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, AtomicOrdering::SeqCst);
    }
}

impl SiteGuard {
    pub fn new(policy: SiteGuardPolicy, now: Instant) -> Self {
        Self {
            policy,
            in_flight: Arc::new(AtomicUsize::new(0)),
            bucket: Mutex::new(TokenBucket {
                // M46-S3：初始桶是满的（满 = rate + burst，与今天「初始满 rate」
                // 同一规则的延伸；见 spec §4.2）。rate = 0 时桶分支根本不读它。
                tokens: policy.rate_limit_per_sec as f64 + policy.rate_burst as f64,
                last: now,
            }),
        }
    }

    pub fn policy(&self) -> SiteGuardPolicy {
        self.policy
    }

    /// **非阻塞**：要么立刻拿到，要么立刻返回拒绝。
    pub fn try_admit(&self, now: Instant) -> GuardOutcome {
        // ① 并发
        if self.policy.max_concurrency > 0 {
            let prev = self.in_flight.fetch_add(1, AtomicOrdering::SeqCst);
            if prev >= self.policy.max_concurrency {
                self.in_flight.fetch_sub(1, AtomicOrdering::SeqCst);
                return GuardOutcome::ConcurrencyLimited;
            }
        } else {
            self.in_flight.fetch_add(1, AtomicOrdering::SeqCst);
        }

        // ② 令牌桶（`0` ⇒ 不建桶 = 恒放行）
        if self.policy.rate_limit_per_sec > 0 {
            let mut b = match self.bucket.lock() {
                Ok(b) => b,
                Err(_) => {
                    // 锁中毒：放行（可用性优先），不把并发许可漏掉。
                    return GuardOutcome::Admitted(SiteLease {
                        in_flight: Arc::clone(&self.in_flight),
                    });
                }
            };
            // M46-S3：容量 = rate + burst；补充速率仍是 rate（连续补充，
            // 按真实流逝时间乘 rate，与今天同口径）。burst 只抬上限。
            let cap = self.policy.rate_limit_per_sec as f64 + self.policy.rate_burst as f64;
            let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
            b.tokens = (b.tokens + elapsed * self.policy.rate_limit_per_sec as f64).min(cap);
            b.last = now;
            if b.tokens < 1.0 {
                drop(b);
                self.in_flight.fetch_sub(1, AtomicOrdering::SeqCst);
                return GuardOutcome::RateLimited;
            }
            b.tokens -= 1.0;
        }

        GuardOutcome::Admitted(SiteLease {
            in_flight: Arc::clone(&self.in_flight),
        })
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
/// DEBUG-G7 P3-D1 命名陷阱，注释澄清、不改名：本函数对 5xx 返回 true，
/// 但那只是**熔断语义**（该 (站点, 模型) 记一次失败、喂 EWMA），**不是重放语义**——
/// 网关主循环只对 429 / 连接层失败重放下一候选，5xx 不重放。
/// 读到 `should_failover(status) == true` 时不得推断“会换候选重试”。
pub fn should_failover(status: u16) -> bool {
    status == 429 || (500..=599).contains(&status)
}

/// 熔断键（M39-S3 §4.4）：`(site_id, model)`。
///
/// - 有 model 的请求 ⇒ `(site_id, Some(model))`：站点 A 的 `gpt-x` 失败**不**熔断 A 的 `claude-y`；
/// - 无 model 的请求（`GET /v1/models`、无 body）⇒ `(site_id, None)`，**仍按站点熔断**，
///   与 M39-S3 之前的行为逐字相同。
pub type BreakerKey = (i64, Option<String>);

/// 按站点熔断的键（无 model 请求 / 兼容路径）。
pub fn site_key(site_id: i64) -> BreakerKey {
    (site_id, None)
}

/// 按 (站点, 模型) 熔断的键。
pub fn model_key(site_id: i64, model: &str) -> BreakerKey {
    (site_id, Some(model.to_string()))
}

/// 参与本次请求的候选（M39-S3 §4.1）。
///
/// `probe = true` 表示「这是 HalfOpen 冷却后的探针」——**必须优先尝试**：
/// 如果探针被加权轮转跳过，这个熔断键就永远恢复不了（冷却到点后每次都轮不到它）。
#[derive(Clone, Copy, Debug)]
pub struct Candidate<'a> {
    pub upstream: &'a Upstream,
    pub probe: bool,
}

/// 一个候选的轮转权重（M39-S3 §4.1）。
///
/// `rate` 是站点倍率；`None`（未知）按 1.0 处理。
/// 权重 = `1/max(rate, 0.01)`：**倍率越低（越便宜）权重越高**。
/// 这是「组内未归一」的原始 unit，归一在 [`weighted_pick`] 里做（需要组内最小值）。
///
/// 注意 `rate = Some(0.0)`（免费分组）**不是**未知：按公式应得 `1/0.01 = 100`
/// （最高权重），而不是落到 1.0 被长期冷落（B-224 P2 修复；此前 `0.0`
/// 走 `_ => 1.0` 分支，与 spec 公式不一致）。
pub fn rotation_weight(rate: Option<f64>) -> f64 {
    let r = match rate {
        Some(x) if x.is_finite() && x > 0.0 => x,
        Some(x) if x.is_finite() && x == 0.0 => 0.01,
        _ => 1.0,
    };
    1.0 / r.max(0.01)
}

/// 轮转计数器（每个网关实例一个）。
#[derive(Debug, Default)]
pub struct RoundRobinState {
    cursor: u64,
}

impl RoundRobinState {
    /// 取当前值并自增（`wrapping_add`：u64 溢出现实中不可达，但行为要确定）。
    ///
    /// 名字按 spec 冻结为 `next`；它不是迭代器（不产出序列），只是「取号 + 前进」。
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> u64 {
        let v = self.cursor;
        self.cursor = self.cursor.wrapping_add(1);
        v
    }
}

/// 从前 `top_n` 个候选里按权重选一个。**纯函数**：给定同样的
/// `(candidates, top_n, cursor)` 必得同样的结果（这是可测性的基础）。
///
/// 算法（完整版见 `docs/specs/M39-S3-负载均衡与上游保护.md` §4.1）：
/// 有 `probe` 就直接返回它且**不读 cursor**（否则探针可能永远轮不到，冷却恢复不了）；
/// 否则取前 `top_n` 个（`0` 视为 1）；只剩一个就直接返回且不读 cursor（单候选与今天逐字相同）；
/// 其余**按站点归一**：head 先按 `site_id` 分组（保持首次出现顺序），站点权重取该站
/// `rate` 的 `unit = 1/max(rate, 0.01)`，以组内最小 unit 归一（clamp 到 `[1, 100]`）建槽位表，
/// 用 `cursor % slots.len()` 选站点；站内 key 按 `(cursor / slots.len()) % key_count` 轮换。
///
/// 按站点归一而不是按 key 计权重（B-224 P2-5 决策，2026-10-24）：`rate` 是站点倍率
/// （同站各 key 相同），guard 与熔断也按站点共享，站点才是容量单位；按 key 计会让
/// 2 key 站点与倍率无关地占 2 份槽位，guard 饱和时只会多出本地 429，而不是多出容量。
pub fn weighted_pick<'a>(
    candidates: &[Candidate<'a>],
    top_n: usize,
    cursor: u64,
) -> Option<&'a Upstream> {
    if candidates.is_empty() {
        return None;
    }
    if let Some(probe) = candidates.iter().find(|c| c.probe) {
        return Some(probe.upstream);
    }
    let n = top_n.max(1).min(candidates.len());
    let head = &candidates[..n];
    if head.len() == 1 {
        return Some(head[0].upstream);
    }
    // 按站点分组：(site_id, 站点 unit, 该站在 head 内的 key 列表)。
    // 同站各 key 的 rate 相同（站点倍率），取首个即可。
    let mut sites: Vec<(i64, f64, Vec<&Upstream>)> = Vec::new();
    for c in head {
        let sid = c.upstream.site_id;
        match sites.iter_mut().find(|(id, _, _)| *id == sid) {
            Some((_, _, keys)) => keys.push(c.upstream),
            None => sites.push((sid, rotation_weight(c.upstream.rate), vec![c.upstream])),
        }
    }
    let base = sites
        .iter()
        .map(|(_, u, _)| *u)
        .fold(f64::INFINITY, f64::min);
    let weights: Vec<u64> = sites
        .iter()
        .map(|(_, u, _)| ((u / base).round() as i64).clamp(1, 100) as u64)
        .collect();
    let mut slots: Vec<usize> = Vec::new();
    for (i, w) in weights.iter().enumerate() {
        for _ in 0..*w {
            slots.push(i);
        }
    }
    let site_idx = slots[(cursor % slots.len() as u64) as usize];
    let keys = &sites[site_idx].2;
    // 站内轮换与站点选择解耦：单站时 slots.len() == 1，退化为 cursor 交替（与旧行为一致）；
    // 多站时每过一轮槽位表站内 key 前进一步，两把 key 都轮得到。
    let key_idx = ((cursor / slots.len() as u64) % keys.len() as u64) as usize;
    Some(keys[key_idx])
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
            key_id: None,
            timeout_ms: None,
        }
    }

    #[test]
    fn rotation_weight_gives_free_sites_the_spec_maximum() {
        // B-224 P2：`rate = Some(0.0)`（免费分组）按公式 `1/max(rate, 0.01)`
        // 应得 100，而不是此前落到 1.0 被长期冷落。
        assert_eq!(rotation_weight(Some(0.0)), 100.0);
        assert_eq!(rotation_weight(Some(0.01)), 100.0);
        assert_eq!(rotation_weight(Some(1.0)), 1.0);
        assert_eq!(rotation_weight(None), 1.0);
        assert_eq!(rotation_weight(Some(f64::NAN)), 1.0);
        assert_eq!(rotation_weight(Some(-1.0)), 1.0);
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
        assert_eq!(b.record_failure(&site_key(1), t0), BreakerState::Closed);
        assert_eq!(b.record_failure(&site_key(1), t0), BreakerState::Closed);
        // 第三次达阈值 → Open，opened_at 设为 t0
        assert_eq!(b.record_failure(&site_key(1), t0), BreakerState::Open);
        assert_eq!(b.state(&site_key(1), t0), BreakerState::Open);
    }

    #[test]
    fn record_failure_during_cooldown_does_not_refresh_opened_at() {
        // P1-3 核心：Open 后冷却未过时再次失败，opened_at 不得续期。
        // 旧实现每次失败都 opened_at=Some(now)，请求间隔 < 冷却期时冷却永不到期。
        let mut b = Breaker::new(BreakerPolicy::default());
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure(&site_key(1), t0);
        }
        // 冷却期内（t0+30s）再失败 —— opened_at 应保持 t0，不刷成 t0+30s
        let t1 = t0 + Duration::from_secs(30);
        b.record_failure(&site_key(1), t1);
        assert_eq!(b.state(&site_key(1), t1), BreakerState::Open);
        // t0+61s 冷却应到期 → HalfOpen。
        // 若 opened_at 被续到 t1（旧 bug），则 t1+61s 才到期，t0+61s 仍 Open。
        let t2 = t0 + Duration::from_secs(61);
        assert_eq!(
            b.state(&site_key(1), t2),
            BreakerState::HalfOpen,
            "冷却应从首次打开算起，不被冷却期内的失败续期"
        );
    }

    #[test]
    fn state_transitions_to_half_open_after_cooldown() {
        let mut b = Breaker::new(BreakerPolicy::default());
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure(&site_key(1), t0);
        }
        assert_eq!(b.state(&site_key(1), t0), BreakerState::Open);
        assert_eq!(
            b.state(&site_key(1), t0 + Duration::from_secs(61)),
            BreakerState::HalfOpen
        );
    }

    #[test]
    fn record_failure_after_cooldown_refreshes_opened_at() {
        // HalfOpen 探针失败 → opened_at 重置（探针失败重新冷却，这是合理意图）
        let mut b = Breaker::new(BreakerPolicy::default());
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure(&site_key(1), t0);
        }
        let t1 = t0 + Duration::from_secs(61);
        assert_eq!(b.state(&site_key(1), t1), BreakerState::HalfOpen);
        // 探针失败 —— opened_at 应刷到 t1
        b.record_failure(&site_key(1), t1);
        let t2 = t1 + Duration::from_secs(30);
        assert_eq!(b.state(&site_key(1), t2), BreakerState::Open);
        let t3 = t1 + Duration::from_secs(61);
        assert_eq!(b.state(&site_key(1), t3), BreakerState::HalfOpen);
    }

    // ============================================================ M46-S2：EWMA

    #[test]
    fn ewma_update_first_sample_is_the_sample() {
        // 首次样本直接作为初值，不是 alpha × 样本（0.2 × 200 = 40 是错的）。
        assert_eq!(ewma_update(None, 200), 200.0);
        assert_eq!(ewma_update(None, 0), 0.0);
    }

    #[test]
    fn ewma_update_caps_single_outlier_to_five_times_previous() {
        // DEBUG-G7 P2-G1：单次离群样本（100ms 基线后采到 10000ms）截断后 EWMA
        // 最多涨到 180（+80%），而不是无截断的 2080。
        assert!((ewma_update(Some(100.0), 10_000) - 180.0).abs() < 1e-9);
        // 正常样本不受影响；下跌不截断（本身有界）。
        assert!((ewma_update(Some(100.0), 200) - 120.0).abs() < 1e-9);
        assert!((ewma_update(Some(100.0), 10) - 82.0).abs() < 1e-9);
        // 0 基线不钉死：下一个真实样本能把 EWMA 拉起来。
        assert!((ewma_update(Some(0.0), 200) - 40.0).abs() < 1e-9);
    }

    #[test]
    fn ewma_update_applies_alpha_0_2() {
        assert_eq!(EWMA_ALPHA, 0.2);
        assert!((ewma_update(Some(100.0), 200) - 120.0).abs() < 1e-9);
        assert!((ewma_update(Some(120.0), 200) - 136.0).abs() < 1e-9);
        assert!((ewma_update(Some(136.0), 0) - 108.8).abs() < 1e-9);
    }

    fn reorder_sites(
        ups: &[Upstream],
        probes: &[bool],
        ewma: &dyn Fn(i64) -> Option<f64>,
    ) -> Vec<i64> {
        let candidates: Vec<Candidate<'_>> = ups
            .iter()
            .zip(probes.iter())
            .map(|(u, p)| Candidate {
                upstream: u,
                probe: *p,
            })
            .collect();
        reorder_by_effective_latency(candidates, ewma)
            .iter()
            .map(|c| c.upstream.site_id)
            .collect()
    }

    #[test]
    fn reorder_by_effective_latency_matches_static_order_without_ewma() {
        // 回退用例：无 EWMA 时重排输出必须与 RouteTable::candidates 逐字相等。
        let a = up(1, Some(1.0), Some(10.0), Some(200));
        let b = up(2, Some(0.5), Some(10.0), Some(10));
        let c = up(3, Some(1.0), None, Some(5));
        let d = up(4, Some(1.0), Some(0.0), Some(1));
        let ups = vec![a, b, c, d];
        let route = RouteTable::new(ups.clone());
        let expected: Vec<i64> = route
            .candidates("gpt-5.6")
            .iter()
            .map(|u| u.site_id)
            .collect();
        let got = reorder_sites(&ups, &[false, false, false, false], &|_| None);
        assert_eq!(got, expected, "无 EWMA 时重排不得改变静态顺序");
    }

    #[test]
    fn reorder_by_effective_latency_substitutes_ewma_for_static() {
        let a = up(1, Some(1.0), Some(10.0), Some(10));
        let b = up(2, Some(1.0), Some(10.0), Some(200));
        let ups = vec![a, b];
        let got = reorder_sites(&ups, &[false, false], &|site| match site {
            1 => Some(300.0),
            2 => Some(50.0),
            _ => None,
        });
        assert_eq!(got, vec![2, 1], "EWMA 必须替换静态延迟参与排序");
    }

    #[test]
    fn reorder_by_effective_latency_falls_back_to_static_when_missing() {
        let a = up(1, Some(1.0), Some(10.0), Some(10));
        let b = up(2, Some(1.0), Some(10.0), Some(10));
        let ups = vec![a, b];
        // A 有 EWMA 300，B 无 EWMA、静态 10 ⇒ B 在前（回退，不是按缺失排最后）。
        let got = reorder_sites(&ups, &[false, false], &|site| match site {
            1 => Some(300.0),
            _ => None,
        });
        assert_eq!(got, vec![2, 1]);
        // 两边都缺失 ⇒ 静态平局 ⇒ site_id 兜底。
        let got = reorder_sites(&ups, &[false, false], &|_| None);
        assert_eq!(got, vec![1, 2]);
    }

    #[test]
    fn reorder_by_effective_latency_keeps_rate_and_health_precedence() {
        // 便宜慢站仍排在贵快站前面（倍率档位在延迟之前）。
        let cheap_slow = up(1, Some(0.5), Some(10.0), Some(10));
        let pricey_fast = up(2, Some(2.0), Some(10.0), Some(10));
        let ups = vec![cheap_slow, pricey_fast];
        let got = reorder_sites(&ups, &[false, false], &|site| match site {
            1 => Some(500.0),
            2 => Some(5.0),
            _ => None,
        });
        assert_eq!(got, vec![1, 2], "EWMA 不得推翻倍率档位");
        // 余额耗尽快站仍排在健康慢站后面（健康档位在延迟之前）。
        let exhausted_fast = up(1, Some(1.0), Some(0.0), Some(10));
        let healthy_slow = up(2, Some(1.0), Some(10.0), Some(10));
        let ups = vec![exhausted_fast, healthy_slow];
        let got = reorder_sites(&ups, &[false, false], &|site| match site {
            1 => Some(5.0),
            2 => Some(500.0),
            _ => None,
        });
        assert_eq!(got, vec![2, 1], "EWMA 不得推翻健康档位");
    }

    #[test]
    fn reorder_by_effective_latency_preserves_probe_flags() {
        let slow_probe = up(1, Some(1.0), Some(10.0), Some(10));
        let fast_plain = up(2, Some(1.0), Some(10.0), Some(200));
        let ups = [slow_probe, fast_plain];
        let candidates: Vec<Candidate<'_>> = vec![
            Candidate {
                upstream: &ups[0],
                probe: true,
            },
            Candidate {
                upstream: &ups[1],
                probe: false,
            },
        ];
        let reordered = reorder_by_effective_latency(candidates, &|site| match site {
            1 => Some(300.0),
            2 => Some(50.0),
            _ => None,
        });
        assert_eq!(reordered.len(), 2);
        // 快站排前，但探针旗标仍绑在慢站身上（不剥离、不重建）。
        assert_eq!(reordered[0].upstream.site_id, 2);
        assert!(!reordered[0].probe);
        assert_eq!(reordered[1].upstream.site_id, 1);
        assert!(reordered[1].probe);
    }

    #[test]
    fn reorder_by_effective_latency_rounds_ewma_to_milliseconds() {
        // 10.4 与 10.49 都舍入到 10ms ⇒ 平局 ⇒ site_id 兜底（毫秒粒度是设计）。
        let a = up(2, Some(1.0), Some(10.0), Some(10));
        let b = up(1, Some(1.0), Some(10.0), Some(10));
        let ups = vec![a, b];
        let got = reorder_sites(&ups, &[false, false], &|site| match site {
            2 => Some(10.4),
            1 => Some(10.49),
            _ => None,
        });
        assert_eq!(got, vec![1, 2]);
    }

    #[test]
    fn record_success_closes_breaker() {
        let mut b = Breaker::new(BreakerPolicy::default());
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure(&site_key(1), t0);
        }
        assert_eq!(b.state(&site_key(1), t0), BreakerState::Open);
        b.record_success(&site_key(1), t0);
        assert_eq!(b.state(&site_key(1), t0), BreakerState::Closed);
    }

    #[test]
    fn try_take_half_open_probe_lets_only_one_probe_through() {
        // P2-8 / DEBUG-REPORT-v3 §2-8：冷却一过所有并发请求都看到 HalfOpen（`state`
        // 只读不改），不限流就全部涌向坏上游。`try_take_half_open_probe` 只让第一个
        // 拿到探针，其余看到标记即跳过；探针结果回来后清除标记。
        let mut b = Breaker::new(BreakerPolicy::default());
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure(&site_key(1), t0);
        }
        let t1 = t0 + Duration::from_secs(61);
        assert_eq!(b.state(&site_key(1), t1), BreakerState::HalfOpen);

        assert!(
            b.try_take_half_open_probe(&site_key(1), t1),
            "第一个 HalfOpen 探针应被放行"
        );
        assert!(
            !b.try_take_half_open_probe(&site_key(1), t1),
            "探针在飞时，第二个并发请求不得再放探针（P2-8）"
        );

        // 探针失败 ⇒ 清除标记 + 重新冷却；冷却过后可再放探针（标记已清）
        b.record_failure(&site_key(1), t1);
        let t2 = t1 + Duration::from_secs(61);
        assert_eq!(b.state(&site_key(1), t2), BreakerState::HalfOpen);
        assert!(
            b.try_take_half_open_probe(&site_key(1), t2),
            "探针结果回来后标记清除，冷却过后可再放探针"
        );
    }

    #[test]
    fn half_open_probe_mark_expires_without_a_result() {
        // DEBUG P1-2：探针被取走后没有任何 record_* 回来（预算/限流跳过、
        // 首候选成功提前返回等），旧 HashSet 会让该键永久 HalfOpen 却取不到探针。
        // 新行为：时限内仍互斥，时限过后可再放探针；state 本身仍是 HalfOpen。
        let mut b = Breaker::new(BreakerPolicy::default());
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure(&site_key(1), t0);
        }
        let t1 = t0 + Duration::from_secs(61);
        assert_eq!(b.state(&site_key(1), t1), BreakerState::HalfOpen);
        assert!(b.try_take_half_open_probe(&site_key(1), t1));
        // 时限内：第二个并发请求仍被挡（互斥语义不变）。
        assert!(
            !b.try_take_half_open_probe(&site_key(1), t1 + Duration::from_secs(599)),
            "过期前探针仍在飞，不得再放第二个探针"
        );
        // 时限过后、且无任何结果回来：标记自愈，可再放探针。
        let t_expired = t1 + Duration::from_secs(601);
        assert_eq!(
            b.state(&site_key(1), t_expired),
            BreakerState::HalfOpen,
            "过期只清标记，不改熔断态"
        );
        assert!(
            b.try_take_half_open_probe(&site_key(1), t_expired),
            "泄漏的探针标记过期后应可再放探针"
        );
    }

    #[test]
    fn release_half_open_probe_clears_mark_without_touching_entries() {
        // DEBUG P2-1：释放只删探针标记，不动熔断 entries——state 仍为 HalfOpen
        // （若误清 entries，state 会退回 Closed；若误攒失败，冷却会刷新）。
        let mut b = Breaker::new(BreakerPolicy::default());
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure(&site_key(1), t0);
        }
        let t1 = t0 + Duration::from_secs(61);
        assert_eq!(b.state(&site_key(1), t1), BreakerState::HalfOpen);
        assert!(b.try_take_half_open_probe(&site_key(1), t1));
        assert!(
            !b.try_take_half_open_probe(&site_key(1), t1),
            "探针在飞时不得再放第二个探针"
        );
        // 对非探针键释放是无害 no-op：不改 site1 的标记，也不凭空建 entries。
        b.release_half_open_probe(&site_key(2));
        assert_eq!(
            b.state(&site_key(2), t1),
            BreakerState::Closed,
            "非探针键释放不得凭空建熔断条目"
        );
        assert!(
            !b.try_take_half_open_probe(&site_key(1), t1),
            "释放他键不得放行 site1 的探针"
        );
        // 释放本键：下一次可再取探针，且熔断态仍为 HalfOpen（计数/冷却未动）。
        b.release_half_open_probe(&site_key(1));
        assert_eq!(
            b.state(&site_key(1), t1),
            BreakerState::HalfOpen,
            "释放不得清零熔断计数或刷新冷却"
        );
        assert!(
            b.try_take_half_open_probe(&site_key(1), t1),
            "释放后下一次请求应可再次取探针"
        );
    }

    #[test]
    fn try_take_half_open_probe_is_no_op_for_non_half_open() {
        let mut b = Breaker::new(BreakerPolicy::default());
        let t0 = Instant::now();
        assert!(
            !b.try_take_half_open_probe(&site_key(1), t0),
            "Closed 不放探针"
        );
        for _ in 0..3 {
            b.record_failure(&site_key(1), t0);
        }
        assert!(
            !b.try_take_half_open_probe(&site_key(1), t0),
            "Open（冷却未过）不放探针"
        );
    }

    // ============================================================ M39-S2：available_models / supports_model

    fn upstream_of(site_id: i64, models: &[&str]) -> Upstream {
        Upstream {
            site_id,
            base_url: format!("https://s{site_id}.example.com"),
            key_ref: format!("kr/key/{site_id}/secret"),
            models: models.iter().map(|m| (*m).to_string()).collect(),
            rate: None,
            balance_usd: None,
            latency_ms: None,
            key_id: None,
            timeout_ms: None,
        }
    }

    #[test]
    fn build_route_table_carries_per_site_timeout_verbatim() {
        // M46-S4：SiteFacts.timeout_ms 原样搬进 Upstream，不做 unwrap_or 降级。
        let facts = vec![
            SiteFacts {
                site_id: 1,
                base_url: "http://a.example.com".to_string(),
                models: vec![],
                rate: None,
                balance_usd: None,
                latency_ms: None,
                key_ref: "kr/key/1/secret".to_string(),
                key_id: None,
                timeout_ms: Some(5000),
            },
            SiteFacts {
                site_id: 2,
                base_url: "http://b.example.com".to_string(),
                models: vec![],
                rate: None,
                balance_usd: None,
                latency_ms: None,
                key_ref: "kr/key/2/secret".to_string(),
                key_id: None,
                timeout_ms: None,
            },
        ];
        let table = build_route_table(&facts);
        let all = table.all_candidates();
        assert_eq!(all.len(), 2);
        let by_site: std::collections::HashMap<i64, Option<u64>> =
            all.iter().map(|u| (u.site_id, u.timeout_ms)).collect();
        assert_eq!(by_site[&1], Some(5000), "Some 值原样搬运");
        assert_eq!(by_site[&2], None, "None 保持 None，不降级成数值");
    }

    #[test]
    fn available_models_unions_dedupes_and_sorts() {
        let route = RouteTable::new(vec![
            upstream_of(1, &["b", "a"]),
            upstream_of(2, &["a", "c"]),
        ])
        .with_alias("fast", "c");
        assert_eq!(
            route.available_models(),
            vec!["a", "b", "c", "fast"],
            "并集 + 去重 + 字节序；别名（可服务）要列出"
        );
    }

    #[test]
    fn available_models_includes_only_serviceable_aliases() {
        let route = RouteTable::new(vec![upstream_of(1, &["a"])]).with_alias("old", "retired");
        assert_eq!(route.available_models(), vec!["a"], "不可服务的别名不列");
        assert!(!route.supports_model("old"), "不可服务的别名不路由");
        assert!(route.supports_model("a"));
        assert!(
            !route.supports_model("zzz"),
            "全部目录明确且不含 ⇒ 不可服务"
        );
    }

    #[test]
    fn available_models_for_sites_restricts_to_allowed_sites() {
        // DEBUG-G7 P2-G4：过滤版只算允许站点；别名可服务性也只看允许站点
        // （指向规则外站点的别名不得列出；规则内站点服务的别名照常列出）。
        let route = RouteTable::new(vec![upstream_of(1, &["a", "b"]), upstream_of(2, &["c"])])
            .with_alias("fast", "c")
            .with_alias("slow", "a");
        assert_eq!(
            route.available_models_for_sites(Some(&[1])),
            vec!["a", "b", "slow"],
            "站点 2 的 c 与指向它的 fast 不得漏出"
        );
        assert_eq!(
            route.available_models_for_sites(Some(&[2])),
            vec!["c", "fast"]
        );
        assert_eq!(
            route.available_models_for_sites(None),
            route.available_models(),
            "None 必须与不过滤逐字相同"
        );
        assert!(route.available_models_for_sites(Some(&[99])).is_empty());
    }

    #[test]
    fn available_models_is_empty_for_an_empty_route() {
        assert!(RouteTable::new(vec![]).available_models().is_empty());
    }

    /// 关键语义（M39-S2 §4.1/§4.3）：**空 models = 未知 ⇒ 通配**。
    /// 空目录站点不贡献名字，但它让**任何**模型都「可能可服务」⇒ 不能本地 404。
    #[test]
    fn an_unknown_catalog_site_makes_every_model_maybe_serviceable() {
        let route = RouteTable::new(vec![upstream_of(1, &["a"]), upstream_of(2, &[])]);
        assert_eq!(route.available_models(), vec!["a"], "通配站点不贡献名字");
        assert!(
            route.supports_model("zzz"),
            "有未知目录上游 ⇒ 任何模型都可能可服务（fail-open）"
        );
        assert_eq!(route.candidates("zzz").len(), 1, "候选里就是那个空目录站点");
    }

    #[test]
    fn supports_model_follows_the_same_matching_as_candidates() {
        let route = RouteTable::new(vec![upstream_of(1, &["a"]), upstream_of(2, &["b"])])
            .with_alias("alias-b", "b");
        for model in ["a", "b", "alias-b", "zzz", ""] {
            assert_eq!(
                !route.candidates(model).is_empty(),
                route.supports_model(model),
                "两处判据必须同源：{model}"
            );
        }
    }

    // ============================================================ M46-S7：按 agent 路由规则

    #[test]
    fn parse_routing_rules_accepts_empty_and_valid_json() {
        assert_eq!(parse_routing_rules("").unwrap(), Vec::<RoutingRule>::new());
        assert_eq!(
            parse_routing_rules("  \n ").unwrap(),
            Vec::<RoutingRule>::new()
        );
        assert_eq!(
            parse_routing_rules("[]").unwrap(),
            Vec::<RoutingRule>::new()
        );
        let rules = parse_routing_rules(
            r#"[{"agentLabel": "codex", "siteIds": [1, 2]}, {"agentLabel": "cc", "siteIds": [3]}]"#,
        )
        .unwrap();
        assert_eq!(
            rules,
            vec![
                RoutingRule {
                    agent_label: "codex".to_string(),
                    site_ids: vec![1, 2],
                },
                RoutingRule {
                    agent_label: "cc".to_string(),
                    site_ids: vec![3],
                },
            ]
        );
    }

    #[test]
    fn parse_routing_rules_rejects_malformed() {
        for bad in [
            "{not json",
            r#"{"agentLabel": "a", "siteIds": [1]}"#,
            r#"["not-an-object"]"#,
            r#"[{"agentLabel": 1, "siteIds": [1]}]"#,
            r#"[{"agentLabel": "  ", "siteIds": [1]}]"#,
            r#"[{"agentLabel": "a", "siteIds": []}]"#,
            r#"[{"agentLabel": "a", "siteIds": [0]}]"#,
            r#"[{"agentLabel": "a", "siteIds": [-2]}]"#,
            r#"[{"agentLabel": "a", "siteIds": [1.5]}]"#,
            r#"[{"agentLabel": "a", "siteIds": [1]}, {"agentLabel": "a", "siteIds": [2]}]"#,
            r#"[{"agentLabel": "a"}]"#,
            r#"[{"siteIds": [1]}]"#,
        ] {
            assert!(
                parse_routing_rules(bad).is_err(),
                "应当拒绝：{bad}，得到 {:?}",
                parse_routing_rules(bad)
            );
        }
    }

    #[test]
    fn parse_routing_rules_dedupes_site_ids_and_trims_label() {
        let rules =
            parse_routing_rules(r#"[{"agentLabel": "  codex  ", "siteIds": [2, 1, 2, 1]}]"#)
                .unwrap();
        assert_eq!(rules[0].agent_label, "codex");
        assert_eq!(rules[0].site_ids, vec![2, 1], "去重保序");
    }

    #[test]
    fn parse_routing_rules_enforces_caps() {
        let many: Vec<String> = (0..65)
            .map(|i| format!(r#"{{"agentLabel": "a{i}", "siteIds": [1]}}"#))
            .collect();
        assert!(
            parse_routing_rules(&format!("[{}]", many.join(","))).is_err(),
            "65 条规则应超 64 上限"
        );
        let sites: Vec<String> = (1..=129).map(|i| i.to_string()).collect();
        assert!(
            parse_routing_rules(&format!(
                r#"[{{"agentLabel": "a", "siteIds": [{}]}}]"#,
                sites.join(",")
            ))
            .is_err(),
            "129 站应超 128 上限"
        );
        let long = format!(
            r#"[{{"agentLabel": "{}", "siteIds": [1]}}]"#,
            "x".repeat(MAX_ROUTING_RULES_JSON_LEN)
        );
        assert!(parse_routing_rules(&long).is_err(), "超长文本应被拒");
    }

    #[test]
    fn routing_allowed_sites_matches_exactly() {
        let rules = parse_routing_rules(r#"[{"agentLabel": "codex", "siteIds": [1, 2]}]"#).unwrap();
        assert_eq!(routing_allowed_sites(&rules, "codex"), Some(&[1, 2][..]));
        assert_eq!(routing_allowed_sites(&rules, "Codex"), None, "大小写敏感");
        assert_eq!(routing_allowed_sites(&rules, "code"), None, "非前缀匹配");
        assert_eq!(routing_allowed_sites(&rules, "other"), None);
        assert_eq!(routing_allowed_sites(&rules, ""), None, "空 label 恒不命中");
    }

    #[test]
    fn resolve_routing_rules_strips_unknown_and_reports_them() {
        let rules = parse_routing_rules(
            r#"[{"agentLabel": "a", "siteIds": [1, 99, 2]}, {"agentLabel": "b", "siteIds": [77]}]"#,
        )
        .unwrap();
        let known: HashSet<i64> = [1, 2].into_iter().collect();
        let (effective, unknown) = resolve_routing_rules(rules, &known);
        assert_eq!(effective[0].site_ids, vec![1, 2]);
        assert_eq!(
            effective[1].site_ids,
            Vec::<i64>::new(),
            "全剥离后规则保留为空 allowlist"
        );
        assert_eq!(
            unknown,
            vec![("a".to_string(), 99), ("b".to_string(), 77)],
            "未知条目按规则顺序、站序输出"
        );
    }

    #[test]
    fn filter_upstreams_by_sites_keeps_order_and_is_noop_without_rule() {
        let a = up(1, Some(1.0), Some(10.0), None);
        let b = up(2, Some(1.0), Some(10.0), None);
        let c = up(3, Some(1.0), Some(10.0), None);
        let all = vec![&a, &b, &c];
        let kept = filter_upstreams_by_sites(all.clone(), None);
        assert_eq!(
            kept.iter().map(|u| u.site_id).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        let kept = filter_upstreams_by_sites(all.clone(), Some(&[3, 1]));
        assert_eq!(
            kept.iter().map(|u| u.site_id).collect::<Vec<_>>(),
            vec![1, 3],
            "保输入顺序，不按规则顺序重排"
        );
        let kept = filter_upstreams_by_sites(all, Some(&[]));
        assert!(kept.is_empty(), "空 allowlist ⇒ 空候选");
    }

    #[test]
    fn reorder_failover_tail_puts_listed_sites_first_in_list_order() {
        let a = up(1, Some(1.0), Some(10.0), None);
        let b = up(2, Some(1.0), Some(10.0), None);
        let c = up(3, Some(1.0), Some(10.0), None);
        let got = reorder_failover_tail(vec![&a, &b, &c], &[3, 2, 1]);
        assert_eq!(
            got.iter().map(|u| u.site_id).collect::<Vec<_>>(),
            vec![3, 2, 1],
            "已列出的站点按规则数组顺序排在前面"
        );
    }

    #[test]
    fn reorder_failover_tail_keeps_unlisted_sites_after_in_input_order() {
        let a = up(1, Some(1.0), Some(10.0), None);
        let b = up(2, Some(1.0), Some(10.0), None);
        let c = up(3, Some(1.0), Some(10.0), None);
        let d = up(4, Some(1.0), Some(10.0), None);
        let got = reorder_failover_tail(vec![&a, &b, &c, &d], &[3]);
        assert_eq!(
            got.iter().map(|u| u.site_id).collect::<Vec<_>>(),
            vec![3, 1, 2, 4],
            "未列出的站点不丢弃，只排在已列出之后、保持原顺序"
        );
    }

    #[test]
    fn reorder_failover_tail_creates_nothing_for_unknown_priority_ids() {
        let a = up(1, Some(1.0), Some(10.0), None);
        let b = up(2, Some(1.0), Some(10.0), None);
        let got = reorder_failover_tail(vec![&a, &b], &[99, 2]);
        assert_eq!(
            got.iter().map(|u| u.site_id).collect::<Vec<_>>(),
            vec![2, 1],
            "规则里有但候选里没有的站点不得凭空出现"
        );
        assert_eq!(got.len(), 2, "只重排，不增删");
    }

    #[test]
    fn reorder_failover_tail_is_identity_without_priority() {
        let a = up(1, Some(1.0), Some(10.0), None);
        let b = up(2, Some(1.0), Some(10.0), None);
        let got = reorder_failover_tail(vec![&b, &a], &[]);
        assert_eq!(
            got.iter().map(|u| u.site_id).collect::<Vec<_>>(),
            vec![2, 1],
            "空优先级 ⇒ 原样返回"
        );
    }

    #[test]
    fn reorder_failover_tail_keeps_same_site_keys_in_relative_order() {
        // 同站多 key：用不同 base_url 区分两个同一 site_id 的候选。
        let first_key = Upstream {
            site_id: 2,
            key_id: Some(1),
            base_url: "http://key1.example.com".to_string(),
            key_ref: "kr/key/2/a".to_string(),
            models: vec!["gpt-5.6".to_string()],
            rate: Some(1.0),
            balance_usd: Some(10.0),
            latency_ms: None,
            timeout_ms: None,
        };
        let second_key = Upstream {
            site_id: 2,
            key_id: Some(2),
            base_url: "http://key2.example.com".to_string(),
            key_ref: "kr/key/2/b".to_string(),
            models: vec!["gpt-5.6".to_string()],
            rate: Some(1.0),
            balance_usd: Some(10.0),
            latency_ms: None,
            timeout_ms: None,
        };
        let other = up(1, Some(1.0), Some(10.0), None);
        let got = reorder_failover_tail(vec![&first_key, &other, &second_key], &[2, 1]);
        assert_eq!(
            got.iter().map(|u| u.base_url.as_str()).collect::<Vec<_>>(),
            vec![
                "http://key1.example.com",
                "http://key2.example.com",
                "http://site1.example.com"
            ],
            "同 rank 的同站 key 彼此顺序不变（站内轮换不被打乱）"
        );
    }
}
