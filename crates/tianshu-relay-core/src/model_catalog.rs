//! 内置模型名单（M47-S2）：按模型名查 **上下文 / 最大输出 / 价格 / 协议 / 思考档位**。
//!
//! # 为什么要独立于 [`crate::model_meta`]
//!
//! `model_meta` 只有两个数字（窗口、输出），数据源是编译期 `const` 表 + models.dev。
//! 这一波要的是「一份我们自己维护、能随 GitHub 更新的名单」，字段多出
//! **价格、协议、思考档位**，并且要能落盘、能同步、能被用户覆盖。把它塞进
//! `model_meta` 会让那份「同步纯函数」变成带 IO 的东西，所以分层：
//!
//! - 本模块：**名单本身**（解析 / 校验 / 匹配 / 覆盖 / 同步 / 落盘）；
//! - [`crate::model_meta`]：把名单条目投影成投递层要的那几个数（`ModelMeta`），
//!   并保留 models.dev 作为最后兜底。
//!
//! # 数据源与优先级（高 → 低）
//!
//! 1. **本机覆盖**（`~/.tianshu-relay/catalog/overrides.json`，按模型 id）；
//! 2. **GitHub 名单缓存**（`~/.tianshu-relay/catalog/models.json`，由 [`CatalogStore::sync`] 写入）；
//! 3. **编译进二进制的名单**（`include_str!("../../../catalog/models.json")`，离线兜底）；
//! 4. models.dev（在 `model_meta` 里，只补窗口/输出）；
//! 5. 都没有 ⇒ `None`（调用方只写模型名，绝不写 0）。
//!
//! # 红线
//!
//! - 投递是**同步**路径：这里所有查询都只读内存快照，**永不联网**；
//! - 同步失败**不动旧缓存**（坏数据不能把好数据冲掉）；
//! - 价格未知 ⇒ `None`，绝不回落到 `0.0`（与 `usage_cost` 同一条纪律）。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::model_meta::ModelMeta;
use crate::site::transport::{HttpRequest, HttpTransport, Method};

/// 名单 schema 版本。客户端只认 `<=` 这个值的文件，更高的整份忽略（留 warn）。
pub const CATALOG_SCHEMA_VERSION: u32 = 1;

/// 名单的默认远端地址（公开仓 + `main` 分支）。
///
/// 选 raw.githubusercontent 而不是 Release 资产：名单要能随 PR 立刻生效，
/// 而 Release 资产只在发版时更新。代价是「main 上写错一个字会影响所有客户端」，
/// 所以仓库侧加了 `scripts/check-model-catalog.mjs` 门禁，且客户端对坏数据一律保旧。
pub const CATALOG_URL: &str =
    "https://raw.githubusercontent.com/lorek666/keyrelay/main/catalog/models.json";

/// 名单文件大小上限。34 条 ≈ 17KB，2MB 足够容纳上千条，同时挡住「拉回来一个网页」。
pub const MAX_CATALOG_BYTES: usize = 2 * 1024 * 1024;

/// 编译进二进制的名单（离线兜底；也保证首次启动就有数据）。
pub const BUNDLED_CATALOG: &str = include_str!("../../../catalog/models.json");

/// 缓存目录名（相对应用数据目录）。
pub const CATALOG_DIR: &str = "catalog";
/// 缓存文件名。
pub const CACHE_FILE: &str = "models.json";
/// 本机覆盖文件名。
pub const OVERRIDES_FILE: &str = "overrides.json";

/// 上游协议（模型**原生**说的是哪套）。
///
/// 用途：判断「投递出去的客户端要的那套协议，这个模型/站点能不能满足」。
/// 注意网关当前的上游固定是 OpenAI Chat（ADR-0005），所以 `AnthropicMessages`
/// 只表示「原生支持」，不代表网关会直通。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProtocol {
    OpenAiChat,
    OpenAiResponses,
    AnthropicMessages,
    Gemini,
}

impl UpstreamProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiChat => "openai_chat",
            Self::OpenAiResponses => "openai_responses",
            Self::AnthropicMessages => "anthropic_messages",
            Self::Gemini => "gemini",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "openai_chat" => Some(Self::OpenAiChat),
            "openai_responses" => Some(Self::OpenAiResponses),
            "anthropic_messages" => Some(Self::AnthropicMessages),
            "gemini" => Some(Self::Gemini),
            _ => None,
        }
    }
}

/// 思考档位（统一五档，与厂商各自的叫法解耦）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThinkingLevel {
    Off,
    Low,
    Medium,
    High,
    XHigh,
}

impl ThinkingLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::XHigh => "xhigh",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "disabled" => Some(Self::Off),
            "low" | "minimal" => Some(Self::Low),
            "medium" | "med" => Some(Self::Medium),
            "high" => Some(Self::High),
            "xhigh" | "max" | "highest" => Some(Self::XHigh),
            _ => None,
        }
    }
}

/// 思考档位怎么表达给上游 / 客户端。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThinkingParam {
    /// Anthropic 的 `thinking: {type, budget_tokens}`。
    Thinking,
    /// OpenAI Chat / Codex 的 `reasoning_effort`。
    ReasoningEffort,
}

impl ThinkingParam {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Thinking => "thinking",
            Self::ReasoningEffort => "reasoning_effort",
        }
    }
}

/// 一个模型的思考能力。`Copy`：`ModelMeta` 要靠它保持 `Copy`（既有投递层到处在拷它）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThinkingSpec {
    pub param: ThinkingParam,
    /// 支持到哪一档（`Off` 表示「只支持关闭」= 实际不支持）。
    pub max_level: ThinkingLevel,
    pub default_level: ThinkingLevel,
    /// 各档对应的 `budget_tokens`（`reasoning_effort` 形态没有预算，四个值都是 0）。
    pub budget_low: u32,
    pub budget_medium: u32,
    pub budget_high: u32,
    pub budget_xhigh: u32,
    /// 明确声明的档位（含 off）；缺失/非法档位让整条 thinking 视为未声明。
    pub levels: u8,
}

impl ThinkingSpec {
    /// 这个档位能不能用（超过 `max_level` ⇒ 不可用）。
    pub fn accepts(&self, level: ThinkingLevel) -> bool {
        level <= self.max_level
            && level != ThinkingLevel::Off
            && self.levels & (1 << level as u8) != 0
    }

    /// 名单有没有给出预算表（四条预算全 0 = 没给）。
    ///
    /// `param: thinking` 但预算表为空时，按预算折算只会永远落到最低档——那不是
    /// 「用户要 low」，而是「名单没数据」。调用方据此退回默认档。
    pub fn has_budgets(&self) -> bool {
        self.budget_low > 0
            || self.budget_medium > 0
            || self.budget_high > 0
            || self.budget_xhigh > 0
    }

    /// 档位 → `budget_tokens`。`Off` 或超档 ⇒ `None`（调用方据此不写该参数）。
    pub fn budget(&self, level: ThinkingLevel) -> Option<u32> {
        if !self.accepts(level) {
            return None;
        }
        let budget = match level {
            ThinkingLevel::Off => return None,
            ThinkingLevel::Low => self.budget_low,
            ThinkingLevel::Medium => self.budget_medium,
            ThinkingLevel::High => self.budget_high,
            ThinkingLevel::XHigh => self.budget_xhigh,
        };
        (budget > 0).then_some(budget)
    }
}

/// 名单里的一条价格。
#[derive(Clone, Debug, PartialEq)]
pub struct CatalogPrice {
    pub currency: String,
    pub input_per_mtok: f64,
    pub output_per_mtok: f64,
    pub cache_read_per_mtok: Option<f64>,
    /// 生效时间（unix 秒）。`0` = 名单没给 ⇒ 用文件的 `generatedAt`。
    pub effective_from: i64,
}

/// 名单里的一个模型。
#[derive(Clone, Debug, PartialEq)]
pub struct CatalogModel {
    pub id: String,
    pub display_name: String,
    pub aliases: Vec<String>,
    pub vendor: String,
    pub protocol: UpstreamProtocol,
    pub anthropic_compatible: bool,
    pub context_window: u32,
    pub max_output_tokens: u32,
    pub thinking: Option<ThinkingSpec>,
    /// 名单是否明确写了 `supported: false`。
    ///
    /// 与「没写 thinking」严格区分：前者可以清理受管客户端的旧思考档位，后者是未知，
    /// 只能不写，不能删除用户自己的配置。本机覆盖选择「关闭」也会置为 true。
    pub thinking_unsupported: bool,
    pub prices: Vec<CatalogPrice>,
    pub deprecated: bool,
}

impl CatalogModel {
    /// 投影成投递层要的 `ModelMeta`（窗口 / 输出 / 思考 / 协议）。
    pub fn to_meta(&self) -> ModelMeta {
        ModelMeta::from_catalog(
            self.context_window,
            self.max_output_tokens,
            self.thinking,
            self.thinking_unsupported,
            self.protocol,
            self.anthropic_compatible,
        )
    }
}

/// 本机覆盖（一行）。全字段可选：只覆盖用户真正改过的那些。
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_window: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    /// `None` = 不动；`Some(None)` 表达不出来（JSON 里就是缺省），所以用
    /// `thinking_level` 直接覆盖「最高档」，`thinking_supported = false` 才能关掉。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking_level: Option<ThinkingLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking_supported: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price_input_per_mtok: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price_output_per_mtok: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price_currency: Option<String>,
}

impl ModelOverride {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// 覆盖文件形态。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OverridesFile {
    #[serde(default)]
    schema_version: u32,
    #[serde(default)]
    models: HashMap<String, ModelOverride>,
}

/// 一份解析好的名单。
#[derive(Clone, Debug)]
pub struct Catalog {
    pub schema_version: u32,
    pub generated_at: String,
    pub generated_at_ts: i64,
    pub models: Vec<CatalogModel>,
    /// 规范化名（含别名）→ `models` 下标。
    index: HashMap<String, usize>,
}

/// 解析结果里的「跳过了几条坏数据」——**必须报出来**，否则名单少一半没人知道。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ParseStats {
    pub accepted: usize,
    pub skipped: usize,
}

impl Catalog {
    /// 空名单（bundled 文件都坏掉时的兜底，保证 `open()` 不会失败）。
    pub fn empty() -> Self {
        Self {
            schema_version: CATALOG_SCHEMA_VERSION,
            generated_at: String::new(),
            generated_at_ts: 0,
            models: Vec::new(),
            index: HashMap::new(),
        }
    }

    /// 解析并**逐条校验**。
    ///
    /// 单条坏数据只跳过它自己并把计数交回去；`schemaVersion` 过高、根形态不对
    /// 这类「整份不可信」的错误才整体失败——那种情况下调用方必须保留旧缓存。
    pub fn parse(text: &str) -> std::result::Result<(Self, ParseStats), CatalogParseError> {
        let value: Value = serde_json::from_str(text)
            .map_err(|e| CatalogParseError::new(format!("名单不是合法 JSON: {e}")))?;
        let schema_version = value
            .get("schemaVersion")
            .and_then(Value::as_u64)
            .ok_or_else(|| CatalogParseError::new("名单缺少 schemaVersion"))?;
        if schema_version > u64::from(CATALOG_SCHEMA_VERSION) {
            return Err(CatalogParseError::new(format!(
                "名单 schemaVersion={schema_version} 高于本版本支持的 {CATALOG_SCHEMA_VERSION}，整份忽略"
            )));
        }
        let generated_at = value
            .get("generatedAt")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let generated_at_ts = value
            .get("generatedAtTs")
            .and_then(Value::as_i64)
            .unwrap_or_else(|| parse_rfc3339_secs(&generated_at).unwrap_or(0));
        let raw_models = value
            .get("models")
            .and_then(Value::as_array)
            .ok_or_else(|| CatalogParseError::new("名单缺少 models 数组"))?;

        let mut models = Vec::with_capacity(raw_models.len());
        let mut skipped = 0usize;
        for raw in raw_models {
            match parse_model(raw) {
                Some(model) => models.push(model),
                None => skipped += 1,
            }
        }

        let mut index = HashMap::new();
        for (i, model) in models.iter().enumerate() {
            index.entry(normalize_key(&model.id)).or_insert(i);
            for alias in &model.aliases {
                index.entry(normalize_key(alias)).or_insert(i);
            }
            // 别名也可能是带 `vendor/` 前缀或 `[1m]` 后缀的形态，两种写法都收。
        }

        let catalog = Self {
            schema_version: u32::try_from(schema_version).unwrap_or(CATALOG_SCHEMA_VERSION),
            generated_at,
            generated_at_ts,
            models,
            index,
        };
        let stats = ParseStats {
            accepted: catalog.models.len(),
            skipped,
        };
        Ok((catalog, stats))
    }

    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
    }

    /// 按名字（含别名、前缀、方括号后缀、日期后缀）查一条。
    ///
    /// 匹配顺序与 [`crate::model_meta::lookup`] 同源：精确 → 逐段剥尾。
    /// 多一步「剥掉 `vendor/` 前缀」和「剥掉 `[...]` 后缀」，因为中转站的模型名
    /// 常见形态是 `zcode/GLM-5.3-Flash[1m]`——这两个都不能靠逐段剥尾命中。
    pub fn resolve(&self, model: &str) -> Option<&CatalogModel> {
        let key = normalize_key(model);
        if key.is_empty() {
            return None;
        }
        if let Some(i) = self.index.get(&key) {
            return self.models.get(*i);
        }
        // 逐段剥尾，**只剥纯数字段**（日期 / 版本号）：`gpt-4o-2024-08-06` → `gpt-4o`。
        //
        // 早先是无条件剥任意一段，于是 `glm-4-air` 会被认成 `glm-4`——两个不同模型，
        // 窗口/价格/思考能力都不一样，投递会带着错参数出去。宁可查不到（退回
        // models.dev / 无名单），也不要猜错一个。
        let mut name = key.as_str();
        while let Some(pos) = name.rfind('-') {
            let (head, tail) = (&name[..pos], &name[pos + 1..]);
            if tail.is_empty() || !tail.bytes().all(|b| b.is_ascii_digit()) {
                break;
            }
            name = head;
            if let Some(i) = self.index.get(name) {
                return self.models.get(*i);
            }
        }
        None
    }

    /// 名字 → 投递层要的 `ModelMeta`。
    pub fn meta_for(&self, model: &str) -> Option<ModelMeta> {
        self.resolve(model).map(CatalogModel::to_meta)
    }
}

/// 「整份不可信」的解析错误。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogParseError {
    pub message: String,
}

impl CatalogParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CatalogParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// 规范化模型名：trim → 小写 → 去 `vendor/` 前缀 → 去 `[...]` 后缀。
///
/// 例：
/// - `"zcode/GLM-5.3-Flash[1m]"` → `"glm-5.3-flash"`
/// - `"OpenAI/GPT-4o"` → `"gpt-4o"`
/// - `"  kimi-k2[128k] "` → `"kimi-k2"`
pub fn normalize_key(raw: &str) -> String {
    let lowered = raw.trim().to_ascii_lowercase();
    if lowered.is_empty() {
        return String::new();
    }
    // 去 `[...]` 后缀（可能有出现在中间以外的多个，只取最后一个之后的部分不要）
    let without_brackets = match lowered.find('[') {
        Some(pos) => lowered[..pos].trim_end().to_string(),
        None => lowered,
    };
    // 去 `vendor/` 前缀：`a/b/c` 取最后一段（中转站常见 `zcode/xxx`、`openai/gpt-4o`）
    let last_segment = without_brackets
        .rsplit('/')
        .next()
        .unwrap_or(&without_brackets)
        .trim()
        .to_string();
    last_segment
}

/// 单条模型：任何字段不合规 ⇒ `None`（跳过它自己，不拖垮整份名单）。
fn parse_model(raw: &Value) -> Option<CatalogModel> {
    let id = raw.get("id").and_then(Value::as_str)?.trim();
    if id.is_empty() {
        return None;
    }
    let context_window = raw
        .get("limits")
        .and_then(|l| l.get("contextWindow"))
        .and_then(Value::as_u64)?;
    let max_output_tokens = raw
        .get("limits")
        .and_then(|l| l.get("maxOutputTokens"))
        .and_then(Value::as_u64)?;
    // 0 或超 u32 的窗口没有意义：写 0 会让 agent 一开口就被截断，宁可当没这条。
    let context_window = u32::try_from(context_window).ok().filter(|v| *v > 0)?;
    let max_output_tokens = u32::try_from(max_output_tokens).ok().filter(|v| *v > 0)?;
    // 输出上限大于窗口本身没有意义，写进客户端配置只会得到「一开口就超窗」。
    if max_output_tokens > context_window {
        return None;
    }

    let protocol = raw
        .get("protocol")
        .and_then(|p| p.get("upstream"))
        .and_then(Value::as_str)
        .and_then(UpstreamProtocol::parse)?;
    let anthropic_compatible = raw
        .get("protocol")
        .and_then(|p| p.get("anthropicCompatible"))
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let display_name = raw
        .get("displayName")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(id)
        .to_string();
    let vendor = raw
        .get("vendor")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    let aliases = raw
        .get("aliases")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let deprecated = raw
        .get("deprecated")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let prices = raw
        .get("prices")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(parse_price).collect::<Vec<_>>())
        .unwrap_or_default();

    Some(CatalogModel {
        id: id.to_string(),
        display_name,
        aliases,
        vendor,
        protocol,
        anthropic_compatible,
        context_window,
        max_output_tokens,
        thinking: parse_thinking(raw.get("thinking")),
        thinking_unsupported: raw
            .get("thinking")
            .and_then(|t| t.get("supported"))
            .and_then(Value::as_bool)
            == Some(false),
        prices,
        deprecated,
    })
}

fn parse_price(raw: &Value) -> Option<CatalogPrice> {
    let input = raw.get("inputPerMTok").and_then(Value::as_f64)?;
    let output = raw.get("outputPerMTok").and_then(Value::as_f64)?;
    // 负数价格没有意义；0 是合法的（自建免费模型），但未知必须是「没有这条」而不是 0。
    if !input.is_finite() || input < 0.0 || !output.is_finite() || output < 0.0 {
        return None;
    }
    let currency = raw
        .get("currency")
        .and_then(Value::as_str)
        .map(|c| c.trim().to_ascii_uppercase())
        .filter(|c| c == "USD" || c == "CNY")?;
    let effective_from = raw
        .get("effectiveFrom")
        .and_then(Value::as_str)
        .and_then(parse_rfc3339_secs)
        .unwrap_or(0);
    Some(CatalogPrice {
        currency,
        input_per_mtok: input,
        output_per_mtok: output,
        cache_read_per_mtok: raw
            .get("cacheReadPerMTok")
            .and_then(Value::as_f64)
            .filter(|v| v.is_finite() && *v >= 0.0),
        effective_from,
    })
}

fn parse_thinking(raw: Option<&Value>) -> Option<ThinkingSpec> {
    let raw = raw?;
    if !raw
        .get("supported")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return None;
    }
    let param = match raw.get("param").and_then(Value::as_str)? {
        "thinking" => ThinkingParam::Thinking,
        "reasoning_effort" => ThinkingParam::ReasoningEffort,
        _ => return None,
    };
    let raw_levels = raw.get("levels")?.as_array()?;
    if raw_levels.is_empty() {
        return None;
    }
    let levels = raw_levels
        .iter()
        .map(|level| level.as_str().and_then(ThinkingLevel::parse))
        .collect::<Option<Vec<_>>>()?;
    // 最高档 = 声明支持的最大一档；只有 `off` ⇒ 等于不支持。
    let max_level = levels
        .iter()
        .copied()
        .filter(|l| *l != ThinkingLevel::Off)
        .max()?;
    let default_level = raw
        .get("defaultLevel")
        .and_then(Value::as_str)
        .and_then(ThinkingLevel::parse)
        .filter(|level| levels.contains(level) && *level != ThinkingLevel::Off)
        .unwrap_or(ThinkingLevel::Medium);
    let budget = |key: &str| {
        raw.get("budgetTokens")
            .and_then(|b| b.get(key))
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(0)
    };
    Some(ThinkingSpec {
        param,
        max_level,
        default_level: if default_level <= max_level {
            default_level
        } else {
            max_level
        },
        budget_low: budget("low"),
        budget_medium: budget("medium"),
        budget_high: budget("high"),
        budget_xhigh: budget("xhigh"),
        levels: levels
            .iter()
            .fold(0u8, |mask, level| mask | (1 << *level as u8)),
    })
}

/// `YYYY-MM-DD` 或 `YYYY-MM-DDTHH:MM:SSZ` → unix 秒。解析不出来 ⇒ `None`（不猜）。
fn parse_rfc3339_secs(text: &str) -> Option<i64> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let date = text.get(0..10)?;
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // days since epoch（Howard Hinnant 的 days_from_civil）
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400)
}

/// 同步结果。
#[derive(Clone, Debug, PartialEq)]
pub struct CatalogSyncReport {
    pub bytes: usize,
    pub accepted: usize,
    pub skipped: usize,
    pub generated_at: String,
    /// 是否因为「远端没变」（304 / 内容 sha 相同）而跳过了落盘。
    pub unchanged: bool,
}

/// 名单当前状态（给界面看）。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CatalogStatus {
    /// `"remote"`（GitHub 缓存）/ `"bundled"`（内置）/ `"empty"`。
    pub source: &'static str,
    pub schema_version: u32,
    pub generated_at: String,
    pub generated_at_ts: i64,
    pub entries: usize,
    pub overrides: usize,
    pub last_success_at: i64,
    pub last_error: Option<String>,
}

/// 一台机器上的名单：编译期兜底 + 磁盘缓存 + 本机覆盖。
pub struct CatalogStore {
    dir: PathBuf,
    bundled: Catalog,
    remote: RwLock<Option<Catalog>>,
    overrides: RwLock<HashMap<String, ModelOverride>>,
    /// 覆盖文件损坏/不可读时禁止基于空表重写它，先让用户修复或备份原文件。
    overrides_valid: std::sync::atomic::AtomicBool,
    /// 覆盖的「读旧值 → 合并 → 落盘 → 发布内存」必须整体串行；只保护单个 HashMap
    /// 操作不够，否则两个补丁会基于同一旧值互相覆盖，且共用 pid 临时文件名。
    override_write: std::sync::Mutex<()>,
    state: RwLock<CatalogSyncState>,
    /// 同一时刻只允许一次同步：启动 20s 后的自动同步、24h 轮询、界面「立即同步」三条路径
    /// 会撞在一起，而它们共用同一个 `models.json.tmp`——并发 rename 会有一个失败。
    syncing: std::sync::atomic::AtomicBool,
}

#[derive(Clone, Debug, Default)]
struct CatalogSyncState {
    last_success_at: i64,
    last_error: Option<String>,
}

impl CatalogStore {
    /// 打开（不联网）。`data_dir` 是应用数据目录（`~/.tianshu-relay`）。
    pub fn open(data_dir: &Path) -> Self {
        let dir = data_dir.join(CATALOG_DIR);
        let bundled = match Catalog::parse(BUNDLED_CATALOG) {
            Ok((catalog, _)) => catalog,
            // 内置名单坏了是打包事故，但**不能因此让应用起不来**：退化成空名单，
            // 投递就只剩「写模型名」，与没有这份名单时一模一样。
            Err(_) => Catalog::empty(),
        };
        let store = Self {
            dir,
            bundled,
            remote: RwLock::new(None),
            overrides: RwLock::new(HashMap::new()),
            overrides_valid: std::sync::atomic::AtomicBool::new(true),
            override_write: std::sync::Mutex::new(()),
            state: RwLock::new(CatalogSyncState::default()),
            syncing: std::sync::atomic::AtomicBool::new(false),
        };
        store.load_cache();
        store.load_overrides();
        store
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn cache_path(&self) -> PathBuf {
        self.dir.join(CACHE_FILE)
    }

    fn overrides_path(&self) -> PathBuf {
        self.dir.join(OVERRIDES_FILE)
    }

    /// 读磁盘缓存。**坏文件直接忽略**（不删）：留着它，下一轮同步会覆盖。
    fn load_cache(&self) {
        let Ok(text) = std::fs::read_to_string(self.cache_path()) else {
            return;
        };
        if let Ok((catalog, stats)) = Catalog::parse(&text) {
            // 只挡「明显是坏的」：空名单、或坏条目不少于好条目。**不按条数设下限**——
            // 一份合法的精简名单（比如只收 10 个模型）也必须能加载，否则用户改了名单
            // 却永远看到内置那份，且没有任何提示。
            if catalog.is_empty() || stats.skipped >= stats.accepted {
                if let Ok(mut state) = self.state.write() {
                    state.last_error = Some(format!(
                        "本地缓存不可信（合规 {} 条 / 不合规 {} 条），已忽略",
                        stats.accepted, stats.skipped
                    ));
                }
                return;
            }
            if stats.skipped > 0 {
                // 计数进状态，让界面能说「有 3 条坏数据已跳过」。
                if let Ok(mut state) = self.state.write() {
                    state.last_error =
                        Some(format!("缓存里有 {} 条条目不合规，已跳过", stats.skipped));
                }
            }
            if let Ok(mut guard) = self.remote.write() {
                *guard = Some(catalog);
            }
        }
    }

    fn load_overrides(&self) {
        let text = match std::fs::read_to_string(self.overrides_path()) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
            Err(err) => {
                self.overrides_valid
                    .store(false, std::sync::atomic::Ordering::Release);
                self.record_failure(&format!(
                    "本机覆盖文件不可读: {err}；未改写它，请先修复或移走该文件"
                ));
                return;
            }
        };
        match serde_json::from_str::<OverridesFile>(&text) {
            Ok(file) => {
                if let Ok(mut guard) = self.overrides.write() {
                    *guard = file.models;
                }
            }
            Err(err) => {
                self.overrides_valid
                    .store(false, std::sync::atomic::Ordering::Release);
                self.record_failure(&format!(
                    "本机覆盖文件损坏: {err}；未改写它，请先修复或移走该文件"
                ));
            }
        }
    }

    /// 当前生效的名单（远端优先，其次内置）。
    fn active(&self) -> Option<Catalog> {
        if let Ok(guard) = self.remote.read() {
            if let Some(catalog) = guard.as_ref() {
                if !catalog.is_empty() {
                    return Some(catalog.clone());
                }
            }
        }
        (!self.bundled.is_empty()).then(|| self.bundled.clone())
    }

    /// 名字 → 条目（**已合并本机覆盖**）。同步路径用这个。
    pub fn resolve(&self, model: &str) -> Option<CatalogModel> {
        let catalog = self.active()?;
        let mut found = catalog.resolve(model).cloned()?;
        let key = normalize_key(&found.id);
        if let Ok(guard) = self.overrides.read() {
            if let Some(patch) = guard.get(&key).or_else(|| guard.get(&found.id)) {
                apply_override(&mut found, patch);
            }
        }
        Some(found)
    }

    /// 名字 → `ModelMeta`（投递路径的唯一入口）。
    pub fn meta_for(&self, model: &str) -> Option<ModelMeta> {
        self.resolve(model).map(|m| m.to_meta())
    }

    /// 全部条目（已合并覆盖），按 id 排序——给界面用。
    pub fn entries(&self) -> Vec<CatalogModel> {
        let Some(catalog) = self.active() else {
            return Vec::new();
        };
        let mut models = catalog.models.clone();
        if let Ok(guard) = self.overrides.read() {
            for model in models.iter_mut() {
                let key = normalize_key(&model.id);
                if let Some(patch) = guard.get(&key).or_else(|| guard.get(&model.id)) {
                    apply_override(model, patch);
                }
            }
        }
        models.sort_by(|a, b| a.id.cmp(&b.id));
        models
    }

    pub fn status(&self, now_secs: i64) -> CatalogStatus {
        let remote = self
            .remote
            .read()
            .ok()
            .and_then(|guard| {
                guard.as_ref().map(|c| {
                    (
                        c.schema_version,
                        c.generated_at.clone(),
                        c.generated_at_ts,
                        c.models.len(),
                    )
                })
            })
            .filter(|(_, _, _, n)| *n > 0);
        let overrides = self.overrides.read().map(|g| g.len()).unwrap_or(0);
        let state = self.state.read().map(|s| s.clone()).unwrap_or_default();
        let _ = now_secs;
        match remote {
            Some((schema_version, generated_at, generated_at_ts, entries)) => CatalogStatus {
                source: "remote",
                schema_version,
                generated_at,
                generated_at_ts,
                entries,
                overrides,
                last_success_at: state.last_success_at,
                last_error: state.last_error,
            },
            None if !self.bundled.is_empty() => CatalogStatus {
                source: "bundled",
                schema_version: self.bundled.schema_version,
                generated_at: self.bundled.generated_at.clone(),
                generated_at_ts: self.bundled.generated_at_ts,
                entries: self.bundled.models.len(),
                overrides,
                last_success_at: state.last_success_at,
                last_error: state.last_error,
            },
            None => CatalogStatus {
                source: "empty",
                entries: 0,
                overrides,
                last_success_at: state.last_success_at,
                last_error: state.last_error,
                ..Default::default()
            },
        }
    }

    /// 从远端拉一次并落盘。**失败不动旧缓存**（也只记错误，不抛给投递）。
    pub async fn sync<T: HttpTransport + ?Sized>(
        &self,
        transport: &T,
        url: &str,
        now_secs: i64,
    ) -> std::result::Result<CatalogSyncReport, String> {
        // 抢不到就直接说「进行中」，不排队：排队会让用户连点两次、等两轮网络。
        if self.syncing.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return Err("已有一次名单同步在进行中，请稍候".to_string());
        }
        struct SyncGuard<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for SyncGuard<'_> {
            fn drop(&mut self) {
                self.0.store(false, std::sync::atomic::Ordering::Release);
            }
        }
        let _sync_guard = SyncGuard(&self.syncing);
        let req = HttpRequest::new(Method::Get, url);
        let resp = match transport.request(req).await {
            Ok(resp) => resp,
            Err(err) => {
                let message = format!("拉取名单失败: {}", crate::redact::scrub(&err.to_string()));
                self.record_failure(&message);
                return Err(message);
            }
        };
        if !(200..300).contains(&resp.status) {
            let message = format!("拉取名单失败: HTTP {}", resp.status);
            self.record_failure(&message);
            return Err(message);
        }
        // `HttpResponse` 只给字节：名单是 UTF-8 JSON，非法字节按替换字符处理后仍会
        // 在 `Catalog::parse` 那一步被当成坏 JSON 拒掉（而不是在这里 panic）。
        let body = String::from_utf8_lossy(&resp.body).to_string();
        if body.len() > MAX_CATALOG_BYTES {
            let message = format!("名单文件过大（{} 字节），已忽略", body.len());
            self.record_failure(&message);
            return Err(message);
        }
        // 先解析再比较字节：坏缓存与远端坏文件相同，也不能靠 unchanged 绕过校验。
        let (catalog, stats) = Catalog::parse(&body).map_err(|e| {
            let message = format!("名单不可用: {e}");
            self.record_failure(&message);
            message
        })?;
        if catalog.is_empty() {
            let message = "名单是空的，已保留旧缓存".to_string();
            self.record_failure(&message);
            return Err(message);
        }
        // 「解析出来一条就算成功」是危险的：远端文件被截断/改坏时往往仍是合法 JSON，
        // 只是只剩几条——照单接收等于把 34 条名单悄悄缩成 1 条，投递立刻退化到
        // 「只写模型名」。这里加两道闸，宁可报错继续用旧缓存：
        //   ① 坏条目比好条目还多 ⇒ 这份文件本身有问题，不是个别条目的问题；
        //   ② 条目数掉到现有的一半以下 ⇒ 不足以替换，先让人看一眼。
        if stats.skipped >= stats.accepted {
            let message = format!(
                "名单整体不可信（合规 {} 条 / 不合规 {} 条），已保留旧缓存",
                stats.accepted, stats.skipped
            );
            self.record_failure(&message);
            return Err(message);
        }
        // 只有「已经有一份远端名单」时才比较新旧条数：新名单腰斩多半是文件被截断。
        // 首次同步不设条数下限——一份合法的精简名单也得能用（否则永远同步不上）。
        let previous = self
            .remote
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(|c| c.models.len()));
        if let Some(previous) = previous {
            if previous >= 8 && catalog.models.len() * 2 < previous {
                let message = format!(
                    "名单条目数骤降（{} → {}），已保留旧缓存；确认无误后再同步",
                    previous,
                    catalog.models.len()
                );
                self.record_failure(&message);
                return Err(message);
            }
        }
        if std::fs::read_to_string(self.cache_path()).ok().as_deref() == Some(body.as_str()) {
            if let Ok(mut guard) = self.remote.write() {
                *guard = Some(catalog.clone());
            }
            if let Ok(mut state) = self.state.write() {
                state.last_success_at = now_secs;
                state.last_error = (stats.skipped > 0)
                    .then(|| format!("有 {} 条条目不合规，已跳过；已接受合规条目", stats.skipped));
            }
            return Ok(CatalogSyncReport {
                bytes: body.len(),
                accepted: stats.accepted,
                skipped: stats.skipped,
                generated_at: catalog.generated_at,
                unchanged: true,
            });
        }
        if let Err(message) = self.write_cache(&body) {
            self.record_failure(&message);
            return Err(message);
        }
        let generated_at = catalog.generated_at.clone();
        if let Ok(mut guard) = self.remote.write() {
            *guard = Some(catalog);
        }
        if let Ok(mut state) = self.state.write() {
            state.last_success_at = now_secs;
            state.last_error = (stats.skipped > 0)
                .then(|| format!("有 {} 条条目不合规，已跳过；已接受合规条目", stats.skipped));
        }
        Ok(CatalogSyncReport {
            bytes: body.len(),
            accepted: stats.accepted,
            skipped: stats.skipped,
            generated_at,
            unchanged: false,
        })
    }

    /// 原子落盘：先写临时文件再 rename，避免半个 JSON 被下一次启动读到。
    fn write_cache(&self, text: &str) -> std::result::Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("创建名单目录失败: {e}"))?;
        let path = self.cache_path();
        let tmp = self
            .dir
            .join(format!("{CACHE_FILE}.{}.tmp", std::process::id()));
        std::fs::write(&tmp, text).map_err(|e| format!("写入名单缓存失败: {e}"))?;
        std::fs::rename(&tmp, &path).map_err(|e| format!("替换名单缓存失败: {e}"))
    }

    /// 同步附属数据（如价格表）失败时，也把原因显示在名单状态里。
    pub fn record_sync_failure(&self, message: &str) {
        self.record_failure(message);
    }

    fn record_failure(&self, message: &str) {
        if let Ok(mut state) = self.state.write() {
            state.last_error = Some(message.to_string());
        }
    }

    /// 读一条本机覆盖（界面据此标「本机覆盖」并回填编辑框）。
    pub fn override_for(&self, model_id: &str) -> Option<ModelOverride> {
        let key = self
            .resolve(model_id)
            .map(|m| normalize_key(&m.id))
            .unwrap_or_else(|| normalize_key(model_id));
        let guard = self.overrides.read().ok()?;
        guard.get(&key).or_else(|| guard.get(model_id)).cloned()
    }

    /// 写一条本机覆盖（按模型 id 或原名均可，内部统一成规范化 id）。
    ///
    /// **合并语义**：`patch` 里给了的字段覆盖旧值，没给的字段保留——界面只提交用户真正
    /// 改过的那几格（空白 = 不改）。早先这里是**整条替换**，于是「只改价格」的一次保存会
    /// 把之前设过的窗口/档位一起抹掉，而且界面看不出来。
    ///
    /// 想撤销整条（含单独某一个字段）用 [`Self::clear_override`]：单选一格的「改回名单值」
    /// 表达不出来（`Option` 里没有第三个状态），与其加一个只有后端懂的哨兵值，不如让
    /// 「恢复名单值」明确地一次清干净。
    pub fn set_override(&self, model_id: &str, patch: ModelOverride) -> Result<()> {
        // 统一存到**规范 id** 上：名单匹配时会脱掉 `zcode/`、`[1m]`、日期尾巴，而覆盖查找
        // 只看 `found.id`——按别名或带版本号的名字写进来，会存成一条永远不生效的孤儿
        // （界面还标着「本机覆盖」，用户怎么调都没反应）。
        let key = self
            .resolve(model_id)
            .map(|m| normalize_key(&m.id))
            .unwrap_or_else(|| normalize_key(model_id));
        if key.is_empty() {
            return Err(Error::InvalidInput("模型 id 为空".to_string()));
        }
        let _write = self
            .override_write
            .lock()
            .map_err(|_| Error::Store("名单覆盖写锁中毒".to_string()))?;
        if !self
            .overrides_valid
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(Error::Store(
                "本机覆盖文件损坏或不可读，未执行保存；请先修复或移走 overrides.json".to_string(),
            ));
        }
        let mut merged = {
            let guard = self
                .overrides
                .read()
                .map_err(|_| Error::Store("名单覆盖锁中毒".to_string()))?;
            guard.get(&key).cloned().unwrap_or_default()
        };
        merged.context_window = patch.context_window.or(merged.context_window);
        merged.max_output_tokens = patch.max_output_tokens.or(merged.max_output_tokens);
        merged.thinking_level = patch.thinking_level.or(merged.thinking_level);
        merged.thinking_supported = patch.thinking_supported.or(merged.thinking_supported);
        if patch
            .thinking_level
            .is_some_and(|level| level != ThinkingLevel::Off)
        {
            // 非 Off 是明确的重新开启动作，不能被上一次的 supported=false 永久压住。
            merged.thinking_supported = Some(true);
        }
        merged.price_input_per_mtok = patch.price_input_per_mtok.or(merged.price_input_per_mtok);
        merged.price_output_per_mtok = patch.price_output_per_mtok.or(merged.price_output_per_mtok);
        merged.price_currency = patch.price_currency.or(merged.price_currency);
        let mut effective = self
            .resolve(model_id)
            .ok_or_else(|| Error::InvalidInput(format!("模型不在名单中: {model_id}")))?;
        apply_override(&mut effective, &merged);
        if effective.max_output_tokens > effective.context_window {
            return Err(Error::InvalidInput(
                "最大输出不能超过上下文窗口；请同时调整这两项".to_string(),
            ));
        }
        for (name, value) in [
            ("输入价", merged.price_input_per_mtok),
            ("输出价", merged.price_output_per_mtok),
        ] {
            if value.is_some_and(|v| !v.is_finite() || v <= 0.0) {
                return Err(Error::InvalidInput(format!(
                    "{name}必须是大于 0 的有限数；未定价请撤销覆盖"
                )));
            }
        }
        if merged.price_input_per_mtok.is_some() != merged.price_output_per_mtok.is_some() {
            return Err(Error::InvalidInput(
                "输入价与输出价必须一起填写".to_string(),
            ));
        }
        if let Some(currency) = merged.price_currency.as_deref() {
            if !matches!(currency.trim().to_ascii_uppercase().as_str(), "USD" | "CNY") {
                return Err(Error::InvalidInput("价格币种只支持 USD / CNY".to_string()));
            }
        }
        // 先落盘，再发布内存快照：写盘失败不能留下「界面报错、投递却已用新值」。
        let mut models = self
            .overrides
            .read()
            .map_err(|_| Error::Store("名单覆盖锁中毒".to_string()))?
            .clone();
        if merged.is_empty() {
            models.remove(&key);
        } else {
            models.insert(key, merged);
        }
        self.persist_overrides(&models)?;
        *self
            .overrides
            .write()
            .map_err(|_| Error::Store("名单覆盖锁中毒".to_string()))? = models;
        Ok(())
    }

    /// 撤销一条覆盖。
    pub fn clear_override(&self, model_id: &str) -> Result<()> {
        let _write = self
            .override_write
            .lock()
            .map_err(|_| Error::Store("名单覆盖写锁中毒".to_string()))?;
        if !self
            .overrides_valid
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(Error::Store(
                "本机覆盖文件损坏或不可读，未执行撤销；请先修复或移走 overrides.json".to_string(),
            ));
        }
        let key = self
            .resolve(model_id)
            .map(|m| normalize_key(&m.id))
            .unwrap_or_else(|| normalize_key(model_id));
        let mut models = self
            .overrides
            .read()
            .map_err(|_| Error::Store("名单覆盖锁中毒".to_string()))?
            .clone();
        models.remove(&key);
        models.remove(model_id);
        self.persist_overrides(&models)?;
        *self
            .overrides
            .write()
            .map_err(|_| Error::Store("名单覆盖锁中毒".to_string()))? = models;
        Ok(())
    }

    fn persist_overrides(&self, models: &HashMap<String, ModelOverride>) -> Result<()> {
        if models.is_empty() {
            // 空覆盖 ⇒ 删文件，别留一个 `{}` 让人以为配置还在。
            return match std::fs::remove_file(self.overrides_path()) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(Error::Store(format!("删除覆盖失败: {err}"))),
            };
        }
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| Error::Store(format!("创建名单目录失败: {e}")))?;
        let file = OverridesFile {
            schema_version: CATALOG_SCHEMA_VERSION,
            models: models.clone(),
        };
        let text = serde_json::to_string_pretty(&file)
            .map_err(|e| Error::Store(format!("序列化覆盖失败: {e}")))?;
        let path = self.overrides_path();
        let tmp = self
            .dir
            .join(format!("{OVERRIDES_FILE}.{}.tmp", std::process::id()));
        std::fs::write(&tmp, text).map_err(|e| Error::Store(format!("写入覆盖失败: {e}")))?;
        std::fs::rename(&tmp, &path).map_err(|e| Error::Store(format!("替换覆盖失败: {e}")))
    }
}

/// 把覆盖应用到条目上（只改用户真改过的字段）。
fn apply_override(model: &mut CatalogModel, patch: &ModelOverride) {
    if let Some(window) = patch.context_window.filter(|v| *v > 0) {
        model.context_window = window;
    }
    if let Some(output) = patch.max_output_tokens.filter(|v| *v > 0) {
        model.max_output_tokens = output;
    }
    // `thinking_supported = false` 与 `thinking_level` 同时存在时，**关掉**优先：
    // 否则下一段会把刚设成 None 的 spec 又造出来（覆盖里「关思考」永远失效）。
    if patch.thinking_supported == Some(false) {
        model.thinking = None;
        model.thinking_unsupported = true;
    } else if let Some(level) = patch.thinking_level {
        if level == ThinkingLevel::Off {
            model.thinking = None;
            model.thinking_unsupported = true;
        } else {
            model.thinking_unsupported = false;
            let param = model
                .thinking
                .map(|t| t.param)
                .unwrap_or(ThinkingParam::ReasoningEffort);
            let mut spec = model.thinking.unwrap_or(ThinkingSpec {
                param,
                max_level: level,
                default_level: level,
                budget_low: 0,
                budget_medium: 0,
                budget_high: 0,
                budget_xhigh: 0,
                levels: 0b11111,
            });
            spec.max_level = spec.max_level.max(level);
            spec.default_level = level;
            model.thinking = spec.accepts(level).then_some(spec);
        }
    }
    if let (Some(input), Some(output)) = (patch.price_input_per_mtok, patch.price_output_per_mtok) {
        if input.is_finite() && output.is_finite() && input >= 0.0 && output >= 0.0 {
            let currency = patch
                .price_currency
                .as_deref()
                .map(|c| c.trim().to_ascii_uppercase())
                .filter(|c| c == "USD" || c == "CNY")
                .unwrap_or_else(|| "USD".to_string());
            model.prices = vec![CatalogPrice {
                currency,
                input_per_mtok: input,
                output_per_mtok: output,
                cache_read_per_mtok: None,
                effective_from: 0,
            }];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> String {
        r#"{
          "schemaVersion": 1,
          "generatedAt": "2026-10-01T00:00:00Z",
          "models": [
            {
              "id": "glm-5.3-flash",
              "displayName": "GLM-5.3-Flash",
              "aliases": ["zcode/GLM-5.3-Flash[1m]"],
              "protocol": {"upstream": "openai_chat", "anthropicCompatible": true},
              "limits": {"contextWindow": 1000000, "maxOutputTokens": 128000},
              "thinking": {
                "supported": true, "param": "reasoning_effort",
                "levels": ["off", "low", "medium", "high"],
                "defaultLevel": "medium", "budgetTokens": {"low": 1024, "medium": 8192}
              },
              "prices": [{"currency": "usd", "inputPerMTok": 0.5, "outputPerMTok": 2.0,
                          "effectiveFrom": "2026-10-01"}]
            },
            {"id": "broken", "limits": {"contextWindow": 0, "maxOutputTokens": 1}},
            {"id": "claude-x", "protocol": {"upstream": "anthropic_messages", "anthropicCompatible": true},
             "limits": {"contextWindow": 200000, "maxOutputTokens": 64000}},
            {"id": "filler-1", "protocol": {"upstream": "openai_chat"}, "limits": {"contextWindow": 8000, "maxOutputTokens": 2000}},
            {"id": "filler-2", "protocol": {"upstream": "openai_chat"}, "limits": {"contextWindow": 8000, "maxOutputTokens": 2000}},
            {"id": "filler-3", "protocol": {"upstream": "openai_chat"}, "limits": {"contextWindow": 8000, "maxOutputTokens": 2000}},
            {"id": "filler-4", "protocol": {"upstream": "openai_chat"}, "limits": {"contextWindow": 8000, "maxOutputTokens": 2000}},
            {"id": "filler-5", "protocol": {"upstream": "openai_chat"}, "limits": {"contextWindow": 8000, "maxOutputTokens": 2000}},
            {"id": "filler-6", "protocol": {"upstream": "openai_chat"}, "limits": {"contextWindow": 8000, "maxOutputTokens": 2000}},
            {"id": "filler-7", "protocol": {"upstream": "openai_chat"}, "limits": {"contextWindow": 8000, "maxOutputTokens": 2000}},
            {"id": "filler-8", "protocol": {"upstream": "openai_chat"}, "limits": {"contextWindow": 8000, "maxOutputTokens": 2000}},
            {"id": "filler-9", "protocol": {"upstream": "openai_chat"}, "limits": {"contextWindow": 8000, "maxOutputTokens": 2000}},
            {"id": "filler-10", "protocol": {"upstream": "openai_chat"}, "limits": {"contextWindow": 8000, "maxOutputTokens": 2000}},
            {"id": "filler-11", "protocol": {"upstream": "openai_chat"}, "limits": {"contextWindow": 8000, "maxOutputTokens": 2000}},
            {"id": "filler-12", "protocol": {"upstream": "openai_chat"}, "limits": {"contextWindow": 8000, "maxOutputTokens": 2000}},
            {"id": "filler-13", "protocol": {"upstream": "openai_chat"}, "limits": {"contextWindow": 8000, "maxOutputTokens": 2000}},
            {"id": "filler-14", "protocol": {"upstream": "openai_chat"}, "limits": {"contextWindow": 8000, "maxOutputTokens": 2000}},
            {"id": "filler-15", "protocol": {"upstream": "openai_chat"}, "limits": {"contextWindow": 8000, "maxOutputTokens": 2000}},
            {"id": "filler-16", "protocol": {"upstream": "openai_chat"}, "limits": {"contextWindow": 8000, "maxOutputTokens": 2000}},
            {"id": "filler-17", "protocol": {"upstream": "openai_chat"}, "limits": {"contextWindow": 8000, "maxOutputTokens": 2000}}
          ]
        }"#
        .to_string()
    }

    #[test]
    fn parse_skips_bad_entries_and_counts_them() {
        let (catalog, stats) = Catalog::parse(&sample()).expect("可解析");
        assert_eq!(stats.accepted, 19, "broken 被跳过");
        assert_eq!(stats.skipped, 1);
        assert_eq!(catalog.models.len(), 19);
    }

    #[test]
    fn resolve_handles_vendor_prefix_and_bracket_suffix() {
        let (catalog, _) = Catalog::parse(&sample()).unwrap();
        for name in [
            "glm-5.3-flash",
            "GLM-5.3-Flash",
            "zcode/GLM-5.3-Flash[1m]",
            "  zcode/glm-5.3-flash[1m]  ",
            "zcode/glm-5.3-flash-20261001",
        ] {
            assert_eq!(
                catalog.resolve(name).map(|m| m.id.as_str()),
                Some("glm-5.3-flash"),
                "{name} 应命中"
            );
        }
        assert!(catalog.resolve("no-such-model").is_none());
    }

    #[test]
    fn schema_version_too_high_rejects_whole_file() {
        let text = r#"{"schemaVersion": 99, "models": []}"#;
        let err = Catalog::parse(text).expect_err("必须整份拒绝");
        assert!(err.message.contains("schemaVersion"), "{err}");
    }

    #[test]
    fn missing_required_fields_rejects_file() {
        assert!(Catalog::parse("{}").is_err());
        assert!(Catalog::parse(r#"{"schemaVersion":1}"#).is_err());
        assert!(Catalog::parse("not json").is_err());
    }

    #[test]
    fn price_requires_known_currency_and_non_negative_numbers() {
        let text = r#"{"schemaVersion":1,"models":[{"id":"m","protocol":{"upstream":"openai_chat"},
            "limits":{"contextWindow":10,"maxOutputTokens":5},
            "prices":[{"currency":"EUR","inputPerMTok":1,"outputPerMTok":1},
                      {"currency":"USD","inputPerMTok":-1,"outputPerMTok":1},
                      {"currency":"CNY","inputPerMTok":1.5,"outputPerMTok":3}]}]}"#;
        let (catalog, _) = Catalog::parse(text).unwrap();
        let prices = &catalog.resolve("m").unwrap().prices;
        assert_eq!(prices.len(), 1, "EUR 与负价都必须被丢掉: {prices:?}");
        assert_eq!(prices[0].currency, "CNY");
        assert_eq!(prices[0].effective_from, 0, "没给日期就不猜");
    }

    #[test]
    fn thinking_off_only_means_unsupported() {
        let text = r#"{"schemaVersion":1,"models":[{"id":"m","protocol":{"upstream":"openai_chat"},
            "limits":{"contextWindow":10,"maxOutputTokens":5},
            "thinking":{"supported":true,"param":"thinking","levels":["off"]}}]}"#;
        let (catalog, _) = Catalog::parse(text).unwrap();
        assert!(
            catalog.resolve("m").unwrap().thinking.is_none(),
            "只有 off 等于不支持思考"
        );
    }

    #[test]
    fn thinking_budget_respects_max_level() {
        let (catalog, _) = Catalog::parse(&sample()).unwrap();
        let spec = catalog.resolve("glm-5.3-flash").unwrap().thinking.unwrap();
        assert_eq!(spec.max_level, ThinkingLevel::High);
        assert_eq!(spec.budget(ThinkingLevel::Medium), Some(8192));
        assert_eq!(spec.budget(ThinkingLevel::High), None, "没给预算 ⇒ 不写");
        assert_eq!(spec.budget(ThinkingLevel::Off), None);
    }

    #[test]
    fn meta_projection_carries_thinking_and_protocol() {
        let (catalog, _) = Catalog::parse(&sample()).unwrap();
        let meta = catalog.meta_for("zcode/GLM-5.3-Flash[1m]").unwrap();
        assert_eq!(meta.context_window, 1_000_000);
        assert_eq!(meta.max_output_tokens, 128_000);
        assert_eq!(meta.protocol, UpstreamProtocol::OpenAiChat);
        assert!(meta.anthropic_compatible);
        assert_eq!(
            meta.thinking.map(|t| t.param),
            Some(ThinkingParam::ReasoningEffort)
        );
    }

    #[test]
    fn normalize_key_strips_prefix_and_brackets() {
        assert_eq!(normalize_key("zcode/GLM-5.3-Flash[1m]"), "glm-5.3-flash");
        assert_eq!(normalize_key("  OpenAI/GPT-4o  "), "gpt-4o");
        assert_eq!(normalize_key("kimi-k2[128k]"), "kimi-k2");
        assert_eq!(normalize_key(""), "");
    }

    #[test]
    fn override_applies_only_the_touched_fields() {
        let dir = tempfile::tempdir().unwrap();
        let store = CatalogStore::open(dir.path());
        // `glm-4` 在内置名单里，用它验证「覆盖只改被改的字段」。
        let before = store.resolve("glm-4").expect("内置名单里应有 glm-4");
        let patch = ModelOverride {
            max_output_tokens: Some(4096),
            thinking_supported: Some(false),
            ..Default::default()
        };
        store.set_override("glm-4", patch).unwrap();
        let after = store.resolve("glm-4").unwrap();
        assert_eq!(after.max_output_tokens, 4096);
        assert_eq!(
            after.context_window, before.context_window,
            "没改的字段不动"
        );
        assert!(after.thinking.is_none(), "覆盖可以关掉思考");
        store.clear_override("glm-4").unwrap();
        assert_eq!(store.resolve("glm-4").unwrap(), before);
    }

    #[test]
    fn a_second_override_merges_instead_of_wiping_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = CatalogStore::open(dir.path());
        // 回归：界面只提交「用户改过的那几格」，后端必须合并而不是整条替换——
        // 否则「先设窗口、后改价格」会把窗口那条覆盖悄悄抹掉。
        store
            .set_override(
                "glm-4",
                ModelOverride {
                    context_window: Some(64_000),
                    ..Default::default()
                },
            )
            .unwrap();
        store
            .set_override(
                "glm-4",
                ModelOverride {
                    max_output_tokens: Some(2_048),
                    ..Default::default()
                },
            )
            .unwrap();
        let patch = store.override_for("glm-4").expect("合并后应仍有覆盖");
        assert_eq!(patch.context_window, Some(64_000), "第一次的窗口必须还在");
        assert_eq!(
            patch.max_output_tokens,
            Some(2_048),
            "第二次的输出必须写进去"
        );
        // 空 patch 不等于「清空」——要清就明确调用 clear_override。
        store
            .set_override("glm-4", ModelOverride::default())
            .unwrap();
        assert_eq!(
            store.override_for("glm-4").and_then(|p| p.context_window),
            Some(64_000),
            "空 patch 不该把已有覆盖抹掉"
        );
        store.clear_override("glm-4").unwrap();
        assert!(store.override_for("glm-4").is_none());
    }

    #[test]
    fn closing_thinking_does_not_drop_the_price_in_the_same_patch() {
        let dir = tempfile::tempdir().unwrap();
        let store = CatalogStore::open(dir.path());
        store
            .set_override(
                "o3",
                ModelOverride {
                    thinking_level: Some(ThinkingLevel::Off),
                    price_input_per_mtok: Some(1.25),
                    price_output_per_mtok: Some(2.5),
                    ..Default::default()
                },
            )
            .unwrap();
        let model = store.resolve("o3").unwrap();
        assert!(model.thinking.is_none());
        assert!(model.thinking_unsupported);
        assert_eq!(model.prices[0].input_per_mtok, 1.25);
        assert_eq!(model.prices[0].output_per_mtok, 2.5);
    }

    #[test]
    fn missing_thinking_is_unknown_not_an_instruction_to_disable_it() {
        let (catalog, _) = Catalog::parse(BUNDLED_CATALOG).unwrap();
        let model = catalog.resolve("gpt-4o").unwrap();
        assert!(model.thinking.is_none());
        assert!(!model.thinking_unsupported, "未核对不能推断成不支持");
    }

    #[test]
    fn concurrent_override_patches_keep_both_fields_on_disk_and_in_memory() {
        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(CatalogStore::open(dir.path()));
        for round in 0u32..12 {
            let first = std::sync::Arc::clone(&store);
            let second = std::sync::Arc::clone(&store);
            let context = 64_000 + round;
            let output = 2_048 + round;
            let a = std::thread::spawn(move || {
                let patch = ModelOverride {
                    context_window: Some(context),
                    ..Default::default()
                };
                first.set_override("glm-4", patch)
            });
            let b = std::thread::spawn(move || {
                let patch = ModelOverride {
                    max_output_tokens: Some(output),
                    ..Default::default()
                };
                second.set_override("glm-4", patch)
            });
            a.join().unwrap().unwrap();
            b.join().unwrap().unwrap();
            let patch = store.override_for("glm-4").unwrap();
            let model = store.resolve("glm-4").unwrap();
            assert_eq!(patch.context_window, Some(context));
            assert_eq!(patch.max_output_tokens, Some(output));
            assert_eq!(model.context_window, context);
            assert_eq!(model.max_output_tokens, output);
            let on_disk: OverridesFile =
                serde_json::from_str(&std::fs::read_to_string(store.overrides_path()).unwrap())
                    .unwrap();
            let disk = on_disk.models.get("glm-4").unwrap();
            assert_eq!(disk.context_window, Some(context));
            assert_eq!(disk.max_output_tokens, Some(output));
        }
    }

    #[test]
    fn bundled_catalog_is_parseable_and_has_entries() {
        let (catalog, stats) = Catalog::parse(BUNDLED_CATALOG).expect("内置名单必须可解析");
        assert!(
            catalog.models.len() >= 30,
            "内置名单条数: {}",
            catalog.models.len()
        );
        assert_eq!(stats.skipped, 0, "内置名单不该有坏条目");
        assert_eq!(catalog.schema_version, CATALOG_SCHEMA_VERSION);
    }

    // ==================================================== 同步（P2）

    #[tokio::test]
    async fn sync_rejects_a_catalog_that_is_mostly_garbage() {
        use crate::site::transport::{HttpResponse, MockTransport};
        let dir = tempfile::tempdir().unwrap();
        let store = CatalogStore::open(dir.path());
        // 1 条合规 + 3 条不合规：语法合法、解析只有 1 条——照单接收会把 34 条名单缩成 1 条。
        let body = r#"{"schemaVersion":1,"generatedAt":"2026-10-01T00:00:00Z","models":[
            {"id":"only-one","protocol":{"upstream":"openai_chat"},"limits":{"contextWindow":8000,"maxOutputTokens":1000}},
            {"id":"bad-1","limits":{"contextWindow":0,"maxOutputTokens":1}},
            {"id":"bad-2","protocol":{"upstream":"nope"},"limits":{"contextWindow":8000,"maxOutputTokens":1000}},
            {"id":"bad-3","limits":{"contextWindow":8000,"maxOutputTokens":999999}}
        ]}"#;
        let transport = MockTransport::new(vec![HttpResponse::new(200, body)]);
        let err = store
            .sync(&transport, "https://example.com/models.json", 1_000)
            .await
            .expect_err("坏条目多于好条目必须拒绝");
        assert!(err.contains("整体不可信") || err.contains("骤降"), "{err}");
        assert!(
            store.status(1_000).entries >= 30,
            "必须继续用内置名单: {}",
            store.status(1_000).entries
        );
    }

    #[test]
    fn suffix_stripping_only_removes_numeric_segments() {
        let dir = tempfile::tempdir().unwrap();
        let store = CatalogStore::open(dir.path());
        assert_eq!(
            store.resolve("gpt-4o-2024-08-06").map(|m| m.id),
            Some("gpt-4o".to_string())
        );
        // 回归：`glm-4-air` 不是 `glm-4`——早先无条件剥段会把它认成 glm-4，带着错窗口投递。
        assert!(
            store.resolve("glm-4-air").is_none(),
            "非数字后缀不许被剥掉: {:?}",
            store.resolve("glm-4-air").map(|m| m.id)
        );
    }

    #[test]
    fn an_override_written_under_an_alias_still_applies() {
        let dir = tempfile::tempdir().unwrap();
        let store = CatalogStore::open(dir.path());
        // 回归：覆盖按 normalize 后的**输入**存，但匹配时按 `found.id` 查——用别名或带版本号的
        // 名字写进来会存成一条永不生效的孤儿（界面还标着「本机覆盖」）。
        store
            .set_override(
                "claude-3-5-sonnet-20241022",
                ModelOverride {
                    max_output_tokens: Some(1234),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            store
                .resolve("claude-3-5-sonnet")
                .unwrap()
                .max_output_tokens,
            1234,
            "按别名写的覆盖必须作用到规范条目上"
        );
        assert!(store.override_for("claude-3-5-sonnet").is_some());
        store.clear_override("claude-3-5-sonnet-20241022").unwrap();
        assert!(
            store.override_for("claude-3-5-sonnet").is_none(),
            "清也要清得掉"
        );
    }

    #[test]
    fn thinking_supported_false_beats_a_retained_thinking_level() {
        let dir = tempfile::tempdir().unwrap();
        let store = CatalogStore::open(dir.path());
        store
            .set_override(
                "o3",
                ModelOverride {
                    thinking_level: Some(crate::model_catalog::ThinkingLevel::High),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(store.resolve("o3").unwrap().thinking.is_some());
        // 之后再写一条「关掉思考」：不能因为合并保留了 thinking_level 就又把思考打开了。
        store
            .set_override(
                "o3",
                ModelOverride {
                    thinking_supported: Some(false),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(
            store.resolve("o3").unwrap().thinking.is_none(),
            "thinking_supported=false 必须赢过残留的 thinking_level"
        );
        store
            .set_override(
                "o3",
                ModelOverride {
                    thinking_level: Some(ThinkingLevel::High),
                    ..Default::default()
                },
            )
            .unwrap();
        let reopened = store.resolve("o3").unwrap();
        assert!(reopened.thinking.is_some(), "off 后选 high 必须能重开");
        assert!(!reopened.thinking_unsupported);
        let persisted = CatalogStore::open(dir.path()).resolve("o3").unwrap();
        assert_eq!(
            persisted.thinking.map(|s| s.default_level),
            Some(ThinkingLevel::High)
        );
    }

    #[tokio::test]
    async fn sync_writes_cache_and_keeps_the_old_copy_on_failure() {
        use crate::site::transport::{HttpResponse, MockTransport};

        let dir = tempfile::tempdir().unwrap();
        let store = CatalogStore::open(dir.path());
        let ok = MockTransport::new(vec![HttpResponse::new(200, sample())]);
        let report = store
            .sync(&ok, "https://example.com/models.json", 1_000)
            .await
            .expect("首次同步应成功");
        assert_eq!(report.accepted, 19);
        assert!(!report.unchanged);
        assert!(
            dir.path().join(CATALOG_DIR).join(CACHE_FILE).exists(),
            "必须落盘"
        );
        assert_eq!(
            store.resolve("glm-5.3-flash").map(|m| m.id),
            Some("glm-5.3-flash".to_string())
        );

        // 坏 JSON：整份拒绝，旧缓存不动（这是最重要的一条：坏数据不能冲掉好数据）。
        let bad = MockTransport::new(vec![HttpResponse::new(200, "not a json")]);
        let err = store
            .sync(&bad, "https://example.com/models.json", 2_000)
            .await
            .expect_err("坏 JSON 必须失败");
        assert!(err.contains("名单不可用"), "{err}");
        assert!(
            store.resolve("glm-5.3-flash").is_some(),
            "坏数据之后旧条目必须还在"
        );

        // 非 2xx：同样保留旧缓存。
        let not_found = MockTransport::new(vec![HttpResponse::new(404, "")]);
        assert!(store
            .sync(&not_found, "https://example.com/models.json", 3_000)
            .await
            .is_err());
        assert!(store.resolve("glm-5.3-flash").is_some());

        // 内容没变 ⇒ 回 `unchanged`（不重写文件）。
        let same = MockTransport::new(vec![HttpResponse::new(200, sample())]);
        let again = store
            .sync(&same, "https://example.com/models.json", 4_000)
            .await
            .expect("同内容同步应成功");
        assert!(again.unchanged, "内容相同应报 unchanged");
    }

    #[tokio::test]
    async fn sync_rejects_a_schema_version_from_the_future() {
        use crate::site::transport::{HttpResponse, MockTransport};

        let dir = tempfile::tempdir().unwrap();
        let store = CatalogStore::open(dir.path());
        let future = MockTransport::new(vec![HttpResponse::new(
            200,
            r#"{"schemaVersion": 99, "models": []}"#,
        )]);
        let err = store
            .sync(&future, "https://example.com/models.json", 1_000)
            .await
            .expect_err("未来版本必须整份忽略");
        assert!(err.contains("schemaVersion"), "{err}");
        // 内置那份还在（离线兜底不能被远端坏数据搞没）。
        assert!(store.status(1_000).entries >= 30);
    }
}
