//! 模型元数据：按模型名查上下文窗口 / 最大输出参数。
//!
//! 数据源分两层（按优先级）：
//! 1. **内置 `const` 表**（34 个常见模型）——离线可用，编译期常量；命中即返回，**不联网**。
//! 2. **models.dev 在线补全**（[`OnlineMetaCache`]）——内置表未命中时查 `GET /api.json`，
//!    进程内缓存 1 小时；网络失败 / 超时 / 形态不符一律返回 `None`，**不阻断投递**。
//!
//! 投递路径是同步的，所以在线结果通过 [`OnlineMetaCache::lookup_cached`] 读取
//! （缓存由异步的预热调用填好），同步路径**永不发起网络请求**。
//!
//! GPT 系列的 `context_window` 按 [`GPT_CONTEXT_WINDOW_CAP`]（272K）封顶：
//! 中转站分发的是订阅制窗口，不是 API 的 1.05M。在线条目按名字判（`gpt*`），
//! 内置条目按 `is_gpt` 标记判。

use std::collections::HashMap;

use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::site::transport::{HttpRequest, HttpTransport, Method};

/// GPT 模型的窗口封顶（中转站分发的是订阅制窗口，非 API 的 1.05M）。
pub const GPT_CONTEXT_WINDOW_CAP: u32 = 272_000;

/// 一个模型的投递参数：窗口 / 输出 / 思考能力 / 原生协议。
///
/// **`Copy` 是刻意的**：投递层到处在拷贝它（`resolve_for_binding_with_meta` 每个通道一份），
/// 所以这里只放定长值类型——价格带 `String`/版本，留在
/// [`crate::model_catalog::CatalogPrice`] 里，不进来。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelMeta {
    pub context_window: u32,
    pub max_output_tokens: u32,
    /// 思考能力。`None` = 不知道或不支持 ⇒ 调用方不写任何思考参数。
    pub thinking: Option<crate::model_catalog::ThinkingSpec>,
    /// 只有名单/本机覆盖明确声明不支持时才为 true；未知不删除用户配置。
    pub thinking_unsupported: bool,
    /// 模型**原生**协议（名单给；内置表与 models.dev 都按 OpenAI Chat 记）。
    pub protocol: crate::model_catalog::UpstreamProtocol,
    /// 是否原生兼容 Anthropic Messages（Claude Code 这类客户端要这项）。
    pub anthropic_compatible: bool,
}

impl ModelMeta {
    /// 只带窗口/输出的最小形态（内置表与 models.dev 走这条）。
    const fn new(context_window: u32, max_output_tokens: u32) -> Self {
        Self {
            context_window,
            max_output_tokens,
            thinking: None,
            thinking_unsupported: false,
            protocol: crate::model_catalog::UpstreamProtocol::OpenAiChat,
            anthropic_compatible: false,
        }
    }

    /// 名单条目的投影（`crate::model_catalog::CatalogModel::to_meta` 用它）。
    pub const fn from_catalog(
        context_window: u32,
        max_output_tokens: u32,
        thinking: Option<crate::model_catalog::ThinkingSpec>,
        thinking_unsupported: bool,
        protocol: crate::model_catalog::UpstreamProtocol,
        anthropic_compatible: bool,
    ) -> Self {
        Self {
            context_window,
            max_output_tokens,
            thinking,
            thinking_unsupported,
            protocol,
            anthropic_compatible,
        }
    }
}

/// 内置模型表条目。
struct BuiltinEntry {
    /// 规范化后的模型名（小写）。
    name: &'static str,
    meta: ModelMeta,
    /// 是否为 GPT 系列（需要封顶）。
    is_gpt: bool,
}

/// 内置模型表（34 个）。
///
/// 数值来源：各厂商官方文档 + models.dev。GPT 系列的 `context_window` 已按 272K 封顶写入。
const BUILTIN: &[BuiltinEntry] = &[
    // GPT 系列（context_window 已封顶为 272K）
    BuiltinEntry {
        name: "gpt-4o",
        meta: ModelMeta::new(128_000, 16_384),
        is_gpt: true,
    },
    BuiltinEntry {
        name: "gpt-4o-mini",
        meta: ModelMeta::new(128_000, 16_384),
        is_gpt: true,
    },
    BuiltinEntry {
        name: "gpt-4-turbo",
        meta: ModelMeta::new(128_000, 4_096),
        is_gpt: true,
    },
    BuiltinEntry {
        name: "gpt-4",
        meta: ModelMeta::new(8_192, 4_096),
        is_gpt: true,
    },
    BuiltinEntry {
        name: "gpt-3.5-turbo",
        meta: ModelMeta::new(16_385, 4_096),
        is_gpt: true,
    },
    BuiltinEntry {
        name: "o1",
        meta: ModelMeta::new(200_000, 100_000),
        is_gpt: true,
    },
    BuiltinEntry {
        name: "o1-mini",
        meta: ModelMeta::new(128_000, 65_536),
        is_gpt: true,
    },
    BuiltinEntry {
        name: "o3",
        meta: ModelMeta::new(200_000, 100_000),
        is_gpt: true,
    },
    BuiltinEntry {
        name: "o3-mini",
        meta: ModelMeta::new(200_000, 100_000),
        is_gpt: true,
    },
    // Claude 系列
    BuiltinEntry {
        name: "claude-3-5-sonnet",
        meta: ModelMeta::new(200_000, 8_192),
        is_gpt: false,
    },
    BuiltinEntry {
        name: "claude-3-5-haiku",
        meta: ModelMeta::new(200_000, 8_192),
        is_gpt: false,
    },
    BuiltinEntry {
        name: "claude-3-opus",
        meta: ModelMeta::new(200_000, 4_096),
        is_gpt: false,
    },
    BuiltinEntry {
        name: "claude-3-sonnet",
        meta: ModelMeta::new(200_000, 4_096),
        is_gpt: false,
    },
    BuiltinEntry {
        name: "claude-3-haiku",
        meta: ModelMeta::new(200_000, 4_096),
        is_gpt: false,
    },
    // Gemini 系列
    BuiltinEntry {
        name: "gemini-2.0-flash",
        meta: ModelMeta::new(1_048_576, 8_192),
        is_gpt: false,
    },
    BuiltinEntry {
        name: "gemini-1.5-pro",
        meta: ModelMeta::new(2_097_152, 8_192),
        is_gpt: false,
    },
    BuiltinEntry {
        name: "gemini-1.5-flash",
        meta: ModelMeta::new(1_048_576, 8_192),
        is_gpt: false,
    },
    // DeepSeek
    BuiltinEntry {
        name: "deepseek-chat",
        meta: ModelMeta::new(64_000, 8_192),
        is_gpt: false,
    },
    BuiltinEntry {
        name: "deepseek-reasoner",
        meta: ModelMeta::new(64_000, 8_192),
        is_gpt: false,
    },
    // Qwen
    BuiltinEntry {
        name: "qwen-max",
        meta: ModelMeta::new(32_768, 8_192),
        is_gpt: false,
    },
    BuiltinEntry {
        name: "qwen-plus",
        meta: ModelMeta::new(131_072, 8_192),
        is_gpt: false,
    },
    BuiltinEntry {
        name: "qwen-turbo",
        meta: ModelMeta::new(1_000_000, 8_192),
        is_gpt: false,
    },
    // MiniMax
    BuiltinEntry {
        name: "abab6.5",
        meta: ModelMeta::new(245_760, 8_192),
        is_gpt: false,
    },
    BuiltinEntry {
        name: "abab6.5s",
        meta: ModelMeta::new(245_760, 8_192),
        is_gpt: false,
    },
    // GLM
    BuiltinEntry {
        name: "glm-4",
        meta: ModelMeta::new(128_000, 4_096),
        is_gpt: false,
    },
    BuiltinEntry {
        name: "glm-4-plus",
        meta: ModelMeta::new(128_000, 4_096),
        is_gpt: false,
    },
    BuiltinEntry {
        name: "glm-4-flash",
        meta: ModelMeta::new(128_000, 4_096),
        is_gpt: false,
    },
    // Moonshot
    BuiltinEntry {
        name: "moonshot-v1-8k",
        meta: ModelMeta::new(8_192, 4_096),
        is_gpt: false,
    },
    BuiltinEntry {
        name: "moonshot-v1-32k",
        meta: ModelMeta::new(32_768, 8_192),
        is_gpt: false,
    },
    BuiltinEntry {
        name: "moonshot-v1-128k",
        meta: ModelMeta::new(131_072, 8_192),
        is_gpt: false,
    },
    // Mistral / Llama
    BuiltinEntry {
        name: "mistral-large",
        meta: ModelMeta::new(128_000, 8_192),
        is_gpt: false,
    },
    BuiltinEntry {
        name: "mixtral-8x7b",
        meta: ModelMeta::new(32_768, 8_192),
        is_gpt: false,
    },
    BuiltinEntry {
        name: "llama-3.1-405b",
        meta: ModelMeta::new(131_072, 8_192),
        is_gpt: false,
    },
    BuiltinEntry {
        name: "llama-3.1-70b",
        meta: ModelMeta::new(131_072, 8_192),
        is_gpt: false,
    },
];

/// 内置表索引：规范化模型名 → `BuiltinEntry`。
///
/// 用 `Lazy<HashMap>` 而不是每次线性扫描：34 条虽小，但 `lookup` 在投递路径上、
/// 可能对每条通道各调一次，做成 O(1) 查找。
static BUILTIN_MAP: LazyLock<HashMap<&'static str, &'static BuiltinEntry>> =
    LazyLock::new(|| BUILTIN.iter().map(|e| (e.name, e)).collect());

/// 按模型名查参数（内置表）。
///
/// 查询做大小写不敏感 + 去版本后缀匹配：
/// - `"gpt-4o"` → 命中
/// - `"GPT-4O"` → 命中（大小写不敏感）
/// - `"gpt-4o-2024-08-06"` → 命中 `gpt-4o`（去日期后缀）
/// - `"claude-3-5-sonnet-20241022"` → 命中 `claude-3-5-sonnet`（去版本后缀）
///
/// 返回的 `context_window` 对 GPT 系列已按 272K 封顶。
/// 未命中返回 `None`——调用方只写模型名、不写参数。
pub fn lookup(model: &str) -> Option<ModelMeta> {
    let normalized = normalize(model);
    if normalized.is_empty() {
        return None;
    }

    // 精确命中
    if let Some(entry) = BUILTIN_MAP.get(normalized.as_str()) {
        return Some(apply_cap(entry));
    }

    // 去后缀命中：逐步去掉最后一个 `-` 段
    let mut name = normalized.as_str();
    while let Some(pos) = name.rfind('-') {
        name = &name[..pos];
        if let Some(entry) = BUILTIN_MAP.get(name) {
            return Some(apply_cap(entry));
        }
    }

    None
}

/// GPT 封顶：如果 `is_gpt` 且 `context_window > cap`，封顶。
fn apply_cap(entry: &BuiltinEntry) -> ModelMeta {
    let mut meta = entry.meta;
    if entry.is_gpt && meta.context_window > GPT_CONTEXT_WINDOW_CAP {
        meta.context_window = GPT_CONTEXT_WINDOW_CAP;
    }
    meta
}

/// 规范化：trim + 小写。
fn normalize(s: &str) -> String {
    s.trim().to_lowercase()
}

// ==================================================== models.dev 在线补全（spec §4.2）

/// models.dev 全量目录端点。
pub const MODELS_DEV_URL: &str = "https://models.dev/api.json";

/// 在线目录缓存 TTL（spec §5：进程内缓存 1 小时）。
pub const ONLINE_TTL: Duration = Duration::from_secs(3600);

/// 拉下来的 models.dev 目录，已扁平化成 `模型名 → 参数`。
struct Catalog {
    fetched_at: Instant,
    /// 生产恒为 [`ONLINE_TTL`]；测试注入 `Duration::ZERO` 即可让缓存「立刻过期」，
    /// 不用跟 `Instant` 的时间穿越较劲。
    ttl: Duration,
    by_model: HashMap<String, ModelMeta>,
}

impl Catalog {
    fn fresh(&self) -> bool {
        self.fetched_at.elapsed() < self.ttl
    }
}

/// models.dev 在线补全缓存（进程内、1 小时 TTL）。
///
/// 为什么是**实例**而不是全局 `static`：同步的投递路径需要一份「不联网也能读」的快照
/// （[`OnlineMetaCache::lookup_cached`]），而全局可变缓存会让并发跑的单测互相踩状态。
/// 实例由 `TianshuRelayService` 持有 ⇒ 生产上仍是「一个进程一份缓存，重启后重新拉取」
/// （spec §5 语义），测试之间则天然隔离。
///
/// 锁用 `std::sync::RwLock` 而不是 spec §5 写的 `tokio::sync::RwLock`：同步读也要拿这份
/// 缓存，而 `tokio` 的守卫只能 `await`。读守卫**绝不跨 `.await`**（先 `Arc::clone` 再放锁），
/// 所以不会阻塞执行器。
#[derive(Default)]
pub struct OnlineMetaCache {
    inner: RwLock<Option<Arc<Catalog>>>,
}

impl OnlineMetaCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// 查参数：内置表命中直接返回（**不联网**），否则查 models.dev 目录
    /// （缓存缺失/过期时拉取一次）。
    ///
    /// 网络失败、超时、非 2xx、JSON 形态不符一律返回 `None`——**不是错误**：
    /// 在线补全是增强项，失败必须退化成「只写模型名」，绝不让投递报错（spec §6）。
    pub async fn lookup_online<T: HttpTransport + ?Sized>(
        &self,
        transport: &T,
        model: &str,
    ) -> Option<ModelMeta> {
        if let Some(meta) = lookup(model) {
            return Some(meta);
        }
        let normalized = normalize(model);
        if normalized.is_empty() {
            return None;
        }
        let catalog = self.catalog(transport).await?;
        match_in(&catalog.by_model, &normalized)
    }

    /// 同步读：内置表 → **已缓存**的在线目录。**不联网**（同步的投递路径用这个）。
    pub fn lookup_cached(&self, model: &str) -> Option<ModelMeta> {
        if let Some(meta) = lookup(model) {
            return Some(meta);
        }
        let normalized = normalize(model);
        if normalized.is_empty() {
            return None;
        }
        let catalog = self.fresh_catalog()?;
        match_in(&catalog.by_model, &normalized)
    }

    /// 取目录：缓存新鲜就直接复用，否则拉一次并落缓存。
    async fn catalog<T: HttpTransport + ?Sized>(&self, transport: &T) -> Option<Arc<Catalog>> {
        if let Some(fresh) = self.fresh_catalog() {
            return Some(fresh);
        }
        let fetched = Arc::new(fetch_catalog(transport).await?);
        if let Ok(mut guard) = self.inner.write() {
            *guard = Some(Arc::clone(&fetched));
        }
        Some(fetched)
    }

    fn fresh_catalog(&self) -> Option<Arc<Catalog>> {
        let guard = self.inner.read().ok()?;
        let catalog = guard.as_ref()?;
        if catalog.fresh() {
            Some(Arc::clone(catalog))
        } else {
            None
        }
    }

    /// 仅供测试：改 TTL（`Instant` 在测试里没法穿越，只能让「新鲜」判据变严）。
    #[cfg(test)]
    fn set_ttl_for_test(&self, ttl: Duration) {
        if let Ok(mut guard) = self.inner.write() {
            if let Some(old) = guard.as_ref() {
                *guard = Some(Arc::new(Catalog {
                    fetched_at: old.fetched_at,
                    ttl,
                    by_model: old.by_model.clone(),
                }));
            }
        }
    }
}

/// 拉取并扁平化 models.dev 目录。任何失败都返回 `None`（不抛错、不落事件）。
async fn fetch_catalog<T: HttpTransport + ?Sized>(transport: &T) -> Option<Catalog> {
    let req = HttpRequest::new(Method::Get, MODELS_DEV_URL);
    let resp = transport.request(req).await.ok()?;
    if !(200..300).contains(&resp.status) {
        return None;
    }
    let value = resp.json_value().ok()?;
    Some(Catalog {
        fetched_at: Instant::now(),
        ttl: ONLINE_TTL,
        by_model: flatten(&value),
    })
}

/// models.dev 形态：`Record<provider_id, { models: Record<model_id, { limit: { context, output } }> }>`。
///
/// 只收 **context 与 output 都 > 0** 的条目：缺一个就写不出完整参数，宁可退回「只写模型名」，
/// 也不写一个 `0` 出去（`max_output = 0` 会让 agent 一开口就被截断）。
fn flatten(value: &Value) -> HashMap<String, ModelMeta> {
    let mut out: HashMap<String, ModelMeta> = HashMap::new();
    let Some(providers) = value.as_object() else {
        return out;
    };
    for provider in providers.values() {
        let Some(models) = provider.get("models").and_then(Value::as_object) else {
            continue;
        };
        for (id, entry) in models {
            let limit = entry.get("limit");
            let context = limit.and_then(|l| l.get("context")).and_then(Value::as_u64);
            let output = limit.and_then(|l| l.get("output")).and_then(Value::as_u64);
            let (Some(context), Some(output)) = (context, output) else {
                continue;
            };
            // 超出 u32 的数值按饱和处理：models.dev 里没有这种条目，但真出现时也不能
            // 静默截断成一个更小的窗口（截断比饱和更危险——写小了 agent 会提前压缩）。
            let context = u32::try_from(context).unwrap_or(u32::MAX);
            let output = u32::try_from(output).unwrap_or(u32::MAX);
            if context == 0 || output == 0 {
                continue;
            }
            let key = normalize(id);
            if key.is_empty() {
                continue;
            }
            let meta = ModelMeta::new(cap_for_name(&key, context), output);
            // 同名模型可能挂在多个 provider 下（如 `openai/gpt-4o` 与聚合商）。数值不一致时
            // 保守取**更小的 context**：写小只是提前压缩，写大会被上游拒收。
            match out.get(&key) {
                Some(existing) if existing.context_window <= meta.context_window => {}
                _ => {
                    out.insert(key, meta);
                }
            }
        }
    }
    out
}

/// 在线条目的 GPT 封顶：内置表用 `is_gpt` 标记，在线条目只有名字，就按名字判。
/// 理由与内置表一致——中转站分发的 GPT 窗口是订阅制，写 1.05M 会被上游拒收。
fn cap_for_name(normalized_name: &str, context_window: u32) -> u32 {
    if normalized_name.starts_with("gpt") && context_window > GPT_CONTEXT_WINDOW_CAP {
        GPT_CONTEXT_WINDOW_CAP
    } else {
        context_window
    }
}

/// 目录内匹配：先精确，再逐段去后缀（与内置表同一套口径）。
fn match_in(by_model: &HashMap<String, ModelMeta>, normalized: &str) -> Option<ModelMeta> {
    if let Some(meta) = by_model.get(normalized) {
        return Some(*meta);
    }
    let mut name = normalized;
    while let Some(pos) = name.rfind('-') {
        name = &name[..pos];
        if let Some(meta) = by_model.get(name) {
            return Some(*meta);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exact_hit() {
        let meta = lookup("gpt-4o").unwrap();
        assert_eq!(meta, ModelMeta::new(128_000, 16_384));
    }

    #[test]
    fn case_insensitive() {
        let meta = lookup("GPT-4O").unwrap();
        assert_eq!(meta.context_window, 128_000);
        assert_eq!(meta.max_output_tokens, 16_384);
    }

    #[test]
    fn strips_date_suffix() {
        let meta = lookup("gpt-4o-2024-08-06").unwrap();
        assert_eq!(meta.context_window, 128_000);
    }

    #[test]
    fn strips_version_suffix() {
        let meta = lookup("claude-3-5-sonnet-20241022").unwrap();
        assert_eq!(meta.context_window, 200_000);
        assert_eq!(meta.max_output_tokens, 8_192);
    }

    #[test]
    fn unknown_model_returns_none() {
        assert!(lookup("unknown-model").is_none());
    }

    #[test]
    fn empty_string_returns_none() {
        assert!(lookup("").is_none());
        assert!(lookup("   ").is_none());
    }

    #[test]
    fn gpt_cap_applied() {
        let meta = lookup("o1").unwrap();
        assert!(meta.context_window <= GPT_CONTEXT_WINDOW_CAP);
    }

    #[test]
    fn gpt_cap_not_applied_to_non_gpt() {
        let meta = lookup("gemini-1.5-pro").unwrap();
        assert_eq!(meta.context_window, 2_097_152);
    }

    #[test]
    fn builtin_table_has_at_least_30_models() {
        assert!(BUILTIN.len() >= 30, "内置表只有 {} 条", BUILTIN.len());
    }

    #[test]
    fn all_gpt_entries_are_capped() {
        for entry in BUILTIN.iter().filter(|e| e.is_gpt) {
            assert!(
                entry.meta.context_window <= GPT_CONTEXT_WINDOW_CAP,
                "GPT 模型 {} 的 context_window {} 超过封顶 {}",
                entry.name,
                entry.meta.context_window,
                GPT_CONTEXT_WINDOW_CAP
            );
        }
    }

    #[test]
    fn no_duplicate_names() {
        let mut seen = std::collections::HashSet::new();
        for entry in BUILTIN.iter() {
            assert!(
                seen.insert(entry.name),
                "内置表有重复模型名: {}",
                entry.name
            );
        }
    }

    #[test]
    fn strips_multiple_suffixes() {
        let meta = lookup("gpt-4o-2024-08-06-extra").unwrap();
        assert_eq!(meta.context_window, 128_000);
    }

    #[test]
    fn prefix_match_not_accidental() {
        let meta = lookup("gpt-4o-mini").unwrap();
        assert_eq!(meta.max_output_tokens, 16_384);
        assert_eq!(meta.context_window, 128_000);
    }

    // ==================================================== models.dev 在线补全

    use crate::site::transport::{HttpResponse, MockTransport};

    /// 一份典型的 models.dev 响应：多 provider，含各种残缺形态。
    fn models_dev_response() -> HttpResponse {
        HttpResponse::json(
            200,
            json!({
                "openai": { "models": {
                    "gpt-4o": {"limit": {"context": 1_050_000, "output": 100_000}},
                    "gpt-9-turbo": {"limit": {"context": 1_050_000, "output": 50_000}}
                }},
                "anthropic": { "models": {
                    "claude-sonnet-4-5": {"limit": {"context": 200_000, "output": 64_000}}
                }},
                "alpha": { "models": {
                    "shared-model": {"limit": {"context": 100_000, "output": 8_000}}
                }},
                "zeta": { "models": {
                    "shared-model": {"limit": {"context": 1_000_000, "output": 8_000}}
                }},
                "acme": { "models": {
                    "acme-tiny": {"limit": {"context": 32_000, "output": 4_000}},
                    "acme-no-output": {"limit": {"context": 8_000}},
                    "acme-zero": {"limit": {"context": 0, "output": 0}},
                    "acme-no-limit": {}
                }}
            }),
        )
        .expect("构造 models.dev 响应")
    }

    #[tokio::test]
    async fn online_builtin_hit_never_touches_network() {
        let mock = MockTransport::new(vec![]);
        let cache = OnlineMetaCache::new();
        let meta = cache
            .lookup_online(&mock, "gpt-4o")
            .await
            .expect("内置命中");
        assert_eq!(meta, ModelMeta::new(128_000, 16_384));
        assert_eq!(mock.request_count(), 0, "内置命中不得联网（spec §4.2）");
    }

    #[tokio::test]
    async fn online_miss_fetches_once_then_serves_from_cache() {
        let mock = MockTransport::new(vec![models_dev_response()]);
        let cache = OnlineMetaCache::new();

        let meta = cache
            .lookup_online(&mock, "acme-tiny")
            .await
            .expect("在线命中");
        assert_eq!(meta, ModelMeta::new(32_000, 4_000));
        assert_eq!(mock.request_count(), 1);
        assert_eq!(
            mock.nth_request(0).expect("有请求").url,
            MODELS_DEV_URL,
            "打的是 models.dev 目录端点"
        );

        // 同进程第二次（换一个模型）走缓存，不再联网
        let meta2 = cache
            .lookup_online(&mock, "claude-sonnet-4-5")
            .await
            .expect("缓存命中");
        assert_eq!(meta2, ModelMeta::new(200_000, 64_000));
        assert_eq!(mock.request_count(), 1, "1 小时 TTL 内不得重复拉取");
    }

    #[tokio::test]
    async fn online_suffix_stripped_match() {
        let mock = MockTransport::new(vec![models_dev_response()]);
        let cache = OnlineMetaCache::new();
        let meta = cache
            .lookup_online(&mock, "acme-tiny-2025-01-01")
            .await
            .expect("去后缀命中");
        assert_eq!(meta.context_window, 32_000);
    }

    #[tokio::test]
    async fn online_gpt_cap_applied_by_name() {
        let mock = MockTransport::new(vec![models_dev_response()]);
        let cache = OnlineMetaCache::new();
        let meta = cache
            .lookup_online(&mock, "gpt-9-turbo")
            .await
            .expect("在线命中");
        assert_eq!(
            meta.context_window, GPT_CONTEXT_WINDOW_CAP,
            "在线 GPT 条目也必须按 272K 封顶"
        );
        assert_eq!(meta.max_output_tokens, 50_000);
    }

    #[tokio::test]
    async fn online_skips_incomplete_limits() {
        let mock = MockTransport::new(vec![models_dev_response()]);
        let cache = OnlineMetaCache::new();
        for model in ["acme-no-output", "acme-zero", "acme-no-limit"] {
            assert!(
                cache.lookup_online(&mock, model).await.is_none(),
                "{model} 缺 context/output ⇒ 不写参数（宁可只写模型名，也不写 0）"
            );
        }
    }

    #[tokio::test]
    async fn online_duplicate_model_keeps_smaller_context() {
        let mock = MockTransport::new(vec![models_dev_response()]);
        let cache = OnlineMetaCache::new();
        let meta = cache
            .lookup_online(&mock, "shared-model")
            .await
            .expect("在线命中");
        assert_eq!(
            meta.context_window, 100_000,
            "同名模型挂在多个 provider 下时保守取更小的窗口"
        );
    }

    #[tokio::test]
    async fn online_non_2xx_returns_none() {
        let mock = MockTransport::new(vec![HttpResponse::new(500, Vec::new())]);
        let cache = OnlineMetaCache::new();
        assert!(cache.lookup_online(&mock, "acme-tiny").await.is_none());
    }

    #[tokio::test]
    async fn online_malformed_json_returns_none() {
        let mock = MockTransport::new(vec![HttpResponse::new(200, b"not json".to_vec())]);
        let cache = OnlineMetaCache::new();
        assert!(cache.lookup_online(&mock, "acme-tiny").await.is_none());
    }

    #[tokio::test]
    async fn online_transport_error_returns_none() {
        let mock = MockTransport::new(vec![]);
        mock.push_error(crate::error::Error::Transport("网络不可达".into()));
        let cache = OnlineMetaCache::new();
        assert!(
            cache.lookup_online(&mock, "acme-tiny").await.is_none(),
            "网络失败是「没查到」，不是错误（不影响投递）"
        );
    }

    #[tokio::test]
    async fn online_empty_model_returns_none_without_request() {
        let mock = MockTransport::new(vec![models_dev_response()]);
        let cache = OnlineMetaCache::new();
        assert!(cache.lookup_online(&mock, "").await.is_none());
        assert!(cache.lookup_online(&mock, "   ").await.is_none());
        assert_eq!(mock.request_count(), 0, "空模型名不该触发联网");
    }

    #[tokio::test]
    async fn online_expired_cache_refetches() {
        let mock = MockTransport::new(vec![models_dev_response(), models_dev_response()]);
        let cache = OnlineMetaCache::new();
        assert!(cache.lookup_online(&mock, "acme-tiny").await.is_some());
        assert_eq!(mock.request_count(), 1);

        cache.set_ttl_for_test(Duration::ZERO); // 让缓存立刻过期
        assert!(cache.lookup_online(&mock, "acme-tiny").await.is_some());
        assert_eq!(mock.request_count(), 2, "过期后必须重新拉取");
    }

    #[tokio::test]
    async fn lookup_cached_is_cold_then_hot_without_network() {
        let mock = MockTransport::new(vec![models_dev_response()]);
        let cache = OnlineMetaCache::new();

        assert!(
            cache.lookup_cached("acme-tiny").is_none(),
            "冷缓存不得凭空变出参数（同步路径永不联网）"
        );
        assert_eq!(mock.request_count(), 0);

        cache.lookup_online(&mock, "acme-tiny").await.expect("预热");

        assert_eq!(
            cache.lookup_cached("acme-tiny"),
            Some(ModelMeta::new(32_000, 4_000)),
            "预热后同步读要能拿到在线结果"
        );
        assert_eq!(
            cache.lookup_cached("gpt-4o"),
            Some(ModelMeta::new(128_000, 16_384)),
            "同步读里内置表仍然优先"
        );
        assert_eq!(mock.request_count(), 1, "同步读一次网络都不发");
    }

    // ============================================================ 变异测试

    #[test]
    fn mutation_lookup_returns_none_breaks_this_test() {
        let meta = lookup("gpt-4o");
        assert!(meta.is_some(), "lookup 对已知模型必须返回 Some");
    }

    #[test]
    fn mutation_cap_removed_breaks_this_test() {
        let gpt_entry = BuiltinEntry {
            name: "test-gpt",
            meta: ModelMeta::new(400_000, 4_096),
            is_gpt: true,
        };
        let capped = apply_cap(&gpt_entry);
        assert_eq!(
            capped.context_window, GPT_CONTEXT_WINDOW_CAP,
            "GPT 模型 context_window > 272K 时必须封顶"
        );
    }
}
