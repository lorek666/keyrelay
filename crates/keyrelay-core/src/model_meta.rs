//! 模型元数据：按模型名查上下文窗口 / 最大输出参数。
//!
//! 数据源分两层（按优先级）：
//! 1. **内置 `const` 表**（34 个常见模型）——离线可用，编译期常量。
//! 2. models.dev API（在线补全）——进程内缓存 1 小时，网络失败返回 `None` 不阻断投递。
//!
//! GPT 系列的 `context_window` 按 [`GPT_CONTEXT_WINDOW_CAP`]（272K）封顶：
//! 中转站分发的是订阅制窗口，不是 API 的 1.05M。

use std::collections::HashMap;

use std::sync::LazyLock;

/// GPT 模型的窗口封顶（中转站分发的是订阅制窗口，非 API 的 1.05M）。
pub const GPT_CONTEXT_WINDOW_CAP: u32 = 272_000;

/// 一个模型的上下文/输出参数。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelMeta {
    pub context_window: u32,
    pub max_output_tokens: u32,
}

impl ModelMeta {
    const fn new(context_window: u32, max_output_tokens: u32) -> Self {
        Self {
            context_window,
            max_output_tokens,
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

#[cfg(test)]
mod tests {
    use super::*;

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
