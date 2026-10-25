//! 密钥投递：把钥匙串里的密钥写进某个 agent 的配置文件。
//!
//! 与 `inject` 的分工：`inject` 负责「原子写 + 备份 + 回滚」的机械动作，
//! 本模块负责「写到哪个文件、写哪些字段、用户是否同意」。
//!
//! 红线：
//! - 预览（[`DeliveryPlan`]）里**只有掩码**，永远不含密钥明文。
//! - 投递结果（[`DeliveryOutcome`]）同样不含密钥。
//! - 生成的 [`Patch`] 含密钥，其 `Debug` 已手写脱敏（BACKLOG B-12）。

pub mod claude_code;
pub mod claude_desktop;
pub mod cline;
pub mod cline_desktop;
pub mod codex_auth;
pub mod codex_config;
pub mod cursor;
pub mod deepseek;
pub mod dsh;
pub mod gemini_cli;
pub mod grok_build;
pub mod hermes;
pub mod json_text;
pub mod mcode;
pub mod mimo_code;
pub mod model_check;
pub mod openclaw;
pub mod opencode;
pub mod pi;
pub mod qwen_code;
pub mod trae;

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::inject::Patch;
use crate::model_meta;
use crate::redact::mask_secret;

/// 投递通道：一个通道 = 一个 agent 的一种配置落点。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeliveryChannel {
    /// `~/.codex/auth.json`（本步实现）
    CodexAuthJson,
    /// `~/.codex/config.toml` 的 `[model_providers.custom]` 段（M25-S1）。
    /// 与 [`DeliveryChannel::CodexAuthJson`] 配套投递——同一把 sk 走两个文件。
    CodexConfig,
    /// `~/.claude/settings.json` 的 `env` 段（M1-S3）
    ClaudeCodeSettings,
    /// `~/.config/opencode/opencode.json` 的 `provider.<id>.options`（M6-S1）
    OpenCode,
    /// `~/.gemini/.env`（M6-S1）
    GeminiCli,
    /// `~/.config/opencode/opencode.jsonc`（M7-S3 / B-76）。
    ///
    /// 与 [`DeliveryChannel::OpenCode`] **并存**且互不回退：用户在预览里看到两个落点、
    /// 自己选一个（产品不猜「哪个文件优先」，那正是 B-76 的根因）。
    /// 目标文件必须是**严格 JSON**；带注释/尾随逗号会被拒绝（见 `delivery/mod.rs::jsonc_hazard`
    /// 与 `docs/specs/M7-S3-落点扩展与生效策略.md` §6.2 / §13.1 O-1）。
    OpenCodeJsonc,
    /// Claude Desktop 的 `claude_desktop_config.json`（M14-S1）
    ClaudeDesktop,
    /// `~/.grok/config.toml` 的 `[models.custom]` 段（M14-S1）
    GrokBuild,
    /// `~/.openclaw/openclaw.json`（JSON5，M14-S1）
    OpenClaw,
    /// `~/.hermes/config.yaml`（YAML 标记块，M14-S1）
    Hermes,
    /// `~/.minimax/config.yaml`（YAML 标记块，M14-S1）
    MCode,
    /// `~/.pi/agent/models.json`（JSON，M14-S1）
    Pi,
    /// `~/.cursor/settings.json`（M14-S2）
    Cursor,
    /// VS Code globalStorage Cline 配置（M14-S2）
    Cline,
    /// `~/.qwen/settings.json`（M14-S2）
    QwenCode,
    /// `~/.reasonix/config.json`（M14-S2）
    DeepSeek,
    /// `~/.trae/config.json`（M14-S2）
    Trae,
    /// `~/.mimocode/mimocode.json`（M14-S2）
    MiMoCode,
    /// `~/.cline/data/settings/providers.json`（M14-S3）
    ClineDesktop,
    /// `~/.dsh/.credentials.yaml`（M14-S3）
    DeepSeekHarness,
}

impl DeliveryChannel {
    pub const ALL: [DeliveryChannel; 20] = [
        DeliveryChannel::CodexAuthJson,
        DeliveryChannel::CodexConfig,
        DeliveryChannel::ClaudeCodeSettings,
        DeliveryChannel::OpenCode,
        DeliveryChannel::GeminiCli,
        DeliveryChannel::OpenCodeJsonc,
        DeliveryChannel::ClaudeDesktop,
        DeliveryChannel::GrokBuild,
        DeliveryChannel::OpenClaw,
        DeliveryChannel::Hermes,
        DeliveryChannel::MCode,
        DeliveryChannel::Pi,
        DeliveryChannel::Cursor,
        DeliveryChannel::Cline,
        DeliveryChannel::QwenCode,
        DeliveryChannel::DeepSeek,
        DeliveryChannel::Trae,
        DeliveryChannel::MiMoCode,
        DeliveryChannel::ClineDesktop,
        DeliveryChannel::DeepSeekHarness,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            DeliveryChannel::CodexAuthJson => "codex-auth-json",
            DeliveryChannel::CodexConfig => "codex-config",
            DeliveryChannel::ClaudeCodeSettings => "claude-code-settings",
            DeliveryChannel::OpenCode => "opencode",
            DeliveryChannel::GeminiCli => "gemini-cli",
            DeliveryChannel::OpenCodeJsonc => "opencode-jsonc",
            DeliveryChannel::ClaudeDesktop => "claude-desktop",
            DeliveryChannel::GrokBuild => "grok-build",
            DeliveryChannel::OpenClaw => "openclaw",
            DeliveryChannel::Hermes => "hermes",
            DeliveryChannel::MCode => "mcode",
            DeliveryChannel::Pi => "pi",
            DeliveryChannel::Cursor => "cursor",
            DeliveryChannel::Cline => "cline",
            DeliveryChannel::QwenCode => "qwen-code",
            DeliveryChannel::DeepSeek => "deepseek",
            DeliveryChannel::Trae => "trae",
            DeliveryChannel::MiMoCode => "mimo-code",
            DeliveryChannel::ClineDesktop => "cline-desktop",
            DeliveryChannel::DeepSeekHarness => "dsh",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "codex-auth-json" => Ok(DeliveryChannel::CodexAuthJson),
            "codex-config" => Ok(DeliveryChannel::CodexConfig),
            "claude-code-settings" => Ok(DeliveryChannel::ClaudeCodeSettings),
            "opencode" => Ok(DeliveryChannel::OpenCode),
            "gemini-cli" => Ok(DeliveryChannel::GeminiCli),
            "opencode-jsonc" => Ok(DeliveryChannel::OpenCodeJsonc),
            "claude-desktop" => Ok(DeliveryChannel::ClaudeDesktop),
            "grok-build" => Ok(DeliveryChannel::GrokBuild),
            "openclaw" => Ok(DeliveryChannel::OpenClaw),
            "hermes" => Ok(DeliveryChannel::Hermes),
            "mcode" => Ok(DeliveryChannel::MCode),
            "pi" => Ok(DeliveryChannel::Pi),
            "cursor" => Ok(DeliveryChannel::Cursor),
            "cline" => Ok(DeliveryChannel::Cline),
            "qwen-code" => Ok(DeliveryChannel::QwenCode),
            "deepseek" => Ok(DeliveryChannel::DeepSeek),
            "trae" => Ok(DeliveryChannel::Trae),
            "mimo-code" => Ok(DeliveryChannel::MiMoCode),
            "cline-desktop" => Ok(DeliveryChannel::ClineDesktop),
            "dsh" => Ok(DeliveryChannel::DeepSeekHarness),
            other => Err(Error::NotFound(format!("未知的投递通道: {other}"))),
        }
    }

    /// 该通道服务的 agent 标识，与 `bindings.agent_id` 对齐。
    ///
    /// **必须 1:1**（`from_agent_id(agent_id()) == Some(self)` 对每个通道成立）：
    /// 它是漂移报告的**逆映射**（`bindings.agent_id` → 通道名）。两条通道共享同一个
    /// `agent_id` 时，`.jsonc` 上的漂移会被归到 `.json` 上——**报告错的落点比不报告更糟**
    /// （用户会去检查一个根本没被改过的文件）。`consents` 表不受影响（它按
    /// `UNIQUE(agent_id, channel, target_path)` 存），但漂移这条路只有 `agent_id` 一个键。
    ///
    /// 因此 `OpenCodeJsonc` 的取值是 `"opencode-jsonc"`（与 `as_str()` 一致）：
    /// 它服务的是同一个 agent，但在**漂移归属**上必须是两个可区分的身份。
    /// （章程 §3.3 原本冻结成 `"opencode"`，M7-S0 v1.2 已按此理由更正。）
    pub fn agent_id(self) -> &'static str {
        match self {
            DeliveryChannel::CodexAuthJson => "codex",
            DeliveryChannel::CodexConfig => "codex-config",
            DeliveryChannel::ClaudeCodeSettings => "claude-code",
            DeliveryChannel::OpenCode => "opencode",
            DeliveryChannel::GeminiCli => "gemini-cli",
            DeliveryChannel::OpenCodeJsonc => "opencode-jsonc",
            DeliveryChannel::ClaudeDesktop => "claude-desktop",
            DeliveryChannel::GrokBuild => "grok-build",
            DeliveryChannel::OpenClaw => "openclaw",
            DeliveryChannel::Hermes => "hermes",
            DeliveryChannel::MCode => "mcode",
            DeliveryChannel::Pi => "pi",
            DeliveryChannel::Cursor => "cursor",
            DeliveryChannel::Cline => "cline",
            DeliveryChannel::QwenCode => "qwen-code",
            DeliveryChannel::DeepSeek => "deepseek",
            DeliveryChannel::Trae => "trae",
            DeliveryChannel::MiMoCode => "mimo-code",
            DeliveryChannel::ClineDesktop => "cline-desktop",
            DeliveryChannel::DeepSeekHarness => "dsh",
        }
    }

    /// [`Self::agent_id`] 的逆映射（漂移报告要把 `bindings.agent_id` 还原成通道名）。
    pub fn from_agent_id(agent_id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.agent_id() == agent_id)
    }

    /// 该通道声明的目标路径，**相对于用户目录**。
    ///
    /// 存在的理由（M6-S0）：`service.rs::checked_target` 原先对 `DeliveryChannel` 做穷举
    /// `match` 来取得期望路径，于是「新增一条通道」必须同时改 `delivery` 与 `service`
    /// 两个文件——两个包各改一处就会编译中断。把映射收到通道自己身上之后，
    /// 新增通道只需要改本文件一处，路径白名单自动跟着走。
    ///
    /// 这是**安全边界**：`checked_target` 用它逐字比对投递目标，因此这里返回的路径
    /// 必须与写入器实际写入的路径一致，否则投递会被拒绝（fail-closed）。
    ///
    /// 两条 M6-S1 通道的路径都是**常量**，不随磁盘状态变化：`.jsonc` 存在而 `.json`
    /// 不存在时仍返回 `.json`（见 `docs/specs/M6-S1-通道扩展.md` §11 D-1）。
    pub fn relative_target(self) -> PathBuf {
        match self {
            DeliveryChannel::CodexAuthJson => PathBuf::from(".codex").join("auth.json"),
            DeliveryChannel::CodexConfig => PathBuf::from(".codex").join("config.toml"),
            DeliveryChannel::ClaudeCodeSettings => PathBuf::from(".claude").join("settings.json"),
            DeliveryChannel::OpenCode => PathBuf::from(".config")
                .join("opencode")
                .join("opencode.json"),
            DeliveryChannel::GeminiCli => PathBuf::from(".gemini").join(".env"),
            // M7-S3：两条新通道的落点同样是**常量**（见本函数文档与 M7-S3 spec §4.1）。
            DeliveryChannel::OpenCodeJsonc => PathBuf::from(".config")
                .join("opencode")
                .join("opencode.jsonc"),
            DeliveryChannel::ClaudeDesktop => claude_desktop::relative_config_path(),
            DeliveryChannel::GrokBuild => PathBuf::from(".grok").join("config.toml"),
            DeliveryChannel::OpenClaw => PathBuf::from(".openclaw").join("openclaw.json"),
            DeliveryChannel::Hermes => PathBuf::from(".hermes").join("config.yaml"),
            DeliveryChannel::MCode => PathBuf::from(".minimax").join("config.yaml"),
            DeliveryChannel::Pi => PathBuf::from(".pi").join("agent").join("models.json"),
            DeliveryChannel::Cursor => PathBuf::from(".cursor").join("settings.json"),
            DeliveryChannel::Cline => cline::relative_config_path(),
            DeliveryChannel::QwenCode => PathBuf::from(".qwen").join("settings.json"),
            DeliveryChannel::DeepSeek => PathBuf::from(".reasonix").join("config.json"),
            DeliveryChannel::Trae => PathBuf::from(".trae").join("config.json"),
            DeliveryChannel::MiMoCode => PathBuf::from(".mimocode").join("mimocode.json"),
            DeliveryChannel::ClineDesktop => PathBuf::from(".cline")
                .join("data")
                .join("settings")
                .join("providers.json"),
            DeliveryChannel::DeepSeekHarness => PathBuf::from(".dsh").join(".credentials.yaml"),
        }
    }
}

/// 投递后该 agent 是否需要重启才能读到新配置（PRD FR-4:137 / 章程 R-11 现行裁定：
/// **标注 + 用户确认后一键重启**；旧裁定“只标注、不重启”已被取代）。
///
/// P2-3（后端半）：该通道的**落点文件里是否含 endpoint**。
///
/// `false` ⇒ 切到网关模式时这个通道**只换了令牌、没换地址**：界面必须提示用户去改另一个
/// 文件（Codex 的 endpoint 在 `~/.codex/config.toml`，不在 `auth.json` 里），否则 agent 会把
/// 本地令牌发到站点、拿回 401。
///
/// 判据**不是**「writer 的构造器吃不吃 `base_url`」，而是「**落点文件里到底有没有 endpoint**」——
/// 两者会分叉：`DshWriter::new(home, _base_url)` 收了 `base_url` 却**不使用**
/// （`dsh.rs` 只写 `KEYRELAY_API_KEY`；DSH 的 endpoint 在用户自己配的
/// `~/.dsh/profiles/desktop/cordis.patch.yml` 里，M14-S3 spec §4.3）⇒ 它和 Codex 一样属于
/// 「落点文件里没有 endpoint」。
///
/// 例外集是**显式清单**，并由 `endpoint_in_channel_matches_what_the_writer_writes`
/// 从 writer 真正产出的 `fields` 反推校验（不是复读本函数）。
pub fn channel_carries_endpoint(channel: DeliveryChannel) -> bool {
    !matches!(
        channel,
        DeliveryChannel::CodexAuthJson | DeliveryChannel::DeepSeekHarness
    )
}

// ==================================================== P0-1：每通道必填字段表 + 整单校验
//
// 为什么表是「通道 + 构造输入」的函数，而不是一张静态表：writer 的产出集随构造输入
// 变化——base_url 为空时不写 endpoint 行、model 为空时不写 model 行、meta 缺失时不写
// 模型参数行（见各 writer 的 `fields()`）。一张静态表要么把「只投密钥」的合法投递误杀，
// 要么把「应写 endpoint 却没写」漏过去。于是：
//
// - 调用方（service）从**构造 writer 的同一批输入**（站点/网关 base_url 是否非空、
//   model 是否非空、meta 缓存快照是否存在、opencode 的 provider_id）算出
//   [`FieldSetOptions`]，再与 writer 实际产出的 `fields()` 逐项比对；
// - 表本身是本文件里独立写出的另一份代码（引用各 writer 的 `FIELD_*` 常量，但**不调用**
//   `writer.field_names()` / `writer.fields()`），writer 回归（改了 `fields()` 却漏了一行）
//   会在这里被拦下；矩阵测试 `required_field_table_matches_writer_fields` 钉住「表 == writer
//   产出」，两者任一 drift 都会红。
//
// 锚点是 `fields()`（预览/计划字段），不是 `field_names()`：cline / cline-desktop /
// qwen-code / mimo-code 的 `field_names()`（同意记录用）带限定前缀（如 `providers.apiKey`、
// `model.apiKey`），而 `fields()` 用叶键名（如 `apiKey`）——两处口径本就不同，
// 表跟 `fields()` 走；统一 `field_names()` 口径不在本项范围。
//
// 「多出未知关键字段」的处理：**拒绝**（不是告警后放行）。理由：告警 + 报成功会让一次
// 「写了不该写的东西」的投递被记成成功，而本项的语义就是整单全有或全无；拒绝与
// `checked_target` / `inject` 的 fail-closed 口径一致。
//
// 表里**不含** writer 写盘时的脚手架键：cline-desktop 的 `provider` / `tokenSource` /
// `updatedAt`、cline 的条目 `id` 是固定脚手架，不是本次投递的「关键字段」，
// 故不在表里——它们变了不该让整单校验红，丢了也不影响「密钥 + 端点 + 模型是否齐全」
// 的判断。opencode 的 meta 参数（`limit.context` / `limit.output`）同样不在 `fields()` 里，
// 故也不在表里。

/// plan/apply 校验用的「writer 构造输入」快照。
///
/// `provider_id` 只对 OpenCode / OpenCodeJsonc 有意义（限定键名里的 provider 段）；
/// 其余通道忽略它。`has_meta` 只有在 `has_model` 同时为真时才产生参数行
/// （各 writer 的 meta 参数都包在 `model` 分支里）。
#[derive(Clone, Copy, Debug)]
pub struct FieldSetOptions<'a> {
    pub provider_id: &'a str,
    pub has_endpoint: bool,
    pub has_model: bool,
    pub has_meta: bool,
}

impl<'a> FieldSetOptions<'a> {
    pub fn new(provider_id: &'a str, has_endpoint: bool, has_model: bool, has_meta: bool) -> Self {
        Self {
            provider_id,
            has_endpoint,
            has_model,
            has_meta,
        }
    }
}

/// opencode 的限定键名：`provider.<id>.options.<field>`。
///
/// 与 [`opencode::OpenCodeWriter::qualified_field`] 同规则的镜像（简单标识符走点号分段，
/// 否则走方括号形态）：矩阵测试会把两者逐字钉住，任一侧改规则都会红。
fn opencode_qualified_field(provider_id: &str, field: &str) -> String {
    let simple = !provider_id.is_empty()
        && provider_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if simple {
        format!(
            "{}.{}.{}.{}",
            opencode::OpenCodeWriter::PROVIDER_KEY,
            provider_id,
            opencode::OpenCodeWriter::OPTIONS_KEY,
            field
        )
    } else {
        format!(
            "{}[{}].{}.{}",
            opencode::OpenCodeWriter::PROVIDER_KEY,
            serde_json::to_string(provider_id).unwrap_or_else(|_| format!("\"{provider_id}\"")),
            opencode::OpenCodeWriter::OPTIONS_KEY,
            field
        )
    }
}

/// 该通道在给定构造输入下**必须**产出的字段键名表（顺序与 writer 的 `fields()` 一致）。
///
/// 逐通道摘要（`E` = 仅 `has_endpoint` 时有，`M` = 仅 `has_model` 时有，
/// `P` = 仅 `has_model && has_meta` 时有）：
/// - codex-auth-json：`auth_mode`、`OPENAI_API_KEY`（恒定两项；**不含**任何端点/模型键——
///   api_key 不进 config，endpoint 在另一张表）。
/// - codex-config：`model_provider`、`disable_response_storage`、`[M] model`、`name`、
///   `[E] base_url`、`wire_api`（**不含** api_key——密钥只在 auth.json 里，这是两张表
///   必须分开的理由；混成一张会把「密钥进了 config.toml」误判为正常）。
/// - claude-code-settings：`ANTHROPIC_AUTH_TOKEN`、`[E] ANTHROPIC_BASE_URL`、
///   `[M] ANTHROPIC_MODEL`。
/// - opencode / opencode-jsonc（同一写入器）：`provider.<id>.options.apiKey`、
///   `[E] provider.<id>.options.baseURL`、`[M] model`（meta 不进 `fields()`，故无参数行）。
/// - gemini-cli：`GEMINI_API_KEY`、`[E] GOOGLE_GEMINI_BASE_URL`、`[M] GEMINI_MODEL`。
/// - claude-desktop：`ANTHROPIC_AUTH_TOKEN`、`[E] ANTHROPIC_BASE_URL`（model 被忽略，
///   故无论 `has_model` 都无 model 行）。
/// - grok-build：`api_key`、`[E] base_url`、`[M] model`、`[P] context_window`
///   （meta 只有 context_window，没有 max_tokens）。
/// - openclaw：`api_key`、`[E] base_url`、`[M] model`、`[P] contextWindow`、`[P] maxTokens`。
/// - hermes：`api_key`、`[E] base_url`、`[M] model`、`[P] context_length`
///   （meta 只有 context_length）。
/// - mcode：`api_key`、`[E] base_url`、`[M] model`、`[P] context_window`、`[P] max_tokens`。
/// - pi / deepseek / trae：`api_key`、`[E] base_url`、`[M] model`、
///   `[P] contextWindow`、`[P] maxTokens`。
/// - cursor：`OPENAI_API_KEY`、`[E] OPENAI_BASE_URL`（model 被忽略）。
/// - cline / qwen-code / mimo-code：`apiKey`、`[E] baseUrl`、`[M] model`、
///   `[P] contextWindow`、`[P] maxTokens`（叶键名，见本节头部的口径说明）。
/// - cline-desktop：`apiKey`、`[E] baseUrl`、`[M] modelId`（注意不是 `model`）、
///   `[P] contextWindow`、`[P] maxTokens`。
/// - dsh：恒定只有 `KEYRELAY_API_KEY`——**无端点字段**：`DshWriter` 收了 `base_url` 却不写
///   （DSH 的 endpoint 在用户自配的 profile 文件里），`has_endpoint` / `has_model` /
///   `has_meta` 对它一律无效；DSH 引用校验见 `dsh.rs` 的 P0-3 节（本项已实现）。
pub fn expected_fields(channel: DeliveryChannel, opts: &FieldSetOptions<'_>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |key: String| out.push(key);
    // 条件行：与各 writer `fields()` 里的 gating 逐字对应（base_url 非空 / model 非空 /
    // model 非空且 meta 存在），不得凭空加减。
    let endpoint = opts.has_endpoint;
    let model = opts.has_model;
    let params = opts.has_model && opts.has_meta;
    match channel {
        DeliveryChannel::CodexAuthJson => {
            push(codex_auth::CodexAuthWriter::FIELD_AUTH_MODE.to_string());
            push(codex_auth::CodexAuthWriter::FIELD_API_KEY.to_string());
        }
        DeliveryChannel::CodexConfig => {
            push(codex_config::CodexConfigWriter::FIELD_MODEL_PROVIDER.to_string());
            push(codex_config::CodexConfigWriter::FIELD_DISABLE_RESPONSE_STORAGE.to_string());
            if model {
                push(codex_config::CodexConfigWriter::FIELD_MODEL.to_string());
            }
            push(codex_config::CodexConfigWriter::FIELD_NAME.to_string());
            if endpoint {
                push(codex_config::CodexConfigWriter::FIELD_BASE_URL.to_string());
            }
            push(codex_config::CodexConfigWriter::FIELD_WIRE_API.to_string());
        }
        DeliveryChannel::ClaudeCodeSettings => {
            push(claude_code::ClaudeCodeWriter::FIELD_TOKEN.to_string());
            if endpoint {
                push(claude_code::ClaudeCodeWriter::FIELD_BASE_URL.to_string());
            }
            if model {
                push(claude_code::ClaudeCodeWriter::FIELD_MODEL.to_string());
            }
        }
        DeliveryChannel::OpenCode | DeliveryChannel::OpenCodeJsonc => {
            push(opencode_qualified_field(
                opts.provider_id,
                opencode::OpenCodeWriter::FIELD_API_KEY,
            ));
            if endpoint {
                push(opencode_qualified_field(
                    opts.provider_id,
                    opencode::OpenCodeWriter::FIELD_BASE_URL,
                ));
            }
            if model {
                push(opencode::OpenCodeWriter::FIELD_MODEL.to_string());
            }
        }
        DeliveryChannel::GeminiCli => {
            push(gemini_cli::GeminiCliWriter::FIELD_API_KEY.to_string());
            if endpoint {
                push(gemini_cli::GeminiCliWriter::FIELD_BASE_URL.to_string());
            }
            if model {
                push(gemini_cli::GeminiCliWriter::FIELD_MODEL.to_string());
            }
        }
        DeliveryChannel::ClaudeDesktop => {
            push(claude_desktop::ClaudeDesktopWriter::FIELD_TOKEN.to_string());
            if endpoint {
                push(claude_desktop::ClaudeDesktopWriter::FIELD_BASE_URL.to_string());
            }
        }
        DeliveryChannel::GrokBuild => {
            push(grok_build::GrokBuildWriter::FIELD_API_KEY.to_string());
            if endpoint {
                push(grok_build::GrokBuildWriter::FIELD_BASE_URL.to_string());
            }
            if model {
                push(grok_build::GrokBuildWriter::FIELD_MODEL.to_string());
                if params {
                    push(grok_build::GrokBuildWriter::FIELD_CONTEXT_WINDOW.to_string());
                }
            }
        }
        DeliveryChannel::OpenClaw => {
            push(openclaw::OpenClawWriter::FIELD_API_KEY.to_string());
            if endpoint {
                push(openclaw::OpenClawWriter::FIELD_BASE_URL.to_string());
            }
            if model {
                push(openclaw::OpenClawWriter::FIELD_MODEL.to_string());
                if params {
                    push(openclaw::OpenClawWriter::FIELD_CONTEXT_WINDOW.to_string());
                    push(openclaw::OpenClawWriter::FIELD_MAX_TOKENS.to_string());
                }
            }
        }
        DeliveryChannel::Hermes => {
            push(hermes::HermesWriter::FIELD_API_KEY.to_string());
            if endpoint {
                push(hermes::HermesWriter::FIELD_BASE_URL.to_string());
            }
            if model {
                push(hermes::HermesWriter::FIELD_MODEL.to_string());
                if params {
                    push(hermes::HermesWriter::FIELD_CONTEXT_LENGTH.to_string());
                }
            }
        }
        DeliveryChannel::MCode => {
            push(mcode::MCodeWriter::FIELD_API_KEY.to_string());
            if endpoint {
                push(mcode::MCodeWriter::FIELD_BASE_URL.to_string());
            }
            if model {
                push(mcode::MCodeWriter::FIELD_MODEL.to_string());
                if params {
                    push(mcode::MCodeWriter::FIELD_CONTEXT_WINDOW.to_string());
                    push(mcode::MCodeWriter::FIELD_MAX_TOKENS.to_string());
                }
            }
        }
        DeliveryChannel::Pi => {
            push(pi::PiWriter::FIELD_API_KEY.to_string());
            if endpoint {
                push(pi::PiWriter::FIELD_BASE_URL.to_string());
            }
            if model {
                push(pi::PiWriter::FIELD_MODEL.to_string());
                if params {
                    push(pi::PiWriter::FIELD_CONTEXT_WINDOW.to_string());
                    push(pi::PiWriter::FIELD_MAX_TOKENS.to_string());
                }
            }
        }
        DeliveryChannel::Cursor => {
            push(cursor::CursorWriter::FIELD_API_KEY.to_string());
            if endpoint {
                push(cursor::CursorWriter::FIELD_BASE_URL.to_string());
            }
        }
        DeliveryChannel::Cline => {
            push(cline::ClineWriter::FIELD_API_KEY.to_string());
            if endpoint {
                push(cline::ClineWriter::FIELD_BASE_URL.to_string());
            }
            if model {
                push(cline::ClineWriter::FIELD_MODEL.to_string());
                if params {
                    push(cline::ClineWriter::FIELD_CONTEXT_WINDOW.to_string());
                    push(cline::ClineWriter::FIELD_MAX_TOKENS.to_string());
                }
            }
        }
        DeliveryChannel::QwenCode => {
            push(qwen_code::QwenCodeWriter::FIELD_API_KEY.to_string());
            if endpoint {
                push(qwen_code::QwenCodeWriter::FIELD_BASE_URL.to_string());
            }
            if model {
                push(qwen_code::QwenCodeWriter::FIELD_MODEL.to_string());
                if params {
                    push(qwen_code::QwenCodeWriter::FIELD_CONTEXT_WINDOW.to_string());
                    push(qwen_code::QwenCodeWriter::FIELD_MAX_TOKENS.to_string());
                }
            }
        }
        DeliveryChannel::DeepSeek => {
            push(deepseek::DeepSeekWriter::FIELD_API_KEY.to_string());
            if endpoint {
                push(deepseek::DeepSeekWriter::FIELD_BASE_URL.to_string());
            }
            if model {
                push(deepseek::DeepSeekWriter::FIELD_MODEL.to_string());
                if params {
                    push(deepseek::DeepSeekWriter::FIELD_CONTEXT_WINDOW.to_string());
                    push(deepseek::DeepSeekWriter::FIELD_MAX_TOKENS.to_string());
                }
            }
        }
        DeliveryChannel::Trae => {
            push(trae::TraeWriter::FIELD_API_KEY.to_string());
            if endpoint {
                push(trae::TraeWriter::FIELD_BASE_URL.to_string());
            }
            if model {
                push(trae::TraeWriter::FIELD_MODEL.to_string());
                if params {
                    push(trae::TraeWriter::FIELD_CONTEXT_WINDOW.to_string());
                    push(trae::TraeWriter::FIELD_MAX_TOKENS.to_string());
                }
            }
        }
        DeliveryChannel::MiMoCode => {
            push(mimo_code::MiMoCodeWriter::FIELD_API_KEY.to_string());
            if endpoint {
                push(mimo_code::MiMoCodeWriter::FIELD_BASE_URL.to_string());
            }
            if model {
                push(mimo_code::MiMoCodeWriter::FIELD_MODEL.to_string());
                if params {
                    push(mimo_code::MiMoCodeWriter::FIELD_CONTEXT_WINDOW.to_string());
                    push(mimo_code::MiMoCodeWriter::FIELD_MAX_TOKENS.to_string());
                }
            }
        }
        DeliveryChannel::ClineDesktop => {
            push(cline_desktop::ClineDesktopWriter::FIELD_API_KEY.to_string());
            if endpoint {
                push(cline_desktop::ClineDesktopWriter::FIELD_BASE_URL.to_string());
            }
            if model {
                push(cline_desktop::ClineDesktopWriter::FIELD_MODEL_ID.to_string());
                if params {
                    push(cline_desktop::ClineDesktopWriter::FIELD_CONTEXT_WINDOW.to_string());
                    push(cline_desktop::ClineDesktopWriter::FIELD_MAX_TOKENS.to_string());
                }
            }
        }
        DeliveryChannel::DeepSeekHarness => {
            // 只有密钥字段：base_url / model / meta 输入对它一律无效（见本节头部）。
            push(dsh::DshWriter::FIELD_API_KEY.to_string());
        }
    }
    out
}

/// plan 阶段整单校验：writer 实际产出的 `fields()` 键集必须与
/// [`expected_fields`] **完全相等**（集合意义：顺序不同不算错，重复键算错）。
///
/// - 缺失 ⇒ 整单拒绝：不得只写一部分就报成功；
/// - 多出必填表外的键 ⇒ 同样整单拒绝（本节头部说明了为什么选拒绝而不是告警）；
/// - 重复键 ⇒ 整单拒绝（同一键出现两次，说明 writer 产出本身已坏）。
///
/// 错误用 `Error::Inject`：`Display` 自带目标路径，`reason` 里再逐字带上通道名、
/// 缺失/多出/重复字段名与目标路径——调用方与界面都不需要再拼一次文案。
/// 本函数**不落盘、不读盘**：plan 阶段拒绝时磁盘一个字节都不动。
pub fn validate_plan_fields(
    channel: DeliveryChannel,
    fields: &[DeliveryField],
    opts: &FieldSetOptions<'_>,
    target: &Path,
) -> Result<()> {
    let expected = expected_fields(channel, opts);
    let mut actual: Vec<&str> = fields.iter().map(|f| f.key.as_str()).collect();
    actual.sort_unstable();
    let mut duplicates: Vec<&str> = Vec::new();
    for pair in actual.windows(2) {
        if pair[0] == pair[1] && !duplicates.contains(&pair[0]) {
            duplicates.push(pair[0]);
        }
    }
    let mut expected_sorted: Vec<&str> = expected.iter().map(|k| k.as_str()).collect();
    expected_sorted.sort_unstable();
    let missing: Vec<&str> = expected_sorted
        .iter()
        .copied()
        .filter(|k| !actual.contains(k))
        .collect();
    let unknown: Vec<&str> = actual
        .iter()
        .copied()
        .filter(|k| !expected_sorted.contains(k))
        .collect();
    if missing.is_empty() && unknown.is_empty() && duplicates.is_empty() {
        return Ok(());
    }
    let mut parts: Vec<String> = Vec::new();
    if !missing.is_empty() {
        parts.push(format!("缺失必填字段 [{}]", missing.join(", ")));
    }
    if !unknown.is_empty() {
        parts.push(format!(
            "多出必填表外字段 [{}]（未知关键字段按拒绝处理）",
            unknown.join(", ")
        ));
    }
    if !duplicates.is_empty() {
        parts.push(format!("重复字段 [{}]", duplicates.join(", ")));
    }
    Err(Error::inject(
        target,
        format!(
            "通道 {} 投递字段整单校验失败：{}；目标 {}；该单已拒绝，未写入任何内容",
            channel.as_str(),
            parts.join("；"),
            target.display()
        ),
    ))
}

/// 限定键名的叶段：`provider.keyrelay.options.apiKey` → `apiKey`，
/// `provider["a.b"].options.apiKey` → `apiKey`，裸键名原样返回。
fn leaf_key(qualified: &str) -> &str {
    qualified.rsplit('.').next().unwrap_or(qualified)
}

/// 文本里是否以「键」形态出现某叶键，分两种形态：
/// - 行首键（TOML `api_key =`、YAML `api_key:`、.env `GEMINI_API_KEY=`、
///   JSON5 `apiKey:`、pretty JSON `"apiKey":`）：行首（去前导空白、可选 `export `
///   前缀、可选一个引号）是叶键，且紧跟 `"` / `:` / `=` / 空白；
///   `export` 只认行首可选空白后的 `export` + 空白（与 gemini writer 的
///   `match_assignment` 判定一致），行内其他位置的 `export` 不剥离，`exportKEY`
///   （后无空白）也不剥离；
/// - 紧凑 JSON 的行内键（`{"provider":{...,"apiKey":"..."}}` 整份只有一行，
///   行首判定永远够不着）：行内出现 `"叶键"` 后跟可选空白再跟 `:`。
/// 两种形态都用「叶键后紧跟分隔符」来防误撞：`model` 不会撞上 `model_provider`
/// （后跟 `_`），也不会撞上 `"model_provider":`（后跟 `_` 而非引号）。
fn text_contains_key(text: &str, leaf: &str) -> bool {
    if text.lines().any(|line| {
        let trimmed = line.trim_start();
        // 只认行首可选空白后的 `export` + 空白：`export ` 剥离后继续走叶键判定。
        // 行内其他位置的 export（如 `FOO=export GEMINI_API_KEY=...` 的值部分）
        // 不在行首，不会走到这里；`exportKEY` 后无空白，也不剥离。
        let after_export = match trimmed.strip_prefix("export") {
            Some(tail) if tail.starts_with(' ') || tail.starts_with('\t') => tail.trim_start(),
            _ => trimmed,
        };
        let stripped = after_export.strip_prefix('"').unwrap_or(after_export);
        stripped.starts_with(leaf)
            && stripped[leaf.len()..]
                .chars()
                .next()
                .is_some_and(|c| matches!(c, '"' | ':' | '=' | ' ' | '\t'))
    }) {
        return true;
    }
    let quoted = format!("\"{leaf}\"");
    let mut rest = text;
    while let Some(pos) = rest.find(&quoted) {
        let after = &rest[pos + quoted.len()..];
        if after.trim_start().starts_with(':') {
            return true;
        }
        rest = after;
    }
    false
}

/// 标记块内文本（不含起止标记行本身）：Hermes / MCode / OpenClaw 的
/// keyrelay 块都用这对标记界定归属，块外同名键与本通道无关。
fn marker_slice<'a>(text: &'a str, begin: &str, end: &str) -> Option<&'a str> {
    let start = text.find(begin)? + begin.len();
    let rest = &text[start..];
    let end_pos = rest.find(end)?;
    Some(&rest[..end_pos])
}

/// TOML 里某段的文本：从 `header` 行之后、到下一个段头行之前。
/// 段头行判定与各 TOML writer 一致：去空白后恰为 `[…]` 形态的行。
fn toml_section_slice<'a>(text: &'a str, header: &str) -> Option<&'a str> {
    let mut offset = 0usize;
    let mut start: Option<usize> = None;
    let mut end = text.len();
    for chunk in text.split_inclusive('\n') {
        let trimmed = chunk.trim();
        if start.is_none() {
            if trimmed == header {
                start = Some(offset + chunk.len());
            }
        } else if trimmed.starts_with('[') && trimmed.ends_with(']') {
            end = offset;
            break;
        }
        offset += chunk.len();
    }
    start.map(|s| &text[s..end])
}

/// TOML 里第一个段头行之前的文本（顶层键所在区）。
fn toml_top_slice(text: &str) -> &str {
    let mut offset = 0usize;
    for chunk in text.split_inclusive('\n') {
        let trimmed = chunk.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            return &text[..offset];
        }
        offset += chunk.len();
    }
    text
}

/// YAML 里 `refs:` 段的文本：从 `refs:` 行之后、到下一个顶层键行之前。
/// 顶层键行 = 行首无缩进且含 `:` 的行（DSH 凭据文件只在该段写
/// `KEYRELAY_API_KEY`，段外同名引用与写盘归属无关）。
fn yaml_refs_slice(text: &str) -> Option<&str> {
    let mut offset = 0usize;
    let mut start: Option<usize> = None;
    let mut end = text.len();
    for chunk in text.split_inclusive('\n') {
        let trimmed_end = chunk.trim_end();
        if start.is_none() {
            if trimmed_end == "refs:" {
                start = Some(offset + chunk.len());
            }
        } else if !chunk.starts_with([' ', '\t'])
            && !trimmed_end.is_empty()
            && trimmed_end.contains(':')
        {
            end = offset;
            break;
        }
        offset += chunk.len();
    }
    start.map(|s| &text[s..end])
}

/// JSON 值里按段走访：段不存在、或中途不是对象时返回 `None`
/// （与「键存在但值为 null」区分：后者 `get` 返回 `Some(Null)`，
/// 仍算键存在，与旧的全文件存在性口径一致）。
fn json_walk<'a>(
    value: &'a serde_json::Value,
    segments: &[String],
) -> Option<&'a serde_json::Value> {
    let mut cur = value;
    for seg in segments {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

/// 按归属位置校验单个字段（P1-16，收敛 P2-C7）。
///
/// 旧行为是全文件搜叶键：opencode 任一 provider 的 `apiKey`、
/// Cline 任一条目的 `apiKey`、MiMo / OpenClaw / Pi 的别家条目都能
/// 顶替 keyrelay 条目，写错归属、keyrelay 条目缺失都拦不住。
/// 现在每个通道都在**自己写盘的归属位置**内找叶键：
/// - JSON 对象通道：按写盘路径走访（opencode 用限定键全路径；
///   MiMo `providers.keyrelay`、OpenClaw `models.providers.keyrelay`、
///   Pi `keyrelay`、Qwen `model`、Claude 系 `env`、ClineDesktop
///   `providers.keyrelay.settings`、单租户根写盘通道只认根键，
///   不认嵌套对象里的同名键）；
/// - Cline：`providers` 数组只认 `id == "keyrelay"` 的条目；
/// - OpenClaw：有标记块时只认块内（JSON5 形态解析不成 JSON，
///   块是唯一可信的归属边界），无块时走严格 JSON 路径；
/// - TOML 通道：CodexConfig 的 `name` / `base_url` / `wire_api` 只认
///   `[model_providers.custom]` 段内，其余顶层键只认段前区；
///   GrokBuild 全字段只认 `[models.custom]` 段内；
/// - 标记块通道（Hermes / MCode）：只认 keyrelay 块内，块缺失即缺失；
/// - DSH：只认 `refs:` 段内，段缺失即缺失。
/// 返回 `None` = 该通道无位置感知口径，走旧的全文件叶键搜寻。
/// 目前只有 GeminiCli 走这条回退：它的 `.env` 没有 provider 段或
/// 嵌套结构，每行就是一个赋值，行首键判定本身就是归属判定，
/// 且键名带 `GEMINI_` / `GOOGLE_GEMINI_` 通道专属前缀，不存在
/// 别家 provider 用同一叶键顶替的形态——这不是「弱检查声明」，
/// 而是该文件格式下叶键即归属。不得把这条回退扩到多 provider 通道。
/// JSON 通道解析失败时返回 `Some(false)` 而非回退：写盘器只产
/// 严格 JSON（OpenClaw 标记形态除外），解析失败说明文件已被外部
/// 改成写盘器产不出的形态，fail-closed，不以全文件搜寻放行。
fn scoped_verify_present(channel: DeliveryChannel, qualified: &str, text: &str) -> Option<bool> {
    let leaf = leaf_key(qualified);
    match channel {
        DeliveryChannel::OpenClaw => {
            if let Some(block) = marker_slice(text, openclaw::BLOCK_BEGIN, openclaw::BLOCK_END) {
                return Some(text_contains_key(block, leaf));
            }
            let parsed = serde_json::from_str::<serde_json::Value>(text).ok();
            match parsed {
                Some(v) => {
                    let path = vec![
                        "models".to_string(),
                        "providers".to_string(),
                        "keyrelay".to_string(),
                        leaf.to_string(),
                    ];
                    Some(json_walk(&v, &path).is_some())
                }
                None => Some(false),
            }
        }
        DeliveryChannel::Hermes => {
            let block = match marker_slice(text, hermes::BLOCK_BEGIN, hermes::BLOCK_END) {
                Some(b) => b,
                None => return Some(false),
            };
            Some(text_contains_key(block, leaf))
        }
        DeliveryChannel::MCode => {
            let block = match marker_slice(text, mcode::BLOCK_BEGIN, mcode::BLOCK_END) {
                Some(b) => b,
                None => return Some(false),
            };
            Some(text_contains_key(block, leaf))
        }
        DeliveryChannel::DeepSeekHarness => {
            let refs = match yaml_refs_slice(text) {
                Some(r) => r,
                None => return Some(false),
            };
            Some(text_contains_key(refs, leaf))
        }
        DeliveryChannel::CodexConfig => {
            if matches!(leaf, "name" | "base_url" | "wire_api") {
                let section = match toml_section_slice(
                    text,
                    codex_config::CodexConfigWriter::SECTION_PROVIDER,
                ) {
                    Some(s) => s,
                    None => return Some(false),
                };
                Some(text_contains_key(section, leaf))
            } else {
                Some(text_contains_key(toml_top_slice(text), leaf))
            }
        }
        DeliveryChannel::GrokBuild => {
            let section = match toml_section_slice(text, "[models.custom]") {
                Some(s) => s,
                None => return Some(false),
            };
            Some(text_contains_key(section, leaf))
        }
        DeliveryChannel::Cline
        | DeliveryChannel::OpenCode
        | DeliveryChannel::OpenCodeJsonc
        | DeliveryChannel::ClaudeCodeSettings
        | DeliveryChannel::ClaudeDesktop
        | DeliveryChannel::QwenCode
        | DeliveryChannel::MiMoCode
        | DeliveryChannel::Pi
        | DeliveryChannel::ClineDesktop
        | DeliveryChannel::Cursor
        | DeliveryChannel::DeepSeek
        | DeliveryChannel::Trae
        | DeliveryChannel::CodexAuthJson => {
            let parsed = match serde_json::from_str::<serde_json::Value>(text) {
                Ok(v) => v,
                Err(_) => return Some(false),
            };
            let present = match channel {
                DeliveryChannel::Cline => parsed
                    .get("providers")
                    .and_then(|p| p.as_array())
                    .and_then(|arr| {
                        arr.iter().find(|item| {
                            item.get("id").and_then(|i| i.as_str()) == Some("keyrelay")
                        })
                    })
                    .is_some_and(|entry| entry.get(leaf).is_some()),
                DeliveryChannel::OpenCode | DeliveryChannel::OpenCodeJsonc => {
                    json_walk(&parsed, &split_qualified_key(qualified)).is_some()
                }
                DeliveryChannel::ClaudeCodeSettings | DeliveryChannel::ClaudeDesktop => {
                    json_walk(&parsed, &["env".to_string(), leaf.to_string()]).is_some()
                }
                DeliveryChannel::QwenCode => {
                    json_walk(&parsed, &["model".to_string(), leaf.to_string()]).is_some()
                }
                DeliveryChannel::MiMoCode => json_walk(
                    &parsed,
                    &[
                        "providers".to_string(),
                        "keyrelay".to_string(),
                        leaf.to_string(),
                    ],
                )
                .is_some(),
                DeliveryChannel::Pi => {
                    json_walk(&parsed, &["keyrelay".to_string(), leaf.to_string()]).is_some()
                }
                DeliveryChannel::ClineDesktop => json_walk(
                    &parsed,
                    &[
                        "providers".to_string(),
                        "keyrelay".to_string(),
                        "settings".to_string(),
                        leaf.to_string(),
                    ],
                )
                .is_some(),
                _ => json_walk(&parsed, &[leaf.to_string()]).is_some(),
            };
            Some(present)
        }
        // GeminiCli：见本函数文档，`.env` 行首赋值即归属，走回退。
        DeliveryChannel::GeminiCli => None,
    }
}

/// 字段是否在其归属位置内存在：有位置感知口径时用它，否则回退到
/// 全文件叶键搜寻（目前仅 GeminiCli，理由见 `scoped_verify_present`）。
fn field_present_in_scope(channel: DeliveryChannel, qualified: &str, text: &str) -> bool {
    match scoped_verify_present(channel, qualified, text) {
        Some(present) => present,
        None => text_contains_key(text, leaf_key(qualified)),
    }
}

/// apply 后回读比对：读回目标文件，确认必填表里每个字段都在其
/// **归属位置**内存在（见 `scoped_verify_present`，P1-16）。
///
/// 只做**键存在性**比对，不做值比对——值相等已由 `inject` 的字节级回读保证
/// （落盘内容必须与 `patch.after` 逐字节相等）；这里补的是「写完后文件又被改动」
/// 以及「inject 回读语义未来变化」那一层。返回 `Err` 时调用方**必须**走失败补偿
/// （回滚），不得只记一条日志就报成功。
pub fn verify_applied_fields(
    channel: DeliveryChannel,
    expected: &[String],
    target: &Path,
) -> Result<()> {
    let text = std::fs::read_to_string(target).map_err(|e| {
        Error::inject(
            target,
            format!(
                "通道 {} 投递后回读失败：{e}；目标 {}；该单视为投递失败",
                channel.as_str(),
                target.display()
            ),
        )
    })?;
    let missing: Vec<&str> = expected
        .iter()
        .map(|k| k.as_str())
        .filter(|k| !field_present_in_scope(channel, k, &text))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(Error::inject(
        target,
        format!(
            "通道 {} 投递后回读比对失败：文件中缺失字段 [{}]；目标 {}；该单视为投递失败",
            channel.as_str(),
            missing.join(", "),
            target.display()
        ),
    ))
}

// ==================================================== P1-7：首次导入（只读）
//
// 触发条件（服务层定，见 `delivery_plan` 的构造处）：该目标文件上
// **没有任何生效中的绑定**（`bindings_of_target` 里 `unbound_at` 全为空
// 之外，即从未成功投递过、或此前投递已解绑）时，本次预览才算「首次投递」
// 并做导入；已投递过的通道不再导入——文件里的内容已是本产品上次写下
// 的，diff 预览本身就是它与新内容的对照，再导入是重复信息。
//
// 只读保证（四层，缺一层都不算只读）：
// 1. 本函数是纯函数：入参只有通道、必填键表、文件文本、provider 名，
//    不读环境变量、不触磁盘；读盘只发生在调用方那一次 `read`，
//    且读盘函数（`json_text::read_text_or_empty`）在文件不存在时返回空串、
//    绝不创建文件；
// 2. 导入的值**只进预览结构体**（`DeliveryPlan.imported_fields`），
//    绝不 feed 回 `writer.plan()` / `fields()` / apply 路径——写进去的
//    永远是本次投递构造的字段，不是文件里旧值。用户想沿用旧值，
//    必须自己把它填成投递参数并确认后才写盘；
// 3. 密钥类叶键一律掩码（`mask_secret`，只露末 4 位），与 `fields()` 的
//    掩码口径一致；非密钥值（端点、模型、窗口数）按原文展示；
// 4. 拿不准就不导入：见下文「保守规则」，宁可少导入一项，也不把
//    别人的值安到本通道名下。
//
// 提取规则（两路，JSON 成功只走 JSON 路，JSON 失败才走行扫描）：
// - JSON 路：把文件解析成 JSON 对象后按**路径**匹配。限定键
//   （opencode 的 `provider.<id>.options.<leaf>`，含方括号形态的带点
//   provider 名）必须整条路径逐段相等；裸叶键**只在 keyrelay 归属
//   子树内**取第一项（P1-17，收敛 P2-C8）：Cline 的 `providers` 数组
//   只认 `id == "keyrelay"` 的条目，MiMo 只认 `providers.keyrelay`、
//   OpenClaw 只认 `models.providers.keyrelay`、Pi 只认顶层 `keyrelay`、
//   Qwen 只认 `model`、Claude 系只认 `env`、ClineDesktop 只认
//   `providers.keyrelay.settings`、根写盘通道只认根级标量——数组 /
//   对象里别的 provider 的密钥绝不能被当成 keyrelay 的旧值。
//   OpenClaw 的 JSON5 标记形态解析不成 JSON：改走标记块内 JSON
//   对象（块是写盘归属边界），块缺失或块解析失败时不猜。
// - 行扫描路（TOML / YAML / .env / 失去 JSON 形态的文件）：逐行按
//   「行首可选 `export ` + 可选引号 + 叶键 + 分隔符（`"` / `:` / `=` /
//   空白）」匹配，与 P0-1 回读 `text_contains_key` 的分隔符口径一致，
//   因此 `model` 不会撞上 `model_provider`。值取引号内原文，
//   无引号取第一个空白分隔的 token（并去尾随逗号）。行扫描同样
//   按归属切片：Hermes / MCode 只扫 keyrelay 标记块内、DSH 只扫
//   `refs:` 段内、CodexConfig / GrokBuild 按 TOML 段切片（与回读
//   口径同源）；切片缺失时不扫全文。
// - 保守规则：opencode 两通道、Cline 与 OpenClaw 通道**不走行扫描**——它们的
//   文件里可能有多个 provider 条目，行扫描分不清「这行属于哪个
//   provider」，而 JSON 路能按路径 / id 分清；JSON 解析失败
//   （如 .jsonc 带注释）时导入为空，不猜。`expected` 表外的键一律不导入
//   （导入范围 = 本次投递的必填表，与整单校验同一张表）。
//
// 返回：只含「找到了」的项（键 + 展示值）；没找到的键不在返回里，
// 调用方不得把它解读成「旧值为空」——没找到只说明「本次导入没拿到」。

/// 导入展示里算「密钥」的叶键：含 `api_key` / `apikey` / `token` 任一子串
/// 即掩码。`auth_mode`（值为字面量 `"apikey"`）不在此列——它不含上述子串，
/// 按原文展示，与 `fields()` 里它是字面量字段的口径一致。
fn is_secret_import_key(leaf: &str) -> bool {
    let lower = leaf.to_ascii_lowercase();
    lower.contains("api_key") || lower.contains("apikey") || lower.contains("token")
}

/// 导入项的展示值：密钥掩码，非密钥原文。
fn import_display_value(leaf: &str, value: &str) -> String {
    if is_secret_import_key(leaf) {
        mask_secret(value)
    } else {
        value.to_string()
    }
}

/// 限定键名切段：`provider.keyrelay.options.apiKey` → 4 段；
/// `provider["a.b"].options.apiKey` → `provider` / `a.b` / `options` / `apiKey`。
/// 方括号内按 JSON 字符串解析，解析失败则按原文取段（不因此拒绝整单导入）。
fn split_qualified_key(qualified: &str) -> Vec<String> {
    let mut segments: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut chars = qualified.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '.' => {
                segments.push(std::mem::take(&mut current));
            }
            '[' => {
                if !current.is_empty() {
                    segments.push(std::mem::take(&mut current));
                }
                let mut bracket = String::new();
                for bc in chars.by_ref() {
                    if bc == ']' {
                        break;
                    }
                    bracket.push(bc);
                }
                let unquoted = serde_json::from_str::<String>(&bracket)
                    .unwrap_or_else(|_| bracket.trim_matches('"').to_string());
                segments.push(unquoted);
                if chars.peek() == Some(&'.') {
                    chars.next();
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        segments.push(current);
    }
    segments
}

/// JSON 值走访：产出（路径段，标量字符串）序列（文档顺序）。
///
/// Cline 通道专属规则：`providers` 数组里只走访 `id == "keyrelay"` 的
/// 对象条目，其余条目整个跳过（它们的密钥不是本通道的旧值）。
/// 其余通道：数组元素一律走访（单租户配置文件，叶键无归属歧义）。
fn collect_json_values(
    value: &serde_json::Value,
    path: &mut Vec<String>,
    channel: DeliveryChannel,
    out: &mut Vec<(Vec<String>, String)>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                path.push(key.clone());
                collect_json_values(child, path, channel, out);
                path.pop();
            }
        }
        serde_json::Value::Array(items) => {
            let in_providers = path.last().map(|s| s.as_str()) == Some("providers");
            for item in items {
                if channel == DeliveryChannel::Cline
                    && in_providers
                    && item.get("id").and_then(|i| i.as_str()) != Some("keyrelay")
                {
                    continue;
                }
                collect_json_values(item, path, channel, out);
            }
        }
        serde_json::Value::String(s) => {
            out.push((path.clone(), s.clone()));
        }
        serde_json::Value::Number(n) => {
            out.push((path.clone(), n.to_string()));
        }
        serde_json::Value::Bool(b) => {
            out.push((path.clone(), b.to_string()));
        }
        serde_json::Value::Null => {}
    }
}

/// 多 provider 对象文件的 keyrelay 定向过滤（P1-17，收敛 P2-C8）。
///
/// 返回 `Some` = 该通道的 JSON 导入只认 keyrelay 归属子树内的值；
/// `None` = 沿用全文档走访（opencode 靠限定键全路径已定向；
/// Cline 靠 `collect_json_values` 内的数组过滤）。
/// - MiMo：`providers.keyrelay`；OpenClaw：`models.providers.keyrelay`；
///   Pi：顶层 `keyrelay`；Qwen：`model`；Claude 系：`env`；
///   ClineDesktop：`providers.keyrelay.settings`；
/// - 根写盘通道（Cursor / DeepSeek / Trae / CodexAuthJson）：只认根级
///   标量，不认嵌套对象里的同名键（写盘器只写根级）。
/// 归属子树缺失时返回空序列（宁缺不猜），不回退全文档。
fn scoped_json_values(
    channel: DeliveryChannel,
    parsed: &serde_json::Value,
) -> Option<Vec<(Vec<String>, String)>> {
    if matches!(
        channel,
        DeliveryChannel::Cursor
            | DeliveryChannel::DeepSeek
            | DeliveryChannel::Trae
            | DeliveryChannel::CodexAuthJson
    ) {
        let mut out: Vec<(Vec<String>, String)> = Vec::new();
        if let Some(map) = parsed.as_object() {
            for (key, child) in map {
                match child {
                    serde_json::Value::String(s) => {
                        out.push((vec![key.clone()], s.clone()));
                    }
                    serde_json::Value::Number(n) => {
                        out.push((vec![key.clone()], n.to_string()));
                    }
                    serde_json::Value::Bool(b) => {
                        out.push((vec![key.clone()], b.to_string()));
                    }
                    _ => {}
                }
            }
        }
        return Some(out);
    }
    let scope: Vec<String> = match channel {
        DeliveryChannel::MiMoCode => vec!["providers".into(), "keyrelay".into()],
        DeliveryChannel::OpenClaw => {
            vec!["models".into(), "providers".into(), "keyrelay".into()]
        }
        DeliveryChannel::Pi => vec!["keyrelay".into()],
        DeliveryChannel::QwenCode => vec!["model".into()],
        DeliveryChannel::ClaudeCodeSettings | DeliveryChannel::ClaudeDesktop => {
            vec!["env".into()]
        }
        DeliveryChannel::ClineDesktop => {
            vec!["providers".into(), "keyrelay".into(), "settings".into()]
        }
        _ => return None,
    };
    let Some(subtree) = json_walk(parsed, &scope) else {
        return Some(Vec::new());
    };
    let mut out: Vec<(Vec<String>, String)> = Vec::new();
    collect_json_values(subtree, &mut scope.clone(), channel, &mut out);
    Some(out)
}

/// 行扫描路的值解析：引号内取原文，无引号取首个 token（去尾随逗号）。
/// 返回 `None` = 该行没有可用值（空值行不算「找到」）。
fn parse_line_value(rest: &str) -> Option<String> {
    let rest = rest.trim_start();
    if rest.is_empty() {
        return None;
    }
    if let Some(quoted) = rest.strip_prefix('"').or_else(|| rest.strip_prefix('\'')) {
        let quote = rest.chars().next().unwrap();
        let end = quoted.find(quote)?;
        let value = &quoted[..end];
        return if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        };
    }
    let token: String = rest
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != '#')
        .collect();
    let token = token.trim_end_matches(',');
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// 行扫描路：某叶键在文本里的首个值（见本节头部的行匹配口径）。
fn scan_line_value(text: &str, leaf: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim_start();
        let after_export = match trimmed.strip_prefix("export") {
            Some(tail) if tail.starts_with(' ') || tail.starts_with('\t') => tail.trim_start(),
            _ => trimmed,
        };
        let stripped = after_export.strip_prefix('"').unwrap_or(after_export);
        if !stripped.starts_with(leaf) {
            continue;
        }
        let next = stripped[leaf.len()..].chars().next()?;
        if !matches!(next, '"' | ':' | '=' | ' ' | '\t') {
            continue;
        }
        let after_key = stripped[leaf.len()..].trim_start_matches(['"', ' ', '\t']);
        let after_sep = after_key
            .strip_prefix(':')
            .or_else(|| after_key.strip_prefix('='))?;
        if let Some(value) = parse_line_value(after_sep) {
            return Some(value);
        }
    }
    None
}

/// 从现有配置文件文本里只读提取必填键的现有值（纯函数，见本节头部）。
///
/// `expected` 是本次投递的必填键表（与 P0-1 整单校验同一张表）；
/// opencode 的 provider 段已含在限定键名里，不另传 provider 名。
pub fn import_existing_fields(
    channel: DeliveryChannel,
    expected: &[String],
    text: &str,
) -> Vec<DeliveryField> {
    if text.trim().is_empty() {
        return Vec::new();
    }
    let mut out: Vec<DeliveryField> = Vec::new();
    // OpenClaw 标记形态：整份是 JSON5（带注释 / 标记块），解析不成
    // JSON 时不走行扫描——只认标记块内的 JSON 对象，块缺失或块
    // 解析失败时返回空（宁缺不猜，别家条目在块外）。
    if channel == DeliveryChannel::OpenClaw {
        if let Some(block) = marker_slice(text, openclaw::BLOCK_BEGIN, openclaw::BLOCK_END) {
            let Ok(block_value) = serde_json::from_str::<serde_json::Value>(block) else {
                return Vec::new();
            };
            let Some(block_map) = block_value.as_object() else {
                return Vec::new();
            };
            for key in expected {
                let leaf = leaf_key(key);
                let found = block_map.get(leaf).and_then(|v| match v {
                    serde_json::Value::String(s) => Some(s.clone()),
                    serde_json::Value::Number(n) => Some(n.to_string()),
                    serde_json::Value::Bool(b) => Some(b.to_string()),
                    _ => None,
                });
                if let Some(value) = found {
                    out.push(DeliveryField {
                        key: key.clone(),
                        masked: import_display_value(leaf, &value),
                    });
                }
            }
            return out;
        }
    }
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(text) {
        if !parsed.is_object() {
            return Vec::new();
        }
        let collected: Vec<(Vec<String>, String)> = match scoped_json_values(channel, &parsed) {
            Some(scoped) => scoped,
            None => {
                let mut all: Vec<(Vec<String>, String)> = Vec::new();
                collect_json_values(&parsed, &mut Vec::new(), channel, &mut all);
                all
            }
        };
        for key in expected {
            let segments = split_qualified_key(key);
            let leaf = segments.last().cloned().unwrap_or_default();
            let found = if segments.len() > 1 {
                collected
                    .iter()
                    .find(|(path, _)| *path == segments)
                    .map(|(_, v)| v.clone())
            } else {
                collected
                    .iter()
                    .find(|(path, _)| path.last().map(|s| s.as_str()) == Some(leaf.as_str()))
                    .map(|(_, v)| v.clone())
            };
            if let Some(value) = found {
                out.push(DeliveryField {
                    key: key.clone(),
                    masked: import_display_value(&leaf, &value),
                });
            }
        }
        return out;
    }
    // JSON 解析失败：只有非 provider 作用域的通道才走行扫描；
    // opencode / Cline / OpenClaw 的文件可能含多 provider 条目，行扫描
    // 分不清归属，宁缺（OpenClaw 标记块已在上文处理，无块即无导入）。
    if matches!(
        channel,
        DeliveryChannel::OpenCode
            | DeliveryChannel::OpenCodeJsonc
            | DeliveryChannel::Cline
            | DeliveryChannel::OpenClaw
    ) {
        return Vec::new();
    }
    for key in expected {
        let leaf = leaf_key(key);
        // 行扫描同样按归属切片（与回读口径同源），切片缺失时不扫全文。
        let value = match channel {
            DeliveryChannel::Hermes => marker_slice(text, hermes::BLOCK_BEGIN, hermes::BLOCK_END)
                .and_then(|block| scan_line_value(block, leaf)),
            DeliveryChannel::MCode => marker_slice(text, mcode::BLOCK_BEGIN, mcode::BLOCK_END)
                .and_then(|block| scan_line_value(block, leaf)),
            DeliveryChannel::DeepSeekHarness => {
                yaml_refs_slice(text).and_then(|refs| scan_line_value(refs, leaf))
            }
            DeliveryChannel::CodexConfig => {
                let slice = if matches!(leaf, "name" | "base_url" | "wire_api") {
                    toml_section_slice(text, codex_config::CodexConfigWriter::SECTION_PROVIDER)
                } else {
                    Some(toml_top_slice(text))
                };
                slice.and_then(|part| scan_line_value(part, leaf))
            }
            DeliveryChannel::GrokBuild => toml_section_slice(text, "[models.custom]")
                .and_then(|section| scan_line_value(section, leaf)),
            _ => scan_line_value(text, leaf),
        };
        if let Some(value) = value {
            out.push(DeliveryField {
                key: key.clone(),
                masked: import_display_value(leaf, &value),
            });
        }
    }
    out
}

/// 纯函数、无 IO。UI **必须**调用它取文案，不得在界面里硬编码判断——否则新增通道时又会漏一处。
///
/// P1-6 生效分表：不再一刀切 Needed。
/// - Claude Code：新会话即生效（无需重启进程）→ `DependsOnNewSession`。注意不是
///   `NotNeeded`：`NotNeeded` 的语义是「每次运行都重读」，而 cc-switch FAQ 说的是
///   provider 热切，且本项未在真机上验证运行中会话是否重读 env；`NotNeeded` 仍被
///   `restart_hint_does_not_use_not_needed_yet` 禁止，未经实测不得标。
/// - 其余 19 条：仍为 `Needed`（启动时读配置）。其中 Codex / Gemini / Grok /
///   Claude Desktop 的具体动作见 `restart_hint_detail`；其余通道只有通用说法。
/// 保守方向（M7-S3 spec §8）不变：多提示一次重启无害；反过来（说「改完即生效」
/// 而其实没生效）会让用户以为投递失败。
pub fn restart_hint(channel: DeliveryChannel) -> RestartHint {
    match channel {
        DeliveryChannel::ClaudeCodeSettings => RestartHint::DependsOnNewSession,
        DeliveryChannel::CodexAuthJson
        | DeliveryChannel::CodexConfig
        | DeliveryChannel::OpenCode
        | DeliveryChannel::GeminiCli
        | DeliveryChannel::OpenCodeJsonc
        | DeliveryChannel::ClaudeDesktop
        | DeliveryChannel::GrokBuild
        | DeliveryChannel::OpenClaw
        | DeliveryChannel::Hermes
        | DeliveryChannel::MCode
        | DeliveryChannel::Pi
        | DeliveryChannel::Cursor
        | DeliveryChannel::Cline
        | DeliveryChannel::QwenCode
        | DeliveryChannel::DeepSeek
        | DeliveryChannel::Trae
        | DeliveryChannel::MiMoCode
        // B-292：ClineDesktop 已下线，此取值已无投递语义，仅为穷举 match 保留，
        // 不得据此向用户承诺任何生效方式（投递面已无该通道，见下线测试）。
        | DeliveryChannel::ClineDesktop
        | DeliveryChannel::DeepSeekHarness => RestartHint::Needed,
    }
}

/// 按 channel 决定网关 base_url 是否带 `/v1`（P1-5 / P1-2）。
///
/// Claude Code（Anthropic SDK）的 `ANTHROPIC_BASE_URL` 不带 `/v1`——SDK 自己拼 `/v1/messages`，
/// 给它带 `/v1` 会变成 `/v1/v1/messages`。OpenAI / Codex 等 SDK 的 base_url 带 `/v1`（SDK 拼 `/chat/completions`）。
///
/// P1-2：`service::rotate_key` 构造 Gateway endpoint 时也调它，保证轮换后 base_url 与原投递同口径。
pub fn gateway_base_url_for(channel: &DeliveryChannel, local_url: &str) -> String {
    match channel {
        DeliveryChannel::ClaudeCodeSettings | DeliveryChannel::ClaudeDesktop => {
            local_url.to_string()
        }
        _ => format!("{}/v1", local_url),
    }
}

/// 生效策略（章程 §3.3 冻结）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartHint {
    /// 进程每次读配置，改完即生效。
    ///
    /// **当前没有任何通道返回它**：本波次六条通道都是「启动时读配置」。
    /// 它是冻结枚举的一部分，为将来「每次调用都读配置」的通道保留——
    /// **不得**为了「用上这个变体」把某个通道硬标成 `NotNeeded`。
    NotNeeded,
    /// 需要重启该 agent 才能生效
    Needed,
    /// 无法一概而论（例如 shell rc：只对新开的终端生效）
    DependsOnNewSession,
}

/// `restart_hint` 的来源标注（P1-6 诚实线）。
///
/// 三分法，逐条钉在 `restart_hint_detail` 里；前端必须把标注原样呈现给用户，
/// 未实测项不得写成定论：
/// - `CcSwitchUnverified`：说法引自 cc-switch 生效表（公开 FAQ “Do I need to
///   restart the terminal after switching providers?”），但**未在本机真机上实测**。
/// - `Verified`：已在真机上实测生效。**当前没有任何通道取它**（与 `NotNeeded`
///   的冻结逻辑同理：先有实测证据再标，集成测试钉住“Verified 集合为空”）。
/// - `Unverified`：未引自任何外部生效表、亦未实测的本项目保守标注。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartHintSource {
    CcSwitchUnverified,
    Verified,
    Unverified,
}

impl RestartHintSource {
    pub fn as_str(self) -> &'static str {
        match self {
            RestartHintSource::CcSwitchUnverified => "ccSwitchUnverified",
            RestartHintSource::Verified => "verified",
            RestartHintSource::Unverified => "unverified",
        }
    }
}

/// 生效动作（P1-6）：`RestartHint` 只说“要不要重启”，这里补“到底要动什么”。
/// 前端按 action 取 i18n 文案，**不得**按通道硬编码——与 `restart_hint` 同款约束。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartAction {
    /// 新会话即生效，无需重启进程（Claude Code，cc-switch 热切说法）。
    NewSession,
    /// 重启终端或 CLI 后生效（Gemini、Grok，cc-switch 原话）。
    RestartTerminalOrCli,
    /// 完全退出应用后再重开（Claude Desktop，cc-switch 原话 fully quit）。
    RelaunchDesktopApp,
    /// Codex 三分法（必须与 P1-5 事实一致，不得写成“按钮一按全生效”）：
    /// 桌面应用重开走一键重启按钮；终端会话不受按钮影响、需手动重开；
    /// app-server daemon 需另行验证，只关终端不够。
    CodexSplit,
    /// 其余通道的通用说法：重启该 agent（未细化、未实测）。
    RestartAgent,
}

impl RestartAction {
    pub fn as_str(self) -> &'static str {
        match self {
            RestartAction::NewSession => "newSession",
            RestartAction::RestartTerminalOrCli => "restartTerminalOrCli",
            RestartAction::RelaunchDesktopApp => "relaunchDesktopApp",
            RestartAction::CodexSplit => "codexSplit",
            RestartAction::RestartAgent => "restartAgent",
        }
    }
}

/// 一条通道的完整生效分表项：取值 + 来源标注 + 动作。纯函数、无 IO。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestartHintDetail {
    pub hint: RestartHint,
    pub source: RestartHintSource,
    pub action: RestartAction,
}

/// 纯函数、无 IO。`hint` 恒等于 `restart_hint(channel)`（集成测试钉住一致性），
/// 本函数只补来源与动作；不得改投递逻辑、不得改 `restart_hint` 的取值。
pub fn restart_hint_detail(channel: DeliveryChannel) -> RestartHintDetail {
    use RestartAction as Action;
    use RestartHint as Hint;
    use RestartHintSource as Source;
    match channel {
        // cc-switch FAQ 原话：Claude Code 支持 provider 热切、无需重启。
        // 落到本项目枚举是 DependsOnNewSession（新会话即生效），不是 NotNeeded
        // （见 restart_hint 注释：运行中会话是否重读 env 未实测）。
        DeliveryChannel::ClaudeCodeSettings => RestartHintDetail {
            hint: Hint::DependsOnNewSession,
            source: Source::CcSwitchUnverified,
            action: Action::NewSession,
        },
        // Codex 不标 cc-switch：cc-switch 只说“重启终端或 CLI”，而这里的
        // 桌面按钮 / 终端手动 / daemon 三分法是本项目 P1-5 的结论（按钮实际重启
        // 的是 ChatGPT 桌面应用），整体未做真机生效验证，故标 Unverified。
        DeliveryChannel::CodexAuthJson | DeliveryChannel::CodexConfig => RestartHintDetail {
            hint: Hint::Needed,
            source: Source::Unverified,
            action: Action::CodexSplit,
        },
        // cc-switch FAQ 原话：restart your terminal or the CLI tool。
        DeliveryChannel::GeminiCli | DeliveryChannel::GrokBuild => RestartHintDetail {
            hint: Hint::Needed,
            source: Source::CcSwitchUnverified,
            action: Action::RestartTerminalOrCli,
        },
        // cc-switch FAQ 原话：fully quit and reopen Claude Desktop。
        DeliveryChannel::ClaudeDesktop => RestartHintDetail {
            hint: Hint::Needed,
            source: Source::CcSwitchUnverified,
            action: Action::RelaunchDesktopApp,
        },
        // 其余 14 条：P1-6 不细化，穷举列出（新增通道时这里编译失败，不得静默
        // 落入通用说法）。OpenCode / OpenClaw / Hermes / Pi / MCode 在 cc-switch
        // FAQ 里是“共存模式（在工具内选模型）”，但 KeyRelay 是换 key 不是并存
        // 添加，该说法不能直接转成“无需重启”，故不抄表、仍保守标注。
        // Cline / ClineDesktop 按任务范围留给 P2-9，本项不动其动作。
        DeliveryChannel::OpenCode
        | DeliveryChannel::OpenCodeJsonc
        | DeliveryChannel::OpenClaw
        | DeliveryChannel::Hermes
        | DeliveryChannel::MCode
        | DeliveryChannel::Pi
        | DeliveryChannel::Cursor
        | DeliveryChannel::Cline
        | DeliveryChannel::QwenCode
        | DeliveryChannel::DeepSeek
        | DeliveryChannel::Trae
        | DeliveryChannel::MiMoCode
        // B-292：ClineDesktop 已下线，此分表行已无投递语义，仅为穷举 match 保留，
        // 不得据此向用户承诺任何生效方式。
        | DeliveryChannel::ClineDesktop
        | DeliveryChannel::DeepSeekHarness => RestartHintDetail {
            hint: Hint::Needed,
            source: Source::Unverified,
            action: Action::RestartAgent,
        },
    }
}

/// 一个「已知但本版本**不托管**」的落点（M7-S3 / 章程 R-7）。
///
/// `note` 是 `&'static str`（冻结字段类型），因此它**不能**随 `exists` 变化：
/// UI 用 `exists` 决定「检测到 / 未检测到」前缀，用 `note` 说明为什么不写。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectedTarget {
    /// `"Cline"` / `"Roo Code"`
    pub label: &'static str,
    /// 候选落点（`home` 下的绝对路径）
    pub path: PathBuf,
    /// `path.is_dir()`
    pub exists: bool,
    /// 面向用户的一句话
    pub note: &'static str,
}

/// Cline / Roo Code 的候选扩展目录名。
///
/// **是候选，不是实测事实**：本机 VS Code `globalStorage` 下没有任何 cline/roo 目录
/// （M7-S3 spec §15-②），这两个 ID 取自公开约定 → 未验证边界 + BACKLOG B-95。
/// 猜错**无写盘风险**：本模块永不写这些路径。
const CLINE_EXT_ID: &str = "saoudrizwan.claude-dev";
const ROO_EXT_ID: &str = "rooveterinaryinc.roo-cline";

const CLINE_NOTE: &str =
    "本版本不向 Cline 写入：它的配置落点尚未核实，写错文件会让你以为投递成功。";
const ROO_NOTE: &str =
    "本版本不向 Roo Code 写入：它的配置落点尚未核实，写错文件会让你以为投递成功。";

/// 宿主平台。抽出来是为了让**三个平台**的候选路径都能被单测覆盖
/// （macOS 上跑不了 Windows 分支，但「路径拼装」可以逐字断言）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum HostOs {
    MacOs,
    Linux,
    Windows,
}

pub(crate) fn current_host_os() -> HostOs {
    if cfg!(target_os = "macos") {
        HostOs::MacOs
    } else if cfg!(target_os = "windows") {
        HostOs::Windows
    } else {
        HostOs::Linux
    }
}

/// 某编辑器的 `globalStorage` 目录（相对 `home`）——三个平台的约定不同。
///
/// `editor` 是编辑器目录名：VS Code 稳定版为 `"Code"`、Insiders 为
/// `"Code - Insiders"`、Cursor 为 `"Cursor"`（Cursor 是 VS Code 分支，
/// 其扩展 globalStorage 与 Code 同构）。P1-7 只把这三者列入白名单，
/// 其余编辑器名一律不在白名单里（见 `target_variant_names`）。
pub(crate) fn editor_global_storage_dir(os: HostOs, editor: &str) -> PathBuf {
    match os {
        HostOs::MacOs => PathBuf::from("Library")
            .join("Application Support")
            .join(editor)
            .join("User")
            .join("globalStorage"),
        HostOs::Linux => PathBuf::from(".config")
            .join(editor)
            .join("User")
            .join("globalStorage"),
        HostOs::Windows => PathBuf::from("AppData")
            .join("Roaming")
            .join(editor)
            .join("User")
            .join("globalStorage"),
    }
}

/// VS Code 的 `globalStorage` 目录（相对 `home`）——三个平台的约定不同。
pub(crate) fn global_storage_dir(os: HostOs) -> PathBuf {
    editor_global_storage_dir(os, "Code")
}

// ==================================================== P1-7：写路径白名单与落点变体
//
// 背景：`checked_target` 原先只认 `relative_target()` 那一条路径。
// P1-7 要求白名单覆盖「同类变体」——opencode 的 `.json` / `.jsonc`
// 选择、VS Code 的 Code / Insiders / Cursor 变体——但**不开放任意路径**：
// 用户自选路径若不在白名单内必须拒绝，不得静默接受、不得静默回落默认。
//
// 两条边界（缺一不可，否则白名单就是摆设）：
// - opencode 的 `.json` / `.jsonc` 选择**由通道承载**（`OpenCode` 与
//   `OpenCodeJsonc` 是两条独立通道、两个独立 agent_id，见 P0-1 的漂移归属
//   说明）：`allowed_targets(OpenCode)` 只有 `.json`，
//   `allowed_targets(OpenCodeJsonc)` 只有 `.jsonc`。用户拿着 `.jsonc` 的
//   路径去投 `opencode` 通道时是越界，必须拒绝——不能因为「同目录同主名」
//   就替他换通道，那会让同意与漂移记到另一条通道名下。
// - VS Code 变体**只属于 Cline 通道**：Cline 的配置在编辑器的
//   globalStorage 里，编辑器有稳定版 / Insiders / Cursor 三种宿主。
//   其余通道（包括 Cursor 自己的 `~/.cursor/settings.json` 通道与独立的
//   Cline Desktop 应用通道）没有任何变体，传变体名一律拒绝。
// - 变体用**名字**选，不用自由路径选：`resolve_variant_target` 的入参
//   是变体名（`"code"` / `"code-insiders"` / `"cursor"` / `"default"`），
//   不是路径。任何不在名字表里的字符串——包括看起来像路径的字符串
//   （`"/tmp/x/settings.json"`、`"../x"`）——都直接拒绝；
//   本模块**没有**「按用户给的路径写」的入口，白名单外无路可走。
// - Cursor 变体的诚实线：它只是白名单里的一个候选落点（与 Code 同构的
//   globalStorage 布局），**不是**「Cline 在 Cursor 里可用」的实测结论；
//   Cline 落点本身的核实仍是 P2-9 的范围，本项不动默认落点、不改核实结论。

/// Cline 通道的白名单变体名（顺序固定：默认在前，UI 与测试都依赖它稳定）。
pub const CLINE_VARIANT_NAMES: [&str; 3] = ["code", "code-insiders", "cursor"];

/// 该通道可选的落点变体名。非 Cline 通道只有 `"default"`（即「无变体」，
/// 传它等于不传）；Cline 通道为三编辑器变体。
pub fn target_variant_names(channel: DeliveryChannel) -> Vec<&'static str> {
    match channel {
        DeliveryChannel::Cline => CLINE_VARIANT_NAMES.to_vec(),
        _ => vec!["default"],
    }
}

/// Cline 通道某编辑器变体的目标路径（相对 `home`）。
fn cline_variant_relative_target(os: HostOs, editor: &str) -> PathBuf {
    editor_global_storage_dir(os, editor)
        .join("saoudrizwan.claude-dev")
        .join("settings.json")
}

/// 该通道的全部白名单目标（绝对路径，`home` 下）。
///
/// - 非 Cline 通道：只有 `relative_target()` 一条；
/// - Cline 通道：默认 Code + Insiders + Cursor 三条。
/// 服务层 `checked_target` 按**成员关系**判定，不再是单路径相等——
/// 白名单外的任何路径（哪怕落在 `home` 内）一律拒绝。
pub fn allowed_targets(channel: DeliveryChannel, home: &Path) -> Vec<PathBuf> {
    match channel {
        DeliveryChannel::Cline => {
            let os = current_host_os();
            vec![
                home.join(channel.relative_target()),
                home.join(cline_variant_relative_target(os, "Code - Insiders")),
                home.join(cline_variant_relative_target(os, "Cursor")),
            ]
        }
        _ => vec![home.join(channel.relative_target())],
    }
}

/// 按变体名解析目标路径（fail-closed）。
///
/// - `None` / `"default"`：默认落点。Cline 的有效变体名是 `"code"`；
///   其余通道的有效变体名只有 `"default"`。
/// - 返回 `(目标路径, 生效变体名)`：Cline 的 `None` / `"default"` /
///   `"code"` 都生效为 `"code"`（DTO 与前端下拉用它做当前值，
///   而不是把「没选」与「选了 Code」显示成两种状态）；
///   其余通道生效为 `"default"`。
/// - 其余一切取值（未知变体名、路径形态的字符串、给非 Cline 通道传
///   编辑器变体名）都返回 `Err`，错误里逐字列出该通道的变体名表——
///   调用方不得把它翻译成默认落点后继续写。
pub fn resolve_variant_target(
    channel: DeliveryChannel,
    home: &Path,
    variant: Option<&str>,
) -> Result<(PathBuf, &'static str)> {
    let os = current_host_os();
    match (channel, variant) {
        (_, None) | (_, Some("default")) => match channel {
            DeliveryChannel::Cline => Ok((home.join(channel.relative_target()), "code")),
            _ => Ok((home.join(channel.relative_target()), "default")),
        },
        (DeliveryChannel::Cline, Some("code")) => {
            Ok((home.join(channel.relative_target()), "code"))
        }
        (DeliveryChannel::Cline, Some("code-insiders")) => Ok((
            home.join(cline_variant_relative_target(os, "Code - Insiders")),
            "code-insiders",
        )),
        (DeliveryChannel::Cline, Some("cursor")) => Ok((
            home.join(cline_variant_relative_target(os, "Cursor")),
            "cursor",
        )),
        (_, Some(other)) => Err(Error::inject(
            home.join(channel.relative_target()),
            format!(
                "通道 {} 不支持落点变体 {other:?}，可选变体为 [{}]；白名单外的路径一律拒绝，不静默回落默认落点",
                channel.as_str(),
                target_variant_names(channel).join(", ")
            ),
        )),
    }
}

/// 候选清单（顺序固定，UI 与测试都依赖它稳定）。
pub(crate) fn unmanaged_candidates(os: HostOs, home: &Path) -> Vec<DetectedTarget> {
    let base = home.join(global_storage_dir(os));
    [
        ("Cline", CLINE_EXT_ID, CLINE_NOTE),
        ("Roo Code", ROO_EXT_ID, ROO_NOTE),
    ]
    .into_iter()
    .map(|(label, ext_id, note)| {
        let path = base.join(ext_id);
        // 只读判定：`is_dir()` 对不存在的路径返回 false，且**不会**创建任何东西。
        let exists = path.is_dir();
        DetectedTarget {
            label,
            path,
            exists,
            note,
        }
    })
    .collect()
}

/// 探测**已知但本版本不托管**的落点。只读，绝不创建目录、绝不写盘（章程 R-7）。
///
/// 只探测**宿主平台**那一列：Windows 路径在 macOS 的 `home` 下没有意义。
/// 探测失败（权限、不存在）一律表现为 `exists: false`——本函数**不返回 `Err`**：
/// 探测失败不该阻断 UI。
pub fn detect_unmanaged_targets(home: &Path) -> Vec<DetectedTarget> {
    unmanaged_candidates(current_host_os(), home)
}

/// 预览里的一个字段。两个字段都是「可以给用户看」的值。
#[derive(Clone, PartialEq, Eq)]
pub struct DeliveryField {
    /// 将被写入的键名，例如 `OPENAI_API_KEY`
    pub key: String,
    /// 掩码后的值，例如 `…cdef`
    pub masked: String,
}

impl std::fmt::Debug for DeliveryField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeliveryField")
            .field("key", &self.key)
            .field("masked", &self.masked)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConsentState {
    Missing,
    Granted { granted_at: i64 },
    Revoked { revoked_at: i64 },
}

impl ConsentState {
    pub fn is_granted(&self) -> bool {
        matches!(self, ConsentState::Granted { .. })
    }
}

/// 投递预览：给用户看「要写哪里、写什么」，**不含密钥明文**。
#[derive(Clone, PartialEq, Eq)]
pub struct DeliveryPlan {
    pub agent_id: String,
    pub channel: DeliveryChannel,
    pub target_path: PathBuf,
    /// 目标文件当前是否存在（决定 UI 提示「新建」还是「改写」）
    pub target_exists: bool,
    /// 本次是**站点模式**还是**网关模式**（M8-S4 §6.6）。
    /// 界面必须把它显示出来：网关模式下写进去的是**本地令牌**，不是站点密钥——
    /// 两者在预览里的字段名一模一样（`apiKey` / `apiBase`），不说就分不清。
    pub mode: DeliveryMode,
    pub fields: Vec<DeliveryField>,
    /// 已脱敏的 diff 预览
    pub preview: String,
    pub consent: ConsentState,
    // ==================================================== P1-7：预览模式 / 首次导入 / 落点变体
    //
    // - `preview_only`：`true` = 本计划由预览专用入口产出，全程不写盘、
    //   不记 journal、不写绑定（连预览事件日志都不写，见服务层
    //   `delivery_preview_in`）。`false` = 既有 `delivery_plan` 入口
    //   （它仍会写一条 Debug 事件日志，那是既有行为，本项不改它）。
    //   前端据此渲染「仅预览，未写入」横幅，并禁用投递按钮。
    // - `is_first_delivery` / `imported_fields`：首次投递判定与只读导入
    //   （规则见本文件 P1-7 导入节）。非首次时 `imported_fields` 为空——
    //   不是「旧值为空」，是「本次不导入」。
    // - `target_variant`：本次生效的落点变体名（见 `resolve_variant_target`）；
    //   非 Cline 通道恒为 `"default"`。
    /// 本计划是否由预览专用入口产出（零副作用模式）。
    pub preview_only: bool,
    /// 该目标文件上是否没有任何生效中的绑定（首次投递判定）。
    pub is_first_delivery: bool,
    /// 首次投递时从现有文件只读导入的现有值（已掩码处理）；非首次为空。
    /// 这些值**不是**投递内容：写盘仍按 `fields` 走，导入值不自动写入。
    pub imported_fields: Vec<DeliveryField>,
    /// 本次生效的落点变体名。
    pub target_variant: &'static str,
    // ==================================================== P0-3：DSH 凭据引用校验
    //
    // 仅 DSH 通道为 `Some`，其余通道一律为 `None`——DSH 是唯一“凭据文件
    // 与 provider 配置分离”的通道（凭据在 `.credentials.yaml`，引用在
    // profile patch 文件里，见 `dsh.rs` 的 P0-3 节）。
    //
    // 预览与落盘的 enforcement 分层（有意如此，不是漏网）：
    // - 预览（plan）**不因未引用而直接报错**：预览的职责是把“未引用及
    //   去向”展示给用户看——plan 一报错，预览结构体本身就不存在了，
    //   “展示结果”无从谈起；
    // - 落盘（apply）在 P0-1 字段校验之后、写盘之前硬拒绝（见服务层
    //   `apply_delivery_in`），未引用时一个字节都不写。
    // 两处调的是同一个 `dsh::check_credential_reference`，不是两条旁路。
    /// DSH 通道的凭据引用校验结果；非 DSH 通道为 `None`。
    pub dsh_credential_reference: Option<dsh::DshReferenceCheck>,
}

impl std::fmt::Debug for DeliveryPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeliveryPlan")
            .field("agent_id", &self.agent_id)
            .field("channel", &self.channel)
            .field("target_path", &self.target_path)
            .field("target_exists", &self.target_exists)
            .field("mode", &self.mode)
            .field("fields", &self.fields)
            .field("preview_len", &self.preview.len())
            .field("consent", &self.consent)
            .field("preview_only", &self.preview_only)
            .field("is_first_delivery", &self.is_first_delivery)
            .field("imported_fields", &self.imported_fields)
            .field("target_variant", &self.target_variant)
            .field("dsh_credential_reference", &self.dsh_credential_reference)
            .finish()
    }
}

/// 投递结果：**不含任何密钥材料**，可直接序列化给前端。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryOutcome {
    pub channel: DeliveryChannel,
    pub target_path: PathBuf,
    pub journal_id: String,
    pub backup_path: Option<PathBuf>,
}

// ==================================================== P0-2：Codex 双文件同单
//
// 背景：Codex 真调通上游必须同时写 `~/.codex/auth.json`（密钥）与
// `~/.codex/config.toml`（端点 / provider / 模型）。此前它们是两次独立投递，
// 中间存在「密钥换了、端点没换」的半注入窗口（旧密钥 + 新端点、或新密钥 +
// 旧端点都会拿 401，而两次投递又各自报成功）。
//
// 本节只定**形状**（两个文件各自的计划 / 结果怎么拼成一单），同单的执行语义
// （共享 journal、双锁、双校验、双记账、失败整体回滚）在服务层
// `apply_codex_in` 里实现，见那里的注释。

/// Codex 双文件投递的预览：两文件各自一份 [`DeliveryPlan`]，拼成一单。
///
/// - `auth` 为 `Some` ⇔ 双文件模式：预览必须同时展示两文件的内容与字段，
///   只看其中一份就确认，等于没看到另一半；
/// - `auth` 为 `None` ⇔ 保留模式（见 `preserve_auth`）：auth.json 不在单里，
///   预览里也没有它——不是「auth 没变化」，而是「auth 根本不写」。
/// - 两份计划的 `fields` 各自走 P0-1 的必填表校验：auth 表不得含端点 / 模型键，
///   config 表不得含任何 API_KEY 键；两张表分开校验，混成一张会把
///   「密钥进了 config.toml」误判为正常。
#[derive(Clone, PartialEq, Eq)]
pub struct CodexDeliveryPlan {
    /// `true` = 保留模式：只写 config.toml，auth.json 一个字节都不碰。
    /// `false` = 双文件模式：两文件同单写。
    ///
    /// **默认值与显式性**：服务层入口收的是 `bool`，没有「缺省」这个第三态——
    /// 调用方必须传 `true` 或 `false`，不存在「没传就按保留算」的路径；
    /// 命令层把「没传」翻译成 `false`（双文件），见命令层 `DeliveryArgs` 的注释。
    /// 「auth.json 已存在」**绝不**被推断为保留：已存在只说明用户以前投递过，
    /// 不能说明这次他想保留官方登录。
    pub preserve_auth: bool,
    pub mode: DeliveryMode,
    pub auth: Option<DeliveryPlan>,
    pub config: DeliveryPlan,
}

impl std::fmt::Debug for CodexDeliveryPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodexDeliveryPlan")
            .field("preserve_auth", &self.preserve_auth)
            .field("mode", &self.mode)
            .field("auth", &self.auth)
            .field("config", &self.config)
            .finish()
    }
}

/// Codex 双文件投递的结果：**不含任何密钥材料**，可直接序列化给前端。
///
/// ## 记账语义（本单唯一正确的读法）
///
/// - **journal 共享一个 id**：双文件是一次 `inject::apply_holding_lock` 调用，
///   产出一个 `Journal { id, entries: [auth, config] }`。`record_journal`
///   据此写两行（`id = "<journal>:<target_path>"`，按目标路径区分），
///   回滚时 `journal_entries(journal_id)` 一次取回两条，按逆序还原——
///   滚一单就是滚两文件，不存在「只滚一半」的入口。
/// - **绑定各记一条**：`bindings` 表按 `(agent_id, target_path)` 区分落点，
///   因此双文件记**两行**，`agent_id` 各取通道自己的值（`codex` /
///   `codex-config`）、`journal_id` 填**同一个**共享 id。漂移按行取
///   `journal_id || ':' || target_path` 的哈希，各文件独立判定，互不干扰。
/// - **保留模式只记 config 一行**：auth.json 没写，就没有它的绑定行；
///   绝不能为一个没动过的文件记一条「已投递」的绑定——那会让漂移报告
///   把用户官方登录态的后续变化算成我们的漂移。
/// - 回滚一单后，两条绑定行的 journal 状态同时变 `rolled_back`，
///   漂移报告里两文件同时退出（`mark_journal_rolled_back` 按 journal id 前缀匹配）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexDeliveryOutcome {
    /// 与 `auth` / `config` 各自的 `journal_id` 是**同一个值**（共享 journal）。
    pub journal_id: String,
    pub preserve_auth: bool,
    /// 双文件模式为 `Some`，保留模式为 `None`（auth 没写，就没有结果行）。
    pub auth: Option<DeliveryOutcome>,
    pub config: DeliveryOutcome,
}

/// 通道实现。
pub trait DeliveryWriter: Send + Sync {
    fn channel(&self) -> DeliveryChannel;

    fn target_path(&self) -> PathBuf;

    /// 将被写入的键名清单。**不需要密钥**，因此「记录用户同意」这一步不必读钥匙串。
    fn field_names(&self) -> Vec<String>;

    /// 预览字段清单：**键名 + 可展示的值**（密钥一律掩码）。
    ///
    /// 由写入器自己决定哪些值是秘密：`auth_mode` 的 `"apikey"` 是字面量，不该被掩码成 `…`。
    fn fields(&self, api_key: &str) -> Vec<DeliveryField>;

    /// 生成补丁。返回的 `Patch.after` **含密钥明文**，调用方不得打印它。
    fn plan(&self, api_key: &str) -> Result<Patch>;
}

/// 按通道解析出写入器。`home` 显式传入以便测试重定向（不读环境变量）。
pub fn resolve(channel: DeliveryChannel, home: &Path) -> Result<Box<dyn DeliveryWriter>> {
    resolve_for(channel, home, "")
}

/// 带站点 `base_url` 的解析。**签名保持不变**——`service.rs` 的调用点在这里，
/// 本步的作者写域不含 `service.rs`（M6-S0 章程 §3）。
///
/// `base_url` 为空表示「只投递密钥，不动 endpoint」——会写 base_url 的通道
/// （Claude Code / OpenCode / OpenCodeJsonc / Gemini CLI / ClaudeDesktop / GrokBuild / OpenClaw / Hermes / MCode / Pi）据此少写一行。
///
/// OpenCode 通道在这里走**默认 provider 名**
/// （[`opencode::OpenCodeWriter::DEFAULT_PROVIDER_ID`]）且不写 `model`。
/// 需要站点自选的 provider 名与模型时用 [`resolve_for_binding`]（S5 接线面）。
pub fn resolve_for(
    channel: DeliveryChannel,
    home: &Path,
    base_url: &str,
) -> Result<Box<dyn DeliveryWriter>> {
    resolve_for_binding(
        channel,
        home,
        base_url,
        opencode::OpenCodeWriter::DEFAULT_PROVIDER_ID,
        None,
    )
}

/// 完整入口：`provider_id` / `model` 对 `OpenCode`、`OpenCodeJsonc` 两条通道生效；
/// 其余通道忽略。
///
/// DEBUG-G7 P2-D8（文档级约定，不改行为）：服务层投递路径（`service.rs`
/// `prepare_delivery` / `delivery_field_options`）**永远传默认 provider**
/// （`DEFAULT_PROVIDER_ID`）。`resolve_for_binding` 允许调用方传自定义 provider，
/// 但那只是换了写盘键里的 provider 段——整单校验的必填表（`expected_fields`）
/// 必须由调用方用**同一 provider**的 `FieldSetOptions` 去算，否则校验会把自定义
/// 键当“多出必填表外字段”误杀（或把默认键当缺失误报）。换言之：自定义 provider
/// 不是“只传一个参数就能用”的开关，调用方必须自带匹配的选项；服务层不走这条路，
/// 故服务层行为不变。
///
/// `provider_id` 为空（trim 后）时**在这里就报错**，而不是等到 `plan()`：
/// 调用方传空 provider 名是接线错误，早报比写到一个 `provider.""` 上强。
/// `model` 为 `None` 或 trim 后为空 → 不写、也不动已有的 `model` 键。
/// 它的 schema 把条目的 `model` 定为必填，于是沿用受管块里已有的，块里也没有就**拒绝**
/// ——两种情况都**不编造默认模型**。
pub fn resolve_for_binding(
    channel: DeliveryChannel,
    home: &Path,
    base_url: &str,
    provider_id: &str,
    model: Option<&str>,
) -> Result<Box<dyn DeliveryWriter>> {
    // M14-S7：查模型元数据。这里**只查内置表**（同步、不联网）——在线补全的结果由调用方
    // 经 [`resolve_for_binding_with_meta`] 传进来（投递路径是同步的，不能在这里 `.await`）。
    let meta = model.map(str::trim).and_then(model_meta::lookup);
    resolve_for_binding_with_meta(channel, home, base_url, provider_id, model, meta)
}

/// 与 [`resolve_for_binding`] 相同，但 `meta` 由调用方给定。
///
/// 存在的理由：models.dev 在线补全是异步的（[`model_meta::OnlineMetaCache::lookup_online`]），
/// 而投递路径是同步的。`TianshuRelayService` 先预热缓存、再用
/// [`model_meta::OnlineMetaCache::lookup_cached`] 取一份同步快照传进来，于是「在线查到的
/// 参数」也能进投递，而同步路径一次网络都不发。
pub fn resolve_for_binding_with_meta(
    channel: DeliveryChannel,
    home: &Path,
    base_url: &str,
    provider_id: &str,
    model: Option<&str>,
    meta: Option<model_meta::ModelMeta>,
) -> Result<Box<dyn DeliveryWriter>> {
    // `None` 表示未命中（内置表 + models.dev 都没查到），不写参数行。
    let model_owned = model
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .map(str::to_string);

    match channel {
        DeliveryChannel::CodexAuthJson => Ok(Box::new(codex_auth::CodexAuthWriter::new(home))),
        DeliveryChannel::CodexConfig => Ok(Box::new(codex_config::CodexConfigWriter::with_model(
            home,
            base_url,
            model_owned.as_deref(),
        ))),
        DeliveryChannel::ClaudeCodeSettings => Ok(Box::new(
            claude_code::ClaudeCodeWriter::with_model(home, base_url, model_owned.as_deref()),
        )),
        DeliveryChannel::OpenCode | DeliveryChannel::OpenCodeJsonc => {
            if provider_id.trim().is_empty() {
                return Err(Error::inject(
                    home.join(channel.relative_target()),
                    "provider id 为空，拒绝写入",
                ));
            }
            Ok(Box::new(opencode::OpenCodeWriter::with_path_and_channel(
                home.join(channel.relative_target()),
                channel,
                provider_id,
                base_url,
                model_owned.as_deref(),
                meta,
            )))
        }
        DeliveryChannel::GeminiCli => Ok(Box::new(gemini_cli::GeminiCliWriter::with_model(
            home,
            base_url,
            model_owned.as_deref(),
        ))),
        DeliveryChannel::ClaudeDesktop => Ok(Box::new(claude_desktop::ClaudeDesktopWriter::new(
            home, base_url,
        ))),
        DeliveryChannel::GrokBuild => Ok(Box::new(grok_build::GrokBuildWriter::with_model(
            home,
            base_url,
            model_owned.as_deref(),
            meta,
        ))),
        DeliveryChannel::OpenClaw => Ok(Box::new(openclaw::OpenClawWriter::with_model(
            home,
            base_url,
            model_owned.as_deref(),
            meta,
        ))),
        DeliveryChannel::Hermes => Ok(Box::new(hermes::HermesWriter::with_model(
            home,
            base_url,
            model_owned.as_deref(),
            meta,
        ))),
        DeliveryChannel::MCode => Ok(Box::new(mcode::MCodeWriter::with_model(
            home,
            base_url,
            model_owned.as_deref(),
            meta,
        ))),
        DeliveryChannel::Pi => Ok(Box::new(pi::PiWriter::with_model(
            home,
            base_url,
            model_owned.as_deref(),
            meta,
        ))),
        DeliveryChannel::Cursor => Ok(Box::new(cursor::CursorWriter::new(home, base_url))),
        DeliveryChannel::Cline => Ok(Box::new(cline::ClineWriter::with_model(
            home,
            base_url,
            model_owned.as_deref(),
            meta,
        ))),
        DeliveryChannel::QwenCode => Ok(Box::new(qwen_code::QwenCodeWriter::with_model(
            home,
            base_url,
            model_owned.as_deref(),
            meta,
        ))),
        DeliveryChannel::DeepSeek => Ok(Box::new(deepseek::DeepSeekWriter::with_model(
            home,
            base_url,
            model_owned.as_deref(),
            meta,
        ))),
        DeliveryChannel::Trae => Ok(Box::new(trae::TraeWriter::with_model(
            home,
            base_url,
            model_owned.as_deref(),
            meta,
        ))),
        DeliveryChannel::MiMoCode => Ok(Box::new(mimo_code::MiMoCodeWriter::with_model(
            home,
            base_url,
            model_owned.as_deref(),
            meta,
        ))),
        DeliveryChannel::ClineDesktop => {
            // B-292 下线：不再提供文件直写。writer 本体留仓备复活（见
            // cline_desktop.rs 文件头），但解析入口一律拒绝——站点与网关两路都经
            // 本函数，故两路同禁。决策依据见 ADR-0006 §9：cc-switch 根本不把
            // Cline 当可写文件目标、LoongPort 干脆不提供 Cline、magpie 即使标支持
            // Cline 也只做最小单键编辑（与本 writer 整条目替换相反）、官方
            // `cline auth` CLI 是唯一不依赖 schema 的路线。
            return Err(Error::inject(
                home.join(channel.relative_target()),
                "暂不支持文件直写，请走 cline auth CLI",
            ));
        }
        DeliveryChannel::DeepSeekHarness => Ok(Box::new(dsh::DshWriter::new(home, base_url))),
    }
}

/// 「指向网关」的目标：agent 侧该写什么（M8-S4 §6.2 / FR-5:158）。
///
/// **不是新通道**：落点与站点模式**逐字相同**（同一个 `relative_target`），只换两个值——
/// `base_url` 换成网关的本地地址、`api_key` 换成网关的本地令牌。
/// 新增一条通道会让 `DeliveryChannel::ALL` 膨胀，而「指向哪里」与「写到哪个文件」
/// 是两件正交的事。
///
/// 手写 `Debug`：`token` 是秘密。它只对回环地址有效，但那不构成「可以打印」的理由——
/// 拿到它就等于拿到「以本机身份经网关转发」的能力。
#[derive(Clone, PartialEq, Eq)]
pub struct GatewayEndpoint {
    /// 网关的本地地址，**含 `/v1` 前缀**（网关只服务 `/health` 与 `/v1/*`）。
    pub base_url: String,
    pub token: String,
}

impl std::fmt::Debug for GatewayEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayEndpoint")
            .field("base_url", &self.base_url)
            .field("token", &"***")
            .finish()
    }
}

/// 预检用的占位密钥（M8-S4 §9-8）。
///
/// **不是**任何真实密钥形态（没有 `sk-` / `nap-` 前缀，也不像 32 位 hex）——
/// 它只用于 `writer.plan()` 的空跑，证明「每个通道都写得进去」，
/// 从而让轮换在**建新 key 之前**就失败，而不是建好之后再停在第②步。
pub const PLACEHOLDER_KEY: &str = "tianshu-relay-dry-run-placeholder";

/// 指向网关的解析入口（M8-S4 §6.2）。
///
/// `provider_id` / `model` 的语义与 [`resolve_for_binding`] **完全一致**——
/// 因为它就是同一个函数，只是 `base_url` 换成了网关地址。
/// 这样「落点与站点模式逐字相同」不是靠人工比对，而是靠**同一个构造路径**保证的。
///
/// 空 `base_url` / 空 `token` 在这里就拒绝：写一个空 base_url 会把 agent 指向一个
/// 语法错误的目标，而那种失败要到 agent 启动时才看得见。
pub fn resolve_for_gateway(
    channel: DeliveryChannel,
    home: &Path,
    gateway: &GatewayEndpoint,
    provider_id: &str,
    model: Option<&str>,
) -> Result<Box<dyn DeliveryWriter>> {
    let meta = model.map(str::trim).and_then(model_meta::lookup);
    resolve_for_gateway_with_meta(channel, home, gateway, provider_id, model, meta)
}

/// 与 [`resolve_for_gateway`] 相同，但 `meta` 由调用方给定（理由同
/// [`resolve_for_binding_with_meta`]）。
pub fn resolve_for_gateway_with_meta(
    channel: DeliveryChannel,
    home: &Path,
    gateway: &GatewayEndpoint,
    provider_id: &str,
    model: Option<&str>,
    meta: Option<model_meta::ModelMeta>,
) -> Result<Box<dyn DeliveryWriter>> {
    let target = home.join(channel.relative_target());
    if gateway.base_url.trim().is_empty() {
        return Err(Error::inject(target, "网关地址为空，拒绝写入"));
    }
    if gateway.token.trim().is_empty() {
        return Err(Error::inject(target, "网关令牌为空，拒绝写入"));
    }
    resolve_for_binding_with_meta(channel, home, &gateway.base_url, provider_id, model, meta)
}

/// 投递的**取值来源**（M8-S4 §6.2 / §6.6）。
///
/// 用一个枚举而不是「模式 + `Option<端点>`」两个参数：那两个必须一致，
/// 而不一致的组合（网关模式但没有端点）只能靠运行期拒绝——枚举让它**无法表达**。
///
/// 默认 `Site`：**任何既有调用点不传来源时的行为一字不变**。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DeliverySource<'a> {
    /// 站点模式：`base_url` = 站点 base_url、`api_key` = 站点密钥。
    #[default]
    Site,
    /// 网关模式：`base_url` = `<local_url>/v1`、`api_key` = 本地令牌。
    Gateway(&'a GatewayEndpoint),
}

/// 投递模式的名字。**只用于界面与 DTO**（`"site"` / `"gateway"`），不参与判断。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DeliveryMode {
    #[default]
    Site,
    LocalGateway,
}

impl DeliveryMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Site => "site",
            Self::LocalGateway => "gateway",
        }
    }
}

impl DeliverySource<'_> {
    pub fn mode(self) -> DeliveryMode {
        match self {
            Self::Site => DeliveryMode::Site,
            Self::Gateway(_) => DeliveryMode::LocalGateway,
        }
    }
}

/// 按**来源**解析通道写入器：站点模式走 [`resolve_for_binding`]，
/// 网关模式走 [`resolve_for_gateway`]。两者产出的类型完全相同。
pub fn resolve_for_source(
    source: DeliverySource<'_>,
    channel: DeliveryChannel,
    home: &Path,
    site_base_url: &str,
    provider_id: &str,
    model: Option<&str>,
) -> Result<Box<dyn DeliveryWriter>> {
    let meta = model.map(str::trim).and_then(model_meta::lookup);
    resolve_for_source_with_meta(
        source,
        channel,
        home,
        site_base_url,
        provider_id,
        model,
        meta,
    )
}

/// 与 [`resolve_for_source`] 相同，但 `meta` 由调用方给定（理由同
/// [`resolve_for_binding_with_meta`]）——服务层用它把 models.dev 在线补全的结果带进投递。
pub fn resolve_for_source_with_meta(
    source: DeliverySource<'_>,
    channel: DeliveryChannel,
    home: &Path,
    site_base_url: &str,
    provider_id: &str,
    model: Option<&str>,
    meta: Option<model_meta::ModelMeta>,
) -> Result<Box<dyn DeliveryWriter>> {
    match source {
        DeliverySource::Site => {
            resolve_for_binding_with_meta(channel, home, site_base_url, provider_id, model, meta)
        }
        DeliverySource::Gateway(endpoint) => {
            resolve_for_gateway_with_meta(channel, home, endpoint, provider_id, model, meta)
        }
    }
}

/// 构造一个掩码字段（用于密钥值）。
pub fn masked_field(key: impl Into<String>, secret: &str) -> DeliveryField {
    DeliveryField {
        key: key.into(),
        masked: mask_secret(secret),
    }
}

/// 构造一个字面量字段（用于非秘密的配置值，例如 `auth_mode: "apikey"`）。
pub fn literal_field(key: impl Into<String>, value: impl Into<String>) -> DeliveryField {
    DeliveryField {
        key: key.into(),
        masked: value.into(),
    }
}

/// 行级 diff 预览。任何一行在输出前都会把 `secrets` 里每一条原文替换成掩码，
/// 再过一遍 `scrub`。
///
/// `secrets` 是**本次要掩的全部密钥**：写入的新密钥、以及 `before` 里可能仍在的
/// 旧密钥（改指网关时，`-` 行是旧站点密钥——它不一定是 `sk-` / `nap-` / 长 hex
/// 这类 `scrub` 认得的形态，不显式替换就会明文带出去，P2-5 / DEBUG-REPORT-v3 §2-5）。
/// `scrub` 仍是兜底，掩掉文件里**别的**密钥形态。
///
/// 只输出**变化了的行**（`-` / `+`）：整份打印会把无关内容淹没掉差异，
/// 而配置文件（`auth.json` 等）的改动通常只有一两行。
pub fn diff_preview(before: &str, after: &str, secrets: &[&str]) -> String {
    let mut out = String::new();
    for (tag, line) in diff_lines(before, after) {
        let prefix = match tag {
            '-' => "- ",
            '+' => "+ ",
            _ => continue,
        };
        out.push_str(prefix);
        out.push_str(&redact_line(&line, secrets));
        out.push('\n');
    }
    if out.is_empty() {
        out.push_str("(无变化)\n");
    }
    out
}

fn redact_line(line: &str, secrets: &[&str]) -> String {
    let mut replaced = line.to_string();
    for secret in secrets.iter().filter(|s| !s.is_empty()) {
        replaced = replaced.replace(*secret, &mask_secret(secret));
    }
    crate::redact::scrub(&replaced)
}

/// 极简行级 LCS diff。输入是本产品的配置文件（几十行量级），O(n·m) 足够。
fn diff_lines(before: &str, after: &str) -> Vec<(char, String)> {
    let a: Vec<&str> = split_lines(before);
    let b: Vec<&str> = split_lines(after);
    let (n, m) = (a.len(), b.len());

    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }

    let mut result = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if a[i] == b[j] {
            result.push((' ', a[i].to_string()));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            result.push(('-', a[i].to_string()));
            i += 1;
        } else {
            result.push(('+', b[j].to_string()));
            j += 1;
        }
    }
    while i < n {
        result.push(('-', a[i].to_string()));
        i += 1;
    }
    while j < m {
        result.push(('+', b[j].to_string()));
        j += 1;
    }
    result
}

/// 按行切分，且**保留尾随空行的语义**：`"a\n"` 与 `"a"` 视为同一行集（差异只在末尾换行）。
fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    let trimmed = text.strip_suffix('\n').unwrap_or(text);
    trimmed.split('\n').collect()
}

// ==================================================== M7-S3：`.jsonc` 与标记块的文本工具
//
// 三个 `pub(crate)` helper，都只服务于 M7-S3 的两条新通道。它们**只做文本判定**，
// 不做 YAML / JSONC 解析（章程 §3.3 规则 3：不引入新依赖）。

/// JSONC 专有语法。
///
/// **只用于把错误说清楚**，不参与写入决策：任何 `serde_json` 解析失败都拒绝写入
/// （fail-closed），因此「是不是 JSONC」只影响文案，不影响安全。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum JsoncHazard {
    LineComment,
    BlockComment,
    TrailingComma,
}

/// 字符串感知的有界扫描：只在**字符串外**判定 `//`、`/*` 与尾随逗号。
///
/// 字符串感知是必须的：`{"url": "https://x//y"}` 里的 `//` 不是注释
/// （M7-S3 spec §10.2 J8 钉住这一点）。
pub(crate) fn jsonc_hazard(text: &str) -> Option<JsoncHazard> {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    let mut in_string = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            match b {
                b'\\' => i += 2, // 跳过被转义的字符（`\"` 不结束字符串）
                b'"' => {
                    in_string = false;
                    i += 1;
                }
                _ => i += 1,
            }
            continue;
        }
        match b {
            b'"' => {
                in_string = true;
                i += 1;
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => return Some(JsoncHazard::LineComment),
            b'/' if bytes.get(i + 1) == Some(&b'*') => return Some(JsoncHazard::BlockComment),
            b',' => {
                let mut j = i + 1;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if matches!(bytes.get(j), Some(b'}') | Some(b']')) {
                    return Some(JsoncHazard::TrailingComma);
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P0-2：双文件各自的回读比对——缺一个必填叶键即失败，服务层据此回滚整单。
    /// 服务层无法在不挂钩子的情况下确定性制造「写完后文件又被改动」，
    /// 因此回读函数本身的语义由这条单元测试钉住，整单回滚路径由集成测试
    /// （记账失败回滚两文件、写盘失败补偿）覆盖同一条回滚代码。
    #[test]
    fn verify_applied_fields_checks_each_codex_file_separately() {
        let dir = tempfile::tempdir().expect("临时目录");
        let opts = FieldSetOptions::new("keyrelay", true, true, false);

        // auth：缺 OPENAI_API_KEY 即失败。
        let auth_path = dir.path().join("auth.json");
        std::fs::write(&auth_path, "{\n  \"auth_mode\": \"apikey\"\n}").unwrap();
        let auth_expected = expected_fields(DeliveryChannel::CodexAuthJson, &opts);
        let err = verify_applied_fields(DeliveryChannel::CodexAuthJson, &auth_expected, &auth_path)
            .unwrap_err();
        assert!(err.to_string().contains("OPENAI_API_KEY"), "{err}");

        // config：缺 base_url 即失败；齐全则通过。
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            "model_provider = \"custom\"\nmodel = \"m\"\ndisable_response_storage = true\n\n[model_providers.custom]\nname = \"custom\"\nwire_api = \"responses\"\n",
        )
        .unwrap();
        let config_expected = expected_fields(DeliveryChannel::CodexConfig, &opts);
        let err =
            verify_applied_fields(DeliveryChannel::CodexConfig, &config_expected, &config_path)
                .unwrap_err();
        assert!(err.to_string().contains("base_url"), "{err}");
        std::fs::write(
            &config_path,
            "model_provider = \"custom\"\nmodel = \"m\"\ndisable_response_storage = true\n\n[model_providers.custom]\nname = \"custom\"\nbase_url = \"https://relay.example.com\"\nwire_api = \"responses\"\n",
        )
        .unwrap();
        verify_applied_fields(DeliveryChannel::CodexConfig, &config_expected, &config_path)
            .unwrap();
    }

    #[test]
    fn channel_strings_are_exact() {
        // M6-S1 章程 §4.1 / M7-S0 §3.3 冻结：通道字符串逐字如下，且 `ALL` 的顺序是稳定契约。
        let strings: Vec<&str> = DeliveryChannel::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            strings,
            vec![
                "codex-auth-json",
                "codex-config",
                "claude-code-settings",
                "opencode",
                "gemini-cli",
                "opencode-jsonc",
                "claude-desktop",
                "grok-build",
                "openclaw",
                "hermes",
                "mcode",
                "pi",
                "cursor",
                "cline",
                "qwen-code",
                "deepseek",
                "trae",
                "mimo-code",
                "cline-desktop",
                "dsh"
            ]
        );
        assert_eq!(DeliveryChannel::OpenCode.agent_id(), "opencode");
        assert_eq!(DeliveryChannel::GeminiCli.agent_id(), "gemini-cli");
        // M7-S0 v1.2 更正：`OpenCodeJsonc` 必须与 `OpenCode` **可区分**（漂移归属靠它）
        assert_eq!(DeliveryChannel::OpenCodeJsonc.agent_id(), "opencode-jsonc");
    }

    #[test]
    fn agent_id_is_injective_so_drift_cannot_misattribute() {
        // 这条断言是 M7-S0 v1.2 那次更正的**理由**本身：`from_agent_id` 是漂移报告的逆映射，
        // 两条通道共享 agent_id 会让 `.jsonc` 的漂移被归到 `.json` 上。
        let mut seen: Vec<&str> = Vec::new();
        for channel in DeliveryChannel::ALL {
            let id = channel.agent_id();
            assert!(
                !seen.contains(&id),
                "agent_id 重复: {id}（{} 与另一条通道撞了）",
                channel.as_str()
            );
            seen.push(id);
        }
        assert_eq!(seen.len(), 20);
    }

    #[test]
    fn new_channel_relative_targets_are_exact() {
        assert_eq!(
            DeliveryChannel::OpenCode.relative_target(),
            PathBuf::from(".config")
                .join("opencode")
                .join("opencode.json")
        );
        assert_eq!(
            DeliveryChannel::GeminiCli.relative_target(),
            PathBuf::from(".gemini").join(".env")
        );
        // M7-S3 两条新通道（章程 §3.3 冻结）
        assert_eq!(
            DeliveryChannel::OpenCodeJsonc.relative_target(),
            PathBuf::from(".config")
                .join("opencode")
                .join("opencode.jsonc")
        );
        // M14-S1 新通道
        assert_eq!(
            DeliveryChannel::ClaudeDesktop.relative_target(),
            claude_desktop::relative_config_path()
        );
        assert_eq!(
            DeliveryChannel::GrokBuild.relative_target(),
            PathBuf::from(".grok").join("config.toml")
        );
        assert_eq!(
            DeliveryChannel::OpenClaw.relative_target(),
            PathBuf::from(".openclaw").join("openclaw.json")
        );
        assert_eq!(
            DeliveryChannel::Hermes.relative_target(),
            PathBuf::from(".hermes").join("config.yaml")
        );
        assert_eq!(
            DeliveryChannel::MCode.relative_target(),
            PathBuf::from(".minimax").join("config.yaml")
        );
        assert_eq!(
            DeliveryChannel::Pi.relative_target(),
            PathBuf::from(".pi").join("agent").join("models.json")
        );
    }

    #[test]
    fn relative_targets_are_pairwise_distinct() {
        // 安全边界：`checked_target` 用 `home.join(relative_target())` 逐字比对。
        // 两条通道落在同一个文件上会让「同意」与「漂移」串味。
        let mut seen: Vec<PathBuf> = Vec::new();
        for channel in DeliveryChannel::ALL {
            let target = channel.relative_target();
            assert!(
                !seen.contains(&target),
                "{} 的落点与另一条通道重复: {}",
                channel.as_str(),
                target.display()
            );
            seen.push(target);
        }
        assert_eq!(seen.len(), 20);
    }

    #[test]
    fn resolve_target_matches_relative_target_for_every_channel() {
        // **安全边界**：`service.rs::checked_target` 用 `home.join(relative_target())`
        // 逐字比对投递目标。写入器声明的路径只要差一个字节，投递就会被拒绝（fail-closed）。
        // B-292：ClineDesktop 已下线，不再能解析出 writer，不进本测试。
        let home = Path::new("/tmp/nobody");
        for channel in DeliveryChannel::ALL {
            if channel == DeliveryChannel::ClineDesktop {
                continue;
            }
            let writer = resolve_for(channel, home, "https://relay.example.com")
                .unwrap_or_else(|e| panic!("{} 应可解析: {e}", channel.as_str()));
            assert_eq!(
                writer.target_path(),
                home.join(channel.relative_target()),
                "{} 的 target_path 与 relative_target 不一致",
                channel.as_str()
            );
        }
    }

    #[test]
    fn resolve_for_binding_uses_provider_and_model() {
        let home = Path::new("/tmp/nobody");
        let writer = resolve_for_binding(
            DeliveryChannel::OpenCode,
            home,
            "https://relay.example.com",
            "my-relay",
            Some("my-relay/gpt-4o"),
        )
        .unwrap();
        assert_eq!(
            writer.field_names(),
            vec![
                "provider.my-relay.options.apiKey",
                "provider.my-relay.options.baseURL",
                "model"
            ]
        );
        // 目标路径与 provider 名无关，仍是通道声明的常量路径
        assert_eq!(
            writer.target_path(),
            home.join(DeliveryChannel::OpenCode.relative_target())
        );
    }

    #[test]
    fn resolve_for_defaults_opencode_provider_and_skips_model() {
        let home = Path::new("/tmp/nobody");
        let writer = resolve_for(DeliveryChannel::OpenCode, home, "https://x").unwrap();
        assert_eq!(
            writer.field_names(),
            vec![
                "provider.keyrelay.options.apiKey",
                "provider.keyrelay.options.baseURL"
            ],
            "默认 provider 名 + 不写 model"
        );
    }

    #[test]
    fn resolve_for_binding_rejects_empty_provider_id() {
        let home = Path::new("/tmp/nobody");
        for bad in ["", "   "] {
            // `Box<dyn DeliveryWriter>` 不实现 `Debug`，因此用 match 而不是 `unwrap_err()`
            match resolve_for_binding(DeliveryChannel::OpenCode, home, "https://x", bad, None) {
                Err(err) => {
                    assert!(matches!(err, Error::Inject { .. }), "{bad:?}");
                    assert!(err.to_string().contains("provider id"), "{err}");
                }
                Ok(_) => panic!("provider_id={bad:?} 应当被拒绝"),
            }
        }
        // 其余通道不受 provider_id 影响（它们根本没有 provider 概念）
        for channel in [
            DeliveryChannel::CodexAuthJson,
            DeliveryChannel::ClaudeCodeSettings,
            DeliveryChannel::GeminiCli,
            DeliveryChannel::ClaudeDesktop,
            DeliveryChannel::GrokBuild,
            DeliveryChannel::OpenClaw,
            DeliveryChannel::Hermes,
            DeliveryChannel::MCode,
            DeliveryChannel::Pi,
            DeliveryChannel::Cursor,
            DeliveryChannel::Cline,
            DeliveryChannel::QwenCode,
            DeliveryChannel::DeepSeek,
            DeliveryChannel::Trae,
            DeliveryChannel::MiMoCode,
        ] {
            assert!(
                resolve_for_binding(channel, home, "https://x", "", None).is_ok(),
                "{} 不该被 provider_id 校验误伤",
                channel.as_str()
            );
        }
        // 而 `OpenCodeJsonc` **和** `OpenCode` 一样受 provider_id 校验（同一个写入器）
        assert!(
            resolve_for_binding(DeliveryChannel::OpenCodeJsonc, home, "https://x", "", None)
                .is_err()
        );
    }

    // ==================================================== M7-S3：新增通道与生效策略

    #[test]
    fn restart_hint_table_is_verbatim() {
        // P1-6 生效分表：Claude Code 新会话即生效（DependsOnNewSession），其余 19 条
        // 仍按「需要重启」保守标注（DependsOnNewSession 已随 ShellBlock 删除一说作废，
        // 现为 Claude Code 的热切取值；逐条对照见 delivery_restart_hint 集成测试）。
        assert_eq!(
            restart_hint(DeliveryChannel::ClaudeCodeSettings),
            RestartHint::DependsOnNewSession,
            "claude-code-settings 应按「新会话即生效、无需重启进程」标注"
        );
        for channel in DeliveryChannel::ALL {
            if channel == DeliveryChannel::ClaudeCodeSettings {
                continue;
            }
            assert_eq!(
                restart_hint(channel),
                RestartHint::Needed,
                "{}",
                channel.as_str()
            );
        }
        assert_eq!(DeliveryChannel::ALL.len(), 20);
    }

    #[test]
    fn restart_hint_does_not_use_not_needed_yet() {
        // `NotNeeded` 是冻结枚举的一部分，但**当前没有通道该返回它**。
        // 这条断言存在的意义：将来有人为了「用上这个变体」把某通道硬标成 NotNeeded 时，
        // 会在这里被拦下来并被迫先论证「该 agent 真的每次调用都读配置」。
        for channel in DeliveryChannel::ALL {
            assert_ne!(
                restart_hint(channel),
                RestartHint::NotNeeded,
                "{} 不该被标成「改完即生效」（本机无 agent 运行时，无法验证热加载）",
                channel.as_str()
            );
        }
    }

    #[test]
    fn unmanaged_candidates_cover_three_platforms() {
        let home = Path::new("/home/u");
        let mac = unmanaged_candidates(HostOs::MacOs, home);
        assert_eq!(mac.len(), 2);
        assert_eq!(mac[0].label, "Cline");
        assert_eq!(mac[1].label, "Roo Code");
        assert_eq!(
            mac[0].path,
            home.join("Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev")
        );
        assert_eq!(
            mac[1].path,
            home.join(
                "Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline"
            )
        );

        let linux = unmanaged_candidates(HostOs::Linux, home);
        assert_eq!(
            linux[0].path,
            home.join(".config/Code/User/globalStorage/saoudrizwan.claude-dev")
        );

        let windows = unmanaged_candidates(HostOs::Windows, home);
        assert_eq!(
            windows[0].path,
            home.join("AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev")
        );
    }

    #[test]
    fn unmanaged_notes_are_verbatim() {
        let items = unmanaged_candidates(HostOs::MacOs, Path::new("/home/u"));
        assert_eq!(
            items[0].note,
            "本版本不向 Cline 写入：它的配置落点尚未核实，写错文件会让你以为投递成功。"
        );
        assert_eq!(
            items[1].note,
            "本版本不向 Roo Code 写入：它的配置落点尚未核实，写错文件会让你以为投递成功。"
        );
    }

    #[test]
    fn detect_unmanaged_targets_never_writes() {
        // 章程 R-7：只读。目录不存在时**不得**创建它。
        let dir = tempfile::tempdir().expect("临时目录");
        let missing_home = dir.path().join("home-does-not-exist");
        let items = detect_unmanaged_targets(&missing_home);
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|t| !t.exists));
        assert!(!missing_home.exists(), "探测不得创建 home");

        // 造出目录 → exists 变 true，且仍不写任何东西
        let cline = items[0].path.clone();
        std::fs::create_dir_all(&cline).unwrap();
        let again = detect_unmanaged_targets(&missing_home);
        assert!(again[0].exists);
        assert!(!again[1].exists);
        assert_eq!(std::fs::read_dir(&cline).unwrap().count(), 0);
    }

    #[test]
    fn jsonc_hazard_is_string_aware() {
        assert_eq!(jsonc_hazard("{\"url\": \"https://x//y\"}"), None);
        assert_eq!(jsonc_hazard("{\"a\": \"/* not a comment */\"}"), None);
        assert_eq!(jsonc_hazard("{\"a\": \"b\"}"), None);
        assert_eq!(
            jsonc_hazard("{\n  // c\n  \"a\": 1\n}"),
            Some(JsoncHazard::LineComment)
        );
        assert_eq!(
            jsonc_hazard("{\n  /* c */\n  \"a\": 1\n}"),
            Some(JsoncHazard::BlockComment)
        );
        assert_eq!(
            jsonc_hazard("{\"a\": 1,}"),
            Some(JsoncHazard::TrailingComma)
        );
        assert_eq!(
            jsonc_hazard("{\"a\": [1,]}"),
            Some(JsoncHazard::TrailingComma)
        );
        assert_eq!(jsonc_hazard("{\"a\": [1, 2]}"), None);
        // 转义引号不会提前结束字符串
        assert_eq!(jsonc_hazard("{\"a\": \"x\\\"//y\"}"), None);
    }

    // ==================================================== P1-7：首次导入与落点变体

    #[test]
    fn import_existing_fields_reads_json_nested_and_masks_secrets() {
        let text = r#"{
  "env": {
    "ANTHROPIC_AUTH_TOKEN": "sk-old-00001111",
    "ANTHROPIC_BASE_URL": "https://old.example.com",
    "ANTHROPIC_MODEL": "old-model"
  }
}"#;
        let expected = vec![
            "ANTHROPIC_AUTH_TOKEN".to_string(),
            "ANTHROPIC_BASE_URL".to_string(),
            "ANTHROPIC_MODEL".to_string(),
        ];
        let got = import_existing_fields(DeliveryChannel::ClaudeCodeSettings, &expected, text);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].key, "ANTHROPIC_AUTH_TOKEN");
        assert_eq!(got[0].masked, "…1111");
        assert_eq!(got[1].masked, "https://old.example.com");
        assert_eq!(got[2].masked, "old-model");
    }

    #[test]
    fn import_existing_fields_ignores_other_providers_in_cline_array() {
        let text = r#"{"providers": [
          {"id": "other", "apiKey": "sk-other-2222", "baseUrl": "https://other.example.com"},
          {"id": "keyrelay", "apiKey": "sk-mine-3333", "baseUrl": "https://old.example.com"}
        ]}"#;
        let expected = vec!["apiKey".to_string(), "baseUrl".to_string()];
        let got = import_existing_fields(DeliveryChannel::Cline, &expected, text);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].masked, "…3333");
        assert_eq!(got[1].masked, "https://old.example.com");
        assert!(!got.iter().any(|f| f.masked.contains("2222")));
    }

    #[test]
    fn import_existing_fields_opencode_matches_only_its_provider() {
        let text = r#"{"provider": {
          "other": {"options": {"apiKey": "sk-other-2222"}},
          "keyrelay": {"options": {"apiKey": "sk-mine-4444", "baseURL": "https://old.example.com"}}
        }}"#;
        let expected = vec![
            "provider.keyrelay.options.apiKey".to_string(),
            "provider.keyrelay.options.baseURL".to_string(),
        ];
        let got = import_existing_fields(DeliveryChannel::OpenCode, &expected, text);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].masked, "…4444");
        assert_eq!(got[1].masked, "https://old.example.com");

        // 带点 provider 名走方括号形态，路径逐段相等才算命中。
        let dotted = r#"{"provider": {"a.b": {"options": {"apiKey": "sk-dot-5555"}}}}"#;
        let expected = vec!["provider[\"a.b\"].options.apiKey".to_string()];
        let got = import_existing_fields(DeliveryChannel::OpenCode, &expected, dotted);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].masked, "…5555");
    }

    #[test]
    fn import_existing_fields_line_scan_for_env_and_toml() {
        // .env：export 前缀剥离、空值行不算找到。
        let env = "export GEMINI_API_KEY=sk-env-6666\nGOOGLE_GEMINI_BASE_URL=https://env.example.com\nGEMINI_MODEL=\n";
        let expected = vec![
            "GEMINI_API_KEY".to_string(),
            "GOOGLE_GEMINI_BASE_URL".to_string(),
            "GEMINI_MODEL".to_string(),
        ];
        let got = import_existing_fields(DeliveryChannel::GeminiCli, &expected, env);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].masked, "…6666");
        assert_eq!(got[1].masked, "https://env.example.com");

        // TOML：`model` 不得撞上 `model_provider`（后跟 `_` 不是分隔符）；
        // `base_url` 只认 `[model_providers.custom]` 段内（与写盘归属一致）。
        let toml = "model_provider = \"custom\"\nmodel = \"gpt-4o\"\n\n[model_providers.custom]\nbase_url = \"https://toml.example.com\"\n";
        let expected = vec![
            "model_provider".to_string(),
            "model".to_string(),
            "base_url".to_string(),
        ];
        let got = import_existing_fields(DeliveryChannel::CodexConfig, &expected, toml);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].masked, "custom");
        assert_eq!(got[1].masked, "gpt-4o");
        assert_eq!(got[2].masked, "https://toml.example.com");
    }

    #[test]
    fn import_existing_fields_jsonc_comments_yield_nothing_for_provider_channels() {
        // 带注释的 .jsonc 解析不成 JSON：opencode 宁缺不猜（行扫描分不清归属）。
        let text = "{\n  // old provider\n  \"provider\": {\"keyrelay\": {\"options\": {\"apiKey\": \"sk-x-7777\"}}}\n}\n";
        let expected = vec!["provider.keyrelay.options.apiKey".to_string()];
        assert!(import_existing_fields(DeliveryChannel::OpenCodeJsonc, &expected, text).is_empty());
        // 对照：单租户文件走行扫描，同一行能被认出来（规则只对多 provider 通道收紧）。
        let single = "{\n  // note\n  \"OPENAI_API_KEY\": \"sk-x-7777\"\n}\n";
        let expected = vec!["OPENAI_API_KEY".to_string()];
        let got = import_existing_fields(DeliveryChannel::Cursor, &expected, single);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].masked, "…7777");
    }

    #[test]
    fn variant_allowlist_is_exact_and_fail_closed() {
        let home = Path::new("/home/u");
        // Cline：三条（本机 Linux 布局）；其余通道：只有默认一条。
        let cline_targets = allowed_targets(DeliveryChannel::Cline, home);
        assert_eq!(cline_targets.len(), 3);
        assert!(cline_targets[0]
            .ends_with("Code/User/globalStorage/saoudrizwan.claude-dev/settings.json"));
        assert!(cline_targets[1]
            .ends_with("Code - Insiders/User/globalStorage/saoudrizwan.claude-dev/settings.json"));
        assert!(cline_targets[2]
            .ends_with("Cursor/User/globalStorage/saoudrizwan.claude-dev/settings.json"));
        assert_eq!(allowed_targets(DeliveryChannel::OpenCode, home).len(), 1);
        assert_eq!(
            allowed_targets(DeliveryChannel::OpenCodeJsonc, home).len(),
            1
        );
        assert_ne!(
            allowed_targets(DeliveryChannel::OpenCode, home),
            allowed_targets(DeliveryChannel::OpenCodeJsonc, home),
            "opencode 的 .json / .jsonc 选择由通道承载，不得串味"
        );

        // 变体名解析：默认 / code / insiders / cursor 各归其位。
        let (target, name) = resolve_variant_target(DeliveryChannel::Cline, home, None).unwrap();
        assert_eq!(name, "code");
        assert_eq!(target, cline_targets[0]);
        let (target, name) =
            resolve_variant_target(DeliveryChannel::Cline, home, Some("code-insiders")).unwrap();
        assert_eq!(name, "code-insiders");
        assert_eq!(target, cline_targets[1]);
        let (target, name) =
            resolve_variant_target(DeliveryChannel::Cline, home, Some("cursor")).unwrap();
        assert_eq!(name, "cursor");
        assert_eq!(target, cline_targets[2]);
        let (target, name) =
            resolve_variant_target(DeliveryChannel::ClaudeCodeSettings, home, None).unwrap();
        assert_eq!(name, "default");
        assert_eq!(
            target,
            home.join(DeliveryChannel::ClaudeCodeSettings.relative_target())
        );

        // 越界一律拒绝：未知名、路径形态、给非 Cline 通道传编辑器变体、
        // 给 opencode 传编辑器变体（.json/.jsonc 选择只能走通道）。
        for (channel, variant) in [
            (DeliveryChannel::Cline, "vscode-foo"),
            (DeliveryChannel::Cline, "/tmp/evil/settings.json"),
            (DeliveryChannel::Cline, "../x"),
            (DeliveryChannel::ClaudeCodeSettings, "cursor"),
            (DeliveryChannel::OpenCode, "code-insiders"),
            (DeliveryChannel::OpenCodeJsonc, "cursor"),
            (DeliveryChannel::Cursor, "code"),
        ] {
            let err = resolve_variant_target(channel, home, Some(variant)).unwrap_err();
            assert!(
                err.to_string().contains("可选变体"),
                "{} + {variant:?} 应被拒绝并列出变体表: {err}",
                channel.as_str()
            );
        }
        assert_eq!(
            target_variant_names(DeliveryChannel::Cline),
            vec!["code", "code-insiders", "cursor"]
        );
        assert_eq!(
            target_variant_names(DeliveryChannel::OpenCode),
            vec!["default"]
        );
    }

    #[test]
    fn channel_roundtrip_and_agent_id() {
        for channel in DeliveryChannel::ALL {
            assert_eq!(DeliveryChannel::parse(channel.as_str()).unwrap(), channel);
            assert!(!channel.agent_id().is_empty());
            assert_eq!(
                DeliveryChannel::from_agent_id(channel.agent_id()),
                Some(channel),
                "agent_id 的逆映射必须自洽"
            );
        }
        assert_eq!(DeliveryChannel::from_agent_id("nope"), None);
        assert!(matches!(
            DeliveryChannel::parse("nope"),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    // B-292：ClineDesktop 已下线后，“每条通道都可解析”不再成立——本测试改名，
    // 只覆盖可投递通道；下线通道的拒绝行为由上文的下线断言钉住。
    fn every_deliverable_channel_resolves() {
        let home = Path::new("/tmp/nobody");
        for channel in DeliveryChannel::ALL {
            if channel == DeliveryChannel::ClineDesktop {
                continue;
            }
            let writer = resolve_for(channel, home, "https://relay.example.com")
                .unwrap_or_else(|e| panic!("{} 应可解析: {e}", channel.as_str()));
            assert_eq!(writer.channel(), channel);
            assert!(
                writer.target_path().starts_with(home),
                "{} 的目标应落在 home 内",
                channel.as_str()
            );
        }
    }

    #[test]
    fn masked_and_literal_fields() {
        let masked = masked_field("OPENAI_API_KEY", "sk-0123456789abcdef");
        assert_eq!(masked.key, "OPENAI_API_KEY");
        assert_eq!(masked.masked, "…cdef");

        let literal = literal_field("auth_mode", "apikey");
        assert_eq!(literal.masked, "apikey");

        let text = format!("{:?}", vec![masked]);
        assert!(!text.contains("sk-0123"), "{text}");
    }

    #[test]
    fn diff_preview_never_leaks_secret() {
        let secret = "sk-0123456789abcdef";
        let before = "{\n  \"OPENAI_API_KEY\": \"sk-OLDSECRET0123456\"\n}\n";
        let after = format!("{{\n  \"OPENAI_API_KEY\": \"{secret}\"\n}}\n");

        let preview = diff_preview(before, &after, &[secret]);
        assert!(!preview.contains(secret), "{preview}");
        assert!(!preview.contains("sk-0123"), "{preview}");
        assert!(preview.contains("…cdef"), "{preview}");
        assert!(preview.contains("+ "), "{preview}");
        assert!(preview.contains("- "), "{preview}");
    }

    #[test]
    fn diff_preview_scrubs_non_target_secrets_too() {
        // 文件里本就有别的明文密钥（用户自己的），也不能带出去
        let before = "{\n  \"OTHER\": \"sk-leaked-somewhere-else\"\n}\n";
        let after =
            "{\n  \"OTHER\": \"sk-leaked-somewhere-else\",\n  \"OPENAI_API_KEY\": \"sk-new\"\n}\n";
        let preview = diff_preview(before, after, &["sk-new"]);
        assert!(!preview.contains("sk-leaked"), "{preview}");
    }

    #[test]
    fn diff_preview_reports_no_change() {
        assert_eq!(diff_preview("a\n", "a\n", &["s"]), "(无变化)\n");
        assert_eq!(diff_preview("", "", &["s"]), "(无变化)\n");
    }

    #[test]
    fn diff_preview_masks_old_secret_that_scrub_does_not_recognize() {
        // P2-5 / DEBUG-REPORT-v3 §2-5：改指网关时 `-` 行是旧站点密钥，它不是 `sk-` /
        // `nap-` / 长 hex 这类 `scrub` 认得的形态，`scrub` 兜不住；必须靠 `secrets`
        // 参数把旧密钥也显式替换掉，否则明文带进 diff。
        let old_secret = "tok_old_secret_xyz_not_a_known_prefix_shape";
        let new_secret = "sk-gw-new0123456789abcdef";
        let before = format!("{{\n  \"OPENAI_API_KEY\": \"{old_secret}\"\n}}\n");
        let after = format!("{{\n  \"OPENAI_API_KEY\": \"{new_secret}\"\n}}\n");

        // 只传新密钥 ⇒ 旧密钥仍明文（scrub 认不出这个形态）
        let leaked = diff_preview(&before, &after, &[new_secret]);
        assert!(
            leaked.contains(old_secret),
            "前置：只掩新密钥时旧密钥确实漏出来（scrub 不认这个形态）: {leaked}"
        );

        // 两个都传 ⇒ 旧密钥也掩掉（修复后的正确用法）
        let masked = diff_preview(&before, &after, &[new_secret, old_secret]);
        assert!(!masked.contains(old_secret), "旧密钥必须被掩: {masked}");
        assert!(!masked.contains(new_secret));
    }

    #[test]
    fn diff_ignores_trailing_newline_only_difference() {
        let (tag, line) = diff_lines("a\n", "a").into_iter().next().unwrap();
        assert_eq!((tag, line.as_str()), (' ', "a"));
    }

    /// P2-3：只有 Codex 的落点文件不含 endpoint（其余通道都吃 `base_url`）。
    ///
    /// 这条钉住的是**事实表**：新增一个「只吃 home、不吃 base_url」的 writer 时，
    /// 这里会红——提醒作者把它加进 `channel_carries_endpoint` 的例外集，
    /// 否则界面会以为「换了令牌就等于换了地址」，而 Codex 那类通道会 401。
    #[test]
    fn endpoint_in_channel_matches_what_the_writer_writes() {
        // M16-S9：这条守卫**由 writer 的产出反推**，不再复读 `channel_carries_endpoint`
        // 的实现（旧写法遍历 `ALL` 却断言同一个 `matches!`，是同义反复：`DshWriter`
        // 收了 `base_url` 却不写 endpoint 这件事它抓不到）。
        //
        // 判据：对每个通道，用**非空** `base_url` 解析出 writer，取它真正会写进文件的
        // `fields`；`fields` 里有没有 endpoint 形状的键，必须与 `channel_carries_endpoint`
        // 的取值一致。`base_url` 传空会让「会写 endpoint 的通道」少写那一行（`resolve_for`
        // 的口径），所以必须传非空——否则这条守卫会往反方向假绿。
        //
        // 形状判据与前端 `planWritesEndpoint` 同源（`src/lib/deliveryView.ts`）。
        let is_endpoint_key = |key: &str| {
            let lower = key.to_ascii_lowercase();
            lower.contains("base_url")
                || lower.contains("baseurl")
                || lower.contains("api_base")
                || lower.contains("apibase")
                || lower.contains("endpoint")
        };

        let home = tempfile::tempdir().expect("临时 home");
        // B-292：ClineDesktop 已下线，不再能解析出 writer——它不进本守卫的计数，
        // 而是在这里钉住下线错误本身（下线错误必须提到 cline auth CLI 去向）。
        let delisted_err = match resolve_for(
            DeliveryChannel::ClineDesktop,
            home.path(),
            "https://relay.example.com",
        ) {
            Ok(_) => panic!("ClineDesktop 应已下线，不应解析出 writer"),
            Err(e) => e,
        };
        assert!(
            delisted_err.to_string().contains("cline auth"),
            "ClineDesktop 下线错误必须指明 cline auth CLI 去向：{delisted_err}"
        );
        let mut checked = 0usize;
        for channel in DeliveryChannel::ALL {
            if channel == DeliveryChannel::ClineDesktop {
                continue;
            }
            let writer = resolve_for(channel, home.path(), "https://relay.example.com")
                .unwrap_or_else(|e| panic!("{} 应能解析出 writer: {e}", channel.as_str()));
            let fields = writer.fields("sk-probe-0123456789abcdef");
            let writes_endpoint = fields.iter().any(|f| is_endpoint_key(&f.key));
            assert_eq!(
                channel_carries_endpoint(channel),
                writes_endpoint,
                "{}：`channel_carries_endpoint` 说 {}，但 writer 的 fields 里{} endpoint 形状的键（{:?}）",
                channel.as_str(),
                channel_carries_endpoint(channel),
                if writes_endpoint { "有" } else { "没有" },
                fields.iter().map(|f| f.key.clone()).collect::<Vec<_>>()
            );
            checked += 1;
        }
        // B-292：ClineDesktop 已下线，不计入本守卫（它的下线错误已在上文钉住）。
        assert_eq!(
            checked,
            DeliveryChannel::ALL.len() - 1,
            "必须逐条可投递通道都核过"
        );
        // canary：判据本身要能识别 endpoint 形状（否则整条守卫会恒绿）
        assert!(is_endpoint_key("OPENAI_BASE_URL"));
        assert!(!is_endpoint_key("OPENAI_API_KEY"));
    }

    #[test]
    fn consent_state_is_granted() {
        assert!(ConsentState::Granted { granted_at: 1 }.is_granted());
        assert!(!ConsentState::Missing.is_granted());
        assert!(!ConsentState::Revoked { revoked_at: 1 }.is_granted());
    }

    // ==================================================== P0-1：必填表测试

    #[test]
    fn required_field_table_matches_writer_fields() {
        // 矩阵：19 条可投递通道 × 5 种构造输入（无端点无模型 / 纯空白端点无模型 /
        // 有端点无模型 / 有端点有模型 / 有端点有模型有 meta）。表与 writer 的 `fields()` 必须逐字相等（含顺序）：
        // 任一侧改了一行都会在这里红，而不是等到线上投递才被整单校验拦下。
        // DEBUG-G7 补齐小残留：纯空白端点一格——助手口径须与 writer 的 trim 门禁
        // 一致（空白 = 无端点），否则矩阵会把“writer 已 trim、表未 trim”的分叉漏过去。
        let home = tempfile::tempdir().expect("临时 home");
        let meta = Some(crate::model_meta::ModelMeta {
            context_window: 128_000,
            max_output_tokens: 4_096,
        });
        let configs: [(&str, Option<&str>, Option<crate::model_meta::ModelMeta>); 5] = [
            ("", None, None),
            ("   ", None, None),
            ("https://relay.example.com", None, None),
            ("https://relay.example.com", Some("gpt-4o"), None),
            ("https://relay.example.com", Some("gpt-4o"), meta),
        ];
        let mut checked = 0usize;
        for channel in DeliveryChannel::ALL {
            // B-292：ClineDesktop 已下线，不再能解析出 writer——必填表里它的行
            // 就此失去 writer 对照（行本身保留，plan 不可达），本矩阵不再核它。
            if channel == DeliveryChannel::ClineDesktop {
                continue;
            }
            for (base_url, model, meta) in configs {
                let writer = resolve_for_binding_with_meta(
                    channel,
                    home.path(),
                    base_url,
                    "keyrelay",
                    model,
                    meta,
                )
                .unwrap_or_else(|e| panic!("{} 应能解析出 writer: {e}", channel.as_str()));
                let opts = FieldSetOptions::new(
                    "keyrelay",
                    !base_url.trim().is_empty(),
                    model.is_some(),
                    meta.is_some(),
                );
                let expected = expected_fields(channel, &opts);
                let actual: Vec<String> = writer
                    .fields("sk-probe-0123456789abcdef")
                    .iter()
                    .map(|f| f.key.clone())
                    .collect();
                assert_eq!(
                    actual,
                    expected,
                    "{} 在 base_url={base_url:?} model={model:?} meta={} 时表与 writer 产出不一致",
                    channel.as_str(),
                    meta.is_some()
                );
                checked += 1;
            }
        }
        // B-292：ClineDesktop 已下线，不计入本矩阵（19 条 × 5 种构造输入）。
        assert_eq!(checked, (DeliveryChannel::ALL.len() - 1) * 5);
        // opencode 限定键的 provider 段：点号 provider 与带点 provider（方括号形态）
        // 都要与 writer 的 qualified_field 逐字一致。
        for provider in ["my-relay", "a.b"] {
            for channel in [DeliveryChannel::OpenCode, DeliveryChannel::OpenCodeJsonc] {
                let writer = resolve_for_binding_with_meta(
                    channel,
                    home.path(),
                    "https://relay.example.com",
                    provider,
                    None,
                    None,
                )
                .unwrap();
                let opts = FieldSetOptions::new(provider, true, false, false);
                let actual: Vec<String> = writer
                    .fields("sk-probe-0123456789abcdef")
                    .iter()
                    .map(|f| f.key.clone())
                    .collect();
                assert_eq!(
                    actual,
                    expected_fields(channel, &opts),
                    "{} provider={provider:?} 的限定键名不一致",
                    channel.as_str()
                );
            }
        }
    }

    #[test]
    fn codex_two_tables_and_dsh_table_are_distinct() {
        // Codex 两张表不得混成一张：auth.json 只有密钥（无端点），config.toml 只有
        // 端点/模型（无密钥）。DSH 只有密钥字段，任何构造输入都不产生端点行。
        let full = FieldSetOptions::new("keyrelay", true, true, true);
        let auth = expected_fields(DeliveryChannel::CodexAuthJson, &full);
        assert_eq!(auth, vec!["auth_mode", "OPENAI_API_KEY"]);
        let config = expected_fields(DeliveryChannel::CodexConfig, &full);
        assert!(
            !config.iter().any(|k| k.contains("API_KEY")),
            "config 表不得含密钥键: {config:?}"
        );
        assert!(config.contains(&"base_url".to_string()), "{config:?}");
        assert!(config.contains(&"model".to_string()), "{config:?}");
        assert!(
            !auth.iter().any(|k| k.contains("base_url") || k == "model"),
            "auth 表不得含端点/模型键: {auth:?}"
        );
        for opts in [
            FieldSetOptions::new("keyrelay", false, false, false),
            FieldSetOptions::new("keyrelay", true, true, true),
        ] {
            assert_eq!(
                expected_fields(DeliveryChannel::DeepSeekHarness, &opts),
                vec!["KEYRELAY_API_KEY"],
                "DSH 表恒定只有密钥字段"
            );
        }
    }

    #[test]
    fn validate_plan_fields_rejects_missing_unknown_and_duplicate() {
        let target = Path::new("/tmp/nobody/.codex/config.toml");
        let opts = FieldSetOptions::new("keyrelay", true, true, false);
        let expected = expected_fields(DeliveryChannel::CodexConfig, &opts);
        // 缺失：拿掉 base_url 一行 ⇒ 错误必须带通道名、缺失字段名、目标路径。
        let mut missing_fields: Vec<DeliveryField> = expected
            .iter()
            .filter(|k| k.as_str() != "base_url")
            .map(|k| literal_field(k.clone(), "x"))
            .collect();
        let err =
            validate_plan_fields(DeliveryChannel::CodexConfig, &missing_fields, &opts, target)
                .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("codex-config"), "{text}");
        assert!(text.contains("base_url"), "{text}");
        assert!(text.contains(".codex/config.toml"), "{text}");
        // 多出未知字段 ⇒ 同样拒绝（不是告警放行）。
        missing_fields.push(literal_field("surprise_key", "x"));
        let err =
            validate_plan_fields(DeliveryChannel::CodexConfig, &missing_fields, &opts, target)
                .unwrap_err();
        assert!(err.to_string().contains("surprise_key"), "{err}");
        // 重复键 ⇒ 拒绝。
        let mut dup_fields: Vec<DeliveryField> = expected
            .iter()
            .map(|k| literal_field(k.clone(), "x"))
            .collect();
        dup_fields.push(literal_field("name", "y"));
        let err = validate_plan_fields(DeliveryChannel::CodexConfig, &dup_fields, &opts, target)
            .unwrap_err();
        assert!(err.to_string().contains("name"), "{err}");
        // 全量一致 ⇒ 放行。
        let ok_fields: Vec<DeliveryField> = expected
            .iter()
            .map(|k| literal_field(k.clone(), "x"))
            .collect();
        assert!(
            validate_plan_fields(DeliveryChannel::CodexConfig, &ok_fields, &opts, target).is_ok()
        );
    }

    #[test]
    fn verify_applied_fields_checks_leaf_keys() {
        let dir = tempfile::tempdir().expect("临时目录");
        // TOML：`model` 不得误撞 `model_provider`；`name` 只认
        // `[model_providers.custom]` 段内，不认段外同名键（P1-16 归属校验）。
        let json_path = dir.path().join("a.json");
        std::fs::write(
            &json_path,
            "model_provider = \"custom\"\n\n[model_providers.custom]\nname = \"x\"\n",
        )
        .unwrap();
        assert!(verify_applied_fields(
            DeliveryChannel::CodexConfig,
            &["model".to_string()],
            &json_path
        )
        .is_err());
        assert!(verify_applied_fields(
            DeliveryChannel::CodexConfig,
            &["model_provider".to_string(), "name".to_string()],
            &json_path
        )
        .is_ok());
        // 段外 `name` 不顶替段内 `name`：段内无 name 即缺失。
        std::fs::write(
            &json_path,
            "model_provider = \"custom\"\nname = \"other\"\n\n[model_providers.custom]\nwire_api = \"responses\"\n",
        )
        .unwrap();
        assert!(verify_applied_fields(
            DeliveryChannel::CodexConfig,
            &["name".to_string()],
            &json_path
        )
        .is_err());
        // 紧凑 JSON：整份只有一行，键在行中而非行首（回归：单行预置文件曾让回读误报缺失）。
        let compact_path = dir.path().join("d.json");
        std::fs::write(
            &compact_path,
            "{\"provider\":{\"keyrelay\":{\"options\":{\"baseURL\":\"https://keep.example.com\",\"apiKey\":\"sk-x\"}}}}",
        )
        .unwrap();
        assert!(verify_applied_fields(
            DeliveryChannel::OpenCode,
            &[
                "provider.keyrelay.options.apiKey".to_string(),
                "provider.keyrelay.options.baseURL".to_string()
            ],
            &compact_path
        )
        .is_ok());
        assert!(verify_applied_fields(
            DeliveryChannel::OpenCode,
            &["provider.keyrelay.options.model".to_string()],
            &compact_path
        )
        .is_err());
        // TOML / YAML / .env 三种裸键渲染。
        let toml_path = dir.path().join("b.toml");
        std::fs::write(
            &toml_path,
            "[models.custom]\napi_key = \"sk-x\"\nbase_url = \"https://x\"\n",
        )
        .unwrap();
        assert!(verify_applied_fields(
            DeliveryChannel::GrokBuild,
            &["api_key".to_string(), "base_url".to_string()],
            &toml_path
        )
        .is_ok());
        let env_path = dir.path().join("c.env");
        std::fs::write(
            &env_path,
            "GEMINI_API_KEY=sk-x\nGOOGLE_GEMINI_BASE_URL=https://x\n",
        )
        .unwrap();
        assert!(verify_applied_fields(
            DeliveryChannel::GeminiCli,
            &[
                "GEMINI_API_KEY".to_string(),
                "GOOGLE_GEMINI_BASE_URL".to_string()
            ],
            &env_path
        )
        .is_ok());
        // export 前缀形态（回归 P1-1：gemini writer 保留 `  export KEY=...`，回读
        // 曾把这类行判为缺失，导致 plan 能过、apply 必回滚）。
        // 端到端：writer 对 export 风格旧文件 plan 后仍保留 export 前缀，
        // 且对 plan 产物回读通过。
        let export_path = dir.path().join("export.env");
        std::fs::write(
            &export_path,
            "  export GEMINI_API_KEY=<redacted>\n  export GOOGLE_GEMINI_BASE_URL=https://old.example.com\n",
        )
        .unwrap();
        let writer =
            gemini_cli::GeminiCliWriter::with_path(&export_path, "https://relay.example.com");
        let patch = writer.plan("sk-new").unwrap();
        assert!(
            patch.after.contains("  export GEMINI_API_KEY="),
            "writer 应保留 export 前缀与缩进:\n{}",
            patch.after
        );
        assert!(
            patch.after.contains("  export GOOGLE_GEMINI_BASE_URL="),
            "writer 应保留 export 前缀与缩进:\n{}",
            patch.after
        );
        std::fs::write(&export_path, &patch.after).unwrap();
        assert!(verify_applied_fields(
            DeliveryChannel::GeminiCli,
            &[
                "GEMINI_API_KEY".to_string(),
                "GOOGLE_GEMINI_BASE_URL".to_string()
            ],
            &export_path
        )
        .is_ok());
        // 剥离只认行首 `export `：`exportKEY`（后无空白）与行内 export 均不得放行。
        let bad_export_path = dir.path().join("bad-export.env");
        std::fs::write(
            &bad_export_path,
            "exportGEMINI_API_KEY=<redacted>\n  export GOOGLE_GEMINI_BASE_URL=https://old.example.com\n",
        )
        .unwrap();
        // 注：第二行是合法 export 行故放行 base_url；第一行不是合法 export 行，
        // 故 GEMINI_API_KEY 必须判缺失。
        assert!(verify_applied_fields(
            DeliveryChannel::GeminiCli,
            &["GEMINI_API_KEY".to_string()],
            &bad_export_path
        )
        .is_err());
        assert!(verify_applied_fields(
            DeliveryChannel::GeminiCli,
            &["GOOGLE_GEMINI_BASE_URL".to_string()],
            &bad_export_path
        )
        .is_ok());
        let inline_export_path = dir.path().join("inline-export.env");
        std::fs::write(
            &inline_export_path,
            "FOO=export GEMINI_API_KEY=<redacted>\n  export GOOGLE_GEMINI_BASE_URL=https://old.example.com\n",
        )
        .unwrap();
        assert!(verify_applied_fields(
            DeliveryChannel::GeminiCli,
            &["GEMINI_API_KEY".to_string()],
            &inline_export_path
        )
        .is_err());
        // 缺失字段的错误同样带通道名、字段名、目标路径。
        let err = verify_applied_fields(
            DeliveryChannel::GeminiCli,
            &["GEMINI_API_KEY".to_string(), "GEMINI_MODEL".to_string()],
            &env_path,
        )
        .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("gemini-cli"), "{text}");
        assert!(text.contains("GEMINI_MODEL"), "{text}");
        assert!(text.contains("c.env"), "{text}");
    }

    #[test]
    fn verify_applied_fields_rejects_wrong_provider_ownership() {
        let dir = tempfile::tempdir().expect("临时目录");
        // P1-16 验收：opencode 文件只留其它 provider 的 apiKey、删除
        // keyrelay 条目后，回读必须失败（旧的全文件搜叶键会放行）。
        let opencode_path = dir.path().join("opencode.json");
        std::fs::write(
            &opencode_path,
            r#"{"provider":{"anthropic":{"options":{"apiKey":"sk-other","baseURL":"https://api.anthropic.com"}}}}"#,
        )
        .unwrap();
        let err = verify_applied_fields(
            DeliveryChannel::OpenCode,
            &["provider.keyrelay.options.apiKey".to_string()],
            &opencode_path,
        )
        .unwrap_err();
        assert!(err.to_string().contains("apiKey"), "{err}");
        // 写对归属时仍通过。
        std::fs::write(
            &opencode_path,
            r#"{"provider":{"anthropic":{"options":{"apiKey":"sk-other"}},"keyrelay":{"options":{"apiKey":"sk-mine"}}}}"#,
        )
        .unwrap();
        verify_applied_fields(
            DeliveryChannel::OpenCode,
            &["provider.keyrelay.options.apiKey".to_string()],
            &opencode_path,
        )
        .unwrap();

        // MiMo：只留其它 provider 的 apiKey 时必须失败。
        let mimo_path = dir.path().join("mimo.json");
        std::fs::write(
            &mimo_path,
            r#"{"providers":{"anthropic":{"apiKey":"sk-other"}}}"#,
        )
        .unwrap();
        assert!(verify_applied_fields(
            DeliveryChannel::MiMoCode,
            &["apiKey".to_string()],
            &mimo_path
        )
        .is_err());
        std::fs::write(
            &mimo_path,
            r#"{"providers":{"anthropic":{"apiKey":"sk-other"},"keyrelay":{"apiKey":"sk-mine"}}}"#,
        )
        .unwrap();
        verify_applied_fields(
            DeliveryChannel::MiMoCode,
            &["apiKey".to_string()],
            &mimo_path,
        )
        .unwrap();

        // Pi：顶层其它 provider 的 apiKey 不顶替 keyrelay 条目。
        let pi_path = dir.path().join("pi.json");
        std::fs::write(&pi_path, r#"{"official":{"api_key":"sk-other"}}"#).unwrap();
        assert!(
            verify_applied_fields(DeliveryChannel::Pi, &["api_key".to_string()], &pi_path).is_err()
        );

        // Cline：数组里只有其它条目时必须失败。
        let cline_path = dir.path().join("cline.json");
        std::fs::write(
            &cline_path,
            r#"{"providers":[{"id":"other","apiKey":"sk-other"}]}"#,
        )
        .unwrap();
        assert!(verify_applied_fields(
            DeliveryChannel::Cline,
            &["apiKey".to_string()],
            &cline_path
        )
        .is_err());

        // OpenClaw JSON 形态：models.providers 里只有其它条目时失败。
        let claw_path = dir.path().join("openclaw.json");
        std::fs::write(
            &claw_path,
            r#"{"models":{"providers":{"other":{"api_key":"sk-other"}}}}"#,
        )
        .unwrap();
        assert!(verify_applied_fields(
            DeliveryChannel::OpenClaw,
            &["api_key".to_string()],
            &claw_path
        )
        .is_err());
        std::fs::write(
            &claw_path,
            r#"{"models":{"providers":{"keyrelay":{"api_key":"sk-mine"}}}}"#,
        )
        .unwrap();
        verify_applied_fields(
            DeliveryChannel::OpenClaw,
            &["api_key".to_string()],
            &claw_path,
        )
        .unwrap();

        // OpenClaw 标记块形态：块外同名键不顶替块内键。
        std::fs::write(&claw_path, "{\n  \"api_key\": \"sk-outside\"\n}\n").unwrap();
        assert!(verify_applied_fields(
            DeliveryChannel::OpenClaw,
            &["api_key".to_string()],
            &claw_path
        )
        .is_err());
    }

    #[test]
    fn import_existing_fields_filters_multi_provider_objects_to_keyrelay() {
        // P1-17 验收：MiMo 文件里其它 provider 在前，首次预览导入的
        // 必须是 keyrelay 的值（旧的裸叶键首项会取到别家密钥末 4 位）。
        let mimo = r#"{"providers":{"anthropic":{"apiKey":"sk-aaa-1111"},"keyrelay":{"apiKey":"sk-bbb-2222","baseUrl":"https://old.example.com"}}}"#;
        let expected = vec!["apiKey".to_string(), "baseUrl".to_string()];
        let got = import_existing_fields(DeliveryChannel::MiMoCode, &expected, mimo);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].masked, "…2222");
        assert_eq!(got[1].masked, "https://old.example.com");
        assert!(!got.iter().any(|f| f.masked.contains("1111")));

        // OpenClaw JSON 形态：同理只认 keyrelay 条目。
        let claw = r#"{"models":{"providers":{"other":{"api_key":"sk-aaa-1111"},"keyrelay":{"api_key":"sk-bbb-2222"}}}}"#;
        let got = import_existing_fields(DeliveryChannel::OpenClaw, &["api_key".to_string()], claw);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].masked, "…2222");

        // Pi：顶层其它 provider 在前，仍只认 keyrelay 条目。
        let pi = r#"{"official":{"api_key":"sk-aaa-1111"},"keyrelay":{"api_key":"sk-bbb-2222"}}"#;
        let got = import_existing_fields(DeliveryChannel::Pi, &["api_key".to_string()], pi);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].masked, "…2222");

        // OpenClaw 标记块形态：块内值可导入，块外别家值不导入。
        let claw_block = format!(
            "{{\n  \"other\": {{\"api_key\": \"sk-aaa-1111\"}},\n  {}\n  {{ \"api_key\": \"sk-bbb-2222\" }}\n  {}\n}}\n",
            openclaw::BLOCK_BEGIN, openclaw::BLOCK_END
        );
        let got = import_existing_fields(
            DeliveryChannel::OpenClaw,
            &["api_key".to_string()],
            &claw_block,
        );
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].masked, "…2222");

        // 归属子树缺失时宁缺：只有别家条目，不导入别家值。
        let mimo_other_only = r#"{"providers":{"anthropic":{"apiKey":"sk-aaa-1111"}}}"#;
        assert!(import_existing_fields(
            DeliveryChannel::MiMoCode,
            &["apiKey".to_string()],
            mimo_other_only
        )
        .is_empty());
    }
}
