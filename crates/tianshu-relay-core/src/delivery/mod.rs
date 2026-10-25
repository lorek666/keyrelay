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

/// 投递后该 agent 是否需要重启才能读到新配置（PRD FR-4:137 / 章程 R-11：**只标注，不重启**）。
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
///   `has_meta` 对它一律无效；DSH 引用校验是 P0-3 的范围，本项不碰。
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

/// apply 后回读比对：读回目标文件，确认必填表里每个字段的叶键都在文件中。
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
        .filter(|k| !text_contains_key(&text, leaf_key(k)))
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

/// 纯函数、无 IO。UI **必须**调用它取文案，不得在界面里硬编码判断——否则新增通道时又会漏一处。
pub fn restart_hint(channel: DeliveryChannel) -> RestartHint {
    match channel {
        // rc 文件在 **shell 启动时** source：不是「重启某个 agent」能解决的，
        // 而是「**新开的终端**才生效」——改的是会话环境，不是某个进程的配置。
        // 其余六条都是「进程启动时读配置」：已在跑的会话不会自动重读。
        // 保守方向（M7-S3 spec §8）：多提示一次重启无害；反过来（说「改完即生效」而其实没生效）
        // 会让用户以为投递失败。
        DeliveryChannel::CodexAuthJson
        | DeliveryChannel::CodexConfig
        | DeliveryChannel::ClaudeCodeSettings
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

/// VS Code 的 `globalStorage` 目录（相对 `home`）——三个平台的约定不同。
pub(crate) fn global_storage_dir(os: HostOs) -> PathBuf {
    match os {
        HostOs::MacOs => PathBuf::from("Library")
            .join("Application Support")
            .join("Code")
            .join("User")
            .join("globalStorage"),
        HostOs::Linux => PathBuf::from(".config")
            .join("Code")
            .join("User")
            .join("globalStorage"),
        HostOs::Windows => PathBuf::from("AppData")
            .join("Roaming")
            .join("Code")
            .join("User")
            .join("globalStorage"),
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
            Ok(Box::new(cline_desktop::ClineDesktopWriter::with_model(
                home,
                base_url,
                model_owned.as_deref(),
                meta,
            )))
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
        let home = Path::new("/tmp/nobody");
        for channel in DeliveryChannel::ALL {
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
        // M14-S1：所有通道都按「需要重启」保守标注（DependsOnNewSession 已随 ShellBlock 删除）
        for channel in DeliveryChannel::ALL {
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
    fn every_channel_resolves() {
        let home = Path::new("/tmp/nobody");
        for channel in DeliveryChannel::ALL {
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
        let mut checked = 0usize;
        for channel in DeliveryChannel::ALL {
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
        assert_eq!(checked, DeliveryChannel::ALL.len(), "必须逐条通道都核过");
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
        // 矩阵：20 通道 × 4 种构造输入（无端点无模型 / 有端点无模型 / 有端点有模型 /
        // 有端点有模型有 meta）。表与 writer 的 `fields()` 必须逐字相等（含顺序）：
        // 任一侧改了一行都会在这里红，而不是等到线上投递才被整单校验拦下。
        let home = tempfile::tempdir().expect("临时 home");
        let meta = Some(crate::model_meta::ModelMeta {
            context_window: 128_000,
            max_output_tokens: 4_096,
        });
        let configs: [(&str, Option<&str>, Option<crate::model_meta::ModelMeta>); 4] = [
            ("", None, None),
            ("https://relay.example.com", None, None),
            ("https://relay.example.com", Some("gpt-4o"), None),
            ("https://relay.example.com", Some("gpt-4o"), meta),
        ];
        let mut checked = 0usize;
        for channel in DeliveryChannel::ALL {
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
                    !base_url.is_empty(),
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
        assert_eq!(checked, DeliveryChannel::ALL.len() * 4);
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
        // JSON：引号键；`model` 不得误撞 `model_provider`。
        let json_path = dir.path().join("a.json");
        std::fs::write(
            &json_path,
            "{\n  \"model_provider\": \"custom\",\n  \"name\": \"x\"\n}\n",
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
}
