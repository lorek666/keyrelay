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
pub mod codex_auth;
pub mod cursor;
pub mod deepseek;
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
use crate::redact::mask_secret;

/// 投递通道：一个通道 = 一个 agent 的一种配置落点。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeliveryChannel {
    /// `~/.codex/auth.json`（本步实现）
    CodexAuthJson,
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
}

impl DeliveryChannel {
    pub const ALL: [DeliveryChannel; 17] = [
        DeliveryChannel::CodexAuthJson,
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
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            DeliveryChannel::CodexAuthJson => "codex-auth-json",
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
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "codex-auth-json" => Ok(DeliveryChannel::CodexAuthJson),
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
        }
    }
}

/// 投递后该 agent 是否需要重启才能读到新配置（PRD FR-4:137 / 章程 R-11：**只标注，不重启**）。
///
/// 纯函数、无 IO。UI **必须**调用它取文案，不得在界面里硬编码判断——否则新增通道时又会漏一处。
pub fn restart_hint(channel: DeliveryChannel) -> RestartHint {
    match channel {
        // rc 文件在 **shell 启动时** source：不是「重启某个 agent」能解决的，
        // 而是「**新开的终端**才生效」——改的是会话环境，不是某个进程的配置。
        // 其余六条都是「进程启动时读配置」：已在跑的会话不会自动重读。
        // 保守方向（M7-S3 spec §8）：多提示一次重启无害；反过来（说「改完即生效」而其实没生效）
        // 会让用户以为投递失败。
        DeliveryChannel::CodexAuthJson
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
        | DeliveryChannel::MiMoCode => RestartHint::Needed,
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
    match channel {
        DeliveryChannel::CodexAuthJson => Ok(Box::new(codex_auth::CodexAuthWriter::new(home))),
        DeliveryChannel::ClaudeCodeSettings => {
            Ok(Box::new(claude_code::ClaudeCodeWriter::new(home, base_url)))
        }
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
                model,
            )))
        }
        DeliveryChannel::GeminiCli => {
            Ok(Box::new(gemini_cli::GeminiCliWriter::new(home, base_url)))
        }
        DeliveryChannel::ClaudeDesktop => Ok(Box::new(claude_desktop::ClaudeDesktopWriter::new(
            home, base_url,
        ))),
        DeliveryChannel::GrokBuild => {
            Ok(Box::new(grok_build::GrokBuildWriter::new(home, base_url)))
        }
        DeliveryChannel::OpenClaw => Ok(Box::new(openclaw::OpenClawWriter::new(home, base_url))),
        DeliveryChannel::Hermes => Ok(Box::new(hermes::HermesWriter::new(home, base_url))),
        DeliveryChannel::MCode => Ok(Box::new(mcode::MCodeWriter::new(home, base_url))),
        DeliveryChannel::Pi => Ok(Box::new(pi::PiWriter::new(home, base_url))),
        DeliveryChannel::Cursor => Ok(Box::new(cursor::CursorWriter::new(home, base_url))),
        DeliveryChannel::Cline => Ok(Box::new(cline::ClineWriter::new(home, base_url))),
        DeliveryChannel::QwenCode => Ok(Box::new(qwen_code::QwenCodeWriter::new(home, base_url))),
        DeliveryChannel::DeepSeek => Ok(Box::new(deepseek::DeepSeekWriter::new(home, base_url))),
        DeliveryChannel::Trae => Ok(Box::new(trae::TraeWriter::new(home, base_url))),
        DeliveryChannel::MiMoCode => Ok(Box::new(mimo_code::MiMoCodeWriter::new(home, base_url))),
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
pub const PLACEHOLDER_KEY: &str = "keyrelay-dry-run-placeholder";

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
    let target = home.join(channel.relative_target());
    if gateway.base_url.trim().is_empty() {
        return Err(Error::inject(target, "网关地址为空，拒绝写入"));
    }
    if gateway.token.trim().is_empty() {
        return Err(Error::inject(target, "网关令牌为空，拒绝写入"));
    }
    resolve_for_binding(channel, home, &gateway.base_url, provider_id, model)
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
    match source {
        DeliverySource::Site => {
            resolve_for_binding(channel, home, site_base_url, provider_id, model)
        }
        DeliverySource::Gateway(endpoint) => {
            resolve_for_gateway(channel, home, endpoint, provider_id, model)
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

    #[test]
    fn channel_strings_are_exact() {
        // M6-S1 章程 §4.1 / M7-S0 §3.3 冻结：通道字符串逐字如下，且 `ALL` 的顺序是稳定契约。
        let strings: Vec<&str> = DeliveryChannel::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            strings,
            vec![
                "codex-auth-json",
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
                "mimo-code"
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
        assert_eq!(seen.len(), 17);
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
        assert_eq!(seen.len(), 17);
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
        assert_eq!(DeliveryChannel::ALL.len(), 17);
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

    #[test]
    fn consent_state_is_granted() {
        assert!(ConsentState::Granted { granted_at: 1 }.is_granted());
        assert!(!ConsentState::Missing.is_granted());
        assert!(!ConsentState::Revoked { revoked_at: 1 }.is_granted());
    }
}
