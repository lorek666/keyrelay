//! M34-S1：Agent 更新检查与白名单一键更新。
//!
//! 两块能力：
//!
//! 1. **只读检查** [`check_agent_updates`]：复用 [`crate::agents::detect_agents`] 拿到的本机版本，
//!    按去重后的更新源并发拉最新版本，逐通道给出 `state`。
//! 2. **白名单一键更新** [`update_agent`]：只执行 [`specs`] 静态表里的 argv，
//!    **不经 shell、不接受任何调用方传入的命令或参数**；`argv[0]` 先经
//!    [`crate::agents::find_bin`] 解析成绝对路径，找不到就 `skipped`。
//!
//! 安全边界（spec §4.4，硬性）：
//! - `stdin = null`，不 sudo、不提权；
//! - 每条策略独立超时，超时 `kill` + `wait`，不无限等待；
//! - 输出去 ANSI → `redact::scrub` → 只留尾部 4096 字符；**不写日志、不进事件、不落库**；
//! - 检查请求只发往 npm registry / Homebrew cask API / VS Code Marketplace 三个公开端点，
//!   不带任何站点密钥、PAT、cookie；失败只返回状态码类别，不回传响应正文。

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::agents::{self, AgentSpec, AgentStatus};
use crate::error::{Error, Result};

// ============================================================ 版本比较

/// 当前版本 vs 最新版本。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionDiff {
    /// 最新版本比当前新
    UpdateAvailable,
    /// 相同
    UpToDate,
    /// 当前版本比最新还新（本地领先，不提示更新）
    InstalledNewer,
    /// 任一侧无法解析
    Unparsable,
}

/// prerelease 的一段标识符（spec §4.2 第 3 条）。
#[derive(Clone, Debug, PartialEq, Eq)]
enum PreIdent {
    /// 纯数字段，按数值比较
    Numeric(u64),
    /// 字母段，按 ASCII 字典序比较
    Alpha(String),
}

/// 解析后的版本：4 段 core + 可选 prerelease。
#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedVersion {
    core: [u64; 4],
    /// `None` = 正式版（没有 prerelease）
    pre: Option<Vec<PreIdent>>,
}

/// 解析一个版本串（spec §4.2 第 1–2 条）。任何不合规都回 `None`（= Unparsable）。
fn parse_version(input: &str) -> Option<ParsedVersion> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    // 去掉开头的 v / V
    let trimmed = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    // 去掉 + 之后的 build metadata
    let trimmed = trimmed.split_once('+').map_or(trimmed, |(head, _)| head);
    // 第一个 - 处拆 core / prerelease
    let (core_text, pre_text) = match trimmed.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (trimmed, None),
    };

    let segments: Vec<&str> = core_text.split('.').collect();
    if segments.is_empty() || segments.len() > 4 {
        return None;
    }
    let mut core = [0_u64; 4];
    for (index, segment) in segments.iter().enumerate() {
        if segment.is_empty() || !segment.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        core[index] = segment.parse::<u64>().ok()?;
    }

    let pre = match pre_text {
        None => None,
        Some(text) => {
            if text.is_empty() {
                return None;
            }
            let mut idents = Vec::new();
            for part in text.split('.') {
                if part.is_empty() {
                    return None;
                }
                if part.bytes().all(|b| b.is_ascii_digit()) {
                    idents.push(PreIdent::Numeric(part.parse::<u64>().ok()?));
                } else {
                    idents.push(PreIdent::Alpha(part.to_string()));
                }
            }
            Some(idents)
        }
    };

    Some(ParsedVersion { core, pre })
}

/// semver-lite 比较：`latest` 与 `current` 比较（spec §4.2）。
///
/// 规则要点：没有 prerelease 的版本**大于**有 prerelease 的；prerelease 逐段比较，
/// 数字段按数值、字母段按 ASCII、数字段小于字母段；前缀相同则段数少的更小。
/// 任一侧无法解析 ⇒ [`VersionDiff::Unparsable`]，绝不猜成「有新版本」。
pub fn compare_versions(current: &str, latest: &str) -> VersionDiff {
    let (Some(current), Some(latest)) = (parse_version(current), parse_version(latest)) else {
        return VersionDiff::Unparsable;
    };

    if current.core != latest.core {
        return if latest.core > current.core {
            VersionDiff::UpdateAvailable
        } else {
            VersionDiff::InstalledNewer
        };
    }

    // core 相同，比 prerelease：None（正式版）> Some（预发布）
    let diff = match (current.pre.as_ref(), latest.pre.as_ref()) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(current_pre), Some(latest_pre)) => compare_prerelease(current_pre, latest_pre),
    };
    match diff {
        std::cmp::Ordering::Equal => VersionDiff::UpToDate,
        std::cmp::Ordering::Greater => VersionDiff::InstalledNewer,
        std::cmp::Ordering::Less => VersionDiff::UpdateAvailable,
    }
}

fn compare_prerelease(current: &[PreIdent], latest: &[PreIdent]) -> std::cmp::Ordering {
    for (left, right) in current.iter().zip(latest.iter()) {
        let ordering = match (left, right) {
            (PreIdent::Numeric(a), PreIdent::Numeric(b)) => a.cmp(b),
            (PreIdent::Alpha(a), PreIdent::Alpha(b)) => a.cmp(b),
            // 数字段 < 字母段（spec §4.2 第 3 条）
            (PreIdent::Numeric(_), PreIdent::Alpha(_)) => std::cmp::Ordering::Less,
            (PreIdent::Alpha(_), PreIdent::Numeric(_)) => std::cmp::Ordering::Greater,
        };
        if ordering != std::cmp::Ordering::Equal {
            return ordering;
        }
    }
    // 前缀相同：段数少的更小
    current.len().cmp(&latest.len())
}

// ============================================================ 静态更新源 / 策略表

/// 更新源种类（spec §4.1）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateSourceKind {
    Npm,
    BrewCask,
    Marketplace,
}

impl UpdateSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            UpdateSourceKind::Npm => "npm",
            UpdateSourceKind::BrewCask => "brewCask",
            UpdateSourceKind::Marketplace => "marketplace",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateSource {
    pub kind: UpdateSourceKind,
    /// npm 包名 / brew cask token / VS Code 扩展 id
    pub id: &'static str,
}

/// 一次更新尝试的静态定义。`argv[0]` 是工具名（执行前用 [`crate::agents::find_bin`] 解析成绝对路径）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateStrategy {
    /// 展示标签："自更新" / "npm" / "Homebrew" / "VS Code"
    pub label: &'static str,
    pub argv: &'static [&'static str],
    pub timeout_secs: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentUpdateSpec {
    /// 必须与 [`agents::specs`] 的 channel 逐位一致（测试钉住）。
    pub channel: &'static str,
    /// `None` = 没有公开版本源（不显示「可更新」）。
    pub source: Option<UpdateSource>,
    /// 空 = 不支持一键更新（有版本源也只能手动，例如 dsh）。
    pub strategies: &'static [UpdateStrategy],
    /// 手动更新/安装地址（来自 [`agents::AgentSpec::install_url`]）。
    pub manual_url: &'static str,
}

// ---- 策略简写（argv 全部写死在这里；**任何调用方都无法注入命令/参数**） ----

const SELF_UPDATE_CODEX: UpdateStrategy = UpdateStrategy {
    label: "自更新",
    argv: &["codex", "update"],
    timeout_secs: 180,
};

const SELF_UPDATE_CLAUDE: UpdateStrategy = UpdateStrategy {
    label: "自更新",
    argv: &["claude", "update"],
    timeout_secs: 180,
};

const NPM_CODEX: UpdateStrategy = UpdateStrategy {
    label: "npm",
    argv: &["npm", "install", "-g", "@openai/codex@latest"],
    timeout_secs: 240,
};

const NPM_CLAUDE: UpdateStrategy = UpdateStrategy {
    label: "npm",
    argv: &["npm", "install", "-g", "@anthropic-ai/claude-code@latest"],
    timeout_secs: 240,
};

const NPM_OPENCODE: UpdateStrategy = UpdateStrategy {
    label: "npm",
    argv: &["npm", "install", "-g", "opencode-ai@latest"],
    timeout_secs: 240,
};

const NPM_GEMINI: UpdateStrategy = UpdateStrategy {
    label: "npm",
    argv: &["npm", "install", "-g", "@google/gemini-cli@latest"],
    timeout_secs: 240,
};

const NPM_OPENCLAW: UpdateStrategy = UpdateStrategy {
    label: "npm",
    argv: &["npm", "install", "-g", "openclaw@latest"],
    timeout_secs: 240,
};

const NPM_HERMES: UpdateStrategy = UpdateStrategy {
    label: "npm",
    argv: &["npm", "install", "-g", "hermes-agent@latest"],
    timeout_secs: 240,
};

const NPM_MCODE: UpdateStrategy = UpdateStrategy {
    label: "npm",
    argv: &["npm", "install", "-g", "@minimax-ai/code@latest"],
    timeout_secs: 240,
};

const NPM_PI: UpdateStrategy = UpdateStrategy {
    label: "npm",
    argv: &[
        "npm",
        "install",
        "-g",
        "@earendil-works/pi-coding-agent@latest",
    ],
    timeout_secs: 240,
};

const NPM_QWEN: UpdateStrategy = UpdateStrategy {
    label: "npm",
    argv: &["npm", "install", "-g", "@qwen-code/qwen-code@latest"],
    timeout_secs: 240,
};

const NPM_REASONIX: UpdateStrategy = UpdateStrategy {
    label: "npm",
    argv: &["npm", "install", "-g", "reasonix@latest"],
    timeout_secs: 240,
};

const NPM_MIMOCODE: UpdateStrategy = UpdateStrategy {
    label: "npm",
    argv: &["npm", "install", "-g", "mimocode@latest"],
    timeout_secs: 240,
};
const NPM_QODER: UpdateStrategy = UpdateStrategy {
    label: "npm",
    argv: &["npm", "install", "-g", "@qoder-ai/qodercli@latest"],
    timeout_secs: 240,
};

const NPM_QODER_CN: UpdateStrategy = UpdateStrategy {
    label: "npm",
    argv: &["npm", "install", "-g", "@qodercn-ai/qoderclicn@latest"],
    timeout_secs: 240,
};

const NPM_KIMI_CODE: UpdateStrategy = UpdateStrategy {
    label: "npm",
    argv: &["npm", "install", "-g", "@moonshot-ai/kimi-code@latest"],
    timeout_secs: 240,
};

const NPM_CODEBUDDY: UpdateStrategy = UpdateStrategy {
    label: "npm",
    argv: &["npm", "install", "-g", "@tencent-ai/codebuddy-code@latest"],
    timeout_secs: 240,
};

const NPM_CRUSH: UpdateStrategy = UpdateStrategy {
    label: "npm",
    argv: &["npm", "install", "-g", "@charmland/crush@latest"],
    timeout_secs: 240,
};

const BREW_CLAUDE: UpdateStrategy = UpdateStrategy {
    label: "Homebrew",
    argv: &["brew", "upgrade", "--cask", "claude"],
    timeout_secs: 300,
};

const BREW_CURSOR: UpdateStrategy = UpdateStrategy {
    label: "Homebrew",
    argv: &["brew", "upgrade", "--cask", "cursor"],
    timeout_secs: 300,
};

const BREW_TRAE: UpdateStrategy = UpdateStrategy {
    label: "Homebrew",
    argv: &["brew", "upgrade", "--cask", "trae"],
    timeout_secs: 300,
};

const BREW_CLINE_APP: UpdateStrategy = UpdateStrategy {
    label: "Homebrew",
    argv: &["brew", "upgrade", "--cask", "cline-app"],
    timeout_secs: 300,
};

const CODE_CLINE: UpdateStrategy = UpdateStrategy {
    label: "VS Code",
    argv: &[
        "code",
        "--install-extension",
        "saoudrizwan.claude-dev",
        "--force",
    ],
    timeout_secs: 180,
};

static CODEX_STRATEGIES: &[UpdateStrategy] = &[SELF_UPDATE_CODEX, NPM_CODEX];
static CLAUDE_STRATEGIES: &[UpdateStrategy] = &[SELF_UPDATE_CLAUDE, NPM_CLAUDE];
static OPENCODE_STRATEGIES: &[UpdateStrategy] = &[NPM_OPENCODE];
static GEMINI_STRATEGIES: &[UpdateStrategy] = &[NPM_GEMINI];
static CLAUDE_DESKTOP_STRATEGIES: &[UpdateStrategy] = &[BREW_CLAUDE];
static OPENCLAW_STRATEGIES: &[UpdateStrategy] = &[NPM_OPENCLAW];
static HERMES_STRATEGIES: &[UpdateStrategy] = &[NPM_HERMES];
static MCODE_STRATEGIES: &[UpdateStrategy] = &[NPM_MCODE];
static PI_STRATEGIES: &[UpdateStrategy] = &[NPM_PI];
static CURSOR_STRATEGIES: &[UpdateStrategy] = &[BREW_CURSOR];
static CLINE_STRATEGIES: &[UpdateStrategy] = &[CODE_CLINE];
static QWEN_STRATEGIES: &[UpdateStrategy] = &[NPM_QWEN];
static REASONIX_STRATEGIES: &[UpdateStrategy] = &[NPM_REASONIX];
static TRAE_STRATEGIES: &[UpdateStrategy] = &[BREW_TRAE];
static MIMOCODE_STRATEGIES: &[UpdateStrategy] = &[NPM_MIMOCODE];
static CLINE_DESKTOP_STRATEGIES: &[UpdateStrategy] = &[BREW_CLINE_APP];
static QODER_STRATEGIES: &[UpdateStrategy] = &[NPM_QODER];
static QODER_CN_STRATEGIES: &[UpdateStrategy] = &[NPM_QODER_CN];
static KIMI_CODE_STRATEGIES: &[UpdateStrategy] = &[NPM_KIMI_CODE];
static CODEBUDDY_STRATEGIES: &[UpdateStrategy] = &[NPM_CODEBUDDY];
static CRUSH_STRATEGIES: &[UpdateStrategy] = &[NPM_CRUSH];

// ---- 更新源（同一 agent 的多个落点共用同一源；检查时按源去重） ----

const SRC_CODEX: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::Npm,
    id: "@openai/codex",
};
const SRC_CLAUDE_CODE: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::Npm,
    id: "@anthropic-ai/claude-code",
};
const SRC_OPENCODE: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::Npm,
    id: "opencode-ai",
};
const SRC_GEMINI: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::Npm,
    id: "@google/gemini-cli",
};
const SRC_CLAUDE_DESKTOP: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::BrewCask,
    id: "claude",
};
const SRC_OPENCLAW: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::Npm,
    id: "openclaw",
};
const SRC_HERMES: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::Npm,
    id: "hermes-agent",
};
const SRC_MCODE: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::Npm,
    id: "@minimax-ai/code",
};
const SRC_PI: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::Npm,
    id: "@earendil-works/pi-coding-agent",
};
const SRC_CURSOR: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::BrewCask,
    id: "cursor",
};
const SRC_CLINE: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::Marketplace,
    id: "saoudrizwan.claude-dev",
};
const SRC_QWEN: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::Npm,
    id: "@qwen-code/qwen-code",
};
const SRC_REASONIX: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::Npm,
    id: "reasonix",
};
const SRC_TRAE: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::BrewCask,
    id: "trae",
};
const SRC_MIMOCODE: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::Npm,
    id: "mimocode",
};
const SRC_CLINE_DESKTOP: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::BrewCask,
    id: "cline-app",
};
const SRC_DSH: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::Npm,
    id: "@deepseek-ai/dsh",
};
const SRC_QODER: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::Npm,
    id: "@qoder-ai/qodercli",
};
const SRC_QODER_CN: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::Npm,
    id: "@qodercn-ai/qoderclicn",
};
const SRC_KIMI_CODE: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::Npm,
    id: "@moonshot-ai/kimi-code",
};
const SRC_CODEBUDDY: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::Npm,
    id: "@tencent-ai/codebuddy-code",
};
const SRC_CRUSH: UpdateSource = UpdateSource {
    kind: UpdateSourceKind::Npm,
    id: "@charmland/crush",
};

/// 28 条静态表（spec §5 逐字；顺序与 [`agents::specs`] 逐位一致，测试钉住）。
static SPECS: [AgentUpdateSpec; 28] = [
    AgentUpdateSpec {
        channel: "codex-auth-json",
        source: Some(SRC_CODEX),
        strategies: CODEX_STRATEGIES,
        manual_url: "https://chatgpt.com/codex",
    },
    AgentUpdateSpec {
        channel: "codex-config",
        source: Some(SRC_CODEX),
        strategies: CODEX_STRATEGIES,
        manual_url: "https://chatgpt.com/codex",
    },
    AgentUpdateSpec {
        channel: "claude-code-settings",
        source: Some(SRC_CLAUDE_CODE),
        strategies: CLAUDE_STRATEGIES,
        manual_url: "https://code.claude.com/docs",
    },
    AgentUpdateSpec {
        channel: "opencode",
        source: Some(SRC_OPENCODE),
        strategies: OPENCODE_STRATEGIES,
        manual_url: "https://opencode.ai",
    },
    AgentUpdateSpec {
        channel: "gemini-cli",
        source: Some(SRC_GEMINI),
        strategies: GEMINI_STRATEGIES,
        manual_url: "https://github.com/google-gemini/gemini-cli",
    },
    AgentUpdateSpec {
        channel: "opencode-jsonc",
        source: Some(SRC_OPENCODE),
        strategies: OPENCODE_STRATEGIES,
        manual_url: "https://opencode.ai",
    },
    AgentUpdateSpec {
        channel: "claude-desktop",
        source: Some(SRC_CLAUDE_DESKTOP),
        strategies: CLAUDE_DESKTOP_STRATEGIES,
        manual_url: "https://claude.ai/download",
    },
    AgentUpdateSpec {
        channel: "grok-build",
        source: None,
        strategies: &[],
        manual_url: "https://x.ai/cli",
    },
    AgentUpdateSpec {
        channel: "openclaw",
        source: Some(SRC_OPENCLAW),
        strategies: OPENCLAW_STRATEGIES,
        manual_url: "https://www.npmjs.com/package/openclaw",
    },
    AgentUpdateSpec {
        channel: "hermes",
        source: Some(SRC_HERMES),
        strategies: HERMES_STRATEGIES,
        manual_url: "https://www.npmjs.com/package/hermes-agent",
    },
    AgentUpdateSpec {
        channel: "mcode",
        source: Some(SRC_MCODE),
        strategies: MCODE_STRATEGIES,
        manual_url: "https://www.npmjs.com/package/@minimax-ai/code",
    },
    AgentUpdateSpec {
        channel: "pi",
        source: Some(SRC_PI),
        strategies: PI_STRATEGIES,
        manual_url: "https://www.npmjs.com/package/@earendil-works/pi-coding-agent",
    },
    AgentUpdateSpec {
        channel: "cursor",
        source: Some(SRC_CURSOR),
        strategies: CURSOR_STRATEGIES,
        manual_url: "https://cursor.com",
    },
    AgentUpdateSpec {
        channel: "cline",
        source: Some(SRC_CLINE),
        strategies: CLINE_STRATEGIES,
        manual_url: "https://marketplace.visualstudio.com/items?itemName=saoudrizwan.claude-dev",
    },
    AgentUpdateSpec {
        channel: "qwen-code",
        source: Some(SRC_QWEN),
        strategies: QWEN_STRATEGIES,
        manual_url: "https://github.com/QwenLM/qwen-code",
    },
    AgentUpdateSpec {
        channel: "deepseek",
        source: Some(SRC_REASONIX),
        strategies: REASONIX_STRATEGIES,
        manual_url: "https://www.npmjs.com/package/reasonix",
    },
    AgentUpdateSpec {
        channel: "trae",
        source: Some(SRC_TRAE),
        strategies: TRAE_STRATEGIES,
        manual_url: "https://www.trae.ai",
    },
    AgentUpdateSpec {
        channel: "mimo-code",
        source: Some(SRC_MIMOCODE),
        strategies: MIMOCODE_STRATEGIES,
        manual_url: "https://www.npmjs.com/package/mimocode",
    },
    AgentUpdateSpec {
        channel: "cline-desktop",
        source: Some(SRC_CLINE_DESKTOP),
        strategies: CLINE_DESKTOP_STRATEGIES,
        manual_url: "https://cline.bot",
    },
    AgentUpdateSpec {
        channel: "dsh",
        source: Some(SRC_DSH),
        strategies: &[],
        manual_url: "https://www.npmjs.com/package/@deepseek-ai/dsh",
    },
    // 新增通道的 npm 包名先经 registry 核对；Droid / WorkBuddy / WorkBuddy AI
    // 只提供手动更新入口（桌面安装器 / 厂商文档），不把未验证的 argv 放进白名单。
    AgentUpdateSpec {
        channel: "qoder",
        source: Some(SRC_QODER),
        strategies: QODER_STRATEGIES,
        manual_url: "https://qoder.com",
    },
    AgentUpdateSpec {
        channel: "qoder-cn",
        source: Some(SRC_QODER_CN),
        strategies: QODER_CN_STRATEGIES,
        manual_url: "https://qoder.cn",
    },
    AgentUpdateSpec {
        channel: "kimi-code",
        source: Some(SRC_KIMI_CODE),
        strategies: KIMI_CODE_STRATEGIES,
        manual_url: "https://www.kimi.com/coding",
    },
    AgentUpdateSpec {
        channel: "droid",
        source: None,
        strategies: &[],
        manual_url: "https://factory.ai",
    },
    AgentUpdateSpec {
        channel: "codebuddy",
        source: Some(SRC_CODEBUDDY),
        strategies: CODEBUDDY_STRATEGIES,
        manual_url: "https://codebuddy.ai",
    },
    AgentUpdateSpec {
        channel: "workbuddy",
        source: None,
        strategies: &[],
        manual_url: "https://www.workbuddy.ai",
    },
    AgentUpdateSpec {
        channel: "workbuddy-ai",
        source: None,
        strategies: &[],
        manual_url: "https://www.workbuddy.ai",
    },
    AgentUpdateSpec {
        channel: "crush",
        source: Some(SRC_CRUSH),
        strategies: CRUSH_STRATEGIES,
        manual_url: "https://github.com/charmbracelet/crush",
    },
];

/// 28 条，顺序与 [`agents::specs`] 逐位一致。
pub fn specs() -> &'static [AgentUpdateSpec] {
    &SPECS
}

fn spec_for_channel(channel: &str) -> Option<&'static AgentUpdateSpec> {
    SPECS.iter().find(|spec| spec.channel == channel)
}

fn agent_spec_for_channel(channel: &str) -> Option<&'static AgentSpec> {
    agents::specs().iter().find(|spec| spec.channel == channel)
}

// ============================================================ 检查结果

/// 单个通道的更新检查结果（spec §4.1；serde camelCase）。
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentUpdateStatus {
    pub channel: String,
    pub installed: bool,
    pub current_version: Option<String>,
    pub latest_version: Option<String>,
    /// "available" | "upToDate" | "unknown" | "unsupported" | "error" | "notInstalled"
    pub state: String,
    /// "npm" | "brewCask" | "marketplace" | "none"
    pub source: String,
    /// 至少有一个策略所需工具能在本机找到
    pub auto_update: bool,
    /// 第一个可执行策略的展示命令（`argv.join(" ")`）；没有则 `None`
    pub command: Option<String>,
    pub manual_url: Option<String>,
    /// 人话补充：检查失败原因 / 为什么不支持 / 为什么无法比较；成功且最新时为 `None`
    pub message: Option<String>,
}

/// 一次更新尝试的结果（serde camelCase）。
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAttempt {
    pub label: String,
    /// 展示用命令（`argv.join(" ")`）
    pub command: String,
    /// 工具没找到 ⇒ true（该策略没执行）
    pub skipped: bool,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    /// 去 ANSI + `redact::scrub` + 只留尾部 4096 字符
    pub output_tail: String,
}

/// 一次一键更新的结果（serde camelCase）。
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentUpdateOutcome {
    pub channel: String,
    /// 任一策略成功即 true
    pub success: bool,
    pub attempts: Vec<UpdateAttempt>,
    pub version_before: Option<String>,
    pub version_after: Option<String>,
    pub version_changed: bool,
    pub message: Option<String>,
}

/// 单通道评估所需的输入（纯函数参数，便于单测六态）。
#[derive(Clone, Debug, Default)]
struct EvaluateInput<'a> {
    installed: bool,
    current_version: Option<&'a str>,
    /// 该通道更新源的拉取结果：`None` = 没有源；`Some(Err(msg))` = 拉取失败
    latest: Option<std::result::Result<&'a str, &'a str>>,
}

/// 六态评估（spec §6）。`auto_update` / `command` 由调用方按本机工具另行算好传入。
///
/// `has_strategies` 只影响「可更新但本机没有可执行策略」时的 `message`：
/// 有策略但工具缺失（npm/brew/code 都不在）与压根没有策略（dsh，只能在应用内更新）
/// 是两种不同的原因，给用户的话术也不同。
fn evaluate(
    channel: &str,
    input: &EvaluateInput<'_>,
    source_label: &str,
    manual_url: Option<&str>,
    auto_update: bool,
    command: Option<&str>,
    has_strategies: bool,
) -> AgentUpdateStatus {
    let mut status = AgentUpdateStatus {
        channel: channel.to_string(),
        installed: input.installed,
        current_version: input.current_version.map(str::to_string),
        latest_version: None,
        state: "unknown".to_string(),
        source: source_label.to_string(),
        auto_update,
        command: command.map(str::to_string),
        manual_url: manual_url.map(str::to_string),
        message: None,
    };

    if !input.installed {
        status.state = "notInstalled".to_string();
        return status;
    }

    let Some(latest) = input.latest else {
        // 没有公开版本源（grok-build）
        status.state = "unsupported".to_string();
        status.auto_update = false;
        status.command = None;
        status.message = Some("该 Agent 没有公开版本源，无法自动检查更新".to_string());
        return status;
    };

    match latest {
        Err(reason) => {
            status.state = "error".to_string();
            status.auto_update = false;
            status.command = None;
            status.message = Some(format!("检查更新失败：{reason}"));
            return status;
        }
        Ok(latest) => status.latest_version = Some(latest.to_string()),
    }

    let Some(current) = input.current_version else {
        status.state = "unknown".to_string();
        status.auto_update = false;
        status.command = None;
        status.message = Some("无法读取当前版本，不能判断是否需要更新".to_string());
        return status;
    };

    match compare_versions(
        current,
        status.latest_version.as_deref().unwrap_or_default(),
    ) {
        VersionDiff::UpdateAvailable => status.state = "available".to_string(),
        VersionDiff::UpToDate | VersionDiff::InstalledNewer => {
            status.state = "upToDate".to_string();
            status.message = None;
        }
        VersionDiff::Unparsable => {
            status.state = "unknown".to_string();
            status.auto_update = false;
            status.command = None;
            status.message = Some(format!(
                "无法比较版本（当前 {current}，最新 {}）",
                status.latest_version.as_deref().unwrap_or("—")
            ));
        }
    }

    // 只有「可更新」才允许一键更新；其它状态不提供执行入口。
    if status.state != "available" {
        status.auto_update = false;
        status.command = None;
    }

    // 可更新但本机无法一键更新：必须说明原因（前端徽标的 title 依赖它，spec §6）。
    if status.state == "available" && !status.auto_update {
        status.message = Some(if has_strategies {
            "未找到可用的更新工具（npm/brew/code），请手动更新".to_string()
        } else {
            "该 Agent 需在其应用内更新".to_string()
        });
    }
    status
}

/// 计算某条 spec 在本机的可执行策略（`auto_update` 与展示命令）。
fn auto_update_for(spec: &AgentUpdateSpec, home: &Path) -> (bool, Option<String>) {
    for strategy in spec.strategies {
        if let Some(program) = strategy.argv.first() {
            if agents::find_bin(program, home).is_some() {
                return (true, Some(strategy.argv.join(" ")));
            }
        }
    }
    (false, None)
}

// ============================================================ 更新源拉取

/// 8 秒超时（spec §4.1：`check_agent_updates` 的拉取超时）。
const FETCH_TIMEOUT: Duration = Duration::from_secs(8);

/// 传输层失败后重试一次的等待时间（spec §4.4 第 9 条）。
///
/// 本机实测：某些网络中间层会把**进程内首个** TLS 握手掐断（`tls handshake eof`，20s 后失败），
/// 同一进程的第二次请求 0.5s 内 200。重试一次让首次检查不再整页红；HTTP 4xx/5xx 是确定性答案，
/// **不**重试（否则 404 会白等一轮）。
const FETCH_RETRY_DELAY: Duration = Duration::from_millis(250);

/// 一次拉取失败的两类：可重试的传输错误 / 确定性的 HTTP 状态错误。
#[derive(Debug)]
enum FetchFailure {
    Retryable(String),
    Definitive(String),
}

impl FetchFailure {
    fn message(self) -> String {
        match self {
            Self::Retryable(message) | Self::Definitive(message) => message,
        }
    }

    fn retryable(&self) -> bool {
        matches!(self, Self::Retryable(_))
    }
}

/// 把 reqwest 错误分类：带 HTTP 状态码的（`error_for_status`）是确定性错误，其余重试一次。
fn transport_failure(error: &reqwest::Error) -> FetchFailure {
    let summary = fetch_error_summary(error);
    if error.status().is_some() {
        FetchFailure::Definitive(summary)
    } else {
        FetchFailure::Retryable(summary)
    }
}

fn http_client(proxy: Option<&str>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .user_agent(concat!("TianshuRelay/", env!("CARGO_PKG_VERSION")));
    if let Some(proxy_url) = proxy {
        crate::proxy::validate_proxy_url(proxy_url)?;
        let proxy = reqwest::Proxy::all(proxy_url.to_string())
            .map_err(|error| Error::Transport(format!("更新检查代理配置无效: {error}")))?;
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|error| Error::Transport(format!("更新检查 HTTP 客户端初始化失败: {error}")))
}

/// 只返回脱敏的失败摘要（spec §4.4 第 8 条：不回传响应正文）。
fn fetch_error_summary(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        return "请求超时".to_string();
    }
    if error.is_connect() {
        return "连接失败".to_string();
    }
    if let Some(status) = error.status() {
        return format!("HTTP {}", status.as_u16());
    }
    "网络错误".to_string()
}

/// 从 JSON 取字符串字段（缺失/类型不对 ⇒ None）。
fn json_string(value: &serde_json::Value, path: &[&str]) -> Option<String> {
    let mut cursor = value;
    for key in path {
        cursor = cursor.get(*key)?;
    }
    cursor.as_str().map(str::to_string)
}

/// 解析 npm `GET /<package>/latest` 的响应体（夹具测试用）。
fn parse_npm_latest(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    json_string(&value, &["version"])
}

/// 解析 brew `GET /api/cask/<token>.json` 的响应体：`version` 可能带 `,sha` 后缀。
fn parse_brew_latest(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let version = json_string(&value, &["version"])?;
    // spec §4.2 第 4 条：取第一个逗号前的部分再比较（在解析层做）
    Some(
        version
            .split(',')
            .next()
            .unwrap_or_default()
            .trim()
            .to_string(),
    )
}

/// 解析 VS Code Marketplace 的 extensionquery 响应体。
///
/// `results` / `extensions` / `versions` 都是 JSON **数组** ⇒ 用 `usize` 下标，
/// 不能用 `json_string` 的字符串路径（那是给对象用的）。
fn parse_marketplace_latest(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    value["results"][0]["extensions"][0]["versions"][0]["version"]
        .as_str()
        .map(str::to_string)
}

/// 拉一个更新源的最新版本（成功 ⇒ `Ok(Some(version))`；响应无版本 ⇒ `Ok(None)`）。
///
/// 传输错误重试一次（见 [`FETCH_RETRY_DELAY`]）；第二次仍失败才把**第一次**的摘要返回
/// （两次通常同一类错误，保留第一次更有诊断价值）。
async fn fetch_latest(client: &reqwest::Client, source: &UpdateSource) -> Result<Option<String>> {
    match with_one_retry(|| fetch_latest_once(client, source)).await {
        Ok(value) => Ok(value),
        Err(failure) => Err(Error::Transport(failure.message())),
    }
}

/// 只重试**可重试**失败一次；确定性的 HTTP 状态错误直接返回。
async fn with_one_retry<F, Fut>(mut attempt: F) -> std::result::Result<Option<String>, FetchFailure>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<Option<String>, FetchFailure>>,
{
    match attempt().await {
        Ok(value) => Ok(value),
        Err(first) if first.retryable() => {
            tokio::time::sleep(FETCH_RETRY_DELAY).await;
            attempt().await.map_err(|_| first)
        }
        Err(error) => Err(error),
    }
}

/// 单次拉取（不做重试）。
async fn fetch_latest_once(
    client: &reqwest::Client,
    source: &UpdateSource,
) -> std::result::Result<Option<String>, FetchFailure> {
    match source.kind {
        UpdateSourceKind::Npm => {
            let url = format!("https://registry.npmjs.org/{}/latest", source.id);
            let response = client
                .get(&url)
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
                .await
                .map_err(|error| transport_failure(&error))?;
            let response = response
                .error_for_status()
                .map_err(|error| transport_failure(&error))?;
            let body = response
                .text()
                .await
                .map_err(|error| transport_failure(&error))?;
            Ok(parse_npm_latest(&body))
        }
        UpdateSourceKind::BrewCask => {
            let url = format!("https://formulae.brew.sh/api/cask/{}.json", source.id);
            let response = client
                .get(&url)
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
                .await
                .map_err(|error| transport_failure(&error))?;
            let response = response
                .error_for_status()
                .map_err(|error| transport_failure(&error))?;
            let body = response
                .text()
                .await
                .map_err(|error| transport_failure(&error))?;
            Ok(parse_brew_latest(&body))
        }
        UpdateSourceKind::Marketplace => {
            // 只读的扩展查询：不带任何凭证，正文只含扩展 id。
            let body = serde_json::json!({
                "filters": [{
                    "criteria": [{ "filterType": 7, "value": source.id }],
                }],
                "flags": 914,
            });
            let response = client
                .post("https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery")
                .header(
                    reqwest::header::ACCEPT,
                    "application/json;api-version=7.2-preview.1",
                )
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_string())
                .send()
                .await
                .map_err(|error| transport_failure(&error))?;
            let response = response
                .error_for_status()
                .map_err(|error| transport_failure(&error))?;
            let text = response
                .text()
                .await
                .map_err(|error| transport_failure(&error))?;
            Ok(parse_marketplace_latest(&text))
        }
    }
}

/// 按源去重（Codex 两落点、OpenCode 两落点各只请求一次）。
fn dedupe_sources() -> Vec<UpdateSource> {
    let mut sources: Vec<UpdateSource> = Vec::new();
    for spec in SPECS.iter() {
        let Some(source) = spec.source else { continue };
        if !sources
            .iter()
            .any(|existing| existing.kind == source.kind && existing.id == source.id)
        {
            sources.push(source);
        }
    }
    sources
}

// ============================================================ 只读检查

/// 只读检查（spec §4.1）。`statuses` 由调用方先跑 [`agents::detect_agents`] 得到。
///
/// 单个更新源失败只影响对应通道，不整体报错；返回 28 条、顺序与 [`specs`] 一致。
pub async fn check_agent_updates(
    home: &Path,
    statuses: &[AgentStatus],
    proxy: Option<String>,
) -> Vec<AgentUpdateStatus> {
    let sources = dedupe_sources();

    // 并发拉取（同一源只拉一次）；失败按源记下摘要，逐通道降级成 state="error"。
    let mut latest: std::collections::HashMap<
        (&'static str, &'static str),
        Result<Option<String>>,
    > = std::collections::HashMap::new();
    match http_client(proxy.as_deref()) {
        Ok(client) => {
            let futures = sources
                .iter()
                .map(|source| {
                    let client = client.clone();
                    let source = *source;
                    async move {
                        let result = fetch_latest(&client, &source).await;
                        (source, result)
                    }
                })
                .collect::<Vec<_>>();
            for (source, result) in futures_util::future::join_all(futures).await {
                latest.insert((source.kind.as_str(), source.id), result);
            }
        }
        Err(error) => {
            let message = error.to_string();
            for source in &sources {
                latest.insert(
                    (source.kind.as_str(), source.id),
                    Err(Error::Transport(message.clone())),
                );
            }
        }
    }

    SPECS
        .iter()
        .map(|spec| {
            let status = statuses.iter().find(|row| row.channel == spec.channel);
            let installed = status.map(|row| row.installed).unwrap_or(false);
            let current_version = status.and_then(|row| row.version.clone());
            let (auto_update, command) = auto_update_for(spec, home);

            let latest_ref: Option<std::result::Result<&str, String>> =
                spec.source.and_then(|source| {
                    latest
                        .get(&(source.kind.as_str(), source.id))
                        .map(|result| match result {
                            Ok(Some(version)) => Ok(version.as_str()),
                            Ok(None) => Err("响应里没有版本字段".to_string()),
                            Err(error) => Err(error_message(error)),
                        })
                });
            let latest_for_input = match &latest_ref {
                None => None,
                Some(Ok(version)) => Some(Ok(*version)),
                Some(Err(reason)) => Some(Err(reason.as_str())),
            };

            let input = EvaluateInput {
                installed,
                current_version: current_version.as_deref(),
                latest: latest_for_input,
            };
            evaluate(
                spec.channel,
                &input,
                spec.source
                    .map(|source| source.kind.as_str())
                    .unwrap_or("none"),
                Some(spec.manual_url),
                auto_update,
                command.as_deref(),
                !spec.strategies.is_empty(),
            )
        })
        .collect()
}

/// 检查失败的**类别摘要**（spec §4.4 第 8 条：不回传响应正文）。
///
/// `fetch_latest` 只会把「超时 / 连接失败 / HTTP 状态码」这类类别塞进 `Transport`，
/// 这里原样透传——比再压成一句「网络请求失败」更有用，且同样不含正文。
fn error_message(error: &Error) -> String {
    match error {
        Error::Transport(detail) => format!("网络请求失败（{detail}）"),
        other => format!("检查更新失败（{other}）"),
    }
}

// ============================================================ 一键更新

/// 输出尾部最多保留的字符数（spec §4.4 第 6 条）。
const OUTPUT_TAIL_CHARS: usize = 4096;

/// 执行更新（spec §4.1）。
///
/// 未知 channel / 不支持一键更新 ⇒ `Err(Error::InvalidInput)`，**不启动任何进程**。
/// 命令跑完但失败 ⇒ `Ok(outcome { success: false })`（有输出可展示）。
pub fn update_agent(home: &Path, channel: &str) -> Result<AgentUpdateOutcome> {
    let spec = spec_for_channel(channel)
        .ok_or_else(|| Error::InvalidInput(format!("未知的投递通道: {channel}")))?;
    let agent_spec = agent_spec_for_channel(channel)
        .ok_or_else(|| Error::InvalidInput(format!("未知的投递通道: {channel}")))?;

    if spec.strategies.is_empty() {
        return Err(Error::InvalidInput(format!(
            "该 Agent 不支持一键更新（{}），请按提示手动更新",
            spec.channel
        )));
    }

    let version_before = agents::detect_one(agent_spec, home).version;
    let mut attempts = Vec::new();
    let mut success = false;

    for strategy in spec.strategies {
        let command = strategy.argv.join(" ");
        let Some(program) = strategy.argv.first() else {
            continue;
        };
        let Some(path) = agents::find_bin(program, home) else {
            // 工具没找到 ⇒ 记 skipped 并继续下一条（spec §4.4 第 3 条）
            attempts.push(UpdateAttempt {
                label: strategy.label.to_string(),
                command,
                skipped: true,
                success: false,
                exit_code: None,
                timed_out: false,
                output_tail: String::new(),
            });
            continue;
        };

        let run = run_command(&path, &strategy.argv[1..], strategy.timeout_secs, home);
        attempts.push(UpdateAttempt {
            label: strategy.label.to_string(),
            command,
            skipped: false,
            success: run.success,
            exit_code: run.exit_code,
            timed_out: run.timed_out,
            output_tail: run.output_tail,
        });
        if run.success {
            success = true;
            break;
        }
    }

    let version_after = agents::detect_one(agent_spec, home).version;
    let version_changed = version_before != version_after;
    let all_skipped = attempts.iter().all(|attempt| attempt.skipped);
    let message = update_message(
        success,
        version_before.as_deref(),
        version_after.as_deref(),
        all_skipped,
    );

    Ok(AgentUpdateOutcome {
        channel: spec.channel.to_string(),
        success,
        attempts,
        version_before,
        version_after,
        version_changed,
        message,
    })
}

/// 更新结果的人话说明（spec §6 的四种成功/失败分支）。
///
/// 关键点：**「更新前读不到版本、更新后读到了」不是「版本没变」**——
/// 前者是「之前没探到」，后者是「命令白跑」，两者的话术必须不同。
fn update_message(
    success: bool,
    version_before: Option<&str>,
    version_after: Option<&str>,
    all_skipped: bool,
) -> Option<String> {
    if success {
        if version_after.is_none() {
            return Some("命令执行成功，但更新后无法读取版本，请重新检测".to_string());
        }
        if version_before == version_after {
            return Some(
                "更新命令执行成功，但检测到的版本没有变化（可能不是通过该方式安装的）".to_string(),
            );
        }
        // before=None 且 after=Some：从「读不到」变成「读得到」，如实交给前端展示
        return None;
    }
    if all_skipped {
        Some("本机没有找到任何可用的更新工具，未执行任何命令".to_string())
    } else {
        Some("更新失败，请查看每次尝试的输出尾部".to_string())
    }
}

struct CommandRun {
    success: bool,
    exit_code: Option<i32>,
    timed_out: bool,
    output_tail: String,
}

/// 跑一条静态 argv（**不经 shell**）：独立超时、超时 kill + wait、输出去 ANSI/scrub/截断。
fn run_command(program: &Path, args: &[&str], timeout_secs: u64, home: &Path) -> CommandRun {
    let mut child = match Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // GUI 应用 PATH 过窄会让 `#!/usr/bin/env node` 失败（spec §4.4 第 4 条）
        .env("PATH", agents::enriched_path(home))
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return CommandRun {
                success: false,
                exit_code: None,
                timed_out: false,
                output_tail: sanitize_output(&format!("无法启动命令: {error}")),
            };
        }
    };

    // 两路并发读，避免子进程写满管道后阻塞（与 agents.rs 的版本探测同一做法）。
    let stdout = child.stdout.take().map(agents::read_to_string_async);
    let stderr = child.stderr.take().map(agents::read_to_string_async);

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let exit = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => break None,
        }
    };

    let out = agents::read_available(stdout);
    let err = agents::read_available(stderr);
    let combined = format!("{out}{err}");
    let output_tail = sanitize_output(&combined);

    match exit {
        Some(status) => CommandRun {
            success: status.success(),
            exit_code: status.code(),
            timed_out: false,
            output_tail,
        },
        None => CommandRun {
            success: false,
            exit_code: None,
            timed_out: true,
            output_tail: if output_tail.is_empty() {
                format!("命令超过 {timeout_secs}s 未结束，已终止")
            } else {
                output_tail
            },
        },
    }
}

/// 去 ANSI → `redact::scrub` → 只留尾部 4096 字符（spec §4.4 第 6 条）。
fn sanitize_output(raw: &str) -> String {
    let plain = agents::strip_ansi(raw);
    let scrubbed = crate::redact::scrub(&plain);
    let trimmed = scrubbed.trim_end();
    let chars: Vec<char> = trimmed.chars().collect();
    if chars.len() <= OUTPUT_TAIL_CHARS {
        return trimmed.to_string();
    }
    let tail: String = chars[chars.len() - OUTPUT_TAIL_CHARS..].iter().collect();
    format!("…{tail}")
}

// ============================================================ 单测

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn home() -> PathBuf {
        // 不存在的 HOME：只用于 find_bin 的确定性（它仍会查 PATH）。
        PathBuf::from("/nonexistent-tianshu-relay-m34-test-home")
    }

    // ---------- compare_versions ----------

    #[test]
    fn compare_equal_versions() {
        assert_eq!(compare_versions("1.2.3", "1.2.3"), VersionDiff::UpToDate);
        assert_eq!(compare_versions("v1.2.3", "1.2.3"), VersionDiff::UpToDate);
        assert_eq!(
            compare_versions("1.2.3+build.7", "1.2.3"),
            VersionDiff::UpToDate
        );
    }

    #[test]
    fn compare_patch_minor_major_updates() {
        assert_eq!(
            compare_versions("0.162.1", "0.162.2"),
            VersionDiff::UpdateAvailable
        );
        assert_eq!(
            compare_versions("0.162.1", "0.163.0"),
            VersionDiff::UpdateAvailable
        );
        assert_eq!(
            compare_versions("1.9.9", "2.0.0"),
            VersionDiff::UpdateAvailable
        );
        assert_eq!(
            compare_versions("2.0.0", "1.9.9"),
            VersionDiff::InstalledNewer
        );
    }

    #[test]
    fn compare_handles_short_and_long_cores() {
        assert_eq!(compare_versions("1.2", "1.2.0"), VersionDiff::UpToDate);
        assert_eq!(
            compare_versions("1.2", "1.2.1"),
            VersionDiff::UpdateAvailable
        );
        assert_eq!(
            compare_versions("1.2.3.4", "1.2.3.5"),
            VersionDiff::UpdateAvailable
        );
        assert_eq!(
            compare_versions("1.2.3.4", "1.2.3.4"),
            VersionDiff::UpToDate
        );
    }

    #[test]
    fn compare_prerelease_vs_release() {
        // 正式版 > 预发布
        assert_eq!(
            compare_versions("1.2.3-rc.2", "1.2.3"),
            VersionDiff::UpdateAvailable
        );
        assert_eq!(
            compare_versions("1.2.3", "1.2.3-rc.2"),
            VersionDiff::InstalledNewer
        );
        // 两个 prerelease 的数字段按数值比较
        assert_eq!(
            compare_versions("1.2.3-rc.2", "1.2.3-rc.10"),
            VersionDiff::UpdateAvailable
        );
        assert_eq!(
            compare_versions("1.2.3-rc.10", "1.2.3-rc.2"),
            VersionDiff::InstalledNewer
        );
        // 段数少的更小
        assert_eq!(
            compare_versions("1.2.3-rc", "1.2.3-rc.1"),
            VersionDiff::UpdateAvailable
        );
        // 数字段 < 字母段
        assert_eq!(
            compare_versions("1.2.3-1", "1.2.3-alpha"),
            VersionDiff::UpdateAvailable
        );
    }

    #[test]
    fn compare_unparsable_inputs() {
        for (current, latest) in [
            ("", "1.2.3"),
            ("1.2.3", ""),
            ("   ", "1.2.3"),
            ("garbage", "1.2.3"),
            ("1.2.3", "garbage"),
            ("1.x.3", "1.2.3"),
            ("1.2.3.4.5", "1.2.3"),
            ("1.2.3-", "1.2.3"),
            ("1.2.3-a..b", "1.2.3"),
        ] {
            assert_eq!(
                compare_versions(current, latest),
                VersionDiff::Unparsable,
                "current={current:?} latest={latest:?}"
            );
        }
    }

    // ---------- 静态表 ----------

    #[test]
    fn specs_cover_all_channels_in_order() {
        let channels: Vec<&str> = specs().iter().map(|spec| spec.channel).collect();
        let agent_channels: Vec<&str> = agents::specs().iter().map(|spec| spec.channel).collect();
        assert_eq!(channels.len(), 28);
        assert_eq!(channels, agent_channels);
        // manual_url 一律来自 agents::specs()[i].install_url
        for (update, agent) in specs().iter().zip(agents::specs()) {
            assert_eq!(
                update.manual_url, agent.install_url,
                "{} 的 manual_url 与 install_url 不一致",
                update.channel
            );
        }
    }

    #[test]
    fn every_strategy_is_a_whitelisted_tool() {
        const WHITELIST: [&str; 5] = ["npm", "brew", "code", "codex", "claude"];
        for spec in specs() {
            for strategy in spec.strategies {
                assert!(!strategy.argv.is_empty(), "{} 的 argv 为空", spec.channel);
                let program = strategy.argv[0];
                assert!(
                    WHITELIST.contains(&program),
                    "{} 的策略用了白名单外的工具 {program}",
                    spec.channel
                );
                assert!(
                    strategy.timeout_secs > 0,
                    "{} 的策略超时必须 > 0",
                    spec.channel
                );
                assert!(!strategy.label.is_empty());
            }
        }
    }

    #[test]
    fn sources_and_strategies_are_consistent() {
        for spec in specs() {
            match spec.source {
                None => assert!(
                    spec.strategies.is_empty(),
                    "{} 没有源却配了策略",
                    spec.channel
                ),
                Some(_) => {
                    // dsh 允许「有 source、无策略」
                    if spec.channel != "dsh" {
                        assert!(
                            !spec.strategies.is_empty(),
                            "{} 有源却没有策略",
                            spec.channel
                        );
                    }
                }
            }
        }
        // 反方向：有策略必须有源
        for spec in specs() {
            if !spec.strategies.is_empty() {
                assert!(spec.source.is_some(), "{} 有策略却没有源", spec.channel);
            }
        }
    }

    // ---------- 解析夹具 ----------

    #[test]
    fn parse_npm_fixtures() {
        assert_eq!(
            parse_npm_latest(r#"{"version":"1.2.3"}"#).as_deref(),
            Some("1.2.3")
        );
        assert_eq!(parse_npm_latest(r#"{"name":"x"}"#), None);
        assert_eq!(parse_npm_latest("not json"), None);
    }

    #[test]
    fn parse_brew_strips_comma_suffix() {
        assert_eq!(
            parse_brew_latest(r#"{"version":"3.1623.0,e751f9d5a1b2"}"#).as_deref(),
            Some("3.1623.0")
        );
        assert_eq!(
            parse_brew_latest(r#"{"version":"1.0.0"}"#).as_deref(),
            Some("1.0.0")
        );
        assert_eq!(parse_brew_latest("{}"), None);
    }

    #[test]
    fn parse_marketplace_nested_fixture() {
        let body = r#"{
            "results": [{
                "extensions": [{
                    "versions": [{ "version": "4.1.25" }]
                }]
            }]
        }"#;
        assert_eq!(parse_marketplace_latest(body).as_deref(), Some("4.1.25"));
        assert_eq!(parse_marketplace_latest("{}"), None);
    }

    #[tokio::test]
    async fn retry_once_only_for_retryable_failures() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        // 第一次可重试失败、第二次成功 ⇒ 共 2 次调用，返回第二次的值。
        let calls = Arc::new(AtomicU32::new(0));
        let result = {
            let calls = calls.clone();
            with_one_retry(move || {
                let calls = calls.clone();
                async move {
                    let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
                    if n == 1 {
                        Err(FetchFailure::Retryable("请求超时".to_string()))
                    } else {
                        Ok(Some("1.2.3".to_string()))
                    }
                }
            })
            .await
        };
        assert_eq!(result.unwrap().as_deref(), Some("1.2.3"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        // 确定性失败（HTTP 4xx）⇒ 不重试，只调用 1 次。
        let calls = Arc::new(AtomicU32::new(0));
        let result = {
            let calls = calls.clone();
            with_one_retry(move || {
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(FetchFailure::Definitive("HTTP 404".to_string()))
                }
            })
            .await
        };
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // 两次都可重试失败 ⇒ 返回**第一次**的摘要。
        let calls = Arc::new(AtomicU32::new(0));
        let result = {
            let calls = calls.clone();
            with_one_retry(move || {
                let calls = calls.clone();
                async move {
                    let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
                    Err(FetchFailure::Retryable(format!("第 {n} 次失败")))
                }
            })
            .await
        };
        assert_eq!(result.unwrap_err().message(), "第 1 次失败");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    // ---------- evaluate 六态 ----------

    fn eval_with(input: EvaluateInput<'_>) -> AgentUpdateStatus {
        evaluate(
            "x",
            &input,
            "npm",
            Some("https://example.invalid"),
            true,
            Some("npm x"),
            true,
        )
    }

    /// 可更新、但本机没有可执行策略（工具缺失 / 无策略）时的评估。
    fn eval_unavailable(has_strategies: bool) -> AgentUpdateStatus {
        evaluate(
            "x",
            &EvaluateInput {
                installed: true,
                current_version: Some("1.0.0"),
                latest: Some(Ok("2.0.0")),
            },
            "npm",
            Some("https://example.invalid"),
            false,
            None,
            has_strategies,
        )
    }

    #[test]
    fn evaluate_states() {
        // notInstalled
        let status = eval_with(EvaluateInput {
            installed: false,
            ..Default::default()
        });
        assert_eq!(status.state, "notInstalled");

        // unsupported（无源）
        let status = evaluate(
            "x",
            &EvaluateInput {
                installed: true,
                current_version: Some("1.0.0"),
                latest: None,
            },
            "none",
            Some("https://example.invalid"),
            false,
            None,
            false,
        );
        assert_eq!(status.state, "unsupported");
        assert!(status.message.is_some());

        // error（拉取失败）
        let status = eval_with(EvaluateInput {
            installed: true,
            current_version: Some("1.0.0"),
            latest: Some(Err("请求超时")),
        });
        assert_eq!(status.state, "error");
        assert!(!status.auto_update);
        assert!(status.command.is_none());

        // unknown（读不到当前版本）
        let status = eval_with(EvaluateInput {
            installed: true,
            current_version: None,
            latest: Some(Ok("2.0.0")),
        });
        assert_eq!(status.state, "unknown");
        assert!(!status.auto_update);

        // unknown（不可比较）
        let status = eval_with(EvaluateInput {
            installed: true,
            current_version: Some("garbage"),
            latest: Some(Ok("2.0.0")),
        });
        assert_eq!(status.state, "unknown");

        // available
        let status = eval_with(EvaluateInput {
            installed: true,
            current_version: Some("1.0.0"),
            latest: Some(Ok("2.0.0")),
        });
        assert_eq!(status.state, "available");
        assert!(status.auto_update);
        assert_eq!(status.command.as_deref(), Some("npm x"));

        // upToDate
        let status = eval_with(EvaluateInput {
            installed: true,
            current_version: Some("2.0.0"),
            latest: Some(Ok("2.0.0")),
        });
        assert_eq!(status.state, "upToDate");
        assert!(!status.auto_update);
        assert!(status.command.is_none());
    }

    #[test]
    fn available_without_tool_explains_why() {
        // 有策略但本机工具缺失 ⇒ 明确说「未找到可用的更新工具」
        let status = eval_unavailable(true);
        assert_eq!(status.state, "available");
        assert!(!status.auto_update);
        assert!(status.command.is_none());
        let message = status.message.expect("必须说明原因");
        assert!(
            message.contains("未找到可用的更新工具"),
            "话术不对: {message}"
        );

        // 压根没有策略（dsh）⇒ 说「需在其应用内更新」
        let status = eval_unavailable(false);
        assert_eq!(status.state, "available");
        assert!(!status.auto_update);
        let message = status.message.expect("必须说明原因");
        assert!(message.contains("应用内更新"), "话术不对: {message}");

        // 可更新且可自动更新 ⇒ 不写 message（前端只显示徽标）
        let status = eval_with(EvaluateInput {
            installed: true,
            current_version: Some("1.0.0"),
            latest: Some(Ok("2.0.0")),
        });
        assert!(status.auto_update);
        assert!(status.message.is_none());
    }

    #[test]
    fn update_message_covers_every_branch() {
        // 成功 + 版本变了 ⇒ 不写 message
        assert_eq!(
            update_message(true, Some("1.0.0"), Some("2.0.0"), false),
            None
        );
        // 成功 + 更新前读不到、更新后读到了 ⇒ 不写 message（不是「没变化」）
        assert_eq!(update_message(true, None, Some("2.0.0"), false), None);
        // 成功 + 更新后仍读不到 ⇒ 明确「请重新检测」
        let message = update_message(true, Some("1.0.0"), None, false).expect("要有说明");
        assert!(message.contains("无法读取版本"), "话术不对: {message}");
        // 成功 + 版本没变 ⇒ 如实说没变
        let message = update_message(true, Some("1.0.0"), Some("1.0.0"), false).expect("要有说明");
        assert!(message.contains("版本没有变化"), "话术不对: {message}");
        // 失败 + 全部 skipped ⇒ 说缺工具
        let message = update_message(false, Some("1.0.0"), Some("1.0.0"), true).expect("要有说明");
        assert!(
            message.contains("没有找到任何可用的更新工具"),
            "话术不对: {message}"
        );
        // 失败 + 真的执行过 ⇒ 让用户看输出
        let message = update_message(false, Some("1.0.0"), Some("1.0.0"), false).expect("要有说明");
        assert!(message.contains("更新失败"), "话术不对: {message}");
    }

    // ---------- auto_update ----------

    #[test]
    fn auto_update_requires_a_present_tool() {
        let missing = AgentUpdateSpec {
            channel: "x",
            source: None,
            strategies: &[UpdateStrategy {
                label: "test",
                argv: &["tianshu-relay-definitely-not-a-real-tool-m34"],
                timeout_secs: 5,
            }],
            manual_url: "",
        };
        assert_eq!(auto_update_for(&missing, &home()), (false, None));

        // 用绝对存在的系统命令做「存在」的一半
        let present = AgentUpdateSpec {
            channel: "x",
            source: None,
            strategies: &[UpdateStrategy {
                label: "test",
                argv: &["echo", "hi"],
                timeout_secs: 5,
            }],
            manual_url: "",
        };
        let (auto_update, command) = auto_update_for(&present, &home());
        assert!(auto_update);
        assert_eq!(command.as_deref(), Some("echo hi"));
    }

    // ---------- update_agent 拒绝路径 ----------

    #[test]
    fn update_agent_rejects_unknown_and_unsupported_channels() {
        for channel in ["no-such-channel", "grok-build", "dsh"] {
            let error = update_agent(&home(), channel).expect_err("必须拒绝");
            assert!(
                matches!(error, Error::InvalidInput(_)),
                "{channel} 的错误类型不对: {error:?}"
            );
        }
    }

    // ---------- run_command ----------

    #[test]
    fn run_command_captures_output() {
        let path = agents::find_bin("echo", &home()).expect("本机应有 echo");
        let run = run_command(&path, &["hello-m34"], 10, &home());
        assert!(run.success);
        assert_eq!(run.exit_code, Some(0));
        assert!(!run.timed_out);
        assert!(run.output_tail.contains("hello-m34"));
    }

    #[test]
    fn run_command_kills_on_timeout() {
        let path = agents::find_bin("sleep", &home()).expect("本机应有 sleep");
        let started = Instant::now();
        let run = run_command(&path, &["30"], 1, &home());
        assert!(!run.success);
        assert!(run.timed_out);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "超时 kill 太慢"
        );
    }

    #[test]
    fn run_command_scrubs_and_truncates_output() {
        let path = agents::find_bin("echo", &home()).expect("本机应有 echo");
        let secret = format!("sk-{}", "A".repeat(60));
        let run = run_command(&path, &[&secret], 10, &home());
        assert!(
            !run.output_tail.contains(&secret),
            "输出尾部必须经过 scrub: {}",
            run.output_tail
        );

        // 超长输出只留尾部 4096 字符（+ 前导省略号）
        let long = "x".repeat(6000);
        let run = run_command(&path, &[&long], 10, &home());
        let chars = run.output_tail.chars().count();
        assert!(
            chars <= OUTPUT_TAIL_CHARS + 1,
            "输出尾部没有截断：{chars} 字符"
        );
        assert!(run.output_tail.starts_with('…'));
    }

    // ---------- enriched_path ----------

    #[test]
    fn enriched_path_contains_common_dirs_and_dedupes() {
        let path = agents::enriched_path(&home());
        assert!(path.contains(".local/bin"));
        assert!(path.contains(".cargo/bin"));
        assert!(path.contains("/opt/homebrew/bin"));
        assert!(path.contains("/usr/local/bin"));
        assert!(path.contains("/usr/bin"));
        // 去重：同一个目录只出现一次
        let segments: Vec<&str> = path.split(':').collect();
        let mut unique = segments.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            segments.len(),
            unique.len(),
            "enriched_path 有重复段: {path}"
        );
    }

    // ---------- serde camelCase ----------

    #[test]
    fn status_and_outcome_serialize_camel_case() {
        let status = AgentUpdateStatus {
            channel: "codex-auth-json".to_string(),
            installed: true,
            current_version: Some("0.162.1".to_string()),
            latest_version: Some("0.163.0".to_string()),
            state: "available".to_string(),
            source: "npm".to_string(),
            auto_update: true,
            command: Some("codex update".to_string()),
            manual_url: Some("https://chatgpt.com/codex".to_string()),
            message: None,
        };
        let json = serde_json::to_value(&status).expect("序列化");
        for key in [
            "currentVersion",
            "latestVersion",
            "autoUpdate",
            "manualUrl",
            "installed",
            "state",
            "source",
        ] {
            assert!(json.get(key).is_some(), "缺少 camelCase 键 {key}");
        }
        assert!(json.get("current_version").is_none());

        let outcome = AgentUpdateOutcome {
            channel: "codex-auth-json".to_string(),
            success: false,
            attempts: vec![UpdateAttempt {
                label: "npm".to_string(),
                command: "npm install -g @openai/codex@latest".to_string(),
                skipped: false,
                success: false,
                exit_code: Some(1),
                timed_out: false,
                output_tail: "boom".to_string(),
            }],
            version_before: Some("0.162.1".to_string()),
            version_after: Some("0.162.1".to_string()),
            version_changed: false,
            message: Some("失败".to_string()),
        };
        let json = serde_json::to_value(&outcome).expect("序列化");
        for key in [
            "versionBefore",
            "versionAfter",
            "versionChanged",
            "outputTail",
        ] {
            assert!(
                json.get(key).is_some() || json["attempts"][0].get(key).is_some(),
                "缺少 camelCase 键 {key}"
            );
        }
    }

    // ---------- 去重 ----------

    #[test]
    fn dedupe_sources_merges_shared_agents() {
        let sources = dedupe_sources();
        // 28 条通道里 24 条有源（Droid / WorkBuddy / WorkBuddy AI / grok-build 为手动），
        // 其中 codex / opencode 各有两个落点共用同一源 ⇒ 24 − 2 = 22 个不同源。
        assert_eq!(sources.len(), 22);
        let codex = sources
            .iter()
            .filter(|source| source.id == "@openai/codex")
            .count();
        assert_eq!(codex, 1);
        let opencode = sources
            .iter()
            .filter(|source| source.id == "opencode-ai")
            .count();
        assert_eq!(opencode, 1);
    }

    // ---------- sanitize_output ----------

    #[test]
    fn sanitize_output_strips_ansi_and_scrubs() {
        // 合成密钥在运行时拼出来：仓库里不出现 `sk-` + 40 位长串的字面量
        //（`check-no-real-credentials.mjs` 的形态禁词；测试意图不变）。
        let secret = format!("sk-{}", "A".repeat(60));
        let raw = format!("\u{1b}[31mred\u{1b}[0m {secret}");
        let cleaned = sanitize_output(&raw);
        assert!(!cleaned.contains('\u{1b}'));
        assert!(!cleaned.contains(&secret), "密钥形态必须被掩：{cleaned}");
        assert!(cleaned.contains("***"), "应掩成 ***：{cleaned}");
    }
}
