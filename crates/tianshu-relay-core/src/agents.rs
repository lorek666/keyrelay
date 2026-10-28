//! Agent 工作台的核心层（M31-S1）：28 种 agent 的「装没装 + 版本 + 安装命令」。
//!
//! # 纪律
//!
//! - **不执行任何安装命令**：`installs` 只作为字符串返回，前端只做展示/复制。
//! - **不写盘、不建目录**：本模块只读（唯一例外是版本命令本身，那是用户机器的程序在跑）。
//! - **不用 shell**：`Command::new(bin).args(...)` 直接执行，不经过 `sh -c`。
//! - 版本命令超时 **2 秒**（超时按「已安装但版本未知」处理，详情见 [`detect_one`]）。

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::Serialize;

/// 探测方式。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    /// 在 PATH / 常见安装目录里找可执行文件，执行 `<bin> --version`。
    Cli {
        bins: &'static [&'static str],
        version_args: &'static [&'static str],
    },
    /// macOS 应用包：`/Applications/<bundle>.app`、`~/Applications/<bundle>.app`。
    /// 版本从 `Contents/Info.plist` 的 `CFBundleShortVersionString` 读取。
    App { bundles: &'static [&'static str] },
    /// 先查 CLI，CLI 不存在时再查 macOS 应用包（Codex 桌面版与 CLI 共用配置）。
    CliOrApp {
        bins: &'static [&'static str],
        version_args: &'static [&'static str],
        bundles: &'static [&'static str],
    },
    /// 编辑器扩展目录：`~/.vscode/extensions/<prefix>*`（也查 `.vscode-insiders`、`.cursor`），
    /// 版本从扩展的 `package.json` 的 `version` 读取。
    Extension { prefixes: &'static [&'static str] },
}

/// 一条安装方式（只展示，不执行）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallCommand {
    /// 面向用户的来源标签：`script` / `npm` / `brew` / `code`。
    pub via: &'static str,
    pub command: &'static str,
}

/// 一个 agent（与 [`crate::delivery::DeliveryChannel`] 一一对应）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentSpec {
    /// 必须与 `DeliveryChannel::as_str()` 一一对应。
    pub channel: &'static str,
    pub name: &'static str,
    pub probe: Probe,
    /// 家目录相对路径；仅用于「配置还在但程序找不到」的说明，不参与安装判定。
    pub config_path: Option<&'static str>,
    pub installs: &'static [InstallCommand],
    pub install_url: &'static str,
}

/// 给界面用的安装命令（`camelCase` 序列化）。
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallCommandInfo {
    pub via: String,
    pub command: String,
}

/// 一个 agent 的探测结果（`camelCase` 序列化）。
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentStatus {
    pub channel: String,
    pub installed: bool,
    pub version: Option<String>,
    /// 命中的可执行文件 / 应用 / 扩展目录绝对路径；未安装为 `None`。
    pub source: Option<String>,
    /// 人话补充：例如「找到配置目录 …，但没有找到命令」；没有就是 `None`。
    pub detail: Option<String>,
    pub install_commands: Vec<InstallCommandInfo>,
    pub install_url: Option<String>,
}

// ============================================================ 静态清单

const V: &[&str] = &["--version"];

macro_rules! inst {
    ($via:literal, $cmd:literal) => {
        InstallCommand {
            via: $via,
            command: $cmd,
        }
    };
}

/// 28 条 agent 清单。**顺序与 `DeliveryChannel::ALL` 逐位一致**（测试钉住）。
static SPECS: [AgentSpec; 28] = [
    AgentSpec {
        channel: "codex-auth-json",
        name: "Codex",
        probe: Probe::CliOrApp {
            bins: &["codex"],
            version_args: V,
            // Codex 桌面版本机实测安装为 /Applications/ChatGPT.app（bundle id
            // com.openai.codex）。先查 CLI，保留原有版本/更新语义；CLI 不在时
            // 用桌面 App 兜底，避免只装桌面版的用户被误判为未安装。
            bundles: &["ChatGPT"],
        },
        config_path: Some(".codex/auth.json"),
        installs: &[
            inst!(
                "script",
                "curl -fsSL https://chatgpt.com/codex/install.sh | sh"
            ),
            inst!("npm", "npm install -g @openai/codex"),
        ],
        install_url: "https://chatgpt.com/codex",
    },
    AgentSpec {
        channel: "codex-config",
        name: "Codex",
        probe: Probe::CliOrApp {
            bins: &["codex"],
            version_args: V,
            bundles: &["ChatGPT"],
        },
        config_path: Some(".codex/config.toml"),
        installs: &[
            inst!(
                "script",
                "curl -fsSL https://chatgpt.com/codex/install.sh | sh"
            ),
            inst!("npm", "npm install -g @openai/codex"),
        ],
        install_url: "https://chatgpt.com/codex",
    },
    AgentSpec {
        channel: "claude-code-settings",
        name: "Claude Code",
        probe: Probe::Cli {
            bins: &["claude"],
            version_args: V,
        },
        config_path: Some(".claude/settings.json"),
        installs: &[
            inst!("script", "curl -fsSL https://claude.ai/install.sh | bash"),
            inst!("npm", "npm install -g @anthropic-ai/claude-code"),
        ],
        install_url: "https://code.claude.com/docs",
    },
    AgentSpec {
        channel: "opencode",
        name: "OpenCode",
        probe: Probe::Cli {
            bins: &["opencode"],
            version_args: V,
        },
        config_path: Some(".config/opencode/opencode.json"),
        installs: &[
            inst!("script", "curl -fsSL https://opencode.ai/install | bash"),
            inst!("npm", "npm install -g opencode-ai"),
        ],
        install_url: "https://opencode.ai",
    },
    AgentSpec {
        channel: "gemini-cli",
        name: "Gemini CLI",
        probe: Probe::Cli {
            bins: &["gemini"],
            version_args: V,
        },
        config_path: Some(".gemini/.env"),
        installs: &[
            inst!("brew", "brew install gemini-cli"),
            inst!("npm", "npm install -g @google/gemini-cli"),
        ],
        install_url: "https://github.com/google-gemini/gemini-cli",
    },
    AgentSpec {
        channel: "opencode-jsonc",
        name: "OpenCode",
        probe: Probe::Cli {
            bins: &["opencode"],
            version_args: V,
        },
        config_path: Some(".config/opencode/opencode.jsonc"),
        installs: &[
            inst!("script", "curl -fsSL https://opencode.ai/install | bash"),
            inst!("npm", "npm install -g opencode-ai"),
        ],
        install_url: "https://opencode.ai",
    },
    AgentSpec {
        channel: "claude-desktop",
        name: "Claude Desktop",
        probe: Probe::App {
            bundles: &["Claude"],
        },
        config_path: Some("Library/Application Support/Claude/claude_desktop_config.json"),
        installs: &[inst!("brew", "brew install --cask claude")],
        install_url: "https://claude.ai/download",
    },
    AgentSpec {
        channel: "grok-build",
        name: "Grok Build",
        probe: Probe::Cli {
            bins: &["grok"],
            version_args: V,
        },
        config_path: Some(".grok/config.toml"),
        installs: &[inst!(
            "script",
            "curl -fsSL https://x.ai/cli/install.sh | bash"
        )],
        install_url: "https://x.ai/cli",
    },
    AgentSpec {
        channel: "openclaw",
        name: "OpenClaw",
        probe: Probe::Cli {
            bins: &["openclaw"],
            version_args: V,
        },
        config_path: Some(".openclaw/openclaw.json"),
        installs: &[inst!("npm", "npm install -g openclaw@latest")],
        install_url: "https://www.npmjs.com/package/openclaw",
    },
    AgentSpec {
        channel: "hermes",
        name: "Hermes",
        probe: Probe::Cli {
            bins: &["hermes"],
            version_args: V,
        },
        config_path: Some(".hermes/config.yaml"),
        installs: &[inst!("npm", "npm install -g hermes-agent")],
        install_url: "https://www.npmjs.com/package/hermes-agent",
    },
    AgentSpec {
        channel: "mcode",
        name: "MCode",
        probe: Probe::Cli {
            bins: &["mcode"],
            version_args: V,
        },
        config_path: Some(".minimax/config.yaml"),
        installs: &[inst!("npm", "npm install -g @minimax-ai/code")],
        install_url: "https://www.npmjs.com/package/@minimax-ai/code",
    },
    AgentSpec {
        channel: "pi",
        name: "Pi",
        probe: Probe::Cli {
            bins: &["pi"],
            version_args: V,
        },
        config_path: Some(".pi/agent/models.json"),
        installs: &[inst!(
            "npm",
            "npm install -g @earendil-works/pi-coding-agent"
        )],
        install_url: "https://www.npmjs.com/package/@earendil-works/pi-coding-agent",
    },
    AgentSpec {
        channel: "cursor",
        name: "Cursor",
        probe: Probe::App {
            bundles: &["Cursor"],
        },
        config_path: Some(".cursor/settings.json"),
        installs: &[inst!("brew", "brew install --cask cursor")],
        install_url: "https://cursor.com",
    },
    AgentSpec {
        channel: "cline",
        name: "Cline",
        probe: Probe::Extension {
            prefixes: &["saoudrizwan.claude-dev"],
        },
        config_path: Some(".cline/providers.json"),
        installs: &[inst!(
            "code",
            "code --install-extension saoudrizwan.claude-dev"
        )],
        install_url: "https://marketplace.visualstudio.com/items?itemName=saoudrizwan.claude-dev",
    },
    AgentSpec {
        channel: "qwen-code",
        name: "Qwen Code",
        probe: Probe::Cli {
            bins: &["qwen"],
            version_args: V,
        },
        config_path: Some(".qwen/settings.json"),
        installs: &[inst!("npm", "npm install -g @qwen-code/qwen-code")],
        install_url: "https://github.com/QwenLM/qwen-code",
    },
    AgentSpec {
        channel: "deepseek",
        name: "DeepSeek",
        probe: Probe::Cli {
            bins: &["reasonix"],
            version_args: V,
        },
        config_path: Some(".reasonix/config.json"),
        installs: &[inst!("npm", "npm install -g reasonix")],
        install_url: "https://www.npmjs.com/package/reasonix",
    },
    AgentSpec {
        channel: "trae",
        name: "Trae",
        probe: Probe::App { bundles: &["Trae"] },
        config_path: Some(".trae/config.json"),
        installs: &[inst!("brew", "brew install --cask trae")],
        install_url: "https://www.trae.ai",
    },
    AgentSpec {
        channel: "mimo-code",
        name: "MiMo Code",
        probe: Probe::Cli {
            bins: &["mimocode", "mimo"],
            version_args: V,
        },
        config_path: Some(".mimocode/mimocode.json"),
        installs: &[inst!("npm", "npm install -g mimocode")],
        install_url: "https://www.npmjs.com/package/mimocode",
    },
    AgentSpec {
        channel: "cline-desktop",
        name: "Cline Desktop",
        probe: Probe::App {
            bundles: &["Cline"],
        },
        config_path: Some(".cline/data/settings/providers.json"),
        installs: &[inst!("brew", "brew install --cask cline-app")],
        install_url: "https://cline.bot",
    },
    AgentSpec {
        channel: "dsh",
        name: "DeepSeek Harness",
        // M31-S1 验收（2026-10-21）：dsh 走**应用包**而不是 CLI。
        // 本机实测 `~/.local/bin/dsh --version` 返回 126（Permission denied —— 文件在但跑不起来），
        // 而 `/Applications/DeepSeek Harness.app` 的 Info.plist 有 `0.2.1-rc.2` ⇒ 只有 App 探测
        // 能拿到 spec 验收要求的版本。取舍见模块文档 / 报告（CLI-only 安装会漏检）。
        probe: Probe::App {
            bundles: &["DeepSeek Harness"],
        },
        config_path: Some(".dsh/.credentials.yaml"),
        installs: &[inst!("npm", "npm install -g @deepseek-ai/dsh")],
        install_url: "https://www.npmjs.com/package/@deepseek-ai/dsh",
    },
    AgentSpec {
        channel: "qoder",
        name: "Qoder",
        probe: Probe::Cli {
            bins: &["qodercli"],
            version_args: V,
        },
        config_path: Some(".qoder/settings.json"),
        installs: &[inst!("npm", "npm install -g @qoder-ai/qodercli")],
        install_url: "https://qoder.com",
    },
    AgentSpec {
        channel: "qoder-cn",
        name: "Qoder CN",
        probe: Probe::Cli {
            bins: &["qoderclicn"],
            version_args: V,
        },
        config_path: Some(".qoder-cn/settings.json"),
        installs: &[inst!("npm", "npm install -g @qodercn-ai/qoderclicn")],
        install_url: "https://qoder.cn",
    },
    AgentSpec {
        channel: "kimi-code",
        name: "Kimi Code",
        probe: Probe::Cli {
            bins: &["kimi"],
            version_args: V,
        },
        config_path: Some(".kimi-code/config.toml"),
        installs: &[inst!("npm", "npm install -g @moonshot-ai/kimi-code")],
        install_url: "https://www.kimi.com/coding",
    },
    AgentSpec {
        channel: "droid",
        name: "Droid",
        probe: Probe::Cli {
            bins: &["droid"],
            version_args: V,
        },
        config_path: Some(".factory/settings.json"),
        installs: &[inst!(
            "script",
            "curl -fsSL https://app.factory.ai/cli | sh"
        )],
        install_url: "https://factory.ai",
    },
    AgentSpec {
        channel: "codebuddy",
        name: "CodeBuddy Code",
        probe: Probe::Cli {
            bins: &["codebuddy", "cbc"],
            version_args: V,
        },
        config_path: Some(".codebuddy/models.json"),
        installs: &[inst!("npm", "npm install -g @tencent-ai/codebuddy-code")],
        install_url: "https://codebuddy.ai",
    },
    AgentSpec {
        channel: "workbuddy",
        name: "WorkBuddy",
        probe: Probe::App {
            bundles: &["WorkBuddy"],
        },
        config_path: Some(".workbuddy/models.json"),
        installs: &[inst!("brew", "brew install --cask workbuddy-cn")],
        install_url: "https://www.workbuddy.ai",
    },
    AgentSpec {
        channel: "workbuddy-ai",
        name: "WorkBuddy AI",
        probe: Probe::App {
            bundles: &["WorkBuddy AI"],
        },
        config_path: Some(".workbuddy-ai/models.json"),
        installs: &[inst!("brew", "brew install --cask workbuddy-ai")],
        install_url: "https://www.workbuddy.ai",
    },
    AgentSpec {
        channel: "crush",
        name: "Crush",
        probe: Probe::Cli {
            bins: &["crush"],
            version_args: V,
        },
        config_path: Some(".config/crush/crush.json"),
        installs: &[inst!("npm", "npm install -g @charmland/crush")],
        install_url: "https://github.com/charmbracelet/crush",
    },
];

/// 全部 28 条（顺序与 `DeliveryChannel::ALL` 逐位一致）。
pub fn specs() -> &'static [AgentSpec] {
    &SPECS
}

// ============================================================ 探测

/// 版本命令的超时（spec §4.1，M31-S1 定为 **5 秒**）。
///
/// 为什么不是 2 秒：`node` / `npm` 类 CLI 冷启动就要 1–3 秒，2 秒会把「刚装完第一次检测」
/// 误报成「版本命令超时」；macOS 对新写入脚本的首次 exec 还有 provenance 扫描
/// （实测 8–15 秒，spec §9）——5 秒覆盖不到的极端情况由「再点一次重新检测」兜底
/// （第二次 exec 不再扫描）。
const VERSION_TIMEOUT: Duration = Duration::from_secs(5);

/// 并行探测全部 agent（`std::thread::scope`；单个探测 panic 不影响其余）。
pub fn detect_agents(home: &Path) -> Vec<AgentStatus> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = specs()
            .iter()
            .map(|spec| scope.spawn(move || detect_one(spec, home)))
            .collect();
        handles
            .into_iter()
            .zip(specs().iter())
            .map(|(handle, spec)| match handle.join() {
                Ok(status) => status,
                // 探测 panic 不该让整页崩：降级成「未安装 + 说明」，其余 27 条照常。
                Err(_) => AgentStatus {
                    channel: spec.channel.to_string(),
                    installed: false,
                    version: None,
                    source: None,
                    detail: Some("探测该 agent 时发生内部错误".to_string()),
                    install_commands: install_infos(spec),
                    install_url: Some(spec.install_url.to_string()),
                },
            })
            .collect()
    })
}

/// DEBUG-G7 P2-C3：Cline CLI 探针（B-291 应用内路径之 ① PATH 检测）。
///
/// 只做检测，不写盘、不调 `cline auth`：直写代码不在本组范围（ADR-0006 §9
/// 的下线裁定不变），本探针 + 可复制命令是给下线通道留的应用内路径。
/// 复用 `find_bin` 的加宽搜索（home bin + Homebrew + 系统目录 + `PATH`），
/// 因此“没找到”必须与“确实未安装”区分开写进 `note`——GUI 进程 PATH 假阴性
/// （C2 ③）下，前者只是“本应用的搜索范围里没见到”。
/// 版本用 `run_version`（5s 超时，stdout 优先、stderr 兜底）；拿不到版本时
/// `version` 为 `None`，文案写“版本未确认”，不得编造版本号。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClineCliProbe {
    pub found: bool,
    pub path: Option<String>,
    pub version: Option<String>,
    pub note: String,
}

pub fn probe_cline_cli(home: &Path) -> ClineCliProbe {
    let Some(path) = find_bin("cline", home) else {
        return ClineCliProbe {
            found: false,
            path: None,
            version: None,
            note: "在应用的搜索范围（家目录 bin、Homebrew、系统目录、PATH）里没找到 cline CLI；这不等于确实未安装——经 Finder/Dock 启动的应用 PATH 较窄，终端里能跑的 cline 也可能在这里查不到。请按下方命令在终端确认，或装好 CLI 后点“重新检测”。".to_string(),
        };
    };
    let path_display = path.display().to_string();
    match run_version(&path, &["--version"]) {
        VersionRun::Ok(version) => ClineCliProbe {
            found: true,
            path: Some(path_display),
            version: version.clone(),
            note: match version {
                Some(_) => "已找到 cline CLI。".to_string(),
                None => {
                    "已找到 cline CLI，但版本未确认（--version 未返回可解析的版本号）。".to_string()
                }
            },
        },
        VersionRun::TimedOut => ClineCliProbe {
            found: true,
            path: Some(path_display),
            version: None,
            note: "已找到 cline CLI，但版本探测超时（5 秒），版本未确认；可点“重新检测”再试一次。"
                .to_string(),
        },
        VersionRun::Failed(reason) => ClineCliProbe {
            found: true,
            path: Some(path_display),
            version: None,
            note: format!("已找到 cline CLI，但版本命令执行失败（{reason}），版本未确认。"),
        },
    }
}

/// 探测单个 agent。
pub fn detect_one(spec: &AgentSpec, home: &Path) -> AgentStatus {
    match spec.probe {
        Probe::Cli { bins, version_args } => detect_cli(spec, home, bins, version_args),
        Probe::CliOrApp {
            bins,
            version_args,
            bundles,
        } => detect_cli_or_app(spec, home, bins, version_args, bundles),
        Probe::App { bundles } => detect_app(spec, home, bundles),
        Probe::Extension { prefixes } => detect_extension(spec, home, prefixes),
    }
}

fn install_infos(spec: &AgentSpec) -> Vec<InstallCommandInfo> {
    spec.installs
        .iter()
        .map(|install| InstallCommandInfo {
            via: install.via.to_string(),
            command: install.command.to_string(),
        })
        .collect()
}

/// 收尾：装好基础字段（每条分支都从这里出，避免漏 installCommands）。
fn status(
    spec: &AgentSpec,
    installed: bool,
    version: Option<String>,
    source: Option<String>,
    detail: Option<String>,
) -> AgentStatus {
    AgentStatus {
        channel: spec.channel.to_string(),
        installed,
        version,
        source,
        detail,
        install_commands: install_infos(spec),
        install_url: Some(spec.install_url.to_string()),
    }
}

fn detect_cli(
    spec: &AgentSpec,
    home: &Path,
    bins: &[&'static str],
    version_args: &[&'static str],
) -> AgentStatus {
    for bin in bins {
        if let Some(path) = find_bin(bin, home) {
            let source = Some(path.display().to_string());
            match run_version(&path, version_args) {
                VersionRun::Ok(version) => {
                    return status(spec, true, version, source, None);
                }
                VersionRun::TimedOut => {
                    return status(spec, true, None, source, Some("版本命令超时".to_string()));
                }
                VersionRun::Failed(err) => {
                    // 程序在、但跑不起来（权限 / 缺依赖）：仍算「已安装」，把原因写进 detail。
                    return status(
                        spec,
                        true,
                        None,
                        source,
                        Some(format!("版本命令失败: {err}")),
                    );
                }
            }
        }
    }
    status(spec, false, None, None, config_only_detail(spec, home))
}

/// CLI 优先、macOS 应用包兜底。Codex 桌面版与 CLI 共用 `~/.codex`，但只装
/// 桌面版（`/Applications/ChatGPT.app`）的用户没有 PATH 里的 `codex`，不能
/// 因此判成未安装。CLI 存在时保留 CLI 版本，避免把桌面应用版本 `26.x`
/// 拿去和 npm 上的 `codex` 版本比较。
fn detect_cli_or_app(
    spec: &AgentSpec,
    home: &Path,
    bins: &[&'static str],
    version_args: &[&'static str],
    bundles: &[&'static str],
) -> AgentStatus {
    let cli = detect_cli(spec, home, bins, version_args);
    if cli.installed {
        return cli;
    }

    #[cfg(target_os = "macos")]
    {
        let app = detect_app(spec, home, bundles);
        if app.installed {
            return app;
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = bundles;

    cli
}

/// 「配置还在，但程序没找到」的说明（spec §4.1 的 installed 判据）。
fn config_only_detail(spec: &AgentSpec, home: &Path) -> Option<String> {
    let relative = spec.config_path?;
    let path = home.join(relative);
    path.exists().then(|| {
        format!(
            "找到配置 {}，但没有找到程序（可能已卸载，或装在非常规目录）",
            path.display()
        )
    })
}

#[cfg(target_os = "macos")]
fn detect_app(spec: &AgentSpec, home: &Path, bundles: &[&'static str]) -> AgentStatus {
    detect_app_at(spec, home, bundles, Path::new("/Applications"))
}

#[cfg(target_os = "macos")]
fn detect_app_at(
    spec: &AgentSpec,
    home: &Path,
    bundles: &[&'static str],
    system_applications: &Path,
) -> AgentStatus {
    for bundle in bundles {
        let candidates = [
            system_applications.join(format!("{bundle}.app")),
            home.join("Applications").join(format!("{bundle}.app")),
        ];
        for app in candidates {
            if app.is_dir() {
                let version = app_version(&app);
                return status(spec, true, version, Some(app.display().to_string()), None);
            }
        }
    }
    status(spec, false, None, None, config_only_detail(spec, home))
}

#[cfg(not(target_os = "macos"))]
fn detect_app(spec: &AgentSpec, home: &Path, _bundles: &[&'static str]) -> AgentStatus {
    // 应用包是 macOS 概念：其它平台一律「未安装」（不猜、不去查 Linux 的 .desktop）。
    status(spec, false, None, None, config_only_detail(spec, home))
}

fn detect_extension(spec: &AgentSpec, home: &Path, prefixes: &[&'static str]) -> AgentStatus {
    for root in [
        home.join(".vscode").join("extensions"),
        home.join(".vscode-insiders").join("extensions"),
        home.join(".cursor").join("extensions"),
    ] {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !prefixes.iter().any(|prefix| name.starts_with(prefix)) {
                continue;
            }
            let dir = entry.path();
            let version = read_package_version(&dir.join("package.json"));
            return status(spec, true, version, Some(dir.display().to_string()), None);
        }
    }
    status(spec, false, None, None, config_only_detail(spec, home))
}

// ============================================================ 可执行文件查找

/// `$HOME` 下的常见 bin 目录（**逐条对应 spec §4.1 的清单，不多不少**）。
fn home_bin_dirs(home: &Path) -> [PathBuf; 7] {
    [
        home.join(".local/bin"),
        home.join(".npm-global/bin"),
        home.join(".bun/bin"),
        home.join(".volta/bin"),
        home.join(".cargo/bin"),
        home.join(".grok/bin"),
        home.join(".opencode/bin"),
    ]
}

/// 系统级目录（spec 列出的三个）+ PATH。
fn system_bin_dirs() -> [PathBuf; 3] {
    [
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/usr/bin"),
    ]
}

pub(crate) fn find_bin(bin: &str, home: &Path) -> Option<PathBuf> {
    let names: Vec<String> = if cfg!(windows) {
        vec![format!("{bin}.exe"), format!("{bin}.cmd"), bin.to_string()]
    } else {
        vec![bin.to_string()]
    };

    let mut dirs: Vec<PathBuf> = home_bin_dirs(home)
        .into_iter()
        .chain(system_bin_dirs())
        .collect();
    if let Some(path) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&path));
    }

    for dir in dirs {
        for name in &names {
            let candidate = dir.join(name);
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// 更新执行用的 PATH（M34-S1 spec §4.4 第 4 条）：
/// 家目录常见 bin + 系统目录 + 原 `PATH`，去重后按平台拼成字符串。
///
/// 为什么需要它：GUI 应用从 Finder/Dock 启动时 `PATH` 往往只有
/// `/usr/bin:/bin:/usr/sbin:/sbin`，`npm` / `brew` 都在别处；更隐蔽的是
/// `#!/usr/bin/env node` 的脚本会因找不到 `node` 而失败。注入这份 PATH 后，
/// 子进程与用户终端里的行为一致。
pub(crate) fn enriched_path(home: &Path) -> String {
    let mut dirs: Vec<PathBuf> = home_bin_dirs(home)
        .into_iter()
        .chain(system_bin_dirs())
        .collect();
    if let Some(path) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&path));
    }

    // 去重（保持首次出现顺序：家目录 bin 优先于系统目录）
    let mut seen: Vec<PathBuf> = Vec::with_capacity(dirs.len());
    for dir in dirs {
        if !seen.iter().any(|existing| existing == &dir) {
            seen.push(dir);
        }
    }

    std::env::join_paths(seen)
        .map(|paths| paths.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    path.metadata()
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

// ============================================================ 版本命令

enum VersionRun {
    Ok(Option<String>),
    TimedOut,
    Failed(String),
}

/// 跑 `<bin> --version`（5s 超时；stdout 优先、stderr 兜底）。
fn run_version(path: &Path, version_args: &[&str]) -> VersionRun {
    let mut child = match Command::new(path)
        .args(version_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => return VersionRun::Failed(err.to_string()),
    };

    // 两路并发读，避免子进程写满管道后阻塞。
    let stdout = child.stdout.take().map(read_to_string_async);
    let stderr = child.stderr.take().map(read_to_string_async);

    let deadline = std::time::Instant::now() + VERSION_TIMEOUT;
    let exit = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(err) => return VersionRun::Failed(err.to_string()),
        }
    };
    let Some(status) = exit else {
        return VersionRun::TimedOut;
    };

    // **不要 join 读线程**：子进程正常退出后，如果它派生的后台子孙进程继承了
    // stdout/stderr 管道，`read_to_end` 要等那个子孙也退出才 EOF ⇒ join 会把
    // 「2s/5s 超时」变成无限等待（复审 P2-1）。用 channel + recv_timeout 取已读结果；
    // 极端情况下读线程会晚一点结束，但它不阻塞本命令的返回。
    let out = read_available(stdout);
    let err = read_available(stderr);
    if !status.success() && out.trim().is_empty() && err.trim().is_empty() {
        return VersionRun::Failed(format!("退出码 {}", status.code().unwrap_or(-1)));
    }
    // stdout 优先、stderr 兜底（很多 CLI 把 --version 打到 stderr）。
    let text = if out.trim().is_empty() { err } else { out };
    VersionRun::Ok(extract_version(&text))
}

pub(crate) fn read_to_string_async(
    mut reader: impl std::io::Read + Send + 'static,
) -> std::sync::mpsc::Receiver<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // **按块发送**而不是 read_to_end 后发一次：后台子孙进程继承管道时，
        // read_to_end 要等它退出才 EOF；按块发送能让主线程先拿到已经输出的版本。
        let mut buffer = [0_u8; 4096];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if tx
                        .send(String::from_utf8_lossy(&buffer[..n]).into_owned())
                        .is_err()
                    {
                        break; // 接收端已因超时被丢掉
                    }
                }
                Err(_) => break,
            }
        }
    });
    rx
}

/// 取读线程已经读到的内容；最多等 500ms（管道被后台子孙继承时不会永远等）。
pub(crate) fn read_available(rx: Option<std::sync::mpsc::Receiver<String>>) -> String {
    let Some(rx) = rx else {
        return String::new();
    };
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    let mut out = String::new();
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            break;
        }
        match rx.recv_timeout(left) {
            Ok(chunk) => out.push_str(&chunk),
            Err(_) => break,
        }
    }
    out
}

/// 从版本命令输出里提取版本（spec §4.1）：
/// 取第一行 → 去 ANSI → 第一个「含数字与 `.`」的 token → 去前导 `v` → 最长 40 字符；
/// 解析不到 ⇒ 整行截断到 120 字符；空 ⇒ `None`。
pub fn extract_version(output: &str) -> Option<String> {
    let first_line = output.lines().next().unwrap_or("").trim();
    if first_line.is_empty() {
        return None;
    }
    let cleaned = strip_ansi(first_line);
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        return None;
    }
    for token in cleaned.split_whitespace() {
        if token.chars().any(|c| c.is_ascii_digit()) && token.contains('.') {
            let token = token.trim_start_matches('v');
            let capped: String = token.chars().take(40).collect();
            if !capped.is_empty() {
                return Some(capped);
            }
        }
    }
    // 解析不到：把整行截断到 120 字符（保持可读，不猜版本）。
    Some(cleaned.chars().take(120).collect())
}

/// 去 ANSI 转义（`ESC [ … m` 这类 SGR；版本命令偶尔带颜色）。
pub(crate) fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        // `ESC [` … 终止于 0x40..=0x7E（CSI）；`ESC ]` 是 OSC，这里简单吃到 BEL/ST。
        match chars.peek() {
            Some('[') => {
                chars.next();
                for next in chars.by_ref() {
                    if ('@'..='~').contains(&next) {
                        break;
                    }
                }
            }
            Some(']') => {
                chars.next();
                for next in chars.by_ref() {
                    if next == '\u{7}' || next == '\u{1b}' {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    out
}

// ============================================================ macOS 应用版本

#[cfg(target_os = "macos")]
fn app_version(app: &Path) -> Option<String> {
    let plist = app.join("Contents").join("Info.plist");
    let text = std::fs::read_to_string(&plist).ok()?;
    if let Some(version) = plist_short_version(&text) {
        return Some(version);
    }
    // 二进制 plist：降级走 `defaults read`（仍然是只读）。
    let output = Command::new("/usr/bin/defaults")
        .arg("read")
        .arg(app.join("Contents").join("Info"))
        .arg("CFBundleShortVersionString")
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    extract_plain_version(stdout.trim())
}

#[cfg(target_os = "macos")]
fn plist_short_version(text: &str) -> Option<String> {
    const KEY: &str = "CFBundleShortVersionString";
    let key_pos = text.find(&format!("<key>{KEY}</key>"))?;
    let rest = &text[key_pos..];
    let start = rest.find("<string>")? + "<string>".len();
    let end = rest[start..].find("</string>")? + start;
    extract_plain_version(rest[start..end].trim())
}

/// 只接受「像版本」的串（数字 + 点）；其余返回 `None`（不猜）。
fn extract_plain_version(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let ok = text.chars().any(|c| c.is_ascii_digit()) && text.contains('.');
    ok.then(|| text.chars().take(40).collect())
}

// ============================================================ 扩展版本

fn read_package_version(package_json: &Path) -> Option<String> {
    let text = std::fs::read_to_string(package_json).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    let version = value.get("version")?.as_str()?.trim();
    extract_plain_version(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_cline_cli_finds_fake_bin_and_reports_not_found_without_claiming_uninstalled() {
        // DEBUG-G7 P2-C3：家目录 bin 里有可执行 cline 时 found=true 且版本可解析；
        // 空家目录时 found=false，且 note 必须写清“搜索范围里没找到 ≠ 确实未安装”。
        let dir = tempfile::tempdir().expect("临时目录");
        let bin_dir = dir.path().join(".local").join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        // Windows 下没有 sh：无后缀的 sh 脚本能被 find_bin 找到（非 Unix 的
        // is_executable 只看 is_file），但 Command::new 跑不起来，CI 上表现为
        // found=true、版本 None。生产 find_bin 在 Windows 上本来就先找 .exe/.cmd，
        // 因此夹具用 .cmd；CreateProcess 会经 cmd.exe 执行它，输出同样是
        // "cline 1.2.3"，版本解析不变。
        #[cfg(windows)]
        let script = bin_dir.join("cline.cmd");
        #[cfg(not(windows))]
        let script = bin_dir.join("cline");
        #[cfg(windows)]
        std::fs::write(&script, "@echo cline 1.2.3\r\n").unwrap();
        #[cfg(not(windows))]
        std::fs::write(&script, "#!/bin/sh\necho \"cline 1.2.3\"\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut found = probe_cline_cli(dir.path());
        // macOS 首次执行临时脚本会触发 provenance/安全扫描（实测 8–15s），
        // 在满载 CI 上会超过 probe 的 5s 版本超时。用户是手动重试的，测试也重试
        // 一次以只验证“脚本可解析出版本”，不把系统首次扫描时间当成产品回归。
        if found.version.is_none() {
            found = probe_cline_cli(dir.path());
        }
        assert!(found.found);
        assert_eq!(found.version.as_deref(), Some("1.2.3"));
        // 生产侧候选路径里 `.local/bin` 一段是写死的 `/` 拼接，Windows 上与
        // PathBuf 拼出的 `\` 混用（功能无碍，CreateProcess 接受 `/`）；断言前
        // 两边统一归一化分隔符（与扩展目录断言同款写法），只比路径本身。
        let normalize = |p: &str| p.replace('\\', "/");
        assert_eq!(
            found.path.as_deref().map(normalize),
            Some(normalize(&script.display().to_string()))
        );

        // 注：本断言假设运行环境的 PATH 与系统目录里没有 cline（CI/VM 成立）；
        // 若机器上装有 cline，find_bin 会在系统目录/PATH 里找到它，found 即为真。
        let empty = tempfile::tempdir().expect("临时目录");
        let missing = probe_cline_cli(empty.path());
        assert!(!missing.found);
        assert!(missing.path.is_none());
        assert!(missing.version.is_none());
        assert!(
            missing.note.contains("不等于确实未安装"),
            "{}",
            missing.note
        );
    }

    #[test]
    fn specs_cover_exactly_the_delivery_channels_in_order() {
        use crate::delivery::DeliveryChannel;
        assert_eq!(specs().len(), 28, "spec §4.1：恰好 28 条");
        let channels: Vec<&str> = specs().iter().map(|spec| spec.channel).collect();
        let expected: Vec<&str> = DeliveryChannel::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(channels, expected, "顺序与 DeliveryChannel::ALL 逐位一致");
    }

    #[test]
    fn every_spec_has_display_fields_and_install_commands() {
        for spec in specs() {
            assert!(!spec.name.trim().is_empty(), "{} 缺少 name", spec.channel);
            assert!(!spec.installs.is_empty(), "{} 缺少安装命令", spec.channel);
            assert!(
                !spec.install_url.trim().is_empty(),
                "{} 缺少 install_url",
                spec.channel
            );
            assert!(
                spec.install_url.starts_with("https://"),
                "{} 的 install_url 必须是 https",
                spec.channel
            );
            for install in spec.installs {
                assert!(
                    ["script", "npm", "brew", "code"].contains(&install.via),
                    "{} 的 via 非法：{}",
                    spec.channel,
                    install.via
                );
                assert!(!install.command.trim().is_empty());
            }
            // CLI 或 CLI+App 探测必须有 bin 与 version 参数
            if let Probe::Cli { bins, version_args }
            | Probe::CliOrApp {
                bins, version_args, ..
            } = spec.probe
            {
                assert!(!bins.is_empty(), "{} 没有 bin", spec.channel);
                assert!(!version_args.is_empty());
            }
        }
    }

    #[test]
    fn extract_version_handles_the_documented_shapes() {
        for (input, expected) in [
            ("1.2.3", Some("1.2.3")),
            ("v1.2.3", Some("1.2.3")),
            ("codex-cli 0.9.1", Some("0.9.1")),
            ("\u{1b}[32m9.9.9\u{1b}[0m", Some("9.9.9")),
            ("v0.1.0\nsecond line 2.0.0", Some("0.1.0")),
            ("   ", None),
            ("", None),
        ] {
            assert_eq!(
                extract_version(input).as_deref(),
                expected,
                "输入 {input:?}"
            );
        }
        // 解析不到 ⇒ 整行截断到 120 字符（不是 None）
        let no_version = "no version here";
        assert_eq!(extract_version(no_version).as_deref(), Some(no_version));
        let long = "x".repeat(200);
        assert_eq!(extract_version(&long).unwrap().chars().count(), 120);
        // 版本 token 最长 40 字符
        let long_token = format!("v{}", "1".repeat(60)) + ".0";
        assert_eq!(extract_version(&long_token).unwrap().chars().count(), 40);
    }

    #[cfg(unix)]
    #[test]
    fn detects_a_fake_cli_with_version() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("临时目录");
        let home = dir.path();
        // 用 codex-auth-json 的 spec，但 bin 名固定是 `codex`。
        //
        // **不要在这里写一个临时 shell 脚本再直接 exec**：macOS 会给新 inode 打
        // `com.apple.provenance`，第一次 exec 要做安全扫描（实测 8–15s），
        // 必然超过 run_version 的 5s 超时 ⇒ 测试假红（本文件历史上翻过一次车）。
        // 软链到系统已有的 bash：二进制早已被扫描过，`bash --version` 又能稳定输出
        // 一个带数字与点的版本 token。精确的 `9.9.9` 解析由 `extract_version_...` 覆盖。
        let bin = home.join(".local/bin/codex");
        std::fs::create_dir_all(bin.parent().expect("parent")).expect("建目录");
        symlink("/bin/bash", &bin).expect("建软链");

        let spec = specs()
            .iter()
            .find(|s| s.channel == "codex-auth-json")
            .unwrap();
        let status = detect_one(spec, home);
        assert!(status.installed, "{status:?}");
        assert!(status.version.is_some(), "{status:?}");
        assert!(!status.version.as_deref().unwrap().is_empty());
        assert!(status
            .source
            .as_deref()
            .unwrap()
            .ends_with(".local/bin/codex"));
        assert!(status.detail.is_none());
        assert!(!status.install_commands.is_empty());
    }

    /// 超时路径：软链到 `/bin/bash` + 假 spec 传 `-c "sleep 30"` ⇒ 必超时（真等满 5 秒）。
    ///
    /// 同样**不写临时脚本**（理由同上一条：macOS 首次 exec 的 provenance 扫描会把
    /// 「超时测试」变成「扫描超时」，测的就不是 `run_version` 了）。
    /// P2-1 回归：子进程正常退出，但它派生的后台子孙仍持有 stdout 管道。
    /// 旧实现 `join()` 读线程会等那个子孙退出才返回（可能永久），本测试会挂；
    /// 新实现按块读 + recv_timeout，拿到 `9.9.9` 就返回。
    #[cfg(unix)]
    #[test]
    fn background_child_holding_the_pipe_does_not_block_the_probe() {
        let dir = tempfile::tempdir().expect("临时目录");
        let home = dir.path();
        let bin = home.join(".local/bin/leakybin");
        std::fs::create_dir_all(bin.parent().expect("parent")).expect("建目录");
        std::os::unix::fs::symlink("/bin/bash", &bin).expect("建软链");

        let spec = AgentSpec {
            channel: "fake-leaky",
            name: "Leaky",
            probe: Probe::Cli {
                bins: &["leakybin"],
                version_args: &["-c", "(sleep 2 &); echo 9.9.9"],
            },
            config_path: None,
            installs: &[inst!("npm", "npm i -g x")],
            install_url: "https://example.invalid",
        };
        let started = std::time::Instant::now();
        let status = detect_one(&spec, home);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "后台子孙持有管道时探测不得等待它退出：{:?}",
            started.elapsed()
        );
        assert_eq!(status.version.as_deref(), Some("9.9.9"), "{status:?}");
        assert!(status.detail.is_none(), "{status:?}");
    }

    #[cfg(unix)]
    #[test]
    fn fake_cli_that_times_out_is_installed_without_version() {
        let dir = tempfile::tempdir().expect("临时目录");
        let home = dir.path();
        let bin = home.join(".local/bin/slowbin");
        std::fs::create_dir_all(bin.parent().expect("parent")).expect("建目录");
        std::os::unix::fs::symlink("/bin/bash", &bin).expect("建软链");

        let spec = AgentSpec {
            channel: "fake-slow",
            name: "Slow",
            probe: Probe::Cli {
                bins: &["slowbin"],
                version_args: &["-c", "sleep 30"],
            },
            config_path: None,
            installs: &[inst!("npm", "npm i -g x")],
            install_url: "https://example.invalid",
        };
        let status = detect_one(&spec, home);
        assert!(status.installed, "程序在就算已安装：{status:?}");
        assert_eq!(status.version, None, "超时 ⇒ 版本未知");
        assert_eq!(status.detail.as_deref(), Some("版本命令超时"));
    }

    #[test]
    fn fake_extension_directory_is_detected() {
        let dir = tempfile::tempdir().expect("临时目录");
        let home = dir.path();
        let ext = home
            .join(".vscode/extensions")
            .join("saoudrizwan.claude-dev-3.2.1");
        std::fs::create_dir_all(&ext).expect("建目录");
        std::fs::write(
            ext.join("package.json"),
            r#"{"name":"claude-dev","version":"3.2.1"}"#,
        )
        .expect("写 package.json");
        let spec = specs().iter().find(|s| s.channel == "cline").unwrap();
        let status = detect_one(spec, home);
        assert!(status.installed, "{status:?}");
        assert_eq!(status.version.as_deref(), Some("3.2.1"));
        // source 是生产返回的 display() 路径：Windows 下分隔符是反斜杠，
        // 断言前先归一化，否则 ".vscode/extensions" 在 Windows 上永远匹配不到。
        let source = status.source.as_deref().unwrap().replace('\\', "/");
        assert!(source.contains(".vscode/extensions"), "{status:?}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn fake_app_bundle_is_detected_from_info_plist() {
        let dir = tempfile::tempdir().expect("临时目录");
        let home = dir.path();
        let app = home.join("Applications").join("Cursor.app");
        std::fs::create_dir_all(app.join("Contents")).expect("建目录");
        std::fs::write(
            app.join("Contents/Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleShortVersionString</key><string>0.44.11</string>
  <key>CFBundleIdentifier</key><string>com.todesktop.230313mzl4w4u92</string>
</dict></plist>"#,
        )
        .expect("写 plist");
        let spec = specs().iter().find(|s| s.channel == "cursor").unwrap();
        let status = detect_one(spec, home);
        assert!(status.installed, "{status:?}");
        assert_eq!(status.version.as_deref(), Some("0.44.11"));
        assert!(status.source.as_deref().unwrap().ends_with("Cursor.app"));
    }

    /// M31-S1 验收：dsh 必须走 **App** 探测（本机 CLI 返回 126，只有应用包能给出 0.2.1-rc.2）。
    #[test]
    fn dsh_probe_is_the_app_bundle() {
        let spec = specs().iter().find(|s| s.channel == "dsh").unwrap();
        assert_eq!(
            spec.probe,
            Probe::App {
                bundles: &["DeepSeek Harness"]
            },
            "dsh 的探测方式必须钉在应用包上（CLI 在本机不可执行）"
        );
        assert_eq!(
            spec.config_path,
            Some(".dsh/.credentials.yaml"),
            "config_path 保持（配置还在 / 程序未找到的说明要用）"
        );
        // 换探测方式后，安装命令与 URL 不变（仍是 npm 包 + 官网地址）
        assert_eq!(
            spec.installs,
            &[inst!("npm", "npm install -g @deepseek-ai/dsh")]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn dsh_app_bundle_reports_the_plist_version() {
        let dir = tempfile::tempdir().expect("临时目录");
        let home = dir.path();
        let app = home.join("Applications").join("DeepSeek Harness.app");
        std::fs::create_dir_all(app.join("Contents")).expect("建目录");
        std::fs::write(
            app.join("Contents/Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleShortVersionString</key><string>0.2.1-rc.2</string>
</dict></plist>"#,
        )
        .expect("写 plist");
        let spec = specs().iter().find(|s| s.channel == "dsh").unwrap();
        // 显式注入空的系统应用目录：不能因本机已装同名 App 而覆盖夹具 home。
        let system_applications = dir.path().join("system-applications");
        let status = detect_app_at(spec, home, &["DeepSeek Harness"], &system_applications);
        assert!(status.installed, "{status:?}");
        assert_eq!(status.version.as_deref(), Some("0.2.1-rc.2"));
        assert!(status
            .source
            .as_deref()
            .unwrap()
            .ends_with("DeepSeek Harness.app"));
    }

    /// Codex 桌面版与 CLI 共用 `~/.codex`：CLI 不在 PATH 时，必须能从
    /// `/Applications/ChatGPT.app`（或 `~/Applications/ChatGPT.app`）识别出已安装。
    #[test]
    fn codex_probe_falls_back_to_the_desktop_app() {
        let spec = specs()
            .iter()
            .find(|s| s.channel == "codex-auth-json")
            .unwrap();
        assert_eq!(
            spec.probe,
            Probe::CliOrApp {
                bins: &["codex"],
                version_args: V,
                bundles: &["ChatGPT"],
            }
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cli_or_app_detects_a_desktop_bundle_when_cli_is_absent() {
        let dir = tempfile::tempdir().expect("临时目录");
        let home = dir.path();
        let app = home.join("Applications").join("Codex Test App.app");
        std::fs::create_dir_all(app.join("Contents")).expect("建目录");
        std::fs::write(
            app.join("Contents/Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleShortVersionString</key><string>26.1007.30912</string>
</dict></plist>"#,
        )
        .expect("写 plist");
        let spec = AgentSpec {
            channel: "codex-auth-json",
            name: "Codex",
            probe: Probe::CliOrApp {
                bins: &["kr-no-such-codex-cli"],
                version_args: V,
                bundles: &["Codex Test App"],
            },
            config_path: Some(".codex/auth.json"),
            installs: &[inst!("npm", "npm i -g x")],
            install_url: "https://example.invalid",
        };
        let status = detect_one(&spec, home);
        assert!(status.installed, "{status:?}");
        assert_eq!(status.version.as_deref(), Some("26.1007.30912"));
        assert!(status
            .source
            .as_deref()
            .unwrap()
            .ends_with("Codex Test App.app"));
    }

    #[test]
    fn config_only_means_not_installed_with_detail() {
        let dir = tempfile::tempdir().expect("临时目录");
        let home = dir.path();
        std::fs::create_dir_all(home.join(".codex")).expect("建目录");
        std::fs::write(home.join(".codex/auth.json"), "{}").expect("写文件");
        // 用一条 bin 绝不可能存在的假 spec，避免命中本机真装的 codex
        let fake = AgentSpec {
            channel: "codex-auth-json",
            name: "Codex",
            probe: Probe::Cli {
                bins: &["kr-m31-no-such-bin-xyz"],
                version_args: V,
            },
            config_path: Some(".codex/auth.json"),
            installs: &[inst!("npm", "npm i -g x")],
            install_url: "https://example.invalid",
        };
        let status = detect_one(&fake, home);
        assert!(!status.installed, "只有配置 ⇒ 未安装");
        assert!(status.detail.as_deref().unwrap().contains("找到配置"));
        assert!(status.detail.as_deref().unwrap().contains("没有找到程序"));
    }

    #[test]
    fn empty_home_reports_nothing_installed_but_keeps_install_commands() {
        let dir = tempfile::tempdir().expect("临时目录");
        let home = dir.path();
        // 用假 spec（bin 不存在）而不是 specs()：本机可能真装了 codex/claude，会污染断言。
        let fake = AgentSpec {
            channel: "x",
            name: "X",
            probe: Probe::Cli {
                bins: &["kr-m31-no-such-bin-abc"],
                version_args: V,
            },
            config_path: Some(".x/conf.json"),
            installs: &[inst!("npm", "npm i -g x-agent")],
            install_url: "https://example.invalid",
        };
        let status = detect_one(&fake, home);
        assert!(!status.installed);
        assert_eq!(status.version, None);
        assert!(status.source.is_none());
        assert!(status.detail.is_none(), "既没有配置也没有程序 ⇒ 无 detail");
        assert_eq!(
            status.install_commands,
            vec![InstallCommandInfo {
                via: "npm".to_string(),
                command: "npm i -g x-agent".to_string(),
            }]
        );
        assert_eq!(
            status.install_url.as_deref(),
            Some("https://example.invalid")
        );
        // detect_agents 也应当能在空 HOME 上跑完 28 条（不 panic）
        let all = detect_agents(home);
        assert_eq!(all.len(), 28);
        assert!(all.iter().all(|s| !s.install_commands.is_empty()));
    }

    #[test]
    fn status_serializes_as_camel_case() {
        let spec = &specs()[0];
        let value =
            serde_json::to_value(detect_one(spec, Path::new("/nonexistent-kr-home"))).unwrap();
        for key in ["installCommands", "installUrl", "channel", "installed"] {
            assert!(value.get(key).is_some(), "序列化缺少 {key}：{value}");
        }
        assert!(value.get("install_commands").is_none());
    }
}
