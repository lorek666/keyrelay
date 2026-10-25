//! Agent 重启（投递改进 P1-5）：优雅退出 → 轮询 → 强制杀兜底 → 拉起 → 等进程出现。
//!
//! 流程（抄 AiMaMi `restart_codex` + LoongPort tier 切换的机制，只做本项定下的两批）：
//!
//! 1. 优雅退出：macOS 按 bundle id 发 AppleScript 退出请求（`osascript`），
//!    Windows 用 `taskkill`（不带 `/F`），Linux 用 `pkill -TERM`。
//! 2. 每 50ms 轮询进程是否消失（[`POLL_INTERVAL`]），直到 [`QUIT_TIMEOUT`]。
//! 3. 超时仍在跑 ⇒ 强制杀兜底（macOS/Linux `pkill -KILL`，Windows `taskkill /F`），
//!    再轮询至 [`FORCE_TIMEOUT`]；**仍在跑就报错且绝不拉起**——不能在旧进程还活着时
//!    再起一个新进程，否则新旧进程抢同一份配置，结果不可归因。
//! 4. 确认旧进程已消失（或本来就没在跑）才拉起：macOS `open -b <bundle>`，
//!    Windows `cmd /C start`，Linux 按名从 PATH 执行。**拉起本身不写配置、不注入
//!    环境变量、不传任何 CLI 参数**——它只负责「把应用叫起来」，配置早已由投递写好。
//! 5. 拉起后轮询进程出现，直到 [`APPEAR_TIMEOUT`]；超时 ⇒ 报错，**不再重试拉起**
//!    （一个迟到的旧进程可能随后出现，重拉一个会造成双实例）。
//!
//! 第一批只做两类目标（[`RestartTarget`]）：Codex 与 Claude Desktop，都是「完全退出重开」。
//! 其余 CLI 类 agent 不走本命令拉终端进程——前端只给可复制的启动命令，由用户自己在终端跑
//! （[`RestartSpec::manual_launch_command`]；Codex 为 `codex`，Claude Desktop 没有 CLI 命令）。
//!
//! 写前停 Codex（[`stop_for_write`]）：投递写盘路径在写 Codex 配置前调它——先停、再探查，
//! 探查到仍在写的进程就拒绝写入，绝不在疑似写入进行时写盘。注意它**只停、不拉起**，
//! 拉起永远是用户在前端点了重启按钮之后的事。探查是 fail-closed 的：探查工具本身失败
//! （读不到进程表）也按「仍在跑」处理，宁可拒绝一次写入，也不赌。
//!
//! app-server daemon 是**独立验证项**，不是本命令的返回值里能打勾的一项：外部资料称
//! CLI 0.157 起共享 app-server 在内存里留旧配置，只杀窗口可能不生效。本模块的每次结果
//! 都带一个状态恒为 `unverified` 的 [`AppServerDaemonCheck`]，前端必须把它渲染成「未验证」
//! 的清单项，不得渲染成已通过。VM 上没有真机应用可测，daemon 是否重载新配置只能由用户
//! 在真机上另行确认（例如新开一次会话确认配置已生效）。
//!
//! 身份常量未经真机核实（VM 上没有 macOS/Windows 应用可测）：Codex 的 bundle id 与桌面
//! 进程名按 LoongPort「重开 ChatGPT 桌面应用」的口径取，Claude Desktop 的 bundle id 按其
//! 桌面应用取。它们集中在 [`spec`] 一个函数里，真机验收时若实测不符，只改这里；且流程是
//! fail-closed 的——bundle 退出请求失败时轮询 + 强制杀仍会走，拉起失败时返回明确错误，
//! 绝不会把「没拉起来」报成成功。

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::error::{Error, Result};

/// 轮询间隔：任务书定死 50ms，退出轮询与出现轮询共用。
pub const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// 优雅退出后等进程消失的预算。
pub const QUIT_TIMEOUT: Duration = Duration::from_secs(10);
/// 强制杀后等进程消失的预算。
pub const FORCE_TIMEOUT: Duration = Duration::from_secs(5);
/// 拉起后等进程出现的预算。
pub const APPEAR_TIMEOUT: Duration = Duration::from_secs(10);

/// 本项支持的重启目标：只有这两项。新增目标必须先过「桌面应用还是 CLI」的判定——
/// CLI 类一律不进这里（前端只给可复制命令），不得顺手把一个 CLI 目标塞进来拉终端进程。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartTarget {
    Codex,
    ClaudeDesktop,
}

impl RestartTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            RestartTarget::Codex => "codex",
            RestartTarget::ClaudeDesktop => "claude-desktop",
        }
    }

    pub fn parse(raw: &str) -> Result<RestartTarget> {
        match raw {
            "codex" => Ok(RestartTarget::Codex),
            "claude-desktop" => Ok(RestartTarget::ClaudeDesktop),
            other => Err(Error::Store(format!(
                "不支持一键重启的目标「{other}」：本项只支持 codex 与 claude-desktop，\
                 其余 CLI 类 agent 请用前端给出的可复制启动命令自行重开"
            ))),
        }
    }
}

/// 平台分派。生产取 [`RestartPlatform::current`]；argv 构造类函数显式收平台参数，
/// 这样 macOS/Windows 分支在 Linux 上也能单测（与 notify/system.rs 同款做法）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartPlatform {
    MacOs,
    Windows,
    Linux,
}

impl RestartPlatform {
    pub fn current() -> RestartPlatform {
        if cfg!(target_os = "macos") {
            RestartPlatform::MacOs
        } else if cfg!(windows) {
            RestartPlatform::Windows
        } else {
            // 非 macOS/Windows 一律走 Linux 形态（pkill / PATH 拉起）：其它 Unix 上
            // pkill 缺失时 spawn 失败会以明确错误返回，不会静默当成成功。
            RestartPlatform::Linux
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RestartPlatform::MacOs => "macos",
            RestartPlatform::Windows => "windows",
            RestartPlatform::Linux => "linux",
        }
    }
}

/// 一个重启目标的全部平台身份。字段集中在这里，真机核实后只改 [`spec`]。
pub struct RestartSpec {
    pub target: RestartTarget,
    /// macOS 退出请求与拉起用的 bundle id（见模块文档：未经真机核实）。
    pub bundle_id: Option<&'static str>,
    /// macOS 进程名（`pkill -x` / 出现轮询用）。
    pub mac_process: &'static str,
    /// Windows 映像名（`taskkill /IM` / `tasklist` 用，含 `.exe`）。
    pub windows_image: &'static str,
    /// Linux 进程名（`pkill -x` / `/proc` 扫描用）。
    pub linux_process: &'static str,
    /// CLI 类会话的可复制启动命令：桌面重启管不到终端里的会话时，前端展示它让用户
    /// 自己重开。桌面应用本身没有 CLI 命令时为 `None`。
    pub manual_launch_command: Option<&'static str>,
    /// 写前停进程时除桌面进程外还要停的写进程名（Codex 的 CLI 进程 `codex` 也可能
    /// 在写 `~/.codex/*`；只停桌面应用会漏掉它）。重启流程本身不碰这些进程——
    /// 重启只管桌面应用，CLI 会话由用户按可复制命令重开。
    pub writer_extra_processes: &'static [&'static str],
}

/// 目标 → 身份表。唯一事实来源；调用方不得在别处硬编码 bundle id 或进程名。
pub fn spec(target: RestartTarget) -> RestartSpec {
    match target {
        RestartTarget::Codex => RestartSpec {
            target,
            // ChatGPT 桌面应用（LoongPort 口径：tier 切换时重开的是 ChatGPT 桌面应用）。
            // 若 Codex 独立桌面包的 bundle id 与此不同，真机验收时以实测为准改这里。
            bundle_id: Some("com.openai.chat"),
            mac_process: "ChatGPT",
            windows_image: "ChatGPT.exe",
            linux_process: "chatgpt",
            manual_launch_command: Some("codex"),
            writer_extra_processes: &["codex"],
        },
        RestartTarget::ClaudeDesktop => RestartSpec {
            target,
            bundle_id: Some("com.anthropic.claudefordesktop"),
            mac_process: "Claude",
            windows_image: "Claude.exe",
            linux_process: "claude",
            manual_launch_command: None,
            writer_extra_processes: &[],
        },
    }
}

/// 重启流程要探查的进程名（只含桌面进程，不含 CLI 写进程）。
pub fn restart_process_names(platform: RestartPlatform, spec: &RestartSpec) -> Vec<String> {
    vec![desktop_process_name(platform, spec).to_string()]
}

/// 写前停进程时要探查的进程名（桌面进程 + 可能写配置的 CLI 进程）。
pub fn writer_process_names(platform: RestartPlatform, spec: &RestartSpec) -> Vec<String> {
    let mut names = restart_process_names(platform, spec);
    for extra in spec.writer_extra_processes {
        names.push(extra.to_string());
    }
    names
}

fn desktop_process_name(platform: RestartPlatform, spec: &RestartSpec) -> &str {
    match platform {
        RestartPlatform::MacOs => spec.mac_process,
        RestartPlatform::Windows => spec.windows_image,
        RestartPlatform::Linux => spec.linux_process,
    }
}

/// 优雅退出命令（argv，不经 shell）。macOS 按 bundle id 请求退出；其余平台按进程名
/// 发「请退出」信号（Windows 不带 `/F`，Linux 发 TERM 而非 KILL）。
pub fn quit_commands(platform: RestartPlatform, spec: &RestartSpec) -> Vec<(String, Vec<String>)> {
    match platform {
        RestartPlatform::MacOs => {
            let bundle = spec.bundle_id.unwrap_or("");
            vec![(
                "osascript".to_string(),
                vec![
                    "-e".to_string(),
                    format!("tell application id \"{bundle}\" to quit"),
                ],
            )]
        }
        RestartPlatform::Windows => vec![(
            "taskkill".to_string(),
            vec!["/IM".to_string(), spec.windows_image.to_string()],
        )],
        RestartPlatform::Linux => vec![(
            "pkill".to_string(),
            vec![
                "-TERM".to_string(),
                "-x".to_string(),
                spec.linux_process.to_string(),
            ],
        )],
    }
}

/// 强制杀命令（argv，不经 shell）。只在优雅退出超时后走，不是一上来就用。
pub fn force_kill_commands(
    platform: RestartPlatform,
    spec: &RestartSpec,
) -> Vec<(String, Vec<String>)> {
    match platform {
        RestartPlatform::MacOs => vec![(
            "pkill".to_string(),
            vec![
                "-KILL".to_string(),
                "-x".to_string(),
                spec.mac_process.to_string(),
            ],
        )],
        RestartPlatform::Windows => vec![(
            "taskkill".to_string(),
            vec![
                "/F".to_string(),
                "/IM".to_string(),
                spec.windows_image.to_string(),
            ],
        )],
        RestartPlatform::Linux => vec![(
            "pkill".to_string(),
            vec![
                "-KILL".to_string(),
                "-x".to_string(),
                spec.linux_process.to_string(),
            ],
        )],
    }
}

/// 写前停进程的全部退出命令：桌面优雅退出 + 每个 CLI 写进程的 TERM。
/// macOS 的 CLI 写进程没有 bundle id，走 `pkill -x`；Windows 走 `taskkill`（不带 `/F`）。
fn writer_quit_commands(
    platform: RestartPlatform,
    spec: &RestartSpec,
) -> Vec<(String, Vec<String>)> {
    let mut cmds = quit_commands(platform, spec);
    for extra in spec.writer_extra_processes {
        match platform {
            RestartPlatform::MacOs | RestartPlatform::Linux => cmds.push((
                "pkill".to_string(),
                vec!["-TERM".to_string(), "-x".to_string(), extra.to_string()],
            )),
            RestartPlatform::Windows => cmds.push((
                "taskkill".to_string(),
                vec!["/IM".to_string(), format!("{extra}.exe")],
            )),
        }
    }
    cmds
}

/// 写前停进程的全部强制杀命令：桌面强制杀 + 每个 CLI 写进程的强制杀。
fn writer_force_kill_commands(
    platform: RestartPlatform,
    spec: &RestartSpec,
) -> Vec<(String, Vec<String>)> {
    let mut cmds = force_kill_commands(platform, spec);
    for extra in spec.writer_extra_processes {
        match platform {
            RestartPlatform::MacOs | RestartPlatform::Linux => cmds.push((
                "pkill".to_string(),
                vec!["-KILL".to_string(), "-x".to_string(), extra.to_string()],
            )),
            RestartPlatform::Windows => cmds.push((
                "taskkill".to_string(),
                vec!["/F".to_string(), "/IM".to_string(), format!("{extra}.exe")],
            )),
        }
    }
    cmds
}

/// 拉起命令（argv，不经 shell；不写配置、不注入环境变量、不传 CLI 参数）。
/// macOS 按 bundle id 拉起；Windows 用 `start`（首个空串是窗口标题占位，不是参数）；
/// Linux 按名从 PATH 执行。拉起失败（程序没装 / 注册表没登记）会以 spawn 错误返回，
/// 调用方必须把它报成失败，不得把「叫了拉起」当成「已拉起」。
pub fn launch_command(platform: RestartPlatform, spec: &RestartSpec) -> (String, Vec<String>) {
    match platform {
        RestartPlatform::MacOs => (
            "open".to_string(),
            vec!["-b".to_string(), spec.bundle_id.unwrap_or("").to_string()],
        ),
        RestartPlatform::Windows => (
            "cmd".to_string(),
            vec![
                "/C".to_string(),
                "start".to_string(),
                String::new(),
                spec.windows_image.to_string(),
            ],
        ),
        RestartPlatform::Linux => (spec.linux_process.to_string(), Vec::new()),
    }
}

/// app-server daemon 独立验证项。状态恒为 `unverified`：本模块没有任何办法在 VM 上
/// 证实 daemon 重载了新配置，所以绝不产出已通过的状态；前端也必须原样渲染成「未验证」。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppServerDaemonCheck {
    pub status: &'static str,
    pub note: String,
}

pub fn daemon_check() -> AppServerDaemonCheck {
    AppServerDaemonCheck {
        status: "unverified",
        note: "app-server daemon 为独立验证项：外部资料称 CLI 0.157 起共享 app-server \
               在内存里留旧配置，只杀窗口可能不生效。本次重启未在真机上验证 daemon 是否 \
               已重载新配置；请在真机上另行确认（例如新开一次会话确认配置已生效），\
               不得仅凭窗口重开认定生效。"
            .to_string(),
    }
}

/// 一次重启的结果（不含任何密钥材料，可直接序列化给前端）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestartOutcome {
    pub target: RestartTarget,
    pub was_running: bool,
    /// 本次用的优雅退出方式：`"bundle"`（macOS bundle id）/ `"taskkill"` / `"pkill"` /
    /// `"none"`（本来就没在跑，没发退出请求）。
    pub quit_method: &'static str,
    pub force_killed: bool,
    pub relaunched: bool,
    pub appeared: bool,
    pub manual_launch_command: Option<String>,
    pub app_server_daemon: AppServerDaemonCheck,
}

/// 写前停进程的结果（只停、不拉起）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopForWriteOutcome {
    pub target: RestartTarget,
    pub was_running: bool,
    pub force_killed: bool,
    pub stopped: bool,
}

/// 重启预算。默认值见常量；测试可注入更小的预算加速失败路径。
#[derive(Clone, Copy, Debug)]
pub struct RestartParams {
    pub quit_timeout: Duration,
    pub force_timeout: Duration,
    pub appear_timeout: Duration,
}

impl Default for RestartParams {
    fn default() -> Self {
        RestartParams {
            quit_timeout: QUIT_TIMEOUT,
            force_timeout: FORCE_TIMEOUT,
            appear_timeout: APPEAR_TIMEOUT,
        }
    }
}

impl RestartParams {
    fn polls(timeout: Duration) -> usize {
        let interval_ms = POLL_INTERVAL.as_millis().max(1) as u64;
        ((timeout.as_millis() as u64) / interval_ms).max(1) as usize
    }
}

/// 进程是否在跑（任一名字命中即算在跑）。探查工具本身失败 ⇒ `Err`（fail-closed：
/// 调用方不得把「查不到」当成「没在跑」）。
pub fn is_running(platform: RestartPlatform, names: &[String]) -> Result<bool> {
    match platform {
        RestartPlatform::MacOs => {
            for name in names {
                let output = Command::new("pgrep")
                    .args(["-x", name])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map_err(|e| Error::Store(format!("探查进程失败（pgrep 执行失败）: {e}")))?;
                if output.success() {
                    return Ok(true);
                }
                // pgrep 退出码 1 = 无匹配，是正常结果；其它非零码说明探查本身异常。
                if let Some(code) = output.code() {
                    if code != 1 {
                        return Err(Error::Store(format!("探查进程失败（pgrep 返回 {code}）")));
                    }
                }
            }
            Ok(false)
        }
        RestartPlatform::Windows => {
            for name in names {
                let output = Command::new("tasklist")
                    .args(["/FI", &format!("IMAGENAME eq {name}"), "/FO", "CSV", "/NH"])
                    .output()
                    .map_err(|e| Error::Store(format!("探查进程失败（tasklist 执行失败）: {e}")))?;
                if parse_tasklist(&String::from_utf8_lossy(&output.stdout), name) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        RestartPlatform::Linux => {
            if linux_running(names) {
                return Ok(true);
            }
            // /proc 读不到时退到 pgrep：两个都失败才算探查失败（而不是静默当成没在跑）。
            match linux_running_via_pgrep(names) {
                Ok(found) => Ok(found),
                Err(err) => Err(err),
            }
        }
    }
}

/// Windows `tasklist /FO CSV /NH` 输出解析（纯函数，跨平台可测）。
/// 命中当且仅当某一行第一个 CSV 字段（映像名）与目标相等（大小写不敏感）；
/// `INFO: No tasks...` 这类行第一个字段不是映像名，不会误命中。
pub fn parse_tasklist(output: &str, image: &str) -> bool {
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("INFO:") {
            continue;
        }
        let first = line
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"');
        if first.eq_ignore_ascii_case(image) {
            return true;
        }
    }
    false
}

/// Linux 进程探查：扫描 `/proc/<pid>/comm`（不依赖外部二进制、不经 shell）。
/// `comm` 会被内核截断到 15 字节：本模块的进程名最长 7 字节，不受截断影响；
/// 将来若有更长的名字，必须先确认截断后的形态，否则探查会漏报。
pub fn linux_running(names: &[String]) -> bool {
    linux_running_in(Path::new("/proc"), names)
}

/// 可注入 proc 根目录的版本（测试用假 proc 目录断言扫描逻辑）。
pub fn linux_running_in(proc_root: &Path, names: &[String]) -> bool {
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) else {
            continue;
        };
        let comm = comm.trim();
        if names.iter().any(|n| n == comm) {
            return true;
        }
    }
    false
}

fn linux_running_via_pgrep(names: &[String]) -> Result<bool> {
    // 只有 /proc 完全读不到时才走到这里：此时 /proc 扫描返回 false 可能是「目录不存在」
    // 而不是「进程不存在」，必须用 pgrep 再确认一次；pgrep 也失败 ⇒ 探查失败。
    let proc_readable = std::fs::read_dir("/proc").is_ok();
    if proc_readable {
        return Ok(false);
    }
    for name in names {
        let output = Command::new("pgrep")
            .args(["-x", name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| Error::Store(format!("探查进程失败（pgrep 执行失败）: {e}")))?;
        if output.success() {
            return Ok(true);
        }
        if let Some(code) = output.code() {
            if code != 1 {
                return Err(Error::Store(format!("探查进程失败（pgrep 返回 {code}）")));
            }
        }
    }
    Ok(false)
}

/// 最佳努力执行一批命令：单个命令失败（程序没装、进程已死）不中断整批——
/// 退出请求的失败与否由随后的轮询判定，而不是由退出命令的退出码判定
/// （例如「进程在退出请求到达前刚好自己退了」时 taskkill/pkill 本来就会报找不到进程）。
fn run_all_best_effort(cmds: &[(String, Vec<String>)]) {
    for (program, args) in cmds {
        let _ = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// 等进程消失的轮询状态机（纯轮询逻辑 + 可注入探查闭包，单测不用真的起进程）。
pub enum WaitOutcome {
    Gone,
    StillRunning,
    ProbeFailed(String),
}

pub fn wait_for_gone<F>(mut probe: F, max_polls: usize) -> WaitOutcome
where
    F: FnMut() -> Result<bool>,
{
    wait_for_gone_with_interval(&mut probe, max_polls, POLL_INTERVAL)
}

fn wait_for_gone_with_interval<F>(mut probe: F, max_polls: usize, interval: Duration) -> WaitOutcome
where
    F: FnMut() -> Result<bool>,
{
    for _ in 0..max_polls {
        match probe() {
            Ok(false) => return WaitOutcome::Gone,
            Ok(true) => std::thread::sleep(interval),
            Err(err) => return WaitOutcome::ProbeFailed(err.to_string()),
        }
    }
    // 最后一轮也探一次：预算耗尽那一刻进程刚好消失，不该报成仍在跑。
    match probe() {
        Ok(false) => WaitOutcome::Gone,
        Ok(true) => WaitOutcome::StillRunning,
        Err(err) => WaitOutcome::ProbeFailed(err.to_string()),
    }
}

pub enum AppearOutcome {
    Appeared,
    NotAppeared,
    ProbeFailed(String),
}

pub fn wait_for_appear<F>(mut probe: F, max_polls: usize) -> AppearOutcome
where
    F: FnMut() -> Result<bool>,
{
    wait_for_appear_with_interval(&mut probe, max_polls, POLL_INTERVAL)
}

fn wait_for_appear_with_interval<F>(
    mut probe: F,
    max_polls: usize,
    interval: Duration,
) -> AppearOutcome
where
    F: FnMut() -> Result<bool>,
{
    for _ in 0..max_polls {
        match probe() {
            Ok(true) => return AppearOutcome::Appeared,
            Ok(false) => std::thread::sleep(interval),
            Err(err) => return AppearOutcome::ProbeFailed(err.to_string()),
        }
    }
    match probe() {
        Ok(true) => AppearOutcome::Appeared,
        Ok(false) => AppearOutcome::NotAppeared,
        Err(err) => AppearOutcome::ProbeFailed(err.to_string()),
    }
}

fn quit_method_of(platform: RestartPlatform) -> &'static str {
    match platform {
        RestartPlatform::MacOs => "bundle",
        RestartPlatform::Windows => "taskkill",
        RestartPlatform::Linux => "pkill",
    }
}

/// 完整重启：优雅退出 → 轮询 → 强制杀兜底 → 拉起 → 等出现。
/// 同步阻塞调用（轮询里 sleep）：命令层必须在 `spawn_blocking` 里调，不得占着 async 运行时。
pub fn restart(target: RestartTarget) -> Result<RestartOutcome> {
    restart_with_params(target, &RestartParams::default())
}

pub fn restart_with_params(
    target: RestartTarget,
    params: &RestartParams,
) -> Result<RestartOutcome> {
    let platform = RestartPlatform::current();
    let spec = spec(target);
    let names = restart_process_names(platform, &spec);
    let was_running = is_running(platform, &names)?;
    let mut force_killed = false;
    if was_running {
        run_all_best_effort(&quit_commands(platform, &spec));
        match wait_for_gone(
            || is_running(platform, &names),
            RestartParams::polls(params.quit_timeout),
        ) {
            WaitOutcome::Gone => {}
            WaitOutcome::StillRunning => {
                run_all_best_effort(&force_kill_commands(platform, &spec));
                force_killed = true;
                match wait_for_gone(
                    || is_running(platform, &names),
                    RestartParams::polls(params.force_timeout),
                ) {
                    WaitOutcome::Gone => {}
                    WaitOutcome::StillRunning => {
                        return Err(Error::Store(format!(
                            "重启失败：{} 强制杀后仍在运行，拒绝拉起新进程（旧进程还活着时拉起会造成双实例抢配置）",
                            spec_name(&spec)
                        )));
                    }
                    WaitOutcome::ProbeFailed(err) => {
                        return Err(Error::Store(format!(
                            "重启失败：强制杀后无法确认 {} 是否已退出（{err}），拒绝拉起新进程",
                            spec_name(&spec)
                        )));
                    }
                }
            }
            WaitOutcome::ProbeFailed(err) => {
                return Err(Error::Store(format!(
                    "重启失败：优雅退出后无法确认 {} 是否已退出（{err}），拒绝拉起新进程",
                    spec_name(&spec)
                )));
            }
        }
    }
    // 只有确认旧进程已消失（或本来就没在跑）才走到这里：拉起的前提条件。
    let (program, args) = launch_command(platform, &spec);
    Command::new(&program)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            Error::Store(format!(
                "重启失败：拉起 {} 失败（{} {}）：{e}。程序可能未安装或未在系统注册，\
                 请确认安装后再试",
                spec_name(&spec),
                program,
                args.join(" ")
            ))
        })?;
    match wait_for_appear(
        || is_running(platform, &names),
        RestartParams::polls(params.appear_timeout),
    ) {
        AppearOutcome::Appeared => Ok(RestartOutcome {
            target,
            was_running,
            quit_method: if was_running {
                quit_method_of(platform)
            } else {
                "none"
            },
            force_killed,
            relaunched: true,
            appeared: true,
            manual_launch_command: spec.manual_launch_command.map(|c| c.to_string()),
            app_server_daemon: daemon_check(),
        }),
        AppearOutcome::NotAppeared => Err(Error::Store(format!(
            "重启失败：已拉起 {}，但 {} 内未探查到进程出现，不再重试拉起（迟到的旧进程可能随后出现，重拉会造成双实例）",
            spec_name(&spec),
            format_timeout(params.appear_timeout)
        ))),
        AppearOutcome::ProbeFailed(err) => Err(Error::Store(format!(
            "重启失败：拉起 {} 后无法探查进程是否出现（{err}），不再重试拉起",
            spec_name(&spec)
        ))),
    }
}

fn spec_name(spec: &RestartSpec) -> &'static str {
    match spec.target {
        RestartTarget::Codex => "Codex",
        RestartTarget::ClaudeDesktop => "Claude Desktop",
    }
}

fn format_timeout(d: Duration) -> String {
    format!("{}s", d.as_secs())
}

/// 写前停进程：优雅退出 → 轮询 → 强制杀兜底，**不拉起**。
/// 返回 `Ok` 且 `stopped == true` 时调用方才能写盘；进程仍在跑或探查失败时返回 `Err`，
/// 调用方必须拒绝写入（不得把「停不下来」降级成「照常写」）。
pub fn stop_for_write(target: RestartTarget) -> Result<StopForWriteOutcome> {
    let platform = RestartPlatform::current();
    let spec = spec(target);
    let names = writer_process_names(platform, &spec);
    let was_running = is_running(platform, &names)?;
    if !was_running {
        return Ok(StopForWriteOutcome {
            target,
            was_running: false,
            force_killed: false,
            stopped: true,
        });
    }
    run_all_best_effort(&writer_quit_commands(platform, &spec));
    match wait_for_gone(
        || is_running(platform, &names),
        RestartParams::polls(QUIT_TIMEOUT),
    ) {
        WaitOutcome::Gone => Ok(StopForWriteOutcome {
            target,
            was_running: true,
            force_killed: false,
            stopped: true,
        }),
        WaitOutcome::StillRunning => {
            run_all_best_effort(&writer_force_kill_commands(platform, &spec));
            match wait_for_gone(
                || is_running(platform, &names),
                RestartParams::polls(FORCE_TIMEOUT),
            ) {
                WaitOutcome::Gone => Ok(StopForWriteOutcome {
                    target,
                    was_running: true,
                    force_killed: true,
                    stopped: true,
                }),
                WaitOutcome::StillRunning => Err(Error::Store(format!(
                    "拒绝写入：{} 仍在运行（已尝试优雅退出与强制杀），疑似正在写配置，\
                     此时写盘会被目标进程启动时覆盖或互相覆盖；请先手动退出 {} 后再投递",
                    spec_name(&spec),
                    spec_name(&spec)
                ))),
                WaitOutcome::ProbeFailed(err) => Err(Error::Store(format!(
                    "拒绝写入：强制杀后无法确认 {} 是否已退出（{err}），疑似仍在写配置，\
                     此时写盘不安全",
                    spec_name(&spec)
                ))),
            }
        }
        WaitOutcome::ProbeFailed(err) => Err(Error::Store(format!(
            "拒绝写入：优雅退出后无法确认 {} 是否已退出（{err}），疑似仍在写配置，\
             此时写盘不安全",
            spec_name(&spec)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codex() -> RestartSpec {
        spec(RestartTarget::Codex)
    }

    fn claude() -> RestartSpec {
        spec(RestartTarget::ClaudeDesktop)
    }

    #[test]
    fn target_parse_only_accepts_the_first_batch() {
        assert_eq!(RestartTarget::parse("codex").unwrap(), RestartTarget::Codex);
        assert_eq!(
            RestartTarget::parse("claude-desktop").unwrap(),
            RestartTarget::ClaudeDesktop
        );
        assert!(RestartTarget::parse("claude-code-settings").is_err());
        assert!(RestartTarget::parse("cline").is_err());
    }

    #[test]
    fn macos_quit_uses_bundle_id_and_launch_uses_open_with_bundle() {
        let s = codex();
        assert_eq!(
            quit_commands(RestartPlatform::MacOs, &s),
            vec![(
                "osascript".to_string(),
                vec![
                    "-e".to_string(),
                    "tell application id \"com.openai.chat\" to quit".to_string()
                ]
            )]
        );
        assert_eq!(
            launch_command(RestartPlatform::MacOs, &s),
            (
                "open".to_string(),
                vec!["-b".to_string(), "com.openai.chat".to_string()]
            )
        );
        // 拉起不带任何 CLI 参数：argv 除 bundle 外只有 -b。
        let (program, args) = launch_command(RestartPlatform::MacOs, &claude());
        assert_eq!(program, "open");
        assert_eq!(
            args,
            vec![
                "-b".to_string(),
                "com.anthropic.claudefordesktop".to_string()
            ]
        );
    }

    #[test]
    fn windows_quit_is_graceful_and_force_kill_uses_force_flag() {
        let s = claude();
        assert_eq!(
            quit_commands(RestartPlatform::Windows, &s),
            vec![(
                "taskkill".to_string(),
                vec!["/IM".to_string(), "Claude.exe".to_string()]
            )]
        );
        assert_eq!(
            force_kill_commands(RestartPlatform::Windows, &s),
            vec![(
                "taskkill".to_string(),
                vec![
                    "/F".to_string(),
                    "/IM".to_string(),
                    "Claude.exe".to_string()
                ]
            )]
        );
    }

    #[test]
    fn linux_quit_sends_term_and_force_kill_sends_kill() {
        let s = codex();
        assert_eq!(
            quit_commands(RestartPlatform::Linux, &s),
            vec![(
                "pkill".to_string(),
                vec!["-TERM".to_string(), "-x".to_string(), "chatgpt".to_string()]
            )]
        );
        assert_eq!(
            force_kill_commands(RestartPlatform::Linux, &s),
            vec![(
                "pkill".to_string(),
                vec!["-KILL".to_string(), "-x".to_string(), "chatgpt".to_string()]
            )]
        );
        // Linux 拉起按名执行、无参数。
        assert_eq!(
            launch_command(RestartPlatform::Linux, &s),
            ("chatgpt".to_string(), Vec::<String>::new())
        );
    }

    #[test]
    fn codex_writer_set_includes_the_cli_process_and_claude_has_none_extra() {
        let platform = RestartPlatform::Linux;
        assert_eq!(
            writer_process_names(platform, &codex()),
            vec!["chatgpt".to_string(), "codex".to_string()]
        );
        assert_eq!(
            writer_process_names(platform, &claude()),
            vec!["claude".to_string()]
        );
        // 重启流程本身只管桌面进程：CLI 会话不由重启拉起。
        assert_eq!(
            restart_process_names(platform, &codex()),
            vec!["chatgpt".to_string()]
        );
    }

    #[test]
    fn codex_carries_a_copyable_cli_command_and_claude_carries_none() {
        assert_eq!(codex().manual_launch_command, Some("codex"));
        assert_eq!(claude().manual_launch_command, None);
    }

    #[test]
    fn daemon_check_is_always_unverified() {
        let check = daemon_check();
        assert_eq!(check.status, "unverified");
        assert!(
            check.note.contains("独立验证项"),
            "daemon 说明必须点明它是独立验证项：{}",
            check.note
        );
        assert!(
            check.note.contains("只杀窗口可能不生效"),
            "daemon 说明必须点明只杀窗口可能不生效：{}",
            check.note
        );
    }

    #[test]
    fn tasklist_parse_matches_image_field_only() {
        let output = "\"Claude.exe\",\"1234\",\"Console\",\"1\",\"10,000 K\"\r\n";
        assert!(parse_tasklist(output, "Claude.exe"));
        assert!(parse_tasklist(output, "claude.exe"));
        assert!(!parse_tasklist(output, "ChatGPT.exe"));
        assert!(!parse_tasklist(
            "INFO: No tasks are running which match the specified criteria.\r\n",
            "Claude.exe"
        ));
        assert!(!parse_tasklist("", "Claude.exe"));
    }

    #[test]
    fn linux_proc_scan_matches_comm_exactly() {
        let dir =
            std::env::temp_dir().join(format!("tianshu-relay-restart-proc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("123")).unwrap();
        std::fs::write(dir.join("123").join("comm"), "codex\n").unwrap();
        std::fs::create_dir_all(dir.join("456")).unwrap();
        std::fs::write(dir.join("456").join("comm"), "other\n").unwrap();
        std::fs::create_dir_all(dir.join("selftest")).unwrap();
        assert!(linux_running_in(&dir, &["codex".to_string()]));
        assert!(!linux_running_in(&dir, &["chatgpt".to_string()]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wait_for_gone_returns_gone_as_soon_as_probe_says_so() {
        let mut calls = 0;
        let outcome = wait_for_gone_with_interval(
            || {
                calls += 1;
                // 探查返回「是否仍在跑」：前两次在跑，第三次已消失。
                Ok(calls < 3)
            },
            10,
            Duration::from_millis(1),
        );
        assert!(matches!(outcome, WaitOutcome::Gone));
        assert_eq!(calls, 3);
    }

    #[test]
    fn wait_for_gone_reports_still_running_after_budget() {
        let outcome = wait_for_gone_with_interval(|| Ok(true), 3, Duration::from_millis(1));
        assert!(matches!(outcome, WaitOutcome::StillRunning));
    }

    #[test]
    fn wait_for_gone_reports_probe_failure_without_sleeping_forever() {
        let outcome = wait_for_gone_with_interval(
            || Err::<bool, Error>(Error::Store("探查失败".to_string())),
            10,
            Duration::from_millis(1),
        );
        assert!(matches!(outcome, WaitOutcome::ProbeFailed(_)));
    }

    #[test]
    fn wait_for_appear_reports_not_appeared_after_budget() {
        let outcome = wait_for_appear_with_interval(|| Ok(false), 3, Duration::from_millis(1));
        assert!(matches!(outcome, AppearOutcome::NotAppeared));
    }

    #[test]
    fn poll_params_derive_poll_counts_from_timeouts() {
        assert_eq!(RestartParams::polls(Duration::from_millis(50)), 1);
        assert_eq!(RestartParams::polls(Duration::from_secs(10)), 200);
    }
}
