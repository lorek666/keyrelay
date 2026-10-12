//! 登录自启：macOS LaunchAgent plist、Windows `HKCU\...\Run` 键。
//!
//! 本模块**不执行**任何外部程序（不跑 `launchctl`、不跑 `reg.exe`、不跑 `schtasks.exe`），
//! 只产出 [`EnvPlan`]：macOS 是文件补丁（走 `inject::apply` 落盘），Windows 是纯数据结构 [`RegOp`]。
//!
//! 章程 §4.2 冻结的三个函数（[`plan_enable`] / [`plan_disable`] / [`state`]）按**目标平台**分派；
//! 分派被显式化为 [`AutostartTarget`] + `*_on` 三件套，理由是：Windows 分支在 macOS 上被 `cfg!`
//! 挡在门外，而本机没有 Windows —— 显式目标让「注册表操作对象的构造与 argv 拼装」在本机也能被断言
//! （本机不可执行，只验证构造）。
//!
//! Windows 用 Run 键而不是计划任务：见 spec §12 D-1（`schtasks` 需要新的操作对象类型，超出冻结数据模型）。

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::inject::Patch;
use crate::platform_env::{
    plist, validate_app_id, validate_home, EnvPlan, RegHive, RegOp, LAUNCH_AGENTS_DIR, RUN_KEY,
};

/// 自启 plist 的文件名后缀（`<app_id>-autostart.plist`）。
pub const AUTOSTART_SUFFIX: &str = "-autostart";
/// 受管的 `Label` 键（`<app_id>-autostart`）。
const LABEL_KEY: &str = "Label";
/// 受管的命令行数组键。
const ARGUMENTS_KEY: &str = "ProgramArguments";
/// 受管的「登录时拉起」开关。
const RUN_AT_LOAD_KEY: &str = "RunAtLoad";
/// 常驻参数（`hidden=true` 时追加到 `ProgramArguments`）。
const HIDDEN_FLAG: &str = "--hidden";

/// 自启的判定结果。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AutostartState {
    Enabled,
    Disabled,
    /// 文件存在但判不出（缺 `RunAtLoad`、值不是布尔、内容不是合法 plist），
    /// 或平台无法查询（Windows 侧要读注册表）。**不得**当成 `Enabled`。
    Unknown,
}

/// 自启落点的平台形态（本步新增；`plan_enable` / `plan_disable` / `state` 按 `cfg!(target_os)` 分派）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AutostartTarget {
    /// `~/Library/LaunchAgents/<app_id>-autostart.plist`
    MacLaunchAgent,
    /// `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
    WindowsRunKey,
}

/// 当前平台的自启形态。
fn current_target() -> AutostartTarget {
    if cfg!(target_os = "windows") {
        AutostartTarget::WindowsRunKey
    } else {
        AutostartTarget::MacLaunchAgent
    }
}

/// 打开登录自启：`RunAtLoad=true`，`hidden=true` 时 `ProgramArguments` 追加 `--hidden`。
///
/// 已经是目标形态时返回**空计划**（幂等，不产生无意义的写入与备份）。
pub fn plan_enable(home: &Path, app_id: &str, exe: &Path, hidden: bool) -> Result<EnvPlan> {
    plan_enable_on(current_target(), home, app_id, exe, hidden)
}

/// 关闭登录自启。macOS：把 `RunAtLoad` 置为 `<false/>`（**不删文件**，见 spec §5.6）。
///
/// 文件不存在时返回空计划——不为了「禁用」而凭空创建 plist。
pub fn plan_disable(home: &Path, app_id: &str) -> Result<EnvPlan> {
    plan_disable_on(current_target(), home, app_id)
}

/// 判定自启状态。macOS 读 plist；Windows 返回 `Unknown`（查询注册表需要执行 `reg.exe`）。
pub fn state(home: &Path, app_id: &str) -> Result<AutostartState> {
    state_on(current_target(), home, app_id)
}

/// [`plan_enable`] 的显式平台版本（Windows 分支在本机可断言，见模块文档）。
pub fn plan_enable_on(
    target: AutostartTarget,
    home: &Path,
    app_id: &str,
    exe: &Path,
    hidden: bool,
) -> Result<EnvPlan> {
    validate_home(home)?;
    validate_app_id(app_id)?;
    validate_exe(exe)?;

    match target {
        AutostartTarget::WindowsRunKey => Ok(EnvPlan::Registry(vec![RegOp {
            hive: RegHive::CurrentUser,
            key: RUN_KEY.to_string(),
            name: app_id.to_string(),
            value: Some(run_key_value(exe, hidden)),
        }])),
        AutostartTarget::MacLaunchAgent => {
            let path = autostart_plist_path(home, app_id);
            let before = plist::read_text_or_empty(&path)?;
            let after = if before.trim().is_empty() {
                render_fresh_plist(app_id, exe, hidden)
            } else {
                let mut text = before.clone();
                text = plist::set_entry(
                    &text,
                    &path,
                    LABEL_KEY,
                    &format!(
                        "<string>{}</string>",
                        plist::escape_text(&label_for(app_id))
                    ),
                )?;
                text = set_program_arguments(&text, &path, exe, hidden)?;
                text = plist::set_entry(&text, &path, RUN_AT_LOAD_KEY, "<true/>")?;
                text
            };
            Ok(files_plan(path, before, after))
        }
    }
}

/// [`plan_disable`] 的显式平台版本。
pub fn plan_disable_on(target: AutostartTarget, home: &Path, app_id: &str) -> Result<EnvPlan> {
    validate_home(home)?;
    validate_app_id(app_id)?;

    match target {
        AutostartTarget::WindowsRunKey => Ok(EnvPlan::Registry(vec![RegOp {
            hive: RegHive::CurrentUser,
            key: RUN_KEY.to_string(),
            name: app_id.to_string(),
            value: None,
        }])),
        AutostartTarget::MacLaunchAgent => {
            let path = autostart_plist_path(home, app_id);
            let before = plist::read_text_or_empty(&path)?;
            if before.trim().is_empty() {
                return Ok(EnvPlan::Files(Vec::new()));
            }
            let after = plist::set_entry(&before, &path, RUN_AT_LOAD_KEY, "<false/>")?;
            Ok(files_plan(path, before, after))
        }
    }
}

/// [`state`] 的显式平台版本。
pub fn state_on(target: AutostartTarget, home: &Path, app_id: &str) -> Result<AutostartState> {
    validate_home(home)?;
    validate_app_id(app_id)?;

    match target {
        AutostartTarget::WindowsRunKey => Ok(AutostartState::Unknown),
        AutostartTarget::MacLaunchAgent => {
            let path = autostart_plist_path(home, app_id);
            match std::fs::read(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(AutostartState::Disabled),
                Err(e) => Err(Error::inject(&path, format!("读取失败: {e}"))),
                Ok(bytes) => match String::from_utf8(bytes) {
                    // 不是合法 UTF-8 → 判不出来，保守报 Unknown（不是 Err：文件确实在那儿）
                    Err(_) => Ok(AutostartState::Unknown),
                    Ok(text) => Ok(run_at_load_state(&text, &path)),
                },
            }
        }
    }
}

// =================================================================== 内部实现

/// 自启 plist 的绝对路径：`<home>/Library/LaunchAgents/<app_id>-autostart.plist`。
fn autostart_plist_path(home: &Path, app_id: &str) -> PathBuf {
    home.join(LAUNCH_AGENTS_DIR)
        .join(format!("{app_id}{AUTOSTART_SUFFIX}.plist"))
}

fn label_for(app_id: &str) -> String {
    format!("{app_id}{AUTOSTART_SUFFIX}")
}

fn files_plan(path: PathBuf, before: String, after: String) -> EnvPlan {
    if before == after {
        EnvPlan::Files(Vec::new())
    } else {
        // 自启 plist 里没有密钥 → 普通补丁（新建 0644）
        EnvPlan::Files(vec![Patch::new(path, before, after)])
    }
}

/// `exe` 必须绝对路径且不含 `"`（Windows 路径里 `"` 是保留字符；带引号会破坏 Run 键的值）。
///
/// 注意：`Path::is_absolute()` 是**宿主**语义——本机（macOS）只能验证 POSIX 形态，
/// Windows 的 `C:\...` 形态未验证（spec §13）。
fn validate_exe(exe: &Path) -> Result<()> {
    if exe.as_os_str().is_empty() {
        return Err(Error::Store("exe 为空：无法生成自启项".to_string()));
    }
    if !exe.is_absolute() {
        return Err(Error::Store(format!(
            "exe 必须是绝对路径，收到的是「{}」：登录自启没有工作目录概念，相对路径必然失败",
            exe.display()
        )));
    }
    if exe.to_string_lossy().contains('"') {
        return Err(Error::Store(format!(
            "exe 不能包含双引号（收到的是「{}」）：Windows 路径不允许 `\"`，且它会让 Run 键的值提前闭合",
            exe.display()
        )));
    }
    Ok(())
}

/// Windows Run 键的值：可执行文件路径一律加引号（`CreateProcess` 的解析规则），
/// `hidden=true` 时追加 `--hidden`。
fn run_key_value(exe: &Path, hidden: bool) -> String {
    let quoted = format!("\"{}\"", exe.to_string_lossy());
    if hidden {
        format!("{quoted} {HIDDEN_FLAG}")
    } else {
        quoted
    }
}

/// 按既有缩进渲染 `ProgramArguments`（替换已有值或新建时都要与文件里的缩进一致）。
fn render_program_arguments(indent: &str, exe: &Path, hidden: bool) -> String {
    let item_indent = format!("{indent}\t");
    let mut out = String::from("<array>");
    out.push_str(&format!(
        "\n{item_indent}<string>{}</string>",
        plist::escape_text(&exe.to_string_lossy())
    ));
    if hidden {
        out.push_str(&format!("\n{item_indent}<string>{HIDDEN_FLAG}</string>"));
    }
    out.push_str(&format!("\n{indent}</array>"));
    out
}

fn set_program_arguments(text: &str, path: &Path, exe: &Path, hidden: bool) -> Result<String> {
    let top = plist::top_dict_inner(text, path)?;
    let entries = plist::parse_entries(text, top, path)?;
    let indent = match plist::find_entry(&entries, ARGUMENTS_KEY) {
        Some(entry) => plist::value_indent(text, entry.value_span),
        None => format!("{}\t", plist::close_indent(text, top)),
    };
    let xml = render_program_arguments(&indent, exe, hidden);
    plist::set_entry(text, path, ARGUMENTS_KEY, &xml)
}

fn render_fresh_plist(app_id: &str, exe: &Path, hidden: bool) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
    );
    out.push_str("<plist version=\"1.0\">\n<dict>\n");
    out.push_str(&format!(
        "\t<key>{LABEL_KEY}</key>\n\t<string>{}</string>\n",
        plist::escape_text(&label_for(app_id))
    ));
    // 注意 `render_program_arguments` 返回的 `<array>` **不带**行首缩进：
    // 它同时被 `set_entry` 用作「替换已有值」的片段（那里缩进由原文保留），
    // 所以新建路径要自己补一层。
    out.push_str(&format!(
        "\t<key>{ARGUMENTS_KEY}</key>\n\t{}\n",
        render_program_arguments("\t", exe, hidden)
    ));
    out.push_str(&format!("\t<key>{RUN_AT_LOAD_KEY}</key>\n\t<true/>\n"));
    out.push_str("</dict>\n</plist>\n");
    out
}

/// 严格布尔：`<true/>` / `<false/>`（含成对写法）才有确定语义；
/// 缺键、重复键、非布尔值、解析失败 → `Unknown`（保守：绝不把「判不出来」说成启用）。
fn run_at_load_state(text: &str, path: &Path) -> AutostartState {
    let Ok(inner) = plist::top_dict_inner(text, path) else {
        return AutostartState::Unknown;
    };
    let Ok(entries) = plist::parse_entries(text, inner, path) else {
        return AutostartState::Unknown;
    };
    match plist::find_entry_unique(&entries, RUN_AT_LOAD_KEY, path) {
        Ok(Some(entry)) => match entry.value_kind {
            plist::ValueKind::Bool(true) => AutostartState::Enabled,
            plist::ValueKind::Bool(false) => AutostartState::Disabled,
            _ => AutostartState::Unknown,
        },
        // 缺键 / 重复键（重复键的取舍由解析器决定，判不出来）/ 解析失败
        Ok(None) | Err(_) => AutostartState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe() -> &'static Path {
        Path::new("/tmp/autostart-probe.plist")
    }

    #[test]
    fn run_at_load_state_is_strict() {
        let cases = [
            (
                "<dict><key>RunAtLoad</key><true/></dict>",
                AutostartState::Enabled,
            ),
            (
                "<dict><key>RunAtLoad</key><true></true></dict>",
                AutostartState::Enabled,
            ),
            (
                "<dict><key>RunAtLoad</key><false/></dict>",
                AutostartState::Disabled,
            ),
            (
                "<dict><key>Label</key><string>x</string></dict>",
                AutostartState::Unknown,
            ),
            (
                "<dict><key>RunAtLoad</key><string>true</string></dict>",
                AutostartState::Unknown,
            ),
            (
                "<dict><key>RunAtLoad</key><integer>1</integer></dict>",
                AutostartState::Unknown,
            ),
            ("这不是 plist", AutostartState::Unknown),
            // 嵌套 dict 里的 RunAtLoad 不算顶层键
            (
                "<dict><key>Other</key><dict><key>RunAtLoad</key><true/></dict></dict>",
                AutostartState::Unknown,
            ),
        ];
        for (text, expected) in cases {
            assert_eq!(run_at_load_state(text, probe()), expected, "{text}");
        }
    }

    #[test]
    fn run_key_value_quotes_the_executable() {
        assert_eq!(
            run_key_value(Path::new(r"C:\Program Files\KeyRelay\keyrelay.exe"), true),
            "\"C:\\Program Files\\KeyRelay\\keyrelay.exe\" --hidden"
        );
        assert_eq!(
            run_key_value(Path::new(r"C:\KeyRelay\keyrelay.exe"), false),
            "\"C:\\KeyRelay\\keyrelay.exe\""
        );
    }
}
