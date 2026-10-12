//! 平台环境变量落点：macOS LaunchAgent 的 `EnvironmentVariables` 段、Windows `HKCU\Environment`。
//!
//! 设计约束（章程 §4.2）：
//! - `plan_set` / `plan_unset` 是**纯函数**：只读 `home` 参数下的目标文件（`Patch::before` 必须来自磁盘），
//!   不读时钟、不读环境变量、不读真实 HOME。
//! - `EnvPlan::describe` 只输出路径 / 长度 / 键名，**任何情况下都不得输出 env 值**（值可能是 `sk-` 密钥）。
//! - Windows 分支只产出纯数据结构 [`RegOp`] 与命令行 argv；本模块**不执行** `reg.exe`（本机不可执行）。
//!
//! 与 `delivery/shell_block.rs` 的关系：那个通道管 shell rc 的标记块，本模块管 LaunchAgent plist 的
//! 标记块与注册表值。两者同一哲学——**只动受管区，其余字节逐字保留**；用户手写内容一个字节都不碰。
//!
//! plist 是手工拼装 / 解析的（章程未批准新依赖）：`plist` 子模块是一个只覆盖本模块所需形态的
//! 最小扫描器，遇到看不懂的形态一律**拒绝改写**（`Err`），不猜、不重写整个文件。

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::inject::{self, Journal, Patch};

/// 受管块开始标记（XML 注释；plist 解析器会忽略注释）。
pub const BLOCK_BEGIN: &str = "<!-- keyrelay:managed -->";
/// 受管块结束标记。
pub const BLOCK_END: &str = "<!-- /keyrelay:managed -->";
/// 受管块内的说明行（给手工编辑的用户看）。
const BLOCK_NOTE: &str = "<!-- 由 KeyRelay 管理；手工修改会在下次写入时被覆盖 -->";

/// 环境变量 plist 里受管的顶层键。
pub(crate) const ENV_KEY: &str = "EnvironmentVariables";
/// Windows 环境变量所在的注册表键（相对 hive）。
pub(crate) const WINDOWS_ENV_KEY: &str = "Environment";
/// Windows 自启所在的注册表键（相对 hive）；`autostart` 复用。
pub const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
/// 执行注册表操作的命令行工具（S5 接线时用 `Command::new(REG_EXE).args(op.to_argv())`，**不经 shell**）。
pub const REG_EXE: &str = "reg.exe";
/// LaunchAgent 目录（相对 `home`）；`autostart` 复用。
pub(crate) const LAUNCH_AGENTS_DIR: &str = "Library/LaunchAgents";

// =================================================================== 冻结接口

/// 一条环境变量。
#[derive(Clone, PartialEq, Eq)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

/// 环境变量的落点。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EnvScope {
    /// `~/Library/LaunchAgents/<app_id>.plist` 的 `EnvironmentVariables` 段
    MacLaunchAgent,
    /// `HKCU\Environment`
    WindowsUserEnv,
}

/// 注册表根键。本波次只需要当前用户（写 `HKCU` 不需要管理员权限）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegHive {
    CurrentUser,
}

/// 一次注册表操作。`value: None` 表示删除该值。
#[derive(Clone, PartialEq, Eq)]
pub struct RegOp {
    pub hive: RegHive,
    pub key: String,
    pub name: String,
    pub value: Option<String>,
}

/// 一次落点变更的计划：文件（走 `inject`）或注册表（只产出操作对象）。
#[derive(Clone, PartialEq, Eq)]
pub enum EnvPlan {
    Files(Vec<Patch>),
    Registry(Vec<RegOp>),
}

impl EnvPlan {
    /// 人类可读摘要，**不含任何值**（值可能是密钥）→ 用于事件与 UI 预览。
    ///
    /// 只输出：目标路径、内容字节数、受管键名、注册表键名与动作。
    pub fn describe(&self) -> String {
        match self {
            EnvPlan::Files(patches) if patches.is_empty() => "文件计划：无需改动".to_string(),
            EnvPlan::Files(patches) => {
                let mut out = format!("文件计划：{} 个文件", patches.len());
                for patch in patches {
                    out.push_str(&format!(
                        "\n- {}（{} → {} 字节",
                        patch.path.display(),
                        patch.before.len(),
                        patch.after.len()
                    ));
                    let names = plist::managed_names(&patch.after);
                    if !names.is_empty() {
                        out.push_str(&format!("；受管键：{}", names.join("、")));
                    }
                    out.push('）');
                }
                out
            }
            EnvPlan::Registry(ops) if ops.is_empty() => "注册表计划：无需改动".to_string(),
            EnvPlan::Registry(ops) => {
                let mut out = format!("注册表计划：{} 项", ops.len());
                for op in ops {
                    let action = if op.value.is_some() {
                        "设置"
                    } else {
                        "删除"
                    };
                    out.push_str(&format!("\n- {}：{} {}", op.full_key(), action, op.name));
                }
                out
            }
        }
    }

    /// 只对 `Files` 生效：走 `inject::apply` 落盘（原子写 + 备份 + 回读校验 + 记账）。
    ///
    /// `Registry` 与「空 `Files`」返回 `Ok(None)`——没有可落盘的内容，不建备份目录。
    pub fn apply_files(&self, backup_dir: &Path) -> Result<Option<Journal>> {
        match self {
            EnvPlan::Files(patches) if patches.is_empty() => Ok(None),
            EnvPlan::Files(patches) => inject::apply(patches, backup_dir).map(Some),
            EnvPlan::Registry(_) => Ok(None),
        }
    }
}

/// 手写 `Debug`：**绝不打印 env 值**（值可能是 `sk-` 密钥）。
/// 与 `Patch`（B-12）/ `Binding` 的先例一致——任何 `{:?}` 都不得把密钥写进日志。
impl std::fmt::Debug for EnvVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvVar")
            .field("name", &self.name)
            .field("value", &"<已脱敏>")
            .field("value_len", &self.value.len())
            .finish()
    }
}

/// 手写 `Debug`：只打印值的**有无**，不打印内容。
impl std::fmt::Debug for RegOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegOp")
            .field("hive", &self.hive)
            .field("key", &self.key)
            .field("name", &self.name)
            .field("value", &self.value.as_ref().map(|_| "<已脱敏>"))
            .finish()
    }
}

/// 手写 `Debug`：`Files` 只打印路径，`Registry` 走 [`RegOp`] 的脱敏 `Debug`。
impl std::fmt::Debug for EnvPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvPlan::Files(patches) => f
                .debug_struct("EnvPlan::Files")
                .field(
                    "paths",
                    &patches
                        .iter()
                        .map(|p| p.path.display().to_string())
                        .collect::<Vec<_>>(),
                )
                .field(
                    "after_lens",
                    &patches.iter().map(|p| p.after.len()).collect::<Vec<_>>(),
                )
                .finish(),
            EnvPlan::Registry(ops) => f
                .debug_struct("EnvPlan::Registry")
                .field("ops", ops)
                .finish(),
        }
    }
}

/// 生成/更新落点计划。
///
/// macOS：写 `<home>/Library/LaunchAgents/<app_id>.plist` 的受管块（保留非受管键）。
/// Windows：产出 `HKCU\Environment` 的写值操作（每个变量一条）。
///
/// **受管集合 == `vars`**：上一次写入的、本次不在 `vars` 里的受管键会被移除（幂等，见 spec §12 D-5）。
pub fn plan_set(scope: EnvScope, home: &Path, app_id: &str, vars: &[EnvVar]) -> Result<EnvPlan> {
    validate_home(home)?;
    validate_app_id(app_id)?;
    validate_vars(vars)?;

    match scope {
        EnvScope::MacLaunchAgent => {
            let path = env_plist_path(home, app_id);
            let before = plist::read_text_or_empty(&path)?;
            let after = upsert_env_block(&before, &path, app_id, vars)?;
            // 内容没变 → 空计划（幂等；不产生无意义的写入、备份与 journal 条目）
            Ok(files_plan(path, before, after))
        }
        EnvScope::WindowsUserEnv => Ok(EnvPlan::Registry(
            vars.iter()
                .map(|var| RegOp {
                    hive: RegHive::CurrentUser,
                    key: WINDOWS_ENV_KEY.to_string(),
                    name: var.name.clone(),
                    value: Some(var.value.clone()),
                })
                .collect(),
        )),
    }
}

/// 卸载**全部**受管键。
///
/// macOS：删除受管块（文件保留，非受管键一个字节都不动）。
/// Windows：返回 `Err`——注册表无法在不执行 `reg.exe` 的前提下枚举键名（spec §14 O-1），
/// 请改用 [`plan_unset_named`]。
pub fn plan_unset(scope: EnvScope, home: &Path, app_id: &str) -> Result<EnvPlan> {
    validate_home(home)?;
    validate_app_id(app_id)?;

    match scope {
        EnvScope::MacLaunchAgent => {
            let path = env_plist_path(home, app_id);
            let before = plist::read_text_or_empty(&path)?;
            let after = rewrite_env_block(&before, &path, None)?;
            Ok(files_plan(path, before, after))
        }
        EnvScope::WindowsUserEnv => Err(Error::Store(
            "Windows 上卸载环境变量需要键名清单：注册表无法在不执行 reg.exe 的前提下枚举值名，\
             本模块也不执行外部程序。请改用 plan_unset_named(scope, home, app_id, names)"
                .to_string(),
        )),
    }
}

/// 卸载 `names` 里指定的受管键（本步新增，见 spec §4.2 / §14 O-1）。
///
/// macOS：只删受管块里名字命中的条目；块被删空则连同标记一起删除；`names` 里不存在的名字忽略。
/// Windows：每个名字产出一条 `value: None` 的删除操作（`reg delete`）。
pub fn plan_unset_named(
    scope: EnvScope,
    home: &Path,
    app_id: &str,
    names: &[String],
) -> Result<EnvPlan> {
    validate_home(home)?;
    validate_app_id(app_id)?;

    match scope {
        EnvScope::MacLaunchAgent => {
            let path = env_plist_path(home, app_id);
            let before = plist::read_text_or_empty(&path)?;
            let after = rewrite_env_block(&before, &path, Some(names))?;
            Ok(files_plan(path, before, after))
        }
        EnvScope::WindowsUserEnv => Ok(EnvPlan::Registry(
            names
                .iter()
                .map(|name| RegOp {
                    hive: RegHive::CurrentUser,
                    key: WINDOWS_ENV_KEY.to_string(),
                    name: name.clone(),
                    value: None,
                })
                .collect(),
        )),
    }
}

/// 读出当前受管的环境变量（macOS：读受管块；Windows：`Err`，理由同 [`plan_unset`]）。
///
/// 文件不存在 / 没有 `EnvironmentVariables` 段 / 没有受管块 → `Ok(vec![])`。
pub fn read_managed(scope: EnvScope, home: &Path, app_id: &str) -> Result<Vec<EnvVar>> {
    validate_home(home)?;
    validate_app_id(app_id)?;

    match scope {
        EnvScope::MacLaunchAgent => {
            let path = env_plist_path(home, app_id);
            let text = plist::read_text_or_empty(&path)?;
            if text.trim().is_empty() {
                return Ok(Vec::new());
            }
            let Some(inner) = env_dict_inner(&text, &path)? else {
                return Ok(Vec::new());
            };
            let Some(block) = plist::find_block(&text, inner, &path)? else {
                return Ok(Vec::new());
            };
            let entries = plist::parse_entries(&text, inner, &path)?;
            let mut out = Vec::new();
            for entry in entries.iter().filter(|e| block.contains(e.entry_span)) {
                out.push(EnvVar {
                    name: entry.name.clone(),
                    value: plist::string_value(&text, entry.value_span, &path)?,
                });
            }
            Ok(out)
        }
        EnvScope::WindowsUserEnv => Err(Error::Store(
            "Windows 上读取受管环境变量需要执行 reg.exe query（本模块是纯计划层，不执行外部程序）"
                .to_string(),
        )),
    }
}

// =================================================================== 路径与校验

/// 环境变量 plist 的绝对路径：`<home>/Library/LaunchAgents/<app_id>.plist`。
pub(crate) fn env_plist_path(home: &Path, app_id: &str) -> PathBuf {
    home.join(LAUNCH_AGENTS_DIR).join(format!("{app_id}.plist"))
}

pub(crate) fn validate_home(home: &Path) -> Result<()> {
    if !home.is_absolute() {
        return Err(Error::Store(format!(
            "home 必须是绝对路径，收到的是「{}」。相对路径会随进程工作目录漂移，\
             写入落点就不可预测（与 platform.rs 的 B-14 同一口径）。",
            home.display()
        )));
    }
    Ok(())
}

/// `app_id` 会被拼进文件名，因此**必须**限制字符集：否则 `../x` 能把文件写到
/// `~/Library/LaunchAgents` 之外，甚至覆盖任意 `*.plist`。
pub(crate) fn validate_app_id(app_id: &str) -> Result<()> {
    let legal = !app_id.is_empty()
        && app_id != "."
        && app_id != ".."
        && app_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !legal {
        return Err(Error::Store(format!(
            "app_id 只允许 [A-Za-z0-9._-]（且不能是 . 或 ..），收到的是「{app_id}」。\
             它会被拼进文件名，含路径分隔符的取值会写到 LaunchAgents 目录之外。"
        )));
    }
    Ok(())
}

fn validate_vars(vars: &[EnvVar]) -> Result<()> {
    if vars.is_empty() {
        return Err(Error::Store(
            "vars 为空：没有要写入的环境变量（不静默成功，也不生成空计划）".to_string(),
        ));
    }
    for (index, var) in vars.iter().enumerate() {
        validate_env_name(&var.name)?;
        validate_env_value(&var.value, &var.name)?;
        if vars[..index].iter().any(|prev| prev.name == var.name) {
            return Err(Error::Store(format!(
                "vars 里有重复的键名「{}」：同一批次里同名会让写入顺序决定最终值，拒绝生成计划",
                var.name
            )));
        }
    }
    Ok(())
}

fn validate_env_name(name: &str) -> Result<()> {
    let legal = !name.is_empty()
        && !name
            .chars()
            .any(|c| c.is_whitespace() || c == '=' || c.is_control());
    if !legal {
        return Err(Error::Store(format!(
            "环境变量名不合法（不得为空，不得含空白 / `=` / 控制字符）：「{name}」"
        )));
    }
    Ok(())
}

/// XML 1.0 的文本节点无法表示 `\0` 等 C0 控制字符（`\t` `\n` `\r` 除外）。
/// 两个平台用**同一套**校验，避免同一份输入在两个平台上得到不同的接受/拒绝结果。
fn validate_env_value(value: &str, name: &str) -> Result<()> {
    if value
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
    {
        return Err(Error::Store(format!(
            "环境变量「{name}」的值含 XML 无法表示的控制字符（只允许制表符 / 换行 / 回车）"
        )));
    }
    Ok(())
}

/// 组装 `Files` 计划：内容没变时返回**空计划**（不产生无意义的写入与备份）。
fn files_plan(path: PathBuf, before: String, after: String) -> EnvPlan {
    if before == after {
        EnvPlan::Files(Vec::new())
    } else {
        EnvPlan::Files(vec![Patch::secret_bearing(path, before, after)])
    }
}

// =================================================================== plist 改写

/// 定位 `EnvironmentVariables` 段的 dict 内部区间；文件里没有这个键时返回 `None`。
fn env_dict_inner(text: &str, path: &Path) -> Result<Option<plist::Span>> {
    let top = plist::top_dict_inner(text, path)?;
    let entries = plist::parse_entries(text, top, path)?;
    let Some(entry) = plist::find_entry_unique(&entries, ENV_KEY, path)? else {
        return Ok(None);
    };
    if entry.value_kind != plist::ValueKind::Dict {
        return Err(Error::inject(
            path,
            format!("{ENV_KEY} 的值不是 <dict>（拒绝改写，避免把既有内容换成别的东西）"),
        ));
    }
    Ok(Some(plist::container_inner(text, entry.value_span, path)?))
}

/// 生成/更新受管块，其余字节逐字保留。
fn upsert_env_block(before: &str, path: &Path, app_id: &str, vars: &[EnvVar]) -> Result<String> {
    if before.trim().is_empty() {
        return Ok(render_fresh_env_plist(app_id, vars));
    }

    let top = plist::top_dict_inner(before, path)?;
    let top_indent = plist::close_indent(before, top);
    let entries = plist::parse_entries(before, top, path)?;

    let Some(entry) = plist::find_entry_unique(&entries, ENV_KEY, path)? else {
        // 文件里有顶层 dict 但没有环境变量段：插一个（放在 dict 末尾）
        let entry_indent = format!("{top_indent}\t");
        let dict_indent = entry_indent.clone();
        let block = render_block(&format!("{dict_indent}\t"), vars);
        let dict_inner = format!("\n{block}\n{dict_indent}");
        let new_entry =
            format!("{entry_indent}<key>{ENV_KEY}</key>\n{entry_indent}<dict>{dict_inner}</dict>");
        return Ok(plist::rewrite_dict_inner(
            before,
            top,
            None,
            &new_entry,
            &top_indent,
        ));
    };

    if entry.value_kind != plist::ValueKind::Dict {
        return Err(Error::inject(
            path,
            format!("{ENV_KEY} 的值不是 <dict>（拒绝改写，避免把既有内容换成别的东西）"),
        ));
    }

    let dict_inner = plist::container_inner(before, entry.value_span, path)?;
    let dict_indent = plist::close_indent(before, dict_inner);
    let dict_entries = plist::parse_entries(before, dict_inner, path)?;
    let block = plist::find_block(before, dict_inner, path)?;

    // 同名冲突：段内的**非受管**条目与我们要写的键同名 → 拒绝（PRD FR-4：
    // 「重名冲突时先报冲突让用户确认」；静默覆盖会违反同一条 PRD 的「非受管内容一律不动」）。
    for existing in &dict_entries {
        let managed = block.is_some_and(|span| span.contains(existing.entry_span));
        if managed {
            continue;
        }
        if vars.iter().any(|var| var.name == existing.name) {
            return Err(Error::inject(
                path,
                format!(
                    "同名键冲突：{ENV_KEY} 段里已有非受管键「{}」，KeyRelay 不覆盖你手写的内容。\
                     请手工删除或改名该键后重试（或改用不冲突的变量名）。",
                    existing.name
                ),
            ));
        }
    }

    let new_block = render_block(&format!("{dict_indent}\t"), vars);
    Ok(plist::rewrite_dict_inner(
        before,
        dict_inner,
        block,
        &new_block,
        &dict_indent,
    ))
}

/// 卸载：`names = None` 删整个受管块，`Some(names)` 只删命中的条目。
fn rewrite_env_block(before: &str, path: &Path, names: Option<&[String]>) -> Result<String> {
    if before.trim().is_empty() {
        return Ok(before.to_string());
    }
    let Some(dict_inner) = env_dict_inner(before, path)? else {
        return Ok(before.to_string());
    };
    let Some(block) = plist::find_block(before, dict_inner, path)? else {
        return Ok(before.to_string());
    };
    let dict_indent = plist::close_indent(before, dict_inner);

    let Some(names) = names else {
        return Ok(plist::rewrite_dict_inner(
            before,
            dict_inner,
            Some(block),
            "",
            &dict_indent,
        ));
    };

    // 部分卸载：保留块内没被点名的条目（用原文，不改写它们的格式）
    let entries = plist::parse_entries(before, dict_inner, path)?;
    let kept: Vec<&plist::Entry> = entries
        .iter()
        .filter(|e| block.contains(e.entry_span) && !names.contains(&e.name))
        .collect();
    if kept.len()
        == entries
            .iter()
            .filter(|e| block.contains(e.entry_span))
            .count()
    {
        // 没有任何条目被点名 → 文件不需要改动
        return Ok(before.to_string());
    }
    if kept.is_empty() {
        return Ok(plist::rewrite_dict_inner(
            before,
            dict_inner,
            Some(block),
            "",
            &dict_indent,
        ));
    }

    let block_indent = plist::value_indent(
        before,
        plist::Span {
            start: block.start,
            end: block.start,
        },
    );
    let mut lines = vec![
        format!("{block_indent}{BLOCK_BEGIN}"),
        format!("{block_indent}{BLOCK_NOTE}"),
    ];
    for entry in kept {
        lines.push(format!(
            "{block_indent}{}",
            &before[entry.entry_span.start..entry.entry_span.end]
        ));
    }
    lines.push(format!("{block_indent}{BLOCK_END}"));
    let rebuilt = lines.join("\n");
    Ok(plist::rewrite_dict_inner(
        before,
        dict_inner,
        Some(block),
        &rebuilt,
        &dict_indent,
    ))
}

/// 新建的 plist（文件不存在或 0 字节）。
fn render_fresh_env_plist(app_id: &str, vars: &[EnvVar]) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
    );
    out.push_str("<plist version=\"1.0\">\n<dict>\n");
    out.push_str(&format!(
        "\t<key>Label</key>\n\t<string>{}</string>\n",
        plist::escape_text(app_id)
    ));
    out.push_str(&format!("\t<key>{ENV_KEY}</key>\n\t<dict>\n"));
    out.push_str(&render_block("\t\t", vars));
    out.push('\n');
    out.push_str("\t</dict>\n</dict>\n</plist>\n");
    out
}

/// 渲染受管块（不含首尾换行；每行都带 `indent`）。
fn render_block(indent: &str, vars: &[EnvVar]) -> String {
    let mut lines = vec![
        format!("{indent}{BLOCK_BEGIN}"),
        format!("{indent}{BLOCK_NOTE}"),
    ];
    for var in vars {
        lines.push(format!(
            "{indent}<key>{}</key>",
            plist::escape_text(&var.name)
        ));
        lines.push(format!(
            "{indent}<string>{}</string>",
            plist::escape_text(&var.value)
        ));
    }
    lines.push(format!("{indent}{BLOCK_END}"));
    lines.join("\n")
}

// =================================================================== 注册表操作

impl RegHive {
    /// `reg.exe` 的根键前缀。
    pub fn as_reg_prefix(self) -> &'static str {
        match self {
            RegHive::CurrentUser => "HKCU",
        }
    }
}

impl RegOp {
    /// `HKCU\Environment` 这样的完整键路径（分隔符固定是 `\`，与宿主 OS 无关）。
    pub fn full_key(&self) -> String {
        format!("{}\\{}", self.hive.as_reg_prefix(), self.key)
    }

    /// `reg.exe` 的参数列表（**不含程序名**），原样传递、不做转义。
    ///
    /// 执行方式必须是 `Command::new(REG_EXE).args(op.to_argv())`——**不经 shell**，
    /// 因此值里的空格、`"`、`%` 都按字面量到达 `reg.exe`。
    pub fn to_argv(&self) -> Vec<String> {
        let mut argv = Vec::with_capacity(9);
        match &self.value {
            Some(value) => {
                argv.push("add".to_string());
                argv.push(self.full_key());
                argv.push("/v".to_string());
                argv.push(self.name.clone());
                // REG_SZ 而不是 REG_EXPAND_SZ：base_url 里可能出现百分号编码（`%20`），
                // REG_EXPAND_SZ 会在登录时把它当变量展开。
                argv.push("/t".to_string());
                argv.push("REG_SZ".to_string());
                argv.push("/d".to_string());
                argv.push(value.clone());
                argv.push("/f".to_string());
            }
            None => {
                argv.push("delete".to_string());
                argv.push(self.full_key());
                argv.push("/v".to_string());
                argv.push(self.name.clone());
                argv.push("/f".to_string());
            }
        }
        argv
    }

    /// **仅供展示 / 日志 / 预览**的可读命令行：含空白或 `"` 的参数用 `"` 包裹，
    /// 参数内的 `"` 用 `""` 表示（cmd.exe 习惯）。
    ///
    /// 不要把它交给 shell 执行：cmd.exe 会展开 `%VAR%`，且 `""` 的语义随宿主而变。
    /// 真正的执行路径是 [`RegOp::to_argv`]。
    pub fn to_command_line(&self) -> String {
        let mut parts = vec![REG_EXE.to_string()];
        parts.extend(self.to_argv().iter().map(|arg| quote_for_display(arg)));
        parts.join(" ")
    }
}

fn quote_for_display(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    if arg.chars().any(|c| c.is_whitespace() || c == '"') {
        format!("\"{}\"", arg.replace('"', "\"\""))
    } else {
        arg.to_string()
    }
}

// =================================================================== plist 最小扫描器

/// plist 文本的最小扫描器。只覆盖本模块需要的形态（`<dict>` / `<key>` / 标量 / 数组），
/// 看不懂就返回 `Err` —— 宁可拒绝改写，也不猜、不重写整个文件。
pub(crate) mod plist {
    use std::path::Path;

    use crate::error::{Error, Result};

    /// 文本里的半开区间 `[start, end)`（字节偏移，始终落在 char 边界上）。
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct Span {
        pub(crate) start: usize,
        pub(crate) end: usize,
    }

    impl Span {
        pub(crate) fn contains(self, other: Span) -> bool {
            other.start >= self.start && other.end <= self.end
        }
    }

    /// dict 条目值的种类。
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum ValueKind {
        Dict,
        Array,
        Bool(bool),
        Scalar,
    }

    /// dict 里的一个 `<key>NAME</key> + 值元素` 条目。
    #[derive(Clone, Debug)]
    pub(crate) struct Entry {
        pub(crate) name: String,
        /// 从 `<key>` 起到值元素结束（含中间空白），用于「原文保留」。
        pub(crate) entry_span: Span,
        pub(crate) value_span: Span,
        pub(crate) value_kind: ValueKind,
    }

    struct Tag {
        name: String,
        closing: bool,
        self_closing: bool,
        /// `>` 之后的位置。
        after: usize,
    }

    pub(crate) fn read_text_or_empty(path: &Path) -> Result<String> {
        match std::fs::read(path) {
            Ok(bytes) => String::from_utf8(bytes)
                .map_err(|_| Error::inject(path, "文件不是合法 UTF-8，拒绝改写")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(Error::inject(path, format!("读取失败: {e}"))),
        }
    }

    fn malformed(path: &Path, why: impl Into<String>) -> Error {
        Error::inject(path, format!("不是合法的 plist：{}", why.into()))
    }

    /// 解析 `lt`（指向 `<`）处的标签。不是标签时返回 `None`。
    fn parse_tag(text: &str, lt: usize) -> Option<Tag> {
        let rest = text.get(lt + 1..)?;
        let closing = rest.starts_with('/');
        let name_start = lt + 1 + usize::from(closing);
        let tail = text.get(name_start..)?;
        let name_end_rel = tail.find(|c: char| c == '>' || c == '/' || c.is_whitespace())?;
        let name = tail[..name_end_rel].to_string();
        if name.is_empty() {
            return None;
        }
        let after_name = name_start + name_end_rel;
        let gt = after_name + text.get(after_name..)?.find('>')?;
        let self_closing = !closing && text[after_name..gt].trim_end().ends_with('/');
        Some(Tag {
            name,
            closing,
            self_closing,
            after: gt + 1,
        })
    }

    /// 跳过空白与 XML 注释。
    pub(crate) fn skip_ws_and_comments(text: &str, mut pos: usize) -> usize {
        loop {
            let bytes = text.as_bytes();
            while pos < bytes.len() && matches!(bytes[pos], b' ' | b'\t' | b'\n' | b'\r') {
                pos += 1;
            }
            if text[pos..].starts_with("<!--") {
                match text[pos..].find("-->") {
                    Some(rel) => {
                        pos += rel + 3;
                        continue;
                    }
                    None => return text.len(),
                }
            }
            return pos;
        }
    }

    fn find_close_tag(text: &str, from: usize, name: &str, path: &Path) -> Result<Span> {
        let mut pos = from;
        while let Some(rel) = text[pos..].find("</") {
            let lt = pos + rel;
            if let Some(tag) = parse_tag(text, lt) {
                if tag.closing && tag.name == name {
                    return Ok(Span {
                        start: lt,
                        end: tag.after,
                    });
                }
            }
            pos = lt + 2;
        }
        Err(malformed(path, format!("<{name}> 没有配对的结束标签")))
    }

    /// 嵌套感知地找 `</name>`（跳过注释；`<string>` 里的 `<` 必然被转义成 `&lt;`）。
    fn scan_container(text: &str, from: usize, name: &str, path: &Path) -> Result<Span> {
        let mut pos = from;
        let mut depth = 1usize;
        while let Some(rel) = text[pos..].find('<') {
            let lt = pos + rel;
            if text[lt..].starts_with("<!--") {
                match text[lt..].find("-->") {
                    Some(rel_end) => {
                        pos = lt + rel_end + 3;
                        continue;
                    }
                    None => return Err(malformed(path, "注释没有结束标记")),
                }
            }
            match parse_tag(text, lt) {
                Some(tag) if tag.name == name => {
                    if tag.closing {
                        depth -= 1;
                        if depth == 0 {
                            return Ok(Span {
                                start: lt,
                                end: tag.after,
                            });
                        }
                    } else if !tag.self_closing {
                        depth += 1;
                    }
                    pos = tag.after;
                }
                _ => pos = lt + 1,
            }
        }
        Err(malformed(path, format!("<{name}> 没有配对的结束标签")))
    }

    fn scan_element(text: &str, pos: usize, path: &Path) -> Result<(Span, ValueKind)> {
        let tag = parse_tag(text, pos).ok_or_else(|| malformed(path, "值元素缺少起始标签"))?;
        if tag.closing {
            return Err(malformed(path, "值元素是结束标签"));
        }
        if tag.self_closing {
            let kind = match tag.name.as_str() {
                "true" => ValueKind::Bool(true),
                "false" => ValueKind::Bool(false),
                "dict" => ValueKind::Dict,
                "array" => ValueKind::Array,
                _ => ValueKind::Scalar,
            };
            return Ok((
                Span {
                    start: pos,
                    end: tag.after,
                },
                kind,
            ));
        }
        match tag.name.as_str() {
            "dict" | "array" => {
                let close = scan_container(text, tag.after, &tag.name, path)?;
                let kind = if tag.name == "dict" {
                    ValueKind::Dict
                } else {
                    ValueKind::Array
                };
                Ok((
                    Span {
                        start: pos,
                        end: close.end,
                    },
                    kind,
                ))
            }
            "true" | "false" => {
                let close = find_close_tag(text, tag.after, &tag.name, path)?;
                Ok((
                    Span {
                        start: pos,
                        end: close.end,
                    },
                    ValueKind::Bool(tag.name == "true"),
                ))
            }
            _ => {
                let close = find_close_tag(text, tag.after, &tag.name, path)?;
                Ok((
                    Span {
                        start: pos,
                        end: close.end,
                    },
                    ValueKind::Scalar,
                ))
            }
        }
    }

    /// 顶层 `<dict>` 的**内部**区间（`<dict>` 之后、`</dict>` 之前）。
    pub(crate) fn top_dict_inner(text: &str, path: &Path) -> Result<Span> {
        let mut pos = 0usize;
        while let Some(rel) = text[pos..].find('<') {
            let lt = pos + rel;
            if text[lt..].starts_with("<!--") {
                match text[lt..].find("-->") {
                    Some(rel_end) => {
                        pos = lt + rel_end + 3;
                        continue;
                    }
                    None => break,
                }
            }
            match parse_tag(text, lt) {
                Some(tag) if !tag.closing && tag.name == "dict" => {
                    if tag.self_closing {
                        return Ok(Span {
                            start: tag.after,
                            end: tag.after,
                        });
                    }
                    let close = scan_container(text, tag.after, "dict", path)?;
                    return Ok(Span {
                        start: tag.after,
                        end: close.start,
                    });
                }
                _ => pos = lt + 1,
            }
        }
        Err(malformed(path, "找不到顶层 <dict>"))
    }

    /// 解析 dict 内部的条目。
    pub(crate) fn parse_entries(text: &str, inner: Span, path: &Path) -> Result<Vec<Entry>> {
        let mut entries = Vec::new();
        let mut pos = inner.start;
        loop {
            pos = skip_ws_and_comments(text, pos);
            if pos >= inner.end {
                break;
            }
            let key_open = parse_tag(text, pos)
                .filter(|t| !t.closing && !t.self_closing && t.name == "key")
                .ok_or_else(|| {
                    malformed(path, format!("dict 里出现了非 <key> 元素（偏移 {pos}）"))
                })?;
            let key_close = find_close_tag(text, key_open.after, "key", path)?;
            let name = unescape_text(&text[key_open.after..key_close.start]);
            let value_at = skip_ws_and_comments(text, key_close.end);
            if value_at >= inner.end {
                return Err(malformed(path, format!("<key>{name}</key> 后面没有值元素")));
            }
            let (value_span, value_kind) = scan_element(text, value_at, path)?;
            entries.push(Entry {
                name,
                entry_span: Span {
                    start: pos,
                    end: value_span.end,
                },
                value_span,
                value_kind,
            });
            pos = value_span.end;
        }
        Ok(entries)
    }

    pub(crate) fn find_entry<'a>(entries: &'a [Entry], name: &str) -> Option<&'a Entry> {
        entries.iter().find(|e| e.name == name)
    }

    /// 找**唯一**的同名条目：出现两次及以上 → `Err`。
    ///
    /// 为什么必须拒绝而不是「改第一个」：plist 解析器对重复键的取舍是实现定义的
    /// （多数是「后者胜」）。如果我们改了第一个而第二个仍然有效，就会出现
    /// 「写进去了但没生效」——而且回读校验也发现不了（`before` 确实被替换了）。
    pub(crate) fn find_entry_unique<'a>(
        entries: &'a [Entry],
        name: &str,
        path: &Path,
    ) -> Result<Option<&'a Entry>> {
        let mut found: Option<&Entry> = None;
        let mut count = 0usize;
        for entry in entries {
            if entry.name == name {
                count += 1;
                found = Some(entry);
            }
        }
        if count > 1 {
            return Err(Error::inject(
                path,
                format!(
                    "有 {count} 个同名的 <key>{name}</key>，语义有歧义（重复键的取舍由解析器决定）；\
                     请手工只保留一个后重试"
                ),
            ));
        }
        Ok(found)
    }

    /// 容器元素（`<dict>` / `<array>`）的内部区间。
    pub(crate) fn container_inner(text: &str, span: Span, path: &Path) -> Result<Span> {
        let tag = parse_tag(text, span.start).ok_or_else(|| malformed(path, "容器缺少起始标签"))?;
        if tag.self_closing {
            return Ok(Span {
                start: tag.after,
                end: tag.after,
            });
        }
        let close = scan_container(text, tag.after, &tag.name, path)?;
        Ok(Span {
            start: tag.after,
            end: close.start,
        })
    }

    /// `at` 所在行的行首缩进（若 `at` 前不是纯空白则返回空串）。
    fn indent_before(text: &str, at: usize) -> String {
        let before = &text[..at];
        let line_start = before.rfind('\n').map_or(0, |i| i + 1);
        let tail = &before[line_start..];
        if tail.chars().all(|c| c == ' ' || c == '\t') {
            tail.to_string()
        } else {
            String::new()
        }
    }

    /// `inner` 结束标签（`</dict>`）的缩进。
    pub(crate) fn close_indent(text: &str, inner: Span) -> String {
        indent_before(text, inner.end)
    }

    /// 某个元素起始处的缩进（用于按既有缩进渲染新值）。
    pub(crate) fn value_indent(text: &str, span: Span) -> String {
        indent_before(text, span.start)
    }

    /// 找受管块 `[BLOCK_BEGIN, BLOCK_END]`。
    ///
    /// 孤立开始标记 / 多个块 → `Err`：这两种文件都是被手工改过的，
    /// 按「从开始标记吃到文件末尾」处理会静默删掉用户写在块后面的内容
    /// （`delivery/shell_block.rs` 的 M2-S2 复审 P1-2 就是这个教训）。
    pub(crate) fn find_block(text: &str, inner: Span, path: &Path) -> Result<Option<Span>> {
        let hay = &text[inner.start..inner.end];
        let mut starts = Vec::new();
        let mut from = 0usize;
        while let Some(rel) = hay[from..].find(super::BLOCK_BEGIN) {
            let at = from + rel;
            starts.push(at);
            from = at + super::BLOCK_BEGIN.len();
        }
        if starts.is_empty() {
            return Ok(None);
        }
        if starts.len() > 1 {
            return Err(Error::inject(
                path,
                format!(
                    "有 {} 个 KeyRelay 受管块，语义有歧义；请手工只保留一个（`{}` … `{}`）后重试",
                    starts.len(),
                    super::BLOCK_BEGIN,
                    super::BLOCK_END
                ),
            ));
        }
        let begin = inner.start + starts[0];
        let after_begin = begin + super::BLOCK_BEGIN.len();
        let end = match text[after_begin..inner.end].find(super::BLOCK_END) {
            Some(rel) => after_begin + rel + super::BLOCK_END.len(),
            None => {
                return Err(Error::inject(
                    path,
                    format!(
                        "受管块只有开始标记（`{}`）却没有结束标记（`{}`）；拒绝改写以免删掉你写在它后面的内容。\
                         请手工补上结束标记，或删掉开始标记后重试",
                        super::BLOCK_BEGIN,
                        super::BLOCK_END
                    ),
                ))
            }
        };
        Ok(Some(Span { start: begin, end }))
    }

    /// 改写 dict 内部：删掉 `cut`（连同它前面的行内缩进），把 `tail_xml` 追加到区间末尾。
    /// 区间外的字节**逐字保留**。
    pub(crate) fn rewrite_dict_inner(
        text: &str,
        inner: Span,
        cut: Option<Span>,
        tail_xml: &str,
        close_indent: &str,
    ) -> String {
        let body = match cut {
            Some(cut) => {
                // 连同块前缩进一起删，否则会留下孤零零的制表符
                let mut start = cut.start;
                while start > inner.start && matches!(text.as_bytes()[start - 1], b' ' | b'\t') {
                    start -= 1;
                }
                format!("{}{}", &text[inner.start..start], &text[cut.end..inner.end])
            }
            None => text[inner.start..inner.end].to_string(),
        };
        let body = body.trim_end();

        let mut out = String::with_capacity(text.len() + tail_xml.len() + 4);
        out.push_str(&text[..inner.start]);
        out.push_str(body);
        out.push('\n');
        if !tail_xml.is_empty() {
            out.push_str(tail_xml);
            out.push('\n');
        }
        out.push_str(close_indent);
        out.push_str(&text[inner.end..]);
        out
    }

    /// 设置顶层 dict 里某个键的值（不存在则追加）；其余字节逐字保留。
    pub(crate) fn set_entry(
        text: &str,
        path: &Path,
        name: &str,
        value_xml: &str,
    ) -> Result<String> {
        let inner = top_dict_inner(text, path)?;
        let entries = parse_entries(text, inner, path)?;
        match find_entry_unique(&entries, name, path)? {
            Some(entry) => {
                let mut out = String::with_capacity(text.len() + value_xml.len());
                out.push_str(&text[..entry.value_span.start]);
                out.push_str(value_xml);
                out.push_str(&text[entry.value_span.end..]);
                Ok(out)
            }
            None => {
                let close = close_indent(text, inner);
                let indent = format!("{close}\t");
                let entry_xml = format!(
                    "{indent}<key>{}</key>\n{indent}{value_xml}",
                    escape_text(name)
                );
                Ok(rewrite_dict_inner(text, inner, None, &entry_xml, &close))
            }
        }
    }

    /// 受管块里的键名（**只读键名，绝不返回值**）。任何解析失败都返回空列表——
    /// 这个函数只服务于 `EnvPlan::describe`，不能因为展示而失败。
    pub(crate) fn managed_names(text: &str) -> Vec<String> {
        let probe = Path::new("<plan>");
        let Ok(top) = top_dict_inner(text, probe) else {
            return Vec::new();
        };
        let Ok(entries) = parse_entries(text, top, probe) else {
            return Vec::new();
        };
        let Some(env) = find_entry(&entries, super::ENV_KEY) else {
            return Vec::new();
        };
        let Ok(inner) = container_inner(text, env.value_span, probe) else {
            return Vec::new();
        };
        let Ok(Some(block)) = find_block(text, inner, probe) else {
            return Vec::new();
        };
        let Ok(entries) = parse_entries(text, inner, probe) else {
            return Vec::new();
        };
        entries
            .iter()
            .filter(|e| block.contains(e.entry_span))
            .map(|e| e.name.clone())
            .collect()
    }

    /// 取 `<string>` 元素的文本内容（XML 反转义后）。
    pub(crate) fn string_value(text: &str, span: Span, path: &Path) -> Result<String> {
        let tag =
            parse_tag(text, span.start).ok_or_else(|| malformed(path, "值元素缺少起始标签"))?;
        if tag.name != "string" {
            return Err(malformed(
                path,
                format!("受管键的值必须是 <string>，实际是 <{}>", tag.name),
            ));
        }
        if tag.self_closing {
            return Ok(String::new());
        }
        let close = find_close_tag(text, tag.after, "string", path)?;
        Ok(unescape_text(&text[tag.after..close.start]))
    }

    /// XML 文本节点转义（`&` `<` `>`）。
    pub(crate) fn escape_text(value: &str) -> String {
        let mut out = String::with_capacity(value.len());
        for c in value.chars() {
            match c {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                other => out.push(other),
            }
        }
        out
    }

    /// XML 文本节点反转义（5 个命名实体 + 十进制 / 十六进制字符引用）。
    pub(crate) fn unescape_text(value: &str) -> String {
        let mut out = String::with_capacity(value.len());
        let mut rest = value;
        while let Some(idx) = rest.find('&') {
            out.push_str(&rest[..idx]);
            let tail = &rest[idx..];
            match decode_entity(tail) {
                Some((decoded, consumed)) => {
                    out.push_str(&decoded);
                    rest = &tail[consumed..];
                }
                None => {
                    out.push('&');
                    rest = &tail[1..];
                }
            }
        }
        out.push_str(rest);
        out
    }

    fn decode_entity(tail: &str) -> Option<(String, usize)> {
        let semi = tail.find(';')?;
        if semi > 12 {
            return None;
        }
        let body = &tail[1..semi];
        let decoded = match body {
            "amp" => "&".to_string(),
            "lt" => "<".to_string(),
            "gt" => ">".to_string(),
            "quot" => "\"".to_string(),
            "apos" => "'".to_string(),
            _ => {
                let digits = body.strip_prefix('#')?;
                let code = match digits
                    .strip_prefix('x')
                    .or_else(|| digits.strip_prefix('X'))
                {
                    Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                    None => digits.parse::<u32>().ok()?,
                };
                char::from_u32(code)?.to_string()
            }
        };
        Some((decoded, semi + 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = "/tmp/probe.plist";
    fn probe() -> &'static Path {
        Path::new(P)
    }

    #[test]
    fn entries_skip_comments_and_whitespace() {
        let text = "<dict>\n\t<!-- c -->\n\t<key>A</key>\n\t<string>1</string>\n\t<key>B</key><integer>2</integer>\n</dict>";
        let inner = plist::top_dict_inner(text, probe()).unwrap();
        let entries = plist::parse_entries(text, inner, probe()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "A");
        assert_eq!(entries[0].value_kind, plist::ValueKind::Scalar);
        assert_eq!(entries[1].name, "B");
        assert_eq!(
            &text[entries[1].entry_span.start..entries[1].entry_span.end],
            "<key>B</key><integer>2</integer>"
        );
    }

    #[test]
    fn nested_containers_are_paired_and_nested_keys_are_not_top_level() {
        let text = "<dict><key>Outer</key><dict><key>RunAtLoad</key><true/></dict><key>RunAtLoad</key><false/></dict>";
        let inner = plist::top_dict_inner(text, probe()).unwrap();
        let entries = plist::parse_entries(text, inner, probe()).unwrap();
        assert_eq!(entries.len(), 2, "嵌套里的键不算顶层键");
        assert_eq!(entries[0].name, "Outer");
        assert_eq!(entries[0].value_kind, plist::ValueKind::Dict);
        assert_eq!(entries[1].name, "RunAtLoad");
        assert_eq!(entries[1].value_kind, plist::ValueKind::Bool(false));
    }

    #[test]
    fn self_closing_and_paired_booleans_are_both_recognised() {
        for (text, expected) in [
            (
                "<dict><key>K</key><true/></dict>",
                plist::ValueKind::Bool(true),
            ),
            (
                "<dict><key>K</key><true></true></dict>",
                plist::ValueKind::Bool(true),
            ),
            (
                "<dict><key>K</key><false/></dict>",
                plist::ValueKind::Bool(false),
            ),
            (
                "<dict><key>K</key><string>true</string></dict>",
                plist::ValueKind::Scalar,
            ),
        ] {
            let inner = plist::top_dict_inner(text, probe()).unwrap();
            let entries = plist::parse_entries(text, inner, probe()).unwrap();
            assert_eq!(entries[0].value_kind, expected, "{text}");
        }
    }

    #[test]
    fn arrays_are_paired_with_nesting() {
        let text = "<dict><key>A</key><array><string>x</string><array><string>y</string></array></array></dict>";
        let inner = plist::top_dict_inner(text, probe()).unwrap();
        let entries = plist::parse_entries(text, inner, probe()).unwrap();
        assert_eq!(entries[0].value_kind, plist::ValueKind::Array);
        assert_eq!(
            &text[entries[0].value_span.start..entries[0].value_span.end],
            "<array><string>x</string><array><string>y</string></array></array>"
        );
    }

    #[test]
    fn escapes_round_trip() {
        let raw = "a&b<c>d\"e'f";
        let escaped = plist::escape_text(raw);
        assert_eq!(escaped, "a&amp;b&lt;c&gt;d\"e'f");
        assert_eq!(plist::unescape_text(&escaped), raw);
        assert_eq!(plist::unescape_text("&#65;&#x42;"), "AB");
        // 非法实体原样保留（不 panic、不吞字符）
        assert_eq!(plist::unescape_text("a&bogus;c"), "a&bogus;c");
    }

    #[test]
    fn malformed_inputs_are_errors_not_panics() {
        for text in [
            "<plist><dict><key>A</key><string>1</string>", // 未闭合 dict
            "<plist><dict><key>A</key></dict></plist>",    // key 后没有值
            "<plist><dict><string>1</string></dict>",      // 非 <key> 开头
            "<plist><array><key>A</key></array>",          // 没有顶层 dict
            "<plist><dict><!-- 未闭合注释 <key>A</key><string>1</string></dict>",
        ] {
            let result = plist::top_dict_inner(text, probe())
                .and_then(|inner| plist::parse_entries(text, inner, probe()));
            assert!(result.is_err(), "应报错: {text}");
        }
    }

    #[test]
    fn indent_is_derived_from_the_closing_tag() {
        let text = "<dict>\n\t\t<key>A</key>\n\t\t<string>1</string>\n\t</dict>";
        let inner = plist::top_dict_inner(text, probe()).unwrap();
        assert_eq!(plist::close_indent(text, inner), "\t");
        let entries = plist::parse_entries(text, inner, probe()).unwrap();
        assert_eq!(plist::value_indent(text, entries[0].value_span), "\t\t");

        let one_line = "<dict></dict>";
        let inner = plist::top_dict_inner(one_line, probe()).unwrap();
        assert_eq!(plist::close_indent(one_line, inner), "");
    }

    #[test]
    fn debug_never_prints_values() {
        let var = EnvVar {
            name: "OPENAI_API_KEY".to_string(),
            value: "sk-LEAKY-VALUE".to_string(),
        };
        assert!(!format!("{var:?}").contains("LEAKY"), "{var:?}");
        let op = RegOp {
            hive: RegHive::CurrentUser,
            key: WINDOWS_ENV_KEY.to_string(),
            name: "OPENAI_API_KEY".to_string(),
            value: Some("sk-LEAKY-VALUE".to_string()),
        };
        assert!(!format!("{op:?}").contains("LEAKY"), "{op:?}");
        let plan = EnvPlan::Registry(vec![op]);
        assert!(!format!("{plan:?}").contains("LEAKY"), "{plan:?}");
    }
}
