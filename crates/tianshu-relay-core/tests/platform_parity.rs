//! macOS / Windows 功能对等的**源码级守护**（PRD 目标里明确要求双端对等）。
//!
//! 为什么是源码扫描而不是编译检查：本机没有 Windows C 工具链，
//! `cargo check --target x86_64-pc-windows-msvc` 会在两个**C 依赖**上停下
//! （`libsqlite3-sys` 的 bundled SQLite 与 `aws-lc-sys`），
//! 那是工具链限制、不是我们的代码问题（见 `docs/evidence/platform-parity.md`）。
//! 因此这里退一步：**把「平台相关代码的清单」钉住**，
//! 让「新增了一段只在一个平台上存在的代码」这件事无法悄悄发生。
//!
//! 三条不变式：
//! 1. 每个出现**非测试** `#[cfg(unix)]` 的文件，必须同时有 `#[cfg(not(unix))]` 的对应实现；
//! 2. 平台相关代码的**文件清单**必须与已知清单一致（新增/删除都要显式更新这里）；
//! 3. `platform::home_dir` 必须是**纯函数**（不直接读环境变量），
//!    这样 Windows 分支能在任何平台上被测试。

use std::fs;
use std::path::{Path, PathBuf};

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("读目录").flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// 去掉 `#[cfg(test)]` 之后的所有内容——测试里的平台分支不算产品代码。
fn production_part(source: &str) -> String {
    match source.find("#[cfg(test)]") {
        Some(at) => source[..at].to_string(),
        None => source.to_string(),
    }
}

fn relative(path: &Path) -> String {
    path.strip_prefix(src_dir())
        .unwrap_or(path)
        .to_string_lossy()
        // Windows 上分隔符是 `\`，期望清单用 `/`：只在这里归一化分隔符，
        // 不动生产清单收集逻辑（见 platform_specific_files_match_the_known_inventory）。
        .replace('\\', "/")
}

/// 跨平台绝对路径夹具：`Path::is_absolute()` 是宿主语义，POSIX 形态在 Windows 上
/// 会被判为相对（`validate_home` / `validate_exe` 先于一切校验，B-14 口径），
/// 反之 `C:\...` 在 Unix 上也不是绝对路径；因此按编译目标分支选形态，
/// 死分支在宿主上不参与判定，只保证「当前宿主上绝对」这一条。
fn fixture_home() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\Users\me")
    } else {
        PathBuf::from("/home/me")
    }
}

fn fixture_exe() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\Program Files\TianshuRelay\tianshu-relay.exe")
    } else {
        PathBuf::from("/Applications/TianshuRelay.app/Contents/MacOS/tianshu-relay")
    }
}

/// 含 `"` 但在当前宿主上仍绝对的 exe：先过绝对路径校验，才能走到引号拒绝，
/// 否则测到的会是绝对路径拒绝而非引号拒绝。
fn fixture_quoted_exe() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r#"C:\a"b.exe"#)
    } else {
        PathBuf::from(r#"/usr/bin/a"b"#)
    }
}

#[test]
fn unix_only_code_always_has_a_non_unix_counterpart() {
    let mut files = Vec::new();
    rust_files(&src_dir(), &mut files);

    let mut offenders = Vec::new();
    for path in &files {
        let source = fs::read_to_string(path).expect("读源码");
        let production = production_part(&source);
        let has_unix = production.contains("#[cfg(unix)]");
        let has_not_unix = production.contains("#[cfg(not(unix))]");
        if has_unix && !has_not_unix {
            offenders.push(relative(path));
        }
    }

    assert!(
        offenders.is_empty(),
        "这些文件里有只在 unix 上存在的代码，却没有 `#[cfg(not(unix))]` 的对应实现，\
         Windows 上会编译不过或行为缺失：{offenders:?}"
    );
}

#[test]
fn platform_specific_files_match_the_known_inventory() {
    let mut files = Vec::new();
    rust_files(&src_dir(), &mut files);

    let mut with_platform_code: Vec<String> = Vec::new();
    for path in &files {
        let source = fs::read_to_string(path).expect("读源码");
        let production = production_part(&source);
        let gated = production.contains("#[cfg(unix)]")
            || production.contains("#[cfg(not(unix))]")
            || production.contains("#[cfg(target_os")
            || production.contains("cfg!(target_os")
            || production.contains("cfg!(windows)");
        if gated {
            with_platform_code.push(relative(path));
        }
    }
    with_platform_code.sort();

    // 已知清单。**新增平台相关代码时必须在这里显式登记**——
    // 登记这个动作本身就是「我想过另一个平台了」的检查点。
    //
    // M6 波次新增两项（2026-10-12）：
    // - `autostart.rs`（M6-S2）：`cfg!(target_os = "windows")` 分派到注册表形态，macOS 走 LaunchAgent plist
    // - `notify/system.rs`（M6-S3）：macOS 走 `osascript`，Windows 走 PowerShell toast
    // 两者都在 `docs/evidence/platform-parity.md` §1 补了双端说明。
    //
    // M7 波次新增一项（2026-10-13）：
    // - `delivery/mod.rs`（M7-S3）：`current_host_os()` 按宿主平台分派 VS Code `globalStorage`
    //   候选路径（macOS `Library/Application Support/Code/…` / Windows `AppData/Roaming/Code/…`），
    //   给 Cline / Roo 的「探测 + 明确拒绝」用。双端说明见 `docs/evidence/platform-parity.md` §1.1。
    //
    // M10-S2 新增一项（2026-10-15）：
    // - `proxy.rs`：系统代理探测按平台分派——macOS 走 `scutil --proxy`、Windows 走 `reg query`
    //   `HKCU\…\Internet Settings`、其余平台只读环境变量。解析 `scutil`/`reg query` 文本是纯函数，
    //   跨平台可测；真实进程探测在真机上验证（见 `docs/evidence/platform-parity.md` §1.2）。
    //
    // M31-S1 新增一项（2026-10-21）：
    // - `agents.rs`：Agent 安装探测按平台分派——macOS 的 App 探测读 `.app/Contents/Info.plist`；
    //   非 macOS 明确返回「未安装」（应用包是 macOS 概念，不猜 Linux 的 .desktop）；
    //   CLI 在 Windows 上额外尝试 `.exe` / `.cmd`。Windows 侧未真机执行，
    //   见 `docs/evidence/platform-parity.md` §1.3。
    // M33-S1 新增一项（2026-10-21）：
    // - `vault/keyfile.rs`：设备绑定取 macOS `IOPlatformUUID` / Windows `MachineGuid` /
    //   Linux `/etc/machine-id` 三条分支 + 非 unix 的文件权限空实现；
    //   真机只跑 macOS 那条，Windows/Linux 分支靠本条清单与单测兜住（未真机执行）。
    let expected = vec![
        "agents.rs".to_string(),
        "autostart.rs".to_string(),
        "delivery/claude_desktop.rs".to_string(),
        "delivery/cline.rs".to_string(),
        "delivery/mod.rs".to_string(),
        "inject/mod.rs".to_string(),
        "notify/system.rs".to_string(),
        "proxy.rs".to_string(),
        // M35-S1：旧数据目录迁移的 0700/0600 只在 unix 上有 mode；
        // 非 unix 分支是空实现（继承 ACL），文件已在本清单登记。
        "rebrand.rs".to_string(),
        // 投递改进 P1-5：重启按平台分派——macOS 走 osascript/open bundle id、
        // Windows 走 taskkill/tasklist、Linux 走 pkill//proc 扫描；argv 构造类函数显式收
        // 平台参数，macOS/Windows 分支在 Linux 上也有单测（未真机执行，见 restart.rs 模块文档）。
        "restart.rs".to_string(),
        // DEBUG-G7 P2-K5（0600 落实）：`store/mod.rs` 的 tighten_db_files 与
        // `vault/local.rs` 的 tighten_vault_files 在 unix 上把库文件权限只收紧
        // 不放宽（`mode & 0o600`，含 -wal / -shm）；非 unix 分支均为继承 ACL 的
        // 空实现。双端说明见 `docs/evidence/platform-parity.md` §1.6。
        "store/mod.rs".to_string(),
        "vault/keychain.rs".to_string(),
        "vault/keyfile.rs".to_string(),
        "vault/local.rs".to_string(),
    ];

    assert_eq!(
        with_platform_code, expected,
        "平台相关代码的文件清单变了。若是有意新增，请更新本测试的 expected 清单，\
         并在 docs/evidence/platform-parity.md 里补上双端说明。"
    );
}

#[test]
fn home_dir_is_a_pure_function_so_windows_branches_are_testable() {
    // `platform::home_dir_with` 接受注入的取值函数，因此 Windows 的分支
    // 能在 macOS 上被真实测试；如果哪天有人把它改成直接读 `std::env::var`，
    // 那条测试路径就失效了。
    let source = fs::read_to_string(src_dir().join("platform.rs")).expect("读 platform.rs");
    let production = production_part(&source);

    assert!(
        production.contains("pub fn home_dir_with"),
        "platform.rs 必须保留可注入的 home_dir_with"
    );
    assert!(
        production.contains("pub fn home_dir()"),
        "platform.rs 必须提供无参的 home_dir"
    );
    // 无参版本应当只是把环境变量读取委托给可注入版本
    let delegating = production
        .split("pub fn home_dir()")
        .nth(1)
        .unwrap_or_default();
    assert!(
        delegating.contains("home_dir_with"),
        "home_dir() 必须委托给 home_dir_with，而不是自己读环境变量"
    );
    // 绝不允许再出现「解析不出来就用当前目录」的老写法
    assert!(
        !production.contains(r#"unwrap_or_else(|_| "."#),
        "platform.rs 不得退化成当前目录"
    );
}

#[test]
fn no_crate_wide_home_env_reads_outside_platform() {
    // 除 `platform.rs` 之外，产品代码不得直接读 `HOME` / `USERPROFILE`——
    // 那正是 B-14 的成因（Windows 上 HOME 常常缺失）。
    let mut files = Vec::new();
    rust_files(&src_dir(), &mut files);

    let mut offenders = Vec::new();
    for path in &files {
        if relative(path) == "platform.rs" {
            continue;
        }
        let source = fs::read_to_string(path).expect("读源码");
        let production = production_part(&source);
        for needle in [
            r#"var("HOME")"#,
            r#"var("USERPROFILE")"#,
            r#"var("HOMEDRIVE")"#,
        ] {
            if production.contains(needle) {
                offenders.push(format!("{}: {needle}", relative(path)));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "主目录解析必须集中在 platform.rs：{offenders:?}"
    );
}

#[test]
fn keychain_backend_names_cover_both_platforms() {
    // 两个平台的后端名都必须在源码里出现（真机上只会命中一个）
    let source = fs::read_to_string(src_dir().join("vault/keychain.rs")).expect("读 keychain.rs");
    assert!(source.contains("macos-keychain"), "缺少 macOS 后端名");
    assert!(
        source.contains("windows-credential-manager"),
        "缺少 Windows 后端名"
    );
    assert!(
        source.contains(r#"target_os = "windows""#),
        "keychain.rs 必须显式处理 Windows"
    );
    assert!(
        source.contains(r#"not(any(target_os = "macos", target_os = "windows"))"#),
        "keychain.rs 必须为其它平台提供兜底实现，否则那些平台编译不过"
    );
}

// ===========================================================================
// M14-S5：Windows 分支注入式测试扩充（在 macOS 上验证 Windows 分支的构造与纯函数）
//
// 为什么这些测试能在 macOS 上跑：autostart 的 `*_on(target, ...)` 显式平台版本、
// notify 的 `system_command`（`cfg!` 分派）都是「两个平台都编译」的代码路径，可注入 `AutostartTarget::WindowsRunKey`
// / `NotifyPlatform::Windows` 直接断言 Windows 分支。proxy 的 `reg_query_value` 与
// keychain 的 `describe` 在 `#[cfg(target_os = "windows")]` 块内或为私有 fn（macOS 不编译
// / 调不到），退化为 source 断言；真机执行留 CI（B-66）。见 spec §6.1 / §7.1。

#[test]
fn autostart_windows_run_key_plan_is_well_formed() {
    use tianshu_relay_core::autostart::{plan_enable_on, AutostartTarget};
    use tianshu_relay_core::platform_env::{EnvPlan, RegHive, RUN_KEY};

    // home / exe 用按目标分支的绝对路径夹具：POSIX 形态在 Windows CI 上会被
    // validate_home / validate_exe 判为相对（CI run 40225644513 的失败根因）。
    // 本测验证 RegOp 四字段结构 + run_key_value 的「引号包裹 + --hidden」拼装
    // （纯函数，与平台无关）。
    let plan = plan_enable_on(
        AutostartTarget::WindowsRunKey,
        &fixture_home(),
        "com.tianshu.relay",
        &fixture_exe(),
        true,
    )
    .expect("合法输入应产出计划");

    let EnvPlan::Registry(ops) = plan else {
        panic!("Windows 分支应产出 Registry 计划");
    };
    assert_eq!(ops.len(), 1, "Run 键只动一条值");
    let op = &ops[0];
    assert_eq!(op.hive, RegHive::CurrentUser, "HKCU 不需提权");
    assert_eq!(op.key, RUN_KEY, "Run 键路径");
    assert_eq!(op.name, "com.tianshu.relay", "值名 = app_id");
    let value = op.value.as_deref().expect("enable 应有 value");
    assert!(
        value.starts_with('"'),
        "CreateProcess 规则：exe 路径必须加引号: {value}"
    );
    assert!(
        value.ends_with("--hidden"),
        "hidden=true 应追加 --hidden: {value}"
    );
}

#[test]
fn autostart_windows_disable_clears_value() {
    use tianshu_relay_core::autostart::{plan_disable_on, AutostartTarget};
    use tianshu_relay_core::platform_env::{EnvPlan, RegHive, RUN_KEY};

    let plan = plan_disable_on(
        AutostartTarget::WindowsRunKey,
        &fixture_home(),
        "com.tianshu.relay",
    )
    .expect("合法输入应产出计划");

    let EnvPlan::Registry(ops) = plan else {
        panic!("Windows 分支应产出 Registry 计划");
    };
    assert_eq!(ops.len(), 1);
    let op = &ops[0];
    assert_eq!(op.hive, RegHive::CurrentUser);
    assert_eq!(op.key, RUN_KEY);
    assert_eq!(op.name, "com.tianshu.relay");
    assert!(op.value.is_none(), "disable 应置 value=None（删除语义）");
}

#[test]
fn autostart_windows_state_is_unknown_by_design() {
    use tianshu_relay_core::autostart::{state_on, AutostartState, AutostartTarget};

    // Windows 分支不执行 reg.exe（本模块不跑外部进程），state 恒 Unknown。
    // 刻意如此：判不出来时保守报 Unknown，绝不把 Unknown 当 Enabled。
    let state = state_on(
        AutostartTarget::WindowsRunKey,
        &fixture_home(),
        "com.tianshu.relay",
    )
    .expect("合法输入应产出状态");
    assert_eq!(state, AutostartState::Unknown);
}

#[test]
fn autostart_windows_rejects_exe_with_quote() {
    use tianshu_relay_core::autostart::{plan_enable_on, AutostartTarget};
    use tianshu_relay_core::error::Error;

    // Windows 路径不允许 `"`，且它会让 Run 键的值提前闭合。
    // home 已是宿主绝对路径、且 home 拒绝文案不含“双引号”，故下断言确实锚定
    // quote 拒绝而非 home 拒绝（此前在 Windows CI 上测到的正是 home 拒绝）。
    let err = plan_enable_on(
        AutostartTarget::WindowsRunKey,
        &fixture_home(),
        "com.tianshu.relay",
        &fixture_quoted_exe(),
        true,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Store(_)), "应为 Store 错误: {err:?}");
    assert!(
        err.to_string().contains("双引号"),
        "文案要说明拒绝原因: {err}"
    );
}

#[test]
fn autostart_windows_rejects_relative_exe() {
    use tianshu_relay_core::autostart::{plan_enable_on, AutostartTarget};
    use tianshu_relay_core::error::Error;

    // 顺带收紧：此前在 Windows 上它只因 home 校验先失败而“碰巧”通过
    // （home 拒绝文案同样含“绝对路径”）；home 改用宿主绝对夹具后，
    // 本测才真正测到 exe 的相对拒绝。
    let err = plan_enable_on(
        AutostartTarget::WindowsRunKey,
        &fixture_home(),
        "com.tianshu.relay",
        Path::new("relative/exe"),
        true,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Store(_)));
    assert!(
        err.to_string().contains("绝对路径"),
        "文案要说明拒绝原因: {err}"
    );
}

#[test]
fn notify_windows_toast_argv_has_no_profile_noninteractive_and_doubled_quotes() {
    use tianshu_relay_core::notify::{system_command, Notification, NotifyKind, NotifyPlatform};

    // system_command 是纯函数（cfg! 分派），macOS 上可注入 NotifyPlatform::Windows 断言
    // Windows toast 的 argv。模块内测（system.rs）已有更细覆盖，本条是 platform_parity
    // 跨文件守护：即使 system.rs 测试被误删，这里仍守住三标志 + 单引号翻倍。
    let n = Notification {
        kind: NotifyKind::NeedsLogin,
        site_id: Some(1),
        title: "it's".to_string(),
        body: "ok".to_string(),
        ts: 1,
    };
    let (program, args) = system_command(NotifyPlatform::Windows, &n).expect("Windows 有命令");
    assert_eq!(program, "powershell");
    assert_eq!(args[0], "-NoProfile", "不加载用户 profile: {args:?}");
    assert_eq!(args[1], "-NonInteractive", "不进交互 REPL: {args:?}");
    assert_eq!(args[2], "-Command", "走 -Command 执行 toast 脚本: {args:?}");
    assert_eq!(args.len(), 4, "argv 个数稳定: {args:?}");
    assert!(
        args[3].contains("it''s"),
        "ps_literal 单引号翻倍（不做变量插值）: {}",
        args[3]
    );
}

#[test]
fn proxy_reg_query_argv_shape_is_stable() {
    // reg_query_value 在 #[cfg(target_os = "windows")] 块内，macOS 不编译，
    // 退化为 source 断言：argv 形状 + cfg 门 + 纯函数解析在场。真机执行留 CI（B-66）。
    let src = fs::read_to_string(src_dir().join("proxy.rs")).expect("读 proxy.rs");
    let production = production_part(&src);
    assert!(
        production.contains("Command::new(\"reg\")"),
        "Windows 分支应跑 reg 进程"
    );
    assert!(
        production.contains(".args([\"query\", key, \"/v\", name])"),
        "reg query argv 形状稳定"
    );
    assert!(
        production.contains("#[cfg(target_os = \"windows\")]"),
        "reg 调用必须在 Windows cfg 块内（macOS 不编译）"
    );
    assert!(
        production.contains("parse_reg_query_value"),
        "输出解析走跨平台纯函数"
    );
}

#[test]
fn keychain_describe_exhaustive_branches() {
    // describe 是私有 fn（集成测试调不到），退化为 source 断言：穷举 match arm 在场 +
    // non_exhaustive 兜底在场。运行级「真喂 keyring::Error 变体验文案不回显密钥」在
    // keychain.rs mod tests 的 describe_never_echoes_payload_bytes 已覆盖 BadEncoding/
    // BadDataFormat；其余变体留 CI。见 spec §6.1 / §7.1。
    let src = fs::read_to_string(src_dir().join("vault/keychain.rs")).expect("读 keychain.rs");
    let production = production_part(&src);
    assert!(production.contains("fn describe("), "describe 函数在场");
    // 穷举 match arm：缺一个就说明新增了未兜底的 keyring::Error 变体
    for arm in [
        "NoEntry",
        "NoStorageAccess",
        "PlatformFailure",
        "NoDefaultStore",
        "NotSupportedByStore",
        "BadEncoding",
        "BadDataFormat",
        "BadStoreFormat",
        "TooLong",
        "Invalid",
        "Ambiguous",
    ] {
        assert!(
            production.contains(arm),
            "describe 缺少 {arm} 分支（keyring::Error 穷举不完整）"
        );
    }
    // non_exhaustive 兜底文案在场（keyring::Error 是 #[non_exhaustive]）
    assert!(
        production.contains("系统钥匙串返回了未知错误"),
        "describe 必须有 non_exhaustive 兜底分支"
    );
}
