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
        .to_string()
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
    let expected = vec![
        "autostart.rs".to_string(),
        "delivery/shell_block.rs".to_string(),
        "inject/mod.rs".to_string(),
        "notify/system.rs".to_string(),
        "vault/keychain.rs".to_string(),
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
fn shell_syntax_supports_both_platforms() {
    use keyrelay_core::delivery::shell_block::ShellSyntax;

    // 两个变体都必须存在且各自可用（真机上只会走其中一个，但代码路径都得在）
    for syntax in [ShellSyntax::Posix, ShellSyntax::PowerShell] {
        let rendered = syntax.render_assignment("OPENAI_API_KEY", "sk-x");
        assert!(
            rendered.contains("OPENAI_API_KEY"),
            "{syntax:?} 渲染失败: {rendered}"
        );
        assert!(
            !syntax.default_rc_relative_path().is_empty(),
            "{syntax:?} 缺少默认 rc 路径"
        );
    }
    assert!(ShellSyntax::PowerShell
        .render_assignment("K", "v")
        .starts_with("$env:"));
    assert!(ShellSyntax::Posix
        .render_assignment("K", "v")
        .starts_with("export "));
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
