//! 参数解析与退出码：exit 2 = 参数/前置不满足（没跑），exit 1 = 运行失败。
//!
//! 这些用例不依赖真钥匙串、不联网——只验 argv 分支与错误文案。

use std::process::Command;

use tianshu_relay_core::delivery::DeliveryChannel;

fn cli_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_tianshu-relay-cli"))
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(cli_bin())
        .args(args)
        .output()
        .expect("spawn cli")
}

/// 测试进程眼中的真实 home：Unix 为 `$HOME`，Windows 为 `USERPROFILE`
///（Windows CI 默认不设 `HOME`）。
///
/// 关键：CLI 的 `resolve_home` / `is_real_home` 只认 `--home` /
/// `TIANSHU_RELAY_HOME` / `HOME`，不认 `USERPROFILE`（spec M14-S4 §12 已记录
/// CLI 侧未复刻 core `platform::home_dir` 的 Windows 分支）。所以只给
/// `--home <USERPROFILE>` 是不够的——子进程的 `HOME` 未设时 `is_real_home`
/// 直接返回 false，防呆根本不会触发；必须把同一值显式写进子进程的 `HOME`。
fn real_home() -> String {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .expect("测试需要 $HOME（Windows 下为 USERPROFILE）")
}

#[test]
fn no_subcommand_exits_2() {
    let out = run(&[]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn unknown_subcommand_exits_2() {
    let out = run(&["frobnicate"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn apply_delivery_needs_key_id_or_smoke() {
    let out = run(&["apply-delivery", "--channel", "codex-auth-json"]);
    assert_eq!(out.status.code(), Some(2), "{:?}", out.stderr);
}

#[test]
fn apply_delivery_smoke_and_key_id_are_mutually_exclusive() {
    let out = run(&[
        "apply-delivery",
        "--channel",
        "codex-auth-json",
        "--smoke",
        "--key-id",
        "1",
        "--home",
        "/tmp/whatever",
    ]);
    assert_eq!(out.status.code(), Some(2), "{:?}", out.stderr);
}

#[test]
fn apply_delivery_smoke_rejects_default_home_without_escape_flag() {
    // 既不给 --home，也不设 TIANSHU_RELAY_HOME ⇒ 会落到 $HOME ⇒ 防呆 exit 2。
    // Windows 下父进程本就没有 HOME，子进程默认继承不到：必须显式把真实
    // home 写进子进程 HOME，否则 resolve_home 先报“无法确定 home”，
    // exit 2 虽对、文案里却没有逃逸阀提示，断言失败。
    let out = Command::new(cli_bin())
        .args(["apply-delivery", "--channel", "codex-auth-json", "--smoke"])
        .env_remove("TIANSHU_RELAY_HOME")
        .env("HOME", real_home())
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2), "{:?}", out.stderr);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("i-know-this-is-real-home"),
        "防呆文案应提示逃逸阀"
    );
}

#[test]
fn apply_delivery_smoke_rejects_explicit_home_equal_to_real_home() {
    // P2-1：显式 --home $HOME 也应拒（除非逃逸阀）。
    // Windows 下光有 --home 还不够：is_real_home 只比对子进程 HOME，
    // 不认 USERPROFILE，所以必须同时把同一值写进子进程 HOME。
    let real_home = real_home();
    let out = Command::new(cli_bin())
        .args([
            "apply-delivery",
            "--channel",
            "codex-auth-json",
            "--smoke",
            "--home",
            &real_home,
        ])
        .env("HOME", &real_home)
        .env_remove("TIANSHU_RELAY_HOME")
        .env("TIANSHU_RELAY_REAL_KEY", "sk-0123456789abcdef")
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2), "{:?}", out.stderr);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("i-know-this-is-real-home"),
        "应提示逃逸阀: {err}"
    );
    assert!(
        err.contains("真实 home") || err.contains("$HOME"),
        "应说明是真实 home 防呆: {err}"
    );
}

#[test]
fn apply_delivery_smoke_allows_temp_home_and_fails_at_key_check() {
    // P2-1 反向：--home <temp> 不被防呆误拒；缺 TIANSHU_RELAY_REAL_KEY ⇒ exit 2（key 校验，非 home 防呆）。
    let dir = tempfile::tempdir().expect("tmp");
    let temp_home = dir.path().to_str().unwrap().to_string();
    let out = Command::new(cli_bin())
        .args([
            "apply-delivery",
            "--channel",
            "codex-auth-json",
            "--smoke",
            "--home",
            &temp_home,
        ])
        .env_remove("TIANSHU_RELAY_HOME")
        .env_remove("TIANSHU_RELAY_REAL_KEY")
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2), "{:?}", out.stderr);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("TIANSHU_RELAY_REAL_KEY"),
        "temp home 应放过防呆、落到 key 校验: {err}"
    );
    assert!(
        !err.contains("i-know-this-is-real-home"),
        "temp home 不应触发真实 home 防呆: {err}"
    );
}

#[test]
fn apply_delivery_smoke_escape_flag_passes_home_check_but_no_key_still_fails() {
    // 逃逸阀放行 home 检查，但没给 TIANSHU_RELAY_REAL_KEY ⇒ 仍在 key 校验前？
    // 实际顺序：resolve_home（含逃逸阀）在 TIANSHU_RELAY_REAL_KEY 读取之前；
    // 逃逸阀放行后，下一步读 TIANSHU_RELAY_REAL_KEY，缺失 ⇒ exit 2。
    // Windows 下必须先给子进程一个 HOME：否则 resolve_home 在 key 校验之前
    // 就以“无法确定 home” exit 2，断言里要的 REAL_KEY 文案永远到不了。
    // HOME 指向临时目录本身：解析出的 home == HOME，逃逸阀是真被行使了
    // （无逃逸阀时此处应先触发防呆），而非被绕过。
    let dir = tempfile::tempdir().expect("tmp");
    let out = Command::new(cli_bin())
        .args([
            "apply-delivery",
            "--channel",
            "codex-auth-json",
            "--smoke",
            "--i-know-this-is-real-home",
        ])
        .env_remove("TIANSHU_RELAY_HOME")
        .env("HOME", dir.path())
        .env_remove("TIANSHU_RELAY_REAL_KEY")
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2), "{:?}", out.stderr);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("TIANSHU_RELAY_REAL_KEY"),
        "应提示缺 TIANSHU_RELAY_REAL_KEY"
    );
}

#[test]
fn apply_delivery_unknown_channel_exits_2() {
    let out = run(&[
        "apply-delivery",
        "--channel",
        "no-such-channel",
        "--smoke",
        "--home",
        "/tmp/x",
    ]);
    assert_eq!(out.status.code(), Some(2), "{:?}", out.stderr);
}

#[test]
fn rollback_delivery_needs_journal() {
    let out = run(&["rollback-delivery", "--store", "/tmp/x.db"]);
    assert_eq!(out.status.code(), Some(2), "{:?}", out.stderr);
}

#[test]
fn list_channels_exits_0_and_lists_all() {
    let out = run(&["list-channels"]);
    assert!(out.status.success(), "{:?}", out.stderr);
    let lines: Vec<&str> = std::str::from_utf8(&out.stdout)
        .expect("utf8")
        .lines()
        .collect();
    let expected: Vec<&str> = DeliveryChannel::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(
        lines, expected,
        "list-channels 应与 DeliveryChannel::ALL 逐字一致"
    );
    assert_eq!(lines.len(), DeliveryChannel::ALL.len());
    assert_eq!(lines.len(), 28, "新增 8 条通道后 list-channels 应有 28 条");
}
