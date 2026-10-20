//! 参数解析与退出码：exit 2 = 参数/前置不满足（没跑），exit 1 = 运行失败。
//!
//! 这些用例不依赖真钥匙串、不联网——只验 argv 分支与错误文案。

use std::process::Command;

use keyrelay_core::delivery::DeliveryChannel;

fn cli_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_keyrelay-cli"))
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(cli_bin())
        .args(args)
        .output()
        .expect("spawn cli")
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
    // 既不给 --home，也不设 KEYRELAY_HOME ⇒ 会落到 $HOME ⇒ 防呆 exit 2。
    let out = Command::new(cli_bin())
        .args(["apply-delivery", "--channel", "codex-auth-json", "--smoke"])
        .env_remove("KEYRELAY_HOME")
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
    let real_home = std::env::var("HOME").expect("测试需要 $HOME");
    let out = Command::new(cli_bin())
        .args([
            "apply-delivery",
            "--channel",
            "codex-auth-json",
            "--smoke",
            "--home",
            &real_home,
        ])
        .env_remove("KEYRELAY_HOME")
        .env("KEYRELAY_REAL_KEY", "sk-0123456789abcdef")
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
    // P2-1 反向：--home <temp> 不被防呆误拒；缺 KEYRELAY_REAL_KEY ⇒ exit 2（key 校验，非 home 防呆）。
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
        .env_remove("KEYRELAY_HOME")
        .env_remove("KEYRELAY_REAL_KEY")
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2), "{:?}", out.stderr);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("KEYRELAY_REAL_KEY"),
        "temp home 应放过防呆、落到 key 校验: {err}"
    );
    assert!(
        !err.contains("i-know-this-is-real-home"),
        "temp home 不应触发真实 home 防呆: {err}"
    );
}

#[test]
fn apply_delivery_smoke_escape_flag_passes_home_check_but_no_key_still_fails() {
    // 逃逸阀放行 home 检查，但没给 KEYRELAY_REAL_KEY ⇒ 仍在 key 校验前？
    // 实际顺序：resolve_home（含逃逸阀）在 KEYRELAY_REAL_KEY 读取之前；
    // 逃逸阀放行后，下一步读 KEYRELAY_REAL_KEY，缺失 ⇒ exit 2。
    let out = Command::new(cli_bin())
        .args([
            "apply-delivery",
            "--channel",
            "codex-auth-json",
            "--smoke",
            "--i-know-this-is-real-home",
        ])
        .env_remove("KEYRELAY_HOME")
        .env_remove("KEYRELAY_REAL_KEY")
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2), "{:?}", out.stderr);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("KEYRELAY_REAL_KEY"),
        "应提示缺 KEYRELAY_REAL_KEY"
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
    assert_eq!(
        lines.len(),
        20,
        "M14-S3 起 19 通道（M25-S1 加 codex-config 变 20）"
    );
}
