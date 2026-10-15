//! list-channels 对账 + mock-agent 双态 + list-keys。
//!
//! `mock-agent`：对「apply --smoke 注入后的配置」exit 0；对「不存在」exit 2；
//! 对「存在但缺密钥字段」exit 1。list-keys 对 seeded store 输出含 key 行。

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use keyrelay_core::delivery::DeliveryChannel;

fn cli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyrelay-cli"))
}

#[test]
fn list_channels_matches_all_exactly() {
    let out = Command::new(cli_bin())
        .arg("list-channels")
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let got: Vec<&str> = std::str::from_utf8(&out.stdout).unwrap().lines().collect();
    let want: Vec<&str> = DeliveryChannel::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(got, want);
    assert_eq!(got.len(), DeliveryChannel::ALL.len());
    assert_eq!(got.len(), 11, "M14-S1 起 11 通道");
}

#[test]
fn mock_agent_fatal_when_file_absent() {
    let dir = tempfile::tempdir().expect("tmp");
    let out = Command::new(cli_bin())
        .args([
            "mock-agent",
            "--channel",
            "codex-auth-json",
            "--home",
            dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2), "{:?}", out.stderr);
}

#[test]
fn mock_agent_ok_after_smoke_apply_for_every_channel() {
    for channel in DeliveryChannel::ALL {
        let dir = tempfile::tempdir().expect("tmp");
        let home = dir.path().join("home");
        let store = dir.path().join("keyrelay.db");
        let backup = dir.path().join("backups");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&backup).unwrap();

        // M14-S1 起 Continue 已删，11 通道均不要求 model。
        let model_arg: Vec<&str> = Vec::new();
        let apply = Command::new(cli_bin())
            .args([
                "apply-delivery",
                "--channel",
                channel.as_str(),
                "--smoke",
                "--home",
                home.to_str().unwrap(),
                "--store",
                store.to_str().unwrap(),
                "--backup-dir",
                backup.to_str().unwrap(),
            ])
            .args(model_arg)
            .env("KEYRELAY_REAL_KEY", "sk-test-0123456789abcdef")
            .output()
            .expect("spawn");
        assert!(
            apply.status.success(),
            "{} apply 失败: {:?}",
            channel.as_str(),
            String::from_utf8_lossy(&apply.stderr)
        );

        let mock = Command::new(cli_bin())
            .args([
                "mock-agent",
                "--channel",
                channel.as_str(),
                "--home",
                home.to_str().unwrap(),
            ])
            .output()
            .expect("spawn");
        assert_eq!(
            mock.status.code(),
            Some(0),
            "{} mock-agent 应 exit 0（注入后密钥字段在）: {:?}",
            channel.as_str(),
            String::from_utf8_lossy(&mock.stderr)
        );
    }
}

#[test]
fn mock_agent_keymissing_when_field_absent() {
    // 文件存在、可解析、但缺密钥字段 ⇒ exit 1。
    let dir = tempfile::tempdir().expect("tmp");
    let home = dir.path().join("home");
    let cfg = home.join(".codex").join("auth.json");
    fs::create_dir_all(cfg.parent().unwrap()).unwrap();
    fs::write(&cfg, r#"{"auth_mode":"apikey"}"#).unwrap(); // 缺 OPENAI_API_KEY

    let out = Command::new(cli_bin())
        .args([
            "mock-agent",
            "--channel",
            "codex-auth-json",
            "--home",
            home.to_str().unwrap(),
        ])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(1), "{:?}", out.stderr);
}

#[test]
fn list_keys_outputs_seeded_key_without_secret() {
    let dir = tempfile::tempdir().expect("tmp");
    let home = dir.path().join("home");
    let store = dir.path().join("keyrelay.db");
    let backup = dir.path().join("backups");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&backup).unwrap();

    // 先 --smoke apply 建一把 key（不 rollback，留着给 list-keys 看）
    let apply = Command::new(cli_bin())
        .args([
            "apply-delivery",
            "--channel",
            "codex-auth-json",
            "--smoke",
            "--home",
            home.to_str().unwrap(),
            "--store",
            store.to_str().unwrap(),
            "--backup-dir",
            backup.to_str().unwrap(),
        ])
        .env("KEYRELAY_REAL_KEY", "sk-test-0123456789abcdef")
        .output()
        .expect("spawn");
    assert!(apply.status.success(), "{:?}", apply.stderr);

    let list = Command::new(cli_bin())
        .args(["list-keys", "--store", store.to_str().unwrap()])
        .output()
        .expect("spawn");
    assert!(list.status.success(), "{:?}", list.stderr);
    let out = String::from_utf8_lossy(&list.stdout);
    // 表头 + 至少一行 smoke key
    assert!(out.contains("id\tname\tsite_id"), "表头: {out}");
    assert!(out.contains("smoke/seed"), "应有 smoke key 行: {out}");
    // 不含明文密钥
    assert!(
        !out.contains("sk-test-0123456789abcdef"),
        "list-keys 不得含明文: {out}"
    );
}
