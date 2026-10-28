//! list-channels 对账 + mock-agent 双态 + list-keys。
//!
//! `mock-agent`：对「apply --smoke 注入后的配置」exit 0；对「不存在」exit 2；
//! 对「存在但缺密钥字段」exit 1。list-keys 对 seeded store 输出含 key 行。

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use tianshu_relay_core::delivery::DeliveryChannel;

fn cli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tianshu-relay-cli"))
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
    assert_eq!(got.len(), 28, "新增 8 条通道后 list-channels 应有 28 条");
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
        // B-292：ClineDesktop 已下线（文件直写已拒，走 cline auth CLI），
        // smoke 投递不再适用；下线通道的拒绝行为由 core 的下线断言钉住。
        // （与 delivery/mod.rs 里 every_deliverable_channel_resolves 同款处理。）
        if channel == DeliveryChannel::ClineDesktop {
            continue;
        }
        let dir = tempfile::tempdir().expect("tmp");
        let home = dir.path().join("home");
        let store = dir.path().join("tianshu-relay.db");
        let backup = dir.path().join("backups");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&backup).unwrap();

        // P0-3 DSH 引用校验：dsh 投递要求至少一个 profile patch 文件引用
        // KEYRELAY_API_KEY，否则 fail-closed 拒绝；测试里按 spec 例建一个
        // 引用了该凭据的 profile（真实 DSH 用户须自己先在 DSH 里建好）。
        if channel == DeliveryChannel::DeepSeekHarness {
            let profile = home.join(".dsh").join("profiles").join("desktop");
            fs::create_dir_all(&profile).unwrap();
            fs::write(
                profile.join("cordis.patch.yml"),
                "provider:\n  apiKeyEnv: KEYRELAY_API_KEY\n",
            )
            .unwrap();
        }

        // 这些通道的配置条目必须有模型名；其余通道不要求。
        let model_arg: Vec<&str> = if matches!(
            channel,
            DeliveryChannel::Droid
                | DeliveryChannel::CodeBuddy
                | DeliveryChannel::WorkBuddy
                | DeliveryChannel::WorkBuddyAi
                | DeliveryChannel::Crush
                | DeliveryChannel::OpenClaw
        ) {
            vec!["--model", "gpt-4o"]
        } else {
            Vec::new()
        };
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
            .env("TIANSHU_RELAY_REAL_KEY", "sk-test-0123456789abcdef")
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
fn kimi_mock_is_scoped_and_accepts_dotted_toml() {
    let dir = tempfile::tempdir().expect("tmp");
    let home = dir.path().join("home");
    let cfg = home.join(".kimi-code").join("config.toml");
    fs::create_dir_all(cfg.parent().unwrap()).unwrap();

    // 别家 provider 的 api_key 不算 keyrelay 已投递。
    fs::write(
        &cfg,
        r#"default_model = "other/model"
[providers.other]
api_key = "sk-other-2222"
"#,
    )
    .unwrap();
    let out = Command::new(cli_bin())
        .args([
            "mock-agent",
            "--channel",
            "kimi-code",
            "--home",
            home.to_str().unwrap(),
        ])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(1),
        "别家 provider 不应被当成 keyrelay: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    // dotted key + 表头尾随注释都是合法 TOML，且归属 keyrelay。
    fs::write(
        &cfg,
        r#"default_model = "keyrelay/kimi-k3" # keep
providers.keyrelay.api_key = "sk-mine-3333" # old
providers.keyrelay.base_url = "https://old.example.com/v1"
"#,
    )
    .unwrap();
    let out = Command::new(cli_bin())
        .args([
            "mock-agent",
            "--channel",
            "kimi-code",
            "--home",
            home.to_str().unwrap(),
        ])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(0),
        "dotted key 应被识别: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn list_keys_outputs_seeded_key_without_secret() {
    let dir = tempfile::tempdir().expect("tmp");
    let home = dir.path().join("home");
    let store = dir.path().join("tianshu-relay.db");
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
        .env("TIANSHU_RELAY_REAL_KEY", "sk-test-0123456789abcdef")
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
