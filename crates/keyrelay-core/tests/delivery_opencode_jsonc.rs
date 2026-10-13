//! M7-S3 集成测试 · `OpenCodeJsonc` 通道（`.config/opencode/opencode.jsonc`）。
//!
//! 核心是 spec §6.2 / D-1：**只接受严格 JSON**。带 JSONC 专有语法（注释 / 尾随逗号）时
//! 明确拒绝并给两条出路——静默丢注释是数据损坏，拒绝不是。

use std::fs;
use std::path::{Path, PathBuf};

use keyrelay_core::delivery::opencode::OpenCodeWriter;
use keyrelay_core::delivery::{resolve_for, DeliveryChannel, DeliveryWriter};
use keyrelay_core::error::Error;

const SECRET: &str = "sk-jsonc-INT-0123456789abcdef";
const BASE: &str = "https://relay.example.com/v1";
const PROVIDER: &str = "keyrelay";

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().expect("临时目录")
}

fn jsonc_in(dir: &Path, base_url: &str, model: Option<&str>) -> OpenCodeWriter {
    OpenCodeWriter::with_path_and_channel(
        dir.join("opencode.jsonc"),
        DeliveryChannel::OpenCodeJsonc,
        PROVIDER,
        base_url,
        model,
    )
}

fn json_in(dir: &Path, base_url: &str, model: Option<&str>) -> OpenCodeWriter {
    OpenCodeWriter::with_path_and_channel(
        dir.join("opencode.json"),
        DeliveryChannel::OpenCode,
        PROVIDER,
        base_url,
        model,
    )
}

// ============================================================ 落点与标识

#[test]
fn channel_targets_the_jsonc_path() {
    let home = Path::new("/tmp/nobody");
    let writer = resolve_for(DeliveryChannel::OpenCodeJsonc, home, BASE).unwrap();
    assert_eq!(
        writer.target_path(),
        home.join(".config").join("opencode").join("opencode.jsonc")
    );
    assert_eq!(
        writer.target_path(),
        home.join(DeliveryChannel::OpenCodeJsonc.relative_target())
    );
    assert_eq!(writer.channel(), DeliveryChannel::OpenCodeJsonc);
    assert_eq!(DeliveryChannel::OpenCodeJsonc.as_str(), "opencode-jsonc");
    // M7-S0 v1.2：必须与 `OpenCode` 可区分——漂移报告靠 `from_agent_id` 反推通道名，
    // 共享 agent_id 会把 `.jsonc` 的漂移归到 `.json` 上。
    assert_eq!(DeliveryChannel::OpenCodeJsonc.agent_id(), "opencode-jsonc");
    assert_ne!(
        DeliveryChannel::OpenCodeJsonc.agent_id(),
        DeliveryChannel::OpenCode.agent_id()
    );
}

#[test]
fn channel_identity_is_not_confused_with_the_json_channel() {
    let dir = tmp();
    assert_eq!(
        jsonc_in(dir.path(), BASE, None).channel(),
        DeliveryChannel::OpenCodeJsonc
    );
    assert_eq!(
        json_in(dir.path(), BASE, None).channel(),
        DeliveryChannel::OpenCode
    );
    assert_ne!(
        DeliveryChannel::OpenCode.relative_target(),
        DeliveryChannel::OpenCodeJsonc.relative_target()
    );
}

// ============================================================ 严格 JSON 可用

#[test]
fn creates_a_new_file_with_the_provider_shape() {
    let dir = tmp();
    let patch = jsonc_in(dir.path(), BASE, Some("gpt-4o"))
        .plan(SECRET)
        .unwrap();
    assert_eq!(patch.before, "");
    assert_eq!(patch.new_file_mode, Some(0o600), "含密钥 → 新建 0600");

    let parsed: serde_json::Value = serde_json::from_str(&patch.after).expect("必须是合法 JSON");
    assert_eq!(parsed["provider"][PROVIDER]["options"]["apiKey"], SECRET);
    assert_eq!(parsed["provider"][PROVIDER]["options"]["baseURL"], BASE);
    assert_eq!(parsed["model"], "gpt-4o");
}

#[test]
fn edits_a_strict_json_file_and_keeps_other_keys() {
    let dir = tmp();
    let path = dir.path().join("opencode.jsonc");
    let before = r#"{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "anthropic": { "options": { "apiKey": "sk-anthropic-user-own" } },
    "keyrelay": { "options": { "baseURL": "https://old.example.com" } }
  },
  "model": "anthropic/claude-sonnet-4"
}"#;
    fs::write(&path, before).unwrap();

    let patch = jsonc_in(dir.path(), BASE, None).plan(SECRET).unwrap();
    let after: serde_json::Value = serde_json::from_str(&patch.after).unwrap();
    let original: serde_json::Value = serde_json::from_str(before).unwrap();

    assert_eq!(after["provider"][PROVIDER]["options"]["apiKey"], SECRET);
    assert_eq!(after["provider"][PROVIDER]["options"]["baseURL"], BASE);
    assert_eq!(
        after["provider"]["anthropic"], original["provider"]["anthropic"],
        "别的 provider 必须逐字保留"
    );
    assert_eq!(after["$schema"], original["$schema"]);
    assert_eq!(
        after["model"], "anthropic/claude-sonnet-4",
        "没给 model 时不得改动已有的 model"
    );
}

#[test]
fn a_url_with_double_slash_inside_a_string_is_not_a_comment() {
    // 反例保护：`https://x//y` 里的 `//` 在字符串内，**不是**注释（hazard 扫描必须字符串感知）
    let dir = tmp();
    let path = dir.path().join("opencode.jsonc");
    fs::write(
        &path,
        r#"{"provider": {"keyrelay": {"options": {"baseURL": "https://x//y"}}}}"#,
    )
    .unwrap();

    let patch = jsonc_in(dir.path(), BASE, None).plan(SECRET).unwrap();
    let after: serde_json::Value = serde_json::from_str(&patch.after).unwrap();
    assert_eq!(after["provider"][PROVIDER]["options"]["apiKey"], SECRET);
}

// ============================================================ 拒绝面（D-1 / O-1）

#[test]
fn refuses_line_comments_with_two_ways_out() {
    let dir = tmp();
    let path = dir.path().join("opencode.jsonc");
    let before = "{\n  // 用户自己的注释\n  \"model\": \"x/y\"\n}\n";
    fs::write(&path, before).unwrap();

    let err = jsonc_in(dir.path(), BASE, None).plan(SECRET).unwrap_err();
    assert!(matches!(err, Error::Inject { .. }), "{err:?}");
    let text = err.to_string();
    assert!(text.contains("行注释"), "{text}");
    assert!(text.contains("两条出路"), "{text}");
    assert!(text.contains("opencode 通道"), "{text}");
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        before,
        "拒绝时磁盘零改动"
    );
}

#[test]
fn refuses_block_comments() {
    let dir = tmp();
    let path = dir.path().join("opencode.jsonc");
    let before = "{\n  /* 块注释 */\n  \"model\": \"x/y\"\n}\n";
    fs::write(&path, before).unwrap();

    let err = jsonc_in(dir.path(), BASE, None).plan(SECRET).unwrap_err();
    assert!(err.to_string().contains("块注释"), "{err}");
    assert_eq!(fs::read_to_string(&path).unwrap(), before);
}

#[test]
fn refuses_trailing_commas() {
    let dir = tmp();
    let path = dir.path().join("opencode.jsonc");
    let before = "{\n  \"model\": \"x/y\",\n}\n";
    fs::write(&path, before).unwrap();

    let err = jsonc_in(dir.path(), BASE, None).plan(SECRET).unwrap_err();
    assert!(err.to_string().contains("尾随逗号"), "{err}");
    assert_eq!(fs::read_to_string(&path).unwrap(), before);
}

#[test]
fn the_json_channel_still_accepts_whatever_it_used_to() {
    // 反例保护：`.json` 通道的行为**不受** D-1 影响（它从来就没有注释语义）
    let dir = tmp();
    let patch = json_in(dir.path(), BASE, None).plan(SECRET).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&patch.after).unwrap();
    assert_eq!(parsed["provider"][PROVIDER]["options"]["apiKey"], SECRET);
}

// ============================================================ 两条通道互不干扰

#[test]
fn jsonc_and_json_do_not_interfere() {
    let dir = tmp();
    let json = dir.path().join("opencode.json");
    let jsonc = dir.path().join("opencode.jsonc");
    fs::write(&json, "{\n  \"model\": \"x/y\"\n}\n").unwrap();
    let json_before = fs::read_to_string(&json).unwrap();

    // 写 `.jsonc` 不动 `.json`
    let patch = jsonc_in(dir.path(), BASE, None).plan(SECRET).unwrap();
    fs::write(&jsonc, &patch.after).unwrap();
    assert_eq!(fs::read_to_string(&json).unwrap(), json_before);

    // 写 `.json` 不动 `.jsonc`
    let jsonc_before = fs::read_to_string(&jsonc).unwrap();
    let patch = json_in(dir.path(), BASE, None).plan(SECRET).unwrap();
    fs::write(&json, &patch.after).unwrap();
    assert_eq!(fs::read_to_string(&jsonc).unwrap(), jsonc_before);
}

#[test]
fn errors_never_echo_the_key() {
    let dir = tmp();
    let path = dir.path().join("opencode.jsonc");
    fs::write(&path, "{\n  // 注释\n}\n").unwrap();
    let err = jsonc_in(dir.path(), BASE, None).plan(SECRET).unwrap_err();
    assert!(!err.to_string().contains(SECRET), "{err}");
}

#[test]
fn writer_target_is_the_declared_relative_target() {
    let home = Path::new("/tmp/nobody");
    let writer = resolve_for(DeliveryChannel::OpenCodeJsonc, home, BASE).unwrap();
    assert_eq!(
        writer.target_path(),
        home.join(DeliveryChannel::OpenCodeJsonc.relative_target())
    );
    assert!(writer.target_path().starts_with(home));
    assert_eq!(
        writer.target_path(),
        PathBuf::from("/tmp/nobody/.config/opencode/opencode.jsonc")
    );
}
