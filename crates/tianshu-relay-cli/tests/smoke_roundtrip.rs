//! 逐通道 --smoke 三连：apply → mock-agent → rollback → 字节比对。
//!
//! 与 `acceptance_matrix.rs::inject_rollback_roundtrip_is_byte_identical` 同构，
//! 差别在：这里走的是**编译出的 CLI 二进制**（`CARGO_BIN_EXE_tianshu-relay-cli`），
//! 证明 `TianshuRelayService::apply_delivery` / `rollback_delivery` 被可脚本化入口真调到。
//!
//! 两种形态（缺一不可，与 A-2 一致）：
//! - 目标原本不存在 ⇒ 回滚后文件消失；
//! - 目标已存在 ⇒ 回滚后逐字节等于原内容。

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use tianshu_relay_core::delivery::DeliveryChannel;

const REAL_KEY: &str = "sk-test-0123456789abcdef";

/// M14-S1 起 Continue 通道已删，11 通道均不要求 model（OpenCode 系列的 model 是可选）。
/// 保留函数形参以便未来某通道重新要求 model 时只改这一处。
fn model_arg(_channel: DeliveryChannel) -> Vec<&'static str> {
    Vec::new()
}

fn cli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tianshu-relay-cli"))
}

struct Tmp {
    _dir: tempfile::TempDir,
    home: PathBuf,
    store: PathBuf,
    backup: PathBuf,
}

fn tmp() -> Tmp {
    let dir = tempfile::tempdir().expect("tmp");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let store = dir.path().join("tianshu-relay.db");
    let backup = dir.path().join("backups");
    fs::create_dir_all(&backup).expect("backup");
    Tmp {
        _dir: dir,
        home,
        store,
        backup,
    }
}

fn apply_smoke(t: &Tmp, channel: DeliveryChannel) -> String {
    let out = Command::new(cli_bin())
        .args([
            "apply-delivery",
            "--channel",
            channel.as_str(),
            "--smoke",
            "--home",
            t.home.to_str().unwrap(),
            "--store",
            t.store.to_str().unwrap(),
            "--backup-dir",
            t.backup.to_str().unwrap(),
        ])
        .args(model_arg(channel))
        .env("TIANSHU_RELAY_REAL_KEY", REAL_KEY)
        .output()
        .expect("spawn cli");
    assert!(
        out.status.success(),
        "{} apply 失败: exit {:?} stderr={}",
        channel.as_str(),
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let journal = String::from_utf8(out.stdout)
        .expect("utf8")
        .trim()
        .to_string();
    assert!(!journal.is_empty(), "{} journal_id 为空", channel.as_str());
    journal
}

fn mock_ok(t: &Tmp, channel: DeliveryChannel) {
    let out = Command::new(cli_bin())
        .args([
            "mock-agent",
            "--channel",
            channel.as_str(),
            "--home",
            t.home.to_str().unwrap(),
        ])
        .output()
        .expect("spawn cli");
    assert!(
        out.status.success(),
        "{} mock-agent 应 exit 0（密钥字段在）: exit {:?} stderr={}",
        channel.as_str(),
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn rollback(t: &Tmp, channel: DeliveryChannel, journal: &str) {
    let out = Command::new(cli_bin())
        .args([
            "rollback-delivery",
            "--journal",
            journal,
            "--store",
            t.store.to_str().unwrap(),
        ])
        .output()
        .expect("spawn cli");
    assert!(
        out.status.success(),
        "{} rollback 失败: exit {:?} stderr={}",
        channel.as_str(),
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn smoke_roundtrip_target_absent_then_rollback_removes() {
    for channel in DeliveryChannel::ALL {
        let t = tmp();
        let target = t.home.join(channel.relative_target());

        // 形态一：目标不存在 ⇒ apply 创建 → mock ok → rollback 删除
        assert!(!target.exists(), "{} 起点应无目标", channel.as_str());
        let journal = apply_smoke(&t, channel);
        assert!(target.exists(), "{} apply 后目标应存在", channel.as_str());
        mock_ok(&t, channel);
        rollback(&t, channel, &journal);
        assert!(
            !target.exists(),
            "{} 回滚后应删掉自己创建的文件",
            channel.as_str()
        );
    }
}

#[test]
fn smoke_roundtrip_target_present_then_rollback_byte_identical() {
    let original = b"{\n  \"user_comment\": \"keep my own bytes\"\n}\n".to_vec();

    for channel in DeliveryChannel::ALL {
        let t = tmp();
        let target = t.home.join(channel.relative_target());
        // 预置原内容（ASCII，字节比对基准）
        fs::create_dir_all(target.parent().unwrap()).expect("parent");
        fs::write(&target, &original).expect("pre-write");
        let journal = apply_smoke(&t, channel);
        assert_ne!(
            fs::read(&target).expect("read after apply"),
            original,
            "{} apply 应改动文件",
            channel.as_str()
        );
        mock_ok(&t, channel);
        rollback(&t, channel, &journal);
        assert_eq!(
            fs::read(&target).expect("read after rollback"),
            original,
            "{} 回滚后应逐字节还原",
            channel.as_str()
        );
    }
}
