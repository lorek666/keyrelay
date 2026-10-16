//! M16-S2 核心守护：**三出口一致性**（事件表 / 诊断包 / 配置导出）+ P2-26 判据。
//!
//! 复跑：
//! ```text
//! CARGO_TARGET_DIR=/Volumes/Date/kr-t-redact CARGO_BUILD_JOBS=4 \
//!   cargo test -p keyrelay-core --test redact_three_exits
//! ```
//!
//! 为什么要有这个文件：DEBUG-REPORT-v3 P2-25 的症状是「同一份输入，不同出口的脱敏结果
//! 不一样」。修法是把三个出口收敛到 `redact` 的**同一套实现**；这个文件是那条收敛的
//! 守护——它比的是**逐字节相等**，不是「都掩了」。

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use keyrelay_core::drift::DriftState;
use keyrelay_core::notify::{encode_snapshot, BalanceSnapshot, DriftFact, SiteSnapshot, Snapshot};
use keyrelay_core::observability::{self, Level};
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::transport::MockTransport;
use keyrelay_core::store::Store;
use keyrelay_core::vault::MemoryVault;

const HOST: &str = "relay.example.com";

struct Fixture {
    _dir: tempfile::TempDir,
    db_path: PathBuf,
    service: KeyRelayService<MockTransport>,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let db_path = dir.path().join("keyrelay.db");
    let store = Store::open(&db_path).expect("文件库");
    let service = KeyRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault: Arc::new(MemoryVault::new()),
            home,
            backup_dir: dir.path().join("backups"),
        },
    );
    Fixture {
        _dir: dir,
        db_path,
        service,
    }
}

/// 六个输入：覆盖「URL 形态 / 口令形态 / 敏感键 / 引用形态 / 邮箱 / 真密钥 / 普通 key 名」。
///
/// 每条都返回 `(原始 message, 原始 payload)`；写库走 `observability` 的两个入口
/// （与 `service.rs` 的写入路径同一套函数）。
fn inputs() -> Vec<(String, Option<serde_json::Value>)> {
    vec![
        (
            format!("登录失败：见 https://carol:p\"ass@{HOST}/x"),
            Some(serde_json::json!({ "url": format!("见 https://carol:p\"ass@{HOST}/x") })),
        ),
        (
            "带载荷的普通文案".to_string(),
            Some(serde_json::json!({ "password": "hunter2", "key_id": 7 })),
        ),
        (
            "钥匙串引用 kr/key/1/secret 不在".to_string(),
            Some(serde_json::json!({ "secret_ref": "kr/key/1/secret" })),
        ),
        ("请联系 me@example.com 处理".to_string(), None),
        ("密钥 sk-abcdefgh12345678 已失效".to_string(), None),
        (
            "站点 task-scheduler 与 desk-assistant 正常".to_string(),
            None,
        ),
        // P3-22 的两种畸形形态：三个出口必须一致（都由同一套实现处理）
        (
            format!("探测失败：见 {HOST}/x?next=https://carol:pw@hook.example.com"),
            None,
        ),
        (
            format!("站点地址 carol:p/ss@{HOST} 不可用"),
            Some(serde_json::json!({ "url": format!("carol:p/ss@{HOST}") })),
        ),
    ]
}

/// 把六个输入写进事件表（**经过写入路径**），返回库里的原文。
fn write_events(f: &Fixture) -> Vec<(String, Option<String>)> {
    let writer = Store::open(&f.db_path).expect("写连接");
    let mut stored = Vec::new();
    for (message, payload) in inputs() {
        let event = match payload {
            Some(value) => observability::event_with_payload(Level::Info, "site", &message, value),
            None => observability::event(Level::Info, "site", &message),
        };
        writer.insert_event(&event).expect("写事件");
        stored.push((event.message.clone(), event.payload.clone()));
    }
    stored
}

/// 出口 A：事件表原文（直接读库，不经任何出口再加工）。
fn exit_a(f: &Fixture) -> Vec<(String, Option<String>)> {
    f.service
        .recent_events(200)
        .expect("读事件表")
        .into_iter()
        .map(|row| (row.message, row.payload))
        .collect()
}

/// 出口 B：诊断包。
fn exit_b(f: &Fixture) -> Vec<(String, Option<String>)> {
    let text = f.service.export_diagnostics(200).expect("诊断包");
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("诊断包是 JSON");
    parsed["events"]
        .as_array()
        .expect("events 数组")
        .iter()
        .map(|row| {
            (
                row["message"].as_str().unwrap_or_default().to_string(),
                row["payload"].as_str().map(str::to_string),
            )
        })
        .collect()
}

/// 出口 C：配置导出。
fn exit_c(f: &Fixture) -> Vec<(String, Option<String>)> {
    let bundle = f.service.export_bundle().expect("导出包");
    let text = keyrelay_core::export::to_json(&bundle).expect("序列化导出包");
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("导出包是 JSON");
    parsed["events"]
        .as_array()
        .expect("events 数组")
        .iter()
        .map(|row| {
            (
                row["message"].as_str().unwrap_or_default().to_string(),
                row["payload"].as_str().map(str::to_string),
            )
        })
        .collect()
}

fn sorted(mut rows: Vec<(String, Option<String>)>) -> Vec<(String, Option<String>)> {
    rows.sort();
    rows
}

/// **本道的核心判据**：同一份输入在三个出口的脱敏结果逐字节一致。
#[test]
fn three_exits_agree_on_every_input() {
    let f = setup();
    let stored = write_events(&f);
    let a = sorted(exit_a(&f));
    let b = sorted(exit_b(&f));
    let c = sorted(exit_c(&f));

    println!("[三出口] A 事件表   = {a:#?}");
    println!("[三出口] B 诊断包   = {b:#?}");
    println!("[三出口] C 配置导出 = {c:#?}");

    assert_eq!(
        a,
        sorted(stored),
        "事件表原文与写入路径的返回值不一致（读回来变了？）"
    );
    assert_eq!(a, b, "事件表与诊断包不一致 —— 三出口必须同一套实现");
    assert_eq!(b, c, "诊断包与配置导出不一致 —— 三出口必须同一套实现");

    // 六个输入里该掩的都掩了（否则「一致」可能只是「一致地漏」）
    let flat = format!("{a:?}");
    for leaked in [
        "hunter2",
        "kr/key/1/secret",
        "sk-abcdefgh12345678",
        "carol:p",
    ] {
        assert!(
            !flat.contains(leaked),
            "三出口一致地漏了「{leaked}」: {flat}"
        );
    }
    // 不该被掩的仍在（否则「一致」是「一致地全删」）
    for kept in [
        "key_id",
        "task-scheduler",
        "desk-assistant",
        "relay.example.com",
    ] {
        assert!(flat.contains(kept), "「{kept}」被过度脱敏: {flat}");
    }
}

/// **老行**（未经当前写入路径落库的行）：出口侧必须自己掩得住。
///
/// 这条对应 DEBUG-REPORT-v3 P2-25 里「原样落库」的那一半：库里可能已经躺着旧版本写下的
/// 明文行，清洗工具（`store` 侧）与导出出口都调本道的统一实现，因此它们必须能独立掩住。
#[test]
fn legacy_rows_are_masked_by_the_export_exits() {
    let f = setup();
    let raw_message = format!("旧版本写的：见 https://carol:p\"ass@{HOST}/x");
    let raw_payload =
        serde_json::json!({ "password": "hunter2", "ref": "kr/key/1/secret" }).to_string();
    Store::open(&f.db_path)
        .expect("写连接")
        .insert_event(&keyrelay_core::observability::Event {
            ts: 0,
            level: Level::Info,
            source: "site".to_string(),
            message: raw_message.clone(),
            payload: Some(raw_payload.clone()),
        })
        .expect("写老行");

    let b = exit_b(&f);
    let c = exit_c(&f);
    for (name, rows) in [("诊断包", &b), ("配置导出", &c)] {
        let flat = format!("{rows:?}");
        assert!(
            !flat.contains("p\\\"ass") && !flat.contains("carol:p"),
            "{name} 漏了带引号口令: {flat}"
        );
        assert!(!flat.contains("hunter2"), "{name} 漏了敏感键的值: {flat}");
        assert!(
            !flat.contains("kr/key/1/secret"),
            "{name} 漏了引用形态: {flat}"
        );
        assert!(
            flat.contains("relay.example.com"),
            "{name} 把主机名也删了: {flat}"
        );
    }
    // 两个出口对同一条老行的结果必须一致
    let pick = |rows: &[(String, Option<String>)]| {
        rows.iter()
            .find(|(message, _)| message.contains("旧版本写的"))
            .cloned()
            .expect("老行在场")
    };
    assert_eq!(pick(&b), pick(&c), "两个出口对老行的结果不一致");
}

/// 幂等：写入路径掩一次、出口再掩一次，结果不得变。
#[test]
fn two_layers_are_idempotent_end_to_end() {
    let f = setup();
    write_events(&f);
    let once = sorted(exit_b(&f));
    // 把出口的产物当成新的「库内容」再走一遍出口（等价于两层叠加）
    let twice: Vec<(String, Option<String>)> = once
        .iter()
        .map(|(message, payload)| {
            (
                keyrelay_core::redact::scrub_event_message(message),
                keyrelay_core::redact::scrub_event_payload(payload.as_deref()),
            )
        })
        .collect();
    assert_eq!(sorted(twice), once, "两层叠加必须逐字节不变");
}

/// P2-26 判据：普通 key 名（`desk-assistant` / `task-scheduler`）能编出基线，真密钥仍拒编。
#[test]
fn p2_26_lookalikes_encode_and_real_keys_still_refuse() {
    let snapshot_with = |name: &str| Snapshot {
        sites: vec![SiteSnapshot {
            site_id: 1,
            display_name: name.to_string(),
            balance: Some(BalanceSnapshot {
                remaining: 3.5,
                used: 20.0,
                currency: "USD".to_string(),
            }),
            needs_login: false,
            quota_exceeded: false,
            models: Some(vec!["gpt-4".to_string()]),
            drift: vec![DriftFact {
                target_path: "/Users/me/.codex/auth.json".to_string(),
                agent_id: "codex".to_string(),
                channel: "codex_auth_json".to_string(),
                state: DriftState::Modified,
            }],
            rotation_due: Vec::new(),
        }],
    };

    for name in ["desk-assistant", "task-scheduler", "普通站点"] {
        assert!(
            encode_snapshot(&snapshot_with(name), 1_760_000_000).is_some(),
            "「{name}」里的 `sk-` 不是密钥前缀，不该让整份基线编不出来（B-81 会被永久关掉）"
        );
    }
    // 对照：真密钥形态仍必须 fail-closed 拒编（不许被顺手放宽）
    assert!(
        encode_snapshot(&snapshot_with("sk-abcdefgh12345678"), 1_760_000_000).is_none(),
        "真密钥形态必须仍然拒编"
    );
    assert!(
        encode_snapshot(&snapshot_with(&"a".repeat(32)), 1_760_000_000).is_none(),
        "32 位 hex 形态必须仍然拒编"
    );
}
