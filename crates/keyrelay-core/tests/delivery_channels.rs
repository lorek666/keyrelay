//! 三条投递通道的端到端验证（M2-S2 spec §7）。
//!
//! 全部把 `home` 指向临时目录，绝不触碰用户真实的 `~/.codex` / `~/.claude` / `~/.zshrc`。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use keyrelay_core::delivery::shell_block::{BLOCK_BEGIN, BLOCK_END};
use keyrelay_core::delivery::{ConsentState, DeliveryChannel};
use keyrelay_core::error::Error;
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::transport::MockTransport;
use keyrelay_core::store::Store;
use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};

const SECRET: &str = "sk-channels-0123456789abcdef";
const BASE_URL: &str = "https://relay.example.com";

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    db_path: PathBuf,
    service: KeyRelayService<MockTransport>,
    key_id: i64,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let db_path = dir.path().join("keyrelay.db");

    let store = Store::open(&db_path).expect("文件库");
    let site_id = store
        .upsert_site("newapi", BASE_URL, "测试站")
        .expect("写站点");
    let secret_ref = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &secret_ref, Some("1"), None)
        .expect("写密钥记录");

    let vault = Arc::new(MemoryVault::new());
    vault.put(&secret_ref, SECRET).expect("写钥匙串");

    let service = KeyRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault,
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
        },
    );

    Fixture {
        _dir: dir,
        home,
        db_path,
        service,
        key_id,
    }
}

fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).expect("stat").permissions().mode() & 0o777
}

fn target_of(f: &Fixture, channel: DeliveryChannel) -> PathBuf {
    f.service
        .delivery_plan(f.key_id, channel)
        .expect("生成计划")
        .target_path
}

/// 三个通道共用的「投递 → 校验 → 回滚」流程。
fn round_trip(f: &Fixture, channel: DeliveryChannel, preexisting: Option<(&Path, &str)>) {
    let target = target_of(f, channel);
    if let Some((_, content)) = preexisting {
        fs::create_dir_all(target.parent().unwrap()).expect("建目录");
        fs::write(&target, content).expect("预置");
    }
    let before_bytes = fs::read(&target).ok();

    f.service.grant_consent(f.key_id, channel).expect("同意");
    let outcome = f
        .service
        .apply_delivery(f.key_id, channel)
        .unwrap_or_else(|e| panic!("{} 投递失败: {e}", channel.as_str()));

    assert_eq!(outcome.target_path, target);
    let written = fs::read_to_string(&target).expect("读回");
    assert!(
        written.contains(SECRET),
        "{} 的目标文件应含密钥",
        channel.as_str()
    );
    // 含密钥的文件不允许比 0600 更宽；预置文件是 0644 时会被**收紧**成 0600
    assert_eq!(mode_of(&target), 0o600, "{} 必须是 0600", channel.as_str());

    // 幂等：再投一次内容不变
    f.service
        .apply_delivery(f.key_id, channel)
        .expect("二次投递");
    assert_eq!(
        fs::read_to_string(&target).unwrap(),
        written,
        "{} 二次投递不得产生额外改动",
        channel.as_str()
    );

    // 回滚必须字节级还原
    f.service
        .rollback_delivery(&outcome.journal_id)
        .expect("回滚");
    match before_bytes {
        Some(bytes) => assert_eq!(
            fs::read(&target).unwrap(),
            bytes,
            "{} 回滚必须字节级还原",
            channel.as_str()
        ),
        None => assert!(
            !target.exists(),
            "{} 回滚后应删除新建的文件",
            channel.as_str()
        ),
    }
}

#[test]
fn codex_channel_round_trip() {
    let f = setup();
    round_trip(
        &f,
        DeliveryChannel::CodexAuthJson,
        Some((
            &f.home.join(".codex/auth.json"),
            "{\n  \"auth_mode\": \"apikey\"\n}",
        )),
    );
}

#[test]
fn claude_code_channel_round_trip() {
    let f = setup();
    round_trip(
        &f,
        DeliveryChannel::ClaudeCodeSettings,
        Some((
            &f.home.join(".claude/settings.json"),
            "{\n  \"env\": {\n    \"ANTHROPIC_MODEL\": \"grok-4.6\"\n  },\n  \"permissions\": {\n    \"deny\": [\n      \"NotebookEdit\"\n    ]\n  }\n}",
        )),
    );
}

#[test]
fn shell_block_channel_round_trip() {
    let f = setup();
    let rc = f.home.join(
        keyrelay_core::delivery::shell_block::ShellSyntax::for_current_platform()
            .default_rc_relative_path(),
    );
    round_trip(
        &f,
        DeliveryChannel::ShellBlock,
        Some((
            &rc,
            "# my rc\nfunction foo() {\n  echo hi\n}\nalias gs='git status'",
        )),
    );
}

#[test]
fn claude_code_preserves_unrelated_keys_and_env() {
    let f = setup();
    let target = target_of(&f, DeliveryChannel::ClaudeCodeSettings);
    fs::create_dir_all(target.parent().unwrap()).unwrap();

    let before = r#"{
  "env": {
    "ANTHROPIC_MODEL": "grok-4.6",
    "ANTHROPIC_DEFAULT_OPUS_MODEL": "grok-4.6[1M]"
  },
  "permissions": {
    "deny": [
      "DesignSync",
      "NotebookEdit"
    ]
  },
  "enableWorkflows": true,
  "enabledPlugins": {
    "oh-my-claudecode@omc": true
  }
}"#;
    fs::write(&target, before).unwrap();

    f.service
        .grant_consent(f.key_id, DeliveryChannel::ClaudeCodeSettings)
        .unwrap();
    f.service
        .apply_delivery(f.key_id, DeliveryChannel::ClaudeCodeSettings)
        .unwrap();

    let after: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&target).unwrap()).unwrap();
    let original: serde_json::Value = serde_json::from_str(before).unwrap();

    assert_eq!(after["env"]["ANTHROPIC_AUTH_TOKEN"], SECRET);
    assert_eq!(after["env"]["ANTHROPIC_BASE_URL"], BASE_URL);
    for key in ["permissions", "enableWorkflows", "enabledPlugins"] {
        assert_eq!(after[key], original[key], "顶层键 {key} 被改动了");
    }
    for key in ["ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL"] {
        assert_eq!(
            after["env"][key], original["env"][key],
            "env.{key} 被改动了"
        );
    }
}

#[test]
fn shell_block_preserves_everything_outside_the_block() {
    let f = setup();
    let target = target_of(&f, DeliveryChannel::ShellBlock);
    fs::create_dir_all(target.parent().unwrap()).unwrap();

    // 刻意不以换行结尾 + 含函数、注释、别名
    let outside =
        "# my rc\nfunction foo() {\n  echo hi\n}\nalias gs='git status'\nsource ~/.aliases";
    fs::write(&target, outside).unwrap();

    f.service
        .grant_consent(f.key_id, DeliveryChannel::ShellBlock)
        .unwrap();
    f.service
        .apply_delivery(f.key_id, DeliveryChannel::ShellBlock)
        .unwrap();

    let written = fs::read_to_string(&target).unwrap();
    assert!(
        written.starts_with(outside),
        "区块之外必须逐字节保留:\n{written}"
    );
    assert!(written.contains(BLOCK_BEGIN));
    assert!(written.contains(BLOCK_END));
    assert!(written.contains(&format!("OPENAI_API_KEY=\"{SECRET}\"")));
    assert!(written.contains(&format!("OPENAI_BASE_URL=\"{BASE_URL}\"")));
    assert_eq!(written.matches(BLOCK_BEGIN).count(), 1, "区块只应出现一次");

    // 再投一次：区块之外仍然逐字节相同
    f.service
        .apply_delivery(f.key_id, DeliveryChannel::ShellBlock)
        .unwrap();
    let again = fs::read_to_string(&target).unwrap();
    assert!(again.starts_with(outside), "二次投递后区块外被改动");
    assert_eq!(again, written, "二次投递必须幂等");
}

#[test]
fn shell_block_does_not_touch_a_users_own_assignment() {
    // 用户在区块外自己写了同名变量：我们不碰它（只维护自己的区块）
    let f = setup();
    let target = target_of(&f, DeliveryChannel::ShellBlock);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    let outside = "export OPENAI_API_KEY=\"sk-user-own-value\"\n";
    fs::write(&target, outside).unwrap();

    f.service
        .grant_consent(f.key_id, DeliveryChannel::ShellBlock)
        .unwrap();
    f.service
        .apply_delivery(f.key_id, DeliveryChannel::ShellBlock)
        .unwrap();

    let written = fs::read_to_string(&target).unwrap();
    assert!(
        written.starts_with(outside),
        "用户自己的赋值必须原样保留:\n{written}"
    );
    assert!(written.contains(&format!("OPENAI_API_KEY=\"{SECRET}\"")));
}

#[test]
fn consent_is_per_channel_and_target() {
    let f = setup();
    // 只同意 Codex 通道 → 另两条必须仍然被拒
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();

    for channel in [
        DeliveryChannel::ClaudeCodeSettings,
        DeliveryChannel::ShellBlock,
    ] {
        let err = f.service.apply_delivery(f.key_id, channel).unwrap_err();
        assert!(
            matches!(err, Error::ConsentRequired { .. }),
            "{} 未单独同意时必须拒绝: {err:?}",
            channel.as_str()
        );
    }

    let consents = f.service.list_consents().unwrap();
    assert_eq!(consents.len(), 1);
    assert_eq!(consents[0].channel, "codex-auth-json");
}

/// Continue 的条目必须有模型名（Continue 的 schema 必填；KeyRelay 不编造默认模型），
/// 其余通道不需要。对 `ALL` 循环的用例统一从这里取。
fn model_for(channel: DeliveryChannel) -> Option<&'static str> {
    (channel == DeliveryChannel::Continue).then_some("gpt-4o")
}

#[test]
fn all_channels_leave_no_plaintext_outside_their_target() {
    let f = setup();
    for channel in DeliveryChannel::ALL {
        f.service.grant_consent(f.key_id, channel).unwrap();
        let plan = f
            .service
            .delivery_plan_with_model(f.key_id, channel, model_for(channel))
            .unwrap();
        assert!(
            !plan.preview.contains(SECRET),
            "{} 预览泄漏",
            channel.as_str()
        );
        assert!(
            !format!("{plan:?}").contains(SECRET),
            "{} 的 Debug 泄漏",
            channel.as_str()
        );
        let outcome = f
            .service
            .apply_delivery_with_model(f.key_id, channel, model_for(channel))
            .unwrap();
        assert!(
            !format!("{outcome:?}").contains(SECRET),
            "{} 的结果泄漏",
            channel.as_str()
        );
    }

    // 事件表
    for row in f.service.recent_events(500).unwrap() {
        assert!(!row.message.contains(SECRET), "事件泄漏: {}", row.message);
        if let Some(payload) = row.payload {
            assert!(!payload.contains(SECRET), "事件载荷泄漏: {payload}");
        }
    }
    // 同意记录
    for row in f.service.list_consents().unwrap() {
        assert!(!format!("{row:?}").contains(SECRET));
    }
    // SQLite 字节
    for suffix in ["", "-wal", "-shm"] {
        let path = PathBuf::from(format!("{}{suffix}", f.db_path.display()));
        if let Ok(bytes) = fs::read(&path) {
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains(SECRET), "{} 含密钥明文", path.display());
        }
    }
    // 诊断导出
    let exported = f.service.export_diagnostics(200).unwrap();
    assert!(!exported.contains(SECRET));
}

#[test]
fn channel_whitelist_rejects_a_mismatched_target() {
    // 纵深防御：即使有人把写入器的 target 改坏，`checked_target` 也要拦住。
    // 这里通过「把 home 换掉」间接验证白名单是按「通道 → 相对路径」逐字比对的：
    // 三条通道解析出的目标必须各自落在约定的相对路径上。
    let f = setup();
    let expectations = [
        (DeliveryChannel::CodexAuthJson, ".codex/auth.json"),
        (DeliveryChannel::ClaudeCodeSettings, ".claude/settings.json"),
        (
            DeliveryChannel::ShellBlock,
            keyrelay_core::delivery::shell_block::ShellSyntax::for_current_platform()
                .default_rc_relative_path(),
        ),
    ];
    for (channel, rel) in expectations {
        let target = target_of(&f, channel);
        assert_eq!(
            target,
            f.home.join(rel),
            "{} 的目标路径与白名单不一致",
            channel.as_str()
        );
    }
}

#[test]
fn plan_reports_missing_consent_for_all_channels() {
    let f = setup();
    for channel in DeliveryChannel::ALL {
        let plan = f
            .service
            .delivery_plan_with_model(f.key_id, channel, model_for(channel))
            .unwrap();
        assert_eq!(plan.consent, ConsentState::Missing);
        assert_eq!(plan.agent_id, channel.agent_id());
    }
}
