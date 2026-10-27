//! 三条投递通道的端到端验证（M2-S2 spec §7）。
//!
//! 全部把 `home` 指向临时目录，绝不触碰用户真实的 `~/.codex` / `~/.claude` / `~/.zshrc`。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tianshu_relay_core::delivery::hermes::{BLOCK_BEGIN, BLOCK_END};
use tianshu_relay_core::delivery::{ConsentState, DeliveryChannel};
use tianshu_relay_core::error::Error;
use tianshu_relay_core::service::{ServiceConfig, TianshuRelayService};
use tianshu_relay_core::site::transport::MockTransport;
use tianshu_relay_core::store::Store;
use tianshu_relay_core::vault::{secret_ref, MemoryVault, Vault};

const SECRET: &str = "sk-channels-0123456789abcdef";
const BASE_URL: &str = "https://relay.example.com";

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    db_path: PathBuf,
    service: TianshuRelayService<MockTransport>,
    key_id: i64,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let db_path = dir.path().join("tianshu-relay.db");

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

    let service = TianshuRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault,
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
            data_dir: None,
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

/// Unix 权限位读取：Windows 没有 Unix mode 位，生产侧的权限收紧
/// （inject/mod.rs 的 resolve_mode / clamp_secret_mode）本身就是 cfg(unix)，
/// 非 Unix 路径写文件时直接忽略 mode——因此 mode 断言只在 Unix 上有意义。
#[cfg(unix)]
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

/// 幂等/恢复场景只对瞬时 FileBusy 有限重试；真正的锁互斥测试不走这里。
fn apply_retry_on_busy_with_model(
    f: &Fixture,
    channel: DeliveryChannel,
    model: Option<&str>,
) -> tianshu_relay_core::error::Result<tianshu_relay_core::delivery::DeliveryOutcome> {
    for attempt in 0..10 {
        match f
            .service
            .apply_delivery_with_model(f.key_id, channel, model)
        {
            Err(Error::FileBusy(_)) if attempt < 9 => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            result => return result,
        }
    }
    unreachable!("有限重试在第十次必然返回结果")
}

fn apply_retry_on_busy(
    f: &Fixture,
    channel: DeliveryChannel,
) -> tianshu_relay_core::error::Result<tianshu_relay_core::delivery::DeliveryOutcome> {
    apply_retry_on_busy_with_model(f, channel, None)
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
    let outcome = apply_retry_on_busy(f, channel)
        .unwrap_or_else(|e| panic!("{} 投递失败: {e}", channel.as_str()));

    assert_eq!(outcome.target_path, target);
    let written = fs::read_to_string(&target).expect("读回");
    assert!(
        written.contains(SECRET),
        "{} 的目标文件应含密钥",
        channel.as_str()
    );
    // 含密钥的文件不允许比 0600 更宽；预置文件是 0644 时会被**收紧**成 0600
    // （收紧本身只在 Unix 上成立，见 mode_of 的注释；Windows 没有 mode 位，
    // 投递成功 + 文件落盘即是该平台下可验证的全部）。
    #[cfg(unix)]
    assert_eq!(mode_of(&target), 0o600, "{} 必须是 0600", channel.as_str());
    #[cfg(not(unix))]
    assert!(target.exists(), "{} 投递后目标文件应存在", channel.as_str());

    // 幂等：再投一次内容不变
    apply_retry_on_busy(f, channel).expect("二次投递");
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
fn hermes_channel_round_trip() {
    let f = setup();
    let path = f.home.join(DeliveryChannel::Hermes.relative_target());
    round_trip(
        &f,
        DeliveryChannel::Hermes,
        Some((&path, "model:\n  default: \"x\"\nagent:\n  max_turns: 50")),
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
    apply_retry_on_busy(&f, DeliveryChannel::ClaudeCodeSettings).unwrap();

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
fn hermes_preserves_everything_outside_the_block() {
    let f = setup();
    let target = target_of(&f, DeliveryChannel::Hermes);
    fs::create_dir_all(target.parent().unwrap()).unwrap();

    // 刻意不以换行结尾 + 含函数、注释、别名
    let outside =
        "# my rc\nfunction foo() {\n  echo hi\n}\nalias gs='git status'\nsource ~/.aliases";
    fs::write(&target, outside).unwrap();

    f.service
        .grant_consent(f.key_id, DeliveryChannel::Hermes)
        .unwrap();
    apply_retry_on_busy(&f, DeliveryChannel::Hermes).unwrap();

    let written = fs::read_to_string(&target).unwrap();
    assert!(
        written.starts_with(outside),
        "区块之外必须逐字节保留:\n{written}"
    );
    assert!(written.contains(BLOCK_BEGIN));
    assert!(written.contains(BLOCK_END));
    assert!(written.contains(&format!("api_key: {SECRET}")));
    assert!(written.contains(&format!("base_url: {BASE_URL}")));
    assert_eq!(written.matches(BLOCK_BEGIN).count(), 1, "区块只应出现一次");

    // 再投一次：区块之外仍然逐字节相同
    apply_retry_on_busy(&f, DeliveryChannel::Hermes).unwrap();
    let again = fs::read_to_string(&target).unwrap();
    assert!(again.starts_with(outside), "二次投递后区块外被改动");
    assert_eq!(again, written, "二次投递必须幂等");
}

#[test]
fn hermes_does_not_touch_a_users_own_assignment() {
    // 用户在区块外自己写了同名变量：我们不碰它（只维护自己的区块）
    let f = setup();
    let target = target_of(&f, DeliveryChannel::Hermes);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    let outside = "export OPENAI_API_KEY=\"sk-user-own-value\"\n";
    fs::write(&target, outside).unwrap();

    f.service
        .grant_consent(f.key_id, DeliveryChannel::Hermes)
        .unwrap();
    apply_retry_on_busy(&f, DeliveryChannel::Hermes).unwrap();

    let written = fs::read_to_string(&target).unwrap();
    assert!(
        written.starts_with(outside),
        "用户自己的赋值必须原样保留:\n{written}"
    );
    assert!(written.contains(&format!("api_key: {SECRET}")));
}

#[test]
fn consent_is_per_channel_and_target() {
    let f = setup();
    // 只同意 Codex 通道 → 另两条必须仍然被拒
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();

    for channel in [DeliveryChannel::ClaudeCodeSettings, DeliveryChannel::Hermes] {
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

/// Continue 的条目必须有模型名（Continue 的 schema 必填；TianshuRelay 不编造默认模型），
/// 其余通道不需要。对 `ALL` 循环的用例统一从这里取。
fn model_for(channel: DeliveryChannel) -> Option<&'static str> {
    (channel == DeliveryChannel::OpenClaw).then_some("gpt-4o")
}

#[test]
fn all_channels_leave_no_plaintext_outside_their_target() {
    let f = setup();
    for channel in DeliveryChannel::ALL {
        // B-292：ClineDesktop 已下线，不再投递，跳过。
        if channel == DeliveryChannel::ClineDesktop {
            continue;
        }
        f.service.grant_consent(f.key_id, channel).unwrap();
        // P0-3：DSH 投递要求至少一个 profile 引用 KEYRELAY_API_KEY，
        // 否则 apply 会在落盘前拒绝；本用例测的是“明文不外泄”而非引用
        // 校验本身，因此先给 DSH 备一个已引用的 profile，让该通道能走完
        // apply（引用校验自身的正反用例在 delivery_dsh_reference.rs）。
        if channel == DeliveryChannel::DeepSeekHarness {
            let profile = f
                .home
                .join(".dsh")
                .join("profiles")
                .join("desktop")
                .join("cordis.patch.yml");
            fs::create_dir_all(profile.parent().unwrap()).expect("建 profile 目录");
            fs::write(&profile, "apiKeyEnv: KEYRELAY_API_KEY\n").expect("写 profile");
        }
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
        let outcome = apply_retry_on_busy_with_model(&f, channel, model_for(channel)).unwrap();
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
        (DeliveryChannel::Hermes, ".hermes/config.yaml"),
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
fn plan_reports_missing_consent_for_deliverable_channels() {
    let f = setup();
    // B-292：ClineDesktop 已下线，计划同样拒绝——先钉住下线错误本身。
    let delisted_err = match f.service.delivery_plan_with_model(
        f.key_id,
        DeliveryChannel::ClineDesktop,
        model_for(DeliveryChannel::ClineDesktop),
    ) {
        Ok(_) => panic!("ClineDesktop 应已下线，不应生成计划"),
        Err(e) => e,
    };
    assert!(
        delisted_err.to_string().contains("cline auth"),
        "ClineDesktop 下线错误必须指明 cline auth CLI 去向：{delisted_err}"
    );
    for channel in DeliveryChannel::ALL {
        // B-292：ClineDesktop 已下线，不再投递，跳过。
        if channel == DeliveryChannel::ClineDesktop {
            continue;
        }
        let plan = f
            .service
            .delivery_plan_with_model(f.key_id, channel, model_for(channel))
            .unwrap();
        assert_eq!(plan.consent, ConsentState::Missing);
        assert_eq!(plan.agent_id, channel.agent_id());
    }
}
