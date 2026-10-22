//! M6-S1 两条新投递通道的端到端验证：OpenCode（`~/.config/opencode/opencode.json`）
//! 与 Gemini CLI（`~/.gemini/.env`）。
//!
//! 全部把 `home` 指向临时目录，**绝不**触碰用户真实的 `~/.config/opencode` / `~/.gemini`。
//! 与 `tests/delivery_channels.rs` 的分工：那个文件覆盖既有三条通道；本文件覆盖新增两条，
//! 并额外钉住「写入器声明的路径 == `home.join(relative_target())`」这条安全边界。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tianshu_relay_core::delivery::gemini_cli::GeminiCliWriter;
use tianshu_relay_core::delivery::opencode::OpenCodeWriter;
use tianshu_relay_core::delivery::{resolve_for, ConsentState, DeliveryChannel, DeliveryWriter};
use tianshu_relay_core::drift::DriftState;
use tianshu_relay_core::error::Error;
use tianshu_relay_core::service::{ServiceConfig, TianshuRelayService};
use tianshu_relay_core::site::transport::MockTransport;
use tianshu_relay_core::store::Store;
use tianshu_relay_core::vault::{secret_ref, MemoryVault, Vault};

const SECRET: &str = "sk-newchannels-0123456789abcdef";
const BASE_URL: &str = "https://relay.example.com";

const OPENCODE_REL: &str = ".config/opencode/opencode.json";
const GEMINI_REL: &str = ".gemini/.env";

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    db_path: PathBuf,
    service: TianshuRelayService<MockTransport>,
    key_id: i64,
}

fn setup_with_base(base_url: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let db_path = dir.path().join("tianshu-relay.db");

    let store = Store::open(&db_path).expect("文件库");
    let site_id = store
        .upsert_site("newapi", base_url, "测试站")
        .expect("写站点");
    let secret_ref = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "opencode/daily", &secret_ref, Some("1"), None)
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

fn setup() -> Fixture {
    setup_with_base(BASE_URL)
}

fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).expect("stat").permissions().mode() & 0o777
}

/// Continue 的条目必须有模型名（Continue 的 schema 必填；TianshuRelay 不编造默认模型），
/// 其余通道不需要。对 `ALL` 循环的用例统一从这里取。
fn model_for(channel: DeliveryChannel) -> Option<&'static str> {
    (channel == DeliveryChannel::OpenClaw).then_some("gpt-4o")
}

fn target_of(f: &Fixture, channel: DeliveryChannel) -> PathBuf {
    f.service
        .delivery_plan_with_model(f.key_id, channel, model_for(channel))
        .expect("生成计划")
        .target_path
}

fn write_preexisting(f: &Fixture, channel: DeliveryChannel, content: &str) -> PathBuf {
    let target = target_of(f, channel);
    fs::create_dir_all(target.parent().expect("父目录")).expect("建目录");
    fs::write(&target, content).expect("预置");
    target
}

/// 两条新通道共用的「投递 → 校验 → 幂等 → 回滚」流程。
fn round_trip(f: &Fixture, channel: DeliveryChannel, preexisting: &str) {
    let target = write_preexisting(f, channel, preexisting);
    let before_bytes = fs::read(&target).expect("读原始字节");

    f.service.grant_consent(f.key_id, channel).expect("同意");
    let outcome = f
        .service
        .apply_delivery(f.key_id, channel)
        .unwrap_or_else(|e| panic!("{} 投递失败: {e}", channel.as_str()));

    assert_eq!(outcome.target_path, target);
    let written = fs::read_to_string(&target).expect("读回");
    assert!(
        written.contains(SECRET),
        "{} 的目标文件应含密钥:\n{written}",
        channel.as_str()
    );
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
    assert_eq!(
        fs::read(&target).unwrap(),
        before_bytes,
        "{} 回滚必须字节级还原",
        channel.as_str()
    );
}

// ============================================================ 往返

#[test]
fn opencode_round_trip() {
    let f = setup();
    round_trip(
        &f,
        DeliveryChannel::OpenCode,
        r#"{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "anthropic": {
      "options": {
        "apiKey": "sk-anthropic-user-own"
      }
    }
  }
}"#,
    );
}

#[test]
fn gemini_cli_round_trip() {
    let f = setup();
    round_trip(
        &f,
        DeliveryChannel::GeminiCli,
        "# 我的 .env\nGOOGLE_CLOUD_PROJECT=my-project\nOTHER=1",
    );
}

// ============================================================ 权限

#[test]
fn new_file_is_created_with_0600() {
    let f = setup();
    for channel in [DeliveryChannel::OpenCode, DeliveryChannel::GeminiCli] {
        let target = target_of(&f, channel);
        assert!(!target.exists(), "前置：目标不存在");

        f.service.grant_consent(f.key_id, channel).unwrap();
        f.service.apply_delivery(f.key_id, channel).unwrap();

        assert_eq!(
            mode_of(&target),
            0o600,
            "{} 的新建文件必须是 0600（不是 umask 决定的 0644）",
            channel.as_str()
        );
    }
}

#[test]
fn existing_world_readable_file_is_tightened() {
    let f = setup();
    for channel in [DeliveryChannel::OpenCode, DeliveryChannel::GeminiCli] {
        let target = write_preexisting(&f, channel, "");
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();

        f.service.grant_consent(f.key_id, channel).unwrap();
        f.service.apply_delivery(f.key_id, channel).unwrap();

        assert_eq!(
            mode_of(&target),
            0o600,
            "{} 不得让含密钥的文件保持 0644",
            channel.as_str()
        );
    }
}

// ============================================================ 安全边界

#[test]
fn target_path_matches_relative_target_for_all_channels() {
    // **安全边界端到端钉住**：`service.rs::checked_target` 用
    // `home.join(channel.relative_target())` 逐字比对投递目标。
    let f = setup();
    for channel in DeliveryChannel::ALL {
        let target = target_of(&f, channel);
        assert_eq!(
            target,
            f.home.join(channel.relative_target()),
            "{} 的目标路径与通道声明的相对路径不一致",
            channel.as_str()
        );
        assert!(
            target.starts_with(&f.home),
            "{} 的目标越出 home",
            channel.as_str()
        );
    }

    // 两条新通道的相对路径逐字（不依赖平台分支）
    assert_eq!(
        target_of(&f, DeliveryChannel::OpenCode),
        f.home.join(OPENCODE_REL)
    );
    assert_eq!(
        target_of(&f, DeliveryChannel::GeminiCli),
        f.home.join(GEMINI_REL)
    );
}

#[test]
fn writer_target_is_inside_home_and_equals_declared_relative_target() {
    // 不经服务层，直接对写入器比对（`checked_target` 的**必要条件**）。
    let home = Path::new("/tmp/nobody");
    for channel in DeliveryChannel::ALL {
        let writer = resolve_for(channel, home, BASE_URL).expect("可解析");
        assert_eq!(
            writer.target_path(),
            home.join(channel.relative_target()),
            "{} 写入器路径与 relative_target 不一致",
            channel.as_str()
        );
        assert!(writer.target_path().starts_with(home));
    }
}

#[test]
fn jsonc_sibling_does_not_move_the_target() {
    // D-1：`.jsonc` 存在而 `.json` 不存在时，落点仍是常量 `.json`。
    let f = setup();
    let jsonc = f.home.join(".config/opencode/opencode.jsonc");
    fs::create_dir_all(jsonc.parent().unwrap()).unwrap();
    let jsonc_body = "{\n  // 用户自己的注释\n  \"model\": \"x/y\"\n}\n";
    fs::write(&jsonc, jsonc_body).unwrap();

    let target = target_of(&f, DeliveryChannel::OpenCode);
    assert_eq!(target, f.home.join(OPENCODE_REL), "落点不得随 .jsonc 变化");
    assert!(!target.exists(), "前置：`.json` 不存在");

    f.service
        .grant_consent(f.key_id, DeliveryChannel::OpenCode)
        .unwrap();
    f.service
        .apply_delivery(f.key_id, DeliveryChannel::OpenCode)
        .unwrap();

    assert!(target.exists(), "仍应新建 `.json`");
    assert!(fs::read_to_string(&target).unwrap().contains(SECRET));
    assert_eq!(
        fs::read_to_string(&jsonc).unwrap(),
        jsonc_body,
        "`.jsonc` 必须一个字节都没动"
    );
}

// ============================================================ 非受管内容

#[test]
fn opencode_preserves_unmanaged_keys_end_to_end() {
    let f = setup();
    let before = r#"{
  "$schema": "https://opencode.ai/config.json",
  "instructions": [
    "AGENTS.md"
  ],
  "provider": {
    "anthropic": {
      "options": {
        "apiKey": "sk-anthropic-user-own",
        "baseURL": "https://api.anthropic.com"
      }
    },
    "keyrelay": {
      "options": {
        "apiKey": "sk-old"
      }
    }
  },
  "model": "anthropic/claude-sonnet-4"
}"#;
    let target = write_preexisting(&f, DeliveryChannel::OpenCode, before);

    f.service
        .grant_consent(f.key_id, DeliveryChannel::OpenCode)
        .unwrap();
    f.service
        .apply_delivery(f.key_id, DeliveryChannel::OpenCode)
        .unwrap();

    let after: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&target).unwrap()).unwrap();
    let original: serde_json::Value = serde_json::from_str(before).unwrap();

    assert_eq!(after["provider"]["keyrelay"]["options"]["apiKey"], SECRET);
    assert_eq!(
        after["provider"]["keyrelay"]["options"]["baseURL"], BASE_URL,
        "base_url 非空时应写入 options.baseURL"
    );
    for key in ["$schema", "instructions", "model"] {
        assert_eq!(after[key], original[key], "非受管顶层键 {key} 被改动了");
    }
    assert_eq!(
        after["provider"]["anthropic"], original["provider"]["anthropic"],
        "别的 provider 被改动了"
    );
}

#[test]
fn gemini_cli_preserves_unmanaged_lines_end_to_end() {
    let f = setup();
    // 刻意不以换行结尾
    let before = "# 我的 .env\n\nGOOGLE_CLOUD_PROJECT=my-project\nOTHER=1";
    let target = write_preexisting(&f, DeliveryChannel::GeminiCli, before);

    f.service
        .grant_consent(f.key_id, DeliveryChannel::GeminiCli)
        .unwrap();
    f.service
        .apply_delivery(f.key_id, DeliveryChannel::GeminiCli)
        .unwrap();

    let written = fs::read_to_string(&target).unwrap();
    assert!(
        written.starts_with(before),
        "非受管行必须逐字节保留:\n{written}"
    );
    assert!(written.contains(&format!("GEMINI_API_KEY={SECRET}")));
    assert!(written.contains(&format!("GOOGLE_GEMINI_BASE_URL={BASE_URL}")));
}

// ============================================================ base_url 为空

#[test]
fn empty_base_url_writes_only_the_key_end_to_end() {
    let f = setup_with_base("");
    // 预置已有的 base_url 行/键，验证「只投递密钥」不把它们改掉
    write_preexisting(
        &f,
        DeliveryChannel::OpenCode,
        r#"{"provider":{"keyrelay":{"options":{"baseURL":"https://keep.example.com"}}}}"#,
    );
    write_preexisting(
        &f,
        DeliveryChannel::GeminiCli,
        "GOOGLE_GEMINI_BASE_URL=https://keep.example.com\n",
    );

    for channel in [DeliveryChannel::OpenCode, DeliveryChannel::GeminiCli] {
        let plan = f.service.delivery_plan(f.key_id, channel).unwrap();
        assert_eq!(
            plan.fields.len(),
            1,
            "{} base_url 为空时预览只应有一个字段",
            channel.as_str()
        );
        assert!(
            !plan.preview.contains(SECRET),
            "{} 预览泄漏",
            channel.as_str()
        );

        f.service.grant_consent(f.key_id, channel).unwrap();
        f.service.apply_delivery(f.key_id, channel).unwrap();
    }

    let opencode = fs::read_to_string(f.home.join(OPENCODE_REL)).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&opencode).unwrap();
    assert_eq!(
        parsed["provider"]["keyrelay"]["options"]["baseURL"], "https://keep.example.com",
        "base_url 为空时不得改动已有 baseURL"
    );
    assert_eq!(parsed["provider"]["keyrelay"]["options"]["apiKey"], SECRET);
    assert!(
        !opencode.contains("relay.example.com"),
        "空 base_url 不得被写成字面量:\n{opencode}"
    );

    let gemini = fs::read_to_string(f.home.join(GEMINI_REL)).unwrap();
    assert_eq!(
        gemini,
        format!("GOOGLE_GEMINI_BASE_URL=https://keep.example.com\nGEMINI_API_KEY={SECRET}\n"),
        "base_url 为空时不得改动已有行"
    );
}

// ============================================================ 泄漏

#[test]
fn no_plaintext_leak_for_new_channels() {
    let f = setup();
    let channels = [DeliveryChannel::OpenCode, DeliveryChannel::GeminiCli];

    for channel in channels {
        f.service.grant_consent(f.key_id, channel).unwrap();
        let plan = f.service.delivery_plan(f.key_id, channel).unwrap();
        assert!(
            !plan.preview.contains(SECRET),
            "{} 预览泄漏:\n{}",
            channel.as_str(),
            plan.preview
        );
        assert!(
            !format!("{plan:?}").contains(SECRET),
            "{} 的 Debug 泄漏",
            channel.as_str()
        );
        assert!(
            !format!("{:?}", plan.fields).contains(SECRET),
            "{} 的字段清单泄漏",
            channel.as_str()
        );

        let outcome = f.service.apply_delivery(f.key_id, channel).unwrap();
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
        assert!(!format!("{row:?}").contains(SECRET), "同意记录泄漏");
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
    assert!(!f.service.export_diagnostics(200).unwrap().contains(SECRET));
    // 脱敏审计
    let report = f.service.audit_redaction().unwrap();
    assert!(report.is_clean(), "{}", report.summary());
}

#[test]
fn error_messages_never_echo_the_key() {
    // 目标文件坏掉 → 错误文案里不得出现密钥
    let f = setup();
    let target = write_preexisting(&f, DeliveryChannel::OpenCode, "not json at all");
    f.service
        .grant_consent(f.key_id, DeliveryChannel::OpenCode)
        .unwrap();

    let err = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::OpenCode)
        .unwrap_err();
    assert!(!err.to_string().contains(SECRET), "{err}");
    assert!(
        err.to_string().contains("拒绝改写"),
        "应给出可操作文案: {err}"
    );
    // 拒绝时文件零改动
    assert_eq!(fs::read_to_string(&target).unwrap(), "not json at all");

    // 写入器层同样不得回显
    let dir = tempfile::tempdir().unwrap();
    let writer = OpenCodeWriter::with_path(
        dir.path().join("opencode.json"),
        OpenCodeWriter::DEFAULT_PROVIDER_ID,
        BASE_URL,
        None,
    );
    fs::write(writer.path(), "not json").unwrap();
    let err = writer.plan(SECRET).unwrap_err();
    assert!(!err.to_string().contains(SECRET), "{err}");
}

// ============================================================ 同意隔离

#[test]
fn each_new_channel_needs_its_own_consent() {
    let f = setup();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::OpenCode)
        .unwrap();

    let err = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::GeminiCli)
        .unwrap_err();
    assert!(
        matches!(err, Error::ConsentRequired { .. }),
        "未同意的通道必须被拒: {err:?}"
    );

    let consents = f.service.list_consents().unwrap();
    assert_eq!(consents.len(), 1);
    assert_eq!(consents[0].channel, "opencode");
    assert_eq!(consents[0].agent_id, "opencode");
}

#[test]
fn agent_id_is_reported_for_new_channels() {
    let f = setup();
    for (channel, agent) in [
        (DeliveryChannel::OpenCode, "opencode"),
        (DeliveryChannel::GeminiCli, "gemini-cli"),
    ] {
        let plan = f.service.delivery_plan(f.key_id, channel).unwrap();
        assert_eq!(plan.agent_id, agent);
        assert_eq!(plan.agent_id, channel.agent_id());
        assert_eq!(plan.consent, ConsentState::Missing);
        assert!(
            plan.target_path.starts_with(&f.home),
            "{} 的目标必须落在 home 内",
            channel.as_str()
        );
    }
}

#[test]
fn delivery_is_refused_without_a_key_record() {
    // 反例保护：通道存在不等于可以乱投——`key_id` 不存在时连计划都生成不了
    let f = setup();
    for channel in [DeliveryChannel::OpenCode, DeliveryChannel::GeminiCli] {
        let err = f.service.delivery_plan(9999, channel).unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "{err:?}");
    }
}

// ============================================================ 漂移

#[test]
fn drift_reports_intact_for_new_channels() {
    let f = setup();
    for channel in [DeliveryChannel::OpenCode, DeliveryChannel::GeminiCli] {
        f.service.grant_consent(f.key_id, channel).unwrap();
        f.service.apply_delivery(f.key_id, channel).unwrap();
    }

    let reports = f.service.drift_report().unwrap();
    for channel in [DeliveryChannel::OpenCode, DeliveryChannel::GeminiCli] {
        let report = reports
            .iter()
            .find(|r| r.channel == channel.as_str())
            .unwrap_or_else(|| panic!("{} 应有一条漂移报告", channel.as_str()));
        assert_eq!(report.state, DriftState::Intact, "{}", channel.as_str());
    }

    // 手工改动 → Modified（证明这条报告真的在看文件，不是恒真）
    let target = f.home.join(GEMINI_REL);
    let mut text = fs::read_to_string(&target).unwrap();
    text.push_str("USER_EDIT=1\n");
    fs::write(&target, text).unwrap();

    let reports = f.service.drift_report().unwrap();
    let report = reports
        .iter()
        .find(|r| r.channel == "gemini-cli")
        .expect("有 gemini-cli 报告");
    assert_eq!(report.state, DriftState::Modified);
}

// ============================================================ 写入器级补充

#[test]
fn opencode_writer_uses_default_provider_and_model_when_asked() {
    let dir = tempfile::tempdir().unwrap();
    let writer = OpenCodeWriter::with_path(
        dir.path().join("opencode.json"),
        "site-a",
        BASE_URL,
        Some("site-a/gpt-4o"),
    );
    let patch = writer.plan(SECRET).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&patch.after).unwrap();
    assert_eq!(parsed["provider"]["site-a"]["options"]["apiKey"], SECRET);
    assert_eq!(parsed["model"], "site-a/gpt-4o");
    assert_eq!(patch.new_file_mode, Some(0o600));
}

#[test]
fn gemini_cli_writer_keeps_duplicates_merged() {
    // 端到端之外的补充：重复受管键必须合并成一行，旧值不得残留
    let dir = tempfile::tempdir().unwrap();
    let writer = GeminiCliWriter::with_path(dir.path().join(".env"), "");
    fs::write(
        writer.path(),
        "GEMINI_API_KEY=sk-first\nA=1\nGEMINI_API_KEY=sk-second\n",
    )
    .unwrap();

    let patch = writer.plan(SECRET).unwrap();
    assert_eq!(patch.after, format!("GEMINI_API_KEY={SECRET}\nA=1\n"));
    assert!(!patch.after.contains("sk-first"));
    assert!(!patch.after.contains("sk-second"));
}

// ==================================================== M6-S1 复审 P2-1 / P2-2 / P2-3 的修复
//
// 这三条是**服务层端到端**的回归。复审者当初就是用这条路径把 P2-1 复现出来的
// （`grant_consent` → `apply_delivery` 返回 `Err`），因此修复必须在同一层被钉住，
// 不能只钉在写入器的单元测试里。

#[test]
fn comment_with_a_lone_quote_does_not_block_gemini_delivery() {
    // **P2-1 回归**（复审者给的原文夹具）：注释里的孤儿双引号曾让整条通道**无法投递**。
    let f = setup();
    let before = "# note: a lone \" quote\nOTHER=1\nGEMINI_API_KEY=sk-old\n";
    let target = write_preexisting(&f, DeliveryChannel::GeminiCli, before);

    f.service
        .grant_consent(f.key_id, DeliveryChannel::GeminiCli)
        .expect("同意");
    f.service
        .apply_delivery(f.key_id, DeliveryChannel::GeminiCli)
        .expect("注释里的孤儿引号不得让投递失败");

    let written = fs::read_to_string(&target).unwrap();
    assert_eq!(
        written,
        format!(
            "# note: a lone \" quote\nOTHER=1\nGEMINI_API_KEY={SECRET}\n\
             GOOGLE_GEMINI_BASE_URL={BASE_URL}\n"
        ),
        "注释与无关变量逐字保留；受管键**原地**替换，base_url 因文件中原本没有而追加"
    );
    assert!(!written.contains("sk-old"), "旧密钥必须被替换掉");
    assert_eq!(mode_of(&target), 0o600);
}

#[test]
fn crlf_env_file_keeps_crlf_after_append_end_to_end() {
    // **P2-2 回归**：CRLF 文件在追加后不得出现混合行尾。
    let f = setup();
    let target = write_preexisting(&f, DeliveryChannel::GeminiCli, "A=1\r\n");

    f.service
        .grant_consent(f.key_id, DeliveryChannel::GeminiCli)
        .unwrap();
    f.service
        .apply_delivery(f.key_id, DeliveryChannel::GeminiCli)
        .unwrap();

    let written = fs::read_to_string(&target).unwrap();
    assert_eq!(
        written,
        format!("A=1\r\nGEMINI_API_KEY={SECRET}\r\nGOOGLE_GEMINI_BASE_URL={BASE_URL}\r\n")
    );
    assert_eq!(
        written.matches('\n').count(),
        written.matches("\r\n").count(),
        "不得有落单的 LF"
    );
}

#[test]
fn dotted_provider_id_is_unambiguous_in_field_names() {
    // **P2-3 回归**：`provider.a.b.options.apiKey` 的归属有歧义 → 改用方括号形态。
    let home = Path::new("/tmp/nobody");
    let writer = tianshu_relay_core::delivery::resolve_for_binding(
        DeliveryChannel::OpenCode,
        home,
        BASE_URL,
        "a.b",
        None,
    )
    .expect("可解析");
    assert_eq!(
        writer.field_names(),
        vec![
            "provider[\"a.b\"].options.apiKey",
            "provider[\"a.b\"].options.baseURL"
        ]
    );
    // 落盘路径与键名格式无关（安全边界不受影响）
    assert_eq!(
        writer.target_path(),
        home.join(DeliveryChannel::OpenCode.relative_target())
    );

    // 反例保护：常见形态仍走点号形式（既有展示不变）
    let simple = resolve_for(DeliveryChannel::OpenCode, home, BASE_URL).unwrap();
    assert_eq!(simple.field_names()[0], "provider.keyrelay.options.apiKey");
}
