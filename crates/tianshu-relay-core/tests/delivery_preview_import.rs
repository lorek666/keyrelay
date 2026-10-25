//! P1-7：首次导入 + 只打印不写盘的预览模式 + 写路径白名单。
//!
//! 覆盖（全部走真实服务层 + 真实临时 home / 库，不用 mock 服务）：
//! ① 首次投递某通道时，现有文件里的值只读进预览（密钥掩码），
//!    文件字节不变、投递内容仍是新值、落盘后旧值不复活；
//! ② 预览模式零写盘：目标文件字节、绑定行、投递历史行、事件行四处
//!    前后一致；且既有 `delivery_plan` 入口仍写一条事件日志（对照，
//!    证明预览入口确实跳过了那一处写操作）；
//! ③ 已投递过的通道不再导入；
//! ④ 白名单变体：Cline 的 Code / Insiders / Cursor 三条可达，
//!    越界变体名与路径形态字符串一律拒绝，opencode 的 .json / .jsonc
//!    选择由通道承载、变体名不得串通道；变体落盘写到变体文件，
//!    默认文件保持不存在。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::json;
use tianshu_relay_core::delivery::{DeliveryChannel, DeliverySource};
use tianshu_relay_core::service::{ServiceConfig, TianshuRelayService};
use tianshu_relay_core::site::transport::{HttpResponse, MockTransport};
use tianshu_relay_core::site::Credentials;
use tianshu_relay_core::store::Store;
use tianshu_relay_core::vault::{secret_ref, MemoryVault, Vault};

const NEW_SECRET: &str = "sk-test-new-9999";
const BASE: &str = "https://relay.example.com";

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    service: TianshuRelayService<MockTransport>,
    key_id: i64,
}

fn encryption_disabled() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": {"enabled": false}})).unwrap()
}

fn login_ok() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": {"id": 7}}))
        .unwrap()
        .with_header("Set-Cookie", "session=abc; Path=/")
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let store = Store::open(&dir.path().join("tianshu-relay.db")).unwrap();
    let site_id = store.upsert_site("newapi", BASE, "测试站").unwrap();
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &reference, Some("1"), None)
        .unwrap();
    let vault = Arc::new(MemoryVault::new());
    vault.put(&reference, NEW_SECRET).unwrap();
    let mock = MockTransport::new(vec![]);
    let service = TianshuRelayService::new(
        store,
        mock.clone(),
        ServiceConfig {
            vault,
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
        },
    );
    mock.push(encryption_disabled());
    mock.push(login_ok());
    service
        .login(site_id, Credentials::new("me", "pw"))
        .await
        .unwrap();
    Fixture {
        _dir: dir,
        home,
        service,
        key_id,
    }
}

fn write(home: &Path, rel: impl AsRef<Path>, content: &str) -> PathBuf {
    let path = home.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, content).unwrap();
    path
}

#[tokio::test]
async fn first_delivery_imports_existing_values_and_apply_ignores_them() {
    let f = setup().await;
    let before = r#"{
  "env": {
    "ANTHROPIC_AUTH_TOKEN": "sk-old-00001111",
    "ANTHROPIC_BASE_URL": "https://old.example.com",
    "ANTHROPIC_MODEL": "old-model"
  }
}"#;
    let target = write(&f.home, ".claude/settings.json", before);

    let plan = f
        .service
        .delivery_plan_with_model(
            f.key_id,
            DeliveryChannel::ClaudeCodeSettings,
            Some("gpt-4o"),
        )
        .unwrap();
    assert!(plan.is_first_delivery, "从未投递过的通道应算首次");
    assert!(!plan.preview_only, "既有预览入口的 preview_only 应为 false");
    assert_eq!(plan.target_variant, "default");
    // 导入：旧值只读进预览，密钥掩码、非密钥原文。
    let imported: Vec<(&str, &str)> = plan
        .imported_fields
        .iter()
        .map(|fld| (fld.key.as_str(), fld.masked.as_str()))
        .collect();
    assert_eq!(
        imported,
        vec![
            ("ANTHROPIC_AUTH_TOKEN", "…1111"),
            ("ANTHROPIC_BASE_URL", "https://old.example.com"),
            ("ANTHROPIC_MODEL", "old-model"),
        ],
        "导入必须含旧密钥（掩码）与旧端点、旧模型"
    );
    // 投递内容仍是新值：导入没有反向 feed 回 fields。
    let fields: Vec<(&str, &str)> = plan
        .fields
        .iter()
        .map(|fld| (fld.key.as_str(), fld.masked.as_str()))
        .collect();
    assert_eq!(
        fields,
        vec![
            ("ANTHROPIC_AUTH_TOKEN", "…9999"),
            ("ANTHROPIC_BASE_URL", BASE),
            ("ANTHROPIC_MODEL", "gpt-4o"),
        ]
    );
    // 预览本身一个字节都不动文件。
    assert_eq!(fs::read_to_string(&target).unwrap(), before);

    // 落盘后文件里是新值，旧值不复活。
    f.service
        .grant_consent(f.key_id, DeliveryChannel::ClaudeCodeSettings)
        .unwrap();
    f.service
        .apply_delivery_with_model(
            f.key_id,
            DeliveryChannel::ClaudeCodeSettings,
            Some("gpt-4o"),
        )
        .unwrap();
    let after: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&target).unwrap()).unwrap();
    assert_eq!(after["env"]["ANTHROPIC_AUTH_TOKEN"], NEW_SECRET);
    assert_eq!(after["env"]["ANTHROPIC_BASE_URL"], BASE);
    assert_eq!(after["env"]["ANTHROPIC_MODEL"], "gpt-4o");

    // 投递过后不再是首次，导入为空（文件里已是本产品写下的内容）。
    let again = f
        .service
        .delivery_plan_with_model(
            f.key_id,
            DeliveryChannel::ClaudeCodeSettings,
            Some("gpt-4o"),
        )
        .unwrap();
    assert!(!again.is_first_delivery);
    assert!(again.imported_fields.is_empty());
}

#[tokio::test]
async fn preview_only_writes_nothing_anywhere() {
    let f = setup().await;
    let target = write(
        &f.home,
        ".claude/settings.json",
        "{\"env\": {\"ANTHROPIC_AUTH_TOKEN\": \"sk-old-00001111\"}}\n",
    );
    let file_before = fs::read_to_string(&target).unwrap();
    let bindings_before = f.service.channel_bindings().unwrap().len();
    let history_before = f.service.delivery_history(100).unwrap().len();
    let events_before = f.service.recent_events(1000).unwrap().len();

    let plan = f
        .service
        .delivery_preview_in(
            f.key_id,
            DeliveryChannel::ClaudeCodeSettings,
            None,
            DeliverySource::Site,
            None,
        )
        .unwrap();
    assert!(plan.preview_only, "预览入口必须标 preview_only");
    assert!(plan.is_first_delivery);
    assert_eq!(
        plan.consent,
        tianshu_relay_core::delivery::ConsentState::Missing
    );
    assert!(
        plan.preview.contains("ANTHROPIC_AUTH_TOKEN"),
        "预览仍须完整打印逐文件 diff：{}",
        plan.preview
    );

    // 四处零写盘 / 零记账：文件字节、绑定行、历史行、事件行前后一致。
    assert_eq!(fs::read_to_string(&target).unwrap(), file_before);
    assert_eq!(f.service.channel_bindings().unwrap().len(), bindings_before);
    assert_eq!(
        f.service.delivery_history(100).unwrap().len(),
        history_before
    );
    assert_eq!(f.service.recent_events(1000).unwrap().len(), events_before);

    // 不存在的文件在预览后仍不存在（预览不得创建文件）。
    let gemini = f.home.join(".gemini").join(".env");
    assert!(!gemini.exists());
    f.service
        .delivery_preview_in(
            f.key_id,
            DeliveryChannel::GeminiCli,
            None,
            DeliverySource::Site,
            None,
        )
        .unwrap();
    assert!(!gemini.exists(), "预览不得创建目标文件");
    assert_eq!(f.service.recent_events(1000).unwrap().len(), events_before);

    // 对照：既有 delivery_plan 入口会写一条事件日志——证明预览入口
    // 确实跳过了预览路径上的最后一处写操作，而不是测试本身测不到写。
    f.service
        .delivery_plan(f.key_id, DeliveryChannel::ClaudeCodeSettings)
        .unwrap();
    assert_eq!(
        f.service.recent_events(1000).unwrap().len(),
        events_before + 1
    );
    assert_eq!(fs::read_to_string(&target).unwrap(), file_before);
    assert_eq!(f.service.channel_bindings().unwrap().len(), bindings_before);
}

#[tokio::test]
async fn preview_after_delivery_writes_nothing_and_imports_nothing() {
    let f = setup().await;
    f.service
        .grant_consent(f.key_id, DeliveryChannel::ClaudeCodeSettings)
        .unwrap();
    f.service
        .apply_delivery(f.key_id, DeliveryChannel::ClaudeCodeSettings)
        .unwrap();
    let target = f.home.join(".claude").join("settings.json");
    let file_before = fs::read_to_string(&target).unwrap();
    let bindings_before = f.service.channel_bindings().unwrap().len();
    let history_before = f.service.delivery_history(100).unwrap().len();
    let events_before = f.service.recent_events(1000).unwrap().len();
    assert_eq!(bindings_before, 1);
    assert_eq!(history_before, 1);

    let plan = f
        .service
        .delivery_preview_in(
            f.key_id,
            DeliveryChannel::ClaudeCodeSettings,
            None,
            DeliverySource::Site,
            None,
        )
        .unwrap();
    assert!(plan.preview_only);
    assert!(!plan.is_first_delivery);
    assert!(plan.imported_fields.is_empty());
    assert_eq!(fs::read_to_string(&target).unwrap(), file_before);
    assert_eq!(f.service.channel_bindings().unwrap().len(), bindings_before);
    assert_eq!(
        f.service.delivery_history(100).unwrap().len(),
        history_before
    );
    assert_eq!(f.service.recent_events(1000).unwrap().len(), events_before);
}

#[tokio::test]
async fn cline_import_reads_only_the_keyrelay_entry() {
    let f = setup().await;
    // 夹具必须写到通道实际解析的落点（cline::relative_config_path() 随平台变化：
    // Linux 是 .config/Code/...，macOS 是 Library/Application Support/Code/...），
    // 写死 Linux 路径在 macOS runner 上会读到空文件、import 返回 []。
    write(
        &f.home,
        DeliveryChannel::Cline.relative_target(),
        r#"{"providers": [
          {"id": "other", "apiKey": "sk-other-2222", "baseUrl": "https://other.example.com"},
          {"id": "keyrelay", "apiKey": "sk-mine-3333", "baseUrl": "https://old.example.com"}
        ]}"#,
    );
    let plan = f
        .service
        .delivery_plan(f.key_id, DeliveryChannel::Cline)
        .unwrap();
    assert!(plan.is_first_delivery);
    let imported: Vec<(&str, &str)> = plan
        .imported_fields
        .iter()
        .map(|fld| (fld.key.as_str(), fld.masked.as_str()))
        .collect();
    assert_eq!(
        imported,
        vec![("apiKey", "…3333"), ("baseUrl", "https://old.example.com"),],
        "别的 provider 的密钥不得被当成 keyrelay 的旧值"
    );
}

#[tokio::test]
async fn gemini_env_import_reads_export_prefixed_lines() {
    let f = setup().await;
    write(
        &f.home,
        ".gemini/.env",
        "export GEMINI_API_KEY=sk-env-6666\nGOOGLE_GEMINI_BASE_URL=https://env.example.com\n",
    );
    let plan = f
        .service
        .delivery_plan(f.key_id, DeliveryChannel::GeminiCli)
        .unwrap();
    assert!(plan.is_first_delivery);
    let imported: Vec<(&str, &str)> = plan
        .imported_fields
        .iter()
        .map(|fld| (fld.key.as_str(), fld.masked.as_str()))
        .collect();
    assert_eq!(
        imported,
        vec![
            ("GEMINI_API_KEY", "…6666"),
            ("GOOGLE_GEMINI_BASE_URL", "https://env.example.com"),
        ]
    );
}

#[tokio::test]
async fn variant_paths_are_reachable_and_out_of_allowlist_is_rejected() {
    let f = setup().await;
    // Cline 三变体各归其位。平台前缀随 OS 变化（Linux .config、macOS
    // Library/Application Support、Windows AppData/Roaming），断言只钉
    // 「变体目录名 + 固定尾巴」这一平台无关部分；完整前缀由
    // relative_target() / allowed_targets() 覆盖。
    let code = f
        .service
        .delivery_preview_in(
            f.key_id,
            DeliveryChannel::Cline,
            None,
            DeliverySource::Site,
            None,
        )
        .unwrap();
    assert_eq!(code.target_variant, "code");
    assert!(code
        .target_path
        .ends_with("Code/User/globalStorage/saoudrizwan.claude-dev/settings.json"));
    let insiders = f
        .service
        .delivery_preview_in(
            f.key_id,
            DeliveryChannel::Cline,
            None,
            DeliverySource::Site,
            Some("code-insiders"),
        )
        .unwrap();
    assert_eq!(insiders.target_variant, "code-insiders");
    assert!(insiders
        .target_path
        .ends_with("Code - Insiders/User/globalStorage/saoudrizwan.claude-dev/settings.json"));
    let cursor = f
        .service
        .delivery_preview_in(
            f.key_id,
            DeliveryChannel::Cline,
            None,
            DeliverySource::Site,
            Some("cursor"),
        )
        .unwrap();
    assert_eq!(cursor.target_variant, "cursor");
    assert!(cursor
        .target_path
        .ends_with("Cursor/User/globalStorage/saoudrizwan.claude-dev/settings.json"));

    // 越界一律拒绝：未知名、路径形态、给非变体通道传变体名。
    for (channel, variant) in [
        (DeliveryChannel::Cline, "vscode-foo"),
        (DeliveryChannel::Cline, "/tmp/evil/settings.json"),
        (DeliveryChannel::Cline, "../evil"),
        (DeliveryChannel::ClaudeCodeSettings, "cursor"),
        (DeliveryChannel::OpenCode, "code-insiders"),
        (DeliveryChannel::OpenCodeJsonc, "cursor"),
    ] {
        let err = f
            .service
            .delivery_preview_in(f.key_id, channel, None, DeliverySource::Site, Some(variant))
            .unwrap_err();
        assert!(
            err.to_string().contains("可选变体"),
            "{} + {variant:?} 应被拒绝并列出变体表: {err}",
            channel.as_str()
        );
    }

    // opencode 的 .json / .jsonc 选择由通道承载：变体名不得串通道，
    // 两通道的默认落点各是各的文件。
    let json = f
        .service
        .delivery_plan(f.key_id, DeliveryChannel::OpenCode)
        .unwrap();
    assert!(json.target_path.ends_with(".config/opencode/opencode.json"));
    let jsonc = f
        .service
        .delivery_plan(f.key_id, DeliveryChannel::OpenCodeJsonc)
        .unwrap();
    assert!(jsonc
        .target_path
        .ends_with(".config/opencode/opencode.jsonc"));

    // 变体落盘写到变体文件，默认文件保持不存在。
    f.service
        .grant_consent_with_variant(f.key_id, DeliveryChannel::Cline, Some("cursor"))
        .unwrap();
    f.service
        .apply_delivery_in_with_variant(
            f.key_id,
            DeliveryChannel::Cline,
            None,
            DeliverySource::Site,
            Some("cursor"),
        )
        .unwrap();
    assert!(
        cursor.target_path.exists(),
        "变体落盘应写到 Cursor 变体文件"
    );
    assert!(
        !code.target_path.exists(),
        "变体落盘不得顺带写默认 Code 文件"
    );
}
