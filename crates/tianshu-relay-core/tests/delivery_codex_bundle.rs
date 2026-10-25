//! Codex 双文件同单（P0-2）的端到端验证。
//!
//! 全部测试把 `home` 指向临时目录，绝不触碰用户真实的 `~/.codex`。
//! 失败注入用**符号链接目标**（`write_atomic` 明确拒绝写穿符号链接），
//! 不用目录只读权限——测试以 root 运行时只读位拦不住写盘，符号链接才稳定。

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use tianshu_relay_core::delivery::{expected_fields, DeliveryChannel, FieldSetOptions};
use tianshu_relay_core::error::Error;
use tianshu_relay_core::service::{ServiceConfig, TianshuRelayService};
use tianshu_relay_core::site::transport::MockTransport;
use tianshu_relay_core::store::Store;
use tianshu_relay_core::vault::{secret_ref, MemoryVault, Vault};

const SECRET: &str = "sk-0123456789abcdefSECRET";
const BASE: &str = "https://relay.example.com";

struct Fixture {
    _dir: tempfile::TempDir,
    db_path: PathBuf,
    vault: Arc<MemoryVault>,
    service: TianshuRelayService<MockTransport>,
    key_id: i64,
    auth_target: PathBuf,
    config_target: PathBuf,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");

    let db_dir = dir.path().join("db");
    fs::create_dir_all(&db_dir).expect("db dir");
    let db_path = db_dir.join("tianshu-relay.db");
    let store = Store::open(&db_path).expect("文件库");
    let site_id = store.upsert_site("newapi", BASE, "测试站").expect("写站点");

    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &reference, Some("1"), None)
        .expect("写密钥记录");

    let vault = Arc::new(MemoryVault::new());
    vault.put(&reference, SECRET).expect("写钥匙串");

    let service = TianshuRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault: vault.clone(),
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
        },
    );

    Fixture {
        _dir: dir,
        db_path,
        vault,
        service,
        key_id,
        auth_target: home.join(".codex").join("auth.json"),
        config_target: home.join(".codex").join("config.toml"),
    }
}

fn grant_both(f: &Fixture) {
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexConfig)
        .unwrap();
}

fn write_both_old(f: &Fixture, auth_old: &str, config_old: &str) {
    fs::create_dir_all(f.auth_target.parent().unwrap()).unwrap();
    fs::write(&f.auth_target, auth_old).unwrap();
    fs::write(&f.config_target, config_old).unwrap();
}

#[test]
fn plan_shows_both_files_and_tables_stay_separate() {
    let f = setup();
    let plan = f
        .service
        .delivery_plan_codex(f.key_id, None, false)
        .unwrap();

    assert!(!plan.preserve_auth);
    let auth = plan.auth.expect("双文件预览必须含 auth 计划");
    assert_eq!(auth.channel, DeliveryChannel::CodexAuthJson);
    assert_eq!(auth.target_path, f.auth_target);
    assert_eq!(plan.config.channel, DeliveryChannel::CodexConfig);
    assert_eq!(plan.config.target_path, f.config_target);

    // 预览必须同时展示两文件的内容：auth 预览含密钥键、config 预览含端点键，
    // 且两份预览都不含密钥明文。
    assert!(auth.preview.contains("OPENAI_API_KEY"), "{}", auth.preview);
    assert!(!auth.preview.contains(SECRET), "{}", auth.preview);
    assert!(
        plan.config.preview.contains("base_url"),
        "{}",
        plan.config.preview
    );
    assert!(
        !plan.config.preview.contains(SECRET),
        "config 预览不得含密钥: {}",
        plan.config.preview
    );

    // P0-1 两张表分开：auth 表不得含端点 / 模型键，config 表不得含任何 API_KEY 键。
    let opts = FieldSetOptions::new("keyrelay", true, true, false);
    let auth_keys = expected_fields(DeliveryChannel::CodexAuthJson, &opts);
    assert_eq!(auth_keys, vec!["auth_mode", "OPENAI_API_KEY"]);
    assert!(
        !auth_keys
            .iter()
            .any(|k| k.contains("base_url") || k == "model"),
        "auth 表不得含端点/模型键: {auth_keys:?}"
    );
    let config_keys = expected_fields(DeliveryChannel::CodexConfig, &opts);
    assert!(config_keys.contains(&"base_url".to_string()));
    assert!(config_keys.contains(&"model".to_string()));
    assert!(
        !config_keys
            .iter()
            .any(|k| k.to_uppercase().contains("API_KEY")),
        "config 表不得含任何 API_KEY 键: {config_keys:?}"
    );

    // 保留模式的预览里根本没有 auth——不是「生成了再藏起来」。
    let preserved = f.service.delivery_plan_codex(f.key_id, None, true).unwrap();
    assert!(preserved.preserve_auth);
    assert!(preserved.auth.is_none(), "保留预览不得含 auth 计划");
    assert_eq!(preserved.config.target_path, f.config_target);
}

#[test]
fn dual_success_writes_both_files_one_journal_two_bindings_and_rolls_both_back() {
    let f = setup();
    let auth_old =
        "{\n  \"auth_mode\": \"apikey\",\n  \"tokens\": {\n    \"id_token\": \"keep-me\"\n  }\n}";
    let config_old = "option_a = \"x\"\n";
    write_both_old(&f, auth_old, config_old);
    grant_both(&f);

    let outcome = f.service.apply_codex(f.key_id, None, false).unwrap();
    assert!(!outcome.preserve_auth);
    let auth_out = outcome.auth.expect("双文件结果必须含 auth");
    assert_eq!(auth_out.journal_id, outcome.journal_id);
    assert_eq!(outcome.config.journal_id, outcome.journal_id);
    assert_eq!(auth_out.target_path, f.auth_target);
    assert_eq!(outcome.config.target_path, f.config_target);
    assert!(auth_out.backup_path.is_some(), "auth 投递必须留备份");
    assert!(
        outcome.config.backup_path.is_some(),
        "config 投递必须留备份"
    );

    let written_auth = fs::read_to_string(&f.auth_target).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&written_auth).unwrap();
    assert_eq!(parsed["OPENAI_API_KEY"], SECRET);
    assert_eq!(parsed["tokens"]["id_token"], "keep-me", "无关键必须保留");
    let written_config = fs::read_to_string(&f.config_target).unwrap();
    assert!(written_config.contains("model_provider = \"custom\""));
    assert!(written_config.contains(BASE));
    assert!(written_config.contains("wire_api = \"responses\""));
    assert!(!written_config.contains(SECRET), "config 不得含密钥");
    assert!(
        written_config.contains("option_a = \"x\""),
        "段外内容必须保留"
    );

    // 记账：两条绑定、同一个 journal_id（投递历史按目标各一行）。
    let history = f.service.delivery_history(10).unwrap();
    let rows: Vec<_> = history
        .iter()
        .filter(|r| r.journal_id == outcome.journal_id)
        .collect();
    assert_eq!(rows.len(), 2, "双文件必须记两条绑定: {rows:?}");
    assert!(rows
        .iter()
        .any(|r| r.target_path == f.auth_target.display().to_string()));
    assert!(rows
        .iter()
        .any(|r| r.target_path == f.config_target.display().to_string()));

    // 漂移：两文件各自 intact。
    let reports = f.service.drift_report().unwrap();
    let auth_report = reports
        .iter()
        .find(|r| r.target_path == f.auth_target)
        .expect("auth 应在漂移报告里");
    let config_report = reports
        .iter()
        .find(|r| r.target_path == f.config_target)
        .expect("config 应在漂移报告里");
    assert_eq!(auth_report.state.as_str(), "intact");
    assert_eq!(config_report.state.as_str(), "intact");

    // 回滚一单 = 滚两文件：共享 journal 的回滚一次取回两条 entry。
    f.service.rollback_delivery(&outcome.journal_id).unwrap();
    assert_eq!(fs::read_to_string(&f.auth_target).unwrap(), auth_old);
    assert_eq!(fs::read_to_string(&f.config_target).unwrap(), config_old);
}

#[test]
fn dual_is_the_default_when_preserve_is_false() {
    // 服务层入口收显式 bool；命令层把「参数没传」翻译成 false（双文件），
    // 见命令层 DeliveryArgs::preserve_auth 的注释——这条测的就是那个默认分支
    // 在服务层的效果：不保留 ⇒ 两文件都写。
    let f = setup();
    grant_both(&f);
    let outcome = f.service.apply_codex(f.key_id, None, false).unwrap();
    assert!(outcome.auth.is_some());
    assert!(f.auth_target.exists());
    assert!(f.config_target.exists());
}

#[test]
fn dual_requires_both_consents_and_writes_nothing_without_either() {
    let f = setup();
    // 只授 auth：双文件必须拒绝，且两文件一个字节都不动。
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    let err = f.service.apply_codex(f.key_id, None, false).unwrap_err();
    assert!(matches!(err, Error::ConsentRequired { .. }), "{err:?}");
    assert!(err.to_string().contains("codex-config"), "{err}");
    assert!(!f.auth_target.exists(), "缺同意时 auth 不得创建");
    assert!(!f.config_target.exists(), "缺同意时 config 不得创建");

    // 只授 config 同样拒绝（缺 auth 那条）。
    let f = setup();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexConfig)
        .unwrap();
    let err = f.service.apply_codex(f.key_id, None, false).unwrap_err();
    assert!(matches!(err, Error::ConsentRequired { .. }), "{err:?}");
    assert!(err.to_string().contains("codex-auth-json"), "{err}");
    assert!(!f.auth_target.exists());
    assert!(!f.config_target.exists());
}

/// Unix 专属：符号链接写盘保护的前提是能建出符号链接；Windows 上
/// 建链接需要特权且 std::os::unix 不存在，本测试只在 Unix 上编译运行；
/// 非链接的写盘失败路径由本文件其他测试覆盖。
#[test]
#[cfg(unix)]
fn config_symlink_failure_rolls_auth_back_then_recovery_succeeds() {
    // 反向验证：临时破坏第二文件（config）的写盘——auth 已写，必须被补偿回滚；
    // 恢复后重投成功，证明失败不是「环境坏了」。
    let f = setup();
    let auth_old = "{\n  \"auth_mode\": \"apikey\",\n  \"OPENAI_API_KEY\": \"sk-old\"\n}";
    let config_old = "option_a = \"x\"\n";
    write_both_old(&f, auth_old, config_old);
    grant_both(&f);

    // 把 config 换成指向另一文件的符号链接：写盘必拒（符号链接保护）。
    let real = f.auth_target.parent().unwrap().join("real-config.toml");
    fs::write(&real, config_old).unwrap();
    fs::remove_file(&f.config_target).unwrap();
    std::os::unix::fs::symlink(&real, &f.config_target).unwrap();

    let err = f.service.apply_codex(f.key_id, None, false).unwrap_err();
    assert!(matches!(err, Error::Inject { .. }), "{err:?}");
    assert_eq!(
        fs::read_to_string(&f.auth_target).unwrap(),
        auth_old,
        "config 写盘失败时 auth 必须被回滚"
    );
    assert_eq!(
        fs::read_to_string(&real).unwrap(),
        config_old,
        "链接目标不得被改"
    );
    assert!(
        fs::symlink_metadata(&f.config_target)
            .unwrap()
            .file_type()
            .is_symlink(),
        "失败后符号链接本身必须还在"
    );

    // 恢复：拆掉链接、放回普通文件，重投成功。
    fs::remove_file(&f.config_target).unwrap();
    fs::write(&f.config_target, config_old).unwrap();
    let outcome = f.service.apply_codex(f.key_id, None, false).unwrap();
    assert!(outcome.auth.is_some());
    let parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&f.auth_target).unwrap()).unwrap();
    assert_eq!(parsed["OPENAI_API_KEY"], SECRET);
    assert!(fs::read_to_string(&f.config_target).unwrap().contains(BASE));
}

/// Unix 专属：理由同 config_symlink_failure_rolls_auth_back_then_recovery_succeeds。
#[test]
#[cfg(unix)]
fn auth_symlink_failure_leaves_config_untouched() {
    // 第一文件（auth）写盘失败时，第二文件（config）根本不应被写。
    let f = setup();
    let auth_old = "{\n  \"auth_mode\": \"apikey\",\n  \"OPENAI_API_KEY\": \"sk-old\"\n}";
    let config_old = "option_a = \"x\"\n";
    write_both_old(&f, auth_old, config_old);
    grant_both(&f);

    let real = f.auth_target.parent().unwrap().join("real-auth.json");
    fs::write(&real, auth_old).unwrap();
    fs::remove_file(&f.auth_target).unwrap();
    std::os::unix::fs::symlink(&real, &f.auth_target).unwrap();

    let err = f.service.apply_codex(f.key_id, None, false).unwrap_err();
    assert!(matches!(err, Error::Inject { .. }), "{err:?}");
    assert_eq!(
        fs::read_to_string(&f.config_target).unwrap(),
        config_old,
        "auth 写盘失败时 config 必须一个字节都不动"
    );
    assert_eq!(fs::read_to_string(&real).unwrap(), auth_old);
}

#[test]
fn preserve_leaves_auth_bytes_untouched_and_records_only_config() {
    // 保留分支的硬核场景：auth 里是官方 ChatGPT 登录态——双文件会拒绝，
    // 保留必须成功且 auth 字节一动不动。
    let f = setup();
    let official =
        "{\n  \"auth_mode\": \"chatgpt\",\n  \"tokens\": {\"access_token\": \"official-token\"}\n}";
    write_both_old(&f, official, "option_a = \"x\"\n");
    // 双文件先确认会拒绝（ChatGPT 登录态保护），且两文件都不动——
    // 为走到计划阶段，双文件这步先把两条同意都授上；保留那步只靠 config 同意。
    grant_both(&f);
    let dual_err = f.service.apply_codex(f.key_id, None, false).unwrap_err();
    assert!(matches!(dual_err, Error::Inject { .. }), "{dual_err:?}");
    assert_eq!(fs::read_to_string(&f.auth_target).unwrap(), official);

    let outcome = f.service.apply_codex(f.key_id, None, true).unwrap();
    assert!(outcome.preserve_auth);
    assert!(outcome.auth.is_none(), "保留结果不得含 auth");
    assert_eq!(
        fs::read_to_string(&f.auth_target).unwrap(),
        official,
        "保留分支 auth.json 必须字节不变"
    );
    let written_config = fs::read_to_string(&f.config_target).unwrap();
    assert!(written_config.contains(BASE));
    assert!(!written_config.contains(SECRET));

    // 记账：只记 config 一行——没动过的文件不得有「已投递」绑定。
    let history = f.service.delivery_history(10).unwrap();
    assert!(
        history
            .iter()
            .any(|r| r.target_path == f.config_target.display().to_string()
                && r.journal_id == outcome.journal_id),
        "保留必须记 config 绑定: {history:?}"
    );
    assert!(
        !history
            .iter()
            .any(|r| r.target_path == f.auth_target.display().to_string()),
        "保留不得记 auth 绑定: {history:?}"
    );

    // 保留分支同样可回滚：滚掉 config，auth 仍是官方内容。
    f.service.rollback_delivery(&outcome.journal_id).unwrap();
    assert_eq!(fs::read_to_string(&f.auth_target).unwrap(), official);
    assert_eq!(
        fs::read_to_string(&f.config_target).unwrap(),
        "option_a = \"x\"\n"
    );
}

#[test]
fn preserve_requires_only_config_consent() {
    let f = setup();
    // 只授 config 同意，保留直接成功（不需要 auth 同意）。
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexConfig)
        .unwrap();
    let outcome = f.service.apply_codex(f.key_id, None, true).unwrap();
    assert!(outcome.auth.is_none());
    assert!(f.config_target.exists());
    assert!(!f.auth_target.exists(), "保留不得创建 auth.json");

    // 反过来：只授 auth 同意、没授 config，保留必须拒绝。
    let f = setup();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    let err = f.service.apply_codex(f.key_id, None, true).unwrap_err();
    assert!(matches!(err, Error::ConsentRequired { .. }), "{err:?}");
    assert!(!f.config_target.exists(), "保留缺同意时 config 不得创建");
}

#[test]
fn dual_accounting_failure_rolls_both_back() {
    // 记账失败（journal 表没了）时，两文件必须一起滚回——否则用户拿不到
    // journal_id，等于留下一个无法撤销的双文件改动。
    let f = setup();
    grant_both(&f);
    f.service.apply_codex(f.key_id, None, false).unwrap();
    let before_auth = fs::read_to_string(&f.auth_target).unwrap();
    let before_config = fs::read_to_string(&f.config_target).unwrap();

    // 换一把密钥，保证这次投递真的会改动两文件（否则「内容没变」是空断言）。
    f.vault
        .put(&secret_ref("key", 1, "secret"), "sk-rotated-999999999999")
        .unwrap();
    let conn = rusqlite::Connection::open(&f.db_path).expect("直连库");
    conn.execute_batch("DROP TABLE journals;").expect("删表");

    let err = f.service.apply_codex(f.key_id, None, false).unwrap_err();
    assert!(matches!(err, Error::Store(_)), "{err:?}");
    assert_eq!(
        fs::read_to_string(&f.auth_target).unwrap(),
        before_auth,
        "记账失败必须回滚 auth"
    );
    assert_eq!(
        fs::read_to_string(&f.config_target).unwrap(),
        before_config,
        "记账失败必须回滚 config"
    );
}

#[test]
fn dual_accounting_second_binding_failure_marks_journal_rolled_back() {
    // P0-2 复审 P1-1：记账失败的另一半路径——`record_journal` 成功、第一条绑定
    // （auth）成功、第二条绑定（config）失败。旧代码只滚文件，不改 journal 状态，
    // 账面会留下「auth 已投递、可回滚」+ 漂移误报 modified + 历史回滚被哈希校验拒绝。
    //
    // 失败注入不用 DROP TABLE（那是第一条写就失败，根本走不到这条路径）：
    // 用触发器拦第二条 INSERT——config 绑定写入时，同 journal_id 的 auth 绑定行
    // 已经存在（第一条刚提交），触发器据此精确地只拦第二条。
    let f = setup();
    grant_both(&f);
    f.service.apply_codex(f.key_id, None, false).unwrap();
    let before_auth = fs::read_to_string(&f.auth_target).unwrap();
    let before_config = fs::read_to_string(&f.config_target).unwrap();

    // 换一把密钥，保证这次投递真的会改动两文件（否则「内容没变」是空断言）。
    f.vault
        .put(&secret_ref("key", 1, "secret"), "sk-rotated-999999999999")
        .unwrap();
    let config_escaped = f.config_target.display().to_string().replace('\'', "''");
    let conn = rusqlite::Connection::open(&f.db_path).expect("直连库");
    conn.execute_batch(&format!(
        "CREATE TRIGGER fail_second_codex_binding BEFORE INSERT ON bindings \
         WHEN NEW.target_path = '{config_escaped}' \
           AND EXISTS (SELECT 1 FROM bindings WHERE journal_id = NEW.journal_id) \
         BEGIN SELECT RAISE(ABORT, 'injected second binding failure'); END;"
    ))
    .expect("建触发器");

    let err = f.service.apply_codex(f.key_id, None, false).unwrap_err();
    assert!(matches!(err, Error::Store(_)), "{err:?}");
    assert_eq!(
        fs::read_to_string(&f.auth_target).unwrap(),
        before_auth,
        "第二条绑定失败时 auth 文件必须被回滚"
    );
    assert_eq!(
        fs::read_to_string(&f.config_target).unwrap(),
        before_config,
        "第二条绑定失败时 config 文件必须被回滚"
    );

    // 账面：这次失败投递的 auth 绑定行（同 target 最新的一行）必须标为已回滚，
    // 而不是继续显示「已投递、可回滚」。
    let history = f.service.delivery_history(10).unwrap();
    let auth_rows: Vec<_> = history
        .iter()
        .filter(|r| r.target_path == f.auth_target.display().to_string())
        .collect();
    let latest_auth = auth_rows
        .iter()
        .max_by_key(|r| r.binding_id)
        .expect("auth 历史行");
    assert!(
        latest_auth.rolled_back,
        "失败单的 auth 绑定必须标已回滚: {latest_auth:?}"
    );

    // 漂移：已回滚的绑定不得再当「现状」算期望哈希——两文件都应回到
    // 第一次成功投递的 intact，而不是 auth 误报 modified。
    let reports = f.service.drift_report().unwrap();
    let auth_report = reports
        .iter()
        .find(|r| r.target_path == f.auth_target)
        .expect("auth 应在漂移报告里");
    let config_report = reports
        .iter()
        .find(|r| r.target_path == f.config_target)
        .expect("config 应在漂移报告里");
    assert_eq!(auth_report.state.as_str(), "intact");
    assert_eq!(config_report.state.as_str(), "intact");
}

#[test]
fn drift_after_dual_reports_per_file() {
    let f = setup();
    grant_both(&f);
    f.service.apply_codex(f.key_id, None, false).unwrap();

    // 只改 config：漂移必须只报 config，auth 仍 intact——共享 journal
    // 不得把两文件的漂移混成一笔账。
    fs::write(&f.config_target, "被外部改过的内容\n").unwrap();
    let reports = f.service.drift_report().unwrap();
    let auth_report = reports
        .iter()
        .find(|r| r.target_path == f.auth_target)
        .expect("auth 应在漂移报告里");
    let config_report = reports
        .iter()
        .find(|r| r.target_path == f.config_target)
        .expect("config 应在漂移报告里");
    assert_eq!(auth_report.state.as_str(), "intact");
    assert_eq!(config_report.state.as_str(), "modified");
    assert_eq!(
        auth_report.journal_id, config_report.journal_id,
        "两行共享同一 journal"
    );
}
