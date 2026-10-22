//! `~/.codex/auth.json` 投递的端到端验证（M1-S2 spec §7 / §8）。
//!
//! 全部测试把 `home` 指向临时目录，绝不触碰用户真实的 `~/.codex`。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tianshu_relay_core::delivery::{ConsentState, DeliveryChannel};
use tianshu_relay_core::error::Error;
use tianshu_relay_core::service::{ServiceConfig, TianshuRelayService};
use tianshu_relay_core::site::transport::MockTransport;
use tianshu_relay_core::store::Store;
use tianshu_relay_core::vault::{secret_ref, MemoryVault, Vault};

/// 记账用钥匙串：把「读了几次」暴露出来，用于断言未同意时**不读钥匙串**。
struct SpyVault {
    inner: MemoryVault,
    gets: std::sync::atomic::AtomicUsize,
}

impl SpyVault {
    fn new() -> Self {
        Self {
            inner: MemoryVault::new(),
            gets: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn gets(&self) -> usize {
        self.gets.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Vault for SpyVault {
    fn backend_name(&self) -> &'static str {
        "memory"
    }
    fn probe(&self) -> tianshu_relay_core::Result<()> {
        Ok(())
    }
    fn put(&self, key: &str, secret: &str) -> tianshu_relay_core::Result<()> {
        self.inner.put(key, secret)
    }
    fn get(&self, key: &str) -> tianshu_relay_core::Result<Option<String>> {
        self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.get(key)
    }
    fn delete(&self, key: &str) -> tianshu_relay_core::Result<()> {
        self.inner.delete(key)
    }
}

const SECRET: &str = "sk-0123456789abcdefSECRET";

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    db_path: PathBuf,
    vault: Arc<SpyVault>,
    service: TianshuRelayService<MockTransport>,
    key_id: i64,
    target: PathBuf,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");

    let db_dir = dir.path().join("db");
    fs::create_dir_all(&db_dir).expect("db dir");
    let db_path = db_dir.join("tianshu-relay.db");
    let store = Store::open(&db_path).expect("文件库");
    let site_id = store
        .upsert_site("newapi", "https://relay.example.com", "测试站")
        .expect("写站点");

    let secret_ref = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &secret_ref, Some("1"), None)
        .expect("写密钥记录");

    let vault = Arc::new(SpyVault::new());
    vault.put(&secret_ref, SECRET).expect("写钥匙串");

    let service = TianshuRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault: vault.clone(),
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
        },
    );

    let target = home.join(".codex").join("auth.json");
    Fixture {
        _dir: dir,
        home,
        db_path,
        vault,
        service,
        key_id,
        target,
    }
}

fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).expect("stat").permissions().mode() & 0o777
}

#[test]
fn without_consent_nothing_is_written() {
    let f = setup();

    let before_gets = f.vault.gets();
    let err = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap_err();
    assert!(matches!(err, Error::ConsentRequired { .. }), "{err:?}");
    assert!(!f.target.exists(), "未同意时不得创建目标文件");
    assert!(!f.target.parent().unwrap().exists(), "连目录都不该建");
    assert_eq!(
        f.vault.gets(),
        before_gets,
        "未同意时不得读取钥匙串（spec §8.4）"
    );

    // 同意状态必须如实反映「从未同意」
    let plan = f
        .service
        .delivery_plan(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    assert_eq!(plan.consent, ConsentState::Missing);
}

#[test]
fn revoked_consent_blocks_delivery_again() {
    let f = setup();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    f.service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .expect("同意后应能投递");

    f.service
        .revoke_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    let err = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap_err();
    assert!(matches!(err, Error::ConsentRequired { .. }), "{err:?}");

    let plan = f
        .service
        .delivery_plan(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    assert!(
        matches!(plan.consent, ConsentState::Revoked { .. }),
        "{:?}",
        plan.consent
    );
}

#[test]
fn consent_is_recorded_without_any_secret() {
    let f = setup();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();

    let rows = f.service.list_consents().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].agent_id, "codex");
    assert_eq!(rows[0].channel, "codex-auth-json");
    assert!(rows[0].revoked_at.is_none());
    assert_eq!(rows[0].fields, r#"["auth_mode","OPENAI_API_KEY"]"#);
    assert!(!rows[0].fields.contains("sk-"), "同意记录里不得有密钥");
}

#[test]
fn plan_preview_never_contains_the_secret() {
    let f = setup();
    let plan = f
        .service
        .delivery_plan(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();

    assert_eq!(plan.agent_id, "codex");
    assert_eq!(plan.target_path, f.target);
    assert!(!plan.target_exists);
    assert_eq!(plan.fields[0].key, "auth_mode");
    assert_eq!(plan.fields[0].masked, "apikey");
    assert_eq!(plan.fields[1].masked, "…CRET");

    assert!(
        !plan.preview.contains(SECRET),
        "预览泄漏密钥: {}",
        plan.preview
    );
    assert!(!format!("{plan:?}").contains(SECRET), "Debug 泄漏密钥");
    assert!(!plan.preview.contains("0123456789"), "{}", plan.preview);
}

#[test]
fn delivery_writes_key_with_0600_and_preserves_other_keys() {
    let f = setup();
    // 预置一个带无关键的文件（模拟用户已有 ChatGPT 相关数据）
    fs::create_dir_all(f.target.parent().unwrap()).unwrap();
    fs::write(
        &f.target,
        "{\n  \"auth_mode\": \"apikey\",\n  \"tokens\": {\n    \"id_token\": \"keep-me\"\n  }\n}",
    )
    .unwrap();
    fs::set_permissions(
        &f.target,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();

    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    let outcome = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();

    assert_eq!(outcome.target_path, f.target);
    assert!(!outcome.journal_id.is_empty());
    assert!(outcome.backup_path.is_some(), "投递必须留备份");

    let written = fs::read_to_string(&f.target).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&written).unwrap();
    assert_eq!(parsed["OPENAI_API_KEY"], SECRET);
    assert_eq!(parsed["auth_mode"], "apikey");
    assert_eq!(parsed["tokens"]["id_token"], "keep-me", "无关键必须保留");
    assert_eq!(mode_of(&f.target), 0o600, "含密钥的文件必须是 0600");

    // 结果对象不得携带密钥
    assert!(!format!("{outcome:?}").contains(SECRET));
}

#[test]
fn fresh_file_is_created_with_0600() {
    let f = setup();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    f.service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();

    assert_eq!(mode_of(&f.target), 0o600, "新建的 auth.json 必须是 0600");
    let parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&f.target).unwrap()).unwrap();
    assert_eq!(parsed["OPENAI_API_KEY"], SECRET);
}

#[test]
fn refuses_to_clobber_chatgpt_auth_mode() {
    let f = setup();
    fs::create_dir_all(f.target.parent().unwrap()).unwrap();
    let before = "{\n  \"auth_mode\": \"chatgpt\",\n  \"tokens\": {\"access_token\": \"x\"}\n}";
    fs::write(&f.target, before).unwrap();

    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    let err = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap_err();
    assert!(matches!(err, Error::Inject { .. }), "{err:?}");
    assert_eq!(
        fs::read_to_string(&f.target).unwrap(),
        before,
        "拒绝时必须一个字节都没动"
    );
}

#[test]
fn refuses_to_overwrite_external_edits() {
    let f = setup();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    f.service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();

    // 外部（Codex CLI）改了这个文件
    let external = "{\n  \"auth_mode\": \"apikey\",\n  \"OPENAI_API_KEY\": \"sk-someone-else\"\n}";
    fs::write(&f.target, external).unwrap();

    // 第二次投递读到的 before 就是外部内容 → 会正常覆盖（这是我们自己的文件）
    // 真正要防的是「计划生成后、写入前」被改动，故手工构造一个过期计划：
    let stale = tianshu_relay_core::inject::Patch::secret_bearing(&f.target, "过期的前置内容", "x");
    let err =
        tianshu_relay_core::inject::apply(&[stale], &f.home.join(".tianshu-relay").join("backups"))
            .unwrap_err();
    assert!(matches!(err, Error::Inject { .. }), "{err:?}");
    assert_eq!(fs::read_to_string(&f.target).unwrap(), external);
}

#[test]
fn second_delivery_is_idempotent() {
    let f = setup();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    f.service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    let first = fs::read(&f.target).unwrap();

    f.service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    assert_eq!(
        fs::read(&f.target).unwrap(),
        first,
        "二次投递不得产生额外改动"
    );

    // 此时预览应显示「无变化」
    let plan = f
        .service
        .delivery_plan(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    assert_eq!(plan.preview, "(无变化)\n");
}

#[test]
fn rollback_restores_bytes_and_mode() {
    let f = setup();
    fs::create_dir_all(f.target.parent().unwrap()).unwrap();
    let before = "{\n  \"auth_mode\": \"apikey\"\n}";
    fs::write(&f.target, before).unwrap();
    fs::set_permissions(
        &f.target,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();

    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    let outcome = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    assert_ne!(fs::read_to_string(&f.target).unwrap(), before);

    f.service.rollback_delivery(&outcome.journal_id).unwrap();
    assert_eq!(
        fs::read_to_string(&f.target).unwrap(),
        before,
        "必须字节级还原"
    );
    assert_eq!(mode_of(&f.target), 0o600, "回滚后权限位必须保持");
}

#[test]
fn rollback_of_unknown_journal_is_not_found() {
    let f = setup();
    let err = f.service.rollback_delivery("j-does-not-exist").unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "{err:?}");
}

#[test]
fn missing_keychain_entry_is_reported_not_swallowed() {
    let f = setup();
    f.vault.delete(&secret_ref("key", 1, "secret")).unwrap();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();

    let err = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap_err();
    assert!(matches!(err, Error::Vault(_)), "{err:?}");
    assert!(!f.target.exists(), "取不到密钥时不得创建文件");
}

#[test]
fn unknown_key_id_is_not_found() {
    let f = setup();
    let err = f
        .service
        .delivery_plan(9999, DeliveryChannel::CodexAuthJson)
        .unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "{err:?}");
}

#[test]
fn every_channel_produces_a_plan() {
    // M2-S2 之后三条通道都实现了：逐个生成计划，确认目标路径落在 home 内、
    // 预览不含密钥、且都没同意时投递会被拒。
    let f = setup();
    for channel in DeliveryChannel::ALL {
        // Continue 的条目必须有模型名（Continue 的 schema 必填），其余通道不需要
        let model = (channel == DeliveryChannel::OpenClaw).then_some("gpt-4o");
        let plan = f
            .service
            .delivery_plan_with_model(f.key_id, channel, model)
            .unwrap_or_else(|e| panic!("{} 应能生成计划: {e}", channel.as_str()));

        assert_eq!(plan.channel, channel);
        assert!(
            plan.target_path.starts_with(&f.home),
            "{} 的目标越出 home: {}",
            channel.as_str(),
            plan.target_path.display()
        );
        assert!(
            !plan.preview.contains(SECRET),
            "{} 的预览泄漏密钥",
            channel.as_str()
        );
        assert!(
            !plan.fields.is_empty(),
            "{} 应至少声明一个字段",
            channel.as_str()
        );
        assert_eq!(
            plan.consent,
            ConsentState::Missing,
            "{} 初始应为未同意",
            channel.as_str()
        );

        let err = f.service.apply_delivery(f.key_id, channel).unwrap_err();
        assert!(
            matches!(err, Error::ConsentRequired { .. }),
            "{} 未同意时必须拒绝: {err:?}",
            channel.as_str()
        );
    }
}

#[test]
fn full_flow_leaves_no_secret_on_disk_or_in_logs() {
    let f = setup();
    // 预置一个不含密钥的文件，使这次投递真的产生备份（备份内容 = 投递前的文件）
    fs::create_dir_all(f.target.parent().unwrap()).unwrap();
    fs::write(&f.target, "{\n  \"auth_mode\": \"apikey\"\n}").unwrap();

    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    let outcome = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();

    // ① 结果对象与预览
    assert!(!format!("{outcome:?}").contains(SECRET));
    let plan = f
        .service
        .delivery_plan(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    assert!(!format!("{plan:?}").contains(SECRET));
    assert!(!plan.preview.contains(SECRET));

    // ② 同意记录
    for row in f.service.list_consents().unwrap() {
        assert!(!format!("{row:?}").contains(SECRET));
    }

    // ③ SQLite 字节（含 WAL / SHM）——这是本产品的红线
    let mut scanned = 0usize;
    for suffix in ["", "-wal", "-shm"] {
        let path = PathBuf::from(format!("{}{suffix}", f.db_path.display()));
        if let Ok(bytes) = fs::read(&path) {
            scanned += 1;
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains(SECRET), "{} 含密钥明文", path.display());
            assert!(
                !text.contains("0123456789abcdef"),
                "{} 含密钥片段",
                path.display()
            );
        }
    }
    assert!(scanned >= 1, "至少要扫到一个数据库文件");

    // ④ 备份目录里的备份**会**含密钥（它就是投递前的内容），
    //    但投递前的内容本来就不含密钥——确认这一点，避免把「备份」当成泄漏通道
    let backup = outcome.backup_path.expect("有备份");
    if let Ok(text) = fs::read_to_string(&backup) {
        assert!(
            !text.contains(SECRET),
            "备份里不该有密钥（投递前文件本就没有）"
        );
    }

    // ⑤ 目标文件里**必须**有密钥（这是投递的目的）
    assert!(fs::read_to_string(&f.target).unwrap().contains(SECRET));
}

// ================================================================ M1-S2 复审 P1 回归

#[test]
fn consent_check_precedes_lock_acquisition() {
    // 复审 P1-2 相关：没同意时必须报 ConsentRequired，而**不是** FileBusy——
    // 证明同意检查发生在取锁之前（否则用户会看到一个与真实原因无关的错误）。
    let f = setup();
    let lock_dir = tianshu_relay_core::inject::default_lock_dir();
    let _held = tianshu_relay_core::inject::lock::FileLock::acquire(&f.target, &lock_dir)
        .expect("手工占锁");

    let err = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap_err();
    assert!(
        matches!(err, Error::ConsentRequired { .. }),
        "无同意时应先报 ConsentRequired，实际: {err:?}"
    );
    assert!(!f.target.exists());
}

#[test]
fn accounting_failure_rolls_the_file_back() {
    // 复审 P1-4：文件写成功但记账失败时，用户拿不到 journal_id 就永远回滚不了。
    // 制造方式：直接 DROP 掉 journals 表，让 `record_journal` 必然失败。
    let f = setup();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();

    // 先正常投递一次，确认路径是通的，并留下一个「投递前」的内容
    f.service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    let before = fs::read_to_string(&f.target).unwrap();

    // 换一把密钥，保证这一次投递**真的会改动文件内容**——
    // 否则「内容没变」可能只是因为两次写入的内容本来就一样（空断言）。
    f.vault
        .put(&secret_ref("key", 1, "secret"), "sk-rotated-999999999999")
        .unwrap();

    let conn = rusqlite::Connection::open(&f.db_path).expect("直连库");
    conn.execute_batch("DROP TABLE journals;").expect("删表");

    let err = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap_err();
    assert!(matches!(err, Error::Store(_)), "{err:?}");
    assert_eq!(
        fs::read_to_string(&f.target).unwrap(),
        before,
        "记账失败必须自动回滚：文件内容要回到投递前的样子"
    );
}

#[test]
fn apply_uses_a_lock_dir_independent_of_backup_dir() {
    // 复审 P1-3：换个 backup_dir 不得换锁文件。这里用服务层验证：
    // 手工按 `default_lock_dir()` 占锁后，投递必须报 FileBusy 而不是照写。
    let f = setup();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();

    let lock_dir = tianshu_relay_core::inject::default_lock_dir();
    let _held = tianshu_relay_core::inject::lock::FileLock::acquire(&f.target, &lock_dir)
        .expect("手工占锁");

    let err = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap_err();
    assert!(matches!(err, Error::FileBusy(_)), "{err:?}");
    assert!(!f.target.exists(), "被锁住时不得写入");
}
