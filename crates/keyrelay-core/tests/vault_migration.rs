//! M33-S1：钥匙串 → 本地加密保险库的一次性迁移。
//!
//! 「钥匙串」在这里用 `MemoryVault` 代替：迁移逻辑只依赖 `Vault` trait，
//! 不需要真的读写系统钥匙串（真机迁移见 `docs/evidence/` 的手工记录）。

use keyrelay_core::service::GATEWAY_TOKEN_REF;
use keyrelay_core::store::Store;
use keyrelay_core::vault::migrate::{
    import_refs, migrate_once, refs_for_migration, MIGRATION_MARKER,
};
use keyrelay_core::vault::{LocalVault, MemoryVault, Vault};
use keyrelay_core::Error;

/// `tempfile::TempDir`：目录名由 OS 生成，并行测试不会撞名（复审 P2-2：
/// 自拼 pid+nanos 的目录曾在并行下产生 `disk I/O error` 的假失败）。
fn temp_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("建临时目录")
}

/// 一条读就报错的源后端：验证「失败条目留在源里、不影响其它条目」。
struct FlakySource {
    inner: MemoryVault,
    fail_on: String,
}

impl Vault for FlakySource {
    fn backend_name(&self) -> &'static str {
        "flaky-test"
    }
    fn probe(&self) -> keyrelay_core::Result<()> {
        Ok(())
    }
    fn put(&self, key: &str, secret: &str) -> keyrelay_core::Result<()> {
        self.inner.put(key, secret)
    }
    fn get(&self, key: &str) -> keyrelay_core::Result<Option<String>> {
        if key == self.fail_on {
            return Err(Error::Vault("模拟读取失败".into()));
        }
        self.inner.get(key)
    }
    fn delete(&self, key: &str) -> keyrelay_core::Result<()> {
        self.inner.delete(key)
    }
}

#[test]
fn imports_then_deletes_only_the_verified_entries() {
    let dir = temp_dir();
    let source = MemoryVault::new();
    source.put("kr/key/1/secret", "sk-one").unwrap();
    source.put("kr/key/2/secret", "sk-two").unwrap();
    let target = LocalVault::open_temp(dir.path()).unwrap();

    let refs = vec![
        "kr/key/1/secret".to_string(),
        "kr/key/2/secret".to_string(),
        "kr/key/3/secret".to_string(), // 源里没有 → skipped
    ];
    let report = import_refs(&source, &target, &refs).unwrap();

    assert_eq!(report.imported, 2);
    assert_eq!(report.skipped, 1);
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    assert_eq!(
        target.get("kr/key/1/secret").unwrap().as_deref(),
        Some("sk-one")
    );
    // 迁走的条目必须从源里删掉，否则「迁移」等于永久双写。
    assert_eq!(source.get("kr/key/1/secret").unwrap(), None);
    assert_eq!(source.get("kr/key/2/secret").unwrap(), None);
}

#[test]
fn a_failing_entry_stays_in_the_source() {
    let dir = temp_dir();
    let source = FlakySource {
        inner: MemoryVault::new(),
        fail_on: "kr/key/2/secret".into(),
    };
    source.put("kr/key/1/secret", "sk-one").unwrap();
    source.put("kr/key/2/secret", "sk-two").unwrap();
    let target = LocalVault::open_temp(dir.path()).unwrap();

    let refs = vec!["kr/key/1/secret".to_string(), "kr/key/2/secret".to_string()];
    let report = import_refs(&source, &target, &refs).unwrap();

    assert_eq!(report.imported, 1);
    assert_eq!(report.failed.len(), 1);
    assert!(report.failed[0].0 == "kr/key/2/secret");
    // 直接看内层：`FlakySource::get` 对失败键恒返回 Err，`is_err()` 分不清
    // 「还在」与「已被删掉」（复审 P2-1 指出的假绿）。
    assert_eq!(
        source.inner.get("kr/key/2/secret").unwrap().as_deref(),
        Some("sk-two"),
        "失败条目必须留在源里"
    );
}

#[test]
fn migrate_once_sets_the_marker_and_is_idempotent() {
    let dir = temp_dir();
    let source = MemoryVault::new();
    source.put("kr/key/1/secret", "sk-one").unwrap();
    let target = LocalVault::open_temp(dir.path()).unwrap();

    let first = migrate_once(&source, &target, vec!["kr/key/1/secret".to_string()]).unwrap();
    assert!(!first.already_done);
    assert_eq!(first.report.imported, 1);
    assert!(target.meta_get(MIGRATION_MARKER).unwrap().is_some());

    let second = migrate_once(&source, &target, vec!["kr/key/1/secret".to_string()]).unwrap();
    assert!(second.already_done);
    assert_eq!(second.report.imported, 0);
}

#[test]
fn a_failed_migration_does_not_set_the_marker() {
    let dir = temp_dir();
    let source = FlakySource {
        inner: MemoryVault::new(),
        fail_on: "kr/key/1/secret".into(),
    };
    source.put("kr/key/1/secret", "sk-one").unwrap();
    let target = LocalVault::open_temp(dir.path()).unwrap();

    let outcome = migrate_once(&source, &target, vec!["kr/key/1/secret".to_string()]).unwrap();
    assert!(!outcome.already_done);
    assert_eq!(outcome.report.failed.len(), 1);
    assert!(
        target.meta_get(MIGRATION_MARKER).unwrap().is_none(),
        "有失败条目就不能写完成标记，否则下次不会再试"
    );
}

#[test]
fn refs_cover_keys_site_sessions_and_the_gateway_token() {
    let store = Store::open_in_memory().unwrap();
    let site_id = store
        .upsert_site("newapi", "https://example.test", "示例")
        .unwrap();
    store
        .insert_key(site_id, "主密钥", "kr/key/7/secret", None, None)
        .unwrap();

    let refs = refs_for_migration(&store).unwrap();
    assert!(refs.contains(&"kr/key/7/secret".to_string()), "{refs:?}");
    assert!(
        refs.contains(&format!("kr/site/{site_id}/session")),
        "站点会话引用必须被枚举到: {refs:?}"
    );
    // 复审 P1-2：网关令牌没有 keys 行，必须显式带上，否则升级后 agent 配置全 401。
    assert!(
        refs.contains(&GATEWAY_TOKEN_REF.to_string()),
        "网关令牌必须进迁移集合: {refs:?}"
    );
    let mut sorted = refs.clone();
    sorted.sort();
    assert_eq!(refs, sorted);
}

#[test]
fn the_gateway_token_is_migrated_like_any_other_secret() {
    let dir = temp_dir();
    let source = MemoryVault::new();
    source.put(GATEWAY_TOKEN_REF, "local-token-value").unwrap();
    let target = LocalVault::open_temp(dir.path()).unwrap();

    let report = import_refs(&source, &target, &[GATEWAY_TOKEN_REF.to_string()]).unwrap();
    assert_eq!(report.imported, 1);
    assert_eq!(
        target.get(GATEWAY_TOKEN_REF).unwrap().as_deref(),
        Some("local-token-value")
    );
    assert_eq!(source.get(GATEWAY_TOKEN_REF).unwrap(), None);
}
