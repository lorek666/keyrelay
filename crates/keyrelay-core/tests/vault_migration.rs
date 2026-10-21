//! M33-S1：钥匙串 → 本地加密保险库的一次性迁移。
//!
//! 「钥匙串」在这里用 `MemoryVault` 代替：迁移逻辑只依赖 `Vault` trait，
//! 不需要真的读写系统钥匙串（真机迁移见 `docs/evidence/` 的手工记录）。

use std::path::PathBuf;

use keyrelay_core::store::Store;
use keyrelay_core::vault::migrate::{import_refs, migrate_once, MIGRATION_MARKER};
use keyrelay_core::vault::{LocalVault, MemoryVault, Vault};
use keyrelay_core::Error;

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "keyrelay-vault-mig-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
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
    let target = LocalVault::open_temp(&dir).unwrap();

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
    std::fs::remove_dir_all(&dir).ok();
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
    let target = LocalVault::open_temp(&dir).unwrap();

    let refs = vec!["kr/key/1/secret".to_string(), "kr/key/2/secret".to_string()];
    let report = import_refs(&source, &target, &refs).unwrap();

    assert_eq!(report.imported, 1);
    assert_eq!(report.failed.len(), 1);
    assert!(report.failed[0].0 == "kr/key/2/secret");
    assert!(
        source.get("kr/key/2/secret").is_err(),
        "源条目必须还在（读它仍报错）"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn migrate_once_sets_the_marker_and_is_idempotent() {
    let dir = temp_dir();
    let source = MemoryVault::new();
    source.put("kr/key/1/secret", "sk-one").unwrap();
    let target = LocalVault::open_temp(&dir).unwrap();

    let first = migrate_once(&source, &target, vec!["kr/key/1/secret".to_string()]).unwrap();
    assert!(!first.already_done);
    assert_eq!(first.report.imported, 1);
    assert!(target.meta_get(MIGRATION_MARKER).unwrap().is_some());

    let second = migrate_once(&source, &target, vec!["kr/key/1/secret".to_string()]).unwrap();
    assert!(second.already_done);
    assert_eq!(second.report.imported, 0);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_failed_migration_does_not_set_the_marker() {
    let dir = temp_dir();
    let source = FlakySource {
        inner: MemoryVault::new(),
        fail_on: "kr/key/1/secret".into(),
    };
    source.put("kr/key/1/secret", "sk-one").unwrap();
    let target = LocalVault::open_temp(&dir).unwrap();

    let outcome = migrate_once(&source, &target, vec!["kr/key/1/secret".to_string()]).unwrap();
    assert!(!outcome.already_done);
    assert_eq!(outcome.report.failed.len(), 1);
    assert!(
        target.meta_get(MIGRATION_MARKER).unwrap().is_none(),
        "有失败条目就不能写完成标记，否则下次不会再试"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn store_refs_cover_keys_and_site_sessions() {
    let store = Store::open_in_memory().unwrap();
    let site_id = store
        .upsert_site("newapi", "https://example.test", "示例")
        .unwrap();
    store
        .insert_key(site_id, "主密钥", "kr/key/7/secret", None, None)
        .unwrap();

    let refs = store.all_secret_refs().unwrap();
    assert!(refs.contains(&"kr/key/7/secret".to_string()), "{refs:?}");
    assert!(
        refs.contains(&format!("kr/site/{site_id}/session")),
        "站点会话引用必须被枚举到: {refs:?}"
    );
    // 去重 + 有序
    let mut sorted = refs.clone();
    sorted.sort();
    assert_eq!(refs, sorted);
}
