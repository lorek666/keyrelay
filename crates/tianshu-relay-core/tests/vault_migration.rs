//! M33-S1：钥匙串 → 本地加密保险库的一次性迁移。
//!
//! 「钥匙串」在这里用 `MemoryVault` 代替：迁移逻辑只依赖 `Vault` trait，
//! 不需要真的读写系统钥匙串（真机迁移见 `docs/evidence/` 的手工记录）。

use tianshu_relay_core::service::GATEWAY_TOKEN_REF;
use tianshu_relay_core::store::Store;
use tianshu_relay_core::vault::migrate::{
    abandon_migration, import_refs, migrate_once, refs_for_migration, retry_migration,
    should_auto_retry, status_for, MIGRATION_ATTEMPTS, MIGRATION_CLEANUP_PENDING,
    MIGRATION_FAILURES, MIGRATION_LAST_AT, MIGRATION_LAST_ERROR, MIGRATION_MARKER,
    MIGRATION_MAX_AUTO_ATTEMPTS,
};
use tianshu_relay_core::vault::{LocalVault, MemoryVault, Vault};
use tianshu_relay_core::Error;

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
    fn probe(&self) -> tianshu_relay_core::Result<()> {
        Ok(())
    }
    fn put(&self, key: &str, secret: &str) -> tianshu_relay_core::Result<()> {
        self.inner.put(key, secret)
    }
    fn get(&self, key: &str) -> tianshu_relay_core::Result<Option<String>> {
        if key == self.fail_on {
            return Err(Error::Vault("模拟读取失败".into()));
        }
        self.inner.get(key)
    }
    fn delete(&self, key: &str) -> tianshu_relay_core::Result<()> {
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

// ============================================================ M38-S2（B-219）状态与上限

/// 一个「删除源条目必失败」的源：验证 cleanup_pending 与 failed 的分离。
struct NoDeleteSource {
    inner: MemoryVault,
}

impl Vault for NoDeleteSource {
    fn backend_name(&self) -> &'static str {
        "no-delete-test"
    }
    fn probe(&self) -> tianshu_relay_core::Result<()> {
        Ok(())
    }
    fn put(&self, key: &str, secret: &str) -> tianshu_relay_core::Result<()> {
        self.inner.put(key, secret)
    }
    fn get(&self, key: &str) -> tianshu_relay_core::Result<Option<String>> {
        self.inner.get(key)
    }
    fn delete(&self, _key: &str) -> tianshu_relay_core::Result<()> {
        Err(Error::Vault("模拟删除失败".into()))
    }
}

/// 一个「读取错误里回显密钥形态」的源：验证失败 JSON 经 scrub 后不含明文。
struct EchoingFailSource {
    inner: MemoryVault,
    fail_on: String,
    echo: String,
}

impl Vault for EchoingFailSource {
    fn backend_name(&self) -> &'static str {
        "echoing-fail-test"
    }
    fn probe(&self) -> tianshu_relay_core::Result<()> {
        Ok(())
    }
    fn put(&self, key: &str, secret: &str) -> tianshu_relay_core::Result<()> {
        self.inner.put(key, secret)
    }
    fn get(&self, key: &str) -> tianshu_relay_core::Result<Option<String>> {
        if key == self.fail_on {
            return Err(Error::Vault(format!("模拟底层错误，回显 {}", self.echo)));
        }
        self.inner.get(key)
    }
    fn delete(&self, key: &str) -> tianshu_relay_core::Result<()> {
        self.inner.delete(key)
    }
}

#[test]
fn migration_attempts_and_failure_details_are_persisted() {
    let dir = temp_dir();
    let fail_ref = "kr/key/1/secret";
    let source = FlakySource {
        inner: MemoryVault::new(),
        fail_on: fail_ref.into(),
    };
    source.put(fail_ref, "sk-persist-probe-12345678").unwrap();
    let target = LocalVault::open_temp(dir.path()).unwrap();

    let outcome = migrate_once(&source, &target, vec![fail_ref.to_string()]).unwrap();
    assert_eq!(outcome.report.failed.len(), 1);

    let status = status_for(&target).unwrap();
    assert_eq!(status.phase, "pending");
    assert_eq!(status.attempts, 1);
    assert!(status.last_at.is_some(), "last_at 必须落库");
    let last_error = status.last_error.expect("last_error 必须有值");
    assert!(last_error.contains(fail_ref), "{last_error}");
    assert_eq!(status.failures.len(), 1);
    assert_eq!(status.failures[0].reference, fail_ref);
    // 失败 JSON 可反序列化，且**不含任何密钥形态**（探针扫整段 JSON）
    let raw = target
        .meta_get(MIGRATION_FAILURES)
        .unwrap()
        .expect("failures JSON 必须写");
    let parsed: serde_json::Value = serde_json::from_str(&raw).expect("failures 必须是合法 JSON");
    assert!(parsed.as_array().is_some_and(|a| a.len() == 1));
    assert!(!raw.contains("sk-"), "失败 JSON 不得含密钥形态: {raw}");
    assert!(!last_error.contains("sk-"), "last_error 不得含密钥形态");
    // 失败不写完成标记
    assert!(target.meta_get(MIGRATION_MARKER).unwrap().is_none());
}

#[test]
fn second_failure_exhausts_auto_retry() {
    let dir = temp_dir();
    let fail_ref = "kr/key/1/secret";
    let source = FlakySource {
        inner: MemoryVault::new(),
        fail_on: fail_ref.into(),
    };
    source.put(fail_ref, "sk-two-fails-12345678").unwrap();
    let target = LocalVault::open_temp(dir.path()).unwrap();

    assert!(should_auto_retry(&target).unwrap(), "初次应允许自动重试");
    migrate_once(&source, &target, vec![fail_ref.to_string()]).unwrap();
    assert!(
        should_auto_retry(&target).unwrap(),
        "第一次失败后仍允许第二次"
    );
    migrate_once(&source, &target, vec![fail_ref.to_string()]).unwrap();
    assert_eq!(
        status_for(&target).unwrap().attempts,
        MIGRATION_MAX_AUTO_ATTEMPTS
    );
    assert!(
        !should_auto_retry(&target).unwrap(),
        "达到上限后启动路径不得再碰钥匙串"
    );
    assert_eq!(status_for(&target).unwrap().phase, "retry_exhausted");
    // 第三次（即使再调）attempts 会变 3——但启动路径已不会调它；显式重试才允许。
}

#[test]
fn a_cleanup_only_failure_still_sets_the_marker() {
    let dir = temp_dir();
    let source = NoDeleteSource {
        inner: MemoryVault::new(),
    };
    source
        .put("kr/key/1/secret", "sk-cleanup-12345678")
        .unwrap();
    let target = LocalVault::open_temp(dir.path()).unwrap();

    let outcome = migrate_once(&source, &target, vec!["kr/key/1/secret".to_string()]).unwrap();
    assert_eq!(outcome.report.failed.len(), 0, "删除失败不阻塞完成标记");
    assert_eq!(outcome.report.cleanup_pending.len(), 1);
    assert!(
        target.meta_get(MIGRATION_MARKER).unwrap().is_some(),
        "数据已在本地库 ⇒ 必须写完成标记"
    );
    let status = status_for(&target).unwrap();
    assert_eq!(status.phase, "done");
    assert_eq!(status.cleanup_pending.len(), 1);
    assert_eq!(
        target
            .meta_get(MIGRATION_CLEANUP_PENDING)
            .unwrap()
            .as_deref()
            .map(|s| s.contains("kr/key/1/secret")),
        Some(true)
    );
    // 只差删除源的条目：源里还在（保留用户可逆性）
    assert_eq!(
        source.inner.get("kr/key/1/secret").unwrap().as_deref(),
        Some("sk-cleanup-12345678")
    );
}

#[test]
fn status_for_scrubs_secret_shapes_already_persisted_in_meta() {
    let dir = temp_dir();
    let target = LocalVault::open_temp(dir.path()).unwrap();
    let secret = "sk-legacy-meta-probe-0123456789";
    target
        .meta_set(MIGRATION_LAST_ERROR, &format!("旧失败原因 {secret}"))
        .unwrap();
    target
        .meta_set(
            MIGRATION_FAILURES,
            &serde_json::json!([{ "reference": "kr/key/1/secret", "reason": format!("回显 {secret}") }])
                .to_string(),
        )
        .unwrap();

    let status = status_for(&target).unwrap();
    let text = format!(
        "{} {:?}",
        status.last_error.unwrap_or_default(),
        status.failures
    );
    assert!(!text.contains(secret), "状态返回不得含密钥明文: {text}");
    assert!(text.contains("sk-***"), "应留下脱敏痕迹: {text}");
}

#[test]
fn abandon_does_not_overwrite_a_completed_marker() {
    let dir = temp_dir();
    let source = MemoryVault::new();
    source.put("kr/key/1/secret", "sk-done-12345678").unwrap();
    let target = LocalVault::open_temp(dir.path()).unwrap();
    migrate_once(&source, &target, vec!["kr/key/1/secret".to_string()]).unwrap();
    let before = target
        .meta_get(MIGRATION_MARKER)
        .unwrap()
        .expect("完成标记必须存在");
    assert!(!before.starts_with("abandoned:"));

    abandon_migration(&target).unwrap();

    assert_eq!(
        target.meta_get(MIGRATION_MARKER).unwrap().as_deref(),
        Some(before.as_str()),
        "已完成迁移不得被「放弃」覆盖"
    );
    assert_eq!(status_for(&target).unwrap().phase, "done");
}

#[test]
fn abandon_blocks_auto_retry_and_retry_clears_it() {
    let dir = temp_dir();
    let source = MemoryVault::new();
    source
        .put("kr/key/1/secret", "sk-abandon-12345678")
        .unwrap();
    let target = LocalVault::open_temp(dir.path()).unwrap();

    abandon_migration(&target).unwrap();
    assert!(!should_auto_retry(&target).unwrap(), "放弃后不得自动重试");
    assert_eq!(status_for(&target).unwrap().phase, "abandoned");
    let marker = target
        .meta_get(MIGRATION_MARKER)
        .unwrap()
        .expect("必须有 abandoned 标记");
    assert!(marker.starts_with("abandoned:"), "{marker}");
    // 幂等：再放弃一次不改写时间戳之外的语义（值仍以 abandoned: 开头）
    abandon_migration(&target).unwrap();
    // 显式重试：先清标记再跑
    let outcome = retry_migration(&source, &target, vec!["kr/key/1/secret".to_string()]).unwrap();
    assert!(!outcome.already_done);
    assert_eq!(outcome.report.imported, 1);
    assert_eq!(status_for(&target).unwrap().phase, "done");
    assert!(should_auto_retry(&target).unwrap() == false);
}

#[test]
fn status_for_reports_pending_done_abandoned_and_exhausted() {
    let dir = temp_dir();

    // pending
    let pending = LocalVault::open_temp(&dir.path().join("pending")).unwrap();
    assert_eq!(status_for(&pending).unwrap().phase, "pending");
    assert_eq!(status_for(&pending).unwrap().attempts, 0);

    // done
    let done = LocalVault::open_temp(&dir.path().join("done")).unwrap();
    let source = MemoryVault::new();
    source.put("kr/key/1/secret", "sk-done-12345678").unwrap();
    migrate_once(&source, &done, vec!["kr/key/1/secret".to_string()]).unwrap();
    assert_eq!(status_for(&done).unwrap().phase, "done");

    // abandoned
    let abandoned = LocalVault::open_temp(&dir.path().join("abandoned")).unwrap();
    abandon_migration(&abandoned).unwrap();
    assert_eq!(status_for(&abandoned).unwrap().phase, "abandoned");

    // retry_exhausted
    let exhausted = LocalVault::open_temp(&dir.path().join("exhausted")).unwrap();
    let failing = FlakySource {
        inner: MemoryVault::new(),
        fail_on: "kr/key/1/secret".into(),
    };
    failing
        .put("kr/key/1/secret", "sk-exhausted-12345678")
        .unwrap();
    migrate_once(&failing, &exhausted, vec!["kr/key/1/secret".to_string()]).unwrap();
    migrate_once(&failing, &exhausted, vec!["kr/key/1/secret".to_string()]).unwrap();
    assert_eq!(status_for(&exhausted).unwrap().phase, "retry_exhausted");
    assert_eq!(
        status_for(&exhausted).unwrap().attempts,
        MIGRATION_MAX_AUTO_ATTEMPTS
    );
    assert!(status_for(&exhausted).unwrap().last_at.is_some());
}

#[test]
fn failure_json_never_contains_secret_shapes_even_if_the_source_echoes_them() {
    let dir = temp_dir();
    let fail_ref = "kr/key/1/secret";
    let secret = "sk-echo-probe-0123456789abcdef";
    let source = EchoingFailSource {
        inner: MemoryVault::new(),
        fail_on: fail_ref.into(),
        echo: secret.to_string(),
    };
    source.put(fail_ref, secret).unwrap();
    let target = LocalVault::open_temp(dir.path()).unwrap();

    migrate_once(&source, &target, vec![fail_ref.to_string()]).unwrap();

    for key in [
        MIGRATION_FAILURES,
        MIGRATION_LAST_ERROR,
        MIGRATION_CLEANUP_PENDING,
    ] {
        if let Some(raw) = target.meta_get(key).unwrap() {
            assert!(!raw.contains(secret), "{key} 不得含密钥明文: {raw}");
            // 注意：脱敏痕迹 `sk-***` 本身含 `sk-` 前缀，所以这里判的是**完整明文**而不是前缀。
            if key == MIGRATION_FAILURES || key == MIGRATION_LAST_ERROR {
                assert!(raw.contains("sk-***"), "{key} 应留下脱敏痕迹: {raw}");
            }
        }
    }
    let attempts = target.meta_get(MIGRATION_ATTEMPTS).unwrap();
    assert_eq!(attempts.as_deref(), Some("1"));
    assert!(target.meta_get(MIGRATION_LAST_AT).unwrap().is_some());
}
