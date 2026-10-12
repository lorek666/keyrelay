//! 导出、加密与备份清理（M4-S2 spec §7）。

use std::fs;
use std::sync::Arc;

use keyrelay_core::delivery::DeliveryChannel;
use keyrelay_core::export;
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::transport::MockTransport;
use keyrelay_core::store::Store;
use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};

const SECRET: &str = "sk-export-0123456789abcdefSECRET";

struct Fixture {
    _dir: tempfile::TempDir,
    backup_dir: std::path::PathBuf,
    service: KeyRelayService<MockTransport>,
    key_id: i64,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let backup_dir = dir.path().join("backups");

    let store = Store::open(&dir.path().join("keyrelay.db")).expect("文件库");
    let site_id = store
        .upsert_site("newapi", "https://relay.example.com", "测试站")
        .expect("写站点");
    let secret_ref = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &secret_ref, Some("12"))
        .expect("写密钥记录");

    let vault = Arc::new(MemoryVault::new());
    vault.put(&secret_ref, SECRET).expect("写钥匙串");

    let service = KeyRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault,
            home,
            backup_dir: backup_dir.clone(),
        },
    );

    Fixture {
        _dir: dir,
        backup_dir,
        service,
        key_id,
    }
}

#[test]
fn plaintext_export_has_no_key_material() {
    let f = setup();
    let bundle = f.service.export_bundle().unwrap();
    let text = export::to_json(&bundle).unwrap();

    assert_eq!(bundle.version, export::EXPORT_VERSION);
    assert_eq!(bundle.sites.len(), 1);
    assert_eq!(bundle.keys.len(), 1);
    assert_eq!(bundle.keys[0].name, "codex/daily");

    // **红线**：导出物里不能有任何密钥材料
    assert!(!text.contains(SECRET), "导出物含密钥明文");
    assert!(!text.contains("sk-"), "导出物出现密钥形态");
    assert!(!text.contains("secret_ref"), "不该导出钥匙串引用");
    assert!(!text.contains("kr/key"), "不该导出钥匙串引用");

    // 也不该含本地网关令牌之类的东西
    assert!(!text.contains("kr-gw-"));
}

#[test]
fn export_file_round_trips_through_disk() {
    let f = setup();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.json");

    let (written, encrypted, bytes) = f.service.export_to_file(&path, None).unwrap();
    assert_eq!(written, path);
    assert!(!encrypted);
    assert!(bytes > 0);
    assert!(path.exists());

    let text = fs::read_to_string(&path).unwrap();
    let bundle = export::from_json(&text).unwrap();
    assert_eq!(bundle.keys.len(), 1);
}

#[test]
fn encrypted_export_round_trips_and_hides_metadata() {
    let f = setup();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.json");

    let (_, encrypted, _) = f
        .service
        .export_to_file(&path, Some("correct horse battery staple"))
        .unwrap();
    assert!(encrypted);

    let text = fs::read_to_string(&path).unwrap();
    assert!(
        !text.contains("relay.example.com"),
        "加密后不该出现明文元数据"
    );
    assert!(!text.contains(SECRET));

    let bundle = export::decrypt(&text, "correct horse battery staple").unwrap();
    assert_eq!(bundle.sites[0].base_url, "https://relay.example.com");

    // 密码错必须失败
    assert!(export::decrypt(&text, "wrong").is_err());
}

/// 把信封里的 `iterations` 换掉（其余字段原样），用来测 KDF 迭代次数的区间校验。
fn with_iterations(envelope_json: &str, iterations: u32) -> String {
    let mut value: serde_json::Value = serde_json::from_str(envelope_json).unwrap();
    value["kdf"]["iterations"] = serde_json::json!(iterations);
    serde_json::to_string(&value).unwrap()
}

#[test]
fn a_tampered_envelope_with_an_absurd_iteration_count_is_refused() {
    // M4-S2 复审 P2-4：`decrypt` 完全信任信封里的 `iterations`。
    // 不设上限 → 伪造信封让 App 卡死（复审实测 5_000_000 次 = 39.1s）；
    // 不设下限 → 「1 轮 PBKDF2」的弱信封被照收。
    let f = setup();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.json");
    let password = "correct horse battery staple";
    f.service.export_to_file(&path, Some(password)).unwrap();
    let text = fs::read_to_string(&path).unwrap();

    // 对照组：区间内的值必须**过掉区间校验**、走到真正的解密那一步。
    // 注意这里不能断言「解密成功」——改了 `iterations` 就改了派生密钥，
    // 密文必然解不开。所以判据是「错误**不是**迭代次数那条」。
    for in_range in [
        export::MIN_KDF_ITERATIONS,
        export::MAX_KDF_ITERATIONS,
        150_000,
    ] {
        assert_ne!(
            in_range,
            export::PBKDF2_ITERATIONS,
            "对照组不能撞上信封里的原值，否则会解密成功"
        );
        let err = export::decrypt(&with_iterations(&text, in_range), password)
            .expect_err("改了迭代次数，密钥就不一样了，必然解不开");
        assert!(
            !err.to_string().contains("迭代次数"),
            "iterations={in_range} 在允许区间内，不该被区间校验拦下: {err}"
        );
    }
    // 前提检查：原封不动的信封能解开，否则上面那些「解不开」的判据都不成立
    assert!(
        export::decrypt(&text, password).is_ok(),
        "原始信封必须能解开"
    );

    // 越界的值必须被**区间校验**当场拒绝，而不是先去算 KDF
    for absurd in [0u32, 1, 1_000, 99_999, 1_000_001, 5_000_000, u32::MAX] {
        let started = std::time::Instant::now();
        let err = export::decrypt(&with_iterations(&text, absurd), password)
            .expect_err(&format!("iterations={absurd} 必须被拒"));
        let elapsed = started.elapsed();
        assert!(
            err.to_string().contains("迭代次数"),
            "错误文案应点明是迭代次数的问题: {err}"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "iterations={absurd} 被拒得太慢（{elapsed:?}）——说明还是先算了 KDF 才判"
        );
    }
}

#[test]
fn export_includes_consents_settings_and_events() {
    let f = setup();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    f.service
        .update_settings(&keyrelay_core::settings::Settings {
            refresh_interval_secs: 600,
            gateway_enabled: true,
            gateway_port: 9999,
            ..Default::default()
        })
        .unwrap();

    let bundle = f.service.export_bundle().unwrap();
    assert_eq!(bundle.consents.len(), 1);
    assert_eq!(bundle.consents[0].channel, "codex-auth-json");
    assert_eq!(bundle.settings.refresh_interval_secs, 600);
    assert!(bundle.settings.gateway_enabled);
    assert_eq!(bundle.settings.gateway_port, 9999);
    assert!(!bundle.events.is_empty(), "事件也应被导出");
}

#[test]
fn prune_backups_keeps_the_newest_entries() {
    let f = setup();
    fs::create_dir_all(&f.backup_dir).unwrap();
    // 手工造 5 个 journal 目录（名字形如 j<纳秒>-<序号>，排序≈时间排序）
    for i in 0..5 {
        let dir = f.backup_dir.join(format!("j{:020}-0", i));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("0-auth.json"), format!("backup {i}")).unwrap();
    }
    // 再放一个不像 journal 的文件，确认不会被误删
    fs::write(f.backup_dir.join("README.txt"), "别删我").unwrap();
    // **还要放一个不像 journal 的目录**（M4-S2 复审 P2-3）：只有文件的话，
    // `path.is_dir()` 这一条天然挡住变异，`starts_with('j')` 这条防呆就零覆盖 ——
    // 复审实测把 `j` 前缀判断删掉后，既有测试 9 passed 全部逃逸。
    // 名字故意排在 `j` **之前**，这样「取前 N 个删掉」的实现会先删到它。
    fs::create_dir_all(f.backup_dir.join("aaa-notes")).unwrap();
    fs::write(f.backup_dir.join("aaa-notes/keep.md"), "用户自己的东西").unwrap();
    fs::create_dir_all(f.backup_dir.join("J-uppercase")).unwrap();

    let removed = f.service.prune_backups(2).unwrap();
    assert_eq!(removed, 3, "5 个留 2 个应删 3 个 —— 只能删 journal 目录");

    let left: Vec<String> = fs::read_dir(&f.backup_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(
        left.len(),
        4,
        "2 个 journal + 2 个非 journal 目录: {left:?}"
    );
    assert_eq!(
        left.iter().filter(|name| name.starts_with('j')).count(),
        2,
        "只该剩最新的 2 个 journal: {left:?}"
    );
    // 最新的两个还在
    assert!(f.backup_dir.join("j00000000000000000003-0").exists());
    assert!(f.backup_dir.join("j00000000000000000004-0").exists());
    // 非 journal 文件没被动
    assert!(f.backup_dir.join("README.txt").exists());
    // 非 journal **目录**也不能被动（含内容）
    assert!(
        f.backup_dir.join("aaa-notes/keep.md").exists(),
        "非 journal 目录被误删了 —— `j` 前缀防呆失效"
    );
    assert!(
        f.backup_dir.join("J-uppercase").exists(),
        "大小写不同也不该删"
    );
}

#[test]
fn prune_backups_with_zero_clears_everything() {
    let f = setup();
    fs::create_dir_all(&f.backup_dir).unwrap();
    for i in 0..3 {
        fs::create_dir_all(f.backup_dir.join(format!("j{i}-0"))).unwrap();
    }
    assert_eq!(f.service.prune_backups(0).unwrap(), 3);
    let left = fs::read_dir(&f.backup_dir).unwrap().count();
    assert_eq!(left, 0);
}

#[test]
fn prune_backups_is_a_noop_when_there_is_no_backup_dir() {
    let f = setup();
    assert_eq!(f.service.prune_backups(3).unwrap(), 0);
}

#[test]
fn prune_backups_keeps_everything_when_keep_exceeds_count() {
    let f = setup();
    fs::create_dir_all(&f.backup_dir).unwrap();
    for i in 0..2 {
        fs::create_dir_all(f.backup_dir.join(format!("j{i}-0"))).unwrap();
    }
    assert_eq!(f.service.prune_backups(10).unwrap(), 0);
    assert_eq!(fs::read_dir(&f.backup_dir).unwrap().count(), 2);
}

#[test]
fn full_delivery_then_export_then_prune_stays_clean() {
    let f = setup();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    f.service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.json");
    f.service.export_to_file(&path, None).unwrap();
    assert!(!fs::read_to_string(&path).unwrap().contains(SECRET));

    f.service.prune_backups(0).unwrap();

    // 清理之后审计仍然干净
    let report = f.service.audit_redaction().unwrap();
    assert!(report.is_clean(), "{}", report.summary());
}
