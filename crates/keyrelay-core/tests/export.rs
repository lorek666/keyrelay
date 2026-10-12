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

    let removed = f.service.prune_backups(2).unwrap();
    assert_eq!(removed, 3, "5 个留 2 个应删 3 个");

    let left: Vec<String> = fs::read_dir(&f.backup_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(left.len(), 2);
    assert!(left.iter().all(|name| name.starts_with('j')));
    // 最新的两个还在
    assert!(f.backup_dir.join("j00000000000000000003-0").exists());
    assert!(f.backup_dir.join("j00000000000000000004-0").exists());
    // 非 journal 文件没被动
    assert!(f.backup_dir.join("README.txt").exists());
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
