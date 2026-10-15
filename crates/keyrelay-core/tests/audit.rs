//! 脱敏审计的端到端验证（M4-S1 spec §7）。
//!
//! 关键：这条测试必须**能失败**——人为往落盘产物里塞明文时，审计要报出来。
//! 否则「审计通过」就只是空跑。

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use keyrelay_core::delivery::DeliveryChannel;
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::transport::MockTransport;
use keyrelay_core::store::Store;
use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};

const SECRET: &str = "sk-audit-0123456789abcdefSECRET";

struct Fixture {
    _dir: tempfile::TempDir,
    db_path: PathBuf,
    backup_dir: PathBuf,
    service: KeyRelayService<MockTransport>,
    key_id: i64,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let db_path = dir.path().join("keyrelay.db");
    let _ = &home;
    let backup_dir = dir.path().join("backups");

    let store = Store::open(&db_path).expect("文件库");
    let site_id = store
        .upsert_site("newapi", "https://relay.example.com", "测试站")
        .expect("写站点");
    let secret_ref = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &secret_ref, Some("1"), None)
        .expect("写密钥记录");

    let vault = Arc::new(MemoryVault::new());
    vault.put(&secret_ref, SECRET).expect("写钥匙串");

    let service = KeyRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault,
            home: home.clone(),
            backup_dir: backup_dir.clone(),
        },
    );

    Fixture {
        _dir: dir,
        db_path,
        backup_dir,
        service,
        key_id,
    }
}

#[test]
fn fresh_installation_is_clean() {
    let f = setup();
    let report = f.service.audit_redaction().unwrap();
    assert!(report.is_clean(), "{}", report.summary());
    assert!(report.files_scanned >= 1, "至少要扫到数据库文件");
    assert!(report.bytes_scanned > 0);
    assert!(report.summary().contains("未发现明文"));
}

#[test]
fn full_delivery_flow_stays_clean() {
    let f = setup();
    for channel in DeliveryChannel::ALL {
        // Continue 的条目必须有模型名（Continue 的 schema 必填），其余通道不需要
        let model = (channel == DeliveryChannel::OpenClaw).then_some("gpt-4o");
        f.service.grant_consent(f.key_id, channel).unwrap();
        f.service
            .apply_delivery_with_model(f.key_id, channel, model)
            .unwrap();
    }

    let report = f.service.audit_redaction().unwrap();
    assert!(
        report.is_clean(),
        "投递全流程后不得出现明文：{}",
        report.summary()
    );

    // 备份目录里的备份是「投递前的内容」，本来就不含密钥 → 仍然干净
    assert!(f.backup_dir.exists(), "应产生备份");
}

#[test]
fn audit_catches_plaintext_smuggled_into_the_backup_dir() {
    // **负对照**：人为把明文写进落盘产物，审计必须报出来
    let f = setup();
    fs::create_dir_all(&f.backup_dir).unwrap();
    fs::write(
        f.backup_dir.join("smuggled.json"),
        format!("{{\"OPENAI_API_KEY\":\"{SECRET}\"}}\n"),
    )
    .unwrap();

    let report = f.service.audit_redaction().unwrap();
    assert!(!report.is_clean(), "审计没发现人为明文 → 是空跑");
    assert!(
        report.summary().contains("smuggled.json"),
        "{}",
        report.summary()
    );
    assert_eq!(report.plaintext_findings(), 1);
}

#[test]
fn audit_catches_plaintext_in_the_database_bytes() {
    let f = setup();
    // 直接往文件库里塞一行含明文的站点名（模拟未来某个缺陷把明文写进了库）
    {
        let conn = rusqlite::Connection::open(&f.db_path).unwrap();
        conn.execute(
            "UPDATE sites SET display_name = ?1 WHERE id = 1",
            [format!("泄露的站 {SECRET}")],
        )
        .unwrap();
    }

    let report = f.service.audit_redaction().unwrap();
    assert!(!report.is_clean(), "数据库字节里的明文必须被发现");
}

#[test]
fn audit_catches_plaintext_in_the_events_table() {
    let f = setup();
    // 绕过 observability 的脱敏入口，手工构造一条含明文的事件
    let raw = keyrelay_core::observability::Event {
        ts: 0,
        level: keyrelay_core::observability::Level::Info,
        source: "app".to_string(),
        message: format!("手工明文 {SECRET}"),
        payload: None,
    };
    Store::open(&f.db_path).unwrap().insert_event(&raw).unwrap();

    let report = f.service.audit_redaction().unwrap();
    assert!(!report.is_clean());
    let has_event_finding = report.findings.iter().any(|finding| {
        matches!(
            finding,
            keyrelay_core::audit::AuditFinding::PlaintextInEvents { .. }
        )
    });
    assert!(has_event_finding, "应有一条针对事件表的发现: {report:?}");
}

#[test]
fn the_events_table_guard_scans_every_row_not_just_the_newest_ones() {
    // 复审 P2-13：`count_events_with_secrets` 以前靠 `list_events(usize::MAX)`，
    // 而 `usize::MAX as i64 == -1` 恰好被 SQLite 解释成「不限制」。
    // 一旦给 `list_events` 加上限（`recent_events` 就有 `min(1000)`），
    // 这条红线守护会静默只扫最近的若干条 —— 所以这里把明文塞进**最老**的一条，
    // 后面再压上远超任何合理上限的干净事件。
    let f = setup();
    let store = Store::open(&f.db_path).unwrap();

    let raw = keyrelay_core::observability::Event {
        ts: 0,
        level: keyrelay_core::observability::Level::Info,
        source: "app".to_string(),
        message: format!("最老的一条手工明文 {SECRET}"),
        payload: None,
    };
    store.insert_event(&raw).unwrap();

    for i in 0..1500 {
        let clean = keyrelay_core::observability::Event {
            ts: i,
            level: keyrelay_core::observability::Level::Debug,
            source: "app".to_string(),
            message: format!("干净事件 {i}"),
            payload: None,
        };
        store.insert_event(&clean).unwrap();
    }

    assert_eq!(
        store.count_events_with_secrets().unwrap(),
        1,
        "最老那条明文必须仍然被扫到——被条数上限截断就说明守护在空跑"
    );

    // 端到端：审计报告同样要报出来
    let report = f.service.audit_redaction().unwrap();
    assert!(!report.is_clean(), "事件表里的明文必须被发现");
}

#[test]
fn audit_covers_the_export_directory() {
    // M4-S2 复审 P2-11：审计以前只扫 db/-wal/-shm + backups，导出产物是盲区。
    // 这里两头都要断言：① 导出物**在扫描范围内**（files_scanned 有增量），
    // ② 密文导出**不误报**、明文导出**必须被抓**。
    // 只断言 ② 是不够的 —— 「没报」也可能只是「压根没扫」。
    let f = setup();
    let exports_dir = f.backup_dir.parent().unwrap().join("exports");
    fs::create_dir_all(&exports_dir).unwrap();

    let baseline = f.service.audit_redaction().unwrap();
    assert!(baseline.is_clean(), "空导出目录不该影响结论");

    // ① 加密导出：不误报，但确实被扫到了
    let encrypted_path = exports_dir.join("encrypted.json");
    let outcome = f
        .service
        .export_to_file(&encrypted_path, Some("correct horse battery staple"))
        .unwrap();
    assert!(outcome.encrypted);

    let with_export = f.service.audit_redaction().unwrap();
    assert!(
        with_export.is_clean(),
        "加密导出物不该被误报成明文: {:?}",
        with_export.findings
    );
    assert!(
        with_export.files_scanned > baseline.files_scanned,
        "导出产物必须真的进了扫描范围（基线 {} → 现在 {}）——没增量就是盲区还在",
        baseline.files_scanned,
        with_export.files_scanned
    );

    // ② 明文落进导出目录：必须被抓出来。
    //    注意不能靠「明文导出物」来测 —— 导出**按设计**就不含密钥本体
    //    （`plaintext_export_has_no_key_material` 钉着这条），所以这里手工塞一个。
    let smuggled = exports_dir.join("smuggled.json");
    fs::write(&smuggled, format!("{{\"leaked\":\"{SECRET}\"}}")).unwrap();

    let dirty = f.service.audit_redaction().unwrap();
    assert!(
        !dirty.is_clean(),
        "导出目录里的明文必须被审计抓出来: {:?}",
        dirty.findings
    );
    assert!(
        dirty.findings.iter().any(|finding| matches!(
            finding,
            keyrelay_core::audit::AuditFinding::PlaintextInFile { path, .. }
                if path == &smuggled
        )),
        "发现项必须指向导出目录里那个文件: {:?}",
        dirty.findings
    );
}

#[test]
fn audit_reports_do_not_leak_the_secret_themselves() {
    // 审计报告会被写进事件表与 UI——它自己不能成为泄漏通道
    let f = setup();
    fs::create_dir_all(&f.backup_dir).unwrap();
    fs::write(f.backup_dir.join("leak.txt"), format!("{SECRET}\n")).unwrap();

    let report = f.service.audit_redaction().unwrap();
    let debug = format!("{report:?}");
    assert!(!debug.contains(SECRET), "审计报告自身泄漏: {debug}");
    assert!(report.summary().contains("leak.txt"), "但要指出是哪个文件");

    for row in f.service.recent_events(200).unwrap() {
        assert!(!row.message.contains(SECRET), "事件泄漏: {}", row.message);
        if let Some(payload) = row.payload {
            assert!(!payload.contains(SECRET), "事件载荷泄漏: {payload}");
        }
    }
}

#[test]
fn audit_scans_wal_and_shm_when_present() {
    let f = setup();
    // 触发一次写入，确保 WAL 里有内容
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();

    let report = f.service.audit_redaction().unwrap();
    assert!(report.is_clean(), "{}", report.summary());
    // 至少扫到 db 本身；WAL/SHM 存在时也应被扫到
    assert!(report.files_scanned >= 1);
}

/// `merge_export_registry` 的并集语义（M5-S1 / B-60 的扫描集合那一半）。
#[test]
fn merge_export_registry_dedupes_and_keeps_order() {
    let mut paths = vec![PathBuf::from("/already/scanned.db")];
    let record = |path: &str, bytes: i64| keyrelay_core::store::ExportRecord {
        path: path.to_string(),
        encrypted: false,
        bytes,
        exported_at: 0,
    };
    let records = vec![
        record("/already/scanned.db", 1), // 与已有项重复
        record("/user/chosen/a.json", 2),
        record("/user/chosen/a.json", 3), // 登记表内部重复
        record("/user/chosen/b.json", 4),
    ];

    keyrelay_core::audit::merge_export_registry(&mut paths, &records);
    assert_eq!(
        paths,
        vec![
            PathBuf::from("/already/scanned.db"),
            PathBuf::from("/user/chosen/a.json"),
            PathBuf::from("/user/chosen/b.json"),
        ],
        "并集去重：已有项不动、新项按登记顺序追加"
    );

    let before = paths.clone();
    keyrelay_core::audit::merge_export_registry(&mut paths, &[]);
    assert_eq!(paths, before, "空登记表不该改动集合");
}

/// B-60：用户自选的导出路径不在任何固定目录里，只能靠登记表找回来。
///
/// 这里构造一个**默认导出目录之外**的明文文件并登记它，断言它真的进了扫描集合 ——
/// 只断言「审计报了」是不够的，还要断言它指向的是那个文件。
/// （`audit_redaction` 里那两行接线由 Lead 在 M5-S5 落地；本测试钉的是原语行为。）
#[test]
fn audit_registry_paths_enter_the_scan_set_outside_the_default_export_dir() {
    let f = setup();
    let chosen_dir = tempfile::tempdir().unwrap(); // 模拟用户自选的目录
    let chosen = chosen_dir.path().join("my-export.json");
    fs::write(&chosen, format!("{{\"leaked\":\"{SECRET}\"}}")).unwrap();

    let store = Store::open(&f.db_path).unwrap();
    store.record_export(&chosen, false, 64).unwrap();

    // 与 `audit_redaction` 的组装顺序一致：固定路径 + 登记表
    let mut paths = vec![f.db_path.clone(), f.backup_dir.clone()];
    let records = store.list_exports().unwrap();
    assert_eq!(records.len(), 1, "登记表应有一条: {records:?}");
    keyrelay_core::audit::merge_export_registry(&mut paths, &records);

    let report = keyrelay_core::audit::scan_paths(&paths);
    assert!(
        !report.is_clean(),
        "登记表里的导出路径必须进扫描集合: {report:?}"
    );
    assert!(
        report.findings.iter().any(|finding| matches!(
            finding,
            keyrelay_core::audit::AuditFinding::PlaintextInFile { path, .. } if path == &chosen
        )),
        "发现项必须指向用户自选路径那个文件: {:?}",
        report.findings
    );
}

/// 登记表里的路径**可能已被用户删掉**：审计不得因此报错、误报或 panic。
#[test]
fn registry_paths_that_no_longer_exist_are_skipped_without_error() {
    let f = setup();
    let store = Store::open(&f.db_path).unwrap();

    let gone_dir = tempfile::tempdir().unwrap();
    let gone = gone_dir.path().join("deleted-after-export.json");
    store.record_export(&gone, true, 128).unwrap();
    // 极端输入：空路径也要扛住（不算 Unreadable、不 panic）
    store
        .record_export(std::path::Path::new(""), false, 0)
        .unwrap();
    drop(gone_dir); // 目录连同文件一起消失，模拟「用户删掉了导出物」

    let mut paths = vec![f.db_path.clone(), f.backup_dir.clone()];
    let baseline = keyrelay_core::audit::scan_paths(&paths);
    keyrelay_core::audit::merge_export_registry(&mut paths, &store.list_exports().unwrap());
    let after = keyrelay_core::audit::scan_paths(&paths);

    assert_eq!(
        after.files_scanned, baseline.files_scanned,
        "不存在的登记路径不该增加扫描计数"
    );
    assert!(after.is_clean(), "{}", after.summary());
    assert!(
        after.findings.is_empty(),
        "不存在的路径不该产生任何发现（含 Unreadable）: {:?}",
        after.findings
    );
}
