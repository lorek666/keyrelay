//! 导出登记表与审计覆盖面（M5-S5 接线 / 关闭 B-60 的另一半）。
//!
//! M5-S1 交付了原语（`Store::record_export` / `Store::list_exports` 由 M5-S0 冻结、
//! `audit::merge_export_registry` 由 M5-S1 交付），但**接线在 `service.rs`**。
//! 这个文件就是那条接线的端到端证据：
//!
//! - 自选导出路径（默认 `<app_data>/exports` 之外）真的进了审计的扫描集合；
//! - 没登记过的路径**不**进扫描集合（审计只扫自己的产物，不做全盘扫描）；
//! - 导出物被用户删掉后审计不报错；
//! - `export_bundle()` 返回的**内存**结构体也已经剥掉 userinfo（纵深防御）；
//! - 诊断导出与配置导出走同一套脱敏规则。

use std::fs;
use std::sync::Arc;

use keyrelay_core::audit::AuditFinding;
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::transport::MockTransport;
use keyrelay_core::store::Store;
use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};

const SECRET: &str = "sk-registry-0123456789abcdefSECRET";

struct Fixture {
    dir: tempfile::TempDir,
    db_path: std::path::PathBuf,
    service: KeyRelayService<MockTransport>,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let backup_dir = dir.path().join("backups");
    let db_path = dir.path().join("keyrelay.db");

    let store = Store::open(&db_path).expect("文件库");
    let site_id = store
        .upsert_site("newapi", "https://relay.example.com", "测试站")
        .expect("写站点");
    let secret_ref = secret_ref("key", 1, "secret");
    store
        .insert_key(site_id, "codex/daily", &secret_ref, Some("12"), None)
        .expect("写密钥记录");

    let vault = Arc::new(MemoryVault::new());
    vault.put(&secret_ref, SECRET).expect("写钥匙串");

    let service = KeyRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault,
            home,
            backup_dir,
        },
    );

    Fixture {
        dir,
        db_path,
        service,
    }
}

/// 绕过 `observability` 的脱敏入口，直接往事件表塞原文。
///
/// 模拟「将来某条路径把敏感文本写进了事件表」——导出是最后一道防线，
/// 这里要能兜住。
fn insert_raw_event(db_path: &std::path::Path, message: &str, payload: Option<&str>) {
    Store::open(db_path)
        .expect("重开文件库")
        .insert_event(&keyrelay_core::observability::Event {
            ts: 0,
            level: keyrelay_core::observability::Level::Info,
            source: "test".to_string(),
            message: message.to_string(),
            payload: payload.map(str::to_string),
        })
        .expect("写事件");
}

fn plaintext_finding_at(
    report: &keyrelay_core::audit::AuditReport,
    path: &std::path::Path,
) -> bool {
    report
        .findings
        .iter()
        .any(|f| matches!(f, AuditFinding::PlaintextInFile { path: p, .. } if p == path))
}

#[test]
fn a_user_chosen_export_path_enters_the_audit_scan_set() {
    let f = setup();
    // 自选路径：默认导出目录是 `<app_data>/exports`（即 `dir/exports`），
    // 这里故意写到 `dir/custom/` 下 —— B-60 说的就是这种「审计看不见」的路径。
    let custom = f.dir.path().join("custom").join("my-export.json");

    let outcome = f
        .service
        .export_to_file(&custom, None)
        .expect("导出到自选路径");
    assert_eq!(outcome.path, custom);
    assert!(!outcome.encrypted, "没给密码就应当是明文导出");
    assert!(outcome.bytes > 0);
    assert!(outcome.registered, "登记成功时 registered 必须为 true");

    // 前提：登记表里真的有它（否则下面的结论可能是别的原因造成的）
    let records = f.service.store().list_exports().expect("读登记表");
    assert_eq!(records.len(), 1, "一次导出应当只登记一条");
    assert_eq!(records[0].path, custom.to_string_lossy());
    assert!(!records[0].encrypted);

    // 前提：此刻审计是干净的（导出物按设计不含密钥本体）
    let clean = f.service.audit_redaction().expect("审计");
    assert!(clean.is_clean(), "前提不成立: {}", clean.summary());

    // 把明文塞进**这个自选路径**
    fs::write(&custom, format!("key={SECRET}\n")).expect("塞明文");

    let report = f.service.audit_redaction().expect("审计");
    assert!(
        !report.is_clean(),
        "登记过的自选导出路径必须被审计覆盖，实际: {}",
        report.summary()
    );
    assert!(
        plaintext_finding_at(&report, &custom),
        "审计必须报出这个自选路径，实际 findings: {:?}",
        report.findings
    );
}

#[test]
fn an_unregistered_path_is_not_scanned() {
    // 反向对照：证明上面那条不是因为「审计顺手扫了整个临时目录」才通过的。
    let f = setup();
    let stranger = f.dir.path().join("not-registered").join("other.json");
    fs::create_dir_all(stranger.parent().expect("父目录")).expect("建目录");
    fs::write(&stranger, format!("key={SECRET}\n")).expect("塞明文");

    let report = f.service.audit_redaction().expect("审计");
    assert!(
        !plaintext_finding_at(&report, &stranger),
        "审计只扫自己的产物，不得做全盘扫描；却报了 {:?}",
        report.findings
    );
}

#[test]
fn an_export_that_was_deleted_does_not_break_the_audit() {
    let f = setup();
    let custom = f.dir.path().join("custom").join("gone.json");
    f.service.export_to_file(&custom, None).expect("导出");
    assert!(custom.exists());

    fs::remove_file(&custom).expect("删掉导出物");

    let report = f
        .service
        .audit_redaction()
        .expect("登记表里的路径已不存在时审计不得报错");
    assert!(
        report.is_clean(),
        "删掉的文件不该产生发现: {}",
        report.summary()
    );
}

#[test]
fn the_in_memory_bundle_already_has_no_embedded_credentials() {
    // 纵深防御：序列化咽喉点已经剥过一次，`export_bundle()` 组装处也要剥 ——
    // 内存里的结构体不该带着内嵌凭证到处传。
    let f = setup();
    let site = f
        .service
        .store()
        .upsert_site("newapi", "https://user:pass@relay.example.com", "带凭证")
        .expect("写站点");

    let bundle = f.service.export_bundle().expect("组装导出包");
    let row = bundle
        .sites
        .iter()
        .find(|s| s.id == site)
        .expect("新站点应当在导出包里");
    assert_eq!(
        row.base_url, "https://relay.example.com",
        "内存态导出包也必须剥掉 userinfo"
    );
}

#[test]
fn diagnostics_export_scrubs_references_and_sensitive_payload_keys() {
    let f = setup();
    insert_raw_event(
        &f.db_path,
        "读到钥匙串引用 kr/key/1/secret 时出错",
        Some(r#"{"cookie":"hunter2","key_id":7,"site_id":1}"#),
    );

    let text = f.service.export_diagnostics(50).expect("诊断导出");

    assert!(
        !text.contains("kr/key/1/secret"),
        "诊断导出不得带出钥匙串引用: {text}"
    );
    assert!(
        !text.contains("hunter2"),
        "诊断导出不得带出敏感键的值: {text}"
    );
    // 非敏感键必须保留，否则脱敏就变成了「把证据全删了」
    assert!(text.contains("key_id"), "非敏感键必须保留: {text}");
    assert!(text.contains("site_id"), "非敏感键必须保留: {text}");
}

#[test]
fn a_failed_registration_is_reported_and_shows_up_in_the_audit_summary() {
    // M5-S2 复审 P2-3 / P2-4 的故障注入：把登记表拆掉，模拟「写登记失败」。
    let f = setup();
    {
        let conn = rusqlite::Connection::open(&f.db_path).expect("直连库");
        conn.execute_batch("DROP TABLE exports;")
            .expect("拆掉登记表");
    }

    let custom = f.dir.path().join("custom").join("unregistered.json");
    let outcome = f
        .service
        .export_to_file(&custom, None)
        .expect("文件本身必须写成功（不回滚、不谎报失败）");

    assert!(outcome.path.exists(), "登记失败不得回滚已经写好的文件");
    assert!(
        !outcome.registered,
        "登记失败必须如实上报 —— 只说「导出成功」就是在骗用户"
    );

    let report = f.service.audit_redaction().expect("审计");
    assert!(report.is_clean(), "读不到登记表 ≠ 有明文");
    assert!(
        report.summary().contains("覆盖面不完整"),
        "主文案必须说出覆盖面缺口，否则就是过度承诺: {}",
        report.summary()
    );
}

#[test]
fn both_export_exits_produce_the_same_scrubbed_payload() {
    // M5-S1 复审 P2-1：两条导出出口原来是各自手抄同一串组合，实测已经分叉。
    // 触发形态很隐蔽：**34 位数字**会被文本级 `scrub` 的「≥32 位 hex」规则打成 `***`，
    // 把 payload 变成**非法 JSON**，于是配置侧的结构化脱敏只能走兜底分支，
    // 而诊断侧拿到原始串能正常解析 —— 同一份事件，两条出口输出不同。
    let f = setup();
    let payload = r#"{"remaining":1234567890123456789012345678901234,"ref":"kr/key/1/secret","cookie":"hunter2","key_id":7}"#;
    insert_raw_event(&f.db_path, "事件 kr/key/1/secret", Some(payload));

    fn wanted(p: &str) -> bool {
        p.contains("key_id")
    }

    // 出口 ①：配置导出（落盘）
    let path = f.dir.path().join("cfg.json");
    f.service.export_to_file(&path, None).expect("配置导出");
    let text = fs::read_to_string(&path).expect("读导出文件");
    let bundle = keyrelay_core::export::from_json(&text).expect("导出物必须是合法 JSON");
    let from_config = bundle
        .events
        .iter()
        .filter_map(|e| e.payload.clone())
        .find(|p| wanted(p))
        .expect("配置导出里应当有那条事件");

    // 出口 ②：诊断导出
    let diag = f.service.export_diagnostics(50).expect("诊断导出");
    let diag_value: serde_json::Value =
        serde_json::from_str(&diag).expect("诊断导出必须是合法 JSON");
    let from_diag = diag_value["events"]
        .as_array()
        .expect("events 是数组")
        .iter()
        .filter_map(|e| e["payload"].as_str())
        .find(|p| wanted(p))
        .expect("诊断导出里应当有那条事件")
        .to_string();

    assert_eq!(
        from_config, from_diag,
        "两条导出出口必须产出同一份脱敏 payload"
    );
    // 而且它必须仍是**合法 JSON**：文本级预脱敏会把大整数打成 `***` 破坏结构
    serde_json::from_str::<serde_json::Value>(&from_config)
        .unwrap_or_else(|e| panic!("脱敏后的 payload 必须仍是合法 JSON（{e}）: {from_config}"));
    assert!(!from_config.contains("hunter2"), "{from_config}");
    assert!(!from_config.contains("kr/key/1/secret"), "{from_config}");
    assert!(
        from_config.contains("key_id"),
        "非敏感键必须保留: {from_config}"
    );
}
