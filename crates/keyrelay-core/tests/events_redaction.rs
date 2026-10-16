//! 事件表零明文守护（BACKLOG B-11 / B-31 / B-36）。
//!
//! 本文件的意义在于：`events` 表在 M1-S3 之前**零写入点**，
//! 「密钥不进事件表」是一条**空断言**（无可验证的防护路径）。
//! 现在有了写入方，这条断言才第一次可以被真正测到。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use keyrelay_core::delivery::DeliveryChannel;
use keyrelay_core::observability::{self, Event, Level};
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::transport::MockTransport;
use keyrelay_core::store::Store;
use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};

const SECRET: &str = "sk-0123456789abcdefSECRET";

struct Fixture {
    _dir: tempfile::TempDir,
    db_path: PathBuf,
    service: KeyRelayService<MockTransport>,
    key_id: i64,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let db_path = dir.path().join("keyrelay.db");

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
            home,
            backup_dir: dir.path().join("backups"),
        },
    );

    Fixture {
        _dir: dir,
        db_path,
        service,
        key_id,
    }
}

/// 另开一个连接扫同一份文件库（WAL 下并发读没问题）。
fn secret_hits(db_path: &Path) -> i64 {
    Store::open(db_path)
        .expect("复开库")
        .count_events_with_secrets()
        .expect("扫描事件表")
}

#[test]
fn full_delivery_flow_leaves_no_plaintext_in_events() {
    let f = setup();

    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    let _ = f
        .service
        .delivery_plan(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    let outcome = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    f.service.rollback_delivery(&outcome.journal_id).unwrap();

    let events = f.service.recent_events(200).unwrap();
    assert!(
        !events.is_empty(),
        "走完整个流程后事件表必须非空（否则「密钥不进事件表」仍是空断言）"
    );

    for row in &events {
        assert!(
            !row.message.contains(SECRET),
            "事件 message 泄漏密钥: {}",
            row.message
        );
        if let Some(payload) = &row.payload {
            assert!(
                !payload.contains(SECRET),
                "事件 payload 泄漏密钥: {payload}"
            );
            assert!(
                !payload.contains("0123456789"),
                "事件 payload 含密钥片段: {payload}"
            );
        }
    }

    assert_eq!(secret_hits(&f.db_path), 0, "事件表存在疑似未脱敏行");

    // 诊断导出同样不得带出密钥
    let exported = f.service.export_diagnostics(200).unwrap();
    assert!(!exported.contains(SECRET), "{exported}");

    // **哨兵**：业务路径本身不会把密钥塞进事件文本，所以只靠上面的扫描，
    // 「把 `event()` 里的 scrub 去掉」这种变异**不会**让本测试失败（复审 P2-5 实测空跑）。
    // 这里直投一条含密钥的事件，把「脱敏入口本身有效」钉进同一条用例。
    let sentinel = observability::event(
        Level::Warn,
        "delivery",
        format!("哨兵：站点回显了 {SECRET}"),
    );
    assert!(
        !sentinel.message.contains(SECRET),
        "脱敏入口失效：{}",
        sentinel.message
    );
    f.service.log_event_for_test(&sentinel);
    let after = f.service.recent_events(500).unwrap();
    assert!(
        after.iter().any(|row| row.message.contains("哨兵")),
        "哨兵事件没有落库"
    );
    assert_eq!(
        secret_hits(&f.db_path),
        0,
        "哨兵事件落库后出现了未脱敏行 → 脱敏入口失效"
    );
}

#[test]
fn event_table_scan_is_not_a_no_op() {
    let f = setup();

    // 负对照：**绕过** `observability::event()`，手工构造一个含明文的 Event 直接落库。
    // （`Event` 的字段是公开的，这正是扫描要抓的「绕过路径」。）
    let raw = Event {
        ts: 0,
        level: Level::Info,
        source: "app".to_string(),
        message: format!("手工明文 {SECRET}"),
        payload: None,
    };
    Store::open(&f.db_path)
        .expect("复开库")
        .insert_event(&raw)
        .expect("写入人为明文");

    assert_eq!(
        secret_hits(&f.db_path),
        1,
        "扫描发现不了人为明文 → 门禁无效（空跑）"
    );
}

#[test]
fn event_table_scan_catches_plaintext_in_payload_too() {
    let f = setup();
    let raw = Event {
        ts: 0,
        level: Level::Info,
        source: "app".to_string(),
        message: "看起来没问题".to_string(),
        payload: Some(format!(r#"{{"token":"{SECRET}"}}"#)),
    };
    Store::open(&f.db_path)
        .expect("复开库")
        .insert_event(&raw)
        .expect("写入人为明文");

    assert_eq!(secret_hits(&f.db_path), 1, "载荷里的明文也必须被发现");
}

#[test]
fn constructed_event_scrubs_even_when_caller_passes_raw_secret() {
    let e = observability::event(Level::Warn, "site", format!("站点回了 {SECRET}"));
    assert!(!e.message.contains(SECRET), "{}", e.message);
    assert!(e.message.contains("sk-***"), "{}", e.message);
}

#[test]
fn nested_payload_is_scrubbed_at_every_depth() {
    let e = observability::event_with_payload(
        Level::Error,
        "delivery",
        "投递失败",
        serde_json::json!({
            "a": { "b": { "c": { "key": SECRET } } },
            "arr": [ { "deep": [SECRET] } ],
        }),
    );
    let payload = e.payload.expect("有载荷");
    assert!(!payload.contains(SECRET), "{payload}");
    assert!(!payload.contains("0123456789"), "{payload}");
}

#[test]
fn events_table_has_writers_after_a_site_operation() {
    // 「零写入点」的回归：任何一次业务操作都应留下事件
    let f = setup();
    let before = f.service.recent_events(1000).unwrap().len();

    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();

    let after = f.service.recent_events(1000).unwrap().len();
    assert!(after > before, "授予同意必须留下事件记录");
}

#[test]
fn diagnostic_export_includes_vault_backend_for_support() {
    let f = setup();
    let exported = f.service.export_diagnostics(10).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&exported).expect("导出应是 JSON");
    assert_eq!(parsed["vault_backend"], "memory");
    assert!(parsed["home"].is_string());
}

// ================================================================ 老行清洗（M8-S5B §7.2）

/// **一次性数据修复**，不是门禁（spec §7.2：不自动执行、不进 CI）。
///
/// 为什么需要它：`observability::event_with_payload` 是**后来**才加上结构化脱敏的
/// （M5-S0），在那之前写进行表的 `message` / `payload` 可能带着密钥明文。
/// 事件表会被导出与审计 ⇒ 那些老行是真实的泄漏面。
///
/// 为什么不给一段 `sqlite3` 的 `UPDATE`：脱敏规则在 Rust 侧
/// （`redact::scrub` / `scrub_event_message` / `scrub_event_payload`）。
/// 用 SQL 复刻一遍只会多一个漂移源，而且 SQL 版**必然漏**（它猜不出 authority 边界、
/// 也不知道哪些 payload 键是敏感键）⇒ 这里用真规则逐行改写。
///
/// 用法一（自检，改的是临时库）：
/// ```console
/// $ cargo test -p keyrelay-core --test events_redaction scrub_legacy_event_rows -- --ignored --nocapture
/// ```
///
/// 用法二（修**真实库**，M8-S5B 独立复审 P2-3：不改成这样就得改源码才能指过去）：
/// ```console
/// $ cp ~/.keyrelay/keyrelay.db{,.bak} && cp ~/.keyrelay/keyrelay.db-wal{,.bak} 2>/dev/null; \
///   cp ~/.keyrelay/keyrelay.db-shm{,.bak} 2>/dev/null; true
/// $ KEYRELAY_DB=~/.keyrelay/keyrelay.db \
///   cargo test -p keyrelay-core --test events_redaction scrub_legacy_event_rows -- --ignored --nocapture
/// $ sqlite3 ~/.keyrelay/keyrelay.db "SELECT count(*) FROM events;"
/// ```
/// **三态**（M16-S1 / P2-23：真实库模式下**不造夹具行、不做数量断言、不 panic、默认不写**）：
///
/// ```console
/// # ① 自检（缺省）：临时库 + 夹具 + 全部断言
/// $ cargo test -p keyrelay-core --test events_redaction scrub_legacy_event_rows -- --ignored --nocapture
///
/// # ② 真实库**干跑**：只列出会改哪些行，一个字节都不写
/// $ KEYRELAY_DB=~/.keyrelay/keyrelay.db \
///     cargo test -p keyrelay-core --test events_redaction scrub_legacy_event_rows -- --ignored --nocapture
///
/// # ③ 真实库**实改**（先备份 <db> 与 <db>-wal / <db>-shm！）
/// $ KEYRELAY_DB=~/.keyrelay/keyrelay.db KEYRELAY_DB_APPLY=1 \
///     cargo test -p keyrelay-core --test events_redaction scrub_legacy_event_rows -- --ignored --nocapture
/// ```
///
/// `KEYRELAY_DB` 指向哪个库就作用在哪个库；**缺省仍是临时目录**（自检形态不变）。
/// 实改必须显式 `KEYRELAY_DB_APPLY=1` —— 不可逆动作不提供「无参数即执行」的形态。
#[tokio::test]
#[ignore = "一次性数据修复：默认干跑；实改要 KEYRELAY_DB_APPLY=1，且先备份数据库"]
async fn scrub_legacy_event_rows() {
    use keyrelay_core::observability::{Event, Level};
    use keyrelay_core::store::Store;

    // `KEYRELAY_DB` 指向真实库 ⇒ 走真实库模式（干跑 / 实改）；否则用临时库自检。
    // **两条路彻底分开**（M16-S1 / P2-23）：真实库模式不造夹具行、不做数量断言、
    // 不 panic —— 旧形态把夹具断言带进真实库，于是「库里有真实泄漏」时先 panic、
    // 「干净库」时又先不可逆改写 `kr/...` 再报失败。
    let dir = tempfile::tempdir().expect("临时目录");
    let target = std::env::var("KEYRELAY_DB")
        .ok()
        .filter(|path| !path.trim().is_empty());
    if let Some(path) = target {
        real_db_mode(std::path::Path::new(&path));
        return;
    }

    let db = dir.path().join("legacy.db");
    println!("目标库（临时自检）: {}", db.display());
    let store = Store::open(&db).expect("文件库");

    // 造两行「老形态」。`Event` 的字段是 pub，所以可以直接拼一个**未脱敏**的行，
    // 绕过构造侧脱敏——这正是修复前的历史数据长什么样。
    // （不往 `Store` 上加「写原始行」的公开 API：那种 API 留在生产里本身就是隐患。）
    let legacy = Event {
        ts: 1_700_000_000,
        level: Level::Warn,
        source: "site".to_string(),
        message: format!("取密钥失败 {SECRET}"),
        payload: Some(format!(r#"{{"note":"{SECRET}","key_id":1}}"#)),
    };
    store.insert_event(&legacy).expect("写老行");
    let before = store.count_events_with_secrets().expect("扫描");
    println!("修复前：{before} 行仍含密钥形态");
    assert_eq!(before, 1, "夹具必须真的造出一行含密钥的老数据");

    let repaired = store.scrub_legacy_events().expect("逐行改写");
    println!("修复：改写了 {repaired} 行");
    assert_eq!(repaired, 1, "只有那一行老数据该被改写");

    let after = store.count_events_with_secrets().expect("复扫");
    println!("修复后：{after} 行仍含密钥形态");
    assert_eq!(after, 0, "修复后不得再有含密钥形态的行");

    // 复核（spec §7.2 要求给）：直接看改完的文本，掩码要落在该落的地方
    let row = store
        .list_all_events()
        .expect("读全部事件")
        .into_iter()
        .next()
        .expect("有那一行");
    assert!(
        !row.message.contains(SECRET),
        "message 仍是明文: {}",
        row.message
    );
    assert!(
        row.message.contains("sk-***"),
        "message 应被掩: {}",
        row.message
    );
    let payload = row.payload.expect("payload 还在");
    assert!(!payload.contains(SECRET), "payload 仍是明文: {payload}");
    assert!(payload.contains("sk-***"), "payload 应被掩: {payload}");
    // 键名与其它字段不被牵连（结构化脱敏的既有契约）
    assert!(
        payload.contains(r#""key_id":1"#),
        "其它字段该原样: {payload}"
    );
    println!("复核通过：message / payload 均已掩码，其它字段原样");
}

/// **真实库模式**（干跑 / 实改）：不造夹具行、不做数量断言、**不 panic**。
///
/// 干跑是缺省：先列出「哪些行会被改写、命中 message 还是 payload」，确认后加
/// `KEYRELAY_DB_APPLY=1` 才写。任何异常（打开失败 / 读取失败 / 改写中断）都只打印，
/// 不 panic —— 用户是在**自己的真实库**上跑这个工具，工具崩掉不能留下半改状态还报错。
fn real_db_mode(path: &Path) {
    println!("目标库（真实）: {}", path.display());
    let store = match Store::open(path) {
        Ok(store) => store,
        Err(err) => {
            println!("打开失败，未写入任何字节: {err}");
            return;
        }
    };

    let planned = plan_legacy_scrub(&store);

    if !apply_requested() {
        println!(
            "【干跑】以上是**计划**，未写入任何字节。确认后加 `KEYRELAY_DB_APPLY=1` 重跑；\
             跑之前先备份 <db> 与 <db>-wal / <db>-shm（WAL 模式下缺一个都不完整）。"
        );
        return;
    }

    println!("【实改】开始逐行改写（不可逆）……");
    match store.scrub_legacy_events() {
        Ok(written) => println!("已改写 {written} 行（计划 {planned} 行）"),
        Err(err) => println!("改写中断: {err}（已改写的行不会回滚；库仍可用）"),
    }
    match store.count_events_with_secrets() {
        Ok(after) => println!("复扫：{after} 行仍含密钥形态"),
        Err(err) => println!("复扫失败: {err}"),
    }
}

/// 实改是否被显式请求（`KEYRELAY_DB_APPLY=1`）。
fn apply_requested() -> bool {
    matches!(
        std::env::var("KEYRELAY_DB_APPLY").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes")
    )
}

/// **干跑**：只打印「哪些行会被改写、命中的是 message 还是 payload」，一个字节都不写。
/// 返回计划改写的行数。
///
/// 用与 [`Store::scrub_legacy_events`] **同一对规则函数**（`redact::scrub_event_message` /
/// `scrub_event_payload`）判定 ⇒「计划」与「实改」不会分叉。
fn plan_legacy_scrub(store: &Store) -> usize {
    let rows = match store.list_all_events() {
        Ok(rows) => rows,
        Err(err) => {
            println!("读取事件失败: {err}");
            return 0;
        }
    };
    let mut planned = 0usize;
    for row in &rows {
        let new_message = keyrelay_core::redact::scrub_event_message(&row.message);
        let new_payload = keyrelay_core::redact::scrub_event_payload(row.payload.as_deref());
        let message_changed = new_message != row.message;
        let payload_changed = new_payload.as_deref() != row.payload.as_deref();
        if message_changed || payload_changed {
            planned += 1;
            println!(
                "  行 #{} 将改写（message: {} / payload: {}）",
                row.id,
                if message_changed { "是" } else { "否" },
                if payload_changed { "是" } else { "否" }
            );
        }
    }
    println!(
        "【计划】共 {planned} 行将被改写（事件总行数 {}）",
        rows.len()
    );
    planned
}

/// 造一个「真实库形态」的库：一行**真泄漏** + 一行**正常事件**（只带钥匙串引用）。
fn real_like_db(dir: &Path) -> (Store, PathBuf) {
    use keyrelay_core::observability::{Event, Level};

    let path = dir.join("real.db");
    let store = Store::open(&path).expect("文件库");
    // 真泄漏：message 里带密钥明文（M8 之前的历史形态）
    store
        .insert_event(&Event {
            ts: 1_700_000_000,
            level: Level::Warn,
            source: "site".to_string(),
            message: format!("取密钥失败 {SECRET}"),
            payload: Some(format!(r#"{{"note":"{SECRET}","key_id":1}}"#)),
        })
        .expect("写泄漏行");
    // 正常事件：只带钥匙串引用 `kr/<scope>/<id>/<field>`，不是密钥明文
    store
        .insert_event(&Event {
            ts: 1_700_000_001,
            level: Level::Info,
            source: "delivery".to_string(),
            message: "已投递（引用 kr/key/1/secret）".to_string(),
            payload: Some(r#"{"key_id":1,"ref":"kr/key/1/secret"}"#.to_string()),
        })
        .expect("写正常行");
    (store, path)
}

/// 库的「数据字节量」指纹：主库 + WAL 的长度。真写入一定会让其中之一变化。
fn db_sizes(path: &Path) -> (u64, u64) {
    let size = |p: &Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    (
        size(path),
        size(&PathBuf::from(format!("{}-wal", path.display()))),
    )
}

#[test]
fn legacy_scrub_dry_run_writes_nothing() {
    // **M16-S1 / P2-23**：真实库形态下，干跑必须**一个字节都不写**、**不 panic**。
    let dir = tempfile::tempdir().expect("临时目录");
    let (store, path) = real_like_db(dir.path());

    let rows_before = store.list_all_events().expect("读事件");
    let secrets_before = store.count_events_with_secrets().expect("扫描");
    let sizes_before = db_sizes(&path);

    let planned = plan_legacy_scrub(&store);

    assert_eq!(
        planned, 2,
        "两行都会被现有规则计划改写（真泄漏 + `kr/...` 引用形态——后者是 B-62 的既有规则）"
    );
    assert_eq!(
        store.list_all_events().expect("读事件"),
        rows_before,
        "干跑不得改动任何事件行"
    );
    assert_eq!(
        store.count_events_with_secrets().expect("复扫"),
        secrets_before,
        "干跑不得改变「含密钥形态」的行数"
    );
    assert_eq!(db_sizes(&path), sizes_before, "干跑不得写入库文件");
}

#[test]
fn legacy_scrub_apply_rewrites_the_leak_and_does_not_panic() {
    // **M16-S1 / P2-23**：实改把泄漏行掩掉，**不 panic**（即使库里还有别的形态）。
    let dir = tempfile::tempdir().expect("临时目录");
    let (store, _path) = real_like_db(dir.path());

    let written = store.scrub_legacy_events().expect("逐行改写");
    assert_eq!(
        written, 2,
        "两行都会被现有规则改写（泄漏行 + 引用行；引用形态被掩是 B-62 的既有规则）"
    );
    assert_eq!(
        store.count_events_with_secrets().expect("复扫"),
        0,
        "实改后不得再有含密钥形态的行"
    );

    let rows = store.list_all_events().expect("读事件");
    let leaky = rows
        .iter()
        .find(|row| row.message.contains("取密钥失败"))
        .expect("泄漏行还在");
    assert!(
        !leaky.message.contains(SECRET),
        "明文必须被掩: {}",
        leaky.message
    );
    assert!(
        leaky.message.contains("sk-***"),
        "该掩成 sk-***: {}",
        leaky.message
    );
    let normal = rows
        .iter()
        .find(|row| row.message.contains("已投递"))
        .expect("正常行还在");
    assert!(
        !normal.message.contains("kr/key/1/secret"),
        "引用形态按既有规则掩掉（行为稳定即可）: {}",
        normal.message
    );
}
