//! 第 9 章验收矩阵（`docs/specs/M8-S3-非功能基线与验收矩阵.md` §4）。
//!
//! 分类口径（spec §4.1）：每条只能属于一类——
//! `本机可跑`（进常规门禁）、`本机可跑（需 --ignored）`、`需要真实站点`、`需要 GUI`、`需要 Windows`。
//! 本文件只放**本机可跑**那类；其余三类由既有测试文件承载（`offline.rs` / `real_site_smoke.rs`）
//! 或在本文件里以**结构性引用**的方式钉住（A-10 / A-12）。
//!
//! 与既有测试的关系（spec §4.2）：矩阵**引用**既有测试而不重写。本文件只补两类：
//! ① 既有测试没有覆盖到的条款；② **跨包集成**（ALL 循环回滚比对、故障注入组合）。
//!
//! §10 的硬约束：任何对 [`DeliveryChannel::ALL`] 的循环，Continue 必须传 `model`
//! ——统一走本文件的 [`model_for`]，不在一处各写一遍。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use rusqlite::Connection;
use serde_json::{json, Value};
use tianshu_relay_core::delivery::DeliveryChannel;
use tianshu_relay_core::error::{Error, Result};
use tianshu_relay_core::inject::lock::FileLock;
use tianshu_relay_core::notify::{
    evaluate, webhook_payload, BalanceSnapshot, NotifyConfig, NotifyKind, SiteSnapshot, Snapshot,
};
use tianshu_relay_core::routing::should_failover;
use tianshu_relay_core::service::{ServiceConfig, StoredKey, TianshuRelayService};
use tianshu_relay_core::site::retry::{RecordingSleeper, RetryPolicy, RetryingTransport};
use tianshu_relay_core::site::transport::{
    HttpRequest, HttpResponse, HttpTransport, MockTransport,
};
use tianshu_relay_core::site::Credentials;
use tianshu_relay_core::site::{KeySpec, SiteKind};
use tianshu_relay_core::store::Store;
use tianshu_relay_core::vault::{secret_ref, MemoryVault, Vault};

const SECRET: &str = "sk-matrix-0123456789abcdef";
const PAT: &str = "0123456789abcdef0123456789abcdef";
const QUOTA_PER_UNIT: i64 = 500_000;
const NOW: i64 = 1_760_000_000;

// ================================================================ 共用夹具

fn balance_ok(quota: i64) -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"success": true, "data": {"quota": quota, "used_quota": 0, "quota_per_unit": QUOTA_PER_UNIT}}),
    )
    .expect("构造响应")
}

fn keys_ok() -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"success": true, "data": {"items": [], "total": 0}}),
    )
    .expect("构造响应")
}

fn encryption_disabled() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": {"enabled": false}})).expect("构造响应")
}

fn login_ok() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": {"id": 7}}))
        .expect("构造响应")
        .with_header("Set-Cookie", "session=abc; Path=/")
}

/// §10：某通道该传什么 `model`。判据来自 [`DeliveryChannel`]，不是硬编码通道名。
fn model_for(channel: DeliveryChannel) -> Option<&'static str> {
    match channel {
        DeliveryChannel::OpenClaw => Some("gpt-4o"),
        _ => None,
    }
}

/// 一个「已登录站点 + 一把已同意投递的 key」的夹具（注入式、零网络）。
struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    db_path: PathBuf,
    service: TianshuRelayService<MockTransport>,
    /// 队列句柄：需要额外响应的用例（如 A-3 的 `add_site` 驱动）自己 push。
    mock: MockTransport,
    key_id: i64,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let db_path = dir.path().join("tianshu-relay.db");

    let store = Store::open(&db_path).expect("文件库");
    let site_id = store
        .upsert_site("newapi", "https://relay.example.com", "测试站")
        .expect("写站点");
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &reference, Some("1"), None)
        .expect("写密钥记录");

    let vault = Arc::new(MemoryVault::new());
    vault.put(&reference, SECRET).expect("写钥匙串");

    let mock = MockTransport::new(vec![]);
    let service = TianshuRelayService::new(
        store,
        mock.clone(),
        ServiceConfig {
            vault,
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
            data_dir: None,
        },
    );
    Fixture {
        _dir: dir,
        home,
        db_path,
        service,
        mock,
        key_id,
    }
}

/// 事件表里带某子串的消息（按写入顺序）。
fn messages(service: &TianshuRelayService<MockTransport>, needle: &str) -> Vec<String> {
    service
        .recent_events(500)
        .expect("读事件")
        .into_iter()
        .filter(|event| event.message.contains(needle))
        .map(|event| event.message)
        .collect()
}

// ================================================================ A-1：契约回放覆盖每个适配器

/// T-1 / A-1：**每个**站点适配器都要有一条 fixture 回放。
///
/// 为什么要结构性断言：新增适配器时最安静的漏测方式就是「忘了给它写契约测试」——
/// 那时没有任何东西会红。这条把「适配器清单」与「真的构造该适配器的测试文件」对账。
///
/// 判据是**构造**而不是「提到名字」：文件里必须出现该适配器的构造函数调用
/// （`NewApi::new(` / `Sub2Api::new(` / `CustomOpenAi::new(`）。第一版按
/// 「文件含 `"newapi"` 字样」匹配，结果 29 个文件全算覆盖（`zeroize_hygiene.rs` /
/// `settings.rs` / `drift.rs` 都只是 `upsert_site("newapi", …)` 带了那个字符串）——
/// 那种判据挡不住「新增适配器忘了写契约测试」（独立复审 P2-2）。
///
/// 已知局限（写进 spec §14）：`SiteKind` 没有公开的 `ALL` 常量（`site/**` 是 M8-S2 的
/// 写域，本包不改），所以适配器清单是**手写**的；新增适配器时必须在这里补一行，
/// 补了才能被这条断言覆盖到。
#[test]
fn fixture_replay_covers_every_adapter() {
    // 适配器 ⇒ 它的构造函数形态（`site/registry.rs::adapter()` 里 `Arc::new(X::new(...))`）。
    //
    // 构造函数形态**不能从 `SiteKind` 安全派生**（第三个不叫 `CustomOpenAiCompatible::new`，
    // 命名没有统一规律），所以仍要这张表。但长度与 `SiteKind::ALL` 对账（B-119 / M8-S6）：
    // 新增变体时下面那个 `assert_eq!` 会红，逼人回来补一行——漏测从静默变成显式。
    //
    // 另外一层强制在 `site::tests::site_kind_all_covers_every_variant`：那边手列变体清单，
    // 新增变体时**编译失败**。两道合起来 = 编译期 + 运行期各一道。
    // 长度不写死在类型里：交给下面那条 `assert_eq!` 与 `SiteKind::ALL.len()` 对账，
    // 报错信息比「数组类型不匹配」清楚（M8-S6 独立复审 P3-1）。
    let adapters = [
        (SiteKind::NewApi, "NewApi::new("),
        (SiteKind::Sub2Api, "Sub2Api::new("),
        (SiteKind::CustomOpenAiCompatible, "CustomOpenAi::new("),
    ];
    assert_eq!(
        adapters.len(),
        SiteKind::ALL.len(),
        "适配器表与 SiteKind::ALL 长度不一致：新增站点类型必须同时补这张表（B-119）"
    );
    let tests_dir = workspace_root().join("crates/tianshu-relay-core/tests");
    // **排除本文件自己**（M8-S6 实测抓到的缺陷）：这条守护是「扫描 tests/ 目录里的文件」，
    // 而它自己就在那个目录里 ⇒ 判据字符串（`NewApi::new(` 等）写在它自己源码中，
    // 于是**任何**字符串都能自我匹配、判据永远成立——实测把构造函数形态改成一个
    // 完全不可能存在的串，`covering` 仍是 1（匹配到它自己）。守护自己的源码不能算证据。
    let this_file = std::path::Path::new(file!())
        .file_name()
        .expect("有文件名")
        .to_string_lossy()
        .to_string();
    let sources: Vec<(String, String)> = fs::read_dir(&tests_dir)
        .expect("读 tests 目录")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .filter(|path| path.file_name().expect("有文件名").to_string_lossy() != this_file)
        .filter_map(|path| {
            fs::read_to_string(&path)
                .ok()
                .map(|text| (path.display().to_string(), text))
        })
        .collect();
    assert!(
        sources.len() >= adapters.len(),
        "tests/ 目录里连一个 .rs 都没读到，这条断言就成了空断言"
    );

    for (kind, constructor) in adapters {
        let canonical = kind.as_str();
        // 覆盖判据（三条都要满足）：
        //   ① 文件里**构造**了这个适配器（不是只提到它的名字）；
        //   ② 走注入式传输层（零网络）；
        //   ③ 文件里至少有一条用例。
        let covering: Vec<&String> = sources
            .iter()
            .filter(|(_, text)| text.contains(constructor))
            .filter(|(_, text)| text.contains("MockTransport"))
            .filter(|(_, text)| {
                text.lines().any(|line| {
                    let trimmed = line.trim_start();
                    trimmed.starts_with("#[test]") || trimmed.starts_with("#[tokio::test]")
                })
            })
            .map(|(name, _)| name)
            .collect();
        assert!(
            !covering.is_empty(),
            "{}（{canonical}）没有任何 fixture 回放测试：新增适配器必须同时补契约测试\
             （判据：文件里出现 `{constructor}` + `MockTransport` + 至少一条用例）",
            kind.as_str()
        );
        // 规范名 ↔ 解析 必须自洽（否则按名字匹配的其它断言会静默失配）
        assert_eq!(SiteKind::parse(canonical), Some(kind));
        println!(
            "A1 {}（{canonical}）的 fixture 回放: {}",
            kind.as_str(),
            covering
                .iter()
                .map(|name| name.rsplit('/').next().unwrap_or(name).to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

// ================================================================ A-2：注入 → 回滚 → 字节比对

/// T-2 / A-2：`DeliveryChannel::ALL` 逐通道「注入 → 回滚 → 字节比对」。
///
/// 两种形态都测（缺一不可）：
/// - **目标原本不存在**：回滚必须把「自己创建的文件」删掉（不是留一个空壳）；
/// - **目标原本存在**：回滚必须**逐字节**还原（不是「解析后重新序列化」的那种还原）。
#[test]
fn inject_rollback_roundtrip_is_byte_identical() {
    let f = setup();
    // 原内容用 ASCII：这是一份「字节级比对」的基准，混进多字节字符只会让
    // 「逐字节还原」这件事的读起来变糊（且 b"" 字面量不接受非 ASCII）。
    let original = b"{\n  \"user_comment\": \"keep my own bytes\"\n}\n".to_vec();

    for channel in DeliveryChannel::ALL {
        // B-292：ClineDesktop 已下线，不再投递，跳过。
        if channel == DeliveryChannel::ClineDesktop {
            continue;
        }
        let model = model_for(channel);
        let name = channel.as_str();

        // P0-3：DSH 投递要求至少一个 profile 引用 KEYRELAY_API_KEY，
        // 否则 apply 在落盘前拒绝；本用例测的是注入/回滚字节比对而非
        // 引用校验本身，因此先给 DSH 备一个已引用的 profile。
        if channel == DeliveryChannel::DeepSeekHarness {
            let profile = f
                .home
                .join(".dsh")
                .join("profiles")
                .join("desktop")
                .join("cordis.patch.yml");
            fs::create_dir_all(profile.parent().unwrap()).expect("建 profile 目录");
            fs::write(&profile, "apiKeyEnv: KEYRELAY_API_KEY\n").expect("写 profile");
        }

        // ---- 形态一：目标不存在 ⇒ 回滚后必须不存在
        let plan = f
            .service
            .delivery_plan_with_model(f.key_id, channel, model)
            .unwrap_or_else(|e| panic!("{name} 应能生成计划: {e}"));
        let target = plan.target_path.clone();
        assert!(
            target.starts_with(&f.home),
            "{name} 的目标越出 home: {}",
            target.display()
        );
        assert!(
            !target.exists(),
            "{name} 的目标在第一次投递前就该不存在（上一轮没清理干净）: {}",
            target.display()
        );
        f.service
            .grant_consent(f.key_id, channel)
            .unwrap_or_else(|e| panic!("{name} 记录同意失败: {e}"));
        let created = f
            .service
            .apply_delivery_with_model(f.key_id, channel, model)
            .unwrap_or_else(|e| panic!("{name} 注入失败: {e}"));
        let after_create =
            fs::read(&target).unwrap_or_else(|e| panic!("{name} 注入后文件必须存在: {e}"));
        let text = String::from_utf8_lossy(&after_create).to_string();
        // 目标文件里**必须**有密钥——那就是投递的目的（`delivery_codex.rs` 的
        // `full_flow_leaves_no_secret_on_disk_or_in_logs` ⑤ 钉的是同一条）。
        // 「密钥不进……」的红线管的是**事件/日志/导出/库**，不是 agent 自己的配置。
        // M25-S1：codex-config 不含密钥（sk 走 codex-auth-json 配套投递），
        // 它的目标文件验「base_url 在」而不是「密钥在」——投递目的仍是写入。
        if channel == DeliveryChannel::CodexConfig {
            assert!(
                text.contains("base_url = \"") && text.contains("wire_api = \"responses\""),
                "{name} 的目标文件里没有 base_url/wire_api：这次投递是空跑"
            );
        } else {
            assert!(
                text.contains(SECRET),
                "{name} 的目标文件里没有密钥：这次投递是空跑"
            );
        }
        f.service
            .rollback_delivery(&created.journal_id)
            .unwrap_or_else(|e| panic!("{name} 回滚失败: {e}"));
        assert!(
            !target.exists(),
            "{name} 回滚后必须删掉自己创建的文件（留空壳等于没回滚）",
        );

        // ---- 形态二：目标已存在 ⇒ 回滚后逐字节等于原内容
        fs::create_dir_all(target.parent().expect("有父目录")).expect("建父目录");
        fs::write(&target, &original).expect("预置原内容");
        let again = f
            .service
            .apply_delivery_with_model(f.key_id, channel, model)
            .unwrap_or_else(|e| panic!("{name} 第二次注入失败: {e}"));
        let after_second = fs::read(&target).expect("读注入后内容");
        assert_ne!(after_second, original, "{name} 的注入没有改动文件（空跑）");
        f.service
            .rollback_delivery(&again.journal_id)
            .unwrap_or_else(|e| panic!("{name} 第二次回滚失败: {e}"));
        assert_eq!(
            fs::read(&target).expect("读回滚后内容"),
            original,
            "{name} 回滚必须逐字节还原"
        );
        // 清掉这一轮的痕迹，让下一轮从「目标不存在」开始
        let _ = fs::remove_file(&target);
    }
}

// ================================================================ A-3：四条出口零密钥形态

/// T-3 / T-16 / A-3：四条出口各造一条含密钥形态的输入，断言出口文本里
/// [`tianshu_relay_core::redact::contains_secret`] 为假。
///
/// 四条出口 = 事件表 / webhook 报文 / 导出包 / 诊断导出。错误串那条由
/// `M8-S2` 的 `detect_failure_never_echoes_userinfo` 一族覆盖，这里不重复。
#[tokio::test]
async fn no_secret_shape_in_any_exit() {
    use tianshu_relay_core::redact::contains_secret;

    let f = setup();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .expect("记录同意");
    let _ = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .expect("注入");

    // M16-S3 P3-29：**喂真密钥形态的输入**。
    //
    // 改前这条用例的 ①④ 两项是空跑：事件表里只有 `apply_delivery` 产生的事件
    // （文案里没有任何密钥形态）⇒ `!contains_secret(...)` 恒真，去掉事件写入口脱敏
    // 与诊断包脱敏也照样全绿（DEBUG-REPORT-v3 §3-29 的变异）。
    //
    // 驱动方式：走**真实写入路径** `add_site` —— 它把 `base_url` 写进事件 payload
    // （`service.rs` 的 `event_with_payload`，即事件写入口）。三个 base_url 的 userinfo
    // 各带一种密钥形态（`sk-` / `nap-` / 32 位 hex）。假站点按 path 路由，userinfo
    // 不影响 `/api/status` 命中 ⇒ 三次都能真的写出一条事件。
    let secrets = [
        format!("https://alice:{SECRET}@relay.example.com"),
        "https://bob:nap-abcdefgh12345678@relay.example.com".to_string(),
        format!("https://carol:{PAT}@relay.example.com"),
    ];
    // 队列式 mock：每次 `add_site` 的探测（NewApi 先试）各消耗一条 `/api/status` 响应。
    for _ in 0..secrets.len() {
        f.mock.push(
            HttpResponse::json(
                200,
                json!({"success": true, "data": {"version": "v0.9.1", "quota_per_unit": 500_000, "system_name": "假站点"}}),
            )
            .expect("构造响应"),
        );
    }
    for base in &secrets {
        f.service
            .add_site(base)
            .await
            .unwrap_or_else(|e| panic!("{base} 应能接入（假站点按 path 路由）: {e}"));
    }

    // ① 事件表：整表扫（message + payload），另开一个连接复扫落库文件
    let events = f.service.recent_events(500).expect("读事件");
    assert!(!events.is_empty(), "事件表必须非空，否则这条是空断言");
    // **驱动证明**：脱敏后的 base_url 必须真的出现在事件里（`***@relay.example.com`）。
    // 没有这一条，将来某个重构把事件去掉，这条用例又会变回空跑而没人发现。
    let joined: String = events
        .iter()
        .map(|e| format!("{} {}", e.message, e.payload.clone().unwrap_or_default()))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("***@relay.example.com"),
        "三条含 userinfo 的 base_url 应各写出一条事件（且 userinfo 已被掩）: {joined}"
    );
    for event in &events {
        assert!(
            !contains_secret(&event.message),
            "事件 message 泄漏: {}",
            event.message
        );
        if let Some(payload) = &event.payload {
            assert!(!contains_secret(payload), "事件 payload 泄漏: {payload}");
        }
    }
    assert_eq!(
        Store::open(&f.db_path)
            .expect("复开库")
            .count_events_with_secrets()
            .expect("扫库"),
        0,
        "落库的事件表里仍有密钥形态"
    );

    // ② webhook 报文：标题与正文都塞密钥形态
    let payload = webhook_payload(&tianshu_relay_core::notify::Notification::new(
        NotifyKind::BalanceLow,
        Some(1),
        format!("标题 {SECRET}"),
        format!("正文 {PAT}"),
        NOW,
    ));
    assert!(!contains_secret(&payload), "webhook 报文泄漏: {payload}");

    // ③ 导出包：站点显示名 / 事件消息里塞密钥形态
    let bundle = tianshu_relay_core::export::ExportBundle {
        version: 1,
        exported_at: NOW,
        app_version: "0.1.0".to_string(),
        sites: vec![tianshu_relay_core::export::ExportSite {
            id: 1,
            kind: "newapi".to_string(),
            base_url: "https://alice:pw@relay.example.com".to_string(),
            display_name: SECRET.to_string(),
        }],
        keys: Vec::new(),
        consents: Vec::new(),
        settings: tianshu_relay_core::export::ExportSettings {
            refresh_interval_secs: 300,
            balance_alert_threshold: 15.0,
            drift_check_on_start: true,
            gateway_enabled: false,
            gateway_port: 8787,
        },
        events: vec![tianshu_relay_core::export::ExportEvent {
            ts: NOW,
            level: "info".to_string(),
            source: "site".to_string(),
            message: SECRET.to_string(),
            payload: Some(PAT.to_string()),
        }],
    };
    let (exported, encrypted) =
        tianshu_relay_core::export::export(&bundle, None).expect("导出（不加密）");
    assert!(!encrypted, "不加密导出才是可读文本，否则这条断言没意义");
    assert!(!contains_secret(&exported), "导出包泄漏: {exported}");
    // URL 里的 userinfo 也要被剥掉（B-63）
    assert!(
        !exported.contains("alice:pw"),
        "导出包泄漏 URL 凭据: {exported}"
    );

    // ④ 诊断导出：必须真的带上那三条事件（驱动证明），且不含密钥形态
    let diagnostics = f.service.export_diagnostics(50).expect("诊断导出");
    assert!(
        diagnostics.contains("***@relay.example.com"),
        "诊断导出应包含上面那三条事件（否则这一项是空跑）: {diagnostics}"
    );
    assert!(
        !contains_secret(&diagnostics),
        "诊断导出泄漏: {diagnostics}"
    );
}

/// M16-S3 P3-29（④ 的**读取层**）：诊断包必须在读取时自己脱敏，即使库里是**老行**
/// （写入口脱敏上线之前写进去、原样带密钥形态的行）。
///
/// 与 `no_secret_shape_in_any_exit` 的分工：那条走真实写入路径（验证写入口脱敏）；
/// 这条用 `Store::insert_event` **故意绕过写入口**造老行，验证
/// `export_diagnostics` 自己那一层（`scrub_event_payload`）还在。
/// 两者合起来：写入口与读取层各有一条能红的用例。
#[test]
fn diagnostics_scrubs_legacy_event_rows_at_read_time() {
    use tianshu_relay_core::observability::{Event, Level};

    let f = setup();
    let store = Store::open(&f.db_path).expect("复开库");
    let legacy = Event {
        ts: NOW,
        level: Level::Warn,
        source: "site".to_string(),
        message: format!("取密钥失败 {SECRET}"),
        payload: Some(format!(
            r#"{{"base_url":"https://alice:{SECRET}@relay.example.com"}}"#
        )),
    };
    store.insert_event(&legacy).expect("写老行");
    assert_eq!(
        store.count_events_with_secrets().expect("扫库"),
        1,
        "夹具必须真的造出一行含密钥形态的老数据（否则这条是空跑）"
    );

    let diagnostics = f.service.export_diagnostics(50).expect("诊断导出");
    assert!(
        diagnostics.contains("relay.example.com"),
        "诊断包应带上那条老事件（驱动证明）: {diagnostics}"
    );
    assert!(
        !tianshu_relay_core::redact::contains_secret(&diagnostics),
        "诊断包必须自己在读取时脱敏（老行）: {diagnostics}"
    );
}

// ================================================================ A-4：401 ⇒ needs_login + 通知

/// T-5 / A-4：401 必须同时产生三件事——本轮 `needs_login`、会话被清（下一轮不再请求）、
/// 以及一条通知（FR-3 的登录态告警在界面上看得见）。
#[tokio::test]
async fn auth_failure_marks_needs_login_and_notifies() {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let store = Store::open(&dir.path().join("tianshu-relay.db")).expect("文件库");
    let site_id = store
        .upsert_site("newapi", "https://relay.example.com", "测试站")
        .expect("写站点");
    let mock = MockTransport::new(vec![]);
    let service = TianshuRelayService::new(
        store,
        mock.clone(),
        ServiceConfig {
            vault: Arc::new(MemoryVault::new()),
            home,
            backup_dir: dir.path().join("backups"),
            data_dir: None,
        },
    )
    // 两个发送出口都关掉：这里验证的是「事实有没有走到规则」，不是发送
    .with_notify(NotifyConfig {
        system_enabled: false,
        webhook_url: None,
        balance_threshold: 0.0,
        timeout: Duration::from_secs(10),
    });

    mock.push(encryption_disabled());
    mock.push(login_ok());
    service
        .login(site_id, Credentials::new("me", "pw"))
        .await
        .expect("登录");

    // 第一轮：余额请求回 401 ⇒ 认证失败
    mock.push(HttpResponse::new(401, b"{}".to_vec()));
    mock.push(balance_ok(2_000_000));
    mock.push(keys_ok());
    let first = service.refresh_all().await.expect("整轮仍应 Ok");
    assert_eq!(
        first.needs_login,
        vec![site_id],
        "401 当轮就要进 needs_login"
    );
    assert_eq!(
        messages(&service, "刷新站点失败"),
        vec!["刷新站点失败: 认证失败"],
        "401 必须分类成认证失败"
    );
    let titles = notification_titles(&service);
    assert!(
        titles
            .iter()
            .any(|t| t.contains("登录态") || t.contains("登录")),
        "登录态失效必须产生一条通知: {titles:?}"
    );
    assert_eq!(
        service.store().get_site(site_id).unwrap().unwrap().health,
        "needs_login",
        "状态必须落库"
    );

    // 第二轮：会话已清 ⇒ 不发请求、不算成功也不算失败，但仍要看得见。
    // 注意与 `refresh_isolation.rs` 的区别：那边是**两个**站点，另一个站点照常成功；
    // 这里只有一个站点，会话被清之后它整轮被跳过 ⇒ (total 1, ok 0, failed 0)。
    let before = mock.request_count();
    mock.push(balance_ok(2_000_000));
    mock.push(keys_ok());
    let second = service.refresh_all().await.expect("整轮仍应 Ok");
    assert_eq!(
        (second.sites_total, second.sites_ok, second.sites_failed),
        (1, 0, 0),
        "会话被清掉的站点按「未登录」跳过，不算成功也不算失败"
    );
    assert_eq!(second.needs_login, vec![site_id], "第二轮仍要带出来");
    assert_eq!(
        mock.request_count() - before,
        0,
        "没有会话的站点在第二轮不得发任何请求"
    );
}

/// 事件表里 `通知: ` 开头那些行的标题（按写入顺序）。
fn notification_titles(service: &TianshuRelayService<MockTransport>) -> Vec<String> {
    service
        .recent_events(500)
        .expect("读事件")
        .into_iter()
        .filter(|event| event.message.starts_with("通知: "))
        .map(|event| event.message.trim_start_matches("通知: ").to_string())
        .collect()
}

// ================================================================ A-5：429 ⇒ 按 Retry-After 重试

/// T-6 / A-5：429 必须按 `Retry-After` 重试，且**只**等 header 指定的时长。
///
/// 注入式：假内层 + [`RecordingSleeper`]（不真的睡），因此这条进常规门禁也不会慢。
#[tokio::test]
async fn rate_limit_is_retried_with_retry_after() {
    let inner = MockTransport::new(vec![
        HttpResponse::new(429, b"{}".to_vec()).with_header("Retry-After", "2"),
        HttpResponse::json(200, json!({"success": true})).expect("构造响应"),
    ]);
    let sleeper = Arc::new(RecordingSleeper::default());
    let retrying = RetryingTransport::with_sleeper(
        inner.clone(),
        RetryPolicy::default(),
        sleeper.clone() as Arc<dyn tianshu_relay_core::site::retry::Sleeper>,
    );

    let response = retrying
        .request(HttpRequest::new(
            tianshu_relay_core::site::transport::Method::Get,
            "https://relay.example.com/api/user/self",
        ))
        .await
        .expect("请求本身成功");

    assert_eq!(response.status, 200, "重试后应拿到 200");
    assert_eq!(inner.request_count(), 2, "429 后必须重试一次");
    assert_eq!(
        sleeper.calls(),
        vec![Duration::from_secs(2)],
        "等待时长必须取 Retry-After，不是退避猜测值"
    );

    // 没有 `Retry-After` 的 429 也要重试（次数受策略约束），但不得凭空等一个 header 时长
    let bare = MockTransport::new(vec![
        HttpResponse::new(429, b"{}".to_vec()),
        HttpResponse::new(429, b"{}".to_vec()),
        HttpResponse::json(200, json!({"success": true})).expect("构造响应"),
    ]);
    let bare_sleeper = Arc::new(RecordingSleeper::default());
    let bare_retrying = RetryingTransport::with_sleeper(
        bare.clone(),
        RetryPolicy::default(),
        bare_sleeper.clone() as Arc<dyn tianshu_relay_core::site::retry::Sleeper>,
    );
    let response = bare_retrying
        .request(HttpRequest::new(
            tianshu_relay_core::site::transport::Method::Get,
            "https://relay.example.com/api/user/self",
        ))
        .await
        .expect("请求本身成功");
    assert_eq!(response.status, 200);
    assert!(bare_sleeper.calls().len() >= 2, "每次重试前都要退避");
}

// ================================================================ A-6：5xx ⇒ 切换 / 记失败

/// T-7 / A-6：5xx 的**两条**路径——网关路径切换上游，刷新路径记失败。
///
/// 为什么两条都要：`should_failover` 是纯函数，单独测它证明不了「刷新真的记了失败」；
/// 反过来单独测刷新又证明不了「网关会切」。两条路径对 5xx 的处理是不同代码。
#[tokio::test]
async fn server_error_fails_over_or_reports() {
    // ① 网关路径（纯函数）：429 与 5xx 切，4xx 不切
    for status in [429u16, 500, 502, 503, 504] {
        assert!(should_failover(status), "{status} 应当切换上游");
    }
    for status in [400u16, 401, 403, 404, 422] {
        assert!(!should_failover(status), "{status} 不该切换上游");
    }

    // ② 刷新路径：5xx 记失败、不中断整轮、不当成需要登录
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let store = Store::open(&dir.path().join("tianshu-relay.db")).expect("文件库");
    let a = store
        .upsert_site("newapi", "https://a.example.com", "甲")
        .expect("写站点");
    let b = store
        .upsert_site("newapi", "https://b.example.com", "乙")
        .expect("写站点");

    let mock = MockTransport::new(vec![]);
    let service = TianshuRelayService::new(store, mock.clone(), ServiceConfig::in_memory(home));
    for _ in 0..2 {
        mock.push(encryption_disabled());
        mock.push(login_ok());
    }
    for site_id in [a, b] {
        service
            .login(site_id, Credentials::new("me", "pw"))
            .await
            .unwrap_or_else(|e| panic!("登录 {site_id} 失败: {e}"));
    }

    // 甲的余额请求 503（⇒ 认证会话还在，但这一轮记失败）；甲随后的令牌请求拿到正常响应。
    // 乙两个请求都正常。**四个响应一个不能少**：队列是共享 FIFO，少推一个就会把
    // 「余额响应」喂给「令牌请求」，那是夹具错不是实现错（第一版就栽在这里）。
    mock.push(HttpResponse::new(503, b"{}".to_vec()));
    mock.push(keys_ok());
    mock.push(balance_ok(2_000_000));
    mock.push(keys_ok());

    let summary = service.refresh_all().await.expect("整轮仍应 Ok");
    assert_eq!(
        (summary.sites_total, summary.sites_ok, summary.sites_failed),
        (2, 1, 1)
    );
    assert!(
        summary.needs_login.is_empty(),
        "5xx 是上游故障，不是凭证问题：不该要求重新登录"
    );
    assert!(
        !messages(&service, "刷新站点失败").is_empty(),
        "5xx 必须留一条失败事件"
    );
}

// ================================================================ A-7：磁盘只读 / 目标为目录

/// T-8 / A-7：写入目标不可写 ⇒ `Err` 且**原文件零改动**（不得留下改了一半的中间态）。
///
/// 用「目标路径是一个**目录**」这条稳定形态：`chmod 500` 在 root 下不生效
/// （与 `drift.rs` 的既有手法一致），而「路径是目录」在任何用户下都必然写不进去。
#[test]
fn readonly_target_is_rejected_without_partial_write() {
    let f = setup();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .expect("记录同意");

    // 先把真正的目标文件挪开，在原地建一个同名目录
    let plan = f
        .service
        .delivery_plan(f.key_id, DeliveryChannel::CodexAuthJson)
        .expect("计划");
    let target = plan.target_path.clone();
    fs::create_dir_all(&target).expect("把目标位置建成目录");
    assert!(target.is_dir());

    let err = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .expect_err("目标不可写时必须失败");
    assert!(matches!(err, Error::Inject { .. }), "{err:?}");
    assert!(
        target.is_dir(),
        "失败后目标位置必须原样还是目录（没有被写成半截文件）"
    );
    assert!(
        fs::read_dir(&target).expect("读目录").next().is_none(),
        "失败后目录里不该留下任何写入痕迹"
    );

    // 对照组：换回正常路径，同一次投递必须成功（证明上面失败的是「目标不可写」，不是夹具坏了）
    fs::remove_dir(&target).expect("拆掉目录");
    let outcome = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .expect("换成正常文件后应能注入");
    assert!(target.is_file());
    f.service
        .rollback_delivery(&outcome.journal_id)
        .expect("回滚");
}

// ================================================================ A-8 / A-9：并发注入同一文件 + 幂等

/// T-9 / T-10 / A-8：同一文件被并发注入 ⇒ 一个成功、一个 [`Error::FileBusy`]，
/// **不得**静默覆盖。
///
/// 用**进程内**并发（两个任务同时 `apply` 同一路径）：文件锁既有进程内登记也有
/// 跨进程 flock，进程内这条在这里就能稳定复现，不需要起第二个进程。
#[tokio::test]
async fn concurrent_inject_same_file_is_rejected() {
    let dir = tempfile::tempdir().expect("临时目录");
    let target = dir.path().join("auth.json");
    fs::create_dir_all(target.parent().expect("有父目录")).expect("建父目录");
    fs::write(&target, b"{\"v\":0}\n").expect("预置内容");

    let outcomes = Arc::new(Mutex::new(Vec::<Result<()>>::new()));
    let lock_dir = Arc::new(dir.path().join("locks"));
    let mut handles = Vec::new();
    for n in 0..2 {
        let target = target.clone();
        let outcomes = Arc::clone(&outcomes);
        let lock_dir = Arc::clone(&lock_dir);
        handles.push(tokio::spawn(async move {
            let result = async {
                let lock = FileLock::acquire(&target, &lock_dir)?;
                // 持锁期间改内容：第二个任务必须在这里被挡住
                tokio::time::sleep(Duration::from_millis(50)).await;
                fs::write(&target, format!("{{\"v\":{n}}}\n")).expect("写文件");
                drop(lock);
                Ok(())
            }
            .await;
            if let Ok(mut log) = outcomes.lock() {
                log.push(result);
            }
        }));
    }
    for handle in handles {
        handle.await.expect("任务不应 panic");
    }

    let results = outcomes.lock().expect("锁").clone();
    let busy = results
        .iter()
        .filter(|r| matches!(r, Err(Error::FileBusy(_))))
        .count();
    assert_eq!(busy, 1, "恰好一个应被 FileBusy 拒绝: {results:?}");
    assert!(
        results.iter().any(|r| r.is_ok()),
        "另一个必须成功（不能两个都失败）: {results:?}"
    );
    // 持锁写进去的内容必须完整（没有被并发写坏）
    let text = fs::read_to_string(&target).expect("读最终内容");
    assert!(
        text == "{\"v\":0}\n" || text == "{\"v\":1}\n",
        "最终内容必须是某一次完整写入: {text:?}"
    );
}

/// 仅对 `FileBusy` 做有界重试的单通道 apply 包装（幂等测试独用）。
///
/// 背景：ac1b130 的 macOS CI 上，本文件 `injection_is_idempotent_across_channels`
/// 在 claude-code-settings 的二投处偶发 `FileBusy(settings.json)`；而此前三轮
/// macOS CI 同测试通过，其间 acceptance_matrix 与 inject 锁生产代码零改动；
/// 本地 Linux 上单测 20 遍、整目标并行 5 遍均未复现。
/// 结论只能是“未定位的瞬时锁竞争抖动”，不是确定性回归——本包装不声称根因。
/// 已排除的项：锁键是完整归一化目标路径、每测试独用 tempdir 夹具，故不存在
/// 跨测试同路径撞锁；首投守卫是函数局部 RAII，顺序双投不存在自撞；回滚不取锁、
/// writer 不取锁、plan 不取锁；第六波的 FileLock::drop 顺序窗口（先删进程内登记、
/// 后关 fd）需要同路径并发抢锁者，而本测试是顺序调用，故不适用。
/// 锁竞争本身就是瞬时的，且本用例断言的是两次注入内容不变，不是“零竞争”，
/// 因此只对 FileBusy 重试（最多 10 次、间隔 20ms）；其它错误立即返回，不掩盖；
/// 锁若真的泄漏（永久占用），10 次都会失败，测试仍红——重试掩盖不了泄漏。
/// 最终失败时附上历次 FileBusy 目标，便于下次定位。
fn apply_delivery_retry_on_busy(
    f: &Fixture,
    channel: DeliveryChannel,
    model: Option<&str>,
) -> Result<tianshu_relay_core::delivery::DeliveryOutcome> {
    let mut last_busy: Option<String> = None;
    for attempt in 0..10 {
        match f
            .service
            .apply_delivery_with_model(f.key_id, channel, model)
        {
            Ok(outcome) => return Ok(outcome),
            Err(Error::FileBusy(path)) => {
                last_busy = Some(path);
                if attempt < 9 {
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            Err(other) => return Err(other),
        }
    }
    Err(Error::FileBusy(format!(
        "重试 10 次后仍被占用（历次目标：{last_busy:?}）",
    )))
}

/// T-2 / B8 / A-9：跨通道的注入**幂等**——同一密钥对同一通道连投两次，
/// 第二次不得产生任何额外改动。
#[test]
fn injection_is_idempotent_across_channels() {
    let f = setup();
    for channel in DeliveryChannel::ALL {
        // B-292：ClineDesktop 已下线，不再投递，跳过。
        if channel == DeliveryChannel::ClineDesktop {
            continue;
        }
        let model = model_for(channel);
        let name = channel.as_str();
        // P0-3：DSH 投递要求至少一个 profile 引用 KEYRELAY_API_KEY，
        // 否则 apply 在落盘前拒绝；本用例测的是跨通道幂等而非引用校验
        // 本身，因此先给 DSH 备一个已引用的 profile。
        if channel == DeliveryChannel::DeepSeekHarness {
            let profile = f
                .home
                .join(".dsh")
                .join("profiles")
                .join("desktop")
                .join("cordis.patch.yml");
            fs::create_dir_all(profile.parent().unwrap()).expect("建 profile 目录");
            fs::write(&profile, "apiKeyEnv: KEYRELAY_API_KEY\n").expect("写 profile");
        }
        let target = f
            .service
            .delivery_plan_with_model(f.key_id, channel, model)
            .unwrap_or_else(|e| panic!("{name} 计划失败: {e}"))
            .target_path
            .clone();
        // 从干净状态开始（A-2 可能已经留下了痕迹）
        let _ = fs::remove_file(&target);
        fs::create_dir_all(target.parent().expect("有父目录")).expect("建父目录");

        f.service
            .grant_consent(f.key_id, channel)
            .unwrap_or_else(|e| panic!("{name} 同意失败: {e}"));
        // 注意：两次 apply 都走 FileBusy 有界重试（见 apply_delivery_retry_on_busy）。
        let first = apply_delivery_retry_on_busy(&f, channel, model)
            .unwrap_or_else(|e| panic!("{name} 首投失败: {e}"));
        let after_first = fs::read(&target).expect("读首投后内容");

        let second = apply_delivery_retry_on_busy(&f, channel, model)
            .unwrap_or_else(|e| panic!("{name} 二投失败: {e}"));
        let after_second = fs::read(&target).expect("读二投后内容");
        assert_eq!(
            after_first, after_second,
            "{name} 第二次注入不得改动文件内容"
        );

        // 逆序回滚：后投的先回，回到「文件不存在」
        f.service
            .rollback_delivery(&second.journal_id)
            .unwrap_or_else(|e| panic!("{name} 二轮回滚失败: {e}"));
        assert_eq!(
            fs::read(&target).expect("读二轮回滚后内容"),
            after_first,
            "{name} 二轮回滚必须回到首投后的样子"
        );
        f.service
            .rollback_delivery(&first.journal_id)
            .unwrap_or_else(|e| panic!("{name} 首轮回滚失败: {e}"));
        assert!(!target.exists(), "{name} 首轮回滚必须删掉自己创建的文件");
    }
}

// ================================================================ A-10：G1 端到端流程完整

/// 按 URL 路由的假站点：把 `e2e_newapi.rs` 的假站点契约搬进零网络的 mock。
///
/// 与 `e2e_newapi.rs` 的分工：那边用**真实 TCP + 真实 RSA 加密登录**验证端到端
/// （含落库扫描），本文件用 mock 验证**流程完整性**（六个步骤一个不少、顺序正确）。
/// 两者互补，不重复。
#[derive(Clone)]
struct FakeSite {
    seen: Arc<Mutex<Vec<String>>>,
    tokens: Arc<Mutex<Vec<String>>>,
}

impl FakeSite {
    fn new() -> Self {
        Self {
            seen: Arc::new(Mutex::new(Vec::new())),
            tokens: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn paths(&self) -> Vec<String> {
        self.seen.lock().expect("锁").clone()
    }
}

#[async_trait]
impl HttpTransport for FakeSite {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse> {
        let path = req
            .url
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(&req.url)
            .to_string();
        let path = path
            .split_once('/')
            .map(|(_, rest)| format!("/{rest}"))
            .unwrap_or(path);
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(path.clone());
        }

        // 顺序有意义：`/api/user/login/encryption-key` 是 `/api/user/login` 的前缀
        if path.starts_with("/api/status") {
            return HttpResponse::json(
                200,
                json!({"success": true, "data": {"version": "v0.9.1", "quota_per_unit": QUOTA_PER_UNIT, "system_name": "假站点"}}),
            );
        }
        if path.starts_with("/api/user/login/encryption-key") {
            return HttpResponse::json(200, json!({"success": true, "data": {"enabled": false}}));
        }
        if path.starts_with("/api/user/login") {
            return Ok(
                HttpResponse::json(200, json!({"success": true, "data": {"id": 42}}))
                    .expect("构造响应")
                    .with_header("Set-Cookie", "session=matrix; Path=/"),
            );
        }
        if path.starts_with("/api/token/") && path.contains("/key") {
            return HttpResponse::json(
                200,
                json!({"success": true, "data": {"key": "sk-matrix-abcdefgh12345678"}}),
            );
        }
        if path.starts_with("/api/token/")
            && req.method == tianshu_relay_core::site::transport::Method::Post
        {
            if let Ok(mut tokens) = self.tokens.lock() {
                tokens.push("codex/daily".to_string());
            }
            return HttpResponse::json(200, json!({"success": true, "message": ""}));
        }
        if path.starts_with("/api/token/") {
            let items: Vec<Value> = self
                .tokens
                .lock()
                .expect("锁")
                .iter()
                .enumerate()
                .map(|(i, name)| json!({"id": i + 1, "name": name, "status": 1, "created_time": NOW + i as i64}))
                .collect();
            return HttpResponse::json(
                200,
                json!({"success": true, "data": {"items": items, "total": items.len()}}),
            );
        }
        if path.starts_with("/api/user/self") {
            return HttpResponse::json(
                200,
                json!({"success": true, "data": {"quota": 1_000_000, "used_quota": 500_000, "quota_per_unit": QUOTA_PER_UNIT}}),
            );
        }
        Err(Error::Transport(format!("夹具没有为 {path} 准备响应")))
    }
}

/// T-14 / A-10：G1「新增账号到拿到 `sk-`」的**流程完整性**。
///
/// 不断言 90 秒：那含人工操作（填 URL、过验证码），本机不可测（spec §14）。
/// 这里断言的是「六个步骤一个不少、顺序正确、密钥落到钥匙串而不是库里」。
#[tokio::test]
async fn g1_end_to_end_within_budget() {
    // G1 夹具的登录密码。**必须够长且唯一**——它会被拿去 ~336KB 的库文件里做子串搜索，
    // 2 字符的 `pw` 会**碰巧命中**：实测 400 次里有 3 次（0.75%）WAL 字节里正好凑出 `pw`
    // （随机 salt / 帧校验和附近，上下文全是二进制垃圾，不是被写进去的密码）。
    // 那正是这条用例 2026-10-16 在整包跑里随机红一次的原因（BACKLOG B-137）。
    const G1_PASSWORD: &str = "pw-g1-matrix-4f7a2b";
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let db_path = dir.path().join("tianshu-relay.db");
    let store = Store::open(&db_path).expect("文件库");
    let site = FakeSite::new();
    let service = TianshuRelayService::new(store, site.clone(), ServiceConfig::in_memory(home));

    let started = Instant::now();

    // ① 录入 + 指纹识别
    let summary = service
        .add_site("https://relay.example.com")
        .await
        .expect("识别站点");
    assert_eq!(summary.kind, "newapi");

    // ② 登录（本夹具走「未启用登录加密」分支；RSA 加密登录由 e2e_newapi.rs 覆盖）
    service
        .login(summary.id, Credentials::new("me", G1_PASSWORD))
        .await
        .expect("登录");

    // ③ 列令牌（此时还没有）
    assert!(service
        .list_keys(summary.id)
        .await
        .expect("列令牌")
        .is_empty());

    // ④ 建令牌 → 读明文 → 进钥匙串
    let stored: StoredKey = service
        .create_key(summary.id, KeySpec::named("codex/daily"))
        .await
        .expect("创建令牌");
    assert_eq!(stored.name, "codex/daily");
    assert!(
        !stored.masked.contains("sk-matrix-abcdefgh12345678"),
        "掩码不得含明文"
    );

    // ⑤ 再列一次：看得见
    let keys = service.list_keys(summary.id).await.expect("再列令牌");
    assert_eq!(keys.len(), 1);

    // ⑥ 余额
    let balance = service.balance(summary.id).await.expect("查余额");
    assert_eq!(balance.remaining, 2.0);

    let elapsed = started.elapsed();
    let paths = site.paths();
    println!(
        "A10 G1 端到端（注入式，零网络）: {} 个步骤 / {} 次请求 / {:?}",
        paths.len(),
        paths.len(),
        elapsed
    );
    println!("   （PRD 的「≤ 90 秒」含人工操作，本机只验流程完整性：{paths:?}）");

    // 六个步骤一个不少。**不断言整串逐字相等**：`create_key` 内部会自己列一次令牌
    // 去解析新 id，所以列令牌出现三次是正常形态（我的 ③、create_key 内部、⑤）。
    // 断言的是：关键节点的先后次序 + 每一步都真的发生过。
    let paths = site.paths();
    assert_eq!(
        paths.iter().take(3).cloned().collect::<Vec<_>>().as_slice(),
        &[
            "/api/status".to_string(),
            "/api/user/login/encryption-key".to_string(),
            "/api/user/login".to_string(),
        ],
        "G1 必须以「识别 → 加密探测 → 登录」开头"
    );
    let create_at = paths
        .iter()
        .position(|p| p == "/api/token/")
        .expect("必须真的创建令牌");
    let read_at = paths
        .iter()
        .position(|p| p == "/api/token/1/key")
        .expect("必须读一次明文");
    assert!(create_at < read_at, "必须先建令牌再读明文");
    assert_eq!(
        paths.last().map(String::as_str),
        Some("/api/user/self"),
        "余额查询是最后一步: {paths:?}"
    );
    assert_eq!(
        paths
            .iter()
            .filter(|p| p.as_str() == "/api/token/?p=1&page_size=100")
            .count(),
        3,
        "列令牌应出现三次（我的 ③、create_key 内部解析 id、我的 ⑤）: {paths:?}"
    );

    // 明文只进钥匙串：库文件里不得出现
    for suffix in ["", "-wal", "-shm"] {
        let path = PathBuf::from(format!("{}{suffix}", db_path.display()));
        let Ok(bytes) = fs::read(&path) else { continue };
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains("sk-matrix-abcdefgh12345678"),
            "数据库文件 {} 含密钥明文",
            path.display()
        );
        assert!(
            !text.contains(G1_PASSWORD),
            "数据库文件 {} 含登录密码",
            path.display()
        );
    }
}

// ================================================================ A-11：G4 余额告警在耗尽前

/// T-17 / A-11：余额告警必须在**耗尽前**触发、同一个坏状态**只报一次**、
/// 未知余额**不报**。
#[test]
fn g4_balance_alert_fires_before_exhaustion() {
    let config = NotifyConfig {
        balance_threshold: 15.0,
        ..NotifyConfig::default()
    };
    let site = |remaining: Option<f64>| SiteSnapshot {
        site_id: 1,
        display_name: "测试站点".to_string(),
        balance: remaining.map(|remaining| BalanceSnapshot {
            remaining,
            used: 20.0,
            currency: "USD".to_string(),
        }),
        needs_login: false,
        quota_exceeded: false,
        models: None,
        drift: Vec::new(),
        rotation_due: Vec::new(),
    };

    // ① 阈值 15、余额 14.9 ⇒ 触发（**耗尽前**）
    let first = evaluate(
        None,
        &Snapshot {
            sites: vec![site(Some(14.9))],
        },
        &config,
        NOW,
    );
    assert_eq!(kinds(&first), vec![NotifyKind::BalanceLow]);

    // ② 继续掉到 0.1（仍未耗尽）⇒ 不重复报（边沿型：上一轮已经在告了）
    let second = evaluate(
        Some(&Snapshot {
            sites: vec![site(Some(14.9))],
        }),
        &Snapshot {
            sites: vec![site(Some(0.1))],
        },
        &config,
        NOW + 60,
    );
    assert!(second.is_empty(), "同一坏状态不得每轮重报: {second:?}");

    // ③ 未知余额（None）⇒ 永不报：把「不知道」当成 0 会制造假告警
    let unknown = evaluate(
        None,
        &Snapshot {
            sites: vec![site(None)],
        },
        &config,
        NOW,
    );
    assert!(unknown.is_empty(), "未知余额不得触发余额告警: {unknown:?}");

    // ④ 阈值关闭（0）⇒ 不报
    let off = NotifyConfig {
        balance_threshold: 0.0,
        ..NotifyConfig::default()
    };
    assert!(evaluate(
        None,
        &Snapshot {
            sites: vec![site(Some(0.5))]
        },
        &off,
        NOW
    )
    .is_empty());
}

fn kinds(notes: &[tianshu_relay_core::notify::Notification]) -> Vec<NotifyKind> {
    notes.iter().map(|n| n.kind).collect()
}

// ================================================================ A-12：G5 前端产物与平台无关

/// T-18 / A-12：G5 要求 macOS 与 Windows **同代码库、同前端产物**。
///
/// 断言 `dist/` 里没有按平台分支的产物名（`.exe` / `.msi` / `.dmg` / `-win32` /
/// `-darwin` / `x86_64` / `aarch64` …）。`dist/` 未构建时跳过并打印
/// （CI 上没跑 `pnpm build` 是正常的，不该因此红）。
#[test]
fn g5_frontend_artifact_is_platform_neutral() {
    let dist = workspace_root().join("dist");
    if !dist.is_dir() {
        println!("A12 dist/ 未构建（跳过）");
        return;
    }
    let markers = [
        ".exe",
        ".msi",
        ".dmg",
        ".app",
        "-win32",
        "-darwin",
        "-linux",
        "x86_64",
        "aarch64",
        "windows",
        "macos",
        "apple-darwin",
    ];
    let mut files = Vec::new();
    collect_files(&dist, &mut files);
    assert!(!files.is_empty(), "dist/ 是空的：前端没构建");
    for path in &files {
        let name = path
            .file_name()
            .expect("有文件名")
            .to_string_lossy()
            .to_ascii_lowercase();
        for marker in markers {
            assert!(
                !name.contains(marker),
                "前端产物里出现平台相关文件名（{} 含 {marker}）: {}",
                name,
                path.display()
            );
        }
    }
    println!("A12 前端产物 {} 个文件，均无平台相关命名", files.len());
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("读目录 {} 失败: {e}", dir.display()));
    for entry in entries {
        let entry = entry.expect("目录项");
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

// ================================================================ A-13：webhook body 掩掉 URL userinfo

/// §9 / A-13：`title` 里带 `https://alice:pw@hook.example.com/x` 的通知，
/// 线上 body 里不得出现 `alice` / `pw`。
///
/// 结构化那一层（`mask_url_userinfo_in_json`）与文本那一层（`scrub`）各有一个
/// 只有它能覆盖的形态，这里两个形态都测——证明两层都在干活，详见
/// `notify/webhook.rs::payload_masks_url_userinfo_on_both_layers`。
#[test]
fn webhook_body_masks_url_userinfo() {
    let payload = webhook_payload(&tianshu_relay_core::notify::Notification::new(
        NotifyKind::Drift,
        Some(3),
        "https://alice:pw@hook.example.com/x".to_string(),
        "站点 https://bob:pw2@relay.example.com/y 的通知".to_string(),
        NOW,
    ));
    assert!(!payload.contains("alice"), "URL 用户名漏了: {payload}");
    // P3-31 / DEBUG-REPORT-v3 §3-31：原断言 !contains("\"pw@") 恒真——序列化的
    // JSON 里 pw 前是 ':' 不是 '"'，就算完全没脱敏也不含 "pw@。改检查真实密码
    // 片段 :pw@（脱敏后 URL 变 ***@hook，不含 :pw@）。
    assert!(!payload.contains(":pw@"), "URL 密码漏了: {payload}");
    assert!(!payload.contains("bob"), "句内 URL 用户名漏了: {payload}");
    assert!(!payload.contains("pw2"), "句内 URL 密码漏了: {payload}");
    assert!(
        payload.contains("hook.example.com"),
        "主机要留着: {payload}"
    );
    // 报文仍是合法 JSON（脱敏不得破坏结构）
    let parsed: Value = serde_json::from_str(&payload).expect("合法 JSON");
    assert_eq!(parsed["kind"], "drift");
    assert_eq!(parsed["site_id"], 3);
}

// ================================================================ 助手

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("工作区根")
        .to_path_buf()
}

// ================================================================ M8-S7：批量改指网关（B-116）

/// 批量动作的候选必须是**仍然有效**的绑定：已解绑的行不该出现
/// （否则用户会把一个早就解绑的通道「改指网关」，白写一次文件）。
#[test]
fn channel_bindings_exclude_unbound_rows() {
    let dir = tempfile::tempdir().expect("临时目录");
    let db = dir.path().join("tianshu-relay.db");
    let store = Store::open(&db).expect("文件库");
    let site = store
        .upsert_site("newapi", "https://relay.example.com", "测试站")
        .expect("写站点");
    let live = store
        .insert_key(site, "codex/live", "kr/key/1/secret", Some("1"), None)
        .expect("写 key");
    let dead = store
        .insert_key(site, "codex/dead", "kr/key/2/secret", Some("2"), None)
        .expect("写 key");
    store
        .record_binding("codex", live, "/home/u/.codex/auth.json", "j1", "site")
        .expect("写绑定");
    store
        .record_binding(
            "claude-code",
            dead,
            "/home/u/.claude/settings.json",
            "j2",
            "site",
        )
        .expect("写绑定");

    // 把第二条解绑（M8-S4 的语义：标记 `unbound_at`，不删行）
    store.unbind_agent("claude-code").expect("解绑 claude-code");

    let all = store.all_bindings().expect("读全部绑定");
    assert_eq!(all.len(), 2, "解绑不删行：两条都还在");
    // 命令层的过滤口径：`unbound_at.is_none()`
    let live_rows: Vec<&tianshu_relay_core::store::BindingRow> =
        all.iter().filter(|row| row.unbound_at.is_none()).collect();
    assert_eq!(live_rows.len(), 1, "只有一条仍然有效");
    assert_eq!(live_rows[0].agent_id, "codex");
    assert_eq!(live_rows[0].key_id, live);
    assert_eq!(live_rows[0].target_path, "/home/u/.codex/auth.json");
    assert_eq!(live_rows[0].site_id, site);
}

/// P2-16 / DEBUG-REPORT-v3 §2-16：同一个 `(agent, key, target)` 上重投时，
/// `current_bindings`（= `channel_bindings` = 批量改指候选）只留最新一行——
/// 被同 key 的更新投递取代的旧行不再作为候选列出。`all_bindings` 仍返回旧行
/// （溯源不删行），但候选视图不该把它再露给 UI，否则每重投一次候选翻倍（2→4）。
#[test]
fn current_bindings_superseded_by_same_key_redelivery_drops_old_row() {
    let dir = tempfile::tempdir().expect("临时目录");
    let db = dir.path().join("tianshu-relay.db");
    let store = Store::open(&db).expect("文件库");
    let site = store
        .upsert_site("newapi", "https://relay.example.com", "测试站")
        .expect("写站点");
    let key = store
        .insert_key(site, "codex/live", "kr/key/1/secret", Some("1"), None)
        .expect("写 key");

    // 同 (agent, key, target) 重投两次
    store
        .record_binding("codex", key, "/home/u/.codex/auth.json", "j1", "site")
        .expect("第一次投递");
    store
        .record_binding("codex", key, "/home/u/.codex/auth.json", "j2", "site")
        .expect("第二次重投");

    // all_bindings 仍两行（溯源用，不删行）
    let all = store.all_bindings().expect("全量");
    assert_eq!(all.len(), 2, "重投不删行：两条都在表里");

    // current_bindings 只留最新一行
    let cur = store.current_bindings().expect("当前生效");
    assert_eq!(cur.len(), 1, "同 key 重投：候选只留最新一行，不翻倍");
    assert_eq!(cur[0].id, 2, "留下的是最新那次（id=2）");
    assert_eq!(cur[0].key_id, key);
    assert_eq!(cur[0].target_path, "/home/u/.codex/auth.json");
}

/// P2-16 口径的另一面（M8-S7 P2-4 钉住）：换 key 重投——同 `(agent, target)` 但
/// **不同 key**——两条都是独立绑定，`current_bindings` 都要列出，不被互相取代。
#[test]
fn current_bindings_keeps_redelivery_with_a_different_key_separate() {
    let dir = tempfile::tempdir().expect("临时目录");
    let db = dir.path().join("tianshu-relay.db");
    let store = Store::open(&db).expect("文件库");
    let site = store
        .upsert_site("newapi", "https://relay.example.com", "测试站")
        .expect("写站点");
    let key_a = store
        .insert_key(site, "codex/live", "kr/key/1/secret", Some("1"), None)
        .expect("写 key A");
    let key_b = store
        .insert_key(site, "codex/dead", "kr/key/2/secret", Some("2"), None)
        .expect("写 key B");

    store
        .record_binding("codex", key_a, "/home/u/.codex/auth.json", "j1", "site")
        .expect("用 key A 投");
    store
        .record_binding("codex", key_b, "/home/u/.codex/auth.json", "j2", "site")
        .expect("换 key B 重投");

    let cur = store.current_bindings().expect("当前生效");
    assert_eq!(cur.len(), 2, "换 key 重投：两条独立绑定都列出（不去重）");
    let ids: Vec<i64> = cur.iter().map(|r| r.id).collect();
    assert_eq!(ids, vec![1, 2]);
    let keys: Vec<i64> = cur.iter().map(|r| r.key_id).collect();
    assert!(keys.contains(&key_a) && keys.contains(&key_b));
}

/// 批量动作的数据源必须是**只读**的：调用前后 `bindings` 逐字节相同。
///
/// 为什么钉这条：批量 UI 会在打开面板时读一次候选，若这个读取路径顺手写了什么
/// （例如「顺手标记已处理」），用户只是看了一眼面板就改了数据库。
#[test]
fn reading_channel_bindings_does_not_touch_the_database() {
    let dir = tempfile::tempdir().expect("临时目录");
    let db = dir.path().join("tianshu-relay.db");
    let store = Store::open(&db).expect("文件库");
    let site = store
        .upsert_site("newapi", "https://relay.example.com", "测试站")
        .expect("写站点");
    let key = store
        .insert_key(site, "codex/daily", "kr/key/1/secret", Some("1"), None)
        .expect("写 key");
    store
        .record_binding("codex", key, "/home/u/.codex/auth.json", "j1", "site")
        .expect("写绑定");

    // 读之前先把整表抄一份
    let before = store.all_bindings().expect("读一次");
    let _ = store.all_bindings().expect("再读一次");
    let after = store.all_bindings().expect("读第三次");
    assert_eq!(before, after, "重复读取必须给出同一份数据（只读）");

    // 行数与字段逐一对照：多一个隐式写入就会在这里现形
    assert_eq!(after.len(), before.len());
    for (b, a) in before.iter().zip(after.iter()) {
        assert_eq!(b.id, a.id);
        assert_eq!(b.key_id, a.key_id);
        assert_eq!(b.unbound_at, a.unbound_at, "读取不得改动 unbound_at");
        assert_eq!(b.applied_at, a.applied_at, "读取不得改动 applied_at");
    }

    // **其它表也不许被碰**（M8-S7 独立复审 P3-2）：只比 `bindings` 抓不到
    // 「顺手写条事件 / 顺手记个 setting」那种最自然的隐式写。这里比行数——
    // 不比对 db 文件字节（WAL 的 checkpoint 会让字节数自己变，那是噪声）。
    let conn = Connection::open(&db).expect("复开库");
    let count = |sql: &str| -> i64 {
        conn.query_row(sql, [], |row| row.get::<_, i64>(0))
            .expect("计数查询")
    };
    assert_eq!(
        count("SELECT COUNT(*) FROM events"),
        0,
        "读绑定不得写事件表（最常见的「顺手写」）"
    );
    assert_eq!(
        count("SELECT COUNT(*) FROM keys"),
        1,
        "读绑定不得改动 keys 表"
    );
    assert_eq!(
        count("SELECT COUNT(*) FROM sites"),
        1,
        "读绑定不得改动 sites 表"
    );
    let settings = count("SELECT COUNT(*) FROM settings");
    assert_eq!(
        settings, 0,
        "读绑定不得写 settings（例如记一个「读取时间」）"
    );

    // ---- M16-S3 P3-30：把只读守护扩到**服务层** ----
    //
    // 上面钉的是存储层的纯 SELECT。真正的数据源是 `service.channel_bindings()`
    // （`service.rs`）——它现在只是转发，但**没有任何东西拦着**下一个人在那里
    // 「顺手记一条事件」（DEBUG-REPORT-v3 §3-30 的变异：加一行写事件，全绿）。
    // 这里把同一个库交给服务，调一次真实的服务层入口，再复扫全部表的行数。
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let service = TianshuRelayService::new(
        Store::open(&db).expect("交给服务的库"),
        MockTransport::new(vec![]),
        ServiceConfig::in_memory(home),
    );
    let rows = service.channel_bindings().expect("服务层读绑定");
    assert_eq!(rows.len(), 1, "服务层应返回那条未解绑的绑定");
    assert_eq!(rows[0].agent_id, "codex");

    let count_after = |sql: &str| -> i64 {
        conn.query_row(sql, [], |row| row.get::<_, i64>(0))
            .expect("计数查询")
    };
    assert_eq!(
        count_after("SELECT COUNT(*) FROM bindings"),
        1,
        "服务层读取不得改动 bindings"
    );
    assert_eq!(
        count_after("SELECT COUNT(*) FROM events"),
        0,
        "服务层读取不得写事件表（服务层最自然的隐式写就是 log 一条）"
    );
    assert_eq!(
        count_after("SELECT COUNT(*) FROM settings"),
        0,
        "服务层读取不得写 settings"
    );
    assert_eq!(
        count_after("SELECT COUNT(*) FROM keys"),
        1,
        "服务层读取不得改动 keys"
    );
}
