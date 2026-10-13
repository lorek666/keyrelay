//! IPC 级命令测试：用 Tauri 官方 mock runtime **真正走一遍 `invoke` 链路**
//! （命令注册 → ACL 鉴权 → 状态注入 → 参数/返回值序列化），关闭 M0-S1 复审遗留的
//! 「capabilities / invoke 未验证」问题（BACKLOG B-15）。
//!
//! 三个关键点（前两个是首次编写时踩到的坑，已由本测试暴露并修复）：
//! 1. 必须用 `tauri::generate_context!()` 构建真实上下文（含 capabilities 解析出的 ACL）。
//!    `mock_context(noop_assets())` 的 ACL 是空的，任何应用命令都会被判
//!    `not allowed. Plugin not found`。
//! 2. 应用自有命令要在 `build.rs` 里用 `AppManifest::commands([...])` 登记，
//!    capabilities 才能引用 `allow-<command>`，否则真实运行时同样会被拒。
//! 3. 请求来源按平台不同（macOS/Linux `tauri://localhost`，Windows `http://tauri.localhost`）。
//!
//! 说明：mock runtime 仍不等于真实 wry 窗口，M1-S3 首次 `pnpm tauri dev` 联调时需再复核一次。

// 测试与 lib 各展开一次 `generate_context!()`，链接期会产生
// `ld: duplicate symbol '__EMBED_INFO_PLIST'` 噪音（复审 P2-6）。功能无影响，此处抑制。
#![allow(linker_messages)]

use serde_json::{json, Value};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{get_ipc_response, mock_builder, INVOKE_KEY};
use tauri::webview::InvokeRequest;

/// 建一个应用实例，并把 `main` 窗口也建好。
///
/// 窗口标签必须是 `main`：`capabilities/default.json` 的 `windows` 只列了它，
/// 换个标签会拿不到权限（ACL 会拒），测试就变成「验证 ACL」而不是「验证业务」。
fn build_app() -> (
    tauri::App<tauri::test::MockRuntime>,
    tauri::WebviewWindow<tauri::test::MockRuntime>,
) {
    let app =
        keyrelay_lib::configure_with_state(mock_builder(), keyrelay_lib::init_state_in_memory())
            .build(tauri::generate_context!())
            .expect("构建 mock 应用");
    let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .expect("构建 mock 窗口");
    (app, webview)
}

/// 在**指定的**窗口上发命令。
///
/// 需要跨调用保持状态（例如「写设置 → 读设置」）时必须用这个：
/// `invoke_impl` 每次都会新建应用，而内存库随应用创建，状态不会跨调用保留。
fn invoke_on(
    webview: &tauri::WebviewWindow<tauri::test::MockRuntime>,
    cmd: &str,
    args: Value,
) -> Result<Value, Value> {
    // 本地源按平台不同：capabilities 的 `local: true` 只覆盖本平台的本地源，用错会被 ACL 拒绝
    let origin = if cfg!(windows) {
        "http://tauri.localhost"
    } else {
        "tauri://localhost"
    };

    get_ipc_response(
        webview,
        InvokeRequest {
            cmd: cmd.to_string(),
            callback: CallbackFn(0),
            error: CallbackFn(1),
            url: origin.parse().expect("解析 url"),
            body: InvokeBody::Json(args),
            headers: Default::default(),
            invoke_key: INVOKE_KEY.to_string(),
        },
    )
    .map(|body| body.deserialize::<Value>().expect("反序列化返回值"))
}

fn invoke_impl(cmd: &str, args: Value) -> Result<Value, Value> {
    let (_app, webview) = build_app();
    invoke_on(&webview, cmd, args)
}

fn invoke(cmd: &str) -> Result<Value, Value> {
    invoke_impl(cmd, json!({}))
}

/// 打开网关总开关并指定端口。
///
/// 用「读 → 改 → 写」而不是手写一个只含 5 个字段的字面量：`SettingsDto` 要求**全部**
/// 字段，M6-S5 加了 13 个新字段之后，任何部分字面量都会在反序列化时空字段失败
/// （`invalid args … missing field 'theme'`）。这个写法对以后再加字段是免疫的，
/// 而且它走的是前端真实的调用序列。
fn enable_gateway(webview: &tauri::WebviewWindow<tauri::test::MockRuntime>, port: u16) {
    let mut payload = invoke_on(webview, "get_settings", json!({})).expect("读设置");
    payload["gatewayEnabled"] = json!(true);
    payload["gatewayPort"] = json!(port);
    invoke_on(
        webview,
        "update_settings",
        json!({"args": {"settings": payload}}),
    )
    .expect("打开网关总开关");
}

/// 断言错误不是「命令未注册 / 未授权」这类装配问题（业务错误可以接受）
fn assert_not_acl_rejection(cmd: &str, err: &Value) {
    let message = err.to_string();
    let lowered = message.to_lowercase();
    assert!(
        !lowered.contains("not allowed"),
        "命令 {cmd} 未通过 ACL（检查 build.rs 登记与 capabilities 引用）: {message}"
    );
    assert!(
        !(lowered.contains("not found") && lowered.contains("command")),
        "命令 {cmd} 未注册到 generate_handler!: {message}"
    );
}

#[test]
fn app_info_returns_expected_shape() {
    let value = invoke("app_info").expect("app_info 应成功");

    assert_eq!(value["name"], "KeyRelay");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(value["siteCount"], 0);
    assert_eq!(value["dbPath"], ":memory:");
    assert!(value["dbError"].is_null(), "内存库不应带降级原因: {value}");
}

#[test]
fn list_sites_returns_empty_array_on_fresh_state() {
    let value = invoke("list_sites").expect("list_sites 应成功");
    assert_eq!(value, json!([]));
}

#[test]
fn unknown_command_is_rejected() {
    let err = invoke("no_such_command").expect_err("未知命令必须报错");
    let message = err.to_string();
    assert!(
        message.contains("no_such_command"),
        "错误信息应指明命令名: {message}"
    );
}

/// 守护测试（复审 P2-4）：命令清单、build.rs 登记、capabilities 引用三者必须一致。
///
/// 漏登记的后果是运行期被 ACL 拒绝且无编译期提示，所以逐个命令实调一次。
/// 参数缺失导致的业务错误不算失败（`detect_site` 需要 `base_url` 等）。
#[test]
fn every_declared_command_is_registered_and_allowed() {
    for cmd in keyrelay_lib::commands_list::COMMANDS {
        if let Err(err) = invoke(cmd) {
            assert_not_acl_rejection(cmd, &err);
        }
    }
}

#[test]
fn capabilities_reference_every_declared_command() {
    let capabilities = include_str!("../capabilities/default.json");
    for cmd in keyrelay_lib::commands_list::COMMANDS {
        let permission = format!("allow-{}", cmd.replace('_', "-"));
        assert!(
            capabilities.contains(&permission),
            "capabilities/default.json 缺少 {permission}"
        );
    }
}

// ---------- M1-S1：真实用例命令的可达性 ----------

#[test]
fn list_keys_on_unknown_site_reports_business_error() {
    let err = invoke_impl("list_keys", json!({"siteId": 999})).expect_err("未知站点必须报错");
    assert_not_acl_rejection("list_keys", &err);
    let message = err.to_string();
    assert!(message.contains("999"), "错误信息应包含站点 id: {message}");
}

#[test]
fn site_balance_on_unknown_site_reports_business_error() {
    let err = invoke_impl("site_balance", json!({"siteId": 999})).expect_err("未知站点必须报错");
    assert_not_acl_rejection("site_balance", &err);
}

#[test]
fn login_site_on_unknown_site_reports_business_error() {
    let err = invoke_impl(
        "login_site",
        json!({"args": {"siteId": 999, "username": "me", "password": "pw"}}),
    )
    .expect_err("未知站点必须报错");
    assert_not_acl_rejection("login_site", &err);
}

#[test]
fn create_key_on_unknown_site_reports_business_error() {
    let err = invoke_impl(
        "create_key",
        json!({"args": {"siteId": 999, "name": "codex/daily"}}),
    )
    .expect_err("未知站点必须报错");
    assert_not_acl_rejection("create_key", &err);
}

#[test]
fn detect_site_reaches_real_transport_layer() {
    // 指向必然拒绝连接的本地端口：应得到传输层错误（而不是 ACL / 命令缺失错误）
    let err = invoke_impl("detect_site", json!({"baseUrl": "http://127.0.0.1:1"}))
        .expect_err("连接必然失败");
    assert_not_acl_rejection("detect_site", &err);
    let message = err.to_string();
    assert!(
        message.contains("连接") || message.contains("请求") || message.contains("未被识别"),
        "应是传输/探测错误: {message}"
    );
}

// ---------- M1-S1：成功路径的返回值结构（复审 P2-4）----------

/// 极简假站点：只应答 `GET /api/status`，用于让 `add_site` 走通真实 HTTP 链路
fn spawn_status_only_site() -> String {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取本地地址");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let body = r#"{"success":true,"data":{"version":"v0.9.1","quota_per_unit":500000,"system_name":"假站点"}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://{addr}")
}

#[test]
fn add_site_returns_expected_shape_against_fake_site() {
    let base_url = spawn_status_only_site();
    let value =
        invoke_impl("add_site", json!({"baseUrl": base_url.clone()})).expect("add_site 应成功");

    assert_eq!(value["id"], 1);
    assert_eq!(value["kind"], "newapi");
    assert_eq!(value["displayName"], "假站点");
    assert_eq!(value["health"], "unknown");
    assert_eq!(value["baseUrl"], base_url);
    assert!(
        value.get("base_url").is_none(),
        "不得出现 snake_case: {value}"
    );
}

#[test]
fn detect_site_returns_fingerprint_shape_against_fake_site() {
    let base_url = spawn_status_only_site();
    let value =
        invoke_impl("detect_site", json!({"baseUrl": base_url})).expect("detect_site 应成功");

    assert_eq!(value["kind"], "newapi");
    assert_eq!(value["displayName"], "假站点");
    assert_eq!(value["version"], "v0.9.1");
}

// ================================================================ 密钥投递（M1-S3）

/// 全新内存状态下没有密钥记录 → 投递相关命令都应报**业务错误**，
/// 而不是「命令未注册 / 未授权」这类装配问题。
#[test]
fn delivery_commands_report_business_errors_on_unknown_key() {
    for (cmd, args) in [
        (
            "delivery_plan",
            json!({"args": {"keyId": 999, "channel": "codex-auth-json"}}),
        ),
        (
            "grant_consent",
            json!({"args": {"keyId": 999, "channel": "codex-auth-json"}}),
        ),
        (
            "revoke_consent",
            json!({"args": {"keyId": 999, "channel": "codex-auth-json"}}),
        ),
        (
            "apply_delivery",
            json!({"args": {"keyId": 999, "channel": "codex-auth-json"}}),
        ),
    ] {
        let err = invoke_impl(cmd, args).expect_err(&format!("{cmd} 应报错"));
        assert_not_acl_rejection(cmd, &err);
        let text = err.as_str().unwrap_or_default();
        assert!(text.contains("999"), "{cmd} 的错误应说明是哪个 key: {text}");
    }
}

#[test]
fn delivery_rejects_unknown_channel_before_touching_state() {
    let err = invoke_impl(
        "delivery_plan",
        json!({"args": {"keyId": 1, "channel": "does-not-exist"}}),
    )
    .expect_err("未知通道应报错");
    assert_not_acl_rejection("delivery_plan", &err);
    assert!(
        err.as_str().unwrap_or_default().contains("未知的投递通道"),
        "{err}"
    );
}

#[test]
fn list_consents_is_empty_on_fresh_state() {
    let value = invoke("list_consents").expect("list_consents 应成功");
    assert_eq!(value, json!([]));
}

#[test]
fn recent_events_returns_array_and_honours_limit() {
    let value = invoke_impl("recent_events", json!({"limit": 10})).expect("recent_events 应成功");
    assert!(value.is_array(), "{value}");

    // limit 缺省也能跑（Option<usize>）
    let value = invoke("recent_events").expect("recent_events 无参应成功");
    assert!(value.is_array(), "{value}");
}

#[test]
fn rollback_of_unknown_journal_reports_business_error() {
    let err = invoke_impl("rollback_delivery", json!({"journalId": "j-nope"}))
        .expect_err("未知 journal 应报错");
    assert_not_acl_rejection("rollback_delivery", &err);
    assert!(err.as_str().unwrap_or_default().contains("j-nope"), "{err}");
}

#[test]
fn delivery_plan_dto_is_camel_case_and_has_no_secret_field() {
    // 用未知 key 走不通，这里直接对 DTO 做序列化断言（在 commands.rs 的单测里已钉死字段名），
    // IPC 侧只验证「错误路径下不泄漏任何密钥形态的字符串」
    let err = invoke_impl(
        "delivery_plan",
        json!({"args": {"keyId": 1, "channel": "codex-auth-json"}}),
    )
    .expect_err("应报错");
    let text = err.to_string();
    assert!(!text.contains("sk-"), "错误里不得出现密钥形态: {text}");
}

// ============================================ 漂移 / 设置 / 刷新（M3-S1）

#[test]
fn drift_report_is_empty_on_a_fresh_install() {
    let value = invoke("drift_report").expect("drift_report 应成功");
    assert_eq!(value, json!([]));
}

#[test]
fn get_settings_returns_defaults() {
    let value = invoke("get_settings").expect("get_settings 应成功");
    assert_eq!(value["refreshIntervalSecs"], 0, "定时刷新必须默认关闭");
    assert_eq!(value["balanceAlertThreshold"], 0.0);
    assert_eq!(value["driftCheckOnStart"], true);
    assert_eq!(value["gatewayEnabled"], false, "网关必须默认关闭");
    assert_eq!(value["gatewayPort"], 8787);
    assert!(
        value.get("refresh_interval_secs").is_none(),
        "不得出现 snake_case: {value}"
    );
}

#[test]
fn update_settings_round_trips_and_rejects_bad_values() {
    // 跨调用保持状态：同一个应用实例里「写 → 读」。
    //
    // 载荷按**前端的真实流程**构造：先 `get_settings` 拿到完整对象，改几个字段，再整体写回。
    // 早先这里手写了一个只含 5 个字段的字面量——M6-S5 给 `Settings` 加了 13 个字段之后，
    // 那个写法会因为 `SettingsDto` 要求全部字段而直接反序列化失败。
    // 改成「读→改→写」之后，以后再加字段这个测试不需要再改，而且它验的是真实路径。
    let (_app, webview) = build_app();
    let mut payload = invoke_on(&webview, "get_settings", json!({})).expect("get_settings");
    payload["refreshIntervalSecs"] = json!(600);
    payload["balanceAlertThreshold"] = json!(3.5);
    payload["driftCheckOnStart"] = json!(false);
    payload["gatewayEnabled"] = json!(true);
    payload["gatewayPort"] = json!(9999);
    // M6-S5 新增字段也走一遍：确认它们真的过得了 IPC 与校验
    payload["theme"] = json!("dark");
    payload["language"] = json!("en-US");
    payload["notifyWebhookUrl"] = json!("https://hooks.example.com/kr");
    payload["rotationMaxAgeDays"] = json!(45);
    payload["rotationWarnBeforeDays"] = json!(10);

    let updated = invoke_on(
        &webview,
        "update_settings",
        json!({"args": {"settings": payload}}),
    )
    .expect("update_settings 应成功");
    assert_eq!(updated["refreshIntervalSecs"], 600);
    assert_eq!(updated["balanceAlertThreshold"], 3.5);
    assert_eq!(updated["driftCheckOnStart"], false);
    assert_eq!(updated["gatewayEnabled"], true);
    assert_eq!(updated["gatewayPort"], 9999);
    assert_eq!(updated["theme"], "dark");
    assert_eq!(updated["language"], "en-US");
    assert_eq!(updated["notifyWebhookUrl"], "https://hooks.example.com/kr");
    assert_eq!(updated["rotationMaxAgeDays"], 45);
    assert_eq!(updated["rotationWarnBeforeDays"], 10);

    let read = invoke_on(&webview, "get_settings", json!({})).expect("get_settings");
    assert_eq!(read, updated, "同一实例内写后读必须一致");

    // 非法值被拒。同样走「读→改→写」，只把要验的那一项改坏。
    let mut bad = read.clone();
    bad["refreshIntervalSecs"] = json!(99999999);
    let err = invoke_impl("update_settings", json!({"args": {"settings": bad}}))
        .expect_err("超上限的间隔应被拒绝");
    assert_not_acl_rejection("update_settings", &err);
    assert!(
        err.as_str().unwrap_or_default().contains("刷新间隔"),
        "{err}"
    );

    // M6-S5 新增的两条校验也要在 IPC 层被验到（不能只在 core 的单测里成立）
    let mut bad_theme = read.clone();
    bad_theme["theme"] = json!("neon");
    let err = invoke_impl("update_settings", json!({"args": {"settings": bad_theme}}))
        .expect_err("未知主题应被拒绝");
    assert_not_acl_rejection("update_settings", &err);
    assert!(err.as_str().unwrap_or_default().contains("主题"), "{err}");

    let mut bad_window = read.clone();
    bad_window["rotationMaxAgeDays"] = json!(30);
    bad_window["rotationWarnBeforeDays"] = json!(31);
    let err = invoke_impl("update_settings", json!({"args": {"settings": bad_window}}))
        .expect_err("提醒窗口宽于轮换周期应被拒绝");
    assert_not_acl_rejection("update_settings", &err);
    assert!(
        err.as_str().unwrap_or_default().contains("提前提醒"),
        "{err}"
    );

    // 被拒之后库里仍是上一次成功写入的值（校验发生在落库之前）
    let after = invoke_on(&webview, "get_settings", json!({})).expect("get_settings");
    assert_eq!(after, updated, "被拒的写入不得改动已保存的设置");
}

#[test]
fn refresh_all_is_a_noop_on_an_empty_installation() {
    let value = invoke("refresh_all").expect("refresh_all 应成功");
    assert_eq!(value["sitesTotal"], 0);
    assert_eq!(value["sitesOk"], 0);
    assert_eq!(value["sitesFailed"], 0);
    assert_eq!(value["keysTotal"], 0);
    assert_eq!(value["balanceAlerts"], json!([]));
}

// ============================================ 脱敏审计（M4-S1）

#[test]
fn audit_redaction_reports_clean_on_a_fresh_install() {
    let value = invoke("audit_redaction").expect("audit_redaction 应成功");
    assert_eq!(value["clean"], true, "{value}");
    assert_eq!(value["findings"], json!([]));
    assert!(value["summary"]
        .as_str()
        .unwrap_or("")
        .contains("未发现明文"));
    // IPC 测试用的是**内存库**（没有 db 文件），备份目录也还没建，
    // 因此 `filesScanned` 可能是 0——这里只断言它是数字，不假设一定扫到了文件。
    assert!(value["filesScanned"].is_number(), "{value}");
    assert!(value["bytesScanned"].is_number(), "{value}");
    assert!(
        value.get("files_scanned").is_none(),
        "不得出现 snake_case: {value}"
    );
}

// ============================================ 网关 / 导出 / 备份清理（M4-S2）

#[test]
fn gateway_status_is_stopped_on_a_fresh_install() {
    let value = invoke("gateway_status").expect("gateway_status 应成功");
    assert_eq!(value["running"], false);
    assert_eq!(value["url"], Value::Null);
    assert_eq!(value["token"], Value::Null);
}

#[test]
fn gateway_stop_is_idempotent() {
    let value = invoke("gateway_stop").expect("未运行时停止也应成功");
    assert_eq!(value["running"], false);
    let again = invoke("gateway_stop").expect("重复停止仍应成功");
    assert_eq!(again["running"], false);
}

#[test]
fn gateway_start_is_refused_while_the_master_switch_is_off() {
    // M4-S2 复审 P2-8：以前只有 UI 把按钮置灰，直接调 IPC 就能把端口打开。
    // 默认 `gateway_enabled = false`，所以这条走的是全新实例。
    let err = invoke_impl("gateway_start", json!({"args": {"siteId": 1, "keyId": 1}}))
        .expect_err("总开关关着时不许启动网关");
    assert_not_acl_rejection("gateway_start", &err);
    let message = err.as_str().unwrap_or_default();
    assert!(message.contains("总开关"), "{message}");
    assert!(
        message.contains("设置"),
        "错误里要告诉用户去哪儿打开: {message}"
    );
}

#[test]
fn gateway_start_on_an_unknown_key_reports_a_business_error() {
    // 先打开总开关，否则会先撞上 P2-8 那道门，测不到「未知密钥」这条业务错误
    let (_app, webview) = build_app();
    enable_gateway(&webview, 8787);

    let err = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": 999, "keyId": 999}}),
    )
    .expect_err("未知站点/密钥必须报错");
    assert_not_acl_rejection("gateway_start", &err);
    assert!(err.as_str().unwrap_or_default().contains("999"), "{err}");
}

#[test]
fn export_bundle_writes_a_file_without_key_material() {
    let dir = tempfile::tempdir().expect("临时目录");
    let path = dir.path().join("export.json");
    let value = invoke_impl(
        "export_bundle",
        json!({"args": {"path": path.display().to_string()}}),
    )
    .expect("export_bundle 应成功");

    assert_eq!(value["encrypted"], false);
    assert!(value["bytes"].as_u64().unwrap_or(0) > 0);
    assert_eq!(value["path"], path.display().to_string());

    let text = std::fs::read_to_string(&path).expect("读导出文件");
    assert!(text.contains("\"version\""), "{text}");
    assert!(!text.contains("sk-"), "导出物出现密钥形态: {text}");
    assert!(!text.contains("secret_ref"), "{text}");
}

#[test]
fn export_bundle_with_a_password_is_encrypted() {
    let dir = tempfile::tempdir().expect("临时目录");
    let path = dir.path().join("export-enc.json");
    let value = invoke_impl(
        "export_bundle",
        json!({"args": {"password": "pw-123456", "path": path.display().to_string()}}),
    )
    .expect("加密导出应成功");
    assert_eq!(value["encrypted"], true);

    let text = std::fs::read_to_string(&path).expect("读导出文件");
    assert!(text.contains("keyrelay-export-v1"), "{text}");
    assert!(!text.contains("\"sites\""), "密文里不该有明文结构");
}

#[test]
fn prune_backups_reports_zero_when_there_is_nothing_to_prune() {
    let value =
        invoke_impl("prune_backups", json!({"args": {"keep": 5}})).expect("prune_backups 应成功");
    assert_eq!(value["removed"], 0);
}

#[test]
fn export_diagnostics_writes_a_package_and_registers_it_for_the_audit() {
    // DEBUG 报告 §1.6：`service::export_diagnostics` 当时**零生产调用点**，
    // 而 `M7-收口记录` 把它记成已交付。这条同时钉三件事：
    // ① 命令真的能落盘；② 条数与文件内容自洽；③ 登记进「已知导出物」表
    // （否则审计扫不到它——B-60 的另一半）。
    let (_app, webview) = build_app();

    let before = invoke_on(&webview, "audit_redaction", json!({})).expect("审计应成功");
    let dir = tempfile::tempdir().expect("临时目录");
    let path = dir.path().join("diag.json");

    let value = invoke_on(
        &webview,
        "export_diagnostics",
        json!({"args": {"path": path.display().to_string()}}),
    )
    .expect("export_diagnostics 应成功");

    assert_eq!(
        value["registered"], true,
        "必须登记，否则审计看不到它: {value}"
    );
    assert_eq!(value["path"], path.display().to_string());

    let text = std::fs::read_to_string(&path).expect("读诊断包");
    let parsed: Value = serde_json::from_str(&text).expect("诊断包必须是合法 JSON");
    for key in ["version", "settings", "events", "vault_backend", "home"] {
        assert!(parsed.get(key).is_some(), "诊断包缺 {key}: {text}");
    }
    // 条数自洽：命令回报的 `events` 必须等于文件里真的写了几条。
    // 只断言「> 0」的话，`diagnostics_json` 少写一半也照样绿。
    let written = parsed["events"]
        .as_array()
        .map(|v| v.len())
        .unwrap_or(usize::MAX);
    assert_eq!(
        value["events"].as_u64().unwrap_or(u64::MAX),
        written as u64,
        "{value}"
    );
    assert_eq!(value["bytes"].as_u64().unwrap_or(0), text.len() as u64);

    assert!(!text.contains("sk-"), "诊断包出现密钥形态: {text}");
    assert!(!text.contains("secret_ref"), "{text}");

    let after = invoke_on(&webview, "audit_redaction", json!({})).expect("审计应成功");
    assert_eq!(after["clean"], true, "诊断包必须自身干净: {after}");
    assert_eq!(
        after["filesScanned"].as_u64().unwrap_or(0),
        before["filesScanned"].as_u64().unwrap_or(0) + 1,
        "登记的意义是进扫描集合：文件数必须 +1（登记失败的话这条会红）"
    );
}

#[test]
fn export_diagnostics_is_reachable_from_the_ui() {
    // 「函数存在但没有调用点」是 DEBUG 报告 §4-3 点名的模式。命令层注册由
    // `every_declared_command_is_registered_and_allowed` 守着，这里补另一半：
    // **前端真的调它**。少了这一半，PRD 里算已交付、用户手里不存在。
    const API: &str = include_str!("../../src/lib/api.ts");
    assert!(
        API.contains("\"export_diagnostics\""),
        "api.ts 里没有 export_diagnostics 的调用点"
    );
    const SETTINGS: &str = include_str!("../../src/pages/Settings.tsx");
    assert!(
        SETTINGS.contains("exportDiagnostics("),
        "Settings.tsx 没有调用 exportDiagnostics——诊断包在界面上不可达"
    );
}

// ============================================ M5-S5：会话失效可见性 + 网关启停串行化

#[test]
fn refresh_all_reports_sites_that_need_a_login() {
    use tauri::Manager;

    let (_app, webview) = build_app();
    let state = webview.app_handle().state::<keyrelay_lib::AppState>();
    let store = state.service.store();

    let site = store
        .upsert_site("newapi", "https://relay.example.com", "需要重登的站")
        .expect("写站点");
    // 造出「上一轮已经失效」的持久形态：无会话 + health=needs_login。
    // 这正是 B-61 里会被静默跳过的组合——既不算成功也不算失败，
    // 于是用户在汇总里永远看不到「这个站需要重新登录」。
    store
        .set_site_health(site, "needs_login")
        .expect("落库会话状态");

    let value = invoke_on(&webview, "refresh_all", json!({})).expect("refresh_all 应成功");

    assert_eq!(value["sitesTotal"], 1);
    assert_eq!(value["sitesOk"], 0);
    assert_eq!(value["sitesFailed"], 0, "被跳过的站点不算失败");
    assert_eq!(
        value["needsLogin"],
        json!([site]),
        "会话失效的站点必须出现在 needsLogin 里: {value}"
    );
}

#[test]
fn gateway_stop_then_start_on_the_same_port_succeeds() {
    use tauri::Manager;

    let (_app, webview) = build_app();
    // 拿一个空闲端口：绑 0 再放掉。窗口期内被抢的概率极低，
    // 而且真被抢了会明确报「端口被占用」，不会假绿。
    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("探端口");
        probe.local_addr().expect("读端口").port()
    };

    let state = webview.app_handle().state::<keyrelay_lib::AppState>();
    let site = state
        .service
        .store()
        .upsert_site("newapi", "https://relay.example.com", "网关测试站")
        .expect("写站点");
    let key_id = state
        .service
        .store_key_material(
            site,
            "codex/daily",
            Some("12"),
            None,
            "sk-gateway-0123456789abcdef",
        )
        .expect("写密钥")
        .id;

    enable_gateway(&webview, port);

    let args = json!({"args": {"siteId": site, "keyId": key_id}});
    let first = invoke_on(&webview, "gateway_start", args.clone()).expect("第一次启动");
    assert_eq!(first["running"], true, "{first}");
    assert_eq!(first["url"], format!("http://127.0.0.1:{port}"));

    let stopped = invoke_on(&webview, "gateway_stop", json!({})).expect("停止");
    assert_eq!(stopped["running"], false);

    // 关键断言：停完**立刻**用同一个端口再起。
    // 命令层若不等待端口真正释放（只发 shutdown 信号），这里会撞上还没释放的
    // 监听套接字并报「端口可能被占用」——就是 B-64 的现象。
    let second =
        invoke_on(&webview, "gateway_start", args).expect("停完立刻用同一端口重启必须成功");
    assert_eq!(second["running"], true, "{second}");
    assert_eq!(second["url"], format!("http://127.0.0.1:{port}"));

    invoke_on(&webview, "gateway_stop", json!({})).expect("收尾停止");
}

#[test]
fn gateway_stop_is_bounded_even_with_an_in_flight_request() {
    // 处置 M5-S4 复审 P2-1：`shutdown_and_wait()` 没有上界 ——
    // 上游卡住且仍有客户端在等时，它要等在途连接收尾才返回，而命令层
    // 正握着 `gateway_op` 操作锁，会把后续 start/stop 一起挂死。
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::{Duration, Instant};
    use tauri::Manager;

    // 上游：接受连接、读掉请求、**永不响应**（让网关侧的请求一直"在途"）
    let upstream = std::net::TcpListener::bind("127.0.0.1:0").expect("绑上游");
    let upstream_addr = upstream.local_addr().expect("上游地址");
    std::thread::spawn(move || {
        for stream in upstream.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            // 不写响应、不关连接
            std::thread::sleep(Duration::from_secs(30));
        }
    });

    let (_app, webview) = build_app();
    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("探端口");
        probe.local_addr().expect("读端口").port()
    };

    let state = webview.app_handle().state::<keyrelay_lib::AppState>();
    let site = state
        .service
        .store()
        .upsert_site("newapi", &format!("http://{upstream_addr}"), "慢上游")
        .expect("写站点");
    let key_id = state
        .service
        .store_key_material(
            site,
            "codex/daily",
            Some("12"),
            None,
            "sk-slow-0123456789abcdef",
        )
        .expect("写密钥")
        .id;

    enable_gateway(&webview, port);

    let started = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key_id}}),
    )
    .expect("启动网关");
    let token = started["token"].as_str().expect("令牌").to_string();

    // 打一个会一直"在途"的请求：不读响应，3 秒后主动断开。
    // 客户端在 3 秒断开，是为了让**去掉上界**的变异体也能结束（只是会晚到 ~3s），
    // 而不是把整个测试套件挂死。
    let mut client = TcpStream::connect(("127.0.0.1", port)).expect("连网关");
    let request = format!(
        "GET /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
         Authorization: Bearer {token}\r\n\r\n"
    );
    client.write_all(request.as_bytes()).expect("发请求");
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(3));
        drop(client);
    });

    // 给网关一点时间把请求转出去
    std::thread::sleep(Duration::from_millis(300));

    let t0 = Instant::now();
    let stopped = invoke_on(&webview, "gateway_stop", json!({})).expect("停止");
    let elapsed = t0.elapsed();

    assert_eq!(stopped["running"], false);
    // 前提：在途请求**确实**拖住了 shutdown —— 否则下面那条断言是空跑
    assert!(
        elapsed >= Duration::from_millis(1500),
        "在途请求没有拖住 shutdown，这条测试失去意义: {elapsed:?}"
    );
    // 结论：上界生效。不设上界时这里要等到客户端 3 秒后断开（≈3s）
    assert!(
        elapsed < Duration::from_millis(2500),
        "shutdown 没有被上界截住: {elapsed:?}"
    );
}

// ==================================================== M6-S5：FR-2 / FR-7 接线

#[test]
fn rotation_due_is_a_local_noop_on_an_empty_installation() {
    // 空安装（没有任何站点/密钥）时必须是「空列表」而不是报错：
    // 它是纯本地判定，不联网、不读密钥。
    let value = invoke("rotation_due").expect("rotation_due 应成功");
    assert_eq!(value, json!([]));
}

#[test]
fn available_groups_on_an_unknown_site_reports_a_business_error() {
    let err =
        invoke_impl("available_groups", json!({"siteId": 999})).expect_err("不存在的站点应报错");
    assert_not_acl_rejection("available_groups", &err);
}

#[test]
fn sync_site_keys_on_an_unknown_site_reports_a_business_error() {
    let err =
        invoke_impl("sync_site_keys", json!({"siteId": 999})).expect_err("不存在的站点应报错");
    assert_not_acl_rejection("sync_site_keys", &err);
}

#[test]
fn autostart_round_trips_through_enable_then_disable() {
    // 注意：这条跑在 mock runtime 上，`std::env::current_exe()` 指向测试二进制本身。
    // 我们断言的是**状态机与产物**，不是「登录时真的会启动它」——后者需要真实登录会话，
    // 本机无法验证（见 spec §3.4 的未验证边界）。
    let before = invoke("autostart_status").expect("autostart_status 应成功");
    assert_not_acl_rejection("autostart_status", &before);
    assert!(
        ["enabled", "disabled", "unknown"].contains(&before["state"].as_str().unwrap_or("")),
        "state 必须是三态之一: {before}"
    );

    let enabled = invoke_impl("autostart_set", json!({"enabled": true}))
        .expect("开启自启应成功（写的是内存测试 home 下的 plist）");
    assert_not_acl_rejection("autostart_set", &enabled);
    // 计划摘要只含路径与键名，**不含任何 env 值**
    assert!(enabled["plan"].is_string(), "{enabled}");

    let disabled = invoke_impl("autostart_set", json!({"enabled": false})).expect("关闭自启应成功");
    assert_not_acl_rejection("autostart_set", &disabled);
    assert!(disabled["plan"].is_string(), "{disabled}");
}

#[test]
fn autostart_set_rejects_a_missing_argument() {
    // 反例保护：缺参数应是**参数错误**而不是静默当作 false 成功。
    let err = invoke_impl("autostart_set", json!({})).expect_err("缺 enabled 参数应被拒");
    assert_not_acl_rejection("autostart_set", &err);
}

#[test]
fn rotation_plan_is_local_and_lists_the_fixed_three_steps() {
    use tauri::Manager;
    let (_app, webview) = build_app();
    let state = webview.app_handle().state::<keyrelay_lib::AppState>();
    let site = state
        .service
        .store()
        .upsert_site("newapi", "https://relay.example.com", "轮换站")
        .expect("写站点");
    let key_id = state
        .service
        .store_key_material(
            site,
            "codex/daily",
            Some("12"),
            None,
            "sk-rotation-0123456789ab",
        )
        .expect("写密钥")
        .id;

    let value = invoke_on(&webview, "rotation_plan", json!({"keyId": key_id}))
        .expect("rotation_plan 应成功");
    assert_not_acl_rejection("rotation_plan", &value);

    assert_eq!(value["keyId"], key_id);
    assert_eq!(
        value["steps"],
        json!(["create_new", "reinject_all", "revoke_old"]),
        "顺序是冻结的，界面展示的就是实际执行的顺序"
    );
    assert_eq!(
        value["channels"],
        json!([]),
        "还没投递过，没有要重注入的目标"
    );
    assert_eq!(value["unmappedTargets"], json!([]));
    assert_eq!(value["oldRemoteId"], "12");
    assert_eq!(value["keyName"], "codex/daily");
    // 预览不得带出明文（命令层至今没有任何一条命令返回过密钥明文）
    assert!(
        !value.to_string().contains("sk-rotation"),
        "预览不得含密钥明文: {value}"
    );
}

#[test]
fn rotate_key_reaches_the_business_path_without_a_session() {
    use tauri::Manager;
    // 断言的是**可达性**：命令已注册、ACL 通过、参数能反序列化、本地前置检查能跑完，
    // 最后停在「没有会话」这条业务错误上。真正的网络路径由 core 层的
    // `tests/rotation_run.rs` 用假传输层覆盖。
    let (_app, webview) = build_app();
    let state = webview.app_handle().state::<keyrelay_lib::AppState>();
    let site = state
        .service
        .store()
        .upsert_site("newapi", "https://relay.example.com", "轮换站")
        .expect("写站点");
    let key_id = state
        .service
        .store_key_material(
            site,
            "codex/daily",
            Some("12"),
            None,
            "sk-rotation-0123456789ab",
        )
        .expect("写密钥")
        .id;

    let err = invoke_on(
        &webview,
        "rotate_key",
        json!({"keyId": key_id, "name": "codex/rotated"}),
    )
    .expect_err("没有会话时必须失败");
    assert_not_acl_rejection("rotate_key", &err);
    let message = err.to_string();
    assert!(
        message.contains("登录"),
        "没有会话时应报「先登录」这类业务错误，而不是装配错误: {message}"
    );
    assert!(
        !message.contains("sk-rotation"),
        "错误文案不得含密钥明文: {message}"
    );
}

#[test]
fn rotate_key_rejects_a_missing_argument() {
    // 反例保护：缺参数应是**参数错误**，不能当成 `keyId = 0` 去查库。
    let err = invoke_impl("rotate_key", json!({})).expect_err("缺参数应被拒");
    assert_not_acl_rejection("rotate_key", &err);
}

#[test]
fn list_stored_keys_is_empty_on_a_fresh_install() {
    // B-93（M7-S5 补）：`list_stored_keys` 出自 M1-S4，是 35 条命令里**唯一**没有
    // IPC 层断言的一条。它此前只在核心层的测试里被覆盖过——而「命令已注册 + 过了 ACL +
    // 返回形状是数组」这三件事只有 IPC 层能证明。
    let value = invoke("list_stored_keys").expect("list_stored_keys 应成功");
    assert_not_acl_rejection("list_stored_keys", &value);
    assert_eq!(value, json!([]), "空安装应是空数组");
}

#[test]
fn revoke_key_requires_confirmation_before_touching_anything() {
    // 破坏性且不可逆：`confirm` 缺失或为 false 时必须在**参数校验**就停住，
    // 不能「先查站点再报错」——那样一次误触就会走到站点侧删除的边界上。
    let err = invoke_impl(
        "revoke_key",
        json!({"siteId": 999, "remoteId": "12", "confirm": false}),
    )
    .expect_err("未确认应被拒");
    assert_not_acl_rejection("revoke_key", &err);
    assert!(
        err.to_string().contains("二次确认"),
        "应给出「需要二次确认」而不是别的错误: {err}"
    );

    // 确认之后才走到业务路径：站点不存在 ⇒ 业务错误（而不是 ACL / 参数错误）。
    let err = invoke_impl(
        "revoke_key",
        json!({"siteId": 999, "remoteId": "12", "confirm": true}),
    )
    .expect_err("不存在的站点应报错");
    assert_not_acl_rejection("revoke_key", &err);
}

#[test]
fn unbind_agent_requires_confirmation_only_when_also_revoking() {
    // M8-S4 §5.4：`confirm` **只对** `alsoRevoke == true` 强制。
    // 解绑本身可恢复（行保留、再投递即可），给它加一道二次确认只会让日常操作变烦；
    // 而站点侧删除没有撤销入口。
    let err = invoke_impl(
        "unbind_agent",
        json!({"agentId": "codex", "alsoRevoke": true, "confirm": false}),
    )
    .expect_err("回收未确认应被拒");
    assert_not_acl_rejection("unbind_agent", &err);
    assert!(
        err.to_string().contains("二次确认"),
        "应给出「需要二次确认」: {err}"
    );

    // 默认路径（不回收）**不需要** confirm：空安装上应当拿到一份零报告而不是错误。
    let value = invoke_impl(
        "unbind_agent",
        json!({"agentId": "codex", "alsoRevoke": false, "confirm": false}),
    )
    .expect("解绑是幂等的收尾动作，零命中也是成功");
    assert_not_acl_rejection("unbind_agent", &value);
    assert_eq!(value["unbound"], 0);
    assert_eq!(value["alreadyUnbound"], 0);
    assert_eq!(value["revoked"], json!([]));
    assert_eq!(value["note"], Value::Null);
}

#[test]
fn gateway_rotate_token_reaches_the_business_path() {
    // 网关没在跑：轮换只换钥匙串里那一份（下一次启动自然用新的），返回当前状态。
    let value = invoke_impl("gateway_rotate_token", json!({})).expect("空安装应成功");
    assert_not_acl_rejection("gateway_rotate_token", &value);
    assert_eq!(value["running"], false);
    assert_eq!(value["tokenPersistent"], true, "写进钥匙串了");
}

// ---------- M8-S2：人工过验证码（IPC 可达性与业务前置） ----------

#[test]
fn captcha_begin_without_a_pending_challenge_reports_business_error() {
    // 没有「等待中的挑战」时点入口 ⇒ 明确拒绝（而不是打开一个空白窗口）。
    // 这条同时证明：窗口创建发生在相位检查**之后**（无 GUI 环境也不会先炸一步）。
    let err =
        invoke_impl("captcha_begin", json!({"siteId": 999})).expect_err("没有等待中的挑战应被拒");
    assert_not_acl_rejection("captcha_begin", &err);
    assert!(err.to_string().contains("人机验证"), "{err}");
}

#[test]
fn captcha_complete_without_a_pending_challenge_reports_business_error() {
    // T7：不在人工态的提交一律拒绝（不建会话）——同样发生在抓 cookie 之前。
    let err =
        invoke_impl("captcha_complete", json!({"siteId": 999})).expect_err("不在人工态应被拒");
    assert_not_acl_rejection("captcha_complete", &err);
    assert!(err.to_string().contains("人工验证"), "{err}");
}

#[test]
fn captcha_cancel_is_idempotent_without_a_window() {
    // T8：取消是幂等的 no-op（这里连窗口都没有）——不得报错、不得炸。
    let value = invoke_impl("captcha_cancel", json!({"siteId": 999})).expect("取消必须幂等");
    assert_not_acl_rejection("captcha_cancel", &value);
}

#[test]
fn delivery_plan_rejects_an_unknown_mode_and_refuses_gateway_mode_without_a_gateway() {
    // 模式认不出 ⇒ 明确拒绝（**不**静默回退成站点模式：那会让用户以为已经切过去了）。
    let err = invoke_impl(
        "delivery_plan",
        json!({"args": {"keyId": 1, "channel": "codex-auth-json", "mode": "gateway2"}}),
    )
    .expect_err("未知模式应被拒");
    assert_not_acl_rejection("delivery_plan", &err);
    assert!(err.to_string().contains("未知的投递模式"), "{err}");

    // 网关模式但网关没在跑 ⇒ 拒绝，而不是写出一个指向空地址的配置。
    let err = invoke_impl(
        "delivery_plan",
        json!({"args": {"keyId": 1, "channel": "codex-auth-json", "mode": "gateway"}}),
    )
    .expect_err("网关没在跑应被拒");
    assert_not_acl_rejection("delivery_plan", &err);
    assert!(err.to_string().contains("没有在运行"), "{err}");

    // 缺省模式（既有调用点的形态）：走到业务路径（key 不存在 ⇒ 业务错误）。
    let err = invoke_impl(
        "delivery_plan",
        json!({"args": {"keyId": 999, "channel": "codex-auth-json"}}),
    )
    .expect_err("不存在的 key 应报错");
    assert_not_acl_rejection("delivery_plan", &err);
    assert!(err.to_string().contains("不存在"), "{err}");
}

#[test]
fn purge_keychain_requires_confirmation_and_reports_counts() {
    let err = invoke_impl("purge_keychain", json!({"confirm": false})).expect_err("未确认应被拒");
    assert_not_acl_rejection("purge_keychain", &err);
    assert!(
        err.to_string().contains("二次确认"),
        "应给出「需要二次确认」而不是别的错误: {err}"
    );

    // 空安装：没有引用 ⇒ 三个计数都是 0，且不是错误。
    // 「没有东西可清」不是失败——把它做成错误会让卸载脚本平白报错。
    let value = invoke_impl("purge_keychain", json!({"confirm": true})).expect("空安装应成功");
    assert_not_acl_rejection("purge_keychain", &value);
    assert_eq!(value["attempted"], 0);
    assert_eq!(value["removed"], 0);
    assert_eq!(value["failed"], 0);
    assert_eq!(value["firstError"], Value::Null);
}

#[test]
fn the_frontend_channel_list_matches_the_backend_channels_exactly() {
    // B-101：前端的 `CHANNELS` 与后端的 `DeliveryChannel::ALL` 是**两份清单**。
    // `check-commands.mjs` 只守护**命令**集合，不覆盖**通道**名——于是新增一条通道时
    // 两边可能不同步，而症状是「界面里选不到那个通道」（不报错，只是少一个选项）。
    //
    // 这里用**扫源码**的方式把两份清单钉在一起：后端是权威（`ALL` 是编译期数组），
    // 前端从 `src/pages/Agents.tsx` 里抽 `id:`。任一边增删而另一边没跟，这条直接红。
    const AGENTS_TSX: &str = include_str!("../../src/pages/Agents.tsx");

    // 只取 `const CHANNELS = [ … ];` 这一段，免得把文件里别的 `id:` 也算进来。
    let start = AGENTS_TSX
        .find("const CHANNELS = [")
        .expect("Agents.tsx 里应当有 CHANNELS 常量");
    let rest = &AGENTS_TSX[start..];
    let end = rest.find("];").expect("CHANNELS 数组应当有结束括号");
    let block = &rest[..end];

    let mut frontend: Vec<String> = Vec::new();
    for line in block.lines() {
        let Some(at) = line.find("id: \"") else {
            continue;
        };
        let tail = &line[at + 5..];
        let Some(close) = tail.find('"') else {
            continue;
        };
        frontend.push(tail[..close].to_string());
    }
    frontend.sort();

    let mut backend: Vec<String> = keyrelay_core::delivery::DeliveryChannel::ALL
        .iter()
        .map(|channel| channel.as_str().to_string())
        .collect();
    backend.sort();

    assert_eq!(
        frontend, backend,
        "前端 CHANNELS 的 id 集合与后端 DeliveryChannel::ALL 的 as_str() 集合不一致。\n\
         后端是权威：新增/删除通道时请同步 src/pages/Agents.tsx 的 CHANNELS。"
    );
}

#[test]
fn gateway_stop_drains_buffered_failures_into_the_event_log() {
    // M7-S5 复审 P2-1：缓冲里的失败原本只在 `refresh_all` 落库，
    // 于是「网关刚报失败、用户随即关掉应用」会让那条失败永远进不了事件表——
    // 而它正是「网关为什么切换了上游」的唯一线索。停止网关是「这次会话结束」的
    // 天然边界，所以在这一步 drain 一次，失败也归给产生它的那次会话。
    let (app, webview) = build_app();
    {
        use tauri::Manager;
        let state = app.state::<keyrelay_lib::AppState>();
        state
            .service
            .record_gateway_failure_for_test(keyrelay_core::gateway::GatewayFailure {
                site_id: 1,
                status: 503,
                model: "gpt-5.6".into(),
            });
    }

    invoke_on(&webview, "gateway_stop", json!({})).expect("停止应成功（没在跑也要幂等）");

    let events = invoke_on(&webview, "recent_events", json!({"limit": 50})).expect("读事件");
    let drained = events
        .as_array()
        .expect("事件是数组")
        .iter()
        .any(|event| event["source"] == "gateway");
    assert!(
        drained,
        "停止网关时应当把缓冲里的失败落库；实际事件：{events}"
    );
}

#[test]
fn site_balance_reports_unknown_without_pretending_it_is_zero() {
    // M7-S5 接线：未知余额必须**结构上**给 null，而不是 0——
    // 界面拿到 0 就会渲染成 `0.00`，而那与「不知道」是两件事。
    // 这里用不存在的站点拿不到余额（业务错误），所以真正的形状断言在
    // `commands.rs` 的 `BalanceDto` 单测里；本测试钉的是「命令已注册且过 ACL」。
    let err = invoke_impl("site_balance", json!({"siteId": 999})).expect_err("不存在的站点应报错");
    assert_not_acl_rejection("site_balance", &err);
}
