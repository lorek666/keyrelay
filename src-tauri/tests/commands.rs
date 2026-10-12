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
    // 跨调用保持状态：同一个应用实例里「写 → 读」
    let (_app, webview) = build_app();
    let updated = invoke_on(
        &webview,
        "update_settings",
        json!({"args": {"settings": {
            "refreshIntervalSecs": 600,
            "balanceAlertThreshold": 3.5,
            "driftCheckOnStart": false,
            "gatewayEnabled": true,
            "gatewayPort": 9999
        }}}),
    )
    .expect("update_settings 应成功");
    assert_eq!(updated["refreshIntervalSecs"], 600);
    assert_eq!(updated["balanceAlertThreshold"], 3.5);
    assert_eq!(updated["driftCheckOnStart"], false);
    assert_eq!(updated["gatewayEnabled"], true);
    assert_eq!(updated["gatewayPort"], 9999);

    let read = invoke_on(&webview, "get_settings", json!({})).expect("get_settings");
    assert_eq!(read, updated, "同一实例内写后读必须一致");

    // 非法值被拒
    let err = invoke_impl(
        "update_settings",
        json!({"args": {"settings": {
            "refreshIntervalSecs": 99999999,
            "balanceAlertThreshold": 0.0,
            "driftCheckOnStart": true,
            "gatewayEnabled": false,
            "gatewayPort": 8787
        }}}),
    )
    .expect_err("超上限的间隔应被拒绝");
    assert_not_acl_rejection("update_settings", &err);
    assert!(
        err.as_str().unwrap_or_default().contains("刷新间隔"),
        "{err}"
    );
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
fn gateway_start_on_an_unknown_key_reports_a_business_error() {
    let err = invoke_impl(
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
