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

fn invoke_impl(cmd: &str, args: Value) -> Result<Value, Value> {
    let app =
        keyrelay_lib::configure_with_state(mock_builder(), keyrelay_lib::init_state_in_memory())
            .build(tauri::generate_context!())
            .expect("构建 mock 应用");

    let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .expect("构建 mock 窗口");

    // 本地源按平台不同：capabilities 的 `local: true` 只覆盖本平台的本地源，用错会被 ACL 拒绝
    let origin = if cfg!(windows) {
        "http://tauri.localhost"
    } else {
        "tauri://localhost"
    };

    get_ipc_response(
        &webview,
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
