//! IPC 级命令测试：用 Tauri 官方 mock runtime **真正走一遍 `invoke` 链路**
//! （命令注册 → ACL 鉴权 → 状态注入 → 参数/返回值序列化），关闭 M0-S1 复审遗留的
//! 「capabilities / invoke 未验证」问题（BACKLOG B-15）。
//!
//! 两个关键点（首次编写时踩到的坑，已由本测试暴露并修复）：
//! 1. 必须用 `tauri::generate_context!()` 构建真实上下文（含 capabilities 解析出的 ACL）。
//!    `mock_context(noop_assets())` 的 ACL 是空的，任何应用命令都会被判
//!    `not allowed. Plugin not found`。
//! 2. 应用自有命令要在 `build.rs` 里用 `AppManifest::commands([...])` 登记，
//!    capabilities 才能引用 `allow-<command>`，否则真实运行时同样会被拒。
//!
//! 说明：mock runtime 仍不等于真实 wry 窗口，M1-S3 首次 `pnpm tauri dev` 联调时需再复核一次。

use serde_json::{json, Value};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{get_ipc_response, mock_builder, INVOKE_KEY};
use tauri::webview::InvokeRequest;

fn invoke(cmd: &str) -> Result<Value, Value> {
    let app =
        keyrelay_lib::configure_with_state(mock_builder(), keyrelay_lib::init_state_in_memory())
            .build(tauri::generate_context!())
            .expect("构建 mock 应用");

    let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .expect("构建 mock 窗口");

    // 本地源按平台不同：macOS/Linux 是 tauri://localhost，Windows 是 http://tauri.localhost。
    // capabilities 的 `local: true` 只覆盖本平台的本地源，用错会被 ACL 拒绝。
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
            body: InvokeBody::default(),
            headers: Default::default(),
            invoke_key: INVOKE_KEY.to_string(),
        },
    )
    .map(|body| body.deserialize::<Value>().expect("反序列化返回值"))
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
