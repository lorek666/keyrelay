//! Continue 模型名在 **IPC 边界**上的接线（独立复审 P2-2）。
//!
//! 核心层的 `continue_model.rs` 只能证明 `*_with_model` 用上了模型名；命令层若把
//! `args.model` 换回 `None`，那边照样全绿，界面上的 Continue 投递却永远报「请填写模型名」
//! ——同一个接线缺口（P-5）原样上移了一层。所以这里从 `invoke` 走一遍：
//! 前端发来的 `model` 必须真的到达预览与投递。

// 与 `commands.rs` 同理：测试与 lib 各展开一次 `generate_context!()`，链接期的重复符号噪音无害。
#![allow(linker_messages)]

use std::fs;
use std::path::PathBuf;

use keyrelay_core::delivery::DeliveryChannel;
use serde_json::{json, Value};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{get_ipc_response, mock_builder, MockRuntime, INVOKE_KEY};
use tauri::webview::InvokeRequest;

const SECRET: &str = "sk-ipc-model-0123456789abcdef";
const MODEL: &str = "gpt-4o";

/// 建应用前先在内存状态里种一个站点和一把 key（内存钥匙串，不碰用户真实钥匙串）。
fn build_app_with_key() -> (
    tauri::App<MockRuntime>,
    tauri::WebviewWindow<MockRuntime>,
    i64,
    PathBuf,
) {
    let state = keyrelay_lib::init_state_in_memory();
    let site_id = state
        .service
        .store()
        .upsert_site("newapi", "https://relay.example.com", "测试站")
        .expect("建站");
    let key = state
        .service
        .store_key_material(site_id, "ipc/continue", Some("1"), None, SECRET)
        .expect("存 key");
    let home = state.service.home().to_path_buf();
    let app = keyrelay_lib::configure_with_state(mock_builder(), state)
        .build(tauri::generate_context!())
        .expect("构建 mock 应用");
    // 窗口标签必须是 `main`：capabilities 只授权给它
    let webview = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .expect("构建 mock 窗口");
    (app, webview, key.id, home)
}

fn invoke_on(
    webview: &tauri::WebviewWindow<MockRuntime>,
    cmd: &str,
    args: Value,
) -> Result<Value, Value> {
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

#[test]
fn continue_model_reaches_preview_and_delivery_through_ipc() {
    let (_app, webview, key_id, home) = build_app_with_key();
    let target = home.join(DeliveryChannel::Continue.relative_target());
    let _ = fs::remove_file(&target);

    let without_model = json!({"args": {"keyId": key_id, "channel": "continue"}});
    let with_model = json!({"args": {"keyId": key_id, "channel": "continue", "model": MODEL}});
    invoke_on(&webview, "grant_consent", without_model.clone()).expect("授予同意");

    // 对照组：不带模型名必须被拒——证明下面的成功确实来自 `model` 字段
    let err = invoke_on(&webview, "delivery_plan", without_model).expect_err("缺模型名应拒绝");
    assert!(err.as_str().unwrap_or_default().contains("模型名"), "{err}");

    let plan = invoke_on(&webview, "delivery_plan", with_model.clone()).expect("预览应成功");
    let preview = plan["preview"].as_str().unwrap_or_default();
    assert!(preview.contains("model: \"gpt-4o\""), "{plan}");
    assert!(!preview.contains(SECRET), "预览不得含明文");

    invoke_on(&webview, "apply_delivery", with_model).expect("投递应成功");
    let written = fs::read_to_string(&target).expect("投递后目标文件应存在");
    assert!(written.contains("    model: \"gpt-4o\"\n"), "{written}");

    // 内存状态的 home 是本进程独占的临时目录，测完清掉
    let _ = fs::remove_dir_all(&home);
}
