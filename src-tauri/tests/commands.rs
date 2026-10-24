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
use tauri::Manager;

/// 建一个应用实例，并把 `main` 窗口也建好。
///
/// 窗口标签必须是 `main`：`capabilities/default.json` 的 `windows` 只列了它，
/// 换个标签会拿不到权限（ACL 会拒），测试就变成「验证 ACL」而不是「验证业务」。
fn build_app() -> (
    tauri::App<tauri::test::MockRuntime>,
    tauri::WebviewWindow<tauri::test::MockRuntime>,
) {
    let app = tianshu_relay_lib::configure_with_state(
        mock_builder(),
        tianshu_relay_lib::init_state_in_memory(),
    )
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

    // M35-S1：产品名（中文）与新增的 dataDir / rebrand
    assert_eq!(value["name"], "天枢 Relay");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(value["siteCount"], 0);
    assert_eq!(value["dbPath"], ":memory:");
    assert!(value["dbError"].is_null(), "内存库不应带降级原因: {value}");
    // 内存态：dataDir 是临时目录（存在），迁移状态 noLegacy
    assert!(
        value["dataDir"].as_str().is_some_and(|d| !d.is_empty()),
        "dataDir 必须非空: {value}"
    );
    assert_eq!(value["rebrand"]["status"], "noLegacy", "{value}");
    assert!(value["rebrand"]["to"].as_str().is_some(), "{value}");
    assert!(value["rebrand"]["warnings"].is_array(), "{value}");
}

#[test]
fn detect_system_proxy_returns_shape_without_acl_rejection() {
    // M10-S2：命令必须可达（被 ACL 拒绝时 `invoke` 返回 Err，这里 expect 就会失败），
    // 且返回 {source, maskedUrl} 两个键。不断言具体值——本机是否配了系统代理不确定，
    // source/maskedUrl 各自 Some 或 null 都合法。
    let value = invoke("detect_system_proxy").expect("detect_system_proxy 应可达");
    assert!(value.get("source").is_some(), "应含 source 键: {value}");
    assert!(
        value.get("maskedUrl").is_some(),
        "应含 maskedUrl 键: {value}"
    );
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
    for cmd in tianshu_relay_lib::commands_list::COMMANDS {
        if let Err(err) = invoke(cmd) {
            assert_not_acl_rejection(cmd, &err);
        }
    }
}

#[test]
fn capabilities_reference_every_declared_command() {
    let capabilities = include_str!("../capabilities/default.json");
    for cmd in tianshu_relay_lib::commands_list::COMMANDS {
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

// ---------- M10-S2：站点适配器 transport 的代理接线 ----------

/// `resolved_proxy_url` 是壳层构造站点 transport 时的代理解析入口（M10-S2）。
/// 它读 settings → resolve_proxy → 返回最终代理 URL。
/// 证伪：删掉 lib.rs 里对 `resolved_proxy_url(&store)` 的调用、或让它忽略 proxy_mode
/// ⇒ manual 断言红。
#[test]
fn resolved_proxy_url_reads_settings_mode_and_url() {
    use tianshu_relay_core::store::Store;
    use tianshu_relay_lib::resolved_proxy_url;

    let store = Store::open_in_memory().expect("内存库");

    // manual + 合法 url ⇒ Some(url)
    store.set_setting("proxy_mode", "manual").unwrap();
    store
        .set_setting("proxy_url", "socks5://127.0.0.1:1080")
        .unwrap();
    assert_eq!(
        resolved_proxy_url(&store).as_deref(),
        Some("socks5://127.0.0.1:1080"),
        "manual + 合法 url ⇒ 返回该 url"
    );

    // direct ⇒ None（即便 proxy_url 还留着）
    store.set_setting("proxy_mode", "direct").unwrap();
    assert_eq!(
        resolved_proxy_url(&store),
        None,
        "direct 模式 ⇒ None，哪怕 proxy_url 非空"
    );

    // manual + 空 url ⇒ None（不让空配置把 app 搞崩）
    store.set_setting("proxy_mode", "manual").unwrap();
    store.set_setting("proxy_url", "").unwrap();
    assert_eq!(
        resolved_proxy_url(&store),
        None,
        "manual + 空 url ⇒ None（等价直连）"
    );

    // manual + 非法 url ⇒ None（不静默直连也不崩，告警后直连；行为见 lib.rs）
    store.set_setting("proxy_mode", "manual").unwrap();
    store
        .set_setting("proxy_url", "file:///etc/passwd")
        .unwrap();
    assert_eq!(
        resolved_proxy_url(&store),
        None,
        "manual + 非法 url ⇒ None（告警并直连，不退出）"
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

    let result = invoke_on(
        &webview,
        "update_settings",
        json!({"args": {"settings": payload}}),
    )
    .expect("update_settings 应成功");
    // M41-S1：返回形状变成 `{settings, gateway, gatewayError}`——设置的断言看 `settings`。
    assert!(
        result["gatewayError"].is_null(),
        "本次没有网关动作: {result}"
    );
    assert_eq!(result["gateway"]["phase"], "stopped", "{result}");
    let updated = result["settings"].clone();
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

/// M40-S2 / D1 + D2（stopped 分支）：新字段在 camelCase 下逐键存在，
/// 且未运行时是**结构性空值**（不是编造的数字）。
#[test]
fn gateway_status_carries_m40s2_metrics_fields_in_camel_case() {
    let value = invoke("gateway_status").expect("gateway_status 应成功");
    for key in [
        "mode",
        "candidates",
        "qps",
        "requestsTotal",
        "inflight",
        "failoversTotal",
        "lastError",
        "generation",
    ] {
        assert!(value.get(key).is_some(), "缺字段 {key}: {value}");
    }
    assert!(
        value.get("requests_total").is_none(),
        "线上键必须是 camelCase：{value}"
    );
    assert_eq!(value["mode"], "stopped");
    assert_eq!(value["candidates"], json!([]));
    assert_eq!(value["requestsTotal"], 0);
    assert_eq!(value["inflight"], 0);
    assert_eq!(value["failoversTotal"], 0);
    assert_eq!(value["lastError"], Value::Null);
    assert_eq!(value["generation"], 0);
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
    assert!(text.contains("tianshu-relay-export-v1"), "{text}");
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
    // M16-S6a / P3-18：`path` 已收敛到「服务 home 下的 .tianshu-relay/exports + 文件名白名单」，
    // 任意路径（含临时目录）会被拒。这里用**允许目录内的合法文件名**，顺带钉住收敛本身。
    let state = {
        use tauri::Manager;
        webview.app_handle().state::<tianshu_relay_lib::AppState>()
    };
    // M35-S1：导出目录跟着**本次解析出的数据目录**走，不再按 home 硬拼新目录名
    let exports = state.data_dir.join("exports");
    std::fs::create_dir_all(&exports).expect("建导出目录");
    let path = exports.join("tianshu-relay-diagnostics-test.json");

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
    // M16-S6a：断言恢复**紧口径 +1**。
    //
    // 收敛之后导出物落在被扫描目录内，曾出现「同一文件计两次」（`filesScanned` 0 → 2）——
    // 根因在 `audit::merge_export_registry` 按**字符串**去重（目录 vs 文件永不相等）。
    // 根因已修（改按规范化真实路径 + 目录前缀覆盖判定），所以这里没有理由留着宽松断言：
    // 一个文件必须**恰好**让覆盖面 +1，多了就是注水（审计报告里唯一的覆盖面证据）。
    assert_eq!(
        after["filesScanned"].as_u64().unwrap_or(0),
        before["filesScanned"].as_u64().unwrap_or(0) + 1,
        "登记的意义是进扫描集合：文件数必须恰好 +1（多计=注水，少计=登记失败）: before={before} after={after}"
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
    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();
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
    let _serial = gateway_test_guard();
    use tauri::Manager;

    let (_app, webview) = build_app();
    // 拿一个空闲端口：绑 0 再放掉。窗口期内被抢的概率极低，
    // 而且真被抢了会明确报「端口被占用」，不会假绿。
    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("探端口");
        probe.local_addr().expect("读端口").port()
    };

    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();
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
    let _serial = gateway_test_guard();
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

    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();
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
    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();
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
    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();
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

#[test]
fn gateway_rotate_token_refuses_mismatched_key_and_keeps_gateway_running() {
    let _serial = gateway_test_guard();
    // P1-6 完整修复：网关在跑时，rotate 用运行态记录的 site_id/key_id，不用命令参数。
    // 切页后 args 带错的密钥 ⇒ 一致性校验拒绝，且网关不被停（令牌没换、继续跑）。
    use tauri::Manager;

    let (_app, webview) = build_app();
    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("探端口");
        probe.local_addr().expect("读端口").port()
    };

    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();
    let site = state
        .service
        .store()
        .upsert_site("newapi", "https://relay.example.com", "P1-6 站")
        .expect("写站点");
    let key_a = state
        .service
        .store_key_material(
            site,
            "codex/daily",
            Some("12"),
            None,
            None,
            "sk-a-0123456789abcdef",
        )
        .expect("写密钥 A")
        .id;
    let key_b = state
        .service
        .store_key_material(
            site,
            "codex/night",
            Some("13"),
            None,
            None,
            "sk-b-0123456789abcdef",
        )
        .expect("写密钥 B")
        .id;
    assert_ne!(key_a, key_b, "两把密钥必须不同");

    enable_gateway(&webview, port);

    // 用密钥 A 启动。
    let started = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key_a}}),
    )
    .expect("启动");
    assert_eq!(started["running"], true, "{started}");

    // P1-6 核心：rotate 传密钥 B（与启动时的 A 不一致）⇒ 拒绝。
    let err = invoke_on(
        &webview,
        "gateway_rotate_token",
        json!({"args": {"siteId": site, "keyId": key_b}}),
    )
    .expect_err("不一致的密钥必须被拒");
    assert_not_acl_rejection("gateway_rotate_token", &err);
    assert!(
        err.to_string().contains("不切换站点"),
        "应说明不切换站点/密钥: {err}"
    );

    // 拒绝后网关仍在跑（没被停、令牌没换）。
    let status = invoke_on(&webview, "gateway_status", json!({})).expect("查状态");
    assert_eq!(status["running"], true, "拒绝后网关应仍在跑: {status}");

    // 用一致的密钥 A rotate ⇒ 成功。
    let rotated = invoke_on(
        &webview,
        "gateway_rotate_token",
        json!({"args": {"siteId": site, "keyId": key_a}}),
    )
    .expect("一致的密钥应成功");
    assert_eq!(rotated["running"], true, "{rotated}");

    invoke_on(&webview, "gateway_stop", json!({})).expect("收尾停止");
}

#[test]
fn gateway_rotate_token_restarts_the_running_gateway_with_the_new_token() {
    let _serial = gateway_test_guard();
    // P2-7 / DEBUG-REPORT-v3 §2-7：rotate 之后运行中的网关要用**新令牌**。旧实现在
    // rotate 之前构造 config，start 用旧令牌，网关仍认旧令牌 ⇒ 指向网关的 agent
    //（新令牌）401/502，直到手动重启。现在 rotate 后重新构造 config。
    use tauri::Manager;

    let (_app, webview) = build_app();
    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("探端口");
        probe.local_addr().expect("读端口").port()
    };
    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();
    let site = state
        .service
        .store()
        .upsert_site("newapi", "https://relay.example.com", "P2-7 站")
        .expect("写站点");
    let key = state
        .service
        .store_key_material(
            site,
            "codex/daily",
            Some("12"),
            None,
            None,
            "sk-a-0123456789abcdef",
        )
        .expect("写密钥")
        .id;
    enable_gateway(&webview, port);

    let started = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key}}),
    )
    .expect("启动");
    let token_before = started["token"]
        .as_str()
        .expect("启动返回 token")
        .to_string();

    let rotated = invoke_on(
        &webview,
        "gateway_rotate_token",
        json!({"args": {"siteId": site, "keyId": key}}),
    )
    .expect("rotate 成功");
    let token_after = rotated["token"]
        .as_str()
        .expect("rotate 返回新 token")
        .to_string();

    assert_ne!(
        token_before, token_after,
        "rotate 后运行中网关的令牌必须换掉（P2-7：start 要用新令牌，不是 rotate 之前那份旧 config）"
    );

    invoke_on(&webview, "gateway_stop", json!({})).expect("收尾停止");
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

    let mut backend: Vec<String> = tianshu_relay_core::delivery::DeliveryChannel::ALL
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
        let state = app.state::<tianshu_relay_lib::AppState>();
        state.service.record_gateway_failure_for_test(
            tianshu_relay_core::gateway::GatewayFailure {
                site_id: 1,
                status: 503,
                model: "gpt-5.6".into(),
                reason: "上游返回可切换状态码 HTTP 503".into(),
            },
        );
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

/// M8-S7 / B-116：命令层的「未解绑过滤」必须真的在命令里。
///
/// 为什么必须在 IPC 层测：过滤那行在 `commands.rs` 里（`.filter(|row| row.unbound_at.is_none())`），
/// core 测试拿不到 `State`。删掉那一行**没有任何东西会红**——core 侧那两条测试自己写了
/// 一份同样的过滤，跑的是 `store.all_bindings()`，跟命令层无关（独立复审 P2-2）。
/// 前端于是会把已解绑的绑定当候选列出来，用户对一个早就解绑的文件白写一次。
#[test]
fn list_channel_bindings_filters_out_unbound_rows() {
    use tauri::Manager;

    let (_app, webview) = build_app();
    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();

    let site = state
        .service
        .store()
        .upsert_site("newapi", "https://relay.example.com", "批量测试站")
        .expect("写站点");
    let live = state
        .service
        .store_key_material(
            site,
            "codex/live",
            Some("1"),
            None,
            None,
            "sk-live-0123456789abcdef",
        )
        .expect("写密钥")
        .id;
    let dead = state
        .service
        .store_key_material(
            site,
            "codex/dead",
            Some("2"),
            None,
            None,
            "sk-dead-0123456789abcdef",
        )
        .expect("写密钥")
        .id;

    state
        .service
        .store()
        .record_binding("codex", live, "/home/u/.codex/auth.json", "j1", "site")
        .expect("写绑定");
    state
        .service
        .store()
        .record_binding(
            "claude-code",
            dead,
            "/home/u/.claude/settings.json",
            "j2",
            "site",
        )
        .expect("写绑定");
    state
        .service
        .store()
        .unbind_agent("claude-code")
        .expect("解绑 claude-code");

    let value = invoke_on(&webview, "list_channel_bindings", json!({}))
        .expect("list_channel_bindings 应成功");
    assert_not_acl_rejection("list_channel_bindings", &value);

    let rows = value.as_array().expect("应返回数组");
    assert_eq!(rows.len(), 1, "已解绑的绑定不得出现在候选里: {rows:?}");
    assert_eq!(
        rows[0]["bindingId"], 1,
        "绑定行 id 要带回（前端用它做 key）"
    );
    assert_eq!(rows[0]["agentId"], "codex");
    assert_eq!(rows[0]["keyId"], live);
    assert_eq!(rows[0]["targetPath"], "/home/u/.codex/auth.json");
    assert_eq!(rows[0]["siteId"], site);

    // 同一文件上的第二条未解绑绑定必须**各自独立成行**（M8-S7 P2-4）：
    // `bindings` 没有 UNIQUE 约束，「换 key 后重投」会留下两条。前一个版本用
    // `${channel}::${targetPath}` 做 key，那两条会共用同一个复选框。
    state
        .service
        .store()
        .record_binding("codex", dead, "/home/u/.codex/auth.json", "j3", "site")
        .expect("写第二条同目标绑定");
    let again = invoke_on(&webview, "list_channel_bindings", json!({})).expect("再查一次应成功");
    let rows = again.as_array().expect("应返回数组");
    assert_eq!(rows.len(), 2, "同一文件上的两条未解绑绑定都要列出");
    let ids: Vec<i64> = rows
        .iter()
        .map(|r| r["bindingId"].as_i64().expect("bindingId 是数字"))
        .collect();
    assert_eq!(
        ids,
        vec![1, 3],
        "两行的 bindingId 必须不同（否则前端 key 会撞）"
    );
    assert_ne!(
        rows[0]["keyId"], rows[1]["keyId"],
        "两条绑定用的是不同的 key（这正是要能让用户分别处理的原因）"
    );
}

/// M9-S4：「变更历史」页的回滚入口。字段名是前端 `DeliveryRecord` 的契约（camelCase），
/// `limit` 必须真的生效（历史页只要最近 N 次，不能把整张表搬过来）。
#[test]
fn list_deliveries_returns_newest_first_with_camel_case_fields() {
    use tauri::Manager;

    let (_app, webview) = build_app();
    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();

    // 先占掉站点 id 1：否则全新内存库里 site = key = 1，`siteId` 与 `keyId` 互换也照样通过（复审 P2-3）
    state
        .service
        .store()
        .upsert_site("newapi", "https://placeholder.example.com", "占位站")
        .expect("写占位站点");
    let site = state
        .service
        .store()
        .upsert_site("newapi", "https://relay.example.com", "历史测试站")
        .expect("写站点");
    let key = state
        .service
        .store_key_material(
            site,
            "codex/a",
            Some("1"),
            None,
            None,
            "sk-hist-0123456789abcdef",
        )
        .expect("写密钥")
        .id;
    assert_ne!(
        site, key,
        "站点 id 与密钥 id 必须不同，否则 siteId 没被钉住"
    );
    let store = state.service.store();
    store
        .record_binding("codex", key, "/home/u/.codex/auth.json", "j1", "site")
        .expect("写绑定");
    store
        .record_binding("codex", key, "/home/u/.codex/auth.json", "j2", "site")
        .expect("写绑定");
    store
        .record_binding("shell", key, "/home/u/.zshrc", "j3", "site")
        .expect("写绑定");

    let value = invoke_on(&webview, "list_deliveries", json!({"limit": 2}))
        .expect("list_deliveries 应成功");
    assert_not_acl_rejection("list_deliveries", &value);
    let rows = value.as_array().expect("应返回数组");
    assert_eq!(rows.len(), 2, "limit 必须生效: {rows:?}");
    assert_eq!(rows[0]["journalId"], "j3", "最新的在前");
    assert_eq!(rows[1]["journalId"], "j2");
    assert_eq!(rows[1]["bindingId"], 2);
    assert_eq!(rows[1]["agentId"], "codex");
    assert_eq!(rows[1]["keyId"], key);
    assert_eq!(rows[1]["siteId"], site);
    assert_eq!(rows[1]["targetPath"], "/home/u/.codex/auth.json");
    assert!(rows[1]["appliedAt"].is_i64());
    assert!(rows[1]["unboundAt"].is_null());
    assert!(rows[1]["backupPath"].is_null());
    assert_eq!(rows[1]["hasJournal"], false, "直接写的绑定没有 journal 行");
    assert_eq!(rows[1]["rolledBack"], false);
    assert_eq!(rows[1]["superseded"], false, "j2 是这个文件上最新的一次");

    let all = invoke_on(&webview, "list_deliveries", json!({})).expect("无参应成功");
    let rows = all.as_array().expect("应返回数组");
    assert_eq!(rows.len(), 3, "缺省 limit 要装得下");
    assert_eq!(rows[2]["journalId"], "j1");
    assert_eq!(rows[2]["superseded"], true, "j1 被同一文件上的 j2 覆盖");
    assert!(
        !all.to_string().contains("sk-"),
        "投递历史不得携带密钥: {all}"
    );
}

// ============================================ M16-S6a：report_ui_ready（界面就绪上报）

/// `report_ui_ready` 必须真的把时间戳写进 `settings` 表（M16-S6a 追加项）。
///
/// 这条命令存在的理由：GUI 真机走查（M16-S7）在 macOS 上**看不到** WebView 内部的 AX 节点，
/// 截图也不稳定 ⇒ 自动化没有判据判断「界面真的起来了」。有了 `ui_ready_at`：
/// ① 走查脚本能轮询它得到真正的端到端冷启动时间；
/// ② B-15「invoke 真实往返」从「AX 看不到 ⇒ 不可证」变成「这个值有 ⇒ 前端确实调通过一次 IPC」。
///
/// 断言三件事：IPC 往返成功、值落在 `settings` 表里、是**数字字符串**（毫秒）。
/// 另外钉一条「不是启动时自动写的」：调用之前该键**必须不存在**。
#[test]
fn report_ui_ready_writes_a_millisecond_timestamp_setting() {
    use tauri::Manager;

    let (_app, webview) = build_app();
    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();
    let store = state.service.store();

    // ① 调用之前不存在：这条命令的价值在于「前端显式调过」，自动写等于没证
    assert_eq!(
        store.get_setting("ui_ready_at").expect("读设置"),
        None,
        "启动时不得自动写 ui_ready_at（那样证不到前端往返）"
    );

    invoke_on(&webview, "report_ui_ready", json!({})).expect("report_ui_ready 应成功");

    // ② 值存在且是数字字符串
    let raw = store
        .get_setting("ui_ready_at")
        .expect("读设置")
        .expect("调用之后必须有 ui_ready_at");
    let ms: i64 = raw
        .parse()
        .unwrap_or_else(|_| panic!("必须是数字字符串: {raw}"));
    assert!(ms > 1_600_000_000_000, "看起来不是 unix 毫秒: {ms}");

    // ③ 幂等：再调一次只覆盖，不报错
    invoke_on(&webview, "report_ui_ready", json!({})).expect("重复调用应成功");
    let again = store
        .get_setting("ui_ready_at")
        .expect("读设置")
        .expect("值仍在");
    let ms2: i64 = again.parse().expect("仍是数字字符串");
    assert!(ms2 >= ms, "重复调用应覆盖成更新的时间戳: {ms} -> {ms2}");
}

// ---------- M34-S1：Agent 更新检查与白名单一键更新 ----------

/// `check_agent_updates` 可达、返回 20 条、顺序与 `agents::specs()` 一致。
///
/// 会真的联网（每个源 8s 超时）；**失败也必须是「20 条 + 逐条 state」而不是整体 Err**，
/// 这条测试同时钉住「单个源失败不影响整体」的契约形状。
#[test]
fn check_agent_updates_returns_twenty_rows_in_specs_order() {
    let value = invoke("check_agent_updates").expect("check_agent_updates 应成功");
    let rows = value.as_array().expect("返回值必须是数组");
    assert_eq!(rows.len(), 20, "检查结果必须是 20 条");

    let channels: Vec<&str> = rows
        .iter()
        .map(|row| row["channel"].as_str().expect("channel 必须是字符串"))
        .collect();
    let expected: Vec<&str> = tianshu_relay_core::agents::specs()
        .iter()
        .map(|spec| spec.channel)
        .collect();
    assert_eq!(channels, expected, "顺序必须与 agents::specs() 逐位一致");

    for row in rows {
        // 序列化契约：camelCase 键存在（Rust 侧字段是 snake_case）
        assert!(
            row.get("currentVersion").is_some(),
            "缺少 camelCase 键 currentVersion: {row}"
        );
        assert!(row.get("latestVersion").is_some());
        assert!(row.get("autoUpdate").is_some());
        assert!(row.get("manualUrl").is_some());
        let state = row["state"].as_str().expect("state 必须是字符串");
        assert!(
            matches!(
                state,
                "available" | "upToDate" | "unknown" | "unsupported" | "error" | "notInstalled"
            ),
            "state 不合法: {state}"
        );
        let source = row["source"].as_str().expect("source 必须是字符串");
        assert!(
            matches!(source, "npm" | "brewCask" | "marketplace" | "none"),
            "source 不合法: {source}"
        );
    }
}

#[test]
fn update_agent_on_unknown_channel_reports_business_error() {
    let err = invoke_impl("update_agent", json!({ "channel": "no-such-channel" }))
        .expect_err("未知通道必须报错");
    assert_not_acl_rejection("update_agent", &err);
    let message = err.to_string();
    assert!(
        message.contains("未知的投递通道"),
        "错误信息应说明是未知通道: {message}"
    );
}

#[test]
fn update_agent_on_unsupported_channel_reports_business_error() {
    // grok-build 没有更新源/策略；dsh 有源但无策略（只能手动）。
    for channel in ["grok-build", "dsh"] {
        let err = invoke_impl("update_agent", json!({ "channel": channel }))
            .expect_err("不支持一键更新的通道必须报错");
        assert_not_acl_rejection("update_agent", &err);
        let message = err.to_string();
        assert!(
            message.contains("不支持一键更新"),
            "{channel} 的拒绝文案不对: {message}"
        );
    }
}

// ---------- M40-S1：gateway_stop 必须先 flush 用量 ----------

/// 停止网关时，缓冲里的用量必须**当场落库**（不能等到下一次 `refresh_all`）。
///
/// 用测试注入点模拟「网关已经产生了用量、但还没 drain」的状态；`gateway_stop` 在
/// 没有运行中的网关时也会走 drain（空跑 stop + drain），所以这条用例同时钉住了
/// 「drain 在 end_gateway_session 之前」的顺序（会话作废后 sink 会拒收，但缓冲里
/// 已有的记录仍然能被 drain 收走）。
#[test]
fn gateway_stop_flushes_buffered_usage() {
    let (app, webview) = build_app();
    let state = app.state::<tianshu_relay_lib::AppState>();
    let site_id = state
        .service
        .store()
        .upsert_site("newapi", "https://m40.example.test", "M40 测试站")
        .expect("建站点");

    state
        .service
        .push_gateway_usage_for_test(tianshu_relay_core::gateway::GatewayUsage {
            token_id: None,
            agent_label: String::new(),
            at: 1_700_000_000,
            site_id,
            key_id: Some(7),
            model: "m40".to_string(),
            prompt_tokens: 1,
            completion_tokens: 2,
            total_tokens: 3,
            status: 200,
            latency_ms: 5,
            attempts: 1,
            stream: false,
        });
    assert!(
        state
            .service
            .store()
            .recent_gateway_usage(24 * 365 * 100)
            .expect("查询")
            .is_empty(),
        "前置：尚未 drain 时库里应为空"
    );

    let status = invoke_on(&webview, "gateway_stop", json!({})).expect("gateway_stop");
    assert_eq!(status["running"], false);

    let rows = state
        .service
        .store()
        .recent_gateway_usage(24 * 365 * 100)
        .expect("查询");
    assert_eq!(rows.len(), 1, "gateway_stop 必须把缓冲里的用量落库");
    assert_eq!(rows[0].total_tokens, 3);
}

// ============================================================ M41-S1：设置同步与 supervisor

/// 建「站点 + 启用密钥」（网关只需要配置完整，不要求站点健康）。
fn seed_gateway_site(webview: &tauri::WebviewWindow<tauri::test::MockRuntime>) -> (i64, i64) {
    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();
    let site = state
        .service
        .store()
        .upsert_site("newapi", "https://relay.example.com", "M41 网关站")
        .expect("写站点");
    let key_id = state
        .service
        .store_key_material(
            site,
            "codex/daily",
            Some("12"),
            None,
            None,
            "sk-m41s1-0123456789abcdef",
        )
        .expect("写密钥")
        .id;
    (site, key_id)
}

fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("探端口");
    probe.local_addr().expect("读端口").port()
}

/// 串行化**真正绑定监听端口**的网关测试。
///
/// `free_port()` 是「绑 0 → 读端口 → 放掉」：两个并发测试可能先后拿到同一个端口，
/// 后启动的那个会把前一个的 `!connect_ok()` 断言打红（M41-S1 合入主仓后实测到一次）。
/// 这里用进程内互斥把窗口关掉；不改变生产代码，也不影响其余不碰端口的测试。
fn gateway_test_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn connect_ok(port: u16) -> bool {
    std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
}

fn read_settings(webview: &tauri::WebviewWindow<tauri::test::MockRuntime>) -> Value {
    invoke_on(webview, "get_settings", json!({})).expect("读设置")
}

/// M41-S1 §7.2-1：关 `gateway_enabled` ⇒ **返回后端口不再监听** + `phase == "stopped"`。
#[test]
fn update_settings_disabling_the_gateway_stops_the_port() {
    let _serial = gateway_test_guard();
    let (_app, webview) = build_app();
    let (site, key_id) = seed_gateway_site(&webview);
    let port = free_port();
    enable_gateway(&webview, port);

    let started = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key_id}}),
    )
    .expect("启动网关");
    assert_eq!(started["phase"], "running", "{started}");
    assert!(connect_ok(port), "启动后端口 {port} 应可连接");

    let mut payload = read_settings(&webview);
    payload["gatewayEnabled"] = json!(false);
    let result = invoke_on(
        &webview,
        "update_settings",
        json!({"args": {"settings": payload}}),
    )
    .expect("保存设置");

    assert_eq!(result["gateway"]["phase"], "stopped", "{result}");
    assert_eq!(result["gateway"]["running"], false, "{result}");
    assert!(result["gatewayError"].is_null(), "关开关不该报错: {result}");
    assert!(!connect_ok(port), "关开关返回后端口 {port} 必须不再监听");

    let status = invoke_on(&webview, "gateway_status", json!({})).expect("读状态");
    assert_eq!(status["phase"], "stopped", "{status}");
    assert_eq!(status["running"], false, "{status}");
}

/// M41-S1 §7.2-2：运行中改端口 ⇒ 旧端口关、新端口开，且站点/密钥仍是**运行态**那一组。
#[test]
fn update_settings_port_change_restarts_on_the_new_port() {
    let _serial = gateway_test_guard();
    let (_app, webview) = build_app();
    let (site, key_id) = seed_gateway_site(&webview);
    let old_port = free_port();
    let new_port = free_port();
    enable_gateway(&webview, old_port);

    let started = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key_id}}),
    )
    .expect("启动网关");
    assert_eq!(started["phase"], "running", "{started}");
    assert!(connect_ok(old_port), "旧端口应可连接");

    let mut payload = read_settings(&webview);
    payload["gatewayPort"] = json!(new_port);
    let result = invoke_on(
        &webview,
        "update_settings",
        json!({"args": {"settings": payload}}),
    )
    .expect("保存设置");

    assert!(result["gatewayError"].is_null(), "重启应成功: {result}");
    assert_eq!(result["gateway"]["phase"], "running", "{result}");
    assert_eq!(
        result["gateway"]["url"],
        format!("http://127.0.0.1:{new_port}"),
        "网关应落在新端口: {result}"
    );
    assert_eq!(
        result["gateway"]["site"], "M41 网关站",
        "站点应保持运行态那一组"
    );
    assert!(!connect_ok(old_port), "旧端口 {old_port} 必须已关闭");
    assert!(connect_ok(new_port), "新端口 {new_port} 应可连接");

    // 设置里也已经是新端口（重启用的是新设置）
    let saved = read_settings(&webview);
    assert_eq!(saved["gatewayPort"], json!(new_port), "{saved}");
}

/// M41-S1 §7.2-3：restart 失败（新端口被占）⇒ `Ok` + `gatewayError` + `phase=="stopped"`
/// 且**设置已保存**（不允许「保存成功但网关静默死掉」）。
#[test]
fn update_settings_restart_failure_reports_error_and_keeps_settings() {
    let _serial = gateway_test_guard();
    let (_app, webview) = build_app();
    let (site, key_id) = seed_gateway_site(&webview);
    let old_port = free_port();
    let busy_port = free_port();
    enable_gateway(&webview, old_port);

    let started = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key_id}}),
    )
    .expect("启动网关");
    assert_eq!(started["phase"], "running", "{started}");

    // 占住新端口：网关 bind 会失败（AddrInUse）。
    let squatter = std::net::TcpListener::bind(("127.0.0.1", busy_port)).expect("占端口");

    let mut payload = read_settings(&webview);
    payload["gatewayPort"] = json!(busy_port);
    let result = invoke_on(
        &webview,
        "update_settings",
        json!({"args": {"settings": payload}}),
    )
    .expect("保存设置（restart 失败也应返回 Ok）");

    assert_eq!(result["gateway"]["phase"], "stopped", "{result}");
    assert_eq!(result["gateway"]["running"], false, "{result}");
    let message = result["gatewayError"]
        .as_str()
        .unwrap_or_else(|| panic!("必须有可读的 gatewayError: {result}"));
    assert!(
        message.contains("设置已保存"),
        "文案必须说明设置已保存: {message}"
    );
    assert!(
        message.contains("网关未能"),
        "文案必须说明网关没重启: {message}"
    );
    // 设置确实保存了（新端口可读回）
    let saved = read_settings(&webview);
    assert_eq!(saved["gatewayPort"], json!(busy_port), "{saved}");
    assert!(!connect_ok(old_port), "旧网关应已停止");
    drop(squatter);
}

/// M41-S1 §7.2-4：`gateway_status` 不能把已死的任务报成 running。
///
/// **为什么没有「crashed 端到端」用例**：mock runtime 下没有让网关任务「死掉但句柄还在」
/// 的公共路径——`GatewayHandle` 只能由 `start()` 产出，而 `shutdown()` / `shutdown_and_wait()`
/// 都会**消费**句柄；IPC 也没有「杀掉网关」的命令。因此「句柄在、任务已死」这一状态
/// 在测试里构造不出来，`crashed` 的判据由两处共同保证：
/// ① core 的 `alive_and_last_exit_track_the_task_lifecycle`（真网关 stop 后 alive=false +
///    `last_exit.reason == Requested`）；
/// ② `gateway_status_of` 的实现（`alive()` 为假 ⇒ 绝不报 running）。
/// 这里钉住的是「正常停止之后**不会**报 running，也不会谎报 crashed」。
///
/// **同理没有「任务真 panic ⇒ `last_exit.reason == Panicked`」用例**（B-224 长尾核查结论）：
/// panic 接线在 core 侧是唯一的调用点——v4 主任务 `served.is_err()`（JoinHandle 的
/// panic/cancel 信号）→ `classify_gateway_exit` → 写 `exit` 槽；`classify` 本身的四格
/// 已由 `classify_gateway_exit_covers_all_four_cells` 全覆盖。但 serve 任务本身无法从外部
/// 弄 panic：handler panic 只杀当条连接任务，serve 任务继续；也没有注入自定义 app 的
/// 公共路径。因此 panic 腿由「四格纯函数 + 唯一调用点 + ①② 的生命周期测试」共同保证，
/// 不造一个测不到该路径的假用例。
#[test]
fn gateway_status_never_reports_a_stopped_gateway_as_running() {
    let _serial = gateway_test_guard();
    let (_app, webview) = build_app();
    let (site, key_id) = seed_gateway_site(&webview);
    let port = free_port();
    enable_gateway(&webview, port);

    invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key_id}}),
    )
    .expect("启动网关");
    let stopped = invoke_on(&webview, "gateway_stop", json!({})).expect("停止网关");
    assert_eq!(stopped["phase"], "stopped", "{stopped}");
    assert_eq!(stopped["running"], false, "{stopped}");

    let status = invoke_on(&webview, "gateway_status", json!({})).expect("读状态");
    assert_eq!(status["running"], false, "{status}");
    assert_eq!(status["phase"], "stopped", "{status}");
    // 正常停止后句柄已被 take，没有结束记录可报 ⇒ 不应出现 crashed。
    assert!(status["lastExit"].is_null(), "{status}");
    // 端口释放是异步任务收尾的最后一刻（mock runtime 下可能比命令返回晚几毫秒）：
    // 用有界轮询而不是「立即成立」，仍然钉住「最终不再监听」。
    let mut released = false;
    for _ in 0..50 {
        if !connect_ok(port) {
            released = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(released, "停止后端口 {port} 必须最终不再监听");
}

/// M41-S1 §7.3：手动成功启动 ⇒ `settings.gateway_last_site_id/key_id` 被写成这一组。
///
/// auto 腿由同一函数保证：应用启动的 `maybe_auto_start_gateway`（`lib.rs`）同样调
/// `start_gateway_locked`（唯一启动出口），写 last_* 的代码不在手动/auto 间分叉；
/// auto-start 选组本身（`auto_start_target`）已有纯函数单测。
#[test]
fn gateway_start_writes_last_site_and_key_into_settings() {
    let _serial = gateway_test_guard();
    let (_app, webview) = build_app();
    let (site, key_id) = seed_gateway_site(&webview);
    let port = free_port();
    enable_gateway(&webview, port);

    let before = read_settings(&webview);
    assert_eq!(
        before["gatewayLastSiteId"],
        json!(0),
        "初始应为 0（无）: {before}"
    );
    assert_eq!(before["gatewayLastKeyId"], json!(0), "{before}");

    let started = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key_id}}),
    )
    .expect("启动网关");
    assert_eq!(started["phase"], "running", "{started}");

    let saved = read_settings(&webview);
    assert_eq!(
        saved["gatewayLastSiteId"],
        json!(site),
        "手动启动后应记下站点: {saved}"
    );
    assert_eq!(
        saved["gatewayLastKeyId"],
        json!(key_id),
        "手动启动后应记下密钥: {saved}"
    );
}

/// M41-S1 §7.2-4（验收 3）：改**非网关**设置 ⇒ 网关不中断（端口不变、仍在跑、
/// `last_exit` 无新记录）。
///
/// `gateway_transition` 是白名单：只有端口 / 多站 / 代理模式 / 代理地址才重启；
/// 这里改一个与网关无关的字段（`driftCheckOnStart` 不在白名单内），断言网关纹丝不动。
#[test]
fn update_settings_non_gateway_field_leaves_the_gateway_running() {
    let _serial = gateway_test_guard();
    let (_app, webview) = build_app();
    let (site, key_id) = seed_gateway_site(&webview);
    let port = free_port();
    enable_gateway(&webview, port);

    let started = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key_id}}),
    )
    .expect("启动网关");
    assert_eq!(started["phase"], "running", "{started}");
    assert!(connect_ok(port), "启动后端口 {port} 应可连接");
    let url_before = started["url"].as_str().unwrap_or("").to_string();

    let mut payload = read_settings(&webview);
    let drift_before = payload["driftCheckOnStart"].as_bool().unwrap_or(false);
    payload["driftCheckOnStart"] = json!(!drift_before);
    let result = invoke_on(
        &webview,
        "update_settings",
        json!({"args": {"settings": payload}}),
    )
    .expect("保存设置");
    assert_eq!(
        result["gateway"]["phase"], "running",
        "改非网关字段不得停网关: {result}"
    );
    assert_eq!(result["gateway"]["url"], url_before, "端口不得变: {result}");
    assert!(result["gatewayError"].is_null(), "不得报错: {result}");
    assert!(connect_ok(port), "端口 {port} 必须仍可连接");

    let status = invoke_on(&webview, "gateway_status", json!({})).expect("读状态");
    assert_eq!(status["phase"], "running", "{status}");
    assert!(status["lastExit"].is_null(), "不得有新的结束记录: {status}");

    // 设置本身确实保存了（改动生效，但网关没动）。
    let saved = read_settings(&webview);
    assert_eq!(saved["driftCheckOnStart"], json!(!drift_before), "{saved}");
}

// ============================================ M42-S1：网关状态 DTO 的监听字段

/// `gateway_status` 必须带 `listenAddrs` / `ipv6Degraded` / `ipv6Note` 三个 camelCase 键。
///
/// 没在跑的网关**不得**凭空报一个监听地址（空数组 + false + null 才是「没在听」）。
#[test]
fn gateway_status_exposes_listen_fields_in_camel_case() {
    let (_app, webview) = build_app();
    let value = invoke_on(&webview, "gateway_status", json!({})).expect("gateway_status 应成功");
    assert_eq!(
        value["listenAddrs"],
        json!([]),
        "没在跑 ⇒ 空数组，不得编造地址: {value}"
    );
    assert_eq!(value["ipv6Degraded"], false, "没在跑 ⇒ 未降级: {value}");
    assert!(
        value.get("ipv6Note").is_some_and(|v| v.is_null()),
        "没在跑 ⇒ ipv6Note 为 null: {value}"
    );
    assert_eq!(value["phase"], "stopped");
}

// ============================================================ M43-S1：Agent 网关令牌（IPC 层）

fn token_row(label: &str) -> Value {
    json!({ "label": label })
}

/// T2：明文**只在 create 的返回里出现一次**；list / gateway_status 都没有明文。
#[test]
fn m43_t2_token_plaintext_is_returned_exactly_once() {
    let (_app, webview) = build_app();
    let created = invoke_on(&webview, "gateway_token_create", token_row("t2-agent")).expect("创建");
    let plaintext = created["token"].as_str().expect("create 必须返回一次明文");
    assert!(plaintext.starts_with("kr-gw-"), "{created}");
    let mut created_keys: Vec<_> = created.as_object().unwrap().keys().cloned().collect();
    created_keys.sort();
    assert_eq!(
        created_keys,
        vec!["createdAt", "id", "label", "token"],
        "create DTO 形状（T13）"
    );

    let list = invoke_on(&webview, "gateway_token_list", json!({})).expect("列表");
    let list_text = list.to_string();
    assert!(
        !list_text.contains(plaintext),
        "列表不得含明文: {list_text}"
    );
    let first = &list[0];
    let mut list_keys: Vec<_> = first.as_object().unwrap().keys().cloned().collect();
    list_keys.sort();
    assert_eq!(
        list_keys,
        vec![
            "active",
            "createdAt",
            "id",
            "isDefault",
            "label",
            "lastUsedAt",
            "revokedAt"
        ],
        "list DTO 形状（T13）"
    );

    let status = invoke_on(&webview, "gateway_status", json!({})).expect("状态");
    assert!(
        !status.to_string().contains(plaintext),
        "gateway_status.tokens 不得含明文"
    );
    assert_eq!(
        status["tokens"][0]["label"], "t2-agent",
        "status 与 list 同形"
    );
}

/// T4 / T4c / T5：默认行迁移按 `is_default=1`（不看 label）、幂等。
#[test]
fn m43_t4_t4c_t5_default_row_migration_is_idempotent_and_flag_based() {
    let (_app, webview) = build_app();
    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();

    assert!(
        state
            .service
            .ensure_default_token_migrated()
            .expect("首次迁移"),
        "首次应插入"
    );
    let rows = state.service.store().list_gateway_tokens().expect("列表");
    assert_eq!(rows.len(), 1, "只剩默认行: {rows:?}");
    assert!(rows[0].is_default);
    assert_eq!(rows[0].label, "默认（迁移）");

    // T5：再跑一次 ⇒ 不新增。
    let _ = state
        .service
        .ensure_default_token_migrated()
        .expect("再次迁移");
    assert_eq!(
        state.service.store().list_gateway_tokens().unwrap().len(),
        1,
        "幂等"
    );

    // T4c：改名（甚至吊销标记）后仍按 is_default 找到 ⇒ 不新插第二行。
    state
        .service
        .store()
        .update_gateway_token_hash(rows[0].id, &rows[0].token_hash)
        .expect("原地更新（无变化）");
    // 直接把 label 改掉，模拟用户改展示名
    state
        .service
        .store()
        .revoke_gateway_token(rows[0].id)
        .expect("标记吊销（模拟手工改库）");
    let _ = state
        .service
        .ensure_default_token_migrated()
        .expect("改名/吊销后再对账");
    let rows = state.service.store().list_gateway_tokens().unwrap();
    assert_eq!(
        rows.len(),
        1,
        "不得因为 label/revoked 变化而新插第二行: {rows:?}"
    );
    assert!(rows[0].is_default, "默认身份不变");
}

/// T4e：默认令牌**不可吊销**（只能轮换）。
#[test]
fn m43_t4e_the_default_token_cannot_be_revoked() {
    let (_app, webview) = build_app();
    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();
    state.service.ensure_default_token_migrated().expect("迁移");
    let default_id = state
        .service
        .store()
        .default_gateway_token()
        .expect("读默认行")
        .expect("必须有默认行")
        .id;

    let err = invoke_on(&webview, "gateway_token_revoke", json!({"id": default_id}))
        .expect_err("默认行不得被吊销");
    assert_not_acl_rejection("gateway_token_revoke", &err);
    assert!(
        err.to_string().contains("轮换"),
        "文案应指向令牌轮换: {err}"
    );
    // agent 令牌可正常吊销（幂等）。
    let created =
        invoke_on(&webview, "gateway_token_create", token_row("t4e-agent")).expect("创建");
    let id = created["id"].as_i64().expect("id");
    let revoked = invoke_on(&webview, "gateway_token_revoke", json!({"id": id})).expect("吊销");
    assert_eq!(revoked["active"], false, "{revoked}");
    let again = invoke_on(&webview, "gateway_token_revoke", json!({"id": id})).expect("幂等");
    assert_eq!(again["active"], false);
}

/// T7：创建令牌后，事件表里**没有明文**（label 已 scrub）。
#[test]
fn m43_t7_token_plaintext_never_reaches_events() {
    let (_app, webview) = build_app();
    let created = invoke_on(&webview, "gateway_token_create", token_row("t7-agent")).expect("创建");
    let plaintext = created["token"].as_str().expect("明文").to_string();
    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();
    let events = state.service.store().list_events(200).expect("事件");
    let haystack = events
        .iter()
        .map(|event| format!("{event:?}"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!haystack.contains(&plaintext), "事件里不得出现令牌明文");
    // B-224 长尾 T7 扩展：诊断导出与备份导出也要扫同一明文（零命中）。
    // 顺序注意：必须在下面塞 canary 之前导出——备份包/诊断包会把事件表
    // 也打进去，塞完再导会把 canary 自身扫出来。两个产物按设计本就不含
    // 令牌明文，所以 canary 证明仍用下面的事件表塞行法——扫描器有效性
    // 已证明，这里只要求产物零命中。
    let exports = state.data_dir.join("exports");
    std::fs::create_dir_all(&exports).expect("建导出目录");
    let diag_path = exports.join("tianshu-relay-diagnostics-t7.json");
    invoke_on(
        &webview,
        "export_diagnostics",
        json!({"args": {"path": diag_path.display().to_string()}}),
    )
    .expect("诊断导出");
    let diag_text = std::fs::read_to_string(&diag_path).expect("读诊断包");
    assert!(!diag_text.contains(&plaintext), "诊断包里不得出现令牌明文");
    let bundle_path = exports.join("tianshu-relay-bundle-t7.json");
    invoke_on(
        &webview,
        "export_bundle",
        json!({"args": {"path": bundle_path.display().to_string()}}),
    )
    .expect("备份导出");
    let bundle_text = std::fs::read_to_string(&bundle_path).expect("读备份包");
    assert!(
        !bundle_text.contains(&plaintext),
        "备份包里不得出现令牌明文"
    );
    // canary（B-224 P3 修复）：此前这里是恒真式
    // `events.iter().any(|_| true) || events.is_empty()`，且「自检」只扫一个
    // 现拼的字符串——扫描器根本没碰过事件表，零命中可能是空转。
    // 现在**真的往事件表里塞一条带明文的行**（直接构造 Event 绕过
    // scrub 构造器，模拟历史泄漏行），再用同一套「Debug 拼串 + contains」
    // 扫表：必须命中，否则下面的「事件里无明文」断言没有证明力。
    state
        .service
        .store()
        .insert_event(&tianshu_relay_core::observability::Event {
            ts: 1_700_000_000,
            level: tianshu_relay_core::observability::Level::Warn,
            source: "gateway".to_string(),
            message: format!("canary 泄漏行 {plaintext}"),
            payload: None,
        })
        .expect("写 canary 事件");
    let events_after = state.service.store().list_events(200).expect("重读事件");
    let haystack_after = events_after
        .iter()
        .map(|event| format!("{event:?}"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        haystack_after.contains(&plaintext),
        "同一扫描必须能命中事件表里故意塞的明文，否则零命中是空转"
    );
}

/// T9：label 校验四条（空 / 超长 / 重名 / 令牌形态）。
#[test]
fn m43_t9_label_validation_rejects_the_four_bad_shapes() {
    let (_app, webview) = build_app();
    for (label, why) in [
        ("", "空"),
        ("   ", "全空白"),
        ("x".repeat(65).as_str(), "超长"),
        ("kr-gw-0123456789abcdef", "令牌形态"),
        ("sk-0123456789abcdef", "密钥形态"),
    ] {
        let err = invoke_on(&webview, "gateway_token_create", token_row(label))
            .expect_err(&format!("{why} 必须被拒"));
        assert_not_acl_rejection("gateway_token_create", &err);
    }
    // 重名：非吊销内唯一。
    invoke_on(&webview, "gateway_token_create", token_row("dup-agent")).expect("首次");
    let err = invoke_on(&webview, "gateway_token_create", token_row("dup-agent"))
        .expect_err("重名必须被拒");
    assert!(err.to_string().contains("同名"), "{err}");
}

// ============================================================ M41-S2：令牌轮换宽限期

/// 原始 HTTP `GET /health`：返回状态码（401/200）。不引 reqwest（壳层 dev-deps 没有）。
fn health_status(port: u16, token: &str) -> u16 {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("连接网关");
    let request = format!(
        "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).expect("写请求");
    let mut buf = String::new();
    let _ = stream.read_to_string(&mut buf);
    buf.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("非法响应: {buf}"))
}

fn set_grace(webview: &tauri::WebviewWindow<tauri::test::MockRuntime>, secs: u16) {
    let mut payload = read_settings(webview);
    payload["gatewayTokenGraceSecs"] = json!(secs);
    invoke_on(
        webview,
        "update_settings",
        json!({"args": {"settings": payload}}),
    )
    .expect("保存宽限期");
}

/// 旧令牌在 grace 内 200、过期 401、新令牌立即 200；默认行 id/label 不变。
#[test]
fn m41s2_grace_rotation_keeps_the_old_token_until_expiry() {
    let (_app, webview) = build_app();
    let (site, key_id) = seed_gateway_site(&webview);
    let port = free_port();
    enable_gateway(&webview, port);
    let started = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key_id}}),
    )
    .expect("启动网关");
    let old_token = started["token"].as_str().expect("旧令牌").to_string();
    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();
    let default_before = state
        .service
        .store()
        .default_gateway_token()
        .expect("默认行")
        .expect("网关启动应已迁移默认行");
    assert_eq!(health_status(port, &old_token), 200);

    set_grace(&webview, 1);
    let rotated = invoke_on(&webview, "gateway_rotate_token", json!({"args": null})).expect("轮换");
    let new_token = rotated["token"].as_str().expect("新令牌").to_string();
    assert_ne!(old_token, new_token, "必须是新令牌");
    let grace = rotated["tokenGraceUntil"]
        .as_i64()
        .expect("必须返回 tokenGraceUntil");
    assert!(grace > 0);

    // 默认行原地更新：id / label 不变，hash 已换。
    let default_after = state
        .service
        .store()
        .default_gateway_token()
        .expect("读默认行")
        .expect("默认行仍在");
    assert_eq!(default_after.id, default_before.id, "默认行 id 不得变");
    assert_eq!(
        default_after.label, default_before.label,
        "默认行 label 不得变"
    );
    assert_ne!(
        default_after.token_hash, default_before.token_hash,
        "hash 应已换新"
    );

    // 新令牌立即 200；旧令牌在 grace 内仍 200。
    assert_eq!(health_status(port, &new_token), 200, "新令牌必须立即生效");
    assert_eq!(health_status(port, &old_token), 200, "宽限内旧令牌应仍可用");

    // 过期 ⇒ 旧 401、新 200。
    std::thread::sleep(std::time::Duration::from_millis(1200));
    assert_eq!(
        health_status(port, &old_token),
        401,
        "宽限到期后旧令牌必须 401"
    );
    assert_eq!(health_status(port, &new_token), 200);
}

/// grace=0 ⇒ 旧令牌立即失效；重启后旧令牌同样失效（宽限不落库）。
#[test]
fn m41s2_grace_zero_and_restart_kill_the_old_token() {
    let (_app, webview) = build_app();
    let (site, key_id) = seed_gateway_site(&webview);
    let port = free_port();
    enable_gateway(&webview, port);
    let started = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key_id}}),
    )
    .expect("启动网关");
    let first_token = started["token"].as_str().expect("旧令牌").to_string();

    set_grace(&webview, 0);
    let rotated = invoke_on(&webview, "gateway_rotate_token", json!({"args": null})).expect("轮换");
    let second_token = rotated["token"].as_str().expect("新令牌").to_string();
    assert_eq!(
        rotated["tokenGraceUntil"],
        Value::Null,
        "grace=0 时不该有宽限"
    );
    assert_eq!(
        health_status(port, &first_token),
        401,
        "grace=0 ⇒ 旧令牌立即 401"
    );
    assert_eq!(health_status(port, &second_token), 200);

    // 重启（stop → start）：宽限是运行态，重启后旧令牌必然 401。
    invoke_on(&webview, "gateway_stop", json!({})).expect("停止");
    let restarted = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key_id}}),
    )
    .expect("重启");
    let current = restarted["token"].as_str().expect("令牌").to_string();
    assert_eq!(
        health_status(port, &first_token),
        401,
        "重启后旧令牌必须 401"
    );
    assert_eq!(health_status(port, &current), 200, "重启后当前令牌可用");
}

/// B-224 P3（M41-S2 T-5 缺口）：grace>0 **进行中重启** ⇒ 旧令牌必须失效。
/// 此前只有「grace 内不重启」（旧 200）与「grace=0 + 重启」（旧 401）两条
/// 用例，宽限期「重启后是否还残留」恰好是未覆盖的组合——宽限是运行态，
/// 重启后若旧令牌仍可用，就是一次未被守住的回归。
#[test]
fn m41s2_grace_positive_and_restart_kills_the_old_token() {
    let (_app, webview) = build_app();
    let (site, key_id) = seed_gateway_site(&webview);
    let port = free_port();
    enable_gateway(&webview, port);
    let started = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key_id}}),
    )
    .expect("启动网关");
    let first_token = started["token"].as_str().expect("令牌").to_string();

    // 宽限 60 秒：轮换后旧令牌在宽限内仍可用（先复现不重启的基线）。
    set_grace(&webview, 60);
    let rotated = invoke_on(&webview, "gateway_rotate_token", json!({"args": null})).expect("轮换");
    let new_token = rotated["token"].as_str().expect("新令牌").to_string();
    assert_ne!(first_token, new_token, "必须是新令牌");
    assert_eq!(
        health_status(port, &first_token),
        200,
        "宽限内旧令牌应仍可用（重启前基线）"
    );
    assert_eq!(health_status(port, &new_token), 200);

    // 重启（stop → start）：宽限是运行态，重启后旧令牌必然 401，
    // 而网关本身仍可用（重启返回的当前令牌 200）。
    invoke_on(&webview, "gateway_stop", json!({})).expect("停止");
    let restarted = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key_id}}),
    )
    .expect("重启");
    let current = restarted["token"].as_str().expect("重启后令牌").to_string();
    assert_eq!(
        health_status(port, &first_token),
        401,
        "grace>0 进行中重启后旧令牌必须 401（宽限不跨重启）"
    );
    assert_eq!(health_status(port, &current), 200, "重启后当前令牌可用");
}

/// M41-S2 T-3：二次轮换 ⇒ 第一代旧令牌**立即** 401（宽限槽只留上一代）。
#[test]
fn m41s2_second_rotation_revokes_the_first_generation_immediately() {
    let (_app, webview) = build_app();
    let (site, key_id) = seed_gateway_site(&webview);
    let port = free_port();
    enable_gateway(&webview, port);
    let started = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key_id}}),
    )
    .expect("启动网关");
    let gen1 = started["token"].as_str().expect("令牌").to_string();

    set_grace(&webview, 60);
    let rotated1 =
        invoke_on(&webview, "gateway_rotate_token", json!({"args": null})).expect("第一次轮换");
    let gen2 = rotated1["token"].as_str().expect("令牌").to_string();
    assert_ne!(gen1, gen2);
    assert_eq!(
        health_status(port, &gen1),
        200,
        "第一次轮换后第一代仍在宽限内"
    );
    assert_eq!(health_status(port, &gen2), 200);

    let rotated2 =
        invoke_on(&webview, "gateway_rotate_token", json!({"args": null})).expect("第二次轮换");
    let gen3 = rotated2["token"].as_str().expect("令牌").to_string();
    assert_ne!(gen2, gen3);
    assert_eq!(
        health_status(port, &gen1),
        401,
        "第二次轮换后第一代必须立即 401（宽限槽只留上一代）"
    );
    assert_eq!(health_status(port, &gen2), 200, "第二代进入新宽限，仍可用");
    assert_eq!(health_status(port, &gen3), 200, "第三代立即生效");
}

/// M41-S2 T-6：轮换后旧明文在令牌表 / 事件表 / 诊断导出 / 备份导出里零命中；
/// 钥匙串里只剩新令牌（旧明文已被覆盖，不是「新旧并存」）。
#[test]
fn m41s2_rotated_old_plaintext_appears_nowhere() {
    use tauri::Manager;
    let (_app, webview) = build_app();
    let (site, key_id) = seed_gateway_site(&webview);
    let port = free_port();
    enable_gateway(&webview, port);
    let started = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key_id}}),
    )
    .expect("启动网关");
    let old_plaintext = started["token"].as_str().expect("令牌").to_string();

    set_grace(&webview, 60);
    let rotated = invoke_on(&webview, "gateway_rotate_token", json!({"args": null})).expect("轮换");
    let new_plaintext = rotated["token"].as_str().expect("令牌").to_string();
    assert_ne!(old_plaintext, new_plaintext);

    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();
    // 令牌表：只有 hash，没有任何明文。
    let rows = state
        .service
        .store()
        .list_gateway_tokens()
        .expect("读令牌表");
    let rows_dump = format!("{rows:?}");
    assert!(
        !rows_dump.contains(&old_plaintext),
        "令牌表里不得出现旧明文"
    );
    // 事件表。
    let events = state.service.store().list_events(200).expect("读事件");
    let events_dump = events
        .iter()
        .map(|e| format!("{e:?}"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !events_dump.contains(&old_plaintext),
        "事件表里不得出现旧明文"
    );
    // 钥匙串当前值必须是新令牌（旧值已被覆盖）。
    let vault_current = state.service.gateway_token_plaintext().expect("读钥匙串");
    assert_eq!(vault_current.as_str(), new_plaintext, "钥匙串应只剩新令牌");
    assert_ne!(vault_current.as_str(), old_plaintext);

    // 诊断导出 + 备份导出（同 app 内导出，不是新 app 的空库）。
    let exports = state.data_dir.join("exports");
    std::fs::create_dir_all(&exports).expect("建导出目录");
    let diag_path = exports.join("tianshu-relay-diagnostics-t6.json");
    invoke_on(
        &webview,
        "export_diagnostics",
        json!({"args": {"path": diag_path.display().to_string()}}),
    )
    .expect("诊断导出");
    let diag_text = std::fs::read_to_string(&diag_path).expect("读诊断包");
    assert!(
        !diag_text.contains(&old_plaintext),
        "诊断包里不得出现旧明文"
    );
    let bundle_path = exports.join("tianshu-relay-bundle-t6.json");
    invoke_on(
        &webview,
        "export_bundle",
        json!({"args": {"path": bundle_path.display().to_string()}}),
    )
    .expect("备份导出");
    let bundle_text = std::fs::read_to_string(&bundle_path).expect("读备份包");
    assert!(
        !bundle_text.contains(&old_plaintext),
        "备份包里不得出现旧明文"
    );
}

/// M41-S2 T-7：轮换后默认行恰好一条、且未被吊销（`is_default == 1` 唯一，`revoked_at` 为空）。
#[test]
fn m41s2_rotation_keeps_exactly_one_unrevoked_default_row() {
    let (_app, webview) = build_app();
    let (site, key_id) = seed_gateway_site(&webview);
    let port = free_port();
    enable_gateway(&webview, port);
    let started = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key_id}}),
    )
    .expect("启动网关");
    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();
    let before = state
        .service
        .store()
        .default_gateway_token()
        .expect("读默认行")
        .expect("默认行");
    set_grace(&webview, 60);
    invoke_on(&webview, "gateway_rotate_token", json!({"args": null})).expect("轮换");

    let rows = state
        .service
        .store()
        .list_gateway_tokens()
        .expect("读令牌表");
    let defaults: Vec<_> = rows.iter().filter(|r| r.is_default).collect();
    assert_eq!(defaults.len(), 1, "默认行必须恰好一条: {rows:?}");
    assert_eq!(defaults[0].id, before.id, "默认行 id 不得变");
    assert!(
        defaults[0].revoked_at.is_none(),
        "默认行不得被吊销: {:?}",
        defaults[0]
    );
}

/// M41-S2 T-10：宽限轮换**不重启**——地址不变、仍在跑、`last_exit` 无新记录。
///
/// 与 legacy 路径的 `gateway_rotate_token_restarts_the_running_gateway_with_the_new_token`
///（重启）并存不矛盾：那条是无默认行时的 legacy 回退；有默认行时走宽限路径，不重启。
#[test]
fn m41s2_grace_rotation_does_not_restart_the_gateway() {
    let (_app, webview) = build_app();
    let (site, key_id) = seed_gateway_site(&webview);
    let port = free_port();
    enable_gateway(&webview, port);
    let started = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key_id}}),
    )
    .expect("启动网关");
    let url_before = started["url"].as_str().unwrap_or("").to_string();
    assert_eq!(started["phase"], "running");

    set_grace(&webview, 60);
    invoke_on(&webview, "gateway_rotate_token", json!({"args": null})).expect("轮换");

    let status = invoke_on(&webview, "gateway_status", json!({})).expect("读状态");
    assert_eq!(status["phase"], "running", "宽限轮换不得停网关: {status}");
    assert_eq!(
        status["url"], url_before,
        "宽限轮换不得换地址（不重启）: {status}"
    );
    assert!(
        status["lastExit"].is_null(),
        "宽限轮换不得产生结束记录: {status}"
    );
    assert!(connect_ok(port), "端口 {port} 必须仍可连接");
}

/// M41-S2 T-14：连轮 3 次 ⇒ 默认行永不吊销；且直接吊销默认行必须被拒。
#[test]
fn m41s2_three_rotations_never_revoke_the_default_row() {
    let (_app, webview) = build_app();
    let (site, key_id) = seed_gateway_site(&webview);
    let port = free_port();
    enable_gateway(&webview, port);
    let started = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key_id}}),
    )
    .expect("启动网关");
    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();
    let default_before = state
        .service
        .store()
        .default_gateway_token()
        .expect("读默认行")
        .expect("默认行");
    set_grace(&webview, 60);
    let mut current = started["token"].as_str().expect("令牌").to_string();
    for _ in 0..3 {
        let rotated =
            invoke_on(&webview, "gateway_rotate_token", json!({"args": null})).expect("轮换");
        current = rotated["token"].as_str().expect("令牌").to_string();
        assert_eq!(health_status(port, &current), 200, "每次轮换后新令牌都可用");
    }
    let rows = state
        .service
        .store()
        .list_gateway_tokens()
        .expect("读令牌表");
    let defaults: Vec<_> = rows.iter().filter(|r| r.is_default).collect();
    assert_eq!(defaults.len(), 1, "连轮 3 次后默认行仍恰好一条: {rows:?}");
    assert_eq!(defaults[0].id, default_before.id, "默认行 id 不得变");
    assert!(
        defaults[0].revoked_at.is_none(),
        "默认行永不得被吊销: {:?}",
        defaults[0]
    );

    let err = invoke_on(
        &webview,
        "gateway_token_revoke",
        json!({"id": default_before.id}),
    )
    .expect_err("吊销默认行必须被拒");
    assert!(err.to_string().contains("默认令牌不能吊销"), "{err}");
}

/// M41-S2 3601：宽限期上限 3600 秒，3601 必须被设置校验拒掉。
#[test]
fn m41s2_grace_secs_above_3600_is_rejected() {
    let (_app, webview) = build_app();
    let mut payload = read_settings(&webview);
    payload["gatewayTokenGraceSecs"] = json!(3601);
    let err = invoke_on(
        &webview,
        "update_settings",
        json!({"args": {"settings": payload}}),
    )
    .expect_err("3601 秒宽限必须被拒");
    assert!(err.to_string().contains("3600"), "{err}");
}

/// M39-S3 P2-2（B-224 长尾）：越界的保护设置必须被拒**且不落库**。
/// 只测 `Settings::validate()` 不够——要钉「先 validate 再写库」的顺序：
/// `update_settings` 报错后重读设置，越界值与其它字段都必须还是旧值
/// （若实现先写库后校验，这里会红）。
#[test]
fn m39s3_guard_settings_out_of_range_are_not_persisted() {
    let (_app, webview) = build_app();
    let before = read_settings(&webview);
    let mut payload = before.clone();
    // 每站并发上限 128，129 越界；另把 top_n 改成一个合法但不同于旧值的数，
    // 让「其它字段未改写」断言也有判别力（B224-TAIL-4 复审 P3-1：payload 若
    // 只是旧值克隆，部分写入实现也会绿；改成不同值后，先写库后校验或逐字段
    // 部分写入都会在这里红）。
    let other = if before["gatewayLbTopN"] == json!(5) {
        json!(4)
    } else {
        json!(5)
    };
    payload["gatewayLbTopN"] = other;
    payload["gatewayPerSiteConcurrency"] = json!(129);
    let err = invoke_on(
        &webview,
        "update_settings",
        json!({"args": {"settings": payload}}),
    )
    .expect_err("越界并发必须被拒");
    assert_not_acl_rejection("update_settings", &err);
    let after = read_settings(&webview);
    assert_eq!(
        after["gatewayPerSiteConcurrency"], before["gatewayPerSiteConcurrency"],
        "越界值不得落库：{err}"
    );
    assert_eq!(
        after["gatewayLbTopN"], before["gatewayLbTopN"],
        "合法但不同的其它字段也不得被连带写入（否则就是先写库后校验或部分写入）"
    );
}

/// M46-S3：`gatewayPerSiteBurst` 的 DTO 双向直传 + 越界拒写。
/// （M46-S1 的 B-238 教训：DTO 直传必须有自动化用例，不只读代码确认。）
#[test]
fn m46s3_per_site_burst_round_trips_and_rejects_out_of_range() {
    let (_app, webview) = build_app();
    let before = read_settings(&webview);
    assert_eq!(before["gatewayPerSiteBurst"], json!(0), "burst 默认 0 = 关");

    let mut payload = before.clone();
    payload["gatewayPerSiteBurst"] = json!(3);
    let result = invoke_on(
        &webview,
        "update_settings",
        json!({"args": {"settings": payload}}),
    )
    .expect("合法 burst 应能保存");
    assert_eq!(result["settings"]["gatewayPerSiteBurst"], json!(3));
    let read = read_settings(&webview);
    assert_eq!(read["gatewayPerSiteBurst"], json!(3), "写后读必须一致");

    let mut bad = read.clone();
    bad["gatewayPerSiteBurst"] = json!(10_001);
    let err = invoke_on(
        &webview,
        "update_settings",
        json!({"args": {"settings": bad}}),
    )
    .expect_err("越界 burst 必须被拒");
    assert_not_acl_rejection("update_settings", &err);
    let after = read_settings(&webview);
    assert_eq!(
        after["gatewayPerSiteBurst"],
        json!(3),
        "越界值不得落库：{err}"
    );
}

/// M46-S4：`gatewayMaxAttempts` 的 DTO 双向直传 + 越界拒写（照 M46-S3 的 burst 用例）。
#[test]
fn m46s4_max_attempts_round_trips_and_rejects_out_of_range() {
    let (_app, webview) = build_app();
    let before = read_settings(&webview);
    assert_eq!(
        before["gatewayMaxAttempts"],
        json!(0),
        "max_attempts 默认 0 = 走全部候选"
    );

    let mut payload = before.clone();
    payload["gatewayMaxAttempts"] = json!(2);
    let result = invoke_on(
        &webview,
        "update_settings",
        json!({"args": {"settings": payload}}),
    )
    .expect("合法 max_attempts 应能保存");
    assert_eq!(result["settings"]["gatewayMaxAttempts"], json!(2));
    let read = read_settings(&webview);
    assert_eq!(read["gatewayMaxAttempts"], json!(2), "写后读必须一致");

    let mut bad = read.clone();
    bad["gatewayMaxAttempts"] = json!(65);
    let err = invoke_on(
        &webview,
        "update_settings",
        json!({"args": {"settings": bad}}),
    )
    .expect_err("越界 max_attempts 必须被拒");
    assert_not_acl_rejection("update_settings", &err);
    let after = read_settings(&webview);
    assert_eq!(
        after["gatewayMaxAttempts"],
        json!(2),
        "越界值不得落库：{err}"
    );
}

/// M41-S2 F-2：DB 写入失败 ⇒ 轮换命令报错、旧令牌仍 200、`tokenGraceUntil` 为空。
///
/// 失败注入点：`Store::fail_next_gateway_token_hash_update_for_test`（一次性开关，
/// 生产代码永不 arm）。写序硬约束——DB 失败时运行态绝不先换新令牌，否则重启后旧
/// hash 复活——由本用例钉住：命令报错后注册表仍是旧 hash，网关仍认旧令牌。
#[test]
fn m41s2_db_failure_keeps_the_old_token_and_no_grace() {
    let (_app, webview) = build_app();
    let (site, key_id) = seed_gateway_site(&webview);
    let port = free_port();
    enable_gateway(&webview, port);
    let started = invoke_on(
        &webview,
        "gateway_start",
        json!({"args": {"siteId": site, "keyId": key_id}}),
    )
    .expect("启动网关");
    let old_token = started["token"].as_str().expect("令牌").to_string();
    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();
    let hash_before = state
        .service
        .store()
        .default_gateway_token()
        .expect("读默认行")
        .expect("默认行")
        .token_hash;

    set_grace(&webview, 60);
    state
        .service
        .store()
        .fail_next_gateway_token_hash_update_for_test();
    let err = invoke_on(&webview, "gateway_rotate_token", json!({"args": null}))
        .expect_err("DB 失败时轮换必须报错");
    assert!(err.to_string().contains("入库失败"), "{err}");

    // 运行态未动：旧令牌仍 200，DB hash 未变，无宽限。
    assert_eq!(
        health_status(port, &old_token),
        200,
        "DB 失败后旧令牌必须仍可用"
    );
    let hash_after = state
        .service
        .store()
        .default_gateway_token()
        .expect("重读默认行")
        .expect("默认行")
        .token_hash;
    assert_eq!(hash_after, hash_before, "DB 失败时 hash 不得变");
    let status = invoke_on(&webview, "gateway_status", json!({})).expect("读状态");
    assert_eq!(
        status["tokenGraceUntil"],
        Value::Null,
        "DB 失败时不得有宽限: {status}"
    );
}

/// M43-S2：模型单价与站点账单命令在 IPC 层可用，DTO 键是 camelCase，
/// 且**空态是结构性空值**（`[]` / `null`，不是编造的数字）。
///
/// 注意：必须**复用同一个 app/webview**——`invoke_impl` 每次都会新建一个内存库，
/// 跨调用看不到上一条命令写的行。
#[test]
fn m43s2_price_and_bill_commands_are_registered_with_camel_case_dtos() {
    let (app, webview) = build_app();
    let invoke_on_app = |cmd: &str, args: Value| invoke_on(&webview, cmd, args);
    let _ = &app;

    let prices = invoke_on_app("model_price_list", json!({})).expect("model_price_list 应成功");
    assert_eq!(prices, json!([]), "空库应返回空数组");

    let bills = invoke_on_app("site_bills", json!({ "days": 7 })).expect("site_bills 应成功");
    assert_eq!(bills, json!([]), "没有账单时返回空数组");

    let created = invoke_on_app(
        "model_price_upsert",
        json!({
            "price": {
                "model": "gpt-4o",
                "inputPerMtok": 2.5,
                "outputPerMtok": 10.0,
                "currency": "USD",
                "effectiveFrom": 1_700_000_000i64
            }
        }),
    )
    .expect("model_price_upsert 应成功");
    for key in [
        "id",
        "model",
        "inputPerMtok",
        "outputPerMtok",
        "currency",
        "effectiveFrom",
        "createdAt",
    ] {
        assert!(created.get(key).is_some(), "缺字段 {key}: {created}");
    }
    assert!(
        created.get("input_per_mtok").is_none(),
        "线上键必须 camelCase"
    );
    assert_eq!(created["inputPerMtok"], 2.5);
    let id = created["id"].as_i64().expect("id");

    let after = invoke_on_app("model_price_list", json!({})).expect("再列一次");
    assert_eq!(after.as_array().map(|a| a.len()), Some(1));

    let deleted = invoke_on_app("model_price_delete", json!({ "id": id })).expect("删除");
    assert_eq!(deleted, json!(true));
    assert_eq!(
        invoke_on_app("model_price_list", json!({})).expect("列"),
        json!([])
    );
}

/// M46-S5：硬预算命令在 IPC 层可用（注册 + ACL + camelCase DTO + validate 拒写）。
#[test]
fn m46s5_site_budget_commands_round_trip_and_reject_bad_input() {
    let (_app, webview) = build_app();
    let invoke_on_app = |cmd: &str, args: Value| invoke_on(&webview, cmd, args);
    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();
    let store = state.service.store();

    let empty = invoke_on_app("site_budget_list", json!({})).expect("site_budget_list 应成功");
    assert_eq!(empty, json!([]), "空库应返回空数组");

    // 非法输入先行：站点不存在、周期非法、上限非正，全部被拒且不落库。
    assert!(
        invoke_on_app(
            "site_budget_create",
            json!({ "budget": { "siteId": 9999, "keyId": null, "period": "day", "limitUsd": 10.0 } }),
        )
        .is_err(),
        "不存在的站点应被拒"
    );
    assert!(
        invoke_on_app(
            "site_budget_create",
            json!({ "budget": { "siteId": 1, "keyId": null, "period": "week", "limitUsd": 10.0 } }),
        )
        .is_err(),
        "非法周期应被拒"
    );
    assert!(
        invoke_on_app(
            "site_budget_create",
            json!({ "budget": { "siteId": 1, "keyId": null, "period": "day", "limitUsd": 0.0 } }),
        )
        .is_err(),
        "上限 0 应被拒"
    );
    assert_eq!(
        invoke_on_app("site_budget_list", json!({})).expect("列"),
        json!([]),
        "拒写后表仍为空"
    );

    let site = store
        .upsert_site("newapi", "https://relay.example.com", "预算测试站")
        .expect("写站点");
    let created = invoke_on_app(
        "site_budget_create",
        json!({ "budget": { "siteId": site, "keyId": null, "period": "month", "limitUsd": 25.5 } }),
    )
    .expect("site_budget_create 应成功");
    for key in [
        "id",
        "siteId",
        "keyId",
        "period",
        "limitUsd",
        "createdAt",
        "spentUsd",
    ] {
        assert!(created.get(key).is_some(), "缺字段 {key}: {created}");
    }
    assert!(created.get("limit_usd").is_none(), "线上键必须 camelCase");
    assert_eq!(created["siteId"], site);
    assert_eq!(created["keyId"], Value::Null);
    assert_eq!(created["spentUsd"], 0.0, "新预算当期已花为 0");
    let id = created["id"].as_i64().expect("id");

    // 重复行被拒（同站同周期站级行只能有一行）。
    assert!(
        invoke_on_app(
            "site_budget_create",
            json!({ "budget": { "siteId": site, "keyId": null, "period": "month", "limitUsd": 30.0 } }),
        )
        .is_err(),
        "重复预算行应被拒"
    );

    let after = invoke_on_app("site_budget_list", json!({})).expect("再列一次");
    assert_eq!(after.as_array().map(|a| a.len()), Some(1));
    assert_eq!(
        invoke_on_app("site_budget_delete", json!({ "id": 9999 })).expect("删不存在"),
        json!(false)
    );
    assert_eq!(
        invoke_on_app("site_budget_delete", json!({ "id": id })).expect("删除"),
        json!(true)
    );
    assert_eq!(
        invoke_on_app("site_budget_list", json!({})).expect("列"),
        json!([])
    );
}

/// M46-S6：账单对账命令在 IPC 层可用（注册 + ACL + camelCase DTO + site 过滤）。
/// 当日 day 字符串不硬编码：先调一次拿到 gateway-only 行的 day，再按该 day 写账单复调。
#[test]
fn m46s6_bill_reconciliation_commands_round_trip() {
    let (_app, webview) = build_app();
    let invoke_on_app = |cmd: &str, args: Value| invoke_on(&webview, cmd, args);
    let state = webview.app_handle().state::<tianshu_relay_lib::AppState>();
    let store = state.service.store();

    let empty = invoke_on_app("bill_reconciliation", json!({})).expect("空库应成功");
    assert_eq!(empty, json!([]), "空库应返回空数组");

    let site = store
        .upsert_site("newapi", "https://relay.example.com", "对账测试站")
        .expect("写站点");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("时钟")
        .as_secs() as i64;
    store
        .model_price_upsert("usd-model", 2.0, 4.0, "USD", now - 40 * 86_400)
        .expect("写价格");
    store
        .insert_gateway_usage(&tianshu_relay_core::gateway::GatewayUsage {
            at: now,
            site_id: site,
            key_id: None,
            model: "usd-model".to_string(),
            prompt_tokens: 5_000_000,
            completion_tokens: 0,
            total_tokens: 5_000_000,
            status: 200,
            latency_ms: 10,
            attempts: 1,
            stream: false,
            token_id: None,
            agent_label: String::new(),
        })
        .expect("写用量");

    // 第一次：只有网关侧 ⇒ gateway-only 行，顺带取当日 day。
    let first = invoke_on_app("bill_reconciliation", json!({})).expect("首调");
    let first_rows = first.as_array().expect("数组");
    assert_eq!(first_rows.len(), 1, "无账单时应恰好一行 gateway-only");
    let row = &first_rows[0];
    for key in [
        "siteId",
        "day",
        "gatewayUsd",
        "billUsd",
        "diffUsd",
        "flagged",
        "kind",
        "source",
    ] {
        assert!(row.get(key).is_some(), "缺字段 {key}: {row}");
    }
    assert!(row.get("site_id").is_none(), "线上键必须 camelCase");
    assert_eq!(row["kind"], "gateway_only");
    assert_eq!(row["gatewayUsd"], 10.0, "5M prompt × 2.0 = 10.0");
    assert_eq!(row["billUsd"], 0.0, "缺失侧按 0 计");
    assert_eq!(row["source"], Value::Null, "gateway-only 行无来源");
    let today = row["day"].as_str().expect("day 字符串").to_string();

    // 按该 day 写账单 ⇒ 第二次应为 matched 行。
    store
        .site_bill_upsert(
            site,
            &today,
            Some(10.0),
            Some("USD"),
            None,
            "newapi-log-self",
        )
        .expect("写账单");
    let second = invoke_on_app("bill_reconciliation", json!({})).expect("复调");
    let second_rows = second.as_array().expect("数组");
    assert_eq!(second_rows.len(), 1);
    assert_eq!(second_rows[0]["kind"], "matched");
    assert_eq!(second_rows[0]["gatewayUsd"], 10.0);
    assert_eq!(second_rows[0]["billUsd"], 10.0);
    assert_eq!(second_rows[0]["diffUsd"], 0.0);
    assert_eq!(second_rows[0]["flagged"], false);
    assert_eq!(second_rows[0]["source"], "newapi-log-self");

    // site 过滤：别站有网关行但不过滤不到；只查本战时只回本行。
    let other = store
        .upsert_site("newapi", "https://other.example.com", "别站")
        .expect("写别站");
    store
        .insert_gateway_usage(&tianshu_relay_core::gateway::GatewayUsage {
            at: now,
            site_id: other,
            key_id: None,
            model: "usd-model".to_string(),
            prompt_tokens: 5_000_000,
            completion_tokens: 0,
            total_tokens: 5_000_000,
            status: 200,
            latency_ms: 10,
            attempts: 1,
            stream: false,
            token_id: None,
            agent_label: String::new(),
        })
        .expect("写别站用量");
    let filtered = invoke_on_app("bill_reconciliation", json!({ "siteId": site })).expect("过滤调");
    let filtered_rows = filtered.as_array().expect("数组");
    assert_eq!(filtered_rows.len(), 1, "site 过滤只回该站");
    assert_eq!(filtered_rows[0]["siteId"], site);
    let unfiltered = invoke_on_app("bill_reconciliation", json!({})).expect("不过滤");
    assert_eq!(
        unfiltered.as_array().map(|a| a.len()),
        Some(2),
        "不过滤时两站各一行"
    );
}
