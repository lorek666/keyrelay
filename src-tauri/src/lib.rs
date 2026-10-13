//! Tauri 桌面壳：只做「命令注册 + 状态管理 + 平台胶水」。
//!
//! 业务逻辑一律在 `keyrelay-core`，本 crate 不出现 SQL、HTTP、文件改写逻辑。
//!
//! `configure` / `configure_with_state` 之所以单独暴露，是为了让 IPC 测试
//! （`tests/commands.rs`）能用 Tauri 官方 mock runtime 复用同一套命令注册。

mod commands;
pub mod commands_list;
pub mod tray;

use std::path::PathBuf;

use tauri::Manager;

use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::registry::SiteRegistry;
use keyrelay_core::site::retry::{RetryPolicy, RetryingTransport};
use keyrelay_core::site::transport_reqwest::{ReqwestTransport, TransportConfig};
use keyrelay_core::site::SiteFingerprint;
use keyrelay_core::store::Store;
use keyrelay_core::Result;

/// 生产装配：真实 reqwest + 重试装饰器
pub type AppTransport = RetryingTransport<ReqwestTransport>;

pub struct AppState {
    pub service: KeyRelayService<AppTransport>,
    pub db_path: PathBuf,
    /// 数据库打开失败时的原因（用于在 UI 上明确提示，而不是静默降级）
    pub db_error: Option<String>,
    /// 正在运行的本地网关（同一时刻只允许一个）。
    pub gateway: std::sync::Mutex<Option<keyrelay_core::gateway::GatewayHandle>>,
    /// 把「停旧 → 绑新」整个序列串起来（M5-S5 / 关闭 B-64 的命令层那一半）。
    ///
    /// 必须是**异步**锁：`gateway_start` 里要 `await` `shutdown_and_wait()`，
    /// 而 `std::sync::MutexGuard` 不能跨 `await`（不是 `Send`）。
    /// 用 std 锁只在取 `Option` 时上锁，等于没修 —— 两个并发启动仍会各自 bind。
    pub gateway_op: tokio::sync::Mutex<()>,
    /// 托盘图标是否真的建起来了（M6-S5）。
    ///
    /// 这个标志位决定「能不能隐藏窗口」：托盘不可用时隐藏窗口会把应用变成
    /// 用户碰不到的后台进程。无 GUI 会话（CI / SSH / headless）下建不出托盘是**正常**结果，
    /// 所以默认 `false`，由 `setup` 里的真实结果覆盖。
    pub tray_available: std::sync::atomic::AtomicBool,
}

/// 用户主目录。解析逻辑在 `keyrelay_core::platform`（按平台处理 `KEYRELAY_HOME` /
/// `USERPROFILE` / `HOMEDRIVE`+`HOMEPATH` / `HOME`）。
///
/// 壳层这里只做「解析不出来就明确退出」——**不静默退化成当前目录**
/// （否则在 Windows 上会把密钥写到 `C:\Program Files\...`，用户找不到）。
pub fn home_dir() -> PathBuf {
    match keyrelay_core::platform::home_dir() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("[keyrelay] {err}");
            std::process::exit(1);
        }
    }
}

/// `~/.keyrelay/keyrelay.db`
pub fn default_db_path() -> PathBuf {
    home_dir().join(".keyrelay").join("keyrelay.db")
}

fn build_transport() -> AppTransport {
    match ReqwestTransport::new(TransportConfig::default()) {
        Ok(inner) => RetryingTransport::new(inner, RetryPolicy::default()),
        Err(err) => {
            // 默认配置理论上不会失败；真失败说明构建环境异常，明确退出而不是静默降级
            eprintln!("[keyrelay] 构造 HTTP 传输层失败: {err}");
            std::process::exit(1);
        }
    }
}

/// 仅做指纹识别（不落库），供前端「测试连接」按钮使用。
pub async fn detect_only(base_url: &str) -> Result<SiteFingerprint> {
    SiteRegistry::new(build_transport()).detect(base_url).await
}

fn state_from_store(store: Store, db_path: PathBuf, db_error: Option<String>) -> AppState {
    state_with_config(
        store,
        db_path,
        db_error,
        ServiceConfig::production(home_dir()),
    )
}

/// 测试用：内存钥匙串，绝不触碰用户真实钥匙串与 `~/.keyrelay`。
fn state_in_memory(store: Store, db_path: PathBuf) -> AppState {
    // **每个 app 一个独立目录**（进程内自增序号）。
    //
    // 原先只用 pid：一个测试进程里所有 app 共享同一个 `keyrelay-test-<pid>`，
    // 于是「另一个测试写进 `exports` / `backups` 的文件」会被本测试的审计扫描到——
    // `export_diagnostics_writes_a_package_and_registers_it_for_the_audit` 的
    // 「文件数必须 +1」因此变成一条**看时序**的断言（并发跑时偶发红）。
    // 隔离目录之后，扫描集合只由本 app 自己写过的东西决定。
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let tmp = std::env::temp_dir().join(format!("keyrelay-test-{}-{seq}", std::process::id()));
    state_with_config(store, db_path, None, ServiceConfig::in_memory(tmp))
}

fn state_with_config(
    store: Store,
    db_path: PathBuf,
    db_error: Option<String>,
    config: ServiceConfig,
) -> AppState {
    // 钥匙串可用性只在启动时探测一次并明确告警；不可用时投递相关能力会各自失败，
    // **不会**静默换成内存实现（ADR-0002）。
    if let Err(err) = config.vault.probe() {
        eprintln!("[keyrelay] 系统钥匙串不可用，密钥投递将被禁用: {err}");
    }
    AppState {
        service: KeyRelayService::new(store, build_transport(), config),
        db_path,
        db_error,
        gateway: std::sync::Mutex::new(None),
        gateway_op: tokio::sync::Mutex::new(()),
        // 真实结果由 `setup` 里的 `tray::build` 覆盖；测试里永远保持 false
        tray_available: std::sync::atomic::AtomicBool::new(false),
    }
}

/// 打开真实数据库；失败时回退内存库并把原因带进状态（不静默降级）。
pub fn init_state() -> AppState {
    let db_path = default_db_path();
    match Store::open(&db_path) {
        Ok(store) => state_from_store(store, db_path, None),
        Err(err) => {
            eprintln!("[keyrelay] 打开本地数据库失败，回退到内存库: {err}");
            match Store::open_in_memory() {
                Ok(store) => state_from_store(store, db_path, Some(err.to_string())),
                Err(fatal) => {
                    eprintln!("[keyrelay] 内存库也不可用，退出: {fatal}");
                    std::process::exit(1);
                }
            }
        }
    }
}

/// 测试用：纯内存状态，不触碰用户 `~/.keyrelay`。
pub fn init_state_in_memory() -> AppState {
    match Store::open_in_memory() {
        Ok(store) => state_in_memory(store, PathBuf::from(":memory:")),
        Err(fatal) => {
            eprintln!("[keyrelay] 内存库不可用: {fatal}");
            std::process::exit(1);
        }
    }
}

/// 注册命令与状态（对任意 Runtime 通用，便于 mock runtime 测试）。
pub fn configure_with_state<R: tauri::Runtime>(
    builder: tauri::Builder<R>,
    state: AppState,
) -> tauri::Builder<R> {
    builder
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::list_sites,
            commands::app_info,
            commands::detect_site,
            commands::add_site,
            commands::login_site,
            commands::list_keys,
            commands::create_key,
            commands::site_balance,
            commands::delivery_plan,
            commands::grant_consent,
            commands::revoke_consent,
            commands::list_consents,
            commands::apply_delivery,
            commands::rollback_delivery,
            commands::recent_events,
            commands::list_stored_keys,
            commands::drift_report,
            commands::get_settings,
            commands::update_settings,
            commands::refresh_all,
            commands::audit_redaction,
            commands::gateway_status,
            commands::gateway_start,
            commands::gateway_stop,
            commands::export_bundle,
            commands::prune_backups,
            // M8-S5A：FR-9:196 诊断包
            commands::export_diagnostics,
            // M6-S5：FR-2 / FR-7 接线
            commands::available_groups,
            commands::sync_site_keys,
            commands::rotation_due,
            commands::rotation_plan,
            commands::rotate_key,
            commands::autostart_status,
            commands::autostart_set,
            // M7-S5：FR-2 回收（B-82）、FR-8 钥匙串清理、FR-4 未托管落点探测（R-7）
            commands::revoke_key,
            commands::purge_keychain,
            commands::detect_unmanaged_targets,
            commands::suggest_key_name,
            // M8-S4：解绑（FR-2:115）、网关令牌轮换（§6.4）
            commands::unbind_agent,
            commands::gateway_rotate_token,
            // M8-S2：人工过验证码（FR-1:102）
            commands::captcha_begin,
            commands::captcha_complete,
            commands::captcha_cancel
        ])
}

pub fn configure<R: tauri::Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
    configure_with_state(builder, init_state())
}

/// 启动时的运维任务（M3-S1）。
///
/// 两条硬约束：
/// 1. **定时刷新默认关闭**（`refresh_interval_secs == 0`）：不替用户决定要不要定时联网；
/// 2. 任务体里**不出现 `unwrap`**：任何失败都转成事件，绝不 panic、绝不退出循环。
///
/// 漂移检测只读本地文件，默认在启动时跑一次。
pub fn spawn_maintenance_tasks<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    use tauri::Manager;

    let Some(state) = app.try_state::<AppState>() else {
        eprintln!("[keyrelay] 拿不到应用状态，跳过运维任务");
        return;
    };
    let settings = match state.service.settings() {
        Ok(settings) => settings,
        Err(err) => {
            eprintln!("[keyrelay] 读取设置失败，使用默认值: {err}");
            Default::default()
        }
    };

    if settings.drift_check_on_start {
        match state.service.drift_report() {
            Ok(reports) => {
                let drifted = reports.iter().filter(|r| r.state.needs_attention()).count();
                if drifted > 0 {
                    eprintln!("[keyrelay] 有 {drifted} 个投递目标被外部改动，详见「变更历史」");
                }
            }
            Err(err) => eprintln!("[keyrelay] 漂移检测失败: {err}"),
        }
    }

    if !settings.scheduler_enabled() {
        return;
    }
    let interval = std::time::Duration::from_secs(settings.refresh_interval_secs);
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            let Some(state) = handle.try_state::<AppState>() else {
                eprintln!("[keyrelay] 后台刷新：拿不到应用状态，退出循环");
                return;
            };
            match state.service.refresh_all().await {
                Ok(summary) => {
                    eprintln!(
                        "[keyrelay] 后台刷新完成: 成功 {} / 失败 {} / 密钥 {} / 告警 {}",
                        summary.sites_ok,
                        summary.sites_failed,
                        summary.keys_total,
                        summary.balance_alerts.len()
                    );
                }
                Err(err) => eprintln!("[keyrelay] 后台刷新失败（下一轮继续）: {err}"),
            }
        }
    });
}

pub fn run() {
    let result = configure(tauri::Builder::default())
        .setup(|app| {
            spawn_maintenance_tasks(app.handle());

            // 托盘（M6-S5 / B-53）。**失败不阻断启动**：无 GUI 会话的环境
            // （CI、SSH、headless）建不出托盘图标，但那不该让整个应用起不来。
            let tray_available = match tray::build(app.handle()) {
                Ok(()) => true,
                Err(err) => {
                    eprintln!("[keyrelay] 托盘图标创建失败（应用继续运行）: {err}");
                    false
                }
            };
            if let Some(state) = app.try_state::<AppState>() {
                state
                    .tray_available
                    .store(tray_available, std::sync::atomic::Ordering::Relaxed);
            }

            // 启动隐藏：命令行 `--hidden` 与设置项 `start_hidden` 任一为真。
            // **托盘不可用时降级为显示窗口**（`should_start_hidden` 的语义）——
            // 否则用户会以为应用根本没启动，而实际上它只是没有入口。
            let hidden_flag = tray::has_hidden_flag(std::env::args());
            let settings = app
                .try_state::<AppState>()
                .and_then(|state| state.service.settings().ok());
            let want_hidden = settings
                .as_ref()
                .map(|s| s.should_start_hidden(hidden_flag, tray_available))
                .unwrap_or(false);
            if want_hidden {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            } else if hidden_flag || settings.map(|s| s.start_hidden).unwrap_or(false) {
                eprintln!(
                    "[keyrelay] 托盘不可用，已忽略「启动时隐藏窗口」的请求：\
                     隐藏之后没有任何入口能把窗口调回来"
                );
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // 关窗 → 隐藏到托盘（默认），除非用户在设置里关掉了 `close_to_tray`，
            // 或托盘压根没建起来（此时隐藏 = 应用不可达）。
            //
            // 为什么每次读设置而不是读一个启动时快照：用户可能在运行中改这个开关，
            // 而关窗行为要立刻跟着变。读库失败时**放行关闭**（fail-open）——
            // 让用户关得掉窗口，比让他关不掉更不容易出事。
            let tauri::WindowEvent::CloseRequested { api, .. } = event else {
                return;
            };
            let handle = window.app_handle();
            let tray_ok = handle
                .try_state::<AppState>()
                .map(|state| {
                    state
                        .tray_available
                        .load(std::sync::atomic::Ordering::Relaxed)
                })
                .unwrap_or(false);
            let hide = handle
                .try_state::<AppState>()
                .and_then(|state| state.service.settings().ok())
                .map(|settings| settings.should_hide_on_close(tray_ok))
                .unwrap_or(false);
            if hide {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!());

    if let Err(err) = result {
        eprintln!("[keyrelay] 应用退出: {err}");
        std::process::exit(1);
    }
}
