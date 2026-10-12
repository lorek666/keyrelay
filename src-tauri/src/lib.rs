//! Tauri 桌面壳：只做「命令注册 + 状态管理 + 平台胶水」。
//!
//! 业务逻辑一律在 `keyrelay-core`，本 crate 不出现 SQL、HTTP、文件改写逻辑。
//!
//! `configure` / `configure_with_state` 之所以单独暴露，是为了让 IPC 测试
//! （`tests/commands.rs`）能用 Tauri 官方 mock runtime 复用同一套命令注册。

mod commands;
pub mod commands_list;

use std::path::PathBuf;

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
    let tmp = std::env::temp_dir().join(format!("keyrelay-test-{}", std::process::id()));
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
            commands::audit_redaction
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
            Ok(())
        })
        .run(tauri::generate_context!());

    if let Err(err) = result {
        eprintln!("[keyrelay] 应用退出: {err}");
        std::process::exit(1);
    }
}
