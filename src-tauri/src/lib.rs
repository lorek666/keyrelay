//! Tauri 桌面壳：只做「命令注册 + 状态管理 + 平台胶水」。
//!
//! 业务逻辑一律在 `keyrelay-core`，本 crate 不出现 SQL、HTTP、文件改写逻辑。
//!
//! `configure` / `configure_with_state` 之所以单独暴露，是为了让 IPC 测试
//! （`tests/commands.rs`）能用 Tauri 官方 mock runtime 复用同一套命令注册。

mod commands;
pub mod commands_list;

use std::path::PathBuf;

use keyrelay_core::service::KeyRelayService;
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

/// `~/.keyrelay/keyrelay.db`
pub fn default_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".keyrelay").join("keyrelay.db")
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
    AppState {
        service: KeyRelayService::new(store, build_transport()),
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
        Ok(store) => state_from_store(store, PathBuf::from(":memory:"), None),
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
            commands::site_balance
        ])
}

pub fn configure<R: tauri::Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
    configure_with_state(builder, init_state())
}

pub fn run() {
    let result = configure(tauri::Builder::default()).run(tauri::generate_context!());

    if let Err(err) = result {
        eprintln!("[keyrelay] 应用退出: {err}");
        std::process::exit(1);
    }
}
