//! Tauri 桌面壳：只做「命令注册 + 状态管理 + 平台胶水」。
//!
//! 业务逻辑一律在 `keyrelay-core`，本 crate 不出现 SQL、HTTP、文件改写逻辑。

mod commands;

use std::path::PathBuf;

use keyrelay_core::store::Store;

pub struct AppState {
    pub store: Store,
    pub db_path: PathBuf,
    /// 数据库打开失败时的原因（用于在 UI 上明确提示，而不是静默降级）
    pub db_error: Option<String>,
}

/// `~/.keyrelay/keyrelay.db`
pub fn default_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".keyrelay").join("keyrelay.db")
}

fn init_state() -> AppState {
    let db_path = default_db_path();
    match Store::open(&db_path) {
        Ok(store) => AppState {
            store,
            db_path,
            db_error: None,
        },
        Err(err) => {
            eprintln!("[keyrelay] 打开本地数据库失败，回退到内存库: {err}");
            match Store::open_in_memory() {
                Ok(store) => AppState {
                    store,
                    db_path,
                    db_error: Some(err.to_string()),
                },
                Err(fatal) => {
                    eprintln!("[keyrelay] 内存库也不可用，退出: {fatal}");
                    std::process::exit(1);
                }
            }
        }
    }
}

pub fn run() {
    let state = init_state();

    let result = tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::list_sites,
            commands::app_info
        ])
        .run(tauri::generate_context!());

    if let Err(err) = result {
        eprintln!("[keyrelay] 应用退出: {err}");
        std::process::exit(1);
    }
}
