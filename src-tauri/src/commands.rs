//! 前端可调用的命令。保持「薄」：参数校验 + 调 core + 转 DTO。

use serde::Serialize;
use tauri::State;

use crate::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteDto {
    id: i64,
    kind: String,
    base_url: String,
    display_name: String,
    health: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfoDto {
    name: String,
    version: String,
    db_path: String,
    site_count: usize,
    /// 数据库降级原因（正常为 null）
    db_error: Option<String>,
}

#[tauri::command]
pub fn list_sites(state: State<'_, AppState>) -> Result<Vec<SiteDto>, String> {
    state
        .store
        .list_sites()
        .map(|rows| {
            rows.into_iter()
                .map(|row| SiteDto {
                    id: row.id,
                    kind: row.kind,
                    base_url: row.base_url,
                    display_name: row.display_name,
                    health: row.health,
                })
                .collect()
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn app_info(state: State<'_, AppState>) -> Result<AppInfoDto, String> {
    let site_count = state.store.list_sites().map_err(|e| e.to_string())?.len();
    Ok(AppInfoDto {
        name: "KeyRelay".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        db_path: state.db_path.display().to_string(),
        site_count,
        db_error: state.db_error.clone(),
    })
}
