//! 前端可调用的命令。保持「薄」：参数校验 + 调服务层 + 转 DTO。
//!
//! 安全约束：`create_key` 返回的密钥只在**返回值**里出现一次，不写日志、不落库。

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::AppState;

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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteSummaryDto {
    id: i64,
    kind: String,
    base_url: String,
    display_name: String,
    health: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteFingerprintDto {
    kind: String,
    display_name: String,
    version: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyMetaDto {
    remote_id: String,
    name: String,
    group: Option<String>,
    status: String,
    created_at: Option<i64>,
    last_used_at: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyMaterialDto {
    remote_id: String,
    /// 明文密钥：仅在创建成功时返回一次，前端展示后由 M1-S2 收进钥匙串
    secret: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceDto {
    currency: String,
    remaining: f64,
    used: f64,
    raw_quota: Option<i64>,
    quota_per_unit: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginArgs {
    site_id: i64,
    username: String,
    password: String,
    second_factor: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateKeyArgs {
    site_id: i64,
    name: String,
    group: Option<String>,
}

#[tauri::command]
pub fn list_sites(state: State<'_, AppState>) -> Result<Vec<SiteSummaryDto>, String> {
    state
        .service
        .sites()
        .map(|rows| {
            rows.into_iter()
                .map(|row| SiteSummaryDto {
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
    let site_count = state.service.sites().map_err(|e| e.to_string())?.len();
    Ok(AppInfoDto {
        name: "KeyRelay".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        db_path: state.db_path.display().to_string(),
        site_count,
        db_error: state.db_error.clone(),
    })
}

#[tauri::command]
pub async fn detect_site(base_url: String) -> Result<SiteFingerprintDto, String> {
    crate::detect_only(&base_url)
        .await
        .map(|fingerprint| SiteFingerprintDto {
            kind: fingerprint.kind.as_str().to_string(),
            display_name: fingerprint.display_name,
            version: fingerprint.version,
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn add_site(
    state: State<'_, AppState>,
    base_url: String,
) -> Result<SiteSummaryDto, String> {
    state
        .service
        .add_site(&base_url)
        .await
        .map(|row| SiteSummaryDto {
            id: row.id,
            kind: row.kind,
            base_url: row.base_url,
            display_name: row.display_name,
            health: row.health,
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn login_site(state: State<'_, AppState>, args: LoginArgs) -> Result<(), String> {
    let mut credentials = keyrelay_core::site::Credentials::new(args.username, args.password);
    if let Some(code) = args.second_factor {
        credentials = credentials.with_second_factor(code);
    }
    state
        .service
        .login(args.site_id, credentials)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_keys(
    state: State<'_, AppState>,
    site_id: i64,
) -> Result<Vec<KeyMetaDto>, String> {
    state
        .service
        .list_keys(site_id)
        .await
        .map(|keys| {
            keys.into_iter()
                .map(|key| KeyMetaDto {
                    remote_id: key.remote_id,
                    name: key.name,
                    group: key.group,
                    status: key.status.as_str().to_string(),
                    created_at: key.created_at,
                    last_used_at: key.last_used_at,
                })
                .collect()
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn create_key(
    state: State<'_, AppState>,
    args: CreateKeyArgs,
) -> Result<KeyMaterialDto, String> {
    let mut spec = keyrelay_core::site::KeySpec::named(args.name);
    spec.group = args.group;
    state
        .service
        .create_key(args.site_id, spec)
        .await
        .map(|material| KeyMaterialDto {
            remote_id: material.remote_id,
            secret: material.secret,
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn site_balance(state: State<'_, AppState>, site_id: i64) -> Result<BalanceDto, String> {
    state
        .service
        .balance(site_id)
        .await
        .map(|balance| BalanceDto {
            currency: balance.currency,
            remaining: balance.remaining,
            used: balance.used,
            raw_quota: balance.raw_quota,
            quota_per_unit: balance.quota_per_unit,
        })
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn to_value<T: Serialize>(value: &T) -> Value {
        serde_json::to_value(value).expect("序列化 DTO")
    }

    /// 复审 P2-4：IPC 测试此前只覆盖「命令可达」，没有返回值结构断言。
    /// 这里把每个 DTO 的线上字段名钉死，改字段名（含 snake_case 回归）会立刻失败。
    #[test]
    fn dtos_serialize_in_camel_case_with_expected_keys() {
        let summary = SiteSummaryDto {
            id: 1,
            kind: "newapi".into(),
            base_url: "https://relay.example.com".into(),
            display_name: "测试站".into(),
            health: "unknown".into(),
        };
        let value = to_value(&summary);
        assert_eq!(value["id"], 1);
        assert_eq!(value["kind"], "newapi");
        assert_eq!(value["baseUrl"], "https://relay.example.com");
        assert_eq!(value["displayName"], "测试站");
        assert_eq!(value["health"], "unknown");
        assert!(
            value.get("base_url").is_none(),
            "不得出现 snake_case: {value}"
        );

        let fingerprint = SiteFingerprintDto {
            kind: "newapi".into(),
            display_name: "测试站".into(),
            version: Some("v0.9.1".into()),
        };
        let value = to_value(&fingerprint);
        assert_eq!(value["displayName"], "测试站");
        assert_eq!(value["version"], "v0.9.1");

        let material = KeyMaterialDto {
            remote_id: "12".into(),
            secret: "sk-dto-shape-test".into(),
        };
        let value = to_value(&material);
        assert_eq!(value["remoteId"], "12");
        assert_eq!(value["secret"], "sk-dto-shape-test");

        let meta = KeyMetaDto {
            remote_id: "12".into(),
            name: "codex/daily".into(),
            group: Some("default".into()),
            status: "enabled".into(),
            created_at: Some(1_700_000_000),
            last_used_at: None,
        };
        let value = to_value(&meta);
        assert_eq!(value["remoteId"], "12");
        assert_eq!(value["createdAt"], 1_700_000_000_i64);
        assert_eq!(value["lastUsedAt"], Value::Null);

        let balance = BalanceDto {
            currency: "USD".into(),
            remaining: 1.5,
            used: 0.5,
            raw_quota: Some(750_000),
            quota_per_unit: Some(500_000),
        };
        let value = to_value(&balance);
        assert_eq!(value["rawQuota"], 750_000);
        assert_eq!(value["quotaPerUnit"], 500_000);

        let info = AppInfoDto {
            name: "KeyRelay".into(),
            version: "0.1.0".into(),
            db_path: ":memory:".into(),
            site_count: 0,
            db_error: None,
        };
        let value = to_value(&info);
        assert_eq!(value["dbPath"], ":memory:");
        assert_eq!(value["siteCount"], 0);
        assert_eq!(value["dbError"], Value::Null);
    }

    #[test]
    fn command_args_deserialize_from_camel_case() {
        let login: LoginArgs = serde_json::from_value(serde_json::json!({
            "siteId": 7,
            "username": "me",
            "password": "pw",
            "secondFactor": "123456"
        }))
        .expect("解析 LoginArgs");
        assert_eq!(login.site_id, 7);
        assert_eq!(login.second_factor.as_deref(), Some("123456"));

        let create: CreateKeyArgs = serde_json::from_value(serde_json::json!({
            "siteId": 7,
            "name": "codex/daily",
            "group": "default"
        }))
        .expect("解析 CreateKeyArgs");
        assert_eq!(create.site_id, 7);
        assert_eq!(create.group.as_deref(), Some("default"));
    }
}
