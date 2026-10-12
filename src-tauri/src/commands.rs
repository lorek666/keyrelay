//! 前端可调用的命令。保持「薄」：参数校验 + 调服务层 + 转 DTO。
//!
//! 安全约束：`create_key` 返回的密钥只在**返回值**里出现一次，不写日志、不落库。

use serde::{Deserialize, Serialize};
use tauri::State;

use keyrelay_core::delivery::ConsentState;

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
    /// 钥匙串后端标识。`"memory"` 出现在真实运行里即为缺陷（意味着密钥没进系统钥匙串）。
    vault_backend: String,
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
pub struct StoredKeyDto {
    id: i64,
    remote_id: String,
    name: String,
    /// 掩码后的密钥（`…末4位`）。**明文永远不返回给前端**——
    /// 密钥在创建时就直接进了系统钥匙串，前端只负责说「是哪一把」。
    masked: String,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryFieldDto {
    key: String,
    /// 已掩码的值（密钥只暴露末 4 位）
    masked: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryPlanDto {
    agent_id: String,
    channel: String,
    target_path: String,
    target_exists: bool,
    fields: Vec<DeliveryFieldDto>,
    /// **已脱敏**的 diff 预览
    preview: String,
    /// `"missing"` | `"granted"` | `"revoked"`
    consent: String,
    consent_granted_at: Option<i64>,
    consent_revoked_at: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentDto {
    agent_id: String,
    channel: String,
    target_path: String,
    fields: String,
    granted_at: i64,
    revoked_at: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryOutcomeDto {
    channel: String,
    target_path: String,
    journal_id: String,
    backup_path: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventDto {
    id: i64,
    ts: i64,
    level: String,
    source: String,
    /// 已脱敏
    message: String,
    /// 已脱敏
    payload: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DriftReportDto {
    target_path: String,
    agent_id: String,
    channel: String,
    /// `"intact"` | `"modified"` | `"missing"` | `"unknown"`
    state: String,
    journal_id: String,
    current_sha256: Option<String>,
    expected_sha256: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SettingsDto {
    refresh_interval_secs: u64,
    balance_alert_threshold: f64,
    drift_check_on_start: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshSummaryDto {
    sites_total: usize,
    sites_ok: usize,
    sites_failed: usize,
    keys_total: usize,
    balance_alerts: Vec<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSettingsArgs {
    settings: SettingsDto,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryArgs {
    key_id: i64,
    channel: String,
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
        vault_backend: state.service.vault_backend().to_string(),
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
) -> Result<StoredKeyDto, String> {
    let mut spec = keyrelay_core::site::KeySpec::named(args.name);
    spec.group = args.group;
    state
        .service
        .create_key(args.site_id, spec)
        .await
        .map(|key| StoredKeyDto {
            id: key.id,
            remote_id: key.remote_id,
            name: key.name,
            masked: key.masked,
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

// ================================================================ 密钥投递（M1-S3）

fn parse_channel(raw: &str) -> Result<keyrelay_core::delivery::DeliveryChannel, String> {
    keyrelay_core::delivery::DeliveryChannel::parse(raw).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn delivery_plan(
    state: State<'_, AppState>,
    args: DeliveryArgs,
) -> Result<DeliveryPlanDto, String> {
    let channel = parse_channel(&args.channel)?;
    state
        .service
        .delivery_plan(args.key_id, channel)
        .map(|plan| {
            let (consent, granted_at, revoked_at) = match plan.consent {
                ConsentState::Missing => ("missing", None, None),
                ConsentState::Granted { granted_at } => ("granted", Some(granted_at), None),
                ConsentState::Revoked { revoked_at } => ("revoked", None, Some(revoked_at)),
            };
            DeliveryPlanDto {
                agent_id: plan.agent_id,
                channel: plan.channel.as_str().to_string(),
                target_path: plan.target_path.display().to_string(),
                target_exists: plan.target_exists,
                fields: plan
                    .fields
                    .into_iter()
                    .map(|f| DeliveryFieldDto {
                        key: f.key,
                        masked: f.masked,
                    })
                    .collect(),
                preview: plan.preview,
                consent: consent.to_string(),
                consent_granted_at: granted_at,
                consent_revoked_at: revoked_at,
            }
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn grant_consent(state: State<'_, AppState>, args: DeliveryArgs) -> Result<(), String> {
    let channel = parse_channel(&args.channel)?;
    state
        .service
        .grant_consent(args.key_id, channel)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn revoke_consent(state: State<'_, AppState>, args: DeliveryArgs) -> Result<(), String> {
    let channel = parse_channel(&args.channel)?;
    state
        .service
        .revoke_consent(args.key_id, channel)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn list_consents(state: State<'_, AppState>) -> Result<Vec<ConsentDto>, String> {
    state
        .service
        .list_consents()
        .map(|rows| {
            rows.into_iter()
                .map(|row| ConsentDto {
                    agent_id: row.agent_id,
                    channel: row.channel,
                    target_path: row.target_path,
                    fields: row.fields,
                    granted_at: row.granted_at,
                    revoked_at: row.revoked_at,
                })
                .collect()
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn apply_delivery(
    state: State<'_, AppState>,
    args: DeliveryArgs,
) -> Result<DeliveryOutcomeDto, String> {
    let channel = parse_channel(&args.channel)?;
    state
        .service
        .apply_delivery(args.key_id, channel)
        .map(|outcome| DeliveryOutcomeDto {
            channel: outcome.channel.as_str().to_string(),
            target_path: outcome.target_path.display().to_string(),
            journal_id: outcome.journal_id,
            backup_path: outcome.backup_path.map(|p| p.display().to_string()),
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn rollback_delivery(state: State<'_, AppState>, journal_id: String) -> Result<(), String> {
    state
        .service
        .rollback_delivery(&journal_id)
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredKeyRowDto {
    id: i64,
    site_id: i64,
    remote_id: Option<String>,
    name: String,
    group: Option<String>,
    status: String,
}

/// 本地已存密钥（不含密钥本体）。
#[tauri::command]
pub fn list_stored_keys(state: State<'_, AppState>) -> Result<Vec<StoredKeyRowDto>, String> {
    state
        .service
        .stored_keys()
        .map(|rows| {
            rows.into_iter()
                .map(|row| StoredKeyRowDto {
                    id: row.id,
                    site_id: row.site_id,
                    remote_id: row.remote_id,
                    name: row.name,
                    group: row.group_name,
                    status: row.status,
                })
                .collect()
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn recent_events(
    state: State<'_, AppState>,
    limit: Option<usize>,
) -> Result<Vec<EventDto>, String> {
    state
        .service
        .recent_events(limit.unwrap_or(100))
        .map(|rows| {
            rows.into_iter()
                .map(|row| EventDto {
                    id: row.id,
                    ts: row.ts,
                    level: row.level,
                    source: row.source,
                    message: row.message,
                    payload: row.payload,
                })
                .collect()
        })
        .map_err(|e| e.to_string())
}

// ============================================ 漂移 / 设置 / 刷新（M3-S1）

fn settings_from_dto(dto: &SettingsDto) -> keyrelay_core::settings::Settings {
    keyrelay_core::settings::Settings {
        refresh_interval_secs: dto.refresh_interval_secs,
        balance_alert_threshold: dto.balance_alert_threshold,
        drift_check_on_start: dto.drift_check_on_start,
    }
}

fn settings_to_dto(settings: &keyrelay_core::settings::Settings) -> SettingsDto {
    SettingsDto {
        refresh_interval_secs: settings.refresh_interval_secs,
        balance_alert_threshold: settings.balance_alert_threshold,
        drift_check_on_start: settings.drift_check_on_start,
    }
}

#[tauri::command]
pub fn drift_report(state: State<'_, AppState>) -> Result<Vec<DriftReportDto>, String> {
    state
        .service
        .drift_report()
        .map(|reports| {
            reports
                .into_iter()
                .map(|r| DriftReportDto {
                    target_path: r.target_path.display().to_string(),
                    agent_id: r.agent_id,
                    channel: r.channel,
                    state: r.state.as_str().to_string(),
                    journal_id: r.journal_id,
                    current_sha256: r.current_sha256,
                    expected_sha256: r.expected_sha256,
                })
                .collect()
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_settings(state: State<'_, AppState>) -> Result<SettingsDto, String> {
    state
        .service
        .settings()
        .map(|s| settings_to_dto(&s))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn update_settings(
    state: State<'_, AppState>,
    args: UpdateSettingsArgs,
) -> Result<SettingsDto, String> {
    let settings = settings_from_dto(&args.settings);
    state
        .service
        .update_settings(&settings)
        .map_err(|e| e.to_string())?;
    Ok(settings_to_dto(&settings))
}

#[tauri::command]
pub async fn refresh_all(state: State<'_, AppState>) -> Result<RefreshSummaryDto, String> {
    state
        .service
        .refresh_all()
        .await
        .map(|s| RefreshSummaryDto {
            sites_total: s.sites_total,
            sites_ok: s.sites_ok,
            sites_failed: s.sites_failed,
            keys_total: s.keys_total,
            balance_alerts: s.balance_alerts,
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

        let stored = StoredKeyDto {
            id: 3,
            remote_id: "12".into(),
            name: "codex/daily".into(),
            masked: "…cdef".into(),
        };
        let value = to_value(&stored);
        assert_eq!(value["id"], 3);
        assert_eq!(value["remoteId"], "12");
        assert_eq!(value["masked"], "…cdef");
        assert!(
            value.get("secret").is_none(),
            "密钥明文永远不得出现在 DTO 里: {value}"
        );

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
            vault_backend: "memory".into(),
        };
        let value = to_value(&info);
        assert_eq!(value["dbPath"], ":memory:");
        assert_eq!(value["siteCount"], 0);
        assert_eq!(value["dbError"], Value::Null);
        assert_eq!(value["vaultBackend"], "memory");
    }

    /// M1-S3：投递相关 DTO 的线上字段名与「不含密钥」双重断言。
    #[test]
    fn delivery_dtos_serialize_in_camel_case_without_secrets() {
        let plan = DeliveryPlanDto {
            agent_id: "codex".into(),
            channel: "codex-auth-json".into(),
            target_path: "/home/u/.codex/auth.json".into(),
            target_exists: false,
            fields: vec![
                DeliveryFieldDto {
                    key: "auth_mode".into(),
                    masked: "apikey".into(),
                },
                DeliveryFieldDto {
                    key: "OPENAI_API_KEY".into(),
                    masked: "…cdef".into(),
                },
            ],
            preview: "+ \"OPENAI_API_KEY\": \"…cdef\"\n".into(),
            consent: "missing".into(),
            consent_granted_at: None,
            consent_revoked_at: None,
        };
        let value = to_value(&plan);
        assert_eq!(value["agentId"], "codex");
        assert_eq!(value["targetPath"], "/home/u/.codex/auth.json");
        assert_eq!(value["targetExists"], false);
        assert_eq!(value["fields"][1]["key"], "OPENAI_API_KEY");
        assert_eq!(value["fields"][1]["masked"], "…cdef");
        assert_eq!(value["consent"], "missing");
        assert_eq!(value["consentGrantedAt"], Value::Null);
        assert!(value.get("target_path").is_none(), "不得出现 snake_case");

        let outcome = DeliveryOutcomeDto {
            channel: "codex-auth-json".into(),
            target_path: "/home/u/.codex/auth.json".into(),
            journal_id: "j1-0".into(),
            backup_path: Some("/home/u/.keyrelay/backups/j1-0/0-auth.json".into()),
        };
        let value = to_value(&outcome);
        assert_eq!(value["journalId"], "j1-0");
        assert_eq!(
            value["backupPath"],
            "/home/u/.keyrelay/backups/j1-0/0-auth.json"
        );
        assert!(
            !value.to_string().contains("sk-"),
            "投递结果不得携带密钥: {value}"
        );

        let event = EventDto {
            id: 1,
            ts: 1_700_000_000,
            level: "info".into(),
            source: "delivery".into(),
            message: "投递完成: codex-auth-json".into(),
            payload: Some(r#"{"journal_id":"j1-0"}"#.into()),
        };
        let value = to_value(&event);
        assert_eq!(value["level"], "info");
        assert_eq!(value["source"], "delivery");
        assert!(value["payload"].is_string());

        let consent = ConsentDto {
            agent_id: "codex".into(),
            channel: "codex-auth-json".into(),
            target_path: "/home/u/.codex/auth.json".into(),
            fields: r#"["auth_mode","OPENAI_API_KEY"]"#.into(),
            granted_at: 1,
            revoked_at: None,
        };
        let value = to_value(&consent);
        assert_eq!(value["agentId"], "codex");
        assert_eq!(value["grantedAt"], 1);
        assert_eq!(value["revokedAt"], Value::Null);
    }

    #[test]
    fn delivery_args_deserialize_from_camel_case() {
        let args: DeliveryArgs = serde_json::from_value(serde_json::json!({
            "keyId": 7,
            "channel": "codex-auth-json"
        }))
        .expect("解析 DeliveryArgs");
        assert_eq!(args.key_id, 7);
        assert_eq!(args.channel, "codex-auth-json");
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
