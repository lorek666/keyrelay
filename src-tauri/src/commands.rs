//! 前端可调用的命令。保持「薄」：参数校验 + 调服务层 + 转 DTO。
//!
//! 安全约束：`create_key` 返回的密钥只在**返回值**里出现一次，不写日志、不落库。

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};

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
    /// 该站点类型的**设计能力**（M7-S5 / M7-S2 的 `capabilities()`）。
    ///
    /// 界面用它灰显按钮，**不得**在页面里按 `kind` 硬编码判断——否则新增站点类型时
    /// 每加一个页面都要改一次，而漏掉的那一处会给出一个点了才报错的按钮。
    capabilities: SiteCapabilitiesDto,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteCapabilitiesDto {
    login: bool,
    list_keys: bool,
    create_key: bool,
    reveal_key: bool,
    revoke_key: bool,
    balance: bool,
    groups: bool,
    key_usage: bool,
}

impl SiteCapabilitiesDto {
    fn from_kind(kind: keyrelay_core::site::SiteKind) -> Self {
        let caps = keyrelay_core::site::capability::capabilities(kind);
        Self {
            login: caps.login,
            list_keys: caps.list_keys,
            create_key: caps.create_key,
            reveal_key: caps.reveal_key,
            revoke_key: caps.revoke_key,
            balance: caps.balance,
            groups: caps.groups,
            key_usage: caps.key_usage,
        }
    }

    /// 解析不出站点类型时的**兜底**：全部 `false`。
    ///
    /// 这是 fail-closed 的方向——界面会把按钮全灰掉，用户看到一个明确的空状态；
    /// 反过来（猜一个「什么都能做」）会给出点了才报错的按钮，而报的错还是别的原因。
    fn none() -> Self {
        Self {
            login: false,
            list_keys: false,
            create_key: false,
            reveal_key: false,
            revoke_key: false,
            balance: false,
            groups: false,
            key_usage: false,
        }
    }
}

impl SiteSummaryDto {
    fn from_row(row: keyrelay_core::service::SiteSummary) -> Self {
        let capabilities = match keyrelay_core::site::SiteKind::parse(&row.kind) {
            Some(kind) => SiteCapabilitiesDto::from_kind(kind),
            None => SiteCapabilitiesDto::none(),
        };
        Self {
            id: row.id,
            kind: row.kind,
            base_url: row.base_url,
            display_name: row.display_name,
            health: row.health,
            capabilities,
        }
    }
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
    /// **该站点的余额是否可观测**（M7-S5 接线，M7-S2 定义）。
    ///
    /// `false` 时下面两个数值字段是 `null`——这是**结构性保证**：界面拿不到 0.00，
    /// 也就不可能把它渲染成 0.00。`custom-openai-compatible` 站点永远是 `false`。
    known: bool,
    remaining: Option<f64>,
    used: Option<f64>,
    raw_quota: Option<i64>,
    quota_per_unit: Option<i64>,
}

impl BalanceDto {
    fn from_balance(balance: keyrelay_core::site::Balance) -> Self {
        // 未知态一律把数值字段置 `null`：不要「反正它是 0」把它们照传——
        // 那等于把「不知道」伪装成「余额为零」，而这两件事在界面上必须能分开。
        let (remaining, used) = if balance.known {
            (Some(balance.remaining), Some(balance.used))
        } else {
            (None, None)
        };
        Self {
            currency: balance.currency,
            known: balance.known,
            remaining,
            used,
            raw_quota: balance.raw_quota,
            quota_per_unit: balance.quota_per_unit,
        }
    }
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
    /// `"site"` | `"gateway"`（M8-S4 §6.6）。网关模式下写进去的是**本地令牌**，
    /// 而两种模式的字段名一模一样（`apiKey` / `apiBase`）⇒ 不说用户分不清。
    mode: String,
    fields: Vec<DeliveryFieldDto>,
    /// **已脱敏**的 diff 预览
    preview: String,
    /// `"missing"` | `"granted"` | `"revoked"`
    consent: String,
    consent_granted_at: Option<i64>,
    consent_revoked_at: Option<i64>,
    /// 提示项（**不是错误**）。当前只有一条来源：同目录下存在「同主名、不同扩展名」
    /// 的兄弟文件，可能被 agent 优先读取，从而让本次投递静默不生效（BACKLOG B-76）。
    warnings: Vec<String>,
    /// 投递后该 agent 是否需要重启才读到新配置（PRD FR-4:137）。
    ///
    /// 取值只能来自 `delivery::restart_hint(channel)`——**界面不得自己判断**。
    /// 这里是**穷举 match**（没有 `_` 分支）：新增一条通道时它会编译失败，
    /// 而不是悄悄给出一个空提示。
    restart_hint: &'static str,
}

/// [`keyrelay_core::delivery::RestartHint`] 的线格式。
///
/// 为什么这个映射在命令层而不是核心层：核心的 `delivery/mod.rs` 在本波次是
/// M7-S3 的写域、且正处于复审冻结期；把它放在这里不改变任何语义
/// （穷举 match 保证新增变体会编译失败），等 `delivery` 解冻后再收进去。
fn restart_hint_str(hint: keyrelay_core::delivery::RestartHint) -> &'static str {
    use keyrelay_core::delivery::RestartHint;
    match hint {
        RestartHint::NotNeeded => "notNeeded",
        RestartHint::Needed => "needed",
        RestartHint::DependsOnNewSession => "dependsOnNewSession",
    }
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

/// 一条「已投递且未解绑」的通道绑定（M8-S7 / B-116）。
///
/// **没有 `channel` 字段，这是有意的**：`bindings` 表没有 channel 列，只有
/// `agent_id` 与 `target_path`。后端 `DeliveryChannel::relative_target()` 是按**当前**
/// home 解析的，而绑定里的 `target_path` 可能是当年另一个 home 下写的 ⇒ 后端猜会猜错。
/// 前端有 `CHANNELS` 那张按 agent 分组的表，用 `agentId` + 文件名二分得到 channel，
/// 猜错的代价也更小。职责划分写在这里，免得下一个人「顺手补一个 channel 字段」。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelBindingDto {
    /// 绑定行自己的 id（M8-S7 P2-4）。**不是**可选项：`bindings` 没有 UNIQUE 约束，
    /// 「换 key 后重投」会在同一文件上留下多条 `unbound_at IS NULL` 的行，
    /// 前端要用它做 React key 与勾选键——用 `${channel}::${targetPath}` 会让那两行
    /// 共用一个复选框（勾一个等于勾两个）并报重复 key。
    pub binding_id: i64,
    pub agent_id: String,
    pub key_id: i64,
    pub target_path: String,
    /// 该 key 所属站点（界面要显示「这条指向哪个站」）。
    pub site_id: i64,
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
    /// `"intact"` | `"modified"` | `"missing"` | `"unreadable"` | `"unknown"`
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
    gateway_enabled: bool,
    gateway_port: u16,
    // ---- M6-S5：FR-9 界面与隐私 ----
    theme: String,
    language: String,
    proxy_url: String,
    telemetry_enabled: bool,
    auto_update_enabled: bool,
    // ---- M6-S5：FR-3 通知 ----
    notify_system_enabled: bool,
    notify_webhook_url: String,
    notify_timeout_secs: u64,
    // ---- M6-S5：FR-7 轮换与常驻 ----
    rotation_max_age_days: u32,
    rotation_warn_before_days: u32,
    autostart_enabled: bool,
    close_to_tray: bool,
    start_hidden: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshSummaryDto {
    sites_total: usize,
    sites_ok: usize,
    sites_failed: usize,
    keys_total: usize,
    balance_alerts: Vec<i64>,
    /// 需要重新登录的站点 id（M5-S5 接线 / B-61）。升序去重。
    ///
    /// 与 `sites_failed` 的关系：当轮认证失败的站点**两边都有**（它确实失败了，
    /// 也确实需要重新登录）；上一轮就已经失效、本轮被跳过的站点**只在这里**。
    needs_login: Vec<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditFindingDto {
    /// `"plaintext-in-file"` | `"unreadable"` | `"plaintext-in-events"`
    kind: String,
    path: Option<String>,
    detail: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditReportDto {
    files_scanned: usize,
    bytes_scanned: u64,
    clean: bool,
    findings: Vec<AuditFindingDto>,
    summary: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSettingsArgs {
    settings: SettingsDto,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayStatusDto {
    running: bool,
    url: Option<String>,
    /// 本地令牌：**只在这里返回给 UI 显示**，不写日志、不入库。
    token: Option<String>,
    site: Option<String>,
    /// 令牌是否**已持久化**（M8-S4 §6.4 第 5 条）。
    ///
    /// `false` = 临时令牌（钥匙串不可用），**重启后会变** ⇒ 指向网关的通道需要重新投递。
    /// 降级必须说出来：不说的话用户会以为「换站零改动」成立了，直到 agent 开始 401。
    /// 取值是**最近一次**装配 / 轮换的结果（网关没在跑时也照报）。
    token_persistent: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayStartArgs {
    site_id: i64,
    key_id: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportResultDto {
    path: String,
    encrypted: bool,
    bytes: usize,
    /// 是否登记进「已知导出物」表。`false` = 文件写成了，但**审计看不到它**。
    /// 界面必须把这件事说出来，不能让用户以为「审计会兜住」。
    registered: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportArgs {
    /// 空/缺省 = 明文导出
    password: Option<String>,
    /// 缺省写到 `~/.keyrelay/exports/keyrelay-export-<时间戳>.json`
    path: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PruneResultDto {
    removed: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PruneArgs {
    keep: usize,
}

/// 诊断包默认带上多少条事件。
///
/// **PRD FR-9:196 逐字规定「最近 500 条事件」**——这里不是随手挑的数：
/// 报障时用户往往是在「刷新完一圈之后」来导包的，条数少了会把出事那几轮挤出去。
/// 上限由核心层 `recent_events` 夹到 1000。
const DEFAULT_DIAGNOSTIC_EVENTS: usize = 500;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsResultDto {
    path: String,
    bytes: usize,
    /// 实际写进去的事件条数（用户报障时第一句会问「带了多少条」）。
    events: usize,
    /// 是否登记进「已知导出物」表。`false` = 文件写成了，但**审计看不到它**。
    registered: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsArgs {
    /// 事件条数上限（缺省 500 = PRD FR-9:196 的口径）。
    limit: Option<usize>,
    /// 缺省写到 `~/.keyrelay/exports/keyrelay-diagnostics-<时间戳>.json`
    path: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryArgs {
    key_id: i64,
    channel: String,
    /// 模型名（可缺）。Continue 通道必须有：Continue 的 schema 把条目的 `model` 定为必填。
    /// 只有预览与投递两条命令读它；同意的授予 / 撤销与模型名无关。
    model: Option<String>,
    /// 投递模式（M8-S4 §6.2）：`"site"`（默认，缺省即此）或 `"gateway"`。
    ///
    /// 缺省 = 站点模式 ⇒ **既有调用点的行为一字不变**。认不出的取值直接拒绝，
    /// 不静默回退（回退会把「指向网关」的请求当成站点投递）。
    mode: Option<String>,
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
        .map(|rows| rows.into_iter().map(SiteSummaryDto::from_row).collect())
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
        .map(SiteSummaryDto::from_row)
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
        .map(BalanceDto::from_balance)
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
    // 模式解析与端点都在**动手之前**：`"gateway"` 但网关没在跑 ⇒ 在这里拒绝，
    // 而不是写出一个指向空地址的配置。
    let mode = parse_delivery_mode(args.mode.as_deref())?;
    let endpoint = match mode {
        keyrelay_core::delivery::DeliveryMode::Site => None,
        keyrelay_core::delivery::DeliveryMode::LocalGateway => Some(gateway_endpoint_of(&state)?),
    };
    let source = match &endpoint {
        Some(endpoint) => keyrelay_core::delivery::DeliverySource::Gateway(endpoint),
        None => keyrelay_core::delivery::DeliverySource::Site,
    };
    state
        .service
        .delivery_plan_in(args.key_id, channel, args.model.as_deref(), source)
        .map(|plan| {
            let (consent, granted_at, revoked_at) = match plan.consent {
                ConsentState::Missing => ("missing", None, None),
                ConsentState::Granted { granted_at } => ("granted", Some(granted_at), None),
                ConsentState::Revoked { revoked_at } => ("revoked", None, Some(revoked_at)),
            };
            // BACKLOG B-76：有些 agent 会优先读**另一个扩展名**的同名文件
            // （本机实测 `~/.config/opencode/` 下 `.json` 与 `.jsonc` 并存）。
            // 写进 A 而 agent 读 B 时投递会**静默不生效**——用户看到「已投递成功」，
            // agent 却拿不到 key，且没有任何报错。这里只提示，不阻断。
            let warnings = delivery_warnings(&plan.target_path);
            DeliveryPlanDto {
                agent_id: plan.agent_id,
                channel: plan.channel.as_str().to_string(),
                target_path: plan.target_path.display().to_string(),
                target_exists: plan.target_exists,
                mode: plan.mode.as_str().to_string(),
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
                warnings,
                restart_hint: restart_hint_str(keyrelay_core::delivery::restart_hint(plan.channel)),
            }
        })
        .map_err(|e| e.to_string())
}

/// 投递预览的提示项。**不是错误**：投递照常可以做，只是用户该知道这件事。
///
/// 只对普通文件给提示（目录不算）。文案里带**文件名**而不是全路径——
/// 全路径在 UI 上已经显示过了，这里补的是「还有哪个兄弟文件」。
fn delivery_warnings(target: &std::path::Path) -> Vec<String> {
    let siblings = keyrelay_core::service::sibling_config_files(target);
    if siblings.is_empty() {
        return Vec::new();
    }
    let names: Vec<String> = siblings
        .iter()
        .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .collect();
    vec![format!(
        "同目录下还有 {}。如果这个 agent 优先读它，本次投递会被静默忽略——\
         请确认 agent 实际读的是哪个文件",
        names.join("、")
    )]
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

/// 已投递且**未解绑**的通道绑定（M8-S7 / B-116）。
///
/// 只读 `bindings`（`unbound_at IS NULL`），不写任何东西——调用前后库内容逐字节相同
/// （有测试钉住）。批量改指网关用它决定「有哪些通道要改、每条该用哪把 key 重投」。
#[tauri::command]
pub fn list_channel_bindings<R: tauri::Runtime>(
    _app: AppHandle<R>,
    state: State<'_, AppState>,
) -> Result<Vec<ChannelBindingDto>, String> {
    state
        .service
        .channel_bindings()
        .map(|rows| {
            rows.into_iter()
                .filter(|row| row.unbound_at.is_none())
                .map(|row| ChannelBindingDto {
                    binding_id: row.id,
                    agent_id: row.agent_id,
                    key_id: row.key_id,
                    target_path: row.target_path,
                    site_id: row.site_id,
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
    let mode = parse_delivery_mode(args.mode.as_deref())?;
    let endpoint = match mode {
        keyrelay_core::delivery::DeliveryMode::Site => None,
        keyrelay_core::delivery::DeliveryMode::LocalGateway => Some(gateway_endpoint_of(&state)?),
    };
    let source = match &endpoint {
        Some(endpoint) => keyrelay_core::delivery::DeliverySource::Gateway(endpoint),
        None => keyrelay_core::delivery::DeliverySource::Site,
    };
    state
        .service
        .apply_delivery_in(args.key_id, channel, args.model.as_deref(), source)
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
        gateway_enabled: dto.gateway_enabled,
        gateway_port: dto.gateway_port,
        theme: dto.theme.clone(),
        language: dto.language.clone(),
        proxy_url: dto.proxy_url.clone(),
        telemetry_enabled: dto.telemetry_enabled,
        auto_update_enabled: dto.auto_update_enabled,
        notify_system_enabled: dto.notify_system_enabled,
        notify_webhook_url: dto.notify_webhook_url.clone(),
        notify_timeout_secs: dto.notify_timeout_secs,
        rotation_max_age_days: dto.rotation_max_age_days,
        rotation_warn_before_days: dto.rotation_warn_before_days,
        autostart_enabled: dto.autostart_enabled,
        close_to_tray: dto.close_to_tray,
        start_hidden: dto.start_hidden,
    }
}

fn settings_to_dto(settings: &keyrelay_core::settings::Settings) -> SettingsDto {
    SettingsDto {
        refresh_interval_secs: settings.refresh_interval_secs,
        balance_alert_threshold: settings.balance_alert_threshold,
        drift_check_on_start: settings.drift_check_on_start,
        gateway_enabled: settings.gateway_enabled,
        gateway_port: settings.gateway_port,
        theme: settings.theme.clone(),
        language: settings.language.clone(),
        proxy_url: settings.proxy_url.clone(),
        telemetry_enabled: settings.telemetry_enabled,
        auto_update_enabled: settings.auto_update_enabled,
        notify_system_enabled: settings.notify_system_enabled,
        notify_webhook_url: settings.notify_webhook_url.clone(),
        notify_timeout_secs: settings.notify_timeout_secs,
        rotation_max_age_days: settings.rotation_max_age_days,
        rotation_warn_before_days: settings.rotation_warn_before_days,
        autostart_enabled: settings.autostart_enabled,
        close_to_tray: settings.close_to_tray,
        start_hidden: settings.start_hidden,
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

// ============================================ 网关 / 导出 / 备份清理（M4-S2）

fn gateway_status_of(state: &AppState) -> GatewayStatusDto {
    // 「令牌是不是持久的」两个分支都用**同一个来源**：服务上「最近一次装配 / 轮换」的结果。
    // 网关没在跑时它不是「没意义」，而是「最近一次的结果」——冷启动时可能是 `false`
    // （本次会话还没装配过），而界面只在 `running` 时显示这个字段，所以不会有误导。
    // 反过来，如果这里硬编码 `false`，一次成功的「重新生成令牌」就会在停止状态下
    // 被报成「临时令牌」——那才是真的在说假话。
    let token_persistent = state.service.gateway_token_persistent();
    let empty = GatewayStatusDto {
        running: false,
        url: None,
        token: None,
        site: None,
        token_persistent,
    };
    let Ok(guard) = state.gateway.lock() else {
        return empty;
    };
    match guard.as_ref() {
        Some(handle) => GatewayStatusDto {
            running: true,
            url: Some(handle.local_url()),
            token: Some(handle.token.clone()),
            site: Some(handle.site_display_name.clone()),
            token_persistent,
        },
        None => empty,
    }
}

/// 运行中网关的「指向网关」端点：`<local_url>/v1` + 本地令牌（M8-S4 §6.1）。
///
/// 拼 `/v1` 是硬要求：网关只服务 `/health` 与 `/v1/*`，而 `local_url()` 没有路径段。
/// 少拼一次的表现是「投递成功、agent 404」——那是最难查的一类失败。
///
/// 网关没在跑 ⇒ 明确拒绝：此时**没有**可信的地址可写（端口来自设置，但网关没跑时
/// 写下去只会让 agent 连不上）。这不是限制，是把「指向网关」的定义执行到底。
fn gateway_endpoint_of(
    state: &State<'_, AppState>,
) -> Result<keyrelay_core::delivery::GatewayEndpoint, String> {
    let guard = state
        .gateway
        .lock()
        .map_err(|_| "网关状态锁失效（需要重启应用）".to_string())?;
    let handle = guard.as_ref().ok_or_else(|| {
        "本地网关没有在运行：请先在「网关」页启动它，再把通道改为指向网关。".to_string()
    })?;
    Ok(keyrelay_core::delivery::GatewayEndpoint {
        base_url: format!("{}/v1", handle.local_url()),
        token: handle.token.clone(),
    })
}

/// 解析投递模式。`None` / 空 / `"site"` ⇒ 站点模式（**既有调用点的行为一字不变**）。
///
/// 认不出的取值 ⇒ `Err`，**不**回退成默认：静默回退会让「指向网关」的请求被当成站点投递，
/// 而用户以为已经切过去了。
fn parse_delivery_mode(raw: Option<&str>) -> Result<keyrelay_core::delivery::DeliveryMode, String> {
    match raw.map(str::trim) {
        None | Some("") | Some("site") => Ok(keyrelay_core::delivery::DeliveryMode::Site),
        Some("gateway") => Ok(keyrelay_core::delivery::DeliveryMode::LocalGateway),
        Some(other) => Err(format!(
            "未知的投递模式 {other:?}；只支持 \"site\" 与 \"gateway\""
        )),
    }
}

#[tauri::command]
pub fn gateway_status(state: State<'_, AppState>) -> Result<GatewayStatusDto, String> {
    Ok(gateway_status_of(&state))
}

/// 等待网关真正停止的**上界**（M5-S5 接线 / 处置 M5-S4 复审 P2-1）。
///
/// `GatewayHandle::shutdown_and_wait()` 本身没有上界：上游卡住且仍有客户端在等时，
/// 它要等在途连接收尾才返回。命令层不能因此把 `gateway_op` 操作锁一直占着 ——
/// 那会把后续的 `gateway_start` / `gateway_stop` 一起挂死。
///
/// **为什么超时是安全的**：`shutdown_and_wait` 先发停止信号**再** await，
/// 而 axum 收到信号后先 `drop(listener)`、然后才等在途连接 ——
/// 端口在信号之后就已经能重新绑定（M5-S4 复审探针实测 2.6ms）。
/// 超时只是放弃「等在途连接收尾」，不影响端口释放，所以照样可以接着 bind。
const GATEWAY_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// 停止一个网关句柄，最多等 `GATEWAY_SHUTDOWN_TIMEOUT`。
///
/// 超时只留一行 stderr，不向上报错：调用方接下来要做的（释放句柄槽、重新 bind）
/// 都不依赖「在途连接是否收尾完成」。
async fn stop_gateway(handle: keyrelay_core::gateway::GatewayHandle) {
    match tokio::time::timeout(GATEWAY_SHUTDOWN_TIMEOUT, handle.shutdown_and_wait()).await {
        Ok(()) => {}
        Err(_) => eprintln!(
            "[keyrelay] 等待网关停止超过 {GATEWAY_SHUTDOWN_TIMEOUT:?}（在途连接未收尾）；\
             监听端口在此之前已释放，继续。"
        ),
    }
}

/// 启动本地网关。同一时刻只允许一个：启动前会先停掉旧的。
#[tauri::command]
pub async fn gateway_start(
    state: State<'_, AppState>,
    args: GatewayStartArgs,
) -> Result<GatewayStatusDto, String> {
    // 总开关在**后端**也要拦一道（M4-S2 复审 P2-8）：之前只有 UI 把按钮置灰，
    // 直接调 IPC 就能绕过设置把端口打开。
    let settings = state.service.settings().map_err(|e| e.to_string())?;
    if !settings.gateway_enabled {
        return Err(
            "本地网关总开关是关的。请到「设置」页勾选「允许启动本地网关」并保存后再启动。"
                .to_string(),
        );
    }

    // 整个「停旧 → 绑新」序列串行化（M5-S5 / 关闭 B-64 的命令层那一半）。
    //
    // 不串行的话，两次并发启动会各自走到 bind：第二次撞 `AddrInUse`，
    // 用户看到「端口可能被占用」——那是并发假象，不是真有人占着端口。
    // 注意是**异步**锁（`std::sync::MutexGuard` 不能跨 `await`，不是 `Send`）。
    let _op = state.gateway_op.lock().await;

    // 先停旧的，并**等端口真正释放**：`shutdown()` 只发信号就返回，
    // 立刻 bind 会撞上还没释放的监听套接字 —— 这正是 B-64 的现象。
    let previous = match state.gateway.lock() {
        Ok(mut guard) => guard.take(),
        Err(_) => None,
    };
    if let Some(previous) = previous {
        stop_gateway(previous).await;
        // 与 `gateway_stop` 同一条理由（M7-S5 复审 P2-1）：换网关之前先把**旧网关**的
        // 失败落库，否则它们会被归到新会话的时间线上。
        state.service.drain_gateway_failures();
    }

    let port = settings.gateway_port;
    let config = state
        .service
        .gateway_config(args.site_id, args.key_id, port)
        .map_err(|e| e.to_string())?;

    let handle = keyrelay_core::gateway::start(config)
        .await
        .map_err(|e| e.to_string())?;
    let status = GatewayStatusDto {
        running: true,
        url: Some(handle.local_url()),
        token: Some(handle.token.clone()),
        site: Some(handle.site_display_name.clone()),
        token_persistent: state.service.gateway_token_persistent(),
    };
    if let Ok(mut guard) = state.gateway.lock() {
        *guard = Some(handle);
    }
    Ok(status)
}

/// **显式轮换**网关本地令牌（M8-S4 §6.4 第 4 条）。
///
/// # 为什么必须「换令牌 + 重启网关」在一个命令里
///
/// 令牌写在两处：钥匙串（下次启动读它）与运行中的网关（内存里那一份）。
/// 只换钥匙串 ⇒ 运行中的网关仍用旧令牌，而 agent 配置与网关不一致；
/// 只重启网关 ⇒ 令牌没变，等于没轮换。两件事分开做就会出现上面两种中间态，
/// 所以合成一个命令：**先换、再停、再启**（用同一组 `site_id` / `key_id`）。
///
/// # 不动 agent 配置
///
/// 轮换后旧令牌立即失效 ⇒ 指向网关的通道**需要重新投递**（界面提示）。
/// 这与「换站」是两件事：换站靠令牌稳定做到零改动（§6.5），轮换是用户显式
/// 作废令牌的动作，本来就该重新投递一次。
///
/// 网关没在跑时只换钥匙串里的那一份（下一次启动自然用新的），不需要 `site_id` / `key_id`。
#[tauri::command]
pub async fn gateway_rotate_token(
    state: State<'_, AppState>,
    args: Option<GatewayStartArgs>,
) -> Result<GatewayStatusDto, String> {
    let _op = state.gateway_op.lock().await;

    // ① 先换钥匙串里那一份。**失败即中止**（不重启）：否则用户以为换掉了，
    //    而重启后会读到旧令牌（或者第三把），状态与预期不符。
    state
        .service
        .rotate_gateway_token()
        .map_err(|e| e.to_string())?;

    // ② 网关没在跑 ⇒ 到此为止（下一次启动用新令牌）。
    let running = match state.gateway.lock() {
        Ok(mut guard) => guard.take(),
        Err(_) => None,
    };
    let Some(handle) = running else {
        return Ok(gateway_status_of(&state));
    };

    // ③ 重启：先停（等端口释放）→ 再按**同一组**站点/密钥启。
    //    取不到参数就明确拒绝：把「轮换」做成「顺手把网关关掉」是最坏的结果。
    let args = args.ok_or_else(|| {
        "轮换令牌需要同时重启网关，请从「网关」页触发（缺少站点与密钥参数）".to_string()
    })?;
    stop_gateway(handle).await;
    state.service.drain_gateway_failures();
    state.service.end_gateway_session();

    let port = state
        .service
        .settings()
        .map_err(|e| e.to_string())?
        .gateway_port;
    let config = state
        .service
        .gateway_config(args.site_id, args.key_id, port)
        .map_err(|e| e.to_string())?;
    let handle = keyrelay_core::gateway::start(config)
        .await
        .map_err(|e| e.to_string())?;
    let status = GatewayStatusDto {
        running: true,
        url: Some(handle.local_url()),
        token: Some(handle.token.clone()),
        site: Some(handle.site_display_name.clone()),
        token_persistent: state.service.gateway_token_persistent(),
    };
    if let Ok(mut guard) = state.gateway.lock() {
        *guard = Some(handle);
    }
    Ok(status)
}

/// 停止网关。与 `gateway_start` 共用同一把操作锁，避免「停」与「启」交错。
#[tauri::command]
pub async fn gateway_stop(state: State<'_, AppState>) -> Result<GatewayStatusDto, String> {
    let _op = state.gateway_op.lock().await;

    let running = match state.gateway.lock() {
        Ok(mut guard) => guard.take(),
        Err(_) => None,
    };
    if let Some(handle) = running {
        // 等端口真正释放再返回：否则调用方紧接着 start 会撞 AddrInUse
        stop_gateway(handle).await;
    }
    // M7-S5 复审 P2-1：把网关攒下的失败**在这里落库一次**。
    //
    // 为什么必须在停止时落：`drain_gateway_failures` 的生产调用点原本只有 `refresh_all`，
    // 于是「网关刚报失败、用户随即关掉应用」会让那条失败**永远进不了事件表**——
    // 而它正是「网关为什么切换了上游」的唯一线索。
    //
    // 为什么在**停止**时（而不是退出时）：退出钩子拿不到 `AppState` 的可靠时机，
    // 而 `gateway_stop` 是「这一次会话结束了」的天然边界——失败归给产生它的那次会话，
    // 顺带解决复审指出的**归因错位**（旧会话的失败被记成当前会话的）。
    state.service.drain_gateway_failures();
    // M8-S1 §11.1：drain **之后**作废会话。顺序是硬要求——
    // 先 drain 才能把「属于被停止那次会话」的失败收走；再作废，于是 stop 之后
    // **在途**请求才产生的失败会看到代号不匹配而被丢弃，不会被记到下一个会话上。
    state.service.end_gateway_session();
    Ok(gateway_status_of(&state))
}

#[tauri::command]
pub fn export_bundle(
    state: State<'_, AppState>,
    args: ExportArgs,
) -> Result<ExportResultDto, String> {
    let path = match args.path {
        Some(path) if !path.trim().is_empty() => std::path::PathBuf::from(path),
        _ => default_export_path("keyrelay-export"),
    };
    state
        .service
        .export_to_file(&path, args.password.as_deref())
        .map(|outcome| ExportResultDto {
            path: outcome.path.display().to_string(),
            encrypted: outcome.encrypted,
            bytes: outcome.bytes,
            registered: outcome.registered,
        })
        .map_err(|e| e.to_string())
}

/// `~/.keyrelay/exports/<prefix>-<unix 秒>.json`。
///
/// 抽出来是因为配置导出与诊断包**必须落在同一个目录**：两者都会被登记进
/// 「已知导出物」表、都会被 `audit_redaction` 扫到，散在两个目录只会让用户
/// 在报障时找错地方。
fn default_export_path(prefix: &str) -> std::path::PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    crate::home_dir()
        .join(".keyrelay")
        .join("exports")
        .join(format!("{prefix}-{stamp}.json"))
}

/// 导出诊断包（FR-9:196）。**脱敏后的**事件表 + 白名单设置快照 + 版本信息。
///
/// 这条命令是 DEBUG 报告 §1.6 的正面处置：`service::export_diagnostics` 当时
/// 只有测试在调，界面与命令层都没有入口——于是「诊断包」在 PRD 里是已交付，
/// 在用户手里不存在。
#[tauri::command]
pub fn export_diagnostics(
    state: State<'_, AppState>,
    args: DiagnosticsArgs,
) -> Result<DiagnosticsResultDto, String> {
    let path = match args.path {
        Some(path) if !path.trim().is_empty() => std::path::PathBuf::from(path),
        _ => default_export_path("keyrelay-diagnostics"),
    };
    state
        .service
        .export_diagnostics_to_file(&path, args.limit.unwrap_or(DEFAULT_DIAGNOSTIC_EVENTS))
        .map(|outcome| DiagnosticsResultDto {
            path: outcome.path.display().to_string(),
            bytes: outcome.bytes,
            events: outcome.events,
            registered: outcome.registered,
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn prune_backups(
    state: State<'_, AppState>,
    args: PruneArgs,
) -> Result<PruneResultDto, String> {
    state
        .service
        .prune_backups(args.keep)
        .map(|removed| PruneResultDto { removed })
        .map_err(|e| e.to_string())
}

/// 脱敏审计：扫描数据库（含 WAL/SHM）、备份目录与事件表，确认零明文。
#[tauri::command]
pub fn audit_redaction(state: State<'_, AppState>) -> Result<AuditReportDto, String> {
    use keyrelay_core::audit::AuditFinding;

    state
        .service
        .audit_redaction()
        .map(|report| AuditReportDto {
            files_scanned: report.files_scanned,
            bytes_scanned: report.bytes_scanned,
            clean: report.is_clean(),
            summary: report.summary(),
            findings: report
                .findings
                .into_iter()
                .map(|finding| {
                    let (kind, path, detail) = match finding {
                        AuditFinding::PlaintextInFile { path, hits } => (
                            "plaintext-in-file",
                            Some(path.display().to_string()),
                            format!("{hits} 处疑似明文凭证"),
                        ),
                        AuditFinding::Unreadable { path, reason } => {
                            ("unreadable", Some(path.display().to_string()), reason)
                        }
                        AuditFinding::PlaintextInEvents { rows } => {
                            ("plaintext-in-events", None, format!("{rows} 行"))
                        }
                    };
                    AuditFindingDto {
                        kind: kind.to_string(),
                        path,
                        detail,
                    }
                })
                .collect(),
        })
        .map_err(|e| e.to_string())
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
            needs_login: s.needs_login,
        })
        .map_err(|e| e.to_string())
}

// ==================================================== M6-S5：FR-2 / FR-7 接线

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupDto {
    name: String,
    /// 分组倍率。`None` = 站点没给（**不是 0**，0 表示免费分组）。
    rate: Option<f64>,
    description: Option<String>,
}

#[tauri::command]
pub async fn available_groups(
    state: State<'_, AppState>,
    site_id: i64,
) -> Result<Vec<GroupDto>, String> {
    state
        .service
        .available_groups(site_id)
        .await
        .map(|groups| {
            groups
                .into_iter()
                .map(|g| GroupDto {
                    name: g.name,
                    rate: g.rate,
                    description: g.description,
                })
                .collect()
        })
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeySyncDto {
    site_id: i64,
    site_total: usize,
    already_local: usize,
    /// 本次**恢复**了多少条：本地行还在、钥匙串被清过，于是把明文取回**原来那一行**。
    /// 与 `imported` 分开报：用户的动作不一样（恢复 = 他清过钥匙串；导入 = 本机第一次见到）。
    restored: usize,
    imported: usize,
    /// 站点没给明文的 `remote_id`。界面据此引导「新建一把」而不是以为对齐成功了。
    unreadable: Vec<String>,
}

/// 把站点侧已有密钥的明文一次性对齐到本地钥匙串（FR-2）。
///
/// **不返回任何明文**——理由见 `KeyRelayService::sync_site_keys` 的文档。
#[tauri::command]
pub async fn sync_site_keys(
    state: State<'_, AppState>,
    site_id: i64,
) -> Result<KeySyncDto, String> {
    state
        .service
        .sync_site_keys(site_id)
        .await
        .map(|s| KeySyncDto {
            site_id: s.site_id,
            site_total: s.site_total,
            already_local: s.already_local,
            restored: s.restored,
            imported: s.imported,
            unreadable: s.unreadable,
        })
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationDueDto {
    key_id: i64,
    site_id: i64,
    name: String,
    created_at: i64,
    due_at: i64,
}

/// 该轮换的密钥（FR-7）。纯本地判定，不联网、不读密钥。
#[tauri::command]
pub fn rotation_due(state: State<'_, AppState>) -> Result<Vec<RotationDueDto>, String> {
    state
        .service
        .rotation_due()
        .map(|due| {
            due.into_iter()
                .map(|d| RotationDueDto {
                    key_id: d.key_id,
                    site_id: d.site_id,
                    name: d.name,
                    created_at: d.created_at,
                    due_at: d.due_at,
                })
                .collect()
        })
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationPlanDto {
    key_id: i64,
    site_id: i64,
    key_name: String,
    /// 固定三步的稳定标识（`create_new` / `reinject_all` / `revoke_old`）
    steps: Vec<String>,
    /// 会被重注入的通道
    channels: Vec<String>,
    /// 认不出通道的目标；**非空 = 界面必须禁用「开始轮换」**
    unmapped_targets: Vec<String>,
    old_remote_id: Option<String>,
}

/// 轮换预览（FR-7）。只读，一个请求都不发。
#[tauri::command]
pub fn rotation_plan(state: State<'_, AppState>, key_id: i64) -> Result<RotationPlanDto, String> {
    state
        .service
        .rotation_plan(key_id)
        .map(|plan| RotationPlanDto {
            key_id: plan.key_id,
            site_id: plan.site_id,
            key_name: plan.key_name,
            steps: plan
                .steps
                .iter()
                .map(|step| step.as_str().to_string())
                .collect(),
            channels: plan.channels,
            unmapped_targets: plan.unmapped_targets,
            old_remote_id: plan.old_remote_id,
        })
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationRunDto {
    /// 新密钥的**掩码**形态（明文只在钥匙串里，绝不过 IPC）
    new_key_id: i64,
    new_key_masked: String,
    reinjected: Vec<String>,
    /// `"revoked"` | `"skippedNoRemoteId"` | `"notAttempted"` | `"failed"`
    revoke: String,
    revoke_reason: Option<String>,
    /// `"create_new"` | `"reinject_all"` | `"revoke_old"`；`None` = 没中途失败
    stopped_at: Option<String>,
    stop_reason: Option<String>,
    /// 三步是否都没中途失败。**界面不得只看它**——`skippedNoRemoteId` 也算完成，
    /// 但那是「本来就没得回收」，必须单独说明。
    completed: bool,
}

/// 执行轮换（FR-7，PRD §176 的「一键三连」）。
///
/// 破坏性操作：界面必须先调 `rotation_plan` 出预览并做二次确认（PRD §7）。
/// 中途失败**不**返回 `Err`——那种情况下「停在哪一步」本身就是用户必须看到的信息，
/// 压成一条错误字符串会被读成「什么都没发生」。
#[tauri::command]
pub async fn rotate_key(
    state: State<'_, AppState>,
    key_id: i64,
    name: String,
) -> Result<RotationRunDto, String> {
    let run = state
        .service
        .rotate_key(key_id, keyrelay_core::site::KeySpec::named(name))
        .await
        .map_err(|e| e.to_string())?;
    let (revoke, revoke_reason) = match &run.revoke {
        keyrelay_core::service::RevokeOutcome::Revoked => ("revoked".to_string(), None),
        keyrelay_core::service::RevokeOutcome::SkippedNoRemoteId => {
            ("skippedNoRemoteId".to_string(), None)
        }
        keyrelay_core::service::RevokeOutcome::NotAttempted => ("notAttempted".to_string(), None),
        keyrelay_core::service::RevokeOutcome::Failed(reason) => {
            ("failed".to_string(), Some(reason.clone()))
        }
    };
    Ok(RotationRunDto {
        new_key_id: run.new_key.id,
        new_key_masked: run.new_key.masked.clone(),
        reinjected: run.reinjected.clone(),
        revoke,
        revoke_reason,
        stopped_at: run.stopped_at.map(|step| step.as_str().to_string()),
        stop_reason: run.stop_reason.clone(),
        completed: run.completed(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutostartDto {
    /// `"enabled"` | `"disabled"` | `"unknown"`
    state: String,
    /// 计划的人类可读摘要（**不含任何值**，见 `EnvPlan::describe`）。
    ///
    /// 仅 `autostart_set` 返回时有内容；`autostart_status` 为 `None`。
    plan: Option<String>,
    /// 是否需要用户在系统设置里手动放行（本产品不做提权）。
    manual_action: Option<String>,
}

fn autostart_dto(state: keyrelay_core::autostart::AutostartState) -> AutostartDto {
    use keyrelay_core::autostart::AutostartState;
    AutostartDto {
        state: match state {
            AutostartState::Enabled => "enabled",
            AutostartState::Disabled => "disabled",
            AutostartState::Unknown => "unknown",
        }
        .to_string(),
        plan: None,
        manual_action: None,
    }
}

#[tauri::command]
pub fn autostart_status(state: State<'_, AppState>) -> Result<AutostartDto, String> {
    state
        .service
        .autostart_state()
        .map(autostart_dto)
        .map_err(|e| e.to_string())
}

/// 开启 / 关闭登录自启（FR-7）。
///
/// `hidden` 固定为 `true`（见 `KeyRelayService::autostart_plan`）：自启的用途就是后台刷新，
/// 弹窗会破坏它。`--hidden` 在托盘不可用时会被壳层降级成显示窗口，所以不会出现
/// 「启动了但没有任何入口」。
#[tauri::command]
pub fn autostart_set(state: State<'_, AppState>, enabled: bool) -> Result<AutostartDto, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("拿不到当前可执行文件路径，无法写入自启项: {e}"))?;
    let plan = state
        .service
        .autostart_plan(enabled, &exe)
        .map_err(|e| e.to_string())?;
    let describe = plan.describe();
    apply_env_plan(&state, &plan)?;
    let mut dto = autostart_dto(state.service.autostart_state().map_err(|e| e.to_string())?);
    dto.plan = Some(describe);
    Ok(dto)
}

/// 探测「已知但本版本不托管」的 agent 落点（M7-S3 / 章程 R-7）。
///
/// 只读：核心层永不创建目录、永不写盘。它存在的理由是**不静默**——
/// 用户在 Cline / Roo Code 里配了中转站，本产品既不能帮他注入，也不该假装没这回事。
#[tauri::command]
pub fn detect_unmanaged_targets(state: State<'_, AppState>) -> Vec<UnmanagedTargetDto> {
    keyrelay_core::delivery::detect_unmanaged_targets(state.service.home())
        .into_iter()
        .map(|target| UnmanagedTargetDto {
            label: target.label.to_string(),
            path: target.path.display().to_string(),
            exists: target.exists,
            note: target.note.to_string(),
        })
        .collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnmanagedTargetDto {
    /// `"Cline"` / `"Roo Code"`
    label: String,
    path: String,
    exists: bool,
    /// 面向用户的一句话：**为什么不写**。UI 直接显示，不得改写。
    note: String,
}

/// 按 FR-2:113 的命名规范给一个默认名：`<app-id>/<agent-id>/<yyyymmdd>`。
///
/// **日期由调用方给**（M7-S5 决策 D-5）：Rust 侧不读时钟、不做时区——
/// 用户看到的「今天」应当是他所在时区的今天，而 `std` 没有日历 API，
/// 为一个**标签**引入 `libc` + unsafe FFI 不值。前端用本地日期算 `(y,m,d)` 传进来。
///
/// 返回 `None` 表示入参不合法（段里有 `/`、空段、超长）——此时界面**不要**回退到
/// 硬编码的默认名，那正是这条规范要消灭的东西（`Keys.tsx` 里原本写死的 `"codex/daily"`
/// 看着像规范、其实是个占位）。
#[tauri::command]
pub fn suggest_key_name(agent_id: String, year: i32, month: u32, day: u32) -> Option<String> {
    keyrelay_core::naming::default_key_name(
        keyrelay_core::naming::DEFAULT_APP_ID,
        &agent_id,
        (year, month, day),
    )
}

/// 回收站点上的某把令牌（B-82 的独立路径）。
///
/// **不是**「删除本地记录」：本地行会被标成 `revoked` 并保留——`bindings` 与漂移追溯
/// 靠 `keys.id` 存活，删行会一起带走（M7-S4 spec §6.1 有实测）。
///
/// `confirm` 必须是 `true`。回收是不可逆的站点侧动作，**不提供「无参数即执行」的形态**：
/// 误触的代价是用户正在用的 key 在站点上消失。
#[tauri::command]
pub async fn revoke_key(
    state: State<'_, AppState>,
    site_id: i64,
    remote_id: String,
    confirm: bool,
) -> Result<RevokeReportDto, String> {
    if !confirm {
        return Err("回收站点侧密钥需要二次确认".to_string());
    }
    state
        .service
        .revoke_key(site_id, &remote_id)
        .await
        .map(RevokeReportDto::from)
        .map_err(|e| e.to_string())
}

/// 解绑一个 agent 与它的密钥（FR-2:115 / M8-S4 §5.4）。
///
/// # 两个参数是**两件事**
///
/// - `also_revoke = false`（默认）：纯本地动作，**一个站点请求都不发**；
/// - `also_revoke = true`：顺带把站点侧那把 key 也删掉（**不可逆**）⇒ 必须 `confirm = true`。
///
/// `confirm` 只对 `also_revoke == true` 强制：解绑本身可恢复（行保留、再投递即可），
/// 给它加一道二次确认只会让日常操作变烦；而站点侧删除没有撤销入口。
#[tauri::command]
pub async fn unbind_agent(
    state: State<'_, AppState>,
    agent_id: String,
    also_revoke: bool,
    confirm: bool,
) -> Result<UnbindOutcomeDto, String> {
    if also_revoke && !confirm {
        return Err(
            "「同时回收站点侧的密钥」不可逆，需要二次确认；若只想解除本机绑定，请取消勾选。"
                .to_string(),
        );
    }
    state
        .service
        .unbind(&agent_id, also_revoke)
        .await
        .map(UnbindOutcomeDto::from)
        .map_err(|e| e.to_string())
}

/// 清空钥匙串里属于本产品的条目（FR-8:191）。
///
/// `confirm` 必须是 `true`，理由同上：这个动作不可逆（秘密删了就没了，站点侧那把 key
/// 还在，但本地再也取不回明文）。**不删** SQLite 记录。
#[tauri::command]
pub fn purge_keychain(
    state: State<'_, AppState>,
    confirm: bool,
) -> Result<KeychainPurgeDto, String> {
    if !confirm {
        return Err("清理钥匙串需要二次确认".to_string());
    }
    state
        .service
        .purge_keychain()
        .map(|report| KeychainPurgeDto {
            attempted: report.attempted,
            removed: report.removed,
            failed: report.failed,
            first_error: report.first_error,
        })
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeychainPurgeDto {
    attempted: usize,
    removed: usize,
    failed: usize,
    /// 第一条失败的文案（已脱敏）。没有失败时为 `null`。
    first_error: Option<String>,
}

/// 一次**回收**（站点侧删除）的回报（B-100 / M8-S4 §7）。
///
/// 两个布尔值必须分开给界面：`revoked = true` + `localStatusUpdated = false` 是
/// 「站点侧已经删了（不可逆），但本地记账没写上」——**整体仍然是成功**，
/// 界面要说的是「已回收，但本地状态没记上」，而不是「回收失败」。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeReportDto {
    site_id: i64,
    remote_id: Option<String>,
    revoked: bool,
    local_status_updated: bool,
    note: Option<String>,
}

impl From<keyrelay_core::service::RevokeReport> for RevokeReportDto {
    fn from(report: keyrelay_core::service::RevokeReport) -> Self {
        Self {
            site_id: report.site_id,
            remote_id: report.remote_id,
            revoked: report.revoked,
            local_status_updated: report.local_status_updated,
            note: report.note,
        }
    }
}

/// 一次解绑的结果（M8-S4 §5.4 第 4 条：**四种文案**都要能说出来）。
///
/// `unbound` / `alreadyUnbound` / `revoked` 三者互相独立：
/// 「这次新解开了 2 条」「本来就是解绑状态」「回收成功 1 把、失败 1 把」可以同时成立。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnbindOutcomeDto {
    unbound: usize,
    already_unbound: usize,
    revoked: Vec<RevokeReportDto>,
    note: Option<String>,
}

impl From<keyrelay_core::service::UnbindOutcome> for UnbindOutcomeDto {
    fn from(outcome: keyrelay_core::service::UnbindOutcome) -> Self {
        Self {
            unbound: outcome.unbound,
            already_unbound: outcome.already_unbound,
            revoked: outcome.revoked.into_iter().map(Into::into).collect(),
            note: outcome.note,
        }
    }
}

// ============================================================== 人工过验证码（M8-S2 / FR-1:102）

/// 人机验证窗口的标签。**按站点**：同一站点的重复打开是「聚焦已有窗口」。
fn captcha_window_label(site_id: i64) -> String {
    format!("captcha-{site_id}")
}

/// 站点 `base_url` 的 host（**去掉端口**）。
///
/// 取不出来（空 host）⇒ `None`：调用方 fail-closed 拒绝本次提交——
/// 「域名不确定」意味着 cookie 的归属过滤无从做起。
fn site_host_of(base_url: &str) -> Option<String> {
    let rest = match base_url.find("://") {
        Some(i) => &base_url[i + 3..],
        None => base_url,
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host_port = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    if host_port.is_empty() {
        return None;
    }
    // IPv6（`[::1]:8443`）走 `rsplit_once` 也能正确切出端口；切不出端口时整体当 host。
    let host = match host_port.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host_port,
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// 只保留**属于该站点**的 cookie：domain 等于 host，或是 host 的父域（含前导点写法）。
///
/// 为什么必须过滤（S2 §9 第 3 条的接线细节）：`webview.cookies()` 返回的是**整个
/// cookie store** 里的全部 cookie——多站点窗口、挑战页的第三方域都在里面。而会话的
/// `Cookie:` 头是把逐条 cookie 拼起来发出去的：不过滤就会把**别的站点**的 cookie
/// 发给本站（跨站串号，同时是对别站的凭证泄漏）。
///
/// 空 domain 一律丢弃：归属不明的 cookie 不进会话（fail-closed）。
fn cookie_belongs_to_site(domain: &str, host: &str) -> bool {
    let domain = domain.trim().trim_start_matches('.').to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    if domain.is_empty() || host.is_empty() {
        return false;
    }
    // 带点的后缀比较：`ample.com` 这种「半个标签」的伪装不会命中。
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// 一次「等待人工验证」的挑战（M8-S2 §2.1）。
///
/// `url` 恒为**站点自己的**官方页面地址（`captcha_page_url` 的保证：只可能是
/// `{站点 origin}/login`、永不带 userinfo、永不指向第三方 host）。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptchaChallengeDto {
    site_id: i64,
    url: String,
}

/// 人工过验证码：把「等待中的官方页面」交给用户，并打开内嵌窗口（M8-S2 §9）。
///
/// # 红线（不得动摇）
///
/// **不绕过验证码**：窗口只是把**官方页面**原样打开，用户**自己**过一次。
/// 不注入脚本、不读 DOM、不自动点击、不调任何打码服务（S2 §9 第 5 条）。
///
/// # 为什么窗口在这里开（而不是前端）
///
/// cookie 的抓取要走 `webview.cookies()`（Rust 侧）——窗口的归属、标签、关窗事件
/// 都必须与「哪个站点」绑定；把窗口生命周期放在命令层是唯一能保证这一点的做法。
/// 前端只负责展示「需要人机验证」与两个按钮（我已过完 / 取消）。
///
/// # 重复点击
///
/// 同站点已有窗口 ⇒ **聚焦**，不重建：`destroy()` 本身不发事件，但任何在重建路径上
/// 误触发的「关窗 = 取消」都会把刚拿到的相位清掉；聚焦是更简单也更符合预期的行为。
#[tauri::command]
pub async fn captcha_begin<R: tauri::Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    site_id: i64,
) -> Result<CaptchaChallengeDto, String> {
    // ① 相位必须是「等待人工验证」——不在人工态时明确拒绝，而不是打开一个空白窗口
    let challenge = state
        .service
        .begin_captcha(site_id)
        .map_err(|e| e.to_string())?;

    // ② 站点显示名（窗口标题要能认出是哪个站；拿不到就退回站点号）
    let display_name = state
        .service
        .sites()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|site| site.id == site_id)
        .map(|site| site.display_name)
        .unwrap_or_else(|| format!("站点 #{site_id}"));

    let label = captcha_window_label(site_id);
    if let Some(existing) = app.get_webview_window(&label) {
        // 窗口已开着：聚焦。**不重建**——见函数的「重复点击」说明。
        let _ = existing.set_focus();
    } else {
        let url = challenge
            .url
            .parse::<tauri::Url>()
            .map_err(|e| format!("人机验证页面地址无法解析: {e}"))?;
        let window =
            tauri::WebviewWindowBuilder::new(&app, label, tauri::WebviewUrl::External(url))
                .title(format!("人机验证 · {display_name}"))
                .inner_size(1000.0, 760.0)
                .build()
                .map_err(|e| format!("打开人机验证窗口失败: {e}"))?;

        // 关窗 = 取消（T6）：相位回 `Idle`，不写缓存 / 钥匙串 / 事件。
        // 只监听 `CloseRequested`（用户发起的关闭）——`destroy()`（我们主动关）不触发它，
        // 于是「提交成功后由我们关窗」不会被误记成取消（相位那时也已是 `Idle`，取消是 no-op）。
        let app_for_close = app.clone();
        window.on_window_event(move |event| {
            if matches!(event, tauri::WindowEvent::CloseRequested { .. }) {
                if let Some(state) = app_for_close.try_state::<AppState>() {
                    state.service.cancel_captcha(site_id);
                }
            }
        });
    }

    Ok(CaptchaChallengeDto {
        site_id: challenge.site_id,
        url: challenge.url,
    })
}

/// 「我已过完」：抓窗口里的会话 cookie → 校验 → 接上会话（M8-S2 §9）。
///
/// # 抓取前置（硬要求，顺序不可换）
///
/// 1. `origin_matches`：页面必须**仍属于该站点**——防「站点把我跳到第三方，我在那边登录」；
/// 2. 按 cookie 的 domain 过滤到本站（见 [`cookie_belongs_to_site`]）。
///
/// # cookie 值不过 IPC
///
/// 值从 WebView 直接进服务层（`complete_captcha`），**不经过前端 JS 堆**——
/// 这也是线上 `captcha_complete` 不带 `cookies` 参数的原因（S2 实现步 D-9）。
#[tauri::command]
pub async fn captcha_complete<R: tauri::Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    site_id: i64,
) -> Result<(), String> {
    // ① 相位必须是「等待人工验证」（T7：不在人工态的提交一律拒绝，不建会话）
    if !matches!(
        state.service.captcha_phase(site_id),
        keyrelay_core::site::captcha::CaptchaPhase::AwaitingHuman { .. }
    ) {
        return Err("该站点当前不在等待人工验证：请先在「站点」页重新发起登录。".to_string());
    }

    // ② 窗口必须在
    let window = app
        .get_webview_window(&captcha_window_label(site_id))
        .ok_or_else(|| "人机验证窗口已关闭：请重新点「打开官方页面过一次」".to_string())?;

    // ③ 抓 cookie **之前**做 origin 比对（S2 §9 第 2 条）
    let base_url = state
        .service
        .sites()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|site| site.id == site_id)
        .map(|site| site.base_url)
        .ok_or_else(|| format!("站点 #{site_id} 不存在"))?;
    let page_url = window.url().map_err(|e| format!("读取窗口地址失败: {e}"))?;
    if !keyrelay_core::site::captcha::origin_matches(&base_url, page_url.as_str()) {
        return Err(
            "页面已不在该站点的域名下（可能被跳转到了别处）；为避免把别处的 cookie 存进来，\
             本次提交被拒绝。请在窗口里回到该站点页面后重试。"
                .to_string(),
        );
    }

    // ④ 抓 + 过滤（值不过 IPC）
    let host = site_host_of(&base_url)
        .ok_or_else(|| "无法从站点地址解析出域名，本次提交被拒绝".to_string())?;
    let cookies = window
        .cookies()
        .map_err(|e| format!("读取窗口 cookie 失败: {e}"))?;
    let pairs: Vec<(String, String)> = cookies
        .into_iter()
        .filter(|cookie| cookie_belongs_to_site(cookie.domain().unwrap_or(""), &host))
        .map(|cookie| (cookie.name().to_string(), cookie.value().to_string()))
        .collect();

    // ⑤ 校验 + 接上会话；失败时窗口**留着**、相位留在人工态，用户可以重试
    state
        .service
        .complete_captcha(site_id, pairs)
        .map_err(|e| e.to_string())?;

    // ⑥ 成功才关窗（`destroy` 不发事件；相位已回 `Idle`）
    let _ = window.destroy();
    Ok(())
}

/// 取消人工验证（关窗）：相位回 `Idle`，窗口关闭。幂等（T6 / T8）。
#[tauri::command]
pub async fn captcha_cancel<R: tauri::Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    site_id: i64,
) -> Result<(), String> {
    state.service.cancel_captcha(site_id);
    if let Some(window) = app.get_webview_window(&captcha_window_label(site_id)) {
        let _ = window.destroy();
    }
    Ok(())
}

/// 落盘一份环境/自启计划。
///
/// Windows 形态（`EnvPlan::Registry`）走 `reg.exe`，**不经 shell**——值里的空格、
/// 引号、`%` 原样到达（`RegOp::to_argv` 已单测）。本机（macOS）上这条分支不可达：
/// `autostart_plan` 只会产出 macOS 的 plist。
fn apply_env_plan(
    state: &State<'_, AppState>,
    plan: &keyrelay_core::platform_env::EnvPlan,
) -> Result<(), String> {
    use keyrelay_core::platform_env::EnvPlan;
    match plan {
        EnvPlan::Files(_) => state
            .service
            .apply_env_plan(plan)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        EnvPlan::Registry(ops) => {
            for op in ops {
                run_reg_op(op)?;
            }
            Ok(())
        }
    }
}

#[cfg(windows)]
fn run_reg_op(op: &keyrelay_core::platform_env::RegOp) -> Result<(), String> {
    use keyrelay_core::platform_env::REG_EXE;
    let output = std::process::Command::new(REG_EXE)
        .args(op.to_argv())
        .output()
        .map_err(|e| format!("执行 {REG_EXE} 失败: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "{REG_EXE} 返回失败（{}）: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

#[cfg(not(windows))]
fn run_reg_op(_op: &keyrelay_core::platform_env::RegOp) -> Result<(), String> {
    // 非 Windows 上不该走到这里：`autostart_plan` 按平台选落点，macOS 产出 plist。
    // 真走到了说明有人把 `EnvScope::WindowsUserEnv` 硬编码进了调用链。
    Err("注册表操作只在 Windows 上可执行（当前平台不支持）".to_string())
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
        let summary = SiteSummaryDto::from_row(keyrelay_core::service::SiteSummary {
            id: 1,
            kind: "newapi".into(),
            base_url: "https://relay.example.com".into(),
            display_name: "测试站".into(),
            health: "unknown".into(),
        });
        let value = to_value(&summary);
        assert_eq!(value["id"], 1);
        assert_eq!(value["kind"], "newapi");
        assert_eq!(value["baseUrl"], "https://relay.example.com");
        assert_eq!(value["displayName"], "测试站");
        assert_eq!(value["health"], "unknown");
        // M7-S5：能力集随站点类型下发，界面据此灰显（不得在页面里按 kind 硬编码）。
        assert_eq!(value["capabilities"]["listKeys"], true);
        assert_eq!(
            value["capabilities"]["keyUsage"], false,
            "用量取不到，见 B-96"
        );

        // 认不出的站点类型 ⇒ 全部 false（fail-closed：宁可全灰，也不给点了才报错的按钮）。
        let unknown = SiteSummaryDto::from_row(keyrelay_core::service::SiteSummary {
            id: 2,
            kind: "some-future-site".into(),
            base_url: "https://x.example.com".into(),
            display_name: String::new(),
            health: "unknown".into(),
        });
        let value = to_value(&unknown);
        assert_eq!(value["capabilities"]["listKeys"], false);
        assert_eq!(value["capabilities"]["login"], false);
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
            known: true,
            remaining: Some(1.5),
            used: Some(0.5),
            raw_quota: Some(750_000),
            quota_per_unit: Some(500_000),
        };
        let value = to_value(&balance);
        assert_eq!(value["rawQuota"], 750_000);
        assert_eq!(value["quotaPerUnit"], 500_000);
        assert_eq!(value["known"], true);
        assert_eq!(value["remaining"], 1.5);

        // M7-S5：未知余额必须**结构上**不可能被渲染成 0.00 —— 数值字段是 null，不是 0。
        let unknown = BalanceDto::from_balance(keyrelay_core::site::Balance::unknown("USD"));
        let value = to_value(&unknown);
        assert_eq!(value["known"], false);
        assert_eq!(value["remaining"], Value::Null, "未知余额不得给 0");
        assert_eq!(value["used"], Value::Null, "未知余额不得给 0");

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
            // M8-S4 §6.6：模式必须到线上字段名上（界面靠它区分「写的是站点密钥还是本地令牌」）。
            mode: keyrelay_core::delivery::DeliveryMode::Site
                .as_str()
                .to_string(),
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
            // M6-S5：同目录有「同主名、不同扩展名」的兄弟文件时的提示（BACKLOG B-76）。
            // 这里塞一条真的，顺带断言它确实到了线上字段名 `warnings` 上。
            warnings: vec!["同目录下还有 auth.jsonc。".into()],
            // M7-S5：生效策略（PRD FR-4:137）。这里取真实值而不是字面量——
            // 若 `restart_hint` 表变了，这条断言跟着变，不会变成一份假的留档。
            restart_hint: restart_hint_str(keyrelay_core::delivery::restart_hint(
                keyrelay_core::delivery::DeliveryChannel::CodexAuthJson,
            )),
        };
        let value = to_value(&plan);
        assert_eq!(value["agentId"], "codex");
        assert_eq!(value["targetPath"], "/home/u/.codex/auth.json");
        assert_eq!(value["targetExists"], false);
        assert_eq!(value["mode"], "site", "模式必须到线上字段名上");
        assert_eq!(value["fields"][1]["key"], "OPENAI_API_KEY");
        assert_eq!(value["fields"][1]["masked"], "…cdef");
        assert_eq!(value["consent"], "missing");
        assert_eq!(value["consentGrantedAt"], Value::Null);
        assert_eq!(value["warnings"][0], "同目录下还有 auth.jsonc。");
        assert_eq!(value["restartHint"], "needed", "codex 的配置进程启动时才读");
        assert!(value.get("target_path").is_none(), "不得出现 snake_case");

        // M7-S5：**每个**通道都必须给出一个非空提示——新增通道时穷举 match 会编译失败，
        // 而不是悄悄给一个空串（界面会因此显示「无需重启」这种最危险的假话）。
        for channel in keyrelay_core::delivery::DeliveryChannel::ALL {
            let hint = restart_hint_str(keyrelay_core::delivery::restart_hint(channel));
            assert!(
                !hint.is_empty(),
                "{} 的 restartHint 不得为空",
                channel.as_str()
            );
        }
        assert_eq!(
            restart_hint_str(keyrelay_core::delivery::restart_hint(
                keyrelay_core::delivery::DeliveryChannel::ShellBlock
            )),
            "dependsOnNewSession",
            "shell rc 只对新开的终端生效，不是「重启某个 agent」能解决的"
        );

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
        assert_eq!(args.model, None, "不传 model 的旧调用方必须照常可用");
    }

    #[test]
    fn delivery_args_carry_an_optional_model() {
        // Continue 通道必须带模型名（Continue 的 schema 把条目的 `model` 定为必填）
        let args: DeliveryArgs = serde_json::from_value(serde_json::json!({
            "keyId": 7,
            "channel": "continue",
            "model": "gpt-4o"
        }))
        .expect("解析 DeliveryArgs");
        assert_eq!(args.model.as_deref(), Some("gpt-4o"));
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

    // ---------- M8-S2：人工过验证码（窗口/cookie 归属的接线细节） ----------

    #[test]
    fn captcha_challenge_dto_serializes_in_camel_case() {
        let challenge = CaptchaChallengeDto {
            site_id: 7,
            url: "https://relay.example.com/login".into(),
        };
        let value = to_value(&challenge);
        assert_eq!(value["siteId"], 7);
        assert_eq!(value["url"], "https://relay.example.com/login");
    }

    #[test]
    fn captcha_cookie_domain_filter_keeps_only_the_sites_cookies() {
        // 本站的 cookie（精确 / 前导点 / 大小写 / 父域四种写法）留下
        assert!(cookie_belongs_to_site(
            "relay.example.com",
            "relay.example.com"
        ));
        assert!(cookie_belongs_to_site(
            ".relay.example.com",
            "relay.example.com"
        ));
        assert!(cookie_belongs_to_site(
            "Relay.Example.COM",
            "relay.example.com"
        ));
        assert!(
            cookie_belongs_to_site("example.com", "relay.example.com"),
            "注册域 cookie 覆盖本站（站点把 cookie 设在父域上）"
        );
        // 别的站 / 后缀伪装 / 空 domain 一律不留（fail-closed）
        assert!(!cookie_belongs_to_site(
            "other.example.com",
            "relay.example.com"
        ));
        assert!(
            !cookie_belongs_to_site("ample.com", "relay.example.com"),
            "「半个标签」的后缀伪装不得命中"
        );
        assert!(!cookie_belongs_to_site(
            "example.com.evil.com",
            "relay.example.com"
        ));
        assert!(!cookie_belongs_to_site("", "relay.example.com"));
        assert!(!cookie_belongs_to_site("relay.example.com", ""));
    }

    #[test]
    fn site_host_of_strips_port_and_userinfo() {
        assert_eq!(
            site_host_of("https://relay.example.com").as_deref(),
            Some("relay.example.com")
        );
        assert_eq!(
            site_host_of("https://relay.example.com:8443/x").as_deref(),
            Some("relay.example.com")
        );
        assert_eq!(
            site_host_of("http://alice:pw@relay.example.com/api").as_deref(),
            Some("relay.example.com")
        );
        assert_eq!(
            site_host_of("http://127.0.0.1:8787").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            site_host_of("https://[::1]:8443/x").as_deref(),
            Some("[::1]")
        );
        assert_eq!(site_host_of("https://").as_deref(), None);
    }
}
