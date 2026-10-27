//! 前端可调用的命令。保持「薄」：参数校验 + 调服务层 + 转 DTO。
//!
//! 安全约束：`create_key` 返回的密钥只在**返回值**里出现一次，不写日志、不落库。

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};

use tianshu_relay_core::delivery::ConsentState;

use crate::AppState;

/// 旧数据迁移结果的 IPC 形态（M35-S1 §4.3）。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RebrandDto {
    /// "noLegacy" | "migrated" | "targetExists" | "failed"
    status: String,
    from: Option<String>,
    to: String,
    files: usize,
    bytes: u64,
    warnings: Vec<String>,
    error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfoDto {
    name: String,
    version: String,
    db_path: String,
    /// 本次启动**实际使用**的数据目录（迁移失败时是旧目录）。
    data_dir: String,
    site_count: usize,
    /// 数据库降级原因（正常为 null）
    db_error: Option<String>,
    /// 钥匙串后端标识。`"memory"` 出现在真实运行里即为缺陷（意味着密钥没进系统钥匙串）。
    vault_backend: String,
    /// 旧数据迁移结果（`noLegacy` 时前端不渲染任何提示）。
    rebrand: RebrandDto,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteSummaryDto {
    id: i64,
    kind: String,
    base_url: String,
    display_name: String,
    health: String,
    /// 登录账号栏的输入约定（M9-S2 / B-120）：`"username"` / `"email"` / `null`。
    ///
    /// 与 `capabilities` **同一处派生**（都从 `SiteKind` 查表）：界面据此决定标签与
    /// placeholder，**不得**在页面里按 `kind` 硬编码——那正是 M7-S2 §3.3 禁掉的形态，
    /// 而这里的代价比灰显更重：标签写错会让用户填一个**注定被站点拒绝**的值
    /// （B-120 的原始症状：Sub2API 的账号栏被标成「用户名」）。
    ///
    /// 认不出的 `kind` ⇒ `null`：界面回落到中性标签「账号」，**不猜**是用户名。
    login_field: Option<&'static str>,
    /// 该站点类型的**设计能力**（M7-S5 / M7-S2 的 `capabilities()`）。
    ///
    /// 界面用它灰显按钮，**不得**在页面里按 `kind` 硬编码判断——否则新增站点类型时
    /// 每加一个页面都要改一次，而漏掉的那一处会给出一个点了才报错的按钮。
    capabilities: SiteCapabilitiesDto,
    /// M38-S1：该站会话是否已持久化到本地加密保险库（后端只用 `Vault::has` 看存在性，
    /// 不读明文）。界面据此显示「已保存会话 · 重启免登」徽标与「退出登录」按钮。
    session_persisted: bool,
    /// M38-S1：当前内存会话的 JWT `exp`（秒）；无会话 / 非 JWT ⇒ `null`。
    session_expires_at: Option<i64>,
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
    /// M26-S1 / B-191：该站点类型能否被 WebView cookie 抓取兜底（与能力表同源）。
    /// 界面据此决定「打开官方页面过一次」面板渲染与否；后端 `captcha_complete` 据此
    /// 在 `window.cookies()` 之前直接拒绝（不调 cookies、不进 validate、不关窗）。
    webview_captcha_supported: bool,
    /// M28-S2 / B-191 B 路：该站点类型能否用「WebView localStorage → `tianshu-relay-creds://`」
    /// 回传会话（与能力表同源）。`true` 的站点（Sub2API）走注入脚本 + 导航拦截；
    /// 界面据此把「不适用」面板换成「登录后点我已登录」。
    ///
    /// 与 `webview_captcha_supported` 是**两种不同的取数机制**，可以同时为 false
    /// （= 该类型没有任何 WebView 兜底）。判据只来自能力表，页面**不得**按 `kind` 硬编码。
    webview_bearer_supported: bool,
}

impl SiteCapabilitiesDto {
    fn from_kind(kind: tianshu_relay_core::site::SiteKind) -> Self {
        let caps = tianshu_relay_core::site::capability::capabilities(kind);
        Self {
            login: caps.login,
            list_keys: caps.list_keys,
            create_key: caps.create_key,
            reveal_key: caps.reveal_key,
            revoke_key: caps.revoke_key,
            balance: caps.balance,
            groups: caps.groups,
            key_usage: caps.key_usage,
            webview_captcha_supported: caps.webview_captcha_supported,
            webview_bearer_supported: caps.webview_bearer_supported,
        }
    }

    /// 解析不出站点类型时的**兜底**：全部 `false`。
    ///
    /// 这是 fail-closed 的方向——界面会把按钮全灰掉，用户看到一个明确的空状态；
    /// 反过来（猜一个「什么都能做」）会给出点了才报错的按钮，而报的错还是别的原因。
    /// M26-S1：`webview_captcha_supported` 同向落点 `false`——
    /// 认不出类型时，绝不让「打开官方页面过一次」面板渲染出来。
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
            webview_captcha_supported: false,
            webview_bearer_supported: false,
        }
    }
}

impl SiteSummaryDto {
    fn from_row(row: tianshu_relay_core::service::SiteSummary) -> Self {
        // 只解析一次 `kind`：`capabilities` 与 `login_field` 必须来自**同一个**判断，
        // 两次 `parse` 写两遍就是两处事实（将来改了其中一处就会分叉）。
        let kind = tianshu_relay_core::site::SiteKind::parse(&row.kind);
        let capabilities = match kind {
            Some(kind) => SiteCapabilitiesDto::from_kind(kind),
            None => SiteCapabilitiesDto::none(),
        };
        let login_field = kind
            .and_then(tianshu_relay_core::site::login_field::LoginField::of)
            .map(tianshu_relay_core::site::login_field::LoginField::as_str);
        Self {
            id: row.id,
            kind: row.kind,
            base_url: row.base_url,
            display_name: row.display_name,
            health: row.health,
            login_field,
            capabilities,
            session_persisted: row.session_persisted,
            session_expires_at: row.session_expires_at,
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
    /// M14-S3：当前累计已用（USD）。`None` = 站点未给 / 未采集。
    quota_used: Option<f64>,
    /// M14-S3：限额（USD）。`None` = 不限 / 未采集。
    quota_limit: Option<f64>,
    /// M14-S3：币种。
    currency: Option<String>,
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
    fn from_balance(balance: tianshu_relay_core::site::Balance) -> Self {
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
    /// P2-3（后端半）：这个通道的**落点文件里有没有 endpoint**。
    ///
    /// `false` ⇒ 切到网关模式时它**只换了令牌、没换地址**（Codex 的 endpoint 在
    /// `~/.codex/config.toml`，不在 `auth.json` 里）⇒ 界面必须提示用户去改那个文件，
    /// 否则 Codex 会把本地令牌发到站点、拿回 401。
    /// 判据来自 `delivery::channel_carries_endpoint`（与 writer 装配表同源）。
    endpoint_in_channel: bool,
    /// 提示项（**不是错误**）。当前只有一条来源：同目录下存在「同主名、不同扩展名」
    /// 的兄弟文件，可能被 agent 优先读取，从而让本次投递静默不生效（BACKLOG B-76）。
    warnings: Vec<String>,
    /// 投递后该 agent 是否需要重启才读到新配置（PRD FR-4:137）。
    ///
    /// 取值只能来自 `delivery::restart_hint(channel)`——**界面不得自己判断**。
    /// 这里是**穷举 match**（没有 `_` 分支）：新增一条通道时它会编译失败，
    /// 而不是悄悄给出一个空提示。
    restart_hint: &'static str,
    /// P1-6：`restart_hint` 的来源标注（三分法：抄 cc-switch 未实测 / 已实测 /
    /// 未实测）。取值只能来自 `delivery::restart_hint_detail(channel)`，与
    /// `restart_hint` 同源；界面必须把标注呈现给用户，未实测不得写成定论。
    restart_hint_source: &'static str,
    /// P1-6：生效动作（新会话 / 重启终端或 CLI / 完全退出重开 / Codex 三分法 /
    /// 通用重启）。取值同样只能来自 `restart_hint_detail`，界面按动作取文案，
    /// 不得按通道硬编码。
    restart_hint_action: &'static str,
    /// P0-2：Codex 保留模式（只写 config，auth.json 不动）时为 true；其余一律 false。
    preserve_auth: bool,
    /// P0-2：本次投递实际覆盖的全部文件。单通道 = 1 条；Codex 双文件 = 2 条
    /// （auth + config，写顺序）；Codex 保留 = 1 条（config）。
    ///
    /// 顶层字段（`target_path` / `fields` / `preview` / `consent`）是历史形态，
    /// 只描述「入口文件」（入口文件在单里就取它，否则取 config——保留模式下
    /// 入口是 auth 时单里没有 auth，只能取 config）；**新界面必须读 `files`
    /// 才算看到整单**，只看顶层会漏掉另一半文件。
    files: Vec<DeliveryFilePlanDto>,
    /// P0-3：DSH 通道的凭据引用校验结果；仅 DSH 为 `Some`，其余通道为 `None`。
    ///
    /// 语义与核心层 `DeliveryPlan.dsh_credential_reference` 一字不差：
    /// 非 DSH 通道序列化为 `null`，不得在映射层把 `None` 写成空对象。
    /// 仅类型层接线：Agents 页渲染是后续项（BACKLOG B-280），在此之前
    /// 不得宣称预览已展示该结果。
    dsh_credential_reference: Option<tianshu_relay_core::delivery::dsh::DshReferenceCheck>,
    /// P1-7：本计划是否由预览专用入口产出（零副作用模式）。
    /// `true` 时前端必须渲染「仅预览，未写入」并禁用投递按钮。
    preview_only: bool,
    /// P1-7：该目标文件上是否没有任何生效中的绑定（首次投递判定）。
    is_first_delivery: bool,
    /// P1-7：首次投递时从现有文件只读导入的现有值（已掩码处理）；
    /// 非首次为空。**不是**投递内容：写盘仍按 `fields` 走。
    imported_fields: Vec<DeliveryFieldDto>,
    /// P1-7：本次生效的落点变体名（Cline 为 `code` / `code-insiders` /
    /// `cursor`，其余通道为 `default`）。
    target_variant: String,
    /// P1-7：该通道可选的落点变体名表（前端下拉直接用它渲染，
    /// 不得在界面里硬编码变体清单——清单变了界面会跟着错）。
    target_variants: Vec<String>,
    /// P2-8：投递前模型验证（静态配对 + `/v1/models` 探针），计划阶段产出、
    /// 前端在计划视图里展示。只读验证结果，不含密钥；硬拦项由
    /// `blocks_delivery` 统一表示（plan 只展示，apply 再探一次并执行硬拦）。
    model_validation: ModelValidationDto,
}

/// 一单里某一个文件的预览（P0-2）。字段含义与顶层同名项一致，
/// 只是作用域收窄到这一个文件；`consent` 同样按文件各自的同意记录取。
///
/// DEBUG-G7 P2-C6（B-276/277）：per-file 的 `warnings` / `restart_hint` /
/// `restart_hint_source` / `restart_hint_action` / `endpoint_in_channel` /
/// `agent_id` 与顶层同源（按该文件自己的通道与路径算），不再只有顶层（入口文件）
/// 才有——双文件单里另一文件的提示此前在计划视图里看不到。
/// 旧二进制兼容：新增字段均为加法字段——旧前端反序列化时忽略未知字段，
/// 顶层字段仍是入口文件视图，语义不变；新前端把这些字段声明为可选，
/// 旧后端（不返回它们）的前端仍能渲染顶层视图。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryFilePlanDto {
    channel: String,
    target_path: String,
    target_exists: bool,
    fields: Vec<DeliveryFieldDto>,
    /// **已脱敏**的 diff 预览（只含这一个文件的变化行）
    preview: String,
    /// `"missing"` | `"granted"` | `"revoked"`
    consent: String,
    consent_granted_at: Option<i64>,
    consent_revoked_at: Option<i64>,
    /// P1-7：该文件的首次投递判定与只读导入（与顶层同口径，
    /// 双文件时两文件各自判定、各自导入）。
    is_first_delivery: bool,
    imported_fields: Vec<DeliveryFieldDto>,
    warnings: Vec<String>,
    restart_hint: String,
    restart_hint_source: String,
    restart_hint_action: String,
    endpoint_in_channel: bool,
    agent_id: String,
}

/// [`tianshu_relay_core::delivery::RestartHint`] 的线格式。
///
/// 为什么这个映射在命令层而不是核心层：核心的 `delivery/mod.rs` 在本波次是
/// M7-S3 的写域、且正处于复审冻结期；把它放在这里不改变任何语义
/// （穷举 match 保证新增变体会编译失败），等 `delivery` 解冻后再收进去。
fn restart_hint_str(hint: tianshu_relay_core::delivery::RestartHint) -> &'static str {
    use tianshu_relay_core::delivery::RestartHint;
    match hint {
        RestartHint::NotNeeded => "notNeeded",
        RestartHint::Needed => "needed",
        RestartHint::DependsOnNewSession => "dependsOnNewSession",
    }
}

/// [`tianshu_relay_core::delivery::RestartHintSource`] 的线格式（P1-6）。
/// 取值集合与前端 `RestartHintSource` 联合类型一致（`restart_hint_str` 那对
/// 由 check-commands 逐字对账；这两对未进对账表，但改动时必须同步改 TS）。
fn restart_hint_source_str(
    source: tianshu_relay_core::delivery::RestartHintSource,
) -> &'static str {
    use tianshu_relay_core::delivery::RestartHintSource;
    match source {
        RestartHintSource::CcSwitchUnverified => "ccSwitchUnverified",
        RestartHintSource::Verified => "verified",
        RestartHintSource::Unverified => "unverified",
    }
}

/// [`tianshu_relay_core::delivery::RestartAction`] 的线格式（P1-6）。
fn restart_hint_action_str(action: tianshu_relay_core::delivery::RestartAction) -> &'static str {
    use tianshu_relay_core::delivery::RestartAction;
    match action {
        RestartAction::NewSession => "newSession",
        RestartAction::RestartTerminalOrCli => "restartTerminalOrCli",
        RestartAction::RelaunchDesktopApp => "relaunchDesktopApp",
        RestartAction::CodexSplit => "codexSplit",
        RestartAction::RestartAgent => "restartAgent",
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
    /// P0-2：Codex 保留模式时为 true；其余一律 false。
    preserve_auth: bool,
    /// P0-2：本次投递实际写了的全部文件（单通道 = 1 条；Codex 双文件 = 2 条，
    /// 写顺序；Codex 保留 = 1 条 config）。`journal_id` 在各条之间**共享**
    /// （同一单、同一 journal），`backup_path` 各取各文件的备份。
    /// 顶层 `target_path` / `backup_path` 只描述入口文件（入口文件没写时取
    /// config——保留模式下入口是 auth 时单里没有 auth），新界面必须读 `files`。
    files: Vec<DeliveryFileOutcomeDto>,
}

/// 一单里某一个文件的投递结果（P0-2）。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryFileOutcomeDto {
    channel: String,
    target_path: String,
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
    /// M42-S1：网关**请求体**上限（MiB，1..=64；默认 16）。camelCase `gatewayMaxRequestMib`。
    gateway_max_request_mib: u16,
    // M41-S1：自动启动 + 上次成功运行的那组 site/key（0 = 无）
    gateway_auto_start: bool,
    gateway_last_site_id: i64,
    gateway_last_key_id: i64,
    gateway_token_grace_secs: u16,
    // M14-S1：多站路由 + 模型采集（B-99）
    gateway_multi_site: bool,
    collect_models: bool,
    models_min_interval_secs: u64,
    // M46-S1：密钥健康巡检间隔秒（0 = 关闭；camelCase `gatewayKeyHealthIntervalSecs`）。
    gateway_key_health_interval_secs: u64,
    // M39-S3：负载均衡与每站保护（默认 3 / 8 / 0；UI 控件由 M41 落地）
    gateway_lb_top_n: usize,
    gateway_per_site_concurrency: usize,
    gateway_per_site_rate_limit: u32,
    // M46-S3：每站限流 burst（默认 0 = 关；camelCase `gatewayPerSiteBurst`）。
    gateway_per_site_burst: u32,
    // M46-S4：每请求最多尝试候选数（默认 0 = 走全部；camelCase `gatewayMaxAttempts`）。
    gateway_max_attempts: usize,
    // M2：显式会话粘性灰度开关（默认关；camelCase `gatewaySessionAffinity`）。
    gateway_session_affinity: bool,
    /// M4：openai_chat | anthropic_messages（默认 openai_chat）。
    gateway_upstream_protocol: String,
    /// M5：balanced | cost | latency。
    gateway_routing_preset: String,
    // M46-S7：按 agent 路由规则 JSON（默认空 = 无规则；camelCase `routingRules`）。
    routing_rules: String,
    // ---- M6-S5：FR-9 界面与隐私 ----
    theme: String,
    language: String,
    proxy_url: String,
    // M10-S2：代理模式 auto / manual / direct。camelCase `proxyMode`。
    proxy_mode: String,
    telemetry_enabled: bool,
    auto_update_enabled: bool,
    // ---- M47-S2：内置模型名单 ----
    /// 是否跟随 GitHub 每天同步一次（camelCase `catalogAutoSync`）。
    catalog_auto_sync: bool,
    /// 名单地址；空 = 用内置默认地址（camelCase `catalogUrl`）。
    catalog_url: String,
    // ---- M6-S5：FR-3 通知 ----
    /// M16-S9：通知**总开关**（默认关）。关着时服务层不装通知状态。
    notify_enabled: bool,
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
pub struct GatewayExitDto {
    /// 结束时刻（unix 秒）。
    at: i64,
    /// `requested` | `panicked` | `unexpected`
    reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayStatusDto {
    /// 兼容字段：等价于 `phase == "running"`。
    running: bool,
    /// `running` | `stopped` | `crashed`
    phase: String,
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
    /// 最近一次任务结束（`crashed` 且有结束记录时才有值）。
    last_exit: Option<GatewayExitDto>,
    /// M41-S2：被轮换掉的默认令牌仍可用的截止时刻（unix 秒）。`None` = 无宽限。
    token_grace_until: Option<i64>,
    /// M42-S1：**实际**监听的地址，例如 `["127.0.0.1:8787", "[::1]:8787"]`。
    /// 网关没在跑时为空 vec（不是「以为在监听」）。
    listen_addrs: Vec<String>,
    /// M42-S1：IPv6 回环是否降级（`false` = 双栈都在听）。
    ipv6_degraded: bool,
    /// M42-S1：降级原因（未降级为 `None`）。
    ipv6_note: Option<String>,

    // —— M40-S2：八个新字段（字段名逐字对齐 M44 §4.3 / M40-S2 §4.2）——
    /// **运行态**三值：`single | multi | stopped`（不是设置值的回声）。
    mode: String,
    candidates: Vec<GatewayCandidateDto>,
    /// 最近 60s 滑动；启动不足 3s 时为 0（UI 显示 `—`）。
    qps: f64,
    /// B-224（M40-S2 P2-2 修复）：核心快照本就有的 `uptime_secs`，此前
    /// IPC 层没透出，前端只能用 `requestsTotal < 3` 另 invent 一套
    /// 「样本不足」判据，与后端的「uptime < 3s」判据不一致。透出后
    /// 前端以它为准（缺失时回退到 requestsTotal < 3）。
    uptime_secs: u64,
    requests_total: u64,
    inflight: u64,
    failovers_total: u64,
    last_error: Option<String>,
    generation: u64,
    /// M46-S2：每站 EWMA（毫秒）；未运行 / 无样本 ⇒ 空 map（字段恒在，IPC 形状稳定）。
    ewma_latency_ms: std::collections::BTreeMap<i64, f64>,
    tokens: Vec<GatewayTokenDto>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayCandidateDto {
    site_id: i64,
    /// 站点显示名（与站点列表同源；**不是** `base_url`，不从 URL 现算）。
    display_name: String,
    key_id: Option<i64>,
    /// `healthy | unknown | exhausted`
    health: String,
    /// `closed | open | halfOpen | unknown`
    breaker: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayStartArgs {
    site_id: i64,
    key_id: i64,
}

/// 运行中的网关 + 它启动时绑定的 `site_id` / `key_id`（P1-6 完整修复）。
///
/// `gateway_rotate_token` 网关在跑时，从这里读 site_id / key_id 构造 config——
/// **不**用命令参数：切页后 UI state 可能带默认值，用 args 会把网关悄悄换到
/// 错误的 site/key（令牌轮换的语义是「不换站、不换密钥」，只换本地令牌）。
/// 前端传来的 `args` 仅作一致性校验：与启动时不一致 ⇒ 拒绝，避免静默切站。
pub struct GatewayRunning {
    pub handle: tianshu_relay_core::gateway::GatewayHandle,
    pub site_id: i64,
    pub key_id: i64,
    /// M41-S2：本轮宽限的截止时刻（unix 秒，仅展示）。只在内存里，stop/重启即丢。
    pub token_grace_until: Option<i64>,
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
    /// 缺省写到 `~/.tianshu-relay/exports/tianshu-relay-export-<时间戳>.json`
    path: Option<String>,
    /// M16-S6a §12 产品裁定：`export_bundle` **保留**「另存为到用户选定路径」这个特性，
    /// 但目标**已存在**时必须显式确认——不传（或 `false`）⇒ 拒绝，绝不静默覆盖。
    overwrite: Option<bool>,
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
    /// 缺省写到 `~/.tianshu-relay/exports/tianshu-relay-diagnostics-<时间戳>.json`
    path: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryArgs {
    key_id: i64,
    channel: String,
    /// 模型名（可缺）。OpenCode 通道可填，其余通道不读它。
    /// 只有预览与投递两条命令读它；同意的授予 / 撤销与模型名无关。
    model: Option<String>,
    /// 投递模式（M8-S4 §6.2）：`"site"`（默认，缺省即此）或 `"gateway"`。
    ///
    /// 缺省 = 站点模式 ⇒ **既有调用点的行为一字不变**。认不出的取值直接拒绝，
    /// 不静默回退（回退会把「指向网关」的请求当成站点投递）。
    mode: Option<String>,
    /// P0-2：Codex 保留选项。**只对两条 Codex 通道有意义**，其余通道传 `true`
    /// 会被直接拒绝（不是静默忽略——忽略会让调用方以为「已保留」而实际没保留）。
    ///
    /// - `None`（没传）：Codex 通道走**双文件**（auth + config 同单）；
    ///   非 Codex 通道走既有单通道行为。**没传 ≠ 保留**。
    /// - `Some(false)`：Codex 双文件（与没传同义，但显式写出来便于调用方自证）。
    /// - `Some(true)`：Codex 保留——只写 config.toml，auth.json 一个字节都不碰；
    ///   且**必须由调用方显式传入**，绝不能从「auth.json 已存在」推断。
    preserve_auth: Option<bool>,
    /// P1-7：落点变体名（白名单名字，不是自由路径）。只对 Cline 通道有意义
    /// （`"code"` / `"code-insiders"` / `"cursor"`）；其余通道只认
    /// `None` / `"default"`，传编辑器变体名直接拒绝（不是静默回落默认）。
    /// opencode 的 `.json` / `.jsonc` 选择由通道承载，不走这个字段。
    target_variant: Option<String>,
    /// P1-7：只打印不写盘的预览模式。只对 `delivery_plan` 有意义：
    /// `true` 时走预览专用入口（计划带 `previewOnly: true`，全程不写盘、
    /// 不记 journal、不写绑定、连事件日志都不写）。对 `apply_delivery` /
    /// `grant_consent` / `revoke_consent` 传 `true` 直接拒绝——
    /// 预览模式下任何写操作都不得发生，更不能静默降级成普通调用。
    preview_only: Option<bool>,
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
    /// **站点原生**的分组标识（Sub2API 是 `"2"` 这种数字，NewAPI 是分组名）。
    group: Option<String>,
    /// 分组的显示名，只用于本地记录与界面展示（M19-S1）。
    ///
    /// 与 `group` 分开传的理由：标识要发给站点，名字要给人看。合成一个字段时，
    /// 落库的 `keys.group_name` 会变成 `"2"`——密钥表显示一个无意义的数字，
    /// 而且按分组名查倍率会落空（网关的倍率排序随之退化）。
    group_label: Option<String>,
}

/// 退出登录（M38-S1）：清内存会话 + 删本地加密保险库条目 + health 回 `unknown`。
///
/// 复用既有 `TianshuRelayService::logout`（幂等：站点不存在也不报错）。
/// 删除失败返回错误（`Error::Vault`），调用方据此显示可读原因。
#[tauri::command]
pub fn logout_site(state: State<'_, AppState>, site_id: i64) -> Result<(), String> {
    state.service.logout(site_id).map_err(|e| e.to_string())?;
    clear_gateway_session_pins(&state);
    Ok(())
}

/// M2：key/site 生命周期变化后，旧会话 pin 不再可靠；只清运行态内存。
fn clear_gateway_session_pins(state: &AppState) {
    if let Ok(guard) = state.gateway.lock() {
        if let Some(run) = guard.as_ref() {
            run.handle.clear_session_pins();
        }
    }
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
        name: "天枢 Relay".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        db_path: state.db_path.display().to_string(),
        data_dir: state.data_dir.display().to_string(),
        site_count,
        db_error: state.db_error.clone(),
        vault_backend: state.service.vault_backend().to_string(),
        rebrand: RebrandDto {
            status: state.rebrand.status.as_str().to_string(),
            from: state.rebrand.from.as_ref().map(|p| p.display().to_string()),
            to: state.rebrand.to.display().to_string(),
            files: state.rebrand.files,
            bytes: state.rebrand.bytes,
            warnings: state.rebrand.warnings.clone(),
            error: state.rebrand.error.clone(),
        },
    })
}

#[tauri::command]
pub async fn detect_site<R: tauri::Runtime>(
    _app: AppHandle<R>,
    state: State<'_, AppState>,
    base_url: String,
) -> Result<SiteFingerprintDto, String> {
    // 代理从 settings 解析，与生产 transport 同一份逻辑（M10-S2）：
    // 测试连接与实际请求走同一条代理，不再各走各的。
    let proxy = state.service.settings().ok().and_then(|s| {
        let mode = tianshu_relay_core::proxy::ProxyMode::parse(&s.proxy_mode)
            .unwrap_or(tianshu_relay_core::proxy::ProxyMode::Auto);
        tianshu_relay_core::proxy::resolve_proxy(mode, &s.proxy_url)
            .ok()
            .flatten()
            .map(|d| d.url)
    });
    crate::detect_only(&base_url, proxy)
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
    let mut credentials = tianshu_relay_core::site::Credentials::new(args.username, args.password);
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
                    quota_used: key.quota_used,
                    quota_limit: key.quota_limit,
                    currency: key.currency,
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
    let mut spec = tianshu_relay_core::site::KeySpec::named(args.name);
    spec.group = args.group;
    spec.group_label = args.group_label;
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

fn parse_channel(raw: &str) -> Result<tianshu_relay_core::delivery::DeliveryChannel, String> {
    tianshu_relay_core::delivery::DeliveryChannel::parse(raw).map_err(|e| e.to_string())
}

/// DEBUG-G7 P2-K4：投递命令层的统一错误脱敏——只 scrub 密钥形态
/// （`crate::redact::scrub`：密钥形长串 → 掩码），正常错误文案逐字不变。
/// 只用于投递命令（`delivery_plan` / `grant_consent` / `revoke_consent` /
/// `apply_delivery` / `rollback_delivery`）；其它命令的错误形态不在本组范围，
/// 不顺手扩大（避免误改正常文案）。
///
/// DEBUG-G7 补齐 P2-K4（全命令层扩大评估，结论：不扩，记残留）：① 核心层
/// 已在咽喉处 scrub（站点错误经 `scrub_error`、传输层 `describe` 先 scrub），
/// 非投递命令的错误多为库内校验/存储错，本身不带上游回显，扩面边际收益低；
/// ② `scrub` 会掩 ≥32 位 hex 串——诊断串里的 journal/sha256 标识同样会被掩，
/// 逐条 103 处未逐一审计诊断损失；③ 命令层集成套件在本 VM 无法链接运行
/// （缺 webkitgtk/gtk）， blanket 改动无验证手段。故扩面留待可在 Mac 上跑
/// 通命令层集成套件时按命令逐条评估，不得以本段为“已全量 scrub”背书。
fn scrub_err<E: std::fmt::Display>(e: E) -> String {
    tianshu_relay_core::redact::scrub(&e.to_string())
}

/// 同意状态 → DTO 三元组（与既有 `delivery_plan` 的映射逐字一致）。
fn consent_parts(consent: &ConsentState) -> (&'static str, Option<i64>, Option<i64>) {
    match consent {
        ConsentState::Missing => ("missing", None, None),
        ConsentState::Granted { granted_at } => ("granted", Some(*granted_at), None),
        ConsentState::Revoked { revoked_at } => ("revoked", None, Some(*revoked_at)),
    }
}

/// P2-8：投递前模型验证的线上形态（camelCase，与核心层
/// `delivery::model_check::ModelValidation` 一一对应）。
///
/// 字段含义（前端按 code 取中英成对文案，不得按文案反推状态）：
/// - `model`：trim 后的模型名；无模型时为 null；
/// - `static_outcome`：`"fail"`（格式无效，硬拦）/ `"not_applicable"`（无模型
///   或通道不写模型）/ `"unchecked"`（格式合格、仓库无依据判定厂商配对）；
/// - `static_code`：静态层原因键（`no_model` / `channel_no_model` /
///   `malformed` / `unchecked`）；
/// - `probe_outcome`：`"passed"` / `"failed"`（硬拦）/ `"warning"`（不拦）/
///   `"skipped"`（未探针）；
/// - `probe_code`：探针原因键（`passed` / `unauthorized` / `forbidden` /
///   `not_in_catalog` / `empty_catalog` / `bad_response` / `unexpected_status` /
///   `unreachable` / `timeout` / `skipped` / `unresolved`）；
/// - `probe_status`：探针 HTTP 状态码（仅状态码，绝不带响应正文）；
/// - `blocks_delivery`：任一层硬拦即 true；plan 只展示它，apply 据此拒绝写盘。
///   本结构**不含密钥**（探针密钥只进请求头，见核心层）。
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ModelValidationDto {
    model: Option<String>,
    static_outcome: String,
    static_code: String,
    probe_outcome: String,
    probe_code: String,
    probe_status: Option<u16>,
    blocks_delivery: bool,
}

fn model_validation_dto(
    v: tianshu_relay_core::delivery::model_check::ModelValidation,
) -> ModelValidationDto {
    ModelValidationDto {
        model: v.model,
        static_outcome: v.static_check.outcome.to_string(),
        static_code: v.static_check.code.to_string(),
        probe_outcome: v.probe.outcome.to_string(),
        probe_code: v.probe.code.to_string(),
        probe_status: v.probe.status,
        blocks_delivery: v.blocks_delivery,
    }
}

/// P2-8：apply 硬拦时的错误文案（与前端 `agents.plan.modelValidation` 的
/// 中文文案同义；401 不得只报裸 401，必须译成「密钥与端点不匹配或旧登录残留」）。
fn model_block_message(v: &tianshu_relay_core::delivery::model_check::ModelValidation) -> String {
    if v.static_check.outcome == "fail" {
        return "模型验证未通过：模型名格式无效（不能含空白字符、不能是 URL 形态、provider 前缀后必须有模型名），已阻止投递；请修正模型名后再试"
            .to_string();
    }
    match v.probe.code {
        "unauthorized" => "模型验证未通过：探针返回 401——密钥与端点不匹配，或本地残留了旧登录的密钥，已阻止投递；请确认这把密钥属于该端点对应的站点，或重新登录换取新密钥后再投递"
            .to_string(),
        "not_in_catalog" => "模型验证未通过：目标模型不在端点 /v1/models 目录中，已阻止投递；请检查模型名是否写错，或确认该端点是否提供此模型"
            .to_string(),
        _ => "模型验证未通过，已阻止投递；请先在投递预览里查看验证结果".to_string(),
    }
}

/// 一份单通道计划 → 一单里某文件的 DTO（借用版：顶层与 `files` 共用同一份
/// 计划时，先用它从借用建 `files`，再移动原计划建顶层）。
fn file_plan_dto(plan: &tianshu_relay_core::delivery::DeliveryPlan) -> DeliveryFilePlanDto {
    let (consent, granted_at, revoked_at) = consent_parts(&plan.consent);
    // DEBUG-G7 P2-C6：per-file 提示与顶层同源——warnings 按该文件路径算，
    // restart 三件套与 endpoint 判定按该文件通道算，agent_id 取该计划自身。
    let hint_detail = tianshu_relay_core::delivery::restart_hint_detail(plan.channel);
    DeliveryFilePlanDto {
        channel: plan.channel.as_str().to_string(),
        target_path: plan.target_path.display().to_string(),
        target_exists: plan.target_exists,
        fields: plan
            .fields
            .iter()
            .map(|f| DeliveryFieldDto {
                key: f.key.clone(),
                masked: f.masked.clone(),
            })
            .collect(),
        preview: plan.preview.clone(),
        consent: consent.to_string(),
        consent_granted_at: granted_at,
        consent_revoked_at: revoked_at,
        // P1-7：按文件透传首次判定与只读导入（双文件时 auth / config 各自算）。
        is_first_delivery: plan.is_first_delivery,
        imported_fields: plan
            .imported_fields
            .iter()
            .map(|f| DeliveryFieldDto {
                key: f.key.clone(),
                masked: f.masked.clone(),
            })
            .collect(),
        warnings: delivery_warnings(&plan.target_path),
        restart_hint: restart_hint_str(hint_detail.hint).to_string(),
        restart_hint_source: restart_hint_source_str(hint_detail.source).to_string(),
        restart_hint_action: restart_hint_action_str(hint_detail.action).to_string(),
        endpoint_in_channel: tianshu_relay_core::delivery::channel_carries_endpoint(plan.channel),
        agent_id: plan.agent_id.clone(),
    }
}

/// 单通道计划 → 完整 DTO（顶层 = 该计划本身，`files` = 只有它一条）。
fn single_plan_dto(
    plan: tianshu_relay_core::delivery::DeliveryPlan,
    model_validation: ModelValidationDto,
) -> DeliveryPlanDto {
    let file = file_plan_dto(&plan);
    let (consent, granted_at, revoked_at) = consent_parts(&plan.consent);
    // BACKLOG B-76：有些 agent 会优先读**另一个扩展名**的同名文件
    // （本机实测 `~/.config/opencode/` 下 `.json` 与 `.jsonc` 并存）。
    // 写进 A 而 agent 读 B 时投递会**静默不生效**——用户看到「已投递成功」，
    // agent 却拿不到 key，且没有任何报错。这里只提示，不阻断。
    let warnings = delivery_warnings(&plan.target_path);
    let channel = plan.channel;
    // P1-6：生效三件套同源取自 restart_hint_detail——取值与旧 restart_hint 一致
    // （分表测试钉住），来源与动作随同一条通道走，Codex 双文件入口同样经此
    // （codex_plan_dto 复用 single_plan_dto，auth/config 两条都是 CodexSplit）。
    let hint_detail = tianshu_relay_core::delivery::restart_hint_detail(channel);
    DeliveryPlanDto {
        agent_id: plan.agent_id,
        channel: channel.as_str().to_string(),
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
        restart_hint: restart_hint_str(hint_detail.hint),
        restart_hint_source: restart_hint_source_str(hint_detail.source),
        restart_hint_action: restart_hint_action_str(hint_detail.action),
        endpoint_in_channel: tianshu_relay_core::delivery::channel_carries_endpoint(channel),
        preserve_auth: false,
        files: vec![file],
        // P0-3：原样透传核心层结果——DSH 为 Some、其余通道为 None，
        // 不在这里把 None 换成空对象，也不在这里把 Some 丢掉。
        dsh_credential_reference: plan.dsh_credential_reference,
        // P1-7：原样透传预览标志、首次判定、只读导入与生效变体；
        // 变体清单由后端变体名表给（前端不得硬编码）。
        preview_only: plan.preview_only,
        is_first_delivery: plan.is_first_delivery,
        imported_fields: plan
            .imported_fields
            .into_iter()
            .map(|f| DeliveryFieldDto {
                key: f.key,
                masked: f.masked,
            })
            .collect(),
        target_variant: plan.target_variant.to_string(),
        target_variants: tianshu_relay_core::delivery::target_variant_names(channel)
            .into_iter()
            .map(|v| v.to_string())
            .collect(),
        model_validation,
    }
}

/// Codex 双文件计划 → 完整 DTO。
///
/// 顶层取「入口文件」的那份计划（入口文件在单里就取它，否则取 config——
///
/// 保留模式下入口是 auth 时单里没有 auth）；`files` 按写顺序列出全部文件。
/// 顶层的 `warnings` / `restart_hint` / `endpoint_in_channel` 同样按顶层
/// 那份计划的文件算，与单通道口径一致。
fn codex_plan_dto(
    entry: tianshu_relay_core::delivery::DeliveryChannel,
    plan: tianshu_relay_core::delivery::CodexDeliveryPlan,
    model_validation: ModelValidationDto,
) -> DeliveryPlanDto {
    let mut files: Vec<DeliveryFilePlanDto> = Vec::new();
    if let Some(auth) = &plan.auth {
        files.push(file_plan_dto(auth));
    }
    files.push(file_plan_dto(&plan.config));
    let top = match (&plan.auth, entry) {
        (Some(auth), tianshu_relay_core::delivery::DeliveryChannel::CodexAuthJson) => auth.clone(),
        _ => plan.config.clone(),
    };
    let mut dto = single_plan_dto(top, model_validation);
    dto.preserve_auth = plan.preserve_auth;
    dto.files = files;
    dto
}

/// 一份单通道结果 → 一单里某文件的 DTO（借用版）。
fn file_outcome_dto(
    outcome: &tianshu_relay_core::delivery::DeliveryOutcome,
) -> DeliveryFileOutcomeDto {
    DeliveryFileOutcomeDto {
        channel: outcome.channel.as_str().to_string(),
        target_path: outcome.target_path.display().to_string(),
        backup_path: outcome
            .backup_path
            .as_ref()
            .map(|p| p.display().to_string()),
    }
}

/// 单通道结果 → 完整 DTO（顶层 = 该结果本身，`files` = 只有它一条）。
fn single_outcome_dto(
    outcome: tianshu_relay_core::delivery::DeliveryOutcome,
) -> DeliveryOutcomeDto {
    let file = file_outcome_dto(&outcome);
    DeliveryOutcomeDto {
        channel: outcome.channel.as_str().to_string(),
        target_path: outcome.target_path.display().to_string(),
        journal_id: outcome.journal_id,
        backup_path: outcome.backup_path.map(|p| p.display().to_string()),
        preserve_auth: false,
        files: vec![file],
    }
}

/// Codex 双文件结果 → 完整 DTO（顶层取入口文件那份结果，否则取 config；
/// `files` 按写顺序列出全部文件；各条的 `journal_id` 相同，见服务层注释）。
fn codex_outcome_dto(
    entry: tianshu_relay_core::delivery::DeliveryChannel,
    outcome: tianshu_relay_core::delivery::CodexDeliveryOutcome,
) -> DeliveryOutcomeDto {
    let mut files: Vec<DeliveryFileOutcomeDto> = Vec::new();
    if let Some(auth) = &outcome.auth {
        files.push(file_outcome_dto(auth));
    }
    files.push(file_outcome_dto(&outcome.config));
    let top = match (&outcome.auth, entry) {
        (Some(auth), tianshu_relay_core::delivery::DeliveryChannel::CodexAuthJson) => auth.clone(),
        _ => outcome.config.clone(),
    };
    let mut dto = single_outcome_dto(top);
    dto.preserve_auth = outcome.preserve_auth;
    dto.files = files;
    dto
}

#[tauri::command]
pub async fn delivery_plan(
    state: State<'_, AppState>,
    args: DeliveryArgs,
) -> Result<DeliveryPlanDto, String> {
    let channel = parse_channel(&args.channel)?;
    // 模式解析与端点都在**动手之前**：`"gateway"` 但网关没在跑 ⇒ 在这里拒绝，
    // 而不是写出一个指向空地址的配置。
    let mode = parse_delivery_mode(args.mode.as_deref())?;
    let endpoint = match mode {
        tianshu_relay_core::delivery::DeliveryMode::Site => None,
        tianshu_relay_core::delivery::DeliveryMode::LocalGateway => {
            Some(gateway_endpoint_of(&state, &channel)?)
        }
    };
    let source = match &endpoint {
        Some(endpoint) => tianshu_relay_core::delivery::DeliverySource::Gateway(endpoint),
        None => tianshu_relay_core::delivery::DeliverySource::Site,
    };
    // DEBUG-G7 P2-C9（B-286）：preview_only 时跳过预热——预览模式的契约是
    // 零副作用（连事件日志都不写），而 warm_model_meta 在 lookup_online == None
    // 时写 1 条 Debug 事件；非预览计划仍预热（缓存已在预览时预热过亦无妨）。
    // M14-S7 §4.2：先把「内置表没覆盖的模型」的在线参数预热进缓存，再走同步的 plan。
    // best-effort：网络失败/超时只是没有参数行，预览照常出（失败不阻断投递）。
    if !args.preview_only.unwrap_or(false) {
        let _ = state.service.warm_model_meta(args.model.as_deref()).await;
    }
    // P2-8：投递前模型验证（静态配对 + 真实 /v1/models 探针），在计划阶段跑、
    // 写盘前可见。验证本身不使计划失败：结果随计划返回前端展示，硬拦项
    // （`blocks_delivery`）由前端禁用投递按钮、并由 apply 再探一次后执行；
    // 探针是只读 GET，计划查询每次刷新会发一次（去重由前端查询键控制）。
    let model_validation = model_validation_dto(
        state
            .service
            .validate_delivery_model(args.key_id, channel, args.model.as_deref(), source)
            .await,
    );
    // P1-7：落点变体与预览模式随参数透传（变体名白名单外即拒绝，
    // 见服务层；预览入口零副作用，见 `delivery_preview_in`）。
    let variant = args.target_variant.as_deref();
    let preview_only = args.preview_only == Some(true);
    // P0-2：两条 Codex 通道走双文件同单——没传 `preserve_auth` 即双文件
    // （`unwrap_or(false)`），显式 `true` 才保留。两条通道的入口等价：
    // 从 auth 卡片还是 config 卡片进来，单里都是同一组文件。
    if matches!(
        channel,
        tianshu_relay_core::delivery::DeliveryChannel::CodexAuthJson
            | tianshu_relay_core::delivery::DeliveryChannel::CodexConfig
    ) {
        let preserve_auth = args.preserve_auth.unwrap_or(false);
        if preview_only {
            return state
                .service
                .delivery_preview_codex_in(
                    args.key_id,
                    args.model.as_deref(),
                    source,
                    preserve_auth,
                    variant,
                )
                .map(|plan| codex_plan_dto(channel, plan, model_validation.clone()))
                .map_err(scrub_err);
        }
        return state
            .service
            .delivery_plan_codex_in_with_variant(
                args.key_id,
                args.model.as_deref(),
                source,
                preserve_auth,
                variant,
            )
            .map(|plan| codex_plan_dto(channel, plan, model_validation))
            .map_err(scrub_err);
    }
    // 非 Codex 通道没有「保留 auth」这个概念：传 `true` 必须拒绝，
    // 不能静默忽略——忽略会让调用方以为「已保留」而实际没保留。
    if args.preserve_auth == Some(true) {
        return Err("preserve_auth 只对 Codex 双文件投递有意义，该通道不支持保留".to_string());
    }
    if preview_only {
        return state
            .service
            .delivery_preview_in(args.key_id, channel, args.model.as_deref(), source, variant)
            .map(|plan| single_plan_dto(plan, model_validation))
            .map_err(scrub_err);
    }
    state
        .service
        .delivery_plan_in_with_variant(args.key_id, channel, args.model.as_deref(), source, variant)
        .map(|plan| single_plan_dto(plan, model_validation))
        .map_err(scrub_err)
}

/// 投递预览的提示项。**不是错误**：投递照常可以做，只是用户该知道这件事。
///
/// 只对普通文件给提示（目录不算）。文案里带**文件名**而不是全路径——
/// 全路径在 UI 上已经显示过了，这里补的是「还有哪个兄弟文件」。
fn delivery_warnings(target: &std::path::Path) -> Vec<String> {
    let siblings = tianshu_relay_core::service::sibling_config_files(target);
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

/// P1-7：预览模式下的写入口守门——`preview_only = true` 时任何写操作
/// （同意授予 / 撤销、落盘）都直接拒绝，不得静默降级成普通调用。
/// DEBUG-G7 P3-D4 层归属声明：本函数与 apply 的模型复核都是 **Tauri 命令层
/// 门禁，不是核心层保证**——直接调核心服务 `apply_delivery_in*` / `delivery_plan_in*`
/// 的调用方绕过这两道门（核心 apply 本身不查 preview_only、不跑模型验证）。
/// 任何“核心层已拦住”的表述都是错的；门禁只对走 Tauri 命令的调用成立。
fn reject_preview_write(args: &DeliveryArgs) -> Result<(), String> {
    if args.preview_only == Some(true) {
        return Err(
            "预览模式下不得执行写操作（同意授予 / 撤销 / 落盘）：请关掉仅预览后再操作".to_string(),
        );
    }
    Ok(())
}

#[tauri::command]
pub fn grant_consent(state: State<'_, AppState>, args: DeliveryArgs) -> Result<(), String> {
    let channel = parse_channel(&args.channel)?;
    reject_preview_write(&args)?;
    state
        .service
        .grant_consent_with_variant(args.key_id, channel, args.target_variant.as_deref())
        .map_err(scrub_err)
}

#[tauri::command]
pub fn revoke_consent(state: State<'_, AppState>, args: DeliveryArgs) -> Result<(), String> {
    let channel = parse_channel(&args.channel)?;
    reject_preview_write(&args)?;
    state
        .service
        .revoke_consent_with_variant(args.key_id, channel, args.target_variant.as_deref())
        .map_err(scrub_err)
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
pub async fn apply_delivery(
    state: State<'_, AppState>,
    args: DeliveryArgs,
) -> Result<DeliveryOutcomeDto, String> {
    let channel = parse_channel(&args.channel)?;
    let mode = parse_delivery_mode(args.mode.as_deref())?;
    // DEBUG-G7 P2-C9（B-282）：Codex 与 Claude Desktop 通道在整个服务 apply 期间
    // 持 restart_op——服务层停写（写盘前停进程）与命令层重启（restart_agent 持
    // 同一把锁）至此互斥；此前两者并发时重启可在停写后、写盘前把应用拉起来，
    // 写盘随即被启动覆盖。其它通道不停进程，不持锁（不扩大锁范围）。
    // DEBUG-G7 补齐 P2-C9：服务层 apply 本身亦持服务层写锁（见核心层
    // `restart_write_op`），轮换直调服务层 apply 时同样受约束，重启命令亦持
    // 同一把服务层锁；命令层锁仍保留作外层，两层锁序一致，无环。
    // 死锁检查：restart 持锁期间只调核心重启（不调 apply）；apply 持锁期间只调
    // 同步服务 apply（不调 Tauri 命令），无嵌套加锁环。
    let _restart_op = if matches!(
        channel,
        tianshu_relay_core::delivery::DeliveryChannel::CodexAuthJson
            | tianshu_relay_core::delivery::DeliveryChannel::CodexConfig
            | tianshu_relay_core::delivery::DeliveryChannel::ClaudeDesktop
    ) {
        Some(state.restart_op.lock().await)
    } else {
        None
    };
    let endpoint = match mode {
        tianshu_relay_core::delivery::DeliveryMode::Site => None,
        tianshu_relay_core::delivery::DeliveryMode::LocalGateway => {
            Some(gateway_endpoint_of(&state, &channel)?)
        }
    };
    let source = match &endpoint {
        Some(endpoint) => tianshu_relay_core::delivery::DeliverySource::Gateway(endpoint),
        None => tianshu_relay_core::delivery::DeliverySource::Site,
    };
    // DEBUG-G7 P2-C9（B-286）：门禁先于预热——此前先 warm_model_meta 后
    // reject_preview_write，preview_only 的拒绝路径仍先写了 1 条 Debug 事件，
    // 违背预览模式“零副作用”契约（连事件日志都不写）。顺序调换后，拒绝
    // 路径在任何副作用之前返回。
    // P1-7：预览模式不得落盘（见 `reject_preview_write`）；变体随参数透传。
    reject_preview_write(&args)?;
    // M14-S7 §4.2：同 `delivery_plan`——直接投递（没先预览）时也要拿到在线参数。
    // 缓存已在预览时预热过，这里通常是一次纯读；best-effort，失败不阻断。
    let _ = state.service.warm_model_meta(args.model.as_deref()).await;
    // P2-8：apply 前复核——plan 里看到的验证可能已过期（模型/端点换过），
    // 且直接投递根本没走过 plan；硬拦项（静态格式无效、探针 401、站点模式
    // 下模型不在非空目录）在这里再探一次并拒绝写盘，警告项不拦——网关模式
    // 下模型不在本地网关目录只是警告（见 `validate_delivery_model` 分流），
    // 与 plan 同走该函数，一处改即两处生效。验证本身不写盘。
    let validation = state
        .service
        .validate_delivery_model(args.key_id, channel, args.model.as_deref(), source)
        .await;
    if validation.blocks_delivery {
        return Err(model_block_message(&validation));
    }
    let variant = args.target_variant.as_deref();
    // P0-2：与 `delivery_plan` 同一条路由——Codex 通道走双文件同单，
    // 没传 `preserve_auth` 即双文件，显式 `true` 才保留；非 Codex 通道传
    // `true` 直接拒绝（不得静默忽略）。
    if matches!(
        channel,
        tianshu_relay_core::delivery::DeliveryChannel::CodexAuthJson
            | tianshu_relay_core::delivery::DeliveryChannel::CodexConfig
    ) {
        let preserve_auth = args.preserve_auth.unwrap_or(false);
        return state
            .service
            .apply_codex_in_with_variant(
                args.key_id,
                args.model.as_deref(),
                source,
                preserve_auth,
                variant,
            )
            .map(|outcome| codex_outcome_dto(channel, outcome))
            .map_err(scrub_err);
    }
    if args.preserve_auth == Some(true) {
        return Err("preserve_auth 只对 Codex 双文件投递有意义，该通道不支持保留".to_string());
    }
    state
        .service
        .apply_delivery_in_with_variant(
            args.key_id,
            channel,
            args.model.as_deref(),
            source,
            variant,
        )
        .map(single_outcome_dto)
        .map_err(scrub_err)
}

/// 投递历史的一行（M9-S4）。字段语义见 `store::DeliveryHistoryRow`。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryHistoryDto {
    pub binding_id: i64,
    pub journal_id: String,
    pub agent_id: String,
    pub key_id: i64,
    pub site_id: i64,
    pub target_path: String,
    pub applied_at: i64,
    pub unbound_at: Option<i64>,
    pub backup_path: Option<String>,
    pub has_journal: bool,
    pub rolled_back: bool,
    pub superseded: bool,
}

/// 投递历史，最新的在前（M9-S4）。「变更历史」页的回滚入口从这里取。
#[tauri::command]
pub fn list_deliveries(
    state: State<'_, AppState>,
    limit: Option<usize>,
) -> Result<Vec<DeliveryHistoryDto>, String> {
    state
        .service
        .delivery_history(limit.unwrap_or(100))
        .map(|rows| {
            rows.into_iter()
                .map(|row| DeliveryHistoryDto {
                    binding_id: row.binding_id,
                    journal_id: row.journal_id,
                    agent_id: row.agent_id,
                    key_id: row.key_id,
                    site_id: row.site_id,
                    target_path: row.target_path,
                    applied_at: row.applied_at,
                    unbound_at: row.unbound_at,
                    backup_path: row.backup_path,
                    has_journal: row.has_journal,
                    rolled_back: row.rolled_back,
                    superseded: row.superseded,
                })
                .collect()
        })
        .map_err(scrub_err)
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
    /// M14-S3：当前累计已用（USD）。`None` = 未采集。
    quota_used: Option<f64>,
    /// M14-S3：限额（USD）。`None` = 不限 / 未采集。
    quota_limit: Option<f64>,
    /// M14-S3：币种。
    currency: Option<String>,
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
                    quota_used: row.quota_used,
                    quota_limit: row.quota_limit,
                    currency: row.currency,
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

// ============================================ Token 消耗统计（M13-S1）

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayUsageDto {
    pub id: i64,
    pub ts: i64,
    pub site_id: i64,
    pub model: String,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageSnapshotDto {
    pub id: i64,
    pub ts: i64,
    pub site_id: i64,
    pub used: f64,
    pub remaining: f64,
    pub currency: String,
    pub known: bool,
}

#[tauri::command]
pub fn recent_gateway_usage(
    state: State<'_, AppState>,
    hours: Option<i64>,
) -> Result<Vec<GatewayUsageDto>, String> {
    state
        .service
        .store()
        .recent_gateway_usage(hours.unwrap_or(24))
        .map(|rows| {
            rows.into_iter()
                .map(|row| GatewayUsageDto {
                    id: row.id,
                    ts: row.ts,
                    site_id: row.site_id,
                    model: row.model,
                    prompt_tokens: row.prompt_tokens,
                    completion_tokens: row.completion_tokens,
                    total_tokens: row.total_tokens,
                })
                .collect()
        })
        .map_err(|e| e.to_string())
}

// ============================================ M14-S1：模型别名映射（B-110）

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AliasEntryDto {
    pub alias: String,
    pub real_model: String,
}

#[tauri::command]
pub fn list_alias_map(state: State<'_, AppState>) -> Result<Vec<AliasEntryDto>, String> {
    state
        .service
        .store()
        .list_alias_map()
        .map(|rows| {
            rows.into_iter()
                .map(|(alias, real_model)| AliasEntryDto { alias, real_model })
                .collect()
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn upsert_alias(
    state: State<'_, AppState>,
    alias: String,
    real_model: String,
) -> Result<(), String> {
    state
        .service
        .store()
        .upsert_alias(&alias, &real_model)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn delete_alias(state: State<'_, AppState>, alias: String) -> Result<(), String> {
    state
        .service
        .store()
        .delete_alias(&alias)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn recent_usage_snapshots(
    state: State<'_, AppState>,
    hours: Option<i64>,
) -> Result<Vec<UsageSnapshotDto>, String> {
    state
        .service
        .store()
        .recent_usage_snapshots(hours.unwrap_or(168))
        .map(|rows| {
            rows.into_iter()
                .map(|row| UsageSnapshotDto {
                    id: row.id,
                    ts: row.ts,
                    site_id: row.site_id,
                    used: row.used,
                    remaining: row.remaining,
                    currency: row.currency,
                    known: row.known,
                })
                .collect()
        })
        .map_err(|e| e.to_string())
}

/// M14-S3：一把 key 一天的用量采样（Sub2API `usage/daily`）。**不含密钥**。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyUsageSampleDto {
    date: String,
    requests: i64,
    input_tokens: i64,
    output_tokens: i64,
    total_tokens: i64,
    cost: f64,
}

/// M14-S3：查一把 key 近 `days`（默认 30）天的 per-key 用量采样（PRD FR-3）。
#[tauri::command]
pub fn recent_key_usage(
    state: State<'_, AppState>,
    key_id: i64,
    days: Option<i64>,
) -> Result<Vec<KeyUsageSampleDto>, String> {
    state
        .service
        .store()
        .recent_key_usage(key_id, days.unwrap_or(30))
        .map(|rows| {
            rows.into_iter()
                .map(|row| KeyUsageSampleDto {
                    date: row.date,
                    requests: row.requests,
                    input_tokens: row.input_tokens,
                    output_tokens: row.output_tokens,
                    total_tokens: row.total_tokens,
                    cost: row.cost,
                })
                .collect()
        })
        .map_err(|e| e.to_string())
}

// ============================================ M34-S1：用量看板

/// M34-S1：网关 token 用量按（本地日, 站点, 模型）聚合的一行。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageDailyDto {
    date: String,
    site_id: i64,
    model: String,
    requests: i64,
    prompt_tokens: i64,
    completion_tokens: i64,
    total_tokens: i64,
    /// M43-S2：本组命中的价格币种（同模型不同时段不同币种 ⇒ 拆成多行）。
    currency: Option<String>,
    /// M43-S2：能定价部分的估算成本；`None` = 整组都没有价格（未知，不是 0）。
    estimated_cost: Option<f64>,
    unpriced_requests: i64,
    unpriced_tokens: i64,
}

/// M34-S1：站点余额快照按（本地日, 站点）聚合的一行（每天取最后一条）。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageSnapshotDailyDto {
    date: String,
    site_id: i64,
    used: f64,
    remaining: f64,
    currency: String,
    samples: i64,
}

/// M34-S1：`usage_samples` 按 key 汇总的一行（join `keys` 取名字与币种）。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyUsageTotalDto {
    key_id: i64,
    site_id: i64,
    key_name: String,
    requests: i64,
    input_tokens: i64,
    output_tokens: i64,
    total_tokens: i64,
    /// M43-S2：站点自报成本合计；`None` = 都没上报（不是 0）。
    cost: Option<f64>,
    currency: Option<String>,
}

/// M34-S1：用量页一次取全的聚合数据。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageDashboardDto {
    /// 夹取后的实际窗口天数（前端据此渲染「近 N 天」）。
    range_days: i64,
    /// 回显筛选；`None` = 全部站点。
    site_id: Option<i64>,
    daily: Vec<UsageDailyDto>,
    snapshots: Vec<UsageSnapshotDailyDto>,
    key_usage: Vec<KeyUsageTotalDto>,
    /// M43-S2：按 agent × 币种的成本聚合（`agent_label = ''` = 未归因旧数据）。
    by_agent: Vec<AgentUsageDto>,
}

/// M43-S2：按 agent（认证时的 label 快照）× 币种。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentUsageDto {
    agent_label: String,
    currency: Option<String>,
    requests: i64,
    total_tokens: i64,
    estimated_cost: Option<f64>,
    unpriced_requests: i64,
}

/// M43-S2：一个价格版本。
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ModelPriceDto {
    pub id: i64,
    pub model: String,
    pub input_per_mtok: f64,
    pub output_per_mtok: f64,
    pub currency: String,
    pub effective_from: i64,
    pub created_at: i64,
}

/// M43-S2：写入一个价格版本（`id` 由服务端生成）。
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelPriceInputDto {
    pub model: String,
    pub input_per_mtok: f64,
    pub output_per_mtok: f64,
    pub currency: String,
    pub effective_from: i64,
}

/// M43-S2：一行站点账单。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteBillDto {
    pub id: i64,
    pub site_id: i64,
    pub day: String,
    pub amount: Option<f64>,
    pub currency: Option<String>,
    pub requests: Option<i64>,
    pub source: String,
    pub fetched_at: i64,
}

/// M43-S2：账单能力探测结果。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BillProbeDto {
    /// `"supported"` | `"unsupported"` | `"needsLogin"` | `"failed"`
    pub status: String,
    pub currency: Option<String>,
    pub reason: Option<String>,
}

/// M43-S2：导入结果。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteBillImportDto {
    pub imported: usize,
    pub pages: usize,
    pub partial: bool,
    pub currency: Option<String>,
    pub currency_override_used: bool,
}

/// M34-S1：用量页数据（只读；不写库、不改采集口径）。
///
/// `days` 缺省 30，夹到 `1..=90`（与 90 天裁剪窗口一致）；`site_id` 缺省 = 全部站点。
/// 三条查询任一失败 ⇒ 整条命令报错（不返回半份数据）。
#[tauri::command]
pub fn usage_dashboard(
    state: State<'_, AppState>,
    days: Option<i64>,
    site_id: Option<i64>,
) -> Result<UsageDashboardDto, String> {
    let range_days = tianshu_relay_core::store::clamp_usage_days(days.unwrap_or(30));
    let store = state.service.store();
    let daily = store
        .usage_daily(range_days, site_id)
        .map_err(|e| e.to_string())?;
    let snapshots = store
        .usage_snapshot_daily(range_days, site_id)
        .map_err(|e| e.to_string())?;
    let key_usage = store
        .key_usage_totals(range_days, site_id)
        .map_err(|e| e.to_string())?;
    let by_agent = store
        .usage_by_agent(range_days)
        .map_err(|e| e.to_string())?;
    Ok(UsageDashboardDto {
        range_days,
        site_id,
        daily: daily
            .into_iter()
            .map(|row| UsageDailyDto {
                date: row.date,
                site_id: row.site_id,
                model: row.model,
                requests: row.requests,
                prompt_tokens: row.prompt_tokens,
                completion_tokens: row.completion_tokens,
                total_tokens: row.total_tokens,
                currency: row.currency,
                estimated_cost: row.estimated_cost,
                unpriced_requests: row.unpriced_requests,
                unpriced_tokens: row.unpriced_tokens,
            })
            .collect(),
        snapshots: snapshots
            .into_iter()
            .map(|row| UsageSnapshotDailyDto {
                date: row.date,
                site_id: row.site_id,
                used: row.used,
                remaining: row.remaining,
                currency: row.currency,
                samples: row.samples,
            })
            .collect(),
        key_usage: key_usage
            .into_iter()
            .map(|row| KeyUsageTotalDto {
                key_id: row.key_id,
                site_id: row.site_id,
                key_name: row.key_name,
                requests: row.requests,
                input_tokens: row.input_tokens,
                output_tokens: row.output_tokens,
                total_tokens: row.total_tokens,
                cost: row.cost,
                currency: row.currency,
            })
            .collect(),
        by_agent: by_agent
            .into_iter()
            .map(|row| AgentUsageDto {
                agent_label: row.agent_label,
                currency: row.currency,
                requests: row.requests,
                total_tokens: row.total_tokens,
                estimated_cost: row.estimated_cost,
                unpriced_requests: row.unpriced_requests,
            })
            .collect(),
    })
}

// ============================================ M43-S2：模型单价与站点账单

/// 全部价格版本（只读）。
#[tauri::command]
pub fn model_price_list(state: State<'_, AppState>) -> Result<Vec<ModelPriceDto>, String> {
    state
        .service
        .store()
        .model_price_list()
        .map(|rows| {
            rows.into_iter()
                .map(|r| ModelPriceDto {
                    id: r.id,
                    model: r.model,
                    input_per_mtok: r.input_per_mtok,
                    output_per_mtok: r.output_per_mtok,
                    currency: r.currency,
                    effective_from: r.effective_from,
                    created_at: r.created_at,
                })
                .collect()
        })
        .map_err(|e| e.to_string())
}

/// 写入一个价格版本（同一 `(model, currency, effectiveFrom)` 覆盖价格）。
#[tauri::command]
pub fn model_price_upsert(
    state: State<'_, AppState>,
    price: ModelPriceInputDto,
) -> Result<ModelPriceDto, String> {
    let store = state.service.store();
    let id = store
        .model_price_upsert(
            &price.model,
            price.input_per_mtok,
            price.output_per_mtok,
            &price.currency,
            price.effective_from,
        )
        .map_err(|e| e.to_string())?;
    store
        .model_price_list()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|r| r.id == id)
        .map(|r| ModelPriceDto {
            id: r.id,
            model: r.model,
            input_per_mtok: r.input_per_mtok,
            output_per_mtok: r.output_per_mtok,
            currency: r.currency,
            effective_from: r.effective_from,
            created_at: r.created_at,
        })
        .ok_or_else(|| "写入后读回价格版本失败".to_string())
}

/// 删除一个价格版本（估算是展示层：删掉后该时段成本变回「未知」）。
#[tauri::command]
pub fn model_price_delete(state: State<'_, AppState>, id: i64) -> Result<bool, String> {
    state
        .service
        .store()
        .model_price_delete(id)
        .map_err(|e| e.to_string())
}

// ============================================ M47-S2：内置模型名单

/// 思考能力（名单给的能力面，不是用户当前选择）。
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CatalogThinkingDto {
    /// `"thinking"`（预算形态）或 `"reasoning_effort"`（枚举形态）。
    param: String,
    max_level: String,
    default_level: String,
    budget_low: u32,
    budget_medium: u32,
    budget_high: u32,
    budget_xhigh: u32,
}

/// 一条价格。
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CatalogPriceDto {
    currency: String,
    input_per_mtok: f64,
    output_per_mtok: f64,
    cache_read_per_mtok: Option<f64>,
}

/// 名单里的一条模型（合并本机覆盖后的**生效值**）。
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CatalogModelDto {
    id: String,
    display_name: String,
    vendor: String,
    /// `"openai_chat"` / `"openai_responses"` / `"anthropic_messages"` / `"gemini"`
    protocol: String,
    anthropic_compatible: bool,
    context_window: u32,
    max_output_tokens: u32,
    thinking: Option<CatalogThinkingDto>,
    thinking_unsupported: bool,
    prices: Vec<CatalogPriceDto>,
    deprecated: bool,
    /// 该条是否被本机覆盖改过（界面据此显示「本机覆盖」+ 恢复入口）。
    overridden: bool,
}

/// 名单状态 + 全部条目（一次调用给界面渲染整张表）。
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CatalogStatusDto {
    /// `"remote"` / `"bundled"` / `"empty"`
    source: String,
    schema_version: u32,
    generated_at: String,
    entries: usize,
    overrides: usize,
    last_success_at: i64,
    last_error: Option<String>,
    url: String,
    auto_sync: bool,
    models: Vec<CatalogModelDto>,
}

/// 一次同步的回报。
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CatalogSyncDto {
    bytes: usize,
    accepted: usize,
    skipped: usize,
    generated_at: String,
    unchanged: bool,
    status: CatalogStatusDto,
}

/// 本机覆盖的入参（缺省字段 = 不改）。
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct CatalogOverrideInputDto {
    context_window: Option<u32>,
    max_output_tokens: Option<u32>,
    thinking_level: Option<String>,
    thinking_supported: Option<bool>,
    price_input_per_mtok: Option<f64>,
    price_output_per_mtok: Option<f64>,
    price_currency: Option<String>,
}

impl CatalogOverrideInputDto {
    fn into_patch(self) -> Result<tianshu_relay_core::model_catalog::ModelOverride, String> {
        let thinking_level = match self.thinking_level.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(raw) => Some(
                tianshu_relay_core::model_catalog::ThinkingLevel::parse(raw)
                    .ok_or_else(|| format!("思考档位非法: {raw}"))?,
            ),
        };
        Ok(tianshu_relay_core::model_catalog::ModelOverride {
            context_window: self.context_window,
            max_output_tokens: self.max_output_tokens,
            thinking_level,
            thinking_supported: self.thinking_supported,
            price_input_per_mtok: self.price_input_per_mtok,
            price_output_per_mtok: self.price_output_per_mtok,
            price_currency: self.price_currency,
        })
    }
}

fn catalog_status_dto(state: &AppState) -> CatalogStatusDto {
    let status = state.service.catalog_status();
    let settings = state.service.settings().ok();
    let models = state
        .service
        .catalog_entries()
        .into_iter()
        .map(|m| CatalogModelDto {
            overridden: state.service.catalog().override_for(&m.id).is_some(),
            id: m.id,
            display_name: m.display_name,
            vendor: m.vendor,
            protocol: m.protocol.as_str().to_string(),
            anthropic_compatible: m.anthropic_compatible,
            context_window: m.context_window,
            max_output_tokens: m.max_output_tokens,
            thinking: m.thinking.map(|spec| CatalogThinkingDto {
                param: spec.param.as_str().to_string(),
                max_level: spec.max_level.as_str().to_string(),
                default_level: spec.default_level.as_str().to_string(),
                budget_low: spec.budget_low,
                budget_medium: spec.budget_medium,
                budget_high: spec.budget_high,
                budget_xhigh: spec.budget_xhigh,
            }),
            thinking_unsupported: m.thinking_unsupported,
            prices: m
                .prices
                .into_iter()
                .map(|p| CatalogPriceDto {
                    currency: p.currency,
                    input_per_mtok: p.input_per_mtok,
                    output_per_mtok: p.output_per_mtok,
                    cache_read_per_mtok: p.cache_read_per_mtok,
                })
                .collect(),
            deprecated: m.deprecated,
        })
        .collect();
    CatalogStatusDto {
        source: status.source.to_string(),
        schema_version: status.schema_version,
        generated_at: status.generated_at,
        entries: status.entries,
        overrides: status.overrides,
        last_success_at: status.last_success_at,
        last_error: status.last_error,
        url: settings
            .as_ref()
            .map(|s| s.catalog_url.clone())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| tianshu_relay_core::model_catalog::CATALOG_URL.to_string()),
        auto_sync: settings.map(|s| s.catalog_auto_sync).unwrap_or(true),
        models,
    }
}

/// 名单现状 + 全部条目（只读，不联网）。
#[tauri::command]
pub fn catalog_status(state: State<'_, AppState>) -> Result<CatalogStatusDto, String> {
    Ok(catalog_status_dto(&state))
}

/// 从 GitHub 拉一次名单（失败保留旧缓存，错误原样给界面）。
#[tauri::command]
pub async fn catalog_sync(state: State<'_, AppState>) -> Result<CatalogSyncDto, String> {
    let report = state.service.sync_model_catalog().await?;
    Ok(CatalogSyncDto {
        bytes: report.bytes,
        accepted: report.accepted,
        skipped: report.skipped,
        generated_at: report.generated_at,
        unchanged: report.unchanged,
        status: catalog_status_dto(&state),
    })
}

/// 写 / 撤销一条本机覆盖（`patch = null` 即撤销）。
#[tauri::command]
pub fn catalog_set_override(
    state: State<'_, AppState>,
    model_id: String,
    patch: Option<CatalogOverrideInputDto>,
) -> Result<CatalogStatusDto, String> {
    let patch = patch.map(|input| input.into_patch()).transpose()?;
    state
        .service
        .set_catalog_override(&model_id, patch)
        .map_err(|e| e.to_string())?;
    Ok(catalog_status_dto(&state))
}

// ============================================ M46-S5：站点 / key 硬预算
//
// 校验全部在 store::budget_create（validate 先行）；命令层只做 DTO 映射与
// 当期已花计算（任一失败 ⇒ 整条命令报错，与 usage_dashboard 同口径）。

/// M46-S5：一行预算（`spent_usd` = 当期已花，命令层逐行算）。
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SiteBudgetDto {
    pub id: i64,
    pub site_id: i64,
    pub key_id: Option<i64>,
    pub period: String,
    pub limit_usd: f64,
    pub created_at: i64,
    pub spent_usd: f64,
}

/// M46-S5：新建预算的输入（`id` 由服务端生成；更新 = 删除 + 重建，不另设命令）。
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteBudgetInputDto {
    pub site_id: i64,
    pub key_id: Option<i64>,
    pub period: String,
    pub limit_usd: f64,
}

fn site_budget_to_dto(
    row: &tianshu_relay_core::store::SiteBudgetRow,
    spent_usd: f64,
) -> SiteBudgetDto {
    SiteBudgetDto {
        id: row.id,
        site_id: row.site_id,
        key_id: row.key_id,
        period: row.period.clone(),
        limit_usd: row.limit_usd,
        created_at: row.created_at,
        spent_usd,
    }
}

/// 全部预算行（含当期已花）。
#[tauri::command]
pub fn site_budget_list(state: State<'_, AppState>) -> Result<Vec<SiteBudgetDto>, String> {
    let store = state.service.store();
    let rows = store.budget_list().map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(rows.len());
    for row in &rows {
        let spent = store
            .budget_spent_usd(row.site_id, row.key_id, &row.period)
            .map_err(|e| e.to_string())?;
        out.push(site_budget_to_dto(row, spent));
    }
    Ok(out)
}

/// 新建一行预算（非法输入由 store 拒绝，不落库）。
#[tauri::command]
pub fn site_budget_create(
    state: State<'_, AppState>,
    budget: SiteBudgetInputDto,
) -> Result<SiteBudgetDto, String> {
    let store = state.service.store();
    let id = store
        .budget_create(
            budget.site_id,
            budget.key_id,
            &budget.period,
            budget.limit_usd,
        )
        .map_err(|e| e.to_string())?;
    let row = store
        .budget_list()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|r| r.id == id)
        .ok_or_else(|| "写入后读回预算行失败".to_string())?;
    let spent = store
        .budget_spent_usd(row.site_id, row.key_id, &row.period)
        .map_err(|e| e.to_string())?;
    Ok(site_budget_to_dto(&row, spent))
}

/// 删除一行预算（不存在 ⇒ false，与 model_price_delete 同口径）。
#[tauri::command]
pub fn site_budget_delete(state: State<'_, AppState>, id: i64) -> Result<bool, String> {
    state
        .service
        .store()
        .budget_delete(id)
        .map_err(|e| e.to_string())
}

/// 只读探测站点账单能力（一次 GET，不写库）。
#[tauri::command]
pub async fn site_bill_probe(
    state: State<'_, AppState>,
    site_id: i64,
) -> Result<BillProbeDto, String> {
    use tianshu_relay_core::site::billing::BillProbe;
    let probe = state.service.probe_site_billing(site_id).await;
    Ok(match probe {
        BillProbe::Supported { currency } => BillProbeDto {
            status: "supported".to_string(),
            currency,
            reason: None,
        },
        BillProbe::Unsupported => BillProbeDto {
            status: "unsupported".to_string(),
            currency: None,
            reason: None,
        },
        BillProbe::NeedsLogin => BillProbeDto {
            status: "needsLogin".to_string(),
            currency: None,
            reason: None,
        },
        BillProbe::Failed { reason } => BillProbeDto {
            status: "failed".to_string(),
            currency: None,
            reason: Some(reason),
        },
    })
}

/// 只读导入站点账单（分页上限 10 / 上限 20；`currency` 只填站点没给币种的洞）。
#[tauri::command]
pub async fn site_bill_import(
    state: State<'_, AppState>,
    site_id: i64,
    max_pages: Option<usize>,
    currency: Option<String>,
) -> Result<SiteBillImportDto, String> {
    let (outcome, _rows) = state
        .service
        .import_site_billing(site_id, max_pages, currency.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    Ok(SiteBillImportDto {
        imported: outcome.imported,
        pages: outcome.pages,
        partial: outcome.partial,
        currency: outcome.currency,
        currency_override_used: outcome.currency_override_used,
    })
}

/// 近 `days` 天的站点账单（只读）。
#[tauri::command]
pub fn site_bills(
    state: State<'_, AppState>,
    days: Option<i64>,
) -> Result<Vec<SiteBillDto>, String> {
    let days = tianshu_relay_core::store::clamp_usage_days(days.unwrap_or(30));
    state
        .service
        .store()
        .site_bills(days)
        .map(|rows| {
            rows.into_iter()
                .map(|r| SiteBillDto {
                    id: r.id,
                    site_id: r.site_id,
                    day: r.day,
                    amount: r.amount,
                    currency: r.currency,
                    requests: r.requests,
                    source: r.source,
                    fetched_at: r.fetched_at,
                })
                .collect()
        })
        .map_err(|e| e.to_string())
}

/// M46-S6：一行账单对账结果（kind 为 "matched" | "gateway_only" | "bill_only" | "gateway_unpriced"；
/// bill_usd / diff_usd 为空只表示不可比——currency 非 USD、或为空、或 amount 为空；
/// 缺失侧按 0 计：gateway-only 行 bill_usd = 0.0、bill-only 行 gateway_usd = 0.0）。
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BillReconciliationDto {
    pub site_id: i64,
    pub day: String,
    pub gateway_usd: f64,
    pub bill_usd: Option<f64>,
    pub diff_usd: Option<f64>,
    pub flagged: bool,
    pub kind: String,
    pub source: Option<String>,
    /// DEBUG-G7 补齐 P3-K3：该站最近一次账单导入是否 partial（站级信号，
    /// 见核心层 `BillReconciliationRow::import_partial` 的语义说明）。
    pub import_partial: bool,
}

/// M46-S6：网关成本与站点自报账单的只读对账（近 `days` 天，缺省 30，夹到 1..=90；
/// `site_id` 缺省 = 全部站点）。任一查询失败 ⇒ 整条命令报错（不返回半份数据，
/// 与 usage_dashboard 同口径）。不写库、不发通知。
#[tauri::command]
pub fn bill_reconciliation(
    state: State<'_, AppState>,
    site_id: Option<i64>,
    days: Option<i64>,
) -> Result<Vec<BillReconciliationDto>, String> {
    let days = tianshu_relay_core::store::clamp_usage_days(days.unwrap_or(30));
    tianshu_relay_core::service::reconcile_bills(state.service.store(), site_id, days)
        .map(|rows| {
            rows.into_iter()
                .map(|r| BillReconciliationDto {
                    site_id: r.site_id,
                    day: r.day,
                    gateway_usd: r.gateway_usd,
                    bill_usd: r.bill_usd,
                    diff_usd: r.diff_usd,
                    flagged: r.flagged,
                    kind: r.kind.as_str().to_string(),
                    source: r.source,
                    import_partial: r.import_partial,
                })
                .collect()
        })
        .map_err(|e| e.to_string())
}

// ============================================ 漂移 / 设置 / 刷新（M3-S1）

fn settings_from_dto(dto: &SettingsDto) -> tianshu_relay_core::settings::Settings {
    tianshu_relay_core::settings::Settings {
        refresh_interval_secs: dto.refresh_interval_secs,
        balance_alert_threshold: dto.balance_alert_threshold,
        drift_check_on_start: dto.drift_check_on_start,
        gateway_enabled: dto.gateway_enabled,
        gateway_port: dto.gateway_port,
        gateway_max_request_mib: dto.gateway_max_request_mib,
        gateway_auto_start: dto.gateway_auto_start,
        gateway_last_site_id: dto.gateway_last_site_id,
        gateway_last_key_id: dto.gateway_last_key_id,
        gateway_token_grace_secs: dto.gateway_token_grace_secs,
        gateway_multi_site: dto.gateway_multi_site,
        collect_models: dto.collect_models,
        models_min_interval_secs: dto.models_min_interval_secs,
        gateway_key_health_interval_secs: dto.gateway_key_health_interval_secs,
        gateway_lb_top_n: dto.gateway_lb_top_n,
        gateway_per_site_concurrency: dto.gateway_per_site_concurrency,
        gateway_per_site_rate_limit: dto.gateway_per_site_rate_limit,
        gateway_per_site_burst: dto.gateway_per_site_burst,
        gateway_max_attempts: dto.gateway_max_attempts,
        gateway_session_affinity: dto.gateway_session_affinity,
        gateway_upstream_protocol: dto.gateway_upstream_protocol.clone(),
        gateway_routing_preset: dto.gateway_routing_preset.clone(),
        routing_rules: dto.routing_rules.clone(),
        theme: dto.theme.clone(),
        language: dto.language.clone(),
        proxy_url: dto.proxy_url.clone(),
        proxy_mode: dto.proxy_mode.clone(),
        telemetry_enabled: dto.telemetry_enabled,
        auto_update_enabled: dto.auto_update_enabled,
        catalog_auto_sync: dto.catalog_auto_sync,
        catalog_url: dto.catalog_url.clone(),
        notify_enabled: dto.notify_enabled,
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

fn settings_to_dto(settings: &tianshu_relay_core::settings::Settings) -> SettingsDto {
    SettingsDto {
        refresh_interval_secs: settings.refresh_interval_secs,
        balance_alert_threshold: settings.balance_alert_threshold,
        drift_check_on_start: settings.drift_check_on_start,
        gateway_enabled: settings.gateway_enabled,
        gateway_port: settings.gateway_port,
        gateway_max_request_mib: settings.gateway_max_request_mib,
        gateway_auto_start: settings.gateway_auto_start,
        gateway_last_site_id: settings.gateway_last_site_id,
        gateway_last_key_id: settings.gateway_last_key_id,
        gateway_token_grace_secs: settings.gateway_token_grace_secs,
        gateway_multi_site: settings.gateway_multi_site,
        collect_models: settings.collect_models,
        models_min_interval_secs: settings.models_min_interval_secs,
        gateway_key_health_interval_secs: settings.gateway_key_health_interval_secs,
        gateway_lb_top_n: settings.gateway_lb_top_n,
        gateway_per_site_concurrency: settings.gateway_per_site_concurrency,
        gateway_per_site_rate_limit: settings.gateway_per_site_rate_limit,
        gateway_per_site_burst: settings.gateway_per_site_burst,
        gateway_max_attempts: settings.gateway_max_attempts,
        gateway_session_affinity: settings.gateway_session_affinity,
        gateway_upstream_protocol: settings.gateway_upstream_protocol.clone(),
        gateway_routing_preset: settings.gateway_routing_preset.clone(),
        routing_rules: settings.routing_rules.clone(),
        theme: settings.theme.clone(),
        language: settings.language.clone(),
        proxy_url: settings.proxy_url.clone(),
        proxy_mode: settings.proxy_mode.clone(),
        telemetry_enabled: settings.telemetry_enabled,
        auto_update_enabled: settings.auto_update_enabled,
        catalog_auto_sync: settings.catalog_auto_sync,
        catalog_url: settings.catalog_url.clone(),
        notify_enabled: settings.notify_enabled,
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

/// 保存设置的返回（M41-S1 §4.2）：设置 + 网关状态 + 网关动作的失败原因。
///
/// `gateway_error` 有值 **也意味着设置已保存**——UI 必须同时说清这两件事。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsUpdateResultDto {
    settings: SettingsDto,
    gateway: GatewayStatusDto,
    gateway_error: Option<String>,
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
pub async fn update_settings(
    state: State<'_, AppState>,
    args: UpdateSettingsArgs,
) -> Result<SettingsUpdateResultDto, String> {
    // M41-S1：**从读旧设置之前就拿锁**，一直持到 stop/restart 结束（不是只锁 restart）。
    // 只锁 restart 的话，并发 `gateway_start` 会基于旧设置起一次网关，再被本函数的
    // restart 抢先——最终运行的那份既不是旧设置也不是新设置。
    let _op = state.gateway_op.lock().await;

    let prev = state.service.settings().map_err(|e| e.to_string())?;
    let mut next = settings_from_dto(&args.settings);
    // M41-S1 复审 P2-1：last_* 是服务端写的「上次成功运行」，不是用户设置。
    // 前端页面可能持有启动前的旧快照，回传会把新值覆盖回 0/旧值；这里强制沿用 prev。
    next.gateway_last_site_id = prev.gateway_last_site_id;
    next.gateway_last_key_id = prev.gateway_last_key_id;
    // 保存失败 ⇒ Err，网关不动（设置是唯一真相，但没保存成功就谈不上对齐）。
    state
        .service
        .update_settings(&next)
        .map_err(|e| e.to_string())?;

    let running = state
        .gateway
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().map(|run| run.handle.alive()))
        .unwrap_or(false);
    let transition = gateway_transition(&prev, &next, running);

    let mut gateway_error: Option<String> = None;
    match transition {
        GatewayTransition::None => {}
        GatewayTransition::Stop => {
            stop_gateway_locked(&state, true).await;
        }
        GatewayTransition::Restart => {
            // 用**运行态**的 site/key（不取命令参数、不取切页默认值）。
            let target = state
                .gateway
                .lock()
                .ok()
                .and_then(|guard| guard.as_ref().map(|run| (run.site_id, run.key_id)));
            stop_gateway_locked(&state, false).await;
            if let Some((site_id, key_id)) = target {
                if let Err(err) = start_gateway_locked(&state, site_id, key_id).await {
                    // 设置已保存，但网关没起来：明确返回 stopped + 可读原因，
                    // 绝不「保存成功但网关静默死掉」。
                    gateway_error =
                        Some(format!("设置已保存；网关未能按新设置重启（已停止）：{err}"));
                }
            }
        }
    }

    let settings = state.service.settings().map_err(|e| e.to_string())?;
    Ok(SettingsUpdateResultDto {
        settings: settings_to_dto(&settings),
        gateway: gateway_status_of(&state),
        gateway_error,
    })
}

/// `detect_system_proxy` 的返回：auto 模式下探测到的系统代理（已脱敏）。
///
/// `source` / `maskedUrl` 都是 `None` ⇒ 未检测到系统代理（auto 模式将直连）。
/// **不返回原始 URL**：`maskedUrl` 经 `DetectedProxy::masked_url` 脱敏，明文不过 IPC。
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct DetectProxyDto {
    pub source: Option<String>,
    pub masked_url: Option<String>,
}

/// 探测系统代理（M10-S2）：供设置页「自动」模式展示「检测到 …（来源 …）」。
///
/// 只读、不落库、不改设置；探测是 `scutil` / `reg query` / 环境变量，无副作用。
/// 失败（探测不到）⇒ `DetectProxyDto { source: None, masked_url: None }`，不报错。
#[tauri::command]
pub fn detect_system_proxy() -> DetectProxyDto {
    match tianshu_relay_core::proxy::detect_system_proxy() {
        Some(d) => DetectProxyDto {
            source: Some(d.source.as_str().to_string()),
            masked_url: Some(d.masked_url()),
        },
        None => DetectProxyDto {
            source: None,
            masked_url: None,
        },
    }
}

// ============================================ 网关 / 导出 / 备份清理（M4-S2）

/// Unix 秒（仅用于把运行态宽限截止时间与「现在」比较；不参与持久化）。
fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn gateway_status_of(state: &AppState) -> GatewayStatusDto {
    // 「令牌是不是持久的」两个分支都用**同一个来源**：服务上「最近一次装配 / 轮换」的结果。
    // 网关没在跑时它不是「没意义」，而是「最近一次的结果」——冷启动时可能是 `false`
    // （本次会话还没装配过），而界面只在 `running` 时显示这个字段，所以不会有误导。
    // 反过来，如果这里硬编码 `false`，一次成功的「重新生成令牌」就会在停止状态下
    // 被报成「临时令牌」——那才是真的在说假话。
    let token_persistent = state.service.gateway_token_persistent();
    // M40-S2：未运行 ⇒ `mode="stopped"`，其余字段是**结构性空值**（UI 不显示它们）

    let tokens = gateway_token_dtos(state);
    let stopped = GatewayStatusDto {
        running: false,
        phase: "stopped".to_string(),
        url: None,
        token: None,
        site: None,
        token_persistent,
        last_exit: None,
        token_grace_until: None,
        // M42-S1：没在跑 ⇒ 没有监听地址（不要凭空写 127.0.0.1:port）。
        listen_addrs: Vec::new(),
        ipv6_degraded: false,
        ipv6_note: None,

        mode: "stopped".to_string(),
        candidates: Vec::new(),
        qps: 0.0,
        uptime_secs: 0,
        requests_total: 0,
        inflight: 0,
        failovers_total: 0,
        last_error: None,
        generation: 0,
        ewma_latency_ms: std::collections::BTreeMap::new(),

        tokens: tokens.clone(),
    };
    let Ok(guard) = state.gateway.lock() else {
        return stopped;
    };
    let Some(run) = guard.as_ref() else {
        return stopped;
    };
    let last_exit = run.handle.last_exit().map(|exit| GatewayExitDto {
        at: exit.at,
        reason: exit.reason.as_str().to_string(),
    });
    // M42-S1 §4.5：监听地址与 IPv6 降级状态来自**运行中的句柄**（不是推断）。
    let listen_addrs: Vec<String> = run
        .handle
        .addrs
        .iter()
        .map(|addr| addr.to_string())
        .collect();
    let (ipv6_degraded, ipv6_note) = match &run.handle.ipv6 {
        tianshu_relay_core::gateway::Ipv6State::Listening => (false, None),
        tianshu_relay_core::gateway::Ipv6State::Degraded { reason, .. } => {
            (true, Some(reason.clone()))
        }
    };
    if run.handle.alive() {
        let m = run.handle.metrics();
        let route_is_empty = run.handle.route_is_empty();
        // 站点 id → 显示名（与站点列表**同源**；查不到就不显示该候选）
        let names: std::collections::HashMap<i64, String> = state
            .service
            .sites()
            .unwrap_or_default()
            .into_iter()
            .map(|s| (s.id, s.display_name))
            .collect();
        let candidates = run
            .handle
            .candidates()
            .into_iter()
            .filter_map(|c| {
                names.get(&c.site_id).map(|name| GatewayCandidateDto {
                    site_id: c.site_id,
                    display_name: name.clone(),
                    key_id: c.key_id,
                    health: c.health.to_string(),
                    breaker: c.breaker.to_string(),
                })
            })
            .collect();
        // M40-S2：**最近**一条错误（按 per_site 的 last_error_at 取最大；无则 None）
        let last_error = m
            .per_site
            .values()
            .filter(|v| v.last_error.is_some())
            .max_by_key(|v| v.last_error_at.unwrap_or(0))
            .and_then(|v| v.last_error.clone());
        // M46-S2：每站 EWMA（只有 Some 的站进 map；无样本的站不在 map 里）。
        let ewma_latency_ms = m
            .per_site
            .iter()
            .filter_map(|(site_id, v)| v.ewma_latency_ms.map(|ewma| (*site_id, ewma)))
            .collect();
        GatewayStatusDto {
            running: true,
            phase: "running".to_string(),
            url: Some(run.handle.local_url()),
            token: Some(run.handle.token.clone()),
            site: Some(run.handle.site_display_name.clone()),
            token_persistent,
            last_exit,
            token_grace_until: run.token_grace_until.filter(|t| *t > unix_now_secs()),
            listen_addrs,
            ipv6_degraded,
            ipv6_note,

            mode: if route_is_empty { "single" } else { "multi" }.to_string(),
            candidates,
            qps: m.qps,
            uptime_secs: m.uptime_secs,
            requests_total: m.requests_total,
            inflight: m.inflight,
            failovers_total: m.failovers_total,
            last_error,
            generation: run.handle.generation(),
            ewma_latency_ms,

            tokens,
        }
    } else {
        // M41-S1：已死的句柄**绝不**报 running（url/token/site 一并清空，避免 UI 展示假地址）。
        GatewayStatusDto {
            running: false,
            phase: "crashed".to_string(),
            url: None,
            token: None,
            site: None,
            token_persistent,
            last_exit,
            token_grace_until: None,
            // 任务已死 ⇒ 端口已释放：不再报任何监听地址。
            listen_addrs: Vec::new(),
            ipv6_degraded: false,
            ipv6_note: None,

            // M40-S2：已死 ⇒ 与未运行同口径（stopped + 结构性空值）
            mode: "stopped".to_string(),
            candidates: Vec::new(),
            qps: 0.0,
            uptime_secs: 0,
            requests_total: 0,
            inflight: 0,
            failovers_total: 0,
            last_error: None,
            generation: 0,
            ewma_latency_ms: std::collections::BTreeMap::new(),

            tokens,
        }
    }
}

/// auto-start 的选组（M41-S1 §4.4.1，纯函数便于单测）。
///
/// ① 优先「上次成功运行」的 `(last_site_id, last_key_id)`，但四项校验全过才用：
///    站点存在、`health == "ok"`、密钥存在、`status == "enabled"`、且 `key.site_id == site_id`；
///    任一不满足 ⇒ **整体放弃**这组（不混用旧 site + 新 key）。
/// ② 回退：第一个 `health == "ok"` 的站点 + 该站点第一把 `enabled` 密钥（按 id 升序）。
/// ③ 都没有 ⇒ `None`（调用方跳过并记日志，不重试）。
pub(crate) fn auto_start_target(
    sites: &[tianshu_relay_core::service::SiteSummary],
    keys: &[tianshu_relay_core::store::KeyRow],
    last_site_id: i64,
    last_key_id: i64,
) -> Option<(i64, i64)> {
    if last_site_id > 0 && last_key_id > 0 {
        let site_ok = sites
            .iter()
            .any(|site| site.id == last_site_id && site.health == "ok");
        let key_ok = keys.iter().any(|key| {
            key.id == last_key_id && key.site_id == last_site_id && key.status == "enabled"
        });
        if site_ok && key_ok {
            return Some((last_site_id, last_key_id));
        }
    }
    let site = sites
        .iter()
        .filter(|site| site.health == "ok")
        .min_by_key(|site| site.id)?;
    let key = keys
        .iter()
        .filter(|key| key.site_id == site.id && key.status == "enabled")
        .min_by_key(|key| key.id)?;
    Some((site.id, key.id))
}

/// auto-start 的**有序候选清单**（B-224 P2 修复）：首选是 [`auto_start_target`]，
/// 其后是其余健康站点 / 启用密钥的组合（按站点 id、密钥 id 升序，去重）。
///
/// 此前选组本身有回退（上次组失效 ⇒ 第一个健康组），但**首选组启动失败**
/// 后没有任何回退——只 eprintln 一句就结束，网关停在「未运行」。现在调用方
/// 按此清单依次试启动，首个成功即停；全部失败才放弃（仍只试一轮，不循环）。
pub(crate) fn auto_start_targets(
    sites: &[tianshu_relay_core::service::SiteSummary],
    keys: &[tianshu_relay_core::store::KeyRow],
    last_site_id: i64,
    last_key_id: i64,
) -> Vec<(i64, i64)> {
    let mut out: Vec<(i64, i64)> = Vec::new();
    if let Some(first) = auto_start_target(sites, keys, last_site_id, last_key_id) {
        out.push(first);
    }
    let mut sites_sorted: Vec<&tianshu_relay_core::service::SiteSummary> =
        sites.iter().filter(|site| site.health == "ok").collect();
    sites_sorted.sort_by_key(|site| site.id);
    for site in sites_sorted {
        let mut site_keys: Vec<&tianshu_relay_core::store::KeyRow> = keys
            .iter()
            .filter(|key| key.site_id == site.id && key.status == "enabled")
            .collect();
        site_keys.sort_by_key(|key| key.id);
        for key in site_keys {
            let pair = (site.id, key.id);
            if !out.contains(&pair) {
                out.push(pair);
            }
        }
    }
    out
}

/// 设置变更需要网关做什么（M41-S1 §4.3 的纯函数，单测钉住矩阵）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GatewayTransition {
    None,
    Stop,
    Restart,
}

/// 判据是**白名单**：只有端口 / 多站 / 代理 / 运行时限流、请求上限与路由规则才重启。
/// 名单覆盖走共享快照，无需重启；catalogUrl/autoSync 只控制同步，也不重启网关。
///
/// 新增设置字段默认不触发重启，除非显式加进这里（复审要点）。
fn gateway_transition(
    prev: &tianshu_relay_core::settings::Settings,
    next: &tianshu_relay_core::settings::Settings,
    running: bool,
) -> GatewayTransition {
    if !next.gateway_enabled {
        // 关总开关 ⇒ 必须停（未运行就是无操作）。
        return if running {
            GatewayTransition::Stop
        } else {
            GatewayTransition::None
        };
    }
    if !prev.gateway_enabled {
        // 打开开关**不**自动启动：用户点「启动」（auto-start 只用于应用启动）。
        return GatewayTransition::None;
    }
    if !running {
        return GatewayTransition::None;
    }
    if prev.gateway_port != next.gateway_port
        || prev.gateway_multi_site != next.gateway_multi_site
        || prev.proxy_mode != next.proxy_mode
        || prev.proxy_url != next.proxy_url
        || prev.gateway_max_request_mib != next.gateway_max_request_mib
        || prev.gateway_key_health_interval_secs != next.gateway_key_health_interval_secs
        || prev.gateway_per_site_concurrency != next.gateway_per_site_concurrency
        || prev.gateway_per_site_rate_limit != next.gateway_per_site_rate_limit
        || prev.gateway_per_site_burst != next.gateway_per_site_burst
        || prev.gateway_max_attempts != next.gateway_max_attempts
        || prev.gateway_session_affinity != next.gateway_session_affinity
        || prev.gateway_upstream_protocol != next.gateway_upstream_protocol
        || prev.gateway_routing_preset != next.gateway_routing_preset
        || prev.routing_rules != next.routing_rules
    {
        GatewayTransition::Restart
    } else {
        GatewayTransition::None
    }
}

/// 运行中网关的「指向网关」端点：`<local_url>/v1` + 本地令牌（M8-S4 §6.1）。
///
/// 拼 `/v1` 是硬要求：网关只服务 `/health` 与 `/v1/*`，而 `local_url()` 没有路径段。
/// 少拼一次的表现是「投递成功、agent 404」——那是最难查的一类失败。
///
/// **例外（P1-5）**：Claude Code（Anthropic SDK）的 `ANTHROPIC_BASE_URL` 约定**不带** `/v1`
/// ——SDK 自己拼 `/v1/messages`。给它带 `/v1` 会变成 `/v1/v1/messages`，网关原样转发 ⇒ 404。
/// OpenAI / Codex 等 SDK 的 base_url 仍要带 `/v1`（SDK 拼 `/chat/completions`）。
///
/// 网关没在跑 ⇒ 明确拒绝：此时**没有**可信的地址可写（端口来自设置，但网关没跑时
/// 写下去只会让 agent 连不上）。这不是限制，是把「指向网关」的定义执行到底。
fn gateway_endpoint_of(
    state: &State<'_, AppState>,
    channel: &tianshu_relay_core::delivery::DeliveryChannel,
) -> Result<tianshu_relay_core::delivery::GatewayEndpoint, String> {
    let guard = state
        .gateway
        .lock()
        .map_err(|_| "网关状态锁失效（需要重启应用）".to_string())?;
    let run = guard.as_ref().ok_or_else(|| {
        "本地网关没有在运行：请先在「网关」页启动它，再把通道改为指向网关。".to_string()
    })?;
    Ok(tianshu_relay_core::delivery::GatewayEndpoint {
        base_url: tianshu_relay_core::delivery::gateway_base_url_for(
            channel,
            &run.handle.local_url(),
        ),
        token: run.handle.token.clone(),
    })
}

/// 解析投递模式。`None` / 空 / `"site"` ⇒ 站点模式（**既有调用点的行为一字不变**）。
///
/// 认不出的取值 ⇒ `Err`，**不**回退成默认：静默回退会让「指向网关」的请求被当成站点投递，
/// 而用户以为已经切过去了。
fn parse_delivery_mode(
    raw: Option<&str>,
) -> Result<tianshu_relay_core::delivery::DeliveryMode, String> {
    match raw.map(str::trim) {
        None | Some("") | Some("site") => Ok(tianshu_relay_core::delivery::DeliveryMode::Site),
        Some("gateway") => Ok(tianshu_relay_core::delivery::DeliveryMode::LocalGateway),
        Some(other) => Err(format!(
            "未知的投递模式 {other:?}；只支持 \"site\" 与 \"gateway\""
        )),
    }
}

#[tauri::command]
pub fn gateway_status(state: State<'_, AppState>) -> Result<GatewayStatusDto, String> {
    Ok(gateway_status_of(&state))
}

/// M1：当前网关进程内的路由轨迹；停止 / 重启后为空，不落库、不走网络。
#[tauri::command]
pub fn gateway_route_traces(
    state: State<'_, AppState>,
) -> Result<Vec<tianshu_relay_core::gateway::trace::RouteTrace>, String> {
    let guard = state
        .gateway
        .lock()
        .map_err(|_| "网关状态锁不可用".to_string())?;
    Ok(guard
        .as_ref()
        .filter(|run| run.handle.alive())
        .map(|run| run.handle.route_traces())
        .unwrap_or_default())
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
async fn stop_gateway(handle: tianshu_relay_core::gateway::GatewayHandle) {
    match tokio::time::timeout(GATEWAY_SHUTDOWN_TIMEOUT, handle.shutdown_and_wait()).await {
        Ok(()) => {}
        Err(_) => eprintln!(
            "[tianshu-relay] 等待网关停止超过 {GATEWAY_SHUTDOWN_TIMEOUT:?}（在途连接未收尾）；\
             监听端口在此之前已释放，继续。"
        ),
    }
}

/// 停掉当前网关并等端口释放，再按 M40/M7 的顺序把用量与失败落库。
///
/// `end_session`：`true` = 这次停止结束当前会话（`gateway_stop` / 设置里关开关 /
/// 令牌轮换）；`false` = 只是「换一个网关」（`gateway_start` / 设置变更重启）——
/// 后者随后调用的 `gateway_config` 会自增会话代号，行为与 M40-S1 逐字一致。
///
/// 调用方**必须**已持有 `gateway_op`（本函数不加锁，避免重入死锁）。
async fn stop_gateway_locked(state: &AppState, end_session: bool) {
    let previous = match state.gateway.lock() {
        Ok(mut guard) => guard.take(),
        Err(_) => None,
    };
    if let Some(run) = previous {
        // 等端口真正释放再返回：否则紧接着 start 会撞 AddrInUse。
        stop_gateway(run.handle).await;
    }
    // M40-S1：用量先落库（同样在 `end_gateway_session` 之前）。
    state.service.drain_gateway_usage();
    // M7-S5 复审 P2-1：旧网关的失败必须归给产生它的那次会话。
    state.service.drain_gateway_failures();
    if end_session {
        // M8-S1 §11.1：drain 之后作废会话（顺序是硬要求）。
        state.service.end_gateway_session();
    }
}

/// 用指定站点/密钥启动网关，并把「上次成功运行」写进设置。
///
/// 调用方**必须**已持有 `gateway_op`。这是**成功启动的唯一出口**——手动启动、自动启动、
/// 设置变更重启、令牌轮换都走这里，保证 `gateway_last_*` 不会漏写。
pub(crate) async fn start_gateway_locked(
    state: &AppState,
    site_id: i64,
    key_id: i64,
) -> Result<(), String> {
    let settings = state.service.settings().map_err(|e| e.to_string())?;
    // M41-S1 复审 P2-3：总开关检查必须在**唯一启动出口**里再做一次。
    // `gateway_start` 的入口检查在 `gateway_op` 之外；并发「关开关」拿到锁后，
    // 旧检查仍可能放行一次启动，留下「设置已关但端口在听」。
    if !settings.gateway_enabled {
        return Err(
            "本地网关总开关是关的。请到「设置」页勾选「允许启动本地网关」并保存后再启动。"
                .to_string(),
        );
    }
    let config = state
        .service
        .gateway_config(site_id, key_id, settings.gateway_port)
        .map_err(|e| e.to_string())?;
    let handle = tianshu_relay_core::gateway::start(config)
        .await
        .map_err(|e| e.to_string())?;
    // M42-S1 §4.5：IPv6 降级必须**可见**——状态字段（`listenAddrs` / `ipv6Degraded`）之外，
    // 再记一条 `Warn` 事件。payload **只含** port 与 kind，message 用固定文案：
    // kind 直接取核心层在绑定失败时按 `ErrorKind` 定好的结构化分类
    // （B-224 P2 修复；此前这里靠 `reason.contains("占用")` 反推 kind，且
    // message 里还带了 reason 原文，与「事件表只留可判定事实」自述矛盾）。
    if let tianshu_relay_core::gateway::Ipv6State::Degraded { kind, .. } = &handle.ipv6 {
        state
            .service
            .record_event(tianshu_relay_core::observability::event_with_payload(
                tianshu_relay_core::observability::Level::Warn,
                "gateway",
                "网关 IPv6 回环未监听，仅监听 127.0.0.1",
                serde_json::json!({ "port": handle.addr.port(), "kind": kind.as_str() }),
            ));
    }

    // M43-S1：把库里的有效令牌播种进运行态集合（空 ⇒ legacy 回退）。
    match state.service.gateway_tokens_for_registry() {
        Ok(tokens) => handle.set_tokens(tokens),
        Err(err) => eprintln!("[tianshu-relay] 读取网关令牌集合失败（回退 legacy 单令牌）: {err}"),
    }
    if let Ok(mut guard) = state.gateway.lock() {
        *guard = Some(GatewayRunning {
            handle,
            site_id,
            key_id,
            token_grace_until: None,
        });
    }
    // M41-S1：成功启动后记下这一组（auto-start 的首选）。写失败只记日志、不回滚网关。
    if settings.gateway_last_site_id != site_id || settings.gateway_last_key_id != key_id {
        let mut next = settings;
        next.gateway_last_site_id = site_id;
        next.gateway_last_key_id = key_id;
        if let Err(err) = state.service.update_settings(&next) {
            eprintln!("[tianshu-relay] 记录上次成功运行的站点/密钥失败（不影响网关）: {err}");
        }
    }
    Ok(())
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

    // 先停旧的（并等端口真正释放：`shutdown()` 只发信号就返回，立刻 bind 会撞 B-64）；
    // 用量/失败的落库顺序与 M40-S1 一致（end_session=false：换网关不结束会话，
    // 下一行 `gateway_config` 会自增会话代号）。
    stop_gateway_locked(&state, false).await;
    start_gateway_locked(&state, args.site_id, args.key_id).await?;
    Ok(gateway_status_of(&state))
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

    // P1-6 完整修复：网关在跑时，用**运行态**记录的 site_id/key_id 构造 config，
    // 不用命令参数。切页后 args 可能带默认值，用它会把网关悄悄换到错误的 site/key
    //（令牌轮换的语义是「不换站、不换密钥」，只换本地令牌）。args 仅作一致性校验。
    //
    // 网关没在跑 ⇒ 只换钥匙串（不需要 args，下一次启动用新令牌）。
    let running = state.gateway.lock().map(|g| g.is_some()).unwrap_or(false);
    if !running {
        state
            .service
            .rotate_gateway_token()
            .map_err(|e| e.to_string())?;
        return Ok(gateway_status_of(&state));
    }

    // 网关在跑：从运行态读 site_id/key_id（不 take——校验/构造/换令牌失败时网关继续跑）。
    let (site_id, key_id) = {
        let guard = state
            .gateway
            .lock()
            .map_err(|_| "网关状态锁失效（需要重启应用）".to_string())?;
        let run = guard.as_ref().ok_or_else(|| "网关已不在运行".to_string())?;
        // args 一致性校验：前端传来的 site/key 必须与启动时一致，否则拒绝，
        // 避免「以为在轮换 A 站令牌、实际切到 B 站」。
        //
        // P2-14：这一步**必须**在 `rotate_gateway_token` **之前**（下面第 1466 行那条注释
        // 写的就是这个顺序）。抽成纯函数是为了让「先校验后换令牌」这条可被单测钉住。
        rotation_args_are_consistent(
            (run.site_id, run.key_id),
            args.map(|args| (args.site_id, args.key_id)),
        )?;
        (run.site_id, run.key_id)
    };

    // 校验（gateway_config 校验 key 存在 + 未回收 + 属于站点）。在 rotate 之前：
    // 校验失败 ⇒ 不换令牌、网关继续跑旧令牌。这一份 config 的 token 是旧令牌，
    // 丢弃——rotate 之后要重新构造一份读新令牌（P2-7）。
    let port = state
        .service
        .settings()
        .map_err(|e| e.to_string())?
        .gateway_port;
    state
        .service
        .validate_gateway_target(site_id, key_id)
        .map_err(|e| e.to_string())?;

    // M41-S2：先取默认行（`is_default = 1`，不看 label）。没有默认行 ⇒ 走 legacy 路径
    // （registry 空 ⇒ 只认 `config.token`，宽限无从表达，保持既有重启语义、零宽限）。
    let default_row = state
        .service
        .store()
        .default_gateway_token()
        .map_err(|e| e.to_string())?;
    let Some(default_row) = default_row else {
        state
            .service
            .rotate_gateway_token()
            .map_err(|e| e.to_string())?;
        let config = state
            .service
            .gateway_config(site_id, key_id, port)
            .map_err(|e| {
                format!("令牌已换，但新令牌无法用于网关（网关仍用旧令牌运行，请重启网关）：{e}")
            })?;
        let run = state
            .gateway
            .lock()
            .map_err(|_| "网关状态锁失效（需要重启应用）".to_string())?
            .take()
            .ok_or_else(|| "网关已不在运行".to_string())?;
        stop_gateway(run.handle).await;
        state.service.drain_gateway_usage();
        state.service.drain_gateway_failures();
        state.service.end_gateway_session();
        let handle = tianshu_relay_core::gateway::start(config)
            .await
            .map_err(|e| e.to_string())?;
        if let Ok(mut guard) = state.gateway.lock() {
            *guard = Some(GatewayRunning {
                handle,
                site_id,
                key_id,
                token_grace_until: None,
            });
        }
        return Ok(gateway_status_of(&state));
    };

    // 写序硬约束：钥匙串 → DB → 内存（DB 失败时运行态绝不先换新令牌，否则重启后旧 hash 复活）。
    let grace_secs = state
        .service
        .settings()
        .map_err(|e| e.to_string())?
        .gateway_token_grace_secs;
    let old_hash = default_row.token_hash.clone();
    let default_id = default_row.id;
    let default_label = default_row.label.clone();

    state
        .service
        .rotate_gateway_token()
        .map_err(|e| e.to_string())?;
    // 新明文只在这里用一下（算 hash），不进日志/事件/DTO。
    // P1（M41-S2 复审）：不能调 `gateway_config`——那会自增会话代号并替换运行时快照，
    // 让**正在运行**的旧网关丢掉后续的 usage/failure 事件。只读钥匙串明文。
    let new_plaintext = state.service.gateway_token_plaintext().map_err(|e| {
        format!("令牌已换，但新令牌无法读取（网关仍用旧令牌运行，请重试轮换）：{e}")
    })?;
    let new_hash = tianshu_relay_core::gateway::sha256_hex(&new_plaintext);
    if let Err(err) = state
        .service
        .store()
        .update_gateway_token_hash(default_id, &new_hash)
    {
        return Err(format!(
            "令牌已换但入库失败（网关仍用旧令牌运行；重启后会自动对账到新令牌，也可重试轮换）：{err}"
        ));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let grace_until_unix = if grace_secs > 0 {
        Some(now + i64::from(grace_secs))
    } else {
        None
    };
    if let Ok(mut guard) = state.gateway.lock() {
        if let Some(run) = guard.as_mut() {
            let registry = run.handle.token_registry();
            if let Ok(mut entries) = registry.write() {
                // 只保留「上一代」宽限：先清掉旧的宽限条目（registry 不膨胀）。
                entries.retain(|entry| entry.grace_until.is_none());
                if let Some(entry) = entries.iter_mut().find(|entry| entry.id == default_id) {
                    entry.token_hash = new_hash.clone();
                } else {
                    entries.push(tianshu_relay_core::gateway::GatewayTokenEntry {
                        id: default_id,
                        token_hash: new_hash,
                        label: default_label.clone(),
                        grace_until: None,
                    });
                }
                if grace_secs > 0 {
                    entries.push(tianshu_relay_core::gateway::GatewayTokenEntry {
                        id: default_id,
                        token_hash: old_hash,
                        label: default_label,
                        grace_until: Some(
                            std::time::Instant::now()
                                + std::time::Duration::from_secs(u64::from(grace_secs)),
                        ),
                    });
                }
            }
            // 状态 DTO 的 `token` 是「当前默认令牌明文」：不重启网关时句柄里的那份要手动换新。
            run.handle.token = new_plaintext.to_string();
            run.token_grace_until = grace_until_unix;
        }
    }
    Ok(gateway_status_of(&state))
}

/// 停止网关。与 `gateway_start` 共用同一把操作锁，避免「停」与「启」交错。
#[tauri::command]
pub async fn gateway_stop(state: State<'_, AppState>) -> Result<GatewayStatusDto, String> {
    let _op = state.gateway_op.lock().await;

    // 停网关 + 等端口释放 + 用量/失败落库 + 作废会话（顺序见 `stop_gateway_locked`；
    // 这是「这一次会话结束了」的天然边界，M7-S5/M8-S1/M40-S1 的理由不变）。
    stop_gateway_locked(&state, true).await;
    Ok(gateway_status_of(&state))
}

#[tauri::command]
pub fn export_bundle(
    state: State<'_, AppState>,
    args: ExportArgs,
) -> Result<ExportResultDto, String> {
    // M16-S6a §12：三条护栏（绝对路径 / 不跟随符号链接 / 已存在须显式确认）。
    let path = resolve_bundle_path(
        &state.data_dir,
        args.path.as_deref(),
        args.overwrite.unwrap_or(false),
    )?;
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

/// `~/.tianshu-relay/exports/<prefix>-<unix 秒>.json`。
///
/// 抽出来是因为配置导出与诊断包**必须落在同一个目录**：两者都会被登记进
/// 「已知导出物」表、都会被 `audit_redaction` 扫到，散在两个目录只会让用户
/// 在报障时找错地方。
fn default_export_path_in(dir: &std::path::Path, prefix: &str) -> std::path::PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    dir.join(format!("{prefix}-{stamp}.json"))
}

/// 诊断包导出文件名白名单前缀（P3-18）。
const DIAGNOSTICS_FILE_PREFIX: &str = "tianshu-relay-diagnostics";

/// `export_bundle` 的路径护栏（M16-S6a §12 的**产品裁定**）。
///
/// 裁定：备份包的「另存为到用户选定路径」是**产品特性**（用户显式选择），
/// 不像诊断包那样必须锁在应用目录内 ⇒ **不收紧路径本身**，但加三条护栏：
///
/// 1. **绝对路径**：相对路径随 cwd 漂移——写到哪里取决于谁启动了进程（Finder / 终端 / 自启）。
/// 2. **不跟随符号链接**：目标是链接时拒绝，否则等于允许写到链接指向的任何地方。
/// 3. **已存在须显式确认**：`overwrite != true` 时拒绝，**绝不静默覆盖**用户的文件。
fn resolve_bundle_path(
    data_dir: &std::path::Path,
    requested: Option<&str>,
    overwrite: bool,
) -> Result<std::path::PathBuf, String> {
    let Some(raw) = requested.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(default_export_path_in(
            &data_dir.join("exports"),
            "tianshu-relay-export",
        ));
    };

    let path = std::path::Path::new(raw);
    if !path.is_absolute() {
        return Err(format!(
            "备份包只能导出到**绝对路径**（相对路径会随工作目录漂移）；被拒路径：{raw}"
        ));
    }
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "备份包目标已存在且是符号链接（拒绝跟随）；被拒路径：{raw}"
            ));
        }
    }
    if path.exists() && !overwrite {
        return Err(format!(
            "目标已存在，未覆盖：{raw}。确认要覆盖它时请带 overwrite=true（界面应先让用户确认）"
        ));
    }
    Ok(path.to_path_buf())
}

/// 诊断包导出的**路径收敛**（P3-18）。
///
/// 背景：`export_diagnostics` 的 IPC `path` 参数此前是**任意路径**——它可以静默覆盖
/// `~/.zshrc` 这类文件，也会跟随符号链接写到别处。诊断包是**用户主动导出**的东西，
/// 它没有理由写到导出目录之外。
///
/// 允许两种形态：
/// ① `requested` 为空 ⇒ 默认路径 `<dir>/tianshu-relay-diagnostics-<stamp>.json`；
/// ② 给了路径 ⇒ 必须落在**导出目录内**、文件名以 `tianshu-relay-diagnostics` 开头、
///    以 `.json` 结尾，且**不得**含 `..`；目标已存在且是**符号链接**时拒绝（不跟随）。
///
/// 拒绝时返回可读原因（含被拒路径原文）：**不静默改成默认路径**——静默改道会让调用方
/// 以为文件写到了自己指定的地方，而实际上没有。
fn resolve_diagnostics_path(
    data_dir: &std::path::Path,
    requested: Option<&str>,
) -> Result<std::path::PathBuf, String> {
    let dir = data_dir.join("exports");
    let Some(raw) = requested.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(default_export_path_in(&dir, DIAGNOSTICS_FILE_PREFIX));
    };

    // ① `..` 一律拒绝（不归一——归一之后就没法告诉用户「你写的路径越界了」）
    let raw_path = std::path::Path::new(raw);
    if raw_path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!(
            "诊断包只能导出到 {} 内的 {DIAGNOSTICS_FILE_PREFIX}-*.json；被拒路径：{raw}（不允许 `..`）",
            dir.display()
        ));
    }

    // ② 相对路径按导出目录解析；绝对路径必须**就在**导出目录里
    let candidate = if raw_path.is_absolute() {
        raw_path.to_path_buf()
    } else {
        dir.join(raw_path)
    };

    // ③ 父目录必须与导出目录是同一个（目录已存在时用 `canonicalize` 消除符号链接差异；
    //    目录还不存在时按字面比较——`create_dir_all` 之后就是它）
    let parent = candidate.parent().unwrap_or(std::path::Path::new(""));
    let same_dir = match (parent.canonicalize(), dir.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => parent == dir,
    };
    if !same_dir {
        return Err(format!(
            "诊断包只能导出到 {} 内；被拒路径：{raw}",
            dir.display()
        ));
    }

    // ④ 文件名白名单：前缀 + `.json`
    let name = candidate
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if !name.starts_with(DIAGNOSTICS_FILE_PREFIX) || !name.ends_with(".json") {
        return Err(format!(
            "诊断包文件名必须是 {DIAGNOSTICS_FILE_PREFIX}-*.json；被拒路径：{raw}"
        ));
    }

    // ⑤ 目标已存在且是符号链接 ⇒ 拒绝（不跟随；否则等于允许写到链接指向的任何地方）
    if let Ok(meta) = std::fs::symlink_metadata(&candidate) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "诊断包目标已存在且是符号链接（拒绝跟随）；被拒路径：{raw}"
            ));
        }
    }

    Ok(candidate)
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
    // P3-18：`path` 不再是任意路径——收敛到导出目录 + 文件名白名单（越界一律拒绝）。
    //
    // 允许目录取**服务自己的 home**（生产 = `home_dir()`，测试 = 每个 app 独立的临时目录）：
    // 与 `ServiceConfig.home` 同源，测试因此不必碰真实 `~/.tianshu-relay`。
    let path = resolve_diagnostics_path(&state.data_dir, args.path.as_deref())?;
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

/// 界面「起来了」的一次**显式**上报（M16-S6a 追加项）。
///
/// # 为什么需要这条命令
///
/// GUI 真机走查（M16-S7）实测：macOS 的 AX 树里看不到 WebView 内部
/// （`entire contents of window 1` = 0），截图又不稳定 ⇒ 自动化**没有任何可靠判据**
/// 判断「界面真的起来了」。有了这条之后：
/// ① 走查脚本轮询临时库里的 `ui_ready_at` 就能得到**真正的端到端冷启动**时间；
/// ② B-15「invoke 真实往返」从「AX 看不到 ⇒ 不可证」变成「`ui_ready_at` 有值 ⇒ 前端确实
///    调通过一次 IPC」。
///
/// # 为什么必须由**前端显式调用**
///
/// 后端自己写等于什么都没证明（那只说明进程起来了）。**不**在启动路径里自动写。
///
/// 幂等：重复调用覆盖时间戳（前端每次进入就绪态都会调一次）。
#[tauri::command]
pub fn report_ui_ready(state: State<'_, AppState>) -> Result<(), String> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    state
        .service
        .store()
        .set_setting("ui_ready_at", &now_ms.to_string())
        .map_err(|e| e.to_string())
}

/// 脱敏审计：扫描数据库（含 WAL/SHM）、备份目录与事件表，确认零明文。
#[tauri::command]
pub fn audit_redaction(state: State<'_, AppState>) -> Result<AuditReportDto, String> {
    use tianshu_relay_core::audit::AuditFinding;

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
    /// **站点原生**的分组标识（M19-S1 / B-161）。`None` = 该站点以分组名为标识。
    ///
    /// 这一层此前也把它丢了：`GroupInfo.id` 在适配器里没被填上，DTO 里又没有这个字段，
    /// 于是前端只拿得到名字。Sub2API 建密钥要的是数字主键 ⇒ 名字被静默丢弃。
    id: Option<String>,
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
                    id: g.id,
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
/// **不返回任何明文**——理由见 `TianshuRelayService::sync_site_keys` 的文档。
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
    /// 旧 key 本地记录的分组**显示名**。`None` = 没绑过分组。
    ///
    /// 预览只展示、不校验（`rotation_plan` 一个请求都不发）；校验发生在执行时
    /// （M20-S1 / B-166：站点上已无该分组 ⇒ 动手前拒绝，不会建出无分组的 key）。
    old_group_name: Option<String>,
    /// 旧 key 本地记录的分组**站点原生 id**（M22-S1）。`None` = 旧行没存过 / 站点没有 id 概念。
    ///
    /// 有它时前端可以做**按 id 的精确在线校验**（id 是站点主键，分组改名不影响）；
    /// 没有它就只能按名字比对，并在界面上如实说明「改过名就认不出来」。
    old_group_id: Option<String>,
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
            old_group_name: plan.old_group_name,
            old_group_id: plan.old_group_id,
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
    /// P2-7：轮换后网关是否**已用新密钥重启**。
    ///
    /// `false` 有三种情形，用 `gatewayNote` 区分：① 网关本来没在跑（最常见，`None`）；
    /// ② 网关跑在**别的**站点上（note 说明）；③ 重启失败（note 说明「网关已停，请手动启动」）。
    gateway_restarted: bool,
    /// 与 `gateway_restarted` 配对的原因（已脱敏）。`None` = 无需说明。
    gateway_note: Option<String>,
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
    // P2-7（跨文件半）：与 gateway_start / gateway_stop / gateway_rotate_token 串行——
    // 「停旧 → 绑新」不能与它们的序列交错（同一把 `gateway_op`）。
    let _op = state.gateway_op.lock().await;

    let run = state
        .service
        .rotate_key(key_id, tianshu_relay_core::site::KeySpec::named(name))
        .await
        .map_err(|e| e.to_string())?;
    clear_gateway_session_pins(&state);
    let (revoke, revoke_reason) = match &run.revoke {
        tianshu_relay_core::service::RevokeOutcome::Revoked => ("revoked".to_string(), None),
        tianshu_relay_core::service::RevokeOutcome::SkippedNoRemoteId => {
            ("skippedNoRemoteId".to_string(), None)
        }
        tianshu_relay_core::service::RevokeOutcome::NotAttempted => {
            ("notAttempted".to_string(), None)
        }
        tianshu_relay_core::service::RevokeOutcome::Failed(reason) => {
            ("failed".to_string(), Some(reason.clone()))
        }
    };

    // P2-7：轮换把站点侧那把旧 key 回收了，运行中的网关若还用**旧 key_id** 取明文，
    // 之后每一次请求都只会 502，直到用户手动重启网关。这里照 `gateway_rotate_token`
    // 的做法，用**新 key_id** 重建 config 并重启。
    //
    // 失败**不**把整次轮换报成失败：轮换的三步已经成功、密钥已经换过；报成失败会诱导
    // 用户重试，而重试会再建一把 key。改为在 DTO 里带 `gatewayRestarted=false` + 原因。
    let (gateway_restarted, gateway_note) =
        match restart_gateway_after_rotation(&state, key_id, run.new_key.id).await {
            Ok(RotationGatewayRestart::Restarted) => (true, None),
            Ok(RotationGatewayRestart::NotRunning) => (false, None),
            Ok(RotationGatewayRestart::OtherSite) => (
                false,
                Some("网关正在别的站点上运行，未重启（轮换不影响它）".to_string()),
            ),
            Err(note) => (false, Some(note)),
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
        gateway_restarted,
        gateway_note,
    })
}

/// P2-14 的**判据**（纯函数，单独可测）：`gateway_rotate_token` 的 `args` 与运行态是否一致。
///
/// - `args = None`（前端没传）⇒ 放行：令牌轮换的语义是「不换站、不换密钥」，
///   运行态就是唯一事实来源（P1-6）。
/// - `args = Some(_)` 且与运行态不符 ⇒ 拒绝。**这一步必须在换令牌之前**——
///   换完再拒会让「令牌已换、网关还在用旧令牌」，用户看到的是永久的 401/502。
fn rotation_args_are_consistent(
    running: (i64, i64),
    args: Option<(i64, i64)>,
) -> Result<(), String> {
    match args {
        Some((site_id, key_id)) if (site_id, key_id) != running => Err(format!(
            "轮换令牌不切换站点/密钥：网关运行在站点 #{} 密钥 #{}，但参数指向站点 #{} 密钥 #{}",
            running.0, running.1, site_id, key_id
        )),
        _ => Ok(()),
    }
}

/// 轮换后网关重启的三种结局。
enum RotationGatewayRestart {
    /// 网关没在跑（最常见）——什么都不做。
    NotRunning,
    /// 网关跑在**别的**站点上——不动它（不把网关悄悄切到被轮换的站点）。
    OtherSite,
    /// 已用新 key_id 重启。
    Restarted,
}

/// P2-7 的**判据**（纯函数，单独可测）：该不该为这次轮换重启网关。
///
/// 两个条件都必需：① 网关在跑；② 它跑的正是**被轮换那把 key 所属的站点**。
/// 只判①会把网关切到别的站点；只判②会在网关没跑时白起一个。
fn should_restart_gateway_after_rotation(running_site: Option<i64>, key_site: Option<i64>) -> bool {
    matches!((running_site, key_site), (Some(a), Some(b)) if a == b)
}

/// P2-7 的执行体：take + stop + drain + end_session + 用 `new_key_id` 重建 config + start。
///
/// `Err(note)` 表示「轮换成功但网关没起来」——note 是给用户看的原因（已脱敏）。
async fn restart_gateway_after_rotation(
    state: &AppState,
    rotated_key_id: i64,
    new_key_id: i64,
) -> Result<RotationGatewayRestart, String> {
    let running = match state.gateway.lock() {
        Ok(guard) => guard.as_ref().map(|run| (run.site_id, run.key_id)),
        Err(_) => return Err("网关状态锁失效（需要重启应用）".to_string()),
    };
    let Some((site_id, _running_key_id)) = running else {
        return Ok(RotationGatewayRestart::NotRunning);
    };

    // 被轮换的 key 属于哪个站点：用 `stored_keys()` 的现成结果，不新开查询路径。
    let key_site = state
        .service
        .stored_keys()
        .ok()
        .and_then(|rows| rows.into_iter().find(|row| row.id == rotated_key_id))
        .map(|row| row.site_id);
    if !should_restart_gateway_after_rotation(Some(site_id), key_site) {
        return Ok(RotationGatewayRestart::OtherSite);
    }

    // 先构造 config（新 key_id）——它失败时网关**还没停**，用户手上的东西不受影响。
    let port = state
        .service
        .settings()
        .map_err(|e| e.to_string())?
        .gateway_port;
    let config = state
        .service
        .gateway_config(site_id, new_key_id, port)
        .map_err(|e| format!("轮换已成功，但新密钥无法用于网关（网关未动）：{e}"))?;

    // take + stop + drain + end_session（与 gateway_rotate_token 同款序列）
    let run = match state.gateway.lock() {
        Ok(mut guard) => guard.take(),
        Err(_) => None,
    }
    .ok_or_else(|| "网关已不在运行（轮换已完成）".to_string())?;
    stop_gateway(run.handle).await;
    state.service.drain_gateway_failures();
    state.service.end_gateway_session();

    let handle = tianshu_relay_core::gateway::start(config)
        .await
        .map_err(|e| format!("轮换已成功，但网关重启失败（网关已停，请手动启动）：{e}"))?;
    if let Ok(mut guard) = state.gateway.lock() {
        *guard = Some(GatewayRunning {
            handle,
            site_id,
            key_id: new_key_id,
            token_grace_until: None,
        });
    }
    Ok(RotationGatewayRestart::Restarted)
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

fn autostart_dto(state: tianshu_relay_core::autostart::AutostartState) -> AutostartDto {
    use tianshu_relay_core::autostart::AutostartState;
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
/// `hidden` 固定为 `true`（见 `TianshuRelayService::autostart_plan`）：自启的用途就是后台刷新，
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

/// 探测每个投递落点的 Agent 是否安装、版本与安装命令（M31-S1）。
///
/// 只读：核心层不执行安装命令、不创建目录、不写盘。返回值里的
/// `installCommands` 只供界面展示/复制，应用不会替用户运行。
#[tauri::command]
pub async fn detect_agents(
    state: State<'_, AppState>,
) -> Result<Vec<tianshu_relay_core::agents::AgentStatus>, String> {
    // 20 条探测内部已是并行，但每条都要等 `--version`（单条上限 5s）。
    // 放到 blocking 线程池执行，避免占住 IPC/窗口主线程：只克隆一个 PathBuf，
    // 不把 `State` 移进闭包。
    let home = state.service.home().to_path_buf();
    tauri::async_runtime::spawn_blocking(move || tianshu_relay_core::agents::detect_agents(&home))
        .await
        .map_err(|error| format!("Agent 探测线程异常退出：{error}"))
}

/// Cline CLI 探针（DEBUG-G7 P2-C3，B-291 应用内路径之 ①）。
///
/// 只读检测：不写盘、不调 `cline auth`。返回找到与否、路径、版本与人话说明；
/// “没找到”不等于“未安装”（见核心层 `probe_cline_cli` 的 note）。
#[tauri::command]
pub async fn cline_cli_probe(
    state: State<'_, AppState>,
) -> Result<tianshu_relay_core::agents::ClineCliProbe, String> {
    let home = state.service.home().to_path_buf();
    tauri::async_runtime::spawn_blocking(move || tianshu_relay_core::agents::probe_cline_cli(&home))
        .await
        .map_err(|error| format!("Cline CLI 探测线程异常退出：{error}"))
}

/// 检查 Agent 更新（M34-S1，**只读**）。
///
/// 先跑既有的 `detect_agents`（blocking 线程池），再按去重后的更新源并发拉最新版本
/// （npm registry / Homebrew cask API / VS Code Marketplace 三个公开端点，不带任何凭证）。
/// 单个源失败只影响对应通道，不整体报错；代理从 settings 解析，与 `detect_site` 同一份逻辑。
#[tauri::command]
pub async fn check_agent_updates(
    state: State<'_, AppState>,
) -> Result<Vec<tianshu_relay_core::agent_updates::AgentUpdateStatus>, String> {
    let home = state.service.home().to_path_buf();
    // 代理从 settings 解析，与 `detect_site` / 生产 transport 同一份 `resolve_proxy`（M10-S2）
    let proxy = state.service.settings().ok().and_then(|s| {
        let mode = tianshu_relay_core::proxy::ProxyMode::parse(&s.proxy_mode)
            .unwrap_or(tianshu_relay_core::proxy::ProxyMode::Auto);
        tianshu_relay_core::proxy::resolve_proxy(mode, &s.proxy_url)
            .ok()
            .flatten()
            .map(|d| d.url)
    });
    let detect_home = home.clone();
    let statuses = tauri::async_runtime::spawn_blocking(move || {
        tianshu_relay_core::agents::detect_agents(&detect_home)
    })
    .await
    .map_err(|error| format!("Agent 探测线程异常退出：{error}"))?;

    Ok(tianshu_relay_core::agent_updates::check_agent_updates(&home, &statuses, proxy).await)
}

/// 执行一次白名单一键更新（M34-S1）。
///
/// **安全边界**：命令 argv 全部来自核心静态表 `agent_updates::specs()`，本命令只接收
/// `channel`；不经 shell、不接受任何命令/参数/URL；`stdin = null`；每条策略独立超时并 kill。
/// 未知 channel / 不支持一键更新的通道 ⇒ `Err(String)`（前端只在用户勾选同意后调用）。
#[tauri::command]
pub async fn update_agent(
    state: State<'_, AppState>,
    channel: String,
) -> Result<tianshu_relay_core::agent_updates::AgentUpdateOutcome, String> {
    let home = state.service.home().to_path_buf();
    tauri::async_runtime::spawn_blocking(move || {
        tianshu_relay_core::agent_updates::update_agent(&home, &channel)
    })
    .await
    .map_err(|error| format!("更新线程异常退出：{error}"))?
    .map_err(|error| error.to_string())
}

/// 用该密钥查询站点上**该分组可用**的模型 id（M32-S1）。
///
/// 只读：密钥只经核心层 `key_secret`（唯一咽喉，已回收的 key 会被拒绝且不发请求），
/// **不落日志、不进事件、不进错误文案**；返回已排序去重的 `string[]`。
/// 站点不可达 / 登出 / 密钥回收 ⇒ `Err`，前端回退为可手动输入的文本框。
#[tauri::command]
pub async fn list_key_models(
    state: State<'_, AppState>,
    key_id: i64,
) -> Result<Vec<String>, String> {
    state
        .service
        .models_for_key(key_id)
        .await
        .map_err(|e| e.to_string())
}

/// 探测「已知但本版本不托管」的 agent 落点（M7-S3 / 章程 R-7）。
///
/// 只读：核心层永不创建目录、永不写盘。它存在的理由是**不静默**——
/// 用户在 Cline / Roo Code 里配了中转站，本产品既不能帮他注入，也不该假装没这回事。
#[tauri::command]
pub fn detect_unmanaged_targets(state: State<'_, AppState>) -> Vec<UnmanagedTargetDto> {
    tianshu_relay_core::delivery::detect_unmanaged_targets(state.service.home())
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
    tianshu_relay_core::naming::default_key_name(
        tianshu_relay_core::naming::DEFAULT_APP_ID,
        &agent_id,
        (year, month, day),
    )
}

/// 删除站点上的某把令牌（B-82 的独立路径）。
///
/// **两件事一起做**（M47-S1）：站点侧 DELETE，然后**物理删掉**本地 `keys` 行——
/// 用户要求「删除后的密钥不要再显示」，所以本地不再留「已回收」墓碑行。
/// 代价是 `ON DELETE CASCADE` 会带走该 key 的绑定 / 用量采样 / 检测历史，
/// 逐条清单见 `tianshu_relay_core::store::Store::delete_key`；最小溯源由一条
/// `events` 事件承担（带 id、名字、站点、远端 id）。
///
/// `confirm` 必须是 `true`。删除是不可逆的站点侧动作，**不提供「无参数即执行」的形态**：
/// 误触的代价是用户正在用的 key 在站点上消失。
#[tauri::command]
pub async fn revoke_key(
    state: State<'_, AppState>,
    site_id: i64,
    remote_id: String,
    confirm: bool,
) -> Result<RevokeReportDto, String> {
    if !confirm {
        return Err("删除站点侧密钥需要二次确认".to_string());
    }
    let report = state
        .service
        .revoke_key(site_id, &remote_id)
        .await
        .map_err(|e| e.to_string())?;
    // M2：密钥生命周期变化后旧 pin 不再可靠（本地自增 id 可能复用）。
    // 清空是保守且便宜的；失败不影响已经完成的撤销结果。
    clear_gateway_session_pins(&state);
    Ok(RevokeReportDto::from(report))
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
            "「同时删除站点侧的密钥」不可逆，需要二次确认；若只想解除本机绑定，请取消勾选。"
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

/// 一次**删除**（站点侧删除 + 本地删行）的回报（B-100 / M8-S4 §7）。
///
/// 两个布尔值必须分开给界面：`revoked = true` + `localRowDeleted = false` 是
/// 「站点侧已经删了（不可逆），但本地记录没删掉」——**整体仍然是成功**，
/// 界面要说的是「已删除，但本地记录没删掉」，而不是「删除失败」。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeReportDto {
    site_id: i64,
    remote_id: Option<String>,
    revoked: bool,
    local_row_deleted: bool,
    vault_deleted: bool,
    note: Option<String>,
}

impl From<tianshu_relay_core::service::RevokeReport> for RevokeReportDto {
    fn from(report: tianshu_relay_core::service::RevokeReport) -> Self {
        Self {
            site_id: report.site_id,
            remote_id: report.remote_id,
            revoked: report.revoked,
            local_row_deleted: report.local_row_deleted,
            vault_deleted: report.vault_deleted,
            note: report.note,
        }
    }
}

/// 一次解绑的结果（M8-S4 §5.4 第 4 条：**四种文案**都要能说出来）。
///
/// `unbound` / `alreadyUnbound` / `revoked` 三者互相独立：
/// 「这次新解开了 2 条」「本来就是解绑状态」「删除成功 1 把、失败 1 把」可以同时成立。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnbindOutcomeDto {
    unbound: usize,
    already_unbound: usize,
    revoked: Vec<RevokeReportDto>,
    note: Option<String>,
}

impl From<tianshu_relay_core::service::UnbindOutcome> for UnbindOutcomeDto {
    fn from(outcome: tianshu_relay_core::service::UnbindOutcome) -> Self {
        Self {
            unbound: outcome.unbound,
            already_unbound: outcome.already_unbound,
            revoked: outcome.revoked.into_iter().map(Into::into).collect(),
            note: outcome.note,
        }
    }
}

// ============================================================== 人工过验证码（M8-S2 / FR-1:102）

/// 人工验证的**取数方式**（M28-S2 / B-191 B 路；判据只来自能力表）。
///
/// - `Cookies`：会话走 `Set-Cookie`，`window.cookies()` 抓得到（NewAPI）；
/// - `Bearer`：会话是响应体里的 access token，走「WebView localStorage → `tianshu-relay-creds://`」
///   回传（Sub2API）；
/// - `Unsupported`：该类型没有任何 WebView 兜底（Custom / 未知类型）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CaptchaCaptureMode {
    Cookies,
    Bearer,
    Unsupported,
}

/// Cookies 分支里是否要走 NewAPI 的「用 `new_api_refresh` 换 access_token」路径
/// （M29-S1 / B-193）。
///
/// 为什么只有 NewAPI：新版 NewAPI 的 API 鉴权只认 `Authorization: Bearer <access_token>`
/// （cookie 对 API 无效），所以抓完 cookie 还要换 token；**其它 cookie 站点**（例如
/// Custom）保持 HEAD 的 cookie-only `complete_captcha`，逐字不动。
///
/// 抽成纯函数是为了让这条分支**可被单测钉住**——内联的 `matches!` 只有读代码才能验证。
fn cookie_login_uses_newapi_exchange(kind: Option<tianshu_relay_core::site::SiteKind>) -> bool {
    matches!(kind, Some(tianshu_relay_core::site::SiteKind::NewApi))
}

/// 能力位 → 取数方式。**cookie 优先**：两者都为 true 的站点目前不存在，但若将来出现，
/// 抓 cookie 比注入脚本更保守（不执行任何 JS、不加 incognito）。
///
/// `None`（认不出的 `kind`）⇒ `Unsupported`：fail-closed，绝不猜一条取数路径。
fn captcha_capture_mode(kind: Option<tianshu_relay_core::site::SiteKind>) -> CaptchaCaptureMode {
    let Some(kind) = kind else {
        return CaptchaCaptureMode::Unsupported;
    };
    let caps = tianshu_relay_core::site::capability::capabilities(kind);
    if caps.webview_captcha_supported {
        CaptchaCaptureMode::Cookies
    } else if caps.webview_bearer_supported {
        CaptchaCaptureMode::Bearer
    } else {
        CaptchaCaptureMode::Unsupported
    }
}

/// 导航回传的 origin 闸门（纯函数，便于单测）：当前文档 URL 必须与站点同源。
///
/// 两侧都走 [`tianshu_relay_core::site::webview_creds::site_origin`]（WHATWG 解析 +
/// 尾点 / IDN / 默认端口归一），避免 `Url::origin()` 与 `origin_of` 口径不一致——
/// 尾点 FQDN 的站点在 Bearer 路径会静默 fail-closed。
fn navigation_origin_allowed(current_url: &str, expected_origin: &str) -> bool {
    tianshu_relay_core::site::webview_creds::site_origin(current_url)
        .map(|origin| origin == expected_origin)
        .unwrap_or(false)
}

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

// ============================================================== 钥匙串迁移（M38-S2 / B-219）

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultMigrationFailureDto {
    reference: String,
    reason: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultMigrationStatusDto {
    /// `done | pending | retryExhausted | abandoned`
    phase: String,
    attempts: u32,
    last_at: Option<i64>,
    last_error: Option<String>,
    failures: Vec<VaultMigrationFailureDto>,
    cleanup_pending: Vec<VaultMigrationFailureDto>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultMigrationReportDto {
    imported: usize,
    skipped: usize,
    cleanup_pending: Vec<VaultMigrationFailureDto>,
    failed: Vec<VaultMigrationFailureDto>,
    status: VaultMigrationStatusDto,
}

fn migration_failure_dtos(pairs: &[(String, String)]) -> Vec<VaultMigrationFailureDto> {
    pairs
        .iter()
        .map(|(reference, reason)| VaultMigrationFailureDto {
            reference: reference.clone(),
            // 核心层已 scrub；命令层再过一次，保证旧库/底层错误串不会把密钥形态送到前端。
            reason: tianshu_relay_core::redact::scrub(reason),
        })
        .collect()
}

fn migration_status_dto(
    status: tianshu_relay_core::vault::MigrationStatus,
) -> VaultMigrationStatusDto {
    let map = |items: &[tianshu_relay_core::vault::MigrationFailure]| {
        items
            .iter()
            .map(|f| VaultMigrationFailureDto {
                reference: f.reference.clone(),
                reason: tianshu_relay_core::redact::scrub(&f.reason),
            })
            .collect::<Vec<_>>()
    };
    VaultMigrationStatusDto {
        phase: match status.phase {
            "done" => "done",
            "retry_exhausted" => "retryExhausted",
            "abandoned" => "abandoned",
            _ => "pending",
        }
        .to_string(),
        attempts: status.attempts,
        last_at: status.last_at,
        last_error: status.last_error,
        failures: map(&status.failures),
        cleanup_pending: map(&status.cleanup_pending),
    }
}

/// 迁移命令共用：按 `data_dir`/`db_path` **重新打开** LocalVault + Store（短连接）。
///
/// - `db_error` 有值 ⇒ 数据库不可用，明确报错（**不**创建空库）；
/// - `db_path` 不存在 ⇒ 同样报错（否则 `Store::open` 会建出一个空库，
///   迁移就会「成功」于一个空引用集合，把完成标记写死）。
fn open_migration_handles(
    state: &AppState,
) -> Result<
    (
        tianshu_relay_core::vault::LocalVault,
        tianshu_relay_core::store::Store,
    ),
    String,
> {
    if let Some(err) = &state.db_error {
        return Err(format!(
            "数据库当前不可用（{err}）：无法执行迁移。请先修复数据库后重启应用。"
        ));
    }
    if !state.db_path.exists() {
        return Err("数据库文件不存在：请先完成初始化，再执行钥匙串迁移。".to_string());
    }
    let (db_path, key_path) = tianshu_relay_core::vault::local::default_paths_in(&state.data_dir);
    let vault = tianshu_relay_core::vault::LocalVault::open(&db_path, &key_path)
        .map_err(|e| e.to_string())?;
    let store =
        tianshu_relay_core::store::Store::open(&state.db_path).map_err(|e| e.to_string())?;
    Ok((vault, store))
}

/// 迁移状态（设置页卡片 / CLI 同源口径）。
#[tauri::command]
pub fn vault_migration_status(
    state: State<'_, AppState>,
) -> Result<VaultMigrationStatusDto, String> {
    let (vault, _store) = open_migration_handles(&state)?;
    let status = tianshu_relay_core::vault::status_for(&vault).map_err(|e| e.to_string())?;
    Ok(migration_status_dto(status))
}

/// 显式重试（忽略自动重试上限；`abandoned:` 会先清标记）。
#[tauri::command]
pub fn vault_migration_retry(
    state: State<'_, AppState>,
) -> Result<VaultMigrationReportDto, String> {
    let (vault, store) = open_migration_handles(&state)?;
    let refs = tianshu_relay_core::vault::migrate::refs_for_migration(&store)
        .map_err(|e| e.to_string())?;
    // 迁移源必须是**旧** service（M35-S1 的不变量）——与启动路径同一个 helper。
    // 与启动路径同口径：先 probe，钥匙串不可用就整体失败（不逐条尝试、不触发多轮授权）。
    let source = crate::keychain_migration_source();
    tianshu_relay_core::vault::Vault::probe(&source)
        .map_err(|e| format!("系统钥匙串不可用：{e}"))?;
    let outcome = tianshu_relay_core::vault::retry_migration(&source, &vault, refs)
        .map_err(|e| e.to_string())?;
    let status = tianshu_relay_core::vault::status_for(&vault).map_err(|e| e.to_string())?;
    Ok(VaultMigrationReportDto {
        imported: outcome.report.imported,
        skipped: outcome.report.skipped,
        cleanup_pending: migration_failure_dtos(&outcome.report.cleanup_pending),
        failed: migration_failure_dtos(&outcome.report.failed),
        status: migration_status_dto(status),
    })
}

/// 放弃迁移：写 `abandoned:<unix>`，不删源条目（之后启动不自动重试）。
#[tauri::command]
pub fn vault_migration_abandon(
    state: State<'_, AppState>,
) -> Result<VaultMigrationStatusDto, String> {
    let (vault, _store) = open_migration_handles(&state)?;
    tianshu_relay_core::vault::abandon_migration(&vault).map_err(|e| e.to_string())?;
    let status = tianshu_relay_core::vault::status_for(&vault).map_err(|e| e.to_string())?;
    Ok(migration_status_dto(status))
}

// ============================================================== Agent 网关令牌（M43-S1）

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedGatewayTokenDto {
    id: i64,
    label: String,
    /// 明文**只在这里出现一次**；库/日志/事件/导出都没有它。
    token: String,
    created_at: i64,
}

#[derive(serde::Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GatewayTokenDto {
    id: i64,
    label: String,
    created_at: i64,
    revoked_at: Option<i64>,
    last_used_at: Option<i64>,
    active: bool,
    is_default: bool,
}

fn gateway_token_dto(row: &tianshu_relay_core::store::GatewayTokenRow) -> GatewayTokenDto {
    GatewayTokenDto {
        id: row.id,
        label: row.label.clone(),
        created_at: row.created_at,
        revoked_at: row.revoked_at,
        last_used_at: row.last_used_at,
        active: row.active(),
        is_default: row.is_default,
    }
}

fn gateway_token_dtos(state: &AppState) -> Vec<GatewayTokenDto> {
    state
        .service
        .store()
        .list_gateway_tokens()
        .map(|rows| rows.iter().map(gateway_token_dto).collect())
        .unwrap_or_default()
}

/// 标签校验（§6）：空 / 超长 / 重名（非吊销内） / 令牌形态，四条都要挡。
fn validate_gateway_label(state: &AppState, label: &str) -> Result<String, String> {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return Err("令牌标签不能为空：它决定用量归因到哪个 agent".to_string());
    }
    if trimmed.chars().count() > 64 {
        return Err("令牌标签最多 64 个字符".to_string());
    }
    let lower = trimmed.to_lowercase();
    let looks_like_token = lower.starts_with("kr-gw-")
        || lower.starts_with("sk-")
        || trimmed
            .split(|c: char| !c.is_ascii_hexdigit())
            .any(|part| part.len() >= 32);
    if looks_like_token {
        return Err("标签不能包含令牌/密钥形态的字符串".to_string());
    }
    let existing = state
        .service
        .store()
        .list_gateway_tokens()
        .map_err(|e| e.to_string())?;
    if existing
        .iter()
        .any(|row| row.active() && row.label == trimmed)
    {
        return Err(format!(
            "已有同名令牌「{trimmed}」；请换一个名字（归因按标签聚合，重名会混账）"
        ));
    }
    Ok(tianshu_relay_core::redact::scrub(trimmed))
}

/// 创建 Agent 令牌：明文**只返回一次**；库只存 hash。
#[tauri::command]
pub fn gateway_token_create(
    state: State<'_, AppState>,
    label: String,
) -> Result<CreatedGatewayTokenDto, String> {
    let label = validate_gateway_label(&state, &label)?;
    let token = tianshu_relay_core::gateway::generate_token();
    let hash = tianshu_relay_core::gateway::sha256_hex(&token);
    let id = state
        .service
        .store()
        .insert_gateway_token(&hash, &label, false)
        .map_err(|e| e.to_string())?;
    // 网关在跑 ⇒ 推进运行态集合（不重启网关、下一请求立即生效）。
    if let Ok(guard) = state.gateway.lock() {
        if let Some(run) = guard.as_ref() {
            if let Ok(mut tokens) = run.handle.token_registry().write() {
                tokens.push(tianshu_relay_core::gateway::GatewayTokenEntry {
                    id,
                    token_hash: hash,
                    label: label.clone(),
                    grace_until: None,
                });
            }
        }
    }
    let row = state
        .service
        .store()
        .gateway_token_by_id(id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "令牌刚写入却读不到".to_string())?;
    Ok(CreatedGatewayTokenDto {
        id: row.id,
        label: row.label,
        token,
        created_at: row.created_at,
    })
}

/// 列表（**永不含明文**）。
#[tauri::command]
pub fn gateway_token_list(state: State<'_, AppState>) -> Result<Vec<GatewayTokenDto>, String> {
    let rows = state
        .service
        .store()
        .list_gateway_tokens()
        .map_err(|e| e.to_string())?;
    Ok(rows.iter().map(gateway_token_dto).collect())
}

/// 吊销（幂等）。**默认行不可吊销**（M43-S1 T4e）：要换它请用轮换。
#[tauri::command]
pub fn gateway_token_revoke(
    state: State<'_, AppState>,
    id: i64,
) -> Result<GatewayTokenDto, String> {
    let row = state
        .service
        .store()
        .gateway_token_by_id(id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("找不到令牌 #{id}"))?;
    if row.is_default {
        return Err("默认令牌不能吊销；要换它请用令牌轮换（M41-S2）".to_string());
    }
    state
        .service
        .store()
        .revoke_gateway_token(id)
        .map_err(|e| e.to_string())?;
    // 运行态集合移除 ⇒ 下一请求立即 401（不重启网关）。
    if let Ok(guard) = state.gateway.lock() {
        if let Some(run) = guard.as_ref() {
            if let Ok(mut tokens) = run.handle.token_registry().write() {
                tokens.retain(|entry| entry.id != id);
            }
        }
    }
    let row = state
        .service
        .store()
        .gateway_token_by_id(id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("找不到令牌 #{id}"))?;
    Ok(gateway_token_dto(&row))
}

// ============================================================== 自动人机验证（M36-S1）

/// 自动完成结果事件（**只发到 `main`**）。payload 只有站点号与状态，绝不含 cookie / token。
pub const CAPTCHA_AUTO_EVENT: &str = "captcha-auto-finished";

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CaptchaAutoEvent {
    site_id: i64,
    /// `"completed"` | `"failed"`
    status: String,
    /// 失败时的可读原因；不得含凭据（来自完整流程的错误串，内部已 scrub）。
    message: Option<String>,
}

/// 广播一次自动完成结果。发送失败（主窗口已关）只当没发生——不影响会话落地。
fn emit_captcha_auto<R: tauri::Runtime>(
    app: &AppHandle<R>,
    site_id: i64,
    status: &str,
    message: Option<String>,
) {
    use tauri::Emitter as _;
    let _ = app.emit_to(
        "main",
        CAPTCHA_AUTO_EVENT,
        CaptchaAutoEvent {
            site_id,
            status: status.to_string(),
            message,
        },
    );
}

/// 触发名 cookie 的指纹（名字 + 值，排序），**只存在内存里**：用于「只有变化才重试」。
fn trigger_cookie_fingerprint(pairs: &[(String, String)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = pairs
        .iter()
        .filter(|(name, _)| {
            tianshu_relay_core::site::captcha::AUTO_CAPTURE_TRIGGERS.contains(&name.as_str())
        })
        .cloned()
        .collect();
    out.sort();
    out
}

/// cookie 型站点的自动接管 watcher（M36-S1）。
///
/// 每 500ms 读一次窗口 cookie（**按站点 domain 过滤**），用纯函数
/// [`tianshu_relay_core::site::captcha::auto_capture_ready`] 判断「会话凭据 cookie 出现
/// 或值发生变化」；命中后走与手工「我已过完」**同一条** [`complete_captcha_window`]
/// （`captcha_op` 串行）。成功 ⇒ 关窗（由完整流程负责）+ `completed` 事件 + 结束；
/// 失败 ⇒ **不关窗**、相位留人工态、`failed` 事件，只有 cookie 指纹变化才再次尝试
/// （避免「每 500ms 撞一次」的高频重试）。
///
/// 结束条件：窗口关闭 / 相位离开 `AwaitingHuman` / 站点 origin 变化 / 10 分钟上限。
async fn watch_cookies_for_auto_complete<R: tauri::Runtime>(
    app: AppHandle<R>,
    label: String,
    base_url: String,
    site_id: i64,
) {
    const INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
    const MAX_RUNTIME: std::time::Duration = std::time::Duration::from_secs(10 * 60);

    let deadline = std::time::Instant::now() + MAX_RUNTIME;
    // **从空基线开始**（M36-S1 真机 fixture 修正）：登录页很可能在窗口 build 完成时就
    // 已经写入 `new_api_refresh`/`session`（或页面打开即带有效 refresh）；任何「建窗后
    // 快照作基线」都会把这份**唯一的**会话 cookie 当成「变化前」，于是永不触发。
    // 现在的语义：**出现即尝试**——第一轮轮询看到任何触发名 cookie 就试一次；
    // 旧 cookie / 登录前 cookie 的噪声由「首败静默」挡掉（P2-2）；cookie 变化才重试。
    let baseline: Vec<(String, String)> = Vec::new();
    let mut last_attempt: Option<Vec<(String, String)>> = None;
    // 尝试次数：**第一次尝试失败不广播**（视为「用户还没登录 / 基线未稳」，只是早触发了一次），
    // 从第二次起才 emit failed——否则登录页刚打开时的瞬时 cookie 变化会在用户眼前闪一条
    // 「自动接入失败」噪声。窗口、相位、指纹语义都不变。
    let mut attempts: u32 = 0;

    loop {
        tokio::time::sleep(INTERVAL).await;
        if std::time::Instant::now() >= deadline {
            break; // 10 分钟上限：不再自动读 cookie，用户仍可手动接入/取消
        }
        // 窗口没了 ⇒ 用户关窗（关窗=取消）或已被接上；结束。
        let Some(window) = app.get_webview_window(&label) else {
            break;
        };
        let Some(state) = app.try_state::<AppState>() else {
            break; // 应用正在退出
        };
        if !captcha_submit_is_allowed(&state.service.captcha_phase(site_id)) {
            break; // 已被取消 / 已接上 / 相位变了：watcher 不再写任何状态
        }
        let Ok(page_url) = window.url() else {
            break;
        };
        if !tianshu_relay_core::site::captcha::origin_matches(&base_url, page_url.as_str()) {
            // 页面跳到第三方 origin：不抓 cookie、不自动完成（spec §6 最后一行）。
            break;
        }
        let Some(host) = site_host_of(&base_url) else {
            break;
        };
        let Ok(cookies) = window.cookies() else {
            continue; // 读失败：不关窗，下一轮再试
        };
        let pairs: Vec<(String, String)> = cookies
            .iter()
            .filter(|cookie| cookie_belongs_to_site(cookie.domain().unwrap_or(""), &host))
            .map(|cookie| (cookie.name().to_string(), cookie.value().to_string()))
            .collect();
        // 空基线：任何触发名 cookie 出现/变化都算「可尝试」（首败静默，见 attempts）。
        if !tianshu_relay_core::site::captcha::auto_capture_ready(&baseline, &pairs) {
            continue;
        }
        let fingerprint = trigger_cookie_fingerprint(&pairs);
        if last_attempt.as_ref() == Some(&fingerprint) {
            continue; // 指纹没变：不重复尝试
        }
        last_attempt = Some(fingerprint);
        attempts += 1;
        match complete_captcha_window(&app, &state, site_id).await {
            Ok(()) => {
                emit_captcha_auto(&app, site_id, "completed", None);
                return;
            }
            Err(message) => {
                // 失败不关窗、相位留人工态（`complete_captcha_window` 保证）；
                // 错误串来自完整流程（含 scrub），不含 cookie / token。
                // 第一次失败静默（见 `attempts` 的注释）：只在第二次及以后上报。
                if attempts > 1 {
                    emit_captcha_auto(&app, site_id, "failed", Some(message));
                }
            }
        }
    }
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
    // P3-15：与 captcha_complete / captcha_cancel 串行（三个命令共用 `captcha_op`）
    let _op = state.captcha_op.lock().await;

    // ① 相位必须是「等待人工验证」——不在人工态时明确拒绝，而不是打开一个空白窗口
    let challenge = state
        .service
        .begin_captcha(site_id)
        .map_err(|e| e.to_string())?;

    // ② 站点**整行**：窗口标题用 `display_name`；Bearer 分支还要 `base_url`（算 origin、
    //    生成注入脚本）。拿不到就退回站点号（与 HEAD 同形——`begin_captcha` 已保证站点存在）。
    let site_row = state
        .service
        .sites()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|site| site.id == site_id);
    let display_name = site_row
        .as_ref()
        .map(|site| site.display_name.clone())
        .unwrap_or_else(|| format!("站点 #{site_id}"));
    // M28-S2：取数方式只由能力表决定（不按 kind 硬编码；认不出类型 ⇒ Unsupported）。
    let mode = captcha_capture_mode(
        site_row
            .as_ref()
            .and_then(|site| tianshu_relay_core::site::SiteKind::parse(&site.kind)),
    );

    let label = captcha_window_label(site_id);
    if let Some(existing) = app.get_webview_window(&label) {
        // 窗口已存在（可能被隐藏过）：show + 聚焦。P1-7：旧实现只 set_focus，
        // macOS 对不可见窗口 set_focus 是空操作 ⇒ 关闭后再也打不开。
        let _ = existing.show();
        let _ = existing.set_focus();
    } else {
        let url = challenge
            .url
            .parse::<tauri::Url>()
            .map_err(|e| format!("人机验证页面地址无法解析: {e}"))?;
        let mut builder =
            tauri::WebviewWindowBuilder::new(&app, label.clone(), tauri::WebviewUrl::External(url))
                // M36-S1：窗口标题也提示「请勿关闭」——站点 CSP 可能拦掉注入的 banner，标题栏改不了。
                .title(tianshu_relay_core::site::captcha::captcha_window_title(
                    &display_name,
                ))
                .inner_size(1000.0, 760.0);

        // M36-S1：cookie / bearer 两种**可接管**模式都注入「请勿关闭」展示条。
        // 只在站点自己的 origin、顶层 frame 生效（脚本自带双重守卫），不读页面/输入/cookie。
        if matches!(
            mode,
            CaptchaCaptureMode::Cookies | CaptchaCaptureMode::Bearer
        ) {
            let base_url = site_row
                .as_ref()
                .map(|site| site.base_url.clone())
                .ok_or_else(|| format!("站点 #{site_id} 不存在"))?;
            let notice = tianshu_relay_core::site::captcha::keep_open_notice_script(&base_url)
                .map_err(|e| e.to_string())?;
            builder = builder.initialization_script(notice);
        }

        // M28-S2 / B-191 B 路：**只有 Bearer 站点**才加 incognito + 注入脚本 + 导航拦截。
        // Cookies / Unsupported 分支逐项保持 HEAD（不加这三项，最终 build 参数与 HEAD 一致）。
        if mode == CaptchaCaptureMode::Bearer {
            let base_url = site_row
                .as_ref()
                .map(|site| site.base_url.clone())
                .ok_or_else(|| format!("站点 #{site_id} 不存在"))?;
            let script = tianshu_relay_core::site::webview_creds::login_script(&base_url)
                .map_err(|e| e.to_string())?;
            let expected_origin = tianshu_relay_core::site::webview_creds::site_origin(&base_url)
                .map_err(|e| e.to_string())?;
            let app_for_nav = app.clone();
            let label_for_nav = label.clone();
            builder = builder
                // incognito：登录页的 localStorage / cookie 不落盘（B 路的凭据只该进钥匙串）。
                .incognito(true)
                .initialization_script(script)
                .on_navigation(move |url| {
                    // ① 不是回传 URL ⇒ 普通导航，放行。
                    let Some(parsed) =
                        tianshu_relay_core::site::webview_creds::parse_creds_navigation(
                            url.as_str(),
                        )
                    else {
                        return true;
                    };
                    // ② 回传只在**本站文档**下接受：先比窗口当前文档的 origin。
                    //    页面被跳到第三方 ⇒ 拦下，什么都不存（防「在别处登录」）。
                    let origin_ok = app_for_nav
                        .get_webview_window(&label_for_nav)
                        .and_then(|window| window.url().ok())
                        .map(|current| {
                            navigation_origin_allowed(current.as_str(), &expected_origin)
                        })
                        .unwrap_or(false);
                    if !origin_ok {
                        return false;
                    }
                    match parsed {
                        Ok(creds) => {
                            // 成功/失败都拦下这次导航（`tianshu-relay-creds://` 不是可加载的页面）。
                            // store 失败只意味着「窗口里这次登录不被接受」：不 panic、不写日志值。
                            if let Some(state) = app_for_nav.try_state::<AppState>() {
                                if state.service.store_webview_creds(site_id, creds).is_ok() {
                                    // M36-S1：**不在导航回调里同步执行**（会阻塞 WebView）。
                                    // 异步补 cf_clearance → 接上会话 → 成功即 strip + destroy，
                                    // 再把结果广播给主界面；失败不关窗，用户可手动接入/取消。
                                    let app_for_auto = app_for_nav.clone();
                                    tauri::async_runtime::spawn(async move {
                                        if let Some(state) = app_for_auto.try_state::<AppState>() {
                                            match complete_captcha_window(
                                                &app_for_auto,
                                                &state,
                                                site_id,
                                            )
                                            .await
                                            {
                                                Ok(()) => emit_captcha_auto(
                                                    &app_for_auto,
                                                    site_id,
                                                    "completed",
                                                    None,
                                                ),
                                                Err(message) => {
                                                    // P2-1：`login_script.js` 的 `sent`
                                                    // 只在单个 document 内生效——登录后整页跳转
                                                    // 可能**二次回传**，第二个 spawn 在第一个已成功
                                                    // 之后才拿到 `captcha_op`，此时相位已 `Idle`，
                                                    // `complete_captcha_window` 必然失败。这种
                                                    // 「已经完成/已取消」的失败**不是失败**，
                                                    // 静默返回，不再 emit failed。
                                                    if captcha_submit_is_allowed(
                                                        &state.service.captcha_phase(site_id),
                                                    ) {
                                                        emit_captcha_auto(
                                                            &app_for_auto,
                                                            site_id,
                                                            "failed",
                                                            Some(message),
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    });
                                }
                            }
                            false
                        }
                        // 畸形回传：拦下（不把畸形 URL 当普通导航加载）。
                        Err(_) => false,
                    }
                });
        }

        let window = builder
            .build()
            .map_err(|e| format!("打开人机验证窗口失败: {e}"))?;

        // M36-S1：cookie 型站点启动后台 watcher（每 500ms 看一次会话凭据 cookie）。
        // 只在新窗口时启动：同站点重复 `captcha_begin` 走「聚焦已有窗口」分支，
        // 不会叠加 watcher。窗口销毁 / 相位变化 / origin 变化 / 10 分钟上限都会让它结束。
        if mode == CaptchaCaptureMode::Cookies {
            let base_url_for_watch = site_row
                .as_ref()
                .map(|site| site.base_url.clone())
                .ok_or_else(|| format!("站点 #{site_id} 不存在"))?;
            // 不再建窗后快照（真机 fixture 证明会把「页面打开即写入的 cookie」当基线 ⇒
            // 永不触发）。watcher 从**空基线**开始：出现即尝试，首败静默、变化才重试。
            let app_for_watch = app.clone();
            let label_for_watch = label.clone();
            tauri::async_runtime::spawn(async move {
                watch_cookies_for_auto_complete(
                    app_for_watch,
                    label_for_watch,
                    base_url_for_watch,
                    site_id,
                )
                .await;
            });
        }

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
/// 复用既有 `captcha_complete` 的完整流程（M36-S1）：
/// 相位检查 → 窗口存在 → origin 比对 → 按能力位抓 cookie/Bearer 凭据 → 服务层落地 →
/// 成功 `destroy()`。
///
/// **内部负责 `captcha_op` 串行**：自动 watcher、Bearer 自动完成、手工「我已过完」与
/// 「取消」全部走同一把锁；后到者看到相位已变 ⇒ 直接失败/无操作，不再写状态。
/// **失败不关窗**、相位留人工态（留给用户手动重试或取消）。
async fn complete_captcha_window<R: tauri::Runtime>(
    app: &AppHandle<R>,
    state: &AppState,
    site_id: i64,
) -> Result<(), String> {
    // P3-15：整段（读相位 → 抓 cookie → 提交）都在锁内。修前这里没有锁，
    // 用户可以在「接上会话中」点取消（`captcha_cancel` 是另一个命令），
    // 于是取消与提交交错：要么取消被覆盖，要么会话在取消之后被接上。
    let _op = state.captcha_op.lock().await;

    // ① 相位必须是「等待人工验证」（T7：不在人工态的提交一律拒绝，不建会话）
    if !captcha_submit_is_allowed(&state.service.captcha_phase(site_id)) {
        return Err("该站点当前不在等待人工验证：请先在「站点」页重新发起登录。".to_string());
    }

    // ② 窗口必须在
    let window = app
        .get_webview_window(&captcha_window_label(site_id))
        .ok_or_else(|| "人机验证窗口已关闭：请重新点「打开官方页面过一次」".to_string())?;

    // ③ 抓 cookie **之前**做 origin 比对（S2 §9 第 2 条）
    let site_row = state
        .service
        .sites()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|site| site.id == site_id)
        .ok_or_else(|| format!("站点 #{site_id} 不存在"))?;
    let base_url = site_row.base_url.clone();
    let page_url = window.url().map_err(|e| format!("读取窗口地址失败: {e}"))?;
    if !tianshu_relay_core::site::captcha::origin_matches(&base_url, page_url.as_str()) {
        return Err(
            "页面已不在该站点的域名下（可能被跳转到了别处）；为避免把别处的 cookie 存进来，\
             本次提交被拒绝。请在窗口里回到该站点页面后重试。"
                .to_string(),
        );
    }

    // ③′ M26-S1 / B-191：WebView cookie 兜底对该站点类型不适用时，**在 `window.cookies()`
    // 之前**直接拒绝。Sub2API 的会话是 `Authorization: Bearer`（JWT 在响应体里，不写
    // `Set-Cookie`），`window.cookies()` 结构性拿不到，且 cookie-only 会话对 Bearer 鉴权
    // 不可用——继续走 ④/⑤ 只会报误导文案（「没抓到 cookie」），用户其实已登录成功。
    // 不调 cookies、不进 validate、**不关窗**（与既有「校验失败留窗」同向，留给用户看）。
    // 错误文案不含任何 cookie 值（沿用 `captcha.rs` 红线）。
    //
    // `kind` 解析与 `commands.rs::SiteSummaryDto::from_row`（`:107`）同形、与
    // `service.rs::kind_of` 同源——见 spec §6.1。`service.rs::kind_of` 报 Store 错，
    // 这里走 fail-closed 文案，是**刻意如此**（认不出类型 ⇒ 绝不渲染兜底面板）。
    let kind = tianshu_relay_core::site::SiteKind::parse(&site_row.kind);
    match captcha_capture_mode(kind) {
        // M28-S2 / B-191 B 路：Sub2API 的会话在响应体里（Bearer），`window.cookies()` 抓不到。
        // 登录页脚本已经通过 `tianshu-relay-creds://` 把 access_token 交给服务层（captcha_begin 的
        // 导航回调里 store_webview_creds）；这里只补 **HttpOnly 的 `cf_clearance`**（JS 读不到），
        // 然后让服务层把两半拼成 Bearer 会话。
        CaptchaCaptureMode::Bearer => {
            // ④' 只读本站域的 cookie（别的站一律不碰），只取第一条合法 cf_clearance。
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
            let cf_clearance =
                tianshu_relay_core::site::webview_creds::extract_cf_clearance(&pairs);

            // ⑤' 与 cookie 路径同口径：读 cookie 跨了 await，提交前再查一次相位。
            if !captcha_submit_is_allowed(&state.service.captcha_phase(site_id)) {
                return Err(
                    "该站点当前已不在等待人工验证（可能已被取消）：本次提交已忽略，窗口保持打开。"
                        .to_string(),
                );
            }
            state
                .service
                .complete_webview_login(site_id, cf_clearance)
                .map_err(|e| e.to_string())?;

            // ⑥' 成功后清掉页面里的两个续期键（尽力而为：失败不阻断——incognito + destroy
            //     已保证页面存储不落盘），再关窗。失败时**不关窗**、相位留在人工态，可重试。
            let _ = window.eval(tianshu_relay_core::site::webview_creds::strip_refresh_keys_js());
            let _ = window.destroy();
            return Ok(());
        }
        // 与 HEAD **逐字一致**：该类型没有任何 WebView 兜底。
        CaptchaCaptureMode::Unsupported => {
            return Err(
                "该站点类型不支持 WebView 兜底人工验证：会话基于访问令牌而非 Cookie，\
                 请改用 API 密钥直连，或在上方表单完成登录后重试。"
                    .to_string(),
            );
        }
        // cookie 路径：下面 ④⑤ 逐字保持 HEAD（NewAPI 行为不变）。
        CaptchaCaptureMode::Cookies => {}
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
    //
    // P3-15 的双保险：抓 cookie 这一步跨了 `await`（窗口是另一个线程），提交之前**再查一次**
    // 相位。锁已经把命令层的并发入口串起来了，这里再查一次是为了防「锁之外的相位变化」
    // （例如将来有人加了别的写入点）——不在人工态就拒绝，且**不关窗**（窗口留给用户看）。
    if !captcha_submit_is_allowed(&state.service.captcha_phase(site_id)) {
        return Err(
            "该站点当前已不在等待人工验证（可能已被取消）：本次提交已忽略，窗口保持打开。"
                .to_string(),
        );
    }
    // M29-S1 / B-193：NewAPI（新版）的 API 鉴权只认 `Authorization: Bearer <access_token>`，
    // 只把 cookie 存进缓存对 API 无效——服务层会用 `new_api_refresh` 调
    // `POST /api/user/auth/refresh` 换一份 access token 并落地（相位 / health / 缓存 /
    // 钥匙串都由服务层负责，失败不关窗）。**其它 cookie 站点逐字保持 HEAD**。
    if cookie_login_uses_newapi_exchange(kind) {
        state
            .service
            .complete_newapi_webview_login(site_id, pairs)
            .await
            .map_err(|e| e.to_string())?;
    } else {
        state
            .service
            .complete_captcha(site_id, pairs)
            .map_err(|e| e.to_string())?;
    }

    // ⑥ 成功才关窗（`destroy` 不发事件；相位已回 `Idle`）
    let _ = window.destroy();
    Ok(())
}

/// 「我已过完」：手工兜底入口（M36-S1 起内部复用 [`complete_captcha_window`]，
/// 与自动完成走同一条流程）。签名与行为与 HEAD 一致。
#[tauri::command]
pub async fn captcha_complete<R: tauri::Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    site_id: i64,
) -> Result<(), String> {
    complete_captcha_window(&app, &state, site_id).await
}

/// 取消人工验证（关窗）：相位回 `Idle`，窗口关闭。幂等（T6 / T8）。
#[tauri::command]
pub async fn captcha_cancel<R: tauri::Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    site_id: i64,
) -> Result<(), String> {
    // P3-15：与 captcha_begin / captcha_complete 串行。取不到锁就一直等——「取消」是
    // 幂等的（service 层不在人工态时是 no-op），排队执行不会产生副作用。
    let _op = state.captcha_op.lock().await;

    state.service.cancel_captcha(site_id);
    if let Some(window) = app.get_webview_window(&captcha_window_label(site_id)) {
        let _ = window.destroy();
    }
    Ok(())
}

/// P3-15 的**判据**（纯函数，单独可测）：当前相位是否允许提交人工验证的结果。
///
/// 只有 `AwaitingHuman` 允许：`Idle`（没在等人 / 已被取消 / 已提交过）一律拒绝。
/// 抽成函数是为了让「取消之后不能再提交」这条**可被单测钉住**——内联的 `matches!`
/// 只有读代码才能验证。
fn captcha_submit_is_allowed(phase: &tianshu_relay_core::site::captcha::CaptchaPhase) -> bool {
    matches!(
        phase,
        tianshu_relay_core::site::captcha::CaptchaPhase::AwaitingHuman { .. }
    )
}

// ---- M15-S1：模型检测（bazaarlink probe）----

/// probe 检测结果（返回前端）。只含身份判定摘要，不含 items[].response 等敏感字段。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeRunDto {
    run_id: String,
    status: String,
    identity_status: Option<String>,
    verdict_status: Option<String>,
    true_family: Option<String>,
    true_model: Option<String>,
    spoof_method: Option<String>,
    confidence: Option<String>,
    warnings_count: u32,
    report_url: Option<String>,
    created_at: Option<i64>,
    completed_at: Option<i64>,
}

impl From<tianshu_relay_core::probe::ProbeRun> for ProbeRunDto {
    fn from(r: tianshu_relay_core::probe::ProbeRun) -> Self {
        Self {
            run_id: r.run_id,
            status: r.status,
            identity_status: r.identity_status,
            verdict_status: r.verdict_status,
            true_family: r.true_family,
            true_model: r.true_model,
            spoof_method: r.spoof_method,
            confidence: r.confidence,
            warnings_count: r.warnings_count,
            report_url: r.report_url,
            created_at: r.created_at,
            completed_at: r.completed_at,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeArgs {
    pub key_id: i64,
    pub model_id: String,
    pub claimed_model: Option<String>,
    pub base_url_override: Option<String>,
    pub confirm: bool,
}

/// 模型检测（M15-S1）。**apiKey 发给第三方 bazaarlink.ai**——`confirm` 必须为 true。
#[tauri::command]
pub async fn probe_run(state: State<'_, AppState>, args: ProbeArgs) -> Result<ProbeRunDto, String> {
    if !args.confirm {
        return Err(
            "模型检测需要二次确认：会把该站点的 API key 发送给第三方 bazaarlink.ai".to_string(),
        );
    }
    state
        .service
        .probe_model(
            args.key_id,
            args.model_id,
            args.claimed_model,
            args.base_url_override,
            args.confirm,
        )
        .await
        .map(ProbeRunDto::from)
        .map_err(|e| e.to_string())
}

/// 检测历史记录（返回前端）。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeRunRowDto {
    id: i64,
    run_id: String,
    site_id: i64,
    key_id: i64,
    model_id: String,
    claimed_model: Option<String>,
    identity_status: Option<String>,
    verdict_status: Option<String>,
    true_family: Option<String>,
    true_model: Option<String>,
    spoof_method: Option<String>,
    confidence: Option<String>,
    warnings_count: u32,
    report_url: Option<String>,
    bazaarlink_created_at: Option<i64>,
    bazaarlink_completed_at: Option<i64>,
    recorded_at: i64,
    /// B-135：bazaarlink run 生命周期状态。老库行是 `null`（那一列 v6 才加，没记过状态）。
    status: Option<String>,
}

impl From<tianshu_relay_core::store::ProbeRunRow> for ProbeRunRowDto {
    fn from(r: tianshu_relay_core::store::ProbeRunRow) -> Self {
        Self {
            id: r.id,
            run_id: r.run_id,
            site_id: r.site_id,
            key_id: r.key_id,
            model_id: r.model_id,
            claimed_model: r.claimed_model,
            identity_status: r.identity_status,
            verdict_status: r.verdict_status,
            true_family: r.true_family,
            true_model: r.true_model,
            spoof_method: r.spoof_method,
            confidence: r.confidence,
            warnings_count: r.warnings_count,
            report_url: r.report_url,
            bazaarlink_created_at: r.bazaarlink_created_at,
            bazaarlink_completed_at: r.bazaarlink_completed_at,
            recorded_at: r.recorded_at,
            status: r.status,
        }
    }
}

#[tauri::command]
pub fn list_probe_runs(
    state: State<'_, AppState>,
    limit: Option<usize>,
) -> Result<Vec<ProbeRunRowDto>, String> {
    state
        .service
        .list_probe_runs(limit.unwrap_or(50))
        .map(|rows| rows.into_iter().map(ProbeRunRowDto::from).collect())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_probe_run(
    state: State<'_, AppState>,
    id: i64,
) -> Result<Option<ProbeRunRowDto>, String> {
    state
        .service
        .get_probe_run(id)
        .map(|opt| opt.map(ProbeRunRowDto::from))
        .map_err(|e| e.to_string())
}

// ================================================================ 一键重启（投递改进 P1-5）
//
// 只做 Codex 与 Claude Desktop（完全退出重开）。其余 CLI 类 agent 不进命令表：
// 前端只给可复制启动命令，绝不替用户拉终端进程。
//
// 两层确认，缺一不可：
// 1. 前端确认框（Agents 页重启区）：明确告知「正在进行的操作会中断」，用户点确认后
//    前端才把 `confirmed: true` 传进来；
// 2. 后端硬门禁：`confirmed` 不是 `true` 就直接拒绝（包括缺字段的调用）。前端确认框
//    被绕过（旧前端、直接调 IPC）时，后端这一层仍能挡住一次无确认的重启。
// 命令层只做「串行 + 转 DTO」：退出/轮询/强制杀/拉起的全部语义在核心层 `restart` 模块。

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestartArgs {
    pub confirmed: bool,
}

/// 一次重启结果的线格式。`app_server_daemon_status` 恒为 `"unverified"`（核心层保证），
/// 前端必须把它渲染成「未验证」的清单项，不得渲染成已通过。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestartOutcomeDto {
    target: String,
    was_running: bool,
    quit_method: String,
    force_killed: bool,
    relaunched: bool,
    appeared: bool,
    manual_launch_command: Option<String>,
    app_server_daemon_status: String,
    app_server_daemon_note: String,
}

fn restart_outcome_dto(outcome: tianshu_relay_core::restart::RestartOutcome) -> RestartOutcomeDto {
    RestartOutcomeDto {
        target: outcome.target.as_str().to_string(),
        was_running: outcome.was_running,
        quit_method: outcome.quit_method.to_string(),
        force_killed: outcome.force_killed,
        relaunched: outcome.relaunched,
        appeared: outcome.appeared,
        manual_launch_command: outcome.manual_launch_command,
        app_server_daemon_status: outcome.app_server_daemon.status.to_string(),
        app_server_daemon_note: outcome.app_server_daemon.note,
    }
}

async fn restart_agent(
    state: State<'_, AppState>,
    args: RestartArgs,
    target: tianshu_relay_core::restart::RestartTarget,
) -> Result<RestartOutcomeDto, String> {
    if !args.confirmed {
        return Err(
            "重启需要用户确认：该操作会中断正在进行的会话，请在确认框里确认后再试".to_string(),
        );
    }
    // 串行化：两次重启不得交错（见 AppState::restart_op 的注释）。
    let _op = state.restart_op.lock().await;
    // DEBUG-G7 补齐 P2-C9（B-282）：重启还要与服务层写盘共用服务层写锁——
    // 轮换直调服务层 apply 时只持服务层锁、不经过命令层 restart_op，只靠
    // 命令层锁拦不住“轮换停写后、写盘前重启拉起”。锁在阻塞线程里取（不得
    // 在 async 上下文里取 std 锁）；中毒 ⇒ 拒绝重启（fail-closed）。锁序与
    // apply 路径一致（命令层锁在外、服务层锁在内），无环。
    let write_op = state.service.restart_write_op();
    // 核心重启是同步阻塞调用（轮询里 sleep），必须走 spawn_blocking，不得占 async 运行时。
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = write_op
            .lock()
            .map_err(|_| "桌面通道写锁中毒：上一任写盘中异常，拒绝重启以免交错".to_string())?;
        tianshu_relay_core::restart::restart(target).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("重启任务异常中断: {e}"))?
    .map(restart_outcome_dto)
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn restart_codex(
    state: State<'_, AppState>,
    args: RestartArgs,
) -> Result<RestartOutcomeDto, String> {
    restart_agent(
        state,
        args,
        tianshu_relay_core::restart::RestartTarget::Codex,
    )
    .await
}

#[tauri::command]
pub async fn restart_claude_desktop(
    state: State<'_, AppState>,
    args: RestartArgs,
) -> Result<RestartOutcomeDto, String> {
    restart_agent(
        state,
        args,
        tianshu_relay_core::restart::RestartTarget::ClaudeDesktop,
    )
    .await
}

/// 落盘一份环境/自启计划。
///
/// Windows 形态（`EnvPlan::Registry`）走 `reg.exe`，**不经 shell**——值里的空格、
/// 引号、`%` 原样到达（`RegOp::to_argv` 已单测）。本机（macOS）上这条分支不可达：
/// `autostart_plan` 只会产出 macOS 的 plist。
fn apply_env_plan(
    state: &State<'_, AppState>,
    plan: &tianshu_relay_core::platform_env::EnvPlan,
) -> Result<(), String> {
    use tianshu_relay_core::platform_env::EnvPlan;
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
fn run_reg_op(op: &tianshu_relay_core::platform_env::RegOp) -> Result<(), String> {
    use tianshu_relay_core::platform_env::REG_EXE;
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
fn run_reg_op(_op: &tianshu_relay_core::platform_env::RegOp) -> Result<(), String> {
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

    /// P1-5：重启结果 DTO 的线上字段名（camelCase）与 daemon 未验证态。
    /// 字面量字段齐全：缺一个字段编译就失败，不得用部分字面量蒙过去。
    #[test]
    fn restart_outcome_dto_serializes_in_camel_case_with_unverified_daemon() {
        let dto = restart_outcome_dto(tianshu_relay_core::restart::RestartOutcome {
            target: tianshu_relay_core::restart::RestartTarget::Codex,
            was_running: true,
            quit_method: "bundle",
            force_killed: false,
            relaunched: true,
            appeared: true,
            manual_launch_command: Some("codex".to_string()),
            app_server_daemon: tianshu_relay_core::restart::daemon_check(),
        });
        let value = to_value(&dto);
        assert_eq!(value["target"], "codex");
        assert_eq!(value["wasRunning"], true);
        assert_eq!(value["quitMethod"], "bundle");
        assert_eq!(value["forceKilled"], false);
        assert_eq!(value["relaunched"], true);
        assert_eq!(value["appeared"], true);
        assert_eq!(value["manualLaunchCommand"], "codex");
        // daemon 状态恒为未验证：这里钉死，前端据此渲染「未验证」清单项。
        assert_eq!(value["appServerDaemonStatus"], "unverified");
        assert!(
            value["appServerDaemonNote"]
                .as_str()
                .is_some_and(|n| n.contains("独立验证项")),
            "daemon 说明必须点明独立验证项：{value}"
        );
    }

    /// 复审 P2-4：IPC 测试此前只覆盖「命令可达」，没有返回值结构断言。
    /// 这里把每个 DTO 的线上字段名钉死，改字段名（含 snake_case 回归）会立刻失败。
    #[test]
    fn dtos_serialize_in_camel_case_with_expected_keys() {
        let summary = SiteSummaryDto::from_row(tianshu_relay_core::service::SiteSummary {
            id: 1,
            kind: "newapi".into(),
            base_url: "https://relay.example.com".into(),
            display_name: "测试站".into(),
            health: "unknown".into(),
            session_persisted: false,
            session_expires_at: None,
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
            value["capabilities"]["keyUsage"], true,
            "M14-S3：NewAPI list_keys 带 used_quota，key_usage=true"
        );
        // M26-S1 / B-191：NewAPI 会话可走 Set-Cookie，WebView cookie 兜底可达。
        assert_eq!(value["capabilities"]["webviewCaptchaSupported"], true);
        // M28-S2 / B-191 B 路：NewAPI 不走 localStorage 回传（cookie 已覆盖）。
        assert_eq!(value["capabilities"]["webviewBearerSupported"], false);
        // M9-S2 / B-120：登录账号栏的约定也随站点类型下发（NewAPI 是用户名）。
        assert_eq!(value["loginField"], "username");
        // M38-S1：会话持久化两字段的线格式（camelCase；无会话 ⇒ null）。
        assert_eq!(value["sessionPersisted"], false);
        assert!(value["sessionExpiresAt"].is_null());

        // Sub2API：账号栏是**邮箱**——真实站点只认邮箱形态，用户名必被 400
        // （`api.example.com` 实测，见 M9-S1 证据 §3）。界面据此改标签，
        // 因此这个取值是**用户可见行为**，不是内部字段。
        let sub2api = SiteSummaryDto::from_row(tianshu_relay_core::service::SiteSummary {
            id: 3,
            kind: "sub2api".into(),
            base_url: "https://api.example.com".into(),
            display_name: "Sub2API 站".into(),
            health: "unknown".into(),
            session_persisted: false,
            session_expires_at: None,
        });
        let value = to_value(&sub2api);
        assert_eq!(value["loginField"], "email");
        // M26-S1 / B-191：Sub2API 走 Bearer (JWT 在响应体)，不写 Set-Cookie，
        // WebView **cookie** 兜底架构性抓不到。
        assert_eq!(value["capabilities"]["webviewCaptchaSupported"], false);
        // M28-S2 / B-191 B 路：但 localStorage 回传可用 ⇒ UI 渲染「登录后点我已登录」。
        assert_eq!(value["capabilities"]["webviewBearerSupported"], true);

        // 认不出的站点类型 ⇒ 全部 false（fail-closed：宁可全灰，也不给点了才报错的按钮）。
        let unknown = SiteSummaryDto::from_row(tianshu_relay_core::service::SiteSummary {
            id: 2,
            kind: "some-future-site".into(),
            base_url: "https://x.example.com".into(),
            display_name: String::new(),
            health: "unknown".into(),
            session_persisted: false,
            session_expires_at: None,
        });
        let value = to_value(&unknown);
        assert_eq!(value["capabilities"]["listKeys"], false);
        assert_eq!(value["capabilities"]["login"], false);
        // M26-S1 / B-191：认不出类型 ⇒ fail-closed，绝不让「打开官方页面过一次」面板渲染。
        assert_eq!(value["capabilities"]["webviewCaptchaSupported"], false);
        // M28-S2：两种取数方式都 fail-closed（不渲染 bearer 面板）。
        assert_eq!(value["capabilities"]["webviewBearerSupported"], false);
        // 认不出类型 ⇒ 账号约定为 `null`：界面回落到中性标签「账号」，**不猜**是用户名
        // （猜错的代价与 B-120 一样：用户按标签填，站点直接拒）。
        //
        // 「键存在且值为 null」要分两条断言：`value["loginField"].is_null()` 对
        // **键缺失**也为真（`serde_json::Value` 索引不存在的键返回 `Null`），单靠它
        // 挡不住 `#[serde(skip_serializing_if = "Option::is_none")]` 这类回归——
        // 那时 TS 侧读到的是 `undefined`，而类型声明是 `"username" | "email" | null`。
        let object = value.as_object().expect("序列化结果必须是对象");
        assert!(
            object.contains_key("loginField"),
            "loginField 必须始终存在（值是 null 也行，但键不能在）：{value}"
        );
        assert_eq!(
            value["loginField"],
            serde_json::json!(null),
            "认不出的类型不得猜一个账号形态: {value}"
        );
        assert!(
            value.get("base_url").is_none(),
            "不得出现 snake_case: {value}"
        );
        assert!(
            value.get("login_field").is_none(),
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
            quota_used: Some(1.2),
            quota_limit: Some(10.0),
            currency: Some("USD".into()),
        };
        let value = to_value(&meta);
        assert_eq!(value["remoteId"], "12");
        assert_eq!(value["createdAt"], 1_700_000_000_i64);
        assert_eq!(value["lastUsedAt"], Value::Null);
        // M14-S3：用量字段进 DTO（camelCase）。
        assert_eq!(value["quotaUsed"], 1.2);
        assert_eq!(value["quotaLimit"], 10.0);
        assert_eq!(value["currency"], "USD");

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
        let unknown = BalanceDto::from_balance(tianshu_relay_core::site::Balance::unknown("USD"));
        let value = to_value(&unknown);
        assert_eq!(value["known"], false);
        assert_eq!(value["remaining"], Value::Null, "未知余额不得给 0");
        assert_eq!(value["used"], Value::Null, "未知余额不得给 0");

        let info = AppInfoDto {
            name: "天枢 Relay".into(),
            version: "0.1.0".into(),
            db_path: ":memory:".into(),
            data_dir: ":memory:".into(),
            site_count: 0,
            db_error: None,
            vault_backend: "memory".into(),
            rebrand: RebrandDto {
                status: "noLegacy".into(),
                from: None,
                to: ":memory:".into(),
                files: 0,
                bytes: 0,
                warnings: Vec::new(),
                error: None,
            },
        };
        let value = to_value(&info);
        assert_eq!(value["name"], "天枢 Relay");
        assert_eq!(value["dbPath"], ":memory:");
        assert_eq!(value["dataDir"], ":memory:");
        assert_eq!(value["siteCount"], 0);
        assert_eq!(value["dbError"], Value::Null);
        assert_eq!(value["vaultBackend"], "memory");
        assert_eq!(value["rebrand"]["status"], "noLegacy");
    }

    /// M34-S1：用量看板 DTO 的线上字段名（前端按 camelCase 读，漏改一侧就是静默空白）。
    #[test]
    fn usage_dashboard_dtos_serialize_in_camel_case() {
        let dto = UsageDashboardDto {
            range_days: 7,
            site_id: Some(1),
            daily: vec![UsageDailyDto {
                date: "2026-10-21".into(),
                site_id: 1,
                model: "gpt-4".into(),
                requests: 3,
                prompt_tokens: 100,
                completion_tokens: 50,
                total_tokens: 150,
                currency: Some("USD".into()),
                estimated_cost: Some(0.25),
                unpriced_requests: 0,
                unpriced_tokens: 0,
            }],
            snapshots: vec![UsageSnapshotDailyDto {
                date: "2026-10-21".into(),
                site_id: 1,
                used: 1.5,
                remaining: 8.5,
                currency: "USD".into(),
                samples: 2,
            }],
            key_usage: vec![KeyUsageTotalDto {
                key_id: 9,
                site_id: 1,
                key_name: "key-a".into(),
                requests: 4,
                input_tokens: 10,
                output_tokens: 5,
                total_tokens: 15,
                cost: Some(0.25),
                currency: Some("USD".into()),
            }],
            by_agent: vec![AgentUsageDto {
                agent_label: "codex".into(),
                currency: Some("USD".into()),
                requests: 4,
                total_tokens: 15,
                estimated_cost: Some(0.25),
                unpriced_requests: 0,
            }],
        };
        let value = to_value(&dto);
        assert_eq!(value["rangeDays"], 7);
        assert_eq!(value["siteId"], 1);
        assert_eq!(value["daily"][0]["date"], "2026-10-21");
        assert_eq!(value["daily"][0]["siteId"], 1);
        assert_eq!(value["daily"][0]["promptTokens"], 100);
        assert_eq!(value["daily"][0]["completionTokens"], 50);
        assert_eq!(value["daily"][0]["totalTokens"], 150);
        assert_eq!(value["snapshots"][0]["remaining"], 8.5);
        assert_eq!(value["snapshots"][0]["samples"], 2);
        assert_eq!(value["keyUsage"][0]["keyId"], 9);
        assert_eq!(value["keyUsage"][0]["keyName"], "key-a");
        assert_eq!(value["keyUsage"][0]["totalTokens"], 15);
        assert_eq!(value["keyUsage"][0]["currency"], "USD");
        // 币种未知时必须是显式 null（键在、值为 null），不是缺键——前端类型是 `string | null`
        let unknown_currency = to_value(&KeyUsageTotalDto {
            key_id: 9,
            site_id: 1,
            key_name: "key-a".into(),
            requests: 0,
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            cost: Some(0.0),
            currency: None,
        });
        assert!(
            unknown_currency
                .as_object()
                .unwrap()
                .contains_key("currency"),
            "currency 键必须始终存在（值可为 null）: {unknown_currency}"
        );
        assert_eq!(unknown_currency["currency"], Value::Null);
        // 反例：不得出现 snake_case
        assert!(value.get("range_days").is_none());
        assert!(value.get("key_usage").is_none());
        assert!(value["daily"][0].get("site_id").is_none());
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
            mode: tianshu_relay_core::delivery::DeliveryMode::Site
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
            // P1-6：来源与动作同源取自 restart_hint_detail（Codex 不标抄表：
            // 其三分法是 P1-5 结论，整体未实测 ⇒ unverified + codexSplit）。
            restart_hint: restart_hint_str(tianshu_relay_core::delivery::restart_hint(
                tianshu_relay_core::delivery::DeliveryChannel::CodexAuthJson,
            )),
            restart_hint_source: restart_hint_source_str(
                tianshu_relay_core::delivery::restart_hint_detail(
                    tianshu_relay_core::delivery::DeliveryChannel::CodexAuthJson,
                )
                .source,
            ),
            restart_hint_action: restart_hint_action_str(
                tianshu_relay_core::delivery::restart_hint_detail(
                    tianshu_relay_core::delivery::DeliveryChannel::CodexAuthJson,
                )
                .action,
            ),
            // M16-S6a / P2-3：Codex 的 `auth.json` 里**没有** endpoint（改指网关时只换令牌不换地址）。
            // 取真实值而不是字面量——事实表变了这条会跟着变。
            endpoint_in_channel: tianshu_relay_core::delivery::channel_carries_endpoint(
                tianshu_relay_core::delivery::DeliveryChannel::CodexAuthJson,
            ),
            // P0-3：Codex 不是 DSH，引用校验恒为 None ⇒ 线上为 null，不得是空对象。
            dsh_credential_reference: None,
            // P0-2：本用例为单文件投递，非保留模式 ⇒ false + 空文件表。
            preserve_auth: false,
            files: vec![],
            // P1-7：本用例为非预览、非首次的单文件投递 ⇒ 预览关、首次关、
            // 导入空、变体取默认落点（与 P1-7 前的默认落点一致）。
            preview_only: false,
            is_first_delivery: false,
            imported_fields: vec![],
            target_variant: "default".into(),
            target_variants: vec!["default".into()],
            // P2-8：本用例无模型输入 ⇒ 静态不适用、探针跳过、不拦；线上字段
            // 名须为 modelValidation，且序列化里不得出现任何密钥材料。
            model_validation: ModelValidationDto {
                model: None,
                static_outcome: "not_applicable".into(),
                static_code: "no_model".into(),
                probe_outcome: "skipped".into(),
                probe_code: "skipped".into(),
                probe_status: None,
                blocks_delivery: false,
            },
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
        assert_eq!(
            value["restartHintSource"], "unverified",
            "codex 三分法是 P1-5 结论、整体未实测，不得标成抄表或已实测"
        );
        assert_eq!(
            value["restartHintAction"], "codexSplit",
            "codex 必须呈现桌面按钮 / 终端手动 / daemon 三分法，不得写成按钮一按全生效"
        );
        // M16-S6a / P2-3：Codex 的落点文件里没有 endpoint ⇒ 线上字段必须是 `false`
        // （界面据此提示「改指网关后还要去改 config.toml 里的地址」）。
        assert_eq!(
            value["endpointInChannel"], false,
            "codex-auth-json 的 auth.json 里没有 endpoint"
        );
        assert_eq!(
            value["dshCredentialReference"],
            Value::Null,
            "非 DSH 通道的引用校验必须为 null，不得是空对象"
        );
        // P1-7：5 个新字段必须到 camelCase 线上名上（本测试的本意就是断言
        // 线上字段名；只填默认值而不断言，新字段的序列化会继续缺席）。
        assert_eq!(value["previewOnly"], false);
        assert_eq!(value["isFirstDelivery"], false);
        assert!(
            value["importedFields"].as_array().unwrap().is_empty(),
            "非首次投递的导入表必须为空"
        );
        assert_eq!(value["targetVariant"], "default");
        assert_eq!(value["targetVariants"][0], "default");
        // P2-8：验证结果必须到 camelCase 线上名上，且不含密钥材料。
        assert_eq!(value["modelValidation"]["staticOutcome"], "not_applicable");
        assert_eq!(value["modelValidation"]["staticCode"], "no_model");
        assert_eq!(value["modelValidation"]["probeOutcome"], "skipped");
        assert_eq!(value["modelValidation"]["probeCode"], "skipped");
        assert_eq!(value["modelValidation"]["probeStatus"], Value::Null);
        assert_eq!(value["modelValidation"]["blocksDelivery"], false);
        assert!(value.get("target_path").is_none(), "不得出现 snake_case");

        // M7-S5：**每个**通道都必须给出一个非空提示——新增通道时穷举 match 会编译失败，
        // 而不是悄悄给一个空串（界面会因此显示「无需重启」这种最危险的假话）。
        // P1-6：来源与动作同样逐通道非空（空来源会被前端默认成未实测，但这里先
        // 钉住“后端必须给”，缺失是后端 bug、不是前端回落的借口）。
        for channel in tianshu_relay_core::delivery::DeliveryChannel::ALL {
            let hint = restart_hint_str(tianshu_relay_core::delivery::restart_hint(channel));
            assert!(
                !hint.is_empty(),
                "{} 的 restartHint 不得为空",
                channel.as_str()
            );
            let detail = tianshu_relay_core::delivery::restart_hint_detail(channel);
            assert!(
                !restart_hint_source_str(detail.source).is_empty(),
                "{} 的 restartHintSource 不得为空",
                channel.as_str()
            );
            assert!(
                !restart_hint_action_str(detail.action).is_empty(),
                "{} 的 restartHintAction 不得为空",
                channel.as_str()
            );
        }

        let outcome = DeliveryOutcomeDto {
            channel: "codex-auth-json".into(),
            target_path: "/home/u/.codex/auth.json".into(),
            journal_id: "j1-0".into(),
            backup_path: Some("/home/u/.tianshu-relay/backups/j1-0/0-auth.json".into()),
            // P0-2：本用例为单文件投递，非保留模式 ⇒ false + 空文件表。
            preserve_auth: false,
            files: vec![],
        };
        let value = to_value(&outcome);
        assert_eq!(value["journalId"], "j1-0");
        assert_eq!(
            value["backupPath"],
            "/home/u/.tianshu-relay/backups/j1-0/0-auth.json"
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
        // OpenCode 通道可带模型名
        let args: DeliveryArgs = serde_json::from_value(serde_json::json!({
            "keyId": 7,
            "channel": "opencode",
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
    fn gateway_base_url_for_omits_v1_for_claude_code_only() {
        // P1-5：Claude Code（Anthropic SDK）的 ANTHROPIC_BASE_URL 不带 /v1（SDK 自己拼 /v1/messages），
        // 给它带 /v1 会变成 /v1/v1/messages。其他通道（OpenAI/Codex 等）带 /v1。
        use tianshu_relay_core::delivery::{gateway_base_url_for, DeliveryChannel};
        let url = "http://127.0.0.1:19387";
        assert_eq!(
            gateway_base_url_for(&DeliveryChannel::ClaudeCodeSettings, url),
            url
        );
        assert_eq!(
            gateway_base_url_for(&DeliveryChannel::CodexAuthJson, url),
            format!("{url}/v1")
        );
        assert_eq!(
            gateway_base_url_for(&DeliveryChannel::GrokBuild, url),
            format!("{url}/v1")
        );
        assert_eq!(
            gateway_base_url_for(&DeliveryChannel::ClaudeDesktop, url),
            url.to_string()
        );
    }

    /// M29-S1 / B-193：Cookies 分支的分流判据——只有 NewAPI 走「refresh 换 token」。
    ///
    /// 这条钉住的是「别的 cookie 站点没被误伤」：Custom / Sub2API / 未知类型都必须
    /// 继续走 HEAD 的 cookie-only `complete_captcha`。
    #[test]
    fn cookie_login_uses_newapi_exchange_only_for_newapi() {
        use tianshu_relay_core::site::SiteKind;
        assert!(cookie_login_uses_newapi_exchange(Some(SiteKind::NewApi)));
        assert!(!cookie_login_uses_newapi_exchange(Some(
            SiteKind::CustomOpenAiCompatible
        )));
        // Sub2API 走 Bearer（`CaptchaCaptureMode::Bearer`），根本到不了这个分支；
        // 这里断言 false 是为了「万一将来有人把 Bearer 站点塞进 Cookies 分支」也不误走 NewAPI 路径。
        assert!(!cookie_login_uses_newapi_exchange(Some(SiteKind::Sub2Api)));
        assert!(!cookie_login_uses_newapi_exchange(None));
    }

    /// M28-S2 / B-191 B 路：取数方式**只**由能力表决定（三臂 + `None` 臂）。
    ///
    /// 这四条钉住的是「壳层的分流判据」：cookie 优先、Bearer 次之、其余/未知一律
    /// Unsupported（fail-closed，绝不猜一条取数路径）。
    #[test]
    fn captcha_capture_mode_follows_the_capability_table() {
        use tianshu_relay_core::site::SiteKind;
        assert_eq!(
            captcha_capture_mode(Some(SiteKind::NewApi)),
            CaptchaCaptureMode::Cookies,
            "NewAPI：会话走 Set-Cookie ⇒ cookie 抓取"
        );
        assert_eq!(
            captcha_capture_mode(Some(SiteKind::Sub2Api)),
            CaptchaCaptureMode::Bearer,
            "Sub2API：会话是响应体里的 JWT ⇒ localStorage 回传"
        );
        assert_eq!(
            captcha_capture_mode(Some(SiteKind::CustomOpenAiCompatible)),
            CaptchaCaptureMode::Unsupported,
            "Custom：没有登录流程 ⇒ 没有任何 WebView 兜底"
        );
        assert_eq!(
            captcha_capture_mode(None),
            CaptchaCaptureMode::Unsupported,
            "认不出的 kind ⇒ fail-closed"
        );
    }

    /// M28-S2 复审 P2-1 / P3-2：origin 闸门必须是**可单测的纯函数**，且两侧口径同源
    /// （`site_origin` 会剥尾点 / IDN→punycode / 默认端口归一；`Url::origin()` 不会）。
    #[test]
    fn navigation_origin_gate_accepts_only_the_site_origin() {
        let expected = "https://sub.example.com";
        assert!(navigation_origin_allowed(
            "https://sub.example.com/login",
            expected
        ));
        assert!(
            navigation_origin_allowed("https://SUB.example.com./login", expected),
            "尾点 FQDN + 大小写必须按同一 origin 处理（P3-2）"
        );
        assert!(!navigation_origin_allowed(
            "https://evil.example.com/login",
            expected
        ));
        assert!(!navigation_origin_allowed(
            "https://sub.example.com.evil.example/login",
            expected
        ));
        assert!(!navigation_origin_allowed("about:blank", expected));
        assert!(!navigation_origin_allowed("data:text/html,x", expected));
        assert!(!navigation_origin_allowed("not a url", expected));
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

    // ---- P3-18：诊断包导出路径收敛 ----

    /// T1：不传路径 ⇒ 默认落在导出目录内、文件名符合白名单。
    #[test]
    fn diagnostics_default_path_is_inside_the_exports_dir() {
        let home = tempfile::tempdir().expect("临时 home");
        let path = resolve_diagnostics_path(&home.path().join(".tianshu-relay"), None)
            .expect("默认路径必须可用");
        assert_eq!(
            path.parent().unwrap(),
            home.path().join(".tianshu-relay/exports")
        );
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(
            name.starts_with("tianshu-relay-diagnostics"),
            "文件名: {name}"
        );
        assert!(name.ends_with(".json"), "文件名: {name}");
    }

    /// T2：四类越界**逐条**被拒（目录外 / 文件名不符 / `..` / 符号链接）。
    ///
    /// 这条是 P3-18 的**证伪**：修前这四类都会被 `export_diagnostics_to_file` 真的写下去
    /// （`create_dir_all` + `fs::write`，见 `service.rs:4380-4384`）。
    #[test]
    fn diagnostics_rejects_every_out_of_bounds_path() {
        let home = tempfile::tempdir().expect("临时 home");
        let exports = home.path().join(".tianshu-relay/exports");
        std::fs::create_dir_all(&exports).expect("建导出目录");

        // ① 目录外（绝对路径）：`~/.zshrc` 与 `/tmp/...` 都在这类
        for outside in [
            home.path().join(".zshrc"),
            std::env::temp_dir().join("kr-s6a-outside.json"),
        ] {
            let err = resolve_diagnostics_path(
                &home.path().join(".tianshu-relay"),
                Some(&outside.display().to_string()),
            )
            .expect_err("目录外路径必须被拒");
            assert!(err.contains("只能导出到"), "文案: {err}");
        }

        // ② 文件名不符（目录对、名字不对）
        let wrong_name = exports.join("other.json");
        assert!(
            resolve_diagnostics_path(
                &home.path().join(".tianshu-relay"),
                Some(&wrong_name.display().to_string())
            )
            .is_err(),
            "非白名单文件名必须被拒"
        );

        // ③ `..`（哪怕最终落在导出目录里也拒——归一之后就说不清用户到底想写哪儿）
        let dotted = exports.join("../exports/tianshu-relay-diagnostics-1.json");
        let err = resolve_diagnostics_path(
            &home.path().join(".tianshu-relay"),
            Some(&dotted.display().to_string()),
        )
        .expect_err("含 `..` 必须被拒");
        assert!(err.contains(".."), "文案: {err}");

        // ④ 符号链接：目标已存在且是链接 ⇒ 拒绝跟随
        #[cfg(unix)]
        {
            let link = exports.join("tianshu-relay-diagnostics-link.json");
            std::os::unix::fs::symlink(home.path().join(".zshrc"), &link).expect("建符号链接");
            let err = resolve_diagnostics_path(
                &home.path().join(".tianshu-relay"),
                Some(&link.display().to_string()),
            )
            .expect_err("符号链接必须被拒");
            assert!(err.contains("符号链接"), "文案: {err}");
        }
    }

    /// T3：正向对照——白名单内的路径**必须通过**（防「一律拒绝」的假修复）。
    #[test]
    fn diagnostics_accepts_whitelisted_paths() {
        let home = tempfile::tempdir().expect("临时 home");
        let exports = home.path().join(".tianshu-relay/exports");

        // 绝对路径 + 白名单文件名
        let ok = exports.join("tianshu-relay-diagnostics-1.json");
        assert_eq!(
            resolve_diagnostics_path(
                &home.path().join(".tianshu-relay"),
                Some(&ok.display().to_string())
            )
            .unwrap(),
            ok
        );

        // 相对路径（按导出目录解析）
        assert_eq!(
            resolve_diagnostics_path(
                &home.path().join(".tianshu-relay"),
                Some("tianshu-relay-diagnostics-2.json")
            )
            .unwrap(),
            exports.join("tianshu-relay-diagnostics-2.json")
        );

        // 空白串等同「没传」
        assert_eq!(
            resolve_diagnostics_path(&home.path().join(".tianshu-relay"), Some("   ")).unwrap(),
            resolve_diagnostics_path(&home.path().join(".tianshu-relay"), None).unwrap()
        );
    }

    /// T4：已有**普通文件**时不得被误判成符号链接（否则等于禁掉覆盖写）。
    #[test]
    fn diagnostics_allows_overwriting_a_regular_file() {
        let home = tempfile::tempdir().expect("临时 home");
        let exports = home.path().join(".tianshu-relay/exports");
        std::fs::create_dir_all(&exports).expect("建导出目录");
        let path = exports.join("tianshu-relay-diagnostics-3.json");
        std::fs::write(&path, "{}").expect("先放一个普通文件");
        assert_eq!(
            resolve_diagnostics_path(
                &home.path().join(".tianshu-relay"),
                Some(&path.display().to_string())
            )
            .unwrap(),
            path
        );
    }

    // ---- M16-S6a §12：export_bundle 的三条护栏 ----

    /// ① 相对路径被拒（绝对路径才不随 cwd 漂移）；② 缺省路径仍在导出目录内。
    #[test]
    fn bundle_requires_an_absolute_path_and_defaults_inside_the_exports_dir() {
        let home = tempfile::tempdir().expect("临时 home");
        let err = resolve_bundle_path(
            &home.path().join(".tianshu-relay"),
            Some("tianshu-relay-export.json"),
            false,
        )
        .expect_err("相对路径必须被拒");
        assert!(err.contains("绝对路径"), "文案: {err}");

        let default = resolve_bundle_path(&home.path().join(".tianshu-relay"), None, false)
            .expect("缺省路径");
        assert_eq!(
            default.parent().unwrap(),
            home.path().join(".tianshu-relay/exports")
        );
        assert!(default
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("tianshu-relay-export"));
    }

    /// ③ 已存在必须显式确认：不传 `overwrite` ⇒ 拒绝；`overwrite=true` ⇒ 放行。
    ///
    /// 这条是「不得静默覆盖用户文件」的**唯一**守护：没有它，`export_bundle` 会像修前那样
    /// 直接盖掉目标（`service::export_to_file` 只做 `fs::write`）。
    #[test]
    fn bundle_refuses_to_overwrite_without_an_explicit_confirmation() {
        let home = tempfile::tempdir().expect("临时 home");
        let dir = tempfile::tempdir().expect("临时目录");
        let target = dir.path().join("backup.json");
        std::fs::write(&target, "old").expect("先放一个已存在的文件");

        let err = resolve_bundle_path(
            &home.path().join(".tianshu-relay"),
            Some(&target.display().to_string()),
            false,
        )
        .expect_err("已存在且未确认 ⇒ 必须拒绝");
        assert!(err.contains("目标已存在"), "文案: {err}");
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "old",
            "被拒时不得改动原文件"
        );

        assert_eq!(
            resolve_bundle_path(
                &home.path().join(".tianshu-relay"),
                Some(&target.display().to_string()),
                true
            )
            .unwrap(),
            target,
            "显式确认后放行"
        );

        // 正向对照：**不**存在的目标无需确认
        let fresh = dir.path().join("fresh.json");
        assert!(resolve_bundle_path(
            &home.path().join(".tianshu-relay"),
            Some(&fresh.display().to_string()),
            false
        )
        .is_ok());
    }

    /// ② 符号链接被拒（不跟随）。
    #[test]
    fn bundle_refuses_a_symlinked_target() {
        #[cfg(unix)]
        let home = tempfile::tempdir().expect("临时 home");
        let dir = tempfile::tempdir().expect("临时目录");
        let real = dir.path().join("real.json");
        std::fs::write(&real, "x").expect("写真实文件");

        #[cfg(unix)]
        {
            let link = dir.path().join("link.json");
            std::os::unix::fs::symlink(&real, &link).expect("建符号链接");
            let err = resolve_bundle_path(
                &home.path().join(".tianshu-relay"),
                Some(&link.display().to_string()),
                true,
            )
            .expect_err("符号链接必须被拒（哪怕显式确认）");
            assert!(err.contains("符号链接"), "文案: {err}");
        }
    }

    // ---- P2-7：轮换后是否重启网关 ----

    /// T6：只有「网关在跑 **且** 跑的正是被轮换 key 的站点」才重启。
    ///
    /// 三个负例各防一种错：没跑却去重启（白起一个）、跑在别的站点却重启（把网关切走）、
    /// key 查不到站点（不确定时不动）。
    #[test]
    fn gateway_restart_decision_requires_the_same_site() {
        assert!(should_restart_gateway_after_rotation(Some(7), Some(7)));
        assert!(!should_restart_gateway_after_rotation(None, Some(7)));
        assert!(!should_restart_gateway_after_rotation(Some(7), Some(8)));
        assert!(!should_restart_gateway_after_rotation(Some(7), None));
    }

    // ---- P2-14：令牌轮换的参数一致性 ----

    /// T7：参数不符 ⇒ 拒绝；没传 ⇒ 放行（运行态是唯一事实来源）。
    ///
    /// 这条钉的是**判据**；「校验发生在换令牌之前」由 `gateway_rotate_token` 的调用顺序保证
    /// （见该函数里 `rotation_args_are_consistent(...)` 与 `rotate_gateway_token()` 的先后）。
    #[test]
    fn rotation_args_must_match_the_running_gateway() {
        assert!(rotation_args_are_consistent((3, 9), None).is_ok());
        assert!(rotation_args_are_consistent((3, 9), Some((3, 9))).is_ok());
        let err = rotation_args_are_consistent((3, 9), Some((4, 9))).expect_err("站点不符必须拒绝");
        assert!(err.contains("不切换站点"), "文案: {err}");
        assert!(rotation_args_are_consistent((3, 9), Some((3, 8))).is_err());
    }

    // ---- P3-15：人工验证的相位守卫 ----

    /// T8：只有 `AwaitingHuman` 允许提交；`Idle`（含「已被取消」）一律拒绝。
    #[test]
    fn captcha_submit_requires_the_awaiting_human_phase() {
        use tianshu_relay_core::site::captcha::CaptchaPhase;
        use tianshu_relay_core::site::CaptchaChallenge;
        let awaiting = CaptchaPhase::AwaitingHuman {
            site_id: 1,
            challenge: CaptchaChallenge {
                site_id: 1,
                url: "https://relay.example.com/login".to_string(),
            },
        };
        assert!(captcha_submit_is_allowed(&awaiting));
        // 取消之后相位回 `Idle` ⇒ 提交必须被拒（修前这条竞态会让会话被接上）
        assert!(!captcha_submit_is_allowed(&CaptchaPhase::Idle));
    }
}

#[cfg(test)]
mod m41s1_tests {
    use super::*;
    use tianshu_relay_core::settings::Settings;

    fn settings() -> Settings {
        Settings::default()
    }

    /// §6.2 的矩阵（11 行 → 关键分支全覆盖）。
    #[test]
    fn gateway_transition_matrix() {
        // 1) 关开关（运行中）⇒ Stop
        let prev = Settings {
            gateway_enabled: true,
            ..settings()
        };
        let next = Settings {
            gateway_enabled: false,
            ..settings()
        };
        assert_eq!(
            gateway_transition(&prev, &next, true),
            GatewayTransition::Stop
        );
        // 2) 关开关（未运行）⇒ None
        assert_eq!(
            gateway_transition(&prev, &next, false),
            GatewayTransition::None
        );
        // 3) 打开开关 ⇒ None（不自动启动）
        assert_eq!(
            gateway_transition(&next, &prev, false),
            GatewayTransition::None
        );
        // 4) 运行中改端口 ⇒ Restart
        let enabled = Settings {
            gateway_enabled: true,
            gateway_port: 8787,
            ..settings()
        };
        let port = Settings {
            gateway_port: 9898,
            ..enabled.clone()
        };
        assert_eq!(
            gateway_transition(&enabled, &port, true),
            GatewayTransition::Restart
        );
        // 5) 未运行改端口 ⇒ None
        assert_eq!(
            gateway_transition(&enabled, &port, false),
            GatewayTransition::None
        );
        // 6) 多站 / 7) 代理模式 / 8) 代理地址 各一条
        let multi = Settings {
            gateway_multi_site: true,
            ..enabled.clone()
        };
        assert_eq!(
            gateway_transition(&enabled, &multi, true),
            GatewayTransition::Restart
        );
        let proxy_mode = Settings {
            proxy_mode: "manual".into(),
            ..enabled.clone()
        };
        assert_eq!(
            gateway_transition(&enabled, &proxy_mode, true),
            GatewayTransition::Restart
        );
        let proxy_url = Settings {
            proxy_url: "socks5://127.0.0.1:1080".into(),
            ..enabled.clone()
        };
        assert_eq!(
            gateway_transition(&enabled, &proxy_url, true),
            GatewayTransition::Restart
        );
        for changed in [
            Settings {
                gateway_max_request_mib: 32,
                ..enabled.clone()
            },
            Settings {
                gateway_per_site_burst: 8,
                ..enabled.clone()
            },
            Settings {
                gateway_per_site_concurrency: 2,
                ..enabled.clone()
            },
            Settings {
                gateway_per_site_rate_limit: 5,
                ..enabled.clone()
            },
            Settings {
                gateway_max_attempts: 3,
                ..enabled.clone()
            },
            Settings {
                gateway_session_affinity: true,
                ..enabled.clone()
            },
            Settings {
                gateway_upstream_protocol:
                    tianshu_relay_core::settings::UPSTREAM_PROTOCOL_ANTHROPIC.into(),
                ..enabled.clone()
            },
            Settings {
                gateway_key_health_interval_secs: 60,
                ..enabled.clone()
            },
            Settings {
                routing_rules: "[]".into(),
                ..enabled.clone()
            },
        ] {
            assert_eq!(
                gateway_transition(&enabled, &changed, true),
                GatewayTransition::Restart
            );
        }
        let catalog = Settings {
            catalog_url: "https://example.com/catalog.json".into(),
            catalog_auto_sync: false,
            ..enabled.clone()
        };
        assert_eq!(
            gateway_transition(&enabled, &catalog, true),
            GatewayTransition::None,
            "名单共享快照/同步设置不需要重启"
        );
        // 9) 白名单外字段 ⇒ None（主题 / 语言 / 自动启动 / last_*）
        let theme = Settings {
            theme: "dark".into(),
            ..enabled.clone()
        };
        assert_eq!(
            gateway_transition(&enabled, &theme, true),
            GatewayTransition::None
        );
        let auto = Settings {
            gateway_auto_start: true,
            ..enabled.clone()
        };
        assert_eq!(
            gateway_transition(&enabled, &auto, true),
            GatewayTransition::None
        );
        let last = Settings {
            gateway_last_site_id: 9,
            gateway_last_key_id: 9,
            ..enabled.clone()
        };
        assert_eq!(
            gateway_transition(&enabled, &last, true),
            GatewayTransition::None
        );
        // 10) 运行中关开关同时改端口 ⇒ Stop（优先级最高）
        let both = Settings {
            gateway_enabled: false,
            gateway_port: 9898,
            ..settings()
        };
        assert_eq!(
            gateway_transition(&enabled, &both, true),
            GatewayTransition::Stop
        );
    }

    fn site(id: i64, health: &str) -> tianshu_relay_core::service::SiteSummary {
        tianshu_relay_core::service::SiteSummary {
            id,
            kind: "newapi".into(),
            base_url: "https://example.test".into(),
            display_name: format!("站点 {id}"),
            health: health.into(),
            session_persisted: false,
            session_expires_at: None,
        }
    }

    fn key(id: i64, site_id: i64, status: &str) -> tianshu_relay_core::store::KeyRow {
        tianshu_relay_core::store::KeyRow {
            id,
            site_id,
            remote_id: None,
            name: format!("key {id}"),
            group_name: None,
            group_id: None,
            secret_ref: format!("kr/key/{id}/secret"),
            status: status.into(),
            created_at: 0,
            quota_used: None,
            quota_limit: None,
            currency: None,
        }
    }

    #[test]
    fn auto_start_prefers_last_run_when_all_four_checks_pass() {
        let sites = vec![site(1, "ok"), site(2, "ok")];
        let keys = vec![key(10, 1, "enabled"), key(20, 2, "enabled")];
        assert_eq!(auto_start_target(&sites, &keys, 2, 20), Some((2, 20)));
    }

    #[test]
    fn auto_start_falls_back_when_last_run_is_invalid() {
        let sites = vec![site(1, "ok"), site(2, "ok")];
        let keys = vec![key(10, 1, "enabled"), key(20, 2, "enabled")];
        // 站点不存在
        assert_eq!(auto_start_target(&sites, &keys, 99, 20), Some((1, 10)));
        // 密钥不存在
        assert_eq!(auto_start_target(&sites, &keys, 2, 99), Some((1, 10)));
        // 密钥不属于该站（不混用）
        assert_eq!(auto_start_target(&sites, &keys, 2, 10), Some((1, 10)));
        // 密钥非 enabled
        let disabled = vec![key(10, 1, "enabled"), key(20, 2, "revoked")];
        assert_eq!(auto_start_target(&sites, &disabled, 2, 20), Some((1, 10)));
        // 站点 health 非 ok
        let sick = vec![site(1, "ok"), site(2, "error")];
        assert_eq!(auto_start_target(&sick, &keys, 2, 20), Some((1, 10)));
        // 0 = 无 ⇒ 直接兜底
        assert_eq!(auto_start_target(&sites, &keys, 0, 0), Some((1, 10)));
    }

    #[test]
    fn auto_start_targets_lists_preferred_first_then_the_rest_in_order() {
        let sites = vec![site(1, "ok"), site(2, "ok"), site(3, "error")];
        let keys = vec![
            key(10, 1, "enabled"),
            key(11, 1, "enabled"),
            key(20, 2, "enabled"),
            key(30, 3, "enabled"),
        ];
        // 首选是上次组，其后按站点/密钥 id 升序，不含不健康站点。
        assert_eq!(
            auto_start_targets(&sites, &keys, 2, 20),
            vec![(2, 20), (1, 10), (1, 11)]
        );
        // 无上次组时首选即第一个健康组，清单仍完整。
        assert_eq!(
            auto_start_targets(&sites, &keys, 0, 0),
            vec![(1, 10), (1, 11), (2, 20)]
        );
        assert!(auto_start_targets(&[], &[], 0, 0).is_empty());
    }

    #[test]
    fn auto_start_returns_none_when_no_healthy_site_or_no_enabled_key() {
        let sites = vec![site(1, "error")];
        let keys = vec![key(10, 1, "enabled")];
        assert_eq!(auto_start_target(&sites, &keys, 0, 0), None);
        let healthy = vec![site(1, "ok")];
        let no_keys = vec![key(10, 1, "revoked")];
        assert_eq!(auto_start_target(&healthy, &no_keys, 0, 0), None);
        assert_eq!(auto_start_target(&[], &[], 0, 0), None);
    }
}
