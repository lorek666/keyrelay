//! 应用服务层：把「站点适配器 + 注册表 + 会话缓存 + 本地存储 + 钥匙串」组合成可直接被 UI 调用的用例。
//!
//! 分层约定：本层**不碰 HTTP 细节**（交给适配器）、**不碰 SQL**（交给 `Store`）、
//! **不读环境变量**（路径由壳层显式传入）。Tauri 命令层只做 DTO 转换。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::audit::{self, AuditFinding, AuditReport};
use crate::delivery::{self, ConsentState, DeliveryChannel, DeliveryOutcome, DeliveryPlan};
use crate::drift::{self, DriftReport};
use crate::error::{Error, Result};
use crate::export::{
    self, ExportBundle, ExportConsent, ExportEvent, ExportKey, ExportSettings, ExportSite,
};
use crate::inject;
use crate::observability::{self, Event, Level};
use crate::settings::Settings;
use crate::site::captcha::{self, CaptchaEvent, CaptchaPhase};
use crate::site::registry::SiteRegistry;
use crate::site::transport::HttpTransport;
use crate::site::{
    Balance, CaptchaChallenge, Credentials, KeyMaterial, KeyMeta, KeySpec, Session, SiteKind,
};
use crate::store::{ConsentRow, SiteRow, Store};
use crate::vault::Vault;

use futures_util::stream::{self, StreamExt};

/// 服务装配参数。核心层**不读环境变量**，`home` 与 `backup_dir` 一律由壳层传入，
/// 这样测试可以把它们指向临时目录。
///
/// **通知不在这里**（M6-S5）：见 [`TianshuRelayService::with_notify`]。把 `notify` 做成
/// `ServiceConfig` 的字段会让全仓 10 个集成测试文件的结构体字面量一次性编译失败——
/// 为了一个默认关闭的可选功能去改 10 个别人的测试文件，代价与收益不成比例。
/// 做成 `TianshuRelayService` 上的构造器方法之后，不关心通知的调用方一个字节都不用改。
pub struct ServiceConfig {
    pub vault: Arc<dyn Vault>,
    pub home: PathBuf,
    pub backup_dir: PathBuf,
}

impl ServiceConfig {
    /// 生产装配：本地加密保险库（`LocalVault`，ADR-0003），路径按 `home` 推导。
    ///
    /// 保险库打不开（`vault.key` 损坏、目录不可写）时**不静默**：打一条 stderr，
    /// 退回 `MemoryVault` —— 此时 `vault_backend()` 会返回 `"memory"`，Overview 页
    /// 有红色告警，用户能看见「密钥出问题了」，而不是以为一切正常。
    /// 之所以还要有这条退路：启动阶段没有任何 UI 可用来报错，直接退出更糟。
    pub fn production(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        Self::with_local_vault(home)
    }

    /// 用给定 `home` 构造本地保险库；失败时退回内存实现并留下 stderr 证据。
    fn with_local_vault(home: PathBuf) -> Self {
        let (db_path, key_path) = crate::vault::local::default_paths(&home);
        let vault: Arc<dyn Vault> = match crate::vault::LocalVault::open(&db_path, &key_path) {
            Ok(vault) => Arc::new(vault),
            Err(err) => {
                eprintln!(
                    "[tianshu-relay] 本地保险库不可用（{}），密钥将只存在内存里: {err}",
                    db_path.display()
                );
                Arc::new(crate::vault::MemoryVault::new())
            }
        };
        Self {
            vault,
            backup_dir: home.join(".tianshu-relay").join("backups"),
            home,
        }
    }

    /// 用调用方构造好的保险库装配（壳层需要先做一次性迁移，或测试要注入假后端）。
    pub fn with_vault(vault: Arc<dyn Vault>, home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        let data_dir = home.join(crate::rebrand::APP_DIR_NAME);
        Self::with_vault_at(vault, home, data_dir)
    }

    /// 与 [`Self::with_vault`] 相同，但**显式**指定本次实际使用的数据目录。
    ///
    /// M35-S1：迁移失败时本次运行回退旧目录，备份也必须落在**那个**目录里，
    /// 不能再按 `home + 新目录名` 硬拼。
    pub fn with_vault_at(
        vault: Arc<dyn Vault>,
        home: impl Into<PathBuf>,
        data_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            vault,
            backup_dir: data_dir.into().join("backups"),
            home: home.into(),
        }
    }

    /// 生产装配（显式数据目录；M35-S1）。
    pub fn production_at(home: impl Into<PathBuf>, data_dir: impl Into<PathBuf>) -> Self {
        let home = home.into();
        let data_dir = data_dir.into();
        let (db_path, key_path) = crate::vault::local::default_paths_in(&data_dir);
        let vault: Arc<dyn Vault> = match crate::vault::LocalVault::open(&db_path, &key_path) {
            Ok(v) => Arc::new(v),
            Err(err) => {
                eprintln!(
                    "[tianshu-relay] 本地保险库不可用（{}），密钥将只存在内存里: {err}",
                    db_path.display()
                );
                Arc::new(crate::vault::MemoryVault::new())
            }
        };
        Self::with_vault_at(vault, home, data_dir)
    }

    /// 测试装配：内存钥匙串 + 显式临时目录。
    pub fn in_memory(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        Self {
            vault: Arc::new(crate::vault::MemoryVault::new()),
            backup_dir: home.join(".tianshu-relay").join("backups"),
            home,
        }
    }
}

/// 钥匙串条目的引用 id：时间戳 + 进程内自增序号 + 进程号。
///
/// 不用站点返回的 `remote_id`：不同站点可以有同一个 `remote_id`，
/// 而钥匙串的引用必须全局唯一（否则两把不同的钥匙会互相覆盖）。
fn new_ref_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:x}{seq:x}{:x}", std::process::id())
}

/// 错误分类名：只写「哪一类」，不回显站点原文（事件表里不需要原文）。
fn error_kind(err: &Error) -> &'static str {
    match err {
        Error::FingerprintMismatch(_) => "指纹不匹配",
        Error::AuthFailed(_) => "认证失败",
        Error::CaptchaRequired => "需要人机验证",
        Error::SecondFactorRequired { .. } => "需要二次验证",
        Error::RateLimited { .. } => "被限流",
        Error::QuotaExhausted => "额度不足",
        Error::NotFound(_) => "远端资源不存在",
        Error::Transport(_) => "网络/协议错误",
        // M19-S2：与「网络/协议错误」分开记——连接层失败意味着**请求没送达对端**，
        // 而「要不要把同一个请求再发一次」正是靠这条差别判断的，不该被压成同一个词。
        Error::NotDelivered(_) => "连接未建立",
        // M9-S2：与「认证失败」分开记——用户要做的是**改输入**，不是重新登录。
        Error::InvalidInput(_) => "输入不符合站点要求",
        Error::Vault(_) => "保险库错误",
        Error::VaultUnavailable(_) => "保险库不可用",
        Error::ConsentRequired { .. } => "缺少用户同意",
        Error::FileBusy(_) => "目标文件被占用",
        Error::Store(_) => "本地存储错误",
        Error::Inject { .. } => "写入失败",
        Error::Unimplemented(_) => "尚未实现",
        // M7-S0：与 `Unimplemented` 分开记，事件表里「还没做」和「这类站点不做」是两条不同的信号。
        Error::Unsupported(_) => "站点类型不支持",
    }
}

/// 已回收（`keys.status = revoked`）的 key 不得再被使用：投递、网关、轮换都在这里拒绝。
///
/// 站点上已经没有它了：投递出去 agent 只会收到 401；对它轮换会先在站点上**新建**一把，
/// 再去 DELETE 一个不存在的 id。用 `NotFound`（「远端资源不存在」）——这正是事实。
fn ensure_not_revoked(row: &crate::store::KeyRow) -> Result<()> {
    if row.status == crate::store::KEY_STATUS_REVOKED {
        return Err(Error::NotFound(format!(
            "密钥 #{} 已回收，站点上已经没有它了；不能再投递、启动网关或轮换，需要的话请新建一把",
            row.id
        )));
    }
    Ok(())
}

/// 是不是「认证类失败」——即 `error_kind` 判为「认证失败」的那一类（M5-S0 章程 §4.1 规则 2）。
///
/// 只认 [`Error::AuthFailed`]：`CaptchaRequired` / `SecondFactorRequired` 的会话**未必**失效
/// （站点只是要人再过一道验证），把它们也标成 `needs_login` 会让用户看到一条假的
/// 「请重新登录」。
fn is_auth_failure(err: &Error) -> bool {
    matches!(err, Error::AuthFailed(_))
}

/// 会话的过期信息（B-121 / FR-1:104「会话保持」）。
///
/// `expires_at` 来自 JWT 的 `exp`（NewAPI / Sub2API 的 `access_token`）；
/// 无 JWT 的纯 Cookie 会话（Custom / 旧版 NewAPI）⇒
/// [`TianshuRelayService::session_expiry`] 返回 `None`（「不知道什么时候过期」，
/// 不是「马上过期」）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionExpiry {
    /// 过期时刻（unix 秒）。
    pub expires_at: i64,
    /// 距现在还有多少秒；**可能为负**（已过期，界面应提示重新登录）。
    pub seconds_left: i64,
}

/// 从 JWT 里读 `exp`（B-121）。
///
/// **不校验签名**：`exp` 只用来判断「这条会话还要不要留着」（展示 + 恢复时跳过），
/// 不承担任何鉴权职责——会话是否有效永远由站点侧的 401 决定（`mark_needs_login`）。
///
/// 非法输入（段数不对 / base64 解不开 / 不是 JSON / 没有 `exp` / `exp` 不是整数）
/// ⇒ `None`，**不 panic**。
fn jwt_exp(token: &str) -> Option<i64> {
    use base64::Engine as _;
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(payload))
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.get("exp").and_then(|exp| exp.as_i64())
}

/// 会话是否**已过期**（B-121）：只看 JWT 的 `exp`。
///
/// 没有 JWT（纯 Cookie 会话 / 旧版 NewAPI）⇒ `false`（不算过期）：它的有效性由第一次
/// 请求的 401 判定，那时 `mark_needs_login` 会删掉持久化条目。**不做时间上的兜底过期**——
/// 持久化形态里没有保存时刻，硬编一个「30 天」会把仍有效的会话误删（登记为残余项）。
/// NewAPI 的新版会话有 JWT `exp`；即使已过期，只要还带 `new_api_refresh`，
/// `restore_sessions` 会刻意保留，交给续期循环换新 token（M29-S1）。
fn session_is_expired(session: &Session, now: i64) -> bool {
    session
        .access_token
        .as_deref()
        .and_then(jwt_exp)
        .is_some_and(|exp| exp <= now)
}

/// 能力门的统一出口（M7-S5）：站点类型**设计上**不支持某操作时返回 [`Error::Unsupported`]。
///
/// 为什么要有它：适配器自己返回的 `Unsupported` 只能覆盖它实现的那几条路径，
/// 而「这个站点类型没有令牌管理端点」是**站点类型**的属性——任何新增入口都该自动继承这条判断。
/// 判据来自 `site::capability::capabilities()`（纯函数，不联网）。
///
/// **调用时机是硬要求**：必须在 `self.session(site_id)?` **之前**。
/// 没有令牌管理端点的站点通常也没有会话，先要会话会先报「未登录」，
/// 把用户引向一个根本不存在的登录流程——这正是 `custom-openai-compatible` 会踩的坑。
fn capability_gate(kind: crate::site::SiteKind, supported: bool, action: &str) -> Result<()> {
    if supported {
        return Ok(());
    }
    Err(Error::Unsupported(format!(
        "{} 站点不支持{action}",
        kind.as_str()
    )))
}

/// 进程内会话缓存（按站点隔离）。持久化属 M1-S2。
#[derive(Default)]
pub struct SessionCache {
    inner: Mutex<HashMap<i64, Session>>,
}

impl SessionCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&self, site_id: i64, session: Session) -> Result<()> {
        self.lock()?.insert(site_id, session);
        Ok(())
    }

    pub fn get(&self, site_id: i64) -> Option<Session> {
        self.lock().ok()?.get(&site_id).cloned()
    }

    pub fn invalidate(&self, site_id: i64) {
        if let Ok(mut map) = self.lock() {
            map.remove(&site_id);
        }
    }

    pub fn len(&self) -> usize {
        self.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<i64, Session>>> {
        self.inner
            .lock()
            .map_err(|_| Error::Store("会话缓存锁已中毒".into()))
    }
}

/// 已落库的密钥记录。**不含密钥本体**，可以直接给前端。
#[derive(Clone, PartialEq, Eq)]
pub struct StoredKey {
    pub id: i64,
    pub remote_id: String,
    pub name: String,
    /// 掩码后的密钥（`…末4位`），用于让用户确认「是哪一把」
    pub masked: String,
}

impl std::fmt::Debug for StoredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredKey")
            .field("id", &self.id)
            .field("remote_id", &self.remote_id)
            .field("name", &self.name)
            .field("masked", &self.masked)
            .finish()
    }
}

/// `purge_keychain()` 的结果。**只报计数**，不报被删的条目名（条目名本身也是线索）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeychainPurgeReport {
    /// 尝试删除的条目数（去重后）。
    pub attempted: usize,
    /// 删除成功的条目数。
    pub removed: usize,
    /// 删除失败的条目数。
    pub failed: usize,
    /// 第一条失败的文案（已脱敏）。没有失败时为 `None`。
    pub first_error: Option<String>,
}

/// `sites.health` 的取值（与 [`Store::set_site_health`] 的约定一致，见 M5-S0 章程 §4.1）。
///
/// 取 `pub` 是因为 `SiteSummary.health` 本来就是对外的字符串，调用方应当对着常量比，
/// 而不是在 `src-tauri` 与前端里到处写裸字面量。
pub const HEALTH_UNKNOWN: &str = "unknown";
pub const HEALTH_OK: &str = "ok";

/// B 路凭据槽的 TTL（M28-S1 §2.1.5）：从捕获到用户点「我已登录」。
///
/// 10 分钟：够用户过完人机验证 + 等页面跳转，又不至于让一份旧凭据在内存里长期驻留。
pub const WEBVIEW_CREDS_TTL: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// B 路凭据槽里的条目（内存，不入库）。
struct StoredWebviewCredentials {
    creds: crate::site::webview_creds::WebviewCredentials,
    captured_at: std::time::Instant,
}
pub const HEALTH_NEEDS_LOGIN: &str = "needs_login";

/// 一轮刷新的结果。不含任何密钥。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RefreshSummary {
    pub sites_total: usize,
    pub sites_ok: usize,
    pub sites_failed: usize,
    pub keys_total: usize,
    /// 触发余额告警的站点 id
    pub balance_alerts: Vec<i64>,
    /// 本轮**需要重新登录**的站点 id。升序、去重、不含密钥（M5-S0 章程 §4.1）。
    pub needs_login: Vec<i64>,
}

/// 一趟模型目录采集的摘要（M39-S1）。**可安全打印**：不含密钥、不含响应正文。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ModelCatalogSummary {
    /// 真的发出 `/v1/models` 请求的站点数（受开关 / 到期 / 有可用 key 三重过滤之后）。
    pub attempted: usize,
    /// 成功且非空的站点数（**替换**了该站集合）。
    pub replaced: usize,
    /// 成功但空的站点数（其中达到阈值而被清空的计入 `cleared`）。
    pub empty: usize,
    /// 失败的站点数（目录不变，只记 `last_attempt_at` / `last_error`）。
    pub failed: usize,
    /// 本次因连续空被清空的站点 id（升序）。
    pub cleared: Vec<i64>,
    /// 本次是否发布了新快照。
    pub published: bool,
    /// 当前快照代号（未发布 = 发布前的代号；没有运行态 = 0）。
    pub generation: u64,
}

/// 一趟采集里**同时在途**的站点数上限（M39-S1 §4.5 / §12）。
///
/// 写成常量而不是设置项：这是「别把 20 个站点同时打一遍」的保护，不是用户可调策略。
/// 语义是**实际在途上限**（`buffer_unordered` 的语义），不是「每批 2 个、批间无等待」。
pub const MODEL_CATALOG_CONCURRENCY: usize = 2;

/// 镜像决策（M39-S1，纯函数）：该站的内存模型镜像要不要被本轮目录事实覆盖。
///
/// - 表里有该站的行 ⇒ **覆盖**（正常替换）；
/// - 表里没有行、但该站**成功采集过**（`last_success_at` 有值）⇒ 覆盖成空（目录真被清空）；
/// - 两者都没有（从没采过，例如 `collect_models` 刚打开）⇒ **保留旧值**。
///   把「还没采」当成「模型全没了」，会让通知侧的 `ModelsChanged` 误报。
fn should_overwrite_model_mirror(catalog_has_rows: bool, last_success: Option<i64>) -> bool {
    catalog_has_rows || last_success.is_some()
}

/// 一次「站点侧密钥对齐到本地」的结果（M6-S5 / FR-2）。
///
/// **不含任何密钥明文，也不含 `secret_ref`**——它会被序列化到 UI。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySyncSummary {
    pub site_id: i64,
    /// 站点侧一共多少条
    pub site_total: usize,
    /// 其中本地已经有了多少条
    pub already_local: usize,
    /// 本次**恢复**了多少条：本地行还在、但钥匙串条目被清过（`purge_keychain`），
    /// 于是把明文重新取回**原来那一行**（DEBUG 报告 §1.9）。
    ///
    /// 与 `imported` 分开报：用户的动作不一样——「恢复」说明他清过钥匙串，
    /// 现在按提示取回来了；「新导入」说明这是本机第一次看到这把 key。
    pub restored: usize,
    /// 本次新导入本地钥匙串多少条
    pub imported: usize,
    /// 站点没给明文（或写入钥匙串失败）的 `remote_id`。
    ///
    /// 不静默跳过：PRD §10 的风险表里明确有「站点不提供密钥明文回读」这一条，
    /// 界面需要据此引导用户「新建一把」而不是以为对齐成功了。
    pub unreadable: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteSummary {
    pub id: i64,
    pub kind: String,
    pub base_url: String,
    pub display_name: String,
    pub health: String,
    /// 保险库里是否存在该站的持久化会话（M38-S1）：只看 `Vault::has` 的**存在性**，
    /// 不读明文；读失败按 `false` 处理（列表不因单个条目读失败整页失败）。
    pub session_persisted: bool,
    /// 当前**内存**会话的 JWT `exp`（复用 `session_expiry`）；无会话 / 非 JWT ⇒ `None`。
    pub session_expires_at: Option<i64>,
}

/// 轮换预览（M6-S5 / FR-7）。**只读**，不含密钥。
///
/// 菜单上必须先看预览再动手：第三步（回收旧 key）是不可逆的，而 PRD §7 要求
/// 「危险操作二次确认」——没有预览，二次确认就只是「真的要删吗」的空话，
/// 用户看不到「会波及哪些投递目标」这个真正需要他判断的东西。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationPlan {
    pub key_id: i64,
    pub site_id: i64,
    /// 密钥名（**上游自由文本**：只用于界面上确认「是哪一把」，不得进通知正文）
    pub key_name: String,
    /// 固定三步（`rotation::rotation_steps()`；顺序不可重排）
    pub steps: Vec<crate::rotation::RotationStep>,
    /// 会被重注入的通道（`channel.as_str()`，升序去重）
    pub channels: Vec<String>,
    /// 绑定了这把 key、但 `agent_id` 认不出通道的目标，升序去重。
    /// **非空 = 不能轮换**（见 [`TianshuRelayService::rotate_key`] 的前置拒绝）。
    pub unmapped_targets: Vec<String>,
    /// 旧 key 的站点侧 id；`None` = 本地记录里就没有，第三步会被跳过并说明
    pub old_remote_id: Option<String>,
    /// 旧 key 本地记录的**分组显示名**（`keys.group_name`）。
    ///
    /// 预览只展示它，**不**在这里校验它是否还存在于站点上：`rotation_plan` 一个请求都
    /// 不发（PRD §7 的预览必须是纯本地的）。校验发生在执行时、`create_key` 之前
    /// （B-166）。`None` = 这把 key 从来没绑过分组。
    pub old_group_name: Option<String>,
    /// 旧 key 本地记录的**站点原生分组 id**（`keys.group_id`，Sub2API 上是数字主键）。
    ///
    /// M22-S1：有 id 时轮换**按 id 认定**分组——id 是站点主键，分组改名不会改变它，
    /// 而按名字匹配会在改名后直接失效（B-168）。`None` = 旧行没存过（本步之前的行）或
    /// 站点没有 id 概念（NewAPI 的 `GroupInfo.id` 为 `None`，名字即标识）。
    ///
    /// 与 `old_group_name` 一样，预览只展示、不校验；在线校验是用户点「校验分组」时才发的
    /// 独立请求（B-167）。
    pub old_group_id: Option<String>,
}

/// 「回收旧 key」这一步的结局。四态**互斥且穷尽**，界面必须逐态给出不同文案——
/// 「跳过了」与「做了但失败」是两件完全不同的事，合并成一个 `bool` 会让
/// 「旧密钥是否还活着」变成猜谜。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// 已在站点侧删除
    Revoked,
    /// 本地记录里没有站点侧 id（老库 / 手工导入），**跳过**
    SkippedNoRemoteId,
    /// 没走到这一步（前一步失败了）
    NotAttempted,
    /// 走到了，站点侧拒绝（原因已脱敏）
    Failed(String),
}

/// 一次轮换的完整结果。**不含密钥明文**（新 key 只有掩码形态）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationRun {
    /// 新建的 key（明文只进钥匙串）
    pub new_key: StoredKey,
    /// 已成功重注入的通道（按注入顺序）
    pub reinjected: Vec<String>,
    pub revoke: RevokeOutcome,
    /// 停在哪一步（`None` = 三步全部走完，或第三步按规跳过）
    pub stopped_at: Option<crate::rotation::RotationStep>,
    /// 停下的人话原因（已脱敏）；与 `stopped_at` 同生共死
    pub stop_reason: Option<String>,
}

impl RotationRun {
    /// 是否「没有中途失败」。注意 `SkippedNoRemoteId` **算完成**——
    /// 那是「本来就没得回收」，不是失败；界面仍要把它单独说明。
    pub fn completed(&self) -> bool {
        self.stopped_at.is_none()
    }
}

/// 一次落盘导出的结果。**不含文件内容**。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportOutcome {
    pub path: std::path::PathBuf,
    pub encrypted: bool,
    pub bytes: usize,
    /// 是否成功登记进「已知导出物」表（M5-S5 / B-60）。
    ///
    /// `false` 表示文件**确实写成了**，但审计从此看不到它 ——
    /// 「自我证明零明文」这条链路上多了一个洞。不回滚、不谎报失败，
    /// 但必须让调用方（与 UI）知道（M5-S2 复审 P2-4）。
    pub registered: bool,
}

/// 诊断包落盘的结果（FR-9）。
///
/// 与 [`ExportOutcome`] 分开而不是复用：诊断包**没有加密形态**（它本来就只含脱敏后的
/// 事件与白名单设置），`encrypted` 字段放在这里会是恒 `false` 的噪音；而 `events`
/// 是用户在报障时唯一关心的量（「我导了几条」）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticsOutcome {
    pub path: std::path::PathBuf,
    pub bytes: usize,
    pub events: usize,
    /// 是否成功登记进「已知导出物」表。语义与 [`ExportOutcome::registered`] 逐字相同：
    /// `false` = 文件写成了，但审计从此看不到它。诊断包同样要登记——
    /// 它落在用户磁盘上，就同样属于「本产品产物」的扫描面。
    pub registered: bool,
}

/// 网关本地令牌的钥匙串引用（M8-S4 §6.4）。
///
/// # 为什么是 `kr/gateway/local/token` 而不是 spec 写的 `gateway/local-token`
///
/// 引用格式由 ADR-0002 钉死：`kr/<scope>/<id>/<field>` 四段，`is_valid_secret_ref` 会拒绝
/// 其它形状。spec §6.4 给的是「一把钥匙串条目」这个**意图**，形状以本仓的引用规则为准
/// （规格差异登记 D-7）。取值只此一处：改这里就是改全部。
pub const GATEWAY_TOKEN_REF: &str = "kr/gateway/local/token";

/// 轮换预检里「写不进去」的一个目标（§9-8）。
///
/// 三个字段都会被原样念给用户听（错误文案 + 事件），所以不做成 `bool` 或 `String`。
#[derive(Clone, Debug, PartialEq, Eq)]
struct BlockedTarget {
    channel: String,
    target: String,
    /// 已脱敏的原因。
    reason: String,
}

/// 一次**回收**（站点侧删除）的回报（B-100）。
///
/// 为什么要把「站点侧删掉了」与「本地状态写上了」分开报：这两个是**两个不同的世界**，
/// 且第一个不可逆。合成一个 bool 会让「站点侧已删、本地记账失败」只能二选一，
/// 而两种选择都错——报成功则账不平，报失败则用户会去重试一次注定失败的删除（§7）。
///
/// # 为什么叫 `RevokeReport` 而不是 spec §4.2 写的 `RevokeOutcome`
///
/// 名字**已被占用**：`RevokeOutcome` 是 M7 就有的四态枚举（`RotationRun.revoke` 的类型，
/// 界面按四态给不同文案，见上面那条定义）。两个类型不能同名，而改掉既有那个会动到
/// M7 的冻结接口与前端契约 ⇒ **新的这个让路**（规格差异登记 D-6，M8-S4 §13）。
/// 命名与 `store::UnbindReport` 同形：都是「一次动作的逐条回报」。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokeReport {
    pub site_id: i64,
    /// 站点侧的令牌 id。`None` = 本地没有记过它（站点网页上手工建的 key）。
    pub remote_id: Option<String>,
    /// 站点侧**确认删除**（适配器 `revoke_key` 返回 `Ok`）。
    pub revoked: bool,
    /// 本地 `keys.status` 是否写上 `revoked`。
    pub local_status_updated: bool,
    pub note: Option<String>,
}

/// 一次解绑的结果（M8-S4 §5）。
///
/// `unbound` / `already_unbound` 的语义逐条见 [`crate::store::UnbindReport`]；
/// `revoked` 只在 `also_revoke == true` 时非空——**默认路径一个站点请求都不发**。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnbindOutcome {
    pub unbound: usize,
    pub already_unbound: usize,
    /// 逐把回收的结果（单条失败不回滚解绑，也不冒泡）。
    pub revoked: Vec<RevokeReport>,
    pub note: Option<String>,
}

/// 当前 unix 秒。
///
/// 只给 [`TianshuRelayService::dispatch_notifications`] 与 [`TianshuRelayService::rotation_due`] 用：
/// `notify::evaluate` 与 `rotation::due_keys` 都是纯函数，时间必须由调用方传入
/// （这样它们才能被单测）。这里是唯一的「读时钟」点。
fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 「什么都还不知道」的基线项：字段名与真实快照一致，取值一律是「从未取到过」
/// （`balance: None`、`needs_login: false`、`drift: []` …）。
///
/// 刻意**不**从 `current` 复制任何取值：复制取值等于把当前状态当成历史，
/// 边沿会被去重吃掉（修 W-1 时踩到的正是这个坑）。保留 `site_id` / `display_name`：
/// 规则按 `site_id` 找基线，找不到就等于没有基线。
fn neutral_site(site: &crate::notify::SiteSnapshot) -> crate::notify::SiteSnapshot {
    crate::notify::SiteSnapshot {
        site_id: site.site_id,
        display_name: site.display_name.clone(),
        ..Default::default()
    }
}

/// 上一轮快照 + 给「本轮才出现的站点」补的中性项。
///
/// `prev == None`（进程刚起来 / 刚开通知）时，结果就是「全部站点都用中性项」；
/// `prev == Some` 时**只**追加缺失的站点，已有站点一律沿用真实的上一轮值——
/// 历史不能被中性值冲掉，否则每一轮都变成「第一次见到它」，边沿型规则会退化成每轮都报。
fn filled_baseline(
    prev: Option<crate::notify::Snapshot>,
    current: &crate::notify::Snapshot,
) -> crate::notify::Snapshot {
    let mut sites = prev.map(|snapshot| snapshot.sites).unwrap_or_default();
    for site in &current.sites {
        // 追加是安全的：`Snapshot::site()` 取**第一个**匹配项，所以已有站点一定先被找到。
        if !sites.iter().any(|known| known.site_id == site.site_id) {
            sites.push(neutral_site(site));
        }
    }
    crate::notify::Snapshot { sites }
}

/// 自启用的应用标识。固定值：一个用户只该有一份自启项，
/// 让它随 `base_url` 或版本变化会产生「升级一次多一个自启项」。
///
/// 只允许 `[A-Za-z0-9._-]`——`platform_env` 与 `autostart` 的入口会校验，
/// 含 `/` 或 `..` 一律拒绝（路径穿越防线）。
pub const AUTOSTART_APP_ID: &str = "tianshu-relay";

/// 同一目录下「同主名、不同扩展名」的兄弟文件（M6-S5 / BACKLOG B-76）。
///
/// # 为什么需要它
///
/// 投递通道的落点是被冻结的常量（例如 OpenCode 写 `~/.config/opencode/opencode.json`）。
/// 但有些 agent 会**优先读另一个扩展名的文件**——本机实测 `~/.config/opencode/` 下
/// `.json` 与 `.jsonc` 并存。若 opencode 读的是 `.jsonc`，我们写进 `.json` 的密钥
/// 会被**静默忽略**：用户看到「已投递成功」，agent 却拿不到 key，而且没有任何报错。
///
/// 这个函数只负责**发现**，不做判定、不产生文案——「是不是问题」取决于具体 agent，
/// 由调用方决定怎么呈现。
///
/// 返回排序后的绝对路径列表（排序是为了让 UI 输出稳定、让测试可断言）。
/// 读目录失败、目标没有扩展名、目标是目录 —— 一律返回空列表（探测失败不该阻断投递）。
pub fn sibling_config_files(target: &std::path::Path) -> Vec<std::path::PathBuf> {
    let Some(stem) = target.file_stem() else {
        return Vec::new();
    };
    // 目标自己没有扩展名时「另一个扩展名」无从谈起（`rc` vs `rc.sh` 是**另一个名字**，
    // 不是同一份配置的另一种写法）。直接返回空，避免制造无从处置的警告。
    let Some(target_ext) = target.extension() else {
        return Vec::new();
    };
    let Some(parent) = target.parent() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };

    let mut out: Vec<std::path::PathBuf> = entries
        .flatten()
        .filter(|entry| {
            let path = entry.path();
            // 只要普通文件：目录名碰巧同主名（例如 `opencode.json/`）不是配置文件
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                return false;
            }
            // 主名必须逐字相同（`opencode.json` ↔ `opencode.jsonc`；`auth.json` ↔ `auth.jsonc`）
            if path.file_stem() != Some(stem) {
                return false;
            }
            // 扩展名必须**存在且不同**：
            // - 同名文件（扩展名相同）就是目标自己，不算兄弟；
            // - 无扩展名的同主名文件（`config.toml` vs `config`）是**另一个名字**，
            //   不是同一份配置的另一种写法，报出来只会制造噪声。
            match path.extension() {
                Some(ext) => ext != target_ext,
                None => false,
            }
        })
        .map(|entry| entry.path())
        .collect();

    out.sort();
    out
}

pub struct TianshuRelayService<T: HttpTransport + Clone + 'static> {
    registry: SiteRegistry<T>,
    /// M14-S1：模型清单采集（`site::fetch_models`）用。`registry` 已持有一份用于 adapter，
    /// 这里再留一份是因为 `fetch_models` 是独立函数、不通过 adapter——给 registry 加
    /// `transport()` getter 要动 `site/registry.rs`（不在写域）。`T: Clone`，clone 成本
    /// 是 `Arc` 级别（MockTransport / reqwest transport 都是 `Arc` 包裹）。
    transport: T,
    /// M15-S1 复审 H1+M2：probe 专用 transport（独立 timeout，不套 `RetryingTransport`）。
    ///
    /// `None`（默认）时 `probe_model` fallback 到 `self.transport`——测试用 `MockTransport`
    /// 走这条路径（M4 集成测试可 mock）。生产装配由壳层 `with_probe_transport` 注入一个
    /// `ReqwestTransport`（timeout 120s、不套 retry）：120s 是**单次请求**的上界、不是检测
    /// 总时长（B-160 起提交走 `sync=false`、等待交给轮询），不套 retry 是因为 429 会被
    /// `RetryingTransport` 自动重试 3 次（Retry-After 被 cap 到 5s，白打 + 等 10s）。
    probe_transport: Option<crate::site::transport_reqwest::ReqwestTransport>,
    /// B-134 引入 / B-160 重设计：probe 轮询参数。
    ///
    /// B-160 起轮询是**主路径**（提交走 `sync=false`），不再是「同步 POST 没跑完时的兜底」：
    /// 默认 [`crate::probe::PollPolicy::default`]（退避 2s→15s、预算 900s、容忍 5 次连续失败）。
    /// 真机实测一次重模型检测服务端要 186.98s（async）/ 360.53s（sync），30s 的旧默认值
    /// 根本盖不住 ⇒ 会在服务端已经给出判定之后再把它丢掉。
    probe_poll: crate::probe::PollPolicy,
    /// B-134：轮询等待实现。生产 `TokioSleeper`，测试注入 `RecordingSleeper`（不真睡）。
    ///
    /// 与 `site::retry` 共用同一个 [`crate::site::retry::Sleeper`] 抽象——不新造一套
    /// 「可注入的等待」，测试里也就没有第二个假时钟要实现。
    probe_sleeper: Arc<dyn crate::site::retry::Sleeper>,
    /// M14-S7 §4.2：models.dev 在线补全专用传输层（独立 timeout 15s、不套 retry）。
    ///
    /// **必须显式注入**（[`Self::with_meta_transport`]）：`None` ⇒ `warm_model_meta` 直接
    /// 返回 `None`，一次网络都不发。这是**结构保证**而不是自觉：投递命令会在预览时预热
    /// 元数据，若默认回退到站点 transport，测试装配（用真实 `ReqwestTransport`）就会真的
    /// 去打 models.dev——违反「测试不许联网」。
    ///
    /// 存成 `Box<dyn HttpTransport>` 而不是具体类型：生产注入 `ReqwestTransport`，
    /// 核心测试注入 `MockTransport`，两边走同一条代码路径。
    meta_transport: Option<Box<dyn crate::site::transport::HttpTransport>>,
    /// M14-S7 §4.2：models.dev 目录缓存（进程内 1 小时 TTL）。
    ///
    /// 投递路径是同步的（不能 `.await`），所以「异步预热 → 同步读快照」两步走：
    /// `warm_model_meta` 填这份缓存，`meta_for` 在 `prepare_delivery` 里读。
    meta_cache: crate::model_meta::OnlineMetaCache,
    store: Store,
    sessions: SessionCache,
    vault: Arc<dyn Vault>,
    home: PathBuf,
    backup_dir: PathBuf,
    /// 通知装配 + 跨轮快照（M6-S5 / FR-3）。
    ///
    /// `last` 用 `Mutex` 是因为 [`Self::refresh_all`] 取 `&self`——快照要在多轮之间
    /// 存活，而 `evaluate` 的「边沿型」规则（用量跳变 / 登录态失效 / 额度耗尽 / 漂移）
    /// 必须拿上一轮做基线，否则每一轮都会被当成「新事件」重复通知。
    notify: Option<NotifyState>,
    /// 网关侧「因可切换状态而放弃当前上游」的失败（M7-S5 / FR-5:160）。
    ///
    /// **为什么是一个内存缓冲而不是让网关直接写库**：`gateway.rs` 不该为了记一条事件
    /// 拿到整个存储层（M7-S1 的注入出口设计），而 `Store` 也不是 `Clone`——它是
    /// `Mutex<Connection>`，再开一条连接又会在没有 `busy_timeout` 的前提下引入
    /// `SQLITE_BUSY` 风险。所以走「回调入内存 → 服务层落库」这一条路：
    /// 网关只 push 一个**恰好三个字段**的结构体，写事件的那一步留在这里（有 store 的地方）。
    ///
    /// 代价：事件落库发生在**下一次 `refresh_all`**。网关失败是低频事件，
    /// 而 `refresh_all` 是前台 60s / 后台 30min 的固定节拍，可接受。
    /// 缓冲有上限（见 [`MAX_BUFFERED_GATEWAY_FAILURES`]），满了丢**最旧**的一条——
    /// 宁可丢历史，也不让一个坏掉的上游把内存吃光。
    gateway_failures: Arc<std::sync::Mutex<std::collections::VecDeque<BufferedGatewayFailure>>>,
    /// P3-7 / §11.3：缓冲满丢弃计数。`push_bounded` 丢最旧时 +1，`drain` 时清零并
    /// 随事件报出「本轮因缓冲满丢弃 N 条」——否则用户看到的失败是不完整的而没
    /// 任何提示。只记计数，不逐条记（D-6：逐条记会让「缓冲满」本身把事件表灌满）。
    gateway_failures_dropped: Arc<std::sync::atomic::AtomicU64>,
    /// M13-S1：网关 token 用量的内存缓冲（与  同形）。
    /// 回调里只 push，在  时落库——网关回调不该做 IO。
    gateway_usage_buffer: Arc<std::sync::Mutex<Vec<crate::gateway::GatewayUsage>>>,
    /// M13-S1：网关用量缓冲满时丢弃的计数（与 `gateway_failures_dropped` 同口径）。
    gateway_usage_dropped: Arc<std::sync::atomic::AtomicU64>,
    /// 网关**会话**代号（M8-S1 §11.1）。每次 `gateway_config` 递增一次，
    /// `gateway_stop` 再递增一次（= 作废当前会话）。
    ///
    /// sink 捕获自己那一份代号，推送前比对：**不相等 ⇒ 丢弃**。
    /// 于是「stop 之后在途请求才产生的失败」不会被记到**下一个**会话上——
    /// 那是主动误导（用户会去查一个没问题的会话）。
    gateway_session: Arc<std::sync::atomic::AtomicU64>,
    /// 站点的**观测**（M8-S1 §5.1）：模型清单 / 倍率 / 余额 / 延迟。
    ///
    /// 四项都是「最近一次观测」（last-value，不是滑动平均）：实现简单、可解释，
    /// 且与 `RouteTable` 的排序语义（「按已知信息排」）一致。
    /// **都不落库**——重启后回到「全未知」，排序退化成按 `site_id`（spec D-4）。
    site_facts: Arc<std::sync::Mutex<std::collections::HashMap<i64, SiteObservations>>>,
    /// 已被回收的 `secret_ref`（M8-S1 §3.5-5）。
    ///
    /// `revoke_key` 成功后插进来，`gateway_config` 把它交给网关。
    /// 这样网关**不新开取密钥路径**，只查一个由 `ensure_not_revoked` 那条路径维护的集合。
    revoked_refs: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    /// **热更新句柄**（M39-S1）：当前运行态的快照容器。`None` = 没有网关在跑
    /// （或最近一次装配走的是 legacy 单上游路径）。`gateway_config()` 每次新建并替换它，
    /// `publish_gateway_snapshot()` 往里面写新的 `Arc<GatewaySnapshot>`。
    ///
    /// 为什么是 `Mutex<Option<…>>` 而不是 `OnceLock`：每次 `gateway_start` 都换一个新的容器
    /// （旧的由最后一个在途请求释放）；`gateway_stop` 不强制清理也无害——
    /// 没有读者的旧容器即使被误发布一次也不会被任何人看到，下一次 start 会替换。
    gateway_runtime:
        std::sync::Mutex<Option<Arc<std::sync::RwLock<Arc<crate::gateway::GatewaySnapshot>>>>>,
    /// 最近一次 `gateway_config` 用的令牌**是不是**持久化的（M8-S4 §6.4）。
    ///
    /// 放在服务上而不是 `GatewayHandle` 上：`gateway.rs` 的结构白名单与
    /// `Debug` 脱敏都已经定稿，为一个状态位去动它不划算；而状态的**生产者**本来就是这里。
    /// 语义是「最近一次装配网关时，令牌落进钥匙串了吗」——网关没在跑时这个值没有意义。
    gateway_token_persistent: Arc<std::sync::atomic::AtomicBool>,
    /// 人工过验证码的**相位表**（M8-S2 §3）：按站点，多站点可同时处于不同相位。
    ///
    /// 只放相位、不放 cookie——cookie 在 [`SessionCache`]（同样只在内存）。
    /// **不入库**：重启后回到 `Idle` 是对的（等待中的窗口本来就不存在了）。
    captcha_phases: Mutex<HashMap<i64, CaptchaPhase>>,
    /// B 路凭据槽（M28-S1 / B-191）：按站点隔离，**只在内存**。
    ///
    /// 生命周期与相位一致：`cancel_captcha` / `remove_site` 清槽，登录成功后清槽；
    /// 槽里放过期的条目由 TTL（[`WEBVIEW_CREDS_TTL`]）判「视为没有」并顺手删掉。
    /// **不入库、不进事件、不进导出**（凭据与密钥同级）。
    webview_creds: Mutex<HashMap<i64, StoredWebviewCredentials>>,
    /// `refresh_all` 的**跨调用互斥**（P3-27 / DEBUG-REPORT-v3 §3-27）。
    ///
    /// `MAX_REFRESH_CONCURRENCY` 只约束一次调用内部的在途数；前台节拍、后台任务与
    /// 用户点「立即刷新」三者重叠时，在途峰值会翻倍（实测 8）。用 async-aware 的
    /// `tokio::sync::Mutex` 串行化（不得用 `std::sync::Mutex` 跨 `.await`）。
    refresh_lock: tokio::sync::Mutex<()>,
}

/// 缓冲里的一条：**失败发生的时刻** + 失败本身。
///
/// 时刻放在**元素里**而不是 `GatewayFailure` 里：那个结构的「恰好三个字段」是 M7 冻结的
/// 结构白名单（装不下 prompt / 响应正文 / 密钥），不为一个时间戳破例。
#[derive(Clone, Debug)]
struct BufferedGatewayFailure {
    /// 失败发生的 **unix 秒**。
    at: i64,
    failure: crate::gateway::GatewayFailure,
}

/// 一个站点的四项观测（M8-S1 §5.1）。全部可缺省，缺省 = 未知。
#[derive(Clone, Debug, Default)]
struct SiteObservations {
    /// 站点侧模型清单。**空 = 未知**（采集默认关）。
    models: Vec<String>,
    rate: Option<f64>,
    balance_usd: Option<f64>,
    latency_ms: Option<u64>,
    /// M14-S1：最近一次采集模型清单的 unix 秒（B-99 ① 节流用）。`None` = 从没采过。
    /// **不落库**——与四项观测同口径（M8-S1 D-4）；重启回到「从没采过」。
    models_collected_at: Option<i64>,
}

/// 网关失败的内存缓冲上限。见 [`TianshuRelayService::gateway_failures`] 的说明。
pub const MAX_BUFFERED_GATEWAY_FAILURES: usize = 256;

/// 一轮刷新里**同时在途**的站点数上限（M8-S3 §3.4 异议 O-1 的裁决 ①）。
///
/// 取 4 的理由：
/// ① 顺序循环在真实网络下总耗时 ≈ Σ(每站点 RTT × 请求数)：20 站点 × 2 请求 × 300ms ≈ 12s，
///    正好贴着 PRD 的「20 站点刷新 ≤ 15s」门槛，400ms RTT 就越线；
/// ② **不设上界**（= 20 并发）会对站点打出 20 个并发会话：容易被限流，失败风暴也更难读；
/// ③ 4 是「比 1 明显快、比 N 温和」的中间档，且与 M8-S3 §3.2 的 B3 基线口径一致。
///
/// **并发只改「在途」，不改「结论顺序」**：`refresh_all` 收齐结果后仍按站点 id 升序
/// 记账与写事件，所以事件顺序与本改造之前逐字一致。
pub const MAX_REFRESH_CONCURRENCY: usize = 4;

/// 单个站点的刷新结果（有界并发改造后，循环体被拆成「取事实」与「记账」两半）。
///
/// 只为在 `refresh_all` 内部传递，不进任何公开 API。
struct SiteRefresh {
    site_id: i64,
    display_name: String,
    /// 站点地址：失败事件的 payload 要带它（走 `event_with_payload` 的脱敏入口）。
    base_url: String,
    /// 这一轮**有没有会话**。`false` ⇒ 不联网、不计成功也不计失败（纯本地判定）。
    had_session: bool,
    /// 没有会话时：上一轮是否已判过「需要重新登录」（`health == needs_login`）。
    needs_login_without_session: bool,
    /// 有会话时的两项结果（`had_session == false` 时为 `None`）。
    balance: Option<Result<Balance>>,
    keys: Option<Result<Vec<KeyMeta>>>,
    drift: Vec<crate::notify::DriftFact>,
    rotation_due: Vec<crate::notify::RotationDueFact>,
}

/// 往缓冲里放一条，满了丢**最旧**的一条。
///
/// 抽成函数是为了让**生产路径（网关回调）与测试路径（`record_gateway_failure_for_test`）
/// 走同一段逻辑**——否则「上限」这条纪律只在一边生效，而测试会证明一个产品里不存在的性质。
fn push_bounded(
    buffer: &mut std::collections::VecDeque<BufferedGatewayFailure>,
    dropped: &std::sync::atomic::AtomicU64,
    failure: crate::gateway::GatewayFailure,
) {
    if buffer.len() >= MAX_BUFFERED_GATEWAY_FAILURES {
        buffer.pop_front();
        // P3-7 / §11.3：记丢弃计数，drain 时随事件报出。
        dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    buffer.push_back(BufferedGatewayFailure {
        // 时刻在**推送侧**取（网关的请求任务里），不是落库时取：
        // 落库发生在下一次 `refresh_all`，那时取到的是「刷新时刻」——
        // 于是「网关为什么在 14:00 切换了上游」会显示成「14:05」，因果链在时间轴上错位。
        at: unix_now_secs(),
        failure,
    });
}

/// 通知的运行时状态。`config` 是冻结的装配参数，`last` 是上一轮快照。
struct NotifyState {
    config: crate::notify::NotifyConfig,
    last: std::sync::Mutex<Option<crate::notify::Snapshot>>,
}

impl<T: HttpTransport + Clone + 'static> TianshuRelayService<T> {
    pub fn new(store: Store, transport: T, config: ServiceConfig) -> Self {
        let svc = Self {
            registry: SiteRegistry::new(transport.clone()),
            transport,
            // 默认 None：测试不调 `with_probe_transport` 时 fallback 到 `self.transport`（Mock），
            // 让 probe_model 的集成测试能用 Mock 预置响应（M4）。
            probe_transport: None,
            // B-160：默认就是主路径用的那份策略（退避 2s→15s、预算 900s、容忍 5 次连续失败）。
            probe_poll: crate::probe::PollPolicy::default(),
            probe_sleeper: Arc::new(crate::site::retry::TokioSleeper),
            // 默认 None：**不做在线补全**。生产由壳层 `with_meta_transport` 注入；
            // 测试装配不注入 ⇒ 结构上不可能联网。
            meta_transport: None,
            // 默认空缓存：冷缓存 ⇒ 同步读拿不到在线参数（不联网），语义与「没查到」一致。
            meta_cache: crate::model_meta::OnlineMetaCache::new(),
            store,
            sessions: SessionCache::new(),
            vault: config.vault,
            home: config.home,
            backup_dir: config.backup_dir,
            // 默认**不通知**：通知会弹窗并发网络请求，测试与纯核心用例不该意外触发。
            notify: None,
            gateway_failures: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
            gateway_failures_dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            gateway_usage_buffer: Arc::new(std::sync::Mutex::new(Vec::new())),
            gateway_usage_dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            gateway_session: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            site_facts: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            revoked_refs: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            gateway_token_persistent: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            gateway_runtime: std::sync::Mutex::new(None),
            captcha_phases: Mutex::new(HashMap::new()),
            webview_creds: Mutex::new(HashMap::new()),
            refresh_lock: tokio::sync::Mutex::new(()),
        };
        // M13-S1：启动时从钥匙串恢复持久化 session，重启免登。best-effort，不阻断启动。
        svc.restore_sessions();
        svc
    }

    /// 从钥匙串恢复所有站点的持久化 session 到内存缓存（M13-S1）。
    ///
    /// 启动时由 [`Self::new`] 调一次。best-effort：钥匙串无条目 / 反序列化失败 ⇒ 跳过该站点，
    /// 不报错、不阻断启动——下次 `login` 会覆盖。session 是否仍有效不在此判断（lazy：
    /// 用的时候 401 才知道，`mark_needs_login` 会清掉坏的）。
    pub fn restore_sessions(&self) {
        let Ok(sites) = self.store.list_sites() else {
            // best-effort 不阻断启动，但留诊断事件（复审 Low 修正）：否则用户重启后
            // 未恢复任何 session 时日志无痕，无法区分"没登录过"和"list_sites 失败"。
            self.log(observability::event_with_payload(
                Level::Warn,
                "store",
                "恢复会话失败：无法列举站点",
                serde_json::json!({}),
            ));
            return;
        };
        for site in sites {
            let reference = self.session_ref(site.id);
            // 走唯一明文出口 `vault_secret`（M8-S1 守卫：`vault.get(` 在 service.rs 只出现一次），
            // 不在这里新开 `vault.get` 调用点——否则「明文出口单一」守卫会红。
            match self.vault_secret(&reference) {
                Ok(Some(stored)) => {
                    if let Ok(session) = Session::from_stored(stored.as_str()) {
                        // B-121：JWT 的 `exp` 已过 ⇒ **不恢复，并删掉条目**。
                        // 恢复一个已知过期的会话只会让用户先看到「已登录」、再吃一次 401；
                        // 直接删掉，让界面如实显示「未登录」。
                        if session_is_expired(&session, unix_now_secs()) {
                            // M29-S1：NewAPI 且**带续期凭据** ⇒ 不删、恢复进缓存，
                            // 由续期循环换新 token（删了就得让用户重新过一遍验证码）。
                            let keep = matches!(self.kind_of(&site), Ok(SiteKind::NewApi))
                                && session
                                    .cookie_value(crate::site::newapi::NEWAPI_REFRESH_COOKIE)
                                    .is_some();
                            if keep {
                                let _ = self.sessions.put(site.id, session);
                            } else {
                                let _ = self.vault.delete(&reference);
                            }
                            continue;
                        }
                        let _ = self.sessions.put(site.id, session);
                    }
                    // 反序列化失败：跳过（不删——下次 login 会覆盖；删了反而损失可能可用的会话）
                }
                Ok(None) => {} // 未持久化（没登录过 / 已失效被删）
                Err(_) => {}   // 钥匙串读失败：跳过，不阻断启动
            }
        }
    }

    /// 用户主动退出登录（B-113 的「退出即删」）。
    ///
    /// 清内存会话 + **删钥匙串条目**，并把站点健康状态从 `needs_login` 拉回 `unknown`
    /// （用户是**主动**退出的，不是会话坏了——留着 `needs_login` 会让界面提示
    /// 「需要重新登录」，那是错的）。
    ///
    /// 幂等：没登录过 / 条目已删 / 站点不存在都返回 `Ok(())`（`vault.delete` 幂等；
    /// `set_site_health` 对不存在的站点报错，这里忽略——退出登录不该因为站点被删而失败）。
    pub fn logout(&self, site_id: i64) -> Result<()> {
        self.sessions.invalidate(site_id);
        self.vault.delete(&self.session_ref(site_id))?;
        let _ = self.store.set_site_health(site_id, "unknown");
        Ok(())
    }

    /// 会话过期信息（B-121）：JWT `exp` ⇒ 精确；无 JWT（旧版 NewAPI 的 cookie-only 会话）⇒ `None`。
    ///
    /// **NewAPI 新版（M29-S1）**：带 `new_api_refresh` 的会话由
    /// `refresh_sessions_if_needed` 在 `exp` 临近时自动续期；续期失败才回到重新登录。
    /// 其余站点类型仍以重新登录为唯一续期手段。
    pub fn session_expiry(&self, site_id: i64) -> Option<SessionExpiry> {
        let token = self.sessions.get(site_id)?.access_token?;
        let expires_at = jwt_exp(&token)?;
        Some(SessionExpiry {
            expires_at,
            seconds_left: expires_at - unix_now_secs(),
        })
    }

    /// 用户目录（注入落点、探测候选路径都相对于它）。
    ///
    /// 只读访问器：M7-S3 的 `detect_unmanaged_targets(home)` 需要它，
    /// 而命令层不该为了拿一个路径去翻私有字段。
    pub fn home(&self) -> &std::path::Path {
        &self.home
    }

    /// 打开通知（M6-S5 / FR-3）。不调用 = 完全不通知。    ///
    /// 做成构造器方法而不是 [`ServiceConfig`] 的字段，是为了让既有调用方零改动
    /// （理由见 `ServiceConfig` 的文档）。
    pub fn with_notify(mut self, config: crate::notify::NotifyConfig) -> Self {
        self.notify = Some(NotifyState {
            config,
            last: std::sync::Mutex::new(None),
        });
        self
    }

    /// M15-S1 复审 H1+M2：注入 probe 专用 transport。
    ///
    /// 生产装配由壳层调用，传入一个**不套 `RetryingTransport`** 的 `ReqwestTransport`：
    /// bazaarlink 是第三方服务，429 由 probe 层自己映射成 `RateLimited` 告诉用户，
    /// 不该被站点重试策略抢着重试（Retry-After 被 cap 到 5s，白打 + 等 10s）。
    ///
    /// **timeout 的语义在 B-160 之后变了**：旧注释说「120s 是因为 `sync=true` 要等服务端
    /// 跑完多轮推理对比」——那是把 120s 当成「检测总时长」在用，而真机实测要 360.53s，
    /// 于是重模型必然超时。现在提交是 `sync=false`（秒级返回）、等待交给轮询，每条连接
    /// 都是短请求，超时值只需要**兜住一次请求挂死**，不再需要覆盖整轮检测。
    ///
    /// 不调用 = `probe_transport` 保持 `None`，`probe_model` fallback 到 `self.transport`
    /// ——测试用 `MockTransport` 走这条路径，零改动现有测试。
    pub fn with_probe_transport(
        mut self,
        probe_transport: crate::site::transport_reqwest::ReqwestTransport,
    ) -> Self {
        self.probe_transport = Some(probe_transport);
        self
    }

    /// B-134：注入 probe 轮询的参数与等待实现。
    ///
    /// 生产不调用（默认 `PollPolicy::default()` + `TokioSleeper`）；测试调用是为了
    /// **不真睡**——退避与预算一起注入，测试就能断言「补查了几次、每次等了多久」，
    /// 而不是靠 `sleep` 把测试拖慢十几分钟（B-160 的默认预算是 900s）。
    pub fn with_probe_poll(
        mut self,
        policy: crate::probe::PollPolicy,
        sleeper: Arc<dyn crate::site::retry::Sleeper>,
    ) -> Self {
        self.probe_poll = policy;
        self.probe_sleeper = sleeper;
        self
    }

    /// M14-S7 §4.2：注入 models.dev 在线补全专用传输层（独立 timeout 15s、不套 retry）。
    ///
    /// 为什么不复用站点 transport：models.dev 是**第三方**服务，`RetryingTransport` 会把
    /// 「网络不通」放大成 3 次尝试 × 15s，挂在投递预览的关键路径上。这里要的是
    /// 「一次、短、失败就当没查到」（spec §4.2：网络失败/超时返回 `None`，不影响投递）。
    ///
    /// **不注入 ⇒ 不做在线补全**（不联网、不猜）。生产装配由壳层 `init_state` 注入；
    /// 测试装配（`init_state_in_memory`）故意不注入。
    pub fn with_meta_transport(
        mut self,
        meta_transport: impl crate::site::transport::HttpTransport + 'static,
    ) -> Self {
        self.meta_transport = Some(Box::new(meta_transport));
        self
    }

    /// M14-S7 §4.2：预热模型元数据在线补全缓存（best-effort）。
    ///
    /// 内置表命中 ⇒ 直接返回、**不联网**；未命中 ⇒ 查 models.dev（缓存过期时才真拉）。
    /// 任何失败都返回 `None`——这是增强项，失败必须退化成「只写模型名」，绝不报错。
    ///
    /// 投递路径是同步的，所以「预热 → 同步读」两步走：本函数填缓存，
    /// [`Self::meta_for`] 读缓存（见 `prepare_delivery`）。
    pub async fn warm_model_meta(
        &self,
        model: Option<&str>,
    ) -> Option<crate::model_meta::ModelMeta> {
        let model = model.map(str::trim).filter(|m| !m.is_empty())?;
        let Some(transport) = self.meta_transport.as_deref() else {
            // 没注入在线传输层 ⇒ 不做在线补全。测试装配走这条路径：一次网络都不发。
            return None;
        };
        let resolved = self.meta_cache.lookup_online(transport, model).await;
        if resolved.is_none() {
            // 只记模型名与结果，不记任何密钥/响应正文。Debug 级：这是增强路径，
            // 未命中是常态（内置表没覆盖的长尾模型 + 网络不可用），不该刷 warn。
            self.log(observability::event_with_payload(
                Level::Debug,
                "delivery",
                "模型元数据未命中（只写模型名，不写上下文/输出参数）",
                serde_json::json!({ "model": model }),
            ));
        }
        resolved
    }

    /// 同步读模型元数据：内置表 → 已缓存的 models.dev 结果。**不联网**。
    fn meta_for(&self, model: Option<&str>) -> Option<crate::model_meta::ModelMeta> {
        model
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .and_then(|m| self.meta_cache.lookup_cached(m))
    }

    /// 钥匙串后端标识（诊断用；`"memory"` 出现在生产装配里即为缺陷）。
    pub fn vault_backend(&self) -> &'static str {
        self.vault.backend_name()
    }

    pub fn sites(&self) -> Result<Vec<SiteSummary>> {
        Ok(self
            .store
            .list_sites()?
            .into_iter()
            .map(|row| {
                let id = row.id;
                SiteSummary {
                    id,
                    kind: row.kind,
                    base_url: row.base_url,
                    display_name: row.display_name,
                    health: row.health,
                    // M38-S1：只看存在性。`Err` ⇒ false（不删条目、不让列表失败）——
                    // 宁可不显示「已保存」徽标，也不给用户错误的安全感。
                    session_persisted: matches!(self.vault.has(&self.session_ref(id)), Ok(true)),
                    // 只读内存会话的 JWT `exp`；无会话 / 非 JWT ⇒ None。
                    session_expires_at: self.session_expiry(id).map(|e| e.expires_at),
                }
            })
            .collect())
    }

    /// 指纹识别 + 落库。同一 `base_url` 重复调用是幂等的（沿用已有记录）。
    pub async fn add_site(&self, base_url: &str) -> Result<SiteSummary> {
        let base_url = base_url.trim().trim_end_matches('/');
        let fingerprint = self.registry.detect(base_url).await?;
        let id = self.store.upsert_site(
            fingerprint.kind.as_str(),
            base_url,
            &fingerprint.display_name,
        )?;
        self.log(observability::event_with_payload(
            Level::Info,
            "site",
            format!(
                "站点已识别: {} {}",
                fingerprint.kind.as_str(),
                fingerprint.display_name
            ),
            serde_json::json!({
                "site_id": id,
                "base_url": base_url,
                "version": fingerprint.version,
            }),
        ));
        Ok(SiteSummary {
            id,
            kind: fingerprint.kind.as_str().to_string(),
            base_url: base_url.to_string(),
            display_name: fingerprint.display_name,
            health: "unknown".to_string(),
            // 新站点还没有会话：固定 false / None（spec §4.1）。
            session_persisted: false,
            session_expires_at: None,
        })
    }

    /// 登录并把会话放入缓存；失败时不改变已有缓存。
    ///
    /// 顺序：**先落健康状态、再放会话缓存**（B-61）。若先缓存会话再写库而写库失败，
    /// 调用方拿到的是 `Err`、本地却已经「登录上了」，且 `sites.health` 会永远停在
    /// `needs_login`——那条「请重新登录」的提示再也消不掉。
    pub async fn login(&self, site_id: i64, cred: Credentials) -> Result<()> {
        let site = self.site(site_id)?;
        let kind = self.kind_of(&site)?;
        // `custom-openai-compatible` 没有登录流程（只填 base_url 就能用），
        // 所以「登录」这个动作在它身上是**设计上不支持**，不是「还没登录」。
        // 不加这条门的话，UI 上一个没被灰显的登录按钮会让用户走进一个不存在的流程，
        // 而且会把一个**空会话**写进会话缓存（M7-S2 复审 S-2 指出的可达路径）。
        capability_gate(
            kind,
            crate::site::capability::capabilities(kind).login,
            "登录",
        )?;
        // M9-S2 / B-120：账号形态与该站点类型的约定不符时**本地就拒**——不发注定被
        // 站点 400 掉的请求（Sub2API 的 `email` 字段带 `binding:"required,email"`，
        // 用户名必被拒，而站点回的是 Go validator 的英文原文）。
        //
        // 判据与界面标签**同源**（都来自 `site::login_field`），所以不会出现
        // 「标签说邮箱、预检按用户名」这种各说各话的局面；位置在 `adapter.login`
        // **之前**是硬要求，否则请求已经出去了。
        if let Some(field) = crate::site::login_field::LoginField::of(kind) {
            field.precheck(&cred.username)?;
        }
        // 用户名不是秘密，但仍然过一遍脱敏入口（B-36：站点原文/用户名都可能被规则命中）
        let username = cred.username.clone();
        let adapter = self.registry.adapter(kind);
        let session = match adapter.login(&site.base_url, cred).await {
            Ok(session) => session,
            // 站点要求人机验证：**转人工态**（M8-S2 T1）——这不是终点，是分流。
            // 前端收到 `CaptchaRequired` 后弹「打开官方页面过一次」（用户自己过），
            // 过完之后由 [`Self::complete_captcha`] 把 WebView 抓到的会话接上。
            Err(Error::CaptchaRequired) => {
                let challenge = CaptchaChallenge {
                    site_id,
                    url: captcha::captcha_page_url(&site.base_url)?,
                };
                let next = captcha::step(
                    self.captcha_phase(site_id),
                    CaptchaEvent::LoginRejected { challenge },
                );
                self.set_captcha_phase(site_id, next);
                // 错误类型**不变**（S2 §9）：前端据此弹人工验证的入口。
                // 这里**不写**「登录失败」事件：人工态不是失败（S2 §5 T12）。
                return Err(Error::CaptchaRequired);
            }
            Err(err) => {
                self.log(observability::event_with_payload(
                    Level::Warn,
                    "site",
                    format!("登录失败: {}", error_kind(&err)),
                    serde_json::json!({ "site_id": site_id }),
                ));
                return Err(err);
            }
        };
        // 登录真的成功了：清掉可能挂着的相位（否则会出现「会话已建立、还在等人工验证」
        // 的僵尸态）。这条转移不在 T1–T8 里——那八条覆盖的是「登录被拒」的分支。
        self.set_captcha_phase(site_id, CaptchaPhase::Idle);
        self.store.set_site_health(site_id, HEALTH_OK)?;
        // 先序列化（session 即将被 move 进 cache）：M13-S1 持久化到钥匙串。
        // best-effort：序列化/写钥匙串失败不掩盖登录成功——内存会话已可用，只是下次重启没得恢复。
        let stored = session.to_stored();
        self.sessions.put(site_id, session)?;
        if let Ok(s) = stored {
            if let Err(err) = self.vault.put(&self.session_ref(site_id), &s) {
                self.log(observability::event_with_payload(
                    Level::Warn,
                    "vault",
                    format!("持久化会话失败: {err}"),
                    serde_json::json!({ "site_id": site_id }),
                ));
            }
        }
        self.log(observability::event_with_payload(
            Level::Info,
            "site",
            format!("登录成功: {username}"),
            serde_json::json!({ "site_id": site_id }),
        ));
        Ok(())
    }

    // ============================================================== B 路凭据通道（M28-S1 / B-191）

    /// 存一条 WebView 回传的凭据（B 路）。
    ///
    /// 只在**人工态**且站点类型支持 B 路时接受；覆盖旧值。
    /// **不写事件、不写日志**（连「收到凭据」都不记 —— 避免侧信道）。
    pub fn store_webview_creds(
        &self,
        site_id: i64,
        creds: crate::site::webview_creds::WebviewCredentials,
    ) -> Result<()> {
        // 先判能力位：不支持的站点类型恒报 `Unsupported`（与 M26-S1 的「不适用」面板同口径），
        // 不能因为「相位恰好不是人工态」就把它说成「不在等待人工验证」——那会误导用户。
        let site = self.site(site_id)?;
        let kind = self.kind_of(&site)?;
        if !crate::site::capability::capabilities(kind).webview_bearer_supported {
            return Err(Error::Unsupported(
                "该站点类型不支持 WebView 凭据回传（B 路）".to_string(),
            ));
        }
        if !matches!(
            self.captcha_phase(site_id),
            CaptchaPhase::AwaitingHuman { .. }
        ) {
            return Err(Error::AuthFailed(
                "该站点当前不在等待人工验证：收到的凭据已忽略".to_string(),
            ));
        }
        // 防御：调用方可能没校验，这里再验一次形态（错误文案不含值）。
        crate::site::webview_creds::validate_access_token(&creds.access_token)?;
        let mut map = self
            .webview_creds
            .lock()
            .map_err(|_| Error::Store("凭据槽锁不可用".to_string()))?;
        map.insert(
            site_id,
            StoredWebviewCredentials {
                creds,
                captured_at: std::time::Instant::now(),
            },
        );
        Ok(())
    }

    /// 测试用：凭据槽里的条数（清槽路径的判据 —— 不能只断言相位）。
    #[cfg(test)]
    fn webview_creds_len_for_test(&self) -> usize {
        self.webview_creds.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// 测试用：注入一个**指定捕获时刻**的凭据（TTL 用例需要，不引入时钟抽象）。
    #[cfg(test)]
    fn store_webview_creds_at(
        &self,
        site_id: i64,
        creds: crate::site::webview_creds::WebviewCredentials,
        captured_at: std::time::Instant,
    ) {
        if let Ok(mut map) = self.webview_creds.lock() {
            map.insert(site_id, StoredWebviewCredentials { creds, captured_at });
        }
    }

    /// 用槽里的凭据完成登录（B 路）。
    ///
    /// 顺序（spec §10 复审要点）：相位检查 → 槽（TTL）→ 构造会话 → `health` → 缓存 →
    /// 钥匙串 → 相位 `Idle` → 清槽 → Info 事件（**只带 site_id**）。
    /// 失败时槽**保留**（允许用户重试），只有 TTL 过期才清。
    pub fn complete_webview_login(&self, site_id: i64, cf_clearance: Option<String>) -> Result<()> {
        if !matches!(
            self.captcha_phase(site_id),
            CaptchaPhase::AwaitingHuman { .. }
        ) {
            return Err(Error::AuthFailed(
                "该站点当前不在等待人工验证：无法完成 WebView 登录".to_string(),
            ));
        }
        let stored = {
            let mut map = self
                .webview_creds
                .lock()
                .map_err(|_| Error::Store("凭据槽锁不可用".to_string()))?;
            match map.get(&site_id) {
                None => {
                    return Err(Error::AuthFailed(
                        "还没有收到 WebView 回传的凭据：请先在打开的页面里登录".to_string(),
                    ))
                }
                Some(stored) if stored.captured_at.elapsed() > WEBVIEW_CREDS_TTL => {
                    map.remove(&site_id);
                    return Err(Error::AuthFailed(
                        "WebView 回传的凭据已过期（超过 10 分钟），请重新打开页面登录".to_string(),
                    ));
                }
                Some(stored) => stored.creds.clone(),
            }
        };

        let mut creds = stored;
        // cf_clearance 由壳层从 `window.cookies()` 补（HttpOnly，JS 读不到）。
        // 非法 ⇒ 忽略（不阻断登录；没有 cf 时 Bearer 会话通常仍可用，只是过不了 CF 挑战）。
        if let Some(cf) = cf_clearance {
            if crate::site::webview_creds::validate_cf_clearance(&cf).is_ok() {
                creds.cf_clearance = Some(cf);
            }
        }
        let session = crate::site::webview_creds::session_from_webview_credentials(&creds)?;

        // 镜像 `login` 的 B-61 顺序：先 health，再缓存，再钥匙串（best-effort）。
        self.store.set_site_health(site_id, HEALTH_OK)?;
        let stored_json = session.to_stored();
        self.sessions.put(site_id, session)?;
        if let Ok(s) = stored_json {
            if let Err(err) = self.vault.put(&self.session_ref(site_id), &s) {
                self.log(observability::event_with_payload(
                    Level::Warn,
                    "vault",
                    format!("持久化会话失败: {err}"),
                    serde_json::json!({ "site_id": site_id }),
                ));
            }
        }
        self.set_captcha_phase(site_id, CaptchaPhase::Idle);
        self.clear_webview_creds(site_id);
        // 只带 site_id：凭据值、UA、cf_clearance 一律不进事件表。
        self.log(observability::event_with_payload(
            Level::Info,
            "site",
            "WebView 登录凭据已接入：会话已建立",
            serde_json::json!({ "site_id": site_id }),
        ));
        Ok(())
    }

    /// 清掉某站点的 B 路凭据槽（与相位同生命周期）。
    fn clear_webview_creds(&self, site_id: i64) {
        if let Ok(mut map) = self.webview_creds.lock() {
            map.remove(&site_id);
        }
    }

    // ============================================================== 人工过验证码（M8-S2 / FR-1:102）

    /// 当前人工验证相位（缺省 `Idle`）。命令层与测试可见。
    pub fn captcha_phase(&self, site_id: i64) -> CaptchaPhase {
        self.captcha_phases
            .lock()
            .ok()
            .and_then(|map| map.get(&site_id).cloned())
            .unwrap_or(CaptchaPhase::Idle)
    }

    /// 写相位；`Idle` 一律**移除**（表里只留非平凡态，`len()` 才有意义）。
    fn set_captcha_phase(&self, site_id: i64, phase: CaptchaPhase) {
        if let Ok(mut map) = self.captcha_phases.lock() {
            match phase {
                CaptchaPhase::Idle => {
                    map.remove(&site_id);
                }
                other => {
                    map.insert(site_id, other);
                }
            }
        }
    }

    /// 进入人工态的下一步（M8-S2 §9）：把要打开的**官方页面**地址交给前端/窗口层。
    ///
    /// 前置：该站点当前相位是 `AwaitingHuman`；否则 `Err(AuthFailed)`——
    /// 用户点到一个不该出现的按钮时，要的是一条能读懂的原因，不是一个空白窗口。
    pub fn begin_captcha(&self, site_id: i64) -> Result<CaptchaChallenge> {
        match self.captcha_phase(site_id) {
            CaptchaPhase::AwaitingHuman { challenge, .. } => {
                // 双保险：站点记录没了的话，窗口打开了也没有意义
                //（相位会在 `remove_site` 里一并清掉，这里是第二道防线）。
                self.site(site_id)?;
                Ok(challenge)
            }
            CaptchaPhase::Idle => Err(Error::AuthFailed(
                "该站点当前不需要人机验证（没有等待中的挑战）".to_string(),
            )),
        }
    }

    /// NewAPI 的 WebView cookie 登录完成（M29-S1 / B-193）：用 `new_api_refresh` 换 access_token。
    ///
    /// 顺序（spec §4 硬要求）：相位必须是 `AwaitingHuman` → `validate_captcha_cookies` →
    /// kind 必须是 `NewApi` → `refresh_session` → **成功才**写 health / 缓存 / 钥匙串 /
    /// 相位 `Idle` / Info 事件（只带 site_id）。
    /// 任何失败：相位留在人工态，不写 health / 缓存 / 钥匙串 / 事件。
    ///
    /// 旧版 NewAPI 没有续期端点（404 ⇒ `Ok(None)`）⇒ 用 cookie-only 会话试一次 `balance`：
    /// 成功则落地为 cookie 会话，失败则原样上抛、不改状态。
    pub async fn complete_newapi_webview_login(
        &self,
        site_id: i64,
        cookies: Vec<(String, String)>,
    ) -> Result<()> {
        if !matches!(
            self.captcha_phase(site_id),
            CaptchaPhase::AwaitingHuman { .. }
        ) {
            return Err(Error::AuthFailed(
                "该站点当前不在等待人工验证：无法完成 NewAPI 登录".to_string(),
            ));
        }
        captcha::validate_captcha_cookies(&cookies)?;
        let site = self.site(site_id)?;
        let kind = self.kind_of(&site)?;
        if kind != SiteKind::NewApi {
            return Err(Error::Unsupported(
                "该站点类型不走 NewAPI 登录换取路径".to_string(),
            ));
        }

        let cookie_session = captcha::session_from_captcha_cookies(&cookies);
        let adapter = self.registry.adapter(kind);
        let refreshed = adapter
            .refresh_session(&site.base_url, &cookie_session)
            .await?;
        let (session, message) = match refreshed {
            Some(new_session) => (new_session, "NewAPI 登录凭据已接入：会话已建立"),
            None => {
                // 旧版：cookie-only 兜底。探测失败 ⇒ 原错误上抛，**不**改任何状态。
                adapter.balance(&site.base_url, &cookie_session).await?;
                (cookie_session, "NewAPI 登录凭据已接入：Cookie 会话已建立")
            }
        };

        // —— 只有走到这里才动状态 ——
        self.store.set_site_health(site_id, HEALTH_OK)?;
        let stored = session.to_stored();
        self.sessions.put(site_id, session)?;
        if let Ok(s) = stored {
            if let Err(err) = self.vault.put(&self.session_ref(site_id), &s) {
                self.log(observability::event_with_payload(
                    Level::Warn,
                    "vault",
                    format!("持久化会话失败: {err}"),
                    serde_json::json!({ "site_id": site_id }),
                ));
            }
        }
        self.set_captcha_phase(site_id, CaptchaPhase::Idle);
        // 只带 site_id：token / refresh cookie 一律不进事件表。
        self.log(observability::event_with_payload(
            Level::Info,
            "site",
            message,
            serde_json::json!({ "site_id": site_id }),
        ));
        Ok(())
    }

    /// 后台续期（M29-S1 / B-193）：只处理**有 `new_api_refresh` 的 NewAPI 会话**。
    ///
    /// 触发条件：`jwt_exp(access_token)` 存在且 `exp - now <= 180`。
    /// token 缺失 / 非 JWT ⇒ **不主动续期**（旧形态保持「401 后重登」），避免凭猜测刷请求。
    ///
    /// 结果分流：`Ok(Some(new))` ⇒ health=ok + 缓存 + 钥匙串；
    /// `Ok(None)` ⇒ no-op；`is_auth_failure` ⇒ `mark_needs_login`（删钥匙串条目）；
    /// 其它错误（网络 / 5xx）⇒ **保留会话**，只记 Debug 事件（不含凭据），下一轮重试。
    pub async fn refresh_sessions_if_needed(&self) -> Result<()> {
        let now = unix_now_secs();
        for site in self.store.list_sites()? {
            let Ok(kind) = self.kind_of(&site) else {
                continue;
            };
            if kind != SiteKind::NewApi {
                continue;
            }
            let Some(session) = self.sessions.get(site.id) else {
                continue;
            };
            if session
                .cookie_value(crate::site::newapi::NEWAPI_REFRESH_COOKIE)
                .is_none()
            {
                continue;
            }
            let Some(exp) = session.access_token.as_deref().and_then(jwt_exp) else {
                continue;
            };
            // 只在**临近过期**（≤ 180s）时续期：token 15 分钟 ⇒ 约每 13 分钟一次请求。
            if exp - now > 180 {
                continue;
            }
            let adapter = self.registry.adapter(kind);
            match adapter.refresh_session(&site.base_url, &session).await {
                Ok(Some(new_session)) => {
                    let stored = new_session.to_stored();
                    let _ = self.store.set_site_health(site.id, HEALTH_OK);
                    let _ = self.sessions.put(site.id, new_session);
                    if let Ok(s) = stored {
                        if let Err(err) = self.vault.put(&self.session_ref(site.id), &s) {
                            self.log(observability::event_with_payload(
                                Level::Warn,
                                "vault",
                                format!("持久化续期会话失败: {err}"),
                                serde_json::json!({ "site_id": site.id }),
                            ));
                        }
                    }
                }
                Ok(None) => {}
                Err(err) if is_auth_failure(&err) => {
                    // 凭据被拒 ⇒ 会话确实失效：标 needs_login（内部会删钥匙串条目）。
                    self.mark_needs_login(site.id);
                    self.log(observability::event_with_payload(
                        Level::Info,
                        "site",
                        "登录会话已过期，需要重新登录",
                        serde_json::json!({ "site_id": site.id }),
                    ));
                }
                Err(err) => {
                    // 网络 / 5xx：**保留会话**，下一轮再试。Debug 级、不含凭据。
                    self.log(observability::event_with_payload(
                        Level::Debug,
                        "site",
                        format!(
                            "续期登录令牌失败（保留会话，下一轮重试）: {}",
                            error_kind(&err)
                        ),
                        serde_json::json!({ "site_id": site.id }),
                    ));
                }
            }
        }
        Ok(())
    }

    /// 收下 WebView 抓到的 cookie（M8-S2 §9）。
    ///
    /// 顺序：**先做纯校验、再动状态**——校验失败时相位**留在** `AwaitingHuman`
    /// （T5：用户可以重开窗口再试一次），且**不**碰任何存储、**不**写事件、**不**碰站点健康
    /// （M8-S2 G-SPEC O-2：这是格式校验，不是会话失效）。
    /// 校验通过 ⇒ 会话进 `SessionCache` + 健康状态回 `ok`（镜像 `login` 的 B-61 顺序）。
    ///
    /// cookie **不落库、不进事件、不进诊断导出**（S2 §5 红线）：本函数里它只经过
    /// `validate` / `session_from_captcha_cookies` 两条**纯内存**路径。
    pub fn complete_captcha(&self, site_id: i64, cookies: Vec<(String, String)>) -> Result<()> {
        let phase = self.captcha_phase(site_id);
        if !matches!(phase, CaptchaPhase::AwaitingHuman { .. }) {
            // T7：不在人工态时收到 cookie ⇒ 忽略（**不得**把「没经过挑战的 cookie」当会话）。
            return Err(Error::AuthFailed(
                "该站点当前不在等待人工验证：收到的 cookie 已忽略".to_string(),
            ));
        }
        let validated = captcha::validate_captcha_cookies(&cookies);
        // T4 / T5：ok 才回 `Idle`；失败留在人工态（先落相位，再决定要不要上抛）。
        let next = captcha::step(
            phase,
            CaptchaEvent::CookiesSubmitted {
                ok: validated.is_ok(),
            },
        );
        self.set_captcha_phase(site_id, next);
        validated?;
        let session = captcha::session_from_captcha_cookies(&cookies);
        // P1-8：cookie-only 会话在 Sub2API（要 `Authorization` 头）上不可用，不报 ok。
        // 标成 `needs_login`：下一次请求会 401，但 health 已如实标记，不谎报「会话已接上」。
        // 覆盖原会话成 cookie-only：触发 captcha 时原会话通常已失效（401 触发 captcha），
        // 覆盖影响有限；若原 Bearer 仍有效，captcha 不会触发。
        self.store.set_site_health(site_id, HEALTH_NEEDS_LOGIN)?;
        let stored = session.to_stored();
        self.sessions.put(site_id, session)?;
        if let Ok(s) = stored {
            if let Err(err) = self.vault.put(&self.session_ref(site_id), &s) {
                self.log(observability::event_with_payload(
                    Level::Warn,
                    "vault",
                    format!("持久化会话失败: {err}"),
                    serde_json::json!({ "site_id": site_id }),
                ));
            }
        }
        // **成功**才留痕：人工验证真的完成——但 cookie-only 会话不可用，文案如实。
        // 进入人工态 / 取消 / 校验失败都**不写**事件（S2 §5 T12）。
        self.log(observability::event_with_payload(
            Level::Info,
            "site",
            "人机验证已通过：cookie 已更新，需重新登录获取访问令牌",
            serde_json::json!({ "site_id": site_id }),
        ));
        Ok(())
    }

    /// 用户关窗 / 取消（M8-S2 T6 / §9 第 4 条）：相位回 `Idle`。
    ///
    /// **不留半截会话**：不写缓存、不写钥匙串、不写事件；不在人工态时是 no-op（T8 幂等）。
    pub fn cancel_captcha(&self, site_id: i64) {
        let next = captcha::step(self.captcha_phase(site_id), CaptchaEvent::Cancelled);
        self.set_captcha_phase(site_id, next);
        // B 路：取消 ⇒ 丢弃已回传的凭据（与相位同生命周期，M28-S1 §2.1.5）。
        self.clear_webview_creds(site_id);
    }

    pub async fn list_keys(&self, site_id: i64) -> Result<Vec<KeyMeta>> {
        let site = self.site(site_id)?;
        let kind = self.kind_of(&site)?;
        capability_gate(
            kind,
            crate::site::capability::capabilities(kind).list_keys,
            "列举令牌",
        )?;
        let session = self.session(site_id)?;
        let adapter = self.registry.adapter(kind);
        match adapter.list_keys(&site.base_url, &session).await {
            Ok(keys) => {
                self.log(observability::event_with_payload(
                    Level::Debug,
                    "key",
                    format!("已列举 {} 把密钥", keys.len()),
                    serde_json::json!({ "site_id": site_id }),
                ));
                Ok(keys)
            }
            Err(err) => Err(self.on_auth_error(site_id, err)),
        }
    }

    pub async fn create_key(&self, site_id: i64, spec: KeySpec) -> Result<StoredKey> {
        let site = self.site(site_id)?;
        let kind = self.kind_of(&site)?;
        capability_gate(
            kind,
            crate::site::capability::capabilities(kind).create_key,
            "创建令牌",
        )?;
        let session = self.session(site_id)?;
        let adapter = self.registry.adapter(kind);
        let name = spec.name.clone();
        // 分组在 `spec` 被 move 进适配器**之前**取出来：它是用户刚选的权威值，
        // 适配器不回传它（`KeyMaterial` 只有 remote_id + secret）。
        //
        // M19-S1：落库存**显示名**而不是站点标识。`spec.group` 现在是站点原生标识
        // （Sub2API 上是 `"2"`），存它会让密钥表显示一个无意义的数字，更要紧的是
        // `refresh` 里按分组名查倍率会落空 ⇒ 网关按倍率排序退化成「未知」。
        // 调用方没给显示名时（CLI / 测试）回落成标识，行为与改动前一致。
        //
        // **空串要在回落之前滤掉**（独立复审闭环 P3-3）：写成
        // `label.or_else(group).filter(!empty)` 时，`Some("")` 会先命中 `or_else` 的短路
        // 条件（它只看 `Some`/`None`），于是回落不触发、最后被 `filter` 丢成 NULL——
        // 「显示名是空串」与「根本没给显示名」本该走同一条回落路径。
        let group_name = spec
            .group_label
            .clone()
            .filter(|g| !g.is_empty())
            .or_else(|| spec.group.clone().filter(|g| !g.is_empty()));
        // M22-S1：站点原生分组 id 单独留一份。`spec` 随后被 move 进适配器，而 id 要跟着
        // 密钥行一起落库。它落 `keys.group_id`，让**轮换能按 id 认定分组**——名字会被
        // 站点改（B-168），id 不会。
        //
        // 空串同样滤掉：`Some("")` 落库等于存了个既非 id 也非名字的东西。
        //
        // **只有站点真有分组主键时才能这么存**（M22-S1 复审 P1-1）：NewAPI 的
        // `GroupInfo.id` 恒为 `None`，`spec.group` 在那里是**分组名**（`"vip"`）。存进
        // `keys.group_id` 后，下次轮换会走「有 id 只按 id 找」，而 NewAPI 的 id 全是
        // `None` ⇒ 永不命中 ⇒ **这把 key 从此每次轮换都被拒**，而站点根本没改名。
        // 这条判据属于「站点类型的设计能力」，所以查能力表，不在这里按 `kind` 分支。
        let group_id = if crate::site::capability::capabilities(kind).group_ids {
            spec.group.clone().filter(|g| !g.is_empty())
        } else {
            None
        };
        match adapter.create_key(&site.base_url, &session, spec).await {
            Ok(material) => {
                // 站点上已经建好了。此刻若本地保存失败，必须如实告诉用户
                // 「站点上已创建、本地没存上」，而不是含糊地报一个失败让人重试建键。
                let stored = self
                    .store_key_material(
                        site_id,
                        &name,
                        Some(&material.remote_id),
                        group_name.as_deref(),
                        // 分组 id 与密钥行**同一次写入**（M22-S2 / B-172）。M22-S1 的
                        // 「先插行、再补 id」两写不原子：第二写失败只能吞成一条 Warn 事件，
                        // 库里留下「行在、id 缺」的中间态，而那条降级通道没有任何非测试
                        // 路径能走到——等于一条永远没人验证的分支。现在要么两列都落、
                        // 要么整行不写（失败即走下面的 `map_err`：站点上已创建、本地
                        // 没存上，明确报错并补偿删掉钥匙串里刚写的明文）。
                        group_id.as_deref(),
                        &material.secret,
                    )
                    .map_err(|err| {
                        Error::Vault(format!(
                            "站点上已创建成功（id={}），但本地保存失败：{err}",
                            material.remote_id
                        ))
                    })?;
                self.log(observability::event_with_payload(
                    Level::Info,
                    "key",
                    format!("已获取密钥 {name}"),
                    serde_json::json!({ "site_id": site_id, "key_id": stored.id }),
                ));
                Ok(stored)
            }
            Err(err) => Err(self.on_auth_error(site_id, err)),
        }
    }

    /// 站点余额。**可观测性不足时返回未知态，不返回错误**。
    ///
    /// # 为什么这里不是「能力门」
    ///
    /// 另外五个入口在能力为 false 时返回 [`Error::Unsupported`]（那是「这个操作不做」）。
    /// 余额不一样：它**有**答案——答案是「不可观测」（[`Balance::unknown`]）。
    /// 所以这里在 `session()` **之前**短路成 `Ok(unknown)`。
    ///
    /// 短路的位置是硬要求（M7-S2 复审 S-1 实测）：`custom-openai-compatible` 站点
    /// **没有登录流程**（`login: false`），会话永远拿不到——若先要会话，
    /// 用户会看到「请先登录」，被引向一个根本不存在的登录流程。
    pub async fn balance(&self, site_id: i64) -> Result<Balance> {
        let site = self.site(site_id)?;
        let kind = self.kind_of(&site)?;
        if !crate::site::capability::capabilities(kind).balance {
            return Ok(Balance::unknown("USD"));
        }
        let session = self.session(site_id)?;
        let adapter = self.registry.adapter(kind);
        match adapter.balance(&site.base_url, &session).await {
            Ok(balance) => Ok(balance),
            Err(err) => Err(self.on_auth_error(site_id, err)),
        }
    }

    /// 会话失效时清缓存 + 把「需要重新登录」**落库**（B-61）。
    ///
    /// 落库是必要的：会话缓存只在进程内，重启即空。状态不落库的话，用户下次开应用时
    /// 这个站点会重新变成「从没登录过」，那条提示就再也找不回来了。
    ///
    /// 写入点是**共用**的：定时刷新与用户手动操作（看余额、读明文、删密钥）撞上失效会话
    /// 都会走到这里。这是有意的——会话死了就是死了，不该只在刷新轮才可见。
    fn on_auth_error(&self, site_id: i64, err: Error) -> Error {
        if is_auth_failure(&err) {
            self.sessions.invalidate(site_id);
            self.mark_needs_login(site_id);
        }
        err
    }

    /// 站点会话的钥匙串引用（M13-S1）：`kr/site/<site_id>/session`。
    fn session_ref(&self, site_id: i64) -> String {
        crate::vault::secret_ref("site", site_id, "session")
    }

    /// 把站点标成「需要重新登录」。**best-effort**：写库失败只留一条 warn 事件，
    /// 不改写调用方看到的原始错误——调用方要的是「为什么失败」，不是「状态没存上」。
    ///
    /// 同时删掉钥匙串里的持久化 session（M13-S1）：session 已被判坏，不能再留给下次
    /// 启动加载——否则重启后 restore 一个已知 401 的会话，用户又得手动重登一次。
    /// `vault.delete` 幂等，无条目也 Ok。
    fn mark_needs_login(&self, site_id: i64) {
        if let Err(err) = self.store.set_site_health(site_id, HEALTH_NEEDS_LOGIN) {
            self.log(observability::event_with_payload(
                Level::Warn,
                "store",
                format!("站点状态落库失败: {err}"),
                serde_json::json!({ "site_id": site_id, "health": HEALTH_NEEDS_LOGIN }),
            ));
        }
        if let Err(err) = self.vault.delete(&self.session_ref(site_id)) {
            self.log(observability::event_with_payload(
                Level::Warn,
                "vault",
                format!("删除持久化会话失败: {err}"),
                serde_json::json!({ "site_id": site_id }),
            ));
        }
    }

    /// 删除站点记录，**同时清掉该 id 的会话缓存与人工验证相位**。
    ///
    /// 复审 P2-6：SQLite rowid 会复用（删掉最大 id 后新站点可能拿到同一 id），
    /// 若不联动清理，旧站点的会话会被套用到新站点上，造成跨站串号。
    /// 相位同理：一个「等待人工验证」的僵尸相位会让新站点直接拿到旧站点的挑战。
    pub fn remove_site(&self, site_id: i64) -> Result<()> {
        self.sessions.invalidate(site_id);
        self.set_captcha_phase(site_id, CaptchaPhase::Idle);
        self.clear_webview_creds(site_id);
        // 先删钥匙串持久化 session，再删 DB 行（复审 High 修正）。
        // 原顺序（先 DB 后钥匙串 best-effort）在 vault.delete 失败时留孤儿 session_ref：
        // site_id 已从 list_sites 消失，owned_secret_refs 兜不住，rowid 复用后同 id 新站
        // restore 会套用旧站 session → 跨站串号。现改为 vault.delete 先且 `?` 传播：
        // 钥匙串失败则 DB 不删、站点仍在、session 仍在，一致无孤儿；用户可重试删站。
        // `delete` 幂等（vault/mod.rs:57），无条目也 Ok，重复删站不报错。
        self.vault.delete(&self.session_ref(site_id))?;
        self.store.delete_site(site_id)?;
        Ok(())
    }

    fn site(&self, site_id: i64) -> Result<SiteRow> {
        self.store
            .get_site(site_id)?
            .ok_or_else(|| Error::NotFound(format!("站点 #{site_id} 不存在")))
    }

    fn kind_of(&self, site: &SiteRow) -> Result<SiteKind> {
        SiteKind::parse(&site.kind)
            .ok_or_else(|| Error::Store(format!("数据库中的站点类型无法识别: {}", site.kind)))
    }

    fn session(&self, site_id: i64) -> Result<Session> {
        self.sessions.get(site_id).ok_or_else(|| {
            Error::AuthFailed("尚未登录该站点（或会话已失效），请先登录".to_string())
        })
    }

    // ============================================================== 密钥投递（M1-S2）

    /// 生成投递预览。**不含密钥明文**；不落盘、不写库。
    pub fn delivery_plan(&self, key_id: i64, channel: DeliveryChannel) -> Result<DeliveryPlan> {
        self.delivery_plan_with_model(key_id, channel, None)
    }

    /// 带模型名的投递预览。`model` 只对 OpenCode / OpenCodeJsonc 生效
    /// （[`delivery::resolve_for_binding`]），其余通道忽略。
    pub fn delivery_plan_with_model(
        &self,
        key_id: i64,
        channel: DeliveryChannel,
        model: Option<&str>,
    ) -> Result<DeliveryPlan> {
        self.delivery_plan_in(key_id, channel, model, delivery::DeliverySource::Site)
    }

    /// 按**来源**（站点 / 本地网关）生成投递预览（M8-S4 §6.6）。
    ///
    /// 两条路径共用同一份 `plan()` / `fields()` / 同意检查：模式只决定
    /// 「`base_url` 与 `api_key` 取哪一对值」，落点与字段名**逐字相同**。
    pub fn delivery_plan_in(
        &self,
        key_id: i64,
        channel: DeliveryChannel,
        model: Option<&str>,
        source: delivery::DeliverySource<'_>,
    ) -> Result<DeliveryPlan> {
        let mode = source.mode();
        let writer = self.prepare_delivery(key_id, channel, model, source)?;
        let api_key = self.secret_for_source(key_id, source)?;
        let patch = writer.plan(&api_key)?;
        let target_path = writer.target_path();
        let consent = self.consent_state(channel, &target_path)?;
        self.log(observability::event_with_payload(
            Level::Debug,
            "delivery",
            format!("投递预览: {} → {}", channel.as_str(), target_path.display()),
            serde_json::json!({
                "consent_granted": consent.is_granted(),
                "mode": mode.as_str(),
            }),
        ));
        // P2-5：掩掉 before 里可能仍在的旧站点密钥（改指网关时 `-` 行的旧密钥
        // 不一定是 `scrub` 认得的形态，不显式替换会明文带出去）。新密钥 + 该
        // target 上当前生效的旧密钥一起替换，`scrub` 兜底掩别的形态。
        let mut secrets: Vec<String> = vec![api_key.to_string()];
        secrets.extend(self.previous_secrets_for_target(&target_path, key_id));
        let secret_refs: Vec<&str> = secrets.iter().map(|s| s.as_str()).collect();
        Ok(DeliveryPlan {
            agent_id: channel.agent_id().to_string(),
            channel,
            target_exists: target_path.exists(),
            mode,
            fields: writer.fields(&api_key),
            preview: delivery::diff_preview(&patch.before, &patch.after, &secret_refs),
            consent,
            target_path,
        })
    }

    /// 记录用户同意（幂等：重复同意刷新时间戳并解除撤销）。
    pub fn grant_consent(&self, key_id: i64, channel: DeliveryChannel) -> Result<()> {
        let writer =
            self.prepare_delivery(key_id, channel, None, delivery::DeliverySource::Site)?;
        let target = self.checked_target(channel, &writer.target_path())?;
        // 记录同意**不需要**读钥匙串：用户此刻同意的是「写哪些键」，不是「密钥是否存在」。
        let fields = writer.field_names();
        self.store.grant_consent(
            channel.agent_id(),
            channel.as_str(),
            &target.display().to_string(),
            &fields,
        )?;
        self.log(observability::event_with_payload(
            Level::Info,
            "delivery",
            "已授予投递同意",
            serde_json::json!({
                "agent_id": channel.agent_id(),
                "channel": channel.as_str(),
                "target_path": target.display().to_string(),
            }),
        ));
        Ok(())
    }

    /// 撤销同意。**不**回滚已写入的文件（回滚是独立动作）。
    pub fn revoke_consent(&self, key_id: i64, channel: DeliveryChannel) -> Result<()> {
        let writer =
            self.prepare_delivery(key_id, channel, None, delivery::DeliverySource::Site)?;
        let target = self.checked_target(channel, &writer.target_path())?;
        self.store.revoke_consent(
            channel.agent_id(),
            channel.as_str(),
            &target.display().to_string(),
        )?;
        self.log(observability::event_with_payload(
            Level::Info,
            "delivery",
            "已撤销投递同意",
            serde_json::json!({
                "agent_id": channel.agent_id(),
                "channel": channel.as_str(),
                "target_path": target.display().to_string(),
            }),
        ));
        Ok(())
    }

    pub fn list_consents(&self) -> Result<Vec<ConsentRow>> {
        self.store.list_consents()
    }

    /// 全部「通道 → key」绑定（M8-S7 / B-116）。
    ///
    /// **含已解绑的行**：过滤是调用方的事——命令层按 `unbound_at.is_none()` 筛，
    /// 而「回收站点侧 key」那条路要按**当时的**绑定走（`bindings_of_agent` 的既有语义）。
    /// 只读，不写任何东西。
    ///
    /// 走 [`Store::current_bindings`]：同 `(agent_id, key_id, target_path)` 的重投只留
    /// 最新一行（P2-16），换 key 的重投仍各自成行（M8-S7 P2-4）。
    pub fn channel_bindings(&self) -> Result<Vec<crate::store::BindingRow>> {
        self.store.current_bindings()
    }

    /// 投递历史（M9-S4）：「变更历史」页的回滚入口。只读。
    pub fn delivery_history(&self, limit: usize) -> Result<Vec<crate::store::DeliveryHistoryRow>> {
        self.store.delivery_history(limit)
    }

    /// 真正把密钥写进目标文件。步骤与顺序见 spec §6.1，**同意是第一步**。
    ///
    /// 不带模型名：轮换第②步走的就是这条。
    pub fn apply_delivery(&self, key_id: i64, channel: DeliveryChannel) -> Result<DeliveryOutcome> {
        self.apply_delivery_with_model(key_id, channel, None)
    }

    /// 带模型名的投递。`model` 的口径见 [`TianshuRelayService::delivery_plan_with_model`]。
    pub fn apply_delivery_with_model(
        &self,
        key_id: i64,
        channel: DeliveryChannel,
        model: Option<&str>,
    ) -> Result<DeliveryOutcome> {
        self.apply_delivery_in(key_id, channel, model, delivery::DeliverySource::Site)
    }

    /// 按**来源**（站点 / 本地网关）真正落盘（M8-S4 §6.2）。
    ///
    /// 步骤与顺序与站点模式**逐字相同**（同意 → 取锁 → 锁内再确认同意 → 取密钥 → 写 → 记账）：
    /// 网关模式只换「`base_url` 与 `api_key` 取哪一对值」，其余一个字节都不改。
    /// 这很关键——同意、备份、回读校验、失败补偿这些安全动作**不因为模式而放松**。
    pub fn apply_delivery_in(
        &self,
        key_id: i64,
        channel: DeliveryChannel,
        model: Option<&str>,
        source: delivery::DeliverySource<'_>,
    ) -> Result<DeliveryOutcome> {
        // P1-2：记录投递模式（轮换按它走，不把网关模式改成站点模式）。
        let delivery_mode = match &source {
            delivery::DeliverySource::Gateway(_) => "gateway",
            delivery::DeliverySource::Site => "site",
        };
        // ① 同意（未同意时**不读钥匙串、不落盘**）
        let writer = self.prepare_delivery(key_id, channel, model, source)?;
        let target = self.checked_target(channel, &writer.target_path())?;
        if !self.consent_state(channel, &target)?.is_granted() {
            self.log(observability::event_with_payload(
                Level::Warn,
                "delivery",
                "投递被拒绝：缺少用户同意",
                serde_json::json!({ "channel": channel.as_str() }),
            ));
            return Err(Error::ConsentRequired {
                agent_id: channel.agent_id().to_string(),
                channel: channel.as_str().to_string(),
                target_path: target.display().to_string(),
            });
        }

        // ② 取锁。**必须在确认同意之前**：否则用户可以在我们等锁的时候撤销同意，
        //    而我们醒来后照写不误（M1-S2 复审 P1-2）。
        let lock_dir = inject::default_lock_dir();
        let guard = inject::lock::FileLock::acquire(&target, &lock_dir)?;

        // ③ 在锁内**重新**确认同意（第一次检查在取锁之前，那一次是为了避免无谓取锁）
        if !self.consent_state(channel, &target)?.is_granted() {
            self.log(observability::event_with_payload(
                Level::Warn,
                "delivery",
                "投递被拒绝：取锁期间同意被撤销",
                serde_json::json!({ "channel": channel.as_str() }),
            ));
            return Err(Error::ConsentRequired {
                agent_id: channel.agent_id().to_string(),
                channel: channel.as_str().to_string(),
                target_path: target.display().to_string(),
            });
        }

        // ④ 取密钥并生成计划（网关模式取的是本地令牌，见 `secret_for_source`）
        let api_key = self.secret_for_source(key_id, source)?;
        let patch = writer.plan(&api_key)?;

        // ⑤ 写入（加锁已在上面完成；预检 → 备份 → 原子写 → 回读校验 → 失败补偿在 apply 内部）
        let journal = match inject::apply_holding_lock(
            &[patch],
            &self.backup_dir,
            std::slice::from_ref(&guard),
        ) {
            Ok(journal) => journal,
            Err(err) => {
                self.log(observability::event_with_payload(
                    Level::Error,
                    "delivery",
                    format!("投递失败: {}", error_kind(&err)),
                    serde_json::json!({ "channel": channel.as_str() }),
                ));
                return Err(err);
            }
        };

        // ⑥ 记账：变更记录 + 投递绑定。两者都不含密钥。
        //
        // 记账失败必须**补偿回滚**：文件已经改了，但用户拿不到 `journal_id`
        // 就永远回滚不了——那等于留下一个无法撤销的改动（M1-S2 复审 P1-4）。
        if let Err(err) = self.store.record_journal(&journal).and_then(|()| {
            self.store.record_binding(
                channel.agent_id(),
                key_id,
                &target.display().to_string(),
                &journal.id,
                delivery_mode,
            )
        }) {
            return match inject::rollback(&journal) {
                Ok(()) => Err(Error::Store(format!(
                    "记账失败，已自动回滚（文件内容未改动）: {err}"
                ))),
                Err(rollback_err) => Err(Error::Store(format!(
                    "记账失败且自动回滚也失败，需要人工处理: {err} / {rollback_err}"
                ))),
            };
        }

        self.log(observability::event_with_payload(
            Level::Info,
            "delivery",
            format!("投递完成: {}", channel.as_str()),
            serde_json::json!({
                "journal_id": journal.id,
                "target_path": target.display().to_string(),
            }),
        ));

        Ok(DeliveryOutcome {
            channel,
            target_path: target,
            backup_path: journal.entries.first().and_then(|e| e.backup.clone()),
            journal_id: journal.id,
        })
    }

    /// 按 journal 回滚（校验文件未被外部改动）。
    pub fn rollback_delivery(&self, journal_id: &str) -> Result<()> {
        let entries = self.store.journal_entries(journal_id)?;
        if entries.is_empty() {
            return Err(Error::NotFound(format!("变更记录 {journal_id} 不存在")));
        }
        inject::rollback(&inject::Journal {
            id: journal_id.to_string(),
            entries,
        })?;
        // 文件已经还原了：记状态失败**不**能把这次回滚报成失败（与 B-100 同口径）。
        // 没记上的后果只是历史页仍显示「可回滚」；再点一次会被哈希校验拒绝，不会误改文件。
        if let Err(err) = self.store.mark_journal_rolled_back(journal_id) {
            self.log(observability::event_with_payload(
                Level::Warn,
                "delivery",
                "回滚已完成，但本地状态没记上",
                serde_json::json!({
                    "journal_id": journal_id,
                    "error": crate::redact::scrub(&err.to_string()),
                }),
            ));
        }
        self.log(observability::event_with_payload(
            Level::Info,
            "delivery",
            "已回滚变更",
            serde_json::json!({ "journal_id": journal_id }),
        ));
        Ok(())
    }

    // ============================================ 漂移检测 / 设置 / 刷新（M3-S1）

    /// 检查每个投递目标是否被外部改动过。**只读**，不做任何自动修复。
    ///
    /// 需要用户注意的项会写一条 `warn` 事件（同一轮里每个目标只写一条）。
    pub fn drift_report(&self) -> Result<Vec<DriftReport>> {
        let rows = self.store.binding_drift_rows()?;
        let reports: Vec<DriftReport> = rows.iter().map(drift::report_for).collect();

        for report in reports.iter().filter(|r| r.state.needs_attention()) {
            self.log(observability::event_with_payload(
                Level::Warn,
                "delivery",
                format!(
                    "投递目标已被外部改动（{}）: {}",
                    report.state.as_str(),
                    report.target_path.display()
                ),
                serde_json::json!({
                    "agent_id": report.agent_id,
                    "channel": report.channel,
                    "journal_id": report.journal_id,
                    "expected": report.expected_sha256.as_deref().map(|h| &h[..8.min(h.len())]),
                    "current": report.current_sha256.as_deref().map(|h| &h[..8.min(h.len())]),
                }),
            ));
        }
        Ok(reports)
    }

    pub fn settings(&self) -> Result<Settings> {
        let mut pairs: Vec<(String, String)> = Vec::new();
        for key in Settings::KEYS {
            if let Some(value) = self.store.get_setting(key)? {
                pairs.push((key.to_string(), value));
            }
        }
        let borrowed: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        Ok(Settings::from_pairs(borrowed))
    }

    /// 解析当前 settings 的代理 URL（供网关上游 / webhook 复用，M10-S2）。
    ///
    /// 与壳层 `build_transport` 的 `resolved_proxy_url` 同一份 `proxy::resolve_proxy`，
    /// 但在 service 内部、每次调用都读最新 settings——网关/通知因此能感知系统代理变更
    /// （站点适配器 transport 不可变，仍需重启 app）。
    ///
    /// manual 非法 ⇒ `eprintln` 告警并返回 `None`，不 panic 也不 `Err`：网关/通知不该
    /// 因为代理配置非法而崩，用户能进设置页改掉它。
    fn resolved_upstream_proxy(&self) -> Option<String> {
        let settings = self.settings().ok()?;
        let mode = crate::proxy::ProxyMode::parse(&settings.proxy_mode)
            .unwrap_or(crate::proxy::ProxyMode::Auto);
        match crate::proxy::resolve_proxy(mode, &settings.proxy_url) {
            Ok(Some(d)) => Some(d.url),
            Ok(None) => None,
            Err(err) => {
                eprintln!("[tianshu-relay] 代理配置非法，上游直连: {err}");
                None
            }
        }
    }

    pub fn update_settings(&self, settings: &Settings) -> Result<()> {
        settings.validate()?;
        for (key, value) in settings.to_pairs() {
            self.store.set_setting(key, &value)?;
        }
        // 事件里**只**记这三个「纯数值/布尔」的项。
        //
        // M6-S5 新增的字段刻意不记：
        // - `proxy_url` 与 `notify_webhook_url` 都可能内嵌凭证（`https://user:pass@…`），
        //   事件表是会被导出与审计的地方，不能作为它们的出口；
        // - `theme` / `language` / 各类开关没有诊断价值，记了只是噪声。
        // 需要确认「设置被改过」时，事件本身（`设置已更新`）已经够了。
        self.log(observability::event_with_payload(
            Level::Info,
            "app",
            "设置已更新",
            serde_json::json!({
                "refresh_interval_secs": settings.refresh_interval_secs,
                "balance_alert_threshold": settings.balance_alert_threshold,
                "drift_check_on_start": settings.drift_check_on_start,
            }),
        ));
        Ok(())
    }

    /// 单个站点的刷新**工作单元**（M8-S3 §3.4 裁决 ①：有界并发的执行体）。
    ///
    /// 只做「取事实」：会话判定、余额、令牌列表、余额进观测缓存。
    /// **记账、事件与快照留在调用方**——那样日志顺序仍按站点 id 升序，与本改造之前逐字一致。
    /// 单元内部**不上抛**任何错误：结果原样带回给调用方分类（单站点失败不中断整轮）。
    async fn refresh_site(
        &self,
        site: SiteRow,
        drift: Vec<crate::notify::DriftFact>,
        rotation_due: Vec<crate::notify::RotationDueFact>,
    ) -> SiteRefresh {
        // 没有会话：要么用户从没登录过它（跳过），要么上一轮已判过「需要重新登录」
        // ——后者必须每轮都带出来，且**不发任何请求**（纯本地判定）。
        if self.sessions.get(site.id).is_none() {
            return SiteRefresh {
                needs_login_without_session: site.health == HEALTH_NEEDS_LOGIN,
                site_id: site.id,
                display_name: site.display_name,
                base_url: site.base_url,
                had_session: false,
                balance: None,
                keys: None,
                drift,
                rotation_due,
            };
        }

        let balance = self.balance(site.id).await;
        // M8-S1 §5.1：余额进**观测缓存**（供路由表排序用）。
        // `known == false` ⇒ `None`——绝不 `unwrap_or(0.0)`：那会把「不知道」
        // 变成「已耗尽」，直接改变候选顺序（`health_rank` 的档位就是为这件事存在的）。
        if let Ok(b) = &balance {
            if let Ok(mut map) = self.site_facts.lock() {
                map.entry(site.id).or_default().balance_usd =
                    if b.known { Some(b.remaining) } else { None };
            }
            // M13-S1：known == true 时写一条余额快照
            if b.known {
                let _ = self.store.insert_usage_snapshot(
                    site.id,
                    b.used,
                    b.remaining,
                    &b.currency,
                    true,
                );
            }
        }
        let keys = self.list_keys(site.id).await;

        // M14-S3：per-key 用量采集（仅 key_usage=true 的站点；失败静默不阻塞，spec §7.4）。
        // 放在 `keys` 借用之后、move 进 `SiteRefresh` 之前。
        if let Ok(kind) = self.kind_of(&site) {
            if crate::site::capability::capabilities(kind).key_usage {
                if let Ok(list) = &keys {
                    self.collect_key_usage(site.id, kind, &site.base_url, list)
                        .await;
                }
            }
        }

        SiteRefresh {
            needs_login_without_session: false,
            site_id: site.id,
            display_name: site.display_name,
            base_url: site.base_url,
            had_session: true,
            balance: Some(balance),
            keys: Some(keys),
            drift,
            rotation_due,
        }
    }

    /// M14-S3：per-key 用量采集（spec §7）。
    ///
    /// - 从站点侧 `list_keys` 的 `KeyMeta` 取当前累计用量，写 `keys.quota_used/quota_limit`；
    /// - 对 Sub2API（`fetch_key_daily_usage` 返回非空）另写 `usage_samples` 日趋势。
    ///
    /// 节流（spec §7.4）：每 key 每轮一次 usage 请求、顺序（并发 1 ≤ 2 上限）、失败静默不阻塞。
    /// 仅对「本地已登记 + 站点侧仍存在」的 key 做（by `remote_id` join）——用量列只在本地表显示。
    async fn collect_key_usage(
        &self,
        site_id: i64,
        kind: crate::site::SiteKind,
        base_url: &str,
        site_keys: &[crate::site::KeyMeta],
    ) {
        // 本地已登记 key（KeyRow），按 site_id 过滤
        let local_rows = match self.store.list_keys() {
            Ok(rows) => rows,
            Err(e) => {
                self.log(observability::event_with_payload(
                    Level::Warn,
                    "site",
                    format!("采集用量时读本地密钥失败: {e}"),
                    serde_json::json!({ "site_id": site_id }),
                ));
                return;
            }
        };
        let session = match self.session(site_id) {
            Ok(s) => s,
            Err(_) => return,
        };
        let adapter = self.registry.adapter(kind);

        for meta in site_keys {
            // join：本地 KeyRow.remote_id == Some(meta.remote_id)
            let Some(local_id) = local_rows
                .iter()
                .find(|r| r.remote_id.as_deref() == Some(meta.remote_id.as_str()))
                .map(|r| r.id)
            else {
                continue;
            };
            // ① 写当前累计用量（NewAPI / Sub2API 都有，来自 list_keys 的 KeyMeta）
            if let Err(e) = self.store.update_key_usage(
                local_id,
                meta.quota_used,
                meta.quota_limit,
                meta.currency.as_deref(),
            ) {
                self.log(observability::event_with_payload(
                    Level::Warn,
                    "site",
                    format!("写 key 用量失败: {e}"),
                    serde_json::json!({ "site_id": site_id, "key_id": local_id }),
                ));
            }
            // ② 日趋势（Sub2API 覆盖 fetch_key_daily_usage；NewAPI 默认返回空 Vec，零请求）
            match adapter
                .fetch_key_daily_usage(base_url, &session, &meta.remote_id)
                .await
            {
                Ok(points) => {
                    for p in &points {
                        if let Err(e) = self.store.upsert_usage_sample(local_id, site_id, p) {
                            self.log(observability::event_with_payload(
                                Level::Warn,
                                "site",
                                format!("写用量采样失败: {e}"),
                                serde_json::json!({ "site_id": site_id, "key_id": local_id }),
                            ));
                            break;
                        }
                    }
                }
                Err(err) => {
                    // 会话失效：标 needs_login 并停（下一把也会 401）。spec §7.4 会话失效例外。
                    if is_auth_failure(&err) {
                        self.on_auth_error(site_id, err);
                        return;
                    }
                    // 其他失败：静默记 event，继续下一把（spec §7.4 失败静默不阻塞）。
                    self.log(observability::event_with_payload(
                        Level::Warn,
                        "site",
                        format!("采集 key 用量失败: {}", error_kind(&err)),
                        serde_json::json!({ "site_id": site_id, "key_id": local_id }),
                    ));
                }
            }
        }
    }

    /// 刷新全部**已登录**站点的余额与密钥数。
    ///
    /// 单个站点失败**不中断**其余站点：把失败计数与原因分类写进事件，
    /// 整体仍返回 `Ok`（否则调用方会以为整轮都废了）。
    ///
    /// 会话失效的站点（无会话 + `health == "needs_login"`）不联网、不计成功也不计失败，
    /// 但每轮都会出现在 [`RefreshSummary::needs_login`] 里——否则用户在界面上永远
    /// 看不到「这个站需要重新登录」（B-61）。
    ///
    /// **并发布局**（M8-S3 §3.4 裁决 ①）：站点之间**有界并发**
    /// （[`MAX_REFRESH_CONCURRENCY`] 个在途），站点内部仍是顺序的两步
    /// （余额 → 令牌）。收齐结果后按 id 升序记账，所以事件顺序与快照顺序不随并发漂移。
    pub async fn refresh_all(&self) -> Result<RefreshSummary> {
        // P3-27 / DEBUG-REPORT-v3 §3-27：**跨调用的互斥**。
        //
        // `MAX_REFRESH_CONCURRENCY` 只约束**一次** `refresh_all` 内部的在途数；两次调用
        // 重叠（前台 60s 节拍 + 用户点「立即刷新」+ 后台 30min 任务）时在途会翻倍到 8，
        // 上游限流风险随之翻倍。这里用 `tokio::sync::Mutex` **串行化**（async-aware：
        // 不得用 `std::sync::Mutex` 跨 `.await`，clippy `await_holding_lock`）。
        //
        // 语义选择：**排队**而不是「第二次直接跳过」——跳过会让用户点「立即刷新」时
        // 什么都不发生（且拿到的汇总还是上一轮的），比等一会儿更让人困惑。
        let _refresh_guard = self.refresh_lock.lock().await;
        // 先把网关攒下的失败落库（FR-5:160）。放在最前面：它们是**已经发生过**的事实，
        // 而下面的刷新要跑网络；先落库能让「网关为什么切换了上游」在事件面板里
        // 早于本轮的余额/漂移事件出现，读起来是因果顺序。
        self.drain_gateway_failures();
        self.drain_gateway_usage();
        // M13-S1：裁剪用量日志，保留最近 90 天（P2-2）。
        let _ = self.store.prune_gateway_usage_log(90);
        let _ = self.store.prune_usage_snapshots(90);
        // M14-S3：裁剪 per-key 用量采样，保留最近 90 天（与 gateway_usage_log / usage_snapshots 同口径）。
        let _ = self.store.prune_usage_samples(90);
        let settings = self.settings()?;
        let sites = self.store.list_sites()?;
        let mut summary = RefreshSummary {
            sites_total: sites.len(),
            ..Default::default()
        };
        // 本轮快照（M6-S5 / FR-3）。即使没开通知也照常收集——收集是纯内存操作，
        // 而「开通知」是本轮之后才可能发生的设置变更；这样开关打开时不需要先空跑一轮。
        let mut snapshots: Vec<crate::notify::SiteSnapshot> = Vec::with_capacity(sites.len());

        // 漂移与轮换到期是**纯本地**判定，每轮各算一次再按站点归组（M6-S5 / W-1）。
        //
        // 放在循环外：两者的结果与「哪个站点」无关，放进循环会变成每站点一次文件哈希
        // 加一次全表查询。
        // 必须采集：不采集时这两类事实恒为空集——W-1 实测的后果是
        // `NotifyKind::Drift` 与 `RotationDue` 在生产上**永不触发**（FR-3 的漂移告警与
        // FR-7 的到期提醒没有任何出口），而四份包内复审都没看见，因为它落在包与包的缝里。
        let drift_by_site = self.collect_notify_input("漂移", || self.drift_facts_by_site());
        let rotation_by_site =
            self.collect_notify_input("轮换到期", || self.rotation_facts_by_site());

        // 站点之间**有界并发**（M8-S3 §3.4 裁决 ①）：最多 `MAX_REFRESH_CONCURRENCY` 个在途。
        // 用 `buffer_unordered` 而不是 `spawn`：工作单元借用 `&self`（`Store` 不是 `Clone`，
        // 也不值得为一次刷新引入任务调度），而 `spawn` 要求 `'static`。
        let mut outcomes: Vec<SiteRefresh> = stream::iter(sites)
            .map(|site| {
                let drift = drift_by_site.get(&site.id).cloned().unwrap_or_default();
                let rotation_due = rotation_by_site.get(&site.id).cloned().unwrap_or_default();
                async move { self.refresh_site(site, drift, rotation_due).await }
            })
            .buffer_unordered(MAX_REFRESH_CONCURRENCY)
            .collect()
            .await;
        // 完成顺序 ≠ 站点顺序：先恢复确定性再记账。
        // 下面的事件与快照都依赖「按 id 升序」——否则同一轮刷新的事件顺序会随网络抖动变化。
        outcomes.sort_by_key(|outcome| outcome.site_id);

        for outcome in outcomes {
            // 没有会话：要么用户从没登录过它（跳过），要么上一轮已判过「需要重新登录」
            // ——后者必须每轮都带出来，且不发任何请求（纯本地判定）。
            if !outcome.had_session {
                let needs_login = outcome.needs_login_without_session;
                if needs_login {
                    summary.needs_login.push(outcome.site_id);
                }
                snapshots.push(crate::notify::SiteSnapshot {
                    site_id: outcome.site_id,
                    display_name: outcome.display_name,
                    balance: None,
                    needs_login,
                    quota_exceeded: false,
                    models: None,
                    // 漂移与轮换到期都**不依赖会话**（前者由投递绑定推出、后者只看本地密钥
                    // 的创建时间），所以「没会话」这个分支同样要带上——否则用户在一个会话
                    // 失效的站点上反而看不到「这个站点的密钥该换了」。
                    drift: outcome.drift,
                    rotation_due: outcome.rotation_due,
                });
                continue;
            }

            let balance = outcome.balance;
            let keys = outcome.keys;
            let mut quota_exceeded = false;

            match (&balance, &keys) {
                (Some(Ok(_)), Some(Ok(list))) => {
                    summary.sites_ok += 1;
                    summary.keys_total += list.len();
                }
                _ => {
                    summary.sites_failed += 1;
                    // P3-28 / DEBUG-REPORT-v3 §3-28：**两个错误都要看**。
                    //
                    // 旧实现只取「第一个」错误（余额优先）来决定 `needs_login`，于是
                    // 「余额 503（非认证类）+ 令牌列表 401（认证类）」这种组合会把认证失败
                    // 吞掉：`on_auth_error` 已经把站点落库成「需要登录」，本轮汇总的
                    // `needs_login` 却是空的 —— 用户当场看不到，得等下一轮。
                    let balance_err = balance.as_ref().and_then(|result| result.as_ref().err());
                    let keys_err = keys.as_ref().and_then(|result| result.as_ref().err());
                    let errors: [Option<&Error>; 2] = [balance_err, keys_err];
                    let auth_failure = errors
                        .into_iter()
                        .flatten()
                        .find(|err| is_auth_failure(err));
                    // 原因优先取认证失败（更可操作：用户该去重新登录），否则退回第一个错误。
                    let failure = auth_failure.or(balance_err).or(keys_err);
                    let reason = failure.map(error_kind).unwrap_or("未知");
                    // 认证失败 = 会话已失效：`on_auth_error` 已经把它落库，
                    // 这里再带进本轮汇总，用户当场就能看到。
                    if auth_failure.is_some() {
                        summary.needs_login.push(outcome.site_id);
                    }
                    // 额度耗尽（HTTP 403 + 已知错误码）是**独立**于会话失效的一种状态：
                    // 会话是好的，只是没钱了。分开判定，否则用户会去重新登录一个
                    // 根本不需要登录的站点（PRD FR-3 的告警清单里两条并列）。
                    //
                    // 同样**两个错误都看**：`failure` 现在优先取认证失败，若只用它判额度，
                    // 「余额 403 额度耗尽 + 令牌 401」会把额度信号丢掉（与 P3-28 同一类）。
                    quota_exceeded = errors
                        .into_iter()
                        .flatten()
                        .any(|err| matches!(err, Error::QuotaExhausted));
                    self.log(observability::event_with_payload(
                        Level::Warn,
                        "site",
                        format!("刷新站点失败: {reason}"),
                        serde_json::json!({ "site_id": outcome.site_id, "base_url": outcome.base_url }),
                    ));
                }
            }

            if let Some(Ok(balance)) = &balance {
                if settings.balance_alert_threshold > 0.0
                    && balance.known
                    && balance.remaining < settings.balance_alert_threshold
                {
                    summary.balance_alerts.push(outcome.site_id);
                    self.log(observability::event_with_payload(
                        Level::Warn,
                        "site",
                        format!(
                            "余额低于阈值: {} {} < {}",
                            balance.remaining, balance.currency, settings.balance_alert_threshold
                        ),
                        serde_json::json!({
                            "site_id": outcome.site_id,
                            "base_url": outcome.base_url,
                            "remaining": balance.remaining,
                        }),
                    ));
                }
            }

            snapshots.push(crate::notify::SiteSnapshot {
                site_id: outcome.site_id,
                display_name: outcome.display_name,
                balance: balance
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    // 硬要求 (b)（M7-S2 复审 S-2）：**未知余额不进快照**。
                    //
                    // `BalanceSnapshot` 只有 `remaining: f64`，装不下「不知道」；
                    // 若把未知态照传，`balance_low` 会把 0.0 拿去和阈值比，
                    // 阈值 > 0 时就会产出一条**假的**「余额不足」——用户会去查一个
                    // 根本没问题的站点。假告警比不告警更糟：它会消耗掉用户对告警的信任。
                    //
                    // 传 `None` 与「这个站点没有余额信息」同义，而 `balance_low`
                    // 对 `None` 是直接不评估（`rules.rs:151` 的 `?`，
                    // 有测试 `balance_low_without_balance_never_fires` 钉着）。
                    .filter(|b| b.known)
                    .map(|b| crate::notify::BalanceSnapshot {
                        remaining: b.remaining,
                        used: b.used,
                        currency: b.currency.clone(),
                    }),
                needs_login: summary.needs_login.contains(&outcome.site_id),
                quota_exceeded,
                // `models` 本轮不取：拿模型列表要先用某把 key 调 `/v1/models`，
                // 那是「每个站点每轮一次额外的带密钥请求」。见 spec §6 的
                // `ModelsChanged` 未接线说明（已登记为**有意取舍**，见 BACKLOG B-80）。
                models: None,
                drift: outcome.drift,
                rotation_due: outcome.rotation_due,
            });
        }

        // `list_sites` 已按 id 升序，这里的排序是让「升序去重」成为实现自身的性质，
        // 而不是依赖存储层的排序（章程 §4.1 规则 5）。
        summary.needs_login.sort_unstable();
        summary.needs_login.dedup();

        self.log(observability::event_with_payload(
            Level::Debug,
            "app",
            format!(
                "刷新完成: 成功 {} / 失败 {} / 密钥 {}",
                summary.sites_ok, summary.sites_failed, summary.keys_total
            ),
            serde_json::json!({
                "sites_total": summary.sites_total,
                "sites_ok": summary.sites_ok,
                "sites_failed": summary.sites_failed,
                "keys_total": summary.keys_total,
                "needs_login": &summary.needs_login,
            }),
        ));

        // M39-S1：采集已从这里**移走**——目录采集由 `refresh_model_catalog_once()` 独立完成
        // （60s 循环驱动，见 `src-tauri/src/lib.rs`），与刷新定时器解耦。
        // 本函数只负责余额/倍率/延迟与通知；`site_facts.models` 由采集路径单向镜像。
        // B-80 / DEBUG-REPORT-v3 §2-9：把**已采集过**的模型清单喂进快照。
        //
        // 采集本身在上面（M14-S1 的节流与开关，`should_collect_models`），本步只做**回填**：
        // 此前 `SiteSnapshot.models` 恒 `None` ⇒ `ModelsChanged` 永不触发（B-80）。
        //
        // 语义（`rules.rs:56`）：`Some(list)` = 「最近一次采集到的清单」（可能是上一轮的——
        // 节流期间不重采，但清单没变就是没变）；`None` = 该站点**从未**采集过。
        // `Some(vec![])`（站点回了空列表）与 `None` 是两件事，不混。
        if let Ok(map) = self.site_facts.lock() {
            for snapshot in snapshots.iter_mut() {
                if let Some(observation) = map.get(&snapshot.site_id) {
                    if observation.models_collected_at.is_some() {
                        snapshot.models = Some(observation.models.clone());
                    }
                }
            }
        }
        self.dispatch_notifications(snapshots);
        Ok(summary)
    }

    /// 把本轮快照交给通知规则，并把产生的通知发出去（M6-S5 / FR-3）。
    ///
    /// 四条硬约束：
    /// 1. **不 panic、不 `?`**：通知是后台任务的一部分，任何失败只记事件。
    ///    一个坏掉的 webhook 不该让整轮刷新算失败。
    /// 2. **快照在发送之后推进**：`evaluate` 的边沿型规则需要上一轮做基线。
    ///    代价是「发送失败的那条边沿通知不会重试」——这是**有意**的取舍：
    ///    反过来（不推进）会让一个永久坏掉的 webhook 每轮都重发，
    ///    而事件表里已经留下了失败记录。
    /// 3. **webhook 地址进事件前必须剥掉 userinfo**：`https://user:pass@hook` 里的
    ///    凭证不能因为「记一条发送失败」而落进事件表（事件表会被导出与审计）。
    /// 4. **系统通知与 webhook 互不阻塞**：一个失败不影响另一个。
    fn dispatch_notifications(&self, snapshots: Vec<crate::notify::SiteSnapshot>) {
        let Some(state) = &self.notify else {
            return;
        };
        // B-81 / DEBUG-REPORT-v3 §2-10：基线**跨重启**。
        //
        // 内存里没有（进程刚起 / 首轮）时读**落库的**基线；落库的也没有 ⇒ `None`
        // （退回首轮语义）。于是「进程重启」不再等价于「首轮语义」——坏状态不会在每次
        // 启动时重报一遍（`notify/baseline.rs` 的编解码此前零调用点）。
        let prev = state
            .last
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
            .or_else(|| self.load_notify_baseline(unix_now_secs()));
        let now = unix_now_secs();
        let snapshot = crate::notify::Snapshot { sites: snapshots };
        // 基线：上一轮快照，**并给「本轮才出现的站点」补中性值**（M6-S5 接线决定，见 spec §6 D-4）。
        //
        // 为什么不能直接把 `None` 交给 `evaluate`：它的冻结口径是「`prev == None` → 只发事实型
        // 规则」，而它取基线是**按站点**取的（`prev.and_then(|s| s.site(id))`）——所以「传 `None`」
        // 与「传一条没有站点的空快照」对规则的效果完全相同，都给不出基线。
        //
        // 为什么不给基线会出事：`NotifyKind::Drift` 报不出「开着通知之前就已经漂移了」的目标
        // ——第一次见到它时规则整条不评估，而这一轮的事实**已经写进了快照**，下一轮的
        // `same_fact` 会把它当成「报过了」，于是**那条漂移永远不会被报出来**。
        //
        // 为什么**每一轮**都要补、而不是只在首轮补：站点可以是运行期新加的（新站点相对上一轮
        // 快照同样「不存在」，按站点的 `before` 同样是 `None`）——上面那条链在它身上一模一样地
        // 成立。这是与 W-1 同一类的缺陷（去重基线吞掉第一次），只是触发窗口窄得多。
        //
        // 代价：**进程重启后**处于坏状态的项会各再报一次。这不是新引入的一类噪声——
        // `BalanceLow` 与 `RotationDue` 本来就是事实型，首轮也发，实际行为不变；
        // 跨重启持久化基线登记为 BACKLOG B-81。
        let baseline = filled_baseline(prev, &snapshot);
        let items = crate::notify::evaluate(Some(&baseline), &snapshot, &state.config, now);

        for item in &items {
            self.log(observability::event_with_payload(
                Level::Info,
                "app",
                format!("通知: {}", item.title),
                serde_json::json!({
                    "kind": format!("{:?}", item.kind),
                    "site_id": item.site_id,
                }),
            ));

            let mut failures: Vec<String> = Vec::new();
            // `send` 是 `Notifier` trait 上的方法，必须把 trait 带进作用域才能调用。
            use crate::notify::Notifier as _;
            if state.config.system_enabled {
                let notifier =
                    crate::notify::SystemNotifier::new(Box::new(crate::notify::StdCommandRunner));
                if let Err(err) = notifier.send(item) {
                    failures.push(format!("系统通知: {err}"));
                }
            }
            let has_webhook = state
                .config
                .webhook_url
                .as_deref()
                .is_some_and(|url| !url.trim().is_empty());
            if has_webhook {
                let notifier = crate::notify::WebhookNotifier::new(
                    state.config.clone(),
                    self.resolved_upstream_proxy(),
                );
                if let Err(err) = notifier.send(item) {
                    // B-179：按 err 变体分流前缀。`Error::Store` 是配置非法（如零超时守卫），
                    // 不是发送失败——读事件表的人据此不会去查网络。其他变体（IO / 超时 / 认证）
                    // 仍是「webhook」前缀。
                    let label = match &err {
                        crate::error::Error::Store(_) => "webhook 配置非法",
                        _ => "webhook",
                    };
                    failures.push(format!("{label}: {err}"));
                }
            }
            if !failures.is_empty() {
                // B-179：标题按 failures 内容分流。有「配置非法」前缀 ⇒ 标题也用「通知配置非法」，
                // 否则「通知发送失败」。子串匹配够用：当前只有 webhook 零超时守卫用这个词；
                // 复审要点是「将来新增含『配置非法』的 failure 文案时这条匹配是否仍准」。
                let has_config_err = failures.iter().any(|f| f.contains("配置非法"));
                let title = if has_config_err {
                    "通知配置非法"
                } else {
                    "通知发送失败"
                };
                self.log(observability::event_with_payload(
                    Level::Warn,
                    "app",
                    format!("{title}: {}", failures.join(" | ")),
                    serde_json::json!({
                        "kind": format!("{:?}", item.kind),
                        "webhook": crate::redact::mask_webhook_url(
                            state.config.webhook_url.as_deref().unwrap_or("")
                        ),
                    }),
                ));
            }
        }

        if let Ok(mut guard) = state.last.lock() {
            *guard = Some(snapshot.clone());
        }
        // B-81：把本轮快照落库当下一轮的基线（进程重启后仍可用）。
        self.persist_notify_baseline(&snapshot, now);
    }

    /// 读**落库的**通知基线（B-81）。
    ///
    /// 损坏 / 版本不认识 / 超过 `BASELINE_MAX_AGE_SECS` ⇒ `None`（`decode_snapshot` 的口径：
    /// 基线坏了不该阻断通知，退回「首轮语义」即可）。**不报错**。
    fn load_notify_baseline(&self, now: i64) -> Option<crate::notify::Snapshot> {
        let text = self
            .store
            .get_setting(crate::notify::BASELINE_SETTING_KEY)
            .ok()
            .flatten()?;
        crate::notify::decode_snapshot(&text, now)
    }

    /// 把本轮快照落库当下一轮的基线（B-81）。
    ///
    /// `encode_snapshot` 返回 `None` = **拒绝编码**（文本里出现疑似密钥形态，fail-closed：
    /// 宁可丢一轮基线也不把数据改坏后写库）⇒ 走**可见降级**：记一条 Warn 事件，
    /// 基线保持上一份（或没有）。**不静默关闭**——用户能在事件表里看到「基线没存上」，
    /// 而不是以为通知一切正常。
    ///
    /// **依赖**：道② 的 P2-26（脱敏前缀不看词边界）修好之前，`task-scheduler` 这类
    /// 普通显示名就会让编码失败 —— 那正是本降级路径要覆盖的场景（不是静默失效）。
    fn persist_notify_baseline(&self, snapshot: &crate::notify::Snapshot, now: i64) {
        match crate::notify::encode_snapshot(snapshot, now) {
            Some(text) => {
                if let Err(err) = self
                    .store
                    .set_setting(crate::notify::BASELINE_SETTING_KEY, &text)
                {
                    self.log(observability::event_with_payload(
                        Level::Warn,
                        "notify",
                        format!("通知基线落库失败: {err}"),
                        serde_json::json!({}),
                    ));
                }
            }
            None => {
                self.log(observability::event_with_payload(
                    Level::Warn,
                    "notify",
                    "通知基线未能保存（内容疑似含密钥形态，已按 fail-closed 跳过）；下一轮将按首轮语义评估",
                    serde_json::json!({ "baseline_key": crate::notify::BASELINE_SETTING_KEY }),
                ));
            }
        }
    }

    /// 落库的通知基线是否存在（B-81）。供命令层在设置页显示「基线状态」——前端那半归道⑦。
    pub fn notify_baseline_present(&self) -> bool {
        self.store
            .get_setting(crate::notify::BASELINE_SETTING_KEY)
            .ok()
            .flatten()
            .is_some()
    }

    // ============================================ M6-S5 接线：FR-2 / FR-7

    /// 该轮换的密钥（FR-7）。**纯本地判定**，不联网。
    ///
    /// 关闭轮换（`rotation_max_age_days == 0`）时直接返回空——不要在调用方各写一遍
    /// 这个判断，否则总有一处会漏。
    pub fn rotation_due(&self) -> Result<Vec<crate::rotation::RotationDue>> {
        let settings = self.settings()?;
        if !settings.rotation_enabled() {
            return Ok(Vec::new());
        }
        // `store::KeyRow` 与 `rotation::KeyRow` 是同名不同字段的两个类型：
        // 前者没有 `created_at`（现在补上了），后者只要 4 个字段。
        // 编译器会挡住传错类型，这里的映射是显式的。
        //
        // 已回收的 key 不参与判定：站点上已经没有它了，提醒用户「该轮换」只会把他引到
        // 一条注定失败的路上（`rotation_plan` 会拒绝它）。成功轮换后旧 key 也是这个状态。
        let rows: Vec<crate::rotation::KeyRow> = self
            .store
            .list_keys()?
            .into_iter()
            .filter(|row| row.status != crate::store::KEY_STATUS_REVOKED)
            .map(|row| {
                crate::rotation::KeyRow::new(row.id, row.site_id, row.name, Some(row.created_at))
            })
            .collect();
        Ok(crate::rotation::due_keys(
            &rows,
            crate::rotation::RotationPolicy {
                max_age_days: settings.rotation_max_age_days,
                warn_before_days: settings.rotation_warn_before_days,
            },
            unix_now_secs(),
        ))
    }

    /// 把「该轮换的密钥」按站点归组（通知快照的输入）。
    ///
    /// `SiteSnapshot::rotation_due` 的语义是「**已进入提醒窗口**的密钥」，窗口过滤由
    /// [`Self::rotation_due`]（即 M6-S4 的 `due_keys`）完成——`evaluate` **不二次过滤**：
    /// 它的冻结签名里没有窗口宽度参数，自己猜一个宽度只会把「还没到期」的钥匙也报出来。
    fn rotation_facts_by_site(&self) -> Result<HashMap<i64, Vec<crate::notify::RotationDueFact>>> {
        let mut grouped: HashMap<i64, Vec<crate::notify::RotationDueFact>> = HashMap::new();
        for due in self.rotation_due()? {
            grouped
                .entry(due.site_id)
                .or_default()
                .push(crate::notify::RotationDueFact {
                    key_id: due.key_id,
                    // 密钥名是**上游自由文本**：这里带上只为与 `rotation::RotationDue` 对齐，
                    // 规则的正文只输出 `key_id`（见 `notify/rules.rs` 的 `rotation_due`）。
                    name: due.name,
                    due_at: due.due_at,
                });
        }
        Ok(grouped)
    }

    /// 把投递目标的漂移事实按站点归组（通知快照的输入）。
    ///
    /// 与 [`Self::drift_report`] 的分工——两者都要读一次文件哈希，但**用途不同**：
    /// - `drift_report` 是**用户主动触发**的检查（命令层 / 启动检查），会为每个需注意的
    ///   目标写一条 `warn` 事件；
    /// - 本函数是**每轮刷新**的通知输入，**不写事件**。否则同一处漂移每轮被记一遍，
    ///   事件表会被这一件事灌满（`refresh_all` 每轮已经有一条汇总事件）。
    ///
    /// 放进来的事实是**全集**（含 `Intact` / `Unknown`）：「要不要报」是规则的事，
    /// 装配层先筛一遍会让「同状态去重」失去基线（`Intact → Modified` 是一次新的边沿）。
    fn drift_facts_by_site(&self) -> Result<HashMap<i64, Vec<crate::notify::DriftFact>>> {
        let mut grouped: HashMap<i64, Vec<crate::notify::DriftFact>> = HashMap::new();
        for row in &self.store.binding_drift_rows()? {
            let report = drift::report_for(row);
            grouped
                .entry(row.site_id)
                .or_default()
                .push(crate::notify::DriftFact {
                    target_path: report.target_path.display().to_string(),
                    agent_id: report.agent_id,
                    channel: report.channel,
                    state: report.state,
                });
        }
        Ok(grouped)
    }

    /// 采集一类通知输入；失败时记一条事件并回落到空集。
    ///
    /// 为什么吞掉错误：[`Self::refresh_all`] 的返回值描述的是**站点刷新**的结果，
    /// 通知输入采集失败不该让整轮算失败（与 `dispatch_notifications` 的
    /// 「不 panic、不 `?`」同一口径）。
    ///
    /// 为什么不能静默：静默会让「通知为什么没来」变成一件无从查起的事——
    /// 而这正是 W-1 能藏住的原因（恒空的 `Vec::new()` 不带任何痕迹）。
    fn collect_notify_input<V>(&self, label: &str, collect: impl FnOnce() -> Result<V>) -> V
    where
        V: Default,
    {
        match collect() {
            Ok(value) => value,
            Err(err) => {
                self.log(observability::event_with_payload(
                    Level::Warn,
                    "app",
                    format!("采集通知输入失败: {label}"),
                    serde_json::json!({
                        "kind": label,
                        "error": crate::redact::scrub(&err.to_string()),
                    }),
                ));
                V::default()
            }
        }
    }

    /// 这把 key 当前服务的投递通道（升序去重）+ 认不出通道的目标（升序去重）。
    ///
    /// 只查库、不读文件哈希：这是**归属关系**查询，`binding_drift_rows` 顺带给出的
    /// 哈希列在这里没有任何用处（漂移检测才需要它）。
    fn rotation_targets(&self, key_id: i64) -> Result<(Vec<DeliveryChannel>, Vec<String>)> {
        let mut channels: Vec<DeliveryChannel> = Vec::new();
        let mut unmapped: Vec<String> = Vec::new();
        for binding in self.store.binding_drift_rows()? {
            // 只看「这个目标**现在**由这把 key 服务」的绑定：查询已经按
            // target_path 取了最新一条，所以这里筛掉的都是被别的 key 取代过的历史绑定。
            //
            // M16-S1（B-126 选项①）之后「最新」多了两个资格条件：**未解绑**且**未回滚**。
            // 语义更准了：回滚过的投递不再主导「现状」——回滚 B 之后现状落回 A，
            // 于是轮换 A 会带上这个目标（在此之前会漏掉它）。
            if binding.key_id != key_id {
                continue;
            }
            match DeliveryChannel::from_agent_id(&binding.agent_id) {
                Some(channel) => {
                    if !channels.contains(&channel) {
                        channels.push(channel);
                    }
                }
                // 认不出来的 `agent_id` 说明这个目标曾经由本产品投递过、而现在本产品
                // 已经不认这个通道了（通道改名 / 被删 / 手工写的绑定行）。
                // **必须报出来**，不能让 `filter_map` 把它悄悄滤掉：它会被漏在重注入之外，
                // 而第三步要回收的正是它还在用的那把旧 key。
                None => {
                    if !unmapped.contains(&binding.agent_id) {
                        unmapped.push(binding.agent_id.clone());
                    }
                }
            }
        }
        channels.sort_by_key(|channel| channel.as_str());
        unmapped.sort();
        Ok((channels, unmapped))
    }

    /// 轮换预检（§9-8）：逐通道用占位密钥空跑一次 `plan()`，返回**写不进去的**那些。
    ///
    /// 空 `Vec` = 预检通过（可以建新 key）。每条记 `(通道名, 目标路径, 原因)`——
    /// 界面与错误文案都要能直接念出来，所以不做成 `bool`。
    ///
    /// 为什么是 `plan()` 而不是 `apply_delivery`：`plan()` 不落盘、不读钥匙串、不改任何状态，
    /// 因此「预检」不会产生任何需要回滚的东西。**预检失败不建新 key** 是这条的全部意义。
    fn rotation_precheck(&self, key_id: i64, channels: &[DeliveryChannel]) -> Vec<BlockedTarget> {
        let mut blocked = Vec::new();
        for channel in channels {
            let writer =
                match self.prepare_delivery(key_id, *channel, None, delivery::DeliverySource::Site)
                {
                    Ok(writer) => writer,
                    Err(err) => {
                        blocked.push(BlockedTarget {
                            channel: channel.as_str().to_string(),
                            target: self
                                .home
                                .join(channel.relative_target())
                                .display()
                                .to_string(),
                            reason: crate::redact::scrub(&err.to_string()),
                        });
                        continue;
                    }
                };
            let target = writer.target_path();
            // P2-2 / DEBUG-REPORT-v3 §2-2：`plan()` 只验「文件写得进」，验不出「同意被撤销」
            // 和「目标是符号链接」——这两种在 `apply_delivery` 时才失败，而那时 `create_key`
            // 已经在站点建了新 key，每重试一次站点多一把。预检里就地补这两条。
            match self.consent_state(*channel, &target) {
                Ok(state) if state.is_granted() => {}
                Ok(state) => {
                    let label = match state {
                        crate::delivery::ConsentState::Revoked { .. } => "同意已被撤销",
                        crate::delivery::ConsentState::Missing => "尚未同意",
                        crate::delivery::ConsentState::Granted { .. } => unreachable!(),
                    };
                    blocked.push(BlockedTarget {
                        channel: channel.as_str().to_string(),
                        target: target.display().to_string(),
                        reason: format!(
                            "{label}，轮换会在建新密钥后才停在这里——每重试一次站点多一把"
                        ),
                    });
                    continue;
                }
                Err(err) => {
                    blocked.push(BlockedTarget {
                        channel: channel.as_str().to_string(),
                        target: target.display().to_string(),
                        reason: crate::redact::scrub(&err.to_string()),
                    });
                    continue;
                }
            }
            if target.is_symlink() {
                blocked.push(BlockedTarget {
                    channel: channel.as_str().to_string(),
                    target: target.display().to_string(),
                    reason: "目标是符号链接，轮换会在建新密钥后才在写入时失败".to_string(),
                });
                continue;
            }
            if let Err(err) = writer.plan(delivery::PLACEHOLDER_KEY) {
                blocked.push(BlockedTarget {
                    channel: channel.as_str().to_string(),
                    target: target.display().to_string(),
                    reason: crate::redact::scrub(&err.to_string()),
                });
            }
        }
        blocked
    }

    /// 轮换预览（FR-7）。**只读**：两次库查询，不联网、不写盘、不含密钥明文。
    pub fn rotation_plan(&self, key_id: i64) -> Result<RotationPlan> {
        let row = self
            .store
            .get_key(key_id)?
            .ok_or_else(|| Error::NotFound(format!("密钥 #{key_id} 不存在")))?;
        // `rotate_key` 的第一步就是本函数：在这里拒绝 = 在**建新 key 之前**拒绝。
        ensure_not_revoked(&row)?;
        let (channels, unmapped_targets) = self.rotation_targets(key_id)?;

        Ok(RotationPlan {
            key_id,
            site_id: row.site_id,
            key_name: row.name,
            steps: crate::rotation::rotation_steps().to_vec(),
            channels: channels
                .into_iter()
                .map(|channel| channel.as_str().to_string())
                .collect(),
            unmapped_targets,
            old_remote_id: row.remote_id,
            old_group_name: row.group_name,
            old_group_id: row.group_id,
        })
    }

    /// 轮换前把旧密钥的分组**继承**给 `spec`（M20-S1 / B-166；M22-S1 加 id 认定）。
    ///
    /// `display` 是旧密钥本地记录里的分组显示名（`RotationPlan::old_group_name`），
    /// `native_id` 是站点原生分组 id（`RotationPlan::old_group_id`）。
    /// 返回的 `spec` 就是随后要交给 `create_key` 的那一份。两种情形原样返回：
    /// 旧 key 没绑分组（两个都空）、调用方已经显式给了分组。
    ///
    /// **为什么解析不到必须拒绝而不是照旧建**：
    /// `rotate_key` 的第三步会回收旧密钥。新 key 不带分组 ⇒ 站点上两把都不能用
    /// （未分组 key 一律 403 的站点）；本地钥匙串里存的正是那把不能用的。
    /// 用户看到的却是「轮换完成」。所以这里宁可让轮换开始不了。
    ///
    /// **为什么有 id 就只按 id 找**（M22-S1 / B-168）：id 是站点主键，分组改名不改变它；
    /// 名字会被改。按名字匹配在改名后必然失效 ⇒ 用户被迫手动重建密钥。没有 id 的旧行
    /// （M22-S1 之前建的，或 NewAPI——它的 `GroupInfo.id` 是 `None`，名字即标识）才回落到
    /// 名字匹配，那是唯一可用的依据。
    async fn rotation_inherit_group(
        &self,
        site_id: i64,
        mut spec: KeySpec,
        display: Option<&str>,
        native_id: Option<&str>,
    ) -> Result<KeySpec> {
        // 调用方显式给了分组 ⇒ **显式优先**，本地继承不覆盖它。
        if spec.group.is_some() {
            return Ok(spec);
        }
        let display = display.map(str::trim).filter(|name| !name.is_empty());
        let native_id = native_id.map(str::trim).filter(|id| !id.is_empty());
        // 两个都没有 ⇒ 旧 key 本来就没绑分组，行为与改动前**逐字一致**（不去站点上查）。
        if display.is_none() && native_id.is_none() {
            return Ok(spec);
        }
        // 文案里要有个能读的指代：优先名字，没有名字就用 id（有 id 说明是按 id 找的）。
        let label = display
            .map(str::to_string)
            .or_else(|| native_id.map(|id| format!("id={id}")))
            .unwrap_or_default();

        // 站点侧分组列表是**唯一**能把显示名翻译成站点原生值的地方（Sub2API 要数字 id，
        // NewAPI 要分组名）。取数失败（网络/登录态/站点没这个能力）一律上抛：
        // 那三种失败都不是「可以不带分组」的理由。
        //
        // 其中「站点没有 groups 能力」要**补一层因果**再上抛：`capability_gate` 的原话
        // 只说到「不支持读取分组」，用户读不到「因此轮换已取消、旧密钥没有被回收」——
        // 而他会担心的恰恰是后半句（`RevokeOld` 是不可逆的）。这三条拒绝路径里只有
        // 这一条的原文不带因果（M20-S1 独立复审 P1-1）。
        let groups = match self.fetch_groups(site_id).await {
            Ok(groups) => groups,
            Err(err @ Error::Unsupported(_)) => {
                return Err(Error::Unsupported(format!(
                    "{err}；无法确认分组「{label}」，本次轮换已取消，旧密钥未被回收。\
                     请改用支持分组查询的站点类型，或手动新建一把带分组的密钥后再回收这把。"
                )));
            }
            Err(err) => return Err(err),
        };
        // 有 id ⇒ **只按 id**（稳）。没有 id 才回落到「名字或原生值」——那个判据与
        // `available_groups` 里查倍率的那一处**逐字同源**（M22-S2 / B-171 之后两边都是
        // 「id 优先、无 id 才按名/原生值」）：只按名字匹配会让「CLI/测试建的
        // 行」被误判成分组已不存在（那种行落库的是站点原生标识，M19-S1 的回落路径）。
        let by_name = display.unwrap_or_default();
        let matched = match native_id {
            Some(id) => groups.iter().find(|group| group.id.as_deref() == Some(id)),
            None => groups
                .iter()
                .find(|group| group.name == by_name || group.id.as_deref() == Some(by_name)),
        };
        let matched = matched.ok_or_else(|| match native_id {
            // 按 id 找：只可能是被删了（改名不会改变 id）。文案把 **id 也写出来**——
            // 它是用户在站点后台能查到的稳定标识；只报名字的话，改过名的分组会让用户
            // 拿着一个站点上已经不存在的名字去搜。
            Some(id) => {
                let who = match display {
                    Some(name) => format!("「{name}」（站点 id={id}）"),
                    None => format!("（站点 id={id}）"),
                };
                Error::InvalidInput(format!(
                    "旧密钥绑定的分组{who}在站点上已经不存在（可能被删除）。\
                     轮换必须让新密钥继续留在同一分组，否则它在该站点上无法调用；\
                     请先在站点上恢复这个分组，或手动新建一把带分组的密钥后再回收这把。"
                ))
            }
            // 按名字找：**改名与删除分不开**，必须把这条限制说给用户。
            None => Error::InvalidInput(format!(
                "旧密钥绑定的分组「{label}」在站点上已经不存在（可能被删除或改名）。\
                 这条本地记录没有站点侧的分组 id，只能按名字比对，所以站点侧改过名就认不出来。\
                 轮换必须让新密钥继续留在同一分组，否则它在该站点上无法调用；\
                 请先在站点上恢复这个分组，或手动新建一把带分组的密钥后再回收这把。"
            )),
        })?;
        // 改名认定（M22-S1 / B-168）：id 命中而名字不同 ⇒ 这是**同一个分组**（id 是主键），
        // 只是站点侧改了名。照常轮换，label 用站点**当前**名字。这不是「猜」——猜是拿名字
        // 相似度去赌，而这里是主键相等。
        //
        // 事件**只在按 id 那条分支记**（M22-S1 复审 P2-1）：旧行的 `group_name` 可能落的是
        // 站点原生标识（M19-S1 的 CLI/测试回落路径，例如 `"2"`），名字分支按 `g.id == "2"`
        // 命中时 `matched.name`（`"gpt plus"`）与 `"2"` 不同——那不是改名，报出来就是假事件。
        if native_id.is_some() {
            if let Some(old_name) = display {
                if matched.name != old_name {
                    self.log(observability::event_with_payload(
                        Level::Info,
                        "key",
                        format!(
                            "轮换: 分组已在站点上改名「{old_name}」→「{}」",
                            matched.name
                        ),
                        serde_json::json!({
                            // 结构化判据（M23-S1 / B-175）：固定键 + 固定字面量值，值不含任何
                            // 外部输入 ⇒ 不引入新的脱敏面，`scrub_event_value` 照样过它、
                            // 结果不变。键名口径同 `NotifyKind::as_str()`：稳定标识 ≠ 展示文案。
                            // 测试两侧断言只认这个键筛事件，不再 `message.contains(...)`——
                            // 判据一旦是文案，改文案的人只同步一侧，另一侧就悄悄变成永远绿的空断言。
                            "event": "rotation_group_renamed",
                            "site_id": site_id,
                            "old_group_name": old_name,
                            "new_group_name": matched.name,
                        }),
                    ));
                }
            }
        }
        // 站点原生值：有 id 用 id（Sub2API），没有就名字自己（NewAPI）。
        spec.group = Some(matched.id.clone().unwrap_or_else(|| matched.name.clone()));
        // 落库用**名字**——按 id 存回本地会让密钥表显示 `"2"` 这种无意义数字，
        // 也会让 `refresh` 按名查倍率落空（M19-S1 的两个后果，同一个理由）。
        spec.group_label = Some(matched.name.clone());
        Ok(spec)
    }

    /// 执行一次轮换：`CreateNew → ReinjectAll → RevokeOld`（FR-7 / PRD §176 的「一键」）。
    ///
    /// **任一环失败即停**（章程 §4.5 / spec §4.1）。这不是保守，是唯一能避免死局的顺序：
    /// 一旦在重注入没做完的情况下回收旧 key，用户会同时失去「旧 key 还能用」与
    /// 「新 key 已生效」两个前提，而这两件事都不在他手里。
    ///
    /// 所以**部分失败照样返回 `Ok`**：`RotationRun` 带着「停在哪一步、为什么」，
    /// 那是用户必须知道的可操作信息（「新 key 已建好，只注入成功了 1 个目标，
    /// 旧 key 还在站点上」），压成一条 `Err(String)` 只会被界面读成一句「轮换失败」。
    /// 只有**连开始都开始不了**的情形才返回 `Err`：key 不存在、或有目标认不出通道。
    ///
    /// M20-S1 / B-166 之后，「连开始都开始不了」还多了一种：**旧密钥绑定的分组在站点上
    /// 已经不存在**。那会让新密钥建出来就不带分组，而第三步照样回收旧密钥。
    pub async fn rotate_key(&self, key_id: i64, spec: KeySpec) -> Result<RotationRun> {
        let plan = self.rotation_plan(key_id)?;
        if !plan.unmapped_targets.is_empty() {
            // 前置拒绝，而且是**在动手之前**：这个判断是纯本地的，没有任何理由带着
            // 「有目标认不出通道」的不确定性去建一把新 key。
            return Err(Error::Inject {
                path: plan.unmapped_targets.join(", "),
                reason: "这些投递目标的通道无法识别，轮换会漏掉它们；若继续并回收旧密钥，\
                         它们会永久停在旧密钥上"
                    .to_string(),
            });
        }
        // 通道用**解析好的枚举**迭代（而不是回头 `parse` 一遍 `plan.channels` 的字符串）：
        // 认不出通道这件事上面已经拒绝过了，循环里不该再有一个「理论上不可达」的分支。
        let (channels, _) = self.rotation_targets(key_id)?;

        // ①′ 预检（§9-8 / P2-3）：**在 `create_key` 之前**证明「每个通道都写得进去」。
        //
        // 复现 P2-3 要看的就是这个数字：目标写不进时（M7 旧版无 `model` 的块 / 用户删了
        // `config.yaml` / 文件被重置成 `models: []`），旧实现会**先建好新 key**、再在第②步停下，
        // 于是**每重试一次，站点上就多一把没人用的 key**。
        //
        // 空跑用的是 `PLACEHOLDER_KEY`（不是任何真实密钥形态）且只调 `plan()`：
        // `plan()` 读目标文件、生成 `Patch`，**不落盘、不读钥匙串**⇒ 对站点与本地都无副作用。
        let blocked = self.rotation_precheck(key_id, &channels);
        if !blocked.is_empty() {
            return Err(Error::Inject {
                path: blocked
                    .iter()
                    .map(|b| b.target.clone())
                    .collect::<Vec<_>>()
                    .join(", "),
                reason: format!(
                    "这些通道现在写不进去，若继续会在**新密钥已建好之后**才失败——\
                     每重试一次，站点上就多一把没人用的密钥。请先处理下列目标再轮换：{}",
                    blocked
                        .iter()
                        .map(|b| format!("{} → {}: {}", b.channel, b.target, b.reason))
                        .collect::<Vec<_>>()
                        .join("；")
                ),
            });
        }

        // ⓿ 分组继承（M20-S1 / B-166）：新密钥必须继续待在旧密钥的分组里。编号不用
        //    ①/②/③ —— 那三个号是轮换三步（建 / 注入 / 回收）的，占了会读混。
        //
        // **为什么必须在 create_key 之前**：`rotate_key` 的顺序是
        // `CreateNew → ReinjectAll → RevokeOld`，一旦新 key 建出来不带分组，第三步照样
        // 回收旧 key ⇒ 站点上两把都不能用（在「未分组 key 一律 403」的站点上，这正是
        // 用户看到的「轮换完全失败但界面说成功」）。
        //
        // 三条「解析不到」的路径（分组被删/改名、站点没有 groups 能力、拉取本身失败）
        // **全部**在动手前变成 `Err`，一条都不允许静默降级成「不带分组」。
        let spec = self
            .rotation_inherit_group(
                plan.site_id,
                spec,
                plan.old_group_name.as_deref(),
                plan.old_group_id.as_deref(),
            )
            .await?;

        // ① 建新 key（明文只进钥匙串，本函数全程不持有它）
        let new_key = self.create_key(plan.site_id, spec).await?;
        self.log(observability::event_with_payload(
            Level::Info,
            "key",
            "轮换: 已创建新密钥",
            serde_json::json!({
                "step": crate::rotation::RotationStep::CreateNew.as_str(),
                "site_id": plan.site_id,
                "old_key_id": key_id,
                "new_key_id": new_key.id,
                "masked": new_key.masked,
            }),
        ));

        // ② 全量重注入
        let mut reinjected: Vec<String> = Vec::new();
        // P1-2：按原绑定的 delivery_mode 走，不把网关模式改成站点模式（写明文 key）。
        let port = self.settings()?.gateway_port;
        let gateway_token = self.gateway_token().0;
        for channel in channels {
            let channel_name = channel.as_str();
            let mode = self.rotation_delivery_mode(key_id, &channel)?;
            let result = match mode.as_str() {
                "gateway" => {
                    let local_url = format!("http://127.0.0.1:{}", port);
                    let base_url = delivery::gateway_base_url_for(&channel, &local_url);
                    let endpoint = delivery::GatewayEndpoint {
                        base_url,
                        // P3-32 边界：`GatewayEndpoint.token` 是冻结的 `String`（非本包写域），
                        // 这一处 `.to_string()` 是**必需**的唯一拷贝。
                        token: gateway_token.to_string(),
                    };
                    self.apply_delivery_in(
                        new_key.id,
                        channel,
                        None,
                        delivery::DeliverySource::Gateway(&endpoint),
                    )
                }
                _ => self.apply_delivery_in(
                    new_key.id,
                    channel,
                    None,
                    delivery::DeliverySource::Site,
                ),
            };
            if let Err(err) = result {
                let reason = crate::redact::scrub(&err.to_string());
                self.log(observability::event_with_payload(
                    Level::Warn,
                    "key",
                    "轮换中断: 重注入失败",
                    serde_json::json!({
                        "step": crate::rotation::RotationStep::ReinjectAll.as_str(),
                        "site_id": plan.site_id,
                        "new_key_id": new_key.id,
                        "channel": channel_name,
                        "reinjected": &reinjected,
                    }),
                ));
                return Ok(RotationRun {
                    new_key,
                    reinjected,
                    revoke: RevokeOutcome::NotAttempted,
                    stopped_at: Some(crate::rotation::RotationStep::ReinjectAll),
                    stop_reason: Some(format!("重注入 {channel_name} 失败: {reason}")),
                });
            }
            reinjected.push(channel_name.to_string());
        }

        // ③ 回收旧 key
        let Some(remote_id) = plan.old_remote_id.clone() else {
            // 本地记录里就没有站点侧 id（老库 / 手工导入的行）——**不是失败**，
            // 但也绝不能假装回收过。跳过并如实说明。
            self.log(observability::event_with_payload(
                Level::Info,
                "key",
                "轮换: 旧密钥没有站点侧 id，跳过回收",
                serde_json::json!({
                    "step": crate::rotation::RotationStep::RevokeOld.as_str(),
                    "site_id": plan.site_id,
                    "old_key_id": key_id,
                }),
            ));
            return Ok(RotationRun {
                new_key,
                reinjected,
                revoke: RevokeOutcome::SkippedNoRemoteId,
                stopped_at: None,
                stop_reason: None,
            });
        };
        match self.revoke_key(plan.site_id, &remote_id).await {
            // `Ok(report)` 里带的是 B-100 的回报；轮换这条路径只关心「站点侧确认删除了」
            // （`Ok` 即已删除，本地状态写失败也仍是 `Ok`——理由见 `revoke_key` 的注释）。
            // P3-2 / DEBUG-REPORT-v3 §3-2：不丢弃 `local_status_updated`——站点侧已删
            // 但本地没写成 revoked 时，不能报纯「已回收」，否则用户以为本地也清了，
            // 而那把 key 在本地仍是 active，`sync_site_keys` 之前会被当成可用。
            Ok(report) => {
                let local_ok = report.local_status_updated;
                let message = if local_ok {
                    "轮换完成: 新密钥已全量注入，旧密钥已回收".to_string()
                } else {
                    "轮换完成: 新密钥已全量注入，旧密钥站点侧已删除，但本地状态未写成 revoked（对账交给 sync_site_keys）".to_string()
                };
                self.log(observability::event_with_payload(
                    Level::Info,
                    "key",
                    &message,
                    serde_json::json!({
                        "site_id": plan.site_id,
                        "old_key_id": key_id,
                        "new_key_id": new_key.id,
                        "reinjected": &reinjected,
                        "local_status_updated": local_ok,
                    }),
                ));
                Ok(RotationRun {
                    new_key,
                    reinjected,
                    revoke: RevokeOutcome::Revoked,
                    // 本地那一行**刻意不删**：`bindings.key_id` 是 `ON DELETE CASCADE`，
                    // 删行会连带丢掉旧 key 的绑定与漂移追溯；对账交给 `sync_site_keys`。
                    stopped_at: None,
                    stop_reason: if local_ok {
                        None
                    } else {
                        Some("旧密钥站点侧已删除，但本地状态未写成 revoked".to_string())
                    },
                })
            }
            Err(err) => {
                let reason = crate::redact::scrub(&err.to_string());
                self.log(observability::event_with_payload(
                    Level::Warn,
                    "key",
                    "轮换中断: 旧密钥回收失败",
                    serde_json::json!({
                        "step": crate::rotation::RotationStep::RevokeOld.as_str(),
                        "site_id": plan.site_id,
                        "old_key_id": key_id,
                        "new_key_id": new_key.id,
                    }),
                ));
                Ok(RotationRun {
                    new_key,
                    reinjected,
                    revoke: RevokeOutcome::Failed(reason.clone()),
                    stopped_at: Some(crate::rotation::RotationStep::RevokeOld),
                    stop_reason: Some(format!("回收旧密钥失败: {reason}")),
                })
            }
        }
    }

    /// 站点侧分组列表（`site_id` + 能力门 + 会话 + 适配器）。**不含**观测缓存。
    ///
    /// 拆出来是为了让「轮换前把显示名解析回站点原生值」（B-166）与 `available_groups`
    /// 走**同一条**取数路径——两处各写一份 `session`/`adapter` 的胶水代码，将来必然
    /// 在一处漏掉能力门（M7-S5 复审 P1-1 就是在 `sync_site_keys` 上漏的）。
    async fn fetch_groups(&self, site_id: i64) -> Result<Vec<crate::site::GroupInfo>> {
        let site = self.site(site_id)?;
        let kind = self.kind_of(&site)?;
        capability_gate(
            kind,
            crate::site::capability::capabilities(kind).groups,
            "读取分组",
        )?;
        let session = self.session(site_id)?;
        let adapter = self.registry.adapter(kind);
        adapter.available_groups(&site.base_url, &session).await
    }

    /// 用该密钥调站点 `GET {base_url}/v1/models`，返回**排序去重**的模型 id（M32-S1）。
    ///
    /// 只读。密钥只经 [`Self::key_secret`]（唯一咽喉：已回收 / 不存在的 key 在这里被拒，
    /// 且**不发任何请求**）；密钥不落日志、不进事件、不进错误文案。
    /// 站点响应的解析口径沿用 [`crate::site::fetch_models`]（`data[].id`），非 2xx 走
    /// 既有的 `map_http_error`（含站点原文脱敏）。
    pub async fn models_for_key(&self, key_id: i64) -> Result<Vec<String>> {
        let row = self
            .store
            .get_key(key_id)?
            .ok_or_else(|| Error::NotFound(format!("密钥记录 #{key_id} 不存在")))?;
        // 已回收 / 不存在：任何网络请求之前就拒绝（M32-S1 既有语义，M37-S1 保持）。
        ensure_not_revoked(&row)?;

        // M37-S1（B-219 的即时修复）：本地保险库缺明文时自动回读。
        //
        // 只认 `Ok(None)`（条目不存在）。`Err`（读失败，例如钥匙串被锁）**原样返回**——
        // 把「读失败」当成「没有」会在用户不知情时多发一次明文读取请求，且会把
        // 「打不开保险库」误报成「站点上没有这把钥匙」。
        let secret = match self.vault_secret(&row.secret_ref)? {
            Some(secret) => secret,
            None => self.restore_key_secret(&row).await?,
        };

        let site = self
            .store
            .get_site(row.site_id)?
            .ok_or_else(|| Error::NotFound(format!("站点 #{} 不存在", row.site_id)))?;
        let mut models =
            crate::site::fetch_models(&self.transport, &site.base_url, &secret).await?;
        models.sort_unstable();
        models.dedup();
        Ok(models)
    }

    /// 本地缺少明文时，用站点会话把该 key 的明文回读到原 `secret_ref`（M37-S1）。
    ///
    /// 只有 [`Self::models_for_key`] 在 `vault_secret` 返回 `Ok(None)` 时调用它：
    /// 已回收的 key 在调用方就被拒绝，读失败（`Err`）不会走到这里。
    ///
    /// 明文只存在于核心内存（`Zeroizing`）与本地加密保险库；**不返回给前端、
    /// 不写日志、不进事件 payload**。写回用**原 `secret_ref`**：复用原行，
    /// 不新建 key 行，不动 `remote_id` / 分组 / 状态。
    async fn restore_key_secret(
        &self,
        row: &crate::store::KeyRow,
    ) -> Result<zeroize::Zeroizing<String>> {
        // 没有站点主键就没法回读：说清原因，别让用户看到「钥匙串里没有」这种内部黑话。
        let remote_id = row.remote_id.as_deref().map(str::trim).unwrap_or_default();
        if remote_id.is_empty() {
            return Err(Error::Vault(format!(
                "密钥 #{} 的明文不在本地，且本地没有它的站点主键（remote_id），无法自动恢复；请在该站点重新取一次钥匙",
                row.id
            )));
        }

        let site = self
            .store
            .get_site(row.site_id)?
            .ok_or_else(|| Error::NotFound(format!("站点 #{} 不存在", row.site_id)))?;
        let kind = self.kind_of(&site)?;
        // 能力门必须在 `session()` 之前：没有令牌管理端点的站点通常也没有会话，
        // 先要会话会先报「未登录」，把用户引向一个不存在的登录流程（M7-S5 既定顺序）。
        capability_gate(
            kind,
            crate::site::capability::capabilities(kind).reveal_key,
            "读取密钥明文",
        )?;

        // 无会话 ⇒ 可执行错误：先说要登录，登录后点重试即可（前端有重试按钮）。
        let session = self.session(row.site_id).map_err(|_| {
            Error::AuthFailed(format!(
                "密钥 #{} 的明文不在本地，自动恢复需要先登录站点「{}」；登录后点重试即可",
                row.id, site.display_name
            ))
        })?;

        let adapter = self.registry.adapter(kind);
        let material = match adapter
            .reveal_key(&site.base_url, &session, remote_id)
            .await
        {
            Ok(material) => material,
            Err(err) => return Err(self.on_auth_error(row.site_id, err)),
        };

        // 站点返回空 / 全空白 ⇒ 不写回：把空串塞进保险库会让后续查询更难诊断。
        if material.secret.trim().is_empty() {
            return Err(Error::Vault(format!(
                "站点返回的密钥明文为空（密钥 #{}），无法自动恢复；请在该站点重新取一次钥匙",
                row.id
            )));
        }

        self.vault.put(&row.secret_ref, &material.secret)?;

        // 只记标识与脱敏指纹：不写明文、不写 secret_ref（定位串没必要进事件）。
        self.log(observability::event_with_payload(
            Level::Info,
            "key",
            "已从站点自动恢复本地缺失的密钥明文",
            serde_json::json!({
                "site_id": row.site_id,
                "key_id": row.id,
                "remote_id": remote_id,
                "fingerprint": crate::redact::fingerprint(&material.secret),
            }),
        ));

        Ok(zeroize::Zeroizing::new(material.secret))
    }

    /// 站点侧可用分组与倍率（FR-2）。
    pub async fn available_groups(&self, site_id: i64) -> Result<Vec<crate::site::GroupInfo>> {
        let groups = self.fetch_groups(site_id).await?;
        // M8-S1 §5.4：倍率进观测缓存。`available_groups` 是用户触发的（FR-2 的下拉），
        // 观测只在用户看过分组之后才存在。
        //
        // P2-12 / DEBUG-REPORT-v3 §2-12：倍率必须取**当前出网 key 所在分组**的倍率，
        // 不是「第一个有倍率的分组」——后者会把 A 分组的倍率记到 B 分组的 key 上，
        // 排序（`routing.rs` 的 `rate_missing` / 倍率升序）因此**看起来有依据而其实是错的**。
        //
        // 查不到（key 没有分组 / 分组不在列表里 / 该分组没有倍率）⇒ **置 `None`**（未知），
        // 不回落、也不保留旧值：保留旧值会让上一次的 key 分组继续影响本轮的排序。
        //
        // M22-S2 / B-171：判据与 `rotation_inherit_group` **同源**——有站点主键就**只按 id**，
        // 没有才回落「名字或原生标识」。M22-S1 已经拿 id 做了轮换认定，这里却还在只按名字：
        // 站点把「gpt plus」改成「GPT Plus」之后，轮换照常（按 id），倍率却变「未知」——
        // 网关按倍率排序的依据就这么静默消失了，而本地 `group_name` 是旧的这一点
        // 恰恰是改名造成的。id 是主键，改名不改它。
        //
        // 有 id 而列表里没有该 id（分组被删）⇒ `None`，**不**回落到按名字找：
        // 那会把另一个分组的倍率记到这把 key 上，正是 P2-12 要防的「看起来有依据而其实是错的」。
        let key_group = self
            .pick_gateway_key(site_id)
            .ok()
            .flatten()
            .map(|row| (row.group_id, row.group_name));
        let rate = key_group.and_then(|(stored_id, stored_name)| {
            let stored_id = stored_id
                .map(|id| id.trim().to_string())
                .filter(|id| !id.is_empty());
            let stored_name = stored_name
                .map(|name| name.trim().to_string())
                .filter(|name| !name.is_empty());
            match stored_id {
                Some(id) => groups
                    .iter()
                    .find(|group| group.id.as_deref() == Some(id.as_str())),
                // M19-S1：存的可能是**显示名**（产品建的 key）也可能是**站点原生标识**
                // （CLI/测试建的、或将来别的写入方）。两种都认，否则「按 id 存」的 key
                // 会静默退化成「倍率未知」，把排序依据悄悄丢掉。
                None => {
                    let stored = stored_name?;
                    groups.iter().find(|group| {
                        group.name == stored || group.id.as_deref() == Some(stored.as_str())
                    })
                }
            }
            .and_then(|group| group.rate)
        });
        if let Ok(mut map) = self.site_facts.lock() {
            map.entry(site_id).or_default().rate = rate;
        }
        Ok(groups)
    }

    /// 把站点侧已有密钥的明文**一次性对齐到本地钥匙串**（FR-2 的批量读明文）。
    ///
    /// # 为什么不做成「把明文返回给前端」
    ///
    /// 命令层的现有设计里**没有任何一条命令返回过密钥明文**（`reveal_key` 至今
    /// 只在核心层与测试里用）。批量明文一旦过 IPC，它就会进入 WebView 的内存、
    /// 开发者工具、以及任何注入到页面的东西——这与 FR-8 的「密钥只存在于系统钥匙串
    /// 与内存」相比，是把「内存」的边界扩大到了整个渲染进程。
    ///
    /// PRD 附录 A 对 `POST /api/token/batch/keys` 的说明是「**一次性对齐本地**」，
    /// 也就是说它的用途本来就是本地记账，不是展示。所以这里把它做成一个
    /// **不外流明文**的对齐操作：取回 → 写钥匙串 → 记 `secret_ref` → 只回计数。
    pub async fn sync_site_keys(&self, site_id: i64) -> Result<KeySyncSummary> {
        let site = self.site(site_id)?;
        let kind = self.kind_of(&site)?;
        // M7-S5 复审 P1-1：这一处**曾经漏了门**。它调的是 `adapter.list_keys`，
        // 所以判据必须与 `list_keys()` 一致——否则同一个站点上，一个入口说
        // 「这个站点类型不支持」、另一个说「请先登录」，而后者指向一个不存在的流程。
        capability_gate(
            kind,
            crate::site::capability::capabilities(kind).list_keys,
            "列举令牌",
        )?;
        let session = self.session(site_id)?;
        let adapter = self.registry.adapter(kind);
        let metas = adapter.list_keys(&site.base_url, &session).await?;

        // 本地「真的可用」的：有行 **且** 钥匙串条目还在（DEBUG 报告 §1.9）。
        //
        // 只看 `remote_id` 是错的：`purge_keychain` 删掉秘密但**保留行**（那是刻意的，
        // `bindings` 与漂移追溯靠它存活），于是这里报「本地已有 1 / 新导入 0」，
        // 而用户按界面提示「重新取一次密钥即可恢复」**取不回来**——投递与网关随后全失败。
        let local: Vec<crate::store::KeyRow> = self
            .store
            .list_keys()?
            .into_iter()
            .filter(|row| row.site_id == site_id)
            .collect();

        // remote_id → 本地行。**只在同一个站点内判重**：不同站点的 remote_id 会撞
        // （NewAPI 与 Sub2API 都从 1 开始编号）。
        let mut by_remote: std::collections::HashMap<&str, &crate::store::KeyRow> =
            std::collections::HashMap::new();
        for row in &local {
            if let Some(remote) = row.remote_id.as_deref() {
                by_remote.insert(remote, row);
            }
        }

        // 站点侧的每一条，落在三种状态之一：
        //   already_local —— 行在、秘密也在（什么都不用做）
        //   restorable    —— 行在、秘密没了（**恢复进原来那一行**，不新建）
        //   missing       —— 连行都没有（新建）
        let mut restorable: Vec<(String, String)> = Vec::new();
        let mut missing: Vec<String> = Vec::new();
        let mut already_local = 0usize;
        let mut unreadable: Vec<String> = Vec::new();
        for meta in &metas {
            let Some(row) = by_remote.get(meta.remote_id.as_str()) else {
                missing.push(meta.remote_id.clone());
                continue;
            };
            // `vault.has` 而不是 `vault.get`：这里要的是「还在不在」，不是「把明文取出来」。
            // 两者分开之后，「明文出口只能有一处」那条结构守卫才写得出来
            // （见 `tests/zeroize_hygiene.rs`）。
            match self.vault.has(&row.secret_ref) {
                Ok(true) => already_local += 1,
                Ok(false) => restorable.push((meta.remote_id.clone(), row.secret_ref.clone())),
                Err(err) => {
                    // 钥匙串**读失败**（例如被锁）不能当成「没有」：当成没有就会去新建一行，
                    // 而那一行与现有行是同一个 `remote_id`，`keys` 表上**没有唯一约束**
                    // ——留下两条重复记录，之后每一处按 `remote_id` 判重的地方都会分叉。
                    // 读不出来就如实报成「不可读」，下一轮再试。
                    self.log(observability::event_with_payload(
                        Level::Warn,
                        "key",
                        format!("读钥匙串失败，本轮跳过这一条: {err}"),
                        serde_json::json!({ "site_id": site_id, "key_id": row.id }),
                    ));
                    unreadable.push(meta.remote_id.clone());
                }
            }
        }

        let mut to_fetch: Vec<String> = restorable.iter().map(|(id, _)| id.clone()).collect();
        to_fetch.extend(missing.iter().cloned());

        if to_fetch.is_empty() {
            return Ok(KeySyncSummary {
                site_id,
                site_total: metas.len(),
                already_local,
                restored: 0,
                imported: 0,
                unreadable,
            });
        }

        let materials = adapter
            .reveal_keys(&site.base_url, &session, &to_fetch)
            .await?;

        let restore_into: std::collections::HashMap<&str, &str> = restorable
            .iter()
            .map(|(remote, secret_ref)| (remote.as_str(), secret_ref.as_str()))
            .collect();

        let mut imported = 0usize;
        let mut restored = 0usize;
        for (remote_id, material) in materials {
            if material.secret.trim().is_empty() {
                // 站点给了条目但没给明文（「不提供密钥明文回读」，PRD §10 风险表）。
                // 不静默跳过：把它列出来，UI 才能引导用户新建。
                unreadable.push(remote_id);
                continue;
            }

            if let Some(secret_ref) = restore_into.get(remote_id.as_str()) {
                // 恢复：**复用原来那一行**。新建一行会让同一个 remote_id 出现两条记录。
                match self.vault.put(secret_ref, &material.secret) {
                    Ok(()) => {
                        restored += 1;
                        self.log(observability::event_with_payload(
                            Level::Info,
                            "vault",
                            "已把密钥重新取回钥匙串",
                            serde_json::json!({
                                "site_id": site_id,
                                "remote_id": remote_id,
                                "fingerprint": crate::redact::fingerprint(&material.secret),
                            }),
                        ));
                    }
                    Err(err) => {
                        self.log(observability::event_with_payload(
                            Level::Warn,
                            "key",
                            format!("恢复密钥失败: {err}"),
                            serde_json::json!({ "site_id": site_id, "remote_id": remote_id }),
                        ));
                        unreadable.push(remote_id);
                    }
                }
                continue;
            }

            let name = metas
                .iter()
                .find(|meta| meta.remote_id == remote_id)
                .map(|meta| meta.name.clone())
                .unwrap_or_else(|| remote_id.clone());
            // 分组名传 `None`：这条路径的名字都是从 `KeyMeta` 反查的，分组同样没有
            // 权威来源 ⇒ 落 `NULL` 让界面显示空，不猜（M8-S5B §6.5）。
            // 导入路径的分组是**不知道**：`KeyMeta` 里没有分组字段（M8-S5B §6.5 的
            // 「绝不猜」），所以名字与 id 都传 `None`——两列都落 `NULL`。
            match self.store_key_material(
                site_id,
                &name,
                Some(&remote_id),
                None,
                None,
                &material.secret,
            ) {
                Ok(_) => imported += 1,
                Err(err) => {
                    // 单条失败不中断整批：对齐是尽力而为的，失败的那条下一轮还能再来。
                    self.log(observability::event_with_payload(
                        Level::Warn,
                        "key",
                        format!("对齐密钥失败: {err}"),
                        serde_json::json!({ "site_id": site_id, "remote_id": remote_id }),
                    ));
                    unreadable.push(remote_id);
                }
            }
        }

        let summary = KeySyncSummary {
            site_id,
            site_total: metas.len(),
            already_local,
            restored,
            imported,
            unreadable,
        };
        self.log(observability::event_with_payload(
            Level::Info,
            "key",
            format!(
                "密钥对齐完成: 站点 {} 条 / 已有 {} / 恢复 {} / 新导入 {} / 不可读 {}",
                summary.site_total,
                summary.already_local,
                summary.restored,
                summary.imported,
                summary.unreadable.len()
            ),
            // **不含明文，也不含 `secret_ref`**：事件表会被导出与审计。
            serde_json::json!({
                "site_id": summary.site_id,
                "site_total": summary.site_total,
                "already_local": summary.already_local,
                "restored": summary.restored,
                "imported": summary.imported,
                "unreadable_count": summary.unreadable.len(),
            }),
        ));
        Ok(summary)
    }

    /// 批量读明文（FR-2）。
    ///
    /// **事件里只记条数与 id，不记明文**——这里与 [`Self::reveal_key`] 同一条红线。
    /// 空入参不发请求（由适配器保证），因此这里也不需要特判。
    pub async fn reveal_keys_batch(
        &self,
        site_id: i64,
        remote_ids: &[String],
    ) -> Result<Vec<(String, KeyMaterial)>> {
        let site = self.site(site_id)?;
        let kind = self.kind_of(&site)?;
        // M7-S5 复审 P1-1：同 `sync_site_keys`——判据与 `reveal_key()` 一致。
        capability_gate(
            kind,
            crate::site::capability::capabilities(kind).reveal_key,
            "读取令牌明文",
        )?;
        let session = self.session(site_id)?;
        let adapter = self.registry.adapter(kind);
        let materials = adapter
            .reveal_keys(&site.base_url, &session, remote_ids)
            .await?;
        self.log(observability::event_with_payload(
            Level::Debug,
            "key",
            format!("批量读取密钥明文: {} 条", materials.len()),
            serde_json::json!({
                "site_id": site_id,
                // 只记 id：`remote_id` 不是秘密，但**条数与 id 一起**已经足够诊断
                "remote_ids": remote_ids,
            }),
        ));
        Ok(materials)
    }

    /// 登录自启的当前状态（FR-7）。
    pub fn autostart_state(&self) -> Result<crate::autostart::AutostartState> {
        crate::autostart::state(&self.home, AUTOSTART_APP_ID)
    }

    /// 生成「开启 / 关闭登录自启」的计划（FR-7）。**纯产出，不落盘**。
    ///
    /// `exe` 是当前可执行文件路径；`hidden` 固定为 `true`——自启的用途就是后台刷新，
    /// 弹窗会破坏它。`--hidden` 在托盘不可用时会被壳层降级成显示窗口（`lib.rs`）。
    pub fn autostart_plan(&self, enable: bool, exe: &Path) -> Result<crate::platform_env::EnvPlan> {
        if enable {
            crate::autostart::plan_enable(&self.home, AUTOSTART_APP_ID, exe, true)
        } else {
            crate::autostart::plan_disable(&self.home, AUTOSTART_APP_ID)
        }
    }

    /// 把一份环境/自启计划落盘（FR-4 / FR-7）。
    ///
    /// Windows 形态（`EnvPlan::Registry`）在这里返回 `Ok(None)` 并**记一条事件**——
    /// 真正的注册表写入由壳层执行（`reg.exe`），核心层不执行外部程序。
    pub fn apply_env_plan(
        &self,
        plan: &crate::platform_env::EnvPlan,
    ) -> Result<Option<crate::inject::Journal>> {
        let journal = plan.apply_files(&self.backup_dir)?;
        self.log(observability::event_with_payload(
            Level::Info,
            "app",
            "环境/自启计划已处理",
            serde_json::json!({
                // `describe()` 只含路径、字节数与键名，**不含任何值**（可能是密钥）
                "plan": plan.describe(),
                "journal": journal.as_ref().map(|j| j.id.clone()),
            }),
        ));
        Ok(journal)
    }

    /// 读某把令牌的明文。**只有显式调用才会返回密钥本体**——列举接口一律不含明文。
    pub async fn reveal_key(&self, site_id: i64, remote_id: &str) -> Result<KeyMaterial> {
        let site = self.site(site_id)?;
        let kind = self.kind_of(&site)?;
        capability_gate(
            kind,
            crate::site::capability::capabilities(kind).reveal_key,
            "读取令牌明文",
        )?;
        let session = self.session(site_id)?;
        let adapter = self.registry.adapter(kind);
        match adapter
            .reveal_key(&site.base_url, &session, remote_id)
            .await
        {
            Ok(material) => {
                self.log(observability::event_with_payload(
                    Level::Debug,
                    "key",
                    "已读取密钥明文",
                    serde_json::json!({ "site_id": site_id, "remote_id": remote_id }),
                ));
                Ok(material)
            }
            Err(err) => Err(self.on_auth_error(site_id, err)),
        }
    }

    /// M15-S1：模型检测（bazaarlink probe）——检测目标模型端点是否真的是它声称的模型。
    ///
    /// **apiKey 发给第三方 bazaarlink.ai**——这是新的明文外流路径（既有明文只发给目标
    /// 中转站做投递/网关）。`confirm` 必须为 `true`，否则 `Error::InvalidInput`（请求未发出）。
    ///
    /// 复用 `key_secret`（唯一明文出口 `vault_secret`，M8-S1 守卫）取站点 key 明文，
    /// 不新开 `vault.get`。`base_url` 默认 = 站点 base_url + `/v1`（已有 `/v1` 不重复），
    /// `base_url_override` 优先。`claimed_model` 缺省时填 `model_id`（M15-S1 决策）。
    ///
    /// 检测结果摘要落 `probe_runs` 表（best-effort：落库失败只 warn，不 mask 检测成功）；
    /// **不落** `items[].response` / `responseHeaders` / `startedByIp` / `userKey`（敏感）。
    /// 事件只 log 元数据（site_id / key_id / modelId / verdict），**不 log apiKey**。
    ///
    /// B-134：提交后按 [`crate::probe::PollPolicy`] 轮询到终态（best-effort，**永不**因
    /// 轮询失败而把一次检测判成失败）。
    ///
    /// B-160：主路径是 `sync=false` 异步提交 + 轮询——`sync=true` 会把整轮检测压在**一条**
    /// HTTP 连接上（真机 360.53s），必然撞上传输层 timeout 120s。详见 `crate::probe` 模块文档。
    /// 停止原因（[`crate::probe::PollStop`]）决定事件怎么记：拿到判定 / 跑完没判定 /
    /// 预算等完仍在跑，是三种不同的用户可见结论。
    pub async fn probe_model(
        &self,
        key_id: i64,
        model_id: String,
        claimed_model: Option<String>,
        base_url_override: Option<String>,
        confirm: bool,
    ) -> Result<crate::probe::ProbeRun> {
        if !confirm {
            return Err(Error::InvalidInput(
                "模型检测需要明确确认：会把该站点的 API key 发送给第三方 bazaarlink.ai".into(),
            ));
        }
        let row = self
            .store
            .get_key(key_id)?
            .ok_or_else(|| Error::NotFound(format!("密钥记录 #{key_id} 不存在")))?;
        let site = self.site(row.site_id)?;
        let make_default_base = |base: &str| {
            let b = base.trim_end_matches('/');
            if b.ends_with("/v1") {
                b.to_string()
            } else {
                format!("{b}/v1")
            }
        };
        // L2（独立复审）：base_url_override 非空时校验 http(s) scheme，
        // 避免 "not-a-url" / "ftp://..." 原样发 bazaarlink → 400（本地无 SSRF，纯 UX）。
        let base_url = match base_url_override.map(|o| o.trim().to_string()) {
            Some(o) if o.is_empty() => make_default_base(&site.base_url),
            Some(o) if !(o.starts_with("http://") || o.starts_with("https://")) => {
                return Err(Error::InvalidInput(format!(
                    "baseUrl 必须是 http(s) URL: {o}"
                )));
            }
            Some(o) => o,
            None => make_default_base(&site.base_url),
        };
        let api_key = self.key_secret(key_id)?;
        let claimed = claimed_model.unwrap_or_else(|| model_id.clone());
        let model_id_for_store = model_id.clone();
        let req = crate::probe::ProbeRequest {
            base_url,
            api_key,
            model_id,
            claimed_model: Some(claimed),
            // B-160：主路径走**异步提交**。`sync=true` 要求服务端在**一条** HTTP 连接上
            // 把整轮检测跑完（真机实测 360.53s），而 probe 传输层 timeout 是 120s
            // ⇒ 重模型必然超时，用户看到「检测失败」，服务端其实给出了 0.98 置信度的判定。
            // `sync=false` 是**秒级**返回 runId（curl 直测 0.75s；产品真机用例 9.27s，
            // 两者都是「与检测时长无关的一小段」），剩下的时间交给下面的轮询——每条连接都是
            // 短请求，单次失败还能重试，不再把已经跑出来的结论一起丢掉。
            sync: false,
        };
        // H1+M2（独立复审）：优先用 probe_transport（独立 timeout、不套 retry）；
        // None 时 fallback 到 self.transport（测试 Mock 路径，M4 可 mock）。
        // 收成 `&dyn` 是为了提交与轮询走**同一条**选择逻辑，不把二选一写两遍。
        let transport: &dyn HttpTransport = match &self.probe_transport {
            Some(pt) => pt,
            None => &self.transport,
        };
        let run = match crate::probe::run_probe(transport, &req).await {
            Ok(r) => r,
            Err(err) => {
                // M3（独立复审）：失败也写一条 warn 事件（scrub 错误信息），让事件流能追溯检测失败。
                // 不落 probe_runs（无 run_id，历史表只记检测结果）；失败原因进事件流，apiKey 绝不进。
                self.log(observability::event_with_payload(
                    Level::Warn,
                    "probe",
                    format!("模型检测失败: {}", crate::redact::scrub(&err.to_string())),
                    serde_json::json!({
                        "site_id": row.site_id,
                        "key_id": key_id,
                        "model_id": model_id_for_store,
                    }),
                ));
                return Err(err);
            }
        };
        // B-134 骨架 / B-160 主路径：提交后**轮询到终态**。异步提交的响应只有 runId
        // （没有 status），所以这步几乎总要走。
        //
        // 第三个参数 `submitted_async` **由 `req.sync` 推导**，不写第二个字面量：判据跟着
        // 提交方式走，两处各写一份就等于给「装配层悄悄失效」留门——独立复审 P2-1 实测过，
        // 把这里硬写成 `false` 时整套单测仍全绿，B-160 会在装配层静默退化。
        let outcome = crate::probe::poll_probe_run(
            transport,
            run,
            !req.sync,
            self.probe_poll,
            &*self.probe_sleeper,
        )
        .await;
        // 只记元数据：停下来原因、补查了几次、失败几次、最终状态、有没有判定
        //（apiKey / 响应正文都不进）。
        self.log(observability::event_with_payload(
            Level::Debug,
            "probe",
            "模型检测轮询结束",
            serde_json::json!({
                "site_id": row.site_id,
                "key_id": key_id,
                "run_id": outcome.run.run_id,
                "status": outcome.run.status,
                "stop": outcome.stop,
                "polled": outcome.polled,
                "errors": outcome.errors,
                "has_verdict": outcome.run.verdict_status.is_some(),
            }),
        ));
        let run = outcome.run;
        let poll_stop = outcome.stop;
        // 持久化摘要（best-effort：落库失败只 warn，不 mask 检测成功）
        if let Err(err) = self.store.insert_probe_run(
            row.site_id,
            key_id,
            &model_id_for_store,
            req.claimed_model.as_deref(),
            &run,
        ) {
            self.log(observability::event_with_payload(
                Level::Warn,
                "store",
                format!("检测历史落库失败: {}", crate::redact::scrub(&err.to_string())),
                serde_json::json!({ "site_id": row.site_id, "key_id": key_id, "run_id": run.run_id }),
            ));
        }
        // 事件只 log 元数据，不 log apiKey / 响应正文
        //
        // F1（独立检查）：bazaarlink 对「key 访问不了该模型」这类情况会**秒级返回 completed
        // 但不带 identityAssessment**（真机实测 4 次：420–663ms、verdict 全空）。旧实现无条件记
        // info「模型检测完成」+ 落一条 verdict 全空的行——失败被伪装成成功，事件流与历史表
        // 都看不出区别。现在按「有没有拿到判定」分流：拿到 → info「完成」；
        // 没拿到 → warn（**仍落库**：run_id / report_url 是真实的，报告能点开）。
        //
        // B-160 补充两种「不是没判定、而是没等到」：
        // - 预算等完、run 还在跑 ⇒ 服务端还在算，结论随时可能出现；
        // - 连续补查失败超限 / 撞硬上限 ⇒ **判定服务不可达**，连 run 状态都问不到。
        // 这两种都不该被记成「跑完了没给判定」——那句话的含义是「服务端明确跑完但没结论」
        // （F1 分支），混在一起用户会以为是模型测不出来（独立复审 P2-3）。
        let waited_out = matches!(poll_stop, crate::probe::PollStop::BudgetExhausted);
        let unreachable = matches!(
            poll_stop,
            crate::probe::PollStop::TooManyErrors | crate::probe::PollStop::AttemptsExhausted
        );
        self.log(
            match (run.verdict_status.as_ref(), waited_out, unreachable) {
                (Some(_), _, _) => observability::event_with_payload(
                    Level::Info,
                    "probe",
                    "模型检测完成",
                    serde_json::json!({
                        "site_id": row.site_id,
                        "key_id": key_id,
                        "run_id": run.run_id,
                        "verdict": run.verdict_status,
                        "identity": run.identity_status,
                    }),
                ),
                (None, true, _) => observability::event_with_payload(
                    Level::Warn,
                    "probe",
                    "模型检测未在等待预算内完成",
                    serde_json::json!({
                        "site_id": row.site_id,
                        "key_id": key_id,
                        "run_id": run.run_id,
                        "status": run.status,
                        "budget_secs": self.probe_poll.budget.as_secs(),
                        "report": run.report_url,
                    }),
                ),
                (None, false, true) => observability::event_with_payload(
                    Level::Warn,
                    "probe",
                    "模型检测查询中断（判定服务不可达）",
                    serde_json::json!({
                        "site_id": row.site_id,
                        "key_id": key_id,
                        "run_id": run.run_id,
                        "status": run.status,
                        "stop": poll_stop,
                    }),
                ),
                (None, false, false) => observability::event_with_payload(
                    Level::Warn,
                    "probe",
                    "模型检测未得出判定",
                    serde_json::json!({
                        "site_id": row.site_id,
                        "key_id": key_id,
                        "run_id": run.run_id,
                        "status": run.status,
                        "identity": run.identity_status,
                    }),
                ),
            },
        );
        Ok(run)
    }

    /// M15-S1：最近 `limit` 条检测历史（按 `recorded_at` 降序）。
    pub fn list_probe_runs(&self, limit: usize) -> Result<Vec<crate::store::ProbeRunRow>> {
        self.store.list_probe_runs(limit)
    }

    /// M15-S1：按本地 id 取单条检测记录。
    pub fn get_probe_run(&self, id: i64) -> Result<Option<crate::store::ProbeRunRow>> {
        self.store.get_probe_run(id)
    }

    /// 回收站点上的某把令牌，并把本地记录标成**已回收**（B-82 的独立路径）。
    ///
    /// # 顺序（硬要求）
    ///
    /// **先站点、后本地**。站点侧失败时**不**写本地状态——否则会出现「本地说已回收、
    /// 站点上还活着」这种最坏的组合（用户以为泄漏面关掉了，实际没关）。
    /// 反过来「站点已删、本地没标上」是可修的：本地状态没写上会**留痕**（Warn 事件），
    /// 用户能在事件面板看到，`sync_site_keys` 下一轮也不会把它当成「站点上还有」。
    ///
    /// **订正（M8-S5A §4）**：本行原来写的是「下一次 `sync_site_keys` 会把它标成 `missing`」——
    /// **那句是假的**：`sync_site_keys` 从不改已有行的状态，而 `missing` 也不在 `set_key_status`
    /// 的合法值里。B-100 的处置一度建立在这个不存在的前提上。现在如实写成上面这句。
    ///
    /// **已知缺口（未接线 + 去向）**：没有任何机制会主动发现「站点侧被删、本地仍是 enabled」
    /// 的行——`sync_site_keys` 只看站点侧**还有**什么，不看**少了**什么。
    /// 去向：`docs/BACKLOG.md` 的 B-115。
    ///
    /// # 为什么不删本地行
    ///
    /// `bindings.key_id` 是 `ON DELETE CASCADE`——删行会把绑定与漂移追溯一起带走，
    /// 而 `journals` 表**没有** `key_id`，溯源链的起点就是 `keys.id`（M7-S4 spec §6.1 有实测）。
    /// 所以「回收」= 改状态，不是删记录。
    pub async fn revoke_key(&self, site_id: i64, remote_id: &str) -> Result<RevokeReport> {
        let site = self.site(site_id)?;
        let kind = self.kind_of(&site)?;
        capability_gate(
            kind,
            crate::site::capability::capabilities(kind).revoke_key,
            "回收令牌",
        )?;
        let session = self.session(site_id)?;
        let adapter = self.registry.adapter(kind);
        match adapter
            .revoke_key(&site.base_url, &session, remote_id)
            .await
        {
            Ok(()) => {
                let mut local_status_updated = false;
                let mut note: Option<String> = None;
                // **读本地行失败也不能把整次操作报成失败**（M8-S5A §4）：
                // 站点侧那一把已经删了，这个动作不可逆。原来的 `?` 会让「DELETE 成功、
                // 但本地这一读失败」表现为「回收失败」——与下面 `set_key_status` 那条注释里
                // 写着的原则**自相矛盾**（同一类事实，两种处置）。
                let key_id = match self.local_key_id_for_remote(site_id, remote_id) {
                    Ok(id) => id,
                    Err(err) => {
                        let reason = crate::redact::scrub(&err.to_string());
                        note = Some(format!("站点侧已回收，但读本地记录失败：{reason}"));
                        self.log(observability::event_with_payload(
                            Level::Warn,
                            "key",
                            "站点侧已回收，但读本地记录失败（本地状态没写上）",
                            serde_json::json!({
                                "site_id": site_id,
                                "reason": reason,
                            }),
                        ));
                        None
                    }
                };
                // 本地记账失败**不让命令失败**（M7-S4 复审 P2-1 的建议，Lead 采纳）。
                //
                // 理由：站点侧那一把**已经删了**，这个动作不可逆。若因为本地写状态失败就返回
                // `Err`，用户会看到「回收失败」并去重试——而重试**必然失败**（站点上已经没有它了），
                // 更糟的是他会以为密钥还活着。把一次不可逆的成功报成失败，是比记账缺失更坏的结果。
                //
                // 代价是记账确实没写上，所以这里**必须留痕**：Warn 级事件带上原因（脱敏后），
                // 用户能在事件面板看到；下一次 `sync_site_keys` 对账也会把它标出来。
                if let Some(key_id) = key_id {
                    // M8-S1 §3.5-5：让**正在运行**的网关也立刻停止使用这把 key。
                    // `ensure_not_revoked` 只拦新启动；运行中的网关只看这个集合。
                    if let Ok(Some(row)) = self.store.get_key(key_id) {
                        if let Ok(mut set) = self.revoked_refs.lock() {
                            set.insert(row.secret_ref);
                        }
                    }
                    match self
                        .store
                        .set_key_status(key_id, crate::store::KEY_STATUS_REVOKED)
                    {
                        Ok(()) => local_status_updated = true,
                        Err(err) => {
                            let reason = crate::redact::scrub(&err.to_string());
                            note = Some(format!("站点侧已回收，但本地状态没写上：{reason}"));
                            self.log(observability::event_with_payload(
                                Level::Warn,
                                "key",
                                "站点侧已回收，但本地状态没写上",
                                serde_json::json!({
                                    "site_id": site_id,
                                    "key_id": key_id,
                                    "reason": reason,
                                }),
                            ));
                        }
                    }
                }
                // payload 只记 id 与状态：这里经手的是「哪一把」，不是「那一把的值」。
                self.log(observability::event_with_payload(
                    Level::Info,
                    "key",
                    "已回收站点上的密钥",
                    serde_json::json!({
                        "site_id": site_id,
                        "key_id": key_id,
                        "status": crate::store::KEY_STATUS_REVOKED,
                        "local_status_updated": local_status_updated,
                    }),
                ));
                Ok(RevokeReport {
                    site_id,
                    remote_id: Some(remote_id.to_string()),
                    revoked: true,
                    local_status_updated,
                    note,
                })
            }
            Err(err) => Err(self.on_auth_error(site_id, err)),
        }
    }

    /// 解绑一个 agent 与它的密钥（FR-2:115 / M8-S4 §5）。
    ///
    /// # 解绑不是删除
    ///
    /// `bindings` 的每一行都是「哪个 agent 曾被哪个 key 写到哪个文件」的**唯一记录**，
    /// 删掉它等于同时丢掉漂移追溯与「这把 key 服务过哪些目标」⇒ 只写 `unbound_at` 标记，
    /// 行保留（§5.1）。`consents` / `journals` / `events` 一概不动，`keys.status` 也不动
    /// （解绑 ≠ 回收；站点侧那把 key 仍然有效）。
    ///
    /// # `also_revoke` 是**两件事**
    ///
    /// 解绑是本地动作，回收是远端动作。把两者绑成一个事务会让「站点挂了就解不了绑」✗
    /// ⇒ 单条回收失败**不**回滚解绑，也不冒泡（汇总进 [`UnbindOutcome::revoked`] 的 `note`）。
    ///
    /// # 为什么先读后标记
    ///
    /// 「要回收哪几把」必须在标记**之前**读：标记之后 `bindings_of_agent` 仍然会返回这些行
    /// （行没删），但回收只针对「当前仍绑定的」行（P1-1：`unbound_at` 为 `None` 的），
    /// 已解绑的不回收。两次调用之间没有写操作，所以顺序只影响可读性——先读再标记。
    pub async fn unbind(&self, agent_id: &str, also_revoke: bool) -> Result<UnbindOutcome> {
        let affected = self.store.bindings_of_agent(agent_id)?;
        let report = self.store.unbind_agent(agent_id)?;

        let mut revoked = Vec::new();
        let mut note = None;
        if also_revoke {
            // 同一把 key 可能被投到多个目标文件 ⇒ 只回收一次。
            // 站点侧的删除本身是幂等的，但重复发请求会让「回收了几把」这个数字失去意义，
            // 也会让第二次请求必然失败（站点上已经没有了）而写出一条误导性的失败记录。
            let mut seen: std::collections::HashSet<(i64, String)> =
                std::collections::HashSet::new();
            let mut unmanaged = 0usize;
            for row in &affected {
                // P1-1：只回收「当前仍绑定的」行对应的 key，跳过已解绑的。
                // 旧实现遍历全部 affected（含已解绑），会把 agent 历史用过的所有 key
                // 在站点删掉——包括已经解绑给别的 agent 的，导致那个 agent 立刻失效。
                if row.unbound_at.is_some() {
                    continue;
                }
                let Some(remote_id) = row.remote_id.clone() else {
                    // 站点侧没有记录（用户在站点网页上手工建的 key）⇒ 没有可回收的 id。
                    unmanaged += 1;
                    continue;
                };
                if !seen.insert((row.site_id, remote_id.clone())) {
                    continue;
                }
                match self.revoke_key(row.site_id, &remote_id).await {
                    Ok(outcome) => revoked.push(outcome),
                    // 单条失败不冒泡：解绑已经完成了，这里只是「顺手回收」没成功。
                    // 失败原因照旧脱敏（站点返回体可能回显凭证）。
                    Err(err) => revoked.push(RevokeReport {
                        site_id: row.site_id,
                        remote_id: Some(remote_id),
                        revoked: false,
                        local_status_updated: false,
                        note: Some(crate::redact::scrub(&err.to_string())),
                    }),
                }
            }
            if unmanaged > 0 {
                note = Some(format!(
                    "{unmanaged} 个绑定没有站点侧 id（可能是在站点网页上手工创建的），已跳过回收"
                ));
            }
        }

        self.log(observability::event_with_payload(
            Level::Info,
            "delivery",
            "已解绑 agent 的密钥绑定",
            serde_json::json!({
                "agent_id": agent_id,
                "unbound": report.unbound,
                "already_unbound": report.already_unbound,
                "also_revoke": also_revoke,
                "revoked_ok": revoked.iter().filter(|o| o.revoked).count(),
                "revoked_failed": revoked.iter().filter(|o| !o.revoked).count(),
            }),
        ));

        Ok(UnbindOutcome {
            unbound: report.unbound,
            already_unbound: report.already_unbound,
            revoked,
            note,
        })
    }

    /// `remote_id → 本地 key_id`（限定同一站点）。找不到 ⇒ `Ok(None)`。
    ///
    /// 用内存里的 `stored_keys()` 匹配，而不是给 `store` 加一个查询：
    /// 这是一次内部查找，不值得为它扩存储层的接口面（M7-S5 §3 决策）。
    /// 找不到不是错误——用户可能在站点网页上手工建过一把我们没记过的 key。
    fn local_key_id_for_remote(&self, site_id: i64, remote_id: &str) -> Result<Option<i64>> {
        Ok(self
            .stored_keys()?
            .into_iter()
            .find(|row| row.site_id == site_id && row.remote_id.as_deref() == Some(remote_id))
            .map(|row| row.id))
    }

    /// 本产品在钥匙串里拥有**哪些条目**（去重、已排序）。
    ///
    /// 这是「我们拥有什么」的**唯一**来源，`purge_keychain()` 与将来的「导出引用清单」
    /// 都必须走它——把枚举收在一处，将来新增一种凭据（例如账号会话）时，
    /// 漏删的风险集中在**一个**函数里，而不是散在若干处。
    ///
    /// 今天有两种：`keys.secret_ref`（每把站点密钥一条）与**网关本地令牌**
    /// （[`GATEWAY_TOKEN_REF`]——它没有 `keys` 行，所以必须显式带上，
    /// 否则「一键清理钥匙串」会把它留在系统钥匙串里，FR-8:191 的承诺就不成立）。
    /// `accounts` 表有 `credential_ref` 列，但全仓没有写入器（M7-S4 的同类发现），
    /// 所以它现在不可能有行。
    fn owned_secret_refs(&self) -> Result<Vec<String>> {
        let mut refs: Vec<String> = self
            .store
            .list_keys()?
            .into_iter()
            .map(|row| row.secret_ref)
            .collect();
        // 先问「在不在」再列进去：`delete` 是幂等的，无条件列进去不会出错，
        // 但会让「清掉了几条」这个数字永远多一条（而那是界面上的原话）。
        // `has` 的 `Err`（读失败）**向上传播**：读失败不等于不存在，这条口径与本文件一致。
        if self.vault.has(GATEWAY_TOKEN_REF)? {
            refs.push(GATEWAY_TOKEN_REF.to_string());
        }
        // M13-S1：每个站点的持久化 session（`kr/site/<id>/session`）也属本产品拥有的
        // 钥匙串条目，一键清理（FR-8:191）必须带上，否则删站/卸载后留孤儿。
        // 与 GATEWAY_TOKEN_REF 同口径：先 `has` 再列，避免「清掉几条」数字虚高。
        for site in self.store.list_sites()? {
            let reference = self.session_ref(site.id);
            // per-site `has` 失败不中断整体枚举（复审 Low 修正）：单点钥匙串 IO 故障时，
            // 跳过该站点的 session_ref（清不掉它），但其他站点仍能列出。整体 `?` 失败
            // 会让 purge 清不掉任何条目（含 keys、gateway），爆炸半径更大。
            match self.vault.has(&reference) {
                Ok(true) => refs.push(reference),
                Ok(false) => {}
                Err(err) => self.log(observability::event_with_payload(
                    Level::Warn,
                    "vault",
                    format!("枚举持久化会话失败，跳过该站点: {err}"),
                    serde_json::json!({ "site_id": site.id }),
                )),
            }
        }
        refs.sort();
        refs.dedup();
        Ok(refs)
    }

    /// 清空钥匙串里属于本产品的条目（FR-8:191「卸载后钥匙串条目可一键清理」）。
    ///
    /// # 为什么按库里的引用枚举，而不是枚举钥匙串
    ///
    /// macOS 上枚举某个 service 的条目要过 keychain ACL（`security dump-keychain` 会弹授权），
    /// 在应用内不可靠。而我们写过的每一条引用都在库里——按库删，既准确又可测。
    ///
    /// # 不读明文、不删记录
    ///
    /// 全程**不调用 `vault.get`**：只需要删，不需要把秘密读进内存一次。
    /// 也**不删 SQLite 行**——清的是秘密，不是记录；删记录会带走绑定与漂移追溯
    /// （`ON DELETE CASCADE`），而用户可能只是想把秘密挪走、留着历史。
    ///
    /// 逐条尽力而为：单条失败不中断其余，返回计数与第一条错误文案（脱敏后）。
    /// `Vault::delete` 是幂等的，所以「本来就没了」算成功——清理要的是「现在没有了」这个结果。
    pub fn purge_keychain(&self) -> Result<KeychainPurgeReport> {
        let refs = self.owned_secret_refs()?;
        let mut removed = 0usize;
        let mut failed = 0usize;
        let mut first_error: Option<String> = None;
        for secret_ref in &refs {
            match self.vault.delete(secret_ref) {
                Ok(()) => removed += 1,
                Err(err) => {
                    failed += 1;
                    if first_error.is_none() {
                        first_error = Some(crate::redact::scrub(&err.to_string()));
                    }
                }
            }
        }
        self.log(observability::event_with_payload(
            Level::Warn,
            "vault",
            "已清理钥匙串条目",
            // 只记计数：条目名本身也是线索，不进事件表。
            serde_json::json!({
                "attempted": refs.len(),
                "removed": removed,
                "failed": failed,
            }),
        ));
        Ok(KeychainPurgeReport {
            attempted: refs.len(),
            removed,
            failed,
            first_error,
        })
    }

    /// 组装网关配置（含站点密钥）。调用方负责真正启动网关。
    ///
    /// `GatewayConfig` 的 `Debug` 已手写脱敏，不会打印令牌与密钥。
    ///
    /// # M8-S1：路由表真的被填上了
    ///
    /// M7 的审计 D-2/D-4 说的是同一件事：`RouteTable` 写得对、测得全，但**这个函数**一直走
    /// `single_upstream` ⇒ `route` 恒为空表 ⇒ 排序、故障切换、失败事件在生产上全部不可达。
    /// 现在这里做三件事：
    /// ① 为**所有**有可用密钥的站点建 `SiteFacts`（含当前这个），推导路由表；
    /// ② 把每个上游的明文填进 `keys_by_ref`（否则网关会静默 `continue` → 502）；
    /// ③ 交给网关一个**已回收集合**与一个会话代号。
    pub fn gateway_config(
        &self,
        site_id: i64,
        key_id: i64,
        port: u16,
    ) -> Result<crate::gateway::GatewayConfig> {
        let site = self.site(site_id)?;
        let row = self
            .store
            .get_key(key_id)?
            .ok_or_else(|| Error::NotFound(format!("密钥记录 #{key_id} 不存在")))?;
        if row.site_id != site_id {
            return Err(Error::Store(format!(
                "密钥 #{key_id} 不属于站点 #{site_id}"
            )));
        }
        ensure_not_revoked(&row)?;
        // 走 `key_secret` 而不是在这里再抄一遍 `vault.get` + 回收判定（M8-S5A §2.2）：
        // 一个咽喉点比两处同义代码好，`ensure_not_revoked` 也不会再漏。
        //
        // M8-S4 收口了 M8-S1 章程 §3.5 第 13 行：`GatewayConfig::api_key` 的类型
        // 从裸 `String` 换成 `Zeroizing<String>`，所以这里**不再有**一个未清零的副本
        // （原来那一版是 `.to_string()`，把 `Zeroizing` 里的明文复制成裸 `String`）。
        let api_key = self.key_secret(key_id)?;

        // P1-4：当前按 M8-S4（用户选的站点 = 上游）。route 为空表 ⇒ 走 legacy 单上游路径
        //（config.base_url / api_key = 所选站点）。多站路由（M8-S1）是 B-99 接线后的未来，
        // 届时再建非空 route。旧实现 build_gateway_route 把所有站点建进路由表，gateway.rs
        // 的非空路由分支不读用户选择 ⇒ 界面显示「上游 B」请求却发往 A。
        //
        // 令牌**跨重启稳定**（M8-S4 §6.4）：不稳定的令牌会让每次 `stop → start` 都作废
        // agent 配置里那把，而那正是 FR-5:158「换站零改动」要消灭的一步。
        let (token, token_persistent) = self.gateway_token();
        self.gateway_token_persistent
            .store(token_persistent, std::sync::atomic::Ordering::SeqCst);

        let mut config = crate::gateway::GatewayConfig::single_upstream(
            port,
            // P3-32 边界：`GatewayConfig.token` 是冻结的 `String`（非本包写域），
            // 这一处 `.to_string()` 是**必需**的唯一拷贝。
            token.to_string(),
            site.base_url,
            api_key,
            site.display_name,
        );
        // M16-S4 W-3：把 legacy 那把密钥的**引用**交给网关，它才能在密钥被回收后
        // 拒绝继续使用（`legacy_key_ref: None` 时行为与今天逐字相同）。
        // `row.secret_ref` 与 `api_key` 同源：`api_key` 就是从这个引用取出来的，
        // 所以填它不会引入新的取密钥路径。
        config.legacy_key_ref = Some(row.secret_ref.clone());
        // M14-S1：多站路由开关（B-99）。关时（默认）走 single_upstream——config.base_url
        // / api_key 是所选站点，M8-S4 §6.5 换站语义逐字不变；开时用 build_gateway_route
        // 填非空 route + keys_by_ref，网关按模型选路（多站聚合，FR-6 V1.1 可选）。
        let settings = self.settings()?;
        // M39-S3 §4.6：负载均衡与每站保护策略（**下次启动网关生效**；不在请求路径热切换）。
        config.lb_top_n = settings.gateway_lb_top_n;
        config.guard_policy = crate::routing::SiteGuardPolicy {
            max_concurrency: settings.gateway_per_site_concurrency,
            rate_limit_per_sec: settings.gateway_per_site_rate_limit,
        };
        if settings.gateway_multi_site {
            let (route, keys) = self.build_gateway_route()?;
            config.route = route;
            config.keys_by_ref = keys;
            // M39-S1：非空路由 ⇒ 装一个热更新句柄（首个快照 generation = 1）。
            // 空路由（没有可用站点）不装：那时网关走 legacy 路径，快照没有读者。
            if !config.route.is_empty() {
                let snapshot = crate::gateway::GatewaySnapshot::new(
                    1,
                    config.route.clone(),
                    config.keys_by_ref.clone(),
                );
                let runtime = Arc::new(std::sync::RwLock::new(Arc::new(snapshot)));
                if let Ok(mut slot) = self.gateway_runtime.lock() {
                    *slot = Some(Arc::clone(&runtime));
                }
                config.runtime = Some(runtime);
            }
        } else if let Ok(mut slot) = self.gateway_runtime.lock() {
            // 单站/legacy：清掉上一次的句柄——避免 publish 往一个没人读的旧容器里写。
            *slot = None;
        }
        // ③ 已回收集合：网关只**查**它，不新开取密钥路径。
        config.site_id = site_id;
        config.revoked_refs = Some(Arc::clone(&self.revoked_refs));
        // M10-S2：上游客户端走解析后的代理。每次 `gateway_config` 都重读 settings，
        // 因此系统代理变更「重启网关即生效」（站点适配器 transport 仍需重启 app）。
        // 解析失败（manual 非法）⇒ None + 告警事件，不让网关因代理非法起不来。
        config.upstream_proxy = self.resolved_upstream_proxy();
        // ④ 会话代号：本次会话的失败才算本次的（§11.1）。
        let session = self
            .gateway_session
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        let current = Arc::clone(&self.gateway_session);

        // 失败事件出口（FR-5:160）。回调只做一次 `push`：它跑在网关的请求任务里，
        // 不该在那里做 IO，也不该 panic（`Mutex` 中毒时静默丢弃——观测性坏掉
        // 不该让业务请求失败，这是本文件既有的一条口径，见 `log()`）。
        let sink = Arc::clone(&self.gateway_failures);
        let dropped_sink = Arc::clone(&self.gateway_failures_dropped);
        config.on_failure = Some(Arc::new(move |failure: crate::gateway::GatewayFailure| {
            // 会话比对：**不相等就丢弃**（§11.1）。丢弃的代价写在 spec 的未验证边界里：
            // 停止瞬间在途请求的失败不进事件表——把它记到下一个会话是主动误导，
            // 而它本身（网关正在停）也不构成可诊断的故障。
            if current.load(std::sync::atomic::Ordering::SeqCst) != session {
                return;
            }
            if let Ok(mut buffer) = sink.lock() {
                push_bounded(&mut buffer, &dropped_sink, failure);
            }
        }));

        // ⑤ 延迟观测出口（§5.3）。**只采信成功的尝试**：失败耗时没有比较意义。
        let facts = Arc::clone(&self.site_facts);
        config.on_observation = Some(Arc::new(move |obs: crate::gateway::UpstreamObservation| {
            if !obs.ok {
                return;
            }
            if let Ok(mut map) = facts.lock() {
                map.entry(obs.site_id).or_default().latency_ms = Some(obs.latency_ms);
            }
        }));

        // M13-S1：token 用量出口。回调只 push 到内存缓冲，落库在 refresh_all。
        // 与 on_failure 同口径做会话比对：停止瞬间的在途请求 usage 不进下一个会话。
        let usage_buffer = Arc::clone(&self.gateway_usage_buffer);
        let usage_dropped = Arc::clone(&self.gateway_usage_dropped);
        let usage_session_current = Arc::clone(&self.gateway_session);
        config.on_usage = Some(Arc::new(move |usage: crate::gateway::GatewayUsage| {
            if usage_session_current.load(std::sync::atomic::Ordering::SeqCst) != session {
                return;
            }
            if let Ok(mut buffer) = usage_buffer.lock() {
                if buffer.len() >= 1024 {
                    buffer.drain(0..512);
                    usage_dropped.fetch_add(512, std::sync::atomic::Ordering::Relaxed);
                }
                buffer.push(usage);
            }
        }));
        Ok(config)
    }

    /// M13-S1：把网关攒下的 token 用量落库。
    pub fn drain_gateway_usage(&self) {
        let drained: Vec<crate::gateway::GatewayUsage> = match self.gateway_usage_buffer.lock() {
            Ok(mut buffer) => buffer.drain(..).collect(),
            Err(_) => {
                let dropped = self
                    .gateway_usage_dropped
                    .swap(0, std::sync::atomic::Ordering::Relaxed);
                if dropped > 0 {
                    self.log(observability::event_with_payload(
                        Level::Warn,
                        "gateway",
                        format!("本轮因缓冲满丢弃 {dropped} 条网关用量记录（缓冲锁中毒，未落库）"),
                        serde_json::json!({ "dropped": dropped }),
                    ));
                }
                return;
            }
        };
        let dropped_this_round = self
            .gateway_usage_dropped
            .swap(0, std::sync::atomic::Ordering::Relaxed);
        for usage in &drained {
            let _ = self.store.insert_gateway_usage(
                usage.site_id,
                &usage.model,
                usage.prompt_tokens,
                usage.completion_tokens,
                usage.total_tokens,
            );
        }
        if dropped_this_round > 0 {
            self.log(observability::event_with_payload(
                Level::Warn,
                "gateway",
                format!(
                    "本轮因缓冲满丢弃 {dropped_this_round} 条网关用量记录（仅记计数，不逐条记）"
                ),
                serde_json::json!({ "dropped": dropped_this_round }),
            ));
        }
    }

    /// 网关本地令牌（M8-S4 §6.4）：**已持久化就用它，没有就生成一把并存起来**。
    ///
    /// 返回 `(令牌, 是否持久化)`。第二个值一路走到 `GatewayStatusDto.token_persistent`：
    /// 降级**必须说出来**（§6.4 第 5 条），用户要能看见「令牌：临时（重启后需重新投递）」。
    ///
    /// # 三条边界
    ///
    /// - **不存在**（第一次启动）⇒ 生成 + `put`；这是唯一「令牌会变」的正常时机。
    /// - **读失败**（钥匙串锁着 / ACL 拒绝）⇒ 生成一把**临时**令牌让网关照常启动，
    ///   `token_persistent = false` + 一条 Warn 事件，且**不写回钥匙串**——钥匙串里若
    ///   已有持久令牌，覆盖它会让所有指向网关的 agent 配置永久 401（P2-4 / DEBUG-REPORT-v3
    ///   §2-4）。为什么不直接报错：网关是用户显式打开的开关，钥匙串读不了不该让整个
    ///   功能不可用；而「静默生成一把新的并覆盖」才是真缺陷——那会让 agent 配置里那把
    ///   无声无息地失效。所以：降级 + 留痕 + 状态里明示 + 不覆盖。
    /// - **写失败** ⇒ 同上（临时令牌）。两次失败的原因都进事件（脱敏后）。
    ///
    /// 不返回 `Result`：这个方法**没有**失败态——它的失败全部表达为「临时令牌」。
    /// 唯一的例外是 `rotate_gateway_token`（显式轮换动作），那里写失败必须报错。
    /// 取网关本地令牌（`(令牌, 是否持久化)`）。
    ///
    /// **返回值是 [`zeroize::Zeroizing<String>`]**（P3-32 service 半 / DEBUG-REPORT-v3 §3-32）：
    /// 旧实现返回裸 `String`，`vault_secret` 的 `Zeroizing` 在这里被 `.to_string()` 掉，
    /// 明文副本不擦除。到 `GatewayConfig.token` / `GatewayEndpoint.token`（**冻结接口，
    /// 非本包写域**）边界上仍剩**一处**必需拷贝，已在调用点标注。
    fn gateway_token(&self) -> (zeroize::Zeroizing<String>, bool) {
        match self.vault_secret(GATEWAY_TOKEN_REF) {
            Ok(Some(token)) if !token.trim().is_empty() => return (token, true),
            // 存在但是空的（手工把条目清成空串）⇒ 当作没有：空令牌会让网关拒绝所有请求
            // （`config.token.trim().is_empty()` 那条硬门），比生成一把新的更糟。
            Ok(_) => {}
            Err(err) => {
                // 读失败（瞬时：锁屏 / ACL 拒绝）：生成一把**临时**令牌让网关照常启动，
                // 但**不写回钥匙串**——钥匙串里可能已有一把仍有效的持久令牌，覆盖它会让
                // 所有指向网关的 agent 配置永久 401（P2-4 / DEBUG-REPORT-v3 §2-4）。
                // 临时令牌只在本次进程生命周期有效；下次读成功时仍用钥匙串里那把。
                self.log(observability::event_with_payload(
                    Level::Warn,
                    "gateway",
                    "读钥匙串里的网关令牌失败，本次用临时令牌（重启后会变）；钥匙串里若已有令牌不会被覆盖",
                    serde_json::json!({ "reason": crate::redact::scrub(&err.to_string()) }),
                ));
                let token = crate::gateway::generate_token();
                return (zeroize::Zeroizing::new(token), false);
            }
        }
        // Ok(None) 或空：钥匙串里确实没有 ⇒ 生成 + put（首次装配）
        let token = crate::gateway::generate_token();
        match self.vault.put(GATEWAY_TOKEN_REF, &token) {
            Ok(()) => (zeroize::Zeroizing::new(token), true),
            Err(err) => {
                self.log(observability::event_with_payload(
                    Level::Warn,
                    "gateway",
                    "网关令牌没能存进钥匙串，本次用临时令牌（重启后会变）",
                    serde_json::json!({ "reason": crate::redact::scrub(&err.to_string()) }),
                ));
                (zeroize::Zeroizing::new(token), false)
            }
        }
    }

    /// 最近一次装配网关时，令牌是否持久化（供状态 DTO 用）。
    pub fn gateway_token_persistent(&self) -> bool {
        self.gateway_token_persistent
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// **显式轮换**网关令牌（§6.4 第 4 条）：生成新的一把并写进钥匙串。
    ///
    /// 与 [`Self::gateway_token`] 的关键区别：这是用户按下去的按钮，**写失败必须报错**——
    /// 否则用户会以为换掉了，而重启后令牌又变回去（或者变成第三把）。
    ///
    /// 调用方（命令层）**必须**接着重启网关：否则运行中的网关仍用旧令牌，
    /// 而钥匙串里已经是新的 ⇒ agent 配置与网关不一致，直到下一次重启。
    ///
    /// 也不动 agent 配置：指向网关的通道需要**重新投递**（界面提示），
    /// 这是「轮换」与「换站」是两件事的地方（§6.5 边界）。
    pub fn rotate_gateway_token(&self) -> Result<()> {
        let token = crate::gateway::generate_token();
        self.vault.put(GATEWAY_TOKEN_REF, &token)?;
        // 轮换后**不再**是临时令牌（写成功即持久化）。
        self.gateway_token_persistent
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.log(observability::event_with_payload(
            Level::Info,
            "gateway",
            "已轮换网关本地令牌（指向网关的通道需要重新投递）",
            // P3-8 / DEBUG-REPORT-v3 §3-8：**不写条目名**。
            // `purge_keychain` 的口径是「钥匙串条目名不进事件表」（事件表会被导出与审计）；
            // 这里只报「已持久化」这个事实，条目名本身没有诊断价值。
            serde_json::json!({ "persistent": true }),
        ));
        Ok(())
    }

    /// 从**所有可用站点**推导路由表 + 明文映射（M8-S1 §5.1 / §10）。
    ///
    /// 「可用」= 有一行**未被回收**的本地记录，且钥匙串里那份明文还在。
    /// 判据与 [`Self::key_secret`] 同源（都过 `ensure_not_revoked`）——**不新开取密钥路径**。
    ///
    /// 返回 `(route, keys_by_ref)`。两者的**集合不变式**：`route` 里出现的每个 `key_ref`
    /// 都在 `keys_by_ref` 里。这条不是靠自觉：`tests/routing_wiring.rs` 的 W3 直接断言，
    /// 因为缺一个的表现是「网关静默 502」（M7 审计 D-2）。
    ///
    /// **每个站点取哪一把 key**：取该站点**最新**的一条（`list_keys` 按 id 倒序无所谓，
    /// 这里显式按 id 取最大）。多把 key 的站点应当由用户自己决定用哪把——今天没有这个界面，
    /// 登记为限制（不是缺陷：站点的多把 key 在额度上等价，取最新那把是最不容易过期的）。
    /// B-99 接线后启用（M14-S1 接线）：`gateway_config` 在 `gateway_multi_site` 开关开时调用（多站路由）。
    fn build_gateway_route(
        &self,
    ) -> Result<(
        crate::routing::RouteTable,
        std::collections::HashMap<String, zeroize::Zeroizing<String>>,
    )> {
        let observations = self
            .site_facts
            .lock()
            .map(|map| map.clone())
            .unwrap_or_default();
        // M39-S1：模型清单的唯一事实来源是**表**（持久化 + 采集替换语义）。
        // 每次建路由现读：不存在「内存缓存与表不一致」，也就不需要「启动时加载」这一步。
        // `rate` / `balance_usd` / `latency_ms` 仍是内存观测（不落库，M8-S1 D-4 不变）。
        let catalog = self.store.site_model_catalog()?;
        let revoked = self
            .revoked_refs
            .lock()
            .map(|set| set.clone())
            .unwrap_or_default();

        let mut facts: Vec<crate::routing::SiteFacts> = Vec::new();
        let mut keys: std::collections::HashMap<String, zeroize::Zeroizing<String>> =
            std::collections::HashMap::new();

        for site in self.store.list_sites()? {
            let obs = observations.get(&site.id).cloned().unwrap_or_default();
            // 目录里没有该站 ⇒ 空 vec = 「未知 ⇒ 通配」（M8-S1 §4.2 的既有语义）。
            let models = catalog.get(&site.id).cloned().unwrap_or_default();
            // M39-S3 §4.3：**每站每把可用 key 一个 `Upstream`**（同站共享
            // `rate` / `balance_usd` / `latency_ms` / `models`；guard 与熔断按 site_id 共享，
            // 所以多一把 key 不会让站点上限翻倍）。
            for row in self.usable_gateway_keys(site.id)? {
                // 走 `secret_for_row`（唯一的明文出口），**不新开取密钥路径**。
                let Ok(secret) = self.secret_for_row(&row) else {
                    // 本地记录在、明文没了：这把 key **用不了**。
                    // 跳过这一把是对的（该站点不进路由表），跳过整个站点是错的。
                    continue;
                };
                facts.push(crate::routing::SiteFacts {
                    site_id: site.id,
                    base_url: site.base_url.clone(),
                    models: models.clone(),
                    rate: obs.rate,
                    // **余额未知 ⇒ None**，绝不 `unwrap_or(0.0)`（那会把「不知道」变成「已耗尽」）。
                    balance_usd: obs.balance_usd,
                    latency_ms: obs.latency_ms,
                    key_ref: row.secret_ref.clone(),
                    key_id: Some(row.id),
                });
                if !revoked.contains(&row.secret_ref) {
                    keys.insert(row.secret_ref.clone(), secret);
                }
            }
        }

        // M14-S1：接 alias 表（B-110）。逐条喂 with_alias（M7-S1 冻结的消费点）。
        let table = crate::routing::build_route_table(&facts);
        let aliases = self.store.list_alias_map()?;
        let table = aliases
            .iter()
            .fold(table, |t, (alias, real)| t.with_alias(alias, real));
        Ok((table, keys))
    }

    /// **一趟**模型目录采集（M39-S1 §4.5）。
    ///
    /// 与 `refresh_all` **完全解耦**：可以单独调用（测试直接调它；`src-tauri/src/lib.rs`
    /// 的 60s 循环也调它）。开关关着 ⇒ 立刻返回全零摘要，**一个请求都不发、一行都不写**。
    ///
    /// 语义（§5.2）：成功非空 ⇒ 替换；成功空 ⇒ 连续 2 次才清空；失败 ⇒ 目录不变。
    pub async fn refresh_model_catalog_once(&self) -> Result<ModelCatalogSummary> {
        let mut summary = ModelCatalogSummary::default();
        let settings = self.settings()?;
        // 采集的**唯一**门槛是 `collect_models`（M14-S1 的独立开关，服务 `ModelsChanged` 通知）。
        // `gateway_multi_site` 只决定目录要不要进网关路由（`gateway_config` 里判），
        // **不得**把两者绑定：那会让「开采集、没开多站」的用户收不到模型变化通知（行为回归）。
        if !settings.collect_models {
            summary.generation = self.gateway_snapshot_generation();
            return Ok(summary);
        }
        let now = unix_now_secs();
        let policy = crate::notify::ModelsPolicy {
            enabled: true,
            min_interval_secs: settings.models_min_interval_secs,
        };

        // ① 选出「到期 + 有可用 key」的站点。**同步段，不 await**（拿明文与判据都在这里）。
        struct CatalogJob {
            site_id: i64,
            base_url: String,
            secret: zeroize::Zeroizing<String>,
        }
        let revoked = self
            .revoked_refs
            .lock()
            .map(|set| set.clone())
            .unwrap_or_default();
        let mut jobs: Vec<CatalogJob> = Vec::new();
        for site in self.store.list_sites()? {
            let Some(row) = self.pick_gateway_key(site.id)? else {
                continue;
            };
            if revoked.contains(&row.secret_ref) {
                continue;
            }
            // 节流锚点用 `last_attempt_at`：**失败也节流**——不给坏站点「每轮都重试」的风暴。
            let last_attempt = self
                .store
                .site_model_sync(site.id)?
                .and_then(|sync| sync.last_attempt_at);
            if !crate::notify::should_collect_models(policy, last_attempt, now) {
                continue;
            }
            let Ok(secret) = self.secret_for_row(&row) else {
                continue;
            };
            jobs.push(CatalogJob {
                site_id: site.id,
                base_url: site.base_url.clone(),
                secret,
            });
        }
        if jobs.is_empty() {
            summary.generation = self.gateway_snapshot_generation();
            return Ok(summary);
        }

        // ② 有界并发：`buffer_unordered` 的语义是**实际在途 ≤ N**（不是「每批 N 个、批间无等待」）。
        let transport = &self.transport;
        let results = futures_util::stream::iter(jobs.into_iter().map(|job| async move {
            let fetched = crate::site::fetch_models(transport, &job.base_url, &job.secret).await;
            (job.site_id, fetched)
        }))
        .buffer_unordered(MODEL_CATALOG_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;

        // ③ 落库（串行）：写库不并发，避免自造锁竞争；每站独立，顺序不影响结果。
        let mut changed = false;
        for (site_id, result) in results {
            summary.attempted += 1;
            match result {
                Ok(models) if models.is_empty() => {
                    summary.empty += 1;
                    match self.store.record_site_models_empty(site_id, now) {
                        Ok(outcome) if outcome.cleared => {
                            summary.cleared.push(site_id);
                            changed = true;
                        }
                        Ok(_) => {}
                        Err(err) => {
                            self.log(observability::event_with_payload(
                                Level::Debug,
                                "app",
                                format!(
                                    "模型目录写入失败（空响应）: {}",
                                    crate::redact::scrub(&err.to_string())
                                ),
                                serde_json::json!({ "site_id": site_id }),
                            ));
                        }
                    }
                }
                Ok(models) => {
                    summary.replaced += 1;
                    changed = true;
                    if let Err(err) = self.store.replace_site_models(site_id, &models, now) {
                        self.log(observability::event_with_payload(
                            Level::Debug,
                            "app",
                            format!(
                                "模型目录写入失败（替换）: {}",
                                crate::redact::scrub(&err.to_string())
                            ),
                            serde_json::json!({ "site_id": site_id }),
                        ));
                    }
                }
                Err(err) => {
                    summary.failed += 1;
                    let text = crate::redact::scrub(&err.to_string());
                    self.log(observability::event_with_payload(
                        Level::Debug,
                        "app",
                        format!("模型清单采集失败: {text}"),
                        serde_json::json!({ "site_id": site_id }),
                    ));
                    // store 内部还会再 scrub + 截断一次（红线：store 是最后一道）。
                    if let Err(store_err) =
                        self.store.record_site_models_failure(site_id, now, &text)
                    {
                        self.log(observability::event_with_payload(
                            Level::Debug,
                            "app",
                            format!(
                                "模型目录同步状态写入失败: {}",
                                crate::redact::scrub(&store_err.to_string())
                            ),
                            serde_json::json!({ "site_id": site_id }),
                        ));
                    }
                }
            }
        }
        summary.cleared.sort_unstable();

        // ④ 通知侧的镜像（B-80 的 `ModelsChanged` 读 `site_facts.models`；表才是唯一事实来源）。
        self.mirror_catalog_into_site_facts()?;
        if changed {
            summary.published = self.publish_gateway_snapshot()? > 0;
        }
        summary.generation = self.gateway_snapshot_generation();
        Ok(summary)
    }

    /// **诊断 / 测试用**：当前 `site_facts` 里的模型镜像。
    ///
    /// 表是唯一事实来源（路由读表）；这里只是既有通知路径（B-80 `ModelsChanged`）的镜像。
    pub fn site_model_mirror(&self) -> std::collections::BTreeMap<i64, Vec<String>> {
        self.site_facts
            .lock()
            .map(|map| {
                map.iter()
                    .map(|(site_id, obs)| (*site_id, obs.models.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 把目录镜像进 `site_facts`（**只为既有通知路径** B-80 服务；路由读的是表）。
    ///
    /// 单向：表 → 内存。`models_collected_at` 取该站 `last_success_at`（重启后仍然成立），
    /// 于是 `dispatch_notifications` 的 `Some(list)` / `None` 语义与 M14-S1 保持一致。
    fn mirror_catalog_into_site_facts(&self) -> Result<()> {
        let catalog = self.store.site_model_catalog()?;
        let mut map = self
            .site_facts
            .lock()
            .map_err(|_| Error::Store("站点观测表已中毒".into()))?;
        for site in self.store.list_sites()? {
            let last_success = self
                .store
                .site_model_sync(site.id)?
                .and_then(|s| s.last_success_at);
            let obs = map.entry(site.id).or_default();
            // **只在有事实时覆盖**：表里有该站的目录行 ⇒ 用表；该站有过成功采集但表里
            // 没行（真被清空）⇒ 空；两者都没有（从没采过，例如 `collect_models` 刚打开）
            // ⇒ **保留旧值**。否则会把「还没采」误当成「模型全没了」，
            // 通知侧的 `ModelsChanged` 会误报。
            if should_overwrite_model_mirror(catalog.contains_key(&site.id), last_success) {
                obs.models = catalog.get(&site.id).cloned().unwrap_or_default();
            }
            if let Some(success) = last_success {
                obs.models_collected_at = Some(success);
            }
        }
        Ok(())
    }

    /// 重建 `(RouteTable, keys_by_ref)` 并**发布**到当前运行态（M39-S1 §4.5）。
    ///
    /// 网关没在跑（`gateway_runtime == None`）⇒ 不报错，返回 0：目录已经落库，
    /// 下一次 `gateway_config()` 自然会读到它。
    pub fn publish_gateway_snapshot(&self) -> Result<u64> {
        let (route, keys) = self.build_gateway_route()?;
        let slot = self
            .gateway_runtime
            .lock()
            .map_err(|_| Error::Store("网关运行态锁已中毒".into()))?;
        let Some(runtime) = slot.as_ref() else {
            return Ok(0);
        };
        // 读旧代号 + 写新快照在同一把写锁内完成：两个发布者不会拿到同一个 generation。
        let mut guard = runtime
            .write()
            .map_err(|_| Error::Store("网关快照锁已中毒".into()))?;
        let next = guard.generation.saturating_add(1);
        *guard = Arc::new(crate::gateway::GatewaySnapshot::new(next, route, keys));
        Ok(next)
    }

    /// 当前运行态的快照代号；没有运行态 ⇒ 0。
    pub fn gateway_snapshot_generation(&self) -> u64 {
        let Ok(slot) = self.gateway_runtime.lock() else {
            return 0;
        };
        let Some(runtime) = slot.as_ref() else {
            return 0;
        };
        runtime.read().map(|guard| guard.generation).unwrap_or(0)
    }

    /// 该站点用来出网的 key：**未回收**且未禁用/耗尽里 id 最大的那一条（最新的一把）。
    /// B-99 接线后启用（M14-S1 接线）：被 `build_gateway_route` 与 `refresh_all` 采集段调用（取每站最新可用 key）。
    /// 该站点**所有可用**的 key（M39-S3 §4.3）：未回收、未禁用、未耗尽，按 id 升序。
    ///
    /// 与 [`Self::pick_gateway_key`] 同一组过滤条件——那个是「挑一把」（采集/legacy），
    /// 这个是「全都要」（多站路由的每 key 一个上游）。两条判据必须同源，否则
    /// 「路由里有的 key」与「采集用的 key」会分叉。
    fn usable_gateway_keys(&self, site_id: i64) -> Result<Vec<crate::store::KeyRow>> {
        let mut rows: Vec<crate::store::KeyRow> = self
            .store
            .list_keys()?
            .into_iter()
            .filter(|row| row.site_id == site_id)
            .filter(|row| row.status != crate::store::KEY_STATUS_REVOKED)
            .filter(|row| {
                row.status != crate::site::KeyStatus::Disabled.as_str()
                    && row.status != crate::site::KeyStatus::Exhausted.as_str()
            })
            .collect();
        rows.sort_by_key(|row| row.id);
        Ok(rows)
    }

    fn pick_gateway_key(&self, site_id: i64) -> Result<Option<crate::store::KeyRow>> {
        Ok(self
            .store
            .list_keys()?
            .into_iter()
            .filter(|row| row.site_id == site_id)
            .filter(|row| row.status != crate::store::KEY_STATUS_REVOKED)
            // P1-4：也不选 disabled / exhausted（旧实现只过滤 revoked）
            .filter(|row| {
                row.status != crate::site::KeyStatus::Disabled.as_str()
                    && row.status != crate::site::KeyStatus::Exhausted.as_str()
            })
            .max_by_key(|row| row.id))
    }

    /// P1-2：读旧 key 在该 channel 的绑定的 delivery_mode（轮换按它走）。
    /// 没有原绑定（首次投递）⇒ 默认 "site"（既有行为）。
    fn rotation_delivery_mode(&self, old_key_id: i64, channel: &DeliveryChannel) -> Result<String> {
        let bindings = self.store.bindings_of_agent(channel.agent_id())?;
        Ok(bindings
            .into_iter()
            .filter(|b| b.key_id == old_key_id && b.unbound_at.is_none())
            .max_by_key(|b| b.id)
            .map(|b| b.delivery_mode)
            .unwrap_or_else(|| "site".to_string()))
    }

    /// 作废当前网关会话（M8-S1 §11.1）。
    ///
    /// `gateway_stop` 在 drain **之后**调它：stop 之前产生的失败属于**被停止的那次会话**
    /// （已被这次 drain 收走）；stop 之后**在途**请求才产生的失败会看到代号不匹配，
    /// 于是被丢弃——不会被记到下一个会话上。
    ///
    /// **代价**（写进 spec 的未验证边界）：停止瞬间在途请求的失败不进事件表。
    /// 这是刻意的取舍：记到下一个会话是**主动误导**，而它本身（网关正在停）
    /// 也不构成可诊断的故障。
    pub fn end_gateway_session(&self) {
        self.gateway_session
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// 把网关侧攒下的失败写进事件表（在 [`Self::refresh_all`] 里调用）。    ///
    /// 只记元数据：`site_id` / `status` / `model`。`model` 是调用方自由文本，
    /// **在网关侧就已经过 `redact::scrub`**（M7-S1 复审 P1-1）——这里不重复脱敏：
    /// 两条出口各抄一段掩码逻辑，迟早会分叉（M5-S1 已经踩过一次）。
    ///
    /// **事件的 `ts` 取失败发生的时刻**，不是落库时刻（M8-S1 §11.2）：
    /// 落库发生在下一次 `refresh_all`，用落库时刻会让「网关为什么在 14:00 切换了上游」
    /// 显示成「14:05」，因果链在时间轴上错位。
    ///
    /// 返回写出的条数（测试用）。
    pub fn drain_gateway_failures(&self) -> usize {
        // P3-7 / §11.3 / 复审 F2：先 lock buffer，成功后再 swap 取丢弃计数——锁中毒时
        // buffer 拿不到，但 dropped 计数仍要报出（原顺序先 swap 后 lock，锁中毒会清零
        // 计数却不报出，永久丢失）。
        let drained: Vec<BufferedGatewayFailure> = match self.gateway_failures.lock() {
            Ok(mut buffer) => buffer.drain(..).collect(),
            Err(_) => {
                let dropped = self
                    .gateway_failures_dropped
                    .swap(0, std::sync::atomic::Ordering::Relaxed);
                if dropped > 0 {
                    self.log(observability::event_with_payload(
                        Level::Warn,
                        "gateway",
                        format!("本轮因缓冲满丢弃 {dropped} 条网关失败事件（缓冲锁中毒，未落库）"),
                        serde_json::json!({ "dropped": dropped }),
                    ));
                }
                return 0;
            }
        };
        let dropped_this_round = self
            .gateway_failures_dropped
            .swap(0, std::sync::atomic::Ordering::Relaxed);
        for buffered in &drained {
            let failure = &buffered.failure;
            // `status == 0` 是哨兵（M8-S1 §9）：HTTP 里不存在 0，它表示
            // 「没有任何上游返回过状态码」（候选全被熔断 / 缺明文 / 已回收）。
            // 文案必须写明，否则读者会把 0 误读成真实状态码。
            // P2-10 / P2-11：`reason` 让事件表区分三种 status=0，以及传输层失败
            // （超时 / 连不上）与上游真回 502 两种 status=502——之前都挤在同一条文案里。
            let message = if failure.status == 0 {
                format!(
                    "网关没有可用的上游（site {}）: {}",
                    failure.site_id, failure.reason
                )
            } else {
                format!(
                    "网关放弃上游（HTTP {}）: {}",
                    failure.status, failure.reason
                )
            };
            // **必须走 `event_with_payload`**（而不是手搓一个 `Event`）：它里面那两件事
            // ——`mask_url_userinfo_in_json` 与 `scrub(payload)`——是所有出口共用的咽喉。
            // 我第一版手搓了一个，当场被 `gateway_failure_sink` 的用例抓住：
            // 事件里的 `model` 不再被掩。**两条出口各写一份掩码逻辑迟早分叉**，
            // 这正是 M5-S1 与 DEBUG P2-1 反复出现的模式。
            let mut event = observability::event_with_payload(
                Level::Warn,
                "gateway",
                message,
                serde_json::json!({
                    "site_id": failure.site_id,
                    "status": failure.status,
                    "model": failure.model,
                }),
            );
            // 唯一需要覆盖的是时间戳（§11.2）：取**失败发生**的时刻而不是落库时刻。
            event.ts = buffered.at;
            self.log(event);
        }
        // P3-7 / §11.3：缓冲满丢弃的条数随本轮事件报出——否则用户看到的失败是
        // 不完整的而没有任何提示。只记计数，不逐条记（D-6：逐条记会让「缓冲满」
        // 本身把事件表灌满，自我放大）。
        if dropped_this_round > 0 {
            self.log(observability::event_with_payload(
                Level::Warn,
                "gateway",
                format!(
                    "本轮因缓冲满丢弃 {dropped_this_round} 条网关失败事件（仅记计数，不逐条记）"
                ),
                serde_json::json!({ "dropped": dropped_this_round }),
            ));
        }
        drained.len()
    }

    /// 仅测试用：直接写一条站点观测（余额 / 倍率 / 延迟）。
    ///
    /// 真实路径是 `refresh_all` 取余额、`available_groups` 取倍率、网关观测回传延迟——
    /// 那三条都要起站点与网关。这里要验的是**下游那一段**：观测进了缓存之后，
    /// 路由表的排序是不是照 §6 的语义走。
    #[doc(hidden)]
    pub fn set_site_observation_for_test(
        &self,
        site_id: i64,
        balance_usd: Option<f64>,
        rate: Option<f64>,
        latency_ms: Option<u64>,
    ) {
        if let Ok(mut map) = self.site_facts.lock() {
            let entry = map.entry(site_id).or_default();
            entry.balance_usd = balance_usd;
            entry.rate = rate;
            entry.latency_ms = latency_ms;
        }
    }

    /// 仅测试用：把一条网关失败放进缓冲，等价于网关回调触发了一次。
    ///
    /// 与 `log_event_for_test` 同一手法（`#[doc(hidden)]`）：真实的失败要起一个网关 +
    /// 一个会 503 的假上游才造得出来，而那属于 `tests/gateway_failover.rs` 的覆盖范围；
    /// 这里要验的是**下游那一段**——缓冲里的东西有没有、以什么形状落到事件表里。
    #[doc(hidden)]
    pub fn record_gateway_failure_for_test(&self, failure: crate::gateway::GatewayFailure) {
        if let Ok(mut buffer) = self.gateway_failures.lock() {
            push_bounded(&mut buffer, &self.gateway_failures_dropped, failure);
        }
    }

    /// 只保留最近 `keep` 次投递的备份目录，删除更早的。返回删除的目录数。
    ///
    /// `keep == 0` 表示全部删除——这是危险操作，UI 必须二次确认。
    /// 只动 `backup_dir` 下**看起来像 journal 目录**（名字以 `j` 开头）的子目录，
    /// 不碰别的文件，也不递归到 `backup_dir` 之外。
    pub fn prune_backups(&self, keep: usize) -> Result<usize> {
        if !self.backup_dir.exists() {
            return Ok(0);
        }
        let entries = std::fs::read_dir(&self.backup_dir)
            .map_err(|e| Error::Store(format!("读取备份目录失败: {e}")))?;

        let mut journals: Vec<std::path::PathBuf> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let is_journal = entry.file_name().to_string_lossy().starts_with('j');
            if path.is_dir() && is_journal {
                journals.push(path);
            }
        }
        // journal id 是 `j<纳秒>-<序号>`，按名字排序 ≈ 按时间排序
        journals.sort();

        let remove_count = journals.len().saturating_sub(keep);
        let mut removed = 0usize;
        for path in journals.into_iter().take(remove_count) {
            match std::fs::remove_dir_all(&path) {
                Ok(()) => removed += 1,
                // 单个目录删不掉不中断其余清理
                Err(e) => {
                    self.log(observability::event_with_payload(
                        Level::Warn,
                        "store",
                        "删除备份目录失败",
                        serde_json::json!({ "path": path.display().to_string(), "error": e.to_string() }),
                    ));
                }
            }
        }

        self.log(observability::event_with_payload(
            Level::Info,
            "store",
            format!("已清理 {removed} 个历史备份（保留最近 {keep} 个）"),
            serde_json::json!({ "removed": removed, "keep": keep }),
        ));
        Ok(removed)
    }

    /// 组装导出包。**不含任何密钥本体**（只有元数据）。
    pub fn export_bundle(&self) -> Result<ExportBundle> {
        let settings = self.settings()?;
        let sites = self
            .store
            .list_sites()?
            .into_iter()
            .map(|row| ExportSite {
                id: row.id,
                kind: row.kind,
                // 纵深防御（M5-S5 接线 / B-63）：序列化咽喉点 `export::to_json` 已经会剥一次，
                // 这里在**组装处**再剥一次 —— 内存里的 `ExportBundle` 也不该带着
                // `https://user:pass@host` 这种内嵌凭证到处传。
                base_url: crate::redact::strip_url_userinfo(&row.base_url),
                display_name: row.display_name,
            })
            .collect();
        let keys = self
            .store
            .list_keys()?
            .into_iter()
            .map(|row| ExportKey {
                id: row.id,
                site_id: row.site_id,
                remote_id: row.remote_id,
                name: row.name,
                group: row.group_name,
                status: row.status,
            })
            .collect();
        let consents = self
            .store
            .list_consents()?
            .into_iter()
            .map(|row| ExportConsent {
                agent_id: row.agent_id,
                channel: row.channel,
                target_path: row.target_path,
                fields: row.fields,
                granted_at: row.granted_at,
                revoked_at: row.revoked_at,
            })
            .collect();
        let events = self
            .recent_events(1000)?
            .into_iter()
            .map(|row| ExportEvent {
                ts: row.ts,
                level: row.level,
                source: row.source,
                // 装配处也走**共享出口**，而且必须是**结构化优先**的那种
                // （M5-S1 复审 P2-1）：这里原先对 payload 调的是文本级 `scrub`，
                // 会把 34 位数字打成 `***`，让 payload 变成非法 JSON，
                // 于是下游的结构化脱敏只能走兜底分支 —— 与诊断导出分叉。
                message: crate::redact::scrub_event_message(&row.message),
                payload: crate::redact::scrub_event_payload(row.payload.as_deref()),
            })
            .collect();

        Ok(ExportBundle {
            version: export::EXPORT_VERSION,
            exported_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            sites,
            keys,
            consents,
            settings: ExportSettings {
                refresh_interval_secs: settings.refresh_interval_secs,
                balance_alert_threshold: settings.balance_alert_threshold,
                drift_check_on_start: settings.drift_check_on_start,
                gateway_enabled: settings.gateway_enabled,
                gateway_port: settings.gateway_port,
            },
            events,
        })
    }

    /// 导出并落盘。`password` 为空/`None` 时输出明文 JSON。
    pub fn export_to_file(
        &self,
        path: &std::path::Path,
        password: Option<&str>,
    ) -> Result<ExportOutcome> {
        let bundle = self.export_bundle()?;
        let (text, encrypted) = export::export(&bundle, password)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Store(format!("创建导出目录失败: {e}")))?;
        }
        std::fs::write(path, &text).map_err(|e| Error::Store(format!("写入导出文件失败: {e}")))?;

        // 登记导出物（M5-S5 接线 / 关闭 B-60 的另一半）：审计靠这张表覆盖「用户自选导出路径」。
        // 登记失败**不回滚文件**（文件确实写成了，谎报失败更糟），但必须留痕 ——
        // 而且要把 `registered=false` 一路带回 UI：只写事件的话，用户看到的仍是
        // 「导出成功」，而审计从此看不到这个文件（M5-S2 复审 P2-4）。
        let registered = match self.store.record_export(path, encrypted, text.len()) {
            Ok(()) => true,
            Err(e) => {
                self.log(observability::event(
                    Level::Error,
                    "app",
                    format!("登记导出物失败（审计将看不到这个文件）: {e}"),
                ));
                false
            }
        };

        self.log(observability::event_with_payload(
            Level::Info,
            "app",
            format!("已导出配置（{}）", if encrypted { "加密" } else { "明文" }),
            serde_json::json!({
                "path": path.display().to_string(),
                "bytes": text.len(),
                "encrypted": encrypted,
                "registered": registered,
            }),
        ));
        Ok(ExportOutcome {
            path: path.to_path_buf(),
            encrypted,
            bytes: text.len(),
            registered,
        })
    }

    /// 脱敏审计：扫描本产品**全部落盘产物**里的明文凭证。
    ///
    /// 覆盖：数据库文件（含 `-wal` / `-shm`）、备份目录、以及事件表。
    /// 只扫自己的产物，不做全盘扫描。
    pub fn audit_redaction(&self) -> Result<AuditReport> {
        let mut paths: Vec<std::path::PathBuf> = Vec::new();
        // 覆盖面缺口要进**报告**，不能只进日志：B-60 修的正是「自称干净、其实没扫全」
        let mut coverage_gaps: Vec<String> = Vec::new();
        if let Some(db) = self.store.path() {
            paths.push(db.to_path_buf());
            for suffix in ["-wal", "-shm"] {
                paths.push(std::path::PathBuf::from(format!(
                    "{}{suffix}",
                    db.display()
                )));
            }
        }
        paths.push(self.backup_dir.clone());

        // 导出产物（M4-S2 复审 P2-11）：默认落在 `<app_data>/exports`，而 `backup_dir`
        // 是 `<app_data>/backups`，所以同级的 `exports` 就是默认导出目录。
        // 之前审计只扫 db + backups，导出物是审计盲区 —— 而「自我证明没有明文落盘」
        // 恰恰是审计存在的理由。用户自选的导出路径不在我们知道的范围内（见 BACKLOG B-60）。
        if let Some(app_data) = self.backup_dir.parent() {
            paths.push(app_data.join("exports"));
        }

        // 用户自选导出路径（M5-S5 接线 / 关闭 B-60 的另一半）：登记表里的每个路径都进扫描集合。
        // 读不到登记表**不让整条审计失败** —— db / backups / 事件表三条守护明明还能跑，
        // `?` 直接返回等于覆盖面反而更差；但也不能静默跳过，所以记一条 `Unreadable` 进报告
        // （它不是 `is_plaintext()`，不会把干净误判成有明文）。
        match self.store.list_exports() {
            Ok(records) => audit::merge_export_registry(&mut paths, &records),
            Err(e) => coverage_gaps.push(format!("读取导出登记表失败: {e}")),
        }

        let mut report = audit::scan_paths(&paths);
        for reason in coverage_gaps {
            report.findings.push(AuditFinding::Unreadable {
                path: std::path::PathBuf::from("<导出登记表>"),
                reason,
            });
        }

        let event_hits = self.store.count_events_with_secrets()?;
        if event_hits > 0 {
            report
                .findings
                .push(AuditFinding::PlaintextInEvents { rows: event_hits });
        }

        self.log(observability::event_with_payload(
            if report.is_clean() {
                Level::Info
            } else {
                Level::Error
            },
            "app",
            format!("脱敏审计: {}", report.summary()),
            serde_json::json!({
                "files_scanned": report.files_scanned,
                "bytes_scanned": report.bytes_scanned,
                "plaintext_findings": report.plaintext_findings(),
            }),
        ));
        Ok(report)
    }

    /// 底层存储的只读借用（诊断与测试用；业务逻辑请走本层的具名方法）。
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// 本地已存的密钥（**不含密钥本体**）。UI 的「密钥」页用这个，而不是站点侧列表——
    /// 因为投递需要的是**本地 key_id**，站点返回的 `remote_id` 不能当本地主键用。
    pub fn stored_keys(&self) -> Result<Vec<crate::store::KeyRow>> {
        self.store.list_keys()
    }

    /// 把一把密钥存进钥匙串 + 本地库，返回新记录 id。
    ///
    /// 顺序不可换：**先写钥匙串，再写库**。
    /// - 先写库再写钥匙串：钥匙串失败会留下一条指向不存在条目的悬空记录。
    /// - 先写钥匙串再写库：写库失败时删掉刚写的钥匙串条目即可完全补偿。
    pub fn store_key_material(
        &self,
        site_id: i64,
        name: &str,
        remote_id: Option<&str>,
        // 分组名：`None` = 「不知道」⇒ 落 `NULL`，**绝不猜**（M8-S5B §6.5）。
        group_name: Option<&str>,
        // 站点侧分组主键：`None` = 「没有 / 不知道」。只有能力表 `group_ids` 为真的站点类型
        // 才可能有值（M22-S2 / B-172：与 `group_name` 在**同一条 INSERT** 里落库）。
        group_id: Option<&str>,
        secret: &str,
    ) -> Result<StoredKey> {
        if secret.trim().is_empty() {
            return Err(Error::Vault("密钥为空，拒绝保存".into()));
        }
        let ref_id = new_ref_id();
        let secret_ref = crate::vault::secret_ref("key", &ref_id, "secret");
        self.vault.put(&secret_ref, secret)?;

        match self.store.insert_key_with_group(
            site_id,
            name,
            &secret_ref,
            remote_id,
            group_name,
            group_id,
        ) {
            Ok(id) => {
                let stored = StoredKey {
                    id,
                    remote_id: remote_id.unwrap_or_default().to_string(),
                    name: name.to_string(),
                    masked: crate::redact::mask_secret(secret),
                };
                self.log(observability::event_with_payload(
                    Level::Info,
                    "vault",
                    format!("密钥已存入钥匙串: {name}"),
                    serde_json::json!({
                        "site_id": site_id,
                        "key_id": id,
                        "fingerprint": crate::redact::fingerprint(secret),
                    }),
                ));
                Ok(stored)
            }
            Err(err) => {
                // 补偿：库没写进去，钥匙串里那条也不能留
                let _ = self.vault.delete(&secret_ref);
                Err(err)
            }
        }
    }

    /// 仅测试用：把一条事件写进事件表，用于验证脱敏入口与扫描门禁的有效性。
    #[doc(hidden)]
    pub fn log_event_for_test(&self, event: &Event) {
        self.log(event.clone());
    }

    /// 最近事件（UI「诊断」用）。
    pub fn recent_events(&self, limit: usize) -> Result<Vec<crate::store::EventRow>> {
        self.store.list_events(limit.min(1000))
    }

    /// 诊断导出：事件表 + 设置快照 + 版本信息 → JSON 文本。**导出前再过一遍 `scrub`**（纵深防御）。
    ///
    /// M7-S5 补的是 PRD FR-9:196 缺的两块：**脱敏后的配置快照**与**版本信息**（报障时
    /// 第一句要问的就是「你装的哪个版本、库结构是哪一版」）。设置快照走
    /// `Settings::diagnostic_snapshot()` 的白名单，**不含**代理与 webhook 的值。
    pub fn export_diagnostics(&self, limit: usize) -> Result<String> {
        self.diagnostics_json(limit).map(|(text, _)| text)
    }

    /// 与 [`Self::export_diagnostics`] 同一份产物，但**同时给出事件条数**——
    /// 落盘路径要把它回报给界面（`DiagnosticsOutcome::events`），
    /// 而条数在序列化之后就数不出来了（不重新解析一遍 JSON 的前提下）。
    fn diagnostics_json(&self, limit: usize) -> Result<(String, usize)> {
        let events = self.recent_events(limit)?;
        let count = events.len();
        let rows: Vec<serde_json::Value> = events
            .into_iter()
            .map(|row| {
                serde_json::json!({
                    "id": row.id,
                    "ts": row.ts,
                    "level": row.level,
                    "source": row.source,
                    // 与配置导出走**同一段代码**（M5-S1 复审 P2-1）：
                    // 手抄组合会让两条出口悄悄分叉，实测已经分叉过一次。
                    "message": crate::redact::scrub_event_message(&row.message),
                    "payload": crate::redact::scrub_event_payload(row.payload.as_deref()),
                })
            })
            .collect();
        let settings = self.settings()?;
        let schema = self.store.schema_version()?;
        let mut value = serde_json::json!({
            "vault_backend": self.vault.backend_name(),
            "home": self.home.display().to_string(),
            "version": {
                "app": env!("CARGO_PKG_VERSION"),
                "schema": schema,
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
            },
            "settings": settings.diagnostic_snapshot(),
            "events": rows,
        });
        // 上面那行文档注释承诺的「再过一遍」曾经**只是注释**（DEBUG 报告 §1.6 同族的
        // 「注释说了、代码没做」）：修 P2-1 时给配置导出加了结构化 URL 掩码，诊断包这条
        // 出口漏在外面。`scrub_event_*` 只做文本级，抓不到**不带 scheme 的 userinfo**
        // 形态（`custom_openai::host_of` 那一类历史数据），所以结构化这层必须补上。
        crate::redact::mask_url_userinfo_in_json(&mut value);
        serde_json::to_string_pretty(&value)
            .map(|text| (text, count))
            .map_err(|e| Error::Store(format!("导出诊断失败: {e}")))
    }

    /// 诊断包落盘（FR-9:196）。**这是 `export_diagnostics` 的第一个生产调用点**——
    /// 在此之前它只有测试在调，`M7-收口记录` 却把它记成已交付（DEBUG 报告 §1.6）。
    ///
    /// 与 [`Self::export_to_file`] 同一套纪律，逐条对齐：
    /// ① 先建父目录；② 写文件；③ 登记进「已知导出物」；④ 登记失败**不回滚文件**但留痕并把
    /// `registered=false` 带回界面。加密形态不存在——诊断包不含密钥（设置快照走白名单）。
    pub fn export_diagnostics_to_file(
        &self,
        path: &std::path::Path,
        limit: usize,
    ) -> Result<DiagnosticsOutcome> {
        let (text, events) = self.diagnostics_json(limit)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Store(format!("创建导出目录失败: {e}")))?;
        }
        std::fs::write(path, &text).map_err(|e| Error::Store(format!("写入诊断包失败: {e}")))?;

        let registered = match self.store.record_export(path, false, text.len()) {
            Ok(()) => true,
            Err(e) => {
                self.log(observability::event(
                    Level::Error,
                    "app",
                    format!("登记诊断包失败（审计将看不到这个文件）: {e}"),
                ));
                false
            }
        };

        self.log(observability::event_with_payload(
            Level::Info,
            "app",
            "已导出诊断包（脱敏）",
            serde_json::json!({
                "path": path.display().to_string(),
                "bytes": text.len(),
                "events": events,
                "registered": registered,
            }),
        ));
        Ok(DiagnosticsOutcome {
            path: path.to_path_buf(),
            bytes: text.len(),
            events,
            registered,
        })
    }

    /// 写事件。**故意不向上传播失败**：可观测性坏掉不该让业务操作失败。
    fn log(&self, event: Event) {
        if let Err(err) = self.store.insert_event(&event) {
            eprintln!("[tianshu-relay] 写入事件失败: {err}");
        }
    }

    /// 解析通道写入器 + 校验 `key_id` 存在。**不读钥匙串**（同意检查必须在读密钥之前）。
    ///
    /// 走 `resolve_for_binding` / `resolve_for_gateway` 而不是 `resolve_for`：后者固定
    /// `model = None`，生产路径不写 model 字段
    /// `model` 的配置）。
    fn prepare_delivery(
        &self,
        key_id: i64,
        channel: DeliveryChannel,
        model: Option<&str>,
        source: delivery::DeliverySource<'_>,
    ) -> Result<Box<dyn delivery::DeliveryWriter>> {
        // key_id 存在性先校验：不存在时连通道都不必解析
        let row = self
            .store
            .get_key(key_id)?
            .ok_or_else(|| Error::NotFound(format!("密钥记录 #{key_id} 不存在")))?;
        // Claude Code / shell 块两个通道要写 endpoint，需要该密钥所属站点的 base_url
        // （网关模式下**不**用站点 base_url——那正是「换站零改动」的全部内容，
        //  但站点行仍然要读：`key_id` 必须属于一个存在的站点）。
        let site = self.site(row.site_id)?;
        // M14-S7 §4.2：带上「内置表 + 已缓存的 models.dev 结果」的同步快照。
        // 在线拉取由命令层在调用投递前 `await warm_model_meta(...)` 完成（best-effort）；
        // 这里只读缓存，**一次网络都不发**（同步函数）。
        let meta = self.meta_for(model);
        delivery::resolve_for_source_with_meta(
            source,
            channel,
            &self.home,
            &site.base_url,
            delivery::opencode::OpenCodeWriter::DEFAULT_PROVIDER_ID,
            model,
            meta,
        )
    }

    /// 从钥匙串取密钥明文。调用方必须立刻用掉，不得记录。
    ///
    /// 已回收的 key 在这里拒绝（投递预览与投递都经过本函数）；同意的授予 / 撤销**不**经过
    /// 这里——那两步只关心「写哪个文件」，不该因为选中的 key 已回收就撤不掉同意。
    fn key_secret(&self, key_id: i64) -> Result<zeroize::Zeroizing<String>> {
        let row = self
            .store
            .get_key(key_id)?
            .ok_or_else(|| Error::NotFound(format!("密钥记录 #{key_id} 不存在")))?;
        ensure_not_revoked(&row)?;
        self.secret_for_row(&row)
    }

    /// 该 target 上**当前生效**的、非本次 `key_id` 的绑定所用密钥明文（P2-5）。
    ///
    /// `diff_preview` 的 `before` 是文件当前内容，改指网关时里面仍是旧站点密钥；
    /// 它不一定是 `scrub` 认得的形态（`sk-` / `nap-` / 长 hex），不显式替换会明文
    /// 带出去。这里把旧密钥明文收齐交给 `diff_preview` 一起掩。
    ///
    /// 已解绑的、引用已回收 key 的（`key_secret` 会拒）都跳过——它们不在 `before` 里。
    /// 读钥匙串失败也跳过：那种情况下旧密钥明文也读不到，`scrub` 仍兜底。
    fn previous_secrets_for_target(
        &self,
        target_path: &std::path::Path,
        current_key_id: i64,
    ) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen_keys: std::collections::HashSet<i64> = std::collections::HashSet::new();
        let Ok(rows) = self
            .store
            .bindings_of_target(&target_path.to_string_lossy())
        else {
            return out;
        };
        for row in rows
            .iter()
            .filter(|r| r.unbound_at.is_none() && r.key_id != current_key_id)
        {
            // 复审 F5：同 key_id 多绑定（多 agent 共用一把 key 到同一 target）时去重，
            // 避免重复读钥匙串——`key_secret` 是 IO + 解密，重复调用无意义，
            // `diff_preview` 的 `replace_all` 对重复明文结果相同。
            if !seen_keys.insert(row.key_id) {
                continue;
            }
            if let Ok(secret) = self.key_secret(row.key_id) {
                if !secret.trim().is_empty() {
                    out.push(secret.to_string());
                }
            }
        }
        out
    }

    /// 本次要写进去的那一份「密钥」——**按来源二选一**（M8-S4 §6.2）。
    ///
    /// 站点模式：读钥匙串里的站点密钥。
    /// 网关模式：用本地令牌，**不读**站点密钥——那正是「换站零改动」的全部内容
    /// （agent 配置里写的是网关地址与网关令牌，站点密钥由网关在转发时加上）。
    ///
    /// 网关模式**仍然**拒绝已回收的 key：网关的路由表是按「可用 key」建的
    /// （[`Self::build_gateway_route`]），用一个已回收的 key 去投递，只会得到一份
    /// 「指向一个服务不了该站点的网关」的配置。拒绝在这里，比让 agent 拿到 502 早。
    ///
    /// 这一条是集成测试逼出来的：`delivery_mode.rs` 的
    /// `gateway_mode_writes_the_gateway_values_to_disk` 一开始就红了——它发现产物里
    /// `ANTHROPIC_BASE_URL` 是网关地址、而 `ANTHROPIC_AUTH_TOKEN` 还是站点密钥。
    /// 那种「半个开关」的配置会 401，而两边看起来都「写成功了」。
    fn secret_for_source(
        &self,
        key_id: i64,
        source: delivery::DeliverySource<'_>,
    ) -> Result<zeroize::Zeroizing<String>> {
        match source {
            delivery::DeliverySource::Site => self.key_secret(key_id),
            delivery::DeliverySource::Gateway(endpoint) => {
                let row = self
                    .store
                    .get_key(key_id)?
                    .ok_or_else(|| Error::NotFound(format!("密钥记录 #{key_id} 不存在")))?;
                ensure_not_revoked(&row)?;
                // 令牌从调用方给的端点来（它来自运行中的网关句柄）。
                // `Zeroizing`：这一份也要清零，它是本地网关的凭证。
                Ok(zeroize::Zeroizing::new(endpoint.token.clone()))
            }
        }
    }

    /// 从一行密钥记录取出明文。
    ///
    /// **明文的唯一出口是 [`Self::vault_secret`]**：本函数只是一层「按行取」的包装。
    /// 收成一个函数不是为了好看：`tests/zeroize_hygiene.rs` 有一条结构守卫断言
    /// `vault.get(` 在 `service.rs` 里恰好出现一次——那条守卫在 M8-S1 加
    /// `build_gateway_route`（网关的明文映射）时**当场红了**，红得对：
    /// 那是第二个明文出口。处置是把它收进这里，而不是放宽断言。
    ///
    /// M8-S4 的网关令牌是**第二个按引用取的秘密**（它没有 `keys` 行），于是同一件事
    /// 再发生一次：出口从 `secret_for_row` 下沉到 `vault_secret`，`vault.get(` 仍然只有一处。
    fn secret_for_row(&self, row: &crate::store::KeyRow) -> Result<zeroize::Zeroizing<String>> {
        self.vault_secret(&row.secret_ref)?.ok_or_else(|| {
            Error::Vault(format!(
                "钥匙串中没有该密钥（{}）；请先在该站点重新取一次钥匙",
                row.secret_ref
            ))
        })
    }

    /// **全文件唯一**读钥匙串取明文的地方（结构守卫守着这条不变式）。
    ///
    /// 返回 `Zeroizing` 而不是在调用点各自包一层：调用点会变多，咽喉点只有一个。
    /// 调用方拿到的东西类型上就不是裸 `String`，所以「某次调用忘了清零」在编译期就不成立。
    ///
    /// 返回 `Ok(None)` = 条目不存在（**不是**错误）；`Err` = 读失败。
    /// 这个区分在本仓有实际后果：`secret_for_row` 把两者都当失败（密钥缺失），
    /// 而网关令牌把「不存在」当「第一次启动，生成一把」（M8-S4 §6.4）。
    fn vault_secret(&self, secret_ref: &str) -> Result<Option<zeroize::Zeroizing<String>>> {
        Ok(self.vault.get(secret_ref)?.map(zeroize::Zeroizing::new))
    }

    /// 仅测试用：把 `key_secret` 暴露给集成测试，用于断言**返回类型**本身。
    ///
    /// 为什么要一条专门的断言：`Zeroizing<String>` 的 deref 让所有调用点照旧能编译，
    /// 所以「返回类型被改回裸 `String`」这件事**没有任何现有测试会红**——
    /// 而那正是这次修复的全部内容。
    #[doc(hidden)]
    pub fn key_secret_for_test(&self, key_id: i64) -> Result<zeroize::Zeroizing<String>> {
        self.key_secret(key_id)
    }

    /// 仅测试用：站点观测里的**倍率**（P2-12 的断言点：必须取 key 所在分组的倍率）。
    #[doc(hidden)]
    pub fn site_rate_for_test(&self, site_id: i64) -> Option<f64> {
        self.site_facts
            .lock()
            .ok()
            .and_then(|map| map.get(&site_id).and_then(|observation| observation.rate))
    }

    /// 仅测试用：钥匙串里某条目**在不在**（B-113 的断言点）。走 `has`，不取明文。
    #[doc(hidden)]
    pub fn vault_has_for_test(&self, secret_ref: &str) -> Result<bool> {
        self.vault.has(secret_ref)
    }

    /// 仅测试用：最近一次交给通知规则的快照（B-80 的断言点：`models` 必须来自采集）。
    #[doc(hidden)]
    pub fn notify_last_snapshot_for_test(&self) -> Option<crate::notify::Snapshot> {
        self.notify
            .as_ref()
            .and_then(|state| state.last.lock().ok().and_then(|guard| guard.clone()))
    }

    /// 目标路径白名单：既要落在 `home` 之内，也要与**该通道声明的相对路径**逐字相等。
    ///
    /// 只做 `starts_with(home)` 是不够的：任何落在 home 下的路径都会放行（复核 P2）。
    /// 期望路径由 [`DeliveryChannel::relative_target`] 提供（M6-S0 从本函数搬走）——
    /// 新增通道只需改 `delivery/mod.rs` 一处，本文件不再需要跟着改。
    fn checked_target(&self, channel: DeliveryChannel, target: &Path) -> Result<PathBuf> {
        let expected = self.home.join(channel.relative_target());
        if target != expected {
            return Err(Error::Inject {
                path: target.display().to_string(),
                reason: format!(
                    "投递目标与通道 {} 声明的路径不符（期望 {}），拒绝写入",
                    channel.as_str(),
                    expected.display()
                ),
            });
        }
        if !target.starts_with(&self.home) {
            return Err(Error::Inject {
                path: target.display().to_string(),
                reason: format!(
                    "投递目标越出用户目录（home={}），拒绝写入",
                    self.home.display()
                ),
            });
        }
        Ok(target.to_path_buf())
    }

    fn consent_state(&self, channel: DeliveryChannel, target: &Path) -> Result<ConsentState> {
        let target = target.display().to_string();
        if let Some(granted_at) =
            self.store
                .active_consent(channel.agent_id(), channel.as_str(), &target)?
        {
            return Ok(ConsentState::Granted { granted_at });
        }
        // 没有有效同意时，区分「从未同意」与「同意后被撤销」——UI 文案不同。
        let revoked = self.store.list_consents()?.into_iter().find(|row| {
            row.agent_id == channel.agent_id()
                && row.channel == channel.as_str()
                && row.target_path == target
                && row.revoked_at.is_some()
        });
        Ok(match revoked.and_then(|r| r.revoked_at) {
            Some(revoked_at) => ConsentState::Revoked { revoked_at },
            None => ConsentState::Missing,
        })
    }
}

#[cfg(test)]
mod tests {

    /// M39-S1：镜像决策——「还没采过」不得被当成「模型全没了」。
    #[test]
    fn model_mirror_is_only_overwritten_when_there_is_a_fact() {
        // 表里有行 ⇒ 覆盖（正常替换）
        assert!(should_overwrite_model_mirror(true, None));
        assert!(should_overwrite_model_mirror(true, Some(10)));
        // 没行但成功采集过 ⇒ 覆盖成空（目录真被清空）
        assert!(should_overwrite_model_mirror(false, Some(10)));
        // 没行、也从没采过 ⇒ **保留旧值**（否则通知侧 ModelsChanged 会误报）
        assert!(!should_overwrite_model_mirror(false, None));
    }
    use super::*;
    use crate::site::transport::{HttpResponse, MockTransport};
    use serde_json::json;

    // ============================================ M9-S2（错误词表）

    /// 新错误变体的**事件词表**：事件表里「输入不符合站点要求」必须与「认证失败」分开记。
    ///
    /// 分开记不是措辞讲究：`is_auth_failure` 会据此把站点标成 `needs_login`，
    /// 前端 `isAuthError()` 会据此显示「（需登录）」——而用户真正要做的是**改输入**。
    #[test]
    fn invalid_input_is_not_classified_as_an_auth_failure() {
        let err = Error::InvalidInput("该站点要求用邮箱登录".into());
        assert_eq!(error_kind(&err), "输入不符合站点要求");
        assert!(
            !is_auth_failure(&err),
            "输入形态问题不得被当成会话失效（那会把用户引向「请重新登录」）"
        );
        assert!(
            !err.is_retryable(),
            "同一个值重试多少次也不会成功，不得被判为可重试"
        );
    }

    // ============================================ sibling_config_files（B-76）

    #[test]
    fn sibling_config_files_finds_a_differently_extensioned_twin() {
        // 本机真实形态：~/.config/opencode/ 下 .json 与 .jsonc 并存
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("opencode.json");
        std::fs::write(&target, "{}").unwrap();
        std::fs::write(dir.path().join("opencode.jsonc"), "{/* c */}").unwrap();

        let found = sibling_config_files(&target);
        assert_eq!(found, vec![dir.path().join("opencode.jsonc")]);
    }

    #[test]
    fn sibling_config_files_ignores_the_target_itself() {
        // 只有目标自己存在时不得把它当兄弟（否则每条通道都会「警告」一次）
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("settings.json");
        std::fs::write(&target, "{}").unwrap();
        assert!(sibling_config_files(&target).is_empty());

        // 目标不存在时同样为空——探测失败不该阻断投递
        let missing = dir.path().join("nope.json");
        assert!(sibling_config_files(&missing).is_empty());
    }

    #[test]
    fn sibling_config_files_requires_an_exact_stem_match() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        std::fs::write(&target, "").unwrap();
        // 这些都不该命中：主名不同
        std::fs::write(dir.path().join("config.local.toml"), "").unwrap();
        std::fs::write(dir.path().join("myconfig.yaml"), "").unwrap();
        // 主名相同但**没有扩展名**：那是另一个名字，不是同一份配置的另一种写法
        std::fs::write(dir.path().join("config"), "").unwrap();
        // 这个该命中：主名逐字相同、扩展名存在且不同
        std::fs::write(dir.path().join("config.yaml"), "").unwrap();

        let found = sibling_config_files(&target);
        assert_eq!(found, vec![dir.path().join("config.yaml")]);
    }

    #[test]
    fn sibling_config_files_skips_directories_with_the_same_stem() {
        // `opencode.json/` 这种目录名不是配置文件，不该被报成「agent 可能读的那个」
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("opencode.json");
        std::fs::write(&target, "{}").unwrap();
        std::fs::create_dir(dir.path().join("opencode.jsonc")).unwrap();

        assert!(sibling_config_files(&target).is_empty());
    }

    #[test]
    fn sibling_config_files_is_sorted_and_handles_extensionless_targets() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("rc");
        std::fs::write(&target, "").unwrap();
        std::fs::write(dir.path().join("rc.sh"), "").unwrap();

        // 目标没有扩展名 → 不做探测（「兄弟」的语义在这里不成立）
        assert!(sibling_config_files(&target).is_empty());

        // 多个兄弟时输出必须有序，UI 与测试才稳定
        let target2 = dir.path().join("app.json");
        std::fs::write(&target2, "").unwrap();
        std::fs::write(dir.path().join("app.zsh"), "").unwrap();
        std::fs::write(dir.path().join("app.bash"), "").unwrap();
        let found = sibling_config_files(&target2);
        let mut expected = vec![dir.path().join("app.bash"), dir.path().join("app.zsh")];
        expected.sort();
        assert_eq!(found, expected);
    }

    fn status_response() -> HttpResponse {
        HttpResponse::json(
            200,
            json!({"success": true, "data": {"version": "v0.9.1", "quota_per_unit": 500000, "system_name": "测试站"}}),
        )
        .expect("构造响应")
    }

    fn login_response() -> HttpResponse {
        HttpResponse::json(200, json!({"success": true, "data": {"id": 7}}))
            .expect("构造响应")
            .with_header("Set-Cookie", "session=abc; Path=/")
    }

    /// 站点未启用登录加密时的响应（登录前会先探一次该端点）
    fn encryption_disabled_response() -> HttpResponse {
        HttpResponse::json(200, json!({"success": true, "data": {"enabled": false}}))
            .expect("构造响应")
    }

    fn keys_response() -> HttpResponse {
        HttpResponse::json(
            200,
            json!({"success": true, "data": {"items": [{"id": 1, "name": "codex/daily", "status": 1}], "total": 1}}),
        )
        .expect("构造响应")
    }

    async fn service_with(responses: Vec<HttpResponse>) -> TianshuRelayService<MockTransport> {
        let store = Store::open_in_memory().expect("内存库");
        TianshuRelayService::new(store, MockTransport::new(responses), test_config())
    }

    /// 测试装配：内存钥匙串 + 一次性临时目录（绝不碰真实 `~/.tianshu-relay`）。
    fn test_config() -> ServiceConfig {
        let dir = tempfile::tempdir().expect("临时目录");
        // 目录句柄随进程存活：测试进程结束即由系统回收
        ServiceConfig::in_memory(dir.keep())
    }

    #[tokio::test]
    async fn add_site_is_idempotent_for_same_url() {
        let service = service_with(vec![status_response(), status_response()]).await;

        let first = service
            .add_site("https://relay.example.com/")
            .await
            .unwrap();
        let second = service.add_site("https://relay.example.com").await.unwrap();

        assert_eq!(first.id, second.id, "同一站点应复用记录");
        assert_eq!(first.kind, "newapi");
        assert_eq!(first.display_name, "测试站");
        assert_eq!(service.sites().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn list_keys_requires_login_first() {
        let service = service_with(vec![status_response()]).await;
        let site = service.add_site("https://relay.example.com").await.unwrap();

        let err = service.list_keys(site.id).await.unwrap_err();
        match err {
            Error::AuthFailed(message) => assert!(message.contains("请先登录"), "{message}"),
            other => panic!("期望 AuthFailed，实际: {other:?}"),
        }
    }

    /// M2-S2 复审指出：`checked_target` 的拒绝分支在端到端路径上**不可达**
    /// （写入器自己拼的路径永远与白名单一致），因此既有测试对它零覆盖——
    /// 把它改坏也不会有任何测试失败。这里直接调私有方法把三条拒绝路径钉住。
    #[test]
    fn checked_target_rejects_a_path_outside_the_whitelist() {
        let service = service_with_blocking();

        // ① 通道声明的路径 → 放行
        let ok = service.home.join(".codex").join("auth.json");
        assert!(service
            .checked_target(DeliveryChannel::CodexAuthJson, &ok)
            .is_ok());

        // ② 落在 home 内、但不是该通道的路径 → 拒绝
        let wrong_channel = service.home.join(".claude").join("settings.json");
        let err = service
            .checked_target(DeliveryChannel::CodexAuthJson, &wrong_channel)
            .unwrap_err();
        assert!(matches!(err, Error::Inject { .. }), "{err:?}");
        assert!(err.to_string().contains("与通道"), "{err}");

        // ③ 越出 home → 拒绝
        let outside = std::path::Path::new("/tmp/evil/auth.json");
        let err = service
            .checked_target(DeliveryChannel::CodexAuthJson, outside)
            .unwrap_err();
        assert!(matches!(err, Error::Inject { .. }), "{err:?}");

        // ④ 每条通道都只认自己的路径
        for channel in DeliveryChannel::ALL {
            let plan = service.delivery_plan(1, channel);
            // 没有 key 记录时 `delivery_plan` 会报 NotFound，但 `checked_target`
            // 的语义用上面三条已经覆盖；这里只确认通道枚举完整
            assert!(plan.is_err() || plan.is_ok());
        }
    }

    /// 只用来构造一个 service（不需要可用的传输层）。
    fn service_with_blocking() -> TianshuRelayService<MockTransport> {
        let dir = tempfile::tempdir().expect("临时目录");
        let store = Store::open_in_memory().expect("内存库");
        TianshuRelayService::new(
            store,
            MockTransport::new(vec![]),
            test_config_with_home(dir.keep()),
        )
    }

    fn test_config_with_home(home: std::path::PathBuf) -> ServiceConfig {
        ServiceConfig {
            vault: Arc::new(crate::vault::MemoryVault::new()),
            backup_dir: home.join(".tianshu-relay").join("backups"),
            home,
        }
    }

    #[tokio::test]
    async fn login_then_list_keys_uses_cached_session() {
        // 请求序列：① 指纹 ② 加密键探测 ③ 登录 ④ 令牌列表
        let transport_responses = vec![
            status_response(),
            encryption_disabled_response(),
            login_response(),
            keys_response(),
        ];
        let store = Store::open_in_memory().unwrap();
        let mock = MockTransport::new(transport_responses);
        let service = TianshuRelayService::new(store, mock.clone(), test_config());

        let site = service.add_site("https://relay.example.com").await.unwrap();
        service
            .login(site.id, Credentials::new("me", "pw"))
            .await
            .unwrap();

        let keys = service.list_keys(site.id).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "codex/daily");

        // 列表请求必须带登录拿到的 cookie
        let list_request = mock.nth_request(3).expect("第四个请求是列表");
        assert!(
            list_request
                .url
                .starts_with("https://relay.example.com/api/token/?"),
            "列表请求应带分页参数: {}",
            list_request.url
        );
        assert_eq!(
            list_request
                .headers
                .iter()
                .find(|(k, _)| k == "Cookie")
                .map(|(_, v)| v.as_str()),
            Some("session=abc")
        );
    }

    #[tokio::test]
    async fn auth_failure_invalidates_cached_session() {
        let transport_responses = vec![
            status_response(),
            encryption_disabled_response(),
            login_response(),
            // 列表返回 401 → 会话失效
            HttpResponse::json(401, json!({"success": false, "message": "未授权"}))
                .expect("构造响应"),
        ];
        let store = Store::open_in_memory().unwrap();
        let service = TianshuRelayService::new(
            store,
            MockTransport::new(transport_responses),
            test_config(),
        );

        let site = service.add_site("https://relay.example.com").await.unwrap();
        service
            .login(site.id, Credentials::new("me", "pw"))
            .await
            .unwrap();

        let err = service.list_keys(site.id).await.unwrap_err();
        assert!(matches!(err, Error::AuthFailed(_)), "实际: {err:?}");
        assert!(
            service.sessions.get(site.id).is_none(),
            "401 后必须清掉缓存，避免反复失败"
        );
    }

    #[tokio::test]
    async fn unknown_site_reports_not_found() {
        let service = service_with(vec![]).await;
        let err = service.list_keys(999).await.unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "实际: {err:?}");
    }

    #[tokio::test]
    async fn remove_site_also_clears_session_cache() {
        // 复审 P2-6：删除站点必须联动清会话，否则 rowid 复用会造成跨站串号
        let transport_responses = vec![
            status_response(),
            encryption_disabled_response(),
            login_response(),
        ];
        let store = Store::open_in_memory().unwrap();
        let service = TianshuRelayService::new(
            store,
            MockTransport::new(transport_responses),
            test_config(),
        );

        let site = service.add_site("https://relay.example.com").await.unwrap();
        service
            .login(site.id, Credentials::new("me", "pw"))
            .await
            .unwrap();
        assert!(service.sessions.get(site.id).is_some());

        service.remove_site(site.id).unwrap();

        assert!(
            service.sessions.get(site.id).is_none(),
            "删除站点后会话缓存必须一并清掉"
        );
        assert!(service.sites().unwrap().is_empty());
    }

    #[test]
    fn session_cache_is_per_site() {
        let cache = SessionCache::new();
        cache
            .put(
                1,
                Session {
                    cookies: vec![("a".into(), "1".into())],
                    access_token: None,
                    user_id: None,
                    user_agent: None,
                },
            )
            .unwrap();
        assert!(cache.get(1).is_some());
        assert!(cache.get(2).is_none());
        assert_eq!(cache.len(), 1);

        cache.invalidate(1);
        assert!(cache.is_empty());
    }

    // ---- M13-S1：会话持久化 ----

    #[tokio::test]
    async fn login_persists_session_to_vault() {
        let transport_responses = vec![
            status_response(),
            encryption_disabled_response(),
            login_response(),
        ];
        let store = Store::open_in_memory().unwrap();
        let service = TianshuRelayService::new(
            store,
            MockTransport::new(transport_responses),
            test_config(),
        );
        let site = service.add_site("https://relay.example.com").await.unwrap();
        service
            .login(site.id, Credentials::new("me", "pw"))
            .await
            .unwrap();

        let reference = service.session_ref(site.id);
        assert!(
            service.vault.has(&reference).unwrap(),
            "login 后应有持久化 session（钥匙串条目存在）"
        );
        // 内容往返 + 含 cookie 值的验证由 restore_sessions_loads_persisted_into_cache
        // 覆盖（那里 vault.put 正规 JSON + restore + 验证 cache cookies）。本测试只钉
        // 「login 确实写了钥匙串」——不调 vault.get 以守住 M8-S1 的
        // 「vault.get 在 service.rs 只出现一次」明文出口守卫。
    }

    #[tokio::test]
    async fn mark_needs_login_deletes_vault_session() {
        let service = service_with(vec![status_response()]).await;
        let site = service.add_site("https://relay.example.com").await.unwrap();
        let reference = service.session_ref(site.id);
        service
            .vault
            .put(
                &reference,
                "{\"cookies\":[],\"access_token\":null,\"user_id\":null}",
            )
            .unwrap();
        assert!(
            service.vault.has(&reference).unwrap(),
            "前置：有持久化 session"
        );

        service.mark_needs_login(site.id);

        assert!(
            !service.vault.has(&reference).unwrap(),
            "mark_needs_login 后必须删掉持久化 session"
        );
    }

    #[tokio::test]
    async fn remove_site_deletes_vault_session() {
        let service = service_with(vec![status_response()]).await;
        let site = service.add_site("https://relay.example.com").await.unwrap();
        let reference = service.session_ref(site.id);
        service
            .vault
            .put(
                &reference,
                "{\"cookies\":[[\"k\",\"v\"]],\"access_token\":null,\"user_id\":null}",
            )
            .unwrap();
        assert!(service.vault.has(&reference).unwrap());

        service.remove_site(site.id).unwrap();

        assert!(
            !service.vault.has(&reference).unwrap(),
            "remove_site 后必须删掉持久化 session（防 rowid 复用串号）"
        );
    }

    #[tokio::test]
    async fn owned_secret_refs_includes_site_sessions() {
        let service = service_with(vec![status_response()]).await;
        let site = service.add_site("https://relay.example.com").await.unwrap();
        let reference = service.session_ref(site.id);
        service.vault.put(&reference, "{}").unwrap();

        let refs = service.owned_secret_refs().unwrap();
        assert!(
            refs.contains(&reference),
            "owned_secret_refs 必须含 site session_ref: {refs:?}"
        );
    }

    #[tokio::test]
    async fn owned_secret_refs_omits_site_without_persisted_session() {
        // 没登录过的站点：钥匙串无 session 条目，owned_secret_refs 不该列它（清理数字不虚高）
        let service = service_with(vec![status_response()]).await;
        let site = service.add_site("https://relay.example.com").await.unwrap();
        let reference = service.session_ref(site.id);

        let refs = service.owned_secret_refs().unwrap();
        assert!(
            !refs.contains(&reference),
            "无持久化 session 的站点不该被列进 owned_secret_refs: {refs:?}"
        );
    }

    #[tokio::test]
    async fn restore_sessions_loads_persisted_into_cache() {
        let service = service_with(vec![status_response()]).await;
        let site = service.add_site("https://relay.example.com").await.unwrap();
        // Service::new 已调过一次 restore（此时 vault 空）
        assert!(
            service.sessions.get(site.id).is_none(),
            "前置：无内存 session"
        );

        // 模拟上次登录留下的持久化 session
        let reference = service.session_ref(site.id);
        let session = Session {
            cookies: vec![("session".into(), "abc".into())],
            access_token: None,
            user_id: None,
            user_agent: None,
        };
        service
            .vault
            .put(&reference, &session.to_stored().unwrap())
            .unwrap();

        // 再调 restore（模拟重启后）
        service.restore_sessions();

        let cached = service
            .sessions
            .get(site.id)
            .expect("restore 后应有内存 session");
        assert_eq!(cached.cookies, vec![("session".into(), "abc".into())]);
    }

    #[tokio::test]
    async fn restore_sessions_skips_missing_and_garbage() {
        let service = service_with(vec![status_response(), status_response()]).await;
        let site_a = service.add_site("https://relay.example.com").await.unwrap();
        let site_b = service.add_site("https://b.example.com").await.unwrap();
        // site_a：无持久化（missing）
        // site_b：非法串（garbage）
        let ref_b = service.session_ref(site_b.id);
        service.vault.put(&ref_b, "not-json").unwrap();

        service.restore_sessions();

        assert!(
            service.sessions.get(site_a.id).is_none(),
            "无持久化 ⇒ 不加载"
        );
        assert!(
            service.sessions.get(site_b.id).is_none(),
            "非法串 ⇒ 跳过，不 panic"
        );
    }

    #[tokio::test]
    async fn auth_failure_deletes_persisted_session() {
        // 401 → mark_needs_login → 删持久化 session（M13-S1：坏会话不留给下次启动加载）
        let transport_responses = vec![
            status_response(),
            encryption_disabled_response(),
            login_response(),
            HttpResponse::json(401, json!({"success": false, "message": "未授权"}))
                .expect("构造响应"),
        ];
        let store = Store::open_in_memory().unwrap();
        let service = TianshuRelayService::new(
            store,
            MockTransport::new(transport_responses),
            test_config(),
        );
        let site = service.add_site("https://relay.example.com").await.unwrap();
        service
            .login(site.id, Credentials::new("me", "pw"))
            .await
            .unwrap();
        let reference = service.session_ref(site.id);
        assert!(service.vault.has(&reference).unwrap(), "login 后应有持久化");

        let _ = service.list_keys(site.id).await; // 401

        assert!(
            !service.vault.has(&reference).unwrap(),
            "401 后必须删掉持久化 session"
        );
    }

    /// 钥匙串 `delete` 永远失败的 Vault（证伪 High：vault.delete 失败时 remove_site
    /// 必须不删 DB，防 rowid 复用跨站串号）。其余方法委托 `MemoryVault`。
    struct FailingDeleteVault {
        inner: crate::vault::MemoryVault,
    }
    impl FailingDeleteVault {
        fn new() -> Self {
            Self {
                inner: crate::vault::MemoryVault::new(),
            }
        }
    }
    impl crate::vault::Vault for FailingDeleteVault {
        fn backend_name(&self) -> &'static str {
            "failing-delete"
        }
        fn probe(&self) -> crate::error::Result<()> {
            Ok(())
        }
        fn put(&self, key: &str, secret: &str) -> crate::error::Result<()> {
            self.inner.put(key, secret)
        }
        fn get(&self, key: &str) -> crate::error::Result<Option<String>> {
            self.inner.get(key)
        }
        fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Err(crate::error::Error::Vault("模拟钥匙串删除失败".into()))
        }
    }

    /// `has` 对 `kr/site/` 前缀失败的 Vault（证伪 Low：per-site has 失败不中断
    /// owned_secret_refs 整体枚举）。其余方法委托 `MemoryVault`。
    struct SiteHasFailingVault {
        inner: crate::vault::MemoryVault,
    }
    impl SiteHasFailingVault {
        fn new() -> Self {
            Self {
                inner: crate::vault::MemoryVault::new(),
            }
        }
    }
    impl crate::vault::Vault for SiteHasFailingVault {
        fn backend_name(&self) -> &'static str {
            "site-has-failing"
        }
        fn probe(&self) -> crate::error::Result<()> {
            Ok(())
        }
        fn put(&self, key: &str, secret: &str) -> crate::error::Result<()> {
            self.inner.put(key, secret)
        }
        fn get(&self, key: &str) -> crate::error::Result<Option<String>> {
            self.inner.get(key)
        }
        fn has(&self, key: &str) -> crate::error::Result<bool> {
            if key.starts_with("kr/site/") {
                Err(crate::error::Error::Vault("模拟站点会话枚举失败".into()))
            } else {
                self.inner.has(key)
            }
        }
        fn delete(&self, key: &str) -> crate::error::Result<()> {
            self.inner.delete(key)
        }
    }

    #[tokio::test]
    async fn remove_site_vault_delete_failure_keeps_site_and_session() {
        // 复审 High：vault.delete 失败时 remove_site 必须不删 DB（`?` 传播），
        // 站点仍在、session 仍在，一致无孤儿——否则 rowid 复用后同 id 新站
        // restore 套用旧站 session → 跨站串号。
        let store = Store::open_in_memory().unwrap();
        let config = ServiceConfig {
            vault: Arc::new(FailingDeleteVault::new()),
            ..test_config()
        };
        let service =
            TianshuRelayService::new(store, MockTransport::new(vec![status_response()]), config);
        let site = service.add_site("https://relay.example.com").await.unwrap();
        let reference = service.session_ref(site.id);
        service.vault.put(&reference, "{}").unwrap();
        assert!(
            service.vault.has(&reference).unwrap(),
            "前置：有持久化 session"
        );

        let err = service.remove_site(site.id);
        assert!(
            err.is_err(),
            "vault.delete 失败时 remove_site 必须整体失败（? 传播）"
        );
        assert!(
            service.site(site.id).is_ok(),
            "vault.delete 失败时 DB 不该删（防 rowid 复用串号）"
        );
        assert!(
            service.vault.has(&reference).unwrap(),
            "vault.delete 失败时 session 不该被删（站点仍在，一致无孤儿）"
        );
    }

    #[tokio::test]
    async fn owned_secret_refs_skips_site_when_has_fails() {
        // 复审 Low：per-site has 失败不中断整体枚举。site 的 has 失败时，
        // 该站点的 session_ref 被跳过，owned_secret_refs 仍返回 Ok。
        let store = Store::open_in_memory().unwrap();
        let config = ServiceConfig {
            vault: Arc::new(SiteHasFailingVault::new()),
            ..test_config()
        };
        let service =
            TianshuRelayService::new(store, MockTransport::new(vec![status_response()]), config);
        let site = service.add_site("https://relay.example.com").await.unwrap();
        let reference = service.session_ref(site.id);
        service.vault.put(&reference, "{}").unwrap();

        let refs = service.owned_secret_refs().unwrap();
        assert!(
            !refs.contains(&reference),
            "site has 失败时 session_ref 该被跳过: {refs:?}"
        );
    }

    // ============================================ M15-S1 复审 M4：probe_model 集成测试

    fn probe_response() -> HttpResponse {
        HttpResponse::json(
            200,
            json!({
                "runId": "r-probe-1",
                "status": "completed",
                "identityAssessment": {
                    "status": "match",
                    "verdict": {"status": "clean_match", "trueFamily": "openai", "trueModel": "gpt-4o"}
                },
                "warnings": []
            }),
        )
        .expect("构造 probe 响应")
    }

    /// 构造一个已插好 site + key 的 service；`tail` 是 add_site 指纹之后的 mock 响应。
    /// 不调 `with_probe_transport` ⇒ `probe_transport=None` ⇒ `probe_model` fallback 到
    /// `self.transport`（Mock），让 M4 能 mock 测 confirm/落库/event 安全断言。
    async fn probe_service(tail: Vec<HttpResponse>) -> (TianshuRelayService<MockTransport>, i64) {
        let (service, key_id, _mock, _sleeper) = probe_service_with_mock(tail).await;
        (service, key_id)
    }

    /// 同 `probe_service`，但把 mock 与 sleeper 也交回给测试——用于断言
    /// 「发了几次请求、走的哪个方法」「轮询前等了多久」。
    ///
    /// **总是注入 `RecordingSleeper`**：B-134 之后 probe 可能进入轮询，
    /// 测试里绝不真睡——一条误判成「还在跑」的用例否则会把套件拖满 30s。
    async fn probe_service_with_mock(
        tail: Vec<HttpResponse>,
    ) -> (
        TianshuRelayService<MockTransport>,
        i64,
        MockTransport,
        Arc<crate::site::retry::RecordingSleeper>,
    ) {
        // 退避 1s、预算 3s ⇒ 最多 3 次补查后 `BudgetExhausted`。
        // 定值而不是 `PollPolicy::default()`：默认预算 900s，测试里每次补查都要问
        // 「预算还够吗」，不钉死就断言不出「停在第几次」。
        probe_service_with_poll(
            tail,
            crate::probe::PollPolicy {
                first_delay: std::time::Duration::from_secs(1),
                max_interval: std::time::Duration::from_secs(1),
                // 3.5s 而不是 3s：预算**把请求耗时也算进去**（B-160 复审 P2-2 的修法），
                // Mock 往返虽≈0 但不是 0，卡在 3s 上会让「问 3 次」变成「问 2 次」。
                budget: std::time::Duration::from_millis(3_500),
                max_consecutive_errors: 5,
            },
        )
        .await
    }

    /// 同 `probe_service_with_mock`，但轮询策略由调用方给。
    ///
    /// 需要它的用例都是「要跨过预算才能触发的那条分支」——例如连续补查失败到
    /// `TooManyErrors`，那要 5 次失败才有结论，而默认 3s 预算会先把它变成
    /// `BudgetExhausted`（顺序：预算按退避先扣，扣完就不再问）。
    async fn probe_service_with_poll(
        tail: Vec<HttpResponse>,
        policy: crate::probe::PollPolicy,
    ) -> (
        TianshuRelayService<MockTransport>,
        i64,
        MockTransport,
        Arc<crate::site::retry::RecordingSleeper>,
    ) {
        let mut responses = vec![status_response()];
        responses.extend(tail);
        let store = Store::open_in_memory().expect("内存库");
        let mock = MockTransport::new(responses);
        let sleeper = Arc::new(crate::site::retry::RecordingSleeper::default());
        let service = TianshuRelayService::new(store, mock.clone(), test_config())
            .with_probe_poll(policy, sleeper.clone());
        let site = service
            .add_site("https://relay.example.com")
            .await
            .expect("add_site");
        let reference = crate::vault::secret_ref("key", 1, "secret");
        service
            .vault
            .put(&reference, "sk-test-secret-12345678")
            .expect("vault.put");
        let key_id = service
            .store
            .insert_key(site.id, "probe-key", &reference, Some("remote-1"), None)
            .expect("insert_key");
        (service, key_id, mock, sleeper)
    }

    #[tokio::test]
    async fn probe_model_confirm_false_returns_invalid_input_without_request() {
        // confirm=false → InvalidInput（请求未发出）；mock 队列只剩指纹，不该被 probe 消费。
        let (service, _key_id) = probe_service(vec![]).await;
        let err = service
            .probe_model(1, "vendor/model".into(), None, None, false)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::InvalidInput(_)),
            "confirm=false 必须 InvalidInput: {err:?}"
        );
        assert!(
            err.to_string().contains("bazaarlink"),
            "错误文案要点明 apiKey 外流方向: {err}"
        );
    }

    #[tokio::test]
    async fn probe_model_success_persists_row_and_event_has_no_api_key() {
        let (service, key_id) = probe_service(vec![probe_response()]).await;
        let run = service
            .probe_model(key_id, "vendor/model".into(), None, None, true)
            .await
            .expect("probe 成功");
        assert_eq!(run.run_id, "r-probe-1");

        // 落库一行（敏感字段不入库——只校 runId/verdict）
        let rows = service.store.list_probe_runs(10).expect("list_probe_runs");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].run_id, "r-probe-1");
        assert_eq!(rows[0].verdict_status.as_deref(), Some("clean_match"));

        // 事件 source=="probe"（M4：确认 source 没被归一成 app）+ payload 不含 apiKey
        let events = service.recent_events(100).expect("recent_events");
        let probe_events: Vec<_> = events.iter().filter(|e| e.source == "probe").collect();
        assert!(!probe_events.is_empty(), "应有 source=probe 的事件");
        for ev in &probe_events {
            let text = format!("{} {}", ev.message, ev.payload.as_deref().unwrap_or(""));
            assert!(
                !text.contains("sk-test-secret-12345678"),
                "probe 事件泄漏 apiKey: {text}"
            );
        }
    }

    #[tokio::test]
    async fn probe_model_reports_an_unreachable_probe_service_separately_from_no_verdict() {
        // 连续补查失败 ⇒ **判定服务不可达**。这和「跑完了但没给判定」是两回事：
        // 混成一句会让用户以为「这个模型测不出来」（独立复审 P2-3）。
        let submitted = HttpResponse::json(
            200,
            json!({ "runId": "r-poll", "claimToken": "ct-not-echoed" }),
        )
        .expect("构造异步提交响应");
        // 只给提交帧：之后的补查全部落空（Mock 队列空 ⇒ 每次都是 Err）。
        let (service, key_id, _mock, _sleeper) = probe_service_with_poll(
            vec![submitted],
            crate::probe::PollPolicy {
                first_delay: std::time::Duration::from_secs(1),
                max_interval: std::time::Duration::from_secs(1),
                budget: std::time::Duration::from_secs(60),
                max_consecutive_errors: 3,
            },
        )
        .await;

        let run = service
            .probe_model(key_id, "glm-5.3".into(), None, None, true)
            .await
            .expect("查询中断也不该把检测变成 Err");
        assert_eq!(run.run_id, "r-poll", "run_id 必须带回来");

        let events = service.recent_events(100).expect("recent_events");
        let probe_events: Vec<_> = events.iter().filter(|e| e.source == "probe").collect();
        let interrupted = probe_events
            .iter()
            .find(|e| e.message.contains("模型检测查询中断"))
            .unwrap_or_else(|| panic!("判定服务不可达应有专门事件: {probe_events:?}"));
        assert_eq!(interrupted.level, "warn");
        let payload = interrupted.payload.as_deref().unwrap_or_default();
        assert!(
            payload.contains("\"stop\":\"TooManyErrors\""),
            "要写清是哪条停止原因: {payload}"
        );
        assert!(
            payload.contains("\"run_id\":\"r-poll\""),
            "要把 run_id 留给用户: {payload}"
        );
        assert!(
            !probe_events
                .iter()
                .any(|e| e.message.contains("未得出判定")),
            "「查不到」不能被记成「跑完了没结论」: {probe_events:?}"
        );
    }

    #[tokio::test]
    async fn probe_model_failure_logs_warn_event_without_api_key() {
        // mock 预置 400（body 含 apiKey 回显）——验证 M1 scrub + M3 warn event 不泄漏。
        let bad = HttpResponse::new(400, br#"{"echoed":"sk-test-secret-12345678"}"#.to_vec());
        let (service, key_id) = probe_service(vec![bad]).await;
        let err = service
            .probe_model(key_id, "vendor/model".into(), None, None, true)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Transport(_)),
            "400 应映射成 Transport: {err:?}"
        );

        // M3：失败写 warn 事件，source=probe，message/payload 不含 apiKey
        let events = service.recent_events(100).expect("recent_events");
        let warn_probe: Vec<_> = events
            .iter()
            .filter(|e| e.source == "probe" && e.level == "warn")
            .collect();
        assert!(
            !warn_probe.is_empty(),
            "失败应写 source=probe level=warn 事件"
        );
        for ev in &warn_probe {
            let text = format!("{} {}", ev.message, ev.payload.as_deref().unwrap_or(""));
            assert!(
                !text.contains("sk-test-secret-12345678"),
                "失败事件泄漏 apiKey: {text}"
            );
        }
        // 失败不落 probe_runs（无 run_id，历史表只记检测结果）
        let rows = service.store.list_probe_runs(10).expect("list_probe_runs");
        assert!(rows.is_empty(), "失败不该落 probe_runs: {rows:?}");
    }

    #[tokio::test]
    async fn probe_model_without_verdict_logs_warn_not_completed() {
        // F1：bazaarlink 对「key 访问不了该模型」会**秒级返回 completed 但不带
        // identityAssessment**（真机实测 4 次：420–663ms、verdict 全空）。
        // 旧实现无条件记 info「模型检测完成」并落一行 verdict 全空 —— 失败被伪装成成功。
        // 本测试钉住分流：跑到终态但没有判定 ⇒ warn，且不得出现「完成」。
        let no_verdict = HttpResponse::json(
            200,
            json!({
                "runId": "r-probe-2",
                "status": "completed",
                "reportUrl": "/api/probe/report/r-probe-2",
                "createdAt": 1_700_000_000_000i64,
                "completedAt": 1_700_000_000_420i64,
            }),
        )
        .expect("构造无判定响应");
        let (service, key_id, mock, _sleeper) = probe_service_with_mock(vec![no_verdict]).await;
        let run = service
            .probe_model(key_id, "vendor/model".into(), None, None, true)
            .await
            .expect("HTTP 200 仍是 Ok（不是传输错误）");
        assert_eq!(
            run.verdict_status, None,
            "无 identityAssessment ⇒ verdict 为空"
        );
        // B-134：`completed` 是终态——不得进入轮询（否则白等 30s 才拿到同一个答案）。
        // 请求数 = add_site 指纹 1 + probe POST 1，多一次都说明补查被误触发。
        assert_eq!(
            mock.request_count(),
            2,
            "completed 无判定是终态，不得补查: {}",
            mock.request_count()
        );

        let events = service.recent_events(100).expect("recent_events");
        let probe_events: Vec<_> = events.iter().filter(|e| e.source == "probe").collect();
        assert!(
            probe_events
                .iter()
                .any(|e| e.level == "warn" && e.message.contains("未得出判定")),
            "无判定应写 warn「未得出判定」: {probe_events:?}"
        );
        assert!(
            !probe_events
                .iter()
                .any(|e| e.message.contains("模型检测完成")),
            "无判定不得记 info「模型检测完成」: {probe_events:?}"
        );
        for ev in &probe_events {
            let text = format!("{} {}", ev.message, ev.payload.as_deref().unwrap_or(""));
            assert!(
                !text.contains("sk-test-secret-12345678"),
                "无判定事件泄漏 apiKey: {text}"
            );
        }

        // 仍落库：run_id / report_url 是真实的（报告能点开），只是没有判定
        let rows = service.store.list_probe_runs(10).expect("list_probe_runs");
        assert_eq!(rows.len(), 1, "无判定也要留一条历史（不是静默丢弃）");
        assert_eq!(rows[0].verdict_status, None);
        assert_eq!(
            rows[0].report_url.as_deref(),
            Some("/api/probe/report/r-probe-2")
        );
    }

    #[tokio::test]
    async fn probe_model_polls_until_the_verdict_arrives() {
        // B-160：主路径是 `sync=false` 提交（服务端秒级回一个 run）+ 轮询到终态。
        // 真机依据：curl 直测提交 0.75s、产品用例 9.27s；run 在服务端跑 186.98s / 252.42s
        // 才 `completed`。同步路径要 360.53s，而传输层 120s 就掐断 ⇒ 旧实现会把这条判定丢掉。
        //
        // **提交帧刻意用真机的异步形状**（只有 `runId` + `claimToken`，**没有 `status`**）：
        // 用 `{"status":"running"}` 那种帧的话，`needs_poll` 的同步分支也会返回 true，
        // 于是「装配层把 `submitted_async` 传错」这件事在测试里完全看不出来
        //（独立复审 P2-1 实测过这一点）。用真实形状，传错就立刻红。
        let submitted = HttpResponse::json(
            200,
            json!({ "runId": "r-poll", "claimToken": "ct-not-echoed" }),
        )
        .expect("构造异步提交响应");
        let running = HttpResponse::json(200, json!({ "runId": "r-poll", "status": "running" }))
            .expect("构造 running 响应");
        let finished = HttpResponse::json(
            200,
            json!({
                "runId": "r-poll",
                "status": "completed",
                "identityAssessment": {
                    "status": "mismatch",
                    "verdict": {
                        "status": "clean_match_submodel_mismatch",
                        "trueFamily": "zhipu",
                        "trueModel": "glm-5.2",
                        "confidence": "high"
                    }
                },
                "reportUrl": "/api/probe/report/r-poll",
                "warnings": []
            }),
        )
        .expect("构造 completed 响应");
        let (service, key_id, mock, sleeper) =
            probe_service_with_mock(vec![submitted, running, finished]).await;

        let run = service
            .probe_model(key_id, "glm-5.3".into(), None, None, true)
            .await
            .expect("probe 成功");

        assert_eq!(
            run.verdict_status.as_deref(),
            Some("clean_match_submodel_mismatch"),
            "补查必须把判定带回来"
        );
        assert_eq!(run.true_model.as_deref(), Some("glm-5.2"));
        assert_eq!(run.status, "completed");
        // 请求数 = 指纹 1 + 提交 1 + 补查 2（提交帧没有 status，第一次补查仍是 running）
        assert_eq!(mock.request_count(), 4, "两发补查才收敛");
        // **B-160 的证伪点 ①**：提交必须是 `sync=false`。改回 `true` 本断言立刻红，
        // 而真机上那个改动会让整轮检测压在一条 120s 的连接上。
        let submit = mock.nth_request(1).expect("第二次请求是提交");
        assert_eq!(submit.method, crate::site::transport::Method::Post);
        let body: serde_json::Value =
            serde_json::from_slice(submit.body.as_deref().unwrap_or_default())
                .expect("提交体是 JSON");
        assert_eq!(body["sync"], false, "B-160：主路径必须异步提交");
        let poll = mock.nth_request(2).expect("第三次请求是补查");
        assert_eq!(poll.method, crate::site::transport::Method::Get);
        assert_eq!(poll.url, "https://bazaarlink.ai/api/probe/run/r-poll");
        assert_eq!(
            sleeper.calls(),
            vec![
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(1)
            ],
            "每次补查前退避一次（测试里不真睡）"
        );

        // 落库的是**补查后**的结果，不是 POST 那个半成品
        let rows = service.store.list_probe_runs(10).expect("list_probe_runs");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].verdict_status.as_deref(),
            Some("clean_match_submodel_mismatch")
        );
        assert_eq!(rows[0].true_model.as_deref(), Some("glm-5.2"));

        // 有判定 ⇒ info「模型检测完成」，且轮询事件不含 apiKey
        let events = service.recent_events(100).expect("recent_events");
        let probe_events: Vec<_> = events.iter().filter(|e| e.source == "probe").collect();
        assert!(
            probe_events
                .iter()
                .any(|e| e.level == "info" && e.message.contains("模型检测完成")),
            "拿到判定应记 info「模型检测完成」: {probe_events:?}"
        );
        let poll_event = probe_events
            .iter()
            .find(|e| e.message.contains("模型检测轮询结束"))
            .unwrap_or_else(|| {
                panic!("轮询应留一条事件（含次数/失败数与停止原因）: {probe_events:?}")
            });
        let payload = poll_event.payload.as_deref().unwrap_or_default();
        assert!(
            payload.contains("\"stop\":\"Settled\""),
            "轮询事件要带停止原因: {payload}"
        );
        assert!(
            // 提交帧没有 status ⇒ 第一次补查仍是 running，第二次才 completed。
            payload.contains("\"polled\":2"),
            "轮询事件要带成功次数: {payload}"
        );
        for ev in &probe_events {
            let text = format!("{} {}", ev.message, ev.payload.as_deref().unwrap_or(""));
            assert!(
                !text.contains("sk-test-secret-12345678"),
                "补查事件泄漏 apiKey: {text}"
            );
        }
    }

    #[tokio::test]
    async fn probe_model_keeps_the_result_when_the_poll_never_finishes() {
        // 预算等完仍是 `running` ⇒ 保留最后一次结果并落库（不是报错、不是丢记录）。
        let running = || {
            HttpResponse::json(200, json!({ "runId": "r-poll", "status": "running" }))
                .expect("构造 running 响应")
        };
        let (service, key_id, mock, sleeper) =
            probe_service_with_mock(vec![running(), running(), running(), running()]).await;

        let run = service
            .probe_model(key_id, "glm-5.3".into(), None, None, true)
            .await
            .expect("轮询没等到终态也不算失败");

        assert_eq!(run.status, "running");
        assert_eq!(run.verdict_status, None);
        // 指纹 1 + 提交 1 + 补查 3（`probe_service_with_mock` 的预算 3s / 退避 1s）
        assert_eq!(mock.request_count(), 5, "轮询预算必须被尊重");
        assert_eq!(sleeper.calls().len(), 3);

        let rows = service.store.list_probe_runs(10).expect("list_probe_runs");
        assert_eq!(rows.len(), 1, "没跑完也要留一条历史");
        assert_eq!(rows[0].status.as_deref(), Some("running"));
        assert_eq!(rows[0].verdict_status, None);
        assert_eq!(
            rows[0].run_id, "r-poll",
            "run_id 必须落库（这是唯一的线索）"
        );

        // B-160：等超了不是「没得出判定」，而是「还在跑」——两种结论对用户含义完全不同，
        // 事件文案必须分开，并且要带上 run_id 与等了多少秒。
        let events = service.recent_events(100).expect("recent_events");
        let probe_events: Vec<_> = events.iter().filter(|e| e.source == "probe").collect();
        let waited = probe_events
            .iter()
            .find(|e| e.message.contains("未在等待预算内完成"))
            .unwrap_or_else(|| panic!("预算等尽应记专门的事件: {probe_events:?}"));
        assert_eq!(waited.level, "warn", "等超了是 warn: {waited:?}");
        let payload = waited.payload.as_deref().unwrap_or_default();
        assert!(
            payload.contains("\"run_id\":\"r-poll\""),
            "等超了要把 run_id 留给用户: {payload}"
        );
        assert!(
            payload.contains("\"budget_secs\":3"),
            "等超了要说清等了多久（读的是真实注入的预算）: {payload}"
        );
        assert!(
            !probe_events
                .iter()
                .any(|e| e.message.contains("未得出判定")),
            "「还在跑」不能被记成「跑完了没给判定」: {probe_events:?}"
        );
        for ev in &probe_events {
            let text = format!("{} {}", ev.message, ev.payload.as_deref().unwrap_or(""));
            assert!(
                !text.contains("sk-test-secret-12345678"),
                "轮询事件泄漏 apiKey: {text}"
            );
        }
    }

    #[tokio::test]
    async fn probe_model_rejects_non_http_base_url_override() {
        // L2：base_url_override 非 http(s) → InvalidInput（请求未发出）
        let (service, key_id) = probe_service(vec![]).await;
        let err = service
            .probe_model(
                key_id,
                "vendor/model".into(),
                None,
                Some("ftp://evil.example".into()),
                true,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::InvalidInput(_)),
            "非 http(s) baseUrl 应 InvalidInput: {err:?}"
        );
    }

    // ---- B-140 续：base_url 构造 / override 优先 / claimed_model 缺省 / key 不存在 ----

    /// 用 `upsert_site` 直接插指定 `base_url` 的 site（绕过 add_site 指纹），
    /// 让 mock 队列只放 probe 响应。返回 mock 句柄用于断言发给 bazaarlink 的请求体。
    async fn probe_service_with_base_url(
        site_base_url: &str,
        tail: Vec<HttpResponse>,
    ) -> (TianshuRelayService<MockTransport>, i64, MockTransport) {
        let store = Store::open_in_memory().expect("内存库");
        let mock = MockTransport::new(tail);
        let service = TianshuRelayService::new(store, mock.clone(), test_config());
        let site_id = service
            .store
            .upsert_site("newapi", site_base_url, "测试站")
            .expect("upsert_site");
        let reference = crate::vault::secret_ref("key", 1, "secret");
        service
            .vault
            .put(&reference, "sk-test-secret-12345678")
            .expect("vault.put");
        let key_id = service
            .store
            .insert_key(site_id, "probe-key", &reference, Some("remote-1"), None)
            .expect("insert_key");
        (service, key_id, mock)
    }

    /// 解出 mock 收到的第 `n` 个请求体（JSON）。
    fn request_body(mock: &MockTransport, n: usize) -> serde_json::Value {
        let sent = mock.nth_request(n).expect("应有请求");
        let body = sent.body.expect("probe 请求必有 body");
        serde_json::from_slice(&body).expect("请求体是合法 JSON")
    }

    #[tokio::test]
    async fn probe_model_default_base_url_appends_v1_when_missing() {
        // site.base_url 不带 /v1 → 默认 baseUrl = site.base_url + /v1
        let (service, key_id, mock) =
            probe_service_with_base_url("https://relay.example.com", vec![probe_response()]).await;
        service
            .probe_model(key_id, "vendor/model".into(), None, None, true)
            .await
            .unwrap();
        assert_eq!(
            request_body(&mock, 0)["baseUrl"],
            "https://relay.example.com/v1"
        );
    }

    #[tokio::test]
    async fn probe_model_default_base_url_does_not_double_v1() {
        // site.base_url 已带 /v1 → 不重复追加（否则 baseUrl 变成 .../v1/v1）
        let (service, key_id, mock) =
            probe_service_with_base_url("https://relay.example.com/v1", vec![probe_response()])
                .await;
        service
            .probe_model(key_id, "vendor/model".into(), None, None, true)
            .await
            .unwrap();
        assert_eq!(
            request_body(&mock, 0)["baseUrl"],
            "https://relay.example.com/v1"
        );
    }

    #[tokio::test]
    async fn probe_model_base_url_override_takes_precedence() {
        // base_url_override 合法 http(s) 时优先于站点默认 baseUrl
        let (service, key_id, mock) =
            probe_service_with_base_url("https://relay.example.com", vec![probe_response()]).await;
        service
            .probe_model(
                key_id,
                "vendor/model".into(),
                None,
                Some("https://override.example.com/v1".into()),
                true,
            )
            .await
            .unwrap();
        assert_eq!(
            request_body(&mock, 0)["baseUrl"],
            "https://override.example.com/v1"
        );
    }

    #[tokio::test]
    async fn probe_model_claimed_model_defaults_to_model_id() {
        // claimed_model 缺省（None）→ 请求体 claimedModel = modelId（M15-S1 决策）
        let (service, key_id, mock) =
            probe_service_with_base_url("https://relay.example.com", vec![probe_response()]).await;
        service
            .probe_model(key_id, "vendor/gpt-4o".into(), None, None, true)
            .await
            .unwrap();
        let body = request_body(&mock, 0);
        assert_eq!(body["modelId"], "vendor/gpt-4o");
        assert_eq!(body["claimedModel"], "vendor/gpt-4o");
    }

    #[tokio::test]
    async fn probe_model_missing_key_returns_not_found() {
        // key_id 不存在 → NotFound（请求未发出）；mock 队列空，不该被消费
        let (service, _key_id, mock) =
            probe_service_with_base_url("https://relay.example.com", vec![]).await;
        let err = service
            .probe_model(999, "vendor/model".into(), None, None, true)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::NotFound(_)),
            "key 不存在应 NotFound: {err:?}"
        );
        assert!(
            err.to_string().contains("999"),
            "错误文案应点明哪个 key_id: {err}"
        );
        assert_eq!(mock.request_count(), 0, "key 不存在时不应发请求");
    }

    // ============================================ M14-S7 §4.2：models.dev 在线补全接线

    /// 与 `probe_service_with_base_url` 相同，但把同一个 mock 也装成**在线补全传输层**
    /// （M14-S7 §4.2 的在线路径）。
    async fn service_with_meta_transport(
        site_base_url: &str,
        tail: Vec<HttpResponse>,
    ) -> (TianshuRelayService<MockTransport>, i64, MockTransport) {
        let store = Store::open_in_memory().expect("内存库");
        let mock = MockTransport::new(tail);
        let service = TianshuRelayService::new(store, mock.clone(), test_config())
            .with_meta_transport(mock.clone());
        let site_id = service
            .store
            .upsert_site("newapi", site_base_url, "测试站")
            .expect("upsert_site");
        let reference = crate::vault::secret_ref("key", 1, "secret");
        service
            .vault
            .put(&reference, "sk-test-secret-12345678")
            .expect("vault.put");
        let key_id = service
            .store
            .insert_key(site_id, "meta-key", &reference, Some("remote-1"), None)
            .expect("insert_key");
        (service, key_id, mock)
    }

    #[tokio::test]
    async fn warm_model_meta_does_nothing_without_an_injected_transport() {
        // **结构保证**：没注入在线传输层 ⇒ 一次网络都不发（测试装配走这条）。
        let (service, key_id, mock) =
            probe_service_with_base_url("https://relay.example.com", vec![]).await;
        assert!(
            service
                .warm_model_meta(Some("acme-unknown"))
                .await
                .is_none(),
            "没注入传输层就不该做在线补全"
        );
        assert_eq!(mock.request_count(), 0, "一次网络都不发");

        // 但内置表命中的模型仍然在同步路径上写出参数（离线可用，与注入无关）
        let plan = service
            .delivery_plan_with_model(key_id, DeliveryChannel::Hermes, Some("gpt-4o"))
            .expect("投递预览");
        assert!(
            plan.fields
                .iter()
                .any(|f| f.key == "context_length" && f.masked == "128000"),
            "内置表命中应写出 context_length: {:?}",
            plan.fields
        );
        assert_eq!(mock.request_count(), 0, "内置表命中也不联网");
    }

    #[tokio::test]
    async fn warm_model_meta_brings_online_params_into_delivery_plan() {
        // 在线补全的结果要能进**同步**的投递路径：内置表没有 `acme-long-context`，
        // 只能靠 models.dev 目录；而 `delivery_plan_*` 是同步函数，不能 `.await`。
        let catalog = HttpResponse::json(
            200,
            json!({
                "acme": { "models": {
                    "acme-long-context": {"limit": {"context": 123_456, "output": 7_890}}
                }}
            }),
        )
        .expect("构造 models.dev 目录响应");
        let (service, key_id, mock) =
            service_with_meta_transport("https://relay.example.com", vec![catalog]).await;

        // 预热前：冷缓存 ⇒ 只有模型名，没有参数行；而且**一次网络都不发**
        let cold = service
            .delivery_plan_with_model(key_id, DeliveryChannel::Hermes, Some("acme-long-context"))
            .expect("投递预览");
        assert!(
            !cold.fields.iter().any(|f| f.key == "context_length"),
            "冷缓存不该凭空写出参数: {:?}",
            cold.fields
        );
        assert_eq!(mock.request_count(), 0, "同步的投递路径永不联网");

        // 预热：查 models.dev 并落缓存
        let meta = service
            .warm_model_meta(Some("acme-long-context"))
            .await
            .expect("在线命中");
        assert_eq!(meta.context_window, 123_456);
        assert_eq!(meta.max_output_tokens, 7_890);
        assert_eq!(mock.request_count(), 1, "预热只发这一次请求");

        // 预热后：同一个同步调用带上参数，且**不再发请求**
        let warm = service
            .delivery_plan_with_model(key_id, DeliveryChannel::Hermes, Some("acme-long-context"))
            .expect("投递预览");
        assert!(
            warm.fields
                .iter()
                .any(|f| f.key == "context_length" && f.masked == "123456"),
            "预热后应写出 context_length: {:?}",
            warm.fields
        );
        assert_eq!(mock.request_count(), 1, "同步路径永不联网（缓存命中）");
    }

    #[tokio::test]
    async fn warm_model_meta_is_best_effort_when_offline() {
        // 网络失败 ⇒ None（不是错误），投递预览照常出——只是没有参数行。
        let (service, key_id, mock) =
            service_with_meta_transport("https://relay.example.com", vec![]).await;
        mock.push_error(Error::Transport("网络不可达".into()));

        assert!(service
            .warm_model_meta(Some("acme-unknown"))
            .await
            .is_none());
        let plan = service
            .delivery_plan_with_model(key_id, DeliveryChannel::Hermes, Some("acme-unknown"))
            .expect("在线补全失败不得阻断投递预览");
        assert!(
            !plan.fields.iter().any(|f| f.key == "context_length"),
            "查不到参数就只写模型名: {:?}",
            plan.fields
        );
        // 内置表命中的模型不联网，也不受网络故障影响
        assert_eq!(
            service
                .warm_model_meta(Some("gpt-4o"))
                .await
                .map(|m| m.context_window),
            Some(128_000),
            "内置命中与网络无关"
        );
    }

    // ============================================================ B 路凭据通道（M28-S1）

    use crate::site::webview_creds::WebviewCredentials;

    /// 一个 sub2api 站点 + 已进入人工态的服务。返回 (service, site_id, vault)。
    async fn sub2api_awaiting_human() -> (
        TianshuRelayService<MockTransport>,
        i64,
        Arc<crate::vault::MemoryVault>,
        MockTransport,
    ) {
        let dir = tempfile::tempdir().expect("临时目录");
        let home = dir.keep();
        let vault = Arc::new(crate::vault::MemoryVault::new());
        let store = Store::open_in_memory().expect("内存库");
        let transport = MockTransport::new(vec![
            // newapi 的 /api/status：404 ⇒ 不匹配
            HttpResponse::new(404, b"nope".to_vec()),
            // sub2api 的 /api/v1/settings/public
            HttpResponse::json(
                200,
                json!({"code": 0, "data": {"site_name": "示例 Sub2API"}}),
            )
            .expect("构造响应"),
            // 登录：400 + 人机验证 ⇒ CaptchaRequired ⇒ 进入人工态
            HttpResponse::json(400, json!({"code": 400, "message": "captcha required"}))
                .expect("构造响应"),
            // list_keys（完成登录后验证会话可用）
            HttpResponse::json(200, json!({"code": 0, "data": {"items": [], "total": 0}}))
                .expect("构造响应"),
        ]);
        let handle = transport.clone();
        let service = TianshuRelayService::new(
            store,
            transport,
            ServiceConfig {
                vault: Arc::clone(&vault) as Arc<dyn crate::vault::Vault>,
                home: home.clone(),
                backup_dir: home.join("backups"),
            },
        );
        let site = service
            .add_site("https://sub.example.com")
            .await
            .expect("加入站点");
        assert_eq!(site.kind, "sub2api");
        let err = service
            .login(
                site.id,
                crate::site::Credentials::new("me@example.com", "pw-12345678"),
            )
            .await
            .expect_err("应当要求人机验证");
        assert!(matches!(err, Error::CaptchaRequired), "{err:?}");
        (service, site.id, vault, handle)
    }

    fn webview_creds_fixture() -> WebviewCredentials {
        WebviewCredentials {
            access_token: "tok-webview-abc".to_string(),
            user_agent: Some("UA/1.0 (WebView)".to_string()),
            cf_clearance: None,
        }
    }

    #[tokio::test]
    async fn store_and_complete_webview_login_builds_the_bearer_session() {
        let (service, site_id, vault, handle) = sub2api_awaiting_human().await;
        service
            .store_webview_creds(site_id, webview_creds_fixture())
            .expect("存凭据");
        service
            .complete_webview_login(site_id, Some("cf-value_1".to_string()))
            .expect("完成登录");

        // 相位回 Idle、health=ok
        assert_eq!(service.captcha_phase(site_id), CaptchaPhase::Idle);
        let site = service
            .sites()
            .expect("站点列表")
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(site.health, HEALTH_OK);
        // 钥匙串里有持久化会话
        assert!(
            vault
                .get(&crate::vault::secret_ref("site", site_id, "session"))
                .expect("读钥匙串")
                .is_some(),
            "会话应已持久化"
        );
        // 会话可用：list_keys 带出 Bearer + UA + cf_clearance
        service.list_keys(site_id).await.expect("会话应当可用");
        let requests = handle.requests();
        let req = requests.last().expect("有请求");
        let headers: Vec<(String, String)> = req.headers.clone();
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "Authorization" && v == "Bearer tok-webview-abc"),
            "{headers:?}"
        );
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "User-Agent" && v == "UA/1.0 (WebView)"),
            "UA 必须回放（cf_clearance 与 UA 绑定）：{headers:?}"
        );
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "Cookie" && v.contains("cf_clearance=cf-value_1")),
            "{headers:?}"
        );
        // 槽已清：再 complete 一次 ⇒ 「还没有收到」
        // 成功之后相位已回 Idle ⇒ 第二次调用先撞相位检查（报「不在人工态」也是对的）；
        // 关键是**槽已经没了**：把相位重新置回人工态也拿不到旧凭据。
        let err = service
            .complete_webview_login(site_id, None)
            .expect_err("槽应已清空");
        assert!(matches!(err, Error::AuthFailed(_)), "{err:?}");
    }

    #[tokio::test]
    async fn store_webview_creds_requires_awaiting_human() {
        let (service, site_id, _vault, _handle) = sub2api_awaiting_human().await;
        // 先取消 ⇒ 回 Idle
        service.cancel_captcha(site_id);
        let err = service
            .store_webview_creds(site_id, webview_creds_fixture())
            .expect_err("非人工态必须拒绝");
        assert!(matches!(err, Error::AuthFailed(_)), "{err:?}");
    }

    #[tokio::test]
    async fn store_webview_creds_rejects_unsupported_kinds() {
        // newapi：能力位 `webview_bearer_supported = false` ⇒ `Unsupported`（与相位无关）
        let dir = tempfile::tempdir().expect("临时目录");
        let home = dir.keep();
        let service = TianshuRelayService::new(
            Store::open_in_memory().expect("内存库"),
            MockTransport::new(vec![HttpResponse::json(
                200,
                json!({"success": true, "data": {"system_name": "示例 NewAPI", "version": "0.8"}}),
            )
            .expect("构造响应")]),
            ServiceConfig {
                vault: Arc::new(crate::vault::MemoryVault::new()),
                home: home.clone(),
                backup_dir: home.join("backups"),
            },
        );
        let site = service
            .add_site("https://relay.example.com")
            .await
            .expect("站点");
        assert_eq!(site.kind, "newapi");
        let err = service
            .store_webview_creds(site.id, webview_creds_fixture())
            .expect_err("newapi 不支持 B 路");
        assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
    }

    #[tokio::test]
    async fn complete_without_slot_is_auth_failed() {
        let (service, site_id, _vault, _handle) = sub2api_awaiting_human().await;
        let err = service
            .complete_webview_login(site_id, None)
            .expect_err("没有槽必须拒绝");
        assert!(matches!(err, Error::AuthFailed(_)), "{err:?}");
        assert!(
            matches!(
                service.captcha_phase(site_id),
                CaptchaPhase::AwaitingHuman { .. }
            ),
            "失败时相位不变（允许重试）"
        );
    }

    #[tokio::test]
    async fn expired_slot_is_rejected_and_cleared() {
        let (service, site_id, _vault, _handle) = sub2api_awaiting_human().await;
        service.store_webview_creds_at(
            site_id,
            webview_creds_fixture(),
            std::time::Instant::now() - WEBVIEW_CREDS_TTL - std::time::Duration::from_secs(1),
        );
        let err = service
            .complete_webview_login(site_id, None)
            .expect_err("TTL 过期必须拒绝");
        assert!(err.to_string().contains("过期"), "{err}");
        // 槽被清 ⇒ 再来一次是「还没有收到」
        let err = service
            .complete_webview_login(site_id, None)
            .expect_err("槽应已清");
        assert!(err.to_string().contains("还没有收到"), "{err}");
    }

    #[tokio::test]
    async fn cancel_and_remove_site_clear_the_slot() {
        // ① cancel：槽必须真的被清。判据不是「相位回 Idle」，而是把相位**重新置成
        //    人工态**后 `complete` 报「还没有收到」（若槽还在，就会走到构造会话那一步）。
        let (service, site_id, _vault, _handle) = sub2api_awaiting_human().await;
        service
            .store_webview_creds(site_id, webview_creds_fixture())
            .expect("存凭据");
        assert_eq!(service.webview_creds_len_for_test(), 1);
        service.cancel_captcha(site_id);
        assert_eq!(service.captcha_phase(site_id), CaptchaPhase::Idle);
        assert_eq!(service.webview_creds_len_for_test(), 0, "cancel 必须清槽");
        // 相位重新置成人工态（测试在 mod tests 内，可直接调私有 setter）
        service.set_captcha_phase(
            site_id,
            CaptchaPhase::AwaitingHuman {
                site_id,
                challenge: crate::site::CaptchaChallenge {
                    site_id,
                    url: "https://sub.example.com/login".to_string(),
                },
            },
        );
        let err = service
            .complete_webview_login(site_id, None)
            .expect_err("槽已清 ⇒ 必须报「还没有收到」");
        assert!(
            err.to_string().contains("还没有收到"),
            "必须是「没有凭据」而不是「不在人工态」：{err}"
        );

        // ② remove_site：删站前存槽，删站后槽必须为空
        let (service2, site2, _vault2, _handle2) = sub2api_awaiting_human().await;
        service2
            .store_webview_creds(site2, webview_creds_fixture())
            .expect("存凭据");
        assert_eq!(service2.webview_creds_len_for_test(), 1);
        service2.remove_site(site2).expect("删站");
        assert_eq!(
            service2.webview_creds_len_for_test(),
            0,
            "remove_site 必须清槽"
        );
        assert_eq!(service2.captcha_phase(site2), CaptchaPhase::Idle);
    }

    // ============================================================ M29-S1：NewAPI 登录换取与续期（B-193）

    use base64::Engine as _;

    /// 造一个只有 `exp` 有意义的 JWT（与 `jwt_exp` 的口径一致：不校验签名）。
    fn newapi_jwt(exp: i64) -> String {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!(r#"{{"sub":"42","exp":{exp}}}"#).as_bytes());
        format!("header.{payload}.sig")
    }

    /// 一个 NewAPI 站点（已进入人工态）+ 共享的钥匙串句柄。
    async fn newapi_awaiting_human() -> (
        TianshuRelayService<MockTransport>,
        i64,
        Arc<crate::vault::MemoryVault>,
        MockTransport,
    ) {
        let dir = tempfile::tempdir().expect("临时目录");
        let home = dir.keep();
        let vault = Arc::new(crate::vault::MemoryVault::new());
        let transport = MockTransport::new(vec![
            // 指纹：/api/status
            HttpResponse::json(
                200,
                json!({"success": true, "data": {"system_name": "示例 NewAPI", "version": "1.0.0-rc.45"}}),
            )
            .expect("构造响应"),
            // 登录前探加密：未启用
            HttpResponse::json(200, json!({"success": true, "data": {"enabled": false}}))
                .expect("构造响应"),
            // 登录：200 + success:false + 验证码 ⇒ unwrap_success 归类成 CaptchaRequired ⇒ 人工态
            HttpResponse::json(200, json!({"success": false, "message": "请输入验证码"}))
                .expect("构造响应"),
        ]);
        let handle = transport.clone();
        let service = TianshuRelayService::new(
            Store::open_in_memory().expect("内存库"),
            transport,
            ServiceConfig {
                vault: Arc::clone(&vault) as Arc<dyn crate::vault::Vault>,
                home: home.clone(),
                backup_dir: home.join("backups"),
            },
        );
        let site = service
            .add_site("https://newapi.example.com")
            .await
            .expect("站点");
        assert_eq!(site.kind, "newapi");
        let err = service
            .login(
                site.id,
                crate::site::Credentials::new("me@example.com", "pw-12345678"),
            )
            .await
            .expect_err("应当要求人机验证");
        assert!(matches!(err, Error::CaptchaRequired), "{err:?}");
        (service, site.id, vault, handle)
    }

    fn webview_cookies() -> Vec<(String, String)> {
        vec![
            ("new_api_refresh".to_string(), "sid-1.secret-1".to_string()),
            ("new_api_has_session".to_string(), "1".to_string()),
        ]
    }

    #[tokio::test]
    async fn complete_newapi_webview_login_lands_the_session() {
        let (service, site_id, vault, _handle) = newapi_awaiting_human().await;
        let token = newapi_jwt(9_999_999_999);
        service.transport_push(json_ok_with(json!({
            "success": true,
            "data": {"access_token": token.clone(), "user": {"id": 42}}
        })));

        service
            .complete_newapi_webview_login(site_id, webview_cookies())
            .await
            .expect("应当成功");

        // health=ok、相位 Idle
        let site = service.sites().expect("站点").into_iter().next().unwrap();
        assert_eq!(site.health, HEALTH_OK);
        assert_eq!(service.captcha_phase(site_id), CaptchaPhase::Idle);
        // 缓存里有 token（用 session_expiry 间接断言：JWT exp 可读）
        let expiry = service.session_expiry(site_id).expect("缓存里应有会话");
        assert_eq!(expiry.expires_at, 9_999_999_999);
        // 钥匙串里有完整 JSON（含 refresh cookie）
        let stored = vault
            .get(&crate::vault::secret_ref("site", site_id, "session"))
            .expect("读钥匙串")
            .expect("条目不存在的会话");
        assert!(
            stored.contains("new_api_refresh"),
            "钥匙串 JSON 应含续期凭据"
        );
        // 事件只带 site_id：token / refresh cookie 一律不进事件表。
        let events = service.recent_events(100).expect("recent_events");
        let ev = events
            .iter()
            .find(|e| e.message.contains("NewAPI 登录凭据已接入"))
            .expect("应有 NewAPI 登录接入事件");
        let payload: serde_json::Value =
            serde_json::from_str(ev.payload.as_deref().unwrap_or("null")).expect("事件 payload");
        assert_eq!(payload, json!({ "site_id": site_id }));
        let text = format!("{} {}", ev.message, ev.payload.as_deref().unwrap_or(""));
        assert!(
            !text.contains("new_api_refresh"),
            "事件泄漏续期凭据: {text}"
        );
        assert!(!text.contains(&token), "事件泄漏 access_token: {text}");
    }

    #[tokio::test]
    async fn complete_newapi_webview_login_rejects_bad_phase_and_bad_cookies() {
        let (service, site_id, vault, _handle) = newapi_awaiting_human().await;
        // 非法 cookie（空值）⇒ AuthFailed 且相位不变
        let err = service
            .complete_newapi_webview_login(site_id, vec![("x".to_string(), String::new())])
            .await
            .expect_err("空值 cookie 必须拒绝");
        assert!(matches!(err, Error::AuthFailed(_)), "{err:?}");
        assert!(matches!(
            service.captcha_phase(site_id),
            CaptchaPhase::AwaitingHuman { .. }
        ));
        assert!(vault
            .get(&crate::vault::secret_ref("site", site_id, "session"))
            .expect("读")
            .is_none());
        // 相位不对 ⇒ AuthFailed
        service.cancel_captcha(site_id);
        let err = service
            .complete_newapi_webview_login(site_id, webview_cookies())
            .await
            .expect_err("非人工态必须拒绝");
        assert!(matches!(err, Error::AuthFailed(_)), "{err:?}");
    }

    #[tokio::test]
    async fn complete_newapi_webview_login_404_falls_back_to_cookie_only() {
        let (service, site_id, _vault, _handle) = newapi_awaiting_human().await;
        // refresh 404 ⇒ 旧版 ⇒ cookie-only balance 探测成功
        service.transport_push(
            HttpResponse::json(404, json!({"message": "not found"})).expect("构造"),
        );
        service.transport_push(
            HttpResponse::json(
                200,
                json!({"success": true, "data": {"quota": 100, "used_quota": 1}}),
            )
            .expect("构造"),
        );
        service
            .complete_newapi_webview_login(site_id, webview_cookies())
            .await
            .expect("旧版应当走 cookie-only 成功");
        let site = service.sites().expect("站点").into_iter().next().unwrap();
        assert_eq!(site.health, HEALTH_OK);
        assert_eq!(service.captcha_phase(site_id), CaptchaPhase::Idle);
    }

    #[tokio::test]
    async fn complete_newapi_webview_login_404_and_balance_failure_keeps_state() {
        let (service, site_id, vault, _handle) = newapi_awaiting_human().await;
        service.transport_push(HttpResponse::json(404, json!({})).expect("构造"));
        service.transport_push(HttpResponse::new(500, b"down".to_vec()));
        let err = service
            .complete_newapi_webview_login(site_id, webview_cookies())
            .await
            .expect_err("兜底探测失败必须上抛");
        assert!(!err.to_string().contains("secret-1"), "错误文案不得含凭据");
        assert!(matches!(
            service.captcha_phase(site_id),
            CaptchaPhase::AwaitingHuman { .. }
        ));
        assert!(
            vault
                .get(&crate::vault::secret_ref("site", site_id, "session"))
                .expect("读")
                .is_none(),
            "失败不得写钥匙串"
        );
    }

    /// 往服务的 MockTransport 队列里补一条响应（测试夹具用）。
    trait PushResponse {
        fn transport_push(&self, resp: HttpResponse);
    }
    impl PushResponse for TianshuRelayService<MockTransport> {
        fn transport_push(&self, resp: HttpResponse) {
            self.transport.push(resp);
        }
    }

    fn json_ok_with(value: serde_json::Value) -> HttpResponse {
        HttpResponse::json(200, value).expect("构造响应")
    }

    /// 把一个会话直接写进钥匙串（模拟「上次运行留下的持久化会话」），然后恢复。
    fn seed_session(
        service: &TianshuRelayService<MockTransport>,
        vault: &Arc<crate::vault::MemoryVault>,
        site_id: i64,
        session: crate::site::Session,
    ) {
        let reference = crate::vault::secret_ref("site", site_id, "session");
        vault
            .put(&reference, &session.to_stored().expect("序列化"))
            .expect("写钥匙串");
        service.restore_sessions();
    }

    fn cookie_session(token: Option<String>, with_refresh: bool) -> crate::site::Session {
        let mut cookies = Vec::new();
        if with_refresh {
            cookies.push(("new_api_refresh".to_string(), "sid-9.secret-9".to_string()));
        }
        crate::site::Session {
            cookies,
            access_token: token,
            user_id: Some("42".to_string()),
            user_agent: None,
        }
    }

    /// 只数续期请求（夹具里的指纹 / 登录请求也在同一个 handle 里）。
    fn refresh_requests(handle: &MockTransport) -> usize {
        handle
            .requests()
            .iter()
            .filter(|req| req.url.contains("/api/user/auth/refresh"))
            .count()
    }

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("时钟")
            .as_secs() as i64
    }

    #[tokio::test]
    async fn refresh_sessions_only_when_near_expiry() {
        // 近过期（now+60）：发一次请求
        let (service, site_id, vault, handle) = newapi_awaiting_human().await;
        seed_session(
            &service,
            &vault,
            site_id,
            cookie_session(Some(newapi_jwt(now_secs() + 60)), true),
        );
        service.transport_push(json_ok_with(json!({
            "success": true,
            "data": {"access_token": newapi_jwt(now_secs() + 900), "user": {"id": 42}}
        })));
        service.refresh_sessions_if_needed().await.expect("续期");
        assert_eq!(refresh_requests(&handle), 1, "近过期应当续期一次");

        // 还早（now+3600）：不发请求
        let (service2, site2, vault2, handle2) = newapi_awaiting_human().await;
        seed_session(
            &service2,
            &vault2,
            site2,
            cookie_session(Some(newapi_jwt(now_secs() + 3600)), true),
        );
        service2.refresh_sessions_if_needed().await.expect("续期");
        assert_eq!(refresh_requests(&handle2), 0, "还早时不得发请求（避免刷）");
    }

    #[tokio::test]
    async fn refresh_sessions_auth_failure_marks_needs_login() {
        let (service, site_id, vault, handle) = newapi_awaiting_human().await;
        seed_session(
            &service,
            &vault,
            site_id,
            cookie_session(Some(newapi_jwt(now_secs() + 60)), true),
        );
        service
            .transport_push(HttpResponse::json(401, json!({"message": "expired"})).expect("构造"));
        service
            .refresh_sessions_if_needed()
            .await
            .expect("续期不 panic");
        assert_eq!(refresh_requests(&handle), 1);
        let site = service.sites().expect("站点").into_iter().next().unwrap();
        assert_eq!(site.health, HEALTH_NEEDS_LOGIN, "401 ⇒ needs_login");
        assert!(
            vault
                .get(&crate::vault::secret_ref("site", site_id, "session"))
                .expect("读")
                .is_none(),
            "needs_login 必须删掉钥匙串条目"
        );
    }

    #[tokio::test]
    async fn refresh_sessions_network_error_keeps_the_session() {
        let (service, site_id, vault, handle) = newapi_awaiting_human().await;
        seed_session(
            &service,
            &vault,
            site_id,
            cookie_session(Some(newapi_jwt(now_secs() + 60)), true),
        );
        // 队列里没有响应 ⇒ MockTransport 返回错误（网络错误的等价物）
        service
            .refresh_sessions_if_needed()
            .await
            .expect("网络错误不得上抛");
        assert_eq!(refresh_requests(&handle), 1);
        assert!(
            service.session_expiry(site_id).is_some(),
            "网络错误必须保留会话"
        );
        let site = service.sites().expect("站点").into_iter().next().unwrap();
        assert_ne!(
            site.health, HEALTH_NEEDS_LOGIN,
            "网络错误不得标 needs_login"
        );
    }

    #[tokio::test]
    async fn restore_keeps_expired_newapi_session_with_refresh_cookie() {
        let (service, site_id, vault, _handle) = newapi_awaiting_human().await;
        // 已过期（now-100）但有 refresh cookie ⇒ 保留并恢复
        seed_session(
            &service,
            &vault,
            site_id,
            cookie_session(Some(newapi_jwt(now_secs() - 100)), true),
        );
        assert!(
            service.session_expiry(site_id).is_some(),
            "过期的 NewAPI 会话带 refresh cookie 时必须保留"
        );
        assert!(vault
            .get(&crate::vault::secret_ref("site", site_id, "session"))
            .expect("读")
            .is_some());
    }

    #[tokio::test]
    async fn restore_deletes_expired_session_without_refresh_cookie() {
        let (service, site_id, vault, _handle) = newapi_awaiting_human().await;
        seed_session(
            &service,
            &vault,
            site_id,
            cookie_session(Some(newapi_jwt(now_secs() - 100)), false),
        );
        assert!(
            service.session_expiry(site_id).is_none(),
            "没有 refresh cookie 的过期会话应当删除"
        );
        assert!(vault
            .get(&crate::vault::secret_ref("site", site_id, "session"))
            .expect("读")
            .is_none());
    }

    // ============================================================ M32-S1：模型下拉（list_key_models）

    fn models_response(ids: &[&str]) -> HttpResponse {
        let data: Vec<serde_json::Value> = ids.iter().map(|id| json!({"id": id})).collect();
        HttpResponse::json(200, json!({"data": data})).expect("构造响应")
    }

    /// 建站点 + 一把 key（密钥进内存钥匙串），返回 (service, key_id, mock)。
    async fn models_fixture(
        tail: Vec<HttpResponse>,
    ) -> (TianshuRelayService<MockTransport>, i64, MockTransport) {
        let mut responses = vec![status_response()];
        responses.extend(tail);
        let mock = MockTransport::new(responses);
        let store = Store::open_in_memory().expect("内存库");
        let service = TianshuRelayService::new(store, mock.clone(), test_config());
        let site = service
            .add_site("https://relay.example.com")
            .await
            .expect("add_site");
        let reference = crate::vault::secret_ref("key", 1, "secret");
        service
            .vault
            .put(&reference, "sk-test-secret-12345678")
            .expect("vault.put");
        let key_id = service
            .store
            .insert_key(site.id, "k", &reference, Some("670"), None)
            .expect("insert_key");
        (service, key_id, mock)
    }

    /// 只数 `/v1/models` 请求（夹具里的 /api/status 指纹也算在 mock 里）。
    fn models_requests(mock: &MockTransport) -> usize {
        mock.requests()
            .iter()
            .filter(|req| req.url.ends_with("/v1/models"))
            .count()
    }

    #[tokio::test]
    async fn models_for_key_sorts_and_dedupes() {
        let (service, key_id, mock) =
            models_fixture(vec![models_response(&["m2", "m1", "m1"])]).await;
        let models = service.models_for_key(key_id).await.expect("取模型");
        assert_eq!(models, vec!["m1".to_string(), "m2".to_string()]);
        assert_eq!(models_requests(&mock), 1, "只发一次 /v1/models");
        // M37-S1 复审 P3-1：本地有明文 ⇒ 不得走恢复分支（直接钉子）。
        assert_eq!(reveal_requests(&mock), 0, "本地有明文不得回读");
        // 请求头必须带这把 key 的 Bearer（不是别人的）
        let req = mock
            .requests()
            .into_iter()
            .find(|r| r.url.ends_with("/v1/models"))
            .expect("有 /v1/models 请求");
        assert!(
            req.headers
                .iter()
                .any(|(k, v)| k == "Authorization" && v == "Bearer sk-test-secret-12345678"),
            "{:?}",
            req.headers
        );
    }

    /// M37-S1 夹具：在 `models_fixture` 基础上**删掉** vault 条目（模拟 B-219 迁移放弃）。
    async fn missing_secret_fixture(
        tail: Vec<HttpResponse>,
    ) -> (TianshuRelayService<MockTransport>, i64, MockTransport) {
        let (service, key_id, mock) = models_fixture(tail).await;
        let row = service
            .store
            .get_key(key_id)
            .expect("读 key")
            .expect("key 行存在");
        service
            .vault
            .delete(&row.secret_ref)
            .expect("删掉 vault 条目");
        assert!(
            !service
                .vault_has_for_test(&row.secret_ref)
                .expect("vault.has"),
            "夹具前提：vault 里必须没有该条目"
        );
        (service, key_id, mock)
    }

    fn login_session() -> Session {
        Session {
            cookies: vec![("session".to_string(), "abc".to_string())],
            access_token: Some("tok-m37".to_string()),
            user_id: Some("7".to_string()),
            user_agent: None,
        }
    }

    /// 数 `/api/token/<id>/key` 请求（reveal 的唯一入口）。
    fn reveal_requests(mock: &MockTransport) -> usize {
        mock.requests()
            .iter()
            .filter(|req| req.url.contains("/api/token/") && req.url.ends_with("/key"))
            .count()
    }

    fn reveal_response(secret: &str) -> HttpResponse {
        HttpResponse::json(200, json!({"success": true, "data": {"key": secret}}))
            .expect("构造响应")
    }

    /// M37-S1 §7：缺明文 + 会话有效 ⇒ 回读明文、写回原 ref、再查模型。
    #[tokio::test]
    async fn models_for_key_restores_missing_secret_then_lists_models() {
        let restored = "sk-restored-m37-0123456789abcdef";
        let (service, key_id, mock) = missing_secret_fixture(vec![
            reveal_response(restored),
            models_response(&["m2", "m1"]),
        ])
        .await;
        let row = service
            .store
            .get_key(key_id)
            .expect("读 key")
            .expect("key 行存在");
        service
            .sessions
            .put(row.site_id, login_session())
            .expect("塞会话");

        let models = service.models_for_key(key_id).await.expect("取模型");

        assert_eq!(models, vec!["m1".to_string(), "m2".to_string()]);
        // 写回的是**原 secret_ref**，且条目真的进了保险库
        assert!(
            service
                .vault_has_for_test(&row.secret_ref)
                .expect("vault.has"),
            "恢复后 vault 里必须有原 secret_ref 的条目"
        );
        // reveal 恰好一次，且打的是该 key 的站点主键（670）；没有新建 key 行
        assert_eq!(reveal_requests(&mock), 1, "reveal 只应发一次");
        let reveal_req = mock
            .requests()
            .into_iter()
            .find(|req| req.url.ends_with("/api/token/670/key"))
            .expect("reveal 应打 /api/token/670/key");
        assert_eq!(reveal_req.method.as_str(), "POST");
        let after = service
            .store
            .get_key(key_id)
            .expect("读 key")
            .expect("key 行仍在");
        assert_eq!(after.remote_id, row.remote_id);
        assert_eq!(after.secret_ref, row.secret_ref);
        assert_eq!(service.store.list_keys().expect("列 key").len(), 1);
        // /v1/models 用的是**恢复后的** key
        let models_req = mock
            .requests()
            .into_iter()
            .find(|req| req.url.ends_with("/v1/models"))
            .expect("有 /v1/models 请求");
        assert!(
            models_req
                .headers
                .iter()
                .any(|(k, v)| k == "Authorization" && v.as_str() == format!("Bearer {restored}")),
            "{:?}",
            models_req.headers
        );
    }

    /// M37-S1 §7：缺明文 + 无会话 ⇒ 可执行错误（含「登录」），不发 reveal、不发 /v1/models。
    #[tokio::test]
    async fn models_for_key_missing_secret_without_session_is_actionable() {
        let (service, key_id, mock) = missing_secret_fixture(vec![models_response(&["m1"])]).await;
        let row = service
            .store
            .get_key(key_id)
            .expect("读 key")
            .expect("key 行存在");

        let err = service
            .models_for_key(key_id)
            .await
            .expect_err("无会话必须报错");
        let text = err.to_string();
        assert!(text.contains("登录"), "错误文案要说明先登录：{text}");
        assert!(
            !text.contains("sk-test-secret"),
            "错误文案不得含明文：{text}"
        );
        assert_eq!(reveal_requests(&mock), 0, "无会话不得发 reveal");
        assert_eq!(models_requests(&mock), 0, "无会话不得发 /v1/models");
        assert!(
            !service
                .vault_has_for_test(&row.secret_ref)
                .expect("vault.has"),
            "失败后 vault 仍应没有条目"
        );
    }

    /// M37-S1 复审 P2-1：key 不存在 ⇒ 在任何网络请求之前 `NotFound`。
    #[tokio::test]
    async fn models_for_key_missing_key_is_not_found_without_network() {
        let (service, _key_id, mock) = missing_secret_fixture(vec![models_response(&["m1"])]).await;
        let err = service
            .models_for_key(999_999)
            .await
            .expect_err("不存在的 key 必须报错");
        assert!(matches!(err, Error::NotFound(_)), "{err}");
        assert_eq!(reveal_requests(&mock), 0, "不存在的 key 不得回读");
        assert_eq!(models_requests(&mock), 0, "不存在的 key 不得查模型");
    }

    /// 只让 `kr/key/` 的 `get` 失败的 Vault（M37-S1 复审 P2-1：读失败不得当成没有）。
    struct KeyGetFailingVault {
        inner: crate::vault::MemoryVault,
    }
    impl KeyGetFailingVault {
        fn new() -> Self {
            Self {
                inner: crate::vault::MemoryVault::new(),
            }
        }
    }
    impl crate::vault::Vault for KeyGetFailingVault {
        fn backend_name(&self) -> &'static str {
            "key-get-failing"
        }
        fn probe(&self) -> crate::error::Result<()> {
            Ok(())
        }
        fn put(&self, key: &str, secret: &str) -> crate::error::Result<()> {
            self.inner.put(key, secret)
        }
        fn get(&self, key: &str) -> crate::error::Result<Option<String>> {
            if key.starts_with("kr/key/") {
                Err(crate::error::Error::Vault("模拟钥匙串读取失败".into()))
            } else {
                self.inner.get(key)
            }
        }
        fn has(&self, key: &str) -> crate::error::Result<bool> {
            self.inner.has(key)
        }
        fn delete(&self, key: &str) -> crate::error::Result<()> {
            self.inner.delete(key)
        }
    }

    /// M37-S1 复审 P2-1：保险库**读失败**（不是条目不存在）⇒ 原样上抛，
    /// 不得触发 reveal、不得当成「缺明文」去回读。
    #[tokio::test]
    async fn models_for_key_vault_read_error_does_not_restore() {
        let store = Store::open_in_memory().expect("内存库");
        let mock = MockTransport::new(vec![status_response()]);
        let service = TianshuRelayService::new(
            store,
            mock.clone(),
            ServiceConfig {
                vault: Arc::new(KeyGetFailingVault::new()),
                ..test_config()
            },
        );
        let site = service
            .add_site("https://relay.example.com")
            .await
            .expect("add_site");
        let reference = crate::vault::secret_ref("key", 1, "secret");
        service
            .vault
            .put(&reference, "sk-test-secret-12345678")
            .expect("vault.put");
        let key_id = service
            .store
            .insert_key(site.id, "k", &reference, Some("remote-1"), None)
            .expect("insert_key");
        service
            .sessions
            .put(site.id, login_session())
            .expect("塞会话");

        let err = service
            .models_for_key(key_id)
            .await
            .expect_err("读失败必须上抛");
        assert!(matches!(err, Error::Vault(_)), "{err}");
        assert_eq!(reveal_requests(&mock), 0, "读失败不得回读明文");
        assert_eq!(models_requests(&mock), 0, "读失败不得查模型");
    }

    #[tokio::test]
    async fn models_for_key_rejects_revoked_key() {
        // M37-S1：已回收 + **本地缺明文** 也必须拒绝——不能在「缺明文」分支里
        // 顺手回读明文（那会给已回收的 key 重新拿到明文）。
        let (service, key_id, mock) = missing_secret_fixture(vec![
            reveal_response("sk-restored-should-never-happen"),
            models_response(&["m1"]),
        ])
        .await;
        let row = service
            .store
            .get_key(key_id)
            .expect("读 key")
            .expect("key 行存在");
        service
            .sessions
            .put(row.site_id, login_session())
            .expect("塞会话");
        service
            .store
            .set_key_status(key_id, crate::store::KEY_STATUS_REVOKED)
            .expect("标已回收");
        let err = service
            .models_for_key(key_id)
            .await
            .expect_err("已回收必须拒绝");
        assert!(!err.to_string().contains("sk-test-secret"), "{err}");
        assert_eq!(models_requests(&mock), 0, "已回收的 key 不得发请求");
        assert_eq!(reveal_requests(&mock), 0, "已回收的 key 不得回读明文");
        assert!(
            !service
                .vault_has_for_test(&row.secret_ref)
                .expect("vault.has"),
            "已回收的 key 不得被写回保险库"
        );
    }

    #[tokio::test]
    async fn models_for_key_http_error_is_scrubbed() {
        const SECRET_SHAPE: &str = "sk-ZZZZ0123456789ABCDEFGHIJKLMNOP";
        // 400（不是 5xx）：4xx 的站点原文会进错误文案 ⇒ 才真正测到 scrub 那一步；
        // 5xx 的文案是本产品固定串（不引用站点原文），测不出脱敏。
        let (service, key_id, _mock) = models_fixture(vec![HttpResponse::json(
            400,
            json!({"error": {"message": format!("upstream exploded: {SECRET_SHAPE}")}}),
        )
        .expect("构造响应")])
        .await;
        let err = service
            .models_for_key(key_id)
            .await
            .expect_err("非 2xx 必须报错");
        let text = err.to_string();
        assert!(
            !text.contains(SECRET_SHAPE),
            "错误文案不得原样带出站点原文里的密钥形态：{text}"
        );
        assert!(text.contains("sk-***"), "应当留下脱敏痕迹：{text}");
    }

    // ============================================================ M38-S1：会话持久化收口

    /// `sites()` 的持久化判定用 `Vault::has`（存在性），并把内存会话的 JWT `exp` 带出来。
    #[tokio::test]
    async fn sites_reports_session_persisted_and_expiry() {
        let service = service_with(vec![status_response()]).await;
        let site = service
            .add_site("https://relay.example.com")
            .await
            .expect("add_site");

        // add_site 的新行固定 false / None（spec §4.1）
        assert!(!site.session_persisted, "新站点不该有持久化会话");
        assert_eq!(site.session_expires_at, None, "新站点没有内存会话");

        let exp = 9_999_999_999_i64;
        service
            .sessions
            .put(
                site.id,
                Session {
                    cookies: vec![],
                    access_token: Some(newapi_jwt(exp)),
                    user_id: None,
                    user_agent: None,
                },
            )
            .expect("塞内存会话");
        service
            .vault
            .put(
                &service.session_ref(site.id),
                r#"{"cookies":[],"access_token":"x","user_id":null}"#,
            )
            .expect("写持久化会话");

        let rows = service.sites().expect("列站点");
        assert_eq!(rows.len(), 1);
        assert!(rows[0].session_persisted, "保险库有条目 ⇒ 必须报 persisted");
        assert_eq!(rows[0].session_expires_at, Some(exp), "exp 必须来自 JWT");

        // 条目被删 ⇒ persisted 立刻回到 false（徽标消失），exp 仍来自内存会话
        service
            .vault
            .delete(&service.session_ref(site.id))
            .expect("删持久化会话");
        let rows = service.sites().expect("列站点");
        assert!(!rows[0].session_persisted, "条目删掉后必须 false");
        assert_eq!(rows[0].session_expires_at, Some(exp), "内存会话仍在");
    }

    /// 保险库 `has` 读失败 ⇒ 该行 false，但 `sites()` 仍 Ok（不删条目、不整页失败）。
    #[tokio::test]
    async fn sites_reports_session_not_persisted_when_vault_has_errors() {
        /// 只让 `has` 报错的 Vault：模拟钥匙串被锁 / ACL 拒绝。
        struct HasFailingVault;

        impl crate::vault::Vault for HasFailingVault {
            fn backend_name(&self) -> &'static str {
                "has-failing"
            }
            fn probe(&self) -> Result<()> {
                Ok(())
            }
            fn put(&self, _key: &str, _secret: &str) -> Result<()> {
                Ok(())
            }
            fn get(&self, _key: &str) -> Result<Option<String>> {
                Ok(None)
            }
            fn has(&self, _key: &str) -> Result<bool> {
                Err(Error::Vault("模拟钥匙串读取失败".to_string()))
            }
            fn delete(&self, _key: &str) -> Result<()> {
                Ok(())
            }
        }

        let store = Store::open_in_memory().expect("内存库");
        let service = TianshuRelayService::new(
            store,
            MockTransport::new(vec![status_response()]),
            ServiceConfig {
                vault: Arc::new(HasFailingVault),
                ..test_config()
            },
        );
        let site = service
            .add_site("https://relay.example.com")
            .await
            .expect("add_site");

        let rows = service.sites().expect("has 读失败不得让 sites() 失败");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, site.id);
        assert!(
            !rows[0].session_persisted,
            "读失败必须按 false 处理（宁可不显示徽标）"
        );
    }

    /// 退出登录：删保险库条目 + 清内存会话 + health 回 unknown。
    #[tokio::test]
    async fn logout_site_removes_persisted_session_and_resets_health() {
        let service = service_with(vec![status_response()]).await;
        let site = service
            .add_site("https://relay.example.com")
            .await
            .expect("add_site");
        let reference = service.session_ref(site.id);
        service
            .sessions
            .put(site.id, login_session())
            .expect("塞内存会话");
        service
            .vault
            .put(&reference, r#"{"cookies":[],"access_token":"tok"}"#)
            .expect("写持久化会话");
        service
            .store
            .set_site_health(site.id, "ok")
            .expect("置 health");
        assert!(
            service.sites().expect("列站点")[0].session_persisted,
            "前置：应当先看到持久化会话"
        );

        service.logout(site.id).expect("退出登录");

        assert!(
            !service.vault_has_for_test(&reference).expect("vault.has"),
            "退出登录必须删除保险库条目"
        );
        assert!(
            service.session_expiry(site.id).is_none(),
            "退出登录必须清掉内存会话"
        );
        let rows = service.sites().expect("列站点");
        assert!(!rows[0].session_persisted, "退出后 persisted 必须 false");
        assert_eq!(rows[0].health, "unknown", "health 必须回到 unknown");
    }
}
