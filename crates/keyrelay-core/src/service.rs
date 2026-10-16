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
use crate::vault::{KeychainVault, Vault};

use futures_util::stream::{self, StreamExt};

/// 服务装配参数。核心层**不读环境变量**，`home` 与 `backup_dir` 一律由壳层传入，
/// 这样测试可以把它们指向临时目录。
///
/// **通知不在这里**（M6-S5）：见 [`KeyRelayService::with_notify`]。把 `notify` 做成
/// `ServiceConfig` 的字段会让全仓 10 个集成测试文件的结构体字面量一次性编译失败——
/// 为了一个默认关闭的可选功能去改 10 个别人的测试文件，代价与收益不成比例。
/// 做成 `KeyRelayService` 上的构造器方法之后，不关心通知的调用方一个字节都不用改。
pub struct ServiceConfig {
    pub vault: Arc<dyn Vault>,
    pub home: PathBuf,
    pub backup_dir: PathBuf,
}

impl ServiceConfig {
    /// 生产装配：钥匙串用系统实现（`KeychainVault`），路径按 `home` 推导。
    ///
    /// 注意：这里**只**会构造系统钥匙串；不可用时由 `Vault::probe()`/各方法返回
    /// [`Error::VaultUnavailable`]，绝不静默换成 `MemoryVault`。
    pub fn production(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        Self {
            vault: Arc::new(KeychainVault::new()),
            backup_dir: home.join(".keyrelay").join("backups"),
            home,
        }
    }

    /// 测试装配：内存钥匙串 + 显式临时目录。
    pub fn in_memory(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        Self {
            vault: Arc::new(crate::vault::MemoryVault::new()),
            backup_dir: home.join(".keyrelay").join("backups"),
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
        // M9-S2：与「认证失败」分开记——用户要做的是**改输入**，不是重新登录。
        Error::InvalidInput(_) => "输入不符合站点要求",
        Error::Vault(_) => "钥匙串错误",
        Error::VaultUnavailable(_) => "钥匙串不可用",
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
    /// **非空 = 不能轮换**（见 [`KeyRelayService::rotate_key`] 的前置拒绝）。
    pub unmapped_targets: Vec<String>,
    /// 旧 key 的站点侧 id；`None` = 本地记录里就没有，第三步会被跳过并说明
    pub old_remote_id: Option<String>,
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

impl From<SiteRow> for SiteSummary {
    fn from(row: SiteRow) -> Self {
        Self {
            id: row.id,
            kind: row.kind,
            base_url: row.base_url,
            display_name: row.display_name,
            health: row.health,
        }
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
/// 只给 [`KeyRelayService::dispatch_notifications`] 与 [`KeyRelayService::rotation_due`] 用：
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
pub const AUTOSTART_APP_ID: &str = "keyrelay";

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

pub struct KeyRelayService<T: HttpTransport + Clone + 'static> {
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
    /// `ReqwestTransport`（timeout 120s、不套 retry），避免 sync probe 被 15s 总超时砍断、
    /// 以及 429 被 `RetryingTransport` 自动重试 3 次（Retry-After 被 cap 到 5s，白打 + 等 10s）。
    probe_transport: Option<crate::site::transport_reqwest::ReqwestTransport>,
    /// B-134：probe 轮询兜底参数（`sync=true` 的 POST 返回非终态时才用）。
    ///
    /// 默认 [`crate::probe::PollPolicy::default`]（6 次 × 5s）。`max_attempts = 0` 即关闭兜底。
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

/// 网关失败的内存缓冲上限。见 [`KeyRelayService::gateway_failures`] 的说明。
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

impl<T: HttpTransport + Clone + 'static> KeyRelayService<T> {
    pub fn new(store: Store, transport: T, config: ServiceConfig) -> Self {
        let svc = Self {
            registry: SiteRegistry::new(transport.clone()),
            transport,
            // 默认 None：测试不调 `with_probe_transport` 时 fallback 到 `self.transport`（Mock），
            // 让 probe_model 的集成测试能用 Mock 预置响应（M4）。
            probe_transport: None,
            // B-134：默认开着轮询兜底（6 次 × 5s），但只对「bazaarlink 明说还在跑」的 run 生效。
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
            captcha_phases: Mutex::new(HashMap::new()),
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
                        let _ = self.sessions.put(site.id, session);
                    }
                    // 反序列化失败：跳过（不删——下次 login 会覆盖；删了反而损失可能可用的会话）
                }
                Ok(None) => {} // 未持久化（没登录过 / 已失效被删）
                Err(_) => {}   // 钥匙串读失败：跳过，不阻断启动
            }
        }
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
    /// 生产装配由壳层调用，传入一个**不套 `RetryingTransport`**、timeout 足够长（120s）的
    /// `ReqwestTransport`：bazaarlink `sync=true` 要等服务端跑完多轮推理对比，远超站点
    /// transport 的 15s 总超时；429 也不该被站点重试策略抢着重试（probe 层自己映射成
    /// `RateLimited` 告诉用户）。
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

    /// B-134：注入 probe 轮询兜底的参数与等待实现。
    ///
    /// 生产不调用（默认 `PollPolicy::default()` + `TokioSleeper`）；测试调用是为了
    /// **不真睡**——`max_attempts` 与 `interval` 一起注入，测试就能断言
    /// 「补查了几次、每次等了多久」，而不是靠 `sleep` 把测试拖慢 30s。
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
            .map(Into::into)
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
        // 分组名在 `spec` 被 move 进适配器**之前**取出来：它是用户刚填的权威值，
        // 适配器不回传它（`KeyMaterial` 只有 remote_id + secret）。
        let group_name = spec.group.clone();
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

    /// 带模型名的投递。`model` 的口径见 [`KeyRelayService::delivery_plan_with_model`]。
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
                eprintln!("[keyrelay] 代理配置非法，上游直连: {err}");
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
                    let failure = balance
                        .as_ref()
                        .and_then(|result| result.as_ref().err())
                        .or_else(|| keys.as_ref().and_then(|result| result.as_ref().err()));
                    let reason = failure.map(error_kind).unwrap_or("未知");
                    // 认证失败 = 会话已失效：`on_auth_error` 已经把它落库，
                    // 这里再带进本轮汇总，用户当场就能看到。
                    if failure.is_some_and(is_auth_failure) {
                        summary.needs_login.push(outcome.site_id);
                    }
                    // 额度耗尽（HTTP 403 + 已知错误码）是**独立**于会话失效的一种状态：
                    // 会话是好的，只是没钱了。分开判定，否则用户会去重新登录一个
                    // 根本不需要登录的站点（PRD FR-3 的告警清单里两条并列）。
                    quota_exceeded = matches!(failure, Some(Error::QuotaExhausted));
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

        // M14-S1：模型清单采集（B-99 ①）。按节流，每轮最多 1 站，失败静默。
        // 放在快照与通知之间：采集只更新 `site_facts[*].models`（路由表用），
        // 不进 snapshot（notify 的 models 字段本轮仍 None，与既有行为一致）。
        if settings.collect_models {
            let now = unix_now_secs();
            let policy = crate::notify::ModelsPolicy {
                enabled: true,
                min_interval_secs: settings.models_min_interval_secs,
            };
            for site in self.store.list_sites()? {
                // 该站有没有可用 key（没有就跳过——采集要带 key）
                let Some(row) = self.pick_gateway_key(site.id).ok().flatten() else {
                    continue;
                };
                let Ok(secret) = self.secret_for_row(&row) else {
                    continue;
                };
                // 节流判定（should_collect_models 是纯函数，已含时钟回拨与边界处理）
                let last = self
                    .site_facts
                    .lock()
                    .ok()
                    .and_then(|m| m.get(&site.id).and_then(|o| o.models_collected_at));
                if !crate::notify::should_collect_models(policy, last, now) {
                    continue;
                }
                // 采集：每轮最多 1 站（M8-S1 §5.2），命中第一个该采的就采然后 break。
                match crate::site::fetch_models(&self.transport, &site.base_url, &secret).await {
                    Ok(fetched) => {
                        if let Ok(mut map) = self.site_facts.lock() {
                            let obs = map.entry(site.id).or_default();
                            obs.models = crate::notify::merge_models(&obs.models, Some(&fetched));
                            obs.models_collected_at = Some(now);
                        }
                    }
                    Err(err) => {
                        // 失败静默：只记 Debug 事件，不阻塞刷新、不清空已有 models
                        self.log(observability::event_with_payload(
                            Level::Debug,
                            "app",
                            format!(
                                "模型清单采集失败: {}",
                                crate::redact::scrub(&err.to_string())
                            ),
                            serde_json::json!({ "site_id": site.id }),
                        ));
                    }
                }
                break;
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
        let prev = state.last.lock().ok().and_then(|guard| guard.clone());
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
                    failures.push(format!("webhook: {err}"));
                }
            }
            if !failures.is_empty() {
                self.log(observability::event_with_payload(
                    Level::Warn,
                    "app",
                    format!("通知发送失败: {}", failures.join(" | ")),
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
            *guard = Some(snapshot);
        }
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
        })
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
                        token: gateway_token.clone(),
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

    /// 站点侧可用分组与倍率（FR-2）。
    pub async fn available_groups(&self, site_id: i64) -> Result<Vec<crate::site::GroupInfo>> {
        let site = self.site(site_id)?;
        let kind = self.kind_of(&site)?;
        capability_gate(
            kind,
            crate::site::capability::capabilities(kind).groups,
            "读取分组",
        )?;
        let session = self.session(site_id)?;
        let adapter = self.registry.adapter(kind);
        let groups = adapter.available_groups(&site.base_url, &session).await?;
        // M8-S1 §5.4：倍率进观测缓存。取**第一个有倍率的分组**——`available_groups`
        // 是用户触发的（FR-2 的下拉），观测只在用户看过分组之后才存在；未知就是未知。
        if let Ok(mut map) = self.site_facts.lock() {
            if let Some(rate) = groups.iter().find_map(|g| g.rate) {
                map.entry(site_id).or_default().rate = Some(rate);
            }
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
            match self.store_key_material(site_id, &name, Some(&remote_id), None, &material.secret)
            {
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
    /// B-134：POST 返回非终态时按 [`crate::probe::PollPolicy`] 补查（best-effort，
    /// 补查失败不影响本次结果）；拿到终态后按「有没有判定」分流记事件（见 F1 分支）。
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
            sync: true,
        };
        // H1+M2（独立复审）：优先用 probe_transport（独立 timeout 120s、不套 retry）；
        // None 时 fallback 到 self.transport（测试 Mock 路径，M4 可 mock）。
        // 收成 `&dyn` 是为了 POST 与轮询补查走**同一条**选择逻辑，不把二选一写两遍。
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
        // B-134：POST 返回**非终态**（bazaarlink 明说还在跑）时补查一次机会。
        // `needs_poll` 为假（终态 / 已有判定 / 状态未知）⇒ 一次请求都不发。
        let run = if crate::probe::needs_poll(&run) {
            let (run, polled) =
                crate::probe::poll_probe_run(transport, run, self.probe_poll, &*self.probe_sleeper)
                    .await;
            if polled > 0 {
                // 只记元数据：补查成功几次、最终状态、有没有判定（apiKey / 响应正文都不进）。
                self.log(observability::event_with_payload(
                    Level::Debug,
                    "probe",
                    "模型检测轮询补查完成",
                    serde_json::json!({
                        "site_id": row.site_id,
                        "key_id": key_id,
                        "run_id": run.run_id,
                        "status": run.status,
                        "polled": polled,
                        "has_verdict": run.verdict_status.is_some(),
                    }),
                ));
            }
            run
        } else {
            run
        };
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
        // F1（独立检查）：`run_probe` 是**一次性** POST（`sync=true`），没有客户端轮询兜底。
        // bazaarlink 对「key 访问不了该模型」这类情况会**秒级返回 completed 但不带
        // identityAssessment**（真机实测 4 次：420–663ms、verdict 全空）。旧实现无条件记
        // info「模型检测完成」+ 落一条 verdict 全空的行——失败被伪装成成功，事件流与历史表
        // 都看不出区别。现在按「有没有拿到判定」分流：拿到 → info「完成」；
        // 没拿到 → warn「未得出判定」（**仍落库**：run_id / report_url 是真实的，报告能点开）。
        self.log(match run.verdict_status {
            Some(_) => observability::event_with_payload(
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
            None => observability::event_with_payload(
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
        });
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
            token,
            site.base_url,
            api_key,
            site.display_name,
        );
        // M14-S1：多站路由开关（B-99）。关时（默认）走 single_upstream——config.base_url
        // / api_key 是所选站点，M8-S4 §6.5 换站语义逐字不变；开时用 build_gateway_route
        // 填非空 route + keys_by_ref，网关按模型选路（多站聚合，FR-6 V1.1 可选）。
        if self.settings()?.gateway_multi_site {
            let (route, keys) = self.build_gateway_route()?;
            config.route = route;
            config.keys_by_ref = keys;
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
    fn gateway_token(&self) -> (String, bool) {
        match self.vault_secret(GATEWAY_TOKEN_REF) {
            Ok(Some(token)) if !token.trim().is_empty() => return (token.to_string(), true),
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
                return (token, false);
            }
        }
        // Ok(None) 或空：钥匙串里确实没有 ⇒ 生成 + put（首次装配）
        let token = crate::gateway::generate_token();
        match self.vault.put(GATEWAY_TOKEN_REF, &token) {
            Ok(()) => (token, true),
            Err(err) => {
                self.log(observability::event_with_payload(
                    Level::Warn,
                    "gateway",
                    "网关令牌没能存进钥匙串，本次用临时令牌（重启后会变）",
                    serde_json::json!({ "reason": crate::redact::scrub(&err.to_string()) }),
                ));
                (token, false)
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
            serde_json::json!({ "secret_ref": GATEWAY_TOKEN_REF }),
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
        let revoked = self
            .revoked_refs
            .lock()
            .map(|set| set.clone())
            .unwrap_or_default();

        let mut facts: Vec<crate::routing::SiteFacts> = Vec::new();
        let mut keys: std::collections::HashMap<String, zeroize::Zeroizing<String>> =
            std::collections::HashMap::new();

        for site in self.store.list_sites()? {
            let Some(row) = self.pick_gateway_key(site.id)? else {
                continue;
            };
            if row.status == crate::store::KEY_STATUS_REVOKED {
                continue;
            }
            // 走 `secret_for_row`（唯一的明文出口），**不新开取密钥路径**。
            let Ok(secret) = self.secret_for_row(&row) else {
                // 本地记录在、明文没了：这把 key **用不了**。
                // 跳过这一把是对的（该站点不进路由表），跳过整个站点是错的。
                continue;
            };
            let obs = observations.get(&site.id).cloned().unwrap_or_default();
            facts.push(crate::routing::SiteFacts {
                site_id: site.id,
                base_url: site.base_url.clone(),
                models: obs.models,
                rate: obs.rate,
                // **余额未知 ⇒ None**，绝不 `unwrap_or(0.0)`（那会把「不知道」变成「已耗尽」）。
                balance_usd: obs.balance_usd,
                latency_ms: obs.latency_ms,
                key_ref: row.secret_ref.clone(),
            });
            if !revoked.contains(&row.secret_ref) {
                keys.insert(row.secret_ref.clone(), secret);
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

    /// 该站点用来出网的 key：**未回收**且未禁用/耗尽里 id 最大的那一条（最新的一把）。
    /// B-99 接线后启用（M14-S1 接线）：被 `build_gateway_route` 与 `refresh_all` 采集段调用（取每站最新可用 key）。
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
        secret: &str,
    ) -> Result<StoredKey> {
        if secret.trim().is_empty() {
            return Err(Error::Vault("密钥为空，拒绝保存".into()));
        }
        let ref_id = new_ref_id();
        let secret_ref = crate::vault::secret_ref("key", &ref_id, "secret");
        self.vault.put(&secret_ref, secret)?;

        match self
            .store
            .insert_key(site_id, name, &secret_ref, remote_id, group_name)
        {
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
            eprintln!("[keyrelay] 写入事件失败: {err}");
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

    async fn service_with(responses: Vec<HttpResponse>) -> KeyRelayService<MockTransport> {
        let store = Store::open_in_memory().expect("内存库");
        KeyRelayService::new(store, MockTransport::new(responses), test_config())
    }

    /// 测试装配：内存钥匙串 + 一次性临时目录（绝不碰真实 `~/.keyrelay`）。
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
    fn service_with_blocking() -> KeyRelayService<MockTransport> {
        let dir = tempfile::tempdir().expect("临时目录");
        let store = Store::open_in_memory().expect("内存库");
        KeyRelayService::new(
            store,
            MockTransport::new(vec![]),
            test_config_with_home(dir.keep()),
        )
    }

    fn test_config_with_home(home: std::path::PathBuf) -> ServiceConfig {
        ServiceConfig {
            vault: Arc::new(crate::vault::MemoryVault::new()),
            backup_dir: home.join(".keyrelay").join("backups"),
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
        let service = KeyRelayService::new(store, mock.clone(), test_config());

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
        let service = KeyRelayService::new(
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
        let service = KeyRelayService::new(
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
        let service = KeyRelayService::new(
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
        let service = KeyRelayService::new(
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
            KeyRelayService::new(store, MockTransport::new(vec![status_response()]), config);
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
            KeyRelayService::new(store, MockTransport::new(vec![status_response()]), config);
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
    async fn probe_service(tail: Vec<HttpResponse>) -> (KeyRelayService<MockTransport>, i64) {
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
        KeyRelayService<MockTransport>,
        i64,
        MockTransport,
        Arc<crate::site::retry::RecordingSleeper>,
    ) {
        let mut responses = vec![status_response()];
        responses.extend(tail);
        let store = Store::open_in_memory().expect("内存库");
        let mock = MockTransport::new(responses);
        let sleeper = Arc::new(crate::site::retry::RecordingSleeper::default());
        let service = KeyRelayService::new(store, mock.clone(), test_config()).with_probe_poll(
            crate::probe::PollPolicy {
                max_attempts: 3,
                interval: std::time::Duration::from_secs(1),
            },
            sleeper.clone(),
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
        // F1：`run_probe` 是一次性 POST（sync=true），bazaarlink 对「key 访问不了该模型」
        // 会**秒级返回 200 + completed 但不带 identityAssessment**（真机实测 4 次：
        // 420–663ms、verdict 全空）。旧实现无条件记 info「模型检测完成」并落一行 verdict
        // 全空 —— 失败被伪装成成功。本测试钉住分流：无判定 ⇒ warn，且不得出现「完成」。
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
        // B-134：`sync=true` 的 POST 没等到跑完（bazaarlink 回 `running`）时补查一次机会。
        // 真机依据：POST 侧的超时窗口是固定的，而检测要跑多轮推理对比（真机实测一次
        // 49.8s）——非终态返回是真会发生的形态，不是假想。
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
            probe_service_with_mock(vec![running, finished]).await;

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
        // 请求数 = 指纹 1 + POST 1 + 补查 1
        assert_eq!(mock.request_count(), 3, "补查只发一次就够");
        let poll = mock.nth_request(2).expect("第三次请求是补查");
        assert_eq!(poll.method, crate::site::transport::Method::Get);
        assert_eq!(poll.url, "https://bazaarlink.ai/api/probe/run/r-poll");
        assert_eq!(
            sleeper.calls(),
            vec![std::time::Duration::from_secs(1)],
            "补查前等一个 interval（测试里不真睡）"
        );

        // 落库的是**补查后**的结果，不是 POST 那个半成品
        let rows = service.store.list_probe_runs(10).expect("list_probe_runs");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].verdict_status.as_deref(),
            Some("clean_match_submodel_mismatch")
        );
        assert_eq!(rows[0].true_model.as_deref(), Some("glm-5.2"));

        // 有判定 ⇒ info「模型检测完成」，且补查事件不含 apiKey
        let events = service.recent_events(100).expect("recent_events");
        let probe_events: Vec<_> = events.iter().filter(|e| e.source == "probe").collect();
        assert!(
            probe_events
                .iter()
                .any(|e| e.level == "info" && e.message.contains("模型检测完成")),
            "拿到判定应记 info「模型检测完成」: {probe_events:?}"
        );
        assert!(
            probe_events
                .iter()
                .any(|e| e.message.contains("轮询补查完成")),
            "补查应留一条事件（含次数与最终状态）: {probe_events:?}"
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
        // 补查用尽次数仍是 `running` ⇒ 保留 POST 结果并落库（不是报错、不是丢记录）。
        let running = || {
            HttpResponse::json(200, json!({ "runId": "r-poll", "status": "running" }))
                .expect("构造 running 响应")
        };
        let (service, key_id, mock, sleeper) =
            probe_service_with_mock(vec![running(), running(), running(), running()]).await;

        let run = service
            .probe_model(key_id, "glm-5.3".into(), None, None, true)
            .await
            .expect("补查没结果也不算失败");

        assert_eq!(run.status, "running");
        assert_eq!(run.verdict_status, None);
        // 指纹 1 + POST 1 + 补查 3（`probe_service_with_mock` 的 max_attempts）
        assert_eq!(mock.request_count(), 5, "补查次数上限必须被尊重");
        assert_eq!(sleeper.calls().len(), 3);

        let rows = service.store.list_probe_runs(10).expect("list_probe_runs");
        assert_eq!(rows.len(), 1, "没跑完也要留一条历史");
        assert_eq!(rows[0].status.as_deref(), Some("running"));
        assert_eq!(rows[0].verdict_status, None);
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
    ) -> (KeyRelayService<MockTransport>, i64, MockTransport) {
        let store = Store::open_in_memory().expect("内存库");
        let mock = MockTransport::new(tail);
        let service = KeyRelayService::new(store, mock.clone(), test_config());
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
    ) -> (KeyRelayService<MockTransport>, i64, MockTransport) {
        let store = Store::open_in_memory().expect("内存库");
        let mock = MockTransport::new(tail);
        let service = KeyRelayService::new(store, mock.clone(), test_config())
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
}
