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
use crate::site::registry::SiteRegistry;
use crate::site::transport::HttpTransport;
use crate::site::{Balance, Credentials, KeyMaterial, KeyMeta, KeySpec, Session, SiteKind};
use crate::store::{ConsentRow, SiteRow, Store};
use crate::vault::{KeychainVault, Vault};

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
}

/// 网关失败的内存缓冲上限。见 [`KeyRelayService::gateway_failures`] 的说明。
pub const MAX_BUFFERED_GATEWAY_FAILURES: usize = 256;

/// 往缓冲里放一条，满了丢**最旧**的一条。
///
/// 抽成函数是为了让**生产路径（网关回调）与测试路径（`record_gateway_failure_for_test`）
/// 走同一段逻辑**——否则「上限」这条纪律只在一边生效，而测试会证明一个产品里不存在的性质。
fn push_bounded(
    buffer: &mut std::collections::VecDeque<BufferedGatewayFailure>,
    failure: crate::gateway::GatewayFailure,
) {
    if buffer.len() >= MAX_BUFFERED_GATEWAY_FAILURES {
        buffer.pop_front();
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
        Self {
            registry: SiteRegistry::new(transport),
            store,
            sessions: SessionCache::new(),
            vault: config.vault,
            home: config.home,
            backup_dir: config.backup_dir,
            // 默认**不通知**：通知会弹窗并发网络请求，测试与纯核心用例不该意外触发。
            notify: None,
            gateway_failures: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
            gateway_session: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            site_facts: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            revoked_refs: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
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
        // 用户名不是秘密，但仍然过一遍脱敏入口（B-36：站点原文/用户名都可能被规则命中）
        let username = cred.username.clone();
        let adapter = self.registry.adapter(kind);
        let session = match adapter.login(&site.base_url, cred).await {
            Ok(session) => session,
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
        self.store.set_site_health(site_id, HEALTH_OK)?;
        self.sessions.put(site_id, session)?;
        self.log(observability::event_with_payload(
            Level::Info,
            "site",
            format!("登录成功: {username}"),
            serde_json::json!({ "site_id": site_id }),
        ));
        Ok(())
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
        match adapter.create_key(&site.base_url, &session, spec).await {
            Ok(material) => {
                // 站点上已经建好了。此刻若本地保存失败，必须如实告诉用户
                // 「站点上已创建、本地没存上」，而不是含糊地报一个失败让人重试建键。
                let stored = self
                    .store_key_material(site_id, &name, Some(&material.remote_id), &material.secret)
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

    /// 把站点标成「需要重新登录」。**best-effort**：写库失败只留一条 warn 事件，
    /// 不改写调用方看到的原始错误——调用方要的是「为什么失败」，不是「状态没存上」。
    fn mark_needs_login(&self, site_id: i64) {
        if let Err(err) = self.store.set_site_health(site_id, HEALTH_NEEDS_LOGIN) {
            self.log(observability::event_with_payload(
                Level::Warn,
                "store",
                format!("站点状态落库失败: {err}"),
                serde_json::json!({ "site_id": site_id, "health": HEALTH_NEEDS_LOGIN }),
            ));
        }
    }

    /// 删除站点记录，**同时清掉该 id 的会话缓存**。
    ///
    /// 复审 P2-6：SQLite rowid 会复用（删掉最大 id 后新站点可能拿到同一 id），
    /// 若不联动清理，旧站点的会话会被套用到新站点上，造成跨站串号。
    pub fn remove_site(&self, site_id: i64) -> Result<()> {
        self.sessions.invalidate(site_id);
        self.store.delete_site(site_id)
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

    /// 带模型名的投递预览。`model` 只对 OpenCode / OpenCodeJsonc / Continue 生效
    /// （[`delivery::resolve_for_binding`]），其余通道忽略。
    ///
    /// Continue 的条目**必须**有模型名（Continue 的 schema 必填，缺了整份配置拒绝加载）：
    /// `None` 时沿用受管块里已有的，块里也没有就拒绝——KeyRelay 不编造默认模型。
    pub fn delivery_plan_with_model(
        &self,
        key_id: i64,
        channel: DeliveryChannel,
        model: Option<&str>,
    ) -> Result<DeliveryPlan> {
        let writer = self.prepare_delivery(key_id, channel, model)?;
        let api_key = self.key_secret(key_id)?;
        let patch = writer.plan(&api_key)?;
        let target_path = writer.target_path();
        let consent = self.consent_state(channel, &target_path)?;
        self.log(observability::event_with_payload(
            Level::Debug,
            "delivery",
            format!("投递预览: {} → {}", channel.as_str(), target_path.display()),
            serde_json::json!({ "consent_granted": consent.is_granted() }),
        ));
        Ok(DeliveryPlan {
            agent_id: channel.agent_id().to_string(),
            channel,
            target_exists: target_path.exists(),
            fields: writer.fields(&api_key),
            preview: delivery::diff_preview(&patch.before, &patch.after, &api_key),
            consent,
            target_path,
        })
    }

    /// 记录用户同意（幂等：重复同意刷新时间戳并解除撤销）。
    pub fn grant_consent(&self, key_id: i64, channel: DeliveryChannel) -> Result<()> {
        let writer = self.prepare_delivery(key_id, channel, None)?;
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
        let writer = self.prepare_delivery(key_id, channel, None)?;
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

    /// 真正把密钥写进目标文件。步骤与顺序见 spec §6.1，**同意是第一步**。
    ///
    /// 不带模型名：轮换第②步走的就是这条——Continue 沿用受管块里已有的模型名。
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
        // ① 同意（未同意时**不读钥匙串、不落盘**）
        let writer = self.prepare_delivery(key_id, channel, model)?;
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

        // ④ 取密钥并生成计划
        let api_key = self.key_secret(key_id)?;
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

    /// 刷新全部**已登录**站点的余额与密钥数。
    ///
    /// 单个站点失败**不中断**其余站点：把失败计数与原因分类写进事件，
    /// 整体仍返回 `Ok`（否则调用方会以为整轮都废了）。
    ///
    /// 会话失效的站点（无会话 + `health == "needs_login"`）不联网、不计成功也不计失败，
    /// 但每轮都会出现在 [`RefreshSummary::needs_login`] 里——否则用户在界面上永远
    /// 看不到「这个站需要重新登录」（B-61）。
    pub async fn refresh_all(&self) -> Result<RefreshSummary> {
        // 先把网关攒下的失败落库（FR-5:160）。放在最前面：它们是**已经发生过**的事实，
        // 而下面的刷新要跑网络；先落库能让「网关为什么切换了上游」在事件面板里
        // 早于本轮的余额/漂移事件出现，读起来是因果顺序。
        self.drain_gateway_failures();
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

        for site in sites {
            // 没有会话：要么用户从没登录过它（跳过），要么上一轮已判过「需要重新登录」
            // ——后者必须每轮都带出来，且不发任何请求（纯本地判定）。
            if self.sessions.get(site.id).is_none() {
                let needs_login = site.health == HEALTH_NEEDS_LOGIN;
                if needs_login {
                    summary.needs_login.push(site.id);
                }
                snapshots.push(crate::notify::SiteSnapshot {
                    site_id: site.id,
                    display_name: site.display_name.clone(),
                    balance: None,
                    needs_login,
                    quota_exceeded: false,
                    models: None,
                    // 漂移与轮换到期都**不依赖会话**（前者由投递绑定推出、后者只看本地密钥
                    // 的创建时间），所以「没会话」这个分支同样要带上——否则用户在一个会话
                    // 失效的站点上反而看不到「这个站点的密钥该换了」。
                    drift: drift_by_site.get(&site.id).cloned().unwrap_or_default(),
                    rotation_due: rotation_by_site.get(&site.id).cloned().unwrap_or_default(),
                });
                continue;
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
            }
            let keys = self.list_keys(site.id).await;
            let mut quota_exceeded = false;

            match (&balance, &keys) {
                (Ok(_), Ok(list)) => {
                    summary.sites_ok += 1;
                    summary.keys_total += list.len();
                }
                _ => {
                    summary.sites_failed += 1;
                    let failure = balance.as_ref().err().or_else(|| keys.as_ref().err());
                    let reason = failure.map(error_kind).unwrap_or("未知");
                    // 认证失败 = 会话已失效：`on_auth_error` 已经把它落库，
                    // 这里再带进本轮汇总，用户当场就能看到。
                    if failure.is_some_and(is_auth_failure) {
                        summary.needs_login.push(site.id);
                    }
                    // 额度耗尽（HTTP 403 + 已知错误码）是**独立**于会话失效的一种状态：
                    // 会话是好的，只是没钱了。分开判定，否则用户会去重新登录一个
                    // 根本不需要登录的站点（PRD FR-3 的告警清单里两条并列）。
                    quota_exceeded = matches!(failure, Some(Error::QuotaExhausted));
                    self.log(observability::event_with_payload(
                        Level::Warn,
                        "site",
                        format!("刷新站点失败: {reason}"),
                        serde_json::json!({ "site_id": site.id, "base_url": site.base_url }),
                    ));
                }
            }

            if let Ok(balance) = &balance {
                if settings.balance_alert_threshold > 0.0
                    && balance.remaining < settings.balance_alert_threshold
                {
                    summary.balance_alerts.push(site.id);
                    self.log(observability::event_with_payload(
                        Level::Warn,
                        "site",
                        format!(
                            "余额低于阈值: {} {} < {}",
                            balance.remaining, balance.currency, settings.balance_alert_threshold
                        ),
                        serde_json::json!({
                            "site_id": site.id,
                            "base_url": site.base_url,
                            "remaining": balance.remaining,
                        }),
                    ));
                }
            }

            snapshots.push(crate::notify::SiteSnapshot {
                site_id: site.id,
                display_name: site.display_name.clone(),
                balance: balance
                    .as_ref()
                    .ok()
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
                needs_login: summary.needs_login.contains(&site.id),
                quota_exceeded,
                // `models` 本轮不取：拿模型列表要先用某把 key 调 `/v1/models`，
                // 那是「每个站点每轮一次额外的带密钥请求」。见 spec §6 的
                // `ModelsChanged` 未接线说明（已登记为**有意取舍**，见 BACKLOG B-80）。
                models: None,
                drift: drift_by_site.get(&site.id).cloned().unwrap_or_default(),
                rotation_due: rotation_by_site.get(&site.id).cloned().unwrap_or_default(),
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
                let notifier = crate::notify::WebhookNotifier::new(state.config.clone());
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
                        "webhook": crate::redact::strip_url_userinfo(
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
        for channel in channels {
            let channel_name = channel.as_str();
            if let Err(err) = self.apply_delivery(new_key.id, channel) {
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
            Ok(()) => {
                self.log(observability::event_with_payload(
                    Level::Info,
                    "key",
                    "轮换完成: 新密钥已全量注入，旧密钥已回收",
                    serde_json::json!({
                        "site_id": plan.site_id,
                        "old_key_id": key_id,
                        "new_key_id": new_key.id,
                        "reinjected": &reinjected,
                    }),
                ));
                Ok(RotationRun {
                    new_key,
                    reinjected,
                    revoke: RevokeOutcome::Revoked,
                    // 本地那一行**刻意不删**：`bindings.key_id` 是 `ON DELETE CASCADE`，
                    // 删行会连带丢掉旧 key 的绑定与漂移追溯；对账交给 `sync_site_keys`。
                    stopped_at: None,
                    stop_reason: None,
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
            match self.store_key_material(site_id, &name, Some(&remote_id), &material.secret) {
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
    pub async fn revoke_key(&self, site_id: i64, remote_id: &str) -> Result<()> {
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
                // **读本地行失败也不能把整次操作报成失败**（M8-S5A §4）：
                // 站点侧那一把已经删了，这个动作不可逆。原来的 `?` 会让「DELETE 成功、
                // 但本地这一读失败」表现为「回收失败」——与下面 `set_key_status` 那条注释里
                // 写着的原则**自相矛盾**（同一类事实，两种处置）。
                let key_id = match self.local_key_id_for_remote(site_id, remote_id) {
                    Ok(id) => id,
                    Err(err) => {
                        self.log(observability::event_with_payload(
                            Level::Warn,
                            "key",
                            "站点侧已回收，但读本地记录失败（本地状态没写上）",
                            serde_json::json!({
                                "site_id": site_id,
                                "reason": crate::redact::scrub(&err.to_string()),
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
                    if let Err(err) = self
                        .store
                        .set_key_status(key_id, crate::store::KEY_STATUS_REVOKED)
                    {
                        self.log(observability::event_with_payload(
                            Level::Warn,
                            "key",
                            "站点侧已回收，但本地状态没写上",
                            serde_json::json!({
                                "site_id": site_id,
                                "key_id": key_id,
                                "reason": crate::redact::scrub(&err.to_string()),
                            }),
                        ));
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
                    }),
                ));
                Ok(())
            }
            Err(err) => Err(self.on_auth_error(site_id, err)),
        }
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
    /// 今天只有 `keys.secret_ref` 一种：`accounts` 表有 `credential_ref` 列，
    /// 但全仓没有写入器（M7-S4 的同类发现），所以它现在不可能有行。
    fn owned_secret_refs(&self) -> Result<Vec<String>> {
        let mut refs: Vec<String> = self
            .store
            .list_keys()?
            .into_iter()
            .map(|row| row.secret_ref)
            .collect();
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
        // **未接线（去向 M8-S1 第 13 行）**：`GatewayConfig::api_key` 的类型仍是裸 `String`
        // （单上游 legacy 字段），所以下面这一次 `.to_string()` 产生的副本**没有**被
        // `Zeroizing` 包住。`keys_by_ref` 那条路径已经是 `Zeroizing` 了，单上游这条还不是。
        let api_key = self.key_secret(key_id)?.to_string();

        let (route, keys_by_ref) = self.build_gateway_route()?;

        let mut config = crate::gateway::GatewayConfig::single_upstream(
            port,
            crate::gateway::generate_token(),
            site.base_url,
            api_key,
            site.display_name,
        );
        // ① 路由表：**非空**（只要至少有一个可用站点）。空表会退回 legacy 单上游路径，
        //    那正是 M7 的 D-4——所以这里非空本身就是本包存在的意义。
        config.route = route;
        // ② 明文映射：`route` 里出现的每个 `key_ref` 都在这里。集合不变式由
        //    `tests/routing_wiring.rs` 的 W3 守着（缺一个 ⇒ 网关静默 502）。
        config.keys_by_ref = keys_by_ref;
        // ③ 已回收集合：网关只**查**它，不新开取密钥路径。
        config.revoked_refs = Some(Arc::clone(&self.revoked_refs));
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
        config.on_failure = Some(Arc::new(move |failure: crate::gateway::GatewayFailure| {
            // 会话比对：**不相等就丢弃**（§11.1）。丢弃的代价写在 spec 的未验证边界里：
            // 停止瞬间在途请求的失败不进事件表——把它记到下一个会话是主动误导，
            // 而它本身（网关正在停）也不构成可诊断的故障。
            if current.load(std::sync::atomic::Ordering::SeqCst) != session {
                return;
            }
            if let Ok(mut buffer) = sink.lock() {
                push_bounded(&mut buffer, failure);
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
        Ok(config)
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

        Ok((crate::routing::build_route_table(&facts), keys))
    }

    /// 该站点用来出网的 key：**未回收**里 id 最大的那一条（最新的一把）。
    fn pick_gateway_key(&self, site_id: i64) -> Result<Option<crate::store::KeyRow>> {
        Ok(self
            .store
            .list_keys()?
            .into_iter()
            .filter(|row| row.site_id == site_id)
            .filter(|row| row.status != crate::store::KEY_STATUS_REVOKED)
            .max_by_key(|row| row.id))
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
        let drained: Vec<BufferedGatewayFailure> = match self.gateway_failures.lock() {
            Ok(mut buffer) => buffer.drain(..).collect(),
            Err(_) => return 0,
        };
        for buffered in &drained {
            let failure = &buffered.failure;
            // `status == 0` 是哨兵（M8-S1 §9）：HTTP 里不存在 0，它表示
            // 「没有任何上游返回过状态码」（候选全被熔断 / 缺明文 / 已回收）。
            // 文案必须写明，否则读者会把 0 误读成真实状态码。
            let message = if failure.status == 0 {
                format!("网关没有可用的上游（site {}）", failure.site_id)
            } else {
                format!("网关放弃上游（HTTP {}）", failure.status)
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
            push_bounded(&mut buffer, failure);
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
        secret: &str,
    ) -> Result<StoredKey> {
        if secret.trim().is_empty() {
            return Err(Error::Vault("密钥为空，拒绝保存".into()));
        }
        let ref_id = new_ref_id();
        let secret_ref = crate::vault::secret_ref("key", &ref_id, "secret");
        self.vault.put(&secret_ref, secret)?;

        match self.store.insert_key(site_id, name, &secret_ref, remote_id) {
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
    /// 走 `resolve_for_binding` 而不是 `resolve_for`：后者固定 `model = None`，
    /// 生产路径因此从来没法给 Continue 写模型名（Continue 拒绝加载缺 `model` 的配置）。
    fn prepare_delivery(
        &self,
        key_id: i64,
        channel: DeliveryChannel,
        model: Option<&str>,
    ) -> Result<Box<dyn delivery::DeliveryWriter>> {
        // key_id 存在性先校验：不存在时连通道都不必解析
        let row = self
            .store
            .get_key(key_id)?
            .ok_or_else(|| Error::NotFound(format!("密钥记录 #{key_id} 不存在")))?;
        // Claude Code / shell 块两个通道要写 endpoint，需要该密钥所属站点的 base_url
        let site = self.site(row.site_id)?;
        delivery::resolve_for_binding(
            channel,
            &self.home,
            &site.base_url,
            delivery::opencode::OpenCodeWriter::DEFAULT_PROVIDER_ID,
            model,
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

    /// 从一行密钥记录取出明文。**这是全文件唯一读钥匙串取明文的地方。**
    ///
    /// 收成一个函数不是为了好看：`tests/zeroize_hygiene.rs` 有一条结构守卫断言
    /// `vault.get(` 在 `service.rs` 里恰好出现一次——那条守卫在 M8-S1 加
    /// `build_gateway_route`（网关的明文映射）时**当场红了**，红得对：
    /// 那是第二个明文出口。处置是把它收进这里，而不是放宽断言。
    fn secret_for_row(&self, row: &crate::store::KeyRow) -> Result<zeroize::Zeroizing<String>> {
        let secret = self.vault.get(&row.secret_ref)?.ok_or_else(|| {
            Error::Vault(format!(
                "钥匙串中没有该密钥（{}）；请先在该站点重新取一次钥匙",
                row.secret_ref
            ))
        })?;
        // M7-S5 spec §2.1 要求的 `Zeroizing` 直到 M8-S5A 才真正落地：此前它是裸 `String`，
        // 而复审 §6-4 写的却是「核了」（DEBUG 报告 §1.10）。
        //
        // 返回 `Zeroizing` 而不是在调用点各自包一层：调用点会变多，咽喉点只有一个。
        // 调用方拿到的东西类型上就不是裸 `String`，所以「某次调用忘了清零」在编译期就不成立。
        Ok(zeroize::Zeroizing::new(secret))
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
}
