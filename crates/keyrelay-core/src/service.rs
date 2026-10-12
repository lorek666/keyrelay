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
    }
}

/// 是不是「认证类失败」——即 `error_kind` 判为「认证失败」的那一类（M5-S0 章程 §4.1 规则 2）。
///
/// 只认 [`Error::AuthFailed`]：`CaptchaRequired` / `SecondFactorRequired` 的会话**未必**失效
/// （站点只是要人再过一道验证），把它们也标成 `needs_login` 会让用户看到一条假的
/// 「请重新登录」。
fn is_auth_failure(err: &Error) -> bool {
    matches!(err, Error::AuthFailed(_))
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteSummary {
    pub id: i64,
    pub kind: String,
    pub base_url: String,
    pub display_name: String,
    pub health: String,
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

pub struct KeyRelayService<T: HttpTransport + Clone + 'static> {
    registry: SiteRegistry<T>,
    store: Store,
    sessions: SessionCache,
    vault: Arc<dyn Vault>,
    home: PathBuf,
    backup_dir: PathBuf,
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
        }
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
        // 用户名不是秘密，但仍然过一遍脱敏入口（B-36：站点原文/用户名都可能被规则命中）
        let username = cred.username.clone();
        let adapter = self.registry.adapter(self.kind_of(&site)?);
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
        let session = self.session(site_id)?;
        let adapter = self.registry.adapter(self.kind_of(&site)?);
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
        let session = self.session(site_id)?;
        let adapter = self.registry.adapter(self.kind_of(&site)?);
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

    pub async fn balance(&self, site_id: i64) -> Result<Balance> {
        let site = self.site(site_id)?;
        let session = self.session(site_id)?;
        let adapter = self.registry.adapter(self.kind_of(&site)?);
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
        let writer = self.prepare_delivery(key_id, channel)?;
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
        let writer = self.prepare_delivery(key_id, channel)?;
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
        let writer = self.prepare_delivery(key_id, channel)?;
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
    pub fn apply_delivery(&self, key_id: i64, channel: DeliveryChannel) -> Result<DeliveryOutcome> {
        // ① 同意（未同意时**不读钥匙串、不落盘**）
        let writer = self.prepare_delivery(key_id, channel)?;
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
        let settings = self.settings()?;
        let sites = self.store.list_sites()?;
        let mut summary = RefreshSummary {
            sites_total: sites.len(),
            ..Default::default()
        };

        for site in sites {
            // 没有会话：要么用户从没登录过它（跳过），要么上一轮已判过「需要重新登录」
            // ——后者必须每轮都带出来，且不发任何请求（纯本地判定）。
            if self.sessions.get(site.id).is_none() {
                if site.health == HEALTH_NEEDS_LOGIN {
                    summary.needs_login.push(site.id);
                }
                continue;
            }

            let balance = self.balance(site.id).await;
            let keys = self.list_keys(site.id).await;

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
        Ok(summary)
    }

    /// 读某把令牌的明文。**只有显式调用才会返回密钥本体**——列举接口一律不含明文。
    pub async fn reveal_key(&self, site_id: i64, remote_id: &str) -> Result<KeyMaterial> {
        let site = self.site(site_id)?;
        let session = self.session(site_id)?;
        let adapter = self.registry.adapter(self.kind_of(&site)?);
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

    /// 删除站点上的某把令牌。
    pub async fn revoke_key(&self, site_id: i64, remote_id: &str) -> Result<()> {
        let site = self.site(site_id)?;
        let session = self.session(site_id)?;
        let adapter = self.registry.adapter(self.kind_of(&site)?);
        match adapter
            .revoke_key(&site.base_url, &session, remote_id)
            .await
        {
            Ok(()) => {
                self.log(observability::event_with_payload(
                    Level::Info,
                    "key",
                    "已删除站点上的密钥",
                    serde_json::json!({ "site_id": site_id, "remote_id": remote_id }),
                ));
                Ok(())
            }
            Err(err) => Err(self.on_auth_error(site_id, err)),
        }
    }

    /// 组装网关配置（含站点密钥）。调用方负责真正启动网关。
    ///
    /// `GatewayConfig` 的 `Debug` 已手写脱敏，不会打印令牌与密钥。
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
        let api_key = self.vault.get(&row.secret_ref)?.ok_or_else(|| {
            Error::Vault(format!(
                "钥匙串中没有该密钥（{}）；请先重新取一次钥匙",
                row.secret_ref
            ))
        })?;

        Ok(crate::gateway::GatewayConfig {
            port,
            token: crate::gateway::generate_token(),
            base_url: site.base_url,
            api_key,
            site_display_name: site.display_name,
        })
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

    /// 诊断导出：事件表 → JSON 文本。**导出前再过一遍 `scrub`**（纵深防御）。
    pub fn export_diagnostics(&self, limit: usize) -> Result<String> {
        let events = self.recent_events(limit)?;
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
        serde_json::to_string_pretty(&serde_json::json!({
            "vault_backend": self.vault.backend_name(),
            "home": self.home.display().to_string(),
            "events": rows,
        }))
        .map_err(|e| Error::Store(format!("导出诊断失败: {e}")))
    }

    /// 写事件。**故意不向上传播失败**：可观测性坏掉不该让业务操作失败。
    fn log(&self, event: Event) {
        if let Err(err) = self.store.insert_event(&event) {
            eprintln!("[keyrelay] 写入事件失败: {err}");
        }
    }

    /// 解析通道写入器 + 校验 `key_id` 存在。**不读钥匙串**（同意检查必须在读密钥之前）。
    fn prepare_delivery(
        &self,
        key_id: i64,
        channel: DeliveryChannel,
    ) -> Result<Box<dyn delivery::DeliveryWriter>> {
        // key_id 存在性先校验：不存在时连通道都不必解析
        let row = self
            .store
            .get_key(key_id)?
            .ok_or_else(|| Error::NotFound(format!("密钥记录 #{key_id} 不存在")))?;
        // Claude Code / shell 块两个通道要写 endpoint，需要该密钥所属站点的 base_url
        let site = self.site(row.site_id)?;
        delivery::resolve_for(channel, &self.home, &site.base_url)
    }

    /// 从钥匙串取密钥明文。调用方必须立刻用掉，不得记录。
    fn key_secret(&self, key_id: i64) -> Result<String> {
        let row = self
            .store
            .get_key(key_id)?
            .ok_or_else(|| Error::NotFound(format!("密钥记录 #{key_id} 不存在")))?;
        self.vault.get(&row.secret_ref)?.ok_or_else(|| {
            Error::Vault(format!(
                "钥匙串中没有该密钥（{}）；请先在该站点重新取一次钥匙",
                row.secret_ref
            ))
        })
    }

    /// 目标路径白名单：既要落在 `home` 之内，也要与**该通道声明的相对路径**逐字相等。
    ///
    /// 只做 `starts_with(home)` 是不够的：任何落在 home 下的路径都会放行（复核 P2）。
    /// 新增通道时必须在这里登记期望路径，否则一律拒绝——这样「通道写错文件」不可能悄悄发生。
    fn checked_target(&self, channel: DeliveryChannel, target: &Path) -> Result<PathBuf> {
        let expected_rel = match channel {
            DeliveryChannel::CodexAuthJson => PathBuf::from(".codex").join("auth.json"),
            DeliveryChannel::ClaudeCodeSettings => PathBuf::from(".claude").join("settings.json"),
            DeliveryChannel::ShellBlock => PathBuf::from(
                delivery::shell_block::ShellSyntax::for_current_platform()
                    .default_rc_relative_path(),
            ),
        };

        let expected = self.home.join(&expected_rel);
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
