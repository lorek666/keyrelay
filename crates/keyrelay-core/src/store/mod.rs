//! 本地元数据存储（SQLite / WAL）。
//!
//! 红线：本模块**不存密钥**。`keys.secret_ref` 只是钥匙串引用（见 `vault::secret_ref`）。

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};

use crate::error::{Error, Result};
use crate::inject::Journal;
use crate::site::KeyStatus;

const SCHEMA_VERSION: i64 = 3;

/// 「已回收」——**本地**密钥生命周期状态（M7-S4 / FR-2）。
///
/// **这一列的词表是本地词表**：`keys.status` 今天**没有任何站点侧写入者**——
/// `INSERT INTO keys` 不写它（`store/mod.rs:395`）、也没有把站点侧 `KeyMeta.status` 映射进来的代码，
/// 所以它记的是**本产品对这把钥匙做过什么**，而不是站点怎么报。
///
/// `site::KeyStatus` 只有 `enabled` / `disabled` / `exhausted` / `unknown`，**装不下「已回收」**
/// ——键在站点上已经不存在了，站点永远不会报这个状态。用 `"disabled"` 冒充会让界面无法区分
/// 「站点把它禁了」与「我自己把它回收了」，而后者正是本包存在的理由（章程 §3.4 v1.1 裁决）。
pub const KEY_STATUS_REVOKED: &str = "revoked";

/// `keys.status` 的合法值 = 站点侧词表 ∪ 本地词表。
///
/// 站点侧四个值**从枚举派生**（不抄字面量）：章程 §3.4 的原文就是「只接受 `site::KeyStatus::as_str()`
/// 的合法值」，派生比抄写少一个漂移源。新增站点侧变体时，`tests/key_lifecycle.rs` 里那条
/// 穷举 `match` 会编译失败，逼人回来确认本集合。
fn legal_key_statuses() -> [&'static str; 5] {
    [
        KeyStatus::Enabled.as_str(),
        KeyStatus::Disabled.as_str(),
        KeyStatus::Exhausted.as_str(),
        KeyStatus::Unknown.as_str(),
        KEY_STATUS_REVOKED,
    ]
}

fn is_legal_key_status(status: &str) -> bool {
    legal_key_statuses().contains(&status)
}

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sites(
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,
  base_url TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL DEFAULT '',
  fingerprint_json TEXT,
  health TEXT NOT NULL DEFAULT 'unknown',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts(
  id INTEGER PRIMARY KEY,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  credential_ref TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'unknown',
  plan TEXT,
  last_login_at INTEGER
);
CREATE TABLE IF NOT EXISTS keys(
  id INTEGER PRIMARY KEY,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  account_id INTEGER REFERENCES accounts(id) ON DELETE SET NULL,
  remote_id TEXT,
  name TEXT NOT NULL,
  group_id TEXT,
  group_name TEXT,
  secret_ref TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'unknown',
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  quota_used REAL,
  quota_limit REAL,
  currency TEXT
);
CREATE TABLE IF NOT EXISTS bindings(
  id INTEGER PRIMARY KEY,
  agent_id TEXT NOT NULL,
  key_id INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
  target_path TEXT NOT NULL,
  managed_json TEXT,
  applied_at INTEGER NOT NULL,
  journal_id TEXT,
  -- M8-S4：解绑标记（FR-2:115）。**不删行**——漂移追溯与 journals 的溯源靠它存活。
  -- NULL = 仍然绑定。老库靠 `add_column_if_missing` 补上（见 `migrate()`）。
  unbound_at INTEGER
);
CREATE TABLE IF NOT EXISTS journals(
  id TEXT PRIMARY KEY,
  ts INTEGER NOT NULL,
  op TEXT NOT NULL,
  target_path TEXT NOT NULL,
  before_sha256 TEXT,
  after_sha256 TEXT,
  backup_path TEXT,
  status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  level TEXT NOT NULL,
  source TEXT NOT NULL,
  message TEXT NOT NULL,
  payload_redacted_json TEXT
);
-- 密钥投递的用户授权（M1-S2）。**只存键名**，任何情况下不得出现密钥明文或掩码值。
CREATE TABLE IF NOT EXISTS consents(
  id INTEGER PRIMARY KEY,
  agent_id TEXT NOT NULL,
  channel TEXT NOT NULL,
  target_path TEXT NOT NULL,
  fields TEXT NOT NULL,
  granted_at INTEGER NOT NULL,
  revoked_at INTEGER,
  UNIQUE(agent_id, channel, target_path)
);
CREATE INDEX IF NOT EXISTS idx_consents_agent ON consents(agent_id, channel);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
-- 运行时设置（M3-S1）。键值都是文本，读不到就用默认值。
CREATE TABLE IF NOT EXISTS settings(
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
-- 已知导出物（M5-S1 / 关闭 B-60）。审计按这张表扫，用户自选路径才算进了覆盖范围。
-- 只记路径与统计，不记内容。
CREATE TABLE IF NOT EXISTS exports(
  path        TEXT PRIMARY KEY,
  encrypted   INTEGER NOT NULL,
  bytes       INTEGER NOT NULL,
  exported_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bindings_target ON bindings(target_path);
"#;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 钥匙串引用形状：`kr/<scope>/<id>/<field>`（与 `vault::secret_ref` 一致）。
///
/// 采用白名单而非黑名单：只拦 `sk-` / `nap-` 前缀会放过 32 位 hex 之类的明文
/// （复审 P2-4 的探针即用该形状入库成功）。
fn is_valid_secret_ref(value: &str) -> bool {
    let parts: Vec<&str> = value.split('/').collect();
    parts.len() == 4 && parts[0] == "kr" && parts[1..].iter().all(|p| !p.is_empty())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteRow {
    pub id: i64,
    pub kind: String,
    pub base_url: String,
    pub display_name: String,
    pub health: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRow {
    pub id: i64,
    pub site_id: i64,
    pub remote_id: Option<String>,
    pub name: String,
    pub group_name: Option<String>,
    pub secret_ref: String,
    pub status: String,
    /// 本地记账的创建时间（unix 秒）。M6-S5 起用于密钥轮换判定
    /// （`rotation::due_keys`）；列一直是 `NOT NULL`，只是先前没进 `SELECT`。
    pub created_at: i64,
}

/// 事件行。`message` / `payload` 在写入时已脱敏。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRow {
    pub id: i64,
    pub ts: i64,
    pub level: String,
    pub source: String,
    pub message: String,
    pub payload: Option<String>,
}

/// 一次投递的漂移检测输入：绑定 + 投递时记录的哈希。
///
/// M6-S5（W-1）新增 `site_id`：漂移本身是**投递目标**的属性，但通知快照
/// （章程 §4.3 的 `SiteSnapshot`）是按站点装配的，装配时必须知道归属。
/// 归属取自 `bindings.key_id → keys.site_id`（`keys.id` 有 `ON DELETE CASCADE`，
/// 所以不存在「绑定还在、密钥已删」的悬挂行，用 INNER JOIN 不会丢行）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingDriftRow {
    pub agent_id: String,
    pub target_path: String,
    pub journal_id: String,
    /// 投递时该文件的 sha256；老库可能没有
    pub expected_sha256: Option<String>,
    /// 该绑定所用密钥所属的站点（用于把漂移事实归到站点快照上）
    pub site_id: i64,
    /// 该绑定所用的密钥 id（用于「这把 key 现在服务哪些投递目标」）
    pub key_id: i64,
}

/// 一条投递绑定（M8-S4 的解绑与「同时回收」都要按它走）。
///
/// 含**已解绑**的行：`also_revoke` 要按「这次解绑之前有哪些绑定」去回收站点侧，
/// 而解绑本身不删行（§5.1），所以读的时候必须能把两者分开——判据是 `unbound_at`。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingRow {
    pub id: i64,
    pub agent_id: String,
    pub key_id: i64,
    pub target_path: String,
    pub applied_at: i64,
    /// `None` = 仍然绑定。
    pub unbound_at: Option<i64>,
    /// 该绑定所用密钥所属的站点。
    pub site_id: i64,
    /// 站点侧的令牌 id（回收要用它）。
    pub remote_id: Option<String>,
}

/// 解绑的返回语义（**逐条**，因为它们都会被 UI 直接念给用户听）：
/// - `unbound`：本次**新标记**的行数（已解绑过的行不计 ⇒ 幂等，二次调用返回 0）
/// - `already_unbound`：本次看到但**早已解绑**的行数（用于「本来就是解绑状态」的文案）
///
/// 两者之和 = 这次调用**匹配到**的绑定总数。这是一条可断言的恒等式。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnbindReport {
    pub unbound: usize,
    pub already_unbound: usize,
}

/// 投递授权行。`fields` 是 JSON 数组，**只有键名**。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentRow {
    pub agent_id: String,
    pub channel: String,
    pub target_path: String,
    pub fields: String,
    pub granted_at: i64,
    pub revoked_at: Option<i64>,
}

/// 一次导出的登记行（M5-S1 / 关闭 B-60）。**不含文件内容**。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportRecord {
    pub path: String,
    pub encrypted: bool,
    pub bytes: i64,
    pub exported_at: i64,
}

pub struct Store {
    conn: Mutex<Connection>,
    /// 文件库的路径；内存库为 `None`。审计要用它定位 `*.db` / `-wal` / `-shm`。
    path: Option<std::path::PathBuf>,
}

/// `scheme://user:pass@host/...` 里的 `user:pass@host` 部分（**不含**路径 / query / fragment）。
///
/// 返回的是带 userinfo 的整个 authority，而不是只返回 userinfo：被修的历史数据形态是
/// `display_name == "alice:pw@host.example"`（当时的 `host_of` 把整个 authority 当成了 host）。
/// 逐字比对整段 ⇒ 零误伤。
fn authority_of(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    Some(authority.to_string())
}

/// 从 URL 里取 host[:port]（不含 userinfo、不含路径）。取不到时原样返回。
fn host_of_url(url: &str) -> String {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    if host.is_empty() {
        url.to_string()
    } else {
        host.to_string()
    }
}

/// 表里没有这一列时才 `ALTER TABLE` 加上它。
///
/// 为什么不能直接 `ALTER TABLE ... ADD COLUMN`：`migrate()` 每次打开都跑，
/// 第二次会因 `duplicate column name` 失败。为什么也不能只靠 DDL：
/// `CREATE TABLE IF NOT EXISTS` 对已存在的表是空操作，加列不会生效（M8-S4 §5.2）。
fn add_column_if_missing(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
    decl: &str,
) -> Result<()> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| Error::Store(format!("读取表结构失败: {e}")))?;
    let existing: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| Error::Store(format!("读取表结构失败: {e}")))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Store(format!("读取表结构失败: {e}")))?;
    drop(stmt);

    if existing.iter().any(|name| name == column) {
        return Ok(());
    }
    conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"))
        .map_err(|e| Error::Store(format!("为 {table} 增加 {column} 列失败: {e}")))?;
    Ok(())
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Store(format!("创建数据目录失败: {e}")))?;
        }
        let conn =
            Connection::open(path).map_err(|e| Error::Store(format!("打开数据库失败: {e}")))?;
        // 文件库必须真的跑在 WAL 上（并发读+写）。内存库不支持 WAL，只在 open_in_memory 分支跳过。
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| Error::Store(format!("切换 WAL 模式失败: {e}")))?;
        let store = Self::from_conn(conn)?;
        // 记下路径（`from_conn` 不关心路径）
        Ok(Self {
            conn: store.conn,
            path: Some(path.to_path_buf()),
        })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| Error::Store(format!("打开内存库失败: {e}")))?;
        Self::from_conn(conn)
    }

    fn from_conn(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| Error::Store(format!("开启外键失败: {e}")))?;
        let store = Self {
            conn: Mutex::new(conn),
            path: None,
        };
        store.migrate()?;
        Ok(store)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| Error::Store("数据库锁已中毒".into()))
    }

    fn migrate(&self) -> Result<()> {
        let conn = self.lock()?;
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|e| Error::Store(format!("读取 schema 版本失败: {e}")))?;

        // **每次都跑 DDL**，而不是只在版本变化时跑。
        //
        // DDL 里全是 `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`，天然幂等。
        // 只在 `version < SCHEMA_VERSION` 时跑会有一个隐蔽后果：往 DDL 里**新增**表
        // 却不改版本号时，已经存在的库永远建不出那张新表——
        // 实测：加了 `consents` 之后，跑过旧版的 `~/.keyrelay/keyrelay.db` 里依然没有该表，
        // `grant_consent` 会直接报 `no such table`（M1-S4 真实启动时发现）。
        conn.execute_batch(DDL)
            .map_err(|e| Error::Store(format!("建表失败: {e}")))?;

        // **加列必须显式迁移**（M8-S4 §5.2）。DDL 里全是 `CREATE TABLE IF NOT EXISTS`——
        // 对**已存在**的表它是空操作，所以往建表语句里加一列，老库永远不会有那一列。
        // 这正是 `keys.status` 那个形态：列在 DDL 里、老库里没有。
        //
        // **必须先判存在**：不判的话第二次打开会因 `duplicate column name` 直接失败——
        // 而 `migrate()` 是每次打开都跑的。
        add_column_if_missing(&conn, "bindings", "unbound_at", "INTEGER")?;

        // 版本号仍然只在升级时写，保留它作为「将来需要非幂等迁移」的锚点。
        if version < SCHEMA_VERSION {
            conn.pragma_update(None, "user_version", SCHEMA_VERSION)
                .map_err(|e| Error::Store(format!("写入 schema 版本失败: {e}")))?;
        }
        Ok(())
    }

    /// 文件库的路径；内存库返回 `None`。
    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }

    pub fn schema_version(&self) -> Result<i64> {
        let conn = self.lock()?;
        conn.pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|e| Error::Store(format!("读取 schema 版本失败: {e}")))
    }

    /// 按 `base_url` 去重写入，返回站点 id
    pub fn upsert_site(&self, kind: &str, base_url: &str, display_name: &str) -> Result<i64> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO sites(kind, base_url, display_name, created_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(base_url) DO UPDATE SET kind = ?1, display_name = ?3",
            params![kind, base_url, display_name, now_secs()],
        )
        .map_err(|e| Error::Store(format!("写入站点失败: {e}")))?;
        conn.query_row(
            "SELECT id FROM sites WHERE base_url = ?1",
            params![base_url],
            |row| row.get(0),
        )
        .map_err(|e| Error::Store(format!("读取站点 id 失败: {e}")))
    }

    pub fn list_sites(&self) -> Result<Vec<SiteRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT id, kind, base_url, display_name, health FROM sites ORDER BY id")
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(SiteRow {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    base_url: row.get(2)?,
                    display_name: row.get(3)?,
                    health: row.get(4)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询站点失败: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取站点行失败: {e}")))
    }

    pub fn get_site(&self, id: i64) -> Result<Option<SiteRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT id, kind, base_url, display_name, health FROM sites WHERE id = ?1")
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let mut rows = stmt
            .query_map(params![id], |row| {
                Ok(SiteRow {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    base_url: row.get(2)?,
                    display_name: row.get(3)?,
                    health: row.get(4)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询站点失败: {e}")))?;

        match rows.next() {
            Some(Ok(row)) => Ok(Some(row)),
            Some(Err(e)) => Err(Error::Store(format!("读取站点行失败: {e}"))),
            None => Ok(None),
        }
    }

    pub fn delete_site(&self, id: i64) -> Result<()> {
        let conn = self.lock()?;
        conn.execute("DELETE FROM sites WHERE id = ?1", params![id])
            .map_err(|e| Error::Store(format!("删除站点失败: {e}")))?;
        Ok(())
    }

    /// `secret_ref` 必须是钥匙串引用（`kr/<scope>/<id>/<field>`），禁止传明文
    ///
    /// `group_name` 是**调用方给的权威值**（新建密钥时用户刚填的那个分组）。
    /// 传 `None` 表示「不知道」⇒ 落 `NULL`，界面显示空——**绝不猜**：
    /// `sync_site_keys` 的导入路径就传 `None`，那条路的名字都是从 `KeyMeta` 反查的，
    /// 分组同样没有权威来源。
    ///
    /// `status` **刻意不写**：它是本地词表（见本模块顶部 `KEY_STATUS_REVOKED` 的说明），
    /// `DEFAULT 'unknown'` 的正确含义是「本产品没对这把钥匙做过任何事」。
    /// 新建时写一个站点侧状态会把两套语义混成一列（M8-S5B §6.5）。
    pub fn insert_key(
        &self,
        site_id: i64,
        name: &str,
        secret_ref: &str,
        remote_id: Option<&str>,
        group_name: Option<&str>,
    ) -> Result<i64> {
        if !is_valid_secret_ref(secret_ref) {
            return Err(Error::Store(format!(
                "secret_ref 必须是钥匙串引用（kr/<scope>/<id>/<field>），拒绝写入疑似明文: {}",
                crate::redact::scrub(secret_ref)
            )));
        }
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO keys(site_id, remote_id, name, secret_ref, created_at, group_name)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![site_id, remote_id, name, secret_ref, now_secs(), group_name],
        )
        .map_err(|e| Error::Store(format!("写入密钥记录失败: {e}")))?;
        Ok(conn.last_insert_rowid())
    }

    /// 按 id 取单条密钥记录（投递时用它拿 `secret_ref`）。
    pub fn get_key(&self, id: i64) -> Result<Option<KeyRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, site_id, remote_id, name, group_name, secret_ref, status, created_at
                 FROM keys WHERE id = ?1",
            )
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let mut rows = stmt
            .query_map(params![id], |row| {
                Ok(KeyRow {
                    id: row.get(0)?,
                    site_id: row.get(1)?,
                    remote_id: row.get(2)?,
                    name: row.get(3)?,
                    group_name: row.get(4)?,
                    secret_ref: row.get(5)?,
                    status: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询密钥失败: {e}")))?;
        match rows.next() {
            Some(row) => {
                Ok(Some(row.map_err(|e| {
                    Error::Store(format!("读取密钥行失败: {e}"))
                })?))
            }
            None => Ok(None),
        }
    }

    /// 记录一次投递绑定（agent ← key → 目标文件）。
    pub fn record_binding(
        &self,
        agent_id: &str,
        key_id: i64,
        target_path: &str,
        journal_id: &str,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO bindings(agent_id, key_id, target_path, applied_at, journal_id)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![agent_id, key_id, target_path, now_secs(), journal_id],
        )
        .map_err(|e| Error::Store(format!("写入投递绑定失败: {e}")))?;
        Ok(())
    }

    /// 解绑一个 agent 与它的密钥（FR-2:115）。**默认只解绑不回收**（可恢复）。
    ///
    /// **解绑不是删除**：`bindings` 行**保留**，只写 `unbound_at`。
    /// 删行会连带丢掉 `managed_json` / `journal_id`（回滚要靠它），
    /// 而 `keys.id` 是漂移追溯链的起点——与 B-82 同一条纪律（M7-S4 spec §6.1 有实测）。
    ///
    /// **幂等**：命中已解绑的行时**不刷新时间戳**，只计入 `already_unbound`。
    /// 刷新时间戳会让「什么时候解绑的」随着重复点击漂移。
    pub fn unbind_agent(&self, agent_id: &str) -> Result<UnbindReport> {
        self.unbind_where("agent_id = ?1", &[&agent_id])
    }

    /// 只解绑**某一个目标文件**上的绑定（同一 agent 可能有多个落点）。
    pub fn unbind_target(&self, target_path: &str) -> Result<UnbindReport> {
        self.unbind_where("target_path = ?1", &[&target_path])
    }

    fn unbind_where(
        &self,
        predicate: &str,
        params: &[&dyn rusqlite::ToSql],
    ) -> Result<UnbindReport> {
        let conn = self.lock()?;
        // 先数「早已解绑」的：`UPDATE` 的 `changes()` 只报**真的改了**的行数，
        // 而用户需要知道「本来就是解绑状态」与「这次才解开」的区别（UI 两种文案）。
        let already_unbound: usize = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM bindings WHERE {predicate} AND unbound_at IS NOT NULL"
                ),
                params,
                |row| row.get::<_, i64>(0),
            )
            .map_err(|e| Error::Store(format!("统计解绑记录失败: {e}")))?
            .max(0) as usize;
        // 时间戳**内联**成一个整数字面量而不是占位符：谓词里的占位符编号由调用方给，
        // 再塞一个 `?2` 会让「谓词有几个参数」与「这条语句要几个参数」耦合成一个陷阱
        // （第一版就是这么写的，实测 `Wrong number of parameters`）。
        // 值是 `i64`，不来自任何外部输入，拼接是安全的。
        let unbound = conn
            .execute(
                &format!(
                    "UPDATE bindings SET unbound_at = {} WHERE {predicate} AND unbound_at IS NULL",
                    now_secs()
                ),
                params,
            )
            .map_err(|e| Error::Store(format!("写入解绑标记失败: {e}")))?;
        Ok(UnbindReport {
            unbound,
            already_unbound,
        })
    }

    /// 一个 agent 的绑定（含已解绑的行——`also_revoke` 要按**当时的**绑定去回收）。
    pub fn bindings_of_agent(&self, agent_id: &str) -> Result<Vec<BindingRow>> {
        self.bindings_where("b.agent_id = ?1", &[&agent_id])
    }

    /// 某一个目标文件上的绑定。
    pub fn bindings_of_target(&self, target_path: &str) -> Result<Vec<BindingRow>> {
        self.bindings_where("b.target_path = ?1", &[&target_path])
    }

    /// 全部绑定（含已解绑的行）。
    ///
    /// 给**批量**动作用（M8-S7 / B-116：「把已投递的通道批量改指网关」要拿到全部候选）。
    /// 单 agent 的场景请用 [`Self::bindings_of_agent`]——那个有 predicate，不会把
    /// 无关 agent 的行也拉回来。
    pub fn all_bindings(&self) -> Result<Vec<BindingRow>> {
        self.bindings_where("1 = 1", &[])
    }

    fn bindings_where(
        &self,
        predicate: &str,
        params: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<BindingRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT b.id, b.agent_id, b.key_id, b.target_path, b.applied_at, b.unbound_at,
                        k.site_id, k.remote_id
                 FROM bindings b JOIN keys k ON k.id = b.key_id
                 WHERE {predicate}
                 ORDER BY b.id"
            ))
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let rows = stmt
            .query_map(params, |row| {
                Ok(BindingRow {
                    id: row.get(0)?,
                    agent_id: row.get(1)?,
                    key_id: row.get(2)?,
                    target_path: row.get(3)?,
                    applied_at: row.get(4)?,
                    unbound_at: row.get(5)?,
                    site_id: row.get(6)?,
                    remote_id: row.get(7)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询绑定失败: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取绑定行失败: {e}")))
    }

    /// 把 `sites.display_name` 里**逐字等于该站点 `base_url` 的 userinfo** 的行改写成 host。
    ///
    /// M7 版本录入 `https://alice:pw@host` 时，`display_name` 被写成了 `alice:pw@host`
    /// （`custom_openai::host_of` 当时的形态）。那条数据**已经入库**，而文本级脱敏
    /// 没有 `://` 抓不到它——所以通知与 webhook 正文会持续带出密码（DEBUG 报告 §1.3 / 复审 P2-4）。
    ///
    /// **判据是「逐字等于」而不是「看起来像 URL」**：只有 `display_name` 与从 `base_url`
    /// 里剥出来的 userinfo 完全一致时才改写，所以**零误伤**——一个用户真的想把显示名
    /// 取成 `alice:pw@host` 的情形，与这条迁移想修的形态在字节上无法区分，
    /// 但那种命名本身没有意义，代价可接受。
    pub fn migrate_display_names_stripping_userinfo(&self) -> Result<usize> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT id, base_url, display_name FROM sites")
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let rows: Vec<(i64, String, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|e| Error::Store(format!("查询站点失败: {e}")))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取站点行失败: {e}")))?;
        drop(stmt);

        let mut changed = 0usize;
        for (id, base_url, display_name) in rows {
            // **判据是「逐字等于带 userinfo 的 authority」**，不是「看起来像 userinfo」。
            //
            // 被修的那种形态是 `custom_openai::host_of` 当时产出的：它把整个 authority
            // 当成了 host，所以 `display_name` 是 `alice:pw@host.example`
            // （含 `@` 与 host），不是 `alice:pw`。逐字相等 ⇒ 零误伤。
            let Some(authority) = authority_of(&base_url) else {
                continue;
            };
            if display_name != authority || !authority.contains('@') {
                continue;
            }
            let stripped = crate::redact::strip_url_userinfo(&base_url);
            let host = host_of_url(&stripped);
            conn.execute(
                "UPDATE sites SET display_name = ?1 WHERE id = ?2",
                rusqlite::params![host, id],
            )
            .map_err(|e| Error::Store(format!("改写显示名失败: {e}")))?;
            changed += 1;
        }
        Ok(changed)
    }

    /// 还原一个 journal 的条目，供 `rollback_delivery` 重建 `Journal`。
    ///
    /// 用 `instr(...) = 1` 做前缀匹配而不是 `LIKE`：`LIKE` 的通配符会让
    /// 含 `%` / `_` 的 id 匹配到别的 journal。
    pub fn journal_entries(&self, journal_id: &str) -> Result<Vec<crate::inject::JournalEntry>> {
        use crate::inject::JournalEntry;
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT target_path, backup_path, before_sha256, after_sha256
                 FROM journals WHERE instr(id, ?1 || ':') = 1 ORDER BY rowid",
            )
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let rows = stmt
            .query_map(params![journal_id], |row| {
                Ok(JournalEntry {
                    path: std::path::PathBuf::from(row.get::<_, String>(0)?),
                    backup: row
                        .get::<_, Option<String>>(1)?
                        .map(std::path::PathBuf::from),
                    before_sha256: row.get(2)?,
                    after_sha256: row.get(3)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询变更记录失败: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取变更记录行失败: {e}")))
    }

    pub fn list_keys(&self) -> Result<Vec<KeyRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, site_id, remote_id, name, group_name, secret_ref, status, created_at
                 FROM keys ORDER BY id",
            )
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(KeyRow {
                    id: row.get(0)?,
                    site_id: row.get(1)?,
                    remote_id: row.get(2)?,
                    name: row.get(3)?,
                    group_name: row.get(4)?,
                    secret_ref: row.get(5)?,
                    status: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询密钥失败: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取密钥行失败: {e}")))
    }

    pub fn record_journal(&self, journal: &Journal) -> Result<()> {
        let conn = self.lock()?;
        for entry in &journal.entries {
            conn.execute(
                "INSERT OR REPLACE INTO journals
                 (id, ts, op, target_path, before_sha256, after_sha256, backup_path, status)
                 VALUES (?1, ?2, 'inject', ?3, ?4, ?5, ?6, 'applied')",
                params![
                    format!("{}:{}", journal.id, entry.path.display()),
                    now_secs(),
                    entry.path.display().to_string(),
                    entry.before_sha256,
                    entry.after_sha256,
                    entry.backup.as_ref().map(|p| p.display().to_string()),
                ],
            )
            .map_err(|e| Error::Store(format!("写入变更记录失败: {e}")))?;
        }
        Ok(())
    }

    pub fn journal_count(&self) -> Result<i64> {
        let conn = self.lock()?;
        conn.query_row("SELECT COUNT(*) FROM journals", [], |row| row.get(0))
            .map_err(|e| Error::Store(format!("统计变更记录失败: {e}")))
    }

    // ======================================================== 投递授权（M1-S2）

    /// 授予/刷新同意。同一 `(agent_id, channel, target_path)` 幂等：
    /// 重复同意只刷新 `granted_at` 并清空 `revoked_at`。
    pub fn grant_consent(
        &self,
        agent_id: &str,
        channel: &str,
        target_path: &str,
        fields: &[String],
    ) -> Result<()> {
        let fields_json = serde_json::to_string(fields)
            .map_err(|e| Error::Store(format!("序列化字段名失败: {e}")))?;
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO consents(agent_id, channel, target_path, fields, granted_at, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL)
             ON CONFLICT(agent_id, channel, target_path)
             DO UPDATE SET fields = excluded.fields,
                           granted_at = excluded.granted_at,
                           revoked_at = NULL",
            params![agent_id, channel, target_path, fields_json, now_secs()],
        )
        .map_err(|e| Error::Store(format!("写入投递授权失败: {e}")))?;
        Ok(())
    }

    /// 撤销同意。**不**回滚已写入的文件（回滚是独立动作）。
    pub fn revoke_consent(&self, agent_id: &str, channel: &str, target_path: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE consents SET revoked_at = ?4
             WHERE agent_id = ?1 AND channel = ?2 AND target_path = ?3 AND revoked_at IS NULL",
            params![agent_id, channel, target_path, now_secs()],
        )
        .map_err(|e| Error::Store(format!("撤销投递授权失败: {e}")))?;
        Ok(())
    }

    /// 查有效同意（`revoked_at IS NULL`）。返回 `granted_at`。
    pub fn active_consent(
        &self,
        agent_id: &str,
        channel: &str,
        target_path: &str,
    ) -> Result<Option<i64>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT granted_at FROM consents
                 WHERE agent_id = ?1 AND channel = ?2 AND target_path = ?3 AND revoked_at IS NULL",
            )
            .map_err(|e| Error::Store(format!("查询投递授权失败: {e}")))?;
        let mut rows = stmt
            .query_map(params![agent_id, channel, target_path], |row| row.get(0))
            .map_err(|e| Error::Store(format!("查询投递授权失败: {e}")))?;
        match rows.next() {
            Some(row) => {
                Ok(Some(row.map_err(|e| {
                    Error::Store(format!("读取投递授权失败: {e}"))
                })?))
            }
            None => Ok(None),
        }
    }

    /// 列出全部同意记录（含已撤销），供 UI 展示。
    pub fn list_consents(&self) -> Result<Vec<ConsentRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT agent_id, channel, target_path, fields, granted_at, revoked_at
                 FROM consents ORDER BY agent_id, channel, target_path",
            )
            .map_err(|e| Error::Store(format!("列举投递授权失败: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(ConsentRow {
                    agent_id: row.get(0)?,
                    channel: row.get(1)?,
                    target_path: row.get(2)?,
                    fields: row.get(3)?,
                    granted_at: row.get(4)?,
                    revoked_at: row.get(5)?,
                })
            })
            .map_err(|e| Error::Store(format!("列举投递授权失败: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取投递授权行失败: {e}")))
    }

    // ======================================================== 设置与绑定（M3-S1）

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT value FROM settings WHERE key = ?1")
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let mut rows = stmt
            .query_map(params![key], |row| row.get::<_, String>(0))
            .map_err(|e| Error::Store(format!("查询设置失败: {e}")))?;
        match rows.next() {
            Some(row) => Ok(Some(
                row.map_err(|e| Error::Store(format!("读取设置失败: {e}")))?,
            )),
            None => Ok(None),
        }
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO settings(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )
        .map_err(|e| Error::Store(format!("写入设置失败: {e}")))?;
        Ok(())
    }

    /// 每个投递目标只取**最近一次**投递的绑定，并 LEFT JOIN 出当时的 `after_sha256`。
    ///
    /// 用 LEFT JOIN（journals）而不是 INNER JOIN：老库里可能没有对应的 journal 行，
    /// 那种情况要能被识别成「无法判定」而不是从报告里消失。
    /// `keys` 那一跳反过来必须是 INNER JOIN：那一跳是「这行属于哪个站点」，
    /// 少了它这行就成了无法归组的孤儿数据（而 `keys` 的删除会级联带走 `bindings`，
    /// 所以 INNER JOIN 不会把正常行丢掉）。
    ///
    /// `journal_id` 过 `COALESCE`：列在 schema 里可空（`journal_id TEXT`），而 Rust 侧是
    /// `String`——一行 NULL 会让 `row.get::<String>` 报「Invalid column type Null」，
    /// 于是**整张表**读不出来（一次手工写的/迁移来的绑定行就能让漂移报告与轮换预览
    /// 一起变成 `Err`）。空串的语义与 NULL 在下面那个 `j.id = …` 拼接里完全一致
    /// （都匹配不到 journal 行 → `expected_sha256` 为 NULL → `Unknown`），
    /// 所以这里不需要改类型、也不会把「无法判定」说成「完好」。
    pub fn binding_drift_rows(&self) -> Result<Vec<BindingDriftRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT b.agent_id, b.target_path, COALESCE(b.journal_id, '') AS journal_id,
                        j.after_sha256, k.site_id, b.key_id
                 FROM bindings b
                 -- M8-S4：**已解绑的目标不再出现在漂移报告里**。文件已经不属于我们，
                 -- 继续报「配置已漂移」等于指挥用户去修一个我们不该管的文件。
                 JOIN (SELECT target_path, MAX(id) AS mid FROM bindings
                        WHERE unbound_at IS NULL GROUP BY target_path) latest
                   ON b.id = latest.mid
                 JOIN keys k ON k.id = b.key_id
                 LEFT JOIN journals j ON j.id = b.journal_id || ':' || b.target_path
                 ORDER BY b.target_path",
            )
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(BindingDriftRow {
                    agent_id: row.get(0)?,
                    target_path: row.get(1)?,
                    journal_id: row.get(2)?,
                    expected_sha256: row.get(3)?,
                    site_id: row.get(4)?,
                    key_id: row.get(5)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询投递绑定失败: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取投递绑定行失败: {e}")))
    }

    // ============================================================ 事件（M1-S3）

    /// 写入一条**已脱敏**的事件。
    ///
    /// 只接受 [`crate::observability::Event`]（其构造器已过 `scrub`），
    /// 从类型上挡住「直接塞原文」这条路径。
    pub fn insert_event(&self, event: &crate::observability::Event) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO events(ts, level, source, message, payload_redacted_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                event.ts,
                event.level.as_str(),
                event.source,
                event.message,
                event.payload,
            ],
        )
        .map_err(|e| Error::Store(format!("写入事件失败: {e}")))?;
        Ok(())
    }

    pub fn list_events(&self, limit: usize) -> Result<Vec<EventRow>> {
        let limit = i64::try_from(limit)
            .map_err(|_| Error::Store(format!("事件条数上限超出范围: {limit}")))?;
        self.query_events(limit)
    }

    /// 读**全部**事件，不限条数（事件表守护用）。
    ///
    /// 单独一个方法，而不是 `list_events(usize::MAX)`（复审 P2-13）：后者能「不限制」
    /// 纯粹是因为 `usize::MAX as i64 == -1`，而 SQLite 恰好把负 `LIMIT` 解释成不限制。
    /// 一旦有人给 `list_events` 加上限（`recent_events` 就有 `min(1000)`），
    /// 事件表守护会**静默只扫最近 N 条**，红线守护变成空跑。
    pub fn list_all_events(&self) -> Result<Vec<EventRow>> {
        // `LIMIT -1` 是 SQLite 明文的「不限制」，不是巧合
        self.query_events(-1)
    }

    fn query_events(&self, limit: i64) -> Result<Vec<EventRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, ts, level, source, message, payload_redacted_json
                 FROM events ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let rows = stmt
            .query_map(params![limit], |row| {
                Ok(EventRow {
                    id: row.get(0)?,
                    ts: row.get(1)?,
                    level: row.get(2)?,
                    source: row.get(3)?,
                    message: row.get(4)?,
                    payload: row.get(5)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询事件失败: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取事件行失败: {e}")))
    }

    /// 扫描整表，返回**疑似**含未脱敏凭证的行数（正常应为 0）。
    ///
    /// 用 `redact::scrub` 做判定，而不是硬编码正则：脱敏规则只有一处定义，
    /// 规则升级后本方法自动跟随。
    pub fn count_events_with_secrets(&self) -> Result<i64> {
        let events = self.list_all_events()?;
        let hits = events
            .iter()
            .filter(|row| {
                crate::redact::contains_secret(&row.message)
                    || row
                        .payload
                        .as_deref()
                        .is_some_and(crate::redact::contains_secret)
            })
            .count();
        Ok(hits as i64)
    }

    /// **一次性数据修复**：把 `events` 表里所有老行的 `message` / `payload` 按**当前**
    /// 脱敏规则改写一遍，返回改写的行数。
    ///
    /// 为什么需要（M8-S5B §7.2）：`observability::event_with_payload` 是后来才加上
    /// 结构化脱敏的（M5-S0），在那之前写进行表的老行可能带着密钥明文，而事件表会被
    /// 导出与审计 ⇒ 那些行是真实的泄漏面。
    ///
    /// **未接线（章程 §4 增量）**：本仓库唯一的调用点是
    /// `tests/events_redaction.rs::scrub_legacy_event_rows`（`#[ignore]`）——
    /// 生产代码里没有调用点，命令层也没有入口。去向：需要「在界面上修历史行」时
    /// 再加一条命令（跑前自动备份 `<db>` / `-wal` / `<db>-shm`）；在那之前它是
    /// **可复跑的一次性工具**，不是产品功能。
    ///
    /// **不进门禁、不自动执行**：它是数据修复，由人显式跑
    /// （`cargo test -p keyrelay-core --test events_redaction scrub_legacy_event_rows -- --ignored`）。
    /// 跑之前先备份数据库。
    ///
    /// 用真规则而不是 SQL：脱敏规则在 Rust 侧（`scrub_event_message` /
    /// `scrub_event_payload`），SQL 复刻必然漏（猜不出 authority 边界、也不知道哪些
    /// payload 键是敏感键）。
    ///
    /// 幂等：规则本身幂等，跑第二遍改写行数为 0。
    pub fn scrub_legacy_events(&self) -> Result<usize> {
        let rows = self.list_all_events()?;
        let mut repaired = 0usize;
        for row in &rows {
            let new_message = crate::redact::scrub_event_message(&row.message);
            let new_payload = crate::redact::scrub_event_payload(row.payload.as_deref());
            let message_changed = new_message != row.message;
            let payload_changed = new_payload.as_deref() != row.payload.as_deref();
            if !message_changed && !payload_changed {
                continue;
            }
            let conn = self.lock()?;
            conn.execute(
                "UPDATE events SET message = ?2, payload_redacted_json = ?3 WHERE id = ?1",
                params![row.id, new_message, new_payload],
            )
            .map_err(|e| Error::Store(format!("改写事件行 {} 失败: {e}", row.id)))?;
            repaired += 1;
        }
        Ok(repaired)
    }

    /// 更新站点的健康状态。取值由调用方约定：`"unknown"` / `"ok"` / `"needs_login"`。
    ///
    /// 站点不存在时**报错**而不是静默成功：静默成功会让调用方以为状态已落库，
    /// 而 `needs_login` 正是「用户看不到就永远修不好」的那类状态（B-61）。
    pub fn set_site_health(&self, site_id: i64, health: &str) -> Result<()> {
        let conn = self.lock()?;
        let affected = conn
            .execute(
                "UPDATE sites SET health = ?2 WHERE id = ?1",
                params![site_id, health],
            )
            .map_err(|e| Error::Store(format!("更新站点状态失败: {e}")))?;
        if affected == 0 {
            return Err(Error::Store(format!("站点不存在: {site_id}")));
        }
        Ok(())
    }

    /// 写 `keys.status`（M7-S4 / FR-2「回收站点侧 key」的落点）。
    ///
    /// 合法值 = [`legal_key_statuses`]（站点侧 `site::KeyStatus::as_str()` 四个值
    /// ∪ [`KEY_STATUS_REVOKED`]）。其余值 ⇒ [`Error::Store`]，且**不执行 UPDATE**：
    /// 先校验后写，调用方的入参 bug 不该在库里留下半成品。
    ///
    /// 行不存在时**报错**而不是静默成功（与 [`Store::set_site_health`] 同口径）：
    /// 静默成功会让调用方以为状态已落库，而界面会显示一个**不存在**的 key「已回收」。
    ///
    /// **不删行**：回收语义只改状态。删 `keys` 行会经 `ON DELETE CASCADE` 带走该 key 的
    /// 全部 `bindings`（漂移检测的输入），而 `journals` 没有 `key_id` 列——溯源链的起点就是
    /// `keys.id`，删了它再也答不上「这次投递是哪把 key 造成的」（M7-S4 spec §6.1）。
    pub fn set_key_status(&self, key_id: i64, status: &str) -> Result<()> {
        if !is_legal_key_status(status) {
            // 值本身也过 `scrub`：调用方可能把密钥误传进来，错误文案里不能出现它
            return Err(Error::Store(format!(
                "keys.status 非法值: {}（合法值: {}）",
                crate::redact::scrub(status),
                legal_key_statuses().join("/")
            )));
        }
        let conn = self.lock()?;
        let affected = conn
            .execute(
                "UPDATE keys SET status = ?2 WHERE id = ?1",
                params![key_id, status],
            )
            .map_err(|e| Error::Store(format!("更新密钥状态失败: {e}")))?;
        if affected == 0 {
            return Err(Error::Store(format!("密钥不存在: {key_id}")));
        }
        Ok(())
    }

    /// 读 `keys.status`。行不存在 ⇒ `Ok(None)`。
    ///
    /// 读是查询语义：「没有这行」是正常状态而不是错误——与写的口径**刻意不同**
    /// （写不存在的行是调用方的 bug，见 [`Store::set_key_status`]）。两条都有测试。
    pub fn key_status(&self, key_id: i64) -> Result<Option<String>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT status FROM keys WHERE id = ?1")
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let mut rows = stmt
            .query_map(params![key_id], |row| row.get::<_, String>(0))
            .map_err(|e| Error::Store(format!("查询密钥状态失败: {e}")))?;
        match rows.next() {
            Some(row) => {
                Ok(Some(row.map_err(|e| {
                    Error::Store(format!("读取密钥状态失败: {e}"))
                })?))
            }
            None => Ok(None),
        }
    }

    /// 登记一次导出（同一路径重复导出则覆盖）。**只记路径与统计，不记内容。**
    pub fn record_export(&self, path: &Path, encrypted: bool, bytes: usize) -> Result<()> {
        let bytes = i64::try_from(bytes)
            .map_err(|_| Error::Store(format!("导出字节数超出范围: {bytes}")))?;
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO exports(path, encrypted, bytes, exported_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(path) DO UPDATE SET
               encrypted   = excluded.encrypted,
               bytes       = excluded.bytes,
               exported_at = excluded.exported_at",
            params![
                path.to_string_lossy(),
                i64::from(encrypted),
                bytes,
                now_secs(),
            ],
        )
        .map_err(|e| Error::Store(format!("登记导出失败: {e}")))?;
        Ok(())
    }

    /// 列出已知导出物，最新的在前。同 `exported_at` 时按路径升序，保证顺序确定。
    pub fn list_exports(&self) -> Result<Vec<ExportRecord>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT path, encrypted, bytes, exported_at FROM exports
                 ORDER BY exported_at DESC, path ASC",
            )
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(ExportRecord {
                    path: row.get(0)?,
                    encrypted: row.get::<_, i64>(1)? != 0,
                    bytes: row.get(2)?,
                    exported_at: row.get(3)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询导出记录失败: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取导出行失败: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inject::JournalEntry;
    use std::path::PathBuf;

    #[test]
    fn migrate_adds_new_tables_to_an_existing_database() {
        // M1-S4 实测回归：往 DDL 里新增表后，**已经存在的库**也必须补建。
        // 旧实现只在 `user_version < SCHEMA_VERSION` 时跑 DDL，
        // 于是「加了 consents 却不改版本号」会让旧库永远缺这张表。
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("keyrelay.db");

        {
            let store = Store::open(&path).expect("首次建库");
            assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        }

        // 模拟「旧版库」：把新表与新索引删掉，版本号保持不变
        {
            let conn = rusqlite::Connection::open(&path).expect("直连库");
            conn.execute_batch("DROP TABLE consents; DROP INDEX idx_events_ts;")
                .expect("删表");
        }

        let store = Store::open(&path).expect("重新打开");
        let conn = rusqlite::Connection::open(&path).expect("直连库");
        let consents: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='consents'",
                [],
                |row| row.get(0),
            )
            .expect("查表");
        let index: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_events_ts'",
                [],
                |row| row.get(0),
            )
            .expect("查索引");
        assert_eq!(consents, 1, "已存在的库必须补建 consents 表");
        assert_eq!(index, 1, "已存在的库必须补建 idx_events_ts 索引");

        // 补建后功能可用（不是只有表壳）
        store
            .grant_consent("codex", "codex-auth-json", "/tmp/auth.json", &["k".into()])
            .expect("写入同意");
        assert_eq!(store.list_consents().unwrap().len(), 1);
    }

    #[test]
    fn migrate_is_idempotent() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        store.migrate().unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn exports_table_is_added_to_an_existing_database() {
        // 与 `migrate_adds_new_tables_to_an_existing_database` 同一条回归：
        // M5-S1 新增了 `exports` 表并把 SCHEMA_VERSION 提到 2，
        // 老库（版本号 1、没有 exports）打开后必须补建，否则 `record_export` 直接 no such table。
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("keyrelay.db");

        {
            let conn = rusqlite::Connection::open(&path).expect("直连库");
            conn.execute_batch(
                "CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);",
            )
            .expect("造一个最小旧库");
            conn.pragma_update(None, "user_version", 1)
                .expect("写成旧版本号");
        }

        let store = Store::open(&path).expect("打开旧库");
        assert_eq!(
            store.schema_version().unwrap(),
            SCHEMA_VERSION,
            "版本号必须被抬到当前值"
        );
        store
            .record_export(Path::new("/tmp/old-db-export.json"), false, 12)
            .expect("旧库补建 exports 表后必须能登记");
        assert_eq!(store.list_exports().unwrap().len(), 1);
    }

    #[test]
    fn record_export_upserts_by_path_and_lists_newest_first() {
        let store = Store::open_in_memory().unwrap();
        store
            .record_export(Path::new("/tmp/a.json"), false, 10)
            .unwrap();
        store
            .record_export(Path::new("/tmp/b.krbackup"), false, 20)
            .unwrap();
        // 同一路径再导出一次：覆盖，不新增行
        store
            .record_export(Path::new("/tmp/a.json"), true, 33)
            .unwrap();

        let rows = store.list_exports().unwrap();
        assert_eq!(rows.len(), 2, "同一路径必须覆盖而不是追加");
        // 覆盖后的 a.json 更新，排最前
        assert_eq!(rows[0].path, "/tmp/a.json");
        assert!(rows[0].encrypted);
        assert_eq!(rows[0].bytes, 33);
        assert_eq!(rows[1].path, "/tmp/b.krbackup");
        assert!(!rows[1].encrypted);
    }

    #[test]
    fn set_site_health_persists_and_rejects_an_unknown_site() {
        let store = Store::open_in_memory().unwrap();
        let site = store
            .upsert_site("newapi", "https://h.example.com", "H")
            .unwrap();
        assert_eq!(store.get_site(site).unwrap().unwrap().health, "unknown");

        store.set_site_health(site, "needs_login").unwrap();
        assert_eq!(store.get_site(site).unwrap().unwrap().health, "needs_login");

        let err = store.set_site_health(9999, "ok").unwrap_err();
        assert!(
            err.to_string().contains("站点不存在"),
            "未知站点必须报错而不是静默成功：{}",
            err
        );
    }

    #[test]
    fn upsert_site_dedupes_by_base_url() {
        let store = Store::open_in_memory().unwrap();
        let a = store
            .upsert_site("newapi", "https://a.example.com", "A")
            .unwrap();
        let b = store
            .upsert_site("newapi", "https://a.example.com", "A 改名")
            .unwrap();
        assert_eq!(a, b);
        let sites = store.list_sites().unwrap();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].display_name, "A 改名");
    }

    #[test]
    fn keys_cascade_when_site_deleted() {
        let store = Store::open_in_memory().unwrap();
        let site = store
            .upsert_site("newapi", "https://b.example.com", "B")
            .unwrap();
        store
            .insert_key(site, "codex/daily", "kr/key/1/secret", Some("12"), None)
            .unwrap();
        assert_eq!(store.list_keys().unwrap().len(), 1);

        store.delete_site(site).unwrap();
        assert!(store.list_keys().unwrap().is_empty());
    }

    #[test]
    fn refuses_plaintext_secret_ref() {
        let store = Store::open_in_memory().unwrap();
        let site = store
            .upsert_site("newapi", "https://c.example.com", "C")
            .unwrap();
        let err = store
            .insert_key(site, "bad", "sk-abcdefgh12345678", None, None)
            .unwrap_err();
        assert!(matches!(err, Error::Store(_)));
    }

    #[test]
    fn refuses_non_keychain_shaped_refs() {
        let store = Store::open_in_memory().unwrap();
        let site = store
            .upsert_site("newapi", "https://d.example.com", "D")
            .unwrap();

        // 32 位 hex 明文（复审 P2-4 探针形状）：黑名单时代会被放过
        assert!(matches!(
            store.insert_key(site, "hex", "9f3c1a7b2e5d8046c1b9f4a7d2e83b15", None, None),
            Err(Error::Store(_))
        ));
        // 段数不对的引用
        assert!(matches!(
            store.insert_key(site, "short", "kr/key/1", None, None),
            Err(Error::Store(_))
        ));
        // 合法引用
        assert!(store
            .insert_key(site, "ok", "kr/key/9/secret", None, None)
            .is_ok());
    }

    #[test]
    fn records_journal_entries() {
        let store = Store::open_in_memory().unwrap();
        let journal = Journal {
            id: "j1".into(),
            entries: vec![JournalEntry {
                path: PathBuf::from("/tmp/config.toml"),
                backup: Some(PathBuf::from("/tmp/backups/0-config.toml")),
                before_sha256: Some("aa".into()),
                after_sha256: "bb".into(),
            }],
        };
        store.record_journal(&journal).unwrap();
        assert_eq!(store.journal_count().unwrap(), 1);
    }

    /// 合法值集合必须是「站点侧词表 ∪ 本地词表」，且**从枚举派生**（不是抄字面量）。
    ///
    /// 站点侧新增变体时，`tests/key_lifecycle.rs` 里那条穷举 `match` 会先编译失败；
    /// 这里再钉住集合大小与派生关系，两道一起挡。
    #[test]
    fn legal_key_statuses_are_derived_from_the_site_enum_plus_the_local_revoked() {
        let legal = legal_key_statuses();
        for status in [
            KeyStatus::Enabled,
            KeyStatus::Disabled,
            KeyStatus::Exhausted,
            KeyStatus::Unknown,
        ] {
            assert!(
                legal.contains(&status.as_str()),
                "站点侧 {} 必须是合法值",
                status.as_str()
            );
        }
        assert!(
            legal.contains(&KEY_STATUS_REVOKED),
            "本地 revoked 必须是合法值"
        );
        assert_eq!(
            legal.len(),
            5,
            "集合大小变了要回来确认（4 站点侧 + 1 本地）"
        );

        assert!(!is_legal_key_status("REVOKED"), "大小写敏感");
        assert!(!is_legal_key_status(""));
        assert!(!is_legal_key_status(" revoked"));
    }
}
