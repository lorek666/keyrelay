//! 本地元数据存储（SQLite / WAL）。
//!
//! 红线：本模块**不存密钥**。`keys.secret_ref` 只是钥匙串引用（见 `vault::secret_ref`）。

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};

use crate::error::{Error, Result};
use crate::inject::Journal;

const SCHEMA_VERSION: i64 = 1;

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
  journal_id TEXT
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingDriftRow {
    pub agent_id: String,
    pub target_path: String,
    pub journal_id: String,
    /// 投递时该文件的 sha256；老库可能没有
    pub expected_sha256: Option<String>,
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

pub struct Store {
    conn: Mutex<Connection>,
    /// 文件库的路径；内存库为 `None`。审计要用它定位 `*.db` / `-wal` / `-shm`。
    path: Option<std::path::PathBuf>,
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
    pub fn insert_key(
        &self,
        site_id: i64,
        name: &str,
        secret_ref: &str,
        remote_id: Option<&str>,
    ) -> Result<i64> {
        if !is_valid_secret_ref(secret_ref) {
            return Err(Error::Store(format!(
                "secret_ref 必须是钥匙串引用（kr/<scope>/<id>/<field>），拒绝写入疑似明文: {}",
                crate::redact::scrub(secret_ref)
            )));
        }
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO keys(site_id, remote_id, name, secret_ref, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![site_id, remote_id, name, secret_ref, now_secs()],
        )
        .map_err(|e| Error::Store(format!("写入密钥记录失败: {e}")))?;
        Ok(conn.last_insert_rowid())
    }

    /// 按 id 取单条密钥记录（投递时用它拿 `secret_ref`）。
    pub fn get_key(&self, id: i64) -> Result<Option<KeyRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, site_id, remote_id, name, group_name, secret_ref, status
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
                "SELECT id, site_id, remote_id, name, group_name, secret_ref, status
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
    /// 用 LEFT JOIN 而不是 INNER JOIN：老库里可能没有对应的 journal 行，
    /// 那种情况要能被识别成「无法判定」而不是从报告里消失。
    pub fn binding_drift_rows(&self) -> Result<Vec<BindingDriftRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT b.agent_id, b.target_path, b.journal_id, j.after_sha256
                 FROM bindings b
                 JOIN (SELECT target_path, MAX(id) AS mid FROM bindings GROUP BY target_path) latest
                   ON b.id = latest.mid
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
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, ts, level, source, message, payload_redacted_json
                 FROM events ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let rows = stmt
            .query_map(params![limit as i64], |row| {
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
        let events = self.list_events(usize::MAX)?;
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
            .insert_key(site, "codex/daily", "kr/key/1/secret", Some("12"))
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
            .insert_key(site, "bad", "sk-abcdefgh12345678", None)
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
            store.insert_key(site, "hex", "9f3c1a7b2e5d8046c1b9f4a7d2e83b15", None),
            Err(Error::Store(_))
        ));
        // 段数不对的引用
        assert!(matches!(
            store.insert_key(site, "short", "kr/key/1", None),
            Err(Error::Store(_))
        ));
        // 合法引用
        assert!(store
            .insert_key(site, "ok", "kr/key/9/secret", None)
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
}
