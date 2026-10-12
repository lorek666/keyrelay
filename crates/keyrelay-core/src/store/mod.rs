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
"#;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Store(format!("创建数据目录失败: {e}")))?;
        }
        let conn =
            Connection::open(path).map_err(|e| Error::Store(format!("打开数据库失败: {e}")))?;
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        Self::from_conn(conn)
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
        if version < SCHEMA_VERSION {
            conn.execute_batch(DDL)
                .map_err(|e| Error::Store(format!("建表失败: {e}")))?;
            conn.pragma_update(None, "user_version", SCHEMA_VERSION)
                .map_err(|e| Error::Store(format!("写入 schema 版本失败: {e}")))?;
        }
        Ok(())
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

    pub fn delete_site(&self, id: i64) -> Result<()> {
        let conn = self.lock()?;
        conn.execute("DELETE FROM sites WHERE id = ?1", params![id])
            .map_err(|e| Error::Store(format!("删除站点失败: {e}")))?;
        Ok(())
    }

    /// `secret_ref` 必须是钥匙串引用，禁止传明文
    pub fn insert_key(
        &self,
        site_id: i64,
        name: &str,
        secret_ref: &str,
        remote_id: Option<&str>,
    ) -> Result<i64> {
        if secret_ref.starts_with("sk-") || secret_ref.starts_with("nap-") {
            return Err(Error::Store(
                "拒绝把明文密钥写入数据库，请传钥匙串引用".into(),
            ));
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inject::JournalEntry;
    use std::path::PathBuf;

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
