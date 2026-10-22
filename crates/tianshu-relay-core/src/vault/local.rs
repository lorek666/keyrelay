//! 本地加密保险库：`vault.db` 里只有密文，DEK 在 `vault.key`（见 `keyfile.rs`）。
//!
//! 为什么独立于 `tianshu-relay.db`：
//! - `store` 模块的红线是「本模块不存密钥」，独立文件让这条红线保持字面成立；
//! - `LocalVault` 与 `Store` 各持一个 SQLite 连接，分库避免争同一把写锁。
//!
//! 引用（`kr/<scope>/<id>/<field>`）与今天的 `keys.secret_ref` 完全同构，
//! 所以换后端**不改任何调用方**，也不改 `keys` / `accounts` 两张表。

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use zeroize::Zeroizing;

use super::keyfile::{self, MachineId, SystemMachineId, VaultKey};
use super::{is_valid_secret_ref, seal, Vault};
use crate::error::{Error, Result};

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS vault_meta(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vault_secrets(
  ref        TEXT PRIMARY KEY,
  seal       TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
"#;

const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const KEY_LEN: usize = 32;

pub struct LocalVault {
    conn: Mutex<Connection>,
    dek: Zeroizing<[u8; KEY_LEN]>,
    device_bound: bool,
}

impl LocalVault {
    /// 生产入口：`~/.tianshu-relay/vault.db` + `~/.tianshu-relay/vault.key`。
    pub fn open(db_path: &Path, key_path: &Path) -> Result<Self> {
        Self::open_with_machine(db_path, key_path, &SystemMachineId)
    }

    /// 允许注入设备标识来源（测试「换一台机器解不开」）。
    pub fn open_with_machine(
        db_path: &Path,
        key_path: &Path,
        machine: &dyn MachineId,
    ) -> Result<Self> {
        // P1-1（复审）：密钥文件不在、库里却有密文 —— 这是「密钥丢了」，不是「首次运行」。
        // 必须在这里拦住：否则会生成一把新 DEK，把旧数据锁死，而且启动一切正常。
        if !key_path.exists() && db_has_secrets(db_path)? {
            return Err(Error::Vault(format!(
                "密钥文件 {} 不存在，但保险库里已有密文；拒绝生成新密钥（旧数据将永久解不开）。\
                 请从备份恢复 vault.key，或删掉 vault.db 后重新录入密钥。",
                key_path.display()
            )));
        }
        let key = keyfile::load_or_create(key_path, machine)?;
        Self::open_with_key(db_path, key)
    }

    /// 测试用：临时目录 + 不绑定设备，绝不碰用户 `~/.tianshu-relay`。
    pub fn open_temp(dir: &Path) -> Result<Self> {
        let mut dek = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::fill(dek.as_mut())
            .map_err(|e| Error::Vault(format!("生成测试数据密钥失败: {e}")))?;
        Self::open_with_key(
            &dir.join("vault.db"),
            VaultKey {
                dek,
                device_bound: false,
            },
        )
    }

    fn open_with_key(db_path: &Path, key: VaultKey) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Vault(format!("创建保险库目录失败: {e}")))?;
        }
        let conn =
            Connection::open(db_path).map_err(|e| Error::Vault(format!("打开保险库失败: {e}")))?;
        conn.busy_timeout(BUSY_TIMEOUT)
            .map_err(|e| Error::Vault(format!("设置忙等超时失败: {e}")))?;
        // WAL 与主库同口径；内存库/只读介质上失败不该阻止使用，退化为默认日志模式即可。
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        conn.execute_batch(DDL)
            .map_err(|e| Error::Vault(format!("建保险库表失败: {e}")))?;
        let vault = Self {
            conn: Mutex::new(conn),
            dek: key.dek,
            device_bound: key.device_bound,
        };
        // P2-3（复审）：把「是否设备绑定」写进元信息，诊断时不用去翻密钥文件。
        vault.meta_set(
            "device_bound",
            if vault.device_bound { "true" } else { "false" },
        )?;
        Ok(vault)
    }

    pub fn is_device_bound(&self) -> bool {
        self.device_bound
    }

    pub fn count(&self) -> Result<usize> {
        let conn = self.lock()?;
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM vault_secrets", [], |row| row.get(0))
            .map_err(|e| Error::Vault(format!("统计密文条数失败: {e}")))?;
        Ok(n as usize)
    }

    pub fn meta_get(&self, key: &str) -> Result<Option<String>> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT value FROM vault_meta WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| Error::Vault(format!("读保险库元信息失败: {e}")))
    }

    pub fn meta_set(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO vault_meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )
        .map_err(|e| Error::Vault(format!("写保险库元信息失败: {e}")))?;
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| Error::Vault("保险库连接锁已中毒".into()))
    }
}

impl Vault for LocalVault {
    fn backend_name(&self) -> &'static str {
        "local-sqlite"
    }

    /// 不只 `SELECT 1`：**试解一行真实密文**，这样「密钥文件不属于这个库」
    /// （例如恢复了旧的 vault.key 备份）会在启动时就暴露成 `VaultUnavailable`，
    /// 而不是等到用户点开某把密钥才报「密文校验失败」（复审 P2-5）。
    fn probe(&self) -> Result<()> {
        let first: Option<(String, String)> = {
            let conn = self.lock()?;
            conn.query_row("SELECT ref, seal FROM vault_secrets LIMIT 1", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()
            .map_err(|e| Error::VaultUnavailable(format!("保险库不可读: {e}")))?
        };
        if let Some((reference, sealed)) = first {
            seal::unseal(&self.dek, &reference, &sealed)
                .map_err(|_| Error::VaultUnavailable("密钥文件与保险库不匹配".into()))?;
        }
        Ok(())
    }

    fn put(&self, key: &str, secret: &str) -> Result<()> {
        if !is_valid_secret_ref(key) {
            return Err(Error::Vault(
                "密钥引用必须形如 kr/<scope>/<id>/<field>".into(),
            ));
        }
        let sealed = seal::seal(&self.dek, key, secret)?;
        let now = now_secs();
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO vault_secrets(ref, seal, created_at, updated_at) VALUES(?1, ?2, ?3, ?3)
             ON CONFLICT(ref) DO UPDATE SET seal = excluded.seal, updated_at = excluded.updated_at",
            params![key, sealed, now],
        )
        .map_err(|e| Error::Vault(format!("写密文失败: {e}")))?;
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        if !is_valid_secret_ref(key) {
            return Err(Error::Vault(
                "密钥引用必须形如 kr/<scope>/<id>/<field>".into(),
            ));
        }
        let sealed: Option<String> = {
            let conn = self.lock()?;
            conn.query_row(
                "SELECT seal FROM vault_secrets WHERE ref = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| Error::Vault(format!("读密文失败: {e}")))?
        };
        match sealed {
            None => Ok(None),
            Some(text) => Ok(Some(seal::unseal(&self.dek, key, &text)?)),
        }
    }

    fn has(&self, key: &str) -> Result<bool> {
        if !is_valid_secret_ref(key) {
            return Err(Error::Vault(
                "密钥引用必须形如 kr/<scope>/<id>/<field>".into(),
            ));
        }
        let conn = self.lock()?;
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM vault_secrets WHERE ref = ?1",
                params![key],
                |row| row.get(0),
            )
            .map_err(|e| Error::Vault(format!("查询密文失败: {e}")))?;
        Ok(n > 0)
    }

    fn delete(&self, key: &str) -> Result<()> {
        if !is_valid_secret_ref(key) {
            return Err(Error::Vault(
                "密钥引用必须形如 kr/<scope>/<id>/<field>".into(),
            ));
        }
        let conn = self.lock()?;
        conn.execute("DELETE FROM vault_secrets WHERE ref = ?1", params![key])
            .map_err(|e| Error::Vault(format!("删除密文失败: {e}")))?;
        Ok(())
    }
}

/// 库文件存在且 `vault_secrets` 已有行（只读打开，绝不创建文件）。
fn db_has_secrets(db_path: &Path) -> Result<bool> {
    if !db_path.exists() {
        return Ok(false);
    }
    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| Error::Vault(format!("只读打开保险库失败: {e}")))?;
    let table_exists: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vault_secrets'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| Error::Vault(format!("检查保险库表失败: {e}")))?;
    if table_exists.is_none() {
        return Ok(false);
    }
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM vault_secrets", [], |row| row.get(0))
        .map_err(|e| Error::Vault(format!("统计保险库密文失败: {e}")))?;
    Ok(n > 0)
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 新的保险库路径约定（供壳层构造）。
pub fn default_paths(home: &Path) -> (PathBuf, PathBuf) {
    default_paths_in(&home.join(crate::rebrand::APP_DIR_NAME))
}

/// 用**已解析的数据目录**构造保险库路径（M35-S1 接线）。
///
/// 与 [`default_paths`] 的区别：后者假定「home + 固定目录名」，而迁移之后实际目录
/// 可能仍是旧目录（迁移失败回退），所以调用方必须传**本次真正使用的**目录。
pub fn default_paths_in(data_dir: &Path) -> (PathBuf, PathBuf) {
    (data_dir.join("vault.db"), data_dir.join("vault.key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("建临时目录")
    }

    #[test]
    fn reopening_the_same_db_keeps_rows() {
        let dir = temp_dir();
        {
            let vault = LocalVault::open_temp(dir.path()).unwrap();
            vault.put("kr/key/1/secret", "sk-test-value").unwrap();
            assert_eq!(
                vault.get("kr/key/1/secret").unwrap().as_deref(),
                Some("sk-test-value")
            );
            assert!(vault.has("kr/key/1/secret").unwrap());
            assert_eq!(vault.count().unwrap(), 1);
            assert_eq!(vault.backend_name(), "local-sqlite");
        }
        // `open_temp` 每次换 DEK，所以这里只验库表还在；真正的「同一 key 文件重开可读」
        // 由 `tests/vault_local.rs::secrets_survive_a_restart_with_the_same_key_file` 覆盖。
        let vault = LocalVault::open_temp(dir.path()).unwrap();
        assert_eq!(vault.count().unwrap(), 1);
    }

    #[test]
    fn delete_is_idempotent_and_get_returns_none() {
        let dir = temp_dir();
        let vault = LocalVault::open_temp(dir.path()).unwrap();
        vault.put("kr/key/2/secret", "v").unwrap();
        vault.delete("kr/key/2/secret").unwrap();
        vault.delete("kr/key/2/secret").unwrap();
        assert_eq!(vault.get("kr/key/2/secret").unwrap(), None);
    }

    #[test]
    fn invalid_reference_is_rejected() {
        let dir = temp_dir();
        let vault = LocalVault::open_temp(dir.path()).unwrap();
        assert!(vault.put("not-a-ref", "v").is_err());
        assert!(vault.get("kr/key/1").is_err());
    }

    #[test]
    fn meta_roundtrip() {
        let dir = temp_dir();
        let vault = LocalVault::open_temp(dir.path()).unwrap();
        assert_eq!(vault.meta_get("migrated_from_keychain").unwrap(), None);
        vault.meta_set("migrated_from_keychain", "1").unwrap();
        assert_eq!(
            vault.meta_get("migrated_from_keychain").unwrap().as_deref(),
            Some("1")
        );
    }
}
