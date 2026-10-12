//! 钥匙串抽象：密钥只进系统钥匙串，SQLite 只存引用。
//!
//! M0 只提供内存实现用于测试；macOS Keychain / Windows Credential Manager 实现见 M1-S2。

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::error::{Error, Result};

/// 引用命名规则：`kr/<scope>/<id>/<field>`
///
/// 例：`kr/site/3/password`、`kr/key/17/secret`、`kr/account/5/session`
pub fn secret_ref(scope: &str, id: impl std::fmt::Display, field: &str) -> String {
    format!("kr/{scope}/{id}/{field}")
}

pub trait Vault: Send + Sync {
    fn put(&self, key: &str, secret: &str) -> Result<()>;
    fn get(&self, key: &str) -> Result<Option<String>>;
    fn delete(&self, key: &str) -> Result<()>;
    fn list(&self) -> Result<Vec<String>>;
}

/// 内存实现（测试用）。进程退出即丢失，绝不用于生产。
#[derive(Default)]
pub struct MemoryVault {
    inner: Mutex<BTreeMap<String, String>>,
}

impl MemoryVault {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, String>>> {
        self.inner
            .lock()
            .map_err(|_| Error::Vault("内存钥匙串锁已中毒".into()))
    }
}

impl Vault for MemoryVault {
    fn put(&self, key: &str, secret: &str) -> Result<()> {
        if key.is_empty() {
            return Err(Error::Vault("钥匙串引用不能为空".into()));
        }
        self.lock()?.insert(key.to_string(), secret.to_string());
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        Ok(self.lock()?.get(key).cloned())
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.lock()?.remove(key);
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>> {
        Ok(self.lock()?.keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_put_get_delete_list() {
        let v = MemoryVault::new();
        let r = secret_ref("key", 17, "secret");
        assert_eq!(r, "kr/key/17/secret");

        v.put(&r, "sk-should-not-be-logged").unwrap();
        assert_eq!(
            v.get(&r).unwrap().as_deref(),
            Some("sk-should-not-be-logged")
        );
        assert_eq!(v.list().unwrap(), vec![r.clone()]);

        v.delete(&r).unwrap();
        assert_eq!(v.get(&r).unwrap(), None);
        assert!(v.list().unwrap().is_empty());
    }

    #[test]
    fn rejects_empty_ref() {
        let v = MemoryVault::new();
        assert!(matches!(v.put("", "x"), Err(Error::Vault(_))));
    }
}
