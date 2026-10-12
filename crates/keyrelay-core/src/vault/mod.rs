//! 钥匙串抽象：密钥只进系统钥匙串，SQLite 只存引用。
//!
//! 设计约束（ADR-0002）：
//! - `Vault` 是**哑存储**：只有 `put` / `get` / `delete`。系统钥匙串没有稳定的「按 service 枚举」接口，
//!   因此**没有** `list()`；索引的唯一来源是 SQLite 的 `secret_ref` 列。
//! - `probe()` 让调用方在启动时判定后端可用性；不可用必须明确失败（`VaultUnavailable`），
//!   发布路径**绝不**回退到 [`MemoryVault`]。

pub mod keychain;

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::error::{Error, Result};

pub use keychain::KeychainVault;

/// 引用命名规则：`kr/<scope>/<id>/<field>`
///
/// 例：`kr/site/3/password`、`kr/key/17/secret`、`kr/account/5/session`
pub fn secret_ref(scope: &str, id: impl std::fmt::Display, field: &str) -> String {
    format!("kr/{scope}/{id}/{field}")
}

/// 引用合法性：4 段、首段为 `kr`、其余段非空。与 `store::is_valid_secret_ref` 同规则。
pub fn is_valid_secret_ref(value: &str) -> bool {
    let parts: Vec<&str> = value.split('/').collect();
    parts.len() == 4 && parts[0] == "kr" && parts[1..].iter().all(|p| !p.is_empty())
}

pub trait Vault: Send + Sync {
    /// 后端标识，用于诊断与「拒绝静默降级」断言。
    /// 取值：`"macos-keychain"` / `"windows-credential-manager"` / `"memory"` / `"unsupported"`
    fn backend_name(&self) -> &'static str;

    /// 可用性探测。发布路径启动时调用一次；不可用即拒绝提供钥匙串能力。
    fn probe(&self) -> Result<()>;

    fn put(&self, key: &str, secret: &str) -> Result<()>;

    /// 不存在返回 `Ok(None)`（**不是**错误）。
    fn get(&self, key: &str) -> Result<Option<String>>;

    /// 幂等：不存在也返回 `Ok(())`。
    fn delete(&self, key: &str) -> Result<()>;
}

/// 内存实现（**仅测试用**）。进程退出即丢失；发布路径装配它即为缺陷。
#[derive(Default)]
pub struct MemoryVault {
    inner: Mutex<BTreeMap<String, String>>,
}

impl MemoryVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// 仅供测试的枚举接口。**故意不放进 `Vault` trait**：系统钥匙串无法实现它（ADR-0002）。
    pub fn list(&self) -> Result<Vec<String>> {
        Ok(self.lock()?.keys().cloned().collect())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, String>>> {
        self.inner
            .lock()
            .map_err(|_| Error::Vault("内存钥匙串锁已中毒".into()))
    }

    fn check_ref(key: &str) -> Result<()> {
        if !is_valid_secret_ref(key) {
            return Err(Error::Vault(format!(
                "钥匙串引用必须形如 kr/<scope>/<id>/<field>（长度 {}）",
                key.len()
            )));
        }
        Ok(())
    }
}

impl Vault for MemoryVault {
    fn backend_name(&self) -> &'static str {
        "memory"
    }

    fn probe(&self) -> Result<()> {
        Ok(())
    }

    fn put(&self, key: &str, secret: &str) -> Result<()> {
        Self::check_ref(key)?;
        self.lock()?.insert(key.to_string(), secret.to_string());
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        Self::check_ref(key)?;
        Ok(self.lock()?.get(key).cloned())
    }

    fn delete(&self, key: &str) -> Result<()> {
        Self::check_ref(key)?;
        self.lock()?.remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_put_get_delete() {
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
    fn delete_is_idempotent_and_missing_returns_none() {
        let v = MemoryVault::new();
        let r = secret_ref("key", 1, "secret");
        assert_eq!(v.get(&r).unwrap(), None);
        assert!(v.delete(&r).is_ok());
        assert!(v.delete(&r).is_ok());
    }

    #[test]
    fn backend_name_and_probe() {
        let v = MemoryVault::new();
        assert_eq!(v.backend_name(), "memory");
        assert!(v.probe().is_ok());
    }

    #[test]
    fn rejects_invalid_ref() {
        let v = MemoryVault::new();
        for bad in [
            "",
            "kr/key/1",
            "kr/key/1/secret/extra",
            "key/1/secret",
            "kr//1/secret",
        ] {
            assert!(matches!(v.put(bad, "x"), Err(Error::Vault(_))), "{bad}");
            assert!(matches!(v.get(bad), Err(Error::Vault(_))), "{bad}");
            assert!(matches!(v.delete(bad), Err(Error::Vault(_))), "{bad}");
        }
    }

    #[test]
    fn ref_validation_does_not_echo_input() {
        let v = MemoryVault::new();
        let err = v.put("sk-plaintext-secret-value", "x").unwrap_err();
        assert!(!err.to_string().contains("sk-plaintext"));
    }
}
