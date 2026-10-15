//! 从 argv 装配 `KeyRelayService` 的纯函数。
//!
//! CLI 是 `keyrelay-core` 的外部消费者：只用 `Store::open` / `MemoryVault` /
//! `KeychainVault` / `ServiceConfig` / `MockTransport` 的既有 `pub` API。
//!
//! 为什么用 `MockTransport`（而非 `reqwest`）：`apply_delivery` / `rollback_delivery`
//! / `grant_consent` 全是纯本地操作，零网络。引入 `reqwest` 会让 CLI 背上 GUI 才
//! 需要的网络栈。`MockTransport::new(vec![])` 永不会被调到（差异登记 D-1）。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::transport::MockTransport;
use keyrelay_core::store::Store;
use keyrelay_core::vault::{KeychainVault, MemoryVault, Vault};

/// vault 后端选择。`--smoke` 路径强制 `Memory`（真密钥不进真钥匙串）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum VaultChoice {
    Keychain,
    Memory,
}

/// 默认 home：`KEYRELAY_HOME` ?? `HOME`。两者都缺时返回空（调用方自行决定如何处置）。
pub fn default_home() -> Option<PathBuf> {
    std::env::var_os("KEYRELAY_HOME")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
}

/// 默认 store 路径：`<home>/.keyrelay/keyrelay.db`。
pub fn default_store(home: &Path) -> PathBuf {
    home.join(".keyrelay").join("keyrelay.db")
}

/// 默认备份目录：`<home>/.keyrelay/backups`（与 `ServiceConfig::production` 同口径）。
pub fn default_backup_dir(home: &Path) -> PathBuf {
    home.join(".keyrelay").join("backups")
}

/// 构造一个绑定了给定路径与 vault 后端的 service。
///
/// `MockTransport::new(vec![])`：apply/rollback 不发任何请求，空响应表足够。
pub fn build_service(
    home: &Path,
    store_path: &Path,
    backup_dir: &Path,
    vault: VaultChoice,
) -> Result<KeyRelayService<MockTransport>, BuildError> {
    let store = Store::open(store_path).map_err(BuildError::OpenStore)?;
    let vault: Arc<dyn Vault> = match vault {
        VaultChoice::Keychain => Arc::new(KeychainVault::new()),
        VaultChoice::Memory => Arc::new(MemoryVault::new()),
    };
    Ok(KeyRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault,
            home: home.to_path_buf(),
            backup_dir: backup_dir.to_path_buf(),
        },
    ))
}

#[derive(Debug)]
pub enum BuildError {
    OpenStore(keyrelay_core::Error),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::OpenStore(e) => write!(f, "打开本地库失败: {e}"),
        }
    }
}

impl std::error::Error for BuildError {}
