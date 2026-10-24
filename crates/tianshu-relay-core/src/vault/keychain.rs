//! 系统钥匙串实现（macOS Keychain / Windows Credential Manager），基于 `keyring` 4.x。
//!
//! 选型与实测见 `docs/ADR/0002`。要点：
//! - 引用（`kr/<scope>/<id>/<field>`）直接作为钥匙串条目的 account/username，service 固定为 `Tianshu Relay`。
//! - **禁止降级**：后端不可用时返回 [`Error::VaultUnavailable`]，绝不退回内存实现。
//! - 错误文案一律自建：`keyring::Error` 的部分变体（`BadEncoding`）**携带取回的密钥字节**，
//!   因此本模块**从不**对 `keyring::Error` 使用 `{:?}` 或 `to_string()` 直接外传。

use super::{is_valid_secret_ref, Vault};
use crate::error::{Error, Result};

/// 支持的平台：macOS（Keychain Services）/ Windows（Credential Manager）。
///
/// 用 `cfg!` 而不是 `#[cfg]` 双份实现，是为了让「平台不支持」这条分支在
/// 所有平台上都能被单测覆盖（否则 CI 只在 macOS 跑，Windows 分支永远不被编译）。
pub const fn platform_supported() -> bool {
    cfg!(any(target_os = "macos", target_os = "windows"))
}

pub struct KeychainVault {
    service: String,
}

impl Default for KeychainVault {
    fn default() -> Self {
        Self::new()
    }
}

impl KeychainVault {
    /// 新 service 名（钥匙串条目的 `service` 字段，人可见）。
    pub const DEFAULT_SERVICE: &'static str = "Tianshu Relay";
    /// 旧 service 名（M35-S1 §4.1）——**仅作迁移源**，不再写入。
    pub const LEGACY_SERVICE: &'static str = "KeyRelay";

    /// 生产装配入口：service 固定为 `Tianshu Relay`。
    pub fn new() -> Self {
        Self::with_service(Self::DEFAULT_SERVICE)
    }

    /// 允许自定义 service，仅用于测试隔离（避免污染真实条目）。
    pub fn with_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    pub fn service(&self) -> &str {
        &self.service
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

    fn unavailable(reason: impl Into<String>) -> Error {
        Error::VaultUnavailable(reason.into())
    }
}

/// 把 `keyring::Error` 映射成**不含任何密钥材料**的短描述。
///
/// 刻意穷举匹配：`BadEncoding` / `BadDataFormat` 的载荷是密钥字节，
/// 一旦用 `{:?}` 打印就会把密钥写进日志。
///
/// 平台说明（B-224 P3 / Linux 门禁）：生产调用点都在 `macos/windows`
/// 的 impl 里，Linux 的 lib 目标上它只被测试用例调用，
/// 因此非 macOS/Windows 的非测试编译会判 dead_code——这是平台条件造成
/// 的，不是无用代码，故在此平台上放行该 lint。
#[cfg_attr(not(any(target_os = "macos", target_os = "windows")), allow(dead_code))]
fn describe(err: &keyring::Error) -> String {
    use keyring::Error as K;
    match err {
        K::NoEntry => "条目不存在".to_string(),
        K::NoStorageAccess(_) => "无法访问系统钥匙串（可能被锁定或未授权）".to_string(),
        K::PlatformFailure(_) => "系统钥匙串后端报错".to_string(),
        K::NoDefaultStore => "没有可用的系统钥匙串后端".to_string(),
        K::NotSupportedByStore(issue) => format!("当前钥匙串不支持该操作：{issue}"),
        K::BadEncoding(_) => "钥匙串返回的密钥不是合法 UTF-8".to_string(),
        K::BadDataFormat(_, _) => "钥匙串返回的数据格式异常".to_string(),
        K::BadStoreFormat(reason) => format!("钥匙串数据格式异常：{reason}"),
        K::TooLong(name, limit) => format!("字段 {name} 超出平台长度上限 {limit}"),
        K::Invalid(attr, reason) => format!("字段 {attr} 非法：{reason}"),
        K::Ambiguous(items) => format!("钥匙串中存在 {} 条同名条目，请先清理", items.len()),
        // `keyring::Error` 是 `#[non_exhaustive]`，未来可能新增携带载荷的变体：
        // 兜底分支刻意**不打印任何载荷**，只给固定文案。
        _ => "系统钥匙串返回了未知错误".to_string(),
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl Vault for KeychainVault {
    fn backend_name(&self) -> &'static str {
        #[cfg(target_os = "macos")]
        {
            "macos-keychain"
        }
        #[cfg(target_os = "windows")]
        {
            "windows-credential-manager"
        }
    }

    fn probe(&self) -> Result<()> {
        // `store_status()` 会初始化后端并缓存结果；返回 Err 说明后端不可用。
        match keyring::Entry::store_status() {
            Ok(()) => Ok(()),
            Err(err) => Err(Self::unavailable(describe(err))),
        }
    }

    fn put(&self, key: &str, secret: &str) -> Result<()> {
        Self::check_ref(key)?;
        let entry =
            keyring::Entry::new(&self.service, key).map_err(|e| Self::unavailable(describe(&e)))?;
        entry
            .set_password(secret)
            .map_err(|e| Error::Vault(describe(&e)))
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        Self::check_ref(key)?;
        let entry =
            keyring::Entry::new(&self.service, key).map_err(|e| Self::unavailable(describe(&e)))?;
        match entry.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(Error::Vault(describe(&e))),
        }
    }

    fn delete(&self, key: &str) -> Result<()> {
        Self::check_ref(key)?;
        let entry =
            keyring::Entry::new(&self.service, key).map_err(|e| Self::unavailable(describe(&e)))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(Error::Vault(describe(&e))),
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
impl Vault for KeychainVault {
    fn backend_name(&self) -> &'static str {
        "unsupported"
    }

    fn probe(&self) -> Result<()> {
        Err(Self::unavailable("当前平台没有受支持的系统钥匙串"))
    }

    fn put(&self, key: &str, _secret: &str) -> Result<()> {
        Self::check_ref(key)?;
        Err(Self::unavailable("当前平台没有受支持的系统钥匙串"))
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        Self::check_ref(key)?;
        Err(Self::unavailable("当前平台没有受支持的系统钥匙串"))
    }

    fn delete(&self, key: &str) -> Result<()> {
        Self::check_ref(key)?;
        Err(Self::unavailable("当前平台没有受支持的系统钥匙串"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_names_are_new_and_legacy_distinct() {
        // M35-S1 §7：M35 的最高风险不变量——生产迁移必须显式读旧 service。
        assert_eq!(KeychainVault::DEFAULT_SERVICE, "Tianshu Relay");
        assert_eq!(KeychainVault::LEGACY_SERVICE, "KeyRelay");
        assert_ne!(
            KeychainVault::DEFAULT_SERVICE,
            KeychainVault::LEGACY_SERVICE
        );
    }

    #[test]
    fn platform_support_flag_matches_backend_name() {
        let v = KeychainVault::new();
        assert_eq!(v.service(), "Tianshu Relay");
        if platform_supported() {
            assert!(matches!(
                v.backend_name(),
                "macos-keychain" | "windows-credential-manager"
            ));
        } else {
            assert_eq!(v.backend_name(), "unsupported");
            assert!(matches!(v.probe(), Err(Error::VaultUnavailable(_))));
        }
    }

    #[test]
    fn rejects_invalid_ref_before_touching_backend() {
        let v = KeychainVault::with_service("Tianshu Relay-Test-RefValidation");
        for bad in ["", "kr/key/1", "kr//1/secret", "sk-plaintext"] {
            let err = v.get(bad).unwrap_err();
            assert!(matches!(err, Error::Vault(_)), "{bad}: {err:?}");
            // 引用不合法时必须在触碰钥匙串之前就失败，且不回显入参
            assert!(!err.to_string().contains("sk-plaintext"));
        }
    }

    #[test]
    fn describe_never_echoes_payload_bytes() {
        // BadEncoding 携带的是取回的密钥字节：描述里绝不能出现它
        let err = keyring::Error::BadEncoding(b"sk-LEAKY-SECRET-BYTES".to_vec());
        let text = describe(&err);
        assert!(!text.contains("sk-LEAKY"));
        assert!(!text.contains("LEAKY"));
        let err = keyring::Error::BadDataFormat(
            b"sk-ALSO-LEAKY".to_vec(),
            Box::new(std::io::Error::other("x")),
        );
        assert!(!describe(&err).contains("LEAKY"));
    }

    /// 手工验证用（`--ignored`）：真实系统钥匙串往返。会写入并删除一个条目。
    #[test]
    #[ignore = "需要真实系统钥匙串；用 --ignored 手动跑"]
    fn real_keychain_roundtrip() {
        let v = KeychainVault::with_service("Tianshu Relay-Selftest");
        v.probe().expect("系统钥匙串应可用");
        let r = super::super::secret_ref("key", 1, "secret");

        v.delete(&r).expect("预清理");
        assert_eq!(v.get(&r).unwrap(), None, "不存在应返回 None 而不是报错");

        v.put(&r, "sk-selftest-0123456789").unwrap();
        assert_eq!(
            v.get(&r).unwrap().as_deref(),
            Some("sk-selftest-0123456789")
        );

        v.delete(&r).unwrap();
        assert_eq!(v.get(&r).unwrap(), None);
        v.delete(&r).expect("删除应幂等");
    }
}
