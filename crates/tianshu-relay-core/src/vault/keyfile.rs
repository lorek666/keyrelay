//! `vault.key`：保护数据密钥（DEK）的本机密钥文件。
//!
//! 取舍见 `docs/ADR/0003`：不做主密码、不做解锁界面，所以 DEK 必须放在本机。
//! 能做到的加固只有两条，都写死在这里：
//! 1. 文件（0600）与目录（0700）权限——只挡别的用户，不挡同用户的进程；
//! 2. **设备绑定**：用本机设备标识派生 KEK，把 DEK 包一层。这样把整个 `~/.tianshu-relay`
//!    拷到另一台机器上解不开；设备标识取不到时退化为裸 DEK，并在文件里如实标注
//!    `deviceBound:false`（不假装绑定了）。

use std::fs;
use std::io::Write;
use std::path::Path;

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const KEY_FORMAT: &str = "keyrelay-vault-key-v1";

const ALG: &str = "aes-256-gcm";
const KDF_ALG: &str = "pbkdf2-hmac-sha256";
pub const KDF_ITERATIONS: u32 = 210_000;
/// 与 `export.rs` 同一口径：信封里的迭代次数是**不可信输入**，上下限都卡死，
/// 否则一个伪造的高迭代信封能让启动卡几十秒，低迭代信封等于把离线爆破成本降到零。
const MIN_KDF_ITERATIONS: u32 = 100_000;
const MAX_KDF_ITERATIONS: u32 = 1_000_000;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// 设备标识来源。抽成 trait 只为一件事：测试能注入「另一台机器」。
pub trait MachineId: Send + Sync {
    fn machine_id(&self) -> Option<String>;
}

/// 生产实现：macOS `IOPlatformUUID` / Windows `MachineGuid` / Linux `/etc/machine-id`。
pub struct SystemMachineId;

/// 测试实现：给定固定标识（`None` 模拟取不到设备标识的平台）。
pub struct StaticMachineId(pub Option<String>);

impl MachineId for StaticMachineId {
    fn machine_id(&self) -> Option<String> {
        self.0.clone()
    }
}

pub struct VaultKey {
    pub dek: Zeroizing<[u8; KEY_LEN]>,
    /// `false` = 设备标识不可用，DEK 是裸存的（只受文件权限保护）。
    pub device_bound: bool,
}

#[derive(Serialize, Deserialize)]
struct KdfParams {
    algorithm: String,
    iterations: u32,
    salt: String,
}

#[derive(Serialize, Deserialize)]
struct KeyFileBody {
    format: String,
    /// 包裹 DEK 的算法。明文写出来是为了让「这文件怎么读」不依赖代码考古。
    alg: String,
    #[serde(rename = "deviceBound")]
    device_bound: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdf: Option<KdfParams>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wrapped: Option<String>,
    /// 只在 `device_bound=false` 时出现。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dek: Option<String>,
}

fn vault_error(reason: impl Into<String>) -> Error {
    Error::Vault(reason.into())
}

/// 打开已有密钥文件，或首次生成。
///
/// **已存在但读不出来时绝不覆盖**：那意味着用户的密钥还在，只是当前环境解不开
pub fn load_or_create(path: &Path, machine: &dyn MachineId) -> Result<VaultKey> {
    if path.exists() {
        return read_existing(path, machine);
    }

    let mut dek = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::fill(dek.as_mut()).map_err(|e| vault_error(format!("生成数据密钥失败: {e}")))?;

    let machine_id = machine.machine_id().filter(|s| !s.trim().is_empty());
    let body = match machine_id.as_deref() {
        Some(id) => wrap_dek(&dek, id)?,
        None => KeyFileBody {
            format: KEY_FORMAT.to_string(),
            alg: ALG.to_string(),
            device_bound: false,
            kdf: None,
            nonce: None,
            wrapped: None,
            dek: Some(B64.encode(dek.as_ref())),
        },
    };
    if !write_new(path, &body)? {
        // 另一个进程抢先创建了密钥文件：用它的，不要覆盖。
        return read_existing(path, machine);
    }
    Ok(VaultKey {
        dek,
        device_bound: machine_id.is_some(),
    })
}

fn read_existing(path: &Path, machine: &dyn MachineId) -> Result<VaultKey> {
    let text = fs::read_to_string(path)
        .map_err(|e| vault_error(format!("读密钥文件失败（{}）: {e}", path.display())))?;
    let body: KeyFileBody = serde_json::from_str(&text)
        .map_err(|e| vault_error(format!("密钥文件格式异常（{}）: {e}", path.display())))?;
    if body.format != KEY_FORMAT {
        return Err(vault_error(format!(
            "不认识的密钥文件格式「{}」（期望 {KEY_FORMAT}）",
            body.format
        )));
    }
    if body.alg != ALG {
        return Err(vault_error(format!("不支持的密钥封装算法: {}", body.alg)));
    }

    if body.device_bound {
        let machine_id = machine
            .machine_id()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                vault_error(
                    "密钥文件已绑定本机设备，但当前取不到设备标识；拒绝继续（不会覆盖现场）",
                )
            })?;
        let kdf = body
            .kdf
            .as_ref()
            .ok_or_else(|| vault_error("密钥文件缺少 KDF 参数"))?;
        let nonce = body
            .nonce
            .as_ref()
            .ok_or_else(|| vault_error("密钥文件缺少 nonce"))?;
        let wrapped = body
            .wrapped
            .as_ref()
            .ok_or_else(|| vault_error("密钥文件缺少 wrapped 密文"))?;

        let dek = unwrap_dek(kdf, nonce, wrapped, &machine_id)?;
        return Ok(VaultKey {
            dek,
            device_bound: true,
        });
    }

    let raw = body
        .dek
        .as_ref()
        .ok_or_else(|| vault_error("密钥文件未绑定设备，但缺少 dek 字段"))?;
    let bytes = zeroize::Zeroizing::new(
        B64.decode(raw)
            .map_err(|e| vault_error(format!("密钥文件 dek 解码失败: {e}")))?,
    );
    if bytes.len() != KEY_LEN {
        return Err(vault_error(format!(
            "密钥文件 dek 长度不对：{}（期望 {KEY_LEN}）",
            bytes.len()
        )));
    }
    let mut dek = Zeroizing::new([0u8; KEY_LEN]);
    dek.copy_from_slice(bytes.as_slice());
    Ok(VaultKey {
        dek,
        device_bound: false,
    })
}

fn wrap_dek(dek: &[u8; KEY_LEN], machine_id: &str) -> Result<KeyFileBody> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|e| vault_error(format!("生成随机盐失败: {e}")))?;
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| vault_error(format!("生成随机 nonce 失败: {e}")))?;

    let kek = derive_kek(machine_id, &salt, KDF_ITERATIONS)?;
    let cipher = Aes256Gcm::new_from_slice(kek.as_ref())
        .map_err(|e| vault_error(format!("构造加密器失败: {e}")))?;
    let nonce: Nonce<U12> = nonce_bytes.into();
    let wrapped = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: dek.as_ref(),
                aad: KEY_FORMAT.as_bytes(),
            },
        )
        .map_err(|_| vault_error("封装数据密钥失败"))?;

    Ok(KeyFileBody {
        format: KEY_FORMAT.to_string(),
        alg: ALG.to_string(),
        device_bound: true,
        kdf: Some(KdfParams {
            algorithm: KDF_ALG.to_string(),
            iterations: KDF_ITERATIONS,
            salt: B64.encode(salt),
        }),
        nonce: Some(B64.encode(nonce_bytes)),
        wrapped: Some(B64.encode(wrapped)),
        dek: None,
    })
}

fn unwrap_dek(
    kdf: &KdfParams,
    nonce_b64: &str,
    wrapped_b64: &str,
    machine_id: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if kdf.algorithm != KDF_ALG {
        return Err(vault_error(format!(
            "不认识的密钥派生算法: {}",
            kdf.algorithm
        )));
    }
    if !(MIN_KDF_ITERATIONS..=MAX_KDF_ITERATIONS).contains(&kdf.iterations) {
        return Err(vault_error(format!(
            "密钥文件的 KDF 迭代次数 {} 不在允许范围 {}..={} 内，拒绝解密",
            kdf.iterations, MIN_KDF_ITERATIONS, MAX_KDF_ITERATIONS
        )));
    }
    let salt = B64
        .decode(&kdf.salt)
        .map_err(|e| vault_error(format!("盐解码失败: {e}")))?;
    let nonce_bytes = B64
        .decode(nonce_b64)
        .map_err(|e| vault_error(format!("nonce 解码失败: {e}")))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(vault_error("密钥文件 nonce 长度不对"));
    }
    let wrapped = B64
        .decode(wrapped_b64)
        .map_err(|e| vault_error(format!("密文解码失败: {e}")))?;

    let kek = derive_kek(machine_id, &salt, kdf.iterations)?;
    let cipher = Aes256Gcm::new_from_slice(kek.as_ref())
        .map_err(|e| vault_error(format!("构造解密器失败: {e}")))?;
    let nonce: Nonce<U12> = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| vault_error("密钥文件 nonce 长度不对"))?;
    let dek = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: wrapped.as_ref(),
                aad: KEY_FORMAT.as_bytes(),
            },
        )
        .map_err(|_| vault_error("密钥文件解不开：设备不匹配，或文件被篡改"))?;
    if dek.len() != KEY_LEN {
        return Err(vault_error("解出的数据密钥长度不对"));
    }
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(&dek);
    Ok(out)
}

fn derive_kek(machine_id: &str, salt: &[u8], iterations: u32) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(machine_id.as_bytes(), salt, iterations, key.as_mut());
    Ok(key)
}

/// 返回 `true` = 本次创建成功；`false` = 目标已存在（并发首启），调用方应改读现有文件。
fn write_new(path: &Path, body: &KeyFileBody) -> Result<bool> {
    let dir = path
        .parent()
        .ok_or_else(|| vault_error("密钥文件路径没有父目录"))?;
    fs::create_dir_all(dir).map_err(|e| vault_error(format!("创建数据目录失败: {e}")))?;
    // 目录里会放密钥文件，所以**每次**都收紧到 0700（不只首次创建时）。
    set_dir_private(dir)?;

    // 临时文件名带 pid + 随机串：并发首次启动不会互相踩。
    let mut rand = [0u8; 8];
    getrandom::fill(&mut rand).map_err(|e| vault_error(format!("生成临时文件名失败: {e}")))?;
    let tmp = dir.join(format!(
        ".vault-key-{}-{}.tmp",
        std::process::id(),
        hex::encode(rand)
    ));

    let mut file = open_private_create_new(&tmp)?;
    let serialized = serde_json::to_string_pretty(body)
        .map_err(|e| vault_error(format!("序列化密钥文件失败: {e}")))?;
    file.write_all(serialized.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|e| vault_error(format!("写密钥文件失败: {e}")))?;
    drop(file);

    // 用 `hard_link` 而不是 `rename`：目标已存在时它会失败，而不是**覆盖**掉
    // 另一个进程刚写好的密钥文件（覆盖 = 那一边的密钥永久丢失）。
    match fs::hard_link(&tmp, path) {
        Ok(()) => {
            let _ = fs::remove_file(&tmp);
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&tmp);
            return Ok(false);
        }
        Err(err) => {
            let _ = fs::remove_file(&tmp);
            return Err(vault_error(format!("落盘密钥文件失败: {e}", e = err)));
        }
    }
    set_file_private(path)?;
    Ok(true)
}

#[cfg(unix)]
fn open_private_create_new(path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| vault_error(format!("创建密钥文件失败: {e}")))
}

#[cfg(not(unix))]
fn open_private_create_new(path: &Path) -> Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| vault_error(format!("创建密钥文件失败: {e}")))
}

#[cfg(unix)]
fn set_file_private(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| vault_error(format!("设置密钥文件权限失败: {e}")))
}

#[cfg(not(unix))]
fn set_file_private(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_dir_private(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| vault_error(format!("设置数据目录权限失败: {e}")))
}

#[cfg(not(unix))]
fn set_dir_private(_path: &Path) -> Result<()> {
    Ok(())
}

fn platform_machine_id() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.contains("IOPlatformUUID") {
                let value = line.split('"').nth(3)?;
                if !value.trim().is_empty() {
                    return Some(value.trim().to_string());
                }
            }
        }
        None
    }
    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("reg")
            .args([
                "query",
                r"HKLM\SOFTWARE\Microsoft\Cryptography",
                "/v",
                "MachineGuid",
            ])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.contains("MachineGuid") {
                return line.split_whitespace().last().map(str::to_string);
            }
        }
        None
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        fs::read_to_string("/etc/machine-id")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }
}

impl MachineId for SystemMachineId {
    fn machine_id(&self) -> Option<String> {
        platform_machine_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("建临时目录")
    }

    #[test]
    fn creates_private_file_and_roundtrips() {
        let dir = temp_dir();
        let path = dir.path().join("vault.key");
        let m = StaticMachineId(Some("machine-a".into()));
        let first = load_or_create(&path, &m).unwrap();
        assert!(first.device_bound);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "密钥文件必须是 0600");
            let dir_mode = fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700, "密钥目录必须是 0700");
        }
        let second = load_or_create(&path, &m).unwrap();
        assert_eq!(first.dek.as_ref(), second.dek.as_ref());
    }

    #[test]
    fn another_machine_cannot_unwrap() {
        let dir = temp_dir();
        let path = dir.path().join("vault.key");
        let a = StaticMachineId(Some("machine-a".into()));
        let b = StaticMachineId(Some("machine-b".into()));
        load_or_create(&path, &a).unwrap();
        // 不用 `unwrap_err()`：`VaultKey` 故意没有 `Debug`（防止密钥被 `{:?}` 打出来）。
        let err = match load_or_create(&path, &b) {
            Ok(_) => panic!("换一台机器不该解得开"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("解不开"), "{err}");
    }

    #[test]
    fn unbound_fallback_is_labelled_truthfully() {
        let dir = temp_dir();
        let path = dir.path().join("vault.key");
        let none = StaticMachineId(None);
        let key = load_or_create(&path, &none).unwrap();
        assert!(!key.device_bound);
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"deviceBound\": false"), "{text}");
    }

    #[test]
    fn corrupt_file_is_not_overwritten() {
        let dir = temp_dir();
        let path = dir.path().join("vault.key");
        fs::write(&path, b"not json").unwrap();
        let m = StaticMachineId(Some("machine-a".into()));
        assert!(load_or_create(&path, &m).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"not json");
    }
}
