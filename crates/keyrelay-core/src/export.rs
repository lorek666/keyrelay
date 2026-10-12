//! 配置导出（PRD M4「加密导出」）。
//!
//! **导出物里没有密钥本体**——密钥只存在于系统钥匙串，导出的是站点 / 密钥元数据 /
//! 同意记录 / 设置 / 已脱敏的事件。因此「加密」保护的是**元数据**（站点地址、用户名、
//! 密钥名称），不是密钥本身。这一点在 UI 文案里必须说清楚，否则用户会以为
//! 「导出了密钥但被加密了」。

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::{Error, Result};

/// 导出格式版本。
pub const EXPORT_VERSION: u32 = 1;
/// 加密信封的标识。
pub const ENCRYPTED_FORMAT: &str = "keyrelay-export-v1";
/// PBKDF2 迭代次数（OWASP 对 PBKDF2-HMAC-SHA256 的 2023 年建议下限）。
pub const PBKDF2_ITERATIONS: u32 = 210_000;
/// 解密时允许的信封迭代次数下限：低于这个值说明信封来自「弱 KDF」，
/// 我们不该假装它是合法的（M4-S2 复审 P2-4）。
pub const MIN_KDF_ITERATIONS: u32 = 100_000;
/// 解密时允许的上限：防「伪造信封 → App 卡死」的 DoS。
pub const MAX_KDF_ITERATIONS: u32 = 1_000_000;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExportBundle {
    pub version: u32,
    pub exported_at: i64,
    pub app_version: String,
    pub sites: Vec<ExportSite>,
    pub keys: Vec<ExportKey>,
    pub consents: Vec<ExportConsent>,
    pub settings: ExportSettings,
    pub events: Vec<ExportEvent>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExportSite {
    pub id: i64,
    pub kind: String,
    pub base_url: String,
    pub display_name: String,
}

/// 密钥的**元数据**。刻意不含 `secret_ref`（那是钥匙串里的地址，导出去没意义）
/// 更不含密钥本体。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExportKey {
    pub id: i64,
    pub site_id: i64,
    pub remote_id: Option<String>,
    pub name: String,
    pub group: Option<String>,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExportConsent {
    pub agent_id: String,
    pub channel: String,
    pub target_path: String,
    pub fields: String,
    pub granted_at: i64,
    pub revoked_at: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExportSettings {
    pub refresh_interval_secs: u64,
    pub balance_alert_threshold: f64,
    pub drift_check_on_start: bool,
    pub gateway_enabled: bool,
    pub gateway_port: u16,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExportEvent {
    pub ts: i64,
    pub level: String,
    pub source: String,
    pub message: String,
    pub payload: Option<String>,
}

/// 加密信封。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub format: String,
    pub kdf: KdfParams,
    /// base64（标准字母表，带 padding）
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub iterations: u32,
    pub salt: String,
}

/// 明文导出。
pub fn to_json(bundle: &ExportBundle) -> Result<String> {
    serde_json::to_string_pretty(bundle).map_err(|e| Error::Store(format!("序列化导出包失败: {e}")))
}

/// 从明文 JSON 解析。
pub fn from_json(text: &str) -> Result<ExportBundle> {
    let bundle: ExportBundle =
        serde_json::from_str(text).map_err(|e| Error::Store(format!("解析导出包失败: {e}")))?;
    check_version(bundle.version)?;
    Ok(bundle)
}

fn check_version(version: u32) -> Result<()> {
    if version != EXPORT_VERSION {
        return Err(Error::Store(format!(
            "导出包版本 {version} 不受支持（本版本支持 {EXPORT_VERSION}）"
        )));
    }
    Ok(())
}

/// 用密码加密导出包。
pub fn encrypt(bundle: &ExportBundle, password: &str) -> Result<String> {
    if password.trim().is_empty() {
        return Err(Error::Store("密码为空；要明文导出请直接用 to_json".into()));
    }
    let plaintext = to_json(bundle)?;

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|e| Error::Store(format!("生成随机盐失败: {e}")))?;
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| Error::Store(format!("生成随机 nonce 失败: {e}")))?;

    let key = derive_key(password, &salt, PBKDF2_ITERATIONS)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| Error::Store(format!("构造加密器失败: {e}")))?;
    let ciphertext = cipher
        .encrypt(&nonce(&nonce_bytes)?, plaintext.as_bytes())
        .map_err(|_| Error::Store("加密失败".into()))?;

    let envelope = EncryptedEnvelope {
        format: ENCRYPTED_FORMAT.to_string(),
        kdf: KdfParams {
            algorithm: "pbkdf2-hmac-sha256".to_string(),
            iterations: PBKDF2_ITERATIONS,
            salt: b64(&salt),
        },
        nonce: b64(&nonce_bytes),
        ciphertext: b64(&ciphertext),
    };
    serde_json::to_string_pretty(&envelope)
        .map_err(|e| Error::Store(format!("序列化加密信封失败: {e}")))
}

/// 用密码解密。密码错或密文被改动都会失败（GCM 的认证标签会校验出来）。
pub fn decrypt(envelope_json: &str, password: &str) -> Result<ExportBundle> {
    let envelope: EncryptedEnvelope = serde_json::from_str(envelope_json)
        .map_err(|e| Error::Store(format!("解析加密信封失败: {e}")))?;
    if envelope.format != ENCRYPTED_FORMAT {
        return Err(Error::Store(format!(
            "不认识的加密信封格式: {}",
            envelope.format
        )));
    }
    if envelope.kdf.algorithm != "pbkdf2-hmac-sha256" {
        return Err(Error::Store(format!(
            "不认识的密钥派生算法: {}",
            envelope.kdf.algorithm
        )));
    }
    // 信封里的迭代次数是**不可信输入**（M4-S2 复审 P2-4）：
    // 不设上限，一个伪造的 `iterations: 5_000_000` 就能让 App 卡上几十秒
    // （复审实测 39.1s，线性外推到 u32::MAX 约 9 小时）；不设下限，
    // 一个「1 轮 PBKDF2」的信封等于把离线爆破成本降到最低，我们却照收。
    if !(MIN_KDF_ITERATIONS..=MAX_KDF_ITERATIONS).contains(&envelope.kdf.iterations) {
        return Err(Error::Store(format!(
            "加密信封里的 KDF 迭代次数 {} 不在允许范围 {}..={} 内，拒绝解密",
            envelope.kdf.iterations, MIN_KDF_ITERATIONS, MAX_KDF_ITERATIONS
        )));
    }

    let salt = unb64(&envelope.kdf.salt)?;
    let nonce_bytes = unb64(&envelope.nonce)?;
    let ciphertext = unb64(&envelope.ciphertext)?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(Error::Store("加密信封的 nonce 长度不对".into()));
    }

    let key = derive_key(password, &salt, envelope.kdf.iterations)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| Error::Store(format!("构造解密器失败: {e}")))?;
    let plaintext = cipher
        .decrypt(&nonce(&nonce_bytes)?, ciphertext.as_ref())
        .map_err(|_| Error::Store("解密失败：密码错误，或文件被篡改".into()))?;

    let text =
        String::from_utf8(plaintext).map_err(|_| Error::Store("解密结果不是合法 UTF-8".into()))?;
    from_json(&text)
}

/// 这个字符串看起来是加密信封还是明文导出？
pub fn is_encrypted(text: &str) -> bool {
    serde_json::from_str::<EncryptedEnvelope>(text)
        .map(|envelope| envelope.format == ENCRYPTED_FORMAT)
        .unwrap_or(false)
}

/// 按密码是否为空自动选择明文或加密。
pub fn export(bundle: &ExportBundle, password: Option<&str>) -> Result<(String, bool)> {
    match password.map(str::trim).filter(|p| !p.is_empty()) {
        Some(password) => Ok((encrypt(bundle, password)?, true)),
        None => Ok((to_json(bundle)?, false)),
    }
}

/// 构造 AES-GCM 的 nonce。长度不对时明确报错，而不是 panic。
fn nonce(bytes: &[u8]) -> Result<Nonce<aes_gcm::aead::consts::U12>> {
    let array: [u8; NONCE_LEN] = bytes
        .try_into()
        .map_err(|_| Error::Store("nonce 长度必须是 12 字节".into()))?;
    Ok(array.into())
}

fn derive_key(password: &str, salt: &[u8], iterations: u32) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
    Ok(key)
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(text: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|e| Error::Store(format!("base64 解码失败: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ExportBundle {
        ExportBundle {
            version: EXPORT_VERSION,
            exported_at: 1_760_000_000,
            app_version: "0.1.0".into(),
            sites: vec![ExportSite {
                id: 1,
                kind: "newapi".into(),
                base_url: "https://relay.example.com".into(),
                display_name: "测试站".into(),
            }],
            keys: vec![ExportKey {
                id: 3,
                site_id: 1,
                remote_id: Some("12".into()),
                name: "codex/daily".into(),
                group: Some("default".into()),
                status: "enabled".into(),
            }],
            consents: vec![],
            settings: ExportSettings {
                refresh_interval_secs: 0,
                balance_alert_threshold: 0.0,
                drift_check_on_start: true,
                gateway_enabled: false,
                gateway_port: 8787,
            },
            events: vec![],
        }
    }

    #[test]
    fn json_round_trip() {
        let bundle = sample();
        let text = to_json(&bundle).unwrap();
        assert_eq!(from_json(&text).unwrap(), bundle);
        assert!(text.contains("测试站"), "中文应原样保留");
        assert!(!is_encrypted(&text));
    }

    #[test]
    fn encryption_round_trip() {
        let bundle = sample();
        let envelope = encrypt(&bundle, "correct horse battery staple").unwrap();
        assert!(is_encrypted(&envelope));
        assert!(
            !envelope.contains("relay.example.com"),
            "密文里不该出现明文元数据"
        );
        assert_eq!(
            decrypt(&envelope, "correct horse battery staple").unwrap(),
            bundle
        );
    }

    #[test]
    fn wrong_password_is_rejected() {
        let envelope = encrypt(&sample(), "right").unwrap();
        let err = decrypt(&envelope, "wrong").unwrap_err();
        assert!(err.to_string().contains("密码错误"), "{err}");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let envelope = encrypt(&sample(), "pw").unwrap();
        let mut parsed: EncryptedEnvelope = serde_json::from_str(&envelope).unwrap();
        // 翻转密文的一个字节
        let mut bytes = unb64(&parsed.ciphertext).unwrap();
        bytes[0] ^= 0x01;
        parsed.ciphertext = b64(&bytes);
        let tampered = serde_json::to_string(&parsed).unwrap();

        let err = decrypt(&tampered, "pw").unwrap_err();
        assert!(err.to_string().contains("篡改"), "{err}");
    }

    #[test]
    fn empty_password_is_not_encryption() {
        assert!(encrypt(&sample(), "").is_err());
        assert!(encrypt(&sample(), "   ").is_err());
        let (text, encrypted) = export(&sample(), Some("  ")).unwrap();
        assert!(!encrypted, "空白密码应视为「不加密」");
        assert!(!is_encrypted(&text));
    }

    #[test]
    fn export_chooses_by_password_presence() {
        let (plain, encrypted) = export(&sample(), None).unwrap();
        assert!(!encrypted);
        assert!(!is_encrypted(&plain));

        let (cipher, encrypted) = export(&sample(), Some("pw")).unwrap();
        assert!(encrypted);
        assert!(is_encrypted(&cipher));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let mut bundle = sample();
        bundle.version = 99;
        let text = serde_json::to_string(&bundle).unwrap();
        let err = from_json(&text).unwrap_err();
        assert!(err.to_string().contains("版本"), "{err}");
    }

    #[test]
    fn unknown_format_is_rejected() {
        let mut envelope: EncryptedEnvelope =
            serde_json::from_str(&encrypt(&sample(), "pw").unwrap()).unwrap();
        envelope.format = "something-else".into();
        let err = decrypt(&serde_json::to_string(&envelope).unwrap(), "pw").unwrap_err();
        assert!(err.to_string().contains("格式"), "{err}");
    }

    #[test]
    fn export_has_no_key_material() {
        // 结构性保证：`ExportKey` 里没有 secret_ref / key 字段
        let text = to_json(&sample()).unwrap();
        assert!(!text.contains("secret_ref"), "{text}");
        assert!(!text.contains("\"key\""), "{text}");
        assert!(!text.contains("sk-"), "{text}");
    }
}
