//! 保险库单条密文的封套（`krseal1.`）。
//!
//! 与 `export.rs` 的加密导出信封**同源**：都用 AES-256-GCM，都拒绝不可信参数。
//! 差别只有两点：
//! - 这里的密钥是本机 DEK（32 字节），不经过 KDF（DEK 本身就是随机的）；
//! - **AAD 绑定引用**（`kr/key/17/secret`）。行被搬到别的引用下会解密失败，
//!   这样「换一行密文」不能把 A 的密钥喂给 B。

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// 封套前缀。带版本号，未来换算法时能明确拒绝旧格式而不是猜。
pub const SEAL_PREFIX: &str = "krseal1.";

const NONCE_LEN: usize = 12;
const ALG: &str = "aes-256-gcm";

#[derive(Serialize, Deserialize)]
struct SealBody {
    v: u32,
    alg: String,
    nonce: String,
    ct: String,
}

fn sealed_error(reason: impl Into<String>) -> Error {
    Error::Vault(reason.into())
}

/// 加密一条密钥。`reference` 同时是 AAD。
pub fn seal(dek: &[u8; 32], reference: &str, plaintext: &str) -> Result<String> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| sealed_error(format!("生成随机 nonce 失败: {e}")))?;

    let cipher =
        Aes256Gcm::new_from_slice(dek).map_err(|e| sealed_error(format!("构造加密器失败: {e}")))?;
    let nonce: Nonce<U12> = nonce_bytes.into();
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad: reference.as_bytes(),
            },
        )
        .map_err(|_| sealed_error("加密失败"))?;

    let body = SealBody {
        v: 1,
        alg: ALG.to_string(),
        nonce: B64.encode(nonce_bytes),
        ct: B64.encode(ciphertext),
    };
    let json = serde_json::to_string(&body)
        .map_err(|e| sealed_error(format!("序列化密文封套失败: {e}")))?;
    Ok(format!("{SEAL_PREFIX}{}", B64.encode(json)))
}

/// 解密一条密钥。密码学失败一律折叠成同一句文案：**不回显任何密钥材料**，
/// 也不区分「密钥文件不对」与「密文被改过」给外部（两者对调用方的动作相同）。
pub fn unseal(dek: &[u8; 32], reference: &str, sealed: &str) -> Result<String> {
    let payload = sealed
        .strip_prefix(SEAL_PREFIX)
        .ok_or_else(|| sealed_error("不认识的密文格式（缺少 krseal1. 前缀）"))?;
    let json = B64
        .decode(payload)
        .map_err(|e| sealed_error(format!("密文 base64 解码失败: {e}")))?;
    let body: SealBody = serde_json::from_slice(&json)
        .map_err(|e| sealed_error(format!("解析密文封套失败: {e}")))?;
    if body.v != 1 {
        return Err(sealed_error(format!("不支持的密文版本: {}", body.v)));
    }
    if body.alg != ALG {
        return Err(sealed_error(format!("不支持的加密算法: {}", body.alg)));
    }
    let nonce_bytes = B64
        .decode(&body.nonce)
        .map_err(|e| sealed_error(format!("nonce 解码失败: {e}")))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(sealed_error("密文 nonce 长度不对"));
    }
    let ciphertext = B64
        .decode(&body.ct)
        .map_err(|e| sealed_error(format!("密文解码失败: {e}")))?;

    let cipher =
        Aes256Gcm::new_from_slice(dek).map_err(|e| sealed_error(format!("构造解密器失败: {e}")))?;
    let nonce: Nonce<U12> = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| sealed_error("密文 nonce 长度不对"))?;
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext.as_ref(),
                aad: reference.as_bytes(),
            },
        )
        .map_err(|_| sealed_error("密文校验失败：密钥文件不匹配，或数据被篡改"))?;

    let plaintext = zeroize::Zeroizing::new(plaintext);
    std::str::from_utf8(plaintext.as_slice())
        .map(str::to_string)
        .map_err(|_| sealed_error("解密结果不是合法 UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dek() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn roundtrip_keeps_plaintext() {
        let sealed = seal(&dek(), "kr/key/1/secret", "sk-abc123").unwrap();
        assert!(sealed.starts_with(SEAL_PREFIX));
        assert_eq!(
            unseal(&dek(), "kr/key/1/secret", &sealed).unwrap(),
            "sk-abc123"
        );
    }

    #[test]
    fn same_plaintext_seals_differently_each_time() {
        let a = seal(&dek(), "kr/key/1/secret", "same").unwrap();
        let b = seal(&dek(), "kr/key/1/secret", "same").unwrap();
        assert_ne!(a, b, "nonce 必须每次随机");
    }

    #[test]
    fn another_reference_cannot_open_it() {
        let sealed = seal(&dek(), "kr/key/1/secret", "sk-abc123").unwrap();
        let err = unseal(&dek(), "kr/key/2/secret", &sealed).unwrap_err();
        assert!(err.to_string().contains("密文校验失败"), "{err}");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let sealed = seal(&dek(), "kr/key/1/secret", "sk-abc123").unwrap();
        let mut bytes = sealed.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(unseal(&dek(), "kr/key/1/secret", &tampered).is_err());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let sealed = seal(&dek(), "kr/key/1/secret", "sk-abc123").unwrap();
        assert!(unseal(&[9u8; 32], "kr/key/1/secret", &sealed).is_err());
    }

    #[test]
    fn foreign_prefix_is_rejected() {
        let err = unseal(&dek(), "kr/key/1/secret", "lpenc1.abc").unwrap_err();
        assert!(err.to_string().contains("krseal1."), "{err}");
    }
}
