//! 站点登录密码加密（NewAPI 的 `password_encrypted` 方案）。
//!
//! 站点侧实现（`QuantumNous/new-api`）：
//! - `GET /api/user/login/encryption-key` → `{success, data:{enabled, kid, public_key}}`
//! - 客户端用 **RSA-OAEP(SHA-256)** 加密密码，`POST /api/user/login`
//!   携带 `{username, password_encrypted, encryption_key_id}`
//! - 后端 `DecryptPassword` 用私钥解密；密钥 2048 位，`kid` = 公钥 DER 的 SHA-256 前 16 字节 hex
//!
//! 上游还有一条 **v2** 路径（长密码：随机 AES-256-GCM 密钥 + RSA-OAEP 包裹，输出
//! `v2.<wrappedKey>.<nonce>.<ciphertext>`）。本实现**只做 v1**：
//! 密码超过 OAEP 上限时明确报错，绝不降级为明文发送（见 BACKLOG B-29）。

use base64::Engine as _;
use rsa::pkcs8::DecodePublicKey;
use rsa::rand_core::OsRng;
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, RsaPublicKey};
use sha2::Sha256;

use crate::error::{Error, Result};

/// OAEP-SHA256 的最大明文长度：`k - 2*hLen - 2`（k = 模长字节数，hLen = 32）
pub const OAEP_SHA256_OVERHEAD: usize = 2 * 32 + 2;

#[derive(Clone, PartialEq, Eq)]
pub struct PasswordEncryptionKey {
    pub kid: String,
    pub public_key_pem: String,
}

impl std::fmt::Debug for PasswordEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 公钥不是秘密，但没必要进日志；只留 kid 便于排障
        f.debug_struct("PasswordEncryptionKey")
            .field("kid", &self.kid)
            .field("public_key_pem", &"<已省略>")
            .finish()
    }
}

/// 用站点公钥加密登录密码（v1：RSA-OAEP-SHA256，无 label）。
///
/// 返回 base64 编码的密文。**绝不**在失败时退回明文——调用方据此判断是否需要
/// 引导用户走 WebView 登录。
pub fn encrypt_password(password: &str, key: &PasswordEncryptionKey) -> Result<String> {
    let public_key = RsaPublicKey::from_public_key_pem(&key.public_key_pem)
        .map_err(|e| Error::Transport(format!("站点公钥无法解析（kid={}）: {e}", key.kid)))?;

    let max_plaintext = public_key.size() - OAEP_SHA256_OVERHEAD;
    if password.len() > max_plaintext {
        return Err(Error::AuthFailed(format!(
            "密码长度 {} 字节超过站点加密上限 {} 字节（需 WebView 登录，见 BACKLOG B-29）",
            password.len(),
            max_plaintext
        )));
    }

    let padding = Oaep::new::<Sha256>();
    let ciphertext = public_key
        .encrypt(&mut OsRng, padding, password.as_bytes())
        .map_err(|e| Error::Transport(format!("密码加密失败: {e}")))?;

    Ok(base64::engine::general_purpose::STANDARD.encode(ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::{EncodePublicKey, LineEnding};
    use rsa::{RsaPrivateKey, RsaPublicKey};

    fn test_key() -> (RsaPrivateKey, PasswordEncryptionKey) {
        let private = RsaPrivateKey::new(&mut OsRng, 2048).expect("生成测试密钥");
        let public = RsaPublicKey::from(&private);
        let pem = public.to_public_key_pem(LineEnding::LF).expect("导出 PEM");
        (
            private,
            PasswordEncryptionKey {
                kid: "test-kid".to_string(),
                public_key_pem: pem,
            },
        )
    }

    fn decrypt(private: &RsaPrivateKey, ciphertext_b64: &str) -> Vec<u8> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(ciphertext_b64)
            .expect("base64 解码");
        private
            .decrypt(Oaep::new::<Sha256>(), &bytes)
            .expect("解密失败")
    }

    #[test]
    fn encrypts_password_with_oaep_sha256() {
        let (private, key) = test_key();
        let ciphertext = encrypt_password("hunter2", &key).expect("加密成功");
        assert_eq!(decrypt(&private, &ciphertext), b"hunter2");
    }

    #[test]
    fn ciphertext_is_randomized() {
        let (_, key) = test_key();
        let a = encrypt_password("same-password", &key).unwrap();
        let b = encrypt_password("same-password", &key).unwrap();
        assert_ne!(a, b, "OAEP 每次加密应产生不同密文");
    }

    #[test]
    fn rejects_invalid_pem() {
        let key = PasswordEncryptionKey {
            kid: "bad".into(),
            public_key_pem: "-----BEGIN PUBLIC KEY-----\n不是密钥\n-----END PUBLIC KEY-----".into(),
        };
        let err = encrypt_password("pw", &key).unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "实际: {err:?}");
    }

    #[test]
    fn rejects_overlong_password_instead_of_downgrading() {
        let (_, key) = test_key();
        let long = "a".repeat(200); // RSA-2048 的 OAEP-SHA256 上限是 190 字节
        let err = encrypt_password(&long, &key).unwrap_err();
        match err {
            Error::AuthFailed(message) => {
                assert!(message.contains("超过站点加密上限"), "{message}");
                assert!(!message.contains(&long), "错误信息不得回显密码");
            }
            other => panic!("期望 AuthFailed，实际: {other:?}"),
        }
    }

    #[test]
    fn key_debug_hides_pem() {
        let (_, key) = test_key();
        let debug = format!("{key:?}");
        assert!(debug.contains("test-kid"));
        assert!(
            !debug.contains("BEGIN PUBLIC KEY"),
            "PEM 不应进日志: {debug}"
        );
    }
}
