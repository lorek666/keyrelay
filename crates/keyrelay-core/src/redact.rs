//! 日志/通知脱敏。**任何**写日志、发通知、拼错误信息之前都要过这里。
//!
//! 覆盖三类凭证：
//! - 站点中继密钥：`sk-` 前缀
//! - NewAPI 应用开户密钥：`nap-` 前缀
//! - 站点 PAT / access_token：32 位以上十六进制串
//! - HTTP 头：`Authorization: Bearer <token>`、`X-App-Secret: <token>`

use sha2::{Digest, Sha256};

pub const MASK: &str = "***";

const PREFIXES: [&str; 3] = ["sk-", "nap-", "Bearer "];

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~' | '+' | '/')
}

/// 把输入串里的凭证替换为掩码，其余内容原样保留。
///
/// 该函数是幂等的：对已脱敏的文本再次调用结果不变。
pub fn scrub(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes: Vec<char> = input.chars().collect();
    let mut i = 0usize;

    while i < bytes.len() {
        // 1) 前缀型凭证
        let mut matched_prefix = false;
        for p in PREFIXES {
            let plen = p.chars().count();
            if i + plen <= bytes.len() {
                let candidate: String = bytes[i..i + plen].iter().collect();
                if candidate.eq_ignore_ascii_case(p) {
                    let mut j = i + plen;
                    while j < bytes.len() && is_token_char(bytes[j]) {
                        j += 1;
                    }
                    // 前缀后至少要有 8 个字符才视为凭证，避免误伤 "sk-" 之类的普通文本
                    if j - (i + plen) >= 8 {
                        out.push_str(p);
                        out.push_str(MASK);
                        i = j;
                        matched_prefix = true;
                        break;
                    }
                }
            }
        }
        if matched_prefix {
            continue;
        }

        // 2) 32 位以上十六进制串（PAT / session token）
        if bytes[i].is_ascii_hexdigit() {
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j - i >= 32 {
                out.push_str(MASK);
                i = j;
                continue;
            }
        }

        out.push(bytes[i]);
        i += 1;
    }

    out
}

/// 判断一段文本中是否**可能**仍含未脱敏凭证（用于测试与运行时自检）。
pub fn contains_secret(input: &str) -> bool {
    scrub(input) != input
}

/// 展示用掩码：只保留末 4 个字符，前缀一律用 `…` 代替。
///
/// 按 `char` 截取（不按 byte），因此不会切断多字节字符。
/// 长度不足 8 个 `char` 时只返回 `…`——短密钥的末 4 位已经占了一半以上，不能再给。
pub fn mask_secret(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() < 8 {
        return "…".to_string();
    }
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("…{tail}")
}

/// 比对用指纹：`sha256(secret)` 的前 8 个 hex 字符。
///
/// 用于回答「这两把钥匙是不是同一把」而不暴露明文；不可逆，也不能用来恢复密钥。
pub fn fingerprint(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    hex::encode(digest)[..8].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_sk_key() {
        let s = scrub("OPENAI_API_KEY=sk-abc123DEF456ghi789 done");
        assert_eq!(s, "OPENAI_API_KEY=sk-*** done");
        assert!(!s.contains("abc123"));
    }

    #[test]
    fn masks_nap_and_bearer() {
        assert_eq!(
            scrub("X-App-Secret: nap-0123456789abcdef"),
            "X-App-Secret: nap-***"
        );
        assert_eq!(
            scrub("Authorization: Bearer eyJhbGciOi.payload.sig"),
            "Authorization: Bearer ***"
        );
    }

    #[test]
    fn masks_long_hex_pat() {
        let pat = "a".repeat(32);
        let s = scrub(&format!("token={pat}"));
        assert_eq!(s, "token=***");
    }

    #[test]
    fn keeps_normal_text_intact() {
        let s = "站点 example 余额 12.5 USD，key 数 3";
        assert_eq!(scrub(s), s);
        assert!(!contains_secret(s));
    }

    #[test]
    fn is_idempotent() {
        let once = scrub("k=sk-abcdefgh12345678");
        let twice = scrub(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn short_hex_not_masked() {
        // 16 位 hex 是常见的 id，不应误伤
        assert_eq!(scrub("id=deadbeefdeadbeef"), "id=deadbeefdeadbeef");
    }

    #[test]
    fn mask_secret_boundaries() {
        assert_eq!(mask_secret("sk-0123456789abcdef"), "…cdef");
        assert_eq!(mask_secret("abcdefg"), "…"); // 7 char
        assert_eq!(mask_secret("abcdefgh"), "…efgh"); // 8 char
        assert_eq!(mask_secret(""), "…");
        assert_eq!(mask_secret("密钥abcd"), "…"); // 6 char，不足 8
        assert_eq!(mask_secret("密钥abcdefgh"), "…efgh"); // 10 char
    }

    #[test]
    fn mask_secret_never_leaks_more_than_four_chars() {
        let secret = "sk-0123456789abcdef";
        let masked = mask_secret(secret);
        // 掩码里最多出现原文末 4 位；前缀、中段一律不得出现
        assert!(!masked.contains("sk-"));
        assert!(!masked.contains("0123456789"));
        assert_eq!(masked.chars().count(), 5);
    }

    #[test]
    fn mask_secret_does_not_split_utf8() {
        // 4 字节 emoji 也必须整字符截取：8 个 emoji → 保留末 4 个
        assert_eq!(mask_secret("😀😀😀😀😀😀😀😀"), "…😀😀😀😀");
        assert_eq!(mask_secret("abcdefghij😀😀"), "…ij😀😀");
    }

    #[test]
    fn fingerprint_is_stable_and_hides_plaintext() {
        let a = fingerprint("sk-0123456789abcdef");
        assert_eq!(a, fingerprint("sk-0123456789abcdef"));
        assert_ne!(a, fingerprint("sk-0123456789abcde0"));
        assert_eq!(a.len(), 8);
        assert!(!a.contains("sk-"));
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
