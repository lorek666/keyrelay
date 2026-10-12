//! 日志/通知脱敏。**任何**写日志、发通知、拼错误信息之前都要过这里。
//!
//! 覆盖三类凭证：
//! - 站点中继密钥：`sk-` 前缀
//! - NewAPI 应用开户密钥：`nap-` 前缀
//! - 站点 PAT / access_token：32 位以上十六进制串
//! - HTTP 头：`Authorization: Bearer <token>`、`X-App-Secret: <token>`

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
}
