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

/// 与 [`contains_secret`] 相同，但**忽略恰好 64 位的十六进制串**。
///
/// 给「扫自己落盘产物」的审计用（`audit.rs`）。理由：本产品自己的数据库里
/// 合法地存着 **sha256 十六进制哈希**（`journals` 表的 `before_sha256` / `after_sha256`），
/// 它们恰好是 64 位 hex，会被 [`contains_secret`] 的「≥32 位 hex」规则误报。
/// 审计若天天报假警，就等于没有审计。
///
/// **代价（明确记录，复审 P2-1 已补全）**：一条恰好 64 位的十六进制凭证不会被审计发现。
/// 本产品支持的两类中转站（NewAPI / Sub2API）签发的密钥都是 `sk-` 前缀，
/// 不是裸 hex，因此这个代价可接受。事件表那条守护仍然用严格的
/// [`contains_secret`]（那里不该出现哈希）。
pub fn contains_secret_outside_hashes(input: &str) -> bool {
    scrub_ignoring_sha256(input) != input
}

/// 只按**前缀型规则**（`sk-` / `nap-` / `Bearer `）判断，忽略「≥32 位 hex」那条。
///
/// 给**二进制**产物用（数据库 / WAL / SHM）。理由：在字节层面无法区分
/// 「一个 64 位 sha256 哈希」与「哈希后面紧跟一个恰好也是 hex 的字节」——
/// 后者会拼成 65/66 位的 run，任何基于长度的规则都会误报
/// （M4-S1 实测：`journals.after_sha256` 紧邻下一列的 serial-type 字节，run 变成 65/66）。
///
/// # 已知漏报清单（复审 P2-1 实测，**不是**只有「64 位 hex」一种）
///
/// 用这个变体时，下面这些形态**全部**不会被发现：
///
/// | 形态 | 例 |
/// |------|-----|
/// | **任意长度**的裸 hex | 32 / 33 / 64 / 65 / 128 位，**整条 hex 规则都被关掉** |
/// | 前缀后不足 8 个字符 | `sk-` 或 `Bearer ` 后只有 3 / 7 个字符 |
/// | 前缀被 NUL 打断 | `sk-\0<8 字符>`（UTF-16 形态） |
///
/// 前两行同样适用于 [`contains_secret`]（严格变体）：**事件表守护也会漏**「前缀 + 不足
/// 8 字符」这一种。本产品支持的两类中转站（NewAPI / Sub2API）签发的密钥都是
/// `sk-` 加长随机串，因此这个代价可接受；**文本**产物（备份、导出）仍然用完整的
/// [`contains_secret_outside_hashes`]。
///
/// 边界由 `tests` 模块里的 `binary_variant_leak_list_is_pinned` 钉住——
/// 改阈值或改规则时那条测试会红，逼着人回来更新这份清单。
pub fn contains_secret_prefix_only(input: &str) -> bool {
    scrub_prefixes_only(input) != input
}

fn scrub_prefixes_only(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;

    while i < chars.len() {
        let mut matched = false;
        for p in PREFIXES {
            let plen = p.chars().count();
            if i + plen <= chars.len() {
                let candidate: String = chars[i..i + plen].iter().collect();
                if candidate.eq_ignore_ascii_case(p) {
                    let mut j = i + plen;
                    while j < chars.len() && is_token_char(chars[j]) {
                        j += 1;
                    }
                    if j - (i + plen) >= 8 {
                        out.push_str(p);
                        out.push_str(MASK);
                        i = j;
                        matched = true;
                        break;
                    }
                }
            }
        }
        if matched {
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// 与 [`scrub`] 同样的规则，唯一的区别是**恰好 64 位 hex 的片段原样保留**。
///
/// 刻意写成独立的一遍扫描，而不是「先把 64 位 hex 保护起来、最后再调 `scrub`」——
/// 那样最后的 `scrub` 会把刚保护好的哈希又按「≥32 位 hex」规则掩掉
/// （第一版就是这么写的，被 `tests/audit.rs` 的 WAL 扫描抓出来了）。
fn scrub_ignoring_sha256(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;

    while i < chars.len() {
        // 1) 前缀型凭证（sk- / nap- / Bearer），规则与 `scrub` 完全一致
        let mut matched_prefix = false;
        for p in PREFIXES {
            let plen = p.chars().count();
            if i + plen <= chars.len() {
                let candidate: String = chars[i..i + plen].iter().collect();
                if candidate.eq_ignore_ascii_case(p) {
                    let mut j = i + plen;
                    while j < chars.len() && is_token_char(chars[j]) {
                        j += 1;
                    }
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

        // 2) 十六进制串：64 位视为哈希（保留），32..63 位视为疑似凭证（掩掉）
        if chars[i].is_ascii_hexdigit() {
            let mut j = i;
            while j < chars.len() && chars[j].is_ascii_hexdigit() {
                j += 1;
            }
            let run_len = j - i;
            if run_len == 64 {
                out.extend(&chars[i..j]);
            } else if run_len >= 32 {
                out.push_str(MASK);
            } else {
                out.extend(&chars[i..j]);
            }
            i = j;
            continue;
        }

        out.push(chars[i]);
        i += 1;
    }

    out
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
    fn sha256_length_hex_is_ignored_only_by_the_audit_variant() {
        // 64 位 hex 是 sha256 的形态，本产品自己的 journals 表里合法存在
        let hash = "a".repeat(64);
        assert!(
            contains_secret(&hash),
            "严格判定仍然把 64 位 hex 当成疑似凭证（事件表守护用）"
        );
        assert!(
            !contains_secret_outside_hashes(&hash),
            "审计变体必须放过 64 位 hex，否则数据库里的哈希会天天误报"
        );
    }

    #[test]
    fn audit_variant_preserves_a_hash_even_next_to_other_text() {
        // 第一版把「保护 64 位 hex」与「最后再 scrub 一遍」拼在一起，
        // 结果最后的 scrub 又把哈希掩掉了。这条测试钉住「哈希必须原样保留」。
        let hash = "0162a23f41168cb4ca6083c8aac019a5a07ad7a8b1c2d3e4f5061728394a5b6c";
        assert_eq!(hash.len(), 64);
        let line = format!("/home/me/.codex/auth.json{hash}");
        assert_eq!(
            scrub_ignoring_sha256(&line),
            line,
            "64 位哈希必须原样保留（哪怕是紧跟在文件路径后面）"
        );
        assert!(!contains_secret_outside_hashes(&line));
    }

    #[test]
    fn prefix_only_variant_ignores_hashes_entirely() {
        // 二进制产物里哈希与相邻字节会拼成长 run，任何长度规则都会误报
        let hash_with_neighbour = format!("{}7", "a".repeat(64));
        assert!(!contains_secret_prefix_only(&hash_with_neighbour));
        assert!(!contains_secret_prefix_only(&"a".repeat(32)));
        // 但真实密钥仍然要抓
        assert!(contains_secret_prefix_only("sk-abcdefgh12345678"));
        assert!(contains_secret_prefix_only("Bearer eyJhbGciOiJ"));
        assert!(!contains_secret_prefix_only("普通文本 12.5 USD"));
    }

    /// 把「已知漏报」钉死（复审 P2-1）。
    ///
    /// 这条测试**断言的是漏报**，看起来像写反了——它是在给代价记账：
    /// 哪天有人改了阈值或规则，这里会红，逼着人回来同步
    /// [`contains_secret_prefix_only`] 的文档清单，而不是让代价悄悄变化。
    #[test]
    fn binary_variant_leak_list_is_pinned() {
        // ① 整条 hex 规则被关掉：**任意长度**的裸 hex 都漏
        for len in [32usize, 33, 64, 65, 128] {
            let hex = "a".repeat(len);
            assert!(
                !contains_secret_prefix_only(&hex),
                "{len} 位裸 hex 在二进制变体里应漏报（已知代价）"
            );
            assert!(contains_secret(&hex), "{len} 位裸 hex 在严格变体里必须被抓");
        }

        // ② 前缀后不足 8 个字符：三个变体全漏（含事件表守护用的严格变体）
        for short in ["sk-abc", "sk-abcdefg", "Bearer abc", "Bearer abcdefg"] {
            assert!(
                !contains_secret_prefix_only(short),
                "「{short}」不足 8 字符，二进制变体应漏报"
            );
            assert!(
                !contains_secret_outside_hashes(short),
                "「{short}」不足 8 字符，审计变体应漏报"
            );
            assert!(
                !contains_secret(short),
                "「{short}」不足 8 字符，严格变体也应漏报 —— 事件表守护同样盖不住这种形态"
            );
        }

        // ③ 边界另一侧：正好 8 个字符就必须抓到，否则阈值漂了没人知道
        assert!(contains_secret_prefix_only("sk-abcdefgh"));
        assert!(contains_secret_prefix_only("Bearer abcdefgh"));
        assert!(contains_secret("sk-abcdefgh"));
    }

    #[test]
    fn audit_variant_still_catches_real_secrets() {
        assert!(contains_secret_outside_hashes(
            "OPENAI_API_KEY=sk-abcdefgh12345678"
        ));
        assert!(contains_secret_outside_hashes(
            "X-App-Secret: nap-0123456789abcdef"
        ));
        assert!(contains_secret_outside_hashes(
            "Authorization: Bearer eyJhbGciOiJ"
        ));
        // 32..63 位 hex 仍然算（那是 PAT 的长度区间）
        assert!(contains_secret_outside_hashes(&"b".repeat(32)));
        assert!(contains_secret_outside_hashes(&"b".repeat(40)));
        // 正常文本不误伤
        assert!(!contains_secret_outside_hashes(
            "站点 example 余额 12.5 USD"
        ));
        // 哈希与密钥混在一行时仍要抓出来
        let mixed = format!("{} sk-abcdefgh12345678", "c".repeat(64));
        assert!(contains_secret_outside_hashes(&mixed));
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
