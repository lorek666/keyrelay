//! 日志/通知脱敏。**任何**写日志、发通知、拼错误信息之前都要过这里。
//!
//! 覆盖三类凭证：
//! - 站点中继密钥：`sk-` 前缀
//! - NewAPI 应用开户密钥：`nap-` 前缀
//! - 站点 PAT / access_token：32 位以上十六进制串
//! - HTTP 头：`Authorization: Bearer <token>`、`X-App-Secret: <token>`
//! - URL 内嵌凭证：`scheme://user:pass@host` 的 userinfo（B-63）

use sha2::{Digest, Sha256};

pub const MASK: &str = "***";

const PREFIXES: [&str; 3] = ["sk-", "nap-", "Bearer "];

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~' | '+' | '/')
}

fn is_base64url_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_')
}

/// 裸 JWT（P3-19）：`eyJ` 开头的三段 base64url，用 `.` 分隔。
///
/// 为什么需要单独一条：JWT 不是 `sk-` / `nap-` 前缀，也不是 ≥32 位纯 hex
/// （base64url 含 `-` `_`，而且被 `.` 打断），现有三条规则**一条都不认** ——
/// 站点 400 正文里回显的 token 会原样进错误文案与事件表（DEBUG-REPORT-v3 §3-19）。
///
/// 判据（宁可多掩）：`eyJ` + 第一段 ≥8 + `.` + ≥4 + `.` + ≥4，全部是 base64url 字符。
/// `eyJ` 是 `{"` 的 base64 前缀，正常文本里几乎不会出现；真出现也只是多掩一段**显示**。
fn mask_jwt_tokens(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < chars.len() {
        match jwt_end_at(&chars, i) {
            Some(end) => {
                out.push_str(MASK);
                i = end;
            }
            None => {
                out.push(chars[i]);
                i += 1;
            }
        }
    }
    out
}

/// `i` 处是一个裸 JWT 的起点吗？是则返回它的结束下标（不含）。
fn jwt_end_at(chars: &[char], i: usize) -> Option<usize> {
    if i + 3 > chars.len() || chars[i] != 'e' || chars[i + 1] != 'y' || chars[i + 2] != 'J' {
        return None;
    }
    let mut j = i + 3;
    for segment in 0..3 {
        let start = j;
        while j < chars.len() && is_base64url_char(chars[j]) {
            j += 1;
        }
        let min = if segment == 0 { 8 } else { 4 };
        if j - start < min {
            return None;
        }
        if segment < 2 {
            if j < chars.len() && chars[j] == '.' {
                j += 1;
            } else {
                return None;
            }
        }
    }
    Some(j)
}

/// 值的分隔符：到这些字符为止（`password=hunter2&user=x` ⇒ 值只取 `hunter2`）。
fn is_value_delimiter(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '&' | ';' | ',' | '"' | '\'' | '<' | '>' | '`' | '\\' | ')' | ']' | '}' | '/'
        )
}

/// 文本形态的「敏感键 = 值」（P3-19：`password=hunter2`、`token: abc`、`pwd=…`）。
///
/// 与 [`scrub_payload`] 的键名规则**同源**（[`SENSITIVE_KEYS`]），但作用于**自由文本**：
/// 站点 400 正文里回显的表单/查询串就是这种形态，而 JSON 键名规则认不出它。
///
/// 键名要求词边界（与 P2-26 同口径：前一个输出字符是字母数字 ⇒ 是词中间，不认），
/// 键名与分隔符之间允许空格，分隔符是 `=` 或 `:`。
///
/// **不做**的事（明确边界）：没有键名的**裸口令**（`hunter2` 单独出现）不可判定 ——
/// 任何「看起来像口令」的启发式都会把正常文本吃成 `***`。见 spec §9 风险 8。
fn mask_sensitive_key_values(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < chars.len() {
        // 词边界：前一个输出字符是**词内字符**（字母数字 / `_` / `-`）⇒ 说明在词中间。
        // 这里比前缀规则的判据多算 `_` 与 `-`：`OPENAI_API_KEY=…` 里的 `API_KEY`
        // 不是独立键名（`OPENAI_API_KEY` 归一化后是 `openaiapikey`，不在命中集合里），
        // 只按字母数字判会把 `API_KEY` 单独认出来、把 `sk-…` 掩成 `***`（既有用例抓过）。
        let at_word_start = !out
            .chars()
            .last()
            .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'));
        if at_word_start {
            if let Some((key_end, value_start, value_end)) = sensitive_key_value_at(&chars, i) {
                out.extend(chars[i..key_end].iter());
                out.extend(chars[key_end..value_start].iter());
                out.push_str(MASK);
                i = value_end;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// `i` 处是 `敏感键<空格?><=|:><空格?>值` 吗？返回 `(键结束, 值开始, 值结束)`。
fn sensitive_key_value_at(chars: &[char], i: usize) -> Option<(usize, usize, usize)> {
    let mut j = i;
    while j < chars.len() && (chars[j].is_ascii_alphanumeric() || matches!(chars[j], '_' | '-')) {
        j += 1;
    }
    if j == i {
        return None;
    }
    let key: String = chars[i..j].iter().collect();
    if !is_sensitive_key(&key) {
        return None;
    }
    // P1（S2 复审）：JSON 形态 `"password":"x"` —— 键名与分隔符之间**允许一个 `"`**。
    //
    // 为什么这是**可判定**形态、不属于「裸口令不可判定」那一类：键名精确命中集合、
    // 后面紧跟 `=`/`:`，中间只多了一个 JSON 的键引号。非法 JSON 载荷会走文本层兜底
    // （`scrub_event_payload` 的 fallback），而文本层以前要求键名**紧贴**分隔符 ⇒
    // `"password":"hunter2"` 不命中 ⇒ 首遍漏掩；等 URL 被掩掉、整串变成合法 JSON 之后，
    // 第二遍才走结构化路径掩上 ⇒ 两遍不一致（复审 R2 实测）。
    let mut k = j;
    if k < chars.len() && chars[k] == '"' {
        k += 1;
    }
    while k < chars.len() && chars[k] == ' ' {
        k += 1;
    }
    if k >= chars.len() || !matches!(chars[k], '=' | ':') {
        return None;
    }
    k += 1;
    while k < chars.len() && chars[k] == ' ' {
        k += 1;
    }
    // 值的**开引号**同样允许一个（`":"hunter2"`）；值的结束由 `"` 这个分隔符自然划出，
    // 因此闭引号会留在原地（`"password":"***"` 结构不破）。
    if k < chars.len() && chars[k] == '"' {
        k += 1;
    }
    if k >= chars.len() {
        return None;
    }
    let value_start = k;
    let mut v = k;
    while v < chars.len() && !is_value_delimiter(chars[v]) {
        v += 1;
    }
    if v == value_start {
        return None;
    }
    // `Authorization: Bearer <token>` —— 值是**方案名**，不是凭证本身。
    // 这里必须让路：掩掉 `Bearer` 反而会把后面的 token 留在原地（前缀规则 `Bearer `
    // 本来就是干这个的，有既有用例钉着 `Authorization: Bearer ***`）。
    let value: String = chars[value_start..v].iter().collect();
    if matches!(
        value.to_ascii_lowercase().as_str(),
        "bearer" | "basic" | "digest"
    ) {
        return None;
    }
    Some((j, value_start, v))
}

/// 把输入串里的凭证替换为掩码，其余内容原样保留。
///
/// 该函数是幂等的：对已脱敏的文本再次调用结果不变。
///
/// 顺序（每一层都在**前一层产物**上跑，四层各自幂等）：
/// 1. URL userinfo（文本层）；
/// 2. 裸 JWT（P3-19：站点 400 正文里回显的 `eyJ….….…`）；
/// 3. `敏感键=值` / `敏感键: 值` 的**文本**形态（P3-19：表单式回显的明文口令）；
/// 4. 前缀型密钥 / ≥32 位 hex。
pub fn scrub(input: &str) -> String {
    // URL 规则在**原文**上先跑一遍：前缀规则的 token 字符含 `/`，会把外层路径连同内层 URL 的
    // scheme 一起吞掉，吞完之后内层的 `://` 就不在了（第二次复核 R-1）。
    let input = &mask_url_userinfo(input);
    // P3-19：裸 JWT 与 `password=…` 这类**文本形态**的明文口令（报告 §3-19：scrub 不认它们）
    let input = &mask_sensitive_key_values(&mask_jwt_tokens(input));
    let mut out = String::with_capacity(input.len());
    let bytes: Vec<char> = input.chars().collect();
    let mut i = 0usize;

    while i < bytes.len() {
        // 1) 前缀型凭证
        let mut matched_prefix = false;
        for p in PREFIXES {
            let plen = p.chars().count();
            if i + plen <= bytes.len() {
                // P2-26：前缀必须在词边界处——看**已输出的**末尾字符，若是字母数字，
                // 说明是词中间（如 `desk-assistant` 里的 `sk-`），不得当成密钥前缀。
                // 看输出而非原文前一个字符：前一个 token 可能已被掩成 `***`（非字母数字），
                // 此时紧接的 `sk-` 是新 token（如 32 位 hex 后的 `sk-`），应掩。
                if out
                    .chars()
                    .last()
                    .is_some_and(|c| c.is_ascii_alphanumeric())
                {
                    continue;
                }
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

    // 收尾再跑一遍：`sk-…/p@x` 被前缀规则整段吞成 `sk-***` 之后，`@` 贴到了 authority 上；
    // 不在这里掩掉，就要等第二遍 `scrub` 才掩，幂等就破了（复核 N-1）。
    // 两遍都需要：只留开头漏嵌套 URL，只留收尾破幂等。
    mask_url_userinfo(&out)
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
                // P2-26：前缀必须在词边界处——看**已输出的**末尾字符，若是字母数字，说明是词中间
                //（如 `desk-assistant` 里的 `sk-`），不得当成密钥前缀。看输出而非原文前一个
                // 字符：前一个 token 可能已被掩成 `***`，此时紧接的 `sk-` 是新 token，应掩。
                if out
                    .chars()
                    .last()
                    .is_some_and(|c| c.is_ascii_alphanumeric())
                {
                    continue;
                }
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
                // P2-26：前缀必须在词边界处——看**已输出的**末尾字符，若是字母数字，说明是词中间
                //（如 `desk-assistant` 里的 `sk-`），不得当成密钥前缀。看输出而非原文前一个
                // 字符：前一个 token 可能已被掩成 `***`，此时紧接的 `sk-` 是新 token，应掩。
                if out
                    .chars()
                    .last()
                    .is_some_and(|c| c.is_ascii_alphanumeric())
                {
                    continue;
                }
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

/// 剥掉 URL 的 userinfo：`https://user:pass@relay.example.com/x` → `https://relay.example.com/x`。
///
/// 语义（M5-S0 章程 §4.3 冻结）：
/// - 没有 `://` → **逐字节不变**（不猜、不补 scheme，含 `user:pass@host` 这种形态）；
/// - 有 `://` 但 authority 段里没有 `@` → **逐字节不变**；
/// - authority 段 = `://` 之后到第一个 `/` / `?` / `#` 之前，因此 query/fragment 里的 `@`
///   不算 userinfo（`https://host/p?q=a@b` 原样返回）；
/// - authority 里有多个 `@` 时删到**最后一个** `@`：`https://a@b:pw@host/` 若按第一个 `@` 切，
///   留下的是 `b:pw@host/` —— 密码仍在串里。宁可多删。
///
/// 用途：站点 `base_url` 可能带内嵌凭证（B-63），导出物里不能原样带出去。
pub fn strip_url_userinfo(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let authority_start = scheme_end + "://".len();
    let rest = &url[authority_start..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let Some(at) = authority.rfind('@') else {
        return url.to_string();
    };

    let mut out = String::with_capacity(url.len());
    out.push_str(&url[..authority_start]);
    out.push_str(&authority[at + 1..]);
    out.push_str(&rest[authority_end..]);
    out
}

/// 可安全回显的 webhook 地址：`scheme://host[:port]`，**userinfo / path / query / fragment 一律丢掉**。
///
/// webhook URL 的凭据常在 path / query 里（Slack `/services/T/B/<token>`、Discord
/// `?key=<uuid>`），[`strip_url_userinfo`] 只剥 userinfo 不够（P1-10）。本函数收窄到
/// authority，与 `notify::webhook` 的错误文案同口径。
pub fn mask_webhook_url(url: &str) -> String {
    let stripped = strip_url_userinfo(url);
    let Some((scheme, rest)) = stripped.split_once("://") else {
        return "<无 scheme>".to_string();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return format!("{scheme}://<已隐藏>");
    }
    format!("{scheme}://{authority}")
}

/// authority 段的结束位置：**终止符**与**内嵌的下一个 `://`** 取更早者，都没有则到串尾。
///
/// 为什么要单独认内嵌 `://`（P2-24 形态①）：`https://a.example.comhttps://u:p@h/x` 里
/// 第一个 URL 没有路径，只按 `/` 找 authority 会停在第二个 URL 的 `//` 上，把它的 `://`
/// 一起吃掉 —— 之后串里再没有 `://`，第二个 URL 永远不被认出，userinfo 原样留下
/// （缩放模糊矩阵实测：这类形态两层都漏 18/72）。收口在 `://` 之前，循环下一轮就能从它重新开始。
///
/// `text_mode`：文本层的 authority 还要止于空白与 `"` `<` `>` `` ` `` `\`（JSON 里的
/// `"https://u:p@h"` 不能把结尾引号吃进 authority）；结构化层知道值在哪儿结束，
/// 不需要这些终止符（引号、空格在口令里是合法的，见 P2-25）。
fn authority_end(tail: &str, text_mode: bool) -> usize {
    let by_scheme = tail.find("://").unwrap_or(tail.len());
    let by_stop = if text_mode {
        tail.find(|c: char| {
            matches!(c, '/' | '?' | '#' | '"' | '<' | '>' | '`' | '\\') || c.is_whitespace()
        })
        .unwrap_or(tail.len())
    } else {
        tail.find(['/', '?', '#']).unwrap_or(tail.len())
    };
    by_scheme.min(by_stop)
}

/// 文本层与结构化层**共用**的 URL userinfo 掩蔽循环：唯一差别是 `text_mode` 的终止符集合。
///
/// 两层同源（M16-S2 收敛）：以前两层各写一份循环，形态① 的收口只改一处就会让两层分叉 ——
/// 而「两层结果必须一致」正是 P2-24 的判据。
///
/// **不再对 scheme 做任何校验**（P2-24 形态② 与形态① 的交汇点）：以前结构化层要求
/// 「scheme 以字母开头」，`1https://u:p@h`（粘连）与 `…comhttps://u:p@h`（前一个 URL 不带
/// 路径时 scheme 被吃进上一个 authority）这两种形态都会被短路掉，于是**结构化层比文本层
/// 掩得少**。掩码只在 authority 里确实有 `@` 时才发生，因此「去掉校验」不会误伤普通文本
/// （代价见下）。
///
/// 每个 `://` **之前**那一段也会过一遍 [`mask_scheme_less`]：站点地址允许无 scheme 录入，
/// `carol:pw@host/path?next=https://…` 里第一段自己就带 userinfo（P3-22 第二种形态）。
///
/// 循环每一步都保证前进（`end == 0` 时显式吃掉一个 `://`），否则 `a://://u:p@h` 这类
/// 输入会让 `rest` 不变而死循环。
fn mask_urls(input: &str, text_mode: bool) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find("://") {
        // `://` 之前那一段也过一遍：它可能本身就是**无 scheme 的地址**
        // （`carol:pw@host/path?next=https://…`），不能原样推出去（P3-22 第二种形态）。
        out.push_str(&mask_scheme_less(&rest[..pos], text_mode, true));
        let authority_start = pos + "://".len();
        out.push_str(&rest[pos..authority_start]);
        let tail = &rest[authority_start..];
        match userinfo_end(tail, text_mode) {
            Some(at) => {
                // 掩掉 userinfo（R1 延长时连中间那段一起掩），主机段原样推出，
                // 从 authority 结束处继续扫（后面可能还有下一个 URL）。
                // `at` 可能落在 authority 之外（R1），所以取 `max` 保证切片合法且前进。
                let end = authority_end(tail, text_mode).max(at + 1);
                out.push_str(MASK);
                out.push_str(&tail[at..end]);
                rest = &tail[end..];
            }
            None => {
                let end = authority_end(tail, text_mode);
                if end == 0 {
                    // authority 立刻又被一个 `://` 截住（`a://://u:p@h`）：先把这一个 `://`
                    // 吐出去，从它之后继续。少了这一步 `rest` 不变，循环不前进。
                    rest = tail;
                    continue;
                }
                out.push_str(&tail[..end]);
                rest = &tail[end..];
            }
        }
    }
    // 整串已经不含 `://` 了：文本层在这里只跑 R1（「不猜 userinfo」的契约）。
    out.push_str(&mask_scheme_less(rest, text_mode, !text_mode));
    out
}

/// 一段**无 scheme 的地址**里的 userinfo ⇒ 换成 [`MASK`]。
///
/// 站点地址允许无 scheme 录入（`carol:pw@host`、`host:8080/path`），transport 调用方也会把
/// `user:pass@host` 这类串直接丢进来；`mask_urls` 的循环只认 `://`，因此这些段要单独过。
///
/// 两个开关是**正交**的：
/// - `text_mode`：终止符集合（文本层还止于空白/引号）；
/// - `primary`：是否允许**主规则**（候选段里有 `@` 就掩）。文本层的契约是「**整串**没有
///   `://` 就不猜 userinfo」——`user:pass@host`、`someone@example.com`、`mailto:…` 一律不动
///   （有既有用例钉着），所以整串那一趟只跑 R1；但**一个已经含 `://` 的串**里，
///   `://` 之前那段（`carol:pw@host/path?next=https://…`）是地址的一部分，主规则照跑。
fn mask_scheme_less(span: &str, text_mode: bool, primary: bool) -> String {
    let end = authority_end(span, text_mode);
    let candidate = &span[..end];
    // **字符串化的 JSON** 不当地址处理：`{"url":"…@…"}` 这种文本会被
    // `mask_url_userinfo_in_json` 在整行上再跑一遍（诊断包就有一处），按地址口径掩会把
    // 结构吃掉（`***@relay.example.com"}`）——它的结构由调用方逐字段处理，不该在这里动。
    // 只挡**以 `{` / `[` 开头**的候选：`carol:p"w@host`（口令里有引号）必须照掩。
    let looks_like_json = candidate.trim_start().starts_with(['{', '[']);
    let found = if looks_like_json {
        None
    } else {
        match candidate.rfind('@') {
            Some(at) if primary => Some(at),
            _ => extended_userinfo_end(span, end, text_mode),
        }
    };
    match found {
        Some(at) => {
            // P2（S2 复审）：`email=a@b` —— 掩到 `@` 会把**键名一起吃掉**（`***@b`），
            // 排障时看不出原来是什么字段。若同一个**无空白 token** 里、`@` 之前有
            // `键名=`，掩码从 `=` 之后开始（键名保留，值照掩）。
            // 只在同一 token 内生效：`见 x=1 与 u:p@h` 这种跨空白的形态不动（保持原行为）。
            let mask_start = key_name_start_in_token(span, at).unwrap_or(0);
            format!("{}{MASK}{}", &span[..mask_start], &span[at..])
        }
        None => span.to_string(),
    }
}

/// `at`（一个 `@`）所在的**无空白 token** 里，`@` 之前最后一个 `键名=` 的值起点。
///
/// 返回 `Some(= 之后的位置)` 当且仅当：该 `=` 与 `@` 在同一个无空白 token 内，
/// 且 `=` 前面紧邻一段非空键名字符（`[A-Za-z0-9_.-]`）。否则 `None`（保持「从 span 起点掩」）。
fn key_name_start_in_token(span: &str, at: usize) -> Option<usize> {
    let chars: Vec<char> = span.chars().collect();
    let at_char = span[..at].chars().count();
    // token 起点：`@` 往前第一个空白之后
    let mut token_start = at_char;
    while token_start > 0 && !chars[token_start - 1].is_whitespace() {
        token_start -= 1;
    }
    // token 内 `@` 之前最后一个 `=`
    let eq = (token_start..at_char).rev().find(|&k| chars[k] == '=')?;
    // `=` 前面必须紧邻非空键名（否则 `=a@b` 这种没有键名的形态不动）
    let mut key_start = eq;
    while key_start > token_start
        && (chars[key_start - 1].is_ascii_alphanumeric()
            || matches!(chars[key_start - 1], '_' | '.' | '-'))
    {
        key_start -= 1;
    }
    if key_start == eq {
        return None;
    }
    // 字节偏移（`at` 是字节索引，转回字节位置）
    let byte = span
        .char_indices()
        .nth(eq + 1)
        .map(|(b, _)| b)
        .unwrap_or(span.len());
    Some(byte)
}

/// 在 `tail`（`://` 之后，或一段无 scheme 的候选）里找 userinfo 的 `@` 位置。
///
/// - 候选段（[`authority_end`] 划出的那一截）里有 `@` ⇒ 取**最后一个** `@`（`a@b:pw@host`
///   不能漏，这是既有口径）；
/// - 候选段里没有 `@`，但同一个 token 后面有（R1 / P3-22 第一种形态：口令里有**未编码**的
///   `/` `?` `#`）⇒ 延长到那个 `@`（见 [`extended_userinfo_end`]）。
fn userinfo_end(tail: &str, text_mode: bool) -> Option<usize> {
    let end = authority_end(tail, text_mode);
    if let Some(at) = tail[..end].rfind('@') {
        return Some(at);
    }
    extended_userinfo_end(tail, end, text_mode)
}

/// R1（P3-22 第一种形态）：口令里有**未编码**的 `/` `?` `#`，于是 authority 候选段里没有
/// `@`、`@` 落在候选段之外（`carol:p/ss@host`）。按 URL 语法 authority 真的在 `/` 处结束，
/// 但那是畸形输入，口令会原样显示 —— 宁可多掩。
///
/// 判据**收窄**到四条，避免把正常 URL/普通文本误掩（都有既有用例钉着）：
/// 1. 候选段里**没有** `@`（有 `@` 是主规则的活，`user:pass@host` 因此不受影响）；
/// 2. 候选段里出现过 `:`（userinfo 分隔符）——`https://host/a@b` 的候选段是 `host`，没有 `:`；
/// 3. 最后一个 `:` 之后**不是纯数字**（排除端口）——`https://host:8080/a@b` 不动；
/// 4. 延长段的搜索窗口：文本层止于空白/引号（一句普通的话 `错误: 路径 /tmp/a@b` 不会被吃）；
///    结构化层看到的是**一整段值**，可以一直往后找 —— 否则
///    `站点地址 carol:p/ss@host 不可用` 这种「散文 + 无 scheme 地址」会漏。
fn extended_userinfo_end(tail: &str, end: usize, text_mode: bool) -> Option<usize> {
    let candidate = &tail[..end];
    if candidate.contains('@') {
        return None;
    }
    let lookahead_end = if text_mode {
        tail.find(|c: char| c.is_whitespace() || matches!(c, '"' | '<' | '>' | '`' | '\\'))
            .unwrap_or(tail.len())
    } else {
        tail.len()
    };
    let at = tail[..lookahead_end].rfind('@')?;
    let colon = candidate.rfind(':')?;
    let after_colon = &candidate[colon + 1..];
    if after_colon.is_empty() || after_colon.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(at)
}

/// [`strip_url_userinfo`] 的**掩蔽**版：authority 里的 userinfo 换成 [`MASK`]。
///
/// 与 [`strip_url_userinfo`] 的分工（M8-S2 §7.2 O-1 裁决）：
/// - `strip_url_userinfo`：输入是**一整个 URL**，userinfo **整段删掉**（导出物用）。
///   没有 `://` 时它**不猜**——那是它的契约，不改；
/// - 本函数：输入是**已知是 URL 或 authority** 的东西（站点 `base_url`、`{base}/api/status`
///   这种拼出来的地址），**没有 `://` 也要处理**——`carol:pw@host.example` 这种录入形态
///   必须能被掩住，否则它会原样进错误文案（复核 N-2 的第二种形态）。
///
/// 规则（**宁可多掩**：掩错了只影响显示，漏掩是泄漏）：
/// - 有 `://`：authority 段（`://` 之后到第一个 `/` / `?` / `#`）里**最后一个** `@` 之前
///   的部分换成 `***`；
/// - 无 `://`：把**第一个 `/` 之前**那一段当作 authority，同样处理
///   （`carol:pw@host.example/x` ⇒ `***@host.example/x`）；
/// - 没有 `@` ⇒ **逐字节不变**（`https://host/a@b` 不动：那个 `@` 在路径里，不是 userinfo）。
pub fn mask_authority_userinfo(raw: &str) -> String {
    // 复审 F4：原实现只处理首个 `://`，多 URL 文本会把两 URL 间内容吃进首个
    // authority、`rfind('@')` 取最后一个 @，塌缩成 `prefix://***@h_last`。改成循环，
    // 每个 `scheme://authority` 独立掩。无 `://` 时走「整串即 authority」分支（transport
    // 调用方会传 `user:pass@host` 这类无 scheme 的串，循环 find("://") 失败会原样返回，
    // 丢失这层掩码——所以单独处理）。
    if !raw.contains("://") {
        // 无 scheme 的地址（`carol:pw@host`、`host:8080/path`）走同一条实现：
        // P3-22 的第一种形态（口令里带未编码的 `/` `?` `#`）就落在这一支里。
        return mask_scheme_less(raw, false, true);
    }
    // 有 `://` 时与结构化层走**同一条实现**：authority 止于 `/` `?` `#` 与内嵌的下一个
    // `://`，**不**截 `"` `\` 空白 —— 那正是本函数存在的理由（`scrub` 在 `"` 处截断会漏
    // 带引号密码的 URL，见 P2-25）。
    mask_urls(raw, false)
}

/// [`scrub`] 的首尾两步：**文本里**每个 `scheme://userinfo@host` 的 userinfo 换成 [`MASK`]。
///
/// 与 [`strip_url_userinfo`] 的区别：那个函数的输入是**一整个 URL**，这里的输入是
/// 任意文本（事件文案、序列化后的 payload、错误信息），所以 authority 除了止于
/// `/` `?` `#`，还止于空白、双引号、尖括号、反引号与反斜杠——否则 JSON 里的
/// `"https://u:p@h"` 会把结尾引号吃进 authority。这几个字符 RFC 3986 都不允许裸出现在
/// userinfo 里，URL 解析器（`reqwest`）序列化时会转成 `%XX`。
///
/// **不**在单引号与 `,` `;` `(` `)` 等 sub-delims 处截断：它们在 userinfo 里是合法的、
/// 解析后原样保留，截断就会把 `p'w@host` 切成没有 `@` 的片段而整段放行（独立复审 P2-1）。
/// 代价是相邻文本里的 `@` 偶尔被多掩一段——只影响显示，不泄漏。
///
/// 结构化值里**值内任意位置**的 URL 另走 [`mask_any_url_userinfo`]：那里知道值在哪儿结束，
/// 不需要靠上面这些终止符去猜。两层同源（[`mask_urls`]），只有终止符集合不同。
///
/// 为什么放在 `scrub` 里而不是各调用点（B-63 只剥了导出的 `sites[].base_url`）：
/// 事件 payload 原样记着 `base_url`，按调用点剥就一定会漏一处；`scrub` 是
/// 事件 / 通知 / 错误的共同咽喉点。没有 `://` 的形态（`user@host`、邮箱）**不猜**。
fn mask_url_userinfo(input: &str) -> String {
    mask_urls(input, true)
}

/// **结构化层**的 URL userinfo 掩蔽：值内**任意位置**的 `scheme://user:pass@host`
/// ⇒ 把 userinfo 换成 [`MASK`]。
///
/// 与 [`mask_url_userinfo`]（文本层）的关键差别：authority 的终止符**只有**
/// `/` `?` `#`、**内嵌的下一个 `://`** 与**值结尾**——密码里的引号、反斜杠、空白、
/// 尖括号、反引号**都算在 authority 之内**。这正是文本层做不到的那一角：
///
/// ```text
/// 值：见 https://alice:p"w@hook.example.com/x 已失效
/// 文本层：authority 在 `"` 处被截断 ⇒ 找不到 `@` ⇒ 原样放行（两层全漏）
/// 本函数：authority 一路读到 `/` ⇒ 掩成 https://***@hook.example.com/x
/// ```
///
/// **不再要求 scheme 以字母开头**（P2-24 形态②）：`1https://u:p@h` 这种「scheme 前紧贴
/// 数字 / `.` / `-` / `+`」的形态以前会被 scheme 校验短路。校验本来只为「别把普通文本
/// 当 URL」，而下面的掩码只在 authority 里**确实有 `@`** 时才发生 —— 保留校验只会漏掩，
/// 去掉它才与文本层同口径（两层同源，见 [`mask_urls`]）。
///
/// **代价（明确记录）**：不校验 `://` 后面是不是真的一个 authority。一句正常的话里
/// 出现 `foo://bar@baz` 也会被掩成 `foo://***@baz`。方向取「宁可多掩」——
/// 它只影响**显示**，而漏一个密码的代价是不可撤销的。
///
/// 幂等：掩出来的 `***@host` 再跑一遍，`@` 仍在 authority 内 ⇒ 结果不变。
fn mask_any_url_userinfo(value: &str) -> String {
    mask_urls(value, false)
}

/// 结构化载荷里每个字符串值过 [`mask_any_url_userinfo`]（递归进容器）。
///
/// 给**事件写入口**用（`observability::event_with_payload`）：那里随后对序列化文本做的
/// [`scrub`] 只能按文本规则猜 authority 的边界，带引号的密码会漏（独立复审 P2-1）；
/// M8-S3 的 A-13 又实测出**句内** URL（`"见 https://alice:p\"w@h/x 已失效"`）两层全漏——
/// 因为文本层把 `\` 当 authority 终止符，而这个函数不把 `\` 当终止符。
/// 不按键名打码——那是导出侧 [`scrub_payload`] 的契约，写入口不改变它。
pub fn mask_url_userinfo_in_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => *text = mask_any_url_userinfo(text),
        serde_json::Value::Array(items) => items.iter_mut().for_each(mask_url_userinfo_in_json),
        serde_json::Value::Object(map) => map.values_mut().for_each(mask_url_userinfo_in_json),
        _ => {}
    }
}

/// 钥匙串引用的段字符集：`kr/<scope>/<id>/<field>` 的 scope / id / field 只可能是这些字符。
///
/// **刻意收窄**：若把 `"` `,` `}` 也算进段，JSON 文本里的 `"kr/key/1/secret"` 会把结尾的
/// 引号一起吃进匹配，替换后 JSON 结构就坏了（`{"ref":"kr/***,"x":1}` —— 第一版就是这么写的，
/// 被 `scrub_reference_tokens_keeps_json_parseable` 抓出来的）。
fn is_ref_segment_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')
}

/// 掩掉钥匙串引用形态：`kr/<scope>/<id>/<field>` → `kr/***`（B-62 的「引用形态」那一半）。
///
/// 只认「`kr/` + 至少 3 段、每段非空且由 [`is_ref_segment_char`] 组成」的形态：
/// - 段数不足（`kr/key/1`）或含空段（`kr//1/secret`）→ 原样保留：那不是合法引用
///   （`vault::is_valid_secret_ref` 要求恰好 4 段），当普通文本处理更安全；
/// - 段数多于 4（`kr/key/1/secret/extra`）→ 一并吃掉，不留半截引用；
/// - 幂等：`kr/***` 里的 `*` 不是段字符，再跑一遍不变。
///
/// 代价（明确记录）：这是**文本级**替换，不校验引用合法性，因此 `xxkr/key/1/secret`
/// 也会被掩成 `xxkr/***`。方向是「宁可多掩」。
pub fn scrub_reference_tokens(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < chars.len() {
        let looks_like_ref = chars[i] == 'k'
            && i + 3 < chars.len()
            && chars[i + 1] == 'r'
            && chars[i + 2] == '/'
            && is_ref_segment_char(chars[i + 3]);
        if looks_like_ref {
            let mut j = i + 3;
            let mut segments = 0usize;
            loop {
                let segment_start = j;
                while j < chars.len() && is_ref_segment_char(chars[j]) {
                    j += 1;
                }
                if j == segment_start {
                    break;
                }
                segments += 1;
                // 只有「斜杠后面还跟着一个段」才继续吃，避免把结尾的 `/` 吃进匹配
                if j < chars.len()
                    && chars[j] == '/'
                    && j + 1 < chars.len()
                    && is_ref_segment_char(chars[j + 1])
                {
                    j += 1;
                    continue;
                }
                break;
            }
            if segments >= 3 {
                out.push_str("kr/");
                out.push_str(MASK);
                i = j;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }

    out
}

/// 命中集合（章程 §4.3，**精确匹配**：键名先小写、再去掉 `_` 与 `-`）。
///
/// 清单**不得外扩**：章程把这份集合冻结了，悄悄加一个键名等于悄悄改宽契约。
/// 已知未覆盖的复合键名（如 `session_token` → `sessiontoken`、`x_api_key` → `xapikey`）
/// 记录在 M5-S1 spec §9，不在这里补。
const SENSITIVE_KEYS: [&str; 17] = [
    "password",
    "passwd",
    "pwd",
    "secret",
    "clientsecret",
    "token",
    "accesstoken",
    "refreshtoken",
    "apikey",
    "authorization",
    "cookie",
    "setcookie",
    "session",
    "credential",
    "credentials",
    "privatekey",
    // P1-10：webhook URL 的凭据常在 path/query（Slack `/services/T/B/<token>`、
    // Discord `?key=<uuid>`），`scrub` 不认这类形态。按键名脱敏是纵深防御——
    // 源头（`service.rs` 事件 payload）已用 `mask_webhook_url` 收窄到 scheme+host。
    "webhook",
];

fn is_sensitive_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|c| !matches!(*c, '_' | '-'))
        .flat_map(|c| c.to_lowercase())
        .collect();
    SENSITIVE_KEYS.contains(&normalized.as_str())
}

/// 递归脱敏一个 JSON 值：对象按键名判命中，数组逐元素递归，字符串值先过
/// [`mask_any_url_userinfo`]（值内任意位置的 URL）再过 [`scrub`]。
fn scrub_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let sensitive = is_sensitive_key(key);
                match child {
                    // 值是容器 → 递归进去（契约：不是整块打码）
                    serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
                        scrub_json_value(child);
                    }
                    // 命中键的标量值整体换成 MASK（含 null / 数字 / 布尔：不保留类型）
                    _ if sensitive => *child = serde_json::Value::String(MASK.to_string()),
                    serde_json::Value::String(text) => *text = scrub(&mask_any_url_userinfo(text)),
                    _ => {}
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                scrub_json_value(item);
            }
        }
        serde_json::Value::String(text) => *text = scrub(&mask_any_url_userinfo(text)),
        _ => {}
    }
}

/// 事件 payload 的结构化脱敏（M5-S0 章程 §4.3）。
///
/// - `None` → `None`；
/// - JSON 解析成功 → 按键名脱敏（命中集合见 [`SENSITIVE_KEYS`]），未命中的字符串值仍过 [`scrub`]；
/// - JSON 解析失败（含「payload 只是一段裸文本」）→ 退化为 [`scrub`] 整串；
/// - 键顺序保持原样（本 crate 启用了 `serde_json` 的 `preserve_order`）。
///
/// 注意它**不**负责引用形态：`kr/<scope>/<id>/<field>` 由 [`scrub_reference_tokens`] 处理，
/// 调用方两个都要串（见 `export::sanitize_bundle`）。
pub fn scrub_payload(payload: Option<&str>) -> Option<String> {
    let raw = payload?;
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Some(scrub(raw));
    };
    scrub_json_value(&mut value);
    match serde_json::to_string(&value) {
        Ok(text) => Some(text),
        // 理论上不可达（`Value` 一定能序列化）。真出问题也绝不能返回原串。
        Err(_) => Some(scrub(raw)),
    }
}

/// **事件文本的统一出口**：三个出口（事件写入 / 诊断包 / 配置导出 / 老行清洗）都调它。
///
/// 存在的理由（M5-S1 复审 P2-1）：配置导出与诊断导出原来是**各自手抄**同一串组合的，
/// 「同源」只是注释承诺。M16-S2 又把**写入路径**并了进来 —— 在此之前写入路径自己做
/// `mask_authority_userinfo(scrub(..))`：比出口多了「带引号口令」那一层、却少了引用形态，
/// 于是同一份输入在事件表与导出物里长得不一样（P2-25）。
///
/// 组合顺序固定（三层各管一段，互不吞并）：
/// 1. `scrub`：前缀型密钥 / ≥32 位 hex / 文本层 URL userinfo；
/// 2. `scrub_reference_tokens`：`kr/<scope>/<id>/<field>` → `kr/***`；
/// 3. `mask_authority_userinfo`：authority 只止于 `/` `?` `#`，**不**止于引号/空白 ——
///    补上 `scrub` 在 `"` 处截断而漏掉的带引号口令 URL（P2-25 的原始症状）。
///
/// 幂等：三层各自幂等，且第 3 层的产物（`***@host`）再喂给第 1 层仍是 `***@host`。
pub fn scrub_event_message(message: &str) -> String {
    mask_authority_userinfo(&scrub_reference_tokens(&scrub(message)))
}

/// **事件载荷（Value 层）的统一出口**：结构化 URL 层 + 按键名脱敏。
///
/// 写入路径手里已经有 `Value`，直接调它（不必序列化后再解析）；出口侧拿到的是文本，
/// 走 [`scrub_event_payload`]。两条路径的输出**逐字节一致**（有测试钉住）。
pub fn scrub_event_value(value: &mut serde_json::Value) {
    // 顺序要紧：先按「值内任意位置」的 URL 口径掩 userinfo（引号/空格透明），
    // 再按键名与文本规则走一遍。反过来会让带引号口令的值在 `scrub` 的 `"` 处截断而漏掉。
    mask_url_userinfo_in_json(value);
    scrub_json_value(value);
}

/// 已脱敏的 `Value` → 事件 payload 文本：序列化 + 引用形态。
///
/// 单独抽出来是为了让**写入路径**（手里是 `Value`）与 [`scrub_event_payload`]
/// （手里是文本）共用同一段收尾，不再各写一遍。
pub fn serialize_scrubbed_event_payload(value: &serde_json::Value) -> Option<String> {
    serde_json::to_string(value)
        .ok()
        .map(|text| scrub_reference_tokens(&text))
}

/// **事件 payload（文本层）的统一出口**。见 [`scrub_event_message`] 的说明。
///
/// 非 JSON 输入退化为 [`scrub_event_message`]（与 message 同口径）；`None` → `None`。
/// 幂等：第一遍产出的是 serde 重新序列化的**合法 JSON**，第二遍能正常解析。
pub fn scrub_event_payload(payload: Option<&str>) -> Option<String> {
    let raw = payload?;
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(raw) else {
        // 非法 JSON：文本层兜底。**但兜底之后要再收敛一次**（P1 / S2 复审）：
        // 文本层掩掉值里的引号/URL 之后，整串可能**变成合法 JSON**；那时如果不收敛，
        // 第一遍给的是「带原格式的文本」、第二遍走结构化路径重新序列化 ⇒ 两遍不一致。
        // 收敛用的就是第二遍会走的那条路径，因此两遍必然逐字节相同。
        let text = scrub_event_message(raw);
        return match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(mut value) => {
                scrub_event_value(&mut value);
                serialize_scrubbed_event_payload(&value).or(Some(text))
            }
            Err(_) => Some(text),
        };
    };
    scrub_event_value(&mut value);
    match serialize_scrubbed_event_payload(&value) {
        Some(text) => Some(text),
        // 理论上不可达（`Value` 一定能序列化）。真出问题也绝不能返回原串。
        None => Some(scrub_event_message(raw)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_authority_userinfo_masks_a_single_url() {
        // 基线：单 URL（有 scheme）仍正确掩。
        let m = mask_authority_userinfo("https://alice:pw@hook.example.com/x");
        assert!(m.contains("***@hook.example.com"), "{m}");
        assert!(!m.contains("alice:pw"), "{m}");
    }

    #[test]
    fn mask_authority_userinfo_masks_every_url_in_a_multi_url_text() {
        // 复审 F4：原实现只处理首个 ://，多 URL 文本塌缩成 prefix://***@h_last，
        // 首个 URL 的主机名被吞。循环后每个 URL 独立掩。
        let m = mask_authority_userinfo("见 a://u1:p1@h1/x 和 b://u2:p2@h2/y");
        assert!(m.contains("***@h1"), "首个 URL 应掩: {m}");
        assert!(m.contains("***@h2"), "第二个 URL 也应掩: {m}");
        assert!(!m.contains("u1:p1"), "u1:p1 不许明文: {m}");
        assert!(!m.contains("u2:p2"), "u2:p2 不许明文: {m}");
    }

    #[test]
    fn mask_authority_userinfo_masks_a_schemeless_authority() {
        // 无 scheme（transport 调用方传 user:pass@host）：整串即 authority，仍掩。
        let m = mask_authority_userinfo("alice:pw@hook.example.com");
        assert!(m.contains("***@hook.example.com"), "{m}");
        assert!(!m.contains("alice:pw"), "{m}");
    }

    #[test]
    fn mask_authority_userinfo_leaves_text_without_userinfo_intact() {
        assert_eq!(
            mask_authority_userinfo("plain text no url"),
            "plain text no url"
        );
        assert_eq!(
            mask_authority_userinfo("https://hook.example.com/x"),
            "https://hook.example.com/x"
        );
    }

    #[test]
    fn scrub_does_not_mask_prefix_lookalikes_inside_words() {
        // P2-26：前缀必须在词边界处。`desk-assistant` / `task-scheduler` 里的 `sk-`
        // 是词中间（前一个字符是字母），不得当成密钥前缀掩掉。
        assert_eq!(scrub("desk-assistant"), "desk-assistant");
        assert_eq!(scrub("task-scheduler"), "task-scheduler");
        // 对照：词边界处的真正密钥仍被掩（前面是空格或行首）。
        assert!(scrub("key: sk-0123456789abcdef").contains(MASK));
        assert!(scrub("sk-0123456789abcdef").contains(MASK));
    }

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

    // ---------- M5-S1：strip_url_userinfo ----------

    #[test]
    fn strip_url_userinfo_removes_embedded_credentials() {
        assert_eq!(
            strip_url_userinfo("https://user:pass@relay.example.com/v1"),
            "https://relay.example.com/v1"
        );
        assert_eq!(
            strip_url_userinfo("http://user:pass@relay.example.com:8080"),
            "http://relay.example.com:8080"
        );
        assert_eq!(strip_url_userinfo("https://token@host"), "https://host");
        assert_eq!(strip_url_userinfo("https://@host/"), "https://host/");
    }

    #[test]
    fn strip_url_userinfo_leaves_clean_inputs_byte_identical() {
        for clean in [
            "https://relay.example.com",
            "https://relay.example.com/v1/chat?x=1#frag",
            "relay.example.com",
            "",
            // `@` 在 query / fragment 里，不是 userinfo
            "https://host/p?q=a@b",
            "https://host#a@b",
            // 没有 `://` → 冻结语义要求逐字节不变
            "user:pass@host",
            "mailto:someone@example.com",
        ] {
            assert_eq!(strip_url_userinfo(clean), clean, "「{clean}」不该被改动");
        }
    }

    #[test]
    fn strip_url_userinfo_drops_up_to_the_last_at_of_the_authority() {
        // 按第一个 `@` 切会留下 `b:pw@host/` —— 密码仍在串里
        assert_eq!(strip_url_userinfo("https://a@b:pw@host/"), "https://host/");
        assert_eq!(
            strip_url_userinfo("https://u:p@w@relay.example.com"),
            "https://relay.example.com"
        );
    }

    #[test]
    fn strip_url_userinfo_is_idempotent() {
        let once = strip_url_userinfo("https://user:pass@relay.example.com/x");
        assert_eq!(strip_url_userinfo(&once), once);
    }

    // ---------- 规则顺序的差分守护（M8-S5B §7.3） ----------

    /// 顺序敏感语料：每一串都同时踩到「前缀型凭证」与「URL userinfo」两条规则，
    /// 且两条规则的边界互相影响（`sk-` 的 token 字符含 `/`，会把外层路径连同内层
    /// URL 的 scheme 一起吞掉——M5-S1 复核 R-1 抓到的正是这一类）。
    const ORDER_CORPUS: &[&str] = &[
        "连接 https://alice:s3cretPW@relay.example.com/v1 失败",
        // 密钥紧跟在 URL 后面：前缀规则会一路吃到 `/`
        "https://relay.example.com/sk-abcdefgh12345678/x",
        // URL 里嵌密钥形态
        "https://relay.example.com/?token=sk-abcdefgh12345678",
        // Bearer + 长 hex
        "Authorization: Bearer 0123456789abcdef0123456789abcdef",
        // 嵌套 URL（外层 userinfo 里有内层 URL）
        "https://a:p@host/https://b:q@inner.example.com/x",
        // 两个 URL 连在一起
        "https://alice:pw@a.example.com/x https://bob:pw@b.example.com/y",
        // 掩过一次的串（幂等语料）
        "https://***@relay.example.com/v1",
    ];

    /// 语料里**必须被掩掉**的秘密字面量。
    ///
    /// 显式列出来而不是从输出反推：反推要写通用解析，而这里要的只是
    /// 「这些具体的秘密不允许以明文出现在新输出里」。
    const ORDER_SECRETS: &[&str] = &[
        "s3cretPW",
        "alice",
        "bob",
        "sk-abcdefgh12345678",
        "0123456789abcdef0123456789abcdef",
        // 嵌套 / 相邻两条语料里的 userinfo（没有这两个，那两行就是死重）
        "a:p",
        "b:q",
    ];

    /// 顺序差分守护（M8-S5B §7.3）。
    ///
    /// 断言是**无条件正向**的：语料里出现过的每个秘密，都不得在新口径的输出里以明文出现。
    ///
    /// 为什么不是「与旧口径差分」（第一版的写法，被独立复审 P2-2 抓出空转）：
    /// 旧口径 `scrub_prefixes_only` **只跑前缀规则、永不掩 URL userinfo**，
    /// 于是 `alice` / `bob` / `s3cretPW` 这些 URL 秘密在差分里必然被跳过——
    /// 7 条语料 × 5 个秘密 = 35 对组合里 32 对是死重，恰好漏掉它声称要守的
    /// 「两条规则边界互相影响」。改成无条件正向后，那 4 条纯 URL 语料
    /// （嵌套 URL / 相邻 URL / 掩过的串）才真的被断言。
    ///
    /// **边际价值有限，如实记录**：定稿时试过四种变异（去掉开头的 URL 遍、去掉收尾的
    /// URL 遍、换掉 `PREFIXES` 里的 `Bearer`、收窄 authority 终止符集），**每一种都被
    /// 更专门的既有用例抓到**（`scrub_is_idempotent_across_rule_interactions` /
    /// `scrub_masks_userinfo_of_a_url_nested_behind_a_prefix_lookalike_host` /
    /// `masks_nap_and_bearer` / `scrub_stops_the_authority_at_a_json_quote`）。
    /// 保留它的理由：它把「这些秘密不许露」写成**可增长的语料点**——将来往
    /// `ORDER_CORPUS` 加新形态时，不用再为每个形态手写一条专用用例。
    #[test]
    fn scrub_never_masks_less_than_the_prefix_only_pass() {
        for input in ORDER_CORPUS {
            let new = scrub(input);
            for secret in ORDER_SECRETS {
                if !input.contains(secret) {
                    continue;
                }
                assert!(
                    !new.contains(secret),
                    "{secret:?} 在新口径里是明文：\n  输入: {input}\n  输出: {new}"
                );
            }
        }
    }

    // ---------- mask_url_userinfo_in_json：结构化层（M8-S3 独立复审 P1-3） ----------

    /// 把字符串包成 JSON 值过一遍结构化层，取出结果。
    fn json_masked(text: &str) -> String {
        let mut value = serde_json::Value::String(text.to_string());
        mask_url_userinfo_in_json(&mut value);
        value.as_str().expect("仍是字符串").to_string()
    }

    #[test]
    fn json_layer_masks_an_embedded_url_with_an_escaped_password() {
        // 复审 P1-3 的最小反例：URL 不在值的开头 + 密码含引号。
        // 修前两层全漏（结构化层要求「整个值是 URL」，文本层把 `\` 当终止符）。
        assert_eq!(
            json_masked("见 https://alice:p\"w@hook.example.com/x 已失效"),
            "见 https://***@hook.example.com/x 已失效"
        );
    }

    #[test]
    fn json_layer_masks_passwords_holding_text_layer_terminators() {
        // 文本层的 authority 止于 `"` `\` 空白 `<` `>` 反引号；结构化层一路读到 `/` `?` `#`
        for password in ["p\"w", "p\\\\w", "p w", "p<w", "p>w", "p`w"] {
            let input = format!("站 https://alice:{password}@hook.example.com/x 挂了");
            let masked = json_masked(&input);
            assert!(
                !masked.contains(password),
                "密码 {password:?} 漏了: {masked}"
            );
            assert!(!masked.contains("alice"), "用户名漏了: {masked}");
            assert!(masked.contains("hook.example.com"), "主机要留着: {masked}");
        }
    }

    #[test]
    fn json_layer_masks_a_whole_value_url_too() {
        // 原来的形态也不能退步：整个值就是 URL 时照样掩
        assert_eq!(
            json_masked("https://alice:pw@hook.example.com/x"),
            "https://***@hook.example.com/x"
        );
    }

    #[test]
    fn json_layer_leaves_text_without_userinfo_untouched() {
        for clean in [
            "正常一句话，没有 URL",
            "https://relay.example.com/v1/chat?x=1#frag",
            "",
            // `@` 在 query / fragment 里，不是 userinfo（与 strip_url_userinfo 同口径）
            "https://relay.example.com/v1?email=a@b.com",
        ] {
            assert_eq!(json_masked(clean), clean, "「{clean}」不该被改动");
        }
        // 只有用户名、没有密码的 userinfo **也要掩**（与 `strip_url_userinfo` 的
        // `https://token@host` 口径一致：`@` 之前的一律算 userinfo）
        assert_eq!(
            json_masked("详见 https://bob@relay.example.com/y 无密码"),
            "详见 https://***@relay.example.com/y 无密码"
        );
    }

    /// **口径变更登记（M16-S2）**：`a1://b://c@d 两个冒号` 以前在结构化层**不掩**
    /// （见 git 历史里的同名用例），现在掩成 `a1://b://***@d 两个冒号`。
    ///
    /// 为什么改：
    /// 1. 这个形态与 P2-24 形态① 在第二个 `://` 处**结构完全相同** ——
    ///    `https://a.example.comhttps://carol:pw@h/x` 修好之后，`a1://b://c@d` 必然
    ///    落到同一条分支上。要让它不掩，就得给结构化层加一道「`://` 前必须有 scheme」
    ///    的门槛，而那道门槛正是让形态① 在结构化层继续漏掩的原因（实测：加门槛后
    ///    `json_masked("…comhttps://carol:pw@h/x")` 原样放行）。两者不可兼得。
    /// 2. 旧断言钉的是**两层不一致**：文本层（`scrub`）从来就掩这一段，只有结构化层
    ///    因为 scheme 校验而放过它。本道的判据是两层同口径。
    /// 3. 产品取向是「宁可多掩」（掩错只影响显示，漏掩不可撤销）—— 与
    ///    `mask_authority_userinfo` 的既有注释一致。
    ///
    /// 代价：句子里出现「`://` 后面紧跟 `user@host`」这种**非 URL** 片段时会被多掩一段。
    /// 反例（普通文本、干净 URL、`@` 在 query 里）仍逐条钉在上面那条测试里。
    #[test]
    fn json_layer_now_masks_a_scheme_less_fragment_after_a_cut_authority() {
        assert_eq!(
            json_masked("a1://b://c@d 两个冒号"),
            "a1://b://***@d 两个冒号"
        );
        // 与文本层同口径（这才是本道的判据）
        assert_eq!(
            scrub("a1://b://c@d 两个冒号"),
            json_masked("a1://b://c@d 两个冒号")
        );
    }

    #[test]
    fn json_layer_is_idempotent() {
        let input = "见 https://alice:p\"w@hook.example.com/x 已失效";
        let once = json_masked(input);
        assert_eq!(json_masked(&once), once, "结构化层必须幂等");
    }

    #[test]
    fn json_layer_recurses_into_containers() {
        let mut value = serde_json::json!({
            "title": "见 https://alice:p\"w@h.example.com/x",
            "nested": {"list": ["https://bob:pw@h.example.com/y"]},
            "count": 7,
            "flag": true,
        });
        mask_url_userinfo_in_json(&mut value);
        let text = serde_json::to_string(&value).expect("可序列化");
        assert!(!text.contains("alice"), "{text}");
        assert!(!text.contains("bob"), "{text}");
        assert!(text.contains("h.example.com"), "{text}");
        // 数字与布尔不参与（不是字符串）
        assert!(text.contains("\"count\":7"), "{text}");
        assert!(text.contains("\"flag\":true"), "{text}");
    }

    // ---------- scrub：文本里的 URL userinfo（B-63 的出口那一半） ----------

    #[test]
    fn scrub_masks_url_userinfo_inside_text() {
        assert_eq!(
            scrub("连接 https://alice:s3cretPW@relay.example.com/v1 失败"),
            "连接 https://***@relay.example.com/v1 失败"
        );
        // 事件 payload 是序列化后的 JSON 文本：authority 到引号为止，结构不能被破坏
        let payload = r#"{"site_id":1,"base_url":"https://alice:s3cretPW@relay.example.com"}"#;
        let scrubbed = scrub(payload);
        assert_eq!(
            scrubbed,
            r#"{"site_id":1,"base_url":"https://***@relay.example.com"}"#
        );
        assert!(serde_json::from_str::<serde_json::Value>(&scrubbed).is_ok());
        // 多个 `@` 删到最后一个（与 strip_url_userinfo 同口径：宁可多掩）
        assert_eq!(scrub("https://a@b:pw@host/x"), "https://***@host/x");
        // 一段文本里有多个 URL
        assert_eq!(
            scrub("a=http://u:p@h1 b=https://h2/p c=ssh://git@h3"),
            "a=http://***@h1 b=https://h2/p c=ssh://***@h3"
        );
        assert!(contains_secret("https://alice:s3cretPW@relay.example.com"));
    }

    #[test]
    fn scrub_leaves_urls_without_userinfo_byte_identical() {
        for clean in [
            "https://relay.example.com/v1/chat?x=1#frag",
            // `@` 在 path / query / fragment 里，不是 userinfo
            "https://host/p@q",
            "https://host/p?q=a@b",
            "https://host#a@b",
            // 没有 `://`：不猜（邮箱、无 scheme 的 `user@host` 一律不动）
            "mailto:someone@example.com",
            "someone@example.com",
            "https://host 与 someone@example.com",
        ] {
            assert_eq!(scrub(clean), clean, "「{clean}」不该被改动");
        }
    }

    #[test]
    fn scrub_url_userinfo_is_idempotent() {
        let once = scrub("见 https://alice:s3cretPW@relay.example.com/v1");
        assert_eq!(scrub(&once), once);
    }

    /// 外层 host 含 `sk-` / `nap-` 子串、路径里内嵌另一个带 userinfo 的 URL（代理地址的典型形态）：
    /// 前缀规则连 `/` 一起吞到内层的 `:` 为止，剩下的 `//alice:pw@…` 再也找不到 `://`。
    /// URL 规则若只在前缀规则**之后**跑，内层密码就漏了（第二次复核 R-1）。
    #[test]
    fn scrub_masks_userinfo_of_a_url_nested_behind_a_prefix_lookalike_host() {
        for text in [
            "https://desk-proxy.example.com/fetch/https://alice:PWnested7@relay.example.com",
            "https://snap-cdn.example.com/x/https://alice:PWnested7@relay.example.com/v1",
            "https://ask-ai.example.com/v1/https://alice:PWnested7@relay.example.com",
            "https://sk-abcdefgh/x://b:PWnested7@h",
        ] {
            let once = scrub(text);
            assert!(!once.contains("PWnested7"), "{text:?} → {once:?}");
            assert_eq!(scrub(&once), once, "{text:?}");
        }
    }

    /// 前缀规则的 token 字符含 `/`：`sk-…/p` 被整段吞掉后，`@` 贴到了 authority 上，
    /// 第二遍才被 URL 规则掩掉——违反幂等契约（独立复核 N-1，复核者模糊测试的反例）。
    /// 片段穷举（长度 ≤ 4）覆盖前缀、URL、hex 三条规则两两相邻的组合。
    #[test]
    fn scrub_is_idempotent_across_rule_interactions() {
        for text in [
            "见 https://sk-abcdefgh.example.com/p@x",
            "\\b\\(中://sk-bahttps/b@",
        ] {
            let once = scrub(text);
            assert_eq!(scrub(&once), once, "{text:?}");
        }

        let fragments = [
            "sk-abcdefgh",
            "Bearer ",
            "0123456789abcdef0123456789abcdef",
            "https://",
            "@",
            "/",
            "p",
            " ",
            "\"",
            "'",
            "h.example.com",
            "中",
        ];
        let n = fragments.len();
        for len in 1..=4u32 {
            for mut code in 0..n.pow(len) {
                let mut text = String::new();
                for _ in 0..len {
                    text.push_str(fragments[code % n]);
                    code /= n;
                }
                let once = scrub(&text);
                assert_eq!(scrub(&once), once, "{text:?}");
            }
        }
    }

    /// RFC 3986 的 userinfo 允许 sub-delims（`!$&'()*+,;=`），`reqwest` 解析后 `'` 也原样保留：
    /// 文本规则在它们处截断 authority，截出的片段里没有 `@`，整段就放行了（独立复审 P2-1）。
    #[test]
    fn scrub_masks_userinfo_with_sub_delims_in_the_password() {
        assert_eq!(
            scrub("连接 https://alice:p'w(x),y;z@relay.example.com/v1 失败"),
            "连接 https://***@relay.example.com/v1 失败"
        );
    }

    /// JSON 文本里 URL 止于结尾引号：引号之后另一个值里的 `@` 不是 userinfo（独立复审 P3-3）。
    #[test]
    fn scrub_stops_the_authority_at_a_json_quote() {
        let text = r#"{"a":"https://h","b":"u@x"}"#;
        assert_eq!(scrub(text), text);
    }

    /// 结构化值里「整个值就是 URL」的字符串：authority 只止于 `/` `?` `#`（与
    /// [`strip_url_userinfo`] 同口径），密码里的引号、空白、尖括号、反引号、反斜杠都算在
    /// authority 之内——文本规则不知道值在哪儿结束，做不到这一点（独立复审 P2-1）。
    #[test]
    fn scrub_payload_masks_userinfo_of_a_whole_url_value() {
        for special in ["'", "\"", " ", "<", "`", "\\"] {
            let url = format!("https://alice:pw{special}tail@relay.example.com/v1");
            let raw = serde_json::json!({"base_url": url, "list": [url]}).to_string();
            let scrubbed = scrub_payload(Some(&raw)).unwrap();
            let value: serde_json::Value = serde_json::from_str(&scrubbed).unwrap();
            assert_eq!(
                value["base_url"], "https://***@relay.example.com/v1",
                "{special:?}"
            );
            assert_eq!(
                value["list"][0], "https://***@relay.example.com/v1",
                "{special:?}"
            );
        }
    }

    // ---------- M5-S1：scrub_reference_tokens ----------

    #[test]
    fn scrub_reference_tokens_masks_all_three_real_scopes() {
        assert_eq!(
            scrub_reference_tokens("secret_ref=kr/key/17/secret"),
            "secret_ref=kr/***"
        );
        assert_eq!(scrub_reference_tokens("kr/site/3/password"), "kr/***");
        assert_eq!(
            scrub_reference_tokens("kr/account/5/session 已失效"),
            "kr/*** 已失效"
        );
    }

    #[test]
    fn scrub_reference_tokens_keeps_json_parseable() {
        // 第一版把段字符集放宽到「任何非 `/` 字符」，结果把 JSON 的结尾引号也吃掉了。
        let text = r#"{"ref":"kr/key/1/secret","x":1}"#;
        let scrubbed = scrub_reference_tokens(text);
        assert_eq!(scrubbed, r#"{"ref":"kr/***","x":1}"#);
        let parsed: serde_json::Value =
            serde_json::from_str(&scrubbed).expect("替换后必须仍是合法 JSON");
        assert_eq!(parsed["x"], 1);
    }

    #[test]
    fn scrub_reference_tokens_leaves_non_references_alone() {
        for text in [
            "",
            "kr/",
            "kr/key/1",     // 段数不足（合法引用恰好 4 段）
            "kr//1/secret", // 空段
            "kr/***",       // 已脱敏形态：必须幂等
            "普通文本 kr 与 key",
        ] {
            assert_eq!(scrub_reference_tokens(text), text, "「{text}」不该被改动");
        }
    }

    #[test]
    fn scrub_reference_tokens_swallows_extra_segments_and_is_idempotent() {
        assert_eq!(scrub_reference_tokens("kr/key/1/secret/extra"), "kr/***");
        let once = scrub_reference_tokens("看 kr/key/1/secret 这条");
        assert_eq!(once, "看 kr/*** 这条");
        assert_eq!(scrub_reference_tokens(&once), once);
    }

    // ---------- M5-S1：scrub_payload ----------

    #[test]
    fn scrub_payload_masks_every_sensitive_key_name() {
        // 16 个命中键名，含大小写与 `_` / `-` 变体（归一化后再精确匹配）
        for key in [
            "password",
            "passwd",
            "pwd",
            "secret",
            "clientSecret",
            "token",
            "access_token",
            "refresh-token",
            "apiKey",
            "Authorization",
            "Cookie",
            "Set-Cookie",
            "session",
            "credential",
            "credentials",
            "privateKey",
        ] {
            let payload = format!(r#"{{"{key}":"hunter2"}}"#);
            assert_eq!(
                scrub_payload(Some(&payload)).unwrap(),
                format!(r#"{{"{key}":"***"}}"#),
                "键「{key}」应被掩"
            );
        }
    }

    #[test]
    fn scrub_payload_leaves_the_do_not_touch_keys_alone() {
        // 章程 §4.3 的「不得命中」清单：9 个键必须逐字原样保留（连类型都不变）
        let payload = r#"{"key_id":7,"keyId":"k-1","keys_total":3,"site_id":1,"remote_id":"9","remaining":1.5,"bytes":12,"path":"/tmp/x.json","idempotency_key":"abc"}"#;
        assert_eq!(
            scrub_payload(Some(payload)).unwrap(),
            payload,
            "「不得命中」清单被误伤了"
        );
    }

    #[test]
    fn scrub_payload_recurses_into_containers_and_scrubs_other_strings() {
        // 命中键的值是对象 → 递归进去（不是整块打码）
        assert_eq!(
            scrub_payload(Some(r#"{"credential":{"password":"p","name":"n"}}"#)).unwrap(),
            r#"{"credential":{"password":"***","name":"n"}}"#
        );
        // 数组 → 逐元素递归
        assert_eq!(
            scrub_payload(Some(r#"{"tokens":["sk-abcdefgh12345678","plain"]}"#)).unwrap(),
            r#"{"tokens":["sk-***","plain"]}"#
        );
        // 未命中的字符串值仍过 scrub
        assert_eq!(
            scrub_payload(Some(r#"{"note":"sk-abcdefgh12345678"}"#)).unwrap(),
            r#"{"note":"sk-***"}"#
        );
        // 嵌套结构里也要命中
        assert_eq!(
            scrub_payload(Some(r#"{"a":[{"token":"x"},{"keep":1}]}"#)).unwrap(),
            r#"{"a":[{"token":"***"},{"keep":1}]}"#
        );
    }

    #[test]
    fn scrub_payload_replaces_scalars_of_sensitive_keys_regardless_of_type() {
        assert_eq!(
            scrub_payload(Some(r#"{"token":123}"#)).unwrap(),
            r#"{"token":"***"}"#
        );
        assert_eq!(
            scrub_payload(Some(r#"{"token":true}"#)).unwrap(),
            r#"{"token":"***"}"#
        );
        assert_eq!(
            scrub_payload(Some(r#"{"token":null}"#)).unwrap(),
            r#"{"token":"***"}"#
        );
    }

    #[test]
    fn scrub_payload_falls_back_to_text_scrubbing_and_handles_none() {
        assert_eq!(scrub_payload(None), None);
        assert_eq!(
            scrub_payload(Some("裸文本 sk-abcdefgh12345678")),
            Some("裸文本 sk-***".to_string())
        );
        // 合法 JSON 但只是个标量：原样返回
        assert_eq!(scrub_payload(Some("42")), Some("42".to_string()));
    }

    /// 把「已知未覆盖的复合键名」钉住（M5-S1 spec §9 风险 3）。
    ///
    /// 这条测试**断言的是漏报**，看起来像写反了 —— 它在给冻结契约的边界记账：
    /// 哪天有人扩了 [`SENSITIVE_KEYS`]，这里会红，逼着他回来同步 spec 的清单，
    /// 而不是让覆盖范围悄悄变宽（章程 §10 明确要查「签名有没有被悄悄改宽」）。
    #[test]
    fn scrub_payload_gap_list_is_pinned() {
        for key in ["session_token", "x_api_key", "client_id"] {
            let payload = format!(r#"{{"{key}":"hunter2"}}"#);
            assert_eq!(
                scrub_payload(Some(&payload)).unwrap(),
                payload,
                "「{key}」不在章程 §4.3 的命中集合里，当前不该被掩（已知代价）"
            );
        }
    }

    #[test]
    fn mask_webhook_url_drops_path_query_fragment() {
        // P1-10：webhook 凭据常在 path/query（Slack `/services/T/B/<token>`、Discord `?key=<uuid>`），
        // strip_url_userinfo 只剥 userinfo 不够。
        assert_eq!(
            mask_webhook_url("https://hooks.slack.com/services/T/B/abc123"),
            "https://hooks.slack.com"
        );
        assert_eq!(
            mask_webhook_url("https://discord.com/api/webhooks/123?key=uuid-xyz"),
            "https://discord.com"
        );
    }

    #[test]
    fn mask_webhook_url_keeps_port_and_strips_userinfo() {
        assert_eq!(
            mask_webhook_url("http://localhost:9090/webhook/secret"),
            "http://localhost:9090"
        );
        assert_eq!(
            mask_webhook_url("https://user:pass@hooks.slack.com/services/T"),
            "https://hooks.slack.com"
        );
    }

    #[test]
    fn mask_webhook_url_no_scheme() {
        assert_eq!(
            mask_webhook_url("hooks.slack.com/services/T"),
            "<无 scheme>"
        );
    }

    #[test]
    fn sensitive_keys_includes_webhook() {
        // P1-10：webhook 键名按敏感键脱敏（纵深防御，防别的出口把 webhook 原样进 JSON）
        assert!(is_sensitive_key("webhook"));
        assert!(is_sensitive_key("Webhook"));
        assert!(is_sensitive_key("web-hook"));
        assert!(is_sensitive_key("WEBHOOK"));
    }

    // ---------------------------------------------- M16-S2：P2-24 / P2-25 / 三出口

    #[test]
    fn authority_scan_stops_at_an_embedded_scheme() {
        // P2-24 形态①：第一个 URL 不带路径时，authority 以前会吃掉第二个 URL 的 `://`，
        // 于是第二个 URL 的 userinfo 原样留下。两层都要掩。
        let input = "https://a.example.comhttps://carol:s3cretpw@relay.example.com/x";
        assert_eq!(
            scrub(input),
            "https://a.example.comhttps://***@relay.example.com/x"
        );
        assert_eq!(
            json_masked(input),
            "https://a.example.comhttps://***@relay.example.com/x"
        );
    }

    #[test]
    fn structured_layer_accepts_a_glued_scheme() {
        // P2-24 形态②：`starts_with(字母)` 那半删掉之后，粘连形态也要掩（以前结构化层短路）
        for glue in ["1", ".", "-", "+", "v1.2-"] {
            let input = format!("{glue}https://carol:s3cretpw@relay.example.com/x");
            let masked = json_masked(&input);
            assert!(
                masked.contains("***@relay.example.com"),
                "glue={glue:?} 的结构化层必须掩: {masked}"
            );
        }
    }

    #[test]
    fn event_message_exit_is_the_three_exit_composition() {
        // 三出口共用这一个实现：`scrub` → 引用形态 → authority 层
        let input = "见 https://carol:p\"ass@relay.example.com/x 与 kr/key/1/secret";
        let out = scrub_event_message(input);
        assert!(out.contains("***@relay.example.com"), "{out}");
        assert!(!out.contains("carol:p"), "{out}");
        assert!(out.contains("kr/***"), "{out}");
        assert!(!out.contains("kr/key/1/secret"), "{out}");
        // 幂等
        assert_eq!(scrub_event_message(&out), out);
    }

    #[test]
    fn event_value_and_event_payload_agree_byte_for_byte() {
        // 写入路径（手里是 Value）与出口（手里是文本）必须逐字节一致
        let raw = r#"{"url":"见 https://carol:p\"ass@relay.example.com/x","password":"hunter2","key_id":7}"#;
        let from_text = scrub_event_payload(Some(raw)).expect("文本路径");
        let mut value: serde_json::Value = serde_json::from_str(raw).expect("合法 JSON");
        scrub_event_value(&mut value);
        let from_value = serialize_scrubbed_event_payload(&value).expect("Value 路径");
        assert_eq!(from_text, from_value);
        assert!(from_text.contains("***@relay.example.com"), "{from_text}");
        assert!(from_text.contains(r#""password":"***""#), "{from_text}");
        assert!(from_text.contains(r#""key_id":7"#), "{from_text}");
    }

    #[test]
    fn event_payload_falls_back_to_the_message_exit_for_non_json() {
        let raw = "不是 JSON，但有 https://carol:p\"ass@relay.example.com/x";
        assert_eq!(
            scrub_event_payload(Some(raw)),
            Some(scrub_event_message(raw)),
            "非 JSON 必须与 message 同口径"
        );
        assert_eq!(scrub_event_payload(None), None);
    }

    #[test]
    fn event_exits_leave_reverse_cases_untouched() {
        for clean in [
            "Model gpt-4: 不支持",
            "站点 task-scheduler 与 desk-assistant 都正常",
            "https://relay.example.com/v1?email=a@b.com",
        ] {
            assert_eq!(scrub_event_message(clean), clean, "「{clean}」不该被改动");
        }
        let payload = r#"{"key_id":7,"remaining":1.5,"bytes":12,"path":"/tmp/x.json"}"#;
        assert_eq!(
            scrub_event_payload(Some(payload)).as_deref(),
            Some(payload),
            "「不得命中」的键不能被误伤"
        );
    }
}
