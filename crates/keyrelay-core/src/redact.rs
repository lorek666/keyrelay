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

/// 把输入串里的凭证替换为掩码，其余内容原样保留。
///
/// 该函数是幂等的：对已脱敏的文本再次调用结果不变。
pub fn scrub(input: &str) -> String {
    // URL 规则在**原文**上先跑一遍：前缀规则的 token 字符含 `/`，会把外层路径连同内层 URL 的
    // scheme 一起吞掉，吞完之后内层的 `://` 就不在了（第二次复核 R-1）。
    let input = &mask_url_userinfo(input);
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
    let (prefix, authority_start) = match raw.find("://") {
        Some(scheme_end) => (&raw[..scheme_end + 3], scheme_end + 3),
        // 无 scheme：前缀为空，authority 从 0 开始（这就是「已知是 authority」的含义）。
        None => ("", 0),
    };
    let rest = &raw[authority_start..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let Some(at) = authority.rfind('@') else {
        return raw.to_string();
    };
    // 从 `@` 起（含）原样保留：`@host…`。多掩的那部分只影响显示。
    format!("{prefix}{MASK}{}", &rest[at..])
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
/// 结构化值里**整个值就是 URL** 的字符串另走 [`mask_whole_url_userinfo`]：那里知道值在
/// 哪儿结束，不需要靠上面这些字符去猜。
///
/// 为什么放在 `scrub` 里而不是各调用点（B-63 只剥了导出的 `sites[].base_url`）：
/// 事件 payload 原样记着 `base_url`，按调用点剥就一定会漏一处；`scrub` 是
/// 事件 / 通知 / 错误的共同咽喉点。没有 `://` 的形态（`user@host`、邮箱）**不猜**。
fn mask_url_userinfo(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find("://") {
        let authority_start = pos + "://".len();
        out.push_str(&rest[..authority_start]);
        let tail = &rest[authority_start..];
        let authority_end = tail
            .find(|c: char| {
                matches!(c, '/' | '?' | '#' | '"' | '<' | '>' | '`' | '\\') || c.is_whitespace()
            })
            .unwrap_or(tail.len());
        let authority = &tail[..authority_end];
        match authority.rfind('@') {
            Some(at) => {
                out.push_str(MASK);
                out.push_str(&authority[at..]);
            }
            None => out.push_str(authority),
        }
        rest = &tail[authority_end..];
    }
    out.push_str(rest);
    out
}

/// **整个值就是一个 URL**（`scheme://` 开头）时，按整串 URL 的口径把 userinfo 换成 [`MASK`]：
/// authority 只止于 `/` `?` `#`（与 [`strip_url_userinfo`] 同口径），密码里的引号、空白、
/// 尖括号、反斜杠都算在 authority 之内。不是这种形态 ⇒ 原样返回。
///
/// 只用于**已知边界**的值（JSON 字符串值）；任意文本仍走 [`mask_url_userinfo`]。
fn mask_whole_url_userinfo(value: &str) -> String {
    let Some(scheme_end) = value.find("://") else {
        return value.to_string();
    };
    let scheme = &value[..scheme_end];
    let is_scheme = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    if !is_scheme {
        return value.to_string();
    }
    let authority_start = scheme_end + "://".len();
    let rest = &value[authority_start..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
        Some(at) => format!("{}{MASK}{}", &value[..authority_start], &rest[at..]),
        None => value.to_string(),
    }
}

/// **值内任意位置**的 `scheme://user:pass@host` ⇒ 把 userinfo 换成 [`MASK`]。
///
/// 与 [`mask_url_userinfo`]（文本层）的关键差别：authority 的终止符**只有**
/// `/` `?` `#` 与**值结尾**——密码里的引号、反斜杠、空白、尖括号、反引号**都算在
/// authority 之内**。这正是文本层做不到的那一角：
///
/// ```text
/// 值：见 https://alice:p"w@hook.example.com/x 已失效
/// 文本层：authority 在 `\` 处被截断 ⇒ 找不到 `@` ⇒ 原样放行（两层全漏）
/// 本函数：authority 一路读到 `/` ⇒ 掩成 https://***@hook.example.com/x
/// ```
///
/// scheme 判定是**往前回溯**的：`://` 前面那几个字符才是 scheme（`见 https` 这种
/// 「前缀文本 + scheme」必须认出来，否则句内 URL 永远掩不到——第一版就栽在这里）。
///
/// **代价（明确记录）**：不校验 `://` 后面是不是真的一个 authority。一句正常的话里
/// 出现 `foo://bar@baz` 也会被掩成 `foo://***@baz`。方向取「宁可多掩」——
/// 它只影响**显示**，而漏一个密码的代价是不可撤销的。
///
/// 幂等：掩出来的 `***@host` 再跑一遍，`@` 仍在 authority 内 ⇒ 结果不变。
fn mask_any_url_userinfo(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(pos) = rest.find("://") {
        // scheme 从 `://` 往前回溯：只认「紧贴 `://` 的那一段 scheme 字符」。
        // 前面还有别的字符（`见 https`）时，那些字符属于**正文**，原样留在 `out` 里。
        let mut scheme_start = pos;
        while scheme_start > 0 {
            let c = rest[..scheme_start]
                .chars()
                .next_back()
                .expect("scheme_start > 0 ⇒ 前面有字符");
            if c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.') {
                scheme_start -= c.len_utf8();
            } else {
                break;
            }
        }
        let scheme = &rest[scheme_start..pos];
        let is_scheme = !scheme.is_empty()
            && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));

        if !is_scheme {
            // 不是 scheme：把 `://` 原样吐出，从它之后继续找（`a1://b://c@d` 要能掩到第二个）
            let skip = pos + "://".len();
            out.push_str(&rest[..skip]);
            rest = &rest[skip..];
            continue;
        }

        let authority_start = pos + "://".len();
        // scheme 之前的正文原样保留
        out.push_str(&rest[..scheme_start]);
        out.push_str(&rest[scheme_start..authority_start]);
        let tail = &rest[authority_start..];
        let authority_end = tail.find(['/', '?', '#']).unwrap_or(tail.len());
        let authority = &tail[..authority_end];
        match authority.rfind('@') {
            Some(at) => {
                out.push_str(MASK);
                out.push_str(&authority[at..]);
            }
            None => out.push_str(authority),
        }
        rest = &tail[authority_end..];
    }
    out.push_str(rest);
    out
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
/// [`mask_whole_url_userinfo`]（整个值是 URL 时）再过 [`scrub`]。
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
                    serde_json::Value::String(text) => {
                        *text = scrub(&mask_whole_url_userinfo(text))
                    }
                    _ => {}
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                scrub_json_value(item);
            }
        }
        serde_json::Value::String(text) => *text = scrub(&mask_whole_url_userinfo(text)),
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

/// **事件文本的统一出口**：`scrub` + 钥匙串引用脱敏。
///
/// 存在的理由（M5-S1 复审 P2-1）：配置导出（`export::sanitize_bundle`）与
/// 诊断导出（`service::export_diagnostics`）原来是**各自手抄**同一串组合的。
/// 手抄出来的「同源」只是注释承诺，实测已经分叉 —— 而且分叉方式很隐蔽：
/// 配置侧在**装配处**先做了一次**文本级** `scrub`，一个 34 位数字会被
/// 「≥32 位 hex」规则打成 `***`，于是 `{"remaining":123…}` 变成 `{"remaining":***}`
/// ——**已经不是合法 JSON**；结构化的 `scrub_payload` 再拿到它只能走「解析失败」
/// 的兜底分支，而诊断侧拿到的是原始串、能正常解析。同一份事件，两条出口输出不同。
///
/// 所以：**先结构化、再文本**，而且只有这一个实现。
pub fn scrub_event_message(message: &str) -> String {
    scrub_reference_tokens(&scrub(message))
}

/// **事件 payload 的统一出口**。见 [`scrub_event_message`] 的说明。
///
/// 幂等：第一遍产出的是 serde 重新序列化的**合法 JSON**，第二遍能正常解析。
pub fn scrub_event_payload(payload: Option<&str>) -> Option<String> {
    scrub_payload(payload).map(|text| scrub_reference_tokens(&text))
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
            "a1://b://c@d 两个冒号",
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
        // P1-10：webhook 键名按敏感键脱敏（纵深防御，防别的出口把 webhook URL 原样进 JSON）
        assert!(is_sensitive_key("webhook"));
        assert!(is_sensitive_key("Webhook"));
        assert!(is_sensitive_key("web-hook"));
        assert!(is_sensitive_key("WEBHOOK"));
    }
}
