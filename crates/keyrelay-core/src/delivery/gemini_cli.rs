//! Gemini CLI 通道：`~/.gemini/.env` 的 `GEMINI_API_KEY` 与 `GOOGLE_GEMINI_BASE_URL`。
//!
//! ```dotenv
//! GEMINI_API_KEY=sk-…
//! GOOGLE_GEMINI_BASE_URL=https://relay.example.com
//! ```
//!
//! 与两个 JSON 通道不同，这里是**纯文本行级**操作：只改这两行，**其余字节一个都不动**
//! （注释、空行、无关变量、CRLF、最后一行没有换行——全部原样保留）。
//! 本模块不引入 dotenv 依赖，自己实现匹配与改写（章程未批准加新 crate）。
//!
//! 两处刻意的选择，理由写在对应函数上：
//! - 同名受管键出现多次时**合并到第一处**（多数 dotenv 实现「后者胜」，只改第一处会让
//!   我们写的密钥静默失效；只改最后一处则前面的旧密钥明文永久留在文件里）；
//! - 值不满足保守安全字符集时**加双引号并转义**，保证值永远不跨物理行（无行注入）。
//!
//! `~/.gemini/settings.json` **本波次不写**（章程 §4.1：`checked_target` 每通道只放行一个
//! 路径）→ 见 `docs/specs/M6-S1-通道扩展.md` §11 D-2。

use std::path::{Path, PathBuf};

use super::json_text::read_text_or_empty;
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;

pub struct GeminiCliWriter {
    path: PathBuf,
    base_url: String,
}

impl GeminiCliWriter {
    pub const FIELD_API_KEY: &'static str = "GEMINI_API_KEY";
    pub const FIELD_BASE_URL: &'static str = "GOOGLE_GEMINI_BASE_URL";

    /// `home` 显式传入（不读 `HOME`），便于测试重定向到临时目录。
    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path(home.join(".gemini").join(".env"), base_url)
    }

    pub fn with_path(path: impl Into<PathBuf>, base_url: &str) -> Self {
        Self {
            path: path.into(),
            base_url: base_url.to_string(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 生成写入后的完整文本。`api_key` 会出现在返回值里——调用方不得打印。
    fn build_after(&self, before: &str, api_key: &str) -> Result<String> {
        if api_key.trim().is_empty() {
            return Err(Error::inject(&self.path, "密钥为空，拒绝写入"));
        }

        let lines = split_env_lines(before);
        let mut bodies: Vec<String> = lines.iter().map(|l| l.body.to_string()).collect();
        let endings: Vec<&str> = lines.iter().map(|l| l.ending).collect();
        // 哪些行落在「上一行开始的未闭合双引号值」里面。这些行**不是**行首赋值，
        // 撞上去会把别人（或本键自己）跨行的值改坏。
        let (starts_inside, ends_inside) = multiline_value_flags(&lines);

        let mut assignments: Vec<(&str, String)> =
            vec![(Self::FIELD_API_KEY, render_value(api_key))];
        if !self.base_url.is_empty() {
            assignments.push((Self::FIELD_BASE_URL, render_value(&self.base_url)));
        }

        // `removed` 收集「重复的受管行」下标，`appended` 收集需要新起一行的键。
        let mut removed: Vec<usize> = Vec::new();
        let mut appended: Vec<String> = Vec::new();

        for (key, rendered) in &assignments {
            let hits: Vec<usize> = bodies
                .iter()
                .enumerate()
                .filter(|(index, body)| {
                    !starts_inside[*index] && match_assignment(strip_cr(body), key).is_some()
                })
                .map(|(index, _)| index)
                .collect();

            // 受管键自己的值跨多行（引号未闭合）：改写第一行会留下孤立的续行碎片，
            // 删掉重复行也会。两种都是静默改坏文件，因此**拒绝**而不是猜。
            if let Some(bad) = hits
                .iter()
                .find(|index| unescaped_quote_count(strip_cr(&bodies[**index])) % 2 == 1)
            {
                return Err(Error::inject(
                    &self.path,
                    format!(
                        "`{key}` 的值跨多行（第 {} 行的双引号没有闭合），拒绝改写；\
                         请先手工把该值改成单行",
                        bad + 1
                    ),
                ));
            }

            match hits.first().copied() {
                Some(first) => {
                    let body = strip_cr(&bodies[first]);
                    let style = match_assignment(body, key).expect("上面刚匹配过");
                    let cr = if bodies[first].ends_with('\r') {
                        "\r"
                    } else {
                        ""
                    };
                    bodies[first] =
                        format!("{}{}{}={rendered}{cr}", style.indent, style.export, key);
                    removed.extend(hits.iter().skip(1).copied());
                }
                None => {
                    // 文件在未闭合的引号里结束：追加的行会被解析器吞进那个值里，
                    // 于是我们「写成功了」但密钥不生效——宁可拒绝。
                    if ends_inside {
                        return Err(Error::inject(
                            &self.path,
                            format!(
                                "文件末尾的双引号没有闭合（`{key}` 无处可写），拒绝追加；\
                                 请先手工修好该文件"
                            ),
                        ));
                    }
                    appended.push(format!("{key}={rendered}"));
                }
            }
        }

        let mut out = String::with_capacity(before.len() + 96);
        for (index, body) in bodies.iter().enumerate() {
            if removed.contains(&index) {
                continue;
            }
            out.push_str(body);
            out.push_str(endings[index]);
        }

        if !appended.is_empty() {
            // 追加段沿用文件的**主导行尾**（M6-S1 复审 P2-2）：固定写 `\n` 会让一个 CRLF
            // 文件在追加后出现混合行尾。既有行的行尾本来就逐字节保留，这里只需与它们对齐。
            let eol = dominant_eol(&lines);
            // 原文件最后一行没有换行时先补一个，否则新行会和它粘成一行。
            if !out.is_empty() && !out.ends_with('\n') {
                out.push_str(eol);
            }
            for line in appended {
                out.push_str(&line);
                out.push_str(eol);
            }
        }

        Ok(out)
    }
}

impl DeliveryWriter for GeminiCliWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::GeminiCli
    }

    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }

    fn field_names(&self) -> Vec<String> {
        let mut names = vec![Self::FIELD_API_KEY.to_string()];
        if !self.base_url.is_empty() {
            names.push(Self::FIELD_BASE_URL.to_string());
        }
        names
    }

    fn fields(&self, api_key: &str) -> Vec<DeliveryField> {
        let mut fields = vec![masked_field(Self::FIELD_API_KEY, api_key)];
        if !self.base_url.is_empty() {
            fields.push(literal_field(Self::FIELD_BASE_URL, &self.base_url));
        }
        fields
    }

    fn plan(&self, api_key: &str) -> Result<Patch> {
        let before = read_text_or_empty(&self.path)?;
        let after = self.build_after(&before, api_key)?;
        Ok(Patch::secret_bearing(self.path.clone(), before, after))
    }
}

/// 一行 `.env`：`body` 不含行尾，`ending` 是 `"\n"` / `""`（最后一行无换行）。
///
/// 按「含行尾切分」而不是「去掉行尾再 join」：这样 CRLF、混合行尾、缺尾随换行
/// 都能**逐字节**还原，不需要额外判断整份文件用哪种行尾。
struct EnvLine<'a> {
    body: &'a str,
    ending: &'a str,
}

fn split_env_lines(text: &str) -> Vec<EnvLine<'_>> {
    if text.is_empty() {
        return Vec::new();
    }
    text.split_inclusive('\n')
        .map(|raw| {
            let body = raw.strip_suffix('\n').unwrap_or(raw);
            EnvLine {
                body,
                ending: &raw[body.len()..],
            }
        })
        .collect()
}

/// 去掉 CRLF 里的 `\r`。只在**匹配**时去；重建时按原样拼回。
fn strip_cr(line: &str) -> &str {
    line.strip_suffix('\r').unwrap_or(line)
}

/// 一行受管赋值的既有写法。
struct Assignment<'a> {
    /// 行首空白
    indent: &'a str,
    /// `""` 或 `"export "`
    export: &'a str,
}

/// 判断一行是不是 `[indent][export ][KEY][空白]=…`。
///
/// 刻意不匹配的形态（G14 钉住）：`# KEY=…`（注释）、`MY_KEY=…` / `KEY_EXTRA=…`（前缀相似）、
/// 裸 `KEY`（没有 `=`）。它们都不是我们能安全维护的赋值，撞上去会把用户自己的内容洗掉。
fn match_assignment<'a>(line: &'a str, key: &str) -> Option<Assignment<'a>> {
    let indent_len = line.len() - line.trim_start_matches(is_blank).len();
    let indent = &line[..indent_len];
    let rest = &line[indent_len..];

    let (export, rest) = match rest.strip_prefix("export") {
        Some(tail) if tail.starts_with(is_blank) => ("export ", tail.trim_start_matches(is_blank)),
        _ => ("", rest),
    };

    let tail = rest.strip_prefix(key)?;
    let tail = tail.trim_start_matches(is_blank);
    if !tail.starts_with('=') {
        return None;
    }
    Some(Assignment { indent, export })
}

fn is_blank(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// 统计**未被反斜杠转义**的双引号个数。
///
/// 用于判断「这一行是否把一个双引号值开到了下一行」。裸计 `"` 会把 `a\"b` 数成 3 个，
/// 因此必须跳过被转义的引号。
fn unescaped_quote_count(line: &str) -> usize {
    let mut count = 0usize;
    let mut escaped = false;
    for c in line.chars() {
        match c {
            '\\' if !escaped => escaped = true,
            '"' if !escaped => count += 1,
            _ => escaped = false,
        }
    }
    count
}

/// 逐行判断每一行是否位于「上一行开始的未闭合双引号值」之内。
///
/// 返回 `(每行的标志, 文件结束时是否仍在引号内)`。
///
/// 为什么需要它：dotenv 允许值跨行（`KEY="第一行\n第二行"`）。此时第二行**看起来**像
/// 一个行首赋值，但它其实是第一行那个值的内容。不加判断就会：
/// 把别的键跨行的值改坏、或者把「恰好长成 `GEMINI_API_KEY=…`」的续行当成受管行。
fn multiline_value_flags(lines: &[EnvLine<'_>]) -> (Vec<bool>, bool) {
    let mut inside = false;
    let mut flags = Vec::with_capacity(lines.len());
    for line in lines {
        flags.push(inside);
        let body = strip_cr(line.body);
        // **注释行不参与引号计数**（M6-S1 复审 P2-1）：真实 dotenv 解析器不会让
        // 行首 `#` 开启一个跨行值，`# note: a lone " quote` 里的孤儿引号不该把后续行
        // 拖成续行——那会让整条通道对该文件**无法投递**，且报错文案指向错误的原因。
        //
        // 只有「不在引号值内部」时 `#` 才是注释：续行里的 `#` 是值的一部分，
        // 必须照常计数，否则跨行值里出现 `#` 会把状态算错。
        if !inside && is_comment_line(body) {
            continue;
        }
        if unescaped_quote_count(body) % 2 == 1 {
            inside = !inside;
        }
    }
    (flags, inside)
}

/// 行首（可选空白）+ `#` → 注释行。
fn is_comment_line(body: &str) -> bool {
    body.trim_start().starts_with('#')
}

/// 文件的主导行尾，用于**追加**新行时与既有行保持一致，避免混出行尾（M6-S1 复审 P2-2）。
///
/// 判据：带行尾的行里，行体以 `\r` 结尾的占多数即 CRLF；空文件默认 LF。
fn dominant_eol(lines: &[EnvLine<'_>]) -> &'static str {
    let mut crlf = 0usize;
    let mut lf = 0usize;
    for line in lines {
        if line.ending == "\n" {
            if line.body.ends_with('\r') {
                crlf += 1;
            } else {
                lf += 1;
            }
        }
    }
    if crlf > lf {
        "\r\n"
    } else {
        "\n"
    }
}

/// 把值渲染成 `.env` 里的一段。安全字符集内直接裸写，否则双引号 + 转义。
fn render_value(value: &str) -> String {
    if is_bare_safe(value) {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// 保守的「可以裸写」字符集：ASCII 字母数字 + URL/密钥里常见的少数符号。
///
/// 空格、`#`（注释起始）、`$`/反引号（变量展开）、引号、反斜杠、`=` 一律走引号路径。
fn is_bare_safe(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '-' | '_' | '.' | ':' | '/' | '@' | '+' | '~' | '%')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-gemini-0123456789abcdef";
    const BASE: &str = "https://relay.example.com";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    fn writer_in(dir: &Path, base_url: &str) -> GeminiCliWriter {
        GeminiCliWriter::with_path(dir.join(".env"), base_url)
    }

    #[test]
    fn creates_fresh_file_with_two_lines() {
        let dir = tmp();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert_eq!(patch.before, "");
        assert_eq!(
            patch.after,
            format!("GEMINI_API_KEY={SECRET}\nGOOGLE_GEMINI_BASE_URL={BASE}\n")
        );
        assert_eq!(patch.new_file_mode, Some(0o600));
    }

    #[test]
    fn preserves_unmanaged_lines_byte_for_byte() {
        let dir = tmp();
        // 刻意含注释、空行、无关变量，且**不以换行结尾**
        let before = "# 我的 .env\n\nGOOGLE_CLOUD_PROJECT=my-project\nOTHER=1";
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();

        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert!(
            patch.after.starts_with(before),
            "受管行之外必须逐字节保留:\n{}",
            patch.after
        );
        assert!(patch.after.contains(&format!("GEMINI_API_KEY={SECRET}")));
        assert!(patch
            .after
            .contains(&format!("GOOGLE_GEMINI_BASE_URL={BASE}")));
    }

    #[test]
    fn replaces_existing_assignment_in_place() {
        let dir = tmp();
        let before = "A=1\nGEMINI_API_KEY=sk-old\nB=2\nGOOGLE_GEMINI_BASE_URL=https://old.example.com\nC=3\n";
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();

        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert_eq!(
            patch.after,
            format!("A=1\nGEMINI_API_KEY={SECRET}\nB=2\nGOOGLE_GEMINI_BASE_URL={BASE}\nC=3\n"),
            "位置必须原地保留、顺序不变"
        );
        assert!(!patch.after.contains("sk-old"), "旧密钥必须被替换掉");
        assert!(!patch.after.contains("old.example.com"));
    }

    #[test]
    fn empty_base_url_writes_only_the_key() {
        let dir = tmp();
        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        assert!(
            !patch.after.contains("GOOGLE_GEMINI_BASE_URL"),
            "{}",
            patch.after
        );
        assert_eq!(writer_in(dir.path(), "").field_names().len(), 1);
    }

    #[test]
    fn empty_base_url_leaves_existing_base_url_alone() {
        let dir = tmp();
        let before = "GOOGLE_GEMINI_BASE_URL=https://keep.example.com\n";
        std::fs::write(writer_in(dir.path(), "").path(), before).unwrap();

        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        assert_eq!(
            patch.after,
            format!("GOOGLE_GEMINI_BASE_URL=https://keep.example.com\nGEMINI_API_KEY={SECRET}\n"),
            "base_url 为空时不得改动已有行"
        );
    }

    #[test]
    fn duplicate_managed_keys_collapse_to_one() {
        let dir = tmp();
        let before =
            "GEMINI_API_KEY=sk-first\nA=1\nGEMINI_API_KEY=sk-second\nB=2\nexport GEMINI_API_KEY=sk-third\n";
        std::fs::write(writer_in(dir.path(), "").path(), before).unwrap();

        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        assert_eq!(
            patch.after.matches("GEMINI_API_KEY").count(),
            1,
            "同名受管键必须合并成一行:\n{}",
            patch.after
        );
        assert_eq!(
            patch.after,
            format!("GEMINI_API_KEY={SECRET}\nA=1\nB=2\n"),
            "保留第一处位置，其余同名行删除"
        );
        for old in ["sk-first", "sk-second", "sk-third"] {
            assert!(!patch.after.contains(old), "{old} 应被清掉");
        }
    }

    #[test]
    fn export_prefix_and_indent_are_preserved() {
        let dir = tmp();
        let before = "  export GEMINI_API_KEY=sk-old\n";
        std::fs::write(writer_in(dir.path(), "").path(), before).unwrap();

        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        assert_eq!(patch.after, format!("  export GEMINI_API_KEY={SECRET}\n"));
    }

    #[test]
    fn whitespace_around_equals_is_matched() {
        let dir = tmp();
        let before = "GEMINI_API_KEY = sk-old\n";
        std::fs::write(writer_in(dir.path(), "").path(), before).unwrap();

        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        assert_eq!(
            patch.after.matches("GEMINI_API_KEY").count(),
            1,
            "带空格的赋值必须被识别为受管行，而不是另起一行:\n{}",
            patch.after
        );
        assert_eq!(patch.after, format!("GEMINI_API_KEY={SECRET}\n"));
    }

    #[test]
    fn crlf_and_missing_trailing_newline_are_preserved() {
        let dir = tmp();
        let before = "A=1\r\nGEMINI_API_KEY=sk-old\r\nB=2";
        std::fs::write(writer_in(dir.path(), "").path(), before).unwrap();

        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        assert_eq!(
            patch.after,
            format!("A=1\r\nGEMINI_API_KEY={SECRET}\r\nB=2")
        );
        assert_eq!(patch.after.matches("\r\n").count(), 2);
        assert!(!patch.after.ends_with('\n'), "不需要追加时不得补尾随换行");
    }

    #[test]
    fn appending_terminates_the_previous_line() {
        let dir = tmp();
        let before = "A=1";
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();

        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert_eq!(
            patch.after,
            format!("A=1\nGEMINI_API_KEY={SECRET}\nGOOGLE_GEMINI_BASE_URL={BASE}\n")
        );
    }

    #[test]
    fn plan_is_idempotent() {
        let dir = tmp();
        for base in ["", BASE] {
            let first = writer_in(dir.path(), base).plan(SECRET).unwrap();
            std::fs::write(writer_in(dir.path(), base).path(), &first.after).unwrap();

            let second = writer_in(dir.path(), base).plan(SECRET).unwrap();
            assert_eq!(second.before, first.after);
            assert_eq!(second.after, first.after, "二次投递不得产生额外改动");
        }
    }

    #[test]
    fn rejects_empty_key() {
        let dir = tmp();
        for bad in ["", "   ", "\n"] {
            let err = writer_in(dir.path(), BASE).plan(bad).unwrap_err();
            assert!(matches!(err, Error::Inject { .. }), "{bad:?}");
            assert!(err.to_string().contains("密钥为空"), "{err}");
        }
    }

    #[test]
    fn errors_never_echo_the_key() {
        let dir = tmp();
        // 非法 UTF-8 目标 → 读取阶段报错
        std::fs::write(writer_in(dir.path(), BASE).path(), [0xff, 0xfe, 0x00]).unwrap();
        let err = writer_in(dir.path(), BASE)
            .plan("sk-VERY-SECRET-0123456789")
            .unwrap_err();
        assert!(!err.to_string().contains("VERY-SECRET"), "{err}");
    }

    #[test]
    fn fields_mask_only_the_secret() {
        let dir = tmp();
        let fields = writer_in(dir.path(), BASE).fields(SECRET);
        assert_eq!(fields[0].key, "GEMINI_API_KEY");
        assert_eq!(fields[0].masked, "…cdef");
        assert_eq!(fields[1].key, "GOOGLE_GEMINI_BASE_URL");
        assert_eq!(fields[1].masked, BASE);

        let text = format!("{:?}", fields);
        assert!(!text.contains(SECRET), "{text}");
    }

    #[test]
    fn values_needing_quotes_stay_on_one_line() {
        let dir = tmp();
        // 这个值同时含空格、`#`、`$`、反引号、引号、反斜杠与**真换行**
        let hostile = "sk-a b#c$d`e\"f\\g\nh";
        let patch = writer_in(dir.path(), hostile).plan(SECRET).unwrap();

        // 值里的换行不得变成物理换行
        assert_eq!(
            patch.after.lines().count(),
            2,
            "物理行数必须不变:\n{}",
            patch.after
        );

        // 密钥本身在安全字符集内 → 裸写
        let key_line = patch
            .after
            .lines()
            .find(|l| l.starts_with("GEMINI_API_KEY="))
            .expect("有密钥行");
        assert_eq!(key_line, format!("GEMINI_API_KEY={SECRET}"));

        // base_url 需要转义 → 双引号包裹，且所有危险字符都被转义
        let base_line = patch
            .after
            .lines()
            .find(|l| l.starts_with("GOOGLE_GEMINI_BASE_URL="))
            .expect("有 base 行");
        assert!(
            base_line.starts_with("GOOGLE_GEMINI_BASE_URL=\""),
            "{base_line}"
        );
        assert!(base_line.ends_with('"'), "{base_line}");
        assert!(base_line.contains("\\n"), "换行必须被转义: {base_line}");
        assert!(base_line.contains("\\\""), "引号必须被转义: {base_line}");
        assert!(base_line.contains("\\\\"), "反斜杠必须被转义: {base_line}");
    }

    #[test]
    fn comment_and_prefix_collisions_are_not_managed() {
        let dir = tmp();
        let before = "# GEMINI_API_KEY=sk-commented\nMY_GEMINI_API_KEY=sk-prefixed\nGEMINI_API_KEY_EXTRA=sk-suffixed\nGEMINI_API_KEY\n";
        std::fs::write(writer_in(dir.path(), "").path(), before).unwrap();

        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        assert!(
            patch.after.starts_with(before),
            "非受管行必须原样保留:\n{}",
            patch.after
        );
        assert!(patch.after.contains("sk-commented"));
        assert!(patch.after.contains("sk-prefixed"));
        assert!(patch.after.contains("sk-suffixed"));

        // 只应有一行**行首**受管赋值（子串计数会把 `MY_GEMINI_API_KEY=` 也算进去）
        let managed: Vec<&str> = patch
            .after
            .lines()
            .filter(|l| l.starts_with("GEMINI_API_KEY="))
            .collect();
        assert_eq!(managed.len(), 1, "只应有一行受管赋值:\n{}", patch.after);
        assert_eq!(managed[0], format!("GEMINI_API_KEY={SECRET}"));
    }

    #[test]
    fn bare_value_is_not_quoted() {
        assert_eq!(render_value("sk-abc123"), "sk-abc123");
        assert_eq!(
            render_value("https://relay.example.com"),
            "https://relay.example.com"
        );
        assert_eq!(render_value(""), "\"\"");
        assert_eq!(render_value("a b"), "\"a b\"");
        assert_eq!(render_value("a=b"), "\"a=b\"");
        assert_eq!(render_value("a#b"), "\"a#b\"");
    }

    #[test]
    fn split_env_lines_keeps_endings() {
        assert!(split_env_lines("").is_empty());
        let one = split_env_lines("a");
        assert_eq!((one[0].body, one[0].ending), ("a", ""));
        let two = split_env_lines("a\nb\r\n");
        assert_eq!((two[0].body, two[0].ending), ("a", "\n"));
        assert_eq!((two[1].body, two[1].ending), ("b\r", "\n"));
    }

    #[test]
    fn target_path_is_the_declared_relative_target() {
        let home = Path::new("/tmp/nobody");
        let writer = GeminiCliWriter::new(home, BASE);
        assert_eq!(
            writer.target_path(),
            home.join(DeliveryChannel::GeminiCli.relative_target())
        );
    }

    #[test]
    fn unescaped_quote_count_skips_escaped_quotes() {
        // 完整引号值 → 2（偶数 = 平衡）
        assert_eq!(unescaped_quote_count(r#"KEY="a""#), 2);
        // 结尾的引号被转义 → 只剩开头那个（奇数 = 跨行未闭合）
        assert_eq!(unescaped_quote_count(r#"KEY="a\""#), 1);
        // 中间的引号被转义 → 仍是 2（平衡）
        assert_eq!(unescaped_quote_count(r#"KEY="a\"b""#), 2);
        assert_eq!(unescaped_quote_count(r#"KEY=a"b"#), 1);
        assert_eq!(unescaped_quote_count("KEY=bare"), 0);
        // 连续两个反斜杠：第二个不是转义符，后面的引号仍然算数
        assert_eq!(unescaped_quote_count(r#"KEY="a\\""#), 2);
    }

    #[test]
    fn line_inside_another_multiline_value_is_not_managed() {
        // 别人的值跨行，续行**恰好**长得像受管键 → 不能碰它
        let dir = tmp();
        let before =
            "OTHER=\"start\nGEMINI_API_KEY=sk-inside-other-value\nend\"\nGEMINI_API_KEY=sk-real\n";
        std::fs::write(writer_in(dir.path(), "").path(), before).unwrap();

        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        assert_eq!(
            patch.after,
            format!("OTHER=\"start\nGEMINI_API_KEY=sk-inside-other-value\nend\"\nGEMINI_API_KEY={SECRET}\n"),
            "别的键跨行的值必须逐字节保留；只改真正的行首赋值"
        );
    }

    #[test]
    fn managed_value_spanning_lines_is_refused() {
        // 受管键自己的值跨行：改写会留下孤立碎片 → 拒绝
        let dir = tmp();
        let before = "GEMINI_API_KEY=\"sk-old\ncontinued\"\n";
        std::fs::write(writer_in(dir.path(), "").path(), before).unwrap();

        let err = writer_in(dir.path(), "").plan(SECRET).unwrap_err();
        assert!(matches!(err, Error::Inject { .. }), "{err:?}");
        assert!(err.to_string().contains("跨多行"), "{err}");
        assert_eq!(
            std::fs::read_to_string(writer_in(dir.path(), "").path()).unwrap(),
            before,
            "拒绝时文件零改动"
        );
    }

    #[test]
    fn duplicate_managed_key_with_open_quote_is_refused() {
        // 第一处正常、第二处跨行：删掉第二处会留下孤立碎片 → 同样拒绝
        let dir = tmp();
        let before = "GEMINI_API_KEY=sk-a\nGEMINI_API_KEY=\"sk-b\nx\"\n";
        std::fs::write(writer_in(dir.path(), "").path(), before).unwrap();

        let err = writer_in(dir.path(), "").plan(SECRET).unwrap_err();
        assert!(matches!(err, Error::Inject { .. }), "{err:?}");
        assert!(err.to_string().contains("跨多行"), "{err}");
    }

    #[test]
    fn appending_into_an_unterminated_quote_is_refused() {
        // 文件以未闭合引号结束 → 追加的行会被吞进那个值里（写了但不生效）→ 拒绝
        let dir = tmp();
        let before = "OTHER=\"unterminated\n";
        std::fs::write(writer_in(dir.path(), "").path(), before).unwrap();

        let err = writer_in(dir.path(), "").plan(SECRET).unwrap_err();
        assert!(matches!(err, Error::Inject { .. }), "{err:?}");
        assert!(err.to_string().contains("没有闭合"), "{err}");
    }

    #[test]
    fn escaped_quotes_do_not_confuse_the_scanner() {
        // 单行值里的转义引号不得被误判成「跨行」
        let dir = tmp();
        let before = "OTHER=\"a\\\"b\"\nGEMINI_API_KEY=sk-old\n";
        std::fs::write(writer_in(dir.path(), "").path(), before).unwrap();

        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        assert_eq!(
            patch.after,
            format!("OTHER=\"a\\\"b\"\nGEMINI_API_KEY={SECRET}\n")
        );
    }

    #[test]
    fn quoted_existing_value_is_replaced_cleanly() {
        let dir = tmp();
        let before = "GEMINI_API_KEY=\"sk-old\"\n";
        std::fs::write(writer_in(dir.path(), "").path(), before).unwrap();

        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        assert_eq!(patch.after, format!("GEMINI_API_KEY={SECRET}\n"));
    }

    // ============================================ M6-S1 复审 P2-1 / P2-2 的修复

    #[test]
    fn a_lone_quote_in_a_comment_does_not_block_delivery() {
        // **P2-1 的回归**（复审者给的原文夹具）：注释里的孤儿 `"` 曾让 `inside` 翻转为真，
        // 后续行全被当成「跨行值的续行」→ 无命中 → 追加又被 `ends_inside` 拒 → 整条通道报错。
        // 真实 dotenv 解析器不会让行首 `#` 开启跨行值。
        let dir = tmp();
        let before = "# note: a lone \" quote\nOTHER=1\nGEMINI_API_KEY=sk-old\n";
        std::fs::write(writer_in(dir.path(), "").path(), before).unwrap();

        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        assert_eq!(
            patch.after,
            format!("# note: a lone \" quote\nOTHER=1\nGEMINI_API_KEY={SECRET}\n"),
            "注释里的孤儿引号不得让投递失败，也不得让受管行被跳过"
        );
        assert!(!patch.after.contains("sk-old"), "旧密钥必须被替换掉");
    }

    #[test]
    fn a_comment_inside_a_multiline_value_is_still_counted() {
        // 与上一条**互为反例**：`#` 只有在「不在引号值内部」时才是注释。
        // 若把「跳过注释行」写成无条件的，这里 line 2 会被跳过 → `inside` 卡在 true
        // → 后面的受管行全部被当成续行 → 本用例会失败。
        let dir = tmp();
        let before = "OTHER=\"a\n# b\"\nA=1\nGEMINI_API_KEY=sk-old\n";
        std::fs::write(writer_in(dir.path(), "").path(), before).unwrap();

        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        assert_eq!(
            patch.after,
            format!("OTHER=\"a\n# b\"\nA=1\nGEMINI_API_KEY={SECRET}\n"),
            "跨行值内部的 `#` 是值的一部分，必须照常参与引号计数"
        );
    }

    #[test]
    fn a_comment_line_with_a_balanced_quote_pair_is_harmless() {
        // 偶数个引号本来就无害，钉住它是防「修 P2-1 时把注释行整个吃掉」的回归
        let dir = tmp();
        let before = "# 他说 \"你好\"\nGEMINI_API_KEY=sk-old\n";
        std::fs::write(writer_in(dir.path(), "").path(), before).unwrap();

        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        assert_eq!(
            patch.after,
            format!("# 他说 \"你好\"\nGEMINI_API_KEY={SECRET}\n")
        );
    }

    #[test]
    fn crlf_file_keeps_crlf_for_appended_lines() {
        // **P2-2 的回归**：追加段曾固定写 `\n`，CRLF 文件会变成混合行尾。
        let dir = tmp();
        let before = "A=1\r\n";
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();

        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert_eq!(
            patch.after,
            format!("A=1\r\nGEMINI_API_KEY={SECRET}\r\nGOOGLE_GEMINI_BASE_URL={BASE}\r\n")
        );
        // 逐字节核对：`\n` 的个数与 `\r\n` 的个数必须相等（没有落单的 LF）
        assert_eq!(patch.after.matches('\n').count(), 3);
        assert_eq!(patch.after.matches("\r\n").count(), 3);
    }

    #[test]
    fn crlf_file_without_trailing_newline_gets_a_crlf_separator() {
        let dir = tmp();
        std::fs::write(writer_in(dir.path(), "").path(), "A=1\r\nB=2").unwrap();

        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        assert_eq!(
            patch.after,
            format!("A=1\r\nB=2\r\nGEMINI_API_KEY={SECRET}\r\n")
        );
    }

    #[test]
    fn lf_file_still_appends_lf() {
        // 反例保护：LF 文件不得被 CRLF 化
        let dir = tmp();
        std::fs::write(writer_in(dir.path(), "").path(), "A=1\nB=2\n").unwrap();

        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        assert_eq!(patch.after, format!("A=1\nB=2\nGEMINI_API_KEY={SECRET}\n"));
        assert!(!patch.after.contains('\r'), "LF 文件不得出现 CR");
    }

    #[test]
    fn dominant_eol_picks_the_majority() {
        let cases = [
            ("", "\n"),
            ("A=1\n", "\n"),
            ("A=1\r\n", "\r\n"),
            ("A=1\r\nB=2\nC=3\r\n", "\r\n"),
            ("A=1\nB=2\nC=3\r\n", "\n"),
        ];
        for (text, expected) in cases {
            assert_eq!(dominant_eol(&split_env_lines(text)), expected, "{text:?}");
        }
    }
}
