//! shell 标记块通道：在 rc 文件里维护一个由 KeyRelay 管理的区块。
//!
//! 与两个 JSON 通道不同，这里是**纯文本级**操作：只替换 `# >>> keyrelay >>>` 与
//! `# <<< keyrelay <<<` 之间的内容，**区块之外的字节一个都不动**。
//! 用户的函数定义、别名、注释、甚至没有尾随换行的最后一行，都必须原样保留。

use std::path::{Path, PathBuf};

use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;

pub const BLOCK_BEGIN: &str = "# >>> keyrelay >>>";
pub const BLOCK_END: &str = "# <<< keyrelay <<<";
const BLOCK_NOTE: &str = "# 由 KeyRelay 管理；手工修改会在下次投递时被覆盖";

/// rc 文件语法。按平台选，**不混用**。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ShellSyntax {
    /// `export VAR="value"`（macOS/Linux 的 zsh/bash）
    Posix,
    /// `$env:VAR = "value"`（Windows PowerShell 的 $PROFILE）
    PowerShell,
}

impl ShellSyntax {
    pub fn for_current_platform() -> Self {
        if cfg!(target_os = "windows") {
            Self::PowerShell
        } else {
            Self::Posix
        }
    }

    /// 默认 rc 文件（相对 home）。
    pub fn default_rc_relative_path(self) -> &'static str {
        match self {
            Self::Posix => ".zshrc",
            Self::PowerShell => "Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
        }
    }

    /// 把一个键值对渲染成一行赋值语句。
    pub fn render_assignment(self, key: &str, value: &str) -> String {
        match self {
            Self::Posix => format!("export {key}=\"{}\"", escape_posix(value)),
            Self::PowerShell => format!("$env:{key} = \"{}\"", escape_powershell(value)),
        }
    }
}

/// Posix 双引号内的转义：`\`、`"`、`$`、反引号。
///
/// 不转义 `$` 的话，值里的 `$(...)` 会被 shell 当命令执行——这是真实的注入面。
fn escape_posix(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '$' => out.push_str("\\$"),
            '`' => out.push_str("\\`"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out
}

/// PowerShell 双引号内的转义：反引号本身、`"`、`$`，以及换行。
fn escape_powershell(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '`' => out.push_str("``"),
            '"' => out.push_str("`\""),
            '$' => out.push_str("`$"),
            '\n' => out.push_str("`n"),
            '\r' => out.push_str("`r"),
            other => out.push(other),
        }
    }
    out
}

pub struct ShellBlockWriter {
    path: PathBuf,
    base_url: String,
    syntax: ShellSyntax,
}

impl ShellBlockWriter {
    pub const FIELD_KEY: &'static str = "OPENAI_API_KEY";
    pub const FIELD_BASE_URL: &'static str = "OPENAI_BASE_URL";

    pub fn new(home: &Path, base_url: &str) -> Self {
        let syntax = ShellSyntax::for_current_platform();
        Self::with_path(
            home.join(syntax.default_rc_relative_path()),
            base_url,
            syntax,
        )
    }

    pub fn with_path(path: impl Into<PathBuf>, base_url: &str, syntax: ShellSyntax) -> Self {
        Self {
            path: path.into(),
            base_url: base_url.to_string(),
            syntax,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn syntax(&self) -> ShellSyntax {
        self.syntax
    }

    /// 渲染区块（含首尾标记行，不含尾随换行）。
    pub fn render_block(&self, api_key: &str) -> String {
        let mut lines = vec![
            BLOCK_BEGIN.to_string(),
            BLOCK_NOTE.to_string(),
            self.syntax.render_assignment(Self::FIELD_KEY, api_key),
        ];
        if !self.base_url.is_empty() {
            lines.push(
                self.syntax
                    .render_assignment(Self::FIELD_BASE_URL, &self.base_url),
            );
        }
        lines.push(BLOCK_END.to_string());
        lines.join("\n")
    }
}

impl DeliveryWriter for ShellBlockWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::ShellBlock
    }

    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }

    fn field_names(&self) -> Vec<String> {
        let mut names = vec![Self::FIELD_KEY.to_string()];
        if !self.base_url.is_empty() {
            names.push(Self::FIELD_BASE_URL.to_string());
        }
        names
    }

    fn fields(&self, api_key: &str) -> Vec<DeliveryField> {
        let mut fields = vec![masked_field(Self::FIELD_KEY, api_key)];
        if !self.base_url.is_empty() {
            fields.push(literal_field(Self::FIELD_BASE_URL, &self.base_url));
        }
        fields
    }

    fn plan(&self, api_key: &str) -> Result<Patch> {
        if api_key.trim().is_empty() {
            return Err(Error::inject(&self.path, "密钥为空，拒绝写入"));
        }
        let before = super::json_text::read_text_or_empty(&self.path)?;
        let after = splice_block(&before, &self.render_block(api_key), &self.path)?;
        Ok(Patch::secret_bearing(self.path.clone(), before, after))
    }
}

/// 把区块拼进文件：已有区块就整体替换，否则追加到末尾。
///
/// **区块之外的字节逐字节保留**——包括「文件不以换行结尾」这种常见形态。
fn splice_block(before: &str, block: &str, path: &Path) -> Result<String> {
    if before.is_empty() {
        return Ok(format!("{block}\n"));
    }

    if let Some((start, end)) = locate_block(before, path)? {
        // `end` 指向原区块**收尾换行之后**的位置，`block` 自身不带换行，
        // 因此拼接时必须补回那个换行：
        //   before = prefix + block_old + "\n" + rest
        //   after  = prefix + block_new + "\n" + rest
        // 漏掉它会让「区块与后续内容之间的空行」被吃掉，
        // 而且第二次投递会少一个字节（幂等性断裂）——本模块的测试就是这么抓到的。
        let mut out = String::with_capacity(before.len() + block.len());
        out.push_str(&before[..start]);
        out.push_str(block);
        out.push('\n');
        out.push_str(&before[end..]);
        return Ok(out);
    }

    let mut out = String::with_capacity(before.len() + block.len() + 2);
    out.push_str(before);
    if !before.ends_with('\n') {
        out.push('\n');
    }
    // 与上文之间留一个空行，避免和最后一行粘在一起
    if !before.ends_with("\n\n") {
        out.push('\n');
    }
    out.push_str(block);
    out.push('\n');
    Ok(out)
}

/// 找到**由我们管理的那个区块**的字节范围（含首尾标记行与它们各自的换行）。
///
/// 这个函数比看上去重要：它的每一个「找不到」分支都对应一种会**吃掉用户内容**或
/// **反复追加区块**的真实形态（M2-S2 复审的两条 P1 都出在这里）。
///
/// 规则：
/// 1. 只认**行首**的标记——注释里/字符串里引用过 `# >>> keyrelay >>>` 不算；
/// 2. 把所有行首 `# >>> keyrelay >>>` 都看一遍（**不是只看第一处**）。
///    早先的实现找到第一处发现不在行首就 `return None`，于是：
///    用户注释里提到过这个标记 → 每次投递都**追加**一个新块 →
///    每一把历史密钥的明文永久留在 rc 文件里；
/// 3. 某个行首开始标记之后**没有**匹配的结束标记 → **拒绝写入**并报错。
///    这种文件是被手工改过的；如果按「从开始标记一直吃到文件末尾」处理，
///    用户写在区块后面的函数会被静默删掉；
/// 4. 有**多个**完整区块 → 拒绝写入（不是我们能造出来的状态，语义有歧义）。
fn locate_block(text: &str, path: &Path) -> Result<Option<(usize, usize)>> {
    let begins = line_start_offsets(text, BLOCK_BEGIN);
    if begins.is_empty() {
        return Ok(None);
    }
    let ends = line_start_offsets(text, BLOCK_END);

    let mut complete: Vec<(usize, usize)> = Vec::new();
    for start in &begins {
        // 找这个开始标记之后的第一个结束标记
        match ends.iter().find(|e| **e > *start) {
            Some(end_marker) => {
                let end = text[*end_marker..]
                    .find('\n')
                    .map(|i| end_marker + i + 1)
                    .unwrap_or(text.len());
                complete.push((*start, end));
            }
            None => {
                return Err(Error::inject(
                    path,
                    format!(
                        "文件里有一个孤立的 `{BLOCK_BEGIN}`（第 {} 行）却没有对应的 `{BLOCK_END}`；\
                         拒绝改写以免删掉你写在它后面的内容。请手工补上结束标记或删掉开始标记后重试",
                        line_number_of(text, *start)
                    ),
                ));
            }
        }
    }

    if complete.len() > 1 {
        return Err(Error::inject(
            path,
            format!(
                "文件里有 {} 个 KeyRelay 区块，语义有歧义；\
                 请手工只保留一个（`{BLOCK_BEGIN}` … `{BLOCK_END}`）后重试",
                complete.len()
            ),
        ));
    }

    Ok(complete.into_iter().next())
}

/// 收集 `marker` 在**行首**出现的所有字节偏移。
fn line_start_offsets(text: &str, marker: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    let mut offsets = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = text[from..].find(marker) {
        let at = from + rel;
        if at == 0 || bytes[at - 1] == b'\n' {
            offsets.push(at);
        }
        from = at + marker.len();
    }
    offsets
}

fn line_number_of(text: &str, offset: usize) -> usize {
    text[..offset].matches('\n').count() + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const SECRET: &str = "sk-shell-0123456789abcdef";
    const BASE: &str = "https://relay.example.com";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    fn writer_in(dir: &Path, base_url: &str) -> ShellBlockWriter {
        ShellBlockWriter::with_path(dir.join("rc"), base_url, ShellSyntax::Posix)
    }

    #[test]
    fn creates_fresh_file_with_block() {
        let dir = tmp();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert_eq!(patch.before, "");
        assert!(patch.after.starts_with(BLOCK_BEGIN));
        assert!(patch.after.ends_with(&format!("{BLOCK_END}\n")));
        assert!(patch
            .after
            .contains(&format!("export OPENAI_API_KEY=\"{SECRET}\"")));
        assert!(patch
            .after
            .contains(&format!("export OPENAI_BASE_URL=\"{BASE}\"")));
        assert_eq!(patch.new_file_mode, Some(0o600));
    }

    #[test]
    fn appends_without_touching_existing_bytes() {
        let dir = tmp();
        // 刻意不以换行结尾，且含自定义函数与注释
        let before =
            "# my rc\nfpath=(~/.zsh/completions $fpath)\nalias gs='git status'\nsource ~/.aliases";
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();

        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert!(
            patch.after.starts_with(before),
            "区块之外的内容必须原样保留: {}",
            patch.after
        );
        assert!(patch.after.contains(BLOCK_BEGIN));
        assert!(patch.after.ends_with(&format!("{BLOCK_END}\n")));
    }

    #[test]
    fn replaces_existing_block_in_place() {
        let dir = tmp();
        let first = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        let head = "# head\n";
        let tail = "# tail\nalias x='y'\n";
        let composed = format!("{head}{}{tail}", first.after);
        std::fs::write(writer_in(dir.path(), BASE).path(), &composed).unwrap();

        let patch = writer_in(dir.path(), BASE)
            .plan("sk-shell-ROTATED-999999")
            .unwrap();
        assert!(patch.after.starts_with(head), "{}", patch.after);
        assert!(patch.after.ends_with(tail), "{}", patch.after);
        assert!(patch.after.contains("sk-shell-ROTATED-999999"));
        assert!(!patch.after.contains(SECRET), "旧密钥必须被替换掉");
        // 区块只应出现一次
        assert_eq!(patch.after.matches(BLOCK_BEGIN).count(), 1);
        assert_eq!(patch.after.matches(BLOCK_END).count(), 1);
    }

    #[test]
    fn block_outside_is_byte_identical_after_replace() {
        let dir = tmp();
        let first = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        let head = "# head\nfunction foo() {\n  echo hi\n}\n";
        let tail = "\n# tail without newline";
        let composed = format!("{head}{}{tail}", first.after);
        std::fs::write(writer_in(dir.path(), BASE).path(), &composed).unwrap();

        let patch = writer_in(dir.path(), BASE).plan("sk-new").unwrap();
        let (start, end) = locate_block(&patch.after, Path::new("/tmp/rc"))
            .expect("应能定位")
            .expect("有区块");
        assert_eq!(&patch.after[..start], head, "区块前必须逐字节相同");
        assert_eq!(&patch.after[end..], tail, "区块后必须逐字节相同");
    }

    #[test]
    fn plan_is_idempotent() {
        let dir = tmp();
        let first = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        std::fs::write(writer_in(dir.path(), BASE).path(), &first.after).unwrap();
        let second = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert_eq!(second.after, first.after);
    }

    #[test]
    fn escapes_shell_metacharacters() {
        let dir = tmp();
        let hostile = "sk-a\"b\\c$HOME`id`d";
        let patch = writer_in(dir.path(), "https://x/$(whoami)")
            .plan(hostile)
            .unwrap();

        let key_line = patch
            .after
            .lines()
            .find(|l| l.starts_with("export OPENAI_API_KEY="))
            .expect("有密钥行");
        assert!(key_line.contains("\\\""), "{key_line}");
        assert!(key_line.contains("\\\\"), "{key_line}");
        assert!(key_line.contains("\\$HOME"), "{key_line}");
        assert!(key_line.contains("\\`id\\`"), "{key_line}");
        assert!(!key_line.contains("$(whoami)"), "{key_line}");
        let base_line = patch
            .after
            .lines()
            .find(|l| l.starts_with("export OPENAI_BASE_URL="))
            .expect("有 base 行");
        assert!(base_line.contains("\\$(whoami)"), "{base_line}");
    }

    #[test]
    fn powershell_syntax_uses_env_prefix() {
        let dir = tmp();
        let writer = ShellBlockWriter::with_path(
            dir.path().join("profile.ps1"),
            BASE,
            ShellSyntax::PowerShell,
        );
        let patch = writer.plan(SECRET).unwrap();
        assert!(
            patch
                .after
                .contains(&format!("$env:OPENAI_API_KEY = \"{SECRET}\"")),
            "{}",
            patch.after
        );
        assert!(patch.after.contains("$env:OPENAI_BASE_URL"));
        assert!(!patch.after.contains("export "), "不得混用 Posix 语法");
    }

    #[test]
    fn powershell_escapes_backtick_and_dollar() {
        let rendered = ShellSyntax::PowerShell.render_assignment("K", "a`b$c\"d");
        assert_eq!(rendered, "$env:K = \"a``b`$c`\"d\"");
    }

    #[test]
    fn platform_defaults() {
        let syntax = ShellSyntax::for_current_platform();
        if cfg!(target_os = "windows") {
            assert_eq!(syntax, ShellSyntax::PowerShell);
            assert!(syntax.default_rc_relative_path().ends_with(".ps1"));
        } else {
            assert_eq!(syntax, ShellSyntax::Posix);
            assert_eq!(syntax.default_rc_relative_path(), ".zshrc");
        }
    }

    #[test]
    fn empty_base_url_writes_only_the_key() {
        let dir = tmp();
        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        assert!(!patch.after.contains("OPENAI_BASE_URL"), "{}", patch.after);
        assert_eq!(writer_in(dir.path(), "").field_names().len(), 1);
    }

    #[test]
    fn rejects_empty_key() {
        let dir = tmp();
        assert!(matches!(
            writer_in(dir.path(), BASE).plan("   "),
            Err(Error::Inject { .. })
        ));
    }

    #[test]
    fn a_marker_mentioned_earlier_in_a_comment_does_not_cause_repeated_appends() {
        // **M2-S2 复审 P1-1 的回归**：文件在真实区块**之前**含一处非行首的标记字样时，
        // 旧实现找到第一处就放弃 → 每次投递都追加一个新块 →
        // 每一把历史密钥的明文永久留在 rc 里。
        let dir = tmp();
        let path = writer_in(dir.path(), BASE).path().to_path_buf();

        let mut text = format!(
            "# 注意：下面那段由工具生成，形如 {BLOCK_BEGIN} … {BLOCK_END}\nexport PATH=/usr/bin\n"
        );
        fs::write(&path, &text).unwrap();

        for round in 0..3 {
            let secret = format!("sk-round-{round}-0123456789");
            let patch = writer_in(dir.path(), BASE).plan(&secret).unwrap();
            fs::write(&path, &patch.after).unwrap();
            text = patch.after;
        }

        assert_eq!(
            text.matches(BLOCK_BEGIN).count(),
            2,
            "只应有一处引用 + 一个真实区块，实际:\n{text}"
        );
        assert_eq!(text.matches(BLOCK_END).count(), 2);
        assert!(text.contains("sk-round-2-0123456789"), "应保留最新密钥");
        assert!(
            !text.contains("sk-round-0-0123456789"),
            "历史密钥必须被替换掉，不能留在文件里:\n{text}"
        );
    }

    #[test]
    fn orphan_begin_marker_is_refused_instead_of_eating_user_content() {
        // **M2-S2 复审 P1-2 的回归**：用户删掉结束标记并在区块后追加内容时，
        // 「从开始标记一直吃到文件末尾」会把用户的函数静默删掉。
        let dir = tmp();
        let path = writer_in(dir.path(), BASE).path().to_path_buf();
        let text = format!(
            "# my rc\n{BLOCK_BEGIN}\n{BLOCK_NOTE}\nexport OPENAI_API_KEY=\"sk-old\"\n\nfunction keep_me() {{\n  echo hi\n}}\n"
        );
        fs::write(&path, &text).unwrap();

        let err = writer_in(dir.path(), BASE).plan(SECRET).unwrap_err();
        assert!(matches!(err, Error::Inject { .. }), "{err:?}");
        let message = err.to_string();
        assert!(message.contains("孤立"), "{message}");
        assert!(message.contains("结束标记"), "{message}");

        // 文件一个字节都没动
        assert_eq!(fs::read_to_string(&path).unwrap(), text);
    }

    #[test]
    fn multiple_complete_blocks_are_refused() {
        let dir = tmp();
        let path = writer_in(dir.path(), BASE).path().to_path_buf();
        let text =
            format!("{BLOCK_BEGIN}\na\n{BLOCK_END}\n# middle\n{BLOCK_BEGIN}\nb\n{BLOCK_END}\n");
        fs::write(&path, &text).unwrap();

        let err = writer_in(dir.path(), BASE).plan(SECRET).unwrap_err();
        assert!(matches!(err, Error::Inject { .. }), "{err:?}");
        assert!(err.to_string().contains("歧义"), "{err}");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            text,
            "拒绝时不得改动文件"
        );
    }

    #[test]
    fn a_lone_end_marker_is_tolerated() {
        // 只有一个孤立的结束标记是无害的（它只是注释），照常追加新区块
        let dir = tmp();
        let path = writer_in(dir.path(), BASE).path().to_path_buf();
        let text = format!("# my rc\n{BLOCK_END}\nalias gs='git status'\n");
        fs::write(&path, &text).unwrap();

        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert!(patch.after.starts_with(&text), "{}", patch.after);
        assert!(patch.after.contains(BLOCK_BEGIN));
    }

    #[test]
    fn line_number_is_reported_for_the_orphan_marker() {
        let dir = tmp();
        let path = writer_in(dir.path(), BASE).path().to_path_buf();
        let text = format!("# line1\n# line2\n{BLOCK_BEGIN}\nbody\n");
        fs::write(&path, &text).unwrap();

        let err = writer_in(dir.path(), BASE).plan(SECRET).unwrap_err();
        assert!(err.to_string().contains("第 3 行"), "{err}");
    }

    #[test]
    fn marker_inside_a_comment_is_not_treated_as_the_block() {
        // 只有位于行首的标记才算区块起点
        let dir = tmp();
        let before = format!("# 提到 {BLOCK_BEGIN} 但不在行首\nfoo=1");
        std::fs::write(writer_in(dir.path(), BASE).path(), &before).unwrap();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert!(patch.after.starts_with(&before), "{}", patch.after);
        assert_eq!(patch.after.matches(BLOCK_BEGIN).count(), 2);
    }
}
