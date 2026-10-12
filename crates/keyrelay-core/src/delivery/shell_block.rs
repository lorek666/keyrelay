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
        let after = splice_block(&before, &self.render_block(api_key));
        Ok(Patch::secret_bearing(self.path.clone(), before, after))
    }
}

/// 把区块拼进文件：已有区块就整体替换，否则追加到末尾。
///
/// **区块之外的字节逐字节保留**——包括「文件不以换行结尾」这种常见形态。
fn splice_block(before: &str, block: &str) -> String {
    if before.is_empty() {
        return format!("{block}\n");
    }

    if let Some((start, end)) = find_block(before) {
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
        return out;
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
    out
}

/// 找到区块的字节范围（含首尾标记行与它们各自的换行）。
fn find_block(text: &str) -> Option<(usize, usize)> {
    let start = text.find(BLOCK_BEGIN)?;
    // 起点必须位于行首（否则可能是注释里的引用）
    if start != 0 && text.as_bytes()[start - 1] != b'\n' {
        return None;
    }
    let after_begin = text[start..].find('\n').map(|i| start + i + 1)?;
    let end_marker = text[after_begin..].find(BLOCK_END)? + after_begin;
    // 结束标记也必须位于行首
    if end_marker != 0 && text.as_bytes()[end_marker - 1] != b'\n' {
        return None;
    }
    let end = text[end_marker..]
        .find('\n')
        .map(|i| end_marker + i + 1)
        .unwrap_or(text.len());
    Some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let (start, end) = find_block(&patch.after).expect("有区块");
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
