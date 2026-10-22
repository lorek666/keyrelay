//! DeepSeek Harness 桌面端通道：`~/.dsh/.credentials.yaml`（YAML 行级）。
//!
//! 只写 `refs:` 段中的 `KEYRELAY_API_KEY` 行，`records:` 段逐字节不动。
//! 不引入 YAML 解析依赖，用行级操作实现。

use std::path::{Path, PathBuf};

use super::json_text::read_text_or_empty;
use super::{masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;

const KEY_NAME: &str = "KEYRELAY_API_KEY";
const REFS_HEADER: &str = "refs:";
const VERSION_HEADER: &str = "version: 1";

pub struct DshWriter {
    path: PathBuf,
}

impl DshWriter {
    pub const FIELD_API_KEY: &'static str = "KEYRELAY_API_KEY";

    pub fn new(home: &Path, _base_url: &str) -> Self {
        Self::with_path(home.join(".dsh").join(".credentials.yaml"), _base_url)
    }

    pub fn with_path(path: impl Into<PathBuf>, _base_url: &str) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl DeliveryWriter for DshWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::DeepSeekHarness
    }

    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }

    fn field_names(&self) -> Vec<String> {
        vec![KEY_NAME.to_string()]
    }

    fn fields(&self, api_key: &str) -> Vec<DeliveryField> {
        vec![masked_field(KEY_NAME, api_key)]
    }

    fn plan(&self, api_key: &str) -> Result<Patch> {
        let before = read_text_or_empty(&self.path)?;
        let after = build_after(&before, api_key, &self.path)?;
        Ok(Patch::secret_bearing(self.path.clone(), before, after))
    }
}

fn build_after(before: &str, api_key: &str, path: &Path) -> Result<String> {
    if api_key.trim().is_empty() {
        return Err(Error::inject(path, "密钥为空，拒绝写入"));
    }

    let target_line = format!("  {KEY_NAME}: {api_key}");

    // 找到 refs: 段的起始行
    if let Some(refs_idx) = find_line_starting_with(before, REFS_HEADER) {
        let before_refs = &before[..refs_idx];
        let after_header = &before[refs_idx..];
        // 跳过 `refs:` 这一行
        let newline_after_header = after_header
            .find('\n')
            .map(|p| p + 1)
            .unwrap_or(after_header.len());
        let refs_body = &after_header[newline_after_header..];

        // 在 refs_body 里找 KEYRELAY_API_KEY 行
        if let Some(key_pos) = find_ref_line(refs_body, KEY_NAME) {
            // 替换这一行
            let line_end = refs_body[key_pos..]
                .find('\n')
                .map(|p| key_pos + p)
                .unwrap_or(refs_body.len());
            let before_key = &refs_body[..key_pos];
            let after_key = &refs_body[line_end..];
            let mut result = String::with_capacity(
                before_refs.len()
                    + newline_after_header
                    + before_key.len()
                    + target_line.len()
                    + after_key.len(),
            );
            result.push_str(before_refs);
            result.push_str(&after_header[..newline_after_header]);
            result.push_str(before_key);
            result.push_str(&target_line);
            result.push_str(after_key);
            Ok(result)
        } else {
            // 在 refs 段末尾追加
            let mut result = String::with_capacity(
                before_refs.len() + newline_after_header + refs_body.len() + target_line.len() + 1,
            );
            result.push_str(before_refs);
            result.push_str(&after_header[..newline_after_header]);
            result.push_str(refs_body);
            if !refs_body.is_empty() && !refs_body.ends_with('\n') {
                result.push('\n');
            }
            result.push_str(&target_line);
            result.push('\n');
            Ok(result)
        }
    } else {
        // refs: 段不存在，追加到文件末尾
        let mut result = String::with_capacity(before.len() + target_line.len() + 20);
        result.push_str(before);
        if !before.is_empty() && !before.ends_with('\n') {
            result.push('\n');
        }
        if !before.contains(VERSION_HEADER) {
            result.push_str(VERSION_HEADER);
            result.push('\n');
        }
        result.push_str(REFS_HEADER);
        result.push('\n');
        result.push_str(&target_line);
        result.push('\n');
        Ok(result)
    }
}

/// 找到第一个以指定前缀开头（忽略行首空格）的行的起始偏移。
fn find_line_starting_with(text: &str, prefix: &str) -> Option<usize> {
    let mut offset = 0usize;
    for line in text.lines() {
        if line.trim_start().starts_with(prefix) {
            return Some(offset);
        }
        offset += line.len() + 1;
    }
    None
}

/// 在 YAML 段体里找到 `  KEY_NAME:` 行的起始偏移。
fn find_ref_line(body: &str, key_name: &str) -> Option<usize> {
    let pattern = format!("{key_name}:");
    let mut offset = 0usize;
    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with(&pattern) {
            return Some(offset);
        }
        offset += line.len() + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-dsh-0123456789abcdef";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    fn writer_in(dir: &Path) -> DshWriter {
        DshWriter::with_path(dir.join(".credentials.yaml"), "")
    }

    #[test]
    fn creates_fresh_file() {
        let dir = tmp();
        let patch = writer_in(dir.path()).plan(SECRET).unwrap();
        assert_eq!(patch.before, "");
        assert!(patch.after.contains("version: 1"));
        assert!(patch.after.contains("refs:"));
        assert!(patch.after.contains("KEYRELAY_API_KEY: "));
        assert!(patch.after.contains(SECRET));
        assert_eq!(patch.new_file_mode, Some(0o600));
    }

    #[test]
    fn appends_refs_section_when_missing() {
        let dir = tmp();
        let before =
            "version: 1\nrecords:\n  some-key:\n    kind: grant\n    payload:\n      secret: abc\n";
        std::fs::write(writer_in(dir.path()).path(), before).unwrap();
        let patch = writer_in(dir.path()).plan(SECRET).unwrap();
        assert!(patch.after.contains("records:"));
        assert!(patch.after.contains("kind: grant"));
        assert!(patch.after.contains("refs:"));
        assert!(patch.after.contains("KEYRELAY_API_KEY: "));
        assert!(patch.after.contains(SECRET));
        let records_start = patch.after.find("records:").unwrap();
        let records_end = patch.after.find("refs:").unwrap();
        assert_eq!(
            &patch.after[records_start..records_end],
            "records:\n  some-key:\n    kind: grant\n    payload:\n      secret: abc\n"
        );
    }

    #[test]
    fn appends_key_to_existing_refs() {
        let dir = tmp();
        let before = "version: 1\nrefs:\n  TIANSHU_API_KEY: sk-other\n";
        std::fs::write(writer_in(dir.path()).path(), before).unwrap();
        let patch = writer_in(dir.path()).plan(SECRET).unwrap();
        assert!(patch.after.contains("TIANSHU_API_KEY: sk-other"));
        assert!(patch.after.contains("KEYRELAY_API_KEY: "));
        assert!(patch.after.contains(SECRET));
    }

    #[test]
    fn replaces_existing_key() {
        let dir = tmp();
        let before = "version: 1\nrefs:\n  KEYRELAY_API_KEY: sk-old\n  TIANSHU_API_KEY: sk-keep\n";
        std::fs::write(writer_in(dir.path()).path(), before).unwrap();
        let patch = writer_in(dir.path()).plan(SECRET).unwrap();
        assert!(!patch.after.contains("sk-old"));
        assert!(patch.after.contains(SECRET));
        assert!(patch.after.contains("TIANSHU_API_KEY: sk-keep"));
    }

    #[test]
    fn records_section_byte_for_byte_preserved() {
        let dir = tmp();
        let records = "version: 1\nrecords:\n  client-connection/browser-session:\n    kind: grant\n    payload:\n      secret: BASE64DATA\n";
        std::fs::write(writer_in(dir.path()).path(), records).unwrap();
        let patch = writer_in(dir.path()).plan(SECRET).unwrap();
        let records_end = patch.after.find("refs:").unwrap();
        assert_eq!(&patch.after[..records_end], records);
    }

    #[test]
    fn rejects_empty_key() {
        let dir = tmp();
        assert!(matches!(
            writer_in(dir.path()).plan(""),
            Err(Error::Inject { .. })
        ));
    }

    #[test]
    fn plan_is_idempotent() {
        let dir = tmp();
        let first = writer_in(dir.path()).plan(SECRET).unwrap();
        std::fs::write(writer_in(dir.path()).path(), &first.after).unwrap();
        let second = writer_in(dir.path()).plan(SECRET).unwrap();
        assert_eq!(second.after, first.after);
    }

    #[test]
    fn errors_never_echo_the_key() {
        let dir = tmp();
        let err = writer_in(dir.path()).plan("").unwrap_err();
        assert!(!err.to_string().contains("SECRET"), "{err}");
    }
}
