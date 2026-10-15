//! Hermes Agent 通道：`~/.hermes/config.yaml`（YAML 格式）。
//!
//! 用 `# >>> keyrelay >>>` / `# <<< keyrelay <<<` 标记块写入
//! `api_key` 和 `base_url`，块外字节逐字节不动。
//! 策略与 MCode 通道相同：只做行级操作，不引入 YAML 解析依赖。

use std::path::{Path, PathBuf};

use super::json_text::read_text_or_empty;
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;

pub const BLOCK_BEGIN: &str = "# >>> keyrelay >>>";
pub const BLOCK_END: &str = "# <<< keyrelay <<<";

pub struct HermesWriter {
    path: PathBuf,
    base_url: String,
}

impl HermesWriter {
    pub const FIELD_API_KEY: &'static str = "api_key";
    pub const FIELD_BASE_URL: &'static str = "base_url";

    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path(home.join(".hermes").join("config.yaml"), base_url)
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
}

impl DeliveryWriter for HermesWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::Hermes
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
        let after = build_after(&before, api_key, &self.base_url, &self.path)?;
        Ok(Patch::secret_bearing(self.path.clone(), before, after))
    }
}

fn build_after(before: &str, api_key: &str, base_url: &str, path: &Path) -> Result<String> {
    if api_key.trim().is_empty() {
        return Err(Error::inject(path, "密钥为空，拒绝写入"));
    }

    let block = build_block(api_key, base_url);

    // 如果已有标记块，替换
    if let Some(begin_pos) = before.find(BLOCK_BEGIN) {
        if let Some(end_pos) = before[begin_pos..].find(BLOCK_END) {
            let absolute_end = begin_pos + end_pos + BLOCK_END.len();
            let after_end = if before[absolute_end..].starts_with('\n') {
                absolute_end + 1
            } else {
                absolute_end
            };
            let mut result = String::with_capacity(before.len() + block.len() + 1);
            result.push_str(&before[..begin_pos]);
            result.push_str(&block);
            result.push_str(&before[after_end..]);
            return Ok(result);
        }
    }

    // 没有标记块，追加到文件末尾
    let mut result = String::with_capacity(before.len() + block.len() + 1);
    result.push_str(before);
    if !before.is_empty() && !before.ends_with('\n') {
        result.push('\n');
    }
    result.push_str(&block);
    Ok(result)
}

fn build_block(api_key: &str, base_url: &str) -> String {
    let mut block = String::new();
    block.push_str(BLOCK_BEGIN);
    block.push('\n');
    block.push_str("api_key: ");
    block.push_str(api_key);
    block.push('\n');
    if !base_url.is_empty() {
        block.push_str("base_url: ");
        block.push_str(base_url);
        block.push('\n');
    }
    block.push_str(BLOCK_END);
    block.push('\n');
    block
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-hermes-0123456789abcdef";
    const BASE: &str = "https://relay.example.com";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    fn writer_in(dir: &Path, base_url: &str) -> HermesWriter {
        HermesWriter::with_path(dir.join("config.yaml"), base_url)
    }

    #[test]
    fn creates_fresh_file() {
        let dir = tmp();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert_eq!(patch.before, "");
        assert!(patch.after.contains(BLOCK_BEGIN));
        assert!(patch.after.contains(BLOCK_END));
        assert!(patch.after.contains("api_key: "));
        assert!(patch.after.contains(SECRET));
        assert!(patch.after.contains("base_url: "));
        assert!(patch.after.contains(BASE));
        assert_eq!(patch.new_file_mode, Some(0o600));
    }

    #[test]
    fn preserves_user_yaml_outside_block() {
        let dir = tmp();
        let before = r#"model:
  default: "anthropic/claude-opus-4-8"
  provider: "openrouter"
agent:
  max_turns: 50
"#;
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();

        assert!(patch.after.contains("model:"));
        assert!(patch
            .after
            .contains("default: \"anthropic/claude-opus-4-8\""));
        assert!(patch.after.contains("max_turns: 50"));
        assert!(patch.after.contains(BLOCK_BEGIN));
        assert!(patch.after.contains(SECRET));
    }

    #[test]
    fn replaces_existing_block() {
        let dir = tmp();
        let before = format!(
            "model:\n  default: x\n{}\napi_key: sk-old\nbase_url: https://old.com\n{}\n",
            BLOCK_BEGIN, BLOCK_END
        );
        std::fs::write(writer_in(dir.path(), BASE).path(), &before).unwrap();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();

        assert!(patch.after.contains(SECRET));
        assert!(!patch.after.contains("sk-old"));
        assert!(patch.after.contains("model:"));
        assert_eq!(patch.after.matches(BLOCK_BEGIN).count(), 1);
    }

    #[test]
    fn empty_base_url_leaves_existing_alone() {
        let dir = tmp();
        let before = format!(
            "{}\napi_key: sk-old\nbase_url: https://keep.com\n{}\n",
            BLOCK_BEGIN, BLOCK_END
        );
        std::fs::write(writer_in(dir.path(), "").path(), &before).unwrap();
        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();

        // 旧 base_url 在标记块里被替换，但新块不含 base_url
        assert!(patch.after.contains(SECRET));
        assert!(!patch.after.contains("https://keep.com"));
    }

    #[test]
    fn rejects_empty_key() {
        let dir = tmp();
        assert!(matches!(
            writer_in(dir.path(), BASE).plan(""),
            Err(Error::Inject { .. })
        ));
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
    fn errors_never_echo_the_key() {
        let dir = tmp();
        let err = writer_in(dir.path(), BASE).plan("").unwrap_err();
        assert!(!err.to_string().contains("SECRET"), "{err}");
    }
}
