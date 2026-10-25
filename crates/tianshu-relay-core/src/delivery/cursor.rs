//! Cursor 通道：`~/.cursor/settings.json`。
//!
//! 写入顶层 `OPENAI_API_KEY` 和 `OPENAI_BASE_URL`。

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::json_text::{parse_object, read_text_or_empty, JsonStyle};
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;

pub struct CursorWriter {
    path: PathBuf,
    base_url: String,
}

impl CursorWriter {
    pub const FIELD_API_KEY: &'static str = "OPENAI_API_KEY";
    pub const FIELD_BASE_URL: &'static str = "OPENAI_BASE_URL";

    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path(home.join(".cursor").join("settings.json"), base_url)
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

impl DeliveryWriter for CursorWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::Cursor
    }
    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }

    fn field_names(&self) -> Vec<String> {
        let mut names = vec![Self::FIELD_API_KEY.to_string()];
        if !self.base_url.trim().is_empty() {
            names.push(Self::FIELD_BASE_URL.to_string());
        }
        names
    }

    fn fields(&self, api_key: &str) -> Vec<DeliveryField> {
        let mut fields = vec![masked_field(Self::FIELD_API_KEY, api_key)];
        if !self.base_url.trim().is_empty() {
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
    let style = JsonStyle::detect(before);
    let mut root = parse_object(before, path)?;
    root.insert(
        CursorWriter::FIELD_API_KEY.to_string(),
        Value::String(api_key.to_string()),
    );
    if !base_url.trim().is_empty() {
        root.insert(
            CursorWriter::FIELD_BASE_URL.to_string(),
            Value::String(base_url.to_string()),
        );
    }
    style.serialize(&root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "sk-cursor-0123456789abcdef";
    const BASE: &str = "https://relay.example.com";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }
    fn writer_in(dir: &Path, base_url: &str) -> CursorWriter {
        CursorWriter::with_path(dir.join("settings.json"), base_url)
    }

    #[test]
    fn errors_never_echo_the_key() {
        // DEBUG-G7 P2-K4：畸形旧文件 + 双 canary，见 codex_auth 同名用例。
        let dir = tmp();
        std::fs::write(
            writer_in(dir.path(), BASE).path(),
            "{\"api_key\": \"CANARY-FILE-9x7z",
        )
        .unwrap();
        let err = writer_in(dir.path(), BASE)
            .plan("CANARY-KEY-4k2m")
            .unwrap_err();
        assert!(!err.to_string().contains("CANARY-KEY-4k2m"), "{err}");
        assert!(!err.to_string().contains("CANARY-FILE-9x7z"), "{err}");
    }

    #[test]
    fn creates_fresh_file() {
        let dir = tmp();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert_eq!(patch.before, "");
        let parsed: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(parsed["OPENAI_API_KEY"], SECRET);
        assert_eq!(parsed["OPENAI_BASE_URL"], BASE);
        assert_eq!(patch.new_file_mode, Some(0o600));
    }

    #[test]
    fn preserves_other_keys() {
        let dir = tmp();
        let before = json!({"OPENAI_API_KEY": "sk-old", "other": {"a": 1}}).to_string();
        std::fs::write(writer_in(dir.path(), BASE).path(), &before).unwrap();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        let after: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(after["OPENAI_API_KEY"], SECRET);
        assert_eq!(after["other"]["a"], 1);
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
}
