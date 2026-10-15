//! Pi 通道：`~/.pi/agent/models.json` 的 provider 条目。
//!
//! 用 serde_json 字段级替换写入 `api_key` 和 `base_url`。
//! 在 `models` 对象下创建或更新 `keyrelay` provider 条目，
//! 不影响用户已有的其他 provider。

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::json_text::{object_entry, parse_object, read_text_or_empty, JsonStyle};
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;

pub struct PiWriter {
    path: PathBuf,
    base_url: String,
}

impl PiWriter {
    pub const FIELD_API_KEY: &'static str = "api_key";
    pub const FIELD_BASE_URL: &'static str = "base_url";
    const PROVIDER_KEY: &'static str = "keyrelay";

    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path(home.join(".pi").join("agent").join("models.json"), base_url)
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

impl DeliveryWriter for PiWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::Pi
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

    let style = JsonStyle::detect(before);
    let mut root = parse_object(before, path)?;

    let provider = object_entry(&mut root, PiWriter::PROVIDER_KEY, path)?;
    provider.insert(
        PiWriter::FIELD_API_KEY.to_string(),
        Value::String(api_key.to_string()),
    );
    if !base_url.is_empty() {
        provider.insert(
            PiWriter::FIELD_BASE_URL.to_string(),
            Value::String(base_url.to_string()),
        );
    }

    style.serialize(&root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "sk-pi-0123456789abcdef";
    const BASE: &str = "https://relay.example.com";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    fn writer_in(dir: &Path, base_url: &str) -> PiWriter {
        PiWriter::with_path(dir.join("models.json"), base_url)
    }

    #[test]
    fn creates_fresh_file() {
        let dir = tmp();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert_eq!(patch.before, "");
        let parsed: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(parsed["keyrelay"]["api_key"], SECRET);
        assert_eq!(parsed["keyrelay"]["base_url"], BASE);
        assert_eq!(patch.new_file_mode, Some(0o600));
    }

    #[test]
    fn preserves_other_providers() {
        let dir = tmp();
        let before = r#"{
  "keyrelay": {
    "api_key": "sk-old",
    "base_url": "https://old.example.com"
  },
  "official": {
    "api_key": "sk-user-own",
    "base_url": "https://api.minimax.chat",
    "model": "abab6.5"
  }
}"#;
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();

        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        let after: Value = serde_json::from_str(&patch.after).unwrap();
        let before_v: Value = serde_json::from_str(before).unwrap();

        assert_eq!(after["keyrelay"]["api_key"], SECRET);
        assert_eq!(after["keyrelay"]["base_url"], BASE);
        assert_eq!(
            after["official"], before_v["official"],
            "official provider 被改动了"
        );
    }

    #[test]
    fn empty_base_url_leaves_existing_alone() {
        let dir = tmp();
        let before =
            json!({"keyrelay": {"base_url": "https://keep.example.com", "api_key": "sk-old"}})
                .to_string();
        std::fs::write(writer_in(dir.path(), "").path(), &before).unwrap();

        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        let after: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(after["keyrelay"]["base_url"], "https://keep.example.com");
        assert_eq!(after["keyrelay"]["api_key"], SECRET);
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
        std::fs::write(writer_in(dir.path(), BASE).path(), "not json").unwrap();
        let err = writer_in(dir.path(), BASE)
            .plan("sk-VERY-SECRET-0123456789")
            .unwrap_err();
        assert!(!err.to_string().contains("VERY-SECRET"), "{err}");
    }
}
