//! Cline 通道：VS Code globalStorage 下的 Cline 配置。
//!
//! 在 `providers` 数组中创建或更新 `keyrelay` 条目。

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::json_text::{parse_object, read_text_or_empty, JsonStyle};
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;

pub struct ClineWriter {
    path: PathBuf,
    base_url: String,
}

impl ClineWriter {
    pub const FIELD_API_KEY: &'static str = "apiKey";
    pub const FIELD_BASE_URL: &'static str = "baseUrl";
    const PROVIDER_ID: &'static str = "keyrelay";
    const PROVIDERS_KEY: &'static str = "providers";

    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path(home.join(relative_config_path()), base_url)
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

pub fn relative_config_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("Library")
            .join("Application Support")
            .join("Code")
            .join("User")
            .join("globalStorage")
            .join("saoudrizwan.claude-dev")
            .join("settings.json")
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from("AppData")
            .join("Roaming")
            .join("Code")
            .join("User")
            .join("globalStorage")
            .join("saoudrizwan.claude-dev")
            .join("settings.json")
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from(".config")
            .join("Code")
            .join("User")
            .join("globalStorage")
            .join("saoudrizwan.claude-dev")
            .join("settings.json")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        PathBuf::from(".config")
            .join("Code")
            .join("User")
            .join("globalStorage")
            .join("saoudrizwan.claude-dev")
            .join("settings.json")
    }
}

impl DeliveryWriter for ClineWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::Cline
    }
    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }

    fn field_names(&self) -> Vec<String> {
        let mut names = vec![format!(
            "{}.{}",
            ClineWriter::PROVIDERS_KEY,
            Self::FIELD_API_KEY
        )];
        if !self.base_url.is_empty() {
            names.push(format!(
                "{}.{}",
                ClineWriter::PROVIDERS_KEY,
                Self::FIELD_BASE_URL
            ));
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

    let providers = root
        .entry(ClineWriter::PROVIDERS_KEY.to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let arr = providers
        .as_array_mut()
        .ok_or_else(|| Error::inject(path, "providers 不是数组，拒绝改写"))?;

    let entry = arr
        .iter_mut()
        .find(|v| v.get("id").and_then(|i| i.as_str()) == Some(ClineWriter::PROVIDER_ID));
    if let Some(e) = entry {
        if let Some(obj) = e.as_object_mut() {
            obj.insert(
                ClineWriter::FIELD_API_KEY.to_string(),
                Value::String(api_key.to_string()),
            );
            if !base_url.is_empty() {
                obj.insert(
                    ClineWriter::FIELD_BASE_URL.to_string(),
                    Value::String(base_url.to_string()),
                );
            }
        }
    } else {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "id".to_string(),
            Value::String(ClineWriter::PROVIDER_ID.to_string()),
        );
        obj.insert(
            ClineWriter::FIELD_API_KEY.to_string(),
            Value::String(api_key.to_string()),
        );
        if !base_url.is_empty() {
            obj.insert(
                ClineWriter::FIELD_BASE_URL.to_string(),
                Value::String(base_url.to_string()),
            );
        }
        arr.push(Value::Object(obj));
    }

    style.serialize(&root)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-cline-0123456789abcdef";
    const BASE: &str = "https://relay.example.com";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }
    fn writer_in(dir: &Path, base_url: &str) -> ClineWriter {
        ClineWriter::with_path(dir.join("settings.json"), base_url)
    }

    #[test]
    fn creates_fresh_file() {
        let dir = tmp();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert_eq!(patch.before, "");
        let parsed: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(parsed["providers"][0]["id"], "keyrelay");
        assert_eq!(parsed["providers"][0]["apiKey"], SECRET);
        assert_eq!(parsed["providers"][0]["baseUrl"], BASE);
        assert_eq!(patch.new_file_mode, Some(0o600));
    }

    #[test]
    fn preserves_other_providers() {
        let dir = tmp();
        let before = r#"{"providers":[{"id":"openrouter","apiKey":"sk-user","baseUrl":"https://openrouter.ai"}]}"#;
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        let after: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(after["providers"].as_array().unwrap().len(), 2);
        assert_eq!(after["providers"][0]["id"], "openrouter");
        assert_eq!(after["providers"][0]["apiKey"], "sk-user");
        assert_eq!(after["providers"][1]["id"], "keyrelay");
        assert_eq!(after["providers"][1]["apiKey"], SECRET);
    }

    #[test]
    fn replaces_existing_entry() {
        let dir = tmp();
        let before =
            r#"{"providers":[{"id":"keyrelay","apiKey":"sk-old","baseUrl":"https://old.com"}]}"#;
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        let after: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(after["providers"].as_array().unwrap().len(), 1);
        assert_eq!(after["providers"][0]["apiKey"], SECRET);
        assert_eq!(after["providers"][0]["baseUrl"], BASE);
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
