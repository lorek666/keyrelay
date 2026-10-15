//! DeepSeek Reasonix 通道：`~/.reasonix/config.json`。

use super::json_text::{parse_object, read_text_or_empty, JsonStyle};
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct DeepSeekWriter {
    path: PathBuf,
    base_url: String,
}

impl DeepSeekWriter {
    pub const FIELD_API_KEY: &'static str = "apiKey";
    pub const FIELD_BASE_URL: &'static str = "baseUrl";
    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path(home.join(".reasonix").join("config.json"), base_url)
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

impl DeliveryWriter for DeepSeekWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::DeepSeek
    }
    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }
    fn field_names(&self) -> Vec<String> {
        let mut n = vec![Self::FIELD_API_KEY.to_string()];
        if !self.base_url.is_empty() {
            n.push(Self::FIELD_BASE_URL.to_string());
        }
        n
    }
    fn fields(&self, api_key: &str) -> Vec<DeliveryField> {
        let mut f = vec![masked_field(Self::FIELD_API_KEY, api_key)];
        if !self.base_url.is_empty() {
            f.push(literal_field(Self::FIELD_BASE_URL, &self.base_url));
        }
        f
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
        DeepSeekWriter::FIELD_API_KEY.to_string(),
        Value::String(api_key.to_string()),
    );
    if !base_url.is_empty() {
        root.insert(
            DeepSeekWriter::FIELD_BASE_URL.to_string(),
            Value::String(base_url.to_string()),
        );
    }
    style.serialize(&root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const SECRET: &str = "sk-ds-0123456789abcdef";
    const BASE: &str = "https://relay.example.com";
    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }
    fn w(dir: &Path, b: &str) -> DeepSeekWriter {
        DeepSeekWriter::with_path(dir.join("c.json"), b)
    }

    #[test]
    fn creates_fresh() {
        let d = tmp();
        let p = w(d.path(), BASE).plan(SECRET).unwrap();
        let v: Value = serde_json::from_str(&p.after).unwrap();
        assert_eq!(v["apiKey"], SECRET);
        assert_eq!(v["baseUrl"], BASE);
    }
    #[test]
    fn preserves_others() {
        let d = tmp();
        std::fs::write(
            w(d.path(), BASE).path(),
            json!({"apiKey":"sk-old","model":"deepseek-chat"}).to_string(),
        )
        .unwrap();
        let p = w(d.path(), BASE).plan(SECRET).unwrap();
        let v: Value = serde_json::from_str(&p.after).unwrap();
        assert_eq!(v["apiKey"], SECRET);
        assert_eq!(v["model"], "deepseek-chat");
    }
    #[test]
    fn rejects_empty() {
        let d = tmp();
        assert!(w(d.path(), BASE).plan("").is_err());
    }
    #[test]
    fn idempotent() {
        let d = tmp();
        let f = w(d.path(), BASE).plan(SECRET).unwrap();
        std::fs::write(w(d.path(), BASE).path(), &f.after).unwrap();
        assert_eq!(w(d.path(), BASE).plan(SECRET).unwrap().after, f.after);
    }
}
