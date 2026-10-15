//! MiMo Code 通道：`~/.mimocode/mimocode.json`。
//! 在 `providers` 对象中创建或更新 `keyrelay` 条目。

use super::json_text::{object_entry, parse_object, read_text_or_empty, JsonStyle};
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct MiMoCodeWriter {
    path: PathBuf,
    base_url: String,
}

impl MiMoCodeWriter {
    pub const FIELD_API_KEY: &'static str = "apiKey";
    pub const FIELD_BASE_URL: &'static str = "baseUrl";
    const PROVIDER_ID: &'static str = "keyrelay";
    const PROVIDERS_KEY: &'static str = "providers";

    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path(home.join(".mimocode").join("mimocode.json"), base_url)
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

impl DeliveryWriter for MiMoCodeWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::MiMoCode
    }
    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }
    fn field_names(&self) -> Vec<String> {
        let mut n = vec![format!("{}.{}", Self::PROVIDERS_KEY, Self::FIELD_API_KEY)];
        if !self.base_url.is_empty() {
            n.push(format!("{}.{}", Self::PROVIDERS_KEY, Self::FIELD_BASE_URL));
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
    let providers = object_entry(&mut root, MiMoCodeWriter::PROVIDERS_KEY, path)?;
    let entry = object_entry(providers, MiMoCodeWriter::PROVIDER_ID, path)?;
    entry.insert(
        MiMoCodeWriter::FIELD_API_KEY.to_string(),
        Value::String(api_key.to_string()),
    );
    if !base_url.is_empty() {
        entry.insert(
            MiMoCodeWriter::FIELD_BASE_URL.to_string(),
            Value::String(base_url.to_string()),
        );
    }
    style.serialize(&root)
}

#[cfg(test)]
mod tests {
    use super::*;
    const SECRET: &str = "sk-mimo-0123456789abcdef";
    const BASE: &str = "https://relay.example.com";
    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }
    fn w(dir: &Path, b: &str) -> MiMoCodeWriter {
        MiMoCodeWriter::with_path(dir.join("c.json"), b)
    }

    #[test]
    fn creates_fresh() {
        let d = tmp();
        let p = w(d.path(), BASE).plan(SECRET).unwrap();
        let v: Value = serde_json::from_str(&p.after).unwrap();
        assert_eq!(v["providers"]["keyrelay"]["apiKey"], SECRET);
        assert_eq!(v["providers"]["keyrelay"]["baseUrl"], BASE);
    }
    #[test]
    fn preserves_other_providers() {
        let d = tmp();
        let before = r#"{"providers":{"official":{"apiKey":"sk-user","model":"mimo-v2"}}}"#;
        std::fs::write(w(d.path(), BASE).path(), before).unwrap();
        let p = w(d.path(), BASE).plan(SECRET).unwrap();
        let v: Value = serde_json::from_str(&p.after).unwrap();
        assert_eq!(v["providers"]["official"]["apiKey"], "sk-user");
        assert_eq!(v["providers"]["keyrelay"]["apiKey"], SECRET);
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
