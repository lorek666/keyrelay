//! DeepSeek Reasonix 通道：`~/.reasonix/config.json`。

use super::json_text::{parse_object, read_text_or_empty, JsonStyle};
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;
use crate::model_meta::ModelMeta;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct DeepSeekWriter {
    path: PathBuf,
    base_url: String,
    model: Option<String>,
    meta: Option<ModelMeta>,
}

impl DeepSeekWriter {
    pub const FIELD_API_KEY: &'static str = "apiKey";
    pub const FIELD_BASE_URL: &'static str = "baseUrl";
    pub const FIELD_MODEL: &'static str = "model";
    pub const FIELD_CONTEXT_WINDOW: &'static str = "contextWindow";
    pub const FIELD_MAX_TOKENS: &'static str = "maxTokens";

    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path(home.join(".reasonix").join("config.json"), base_url)
    }
    pub fn with_path(path: impl Into<PathBuf>, base_url: &str) -> Self {
        Self {
            path: path.into(),
            base_url: base_url.to_string(),
            model: None,
            meta: None,
        }
    }
    pub fn with_model(
        home: &Path,
        base_url: &str,
        model: Option<&str>,
        meta: Option<ModelMeta>,
    ) -> Self {
        let mut w = Self::new(home, base_url);
        w.model = model
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .map(str::to_string);
        w.meta = meta;
        w
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
        if self.model.is_some() {
            n.push(Self::FIELD_MODEL.to_string());
            if self.meta.is_some() {
                n.push(Self::FIELD_CONTEXT_WINDOW.to_string());
                n.push(Self::FIELD_MAX_TOKENS.to_string());
            }
        }
        n
    }
    fn fields(&self, api_key: &str) -> Vec<DeliveryField> {
        let mut f = vec![masked_field(Self::FIELD_API_KEY, api_key)];
        if !self.base_url.is_empty() {
            f.push(literal_field(Self::FIELD_BASE_URL, &self.base_url));
        }
        if let Some(m) = &self.model {
            f.push(literal_field(Self::FIELD_MODEL, m));
            if let Some(meta) = self.meta {
                f.push(literal_field(
                    Self::FIELD_CONTEXT_WINDOW,
                    meta.context_window.to_string(),
                ));
                f.push(literal_field(
                    Self::FIELD_MAX_TOKENS,
                    meta.max_output_tokens.to_string(),
                ));
            }
        }
        f
    }
    fn plan(&self, api_key: &str) -> Result<Patch> {
        let before = read_text_or_empty(&self.path)?;
        let after = build_after(
            &before,
            api_key,
            &self.base_url,
            &self.model,
            self.meta,
            &self.path,
        )?;
        Ok(Patch::secret_bearing(self.path.clone(), before, after))
    }
}

fn build_after(
    before: &str,
    api_key: &str,
    base_url: &str,
    model: &Option<String>,
    meta: Option<ModelMeta>,
    path: &Path,
) -> Result<String> {
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
    if let Some(m) = model {
        root.insert(
            DeepSeekWriter::FIELD_MODEL.to_string(),
            Value::String(m.clone()),
        );
        if let Some(meta) = meta {
            root.insert(
                DeepSeekWriter::FIELD_CONTEXT_WINDOW.to_string(),
                Value::Number(serde_json::Number::from(meta.context_window)),
            );
            root.insert(
                DeepSeekWriter::FIELD_MAX_TOKENS.to_string(),
                Value::Number(serde_json::Number::from(meta.max_output_tokens)),
            );
        }
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

    // ============================ M14-S7
    const MODEL: &str = "gpt-4o";
    fn wm(dir: &Path) -> DeepSeekWriter {
        let w =
            DeepSeekWriter::with_model(dir, BASE, Some(MODEL), crate::model_meta::lookup(MODEL));
        std::fs::create_dir_all(w.path().parent().unwrap()).ok();
        w
    }
    #[test]
    fn writes_model_and_meta() {
        let d = tmp();
        let p = wm(d.path()).plan(SECRET).unwrap();
        let v: Value = serde_json::from_str(&p.after).unwrap();
        assert_eq!(v["model"], MODEL);
        assert_eq!(v["contextWindow"], 128000);
        assert_eq!(v["maxTokens"], 16384);
    }
    #[test]
    fn model_idempotent() {
        let d = tmp();
        let f = wm(d.path()).plan(SECRET).unwrap();
        std::fs::write(wm(d.path()).path(), &f.after).unwrap();
        assert_eq!(wm(d.path()).plan(SECRET).unwrap().after, f.after);
    }
    #[test]
    fn model_replaces_existing() {
        let d = tmp();
        std::fs::write(
            wm(d.path()).path(),
            json!({"apiKey":"sk-old","model":"old","contextWindow":1,"maxTokens":1}).to_string(),
        )
        .unwrap();
        let p = wm(d.path()).plan(SECRET).unwrap();
        let v: Value = serde_json::from_str(&p.after).unwrap();
        assert_eq!(v["model"], MODEL);
        assert_eq!(v["contextWindow"], 128000);
    }
    #[test]
    fn model_without_meta_only_name() {
        let d = tmp();
        let writer = DeepSeekWriter::with_model(d.path(), BASE, Some("unknown"), None);
        let p = writer.plan(SECRET).unwrap();
        let v: Value = serde_json::from_str(&p.after).unwrap();
        assert_eq!(v["model"], "unknown");
        assert!(v.get("contextWindow").is_none());
    }
    #[test]
    fn no_model_preserves_existing() {
        let d = tmp();
        std::fs::write(
            w(d.path(), BASE).path(),
            json!({"apiKey":"sk-old","model":"user"}).to_string(),
        )
        .unwrap();
        let p = w(d.path(), BASE).plan(SECRET).unwrap();
        let v: Value = serde_json::from_str(&p.after).unwrap();
        assert_eq!(v["model"], "user");
    }
}
