//! Qwen Code 通道：`~/.qwen/settings.json`。
//!
//! 写入 `model.apiKey` 和 `model.baseUrl`，以及 `model.model` / `model.contextWindow` / `model.maxTokens`。

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::json_text::{object_entry, parse_object, read_text_or_empty, JsonStyle};
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;
use crate::model_meta::ModelMeta;

pub struct QwenCodeWriter {
    path: PathBuf,
    base_url: String,
    model: Option<String>,
    meta: Option<ModelMeta>,
}

impl QwenCodeWriter {
    pub const FIELD_API_KEY: &'static str = "apiKey";
    pub const FIELD_BASE_URL: &'static str = "baseUrl";
    pub const FIELD_MODEL: &'static str = "model";
    pub const FIELD_CONTEXT_WINDOW: &'static str = "contextWindow";
    pub const FIELD_MAX_TOKENS: &'static str = "maxTokens";
    const MODEL_KEY: &'static str = "model";

    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path(home.join(".qwen").join("settings.json"), base_url)
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

impl DeliveryWriter for QwenCodeWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::QwenCode
    }
    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }

    fn field_names(&self) -> Vec<String> {
        let mut names = vec![format!("{}.{}", Self::MODEL_KEY, Self::FIELD_API_KEY)];
        if !self.base_url.trim().is_empty() {
            names.push(format!("{}.{}", Self::MODEL_KEY, Self::FIELD_BASE_URL));
        }
        if self.model.is_some() {
            names.push(format!("{}.{}", Self::MODEL_KEY, "model"));
            if self.meta.is_some() {
                names.push(format!(
                    "{}.{}",
                    Self::MODEL_KEY,
                    Self::FIELD_CONTEXT_WINDOW
                ));
                names.push(format!("{}.{}", Self::MODEL_KEY, Self::FIELD_MAX_TOKENS));
            }
        }
        names
    }

    fn fields(&self, api_key: &str) -> Vec<DeliveryField> {
        let mut fields = vec![masked_field(Self::FIELD_API_KEY, api_key)];
        if !self.base_url.trim().is_empty() {
            fields.push(literal_field(Self::FIELD_BASE_URL, &self.base_url));
        }
        if let Some(m) = &self.model {
            fields.push(literal_field("model", m));
            if let Some(meta) = self.meta {
                fields.push(literal_field(
                    Self::FIELD_CONTEXT_WINDOW,
                    meta.context_window.to_string(),
                ));
                fields.push(literal_field(
                    Self::FIELD_MAX_TOKENS,
                    meta.max_output_tokens.to_string(),
                ));
            }
        }
        fields
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
    let model_obj = object_entry(&mut root, QwenCodeWriter::MODEL_KEY, path)?;
    model_obj.insert(
        QwenCodeWriter::FIELD_API_KEY.to_string(),
        Value::String(api_key.to_string()),
    );
    if !base_url.trim().is_empty() {
        model_obj.insert(
            QwenCodeWriter::FIELD_BASE_URL.to_string(),
            Value::String(base_url.to_string()),
        );
    }
    if let Some(m) = model {
        model_obj.insert("model".to_string(), Value::String(m.clone()));
        if let Some(meta) = meta {
            model_obj.insert(
                QwenCodeWriter::FIELD_CONTEXT_WINDOW.to_string(),
                Value::Number(serde_json::Number::from(meta.context_window)),
            );
            model_obj.insert(
                QwenCodeWriter::FIELD_MAX_TOKENS.to_string(),
                Value::Number(serde_json::Number::from(meta.max_output_tokens)),
            );
        }
    }
    style.serialize(&root)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-qwen-0123456789abcdef";
    const BASE: &str = "https://relay.example.com";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }
    fn writer_in(dir: &Path, base_url: &str) -> QwenCodeWriter {
        QwenCodeWriter::with_path(dir.join("settings.json"), base_url)
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
        let parsed: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(parsed["model"]["apiKey"], SECRET);
        assert_eq!(parsed["model"]["baseUrl"], BASE);
        assert_eq!(patch.new_file_mode, Some(0o600));
    }

    #[test]
    fn preserves_other_model_fields() {
        let dir = tmp();
        let before = r#"{"model":{"apiKey":"sk-old","model":"qwen-max","provider":"qwen"}}"#;
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        let after: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(after["model"]["apiKey"], SECRET);
        assert_eq!(after["model"]["model"], "qwen-max");
        assert_eq!(after["model"]["provider"], "qwen");
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

    // ============================ M14-S7
    const MODEL: &str = "gpt-4o";
    fn writer_with_model(dir: &Path) -> QwenCodeWriter {
        let w =
            QwenCodeWriter::with_model(dir, BASE, Some(MODEL), crate::model_meta::lookup(MODEL));
        std::fs::create_dir_all(w.path().parent().unwrap()).ok();
        w
    }

    #[test]
    fn writes_model_and_meta() {
        let dir = tmp();
        let patch = writer_with_model(dir.path()).plan(SECRET).unwrap();
        let v: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(v["model"]["model"], MODEL);
        assert_eq!(v["model"]["contextWindow"], 128000);
        assert_eq!(v["model"]["maxTokens"], 16384);
    }

    #[test]
    fn model_plan_is_idempotent() {
        let dir = tmp();
        let first = writer_with_model(dir.path()).plan(SECRET).unwrap();
        std::fs::write(writer_with_model(dir.path()).path(), &first.after).unwrap();
        let second = writer_with_model(dir.path()).plan(SECRET).unwrap();
        assert_eq!(second.after, first.after);
    }

    #[test]
    fn model_replaces_existing_values() {
        let dir = tmp();
        let before = serde_json::json!({"model":{"apiKey":"sk-old","model":"old","contextWindow":1,"maxTokens":1}}).to_string();
        std::fs::write(writer_with_model(dir.path()).path(), &before).unwrap();
        let patch = writer_with_model(dir.path()).plan(SECRET).unwrap();
        let v: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(v["model"]["model"], MODEL);
        assert_eq!(v["model"]["contextWindow"], 128000);
    }

    #[test]
    fn model_without_meta_writes_only_name() {
        let dir = tmp();
        let writer = QwenCodeWriter::with_model(dir.path(), BASE, Some("unknown"), None);
        let patch = writer.plan(SECRET).unwrap();
        let v: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(v["model"]["model"], "unknown");
        assert!(v["model"].get("contextWindow").is_none());
    }

    #[test]
    fn no_model_preserves_existing() {
        let dir = tmp();
        let before = serde_json::json!({"model":{"apiKey":"sk-old","model":"user"}}).to_string();
        std::fs::write(writer_in(dir.path(), BASE).path(), &before).unwrap();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        let v: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(v["model"]["model"], "user");
    }
}
