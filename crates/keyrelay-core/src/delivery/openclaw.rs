//! OpenClaw 通道：`~/.openclaw/openclaw.json`（JSON5 格式）。
//!
//! 用 JSON5 行注释标记块写入 `api_key` 和 `base_url`，块外字节逐字节不动。
//! 如果目标文件是严格 JSON（无注释），降级为 serde_json 字段级替换。
//!
//! 标记块格式：
//! ```json5
//! // >>> keyrelay >>>
//! { "api_key": "sk-xxx", "base_url": "https://relay.example.com" }
//! // <<< keyrelay <<<
//! ```

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::json_text::{object_entry, parse_object, read_text_or_empty, JsonStyle};
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;
use crate::model_meta::ModelMeta;

pub const BLOCK_BEGIN: &str = "// >>> keyrelay >>>";
pub const BLOCK_END: &str = "// <<< keyrelay <<<";

pub struct OpenClawWriter {
    path: PathBuf,
    base_url: String,
    model: Option<String>,
    meta: Option<ModelMeta>,
}

impl OpenClawWriter {
    pub const FIELD_API_KEY: &'static str = "api_key";
    pub const FIELD_BASE_URL: &'static str = "base_url";
    pub const FIELD_MODEL: &'static str = "model";
    pub const FIELD_CONTEXT_WINDOW: &'static str = "contextWindow";
    pub const FIELD_MAX_TOKENS: &'static str = "maxTokens";

    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path(home.join(".openclaw").join("openclaw.json"), base_url)
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

impl DeliveryWriter for OpenClawWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::OpenClaw
    }

    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }

    fn field_names(&self) -> Vec<String> {
        let mut names = vec![Self::FIELD_API_KEY.to_string()];
        if !self.base_url.is_empty() {
            names.push(Self::FIELD_BASE_URL.to_string());
        }
        if self.model.is_some() {
            names.push(Self::FIELD_MODEL.to_string());
            if self.meta.is_some() {
                names.push(Self::FIELD_CONTEXT_WINDOW.to_string());
                names.push(Self::FIELD_MAX_TOKENS.to_string());
            }
        }
        names
    }

    fn fields(&self, api_key: &str) -> Vec<DeliveryField> {
        let mut fields = vec![masked_field(Self::FIELD_API_KEY, api_key)];
        if !self.base_url.is_empty() {
            fields.push(literal_field(Self::FIELD_BASE_URL, &self.base_url));
        }
        if let Some(m) = &self.model {
            fields.push(literal_field(Self::FIELD_MODEL, m));
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

    let has_comments =
        before.lines().any(|l| l.trim_start().starts_with("//")) || before.contains("/*");

    if has_comments || before.contains(BLOCK_BEGIN) {
        build_with_marker_block(before, api_key, base_url, model, meta)
    } else {
        build_with_json(before, api_key, base_url, model, meta, path)
    }
}

fn build_with_marker_block(
    before: &str,
    api_key: &str,
    base_url: &str,
    model: &Option<String>,
    meta: Option<ModelMeta>,
) -> Result<String> {
    let block_content = build_block_content(api_key, base_url, model, meta);
    let new_block = format!("{BLOCK_BEGIN}\n{block_content}\n{BLOCK_END}\n");

    if let Some(begin_pos) = before.find(BLOCK_BEGIN) {
        if let Some(end_pos) = before[begin_pos..].find(BLOCK_END) {
            let absolute_end = begin_pos + end_pos + BLOCK_END.len();
            let after_end = if before[absolute_end..].starts_with('\n') {
                absolute_end + 1
            } else {
                absolute_end
            };
            let mut result = String::with_capacity(before.len() + 64);
            result.push_str(&before[..begin_pos]);
            result.push_str(&new_block);
            result.push_str(&before[after_end..]);
            return Ok(result);
        }
    }

    let mut result = String::with_capacity(before.len() + new_block.len() + 1);
    if before.is_empty() {
        result.push_str("{\n");
        result.push_str(&new_block);
        result.push_str("}\n");
    } else if before.trim_end().ends_with('}') {
        let insert_pos = before.trim_end().len() - 1;
        result.push_str(&before[..insert_pos]);
        result.push_str(&new_block);
        result.push_str("}\n");
    } else {
        result.push_str(before);
        if !before.ends_with('\n') {
            result.push('\n');
        }
        result.push_str(&new_block);
    }
    Ok(result)
}

fn build_with_json(
    before: &str,
    api_key: &str,
    base_url: &str,
    model: &Option<String>,
    meta: Option<ModelMeta>,
    path: &Path,
) -> Result<String> {
    let style = JsonStyle::detect(before);
    let mut root = parse_object(before, path)?;

    let providers = object_entry(&mut root, "models", path)?;
    let provider_list = object_entry(providers, "providers", path)?;

    let entry = object_entry(provider_list, "keyrelay", path)?;
    entry.insert(
        OpenClawWriter::FIELD_API_KEY.to_string(),
        Value::String(api_key.to_string()),
    );
    if !base_url.is_empty() {
        entry.insert(
            OpenClawWriter::FIELD_BASE_URL.to_string(),
            Value::String(base_url.to_string()),
        );
    }
    if let Some(m) = model {
        entry.insert(
            OpenClawWriter::FIELD_MODEL.to_string(),
            Value::String(m.clone()),
        );
        if let Some(meta) = meta {
            entry.insert(
                OpenClawWriter::FIELD_CONTEXT_WINDOW.to_string(),
                Value::Number(serde_json::Number::from(meta.context_window)),
            );
            entry.insert(
                OpenClawWriter::FIELD_MAX_TOKENS.to_string(),
                Value::Number(serde_json::Number::from(meta.max_output_tokens)),
            );
        }
    }

    style.serialize(&root)
}

fn build_block_content(
    api_key: &str,
    base_url: &str,
    model: &Option<String>,
    meta: Option<ModelMeta>,
) -> String {
    let mut content = String::from("{ ");
    content.push_str("\"api_key\": \"");
    content.push_str(api_key);
    content.push('"');
    if !base_url.is_empty() {
        content.push_str(", \"base_url\": \"");
        content.push_str(base_url);
        content.push('"');
    }
    if let Some(m) = model {
        content.push_str(", \"model\": \"");
        content.push_str(m);
        content.push('"');
        if let Some(meta) = meta {
            content.push_str(", \"contextWindow\": ");
            content.push_str(&meta.context_window.to_string());
            content.push_str(", \"maxTokens\": ");
            content.push_str(&meta.max_output_tokens.to_string());
        }
    }
    content.push_str(" }");
    content
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-openclaw-0123456789abcdef";
    const BASE: &str = "https://relay.example.com";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    fn writer_in(dir: &Path, base_url: &str) -> OpenClawWriter {
        OpenClawWriter::with_path(dir.join("openclaw.json"), base_url)
    }

    #[test]
    fn creates_fresh_file_json_mode() {
        let dir = tmp();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert_eq!(patch.before, "");
        let parsed: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(parsed["models"]["providers"]["keyrelay"]["api_key"], SECRET);
        assert_eq!(parsed["models"]["providers"]["keyrelay"]["base_url"], BASE);
        assert_eq!(patch.new_file_mode, Some(0o600));
    }

    #[test]
    fn json5_marker_block_preserves_outside() {
        let dir = tmp();
        let before = r#"{
  // user comment
  models: {
    mode: 'merge',
    providers: {},
  },
}"#;
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();

        assert!(patch.after.contains("// user comment"));
        assert!(patch.after.contains("mode: 'merge'"));
        assert!(patch.after.contains(BLOCK_BEGIN));
        assert!(patch.after.contains(BLOCK_END));
        assert!(patch.after.contains(SECRET));
        assert!(patch.after.contains(BASE));
    }

    #[test]
    fn json5_marker_block_replaces_existing() {
        let dir = tmp();
        let before = format!("{{\n  // user\n  {}\n  {}\n}}\n", BLOCK_BEGIN, BLOCK_END);
        std::fs::write(writer_in(dir.path(), BASE).path(), &before).unwrap();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();

        assert!(patch.after.contains(SECRET));
        assert!(patch.after.contains("// user"));
        assert_eq!(patch.after.matches(BLOCK_BEGIN).count(), 1);
    }

    #[test]
    fn empty_base_url_leaves_existing_alone_json() {
        let dir = tmp();
        let before =
            r#"{"models":{"providers":{"keyrelay":{"base_url":"https://keep.example.com"}}}}"#;
        std::fs::write(writer_in(dir.path(), "").path(), before).unwrap();

        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        assert!(patch.after.contains("https://keep.example.com"));
        assert!(patch.after.contains(SECRET));
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
    fn plan_is_idempotent_json() {
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

    // ============================ M14-S7
    const MODEL: &str = "gpt-4o";
    fn writer_with_model(dir: &Path) -> OpenClawWriter {
        let w =
            OpenClawWriter::with_model(dir, BASE, Some(MODEL), crate::model_meta::lookup(MODEL));
        std::fs::create_dir_all(w.path().parent().unwrap()).ok();
        w
    }

    #[test]
    fn writes_model_and_meta_json() {
        let dir = tmp();
        let patch = writer_with_model(dir.path()).plan(SECRET).unwrap();
        let v: Value = serde_json::from_str(&patch.after).unwrap();
        let kr = &v["models"]["providers"]["keyrelay"];
        assert_eq!(kr["model"], MODEL);
        assert_eq!(kr["contextWindow"], 128000);
        assert_eq!(kr["maxTokens"], 16384);
    }

    #[test]
    fn model_plan_is_idempotent_json() {
        let dir = tmp();
        let first = writer_with_model(dir.path()).plan(SECRET).unwrap();
        std::fs::write(writer_with_model(dir.path()).path(), &first.after).unwrap();
        let second = writer_with_model(dir.path()).plan(SECRET).unwrap();
        assert_eq!(second.after, first.after);
    }

    #[test]
    fn model_replaces_existing_json() {
        let dir = tmp();
        let before = r#"{"models":{"providers":{"keyrelay":{"api_key":"sk-old","model":"old","contextWindow":1,"maxTokens":1}}}}"#;
        std::fs::write(writer_with_model(dir.path()).path(), before).unwrap();
        let patch = writer_with_model(dir.path()).plan(SECRET).unwrap();
        let v: Value = serde_json::from_str(&patch.after).unwrap();
        let kr = &v["models"]["providers"]["keyrelay"];
        assert_eq!(kr["model"], MODEL);
        assert_eq!(kr["contextWindow"], 128000);
    }

    #[test]
    fn model_without_meta_only_name_json() {
        let dir = tmp();
        let writer = OpenClawWriter::with_model(dir.path(), BASE, Some("unknown"), None);
        let patch = writer.plan(SECRET).unwrap();
        let v: Value = serde_json::from_str(&patch.after).unwrap();
        let kr = &v["models"]["providers"]["keyrelay"];
        assert_eq!(kr["model"], "unknown");
        assert!(kr.get("contextWindow").is_none());
    }

    #[test]
    fn no_model_preserves_existing_json() {
        let dir = tmp();
        let before = r#"{"models":{"providers":{"keyrelay":{"api_key":"sk-old","model":"user"}}}}"#;
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        let v: Value = serde_json::from_str(&patch.after).unwrap();
        let kr = &v["models"]["providers"]["keyrelay"];
        assert_eq!(kr["model"], "user");
    }
}
