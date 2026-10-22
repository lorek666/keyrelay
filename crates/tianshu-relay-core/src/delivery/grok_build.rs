//! Grok Build 通道：`~/.grok/config.toml` 的 `[models.custom]` 段。
//!
//! TOML 行级操作（不引入 toml 依赖）：
//! 只在 `[models.custom]` 段内替换 `api_key`、`base_url`、`model` 和 `context_window`，
//! 段不存在则在文件末尾追加。段外字节逐字节不动。

use std::path::{Path, PathBuf};

use super::json_text::read_text_or_empty;
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;
use crate::model_meta::ModelMeta;

pub struct GrokBuildWriter {
    path: PathBuf,
    base_url: String,
    model: Option<String>,
    meta: Option<ModelMeta>,
}

impl GrokBuildWriter {
    pub const FIELD_API_KEY: &'static str = "api_key";
    pub const FIELD_BASE_URL: &'static str = "base_url";
    pub const FIELD_MODEL: &'static str = "model";
    pub const FIELD_CONTEXT_WINDOW: &'static str = "context_window";
    const SECTION_HEADER: &'static str = "[models.custom]";

    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path(home.join(".grok").join("config.toml"), base_url)
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

impl DeliveryWriter for GrokBuildWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::GrokBuild
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

    let section_start = find_section(before, GrokBuildWriter::SECTION_HEADER);

    match section_start {
        Some(start) => {
            let section_end =
                find_next_section(before, start + GrokBuildWriter::SECTION_HEADER.len())
                    .unwrap_or(before.len());
            let section_text = &before[start..section_end];
            let updated = replace_in_section(section_text, api_key, base_url, model, meta);
            let mut result = String::with_capacity(before.len() + 64);
            result.push_str(&before[..start]);
            result.push_str(&updated);
            result.push_str(&before[section_end..]);
            Ok(result)
        }
        None => {
            let mut result = String::with_capacity(before.len() + 128);
            if !before.is_empty() && !before.ends_with('\n') {
                result.push_str(before);
                result.push('\n');
            } else {
                result.push_str(before);
            }
            result.push_str(GrokBuildWriter::SECTION_HEADER);
            result.push('\n');
            result.push_str("api_key = \"");
            result.push_str(api_key);
            result.push_str("\"\n");
            if !base_url.is_empty() {
                result.push_str("base_url = \"");
                result.push_str(base_url);
                result.push_str("\"\n");
            }
            if let Some(m) = model {
                result.push_str("model = \"");
                result.push_str(m);
                result.push_str("\"\n");
                if let Some(meta) = meta {
                    result.push_str("context_window = ");
                    result.push_str(&meta.context_window.to_string());
                    result.push('\n');
                }
            }
            Ok(result)
        }
    }
}

fn find_section(text: &str, header: &str) -> Option<usize> {
    let mut offset = 0;
    for line in text.lines() {
        if line.trim_start() == header {
            return Some(offset);
        }
        offset += line.len() + 1;
    }
    None
}

fn find_next_section(text: &str, after: usize) -> Option<usize> {
    let rest = &text[after..];
    let mut offset = after;
    for line in rest.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[')
            && trimmed.ends_with(']')
            && trimmed != GrokBuildWriter::SECTION_HEADER
        {
            return Some(offset);
        }
        offset += line.len() + 1;
    }
    None
}

fn replace_in_section(
    section: &str,
    api_key: &str,
    base_url: &str,
    model: &Option<String>,
    meta: Option<ModelMeta>,
) -> String {
    let lines: Vec<&str> = section.lines().collect();
    let mut out = String::with_capacity(section.len() + 64);
    let mut wrote_api_key = false;
    let mut wrote_base_url = base_url.is_empty();
    let mut wrote_model = model.is_none();
    let mut wrote_context = meta.is_none() || model.is_none();

    for line in &lines {
        let trimmed = line.trim_start();
        if trimmed.starts_with("api_key") && trimmed.contains('=') {
            out.push_str("api_key = \"");
            out.push_str(api_key);
            out.push_str("\"\n");
            wrote_api_key = true;
            continue;
        }
        if !base_url.is_empty() && trimmed.starts_with("base_url") && trimmed.contains('=') {
            out.push_str("base_url = \"");
            out.push_str(base_url);
            out.push_str("\"\n");
            wrote_base_url = true;
            continue;
        }
        if model.is_some()
            && trimmed.starts_with("model")
            && trimmed.contains('=')
            && !trimmed.starts_with("models")
        {
            if let Some(m) = model {
                out.push_str("model = \"");
                out.push_str(m);
                out.push_str("\"\n");
                wrote_model = true;
            }
            continue;
        }
        if meta.is_some()
            && model.is_some()
            && trimmed.starts_with("context_window")
            && trimmed.contains('=')
        {
            if let Some(meta) = meta {
                out.push_str("context_window = ");
                out.push_str(&meta.context_window.to_string());
                out.push('\n');
                wrote_context = true;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }

    if !wrote_api_key {
        out.push_str("api_key = \"");
        out.push_str(api_key);
        out.push_str("\"\n");
    }
    if !wrote_base_url && !base_url.is_empty() {
        out.push_str("base_url = \"");
        out.push_str(base_url);
        out.push_str("\"\n");
    }
    if !wrote_model {
        if let Some(m) = model {
            out.push_str("model = \"");
            out.push_str(m);
            out.push_str("\"\n");
        }
    }
    if !wrote_context {
        if let Some(meta) = meta {
            if model.is_some() {
                out.push_str("context_window = ");
                out.push_str(&meta.context_window.to_string());
                out.push('\n');
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-grok-0123456789abcdef";
    const BASE: &str = "https://relay.example.com";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    fn writer_in(dir: &Path, base_url: &str) -> GrokBuildWriter {
        GrokBuildWriter::with_path(dir.join("config.toml"), base_url)
    }

    #[test]
    fn creates_fresh_file() {
        let dir = tmp();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert_eq!(patch.before, "");
        assert!(patch.after.contains("[models.custom]"));
        assert!(patch.after.contains("api_key = \""));
        assert!(patch.after.contains(SECRET));
        assert!(patch.after.contains("base_url = \""));
        assert!(patch.after.contains(BASE));
        assert_eq!(patch.new_file_mode, Some(0o600));
    }

    #[test]
    fn replaces_existing_keys_in_section() {
        let dir = tmp();
        let before = r#"[models.custom]
model = "grok-4.5"
base_url = "https://old.example.com"
api_key = "sk-old"
api_backend = "responses"
context_window = 500000

[other]
foo = "bar"
"#;
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();

        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert!(patch.after.contains("api_key = \""));
        assert!(patch.after.contains(SECRET));
        assert!(!patch.after.contains("sk-old"));
        assert!(patch
            .after
            .contains("base_url = \"https://relay.example.com\""));
        assert!(!patch.after.contains("https://old.example.com"));

        assert!(patch.after.contains("model = \"grok-4.5\""));
        assert!(patch.after.contains("api_backend = \"responses\""));
        assert!(patch.after.contains("context_window = 500000"));
        assert!(patch.after.contains("[other]"));
        assert!(patch.after.contains("foo = \"bar\""));
    }

    #[test]
    fn empty_base_url_leaves_existing_alone() {
        let dir = tmp();
        let before =
            "[models.custom]\nbase_url = \"https://keep.example.com\"\napi_key = \"sk-old\"\n";
        std::fs::write(writer_in(dir.path(), "").path(), before).unwrap();

        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        assert!(patch.after.contains("https://keep.example.com"));
        assert!(patch.after.contains(SECRET));
        assert!(!patch.after.contains("sk-old"));
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

    // ============================ M14-S7：GrokBuild 只写 context_window，不写 max_output

    const MODEL: &str = "gpt-4o";

    fn writer_with_model(dir: &Path) -> GrokBuildWriter {
        let w =
            GrokBuildWriter::with_model(dir, BASE, Some(MODEL), crate::model_meta::lookup(MODEL));
        std::fs::create_dir_all(w.path().parent().unwrap()).ok();
        w
    }

    #[test]
    fn writes_model_and_context_window() {
        let dir = tmp();
        let patch = writer_with_model(dir.path()).plan(SECRET).unwrap();
        assert!(patch.after.contains("model = \"gpt-4o\""));
        assert!(patch.after.contains("context_window = 128000"));
        // GrokBuild 不写 max_output
        assert!(!patch.after.contains("max_tokens"));
        assert!(!patch.after.contains("max_output"));
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
        let before = r#"[models.custom]
model = "old-model"
context_window = 999
api_key = "sk-old"
"#;
        std::fs::write(writer_with_model(dir.path()).path(), before).unwrap();
        let patch = writer_with_model(dir.path()).plan(SECRET).unwrap();
        assert!(patch.after.contains("model = \"gpt-4o\""));
        assert!(patch.after.contains("context_window = 128000"));
        assert!(!patch.after.contains("old-model"));
        assert!(!patch.after.contains("999"));
    }

    #[test]
    fn model_without_meta_writes_only_name() {
        let dir = tmp();
        let writer = GrokBuildWriter::with_model(dir.path(), BASE, Some("unknown"), None);
        let patch = writer.plan(SECRET).unwrap();
        assert!(patch.after.contains("model = \"unknown\""));
        assert!(!patch.after.contains("context_window = "));
    }

    #[test]
    fn no_model_preserves_existing_model() {
        let dir = tmp();
        let before = "[models.custom]\nmodel = \"grok-4.5\"\napi_key = \"sk-old\"\n";
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert!(patch.after.contains("model = \"grok-4.5\""));
    }

    #[test]
    fn preserves_user_context_window_when_no_model() {
        // 不传 model 时，已有的 context_window 不被替换
        let dir = tmp();
        let before = "[models.custom]\nmodel = \"grok-4.5\"\ncontext_window = 500000\napi_key = \"sk-old\"\n";
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert!(patch.after.contains("context_window = 500000"));
    }
}
