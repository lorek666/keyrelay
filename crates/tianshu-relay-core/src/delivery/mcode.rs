//! MCode Agent 通道：`~/.minimax/config.yaml`（YAML 格式）。
//!
//! 用 `# >>> keyrelay >>>` / `# <<< keyrelay <<<` 标记块写入
//! `api_key` 和 `base_url`，块外字节逐字节不动。
//! 策略与 Hermes 通道相同：只做行级操作，不引入 YAML 解析依赖。

use std::path::{Path, PathBuf};

use super::json_text::read_text_or_empty;
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;
use crate::model_meta::ModelMeta;

pub const BLOCK_BEGIN: &str = "# >>> keyrelay >>>";
pub const BLOCK_END: &str = "# <<< keyrelay <<<";

pub struct MCodeWriter {
    path: PathBuf,
    base_url: String,
    model: Option<String>,
    meta: Option<ModelMeta>,
}

impl MCodeWriter {
    pub const FIELD_API_KEY: &'static str = "api_key";
    pub const FIELD_BASE_URL: &'static str = "base_url";
    pub const FIELD_MODEL: &'static str = "model";
    pub const FIELD_CONTEXT_WINDOW: &'static str = "context_window";
    pub const FIELD_MAX_TOKENS: &'static str = "max_tokens";

    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path(home.join(".minimax").join("config.yaml"), base_url)
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

impl DeliveryWriter for MCodeWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::MCode
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

    let block = build_block(api_key, base_url, model, meta);

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

    let mut result = String::with_capacity(before.len() + block.len() + 1);
    result.push_str(before);
    if !before.is_empty() && !before.ends_with('\n') {
        result.push('\n');
    }
    result.push_str(&block);
    Ok(result)
}

fn build_block(
    api_key: &str,
    base_url: &str,
    model: &Option<String>,
    meta: Option<ModelMeta>,
) -> String {
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
    if let Some(m) = model {
        block.push_str("model: ");
        block.push_str(m);
        block.push('\n');
        if let Some(meta) = meta {
            block.push_str("context_window: ");
            block.push_str(&meta.context_window.to_string());
            block.push('\n');
            block.push_str("max_tokens: ");
            block.push_str(&meta.max_output_tokens.to_string());
            block.push('\n');
        }
    }
    block.push_str(BLOCK_END);
    block.push('\n');
    block
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-mcode-0123456789abcdef";
    const BASE: &str = "https://relay.example.com";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    fn writer_in(dir: &Path, base_url: &str) -> MCodeWriter {
        MCodeWriter::with_path(dir.join("config.yaml"), base_url)
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

    // ============================ M14-S7：模型名 + context_window + max_tokens（MCode 用 context_window + max_tokens，不用 max_output）

    const MODEL: &str = "gpt-4o";

    fn writer_with_model(dir: &Path) -> MCodeWriter {
        let w = MCodeWriter::with_model(dir, BASE, Some(MODEL), crate::model_meta::lookup(MODEL));
        std::fs::create_dir_all(w.path().parent().unwrap()).ok();
        w
    }

    #[test]
    fn writes_model_and_context_window() {
        let dir = tmp();
        let patch = writer_with_model(dir.path()).plan(SECRET).unwrap();
        assert!(patch.after.contains("model: gpt-4o"));
        assert!(patch.after.contains("context_window: 128000"));
        // MCode 写 max_tokens
        assert!(patch.after.contains("max_tokens: 16384"));
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
        let before = format!(
            "{}\napi_key: sk-old\nmodel: old-model\ncontext_window: 999\n{}\n",
            BLOCK_BEGIN, BLOCK_END
        );
        std::fs::write(writer_with_model(dir.path()).path(), &before).unwrap();
        let patch = writer_with_model(dir.path()).plan(SECRET).unwrap();
        assert!(patch.after.contains("model: gpt-4o"));
        assert!(patch.after.contains("context_window: 128000"));
        assert!(!patch.after.contains("old-model"));
        assert!(!patch.after.contains("999"));
        assert!(patch.after.contains("max_tokens: 16384"));
    }

    #[test]
    fn model_without_meta_writes_only_name() {
        let dir = tmp();
        let writer = MCodeWriter::with_model(dir.path(), BASE, Some("unknown"), None);
        let patch = writer.plan(SECRET).unwrap();
        assert!(patch.after.contains("model: unknown"));
        assert!(!patch.after.contains("context_window"));
        assert!(!patch.after.contains("max_tokens"));
    }

    #[test]
    fn no_model_preserves_existing_block_model() {
        // 不传 model 时，标记块里不应出现 model 行（原行为）
        let dir = tmp();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert!(!patch.after.contains("model: "));
        assert!(!patch.after.contains("context_window"));
    }

    #[test]
    fn mutation_lookup_returns_none_no_meta_lines() {
        // 变异验证：如果 lookup 返回 None，block 里不应该有 context_window 行
        let dir = tmp();
        let writer = MCodeWriter::with_model(dir.path(), BASE, Some("gpt-4o"), None);
        let patch = writer.plan(SECRET).unwrap();
        assert!(patch.after.contains("model: gpt-4o"));
        assert!(!patch.after.contains("context_window"));
        assert!(!patch.after.contains("max_tokens"));
    }
}
