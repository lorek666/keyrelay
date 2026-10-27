//! Claude Code 通道：`~/.claude/settings.json` 的 `env.ANTHROPIC_*`。
//!
//! 本机实测（2026-10-12）该文件有 **6 个顶层键**与 **9 个 `env` 键**，
//! 投递只允许碰其中两个（+ M14-S7 新增的 `ANTHROPIC_MODEL`）：
//! ```json
//! { "env": { "ANTHROPIC_AUTH_TOKEN": "sk-…", "ANTHROPIC_BASE_URL": "https://…", "ANTHROPIC_MODEL": "gpt-4o" } }
//! ```
//! 其余键（`permissions` / `enabledPlugins` / 其它 `ANTHROPIC_DEFAULT_*_MODEL`）必须保留。

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::json_text::{object_entry, parse_object, read_text_or_empty, JsonStyle};
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;

pub struct ClaudeCodeWriter {
    path: PathBuf,
    base_url: String,
    model: Option<String>,
    /// M47-S2：名单给的模型参数（思考档位）。`None` = 名单没覆盖这个模型。
    meta: Option<crate::model_meta::ModelMeta>,
}

impl ClaudeCodeWriter {
    pub const FIELD_TOKEN: &'static str = "ANTHROPIC_AUTH_TOKEN";
    pub const FIELD_BASE_URL: &'static str = "ANTHROPIC_BASE_URL";
    pub const FIELD_MODEL: &'static str = "ANTHROPIC_MODEL";
    /// M47-S2：思考档位（Claude Code 读这个决定发不发 `thinking`）。
    ///
    /// 名单说这个模型不支持思考时，本通道会**删掉**这个键——留着一个高的旧值会让
    /// Claude Code 继续发 `thinking`，而网关（上游是 OpenAI Chat）只能把它降级或丢弃。
    pub const FIELD_THINKING_LEVEL: &'static str = "CLAUDE_CODE_EFFORT_LEVEL";
    const ENV_KEY: &'static str = "env";

    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path(home.join(".claude").join("settings.json"), base_url)
    }

    pub fn with_path(path: impl Into<PathBuf>, base_url: &str) -> Self {
        Self {
            path: path.into(),
            base_url: base_url.to_string(),
            model: None,
            meta: None,
        }
    }

    /// M47-S2：带上名单参数（思考档位）。
    pub fn with_meta(mut self, meta: Option<crate::model_meta::ModelMeta>) -> Self {
        self.meta = meta;
        self
    }

    /// 该写的思考档位：名单说支持思考 ⇒ `Some(default)`；否则 `None`。
    /// 是否清理旧档位另由 `thinking_unsupported` 决定，不能从这里反推。
    fn thinking_level(&self) -> Option<crate::model_catalog::ThinkingLevel> {
        // 思考是**模型**的属性：没有模型名就不知道该写哪一档，宁可不写。
        self.model.as_ref()?;
        let spec = self.meta?.thinking?;
        let level = spec.default_level;
        spec.accepts(level).then_some(level)
    }

    pub fn with_model(home: &Path, base_url: &str, model: Option<&str>) -> Self {
        let mut w = Self::new(home, base_url);
        w.model = model
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .map(str::to_string);
        w
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl DeliveryWriter for ClaudeCodeWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::ClaudeCodeSettings
    }

    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }

    fn field_names(&self) -> Vec<String> {
        let mut names = vec![Self::FIELD_TOKEN.to_string()];
        if !self.base_url.trim().is_empty() {
            names.push(Self::FIELD_BASE_URL.to_string());
        }
        if self.model.is_some() {
            names.push(Self::FIELD_MODEL.to_string());
        }
        if self.thinking_level().is_some() {
            names.push(Self::FIELD_THINKING_LEVEL.to_string());
        }
        names
    }

    fn fields(&self, api_key: &str) -> Vec<DeliveryField> {
        let mut fields = vec![masked_field(Self::FIELD_TOKEN, api_key)];
        if !self.base_url.trim().is_empty() {
            fields.push(literal_field(Self::FIELD_BASE_URL, &self.base_url));
        }
        if let Some(m) = &self.model {
            fields.push(literal_field(Self::FIELD_MODEL, m));
        }
        if let Some(level) = self.thinking_level() {
            fields.push(literal_field(Self::FIELD_THINKING_LEVEL, level.as_str()));
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
    meta: Option<crate::model_meta::ModelMeta>,
    path: &Path,
) -> Result<String> {
    if api_key.trim().is_empty() {
        return Err(Error::inject(path, "密钥为空，拒绝写入"));
    }

    let style = JsonStyle::detect(before);
    let mut root = parse_object(before, path)?;

    {
        let env = object_entry(&mut root, ClaudeCodeWriter::ENV_KEY, path)?;
        env.insert(
            ClaudeCodeWriter::FIELD_TOKEN.to_string(),
            Value::String(api_key.to_string()),
        );
        if base_url.trim().is_empty() {
        } else {
            env.insert(
                ClaudeCodeWriter::FIELD_BASE_URL.to_string(),
                Value::String(base_url.to_string()),
            );
        }
        if let Some(m) = model {
            env.insert(
                ClaudeCodeWriter::FIELD_MODEL.to_string(),
                Value::String(m.clone()),
            );
        }
        // M47-S2：思考档位跟着模型走。三种情况必须分清（复审 P1-1 / P1-2）：
        //
        // - 名单**明确支持** ⇒ 写入 `defaultLevel`（用户可以在 Claude Code 里再调）；
        // - 名单**明确不支持**（有 meta、`thinking` 为 `None`）⇒ 删键：旧版/手工留下的
        //   `CLAUDE_CODE_EFFORT_LEVEL=max` 会让 Claude Code 每轮都带 `thinking`，而网关
        //   上游是 OpenAI Chat（ADR-0005），只能降级或丢弃——留着只会「时好时坏」；
        // - **没有模型名 / 名单没覆盖这个模型** ⇒ 未知 ⇒ **不写也不删**。
        //   把「未知」当「不支持」会静默删掉用户手设的档位（批量投递路径就是这样传的）。
        if let (Some(_), Some(m)) = (model.as_ref(), meta) {
            if m.thinking_unsupported {
                env.remove(ClaudeCodeWriter::FIELD_THINKING_LEVEL);
            } else {
                let level = m
                    .thinking
                    .filter(|spec| spec.accepts(spec.default_level))
                    .map(|spec| spec.default_level);
                if let Some(level) = level {
                    env.insert(
                        ClaudeCodeWriter::FIELD_THINKING_LEVEL.to_string(),
                        Value::String(level.as_str().to_string()),
                    );
                }
                // 未知（meta.thinking = None）保留原值，不把「没核对」当成「不支持」。
            }
        }
    }

    style.serialize(&root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "sk-claude-0123456789abcdef";
    const BASE: &str = "https://relay.example.com";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    fn plain_meta() -> crate::model_meta::ModelMeta {
        crate::model_meta::ModelMeta::from_catalog(
            128_000,
            4_096,
            None,
            false,
            crate::model_catalog::UpstreamProtocol::OpenAiChat,
            false,
        )
    }

    fn writer_with_model(dir: &Path, base_url: &str, model: &str) -> ClaudeCodeWriter {
        let mut w = writer_in(dir, base_url);
        w.model = Some(model.to_string());
        w
    }

    fn writer_in(dir: &Path, base_url: &str) -> ClaudeCodeWriter {
        ClaudeCodeWriter::with_path(dir.join("settings.json"), base_url)
    }

    #[test]
    fn creates_fresh_file() {
        let dir = tmp();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert_eq!(patch.before, "");
        let parsed: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(parsed["env"]["ANTHROPIC_AUTH_TOKEN"], SECRET);
        assert_eq!(parsed["env"]["ANTHROPIC_BASE_URL"], BASE);
        assert_eq!(patch.new_file_mode, Some(0o600));
    }

    #[test]
    fn preserves_every_other_key() {
        let dir = tmp();
        let before = r#"{
  "env": {
    "ANTHROPIC_AUTH_TOKEN": "sk-old",
    "ANTHROPIC_BASE_URL": "https://old.example.com",
    "ANTHROPIC_DEFAULT_OPUS_MODEL": "grok-4.6[1M]",
    "ANTHROPIC_MODEL": "grok-4.6"
  },
  "permissions": {
    "deny": [
      "DesignSync",
      "NotebookEdit"
    ]
  },
  "enableWorkflows": true,
  "enabledPlugins": {
    "oh-my-claudecode@omc": true
  }
}"#;
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();

        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        let after: Value = serde_json::from_str(&patch.after).unwrap();
        let before_v: Value = serde_json::from_str(before).unwrap();

        assert_eq!(after["env"]["ANTHROPIC_AUTH_TOKEN"], SECRET);
        assert_eq!(after["env"]["ANTHROPIC_BASE_URL"], BASE);

        for key in ["permissions", "enableWorkflows", "enabledPlugins"] {
            assert_eq!(after[key], before_v[key], "顶层键 {key} 被改动了");
        }
        assert_eq!(
            after["env"]["ANTHROPIC_DEFAULT_OPUS_MODEL"],
            before_v["env"]["ANTHROPIC_DEFAULT_OPUS_MODEL"]
        );
        // ANTHROPIC_MODEL 不传 model 时不改
        assert_eq!(
            after["env"]["ANTHROPIC_MODEL"],
            before_v["env"]["ANTHROPIC_MODEL"]
        );
    }

    #[test]
    fn empty_base_url_leaves_existing_base_url_alone() {
        let dir = tmp();
        let before = json!({"env": {"ANTHROPIC_BASE_URL": "https://keep.example.com"}}).to_string();
        std::fs::write(writer_in(dir.path(), "").path(), &before).unwrap();

        let patch = writer_in(dir.path(), "").plan(SECRET).unwrap();
        let after: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(
            after["env"]["ANTHROPIC_BASE_URL"],
            "https://keep.example.com"
        );
        assert_eq!(after["env"]["ANTHROPIC_AUTH_TOKEN"], SECRET);
        assert_eq!(writer_in(dir.path(), "").field_names().len(), 1);
    }

    #[test]
    fn rejects_env_that_is_not_an_object() {
        let dir = tmp();
        std::fs::write(
            writer_in(dir.path(), BASE).path(),
            json!({"env": [1, 2]}).to_string(),
        )
        .unwrap();
        let err = writer_in(dir.path(), BASE).plan(SECRET).unwrap_err();
        assert!(matches!(err, Error::Inject { .. }), "{err:?}");
        assert!(err.to_string().contains("不是对象"), "{err}");
    }

    #[test]
    fn rejects_invalid_json_and_non_object_root() {
        let dir = tmp();
        for bad in ["not json", "[1,2,3]", "\"str\""] {
            std::fs::write(writer_in(dir.path(), BASE).path(), bad).unwrap();
            assert!(
                matches!(
                    writer_in(dir.path(), BASE).plan(SECRET),
                    Err(Error::Inject { .. })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn rejects_empty_key() {
        let dir = tmp();
        for bad in ["", "   "] {
            assert!(matches!(
                writer_in(dir.path(), BASE).plan(bad),
                Err(Error::Inject { .. })
            ));
        }
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

    #[test]
    fn fields_mask_only_the_secret() {
        let dir = tmp();
        let fields = writer_in(dir.path(), BASE).fields(SECRET);
        assert_eq!(fields[0].key, "ANTHROPIC_AUTH_TOKEN");
        assert_eq!(fields[0].masked, "…cdef");
        assert_eq!(fields[1].key, "ANTHROPIC_BASE_URL");
        assert_eq!(fields[1].masked, BASE);
    }

    // ============================ M14-S7：B 类——只写模型名，不写参数

    const MODEL: &str = "gpt-4o";

    #[test]
    fn writes_model_name_only() {
        let dir = tmp();
        let writer = ClaudeCodeWriter::with_model(dir.path(), BASE, Some(MODEL));
        let patch = writer.plan(SECRET).unwrap();
        let v: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(v["env"]["ANTHROPIC_MODEL"], MODEL);
        // B 类不写 context_window / max_output
        assert!(v["env"].get("contextWindow").is_none());
        assert!(v["env"].get("maxTokens").is_none());
    }

    #[test]
    fn model_plan_is_idempotent() {
        let dir = tmp();
        let writer = ClaudeCodeWriter::with_model(dir.path(), BASE, Some(MODEL));
        std::fs::create_dir_all(writer.path().parent().unwrap()).ok();
        let first = writer.plan(SECRET).unwrap();
        std::fs::write(writer.path(), &first.after).unwrap();
        let second = writer.plan(SECRET).unwrap();
        assert_eq!(second.after, first.after);
    }

    #[test]
    fn model_replaces_existing() {
        let dir = tmp();
        let before = json!({"env": {"ANTHROPIC_MODEL": "old-model"}}).to_string();
        let writer = ClaudeCodeWriter::with_model(dir.path(), BASE, Some(MODEL));
        std::fs::create_dir_all(writer.path().parent().unwrap()).ok();
        std::fs::write(writer.path(), &before).unwrap();
        let patch = writer.plan(SECRET).unwrap();
        let v: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(v["env"]["ANTHROPIC_MODEL"], MODEL);
    }

    #[test]
    fn no_model_preserves_existing_model() {
        let dir = tmp();
        let before = json!({"env": {"ANTHROPIC_MODEL": "user-model"}}).to_string();
        std::fs::write(writer_in(dir.path(), BASE).path(), &before).unwrap();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        let v: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(v["env"]["ANTHROPIC_MODEL"], "user-model");
    }

    // ==================================================== M47-S2：名单带入思考档位

    fn catalog_meta(level: crate::model_catalog::ThinkingLevel) -> crate::model_meta::ModelMeta {
        crate::model_meta::ModelMeta::from_catalog(
            200_000,
            64_000,
            Some(crate::model_catalog::ThinkingSpec {
                param: crate::model_catalog::ThinkingParam::Thinking,
                max_level: crate::model_catalog::ThinkingLevel::High,
                default_level: level,
                budget_low: 4_096,
                budget_medium: 16_384,
                budget_high: 32_768,
                budget_xhigh: 0,
                levels: 0b11111,
            }),
            false,
            crate::model_catalog::UpstreamProtocol::AnthropicMessages,
            true,
        )
    }

    #[test]
    fn writes_thinking_level_from_catalog() {
        let dir = tmp();
        let writer = ClaudeCodeWriter::with_model(dir.path(), BASE, Some("m")).with_meta(Some(
            catalog_meta(crate::model_catalog::ThinkingLevel::Medium),
        ));
        let patch = writer.plan(SECRET).unwrap();
        let after: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(after["env"]["CLAUDE_CODE_EFFORT_LEVEL"], "medium");
        assert!(
            writer
                .fields(SECRET)
                .iter()
                .any(|f| f.key == ClaudeCodeWriter::FIELD_THINKING_LEVEL),
            "预览里必须列出这个键"
        );
    }

    #[test]
    fn removes_stale_thinking_level_when_the_catalog_says_unsupported() {
        let dir = tmp();
        let before =
            r#"{"env":{"ANTHROPIC_AUTH_TOKEN":"sk-old","CLAUDE_CODE_EFFORT_LEVEL":"max"}}"#;
        std::fs::write(dir.path().join("settings.json"), before).unwrap();
        // 只有名单/本机覆盖明确关闭思考才删旧键；「没写 thinking」只是未知。
        let mut meta = plain_meta();
        meta.thinking_unsupported = true;
        let patch = writer_with_model(dir.path(), BASE, "glm-4")
            .with_meta(Some(meta))
            .plan(SECRET)
            .unwrap();
        let after: Value = serde_json::from_str(&patch.after).unwrap();
        assert!(
            after["env"].get("CLAUDE_CODE_EFFORT_LEVEL").is_none(),
            "名单明确不支持 ⇒ 旧档位必须被删掉: {after}"
        );
    }

    #[test]
    fn keeps_a_hand_written_thinking_level_when_thinking_is_unknown() {
        let dir = tmp();
        let before = r#"{"env":{"CLAUDE_CODE_EFFORT_LEVEL":"max"}}"#;
        std::fs::write(dir.path().join("settings.json"), before).unwrap();
        let patch = writer_with_model(dir.path(), BASE, "gpt-4o")
            .with_meta(Some(plain_meta()))
            .plan(SECRET)
            .unwrap();
        let after: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(
            after["env"]["CLAUDE_CODE_EFFORT_LEVEL"], "max",
            "名单没声明 ≠ 明确不支持"
        );
    }

    #[test]
    fn keeps_a_hand_written_thinking_level_when_the_catalog_does_not_cover_the_model() {
        let dir = tmp();
        let before =
            r#"{"env":{"ANTHROPIC_AUTH_TOKEN":"sk-old","CLAUDE_CODE_EFFORT_LEVEL":"max"}}"#;
        std::fs::write(dir.path().join("settings.json"), before).unwrap();
        // meta = None 是「名单没覆盖」= **未知**，不是「不支持」：批量投递（不带模型）走的就是
        // 这条路，删掉就是静默抹掉用户自己设的档位（复审 P1-2）。
        let patch = writer_with_model(dir.path(), BASE, "some-unlisted-model")
            .plan(SECRET)
            .unwrap();
        let after: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(
            after["env"]["CLAUDE_CODE_EFFORT_LEVEL"], "max",
            "名单没覆盖 ⇒ 不写也不删，保留用户原值: {after}"
        );
    }

    #[test]
    fn does_not_write_a_level_without_a_model_name() {
        let dir = tmp();
        // 没有模型名 + 有 meta（理论上不该出现，但契约上必须一致）：不许写，否则
        // fields()/field_names() 里没有这个键，预览与同意都会漏掉一次真实写入（复审 P1-3）。
        let patch = writer_in(dir.path(), BASE)
            .with_meta(Some(plain_meta()))
            .plan(SECRET)
            .unwrap();
        let after: Value = serde_json::from_str(&patch.after).unwrap();
        assert!(after["env"].get("CLAUDE_CODE_EFFORT_LEVEL").is_none());
    }
}
