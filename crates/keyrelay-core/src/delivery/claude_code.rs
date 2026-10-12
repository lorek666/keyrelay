//! Claude Code 通道：`~/.claude/settings.json` 的 `env.ANTHROPIC_*`。
//!
//! 本机实测（2026-10-12）该文件有 **6 个顶层键**与 **9 个 `env` 键**，
//! 投递只允许碰其中两个：
//! ```json
//! { "env": { "ANTHROPIC_AUTH_TOKEN": "sk-…", "ANTHROPIC_BASE_URL": "https://…" } }
//! ```
//! 其余键（`permissions` / `enabledPlugins` / 其它 `ANTHROPIC_DEFAULT_*_MODEL`）必须保留——
//! 把用户的模型别名配置洗掉会让 Claude Code 行为突变。

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::json_text::{object_entry, parse_object, read_text_or_empty, JsonStyle};
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;

pub struct ClaudeCodeWriter {
    path: PathBuf,
    base_url: String,
}

impl ClaudeCodeWriter {
    pub const FIELD_TOKEN: &'static str = "ANTHROPIC_AUTH_TOKEN";
    pub const FIELD_BASE_URL: &'static str = "ANTHROPIC_BASE_URL";
    const ENV_KEY: &'static str = "env";

    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path(home.join(".claude").join("settings.json"), base_url)
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

impl DeliveryWriter for ClaudeCodeWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::ClaudeCodeSettings
    }

    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }

    fn field_names(&self) -> Vec<String> {
        let mut names = vec![Self::FIELD_TOKEN.to_string()];
        if !self.base_url.is_empty() {
            names.push(Self::FIELD_BASE_URL.to_string());
        }
        names
    }

    fn fields(&self, api_key: &str) -> Vec<DeliveryField> {
        let mut fields = vec![masked_field(Self::FIELD_TOKEN, api_key)];
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

/// 生成写入后的完整文本。`api_key` 会出现在返回值里——调用方不得打印。
fn build_after(before: &str, api_key: &str, base_url: &str, path: &Path) -> Result<String> {
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
        if base_url.is_empty() {
            // base_url 为空表示「只投递密钥」：不动用户已有的 BASE_URL
        } else {
            env.insert(
                ClaudeCodeWriter::FIELD_BASE_URL.to_string(),
                Value::String(base_url.to_string()),
            );
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
        // 仿本机真实形态：6 个顶层键 + 9 个 env 键
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

        // 除目标两个键外，其余键的**值**必须完全相同
        for key in ["permissions", "enableWorkflows", "enabledPlugins"] {
            assert_eq!(after[key], before_v[key], "顶层键 {key} 被改动了");
        }
        assert_eq!(
            after["env"]["ANTHROPIC_DEFAULT_OPUS_MODEL"],
            before_v["env"]["ANTHROPIC_DEFAULT_OPUS_MODEL"]
        );
        assert_eq!(
            after["env"]["ANTHROPIC_MODEL"],
            before_v["env"]["ANTHROPIC_MODEL"]
        );
        // 缩进风格保留
        assert!(patch.after.contains("\n  \"env\""), "{}", patch.after);
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
}
