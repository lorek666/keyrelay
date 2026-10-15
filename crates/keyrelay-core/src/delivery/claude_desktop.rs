//! Claude Desktop 通道：`claude_desktop_config.json` 的 `env.ANTHROPIC_*`。
//!
//! 与 Claude Code 通道（`~/.claude/settings.json`）的字段结构相同，
//! 但落点是 Claude Desktop 的应用数据目录（平台相关）。
//!
//! macOS:  `~/Library/Application Support/Claude/claude_desktop_config.json`
//! Windows: `%LOCALAPPDATA%\Claude\claude_desktop_config.json`
//! Linux:  `~/.config/Claude/claude_desktop_config.json`
//!
//! 只写 `env.ANTHROPIC_AUTH_TOKEN` 和 `env.ANTHROPIC_BASE_URL`，
//! 不触碰 `inferenceModels` / `mcpServers` 等模型与 MCP 配置。

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::json_text::{object_entry, parse_object, read_text_or_empty, JsonStyle};
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;

pub struct ClaudeDesktopWriter {
    path: PathBuf,
    base_url: String,
}

impl ClaudeDesktopWriter {
    pub const FIELD_TOKEN: &'static str = "ANTHROPIC_AUTH_TOKEN";
    pub const FIELD_BASE_URL: &'static str = "ANTHROPIC_BASE_URL";
    const ENV_KEY: &'static str = "env";

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

impl DeliveryWriter for ClaudeDesktopWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::ClaudeDesktop
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

/// 配置文件相对于用户目录的路径（平台相关）。
pub fn relative_config_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude_desktop_config.json")
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from("AppData")
            .join("Local")
            .join("Claude")
            .join("claude_desktop_config.json")
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from(".config")
            .join("Claude")
            .join("claude_desktop_config.json")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        PathBuf::from(".config")
            .join("Claude")
            .join("claude_desktop_config.json")
    }
}

fn build_after(before: &str, api_key: &str, base_url: &str, path: &Path) -> Result<String> {
    if api_key.trim().is_empty() {
        return Err(Error::inject(path, "密钥为空，拒绝写入"));
    }

    let style = JsonStyle::detect(before);
    let mut root = parse_object(before, path)?;

    {
        let env = object_entry(&mut root, ClaudeDesktopWriter::ENV_KEY, path)?;
        env.insert(
            ClaudeDesktopWriter::FIELD_TOKEN.to_string(),
            Value::String(api_key.to_string()),
        );
        if !base_url.is_empty() {
            env.insert(
                ClaudeDesktopWriter::FIELD_BASE_URL.to_string(),
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

    const SECRET: &str = "sk-desktop-0123456789abcdef";
    const BASE: &str = "https://relay.example.com";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    fn writer_in(dir: &Path, base_url: &str) -> ClaudeDesktopWriter {
        ClaudeDesktopWriter::with_path(dir.join("claude_desktop_config.json"), base_url)
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
    "ANTHROPIC_BASE_URL": "https://old.example.com"
  },
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem"]
    }
  }
}"#;
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();

        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        let after: Value = serde_json::from_str(&patch.after).unwrap();
        let before_v: Value = serde_json::from_str(before).unwrap();

        assert_eq!(after["env"]["ANTHROPIC_AUTH_TOKEN"], SECRET);
        assert_eq!(after["env"]["ANTHROPIC_BASE_URL"], BASE);
        assert_eq!(
            after["mcpServers"], before_v["mcpServers"],
            "mcpServers 被改动了"
        );
    }

    #[test]
    fn empty_base_url_leaves_existing_alone() {
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
        std::fs::write(writer_in(dir.path(), BASE).path(), "not json").unwrap();
        let err = writer_in(dir.path(), BASE)
            .plan("sk-VERY-SECRET-0123456789")
            .unwrap_err();
        assert!(!err.to_string().contains("VERY-SECRET"), "{err}");
    }
}
