//! Codex CLI 的密钥投递：`~/.codex/auth.json`。
//!
//! 目标文件实测形态（本机真实文件，2026-10-12）：
//! ```json
//! {
//!   "auth_mode": "apikey",
//!   "OPENAI_API_KEY": "sk-…"
//! }
//! ```
//! 该文件**必须含密钥本体**（Codex CLI 不做间接引用），因此：
//! - 新建时权限位 0600（[`Patch::secret_bearing`]）；
//! - `Patch` 的 `Debug` 已手写脱敏（BACKLOG B-12）；
//! - 只改 `auth_mode` 与 `OPENAI_API_KEY` 两个键，其余键**原样保留**。

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::json_text::{kind_name, parse_object, read_text_or_empty, JsonStyle};
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;

pub struct CodexAuthWriter {
    path: PathBuf,
}

impl CodexAuthWriter {
    pub const FIELD_API_KEY: &'static str = "OPENAI_API_KEY";
    pub const FIELD_AUTH_MODE: &'static str = "auth_mode";
    pub const AUTH_MODE_APIKEY: &'static str = "apikey";

    /// `home` 显式传入（不读 `HOME` 环境变量），便于测试重定向到临时目录。
    pub fn new(home: &Path) -> Self {
        Self::with_path(home.join(".codex").join("auth.json"))
    }

    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl DeliveryWriter for CodexAuthWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::CodexAuthJson
    }

    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }

    fn field_names(&self) -> Vec<String> {
        vec![
            Self::FIELD_AUTH_MODE.to_string(),
            Self::FIELD_API_KEY.to_string(),
        ]
    }

    fn fields(&self, api_key: &str) -> Vec<DeliveryField> {
        vec![
            literal_field(Self::FIELD_AUTH_MODE, Self::AUTH_MODE_APIKEY),
            masked_field(Self::FIELD_API_KEY, api_key),
        ]
    }

    fn plan(&self, api_key: &str) -> Result<Patch> {
        let before = read_text_or_empty(&self.path)?;
        let after = build_after(&before, api_key, &self.path)?;
        Ok(Patch::secret_bearing(self.path.clone(), before, after))
    }
}

/// 生成写入后的完整文本。`api_key` 会出现在返回值里——调用方不得打印。
fn build_after(before: &str, api_key: &str, path: &Path) -> Result<String> {
    if api_key.trim().is_empty() {
        return Err(Error::inject(path, "密钥为空，拒绝写入"));
    }

    let style = JsonStyle::detect(before);
    let mut root: Map<String, Value> = parse_object(before, path)?;

    // 冲突保护：`auth_mode` 已是别的模式（例如 `chatgpt`）时，改写成 `apikey`
    // 会把用户已有的 ChatGPT 登录态打掉，且不可逆。
    if let Some(existing) = root.get(CodexAuthWriter::FIELD_AUTH_MODE) {
        let is_apikey = existing
            .as_str()
            .map(|s| s == CodexAuthWriter::AUTH_MODE_APIKEY)
            .unwrap_or(false);
        if !is_apikey {
            let shown = match existing {
                Value::String(s) => crate::redact::scrub(s),
                other => format!("(非字符串: {})", kind_name(other)),
            };
            return Err(Error::inject(
                path,
                format!("现有 auth_mode 是 {shown}，改写会破坏你的登录态；请先手工处理该文件"),
            ));
        }
    }

    root.insert(
        CodexAuthWriter::FIELD_AUTH_MODE.to_string(),
        Value::String(CodexAuthWriter::AUTH_MODE_APIKEY.to_string()),
    );
    root.insert(
        CodexAuthWriter::FIELD_API_KEY.to_string(),
        Value::String(api_key.to_string()),
    );

    style.serialize(&root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    fn writer_in(dir: &Path) -> CodexAuthWriter {
        CodexAuthWriter::with_path(dir.join("auth.json"))
    }

    #[test]
    fn errors_never_echo_the_key() {
        // DEBUG-G7 P2-K4：畸形旧文件 + 双 canary——传入的新密钥与旧文件里的旧
        // 密钥残值都不许出现在错误串里（任一回显路径改坏都会红）。
        let dir = tmp();
        std::fs::write(
            writer_in(dir.path()).path(),
            "{\"api_key\": \"CANARY-FILE-9x7z",
        )
        .unwrap();
        let err = writer_in(dir.path()).plan("CANARY-KEY-4k2m").unwrap_err();
        assert!(!err.to_string().contains("CANARY-KEY-4k2m"), "{err}");
        assert!(!err.to_string().contains("CANARY-FILE-9x7z"), "{err}");
    }

    #[test]
    fn creates_fresh_file_with_expected_shape() {
        let dir = tmp();
        let w = writer_in(dir.path());
        let patch = w.plan("sk-0123456789abcdef").unwrap();

        assert_eq!(patch.before, "");
        assert_eq!(
            patch.after,
            "{\n  \"auth_mode\": \"apikey\",\n  \"OPENAI_API_KEY\": \"sk-0123456789abcdef\"\n}"
        );
        assert_eq!(patch.new_file_mode, Some(0o600));
    }

    #[test]
    fn preserves_unrelated_keys_and_indent() {
        let dir = tmp();
        let w = writer_in(dir.path());
        let before = "{\n    \"tokens\": {\n        \"id_token\": \"abc\"\n    },\n    \"auth_mode\": \"apikey\",\n    \"OPENAI_API_KEY\": \"sk-old\"\n}";
        std::fs::write(w.path(), before).unwrap();

        let patch = w.plan("sk-new-0123456789").unwrap();
        let after: Value = serde_json::from_str(&patch.after).unwrap();

        assert_eq!(after["tokens"]["id_token"], "abc", "无关键必须保留");
        assert_eq!(after["OPENAI_API_KEY"], "sk-new-0123456789");
        assert_eq!(after["auth_mode"], "apikey");
        assert!(patch.after.contains("\n    \"tokens\""), "4 空格缩进应保留");
        assert!(!patch.after.ends_with('\n'), "尾随换行状态应保留");
    }

    #[test]
    fn preserves_trailing_newline_when_present() {
        let dir = tmp();
        let w = writer_in(dir.path());
        std::fs::write(w.path(), "{\n  \"auth_mode\": \"apikey\"\n}\n").unwrap();
        let patch = w.plan("sk-new-0123456789").unwrap();
        assert!(patch.after.ends_with("}\n"), "原文件有尾随换行时应保留");
    }

    #[test]
    fn single_line_file_stays_single_line() {
        let dir = tmp();
        let w = writer_in(dir.path());
        std::fs::write(
            w.path(),
            r#"{"auth_mode":"apikey","OPENAI_API_KEY":"sk-old"}"#,
        )
        .unwrap();
        let patch = w.plan("sk-new-0123456789").unwrap();
        assert_eq!(
            patch.after,
            r#"{"auth_mode":"apikey","OPENAI_API_KEY":"sk-new-0123456789"}"#
        );
    }

    #[test]
    fn refuses_to_clobber_chatgpt_login() {
        let dir = tmp();
        let w = writer_in(dir.path());
        let before = "{\n  \"auth_mode\": \"chatgpt\",\n  \"tokens\": {\"access_token\": \"x\"}\n}";
        std::fs::write(w.path(), before).unwrap();

        let err = w.plan("sk-new-0123456789").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("auth_mode"), "{text}");
        assert!(text.contains("chatgpt"), "{text}");
        assert_eq!(
            std::fs::read_to_string(w.path()).unwrap(),
            before,
            "拒绝时必须一个字节都没动"
        );
    }

    #[test]
    fn rejects_invalid_json_and_non_object_root() {
        let dir = tmp();
        let w = writer_in(dir.path());
        for bad in ["not json at all", "[1,2,3]", "\"just a string\""] {
            std::fs::write(w.path(), bad).unwrap();
            assert!(
                matches!(w.plan("sk-new-0123456789"), Err(Error::Inject { .. })),
                "{bad}"
            );
        }
    }

    #[test]
    fn rejects_empty_key() {
        let dir = tmp();
        let w = writer_in(dir.path());
        for bad in ["", "   ", "\n"] {
            assert!(matches!(w.plan(bad), Err(Error::Inject { .. })), "{bad:?}");
        }
    }

    #[test]
    fn plan_is_idempotent() {
        let dir = tmp();
        let w = writer_in(dir.path());
        let first = w.plan("sk-0123456789abcdef").unwrap();
        std::fs::write(w.path(), &first.after).unwrap();

        let second = w.plan("sk-0123456789abcdef").unwrap();
        assert_eq!(second.before, first.after);
        assert_eq!(second.after, first.after, "二次投递不得产生额外改动");
    }

    #[test]
    fn fields_mask_only_the_secret() {
        let dir = tmp();
        let fields = writer_in(dir.path()).fields("sk-0123456789abcdef");
        assert_eq!(fields[0].key, "auth_mode");
        assert_eq!(fields[0].masked, "apikey");
        assert_eq!(fields[1].key, "OPENAI_API_KEY");
        assert_eq!(fields[1].masked, "…cdef");
    }

    #[test]
    fn error_messages_never_echo_the_key() {
        let dir = tmp();
        let w = writer_in(dir.path());
        std::fs::write(w.path(), "not json").unwrap();
        let err = w.plan("sk-VERY-SECRET-KEY-0123456789").unwrap_err();
        assert!(!err.to_string().contains("VERY-SECRET"), "{err}");
    }
}
