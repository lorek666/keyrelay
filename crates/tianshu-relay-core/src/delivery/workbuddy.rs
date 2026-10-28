//! CodeBuddy / WorkBuddy / WorkBuddy AI 通道：`models.json`。
//!
//! 三个产品共用 Tencent 的模型清单格式（Magpie `workbuddy.go` /
//! `codebuddy.go`）：条目带 `id` / `name` / `vendor` / `apiKey` / `url`。
//! CodeBuddy 的清单是 `{"models":[…]}`，WorkBuddy 是裸数组（也接受对象形态）。
//! 只替换 `vendor == "keyrelay"` 的条目，用户自己的模型原样保留。

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Map, Value};

use super::json_text::{read_text_or_empty, JsonStyle};
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;
use crate::model_meta::ModelMeta;

pub struct WorkBuddyWriter {
    path: PathBuf,
    channel: DeliveryChannel,
    base_url: String,
    model: Option<String>,
    meta: Option<ModelMeta>,
}

impl WorkBuddyWriter {
    pub const VENDOR: &'static str = "keyrelay";
    pub const FIELD_API_KEY: &'static str = "apiKey";
    pub const FIELD_URL: &'static str = "url";
    pub const FIELD_ID: &'static str = "id";

    pub fn new_codebuddy(home: &Path, base_url: &str) -> Self {
        Self::with_path(
            home.join(".codebuddy").join("models.json"),
            DeliveryChannel::CodeBuddy,
            base_url,
            None,
            None,
        )
    }

    pub fn new_workbuddy(home: &Path, base_url: &str) -> Self {
        Self::with_path(
            home.join(".workbuddy").join("models.json"),
            DeliveryChannel::WorkBuddy,
            base_url,
            None,
            None,
        )
    }

    pub fn new_workbuddy_ai(home: &Path, base_url: &str) -> Self {
        Self::with_path(
            home.join(".workbuddy-ai").join("models.json"),
            DeliveryChannel::WorkBuddyAi,
            base_url,
            None,
            None,
        )
    }

    pub fn with_model(
        home: &Path,
        channel: DeliveryChannel,
        base_url: &str,
        model: Option<&str>,
        meta: Option<ModelMeta>,
    ) -> Self {
        let path = match channel {
            DeliveryChannel::CodeBuddy => home.join(".codebuddy").join("models.json"),
            DeliveryChannel::WorkBuddy => home.join(".workbuddy").join("models.json"),
            DeliveryChannel::WorkBuddyAi => home.join(".workbuddy-ai").join("models.json"),
            other => {
                debug_assert!(false, "WorkBuddyWriter 收到不支持的通道 {other:?}");
                home.join(".workbuddy").join("models.json")
            }
        };
        Self::with_path(path, channel, base_url, model, meta)
    }

    pub fn with_path(
        path: impl Into<PathBuf>,
        channel: DeliveryChannel,
        base_url: &str,
        model: Option<&str>,
        meta: Option<ModelMeta>,
    ) -> Self {
        debug_assert!(
            matches!(
                channel,
                DeliveryChannel::CodeBuddy
                    | DeliveryChannel::WorkBuddy
                    | DeliveryChannel::WorkBuddyAi
            ),
            "WorkBuddyWriter 只服务 CodeBuddy / WorkBuddy / WorkBuddyAi，收到 {channel:?}"
        );
        Self {
            path: path.into(),
            channel,
            base_url: base_url.to_string(),
            model: model
                .map(str::trim)
                .filter(|m| !m.is_empty())
                .map(str::to_string),
            meta,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl DeliveryWriter for WorkBuddyWriter {
    fn channel(&self) -> DeliveryChannel {
        self.channel
    }

    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }

    fn field_names(&self) -> Vec<String> {
        vec![
            Self::FIELD_ID.to_string(),
            Self::FIELD_API_KEY.to_string(),
            Self::FIELD_URL.to_string(),
        ]
    }

    fn fields(&self, api_key: &str) -> Vec<DeliveryField> {
        vec![
            literal_field(Self::FIELD_ID, self.model.clone().unwrap_or_default()),
            masked_field(Self::FIELD_API_KEY, api_key),
            literal_field(Self::FIELD_URL, self.chat_url()),
        ]
    }

    fn plan(&self, api_key: &str) -> Result<Patch> {
        let before = read_text_or_empty(&self.path)?;
        let after = build_after(
            &before,
            api_key,
            &self.base_url,
            self.model.as_deref(),
            self.meta,
            self.channel,
            &self.path,
        )?;
        Ok(Patch::secret_bearing(self.path.clone(), before, after))
    }
}

impl WorkBuddyWriter {
    fn chat_url(&self) -> String {
        format!("{}/chat/completions", self.base_url.trim_end_matches('/'))
    }
}

/// 从现有 models.json 里取出 keyrelay 条目的 id，供轮换复用。
pub fn model_from_text(text: &str) -> Option<String> {
    let parsed: Value = serde_json::from_str(text).ok()?;
    let models = match &parsed {
        Value::Array(items) => Some(items),
        Value::Object(map) => map.get("models").and_then(Value::as_array),
        _ => None,
    }?;
    models
        .iter()
        .find(|item| item.get("vendor").and_then(Value::as_str) == Some(WorkBuddyWriter::VENDOR))
        .and_then(|entry| entry.get("id"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn build_after(
    before: &str,
    api_key: &str,
    base_url: &str,
    model: Option<&str>,
    meta: Option<ModelMeta>,
    channel: DeliveryChannel,
    path: &Path,
) -> Result<String> {
    if api_key.trim().is_empty() {
        return Err(Error::inject(path, "密钥为空，拒绝写入"));
    }
    if base_url.trim().is_empty() {
        return Err(Error::inject(path, "base_url 为空，拒绝写入"));
    }
    let Some(model) = model else {
        return Err(Error::inject(
            path,
            "该通道需要模型名：models.json 的条目必须指明 model",
        ));
    };

    let style = JsonStyle::detect(before);
    let mut root: Value = if before.trim().is_empty() {
        if matches!(channel, DeliveryChannel::CodeBuddy) {
            Value::Object(Map::new())
        } else {
            Value::Array(Vec::new())
        }
    } else {
        serde_json::from_str(before)
            .map_err(|e| Error::inject(path, format!("不是合法 JSON，拒绝改写: {e}")))?
    };

    let models: &mut Vec<Value> = match &mut root {
        Value::Array(items) => items,
        Value::Object(map) => {
            let entry = map
                .entry("models".to_string())
                .or_insert_with(|| Value::Array(Vec::new()));
            entry
                .as_array_mut()
                .ok_or_else(|| Error::inject(path, "models 不是数组，拒绝改写"))?
        }
        _ => return Err(Error::inject(path, "顶层必须是对象或数组，拒绝改写")),
    };

    let mut entry = models
        .iter()
        .find(|entry| entry.get("vendor").and_then(Value::as_str) == Some(WorkBuddyWriter::VENDOR))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    models.retain(|entry| {
        entry.get("vendor").and_then(Value::as_str) != Some(WorkBuddyWriter::VENDOR)
    });
    entry.insert("id".to_string(), Value::String(model.to_string()));
    entry.insert("name".to_string(), Value::String(model.to_string()));
    entry.insert(
        "vendor".to_string(),
        Value::String(WorkBuddyWriter::VENDOR.to_string()),
    );
    entry.insert(
        WorkBuddyWriter::FIELD_API_KEY.to_string(),
        Value::String(api_key.to_string()),
    );
    entry.insert(
        WorkBuddyWriter::FIELD_URL.to_string(),
        Value::String(format!(
            "{}/chat/completions",
            base_url.trim_end_matches('/')
        )),
    );
    entry.insert("supportsToolCall".to_string(), Value::Bool(true));
    entry.insert("supportsImages".to_string(), Value::Bool(false));
    entry.insert("supportsReasoning".to_string(), Value::Bool(false));
    if let Some(meta) = meta {
        entry.insert(
            "maxInputTokens".to_string(),
            Value::Number(serde_json::Number::from(meta.context_window)),
        );
        entry.insert(
            "maxOutputTokens".to_string(),
            Value::Number(serde_json::Number::from(meta.max_output_tokens)),
        );
    }
    models.push(Value::Object(entry));

    if matches!(channel, DeliveryChannel::CodeBuddy) && root.is_array() {
        root = Value::Object(Map::from_iter([(
            "models".to_string(),
            std::mem::replace(&mut root, Value::Null),
        )]));
    }

    serialize_value(&root, &style)
}

fn serialize_value(value: &Value, style: &JsonStyle) -> Result<String> {
    let mut out = match &style.indent {
        Some(indent) => {
            let formatter = serde_json::ser::PrettyFormatter::with_indent(indent);
            let mut buf = Vec::new();
            let mut serializer = serde_json::Serializer::with_formatter(&mut buf, formatter);
            value
                .serialize(&mut serializer)
                .map_err(|e| Error::Store(format!("序列化 JSON 失败: {e}")))?;
            String::from_utf8(buf).map_err(|_| Error::Store("序列化 JSON 产出非法 UTF-8".into()))?
        }
        None => serde_json::to_string(value)
            .map_err(|e| Error::Store(format!("序列化 JSON 失败: {e}")))?,
    };
    if style.trailing_newline {
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "sk-wb-0123456789abcdef";
    const BASE: &str = "http://127.0.0.1:19387/v1";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    #[test]
    fn codebuddy_writes_object_models_and_preserves_other_entries() {
        let dir = tmp();
        let path = dir.path().join("models.json");
        std::fs::write(
            &path,
            json!({"models":[{"id":"mine","vendor":"mine","apiKey":"keep"}],"availableModels":[]})
                .to_string(),
        )
        .unwrap();
        let writer = WorkBuddyWriter::with_path(
            &path,
            DeliveryChannel::CodeBuddy,
            BASE,
            Some("kimi-k3"),
            crate::model_meta::lookup("kimi-k3"),
        );
        let after = writer.plan(SECRET).unwrap().after;
        let parsed: Value = serde_json::from_str(&after).unwrap();
        assert_eq!(parsed["models"][0]["id"], "mine");
        let ours = parsed["models"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["vendor"] == "keyrelay")
            .unwrap();
        assert_eq!(ours["id"], "kimi-k3");
        assert_eq!(ours["apiKey"], SECRET);
        assert_eq!(ours["url"], "http://127.0.0.1:19387/v1/chat/completions");
    }

    #[test]
    fn workbuddy_writes_bare_array() {
        let dir = tmp();
        let path = dir.path().join("models.json");
        let writer = WorkBuddyWriter::with_path(
            &path,
            DeliveryChannel::WorkBuddy,
            BASE,
            Some("glm-5"),
            None,
        );
        let after = writer.plan(SECRET).unwrap().after;
        let parsed: Value = serde_json::from_str(&after).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed[0]["vendor"], "keyrelay");
    }

    #[test]
    fn preserves_unknown_keys_on_its_existing_entry() {
        let dir = tmp();
        let path = dir.path().join("models.json");
        std::fs::write(
            &path,
            json!([{"id":"old","vendor":"keyrelay","apiKey":"old","disabled":true,"note":"keep"}])
                .to_string(),
        )
        .unwrap();
        let writer = WorkBuddyWriter::with_path(
            &path,
            DeliveryChannel::WorkBuddy,
            BASE,
            Some("glm-5"),
            None,
        );
        let after = writer.plan(SECRET).unwrap().after;
        let parsed: Value = serde_json::from_str(&after).unwrap();
        assert_eq!(parsed[0]["disabled"], true);
        assert_eq!(parsed[0]["note"], "keep");
        assert_eq!(parsed[0]["id"], "glm-5");
    }

    #[test]
    fn workbuddy_ai_has_its_own_path() {
        let dir = tmp();
        let writer = WorkBuddyWriter::with_model(
            dir.path(),
            DeliveryChannel::WorkBuddyAi,
            BASE,
            Some("glm-5"),
            None,
        );
        assert_eq!(
            writer.target_path(),
            dir.path().join(".workbuddy-ai").join("models.json")
        );
    }

    #[test]
    fn plan_is_idempotent() {
        let dir = tmp();
        let writer = WorkBuddyWriter::with_path(
            dir.path().join("models.json"),
            DeliveryChannel::WorkBuddy,
            BASE,
            Some("glm-5"),
            crate::model_meta::lookup("glm-5"),
        );
        let first = writer.plan(SECRET).unwrap();
        std::fs::write(writer.path(), &first.after).unwrap();
        let second = writer.plan(SECRET).unwrap();
        assert_eq!(second.after, first.after);
    }

    #[test]
    fn requires_model() {
        let dir = tmp();
        let writer = WorkBuddyWriter::with_path(
            dir.path().join("models.json"),
            DeliveryChannel::WorkBuddy,
            BASE,
            None,
            None,
        );
        assert!(writer.plan(SECRET).is_err());
    }

    #[test]
    fn errors_never_echo_the_key() {
        let dir = tmp();
        let path = dir.path().join("models.json");
        std::fs::write(&path, "{ CANARY-FILE").unwrap();
        let writer =
            WorkBuddyWriter::with_path(&path, DeliveryChannel::WorkBuddy, BASE, Some("m"), None);
        let err = writer.plan("CANARY-KEY-4k2m").unwrap_err();
        assert!(!err.to_string().contains("CANARY-KEY-4k2m"));
        assert!(!err.to_string().contains("CANARY-FILE"));
    }
}
