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
use super::{SecondaryPatch, SecondaryTarget};
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

    fn secondary_targets(&self) -> Vec<SecondaryTarget> {
        if self.channel != DeliveryChannel::CodeBuddy {
            return Vec::new();
        }
        vec![SecondaryTarget {
            path: self.settings_path(),
            field_names: vec!["model".to_string()],
            expected_fields: vec!["model".to_string()],
        }]
    }

    fn secondary_plans(&self, _api_key: &str) -> Result<Vec<SecondaryPatch>> {
        if self.channel != DeliveryChannel::CodeBuddy {
            return Ok(Vec::new());
        }
        let Some(model) = self.model.as_deref() else {
            return Err(Error::inject(
                &self.path,
                "CodeBuddy 需要模型名：settings.json 的 model 不能为空",
            ));
        };
        let path = self.settings_path();
        let before = read_text_or_empty(&path)?;
        let after = build_settings_after(&before, model, &path)?;
        Ok(vec![SecondaryPatch {
            target_path: path.clone(),
            fields: vec![literal_field("model", model)],
            patch: Patch::new(path, before, after),
        }])
    }
}

impl WorkBuddyWriter {
    fn chat_url(&self) -> String {
        format!("{}/chat/completions", self.base_url.trim_end_matches('/'))
    }

    /// CodeBuddy 的会话首模型，与 models.json 同目录。
    fn settings_path(&self) -> PathBuf {
        self.path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("settings.json")
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

    let existing = models
        .iter()
        .find(|entry| entry.get("vendor").and_then(Value::as_str) == Some(WorkBuddyWriter::VENDOR))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let old_id = existing
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let ours: Vec<String> = models
        .iter()
        .filter(|entry| {
            entry.get("vendor").and_then(Value::as_str) == Some(WorkBuddyWriter::VENDOR)
        })
        .filter_map(|entry| entry.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let mut entry = existing;
    models.retain(|entry| {
        entry.get("vendor").and_then(Value::as_str) != Some(WorkBuddyWriter::VENDOR)
    });
    // 同一个 id 重投时保留用户改过的显示名；换模型时名称必须跟着换，
    // 否则 picker 会把新模型显示成旧名字。
    if old_id != model {
        entry.insert("name".to_string(), Value::String(model.to_string()));
    } else {
        entry
            .entry("name".to_string())
            .or_insert_with(|| Value::String(model.to_string()));
    }
    entry.insert("id".to_string(), Value::String(model.to_string()));
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
    entry
        .entry("supportsImages".to_string())
        .or_insert(Value::Bool(false));
    // 思考能力只有名单明确给出时才改成 true；未知不把用户已有的 true 降级。
    if meta.is_some_and(|meta| meta.thinking.is_some()) {
        entry.insert("supportsReasoning".to_string(), Value::Bool(true));
    } else {
        entry
            .entry("supportsReasoning".to_string())
            .or_insert(Value::Bool(false));
    }
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

    // CodeBuddy/WorkBuddy 的对象形态会带一个 availableModels 列表（字符串数组）。
    // 列表非空时它才是 picker 的实际来源：旧的 keyrelay id 必须删掉，否则
    // 换模型后 picker 仍会显示/选中旧 id。空列表按既有语义保持不动。
    if let Value::Object(map) = &mut root {
        if let Some(Value::Array(available)) = map.get_mut("availableModels") {
            if !available.is_empty() && available.iter().all(Value::is_string) {
                available.retain(|item| {
                    item.as_str()
                        .is_none_or(|id| !ours.iter().any(|old| old == id))
                });
                if !available.iter().any(|item| item.as_str() == Some(model)) {
                    available.push(Value::String(model.to_string()));
                }
            }
        }
    }

    serialize_value(&root, &style)
}

/// CodeBuddy 的 `settings.json`：只改会话首模型 `model`，其余键原样保留。
fn build_settings_after(before: &str, model: &str, path: &Path) -> Result<String> {
    let style = JsonStyle::detect(before);
    let mut root: Value = if before.trim().is_empty() {
        Value::Object(Map::new())
    } else {
        serde_json::from_str(before).map_err(|e| {
            Error::inject(path, format!("settings.json 不是合法 JSON，拒绝改写: {e}"))
        })?
    };
    let map = root
        .as_object_mut()
        .ok_or_else(|| Error::inject(path, "CodeBuddy settings.json 顶层必须是对象，拒绝改写"))?;
    map.insert("model".to_string(), Value::String(model.to_string()));
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
    fn codebuddy_updates_non_empty_available_models_and_settings_model() {
        let dir = tmp();
        let path = dir.path().join("models.json");
        std::fs::write(
            &path,
            json!({
                "models": [{"id":"old","vendor":"keyrelay","apiKey":"old","name":"My old"}],
                "availableModels": ["mine", "old"]
            })
            .to_string(),
        )
        .unwrap();
        let settings = dir.path().join("settings.json");
        std::fs::write(
            &settings,
            json!({"model":"gpt-5","language":"中文","permissions":{"allow":["Bash(ls)"]}})
                .to_string(),
        )
        .unwrap();
        let writer = WorkBuddyWriter::with_path(
            &path,
            DeliveryChannel::CodeBuddy,
            BASE,
            Some("kimi-k3"),
            None,
        );
        let after = writer.plan(SECRET).unwrap().after;
        let parsed: Value = serde_json::from_str(&after).unwrap();
        assert_eq!(parsed["availableModels"], json!(["mine", "kimi-k3"]));
        let ours = parsed["models"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["vendor"] == "keyrelay")
            .unwrap();
        assert_eq!(ours["name"], "kimi-k3");

        let secondary = writer.secondary_plans(SECRET).unwrap();
        assert_eq!(secondary.len(), 1);
        let settings_after: Value = serde_json::from_str(&secondary[0].patch.after).unwrap();
        assert_eq!(settings_after["model"], "kimi-k3");
        assert_eq!(settings_after["language"], "中文");
        assert_eq!(settings_after["permissions"]["allow"][0], "Bash(ls)");
    }

    #[test]
    fn workbuddy_preserves_user_name_flags_and_disabled() {
        let dir = tmp();
        let path = dir.path().join("models.json");
        std::fs::write(
            &path,
            json!([{
                "id":"glm-5",
                "vendor":"keyrelay",
                "apiKey":"old",
                "name":"My GLM",
                "supportsImages":true,
                "supportsReasoning":true,
                "disabled":true,
                "note":"keep"
            }])
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
        assert_eq!(parsed[0]["name"], "My GLM");
        assert_eq!(parsed[0]["supportsImages"], true);
        assert_eq!(parsed[0]["supportsReasoning"], true);
        assert_eq!(parsed[0]["disabled"], true);
        assert_eq!(parsed[0]["note"], "keep");
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
