//! Droid 通道：`~/.factory/settings.json` 的 `customModels`。
//!
//! Factory Droid 的 BYOK 自定义模型条目（Magpie `droid.go`）：
//! `{model,id,displayName,baseUrl,apiKey,provider,…}`，会话默认模型在
//! `sessionDefaultSettings.model`。只替换 `id` 以 `custom:keyrelay/` 开头的条目，
//! 用户自己的自定义模型和其余设置原样保留。

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Map, Value};

use super::json_text::{parse_object, read_text_or_empty, JsonStyle};
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;
use crate::model_meta::ModelMeta;

pub struct DroidWriter {
    path: PathBuf,
    base_url: String,
    model: Option<String>,
    meta: Option<ModelMeta>,
}

impl DroidWriter {
    pub const PROVIDER: &'static str = "keyrelay";
    pub const FIELD_API_KEY: &'static str = "apiKey";
    pub const FIELD_BASE_URL: &'static str = "baseUrl";
    pub const FIELD_MODEL: &'static str = "model";
    pub const FIELD_SESSION_MODEL: &'static str = "sessionModel";
    const SESSION_MODEL_KEY: &'static str = "model";
    const ID_PREFIX: &'static str = "custom:keyrelay/";

    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path(
            home.join(".factory").join("settings.json"),
            base_url,
            None,
            None,
        )
    }

    pub fn with_model(
        home: &Path,
        base_url: &str,
        model: Option<&str>,
        meta: Option<ModelMeta>,
    ) -> Self {
        Self::with_path(
            home.join(".factory").join("settings.json"),
            base_url,
            model,
            meta,
        )
    }

    pub fn with_path(
        path: impl Into<PathBuf>,
        base_url: &str,
        model: Option<&str>,
        meta: Option<ModelMeta>,
    ) -> Self {
        Self {
            path: path.into(),
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

impl DeliveryWriter for DroidWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::Droid
    }

    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }

    fn field_names(&self) -> Vec<String> {
        vec![
            Self::FIELD_MODEL.to_string(),
            Self::FIELD_API_KEY.to_string(),
            Self::FIELD_BASE_URL.to_string(),
            Self::FIELD_SESSION_MODEL.to_string(),
        ]
    }

    fn fields(&self, api_key: &str) -> Vec<DeliveryField> {
        vec![
            literal_field(Self::FIELD_MODEL, self.model.clone().unwrap_or_default()),
            masked_field(Self::FIELD_API_KEY, api_key),
            literal_field(Self::FIELD_BASE_URL, &self.base_url),
            literal_field(
                Self::FIELD_SESSION_MODEL,
                format!(
                    "{}{}",
                    Self::ID_PREFIX,
                    self.model.clone().unwrap_or_default()
                ),
            ),
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
            &self.path,
        )?;
        Ok(Patch::secret_bearing(self.path.clone(), before, after))
    }
}

/// 从现有 Droid 配置里取出 keyrelay 条目的 model，供轮换复用。
pub fn model_from_text(text: &str) -> Option<String> {
    let parsed: Value = serde_json::from_str(text).ok()?;
    parsed
        .get("customModels")
        .and_then(Value::as_array)
        .and_then(|arr| {
            arr.iter().find(|item| {
                item.get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| id.starts_with(DroidWriter::ID_PREFIX))
            })
        })
        .and_then(|entry| entry.get("model"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn build_after(
    before: &str,
    api_key: &str,
    base_url: &str,
    model: Option<&str>,
    meta: Option<ModelMeta>,
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
            "Droid 通道需要模型名：customModels 的条目必须指明 model",
        ));
    };

    let style = JsonStyle::detect(before);
    let mut root = parse_object(before, path)?;
    let entry = root
        .entry("customModels".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    let models = entry
        .as_array_mut()
        .ok_or_else(|| Error::inject(path, "customModels 不是数组，拒绝改写"))?;
    // 保留同一模型的既有条目：Droid 的自定义模型条目允许用户改显示名、
    // 上下文/输出上限和图片支持等；换 key 只应换连接字段。
    let id = format!("{}{}", DroidWriter::ID_PREFIX, model);
    let existing = models
        .iter()
        .find(|entry| entry.get("id").and_then(Value::as_str) == Some(id.as_str()))
        .and_then(Value::as_object)
        .cloned();
    models.retain(|entry| {
        !entry
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| id.starts_with(DroidWriter::ID_PREFIX))
    });
    let mut item = existing.unwrap_or_default();
    item.insert("model".to_string(), Value::String(model.to_string()));
    item.insert("id".to_string(), Value::String(id.clone()));
    item.entry("displayName".to_string())
        .or_insert_with(|| Value::String(model.to_string()));
    item.insert(
        DroidWriter::FIELD_BASE_URL.to_string(),
        Value::String(base_url.to_string()),
    );
    item.insert(
        DroidWriter::FIELD_API_KEY.to_string(),
        Value::String(api_key.to_string()),
    );
    item.insert(
        "provider".to_string(),
        Value::String("generic-chat-completion-api".to_string()),
    );
    if let Some(meta) = meta {
        item.insert(
            "maxContextLimit".to_string(),
            Value::Number(serde_json::Number::from(meta.context_window)),
        );
        item.insert(
            "maxOutputTokens".to_string(),
            Value::Number(serde_json::Number::from(meta.max_output_tokens)),
        );
    }
    item.entry("noImageSupport".to_string())
        .or_insert(Value::Bool(true));
    models.push(Value::Object(item));

    let session = root
        .entry("sessionDefaultSettings".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let session = session
        .as_object_mut()
        .ok_or_else(|| Error::inject(path, "sessionDefaultSettings 不是对象，拒绝改写"))?;
    session.insert(
        DroidWriter::SESSION_MODEL_KEY.to_string(),
        Value::String(id),
    );

    serialize_object(&root, &style)
}

fn serialize_object(map: &Map<String, Value>, style: &JsonStyle) -> Result<String> {
    let mut out = match &style.indent {
        Some(indent) => {
            let formatter = serde_json::ser::PrettyFormatter::with_indent(indent);
            let mut buf = Vec::new();
            let mut serializer = serde_json::Serializer::with_formatter(&mut buf, formatter);
            Value::Object(map.clone())
                .serialize(&mut serializer)
                .map_err(|e| Error::Store(format!("序列化 JSON 失败: {e}")))?;
            String::from_utf8(buf).map_err(|_| Error::Store("序列化 JSON 产出非法 UTF-8".into()))?
        }
        None => serde_json::to_string(map)
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

    const SECRET: &str = "sk-droid-0123456789abcdef";
    const BASE: &str = "http://127.0.0.1:19387/v1";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    #[test]
    fn writes_custom_model_and_session_default() {
        let dir = tmp();
        let writer = DroidWriter::with_path(
            dir.path().join("settings.json"),
            BASE,
            Some("glm-5"),
            crate::model_meta::lookup("glm-5"),
        );
        let patch = writer.plan(SECRET).unwrap();
        let parsed: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(parsed["customModels"][0]["id"], "custom:keyrelay/glm-5");
        assert_eq!(parsed["customModels"][0]["apiKey"], SECRET);
        assert_eq!(parsed["customModels"][0]["baseUrl"], BASE);
        assert_eq!(
            parsed["sessionDefaultSettings"]["model"],
            "custom:keyrelay/glm-5"
        );
    }

    #[test]
    fn preserves_user_models_and_settings() {
        let dir = tmp();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            json!({"customModels":[{"id":"custom:mine","model":"mine"}],"theme":"dark"})
                .to_string(),
        )
        .unwrap();
        let writer = DroidWriter::with_path(&path, BASE, Some("glm-5"), None);
        let after = writer.plan(SECRET).unwrap().after;
        let parsed: Value = serde_json::from_str(&after).unwrap();
        assert_eq!(parsed["customModels"][0]["id"], "custom:mine");
        assert_eq!(parsed["theme"], "dark");
        assert!(parsed["customModels"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["id"] == "custom:keyrelay/glm-5"));
    }

    #[test]
    fn preserves_existing_model_metadata_on_reapply() {
        let dir = tmp();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            json!({
                "customModels": [{
                    "id": "custom:keyrelay/glm-5",
                    "model": "glm-5",
                    "displayName": "My GLM",
                    "maxContextLimit": 999_000,
                    "noImageSupport": false,
                    "customFlag": "keep"
                }]
            })
            .to_string(),
        )
        .unwrap();
        let writer = DroidWriter::with_path(&path, BASE, Some("glm-5"), None);
        let after = writer.plan(SECRET).unwrap().after;
        let parsed: Value = serde_json::from_str(&after).unwrap();
        let entry = &parsed["customModels"][0];
        assert_eq!(entry["apiKey"], SECRET);
        assert_eq!(entry["displayName"], "My GLM");
        assert_eq!(entry["maxContextLimit"], 999_000);
        assert_eq!(entry["noImageSupport"], false);
        assert_eq!(entry["customFlag"], "keep");
    }

    #[test]
    fn plan_is_idempotent() {
        let dir = tmp();
        let writer = DroidWriter::with_path(
            dir.path().join("settings.json"),
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
        let writer = DroidWriter::with_path(dir.path().join("settings.json"), BASE, None, None);
        assert!(writer.plan(SECRET).is_err());
    }

    #[test]
    fn errors_never_echo_the_key() {
        let dir = tmp();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, "{ CANARY-FILE").unwrap();
        let writer = DroidWriter::with_path(&path, BASE, Some("m"), None);
        let err = writer.plan("CANARY-KEY-4k2m").unwrap_err();
        assert!(!err.to_string().contains("CANARY-KEY-4k2m"));
        assert!(!err.to_string().contains("CANARY-FILE"));
    }
}
