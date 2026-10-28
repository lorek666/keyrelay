//! Crush 通道：`~/.config/crush/crush.json`。
//!
//! Crush 的 provider 条目（Magpie `agents.go` 的 crush 分支）：
//! `providers.<id>` 带 `type` / `name` / `base_url` / `api_key` / `models`，
//! 当前选中的大模型在 `models.large`（`{provider, model}`）。只合并 keyrelay
//! 自己的 provider 和 large pick，用户的其他 provider / 设置保持原样。

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Map, Value};

use super::json_text::{object_entry, parse_object, read_text_or_empty, JsonStyle};
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;
use crate::model_meta::ModelMeta;

pub struct CrushWriter {
    path: PathBuf,
    base_url: String,
    model: Option<String>,
    meta: Option<ModelMeta>,
}

impl CrushWriter {
    pub const PROVIDER_KEY: &'static str = "keyrelay";
    pub const FIELD_API_KEY: &'static str = "api_key";
    pub const FIELD_BASE_URL: &'static str = "base_url";
    pub const FIELD_MODEL: &'static str = "model";
    pub const FIELD_PROVIDER: &'static str = "provider";

    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path(
            home.join(".config").join("crush").join("crush.json"),
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
            home.join(".config").join("crush").join("crush.json"),
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

impl DeliveryWriter for CrushWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::Crush
    }

    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }

    fn field_names(&self) -> Vec<String> {
        let mut names = vec![
            Self::FIELD_API_KEY.to_string(),
            Self::FIELD_BASE_URL.to_string(),
        ];
        if self.model.is_some() {
            names.push(Self::FIELD_MODEL.to_string());
            names.push(Self::FIELD_PROVIDER.to_string());
        }
        names
    }

    fn fields(&self, api_key: &str) -> Vec<DeliveryField> {
        let mut fields = vec![
            masked_field(Self::FIELD_API_KEY, api_key),
            literal_field(Self::FIELD_BASE_URL, &self.base_url),
        ];
        if let Some(model) = &self.model {
            fields.push(literal_field(Self::FIELD_MODEL, model));
            fields.push(literal_field(Self::FIELD_PROVIDER, Self::PROVIDER_KEY));
        }
        fields
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

/// 从现有 Crush 配置里取出 keyrelay large pick 的 model，供轮换复用。
pub fn model_from_text(text: &str) -> Option<String> {
    let parsed: Value = serde_json::from_str(text).ok()?;
    let large = parsed.get("models")?.get("large")?;
    (large.get("provider").and_then(Value::as_str) == Some(CrushWriter::PROVIDER_KEY))
        .then(|| {
            large
                .get("model")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .flatten()
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
            "Crush 通道需要模型名：models.large 的 pick 必须指明 model",
        ));
    };

    let style = JsonStyle::detect(before);
    let mut root = parse_object(before, path)?;
    {
        let providers = object_entry(&mut root, "providers", path)?;
        let provider = object_entry(providers, CrushWriter::PROVIDER_KEY, path)?;
        let mut updated = provider.clone();
        updated.insert("type".to_string(), Value::String("openai".to_string()));
        updated.insert(
            "name".to_string(),
            Value::String(CrushWriter::PROVIDER_KEY.to_string()),
        );
        updated.insert(
            CrushWriter::FIELD_BASE_URL.to_string(),
            Value::String(base_url.to_string()),
        );
        updated.insert(
            CrushWriter::FIELD_API_KEY.to_string(),
            Value::String(api_key.to_string()),
        );
        *provider = updated;
        let models = provider
            .entry("models".to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        let array = models
            .as_array_mut()
            .ok_or_else(|| Error::inject(path, "providers.keyrelay.models 不是数组，拒绝改写"))?;
        // 同一模型的条目可能带用户调过的窗口 / 输出上限 / 思考开关；
        // 只更新 keyrelay 拥有的字段，别把整条元数据替换成默认值。
        let existing = array
            .iter()
            .find(|entry| entry.get("id").and_then(Value::as_str) == Some(model))
            .and_then(Value::as_object)
            .cloned();
        array.retain(|entry| entry.get("id").and_then(Value::as_str) != Some(model));
        let mut item = existing.unwrap_or_default();
        item.insert("id".to_string(), Value::String(model.to_string()));
        item.entry("name".to_string())
            .or_insert_with(|| Value::String(model.to_string()));
        let context = meta.map(|m| m.context_window).unwrap_or(200_000);
        let output = meta.map(|m| m.max_output_tokens).unwrap_or(16_384);
        item.entry("context_window".to_string())
            .or_insert_with(|| Value::Number(serde_json::Number::from(context)));
        item.entry("default_max_tokens".to_string())
            .or_insert_with(|| Value::Number(serde_json::Number::from(output)));
        item.entry("can_reason".to_string())
            .or_insert(Value::Bool(false));
        array.push(Value::Object(item));
    }

    let models = object_entry(&mut root, "models", path)?;
    let large = object_entry(models, "large", path)?;
    large.insert(
        CrushWriter::FIELD_PROVIDER.to_string(),
        Value::String(CrushWriter::PROVIDER_KEY.to_string()),
    );
    large.insert(
        CrushWriter::FIELD_MODEL.to_string(),
        Value::String(model.to_string()),
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

    const SECRET: &str = "sk-crush-0123456789abcdef";
    const BASE: &str = "http://127.0.0.1:19387/v1";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    #[test]
    fn writes_provider_and_large_pick() {
        let dir = tmp();
        let writer = CrushWriter::with_path(
            dir.path().join("crush.json"),
            BASE,
            Some("glm-5"),
            crate::model_meta::lookup("glm-5"),
        );
        let patch = writer.plan(SECRET).unwrap();
        let parsed: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(parsed["providers"]["keyrelay"]["api_key"], SECRET);
        assert_eq!(parsed["providers"]["keyrelay"]["base_url"], BASE);
        assert_eq!(parsed["models"]["large"]["provider"], "keyrelay");
        assert_eq!(parsed["models"]["large"]["model"], "glm-5");
    }

    #[test]
    fn preserves_user_providers_and_small_pick() {
        let dir = tmp();
        let path = dir.path().join("crush.json");
        std::fs::write(
            &path,
            json!({"providers":{"mine":{"type":"openai"}},"models":{"small":{"provider":"mine","model":"x"}}}).to_string(),
        )
        .unwrap();
        let writer = CrushWriter::with_path(&path, BASE, Some("glm-5"), None);
        let after = writer.plan(SECRET).unwrap().after;
        let parsed: Value = serde_json::from_str(&after).unwrap();
        assert_eq!(parsed["providers"]["mine"]["type"], "openai");
        assert_eq!(parsed["models"]["small"]["provider"], "mine");
    }

    #[test]
    fn preserves_existing_model_metadata_on_reapply() {
        let dir = tmp();
        let path = dir.path().join("crush.json");
        std::fs::write(
            &path,
            json!({
                "providers": {
                    "keyrelay": {
                        "models": [{
                            "id": "glm-5",
                            "name": "My GLM",
                            "context_window": 999_000,
                            "can_reason": true,
                            "customFlag": "keep"
                        }]
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        let writer = CrushWriter::with_path(&path, BASE, Some("glm-5"), None);
        let after = writer.plan(SECRET).unwrap().after;
        let parsed: Value = serde_json::from_str(&after).unwrap();
        let entry = &parsed["providers"]["keyrelay"]["models"][0];
        assert_eq!(parsed["providers"]["keyrelay"]["api_key"], SECRET);
        assert_eq!(entry["name"], "My GLM");
        assert_eq!(entry["context_window"], 999_000);
        assert_eq!(entry["can_reason"], true);
        assert_eq!(entry["customFlag"], "keep");
        assert_eq!(parsed["models"]["large"]["model"], "glm-5");
    }

    #[test]
    fn plan_is_idempotent() {
        let dir = tmp();
        let writer = CrushWriter::with_path(
            dir.path().join("crush.json"),
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
        let writer = CrushWriter::with_path(dir.path().join("crush.json"), BASE, None, None);
        assert!(writer.plan(SECRET).is_err());
    }

    #[test]
    fn errors_never_echo_the_key() {
        let dir = tmp();
        let path = dir.path().join("crush.json");
        std::fs::write(&path, "{ CANARY-FILE").unwrap();
        let writer = CrushWriter::with_path(&path, BASE, Some("m"), None);
        let err = writer.plan("CANARY-KEY-4k2m").unwrap_err();
        assert!(!err.to_string().contains("CANARY-KEY-4k2m"));
        assert!(!err.to_string().contains("CANARY-FILE"));
    }
}
