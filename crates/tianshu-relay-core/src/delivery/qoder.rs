//! Qoder / Qoder CN 通道：`~/.qoder/settings.json` / `~/.qoder-cn/settings.json`。
//!
//! Qoder 的 OpenAI-compatible 自定义 provider 形状（Magpie `qoder.go`）：
//! `providers.<id>` 带 `displayName` / `protocol` / `baseUrl` / `apiKey` /
//! `model` / `models`，顶层 `model.name` 是 `<provider>/<model>`。
//! 只合并本通道的键；用户的其他 provider、路由、超时和模型偏好保持原样。

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::json_text::{object_entry, parse_object, read_text_or_empty, JsonStyle};
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;
use crate::model_meta::ModelMeta;

pub struct QoderWriter {
    path: PathBuf,
    channel: DeliveryChannel,
    base_url: String,
    model: Option<String>,
    meta: Option<ModelMeta>,
}

impl QoderWriter {
    pub const PROVIDER_KEY: &'static str = "keyrelay";
    pub const FIELD_API_KEY: &'static str = "apiKey";
    pub const FIELD_BASE_URL: &'static str = "baseUrl";
    pub const FIELD_MODEL: &'static str = "model";
    pub const FIELD_MODEL_NAME: &'static str = "name";

    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path_and_channel(
            home.join(".qoder").join("settings.json"),
            DeliveryChannel::Qoder,
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
        Self::with_path_and_channel(
            home.join(".qoder").join("settings.json"),
            DeliveryChannel::Qoder,
            base_url,
            model,
            meta,
        )
    }

    pub fn new_cn(home: &Path, base_url: &str) -> Self {
        Self::with_path_and_channel(
            home.join(".qoder-cn").join("settings.json"),
            DeliveryChannel::QoderCn,
            base_url,
            None,
            None,
        )
    }

    pub fn with_model_cn(
        home: &Path,
        base_url: &str,
        model: Option<&str>,
        meta: Option<ModelMeta>,
    ) -> Self {
        Self::with_path_and_channel(
            home.join(".qoder-cn").join("settings.json"),
            DeliveryChannel::QoderCn,
            base_url,
            model,
            meta,
        )
    }

    pub fn with_path_and_channel(
        path: impl Into<PathBuf>,
        channel: DeliveryChannel,
        base_url: &str,
        model: Option<&str>,
        meta: Option<ModelMeta>,
    ) -> Self {
        debug_assert!(
            matches!(channel, DeliveryChannel::Qoder | DeliveryChannel::QoderCn),
            "QoderWriter 只服务 Qoder / QoderCn，收到 {channel:?}"
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

    pub fn provider_path(field: &str) -> String {
        format!("providers.{}.{}", Self::PROVIDER_KEY, field)
    }
}

impl DeliveryWriter for QoderWriter {
    fn channel(&self) -> DeliveryChannel {
        self.channel
    }

    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }

    fn field_names(&self) -> Vec<String> {
        let mut names = vec![
            Self::provider_path(Self::FIELD_API_KEY),
            Self::provider_path(Self::FIELD_BASE_URL),
        ];
        if self.model.is_some() {
            names.push(Self::provider_path(Self::FIELD_MODEL));
            names.push(format!("model.{}", Self::FIELD_MODEL_NAME));
        }
        names
    }

    fn fields(&self, api_key: &str) -> Vec<DeliveryField> {
        let mut fields = vec![
            masked_field(Self::provider_path(Self::FIELD_API_KEY), api_key),
            literal_field(Self::provider_path(Self::FIELD_BASE_URL), &self.base_url),
        ];
        if let Some(model) = &self.model {
            fields.push(literal_field(Self::provider_path(Self::FIELD_MODEL), model));
            fields.push(literal_field(
                format!("model.{}", Self::FIELD_MODEL_NAME),
                format!("{}/{}", Self::PROVIDER_KEY, model),
            ));
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

    let style = JsonStyle::detect(before);
    let mut root = parse_object(before, path)?;
    let providers = object_entry(&mut root, "providers", path)?;
    let provider = object_entry(providers, QoderWriter::PROVIDER_KEY, path)?;
    provider
        .entry("displayName".to_string())
        .or_insert_with(|| Value::String(QoderWriter::PROVIDER_KEY.to_string()));
    provider.insert("protocol".to_string(), Value::String("openai".to_string()));
    provider.insert(
        QoderWriter::FIELD_BASE_URL.to_string(),
        Value::String(base_url.to_string()),
    );
    provider.insert(
        QoderWriter::FIELD_API_KEY.to_string(),
        Value::String(api_key.to_string()),
    );

    if let Some(model) = model {
        provider.insert(
            QoderWriter::FIELD_MODEL.to_string(),
            Value::String(model.to_string()),
        );
        let mut model_entry = Map::new();
        model_entry.insert("model".to_string(), Value::String(model.to_string()));
        model_entry.insert("displayName".to_string(), Value::String(model.to_string()));
        let mut capabilities = Map::new();
        capabilities.insert("tools".to_string(), Value::Bool(true));
        capabilities.insert("vision".to_string(), Value::Bool(false));
        model_entry.insert("capabilities".to_string(), Value::Object(capabilities));
        if let Some(meta) = meta {
            model_entry.insert(
                "contextWindow".to_string(),
                Value::Number(serde_json::Number::from(meta.context_window)),
            );
            model_entry.insert(
                "maxOutputTokens".to_string(),
                Value::Number(serde_json::Number::from(meta.max_output_tokens)),
            );
        }
        let models = provider
            .entry("models".to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        let array = models
            .as_array_mut()
            .ok_or_else(|| Error::inject(path, "providers.keyrelay.models 不是数组，拒绝改写"))?;
        array.retain(|entry| entry.get("model").and_then(Value::as_str) != Some(model));
        array.push(Value::Object(model_entry));

        let top_model = object_entry(&mut root, "model", path)?;
        top_model.insert(
            QoderWriter::FIELD_MODEL_NAME.to_string(),
            Value::String(format!("{}/{}", QoderWriter::PROVIDER_KEY, model)),
        );
    }

    style.serialize(&root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "sk-qoder-0123456789abcdef";
    const BASE: &str = "http://127.0.0.1:19387/v1";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    fn writer_in(dir: &Path, channel: DeliveryChannel, base_url: &str) -> QoderWriter {
        QoderWriter::with_path_and_channel(dir.join("settings.json"), channel, base_url, None, None)
    }

    #[test]
    fn creates_provider_and_top_level_model() {
        let dir = tmp();
        let writer = QoderWriter::with_path_and_channel(
            dir.path().join("settings.json"),
            DeliveryChannel::Qoder,
            BASE,
            Some("qwen3-coder-plus"),
            crate::model_meta::lookup("qwen3-coder-plus"),
        );
        let patch = writer.plan(SECRET).unwrap();
        let parsed: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(parsed["providers"]["keyrelay"]["apiKey"], SECRET);
        assert_eq!(parsed["providers"]["keyrelay"]["baseUrl"], BASE);
        assert_eq!(parsed["providers"]["keyrelay"]["protocol"], "openai");
        assert_eq!(parsed["providers"]["keyrelay"]["model"], "qwen3-coder-plus");
        assert_eq!(parsed["model"]["name"], "keyrelay/qwen3-coder-plus");
        assert_eq!(
            parsed["providers"]["keyrelay"]["models"][0]["model"],
            "qwen3-coder-plus"
        );
        assert_eq!(patch.new_file_mode, Some(0o600));
    }

    #[test]
    fn preserves_other_providers_and_top_level_fields() {
        let dir = tmp();
        let before = json!({
            "providers": {"mine": {"apiKey": "keep", "baseUrl": "https://mine"}},
            "theme": "dark"
        })
        .to_string();
        std::fs::write(dir.path().join("settings.json"), &before).unwrap();
        let writer = writer_in(dir.path(), DeliveryChannel::Qoder, BASE);
        let after = writer.plan(SECRET).unwrap().after;
        let parsed: Value = serde_json::from_str(&after).unwrap();
        assert_eq!(parsed["providers"]["mine"]["apiKey"], "keep");
        assert_eq!(parsed["theme"], "dark");
        assert_eq!(parsed["providers"]["keyrelay"]["apiKey"], SECRET);
    }

    #[test]
    fn qoder_cn_uses_its_own_channel_and_path() {
        let dir = tmp();
        let writer = QoderWriter::with_model_cn(dir.path(), BASE, Some("kimi-k3"), None);
        assert_eq!(writer.channel(), DeliveryChannel::QoderCn);
        assert_eq!(
            writer.target_path(),
            dir.path().join(".qoder-cn").join("settings.json")
        );
        let after = writer.plan(SECRET).unwrap().after;
        assert!(after.contains("keyrelay/kimi-k3"));
    }

    #[test]
    fn errors_never_echo_the_key() {
        let dir = tmp();
        std::fs::write(
            dir.path().join("settings.json"),
            "{\"providers\": [CANARY-FILE",
        )
        .unwrap();
        let err = writer_in(dir.path(), DeliveryChannel::Qoder, BASE)
            .plan("CANARY-KEY-4k2m")
            .unwrap_err();
        assert!(!err.to_string().contains("CANARY-KEY-4k2m"));
        assert!(!err.to_string().contains("CANARY-FILE"));
    }

    #[test]
    fn plan_is_idempotent() {
        let dir = tmp();
        let writer = QoderWriter::with_path_and_channel(
            dir.path().join("settings.json"),
            DeliveryChannel::Qoder,
            BASE,
            Some("kimi-k3"),
            None,
        );
        let first = writer.plan(SECRET).unwrap();
        std::fs::write(writer.path(), &first.after).unwrap();
        let second = writer.plan(SECRET).unwrap();
        assert_eq!(second.after, first.after);
    }
}
