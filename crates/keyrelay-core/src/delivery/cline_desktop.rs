//! Cline 桌面端通道：`~/.cline/data/settings/providers.json`。
//!
//! Cline 桌面端（Cline.app）和 Cline CLI 共用 `~/.cline/` 目录。Provider 凭据
//! 存储在 `providers` 对象中。KeyRelay 在其中创建或更新 `keyrelay` 条目。
//!
//! 与 VS Code 扩展的 `cline` 通道是**不同产品**：VS Code 扩展写入 globalStorage 下的
//! `settings.json`（数组结构），桌面端写入 `.cline/data/settings/providers.json`
//!（对象结构）。

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::json_text::{parse_object, read_text_or_empty, JsonStyle};
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;
use crate::model_meta::ModelMeta;

pub struct ClineDesktopWriter {
    path: PathBuf,
    base_url: String,
    model: Option<String>,
    meta: Option<ModelMeta>,
}

impl ClineDesktopWriter {
    pub const FIELD_API_KEY: &'static str = "apiKey";
    pub const FIELD_BASE_URL: &'static str = "baseUrl";
    pub const FIELD_PROVIDER: &'static str = "provider";
    pub const FIELD_UPDATED_AT: &'static str = "updatedAt";
    pub const FIELD_TOKEN_SOURCE: &'static str = "tokenSource";
    pub const FIELD_MODEL_ID: &'static str = "modelId";
    pub const FIELD_CONTEXT_WINDOW: &'static str = "contextWindow";
    pub const FIELD_MAX_TOKENS: &'static str = "maxTokens";
    const PROVIDER_ID: &'static str = "keyrelay";
    const PROVIDERS_KEY: &'static str = "providers";
    const SETTINGS_KEY: &'static str = "settings";

    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path(
            home.join(".cline")
                .join("data")
                .join("settings")
                .join("providers.json"),
            base_url,
        )
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

impl DeliveryWriter for ClineDesktopWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::ClineDesktop
    }

    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }

    fn field_names(&self) -> Vec<String> {
        let mut names = vec![format!(
            "{}.{}.{}",
            Self::PROVIDERS_KEY,
            Self::PROVIDER_ID,
            Self::FIELD_API_KEY
        )];
        if !self.base_url.is_empty() {
            names.push(format!(
                "{}.{}.{}",
                Self::PROVIDERS_KEY,
                Self::PROVIDER_ID,
                Self::FIELD_BASE_URL
            ));
        }
        if self.model.is_some() {
            names.push(format!(
                "{}.{}.{}",
                Self::PROVIDERS_KEY,
                Self::PROVIDER_ID,
                Self::FIELD_MODEL_ID
            ));
            if self.meta.is_some() {
                names.push(format!(
                    "{}.{}.{}",
                    Self::PROVIDERS_KEY,
                    Self::PROVIDER_ID,
                    Self::FIELD_CONTEXT_WINDOW
                ));
                names.push(format!(
                    "{}.{}.{}",
                    Self::PROVIDERS_KEY,
                    Self::PROVIDER_ID,
                    Self::FIELD_MAX_TOKENS
                ));
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
            fields.push(literal_field(Self::FIELD_MODEL_ID, m));
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
    let style = JsonStyle::detect(before);
    let mut root = parse_object(before, path)?;

    let providers = root
        .entry(ClineDesktopWriter::PROVIDERS_KEY.to_string())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let providers_obj = providers
        .as_object_mut()
        .ok_or_else(|| Error::inject(path, "providers 不是对象，拒绝改写"))?;

    // 构建期望的 settings 对象
    let mut settings = serde_json::Map::new();
    settings.insert(
        ClineDesktopWriter::FIELD_PROVIDER.to_string(),
        Value::String("openai".to_string()),
    );
    settings.insert(
        ClineDesktopWriter::FIELD_API_KEY.to_string(),
        Value::String(api_key.to_string()),
    );
    if !base_url.is_empty() {
        settings.insert(
            ClineDesktopWriter::FIELD_BASE_URL.to_string(),
            Value::String(base_url.to_string()),
        );
    }
    if let Some(m) = model {
        settings.insert(
            ClineDesktopWriter::FIELD_MODEL_ID.to_string(),
            Value::String(m.clone()),
        );
        if let Some(meta) = meta {
            settings.insert(
                ClineDesktopWriter::FIELD_CONTEXT_WINDOW.to_string(),
                Value::Number(serde_json::Number::from(meta.context_window)),
            );
            settings.insert(
                ClineDesktopWriter::FIELD_MAX_TOKENS.to_string(),
                Value::Number(serde_json::Number::from(meta.max_output_tokens)),
            );
        }
    }

    // 如果已有 keyrelay 条目且 settings 相同，不更新 updatedAt（幂等）
    let need_timestamp_update = match providers_obj.get(ClineDesktopWriter::PROVIDER_ID) {
        Some(existing) => existing
            .get(ClineDesktopWriter::SETTINGS_KEY)
            .and_then(|s| s.as_object())
            .map(|s| *s != settings)
            .unwrap_or(true),
        None => true,
    };

    let mut entry = serde_json::Map::new();
    entry.insert(
        ClineDesktopWriter::SETTINGS_KEY.to_string(),
        Value::Object(settings),
    );
    // 新建条目或 settings 变化时更新时间戳；幂等写入保持已有时间戳
    if need_timestamp_update {
        entry.insert(
            ClineDesktopWriter::FIELD_UPDATED_AT.to_string(),
            Value::String(iso8601_now()),
        );
    } else if let Some(existing) = providers_obj.get(ClineDesktopWriter::PROVIDER_ID) {
        if let Some(ts) = existing.get(ClineDesktopWriter::FIELD_UPDATED_AT) {
            entry.insert(ClineDesktopWriter::FIELD_UPDATED_AT.to_string(), ts.clone());
        } else {
            entry.insert(
                ClineDesktopWriter::FIELD_UPDATED_AT.to_string(),
                Value::String(iso8601_now()),
            );
        }
    }
    entry.insert(
        ClineDesktopWriter::FIELD_TOKEN_SOURCE.to_string(),
        Value::String("api-key".to_string()),
    );

    providers_obj.insert(
        ClineDesktopWriter::PROVIDER_ID.to_string(),
        Value::Object(entry),
    );

    style.serialize(&root)
}

/// 生成 ISO 8601 时间戳（UTC），不引入 chrono 依赖。
fn iso8601_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hour = remaining / 3600;
    let minute = (remaining % 3600) / 60;
    let second = remaining % 60;
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// 把 epoch 起的天数转换为 (year, month, day)，算法取自 Howard Hinnant 的 date 算法。
fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = (y + if m <= 2 { 1 } else { 0 }) as u32;
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-clinedt-0123456789abcdef";
    const BASE: &str = "https://relay.example.com";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    fn writer_in(dir: &Path, base_url: &str) -> ClineDesktopWriter {
        ClineDesktopWriter::with_path(dir.join("providers.json"), base_url)
    }

    #[test]
    fn creates_fresh_file() {
        let dir = tmp();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert_eq!(patch.before, "");
        let parsed: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(
            parsed["providers"]["keyrelay"]["settings"]["provider"],
            "openai"
        );
        assert_eq!(
            parsed["providers"]["keyrelay"]["settings"]["apiKey"],
            SECRET
        );
        assert_eq!(parsed["providers"]["keyrelay"]["settings"]["baseUrl"], BASE);
        assert_eq!(parsed["providers"]["keyrelay"]["tokenSource"], "api-key");
        assert!(parsed["providers"]["keyrelay"]["updatedAt"].is_string());
        assert_eq!(patch.new_file_mode, Some(0o600));
    }

    #[test]
    fn preserves_other_providers() {
        let dir = tmp();
        let before = r#"{
  "version": 1,
  "lastUsedProvider": "cline",
  "providers": {
    "cline": {
      "settings": { "provider": "cline", "auth": {} },
      "updatedAt": "2026-10-13T00:27:09.062Z",
      "tokenSource": "oauth"
    }
  }
}"#;
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        let after: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(after["version"], 1);
        assert_eq!(after["lastUsedProvider"], "cline");
        assert_eq!(after["providers"]["cline"]["tokenSource"], "oauth");
        assert_eq!(after["providers"]["keyrelay"]["settings"]["apiKey"], SECRET);
        assert_eq!(
            after["providers"]["keyrelay"]["settings"]["provider"],
            "openai"
        );
    }

    #[test]
    fn replaces_existing_entry() {
        let dir = tmp();
        let before = r#"{"providers":{"keyrelay":{"settings":{"apiKey":"sk-old","baseUrl":"https://old.com","provider":"openai"},"updatedAt":"2026-01-01T00:00:00.000Z","tokenSource":"api-key"}}}"#;
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        let after: Value = serde_json::from_str(&patch.after).unwrap();
        assert_eq!(after["providers"]["keyrelay"]["settings"]["apiKey"], SECRET);
        assert_eq!(after["providers"]["keyrelay"]["settings"]["baseUrl"], BASE);
        assert_eq!(after["providers"].as_object().unwrap().len(), 1);
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
    fn plan_is_idempotent_ignoring_timestamp() {
        let dir = tmp();
        let first = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        std::fs::write(writer_in(dir.path(), BASE).path(), &first.after).unwrap();
        let second = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        let first_v: Value = serde_json::from_str(&first.after).unwrap();
        let second_v: Value = serde_json::from_str(&second.after).unwrap();
        let f = &first_v["providers"]["keyrelay"]["settings"];
        let s = &second_v["providers"]["keyrelay"]["settings"];
        assert_eq!(f, s, "settings 内容应一致（仅 updatedAt 不同）");
    }

    #[test]
    fn errors_never_echo_the_key() {
        let dir = tmp();
        let err = writer_in(dir.path(), BASE).plan("").unwrap_err();
        assert!(!err.to_string().contains("SECRET"), "{err}");
    }
}
