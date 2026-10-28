//! Kimi Code 通道：`~/.kimi-code/config.toml`。
//!
//! Kimi Code 的 provider 表（Magpie `kimi.go`）：
//! `[providers.<id>]` 带 `type` / `base_url` / `api_key`，模型表
//! `[models."<id>/<model>"]` 指向该 provider；顶层 `default_model` 选默认模型。
//! 这里只改 keyrelay 自己的表，用户已有 provider / model / 其他顶层键原样保留。

use std::path::{Path, PathBuf};

use toml_edit::{value, DocumentMut, Item, Table};

use super::json_text::read_text_or_empty;
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;
use crate::model_meta::ModelMeta;

pub struct KimiCodeWriter {
    path: PathBuf,
    base_url: String,
    model: Option<String>,
    meta: Option<ModelMeta>,
}

impl KimiCodeWriter {
    pub const PROVIDER_KEY: &'static str = "keyrelay";
    pub const FIELD_API_KEY: &'static str = "api_key";
    pub const FIELD_BASE_URL: &'static str = "base_url";
    pub const FIELD_DEFAULT_MODEL: &'static str = "default_model";
    const DEFAULT_CONTEXT: u32 = 128_000;

    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path(
            home.join(".kimi-code").join("config.toml"),
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
            home.join(".kimi-code").join("config.toml"),
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

    fn model_key(model: &str) -> String {
        format!("{}/{}", Self::PROVIDER_KEY, model)
    }
}

impl DeliveryWriter for KimiCodeWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::KimiCode
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
            names.push(Self::FIELD_DEFAULT_MODEL.to_string());
        }
        names
    }

    fn fields(&self, api_key: &str) -> Vec<DeliveryField> {
        let mut fields = vec![
            masked_field(Self::FIELD_API_KEY, api_key),
            literal_field(Self::FIELD_BASE_URL, &self.base_url),
        ];
        if let Some(model) = &self.model {
            fields.push(literal_field(
                Self::FIELD_DEFAULT_MODEL,
                Self::model_key(model),
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

    let mut doc: DocumentMut = if before.trim().is_empty() {
        DocumentMut::new()
    } else {
        before
            .parse()
            .map_err(|_| Error::inject(path, "TOML 解析失败，拒绝改写"))?
    };

    if !doc.contains_key("providers") {
        doc.insert("providers", Item::Table(Table::new()));
    }
    let providers = doc["providers"]
        .as_table_mut()
        .ok_or_else(|| Error::inject(path, "providers 不是表，拒绝改写"))?;
    if !providers.contains_key(KimiCodeWriter::PROVIDER_KEY) {
        providers.insert(KimiCodeWriter::PROVIDER_KEY, Item::Table(Table::new()));
    }
    let provider = providers[KimiCodeWriter::PROVIDER_KEY]
        .as_table_mut()
        .ok_or_else(|| Error::inject(path, "providers.keyrelay 不是表，拒绝改写"))?;
    provider.insert("type", value("kimi"));
    provider.insert(KimiCodeWriter::FIELD_BASE_URL, value(base_url));
    provider.insert(KimiCodeWriter::FIELD_API_KEY, value(api_key));

    if let Some(model) = model {
        let key = KimiCodeWriter::model_key(model);
        if !doc.contains_key("models") {
            doc.insert("models", Item::Table(Table::new()));
        }
        let models = doc["models"]
            .as_table_mut()
            .ok_or_else(|| Error::inject(path, "models 不是表，拒绝改写"))?;
        let item = models
            .entry(&key)
            .or_insert_with(|| Item::Table(Table::new()));
        let model_table = item
            .as_table_mut()
            .ok_or_else(|| Error::inject(path, "models 的 keyrelay 条目不是表，拒绝改写"))?;
        model_table.insert("provider", value(KimiCodeWriter::PROVIDER_KEY));
        model_table.insert("model", value(model));
        let context = meta
            .map(|m| m.context_window)
            .unwrap_or(KimiCodeWriter::DEFAULT_CONTEXT);
        model_table.insert("max_context_size", value(context as i64));
        model_table.insert("display_name", value(model));
        doc[KimiCodeWriter::FIELD_DEFAULT_MODEL] = value(key);
    }

    Ok(doc.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-kimi-0123456789abcdef";
    const BASE: &str = "http://127.0.0.1:19387/v1";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    #[test]
    fn writes_provider_and_model_table() {
        let dir = tmp();
        let writer = KimiCodeWriter::with_path(
            dir.path().join("config.toml"),
            BASE,
            Some("kimi-k3"),
            crate::model_meta::lookup("kimi-k3"),
        );
        let patch = writer.plan(SECRET).unwrap();
        assert!(patch.after.contains("[providers.keyrelay]"));
        assert!(patch.after.contains("type = \"kimi\""));
        assert!(patch
            .after
            .contains("base_url = \"http://127.0.0.1:19387/v1\""));
        assert!(patch
            .after
            .contains("api_key = \"sk-kimi-0123456789abcdef\""));
        assert!(patch.after.contains("[models.\"keyrelay/kimi-k3\"]"));
        assert!(patch.after.contains("default_model = \"keyrelay/kimi-k3\""));
        assert_eq!(patch.new_file_mode, Some(0o600));
    }

    #[test]
    fn preserves_other_tables_and_comments() {
        let dir = tmp();
        let before = "# my comment\n[providers.mine]\nbase_url = \"https://mine\"\n\n[models.\"mine/x\"]\nprovider = \"mine\"\nmodel = \"x\"\n";
        std::fs::write(dir.path().join("config.toml"), before).unwrap();
        let writer = KimiCodeWriter::with_path(dir.path().join("config.toml"), BASE, None, None);
        let after = writer.plan(SECRET).unwrap().after;
        assert!(after.contains("# my comment"));
        assert!(after.contains("[providers.mine]"));
        assert!(after.contains("[models.\"mine/x\"]"));
        assert!(after.contains("[providers.keyrelay]"));
    }

    #[test]
    fn preserves_unknown_keys_on_an_existing_model_table() {
        let dir = tmp();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[models.\"keyrelay/kimi-k3\"]\nprovider = \"old\"\ncustom_headers = { x = \"y\" }\n",
        )
        .unwrap();
        let writer = KimiCodeWriter::with_path(&path, BASE, Some("kimi-k3"), None);
        let after = writer.plan(SECRET).unwrap().after;
        assert!(after.contains("custom_headers"), "{after}");
        assert!(after.contains("provider = \"keyrelay\""), "{after}");
    }

    #[test]
    fn errors_never_echo_the_key() {
        let dir = tmp();
        std::fs::write(dir.path().join("config.toml"), "providers = [CANARY-FILE").unwrap();
        let err = KimiCodeWriter::with_path(dir.path().join("config.toml"), BASE, None, None)
            .plan("CANARY-KEY-4k2m")
            .unwrap_err();
        assert!(!err.to_string().contains("CANARY-KEY-4k2m"));
        assert!(!err.to_string().contains("CANARY-FILE"));
    }

    #[test]
    fn plan_is_idempotent() {
        let dir = tmp();
        let writer =
            KimiCodeWriter::with_path(dir.path().join("config.toml"), BASE, Some("kimi-k3"), None);
        let first = writer.plan(SECRET).unwrap();
        std::fs::write(writer.path(), &first.after).unwrap();
        let second = writer.plan(SECRET).unwrap();
        assert_eq!(second.after, first.after);
    }
}
