//! Codex CLI 注入器：只改写 `~/.codex/config.toml` 里的受管键。
//!
//! 受管键：
//! - 顶层 `model`、`model_provider`
//! - `[model_providers.<provider_id>]` 下的 `name` / `base_url` / `wire_api` / `env_key`
//!
//! 密钥不写入本文件：Codex 通过 `env_key` 指定的环境变量取密钥，
//! 该环境变量由「密钥投递」环节（M1-S2，需用户显式授权）或本地网关模式提供。

use std::path::PathBuf;

use toml_edit::{value, DocumentMut, Item, Table};

use super::{read_or_empty, Binding, Injector, Patch};
use crate::error::{Error, Result};

pub struct CodexInjector {
    pub config_path: PathBuf,
}

impl CodexInjector {
    pub fn new(config_path: impl Into<PathBuf>) -> Self {
        Self {
            config_path: config_path.into(),
        }
    }

    /// `<主目录>/.codex/config.toml`
    ///
    /// 走 [`crate::platform::home_dir`]：解析不出来就**报错**，
    /// 而不是像早先那样 `unwrap_or(".")` 把配置写到当前工作目录（BACKLOG B-14）。
    pub fn default_path() -> Result<PathBuf> {
        Ok(crate::platform::home_dir()?
            .join(".codex")
            .join("config.toml"))
    }

    /// 环境变量名规则：`KEYRELAY_<PROVIDER_ID>_KEY`（大写、非字母数字转下划线）
    pub fn env_key_name(provider_id: &str) -> String {
        let normalized: String = provider_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect();
        format!("KEYRELAY_{normalized}_KEY")
    }
}

impl Injector for CodexInjector {
    fn id(&self) -> &'static str {
        "codex"
    }

    fn plan(&self, binding: &Binding) -> Result<Vec<Patch>> {
        let before = read_or_empty(&self.config_path)?;
        let mut doc: DocumentMut = if before.trim().is_empty() {
            DocumentMut::new()
        } else {
            before.parse().map_err(|e| {
                Error::inject(&self.config_path, format!("TOML 解析失败，拒绝改写: {e}"))
            })?
        };

        doc["model"] = value(
            binding
                .model
                .clone()
                .unwrap_or_else(|| "gpt-5.6".to_string()),
        );
        doc["model_provider"] = value(binding.provider_id.clone());

        if !doc.contains_key("model_providers") {
            doc.insert("model_providers", Item::Table(Table::new()));
        }
        let providers = doc["model_providers"]
            .as_table_mut()
            .ok_or_else(|| Error::inject(&self.config_path, "model_providers 不是表，拒绝改写"))?;

        let mut provider = Table::new();
        provider.insert("name", value(binding.provider_id.clone()));
        provider.insert(
            "base_url",
            value(format!(
                "{}/v1",
                binding.base_url.trim().trim_end_matches('/')
            )),
        );
        provider.insert("wire_api", value("responses"));
        provider.insert("env_key", value(Self::env_key_name(&binding.provider_id)));
        providers.insert(&binding.provider_id, Item::Table(provider));

        Ok(vec![Patch::new(
            self.config_path.clone(),
            before,
            doc.to_string(),
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn binding() -> Binding {
        Binding {
            base_url: "https://newapi.example.com/".into(),
            api_key: "sk-should-never-be-written".into(),
            model: Some("gpt-5.6".into()),
            provider_id: "keyrelay".into(),
        }
    }

    const FIXTURE: &str = r#"# 我自己的注释，必须保留
model = "gpt-6-astra"
model_reasoning_effort = "xhigh"

notify = [
    "/Users/me/notify",
    "turn-ended",
]

[marketplaces.karpathy-skills]
source_type = "git"
source = "https://github.com/forrestchang/andrej-karpathy-skills.git"

[model_providers.my-own]
name = "my-own"
base_url = "https://my.example.com/v1"
wire_api = "chat"
"#;

    #[test]
    fn plan_preserves_comments_and_user_providers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, FIXTURE).unwrap();

        let injector = CodexInjector::new(&path);
        let patches = injector.plan(&binding()).unwrap();
        let after = &patches[0].after;

        assert!(after.contains("# 我自己的注释，必须保留"));
        assert!(after.contains("gpt-6-astra") || after.contains("model = \"gpt-5.6\""));
        assert!(after.contains("[model_providers.my-own]"));
        assert!(after.contains("https://my.example.com/v1"));
        assert!(after.contains("[model_providers.keyrelay]"));
        assert!(after.contains("base_url = \"https://newapi.example.com/v1\""));
        assert!(after.contains("env_key = \"KEYRELAY_KEYRELAY_KEY\""));
        // 密钥绝不进入受管文件
        assert!(!after.contains("sk-should-never-be-written"));
    }

    #[test]
    fn plan_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, FIXTURE).unwrap();
        let injector = CodexInjector::new(&path);
        let a = injector.plan(&binding()).unwrap();
        let b = injector.plan(&binding()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn plan_on_missing_file_creates_new_document() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("config.toml");
        let injector = CodexInjector::new(&path);
        let patches = injector.plan(&binding()).unwrap();
        assert!(patches[0].before.is_empty());
        assert!(patches[0].after.contains("model_provider = \"keyrelay\""));
    }

    #[test]
    fn plan_rejects_invalid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "model = [unclosed").unwrap();
        let injector = CodexInjector::new(&path);
        let err = injector.plan(&binding()).unwrap_err();
        assert!(matches!(err, Error::Inject { .. }));
    }

    #[test]
    fn env_key_name_normalizes() {
        assert_eq!(
            CodexInjector::env_key_name("keyrelay"),
            "KEYRELAY_KEYRELAY_KEY"
        );
        assert_eq!(
            CodexInjector::env_key_name("my-relay"),
            "KEYRELAY_MY_RELAY_KEY"
        );
    }
}
