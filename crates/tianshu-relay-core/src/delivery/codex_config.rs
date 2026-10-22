//! Codex CLI 配置投递：`~/.codex/config.toml`。
//!
//! 写两块字段：
//! ① 文件顶部全局键：`model_provider = "custom"`、`model = "<model>"`、`disable_response_storage = true`；
//! ② `[model_providers.custom]` 段：`name`、`base_url`、`wire_api = "responses"`。
//!
//! 与 [`super::codex_auth::CodexAuthWriter`] **配套**：codex 真调通上游必须同时写
//! `auth.json`（OPENAI_API_KEY）+ `config.toml`（model/base_url/wire_api）。前者由
//! `CodexAuthJson` 通道负责（已存在），本通道负责后者。
//!
//! ## 协议形状（参考 LoongPort `loongport-cli` 实测路径）
//!
//! ```toml
//! model_provider = "custom"
//! model = "deepseek-v4.1-flash"
//! disable_response_storage = true
//!
//! [model_providers.custom]
//! name = "custom"
//! base_url = "https://relay.example.com/v1"
//! wire_api = "responses"
//! ```
//!
//! `wire_api = "responses"` 是 codex 0.162.1 起唯一支持的协议（"chat" 被砍，
//! 实测报「no longer supported」）。LoongPort `loongport-cli` 也是这条路径
//! （注：LoongPort 桌面版另写 `experimental_bearer_token` 不动 auth.json，
//! 本通道与 keyrelay `CodexAuthJson` 配套走 auth.json OPENAI_API_KEY）。
//!
//! **前置依赖**：上游中转站必须支持 `/v1/responses` Responses API。
//! NewAPI（<relayed-upstream> 部署）实测不支持（curl `/v1/responses` 404）；
//! 跑 `codex exec` 真模型调用要换一个支持 Responses 的中转站。
//!
//! ## 红线
//!
//! - **密钥不进 `config.toml`**：本通道只写 base_url/model/几条固定字符串，
//!   sk 仍走 `auth.json`（M14 的红线「`Patch` 不带 endpoint 时也不会带回密钥」）。
//! - TOML 行级操作（不引入 toml 依赖），段外字节逐字不动。
//! - `disable_response_storage = true` 是 LoongPort 同形——上游不支持 storage 时必关。

use std::path::{Path, PathBuf};

use super::json_text::read_text_or_empty;
use super::{literal_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;

pub struct CodexConfigWriter {
    path: PathBuf,
    base_url: String,
    model: Option<String>,
}

impl CodexConfigWriter {
    pub const FIELD_MODEL_PROVIDER: &'static str = "model_provider";
    pub const FIELD_MODEL: &'static str = "model";
    pub const FIELD_DISABLE_RESPONSE_STORAGE: &'static str = "disable_response_storage";
    pub const FIELD_NAME: &'static str = "name";
    pub const FIELD_BASE_URL: &'static str = "base_url";
    pub const FIELD_WIRE_API: &'static str = "wire_api";
    pub const SECTION_PROVIDER: &'static str = "[model_providers.custom]";
    pub const PROVIDER_NAME: &'static str = "custom";
    pub const WIRE_API: &'static str = "responses";

    pub fn new(home: &Path, base_url: &str) -> Self {
        Self::with_path(home.join(".codex").join("config.toml"), base_url)
    }

    pub fn with_path(path: impl Into<PathBuf>, base_url: &str) -> Self {
        Self {
            path: path.into(),
            base_url: base_url.to_string(),
            model: None,
        }
    }

    pub fn with_model(home: &Path, base_url: &str, model: Option<&str>) -> Self {
        let mut w = Self::new(home, base_url);
        w.model = model
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .map(str::to_string);
        w
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl DeliveryWriter for CodexConfigWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::CodexConfig
    }

    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }

    fn field_names(&self) -> Vec<String> {
        let mut names = vec![
            Self::FIELD_MODEL_PROVIDER.to_string(),
            Self::FIELD_DISABLE_RESPONSE_STORAGE.to_string(),
        ];
        if self.model.is_some() {
            names.push(Self::FIELD_MODEL.to_string());
        }
        // 段内键：name / base_url / wire_api 在 fields() 写，这里也列。
        names.push(Self::FIELD_NAME.to_string());
        if !self.base_url.is_empty() {
            names.push(Self::FIELD_BASE_URL.to_string());
        }
        names.push(Self::FIELD_WIRE_API.to_string());
        names
    }

    fn fields(&self, _api_key: &str) -> Vec<DeliveryField> {
        // api_key 不进 config.toml —— 见 §红线。
        let mut fields = vec![
            literal_field(Self::FIELD_MODEL_PROVIDER, Self::PROVIDER_NAME),
            literal_field(Self::FIELD_DISABLE_RESPONSE_STORAGE, "true"),
        ];
        if let Some(m) = &self.model {
            fields.push(literal_field(Self::FIELD_MODEL, m));
        }
        fields.push(literal_field(Self::FIELD_NAME, Self::PROVIDER_NAME));
        if !self.base_url.is_empty() {
            fields.push(literal_field(Self::FIELD_BASE_URL, &self.base_url));
        }
        fields.push(literal_field(Self::FIELD_WIRE_API, Self::WIRE_API));
        fields
    }

    fn plan(&self, _api_key: &str) -> Result<Patch> {
        let before = read_text_or_empty(&self.path)?;
        let after = build_after(&before, &self.base_url, &self.model, &self.path)?;
        Ok(Patch::secret_bearing(self.path.clone(), before, after))
    }
}

/// 生成写入后的完整文本。本通道文件不含密钥；
/// 调用方仍不得打印——`Patch::secret_bearing` 形式与其它通道一致，
/// 与底层文件是否含密钥无关。
fn build_after(
    before: &str,
    base_url: &str,
    model: &Option<String>,
    path: &Path,
) -> Result<String> {
    if base_url.trim().is_empty() {
        return Err(Error::inject(path, "base_url 为空，拒绝写入 codex config"));
    }

    // M25-S1 复审 P1-1：顶部键（model_provider / model / disable_response_storage）
    // **必须写在文件最开头**——TOML 语义里它们属于「文档顶部键」，落在任何 [section]
    // 之后会被解析成段内键。原实现把它们追加在 stripped 内容之后 ⇒ 用户已有
    // `[model_providers.openai]` 段时，新顶部键落进那段 ⇒ codex 读不到顶层 ⇒ 通道不生效。
    //
    // 现在的顺序：① 新顶部键；② 空行；③ stripped 后的「段外其它内容」（含其它段，
    //   但**没有** `[model_providers.custom]` 段——它被 strip 了）；④ 新 `[model_providers.custom]` 段。
    let stripped = strip_top_keys_and_section(before);
    let stripped_clean = stripped.trim_matches('\n');

    let mut out = String::with_capacity(stripped.len() + 256);
    // ① 顶部键（先写，保证它们在所有 [section] 之前）
    out.push_str("model_provider = \"custom\"\n");
    if let Some(m) = model {
        out.push_str("model = \"");
        out.push_str(m);
        out.push_str("\"\n");
    }
    out.push_str("disable_response_storage = true\n");
    // ② 保留的段外内容（如果非空）
    if !stripped_clean.is_empty() {
        out.push('\n');
        out.push_str(stripped_clean);
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }
    // ③ 新段（追加在最后）
    out.push('\n');
    out.push_str("[model_providers.custom]\n");
    out.push_str("name = \"custom\"\n");
    out.push_str("base_url = \"");
    out.push_str(base_url);
    out.push_str("\"\n");
    out.push_str("wire_api = \"responses\"\n");
    Ok(out)
}

/// 把顶部 `model_provider=`/`model=`/`disable_response_storage=` 行从顶部删掉，
/// 并把 `[model_providers.custom]` 段整段删掉；返回剩下的内容。
///
/// M25-S1 复审 P1-1：原实现 `is_top_key` 不看「行在不在某个段里」⇒ 把段内
/// 的 `model = "..."` 行也当顶部键删掉（数据丢失）。现在加 `in_any_section` 跟踪：
/// 只有在**没有任何活动段**时，才认它是顶部键。
fn strip_top_keys_and_section(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut skip_section = false;
    let mut in_any_section = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        // 进入/退出任意段（不仅是我们的段）
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_any_section = true;
            // 进入目标段：删掉包括 header 行在内的整段
            skip_section = trimmed == CodexConfigWriter::SECTION_PROVIDER;
            if skip_section {
                continue;
            }
        }
        if skip_section {
            continue;
        }
        // 删**顶部**已有同名字段（只有在没有任何段内时才算顶部键；
        // 否则会把用户段内的 `model = ...` 行也删掉——P1-1 的根因）
        if !in_any_section
            && (is_top_key(trimmed, CodexConfigWriter::FIELD_MODEL_PROVIDER)
                || is_top_key(trimmed, CodexConfigWriter::FIELD_MODEL)
                || is_top_key(trimmed, CodexConfigWriter::FIELD_DISABLE_RESPONSE_STORAGE))
        {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// 判断某行是否是「顶部全局键 `KEY = ...`」。
/// 不靠 `config.toml` 解析器，靠前缀字面量匹配（与 grok-build 同源）。
fn is_top_key(line: &str, key: &str) -> bool {
    // 避开「键名以 model_provider 开头但其实是别的字段」：要求 key 后接空格 = 或直接 =。
    if !line.starts_with(key) {
        return false;
    }
    let rest = &line[key.len()..];
    rest.trim_start().starts_with('=')
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-codex-0123456789abcdef";
    const BASE: &str = "https://relay.example.com/v1";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    fn writer_in(dir: &Path, base_url: &str) -> CodexConfigWriter {
        CodexConfigWriter::with_path(dir.join("config.toml"), base_url)
    }

    fn writer_with_model(dir: &Path, base_url: &str, model: Option<&str>) -> CodexConfigWriter {
        // M25-S1 复审 P1-1：用 with_path 与 writer_in 同口径，避免 new() 走 .codex/config.toml
        // 子目录路径而 writer_in 走 dir/config.toml ⇒ 两者 path 不一致导致 read 拿不到 write。
        let mut w = writer_in(dir, base_url);
        w.model = model
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .map(str::to_string);
        w
    }

    #[test]
    fn creates_fresh_file_no_secret() {
        let dir = tmp();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        assert_eq!(patch.before, "");
        assert!(patch.after.contains("model_provider = \"custom\""));
        assert!(patch.after.contains("disable_response_storage = true"));
        assert!(patch.after.contains("[model_providers.custom]"));
        assert!(patch.after.contains("base_url = \""));
        assert!(patch.after.contains(BASE));
        assert!(patch.after.contains("wire_api = \"responses\""));
        // 红线：config.toml 不含密钥
        assert!(!patch.after.contains(SECRET), "config.toml 不应含 sk-");
        assert!(!patch.after.contains("api_key ="));
    }

    #[test]
    fn writes_model_when_provided() {
        let dir = tmp();
        let patch = writer_with_model(dir.path(), BASE, Some("deepseek-v4.1-flash"))
            .plan(SECRET)
            .unwrap();
        assert!(patch.after.contains("model = \"deepseek-v4.1-flash\""));
    }

    #[test]
    fn no_model_omits_model_line() {
        let dir = tmp();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        // 顶部不写 model=
        assert!(!patch.after.starts_with("model ="));
        assert!(!patch.after.contains("\nmodel ="));
    }

    #[test]
    fn replaces_existing_top_keys_and_section() {
        let dir = tmp();
        let before = r#"model_provider = "openai"
model = "old-model"
disable_response_storage = false
option_a = "x"

[model_providers.openai]
key = "v"

[model_providers.custom]
model = "still-old"
base_url = "https://old.example.com"
wire_api = "responses"
"#;
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        // 顶部键被替换
        assert!(patch.after.contains("model_provider = \"custom\""));
        assert!(patch.after.contains("disable_response_storage = true"));
        assert!(!patch.after.contains("old-model"));
        // 段被替换
        assert!(patch.after.contains(&format!("base_url = \"{BASE}\"")));
        assert!(patch.after.contains("wire_api = \"responses\""));
        // 老段内容被删
        assert!(!patch.after.contains("still-old"));
        assert!(!patch.after.contains("https://old.example.com"));
        // 段外其它内容保留
        assert!(patch.after.contains("option_a = \"x\""));
        assert!(patch.after.contains("[model_providers.openai]"));
    }

    #[test]
    fn is_idempotent() {
        let dir = tmp();
        let w = writer_with_model(dir.path(), BASE, Some("deepseek-v4.1-flash"));
        let first = w.plan(SECRET).unwrap();
        if let Some(parent) = w.path().parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(w.path(), &first.after).unwrap();
        let second = w.plan(SECRET).unwrap();
        assert_eq!(second.after, first.after);
    }

    #[test]
    fn empty_base_url_is_rejected() {
        let dir = tmp();
        let w = writer_in(dir.path(), "");
        let err = w.plan(SECRET).unwrap_err();
        assert!(err.to_string().contains("base_url 为空"));
    }

    #[test]
    fn plan_does_not_carry_secret_in_after() {
        let dir = tmp();
        let patch = writer_in(dir.path(), BASE).plan(SECRET).unwrap();
        // 双保险：sk- 不进 config.toml
        assert!(!patch.after.contains("sk-"));
    }

    #[test]
    fn fields_include_endpoint_shape_key() {
        // endpoint_in_channel_matches_what_the_writer_writes 会从 fields 反推
        // channel_carries_endpoint；它判 endpoint 形状靠 "base_url" 子串。
        // 这条断言钉住：codex-config 通道必须把 base_url 写进 fields。
        let dir = tmp();
        let writer = writer_in(dir.path(), BASE);
        let fields = writer.fields(SECRET);
        let keys: Vec<&str> = fields.iter().map(|f| f.key.as_str()).collect();
        assert!(
            keys.contains(&"base_url"),
            "fields 必须含 base_url: {keys:?}"
        );
        // 不含 api_key
        assert!(
            !keys.iter().any(|k| k.contains("api_key")),
            "fields 不应含 api_key: {keys:?}"
        );
    }

    /// M25-S1 复审 P1-1：升级场景——用户已有带 `[model_providers.openai]` 段的 config.toml。
    /// 旧实现的 `build_after` 把新顶部键追加在保留内容**之后** ⇒ 顶部键落进 openai 段
    /// （TOML 语义：[section] 之后的所有键都属于该段）⇒ codex 读不到顶层
    /// `model_provider` ⇒ 通道不生效。同时 `strip_top_keys_and_section` 不看「行在不在段里」
    /// ⇒ 用户段内的 `model = "gpt-4"` 行被当顶部键删掉（数据丢失）。
    ///
    /// 这条回归用复复审者给出的具夹具，把两件事钉死：
    /// ① 新顶部键在文件**最开头**（在所有 [section] 之前）；
    /// ② 用户段内的 `model = "gpt-4"` 不被删。
    #[test]
    fn upgrade_with_existing_provider_section_keeps_top_keys_at_top_and_preserves_user_model() {
        let dir = tmp();
        let before = r#"model_provider = "openai"
option_a = "x"

[model_providers.openai]
model = "gpt-4"
key = "v"
"#;
        std::fs::write(writer_in(dir.path(), BASE).path(), before).unwrap();
        let patch = writer_with_model(dir.path(), BASE, Some("deepseek-v4.1-flash"))
            .plan(SECRET)
            .unwrap();

        // ① 顶部 `model_provider = "custom"` 必须出现在文件**第一个 [section] 之前**。
        let first_section_idx = patch.after.find('[').unwrap_or(patch.after.len());
        let top_provider_idx = patch
            .after
            .find("model_provider = \"custom\"")
            .expect("顶部 model_provider 必须在");
        assert!(
            top_provider_idx < first_section_idx,
            "顶部 model_provider 必须在第一个 [section] 之前；实际位置 {} vs 段 {}",
            top_provider_idx,
            first_section_idx
        );

        // ② 用户段内的 `model = "gpt-4"` 必须保留（旧实现把它当顶部键删掉）
        assert!(
            patch.after.contains("\"gpt-4\""),
            "用户段内的 model = \"gpt-4\" 不该被删: {}",
            patch.after
        );

        // ③ 顶部 disable_response_storage 也必须在第一个 [section] 之前
        let disable_idx = patch
            .after
            .find("disable_response_storage = true")
            .expect("disable_response_storage 必须在");
        assert!(
            disable_idx < first_section_idx,
            "顶部 disable_response_storage 必须在第一个 [section] 之前；实际位置 {} vs 段 {}",
            disable_idx,
            first_section_idx
        );

        // ④ 段外其它内容（option_a）保留
        assert!(patch.after.contains("option_a = \"x\""));
        assert!(patch.after.contains("[model_providers.openai]"));
        // ⑤ 老段被替换：[model_providers.custom] 段在，base_url/wire_api 写正确
        assert!(patch.after.contains("[model_providers.custom]"));
        assert!(patch.after.contains(&format!("base_url = \"{BASE}\"")));
        assert!(patch.after.contains("wire_api = \"responses\""));
    }
}
