//! OpenCode 通道：`~/.config/opencode/opencode.json` 的 `provider.<id>.options`。
//!
//! 目标文件形态（PRD FR-4 注入矩阵第 4 行；本步按给定键名实现，**未**在本机复现 CLI 的读取行为）：
//! ```json
//! {
//!   "$schema": "https://opencode.ai/config.json",
//!   "provider": {
//!     "keyrelay": {
//!       "options": { "apiKey": "sk-…", "baseURL": "https://…" }
//!     }
//!   },
//!   "model": "keyrelay/gpt-4o"
//! }
//! ```
//! 受管字段只有三处：`provider.<id>.options.apiKey`、`provider.<id>.options.baseURL`、顶层 `model`。
//! 其余键（`$schema`、别的 provider、`instructions` 数组…）**原样保留**——把用户的 provider
//! 表洗掉会让 OpenCode 行为突变。
//!
//! 落点是**常量** `.json`（章程 §4.1 冻结）：`.jsonc` 存在而 `.json` 不存在时仍写 `.json`，
//! 理由与后果见 `docs/specs/M6-S1-通道扩展.md` §11 D-1。

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::json_text::{object_entry, parse_object, read_text_or_empty, JsonStyle};
use super::{literal_field, masked_field, DeliveryChannel, DeliveryField, DeliveryWriter};
use crate::error::{Error, Result};
use crate::inject::Patch;
use crate::model_meta::ModelMeta;

pub struct OpenCodeWriter {
    path: PathBuf,
    /// 本写入器服务的通道：`OpenCode`（`.json`）或 `OpenCodeJsonc`（`.jsonc`）。
    ///
    /// 内容逻辑两者**完全相同**，只有落点与 `channel()` 的回报不同——
    /// 回报错了会让漂移报告与同意记录把两条通道混成一条（它们的 `agent_id` 都是 `"opencode"`）。
    channel: DeliveryChannel,
    provider_id: String,
    base_url: String,
    /// `None` = 不写、也不动已有的 `model` 键。
    model: Option<String>,
    /// 模型参数（context_window / max_output）。`None` = 不写参数行。
    meta: Option<ModelMeta>,
}

impl OpenCodeWriter {
    pub const FIELD_API_KEY: &'static str = "apiKey";
    pub const FIELD_BASE_URL: &'static str = "baseURL";
    pub const FIELD_MODEL: &'static str = "model";
    pub const PROVIDER_KEY: &'static str = "provider";
    pub const OPTIONS_KEY: &'static str = "options";

    /// `resolve_for` 使用的默认 provider 名，与 `inject::codex` 的 `[model_providers.keyrelay]`
    /// 取同一个名字，避免同一个产品在两条通道上用两套命名。
    pub const DEFAULT_PROVIDER_ID: &'static str = "keyrelay";

    /// `home` 显式传入（不读 `HOME`），便于测试重定向到临时目录。
    ///
    /// `provider_id` 为空只在 `plan()` 时报错，构造期不 panic：写入器是纯数据，
    /// 让错误发生在「有 `Result` 可传」的地方。
    pub fn new(home: &Path, provider_id: &str, base_url: &str, model: Option<&str>) -> Self {
        Self::with_path(
            home.join(".config").join("opencode").join("opencode.json"),
            provider_id,
            base_url,
            model,
        )
    }

    /// M14-S7：带模型元数据的构造。
    pub fn with_meta(
        home: &Path,
        provider_id: &str,
        base_url: &str,
        model: Option<&str>,
        meta: Option<ModelMeta>,
    ) -> Self {
        Self::with_path_and_meta(
            home.join(".config").join("opencode").join("opencode.json"),
            DeliveryChannel::OpenCode,
            provider_id,
            base_url,
            model,
            meta,
        )
    }

    pub fn with_path(
        path: impl Into<PathBuf>,
        provider_id: &str,
        base_url: &str,
        model: Option<&str>,
    ) -> Self {
        Self::with_path_and_channel(
            path,
            DeliveryChannel::OpenCode,
            provider_id,
            base_url,
            model,
            None,
        )
    }

    /// M14-S7：带 meta 的 `with_path`。
    pub fn with_path_and_meta(
        path: impl Into<PathBuf>,
        channel: DeliveryChannel,
        provider_id: &str,
        base_url: &str,
        model: Option<&str>,
        meta: Option<ModelMeta>,
    ) -> Self {
        let mut w = Self::with_path_and_channel(path, channel, provider_id, base_url, model, None);
        w.meta = meta;
        w
    }

    /// M7-S3：**内容与 `OpenCode` 完全相同**，只是落点与通道标识不同（`.jsonc`）。
    ///
    /// `channel` 只允许是 `OpenCode` 或 `OpenCodeJsonc`（其余通道由别的写入器负责）——
    /// 传错会让 [`DeliveryWriter::channel`] 说谎，因此用 `debug_assert!` 在测试里立刻暴露。
    pub fn with_path_and_channel(
        path: impl Into<PathBuf>,
        channel: DeliveryChannel,
        provider_id: &str,
        base_url: &str,
        model: Option<&str>,
        meta: Option<ModelMeta>,
    ) -> Self {
        debug_assert!(
            matches!(
                channel,
                DeliveryChannel::OpenCode | DeliveryChannel::OpenCodeJsonc
            ),
            "OpenCodeWriter 只服务 OpenCode / OpenCodeJsonc，收到 {channel:?}"
        );
        Self {
            path: path.into(),
            channel,
            provider_id: provider_id.to_string(),
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

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    /// 预览与同意记录用的**限定**键名：`provider.<id>.options.<field>`。
    ///
    /// 用限定名而不是裸 `apiKey`：同一个文件里可能有十几个 provider 各自的 `apiKey`，
    /// 只显示裸键名会让用户无法判断我们到底要改哪一个。
    ///
    /// `provider_id` 不是简单标识符时改用 **JSONPath 方括号形态**
    /// （`provider["a.b"].options.apiKey`）：点号分段的写法下，
    /// `provider.a.b.options.apiKey` 与「provider `a` 下的 provider `b`」同形，
    /// 会让用户与后续解析者读错归属（M6-S1 复审 P2-3）。
    /// 落盘内容与此无关——JSON 键始终是字面量 `"a.b"`，这里只是**可读性**问题。
    pub fn qualified_field(&self, field: &str) -> String {
        if is_simple_identifier(&self.provider_id) {
            format!(
                "{}.{}.{}.{}",
                Self::PROVIDER_KEY,
                self.provider_id,
                Self::OPTIONS_KEY,
                field
            )
        } else {
            format!(
                "{}[{}].{}.{}",
                Self::PROVIDER_KEY,
                json_quoted(&self.provider_id),
                Self::OPTIONS_KEY,
                field
            )
        }
    }

    /// 生成写入后的完整文本。`api_key` 会出现在返回值里——调用方不得打印。
    fn build_after(&self, before: &str, api_key: &str) -> Result<String> {
        if api_key.trim().is_empty() {
            return Err(Error::inject(&self.path, "密钥为空，拒绝写入"));
        }
        if self.provider_id.trim().is_empty() {
            return Err(Error::inject(&self.path, "provider id 为空，拒绝写入"));
        }

        let style = JsonStyle::detect(before);
        let mut root: Map<String, Value> = parse_object(before, &self.path)?;

        {
            let providers = object_entry(&mut root, Self::PROVIDER_KEY, &self.path)?;
            let provider = object_entry(providers, &self.provider_id, &self.path)?;
            let options = object_entry(provider, Self::OPTIONS_KEY, &self.path)?;

            options.insert(
                Self::FIELD_API_KEY.to_string(),
                Value::String(api_key.to_string()),
            );
            if self.base_url.trim().is_empty() {
                // base_url 为空表示「只投递密钥」：不动用户已有的 baseURL。
            } else {
                options.insert(
                    Self::FIELD_BASE_URL.to_string(),
                    Value::String(self.base_url.clone()),
                );
            }
        }

        if let Some(model) = &self.model {
            root.insert(Self::FIELD_MODEL.to_string(), Value::String(model.clone()));
        }

        // M14-S7：写入模型参数到 provider.<id>.models.<id>.limit.{context,output}
        //
        // DEBUG-G7 P2-D3（B-273，显性标注、不改键）：第二 `<id>` 用的是
        // `provider_id` 而非模型名，且该键不在 `fields()`、也不在必填表里——
        // writer 回归删掉它时整单校验仍放行（见 `delivery/mod.rs` 的表注释）。
        // opencode 官方 schema 未在本机核实：schema 要求模型 id 还是 provider 名、
        // `limit.*` 是不是合法键，均未定论；**在核实前不得凭猜测改键**（改错键
        // 等于把参数写到一个 OpenCode 不读的位置，比脱钩更糟）。本注释 + 下面的
        // `limit_keys_are_written_but_outside_field_table` 用例共同钉住当前行为：
        // 键照写、表照旧不含它；schema 核实后另立项决定归属。
        if let Some(meta) = self.meta {
            let providers = object_entry(&mut root, Self::PROVIDER_KEY, &self.path)?;
            let provider = object_entry(providers, &self.provider_id, &self.path)?;
            let models = object_entry(provider, "models", &self.path)?;
            let model_entry = object_entry(models, &self.provider_id, &self.path)?;
            let limit = object_entry(model_entry, "limit", &self.path)?;
            limit.insert(
                "context".to_string(),
                Value::Number(serde_json::Number::from(meta.context_window)),
            );
            limit.insert(
                "output".to_string(),
                Value::Number(serde_json::Number::from(meta.max_output_tokens)),
            );
        }

        style.serialize(&root)
    }
}

impl DeliveryWriter for OpenCodeWriter {
    fn channel(&self) -> DeliveryChannel {
        self.channel
    }

    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }

    fn field_names(&self) -> Vec<String> {
        let mut names = vec![self.qualified_field(Self::FIELD_API_KEY)];
        if !self.base_url.trim().is_empty() {
            names.push(self.qualified_field(Self::FIELD_BASE_URL));
        }
        if self.model.is_some() {
            names.push(Self::FIELD_MODEL.to_string());
        }
        names
    }

    fn fields(&self, api_key: &str) -> Vec<DeliveryField> {
        let mut fields = vec![masked_field(
            self.qualified_field(Self::FIELD_API_KEY),
            api_key,
        )];
        if !self.base_url.trim().is_empty() {
            fields.push(literal_field(
                self.qualified_field(Self::FIELD_BASE_URL),
                &self.base_url,
            ));
        }
        if let Some(model) = &self.model {
            fields.push(literal_field(Self::FIELD_MODEL, model));
        }
        fields
    }

    fn plan(&self, api_key: &str) -> Result<Patch> {
        let before = read_text_or_empty(&self.path)?;
        // M7-S3 / D-1：`.jsonc` 通道**只接受严格 JSON**。
        // 带 JSONC 专有语法时明确拒绝——静默丢注释是数据损坏，拒绝不是（spec §6.2 / §13.1 O-1）。
        if self.channel == DeliveryChannel::OpenCodeJsonc {
            if let Some(hazard) = super::jsonc_hazard(&before) {
                return Err(Error::inject(&self.path, jsonc_refusal(hazard)));
            }
        }
        let after = self.build_after(&before, api_key)?;
        Ok(Patch::secret_bearing(self.path.clone(), before, after))
    }
}

/// `.jsonc` 专有语法的拒绝文案：说清**是什么**、**为什么不改写**、**两条出路**。
fn jsonc_refusal(hazard: super::JsoncHazard) -> String {
    let what = match hazard {
        super::JsoncHazard::LineComment => "行注释（// …）",
        super::JsoncHazard::BlockComment => "块注释（/* … */）",
        super::JsoncHazard::TrailingComma => "尾随逗号",
    };
    format!(
        "opencode.jsonc 里有 JSONC 专有语法（{what}），而天枢 Relay 不做「保注释改写」：\
         改写会把你的注释静默丢掉。两条出路：① 手工把注释与尾随逗号删掉后重投；\
         ② 改用 opencode 通道写 .json（如果你确认 opencode 读的是 .json）。"
    )
}

/// 能否安全地嵌进点号分段路径（不需要方括号引号）。
fn is_simple_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// 把一段文本渲染成 JSON 字符串字面量（含首尾引号与转义）。
///
/// 复用 `serde_json` 而不是自己拼引号：`provider_id` 里可能有 `"` 或 `\`，
/// 手工拼接会产出读起来像「路径断了」的字符串。
fn json_quoted(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| format!("\"{value}\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "sk-opencode-0123456789abcdef";
    const BASE: &str = "https://relay.example.com";
    const MODEL: &str = "keyrelay/gpt-4o";
    const PROVIDER: &str = "keyrelay";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    fn writer_in(dir: &Path, base_url: &str, model: Option<&str>) -> OpenCodeWriter {
        OpenCodeWriter::with_path(dir.join("opencode.json"), PROVIDER, base_url, model)
    }

    fn parsed(text: &str) -> Value {
        serde_json::from_str(text).expect("应是合法 JSON")
    }

    #[test]
    fn limit_keys_are_written_but_outside_field_table() {
        // DEBUG-G7 P2-D3：钉住当前行为——limit.* 照写（第二 <id> 为 provider_id），
        // 但 fields() 与整单校验的必填表仍不含 limit 键；schema 核实前不改键。
        let dir = tmp();
        let meta = crate::model_meta::ModelMeta {
            context_window: 200_000,
            max_output_tokens: 32_000,
        };
        let writer = OpenCodeWriter::with_path_and_meta(
            dir.path().join("opencode.json"),
            DeliveryChannel::OpenCode,
            PROVIDER,
            BASE,
            Some(MODEL),
            Some(meta),
        );
        let patch = writer.plan(SECRET).unwrap();
        let after = parsed(&patch.after);
        assert_eq!(after["provider"][PROVIDER]["models"][PROVIDER]["limit"]["context"], 200_000);
        assert_eq!(after["provider"][PROVIDER]["models"][PROVIDER]["limit"]["output"], 32_000);
        let names = writer_in(dir.path(), BASE, Some(MODEL)).field_names();
        assert!(!names.iter().any(|n| n.contains("limit")), "{names:?}");
        // 整单校验仍放行（limit 键既不在必填表、也不在 fields 里，不触发误杀/缺失）。
        let fields = writer.fields(SECRET);
        let opts = crate::delivery::FieldSetOptions::new(PROVIDER, true, true, true);
        crate::delivery::validate_plan_fields(
            DeliveryChannel::OpenCode,
            &fields,
            &opts,
            writer.target_path().as_path(),
        )
        .unwrap();
    }

    #[test]
    fn creates_fresh_file_with_provider_options() {
        let dir = tmp();
        let patch = writer_in(dir.path(), BASE, Some(MODEL))
            .plan(SECRET)
            .unwrap();

        assert_eq!(patch.before, "");
        let after = parsed(&patch.after);
        assert_eq!(after["provider"][PROVIDER]["options"]["apiKey"], SECRET);
        assert_eq!(after["provider"][PROVIDER]["options"]["baseURL"], BASE);
        assert_eq!(after["model"], MODEL);
        assert_eq!(patch.new_file_mode, Some(0o600));
    }

    #[test]
    fn preserves_every_unmanaged_key() {
        let dir = tmp();
        let before = r#"{
  "$schema": "https://opencode.ai/config.json",
  "instructions": [
    "AGENTS.md"
  ],
  "provider": {
    "anthropic": {
      "options": {
        "apiKey": "sk-anthropic-user-own",
        "baseURL": "https://api.anthropic.com"
      }
    },
    "keyrelay": {
      "options": {
        "apiKey": "sk-old",
        "baseURL": "https://old.example.com"
      }
    }
  },
  "model": "anthropic/claude-sonnet-4"
}"#;
        std::fs::write(writer_in(dir.path(), BASE, Some(MODEL)).path(), before).unwrap();

        let patch = writer_in(dir.path(), BASE, Some(MODEL))
            .plan(SECRET)
            .unwrap();
        let after = parsed(&patch.after);
        let original = parsed(before);

        assert_eq!(after["provider"][PROVIDER]["options"]["apiKey"], SECRET);
        assert_eq!(after["provider"][PROVIDER]["options"]["baseURL"], BASE);
        assert_eq!(after["model"], MODEL);

        // 除三处受管字段外，其余键的**值**必须完全相同
        for key in ["$schema", "instructions"] {
            assert_eq!(after[key], original[key], "顶层键 {key} 被改动了");
        }
        assert_eq!(
            after["provider"]["anthropic"], original["provider"]["anthropic"],
            "别的 provider 被改动了"
        );
        // 缩进风格保留
        assert!(patch.after.contains("\n  \"provider\""), "{}", patch.after);
    }

    #[test]
    fn preserves_indent_and_trailing_newline() {
        let dir = tmp();
        let before = "{\n    \"provider\": {}\n}\n";
        std::fs::write(writer_in(dir.path(), BASE, None).path(), before).unwrap();

        let patch = writer_in(dir.path(), BASE, None).plan(SECRET).unwrap();
        assert!(
            patch.after.contains("\n    \"provider\""),
            "{}",
            patch.after
        );
        assert!(patch.after.ends_with("}\n"), "尾随换行应保留");
    }

    #[test]
    fn single_line_file_stays_single_line() {
        let dir = tmp();
        std::fs::write(
            writer_in(dir.path(), BASE, None).path(),
            r#"{"model":"anthropic/x"}"#,
        )
        .unwrap();

        let patch = writer_in(dir.path(), BASE, None).plan(SECRET).unwrap();
        assert!(!patch.after.contains('\n'), "{}", patch.after);
        assert_eq!(patch.after.matches("apiKey").count(), 1);
    }

    #[test]
    fn empty_base_url_leaves_existing_base_url_alone() {
        let dir = tmp();
        let before = json!({
            "provider": { PROVIDER: { "options": { "baseURL": "https://keep.example.com" } } }
        })
        .to_string();
        std::fs::write(writer_in(dir.path(), "", None).path(), &before).unwrap();

        let patch = writer_in(dir.path(), "", None).plan(SECRET).unwrap();
        let after = parsed(&patch.after);
        assert_eq!(
            after["provider"][PROVIDER]["options"]["baseURL"],
            "https://keep.example.com"
        );
        assert_eq!(after["provider"][PROVIDER]["options"]["apiKey"], SECRET);
        assert_eq!(writer_in(dir.path(), "", None).field_names().len(), 1);
    }

    #[test]
    fn absent_model_does_not_touch_existing_model() {
        let dir = tmp();
        let before = json!({ "model": "other/x" }).to_string();
        std::fs::write(writer_in(dir.path(), BASE, None).path(), &before).unwrap();

        let patch = writer_in(dir.path(), BASE, None).plan(SECRET).unwrap();
        let after = parsed(&patch.after);
        assert_eq!(
            after["model"], "other/x",
            "没给 model 时不得改动已有的 model"
        );
        assert_eq!(writer_in(dir.path(), BASE, None).field_names().len(), 2);
    }

    #[test]
    fn blank_model_is_treated_as_absent() {
        let dir = tmp();
        let before = json!({ "model": "other/x" }).to_string();
        std::fs::write(writer_in(dir.path(), BASE, Some("  ")).path(), &before).unwrap();

        let patch = writer_in(dir.path(), BASE, Some("  "))
            .plan(SECRET)
            .unwrap();
        let after = parsed(&patch.after);
        assert_eq!(after["model"], "other/x");
        assert_eq!(
            writer_in(dir.path(), BASE, Some("  ")).field_names().len(),
            2
        );
    }

    #[test]
    fn model_is_trimmed() {
        let dir = tmp();
        let patch = writer_in(dir.path(), BASE, Some("  keyrelay/gpt-4o  "))
            .plan(SECRET)
            .unwrap();
        assert_eq!(parsed(&patch.after)["model"], MODEL);
    }

    #[test]
    fn rejects_empty_key() {
        let dir = tmp();
        for bad in ["", "   ", "\n"] {
            let err = writer_in(dir.path(), BASE, None).plan(bad).unwrap_err();
            assert!(matches!(err, Error::Inject { .. }), "{bad:?}");
            assert!(err.to_string().contains("密钥为空"), "{err}");
        }
    }

    #[test]
    fn rejects_empty_provider_id() {
        let dir = tmp();
        for bad in ["", "  "] {
            let writer =
                OpenCodeWriter::with_path(dir.path().join("opencode.json"), bad, BASE, None);
            let err = writer.plan(SECRET).unwrap_err();
            assert!(matches!(err, Error::Inject { .. }), "{bad:?}");
            assert!(err.to_string().contains("provider id"), "{err}");
        }
    }

    #[test]
    fn rejects_provider_or_options_that_is_not_an_object() {
        let dir = tmp();
        for bad in [
            json!({ "provider": [] }),
            json!({ "provider": { PROVIDER: [] } }),
            json!({ "provider": { PROVIDER: { "options": [] } } }),
            json!({ "provider": { PROVIDER: { "options": "nope" } } }),
        ] {
            std::fs::write(writer_in(dir.path(), BASE, None).path(), bad.to_string()).unwrap();
            let err = writer_in(dir.path(), BASE, None).plan(SECRET).unwrap_err();
            assert!(matches!(err, Error::Inject { .. }), "{bad}");
            assert!(err.to_string().contains("不是对象"), "{err}");
            // 拒绝时文件零改动
            assert_eq!(
                std::fs::read_to_string(writer_in(dir.path(), BASE, None).path()).unwrap(),
                bad.to_string()
            );
        }
    }

    #[test]
    fn rejects_invalid_json_and_non_object_root() {
        let dir = tmp();
        for bad in ["not json", "[1,2,3]", "\"str\""] {
            std::fs::write(writer_in(dir.path(), BASE, None).path(), bad).unwrap();
            assert!(
                matches!(
                    writer_in(dir.path(), BASE, None).plan(SECRET),
                    Err(Error::Inject { .. })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn plan_is_idempotent() {
        let dir = tmp();
        for model in [None, Some(MODEL)] {
            let first = writer_in(dir.path(), BASE, model).plan(SECRET).unwrap();
            std::fs::write(writer_in(dir.path(), BASE, model).path(), &first.after).unwrap();

            let second = writer_in(dir.path(), BASE, model).plan(SECRET).unwrap();
            assert_eq!(second.before, first.after);
            assert_eq!(second.after, first.after, "二次投递不得产生额外改动");
        }
    }

    #[test]
    fn errors_never_echo_the_key() {
        let dir = tmp();
        std::fs::write(writer_in(dir.path(), BASE, None).path(), "not json").unwrap();
        let err = writer_in(dir.path(), BASE, None)
            .plan("sk-VERY-SECRET-0123456789")
            .unwrap_err();
        assert!(!err.to_string().contains("VERY-SECRET"), "{err}");
    }

    #[test]
    fn fields_mask_only_the_secret() {
        let dir = tmp();
        let fields = writer_in(dir.path(), BASE, Some(MODEL)).fields(SECRET);
        assert_eq!(fields[0].key, "provider.keyrelay.options.apiKey");
        assert_eq!(fields[0].masked, "…cdef");
        assert_eq!(fields[1].key, "provider.keyrelay.options.baseURL");
        assert_eq!(fields[1].masked, BASE);
        assert_eq!(fields[2].key, "model");
        assert_eq!(fields[2].masked, MODEL);

        let text = format!("{:?}", fields);
        assert!(!text.contains(SECRET), "{text}");
    }

    #[test]
    fn jsonc_sibling_is_ignored() {
        // **D-1 钉住**：`.jsonc` 存在而 `.json` 不存在时仍写 `.json`（落点是常量）。
        let dir = tmp();
        let jsonc = dir.path().join("opencode.jsonc");
        std::fs::write(&jsonc, "{\n  // 用户自己的注释\n  \"model\": \"x/y\"\n}\n").unwrap();

        let writer = writer_in(dir.path(), BASE, None);
        assert_eq!(writer.path(), dir.path().join("opencode.json"));

        let patch = writer.plan(SECRET).unwrap();
        assert_eq!(patch.path, dir.path().join("opencode.json"));
        assert_eq!(patch.before, "", "`.json` 不存在 → 视为新建");

        // `.jsonc` 一个字节都没动
        assert_eq!(
            std::fs::read_to_string(&jsonc).unwrap(),
            "{\n  // 用户自己的注释\n  \"model\": \"x/y\"\n}\n"
        );
    }

    #[test]
    fn secret_with_json_metacharacters_is_escaped() {
        let dir = tmp();
        let hostile = "sk-a\"b\\c\n<>&d";
        let patch = writer_in(dir.path(), BASE, None).plan(hostile).unwrap();

        let after = parsed(&patch.after);
        assert_eq!(
            after["provider"][PROVIDER]["options"]["apiKey"], hostile,
            "转义后必须能原样解析回来"
        );
    }

    #[test]
    fn provider_id_with_json_metacharacters_is_escaped() {
        let dir = tmp();
        let weird = "a\"b\\c";
        let writer = OpenCodeWriter::with_path(dir.path().join("opencode.json"), weird, BASE, None);
        let patch = writer.plan(SECRET).unwrap();
        let after = parsed(&patch.after);
        assert_eq!(after["provider"][weird]["options"]["apiKey"], SECRET);
    }

    #[test]
    fn target_path_is_the_declared_relative_target() {
        // 安全边界：写入器声明的路径必须与 `relative_target()` 逐字一致。
        let home = Path::new("/tmp/nobody");
        let writer = OpenCodeWriter::new(home, PROVIDER, BASE, None);
        assert_eq!(
            writer.target_path(),
            home.join(DeliveryChannel::OpenCode.relative_target())
        );
    }

    // ============================================ M6-S1 复审 P2-3 的修复

    #[test]
    fn dotted_provider_id_gets_an_unambiguous_qualified_name() {
        // **P2-3 的回归**：点号分段下 `provider.a.b.options.apiKey` 与
        // 「provider `a` 下的 provider `b`」同形。改用 JSONPath 方括号形态消歧。
        let dir = tmp();
        let writer = OpenCodeWriter::with_path(dir.path().join("opencode.json"), "a.b", BASE, None);
        assert_eq!(
            writer.qualified_field(OpenCodeWriter::FIELD_API_KEY),
            "provider[\"a.b\"].options.apiKey"
        );
        assert_eq!(
            writer.field_names(),
            vec![
                "provider[\"a.b\"].options.apiKey",
                "provider[\"a.b\"].options.baseURL"
            ]
        );
    }

    #[test]
    fn simple_provider_id_keeps_the_dotted_form() {
        // 反例保护：常见形态不得被改写（否则既有同意记录的展示会全体变样）
        let dir = tmp();
        for simple in ["keyrelay", "my-relay", "site_a", "A1"] {
            let writer =
                OpenCodeWriter::with_path(dir.path().join("opencode.json"), simple, BASE, None);
            assert_eq!(
                writer.qualified_field(OpenCodeWriter::FIELD_API_KEY),
                format!("provider.{simple}.options.apiKey"),
                "{simple}"
            );
            assert!(is_simple_identifier(simple), "{simple}");
        }
        assert!(!is_simple_identifier("a.b"));
        assert!(!is_simple_identifier("a b"));
        assert!(!is_simple_identifier(""));
    }

    #[test]
    fn hostile_provider_id_is_json_escaped_in_the_qualified_name() {
        // 含 `"` 的 provider_id：限定名里必须是合法 JSON 字符串字面量，不能把路径拼断
        let dir = tmp();
        let writer =
            OpenCodeWriter::with_path(dir.path().join("opencode.json"), "a\"b", BASE, None);
        assert_eq!(
            writer.qualified_field(OpenCodeWriter::FIELD_API_KEY),
            "provider[\"a\\\"b\"].options.apiKey"
        );
        // 且落盘内容仍是同一个字面量键
        let patch = writer.plan(SECRET).unwrap();
        assert_eq!(
            parsed(&patch.after)["provider"]["a\"b"]["options"]["apiKey"],
            SECRET
        );
    }
}
