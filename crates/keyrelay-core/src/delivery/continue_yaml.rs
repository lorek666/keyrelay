//! Continue 通道：`~/.continue/config.yaml` 的标记块（M7-S3 / PRD FR-4:151）。
//!
//! # 为什么是标记块
//!
//! Continue 的 `models:` 是**用户的**列表（schema 已用 Continue 自己的解析器核实，见 [`CONFIG_NAME`]）。
//! 往里面塞条目有两条路：
//! ① 整份 YAML 解析后重写——会把用户的注释、键序、引号风格全部重排（违反 PRD FR-4:135 ③）；
//! ② 在 `models:` 之下插一个**注释标记块**，只动块内字节。本模块选 ②。
//!
//! # 为什么不做通用 YAML 解析（M7-S3 spec §5.7）
//!
//! 本模块只需要三件事：**找到块**、**找到顶层 `models:` 行**、**推断列表项缩进**。
//! 三件都用「行首 + 缩进 + 首字符」判定即可，**不需要**理解映射/序列/锚点/多行标量；
//! 章程 §3.3 规则 3 又禁止引入新依赖。不解析，才是保住块外字节的手段。
//!
//! # 块外字节不变的保证
//!
//! 只有三处拼接（新建 / 原地替换 / 插入），每处都只做「切两刀 + 塞一段」：
//! 块区间之外的两段原样搬运，因此「块外逐字节不变」是**构造性**的，而不是靠自觉。
//! 集成测试对块外前后缀做**逐字节比对 + sha256**（spec §5.6）。

use std::path::{Path, PathBuf};

use super::json_text::read_text_or_empty;
use super::{
    detect_line_ending, literal_field, locate_block, masked_field, DeliveryChannel, DeliveryField,
    DeliveryWriter,
};
use crate::error::{Error, Result};
use crate::inject::Patch;

/// 受管块开始标记（章程 §3.3 规则 2 逐字）。
pub const BLOCK_BEGIN: &str = "# >>> keyrelay managed >>>";
/// 受管块结束标记（章程 §3.3 规则 2 逐字）。
pub const BLOCK_END: &str = "# <<< keyrelay managed <<<";

/// 块内说明行（给手工编辑的用户看）。
const BLOCK_NOTE: &str = "# 由 KeyRelay 管理；手工修改会在下次投递时被覆盖";
/// 条目的显示名：**本产品自己的字面量**，不从站点或用户数据里编造。
const ENTRY_NAME: &str = "keyrelay";
/// OpenAI 兼容入口的 provider id。schema 层已核实（`provider` 是自由字符串，`parseConfigYaml`
/// 接受）；**运行期**是否按 OpenAI 兼容协议走 `apiBase` 仍未在装了 Continue 的机器上验证
/// （spec §14-3）。改动点只有本常量一行。
const ENTRY_PROVIDER: &str = "openai";
/// 新建文件时的配置头。Continue 的 schema 把顶层 `name` / `version` 定为**必填**——
/// 用它自己的解析器（`@continuedev/config-yaml` 1.42.0 `parseConfigYaml`）实测：
/// 缺了报 `name: Required, version: Required`，整份配置拒绝加载。
/// 取值是本产品自己的字面量（只在**新建**时写；已有文件的头部归用户，我们不动）。
const CONFIG_NAME: &str = "KeyRelay";
const CONFIG_VERSION: &str = "1.0.0";
/// 取不到模型名时的拒绝文案。
const MODEL_REQUIRED: &str =
    "Continue 要求每个模型条目都写明模型名（`model`），缺了它 Continue 会拒绝加载\
     整份配置；KeyRelay 不编造默认模型：请在投递时填写模型名";
/// 没有既有列表项时使用的缩进。
const DEFAULT_INDENT: &str = "  ";
/// 条目字段相对条目起始的额外缩进（对齐 `- ` 的宽度）。
const FIELD_INDENT: &str = "  ";

pub struct ContinueWriter {
    path: PathBuf,
    base_url: String,
    /// `None` = 沿用受管块里已有的模型名（重投 / 轮换）；块里也没有 ⇒ `plan()` 拒绝。
    /// **不编造默认模型**（章程 §4.2 点 4），也不写缺 `model` 的条目（Continue 必填）。
    model: Option<String>,
}

impl ContinueWriter {
    /// `home` 显式传入（不读 `HOME`），便于测试重定向到临时目录。
    pub fn new(home: &Path, base_url: &str, model: Option<&str>) -> Self {
        Self::with_path(home.join(".continue").join("config.yaml"), base_url, model)
    }

    /// 显式落点（测试用；生产走 [`ContinueWriter::new`]）。
    pub fn with_path(path: impl Into<PathBuf>, base_url: &str, model: Option<&str>) -> Self {
        Self {
            path: path.into(),
            base_url: base_url.to_string(),
            // 全空白的 model 与「没给 model」等价（与 `OpenCodeWriter::with_path` 同口径）。
            model: model
                .map(str::trim)
                .filter(|m| !m.is_empty())
                .map(str::to_string),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 纯函数：渲染受管块。返回块的各行，**以 `line_ending` 相连、不带尾随行尾**。
    ///
    /// 值一律走 [`quote`]（双引号 + 转义）——YAML 裸标量在 `: `、` #`、`{`/`[`/`*`/`&` 开头等
    /// 形态下语义会变，而 `apiKey` / `apiBase` 都是**外部输入**，不能靠「碰巧安全」。
    /// 控制字符的**拒绝**发生在 [`ContinueWriter::build_after`]（本函数是纯渲染，不返回 `Result`）。
    pub fn render_block(&self, api_key: &str, indent: &str, line_ending: &str) -> String {
        self.render_block_with(api_key, self.model.as_deref(), indent, line_ending)
    }

    /// [`ContinueWriter::render_block`] 的实体：`model` 由调用方给（`build_after` 用的是
    /// 「显式给的 ∨ 块里已有的」，不一定是 `self.model`）。
    fn render_block_with(
        &self,
        api_key: &str,
        model: Option<&str>,
        indent: &str,
        line_ending: &str,
    ) -> String {
        let field_indent = format!("{indent}{FIELD_INDENT}");
        let mut lines = vec![
            format!("{indent}{BLOCK_BEGIN}"),
            format!("{indent}{BLOCK_NOTE}"),
            format!("{indent}- name: {}", quote(ENTRY_NAME)),
            format!("{field_indent}provider: {}", quote(ENTRY_PROVIDER)),
        ];
        if let Some(model) = model {
            lines.push(format!("{field_indent}model: {}", quote(model)));
        }
        if !self.base_url.is_empty() {
            lines.push(format!("{field_indent}apiBase: {}", quote(&self.base_url)));
        }
        lines.push(format!("{field_indent}apiKey: {}", quote(api_key)));
        lines.push(format!("{indent}{BLOCK_END}"));
        lines.join(line_ending)
    }

    /// 生成写入后的完整文本。`api_key` 会出现在返回值里——调用方不得打印。
    fn build_after(&self, before: &str, api_key: &str) -> Result<String> {
        if api_key.trim().is_empty() {
            return Err(Error::inject(&self.path, "密钥为空，拒绝写入"));
        }
        validate_value(&self.path, "密钥", api_key)?;
        validate_value(&self.path, "base_url", &self.base_url)?;
        if let Some(model) = &self.model {
            validate_value(&self.path, "model", model)?;
        }

        let eol = detect_line_ending(before);

        // 模型名：显式给的优先；没给就只能来自既有受管块（重投 / 轮换）。两处都没有 ⇒ 拒绝——
        // 缺 `model` 的条目会让 Continue 拒绝加载**整份**配置，比不投递更糟。
        // 放在各分支里取（而不是一进来就拒绝）：结构性的拒绝（重复 `models:`、行内值、
        // 残缺块）先报，那些是用户必须先手工处理的。
        let require_model = |model: Option<String>| -> Result<String> {
            let model = model.ok_or_else(|| Error::inject(&self.path, MODEL_REQUIRED))?;
            validate_value(&self.path, "model", &model)?;
            Ok(model)
        };

        // ① 新建（文件不存在 / 0 字节 / 纯空白）：整份文件都是我们写的，补上 Continue 必填的配置头
        if before.trim().is_empty() {
            let model = require_model(self.model.clone())?;
            let block = self.render_block_with(api_key, Some(&model), DEFAULT_INDENT, eol);
            return Ok(format!(
                "name: {}{eol}version: {}{eol}models:{eol}{block}{eol}",
                quote(CONFIG_NAME),
                quote(CONFIG_VERSION)
            ));
        }

        // ② 已有块：原地替换，缩进沿用**旧块首行**（不因重投递而漂移）
        if let Some((begin, end)) = locate_block(before, &self.path)? {
            let model = require_model(
                self.model
                    .clone()
                    .or_else(|| block_model(&before[begin..end])),
            )?;
            let indent = leading_indent(&before[begin..]);
            let block = self.render_block_with(api_key, Some(&model), &indent, eol);
            let had_eol = before[begin..end].ends_with('\n');
            let mut out = String::with_capacity(before.len() + block.len() + 2);
            out.push_str(&before[..begin]);
            out.push_str(&block);
            if had_eol {
                out.push_str(eol);
            }
            out.push_str(&before[end..]);
            return Ok(out);
        }

        // ③ 没有块：挂在**唯一的**顶层 `models:` 之下；没有就追加
        let lines = split_lines_with_spans(before);
        let mut candidates: Vec<(usize, &LineSpan<'_>, ModelsLine)> = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            if let Some(kind) = classify_models_line(line.content) {
                candidates.push((index, line, kind));
            }
        }
        if candidates.len() > 1 {
            return Err(Error::inject(
                &self.path,
                format!(
                    "有 {} 个顶层 `models:` 键，不知道把受管块挂到哪一条上；\
                     请手工只保留一个后重试",
                    candidates.len()
                ),
            ));
        }

        match candidates.first() {
            Some((_, _line, ModelsLine::Flow)) => Err(Error::inject(
                &self.path,
                "顶层 `models:` 是行内值（不是块序列），KeyRelay 不改写它：\
                 请把它改成块序列（`models:` 换行后缩进列表项），或改用其它通道",
            )),
            Some((index, line, ModelsLine::Block)) => {
                let model = require_model(self.model.clone())?;
                let indent = infer_item_indent(&lines, *index);
                let block = self.render_block_with(api_key, Some(&model), &indent, eol);
                let mut out = String::with_capacity(before.len() + block.len() + eol.len() * 2);
                out.push_str(&before[..line.end]);
                // `models:` 是最后一行且没有行尾时先补一个：否则开始标记粘在 `models:` 同一行，
                // `locate_block` 只认行首标记，下一次投递就认不出这个块了。
                if !before[..line.end].ends_with('\n') {
                    out.push_str(eol);
                }
                out.push_str(&block);
                out.push_str(eol);
                out.push_str(&before[line.end..]);
                Ok(out)
            }
            None => {
                let model = require_model(self.model.clone())?;
                let block = self.render_block_with(api_key, Some(&model), DEFAULT_INDENT, eol);
                let mut out = String::with_capacity(before.len() + block.len() + 16);
                out.push_str(before);
                if !before.ends_with('\n') {
                    out.push_str(eol);
                }
                out.push_str("models:");
                out.push_str(eol);
                out.push_str(&block);
                out.push_str(eol);
                Ok(out)
            }
        }
    }
}

impl DeliveryWriter for ContinueWriter {
    fn channel(&self) -> DeliveryChannel {
        DeliveryChannel::Continue
    }

    fn target_path(&self) -> PathBuf {
        self.path.clone()
    }

    /// 将被写入的键名（**不需要密钥**，供「记录用户同意」使用）。
    ///
    /// `model` 总在其中：每次成功的写入都带它（显式给的，或沿用块里已有的）。
    fn field_names(&self) -> Vec<String> {
        let mut names = vec!["apiKey".to_string()];
        if !self.base_url.is_empty() {
            names.push("apiBase".to_string());
        }
        names.push("model".to_string());
        names
    }

    fn fields(&self, api_key: &str) -> Vec<DeliveryField> {
        let mut fields = vec![masked_field("apiKey", api_key)];
        if !self.base_url.is_empty() {
            fields.push(literal_field("apiBase", &self.base_url));
        }
        if let Some(model) = &self.model {
            fields.push(literal_field("model", model));
        }
        fields
    }

    fn plan(&self, api_key: &str) -> Result<Patch> {
        let before = read_text_or_empty(&self.path)?;
        let after = self.build_after(&before, api_key)?;
        Ok(Patch::secret_bearing(self.path.clone(), before, after))
    }
}

/// 顶层 `models:` 的两种形态。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ModelsLine {
    /// `models:` / `models: # 注释`——可以在其后插入块序列
    Block,
    /// `models: [a, b]` 这类行内值——**不改写**
    Flow,
}

/// 判定某一行是不是**顶层** `models:`。`None` = 不是。
///
/// 「顶层」= 行首无空白（缩进的 `models:` 属于别的映射，不是我们要挂的地方）。
///
/// 文件首行可能带 BOM，键也可以写成 `"models"` / `'models'`——YAML 里这三种写法是**同一个键**。
/// 认不出来就会走「追加」分支，写出第二个顶层 `models:`（重复键，Continue 拒绝加载）。
fn classify_models_line(content: &str) -> Option<ModelsLine> {
    let content = content.strip_prefix('\u{FEFF}').unwrap_or(content);
    let rest = ["models", "\"models\"", "'models'"]
        .into_iter()
        .find_map(|key| content.strip_prefix(key))?;
    let rest = rest.trim_start();
    let after_colon = rest.strip_prefix(':')?;
    let tail = after_colon.trim();
    if tail.is_empty() || tail.starts_with('#') {
        Some(ModelsLine::Block)
    } else {
        Some(ModelsLine::Flow)
    }
}

struct LineSpan<'a> {
    content: &'a str,
    end: usize,
}

/// 按行切分并记录每行**行尾之后**的偏移（含 `\n`；`\r` 从 `content` 里剥掉）。
fn split_lines_with_spans(text: &str) -> Vec<LineSpan<'_>> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, b) in text.bytes().enumerate() {
        if b == b'\n' {
            let mut content_end = i;
            if content_end > start && text.as_bytes()[content_end - 1] == b'\r' {
                content_end -= 1;
            }
            out.push(LineSpan {
                content: &text[start..content_end],
                end: i + 1,
            });
            start = i + 1;
        }
    }
    if start < text.len() {
        out.push(LineSpan {
            content: &text[start..],
            end: text.len(),
        });
    }
    out
}

/// 推断 `models:` 之下列表项的缩进：看**第一个**非空、非注释行；
/// 它是列表项（首个非空字符是 `-`）⇒ 沿用它的缩进（**包括空缩进**），否则用默认两空格。
///
/// 为什么必须推断而不是写死：YAML 的块序列要求同一序列内缩进一致，
/// 给一个 4 空格缩进的文件塞 2 空格的条目会让文件变成**非法 YAML**。
///
/// **空缩进也必须沿用**（M7-S3 复审 P1-1）：YAML 允许块序列项与父键**同缩进**——
/// `models:` 的下一行直接是 `- name: x`（0 缩进）。旧实现要求「缩进 > 0」才沿用，
/// 于是给这种文件塞了 2 空格的条目，同一个序列出现两种缩进 ⇒ 产物**非法 YAML**：
/// 原文能 `safe_load`，投递之后 `ParserError: expected <block end>, but found '-'`。
/// 「投递成功但产物不可解析」比没投递更糟——用户以为成功了。
fn infer_item_indent(lines: &[LineSpan<'_>], models_index: usize) -> String {
    for line in lines.iter().skip(models_index + 1) {
        let trimmed = line.content.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('-') {
            return leading_indent(line.content);
        }
        return DEFAULT_INDENT.to_string();
    }
    DEFAULT_INDENT.to_string()
}

/// 行首的空白前缀。
fn leading_indent(text: &str) -> String {
    text.chars()
        .take_while(|c| matches!(c, ' ' | '\t'))
        .collect()
}

/// YAML 双引号字面量：`\` / `"` / 换行 / 制表 / 回车转义，其余 C0 用 `\xNN`。
///
/// 控制字符在 [`ContinueWriter::build_after`] 已被拒绝，这里的 `\xNN` 是**防御性**的
/// （纯渲染函数不该 panic，也不该把控制字符原样写进文件）。
fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// 从既有受管块里取模型名（重投 / 轮换沿用它）。
///
/// 只认本模块自己渲染的形态：块内某行去掉缩进后是 `model: "<quote 的产物>"`。
/// 手工改成别的写法 ⇒ 取不到 ⇒ 由调用方拒绝并要求填写模型名——不猜。
fn block_model(block: &str) -> Option<String> {
    block.lines().find_map(|line| {
        let value = line.trim().strip_prefix("model:")?.trim();
        unquote(value).filter(|model| !model.trim().is_empty())
    })
}

/// [`quote`] 的逆：只接受 `quote` 能产生的转义（`\\` `\"` `\n` `\t` `\r` `\xNN`），其余 ⇒ `None`。
fn unquote(value: &str) -> Option<String> {
    let inner = value.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return None, // 未转义的引号：不是 `quote` 的产物
            '\\' => match chars.next()? {
                '\\' => out.push('\\'),
                '"' => out.push('"'),
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                'x' => {
                    let hex: String = chars.by_ref().take(2).collect();
                    let code = u32::from_str_radix(&hex, 16)
                        .ok()
                        .filter(|_| hex.len() == 2)?;
                    out.push(char::from_u32(code)?);
                }
                _ => return None,
            },
            c => out.push(c),
        }
    }
    Some(out)
}

/// 值校验：C0 控制字符（`\t` `\n` `\r` 除外）⇒ 拒绝（spec §4.3）。
fn validate_value(path: &Path, what: &str, value: &str) -> Result<()> {
    if value
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
    {
        return Err(Error::inject(
            path,
            format!(
                "{what} 含 YAML 双引号字面量无法安全表示的控制字符（只允许制表符 / 换行 / 回车）"
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-continue-0123456789abcdef";
    const BASE: &str = "https://relay.example.com/v1";
    const MODEL: &str = "gpt-4o";

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("临时目录")
    }

    fn writer_in(dir: &Path, base_url: &str, model: Option<&str>) -> ContinueWriter {
        ContinueWriter::with_path(dir.join("config.yaml"), base_url, model)
    }

    #[test]
    fn render_block_is_byte_exact() {
        let writer = writer_in(Path::new("/tmp/nobody"), BASE, Some(MODEL));
        let expected = "  # >>> keyrelay managed >>>\n  # 由 KeyRelay 管理；手工修改会在下次投递时被覆盖\n  - name: \"keyrelay\"\n    provider: \"openai\"\n    model: \"gpt-4o\"\n    apiBase: \"https://relay.example.com/v1\"\n    apiKey: \"sk-continue-0123456789abcdef\"\n  # <<< keyrelay managed <<<";
        assert_eq!(writer.render_block(SECRET, "  ", "\n"), expected);
    }

    #[test]
    fn render_block_omits_optional_lines() {
        let writer = writer_in(Path::new("/tmp/nobody"), "", None);
        let block = writer.render_block(SECRET, "", "\n");
        assert!(!block.contains("model:"), "{block}");
        assert!(!block.contains("apiBase:"), "{block}");
        assert!(block.starts_with("# >>> keyrelay managed >>>"), "{block}");
        assert!(block.ends_with("# <<< keyrelay managed <<<"), "{block}");
    }

    #[test]
    fn fresh_file_is_byte_exact() {
        let dir = tmp();
        let patch = writer_in(dir.path(), BASE, Some(MODEL))
            .plan(SECRET)
            .unwrap();
        assert_eq!(patch.before, "");
        let expected = "name: \"KeyRelay\"\nversion: \"1.0.0\"\nmodels:\n  # >>> keyrelay managed >>>\n  # 由 KeyRelay 管理；手工修改会在下次投递时被覆盖\n  - name: \"keyrelay\"\n    provider: \"openai\"\n    model: \"gpt-4o\"\n    apiBase: \"https://relay.example.com/v1\"\n    apiKey: \"sk-continue-0123456789abcdef\"\n  # <<< keyrelay managed <<<\n";
        assert_eq!(patch.after, expected);
        assert_eq!(patch.new_file_mode, Some(0o600), "含密钥 → 新建 0600");
    }

    #[test]
    fn insert_goes_right_after_models_and_keeps_user_items() {
        let dir = tmp();
        let before = "name: my-config\nmodels:\n  - name: mine\n    provider: openai\n";
        std::fs::write(writer_in(dir.path(), BASE, Some(MODEL)).path(), before).unwrap();

        let patch = writer_in(dir.path(), BASE, Some(MODEL))
            .plan(SECRET)
            .unwrap();
        assert!(
            patch.after.starts_with("name: my-config\nmodels:\n  # >>>"),
            "{}",
            patch.after
        );
        assert!(
            patch.after.contains("  - name: mine\n"),
            "用户条目必须原样保留"
        );
        assert_eq!(
            patch.after.matches("models:").count(),
            1,
            "不得出现第二个 models:"
        );
    }

    #[test]
    fn indent_follows_the_existing_list() {
        let dir = tmp();
        let before = "models:\n    - name: mine\n      provider: openai\n";
        std::fs::write(writer_in(dir.path(), BASE, Some(MODEL)).path(), before).unwrap();

        let patch = writer_in(dir.path(), BASE, Some(MODEL))
            .plan(SECRET)
            .unwrap();
        assert!(
            patch.after.contains("    # >>> keyrelay managed >>>"),
            "{}",
            patch.after
        );
        assert!(
            patch.after.contains("    - name: \"keyrelay\""),
            "{}",
            patch.after
        );
        assert!(patch.after.contains("      apiKey:"), "{}", patch.after);
    }

    #[test]
    fn zero_indent_list_keeps_zero_indent() {
        // **M7-S3 复审 P1-1 的回归**（单元层）：`models:` 的下一行直接是 0 缩进的列表项。
        // 旧实现在这里回落成 2 空格 ⇒ 同一个序列两种缩进 ⇒ 产物非法 YAML。
        let dir = tmp();
        let before = "models:\n- name: mine\n- name: second\n";
        std::fs::write(writer_in(dir.path(), BASE, Some(MODEL)).path(), before).unwrap();

        let patch = writer_in(dir.path(), BASE, Some(MODEL))
            .plan(SECRET)
            .unwrap();
        assert!(
            patch.after.contains("\n- name: \"keyrelay\"\n"),
            "块内条目必须与既有条目同缩进（空）: {}",
            patch.after
        );
        assert!(
            patch.after.contains("\n  apiKey:"),
            "条目字段相对条目再缩进两格: {}",
            patch.after
        );
        assert!(
            !patch.after.contains("\n  - name:"),
            "不得给 0 缩进的序列塞 2 空格的条目: {}",
            patch.after
        );
    }

    #[test]
    fn appends_models_when_absent() {
        let dir = tmp();
        let before = "name: my-config\n"; // 不以换行结尾也覆盖
        std::fs::write(writer_in(dir.path(), BASE, Some(MODEL)).path(), before).unwrap();

        let patch = writer_in(dir.path(), BASE, Some(MODEL))
            .plan(SECRET)
            .unwrap();
        assert!(patch.after.starts_with(before), "原内容必须逐字保留");
        assert!(
            patch.after.contains("\nmodels:\n  # >>>"),
            "{}",
            patch.after
        );
    }

    #[test]
    fn replaces_the_block_in_place_and_is_idempotent() {
        let dir = tmp();
        let path = writer_in(dir.path(), BASE, Some(MODEL))
            .path()
            .to_path_buf();
        let first = writer_in(dir.path(), BASE, Some(MODEL))
            .plan(SECRET)
            .unwrap();
        std::fs::write(&path, &first.after).unwrap();

        let second = writer_in(dir.path(), BASE, Some(MODEL))
            .plan(SECRET)
            .unwrap();
        assert_eq!(second.after, first.after, "同输入二次投递不得产生额外改动");

        let rotated = writer_in(dir.path(), BASE, Some(MODEL))
            .plan("sk-continue-ROTATED-999999")
            .unwrap();
        assert!(rotated.after.contains("sk-continue-ROTATED-999999"));
        assert!(!rotated.after.contains(SECRET), "旧密钥必须被替换掉");
        assert_eq!(rotated.after.matches(BLOCK_BEGIN).count(), 1);
    }

    #[test]
    fn keeps_the_file_line_ending() {
        let dir = tmp();
        let before = "models:\r\n  - name: mine\r\n";
        std::fs::write(writer_in(dir.path(), BASE, Some(MODEL)).path(), before).unwrap();

        let patch = writer_in(dir.path(), BASE, Some(MODEL))
            .plan(SECRET)
            .unwrap();
        assert!(
            patch.after.contains("  # >>> keyrelay managed >>>\r\n"),
            "{:?}",
            patch.after
        );
        assert!(!patch.after.contains("\n\n"), "不得混入 LF 行尾");
    }

    #[test]
    fn refuses_orphan_and_duplicate_blocks() {
        let dir = tmp();
        for bad in [
            format!("models:\n  {BLOCK_BEGIN}\n  - name: x\n"),
            format!("models:\n  - name: x\n  {BLOCK_END}\n"),
            format!("models:\n  {BLOCK_BEGIN}\n  {BLOCK_END}\n  {BLOCK_BEGIN}\n  {BLOCK_END}\n"),
        ] {
            let path = writer_in(dir.path(), BASE, None).path().to_path_buf();
            std::fs::write(&path, &bad).unwrap();
            let err = writer_in(dir.path(), BASE, None).plan(SECRET).unwrap_err();
            assert!(matches!(err, Error::Inject { .. }), "{err:?}");
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                bad,
                "拒绝时磁盘零改动"
            );
        }
    }

    #[test]
    fn refuses_duplicate_models_and_flow_style() {
        let dir = tmp();
        for (bad, needle) in [
            ("models:\n  - a\nmodels:\n  - b\n", "顶层 `models:`"),
            ("models: [a, b]\n", "行内值"),
        ] {
            let path = writer_in(dir.path(), BASE, None).path().to_path_buf();
            std::fs::write(&path, bad).unwrap();
            let err = writer_in(dir.path(), BASE, None).plan(SECRET).unwrap_err();
            assert!(err.to_string().contains(needle), "{err}");
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                bad,
                "拒绝时磁盘零改动"
            );
        }
    }

    #[test]
    fn refuses_empty_key_and_control_characters() {
        let dir = tmp();
        for bad in ["", "   "] {
            let err = writer_in(dir.path(), BASE, None).plan(bad).unwrap_err();
            assert!(err.to_string().contains("密钥为空"), "{err}");
        }
        let err = writer_in(dir.path(), "https://x/\u{7}", None)
            .plan(SECRET)
            .unwrap_err();
        assert!(err.to_string().contains("控制字符"), "{err}");
        let err = writer_in(dir.path(), BASE, None)
            .plan("sk-a\u{1}b")
            .unwrap_err();
        assert!(err.to_string().contains("控制字符"), "{err}");
    }

    #[test]
    fn quotes_hostile_values() {
        assert_eq!(quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(quote("a\nb"), "\"a\\nb\"");
        assert_eq!(quote("a:b#c"), "\"a:b#c\"");
        assert_eq!(quote("\u{7}"), "\"\\x07\"");

        // 落到文件里也是同一形态（值里的 `: ` 与 ` #` 不会把 YAML 读成别的意思）
        let dir = tmp();
        let patch = writer_in(dir.path(), "https://x/a: b #c", Some(MODEL))
            .plan(SECRET)
            .unwrap();
        assert!(
            patch.after.contains("apiBase: \"https://x/a: b #c\""),
            "{}",
            patch.after
        );
    }

    #[test]
    fn preview_fields_mask_only_the_key() {
        let dir = tmp();
        let writer = writer_in(dir.path(), BASE, Some(MODEL));
        assert_eq!(writer.field_names(), vec!["apiKey", "apiBase", "model"]);
        let fields = writer.fields(SECRET);
        assert_eq!(fields[0].key, "apiKey");
        assert_eq!(fields[0].masked, "…cdef");
        assert_eq!(fields[1].masked, BASE);
        assert_eq!(fields[2].masked, MODEL);
        let text = format!("{fields:?}");
        assert!(!text.contains(SECRET), "{text}");
    }

    #[test]
    fn classifies_models_lines() {
        assert_eq!(classify_models_line("models:"), Some(ModelsLine::Block));
        assert_eq!(classify_models_line("models:   "), Some(ModelsLine::Block));
        assert_eq!(
            classify_models_line("models: # 我的模型"),
            Some(ModelsLine::Block)
        );
        assert_eq!(classify_models_line("models :"), Some(ModelsLine::Block));
        assert_eq!(classify_models_line("models: [a]"), Some(ModelsLine::Flow));
        assert_eq!(classify_models_line("  models:"), None, "缩进的不算顶层");
        assert_eq!(classify_models_line("modelsX:"), None);
        assert_eq!(classify_models_line("# models:"), None);
        assert_eq!(classify_models_line("name: models"), None);
    }

    #[test]
    fn classifies_bom_and_quoted_models_keys() {
        // 文件首行可能带 BOM；YAML 键也可以加单 / 双引号——三种写法都是同一个 `models` 键
        assert_eq!(
            classify_models_line("\u{FEFF}models:"),
            Some(ModelsLine::Block)
        );
        assert_eq!(classify_models_line("\"models\":"), Some(ModelsLine::Block));
        assert_eq!(classify_models_line("'models':"), Some(ModelsLine::Block));
        assert_eq!(
            classify_models_line("\"models\" : # 注释"),
            Some(ModelsLine::Block)
        );
        assert_eq!(
            classify_models_line("\u{FEFF}\"models\": []"),
            Some(ModelsLine::Flow)
        );
        assert_eq!(classify_models_line("\"modelsX\":"), None);
        assert_eq!(classify_models_line("\"models':"), None, "引号不成对");
        assert_eq!(classify_models_line("\"models:"), None, "引号不成对");
        assert_eq!(classify_models_line(" \"models\":"), None, "缩进的不算顶层");
    }

    #[test]
    fn insert_after_models_without_trailing_newline_starts_a_new_line() {
        let dir = tmp();
        let before = "models:";
        std::fs::write(writer_in(dir.path(), BASE, Some(MODEL)).path(), before).unwrap();

        let patch = writer_in(dir.path(), BASE, Some(MODEL))
            .plan(SECRET)
            .unwrap();
        assert!(
            patch
                .after
                .starts_with("models:\n  # >>> keyrelay managed >>>\n"),
            "{:?}",
            patch.after
        );
    }

    #[test]
    fn errors_never_echo_the_key() {
        let dir = tmp();
        let path = writer_in(dir.path(), BASE, None).path().to_path_buf();
        std::fs::write(&path, format!("models:\n  {BLOCK_BEGIN}\n")).unwrap();
        let err = writer_in(dir.path(), BASE, None)
            .plan("sk-VERY-SECRET-0123456789")
            .unwrap_err();
        assert!(!err.to_string().contains("VERY-SECRET"), "{err}");
    }
}
