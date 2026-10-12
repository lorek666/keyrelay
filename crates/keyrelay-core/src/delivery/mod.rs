//! 密钥投递：把钥匙串里的密钥写进某个 agent 的配置文件。
//!
//! 与 `inject` 的分工：`inject` 负责「原子写 + 备份 + 回滚」的机械动作，
//! 本模块负责「写到哪个文件、写哪些字段、用户是否同意」。
//!
//! 红线：
//! - 预览（[`DeliveryPlan`]）里**只有掩码**，永远不含密钥明文。
//! - 投递结果（[`DeliveryOutcome`]）同样不含密钥。
//! - 生成的 [`Patch`] 含密钥，其 `Debug` 已手写脱敏（BACKLOG B-12）。

pub mod claude_code;
pub mod codex_auth;
pub mod gemini_cli;
pub mod json_text;
pub mod opencode;
pub mod shell_block;

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::inject::Patch;
use crate::redact::mask_secret;

/// 投递通道：一个通道 = 一个 agent 的一种配置落点。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeliveryChannel {
    /// `~/.codex/auth.json`（本步实现）
    CodexAuthJson,
    /// `~/.claude/settings.json` 的 `env` 段（M1-S3）
    ClaudeCodeSettings,
    /// shell rc 文件的标记块（M1-S3）
    ShellBlock,
    /// `~/.config/opencode/opencode.json` 的 `provider.<id>.options`（M6-S1）
    OpenCode,
    /// `~/.gemini/.env`（M6-S1）
    GeminiCli,
}

impl DeliveryChannel {
    pub const ALL: [DeliveryChannel; 5] = [
        DeliveryChannel::CodexAuthJson,
        DeliveryChannel::ClaudeCodeSettings,
        DeliveryChannel::ShellBlock,
        DeliveryChannel::OpenCode,
        DeliveryChannel::GeminiCli,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            DeliveryChannel::CodexAuthJson => "codex-auth-json",
            DeliveryChannel::ClaudeCodeSettings => "claude-code-settings",
            DeliveryChannel::ShellBlock => "shell-block",
            DeliveryChannel::OpenCode => "opencode",
            DeliveryChannel::GeminiCli => "gemini-cli",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "codex-auth-json" => Ok(DeliveryChannel::CodexAuthJson),
            "claude-code-settings" => Ok(DeliveryChannel::ClaudeCodeSettings),
            "shell-block" => Ok(DeliveryChannel::ShellBlock),
            "opencode" => Ok(DeliveryChannel::OpenCode),
            "gemini-cli" => Ok(DeliveryChannel::GeminiCli),
            other => Err(Error::NotFound(format!("未知的投递通道: {other}"))),
        }
    }

    /// 该通道服务的 agent 标识，与 `bindings.agent_id` 对齐。
    pub fn agent_id(self) -> &'static str {
        match self {
            DeliveryChannel::CodexAuthJson => "codex",
            DeliveryChannel::ClaudeCodeSettings => "claude-code",
            DeliveryChannel::ShellBlock => "shell",
            DeliveryChannel::OpenCode => "opencode",
            DeliveryChannel::GeminiCli => "gemini-cli",
        }
    }

    /// [`Self::agent_id`] 的逆映射（漂移报告要把 `bindings.agent_id` 还原成通道名）。
    pub fn from_agent_id(agent_id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.agent_id() == agent_id)
    }

    /// 该通道声明的目标路径，**相对于用户目录**。
    ///
    /// 存在的理由（M6-S0）：`service.rs::checked_target` 原先对 `DeliveryChannel` 做穷举
    /// `match` 来取得期望路径，于是「新增一条通道」必须同时改 `delivery` 与 `service`
    /// 两个文件——两个包各改一处就会编译中断。把映射收到通道自己身上之后，
    /// 新增通道只需要改本文件一处，路径白名单自动跟着走。
    ///
    /// 这是**安全边界**：`checked_target` 用它逐字比对投递目标，因此这里返回的路径
    /// 必须与写入器实际写入的路径一致，否则投递会被拒绝（fail-closed）。
    ///
    /// 两条 M6-S1 通道的路径都是**常量**，不随磁盘状态变化：`.jsonc` 存在而 `.json`
    /// 不存在时仍返回 `.json`（见 `docs/specs/M6-S1-通道扩展.md` §11 D-1）。
    pub fn relative_target(self) -> PathBuf {
        match self {
            DeliveryChannel::CodexAuthJson => PathBuf::from(".codex").join("auth.json"),
            DeliveryChannel::ClaudeCodeSettings => PathBuf::from(".claude").join("settings.json"),
            DeliveryChannel::ShellBlock => PathBuf::from(
                shell_block::ShellSyntax::for_current_platform().default_rc_relative_path(),
            ),
            DeliveryChannel::OpenCode => PathBuf::from(".config")
                .join("opencode")
                .join("opencode.json"),
            DeliveryChannel::GeminiCli => PathBuf::from(".gemini").join(".env"),
        }
    }
}

/// 预览里的一个字段。两个字段都是「可以给用户看」的值。
#[derive(Clone, PartialEq, Eq)]
pub struct DeliveryField {
    /// 将被写入的键名，例如 `OPENAI_API_KEY`
    pub key: String,
    /// 掩码后的值，例如 `…cdef`
    pub masked: String,
}

impl std::fmt::Debug for DeliveryField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeliveryField")
            .field("key", &self.key)
            .field("masked", &self.masked)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConsentState {
    Missing,
    Granted { granted_at: i64 },
    Revoked { revoked_at: i64 },
}

impl ConsentState {
    pub fn is_granted(&self) -> bool {
        matches!(self, ConsentState::Granted { .. })
    }
}

/// 投递预览：给用户看「要写哪里、写什么」，**不含密钥明文**。
#[derive(Clone, PartialEq, Eq)]
pub struct DeliveryPlan {
    pub agent_id: String,
    pub channel: DeliveryChannel,
    pub target_path: PathBuf,
    /// 目标文件当前是否存在（决定 UI 提示「新建」还是「改写」）
    pub target_exists: bool,
    pub fields: Vec<DeliveryField>,
    /// 已脱敏的 diff 预览
    pub preview: String,
    pub consent: ConsentState,
}

impl std::fmt::Debug for DeliveryPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeliveryPlan")
            .field("agent_id", &self.agent_id)
            .field("channel", &self.channel)
            .field("target_path", &self.target_path)
            .field("target_exists", &self.target_exists)
            .field("fields", &self.fields)
            .field("preview_len", &self.preview.len())
            .field("consent", &self.consent)
            .finish()
    }
}

/// 投递结果：**不含任何密钥材料**，可直接序列化给前端。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryOutcome {
    pub channel: DeliveryChannel,
    pub target_path: PathBuf,
    pub journal_id: String,
    pub backup_path: Option<PathBuf>,
}

/// 通道实现。
pub trait DeliveryWriter: Send + Sync {
    fn channel(&self) -> DeliveryChannel;

    fn target_path(&self) -> PathBuf;

    /// 将被写入的键名清单。**不需要密钥**，因此「记录用户同意」这一步不必读钥匙串。
    fn field_names(&self) -> Vec<String>;

    /// 预览字段清单：**键名 + 可展示的值**（密钥一律掩码）。
    ///
    /// 由写入器自己决定哪些值是秘密：`auth_mode` 的 `"apikey"` 是字面量，不该被掩码成 `…`。
    fn fields(&self, api_key: &str) -> Vec<DeliveryField>;

    /// 生成补丁。返回的 `Patch.after` **含密钥明文**，调用方不得打印它。
    fn plan(&self, api_key: &str) -> Result<Patch>;
}

/// 按通道解析出写入器。`home` 显式传入以便测试重定向（不读环境变量）。
pub fn resolve(channel: DeliveryChannel, home: &Path) -> Result<Box<dyn DeliveryWriter>> {
    resolve_for(channel, home, "")
}

/// 带站点 `base_url` 的解析。**签名保持不变**——`service.rs` 的调用点在这里，
/// 本步的作者写域不含 `service.rs`（M6-S0 章程 §3）。
///
/// `base_url` 为空表示「只投递密钥，不动 endpoint」——会写 base_url 的通道
/// （Claude Code / shell 块 / OpenCode / Gemini CLI）据此少写一行。
///
/// OpenCode 通道在这里走**默认 provider 名**
/// （[`opencode::OpenCodeWriter::DEFAULT_PROVIDER_ID`]）且不写 `model`。
/// 需要站点自选的 provider 名与模型时用 [`resolve_for_binding`]（S5 接线面）。
pub fn resolve_for(
    channel: DeliveryChannel,
    home: &Path,
    base_url: &str,
) -> Result<Box<dyn DeliveryWriter>> {
    resolve_for_binding(
        channel,
        home,
        base_url,
        opencode::OpenCodeWriter::DEFAULT_PROVIDER_ID,
        None,
    )
}

/// 完整入口：`provider_id` / `model` **只对 [`DeliveryChannel::OpenCode`] 生效**，其余通道忽略。
///
/// `provider_id` 为空（trim 后）时**在这里就报错**，而不是等到 `plan()`：
/// 调用方传空 provider 名是接线错误，早报比写到一个 `provider.""` 上强。
/// `model` 为 `None` 或 trim 后为空 → 不写、也不动已有的 `model` 键。
pub fn resolve_for_binding(
    channel: DeliveryChannel,
    home: &Path,
    base_url: &str,
    provider_id: &str,
    model: Option<&str>,
) -> Result<Box<dyn DeliveryWriter>> {
    match channel {
        DeliveryChannel::CodexAuthJson => Ok(Box::new(codex_auth::CodexAuthWriter::new(home))),
        DeliveryChannel::ClaudeCodeSettings => {
            Ok(Box::new(claude_code::ClaudeCodeWriter::new(home, base_url)))
        }
        DeliveryChannel::ShellBlock => {
            Ok(Box::new(shell_block::ShellBlockWriter::new(home, base_url)))
        }
        DeliveryChannel::OpenCode => {
            if provider_id.trim().is_empty() {
                return Err(Error::inject(
                    home.join(channel.relative_target()),
                    "provider id 为空，拒绝写入",
                ));
            }
            Ok(Box::new(opencode::OpenCodeWriter::new(
                home,
                provider_id,
                base_url,
                model,
            )))
        }
        DeliveryChannel::GeminiCli => {
            Ok(Box::new(gemini_cli::GeminiCliWriter::new(home, base_url)))
        }
    }
}

/// 构造一个掩码字段（用于密钥值）。
pub fn masked_field(key: impl Into<String>, secret: &str) -> DeliveryField {
    DeliveryField {
        key: key.into(),
        masked: mask_secret(secret),
    }
}

/// 构造一个字面量字段（用于非秘密的配置值，例如 `auth_mode: "apikey"`）。
pub fn literal_field(key: impl Into<String>, value: impl Into<String>) -> DeliveryField {
    DeliveryField {
        key: key.into(),
        masked: value.into(),
    }
}

/// 行级 diff 预览。任何一行在输出前都会把 `secret` 原文替换成掩码，再过一遍 `scrub`。
///
/// 只输出**变化了的行**（`-` / `+`）：整份打印会把无关内容淹没掉差异，
/// 而配置文件（`auth.json` 等）的改动通常只有一两行。
pub fn diff_preview(before: &str, after: &str, secret: &str) -> String {
    let mut out = String::new();
    for (tag, line) in diff_lines(before, after) {
        let prefix = match tag {
            '-' => "- ",
            '+' => "+ ",
            _ => continue,
        };
        out.push_str(prefix);
        out.push_str(&redact_line(&line, secret));
        out.push('\n');
    }
    if out.is_empty() {
        out.push_str("(无变化)\n");
    }
    out
}

fn redact_line(line: &str, secret: &str) -> String {
    let replaced = if secret.is_empty() {
        line.to_string()
    } else {
        line.replace(secret, &mask_secret(secret))
    };
    crate::redact::scrub(&replaced)
}

/// 极简行级 LCS diff。输入是本产品的配置文件（几十行量级），O(n·m) 足够。
fn diff_lines(before: &str, after: &str) -> Vec<(char, String)> {
    let a: Vec<&str> = split_lines(before);
    let b: Vec<&str> = split_lines(after);
    let (n, m) = (a.len(), b.len());

    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }

    let mut result = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if a[i] == b[j] {
            result.push((' ', a[i].to_string()));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            result.push(('-', a[i].to_string()));
            i += 1;
        } else {
            result.push(('+', b[j].to_string()));
            j += 1;
        }
    }
    while i < n {
        result.push(('-', a[i].to_string()));
        i += 1;
    }
    while j < m {
        result.push(('+', b[j].to_string()));
        j += 1;
    }
    result
}

/// 按行切分，且**保留尾随空行的语义**：`"a\n"` 与 `"a"` 视为同一行集（差异只在末尾换行）。
fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    let trimmed = text.strip_suffix('\n').unwrap_or(text);
    trimmed.split('\n').collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_strings_are_exact() {
        // M6-S1 章程 §4.1 冻结：两条新通道的字符串逐字如下，且 `ALL` 的顺序是稳定契约。
        let strings: Vec<&str> = DeliveryChannel::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            strings,
            vec![
                "codex-auth-json",
                "claude-code-settings",
                "shell-block",
                "opencode",
                "gemini-cli"
            ]
        );
        assert_eq!(DeliveryChannel::OpenCode.agent_id(), "opencode");
        assert_eq!(DeliveryChannel::GeminiCli.agent_id(), "gemini-cli");
    }

    #[test]
    fn new_channel_relative_targets_are_exact() {
        assert_eq!(
            DeliveryChannel::OpenCode.relative_target(),
            PathBuf::from(".config")
                .join("opencode")
                .join("opencode.json")
        );
        assert_eq!(
            DeliveryChannel::GeminiCli.relative_target(),
            PathBuf::from(".gemini").join(".env")
        );
    }

    #[test]
    fn resolve_target_matches_relative_target_for_every_channel() {
        // **安全边界**：`service.rs::checked_target` 用 `home.join(relative_target())`
        // 逐字比对投递目标。写入器声明的路径只要差一个字节，投递就会被拒绝（fail-closed）。
        let home = Path::new("/tmp/nobody");
        for channel in DeliveryChannel::ALL {
            let writer = resolve_for(channel, home, "https://relay.example.com")
                .unwrap_or_else(|e| panic!("{} 应可解析: {e}", channel.as_str()));
            assert_eq!(
                writer.target_path(),
                home.join(channel.relative_target()),
                "{} 的 target_path 与 relative_target 不一致",
                channel.as_str()
            );
        }
    }

    #[test]
    fn resolve_for_binding_uses_provider_and_model() {
        let home = Path::new("/tmp/nobody");
        let writer = resolve_for_binding(
            DeliveryChannel::OpenCode,
            home,
            "https://relay.example.com",
            "my-relay",
            Some("my-relay/gpt-4o"),
        )
        .unwrap();
        assert_eq!(
            writer.field_names(),
            vec![
                "provider.my-relay.options.apiKey",
                "provider.my-relay.options.baseURL",
                "model"
            ]
        );
        // 目标路径与 provider 名无关，仍是通道声明的常量路径
        assert_eq!(
            writer.target_path(),
            home.join(DeliveryChannel::OpenCode.relative_target())
        );
    }

    #[test]
    fn resolve_for_defaults_opencode_provider_and_skips_model() {
        let home = Path::new("/tmp/nobody");
        let writer = resolve_for(DeliveryChannel::OpenCode, home, "https://x").unwrap();
        assert_eq!(
            writer.field_names(),
            vec![
                "provider.keyrelay.options.apiKey",
                "provider.keyrelay.options.baseURL"
            ],
            "默认 provider 名 + 不写 model"
        );
    }

    #[test]
    fn resolve_for_binding_rejects_empty_provider_id() {
        let home = Path::new("/tmp/nobody");
        for bad in ["", "   "] {
            // `Box<dyn DeliveryWriter>` 不实现 `Debug`，因此用 match 而不是 `unwrap_err()`
            match resolve_for_binding(DeliveryChannel::OpenCode, home, "https://x", bad, None) {
                Err(err) => {
                    assert!(matches!(err, Error::Inject { .. }), "{bad:?}");
                    assert!(err.to_string().contains("provider id"), "{err}");
                }
                Ok(_) => panic!("provider_id={bad:?} 应当被拒绝"),
            }
        }
        // 其余通道不受 provider_id 影响（它们根本没有 provider 概念）
        for channel in [
            DeliveryChannel::CodexAuthJson,
            DeliveryChannel::ClaudeCodeSettings,
            DeliveryChannel::ShellBlock,
            DeliveryChannel::GeminiCli,
        ] {
            assert!(
                resolve_for_binding(channel, home, "https://x", "", None).is_ok(),
                "{} 不该被 provider_id 校验误伤",
                channel.as_str()
            );
        }
    }

    #[test]
    fn channel_roundtrip_and_agent_id() {
        for channel in DeliveryChannel::ALL {
            assert_eq!(DeliveryChannel::parse(channel.as_str()).unwrap(), channel);
            assert!(!channel.agent_id().is_empty());
            assert_eq!(
                DeliveryChannel::from_agent_id(channel.agent_id()),
                Some(channel),
                "agent_id 的逆映射必须自洽"
            );
        }
        assert_eq!(DeliveryChannel::from_agent_id("nope"), None);
        assert!(matches!(
            DeliveryChannel::parse("nope"),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn every_channel_resolves() {
        let home = Path::new("/tmp/nobody");
        for channel in DeliveryChannel::ALL {
            let writer = resolve_for(channel, home, "https://relay.example.com")
                .unwrap_or_else(|e| panic!("{} 应可解析: {e}", channel.as_str()));
            assert_eq!(writer.channel(), channel);
            assert!(
                writer.target_path().starts_with(home),
                "{} 的目标应落在 home 内",
                channel.as_str()
            );
        }
    }

    #[test]
    fn shell_block_target_is_platform_specific() {
        let home = Path::new("/tmp/nobody");
        let writer = resolve_for(DeliveryChannel::ShellBlock, home, "https://x").unwrap();
        let expected = shell_block::ShellSyntax::for_current_platform().default_rc_relative_path();
        assert_eq!(writer.target_path(), home.join(expected));
    }

    #[test]
    fn masked_and_literal_fields() {
        let masked = masked_field("OPENAI_API_KEY", "sk-0123456789abcdef");
        assert_eq!(masked.key, "OPENAI_API_KEY");
        assert_eq!(masked.masked, "…cdef");

        let literal = literal_field("auth_mode", "apikey");
        assert_eq!(literal.masked, "apikey");

        let text = format!("{:?}", vec![masked]);
        assert!(!text.contains("sk-0123"), "{text}");
    }

    #[test]
    fn diff_preview_never_leaks_secret() {
        let secret = "sk-0123456789abcdef";
        let before = "{\n  \"OPENAI_API_KEY\": \"sk-OLDSECRET0123456\"\n}\n";
        let after = format!("{{\n  \"OPENAI_API_KEY\": \"{secret}\"\n}}\n");

        let preview = diff_preview(before, &after, secret);
        assert!(!preview.contains(secret), "{preview}");
        assert!(!preview.contains("sk-0123"), "{preview}");
        assert!(preview.contains("…cdef"), "{preview}");
        assert!(preview.contains("+ "), "{preview}");
        assert!(preview.contains("- "), "{preview}");
    }

    #[test]
    fn diff_preview_scrubs_non_target_secrets_too() {
        // 文件里本就有别的明文密钥（用户自己的），也不能带出去
        let before = "{\n  \"OTHER\": \"sk-leaked-somewhere-else\"\n}\n";
        let after =
            "{\n  \"OTHER\": \"sk-leaked-somewhere-else\",\n  \"OPENAI_API_KEY\": \"sk-new\"\n}\n";
        let preview = diff_preview(before, after, "sk-new");
        assert!(!preview.contains("sk-leaked"), "{preview}");
    }

    #[test]
    fn diff_preview_reports_no_change() {
        assert_eq!(diff_preview("a\n", "a\n", "s"), "(无变化)\n");
        assert_eq!(diff_preview("", "", "s"), "(无变化)\n");
    }

    #[test]
    fn diff_ignores_trailing_newline_only_difference() {
        let (tag, line) = diff_lines("a\n", "a").into_iter().next().unwrap();
        assert_eq!((tag, line.as_str()), (' ', "a"));
    }

    #[test]
    fn consent_state_is_granted() {
        assert!(ConsentState::Granted { granted_at: 1 }.is_granted());
        assert!(!ConsentState::Missing.is_granted());
        assert!(!ConsentState::Revoked { revoked_at: 1 }.is_granted());
    }
}
