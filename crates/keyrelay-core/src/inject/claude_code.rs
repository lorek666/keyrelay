//! Claude Code 注入器占位。
//!
//! 目标文件是 `~/.claude/settings.json` 的 `env` 段：
//! ```json
//! { "env": { "ANTHROPIC_BASE_URL": "...", "ANTHROPIC_AUTH_TOKEN": "..." } }
//! ```
//! 该段**必须写入密钥本体**（Claude Code 不支持 env 变量间接引用），
//! 因此本注入器要等「密钥投递授权 + 钥匙串取用」流程（M1-S2）落地后再实现：
//! 用户需在 UI 上显式同意「把密钥写入该 agent 配置」，且写入内容不得进入日志。
//!
//! 在此之前所有方法返回 [`Error::Unimplemented`]，UI 显示「暂不支持」。

use super::{Binding, Injector, Patch};
use crate::error::{Error, Result};

const NOT_YET: &str = "Claude Code 注入器将在 M1-S2 实现（需先落地密钥投递授权流程）";

#[derive(Debug, Default)]
pub struct ClaudeCodeInjector;

impl Injector for ClaudeCodeInjector {
    fn id(&self) -> &'static str {
        "claude-code"
    }

    fn plan(&self, _binding: &Binding) -> Result<Vec<Patch>> {
        Err(Error::Unimplemented(NOT_YET.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_is_explicit() {
        let err = ClaudeCodeInjector.plan(&Binding {
            base_url: "https://x".into(),
            api_key: "sk-x".into(),
            model: None,
            provider_id: "keyrelay".into(),
        });
        assert!(matches!(err, Err(Error::Unimplemented(_))));
    }
}
