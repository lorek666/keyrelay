//! `mock-agent` 子命令：只读解析注入产物，校验密钥字段在（mock 首 token）。
//!
//! **只读**：不写、不创建文件、不联网。按通道分流（11 通道，M14-S1 起）：
//! - JSON 通道（codex / claude-code / opencode(-jsonc) / claude-desktop / pi）：`serde_json` 解析后定位密钥字段；
//! - dotenv 通道（gemini-cli）：行级扫描 `GEMINI_API_KEY=`；
//! - TOML 通道（grok-build）：行级扫描 `[models.custom]` 段内 `api_key =`；
//! - 标记块通道（openclaw / hermes / mcode）：定位受管块后校验密钥行。
//!
//! 退出码：0 字段在 / 1 字段缺失 / 2 文件不存在或解析失败。

use std::path::{Path, PathBuf};

use keyrelay_core::delivery::{hermes, mcode, openclaw, DeliveryChannel};

/// mock 校验结论。`main` 据此映射退出码。
#[derive(Debug)]
pub enum MockOutcome {
    /// 密钥字段在且非空（= mock 首 token 成功）→ exit 0
    Ok,
    /// 解析成功但密钥字段缺失或空 → exit 1
    KeyMissing(String),
    /// 文件不存在 / 解析失败 / 块不完整 → exit 2
    Fatal(String),
}

/// 按 channel 校验 `home/<relative_target>` 里的密钥字段。
pub fn check(channel: DeliveryChannel, home: &Path) -> MockOutcome {
    let target: PathBuf = home.join(channel.relative_target());
    let text = match std::fs::read_to_string(&target) {
        Ok(t) => t,
        Err(e) => {
            return MockOutcome::Fatal(format!(
                "配置文件不存在或不可读: {}: {}",
                target.display(),
                e
            ))
        }
    };
    if text.trim().is_empty() {
        return MockOutcome::Fatal(format!("配置文件为空: {}", target.display()));
    }
    match channel {
        DeliveryChannel::CodexAuthJson => check_json_top_level(&text, "OPENAI_API_KEY"),
        // M25-S1：codex-config 不含密钥（sk 仍走 auth.json），
        // mock-agent 校验 base_url + wire_api 字段在 ⇒ 注入产物结构正确。
        // 与 codex-auth-json 配套投递时，密钥校验由 codex-auth-json 那条负责。
        DeliveryChannel::CodexConfig => check_codex_config_shape(&text),
        DeliveryChannel::ClaudeCodeSettings | DeliveryChannel::ClaudeDesktop => {
            check_json_nested(&text, &["env", "ANTHROPIC_AUTH_TOKEN"])
        }
        DeliveryChannel::OpenCode | DeliveryChannel::OpenCodeJsonc => {
            check_json_nested(&text, &["provider", "keyrelay", "options", "apiKey"])
        }
        DeliveryChannel::GeminiCli => check_dotenv_key(&text, "GEMINI_API_KEY"),
        DeliveryChannel::GrokBuild => check_toml_key(&text, "api_key"),
        DeliveryChannel::OpenClaw => check_openclaw(&text),
        DeliveryChannel::Hermes => {
            check_managed_block(&text, hermes::BLOCK_BEGIN, hermes::BLOCK_END, "api_key")
        }
        DeliveryChannel::MCode => {
            check_managed_block(&text, mcode::BLOCK_BEGIN, mcode::BLOCK_END, "api_key")
        }
        DeliveryChannel::Pi => check_json_nested(&text, &["keyrelay", "api_key"]),
        DeliveryChannel::Cursor => check_json_top_level(&text, "OPENAI_API_KEY"),
        DeliveryChannel::Cline => check_cline_providers(&text),
        DeliveryChannel::QwenCode => check_json_nested(&text, &["model", "apiKey"]),
        DeliveryChannel::DeepSeek => check_json_top_level(&text, "apiKey"),
        DeliveryChannel::Trae => check_json_top_level(&text, "apiKey"),
        DeliveryChannel::MiMoCode => check_json_nested(&text, &["providers", "keyrelay", "apiKey"]),
        DeliveryChannel::ClineDesktop => {
            check_json_nested(&text, &["providers", "keyrelay", "settings", "apiKey"])
        }
        DeliveryChannel::DeepSeekHarness => check_yaml_ref_key(&text, "KEYRELAY_API_KEY"),
    }
}

/// openclaw 双形态：干净文件写结构化 JSON（`models.providers.keyrelay.api_key`），
/// 带注释的文件写 JSON5 标记块。先试 JSON 嵌套，失败（KeyMissing 或 JSON 解析 Fatal）
/// 再回退块标记 —— 两种形态都能认。
fn check_openclaw(text: &str) -> MockOutcome {
    match check_json_nested(text, &["models", "providers", "keyrelay", "api_key"]) {
        MockOutcome::Ok => MockOutcome::Ok,
        // 字段缺失或 JSON 解析失败：可能是块形态（带注释的 JSON5 serde 解析不了），回退
        _ => check_managed_block(text, openclaw::BLOCK_BEGIN, openclaw::BLOCK_END, "api_key"),
    }
}

/// 顶层 JSON 键（codex auth.json 的 `OPENAI_API_KEY`）。
fn check_json_top_level(text: &str, key: &str) -> MockOutcome {
    let v: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => return MockOutcome::Fatal(format!("JSON 解析失败: {e}")),
    };
    match v.get(key).and_then(|x| x.as_str()) {
        Some(s) if !s.is_empty() => MockOutcome::Ok,
        Some(_) => MockOutcome::KeyMissing(format!("{key} 为空字符串")),
        None => MockOutcome::KeyMissing(format!("缺少 {key} 字段")),
    }
}

/// 嵌套 JSON 路径（claude 的 `env.ANTHROPIC_AUTH_TOKEN`、opencode 的
/// `provider.keyrelay.options.apiKey`）。
fn check_json_nested(text: &str, path: &[&str]) -> MockOutcome {
    let v: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => return MockOutcome::Fatal(format!("JSON 解析失败: {e}")),
    };
    let mut cur = &v;
    for seg in path {
        cur = match cur.get(seg) {
            Some(x) => x,
            None => return MockOutcome::KeyMissing(format!("缺少 {} 字段", path.join("."))),
        };
    }
    match cur.as_str() {
        Some(s) if !s.is_empty() => MockOutcome::Ok,
        Some(_) => MockOutcome::KeyMissing(format!("{} 为空字符串", path.join("."))),
        None => MockOutcome::KeyMissing(format!("{} 不是字符串", path.join("."))),
    }
}

/// Cline (VS Code) providers 数组：找 `id == "keyrelay"` 的条目里的 `apiKey`。
fn check_cline_providers(text: &str) -> MockOutcome {
    let v: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => return MockOutcome::Fatal(format!("JSON 解析失败: {e}")),
    };
    let providers = match v.get("providers").and_then(|p| p.as_array()) {
        Some(arr) => arr,
        None => return MockOutcome::KeyMissing("缺少 providers 字段".to_string()),
    };
    for entry in providers {
        if entry.get("id").and_then(|i| i.as_str()) == Some("keyrelay") {
            return match entry.get("apiKey").and_then(|k| k.as_str()) {
                Some(s) if !s.is_empty() => MockOutcome::Ok,
                Some(_) => MockOutcome::KeyMissing("apiKey 为空字符串".to_string()),
                None => MockOutcome::KeyMissing("缺少 apiKey 字段".to_string()),
            };
        }
    }
    MockOutcome::KeyMissing("providers 数组中缺少 keyrelay 条目".to_string())
}

/// YAML `refs:` 段行级扫描：找 `  KEYRELAY_API_KEY: ...`（DeepSeek Harness）。
///
/// 与 `dsh.rs` 的写入形态对齐：在 `refs:` 段内找 `KEYRELAY_API_KEY:` 行。
fn check_yaml_ref_key(text: &str, key_name: &str) -> MockOutcome {
    let pattern = format!("{key_name}:");
    let mut in_refs = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("refs:") {
            in_refs = true;
            continue;
        }
        // 遇到下一个顶层段（非缩进行且非空行）→ refs 段结束
        if in_refs && !line.starts_with(' ') && !line.starts_with('\t') && !trimmed.is_empty() {
            in_refs = false;
        }
        if in_refs && trimmed.starts_with(&pattern) {
            let value = trimmed[pattern.len()..].trim();
            if !value.is_empty() {
                return MockOutcome::Ok;
            }
            return MockOutcome::KeyMissing(format!("{key_name} 为空字符串"));
        }
    }
    MockOutcome::KeyMissing(format!("refs 段中缺少 {key_name}"))
}

/// M25-S1：codex-config 通道的 mock-agent 校验。
///
/// **不含密钥**（sk 走 `~/.codex/auth.json`，由 codex-auth-json 通道负责）。
/// 这里只校验「注入产物结构对」：
/// - 顶部 `model_provider = "custom"` 在；
/// - 段 `[model_providers.custom]` 在；
/// - 段内 `base_url = "..."` 在（非空）；
/// - 段内 `wire_api = "responses"` 在。
///
/// 不解析 TOML（与 grok-build / hermes 等通道同口径，行级扫描）。
fn check_codex_config_shape(text: &str) -> MockOutcome {
    let mut saw_provider_top = false;
    let mut in_provider_section = false;
    let mut saw_base_url = false;
    let mut saw_wire_api = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        // 进入/退出段
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_provider_section = trimmed == "[model_providers.custom]";
            continue;
        }
        if in_provider_section {
            if trimmed.starts_with("base_url") && trimmed.contains('=') {
                let value = trimmed.split('=').nth(1).unwrap_or("").trim();
                if value.is_empty() {
                    return MockOutcome::KeyMissing("base_url 为空字符串".into());
                }
                saw_base_url = true;
            }
            if trimmed.starts_with("wire_api") && trimmed.contains('=') {
                let value = trimmed.split('=').nth(1).unwrap_or("").trim();
                if value.is_empty() {
                    return MockOutcome::KeyMissing("wire_api 为空字符串".into());
                }
                saw_wire_api = true;
            }
        } else if trimmed.starts_with("model_provider") && trimmed.contains('=') {
            saw_provider_top = true;
        }
    }
    if !saw_provider_top {
        return MockOutcome::KeyMissing("缺少顶部 model_provider 字段".into());
    }
    if !in_provider_section && !saw_base_url && !saw_wire_api {
        // 走完都没进过段：段不在
        return MockOutcome::KeyMissing("缺少 [model_providers.custom] 段".into());
    }
    if !saw_base_url {
        return MockOutcome::KeyMissing("段内缺少 base_url 字段".into());
    }
    if !saw_wire_api {
        return MockOutcome::KeyMissing("段内缺少 wire_api 字段".into());
    }
    MockOutcome::Ok
}

/// dotenv 行级扫描：找 `GEMINI_API_KEY=...`（允许 `export ` 前缀与引号值）。
///
/// 与 `gemini_cli.rs` 的写入形态对齐：行首（去前导空白后）`GEMINI_API_KEY=` 或
/// `export GEMINI_API_KEY=`。不认注释行（`#`）与别的键（`MY_GEMINI_API_KEY=`）。
fn check_dotenv_key(text: &str, key: &str) -> MockOutcome {
    let prefix_eq = format!("{key}=");
    let prefix_export = format!("export {key}=");
    for raw in text.lines() {
        let line = raw.trim_start();
        if line.starts_with('#') {
            continue;
        }
        let value = if let Some(rest) = line.strip_prefix(&prefix_export) {
            rest
        } else if let Some(rest) = line.strip_prefix(&prefix_eq) {
            rest
        } else {
            continue;
        };
        let unquoted = strip_dotenv_quotes(value);
        if unquoted.is_empty() {
            return MockOutcome::KeyMissing(format!("{key} 为空"));
        }
        return MockOutcome::Ok;
    }
    MockOutcome::KeyMissing(format!("未找到 {key} 赋值行"))
}

/// TOML 行级扫描：找 `api_key = "..."`（grok-build 的 `[models.custom]` 段）。
///
/// 与 `grok_build.rs` 的写入形态对齐：`api_key = "sk-xxx"`（`=` 两侧可有空白）。
/// 跳过注释（`#`）与段头（`[...]`）；不认 `api_key_extra =`（键名必须精确匹配后接 `=`）。
fn check_toml_key(text: &str, key: &str) -> MockOutcome {
    for raw in text.lines() {
        let line = raw.trim_start();
        if line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        let rest = match line.strip_prefix(key) {
            Some(r) => r.trim_start(),
            None => continue,
        };
        let value = match rest.strip_prefix('=') {
            Some(v) => v.trim(),
            None => continue, // `api_key_extra` 等键名前缀相同但后接非 `=`，跳过
        };
        let unquoted = strip_dotenv_quotes(value);
        if !unquoted.is_empty() {
            return MockOutcome::Ok;
        }
    }
    MockOutcome::KeyMissing(format!("未找到 {key} 赋值行"))
}

/// 剥掉值两端的引号（单/双），与 dotenv / TOML / YAML / JSON5 写入口径一致。
fn strip_dotenv_quotes(s: &str) -> &str {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// 受管块（openclaw / hermes / mcode）：定位块后校验密钥字段行在块内。
///
/// `field_marker`：三者都用 `api_key`（块内行形如 `"api_key": "…"` / `api_key: "…"`，
/// 子串匹配即可，但要去掉注释行）。openclaw 用 `// >>> keyrelay >>>` 标记，
/// hermes / mcode 用 `# >>> keyrelay >>>` 标记（各自模块的 `BLOCK_BEGIN`/`BLOCK_END`）。
fn check_managed_block(text: &str, begin: &str, end: &str, field_marker: &str) -> MockOutcome {
    let begins = line_starts_of(text, begin);
    let ends = line_starts_of(text, end);
    if begins.is_empty() && ends.is_empty() {
        return MockOutcome::Fatal(format!("找不到受管块标记（{begin} / {end}）"));
    }
    if begins.len() != 1 || ends.len() != 1 {
        return MockOutcome::Fatal(format!(
            "受管块不完整：{begin} ×{} / {end} ×{}",
            begins.len(),
            ends.len()
        ));
    }
    let (b, e) = (begins[0], ends[0]);
    if e <= b {
        return MockOutcome::Fatal("受管块结束标记在开始标记之前".into());
    }
    let block = &text[b..e];
    // 块内找密钥字段行（非注释）
    for raw in block.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.contains(field_marker) {
            // 进一步确认不是「字段: 空」/「export X=""」
            if !is_empty_value(line, field_marker) {
                return MockOutcome::Ok;
            }
        }
    }
    MockOutcome::KeyMissing(format!("受管块内未找到非空的 {field_marker} 字段"))
}

/// `text` 里 marker 所在**行首**的字节偏移（行首 = 前面只有空白/换行/文件头）。
fn line_starts_of(text: &str, marker: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = text[from..].find(marker) {
        let at = from + rel;
        let mut head = at;
        while head > 0 && matches!(bytes[head - 1], b' ' | b'\t') {
            head -= 1;
        }
        if head == 0 || bytes[head - 1] == b'\n' {
            out.push(head);
        }
        from = at + marker.len();
    }
    out
}

/// 判断「字段行」是否是空值（`apiKey: ""` / `export OPENAI_API_KEY=""`）。
fn is_empty_value(line: &str, _marker: &str) -> bool {
    let after_eq = line
        .split_once('=')
        .map(|(_, v)| v)
        .or_else(|| line.split_once(':').map(|(_, v)| v))
        .unwrap_or("");
    strip_dotenv_quotes(after_eq).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyrelay_core::delivery::DeliveryChannel;

    fn tmp_home() -> tempfile::TempDir {
        tempfile::tempdir().expect("tmp")
    }

    #[test]
    fn codex_ok_when_key_present() {
        let d = tmp_home();
        let p = d.path().join(".codex").join("auth.json");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, r#"{"auth_mode":"apikey","OPENAI_API_KEY":"sk-xyz"}"#).unwrap();
        assert!(matches!(
            check(DeliveryChannel::CodexAuthJson, d.path()),
            MockOutcome::Ok
        ));
    }

    #[test]
    fn codex_missing_when_key_absent() {
        let d = tmp_home();
        let p = d.path().join(".codex").join("auth.json");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, r#"{"auth_mode":"apikey"}"#).unwrap();
        assert!(matches!(
            check(DeliveryChannel::CodexAuthJson, d.path()),
            MockOutcome::KeyMissing(_)
        ));
    }

    #[test]
    fn fatal_when_file_missing() {
        let d = tmp_home();
        assert!(matches!(
            check(DeliveryChannel::CodexAuthJson, d.path()),
            MockOutcome::Fatal(_)
        ));
    }

    #[test]
    fn fatal_when_json_unparseable() {
        let d = tmp_home();
        let p = d.path().join(".codex").join("auth.json");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "not json").unwrap();
        assert!(matches!(
            check(DeliveryChannel::CodexAuthJson, d.path()),
            MockOutcome::Fatal(_)
        ));
    }

    #[test]
    fn claude_ok_when_token_nested() {
        let d = tmp_home();
        let p = d.path().join(".claude").join("settings.json");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            r#"{"env":{"ANTHROPIC_AUTH_TOKEN":"sk-abc","ANTHROPIC_BASE_URL":"https://x"}}"#,
        )
        .unwrap();
        assert!(matches!(
            check(DeliveryChannel::ClaudeCodeSettings, d.path()),
            MockOutcome::Ok
        ));
    }

    #[test]
    fn opencode_ok_when_provider_keyrelay_apikey_present() {
        let d = tmp_home();
        let p = d
            .path()
            .join(".config")
            .join("opencode")
            .join("opencode.json");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            r#"{"provider":{"keyrelay":{"options":{"apiKey":"sk-oc","baseURL":"https://x"}}}}"#,
        )
        .unwrap();
        assert!(matches!(
            check(DeliveryChannel::OpenCode, d.path()),
            MockOutcome::Ok
        ));
    }

    #[test]
    fn gemini_ok_with_export_prefix_and_quotes() {
        let d = tmp_home();
        let p = d.path().join(".gemini").join(".env");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "export GEMINI_API_KEY=\"sk-gem\"\n").unwrap();
        assert!(matches!(
            check(DeliveryChannel::GeminiCli, d.path()),
            MockOutcome::Ok
        ));
    }

    #[test]
    fn gemini_missing_when_only_other_keys() {
        let d = tmp_home();
        let p = d.path().join(".gemini").join(".env");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "MY_GEMINI_API_KEY=sk-x\nGEMINI_API_KEY_EXTRA=sk-y\n").unwrap();
        assert!(matches!(
            check(DeliveryChannel::GeminiCli, d.path()),
            MockOutcome::KeyMissing(_)
        ));
    }

    #[test]
    fn claude_desktop_ok_when_env_token_nested() {
        let d = tmp_home();
        let p = d
            .path()
            .join(DeliveryChannel::ClaudeDesktop.relative_target());
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            r#"{"env":{"ANTHROPIC_AUTH_TOKEN":"sk-cd","ANTHROPIC_BASE_URL":"https://x"}}"#,
        )
        .unwrap();
        assert!(matches!(
            check(DeliveryChannel::ClaudeDesktop, d.path()),
            MockOutcome::Ok
        ));
    }

    #[test]
    fn grok_build_ok_when_apikey_in_models_custom() {
        let d = tmp_home();
        let p = d.path().join(DeliveryChannel::GrokBuild.relative_target());
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            "[models.custom]\napi_key = \"sk-grok\"\nbase_url = \"https://x\"\n",
        )
        .unwrap();
        assert!(matches!(
            check(DeliveryChannel::GrokBuild, d.path()),
            MockOutcome::Ok
        ));
    }

    #[test]
    fn grok_build_rejects_api_key_extra_prefix() {
        let d = tmp_home();
        let p = d.path().join(DeliveryChannel::GrokBuild.relative_target());
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        // `api_key_extra` 不应被当作 `api_key` 命中（键名精确匹配后接 `=`）
        std::fs::write(&p, "[models.custom]\napi_key_extra = \"sk-x\"\n").unwrap();
        assert!(matches!(
            check(DeliveryChannel::GrokBuild, d.path()),
            MockOutcome::KeyMissing(_)
        ));
    }

    #[test]
    fn openclaw_ok_when_structured_json() {
        // --smoke apply 对干净文件写结构化 JSON（models.providers.keyrelay.api_key）
        let d = tmp_home();
        let p = d.path().join(DeliveryChannel::OpenClaw.relative_target());
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            r#"{"models":{"providers":{"keyrelay":{"api_key":"sk-oclaw","base_url":"https://x"}}}}"#,
        )
        .unwrap();
        assert!(matches!(
            check(DeliveryChannel::OpenClaw, d.path()),
            MockOutcome::Ok
        ));
    }

    #[test]
    fn openclaw_ok_when_json5_block_form() {
        // 带注释的文件走 JSON5 标记块形态（serde 解析不了 ⇒ 回退块标记）
        let d = tmp_home();
        let p = d.path().join(DeliveryChannel::OpenClaw.relative_target());
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let block = format!(
            "{{\n  {}\n  \"api_key\": \"sk-oclaw\"\n  {}\n}}\n",
            openclaw::BLOCK_BEGIN,
            openclaw::BLOCK_END
        );
        std::fs::write(&p, &block).unwrap();
        assert!(matches!(
            check(DeliveryChannel::OpenClaw, d.path()),
            MockOutcome::Ok
        ));
    }

    #[test]
    fn hermes_ok_when_apikey_in_yaml_block() {
        let d = tmp_home();
        let p = d.path().join(DeliveryChannel::Hermes.relative_target());
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let block = format!(
            "{}\napi_key: \"sk-hermes\"\nbase_url: \"https://x\"\n{}\n",
            hermes::BLOCK_BEGIN,
            hermes::BLOCK_END
        );
        std::fs::write(&p, &block).unwrap();
        assert!(matches!(
            check(DeliveryChannel::Hermes, d.path()),
            MockOutcome::Ok
        ));
    }

    #[test]
    fn mcode_ok_when_apikey_in_yaml_block() {
        let d = tmp_home();
        let p = d.path().join(DeliveryChannel::MCode.relative_target());
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let block = format!(
            "{}\napi_key: \"sk-mcode\"\n{}\n",
            mcode::BLOCK_BEGIN,
            mcode::BLOCK_END
        );
        std::fs::write(&p, &block).unwrap();
        assert!(matches!(
            check(DeliveryChannel::MCode, d.path()),
            MockOutcome::Ok
        ));
    }

    #[test]
    fn pi_ok_when_apikey_nested_under_keyrelay() {
        let d = tmp_home();
        let p = d.path().join(DeliveryChannel::Pi.relative_target());
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            r#"{"keyrelay":{"api_key":"sk-pi","base_url":"https://x"}}"#,
        )
        .unwrap();
        assert!(matches!(
            check(DeliveryChannel::Pi, d.path()),
            MockOutcome::Ok
        ));
    }

    #[test]
    fn managed_block_fatal_when_markers_unbalanced() {
        let d = tmp_home();
        let p = d.path().join(DeliveryChannel::Hermes.relative_target());
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        // 只有开始标记、没有结束标记 ⇒ Fatal
        std::fs::write(&p, format!("{}\napi_key: x\n", hermes::BLOCK_BEGIN)).unwrap();
        assert!(matches!(
            check(DeliveryChannel::Hermes, d.path()),
            MockOutcome::Fatal(_)
        ));
    }
}
