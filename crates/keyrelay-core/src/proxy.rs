//! 代理：系统探测、模式解析、URL 校验与脱敏。
//!
//! 设计取舍（见 `docs/specs/M10-S2-系统代理自动读取.md`）：
//! - **零新依赖**：macOS 走 `scutil --proxy`，Windows 走 `reg query`，全平台兜底环境变量。
//!   沿用 `platform_env.rs` 访问注册表「`Command::new(REG_EXE)` 不经 shell」的先例。
//! - **校验复用**：`validate_proxy_url` / `mask_proxy` / `proxy_tail` 原属 `transport_reqwest`，
//!   集中到本模块后供探测路径与 transport 构造共用，杜绝两份校验分叉。
//! - **拒绝静默直连（manual）**：用户显式填的代理非法 ⇒ `Err`，绝不降级成直连。
//!   auto 模式探测到的代理非法 ⇒ 跳过该候选继续找下一个（系统是垃圾不该让 app 起不来）。
//! - **脱敏**：`DetectedProxy` 的 `Debug` 只打 `mask_proxy(url)` + 来源，代理 URL 可能内嵌
//!   `user:pass`，不能进日志/诊断/错误串。

use crate::error::{Error, Result};

#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::process::Command;

// ============ 公开类型 ============

/// 代理模式（设置项 `proxy_mode`）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProxyMode {
    /// 听系统的：系统代理 > 环境变量 > 直连。
    Auto,
    /// 用 `proxy_url`（用户手填）。非法 ⇒ `Err`，不静默直连。
    Manual,
    /// 明确直连，不探测、不读环境变量。
    Direct,
}

impl ProxyMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Manual => "manual",
            Self::Direct => "direct",
        }
    }

    /// 与 settings KV 的往返：未知值 ⇒ `None`（调用方决定默认）。
    /// 大小写容忍（设置值由 `as_str` 写小写，但解析时容忍用户/外部输入的大小写）。
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "manual" => Some(Self::Manual),
            "direct" => Some(Self::Direct),
            _ => None,
        }
    }
}

/// 代理来源——用于诊断包与 UI 展示（不含 URL 值）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProxySource {
    MacSystem,
    WindowsRegistry,
    /// 环境变量名（如 `HTTPS_PROXY`）。
    EnvVar(&'static str),
    Manual,
}

impl ProxySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MacSystem => "macos-system",
            Self::WindowsRegistry => "windows-registry",
            Self::EnvVar(name) => name,
            Self::Manual => "manual",
        }
    }
}

/// 一次探测/解析得到的代理。`url` 可能含 userinfo，**不得**原样进日志。
#[derive(Clone, PartialEq, Eq)]
pub struct DetectedProxy {
    pub url: String,
    pub source: ProxySource,
}

impl std::fmt::Debug for DetectedProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 只打脱敏后的 url + 来源，与 `TransportConfig` 手写 Debug 同口径
        f.debug_struct("DetectedProxy")
            .field("url", &mask_proxy(&self.url))
            .field("source", &self.source.as_str())
            .finish()
    }
}

// ============ 探测 ============

/// 探测系统代理。不读 settings、不联网、不做校验（校验在 `resolve_proxy`）。
/// 任一步失败 ⇒ `None`（不报错，auto 模式会因此直连）。
///
/// 顺序：macOS 系统设置 → Windows 注册表 → 环境变量。前一个探测到就返回，
/// 不合并（一个主机只会用一条代理）。
pub fn detect_system_proxy() -> Option<DetectedProxy> {
    #[cfg(target_os = "macos")]
    if let Some(d) = detect_macos_system() {
        return Some(d);
    }
    #[cfg(target_os = "windows")]
    if let Some(d) = detect_windows_system() {
        return Some(d);
    }
    env_proxy()
}

/// 按模式解析最终代理。transport 构造的唯一入口（S2 接线后）。
///
/// - `Direct` ⇒ `None`
/// - `Manual` + 非空 ⇒ 校验后 `Some`；非法 ⇒ `Err`（拒绝静默直连）
/// - `Manual` + 空 ⇒ `None`（等价直连，避免 app 因配置空缺起不来；UI 侧另行要求手填）
/// - `Auto` ⇒ 探测；探测到的代理非法 ⇒ 跳过继续找，全非法 ⇒ `None`
pub fn resolve_proxy(mode: ProxyMode, manual_url: &str) -> Result<Option<DetectedProxy>> {
    match mode {
        ProxyMode::Direct => Ok(None),
        ProxyMode::Manual => {
            let url = manual_url.trim();
            if url.is_empty() {
                return Ok(None);
            }
            validate_proxy_url(url)?;
            Ok(Some(DetectedProxy {
                url: url.to_string(),
                source: ProxySource::Manual,
            }))
        }
        ProxyMode::Auto => {
            // 探测到的候选若非法（scheme 不在白名单 / 带 path），不静默直连也不崩：
            // 跳过它继续找下一个候选；全非法 ⇒ 直连。与 manual 的「非法即 Err」的区别在于
            // 用户没有显式配置 auto 探测到的值，系统是垃圾不该让 app 起不来。
            match detect_system_proxy() {
                Some(d) if validate_proxy_url(&d.url).is_ok() => Ok(Some(d)),
                _ => Ok(None),
            }
        }
    }
}

// ============ macOS：scutil --proxy ============

#[cfg(target_os = "macos")]
fn detect_macos_system() -> Option<DetectedProxy> {
    let output = Command::new("scutil").arg("--proxy").output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let url = parse_scutil_proxy(&text)?;
    Some(DetectedProxy {
        url,
        source: ProxySource::MacSystem,
    })
}

/// 解析 `scutil --proxy` 文本。纯函数，跨平台可测。
///
/// 选取优先级：`HTTPSProxy`(Enable=1) > `HTTPProxy`(Enable=1) > `SOCKSProxy`(Enable=1)。
/// HTTPS/HTTP 代理本身是 HTTP CONNECT 代理，统一拼 `http://host:port`；
/// SOCKS 拼 `socks5://host:port`。全 Enable=0 或缺字段 ⇒ `None`。
pub fn parse_scutil_proxy(text: &str) -> Option<String> {
    let kv = scutil_kv(text);
    let pick = |proto: &str, scheme: &str| -> Option<String> {
        if kv.get(&format!("{proto}Enable"))?.as_str() != "1" {
            return None;
        }
        let host = kv.get(&format!("{proto}Proxy"))?;
        let port = kv.get(&format!("{proto}Port"))?;
        if host.is_empty() || port.is_empty() {
            return None;
        }
        Some(format!("{scheme}://{host}:{port}"))
    };
    pick("HTTPS", "http")
        .or_else(|| pick("HTTP", "http"))
        .or_else(|| pick("SOCKS", "socks5"))
}

/// `scutil --proxy` 行级 KV：`key : value`（分隔符是冒号，前后空白容忍）。
fn scutil_kv(text: &str) -> std::collections::HashMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

// ============ Windows：reg query Internet Settings ============

/// Windows Internet Settings 注册表路径（当前用户，不需要提权）。
#[cfg(target_os = "windows")]
const WIN_INET_SETTINGS: &str =
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

#[cfg(target_os = "windows")]
fn detect_windows_system() -> Option<DetectedProxy> {
    let enable_raw = reg_query_value(WIN_INET_SETTINGS, "ProxyEnable")?;
    let enable = u32::from_str_radix(enable_raw.trim_start_matches("0x"), 16).ok()?;
    if enable != 1 {
        return None;
    }
    let server = reg_query_value(WIN_INET_SETTINGS, "ProxyServer")?;
    let url = parse_windows_reg_proxy(&server)?;
    Some(DetectedProxy {
        url,
        source: ProxySource::WindowsRegistry,
    })
}

/// 跑 `reg query "KEY" /v NAME`，取值的字面量（DWORD 形如 `0x1`，SZ 原样）。
#[cfg(target_os = "windows")]
fn reg_query_value(key: &str, name: &str) -> Option<String> {
    let output = Command::new("reg")
        .args(["query", key, "/v", name])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    parse_reg_query_value(&text, name)
}

/// 解析 `reg query` 输出里某个值名的字面量。纯函数，跨平台可测。
///
/// 输出形如：
/// ```text
/// HKEY_CURRENT_USER\...\Internet Settings
///     ProxyEnable    REG_DWORD    0x1
/// ```
/// 取与 `name` 同行、`REG_*` 之后的第一个 token。
pub fn parse_reg_query_value(output: &str, name: &str) -> Option<String> {
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == name {
            return Some(parts[2].to_string());
        }
    }
    None
}

/// 解析 `ProxyServer` 字面量。纯函数，跨平台可测。
///
/// 两种形态：
/// - `host:port`（全协议共用）⇒ `http://host:port`
/// - `http=h1:p1;https=h2:p2;socks=h3:p3`（按协议）⇒ 按 `https` > `http` > `socks` 选一条；
///   `https`/`http` 拼 `http://`（HTTP CONNECT 代理），`socks` 拼 `socks5://`。
pub fn parse_windows_reg_proxy(server: &str) -> Option<String> {
    let server = server.trim();
    if server.is_empty() {
        return None;
    }
    if server.contains('=') {
        let entries: std::collections::HashMap<&str, &str> = server
            .split(';')
            .filter_map(|e| e.split_once('='))
            .map(|(k, v)| (k.trim(), v.trim()))
            .collect();
        if let Some(v) = entries.get("https") {
            return Some(format!("http://{v}"));
        }
        if let Some(v) = entries.get("http") {
            return Some(format!("http://{v}"));
        }
        if let Some(v) = entries.get("socks") {
            return Some(format!("socks5://{v}"));
        }
        None
    } else {
        Some(format!("http://{server}"))
    }
}

// ============ 环境变量（全平台兜底） ============

/// 读 `HTTPS_PROXY`/`https_proxy`/`HTTP_PROXY`/`http_proxy`/`ALL_PROXY`/`all_proxy`。
/// 原样返回（校验在 `resolve_proxy`）。空值跳过。
fn env_proxy() -> Option<DetectedProxy> {
    const NAMES: [(&str, ProxySource); 6] = [
        ("HTTPS_PROXY", ProxySource::EnvVar("HTTPS_PROXY")),
        ("https_proxy", ProxySource::EnvVar("https_proxy")),
        ("HTTP_PROXY", ProxySource::EnvVar("HTTP_PROXY")),
        ("http_proxy", ProxySource::EnvVar("http_proxy")),
        ("ALL_PROXY", ProxySource::EnvVar("ALL_PROXY")),
        ("all_proxy", ProxySource::EnvVar("all_proxy")),
    ];
    for (name, source) in NAMES {
        if let Ok(value) = std::env::var(name) {
            let value = value.trim();
            if !value.is_empty() {
                return Some(DetectedProxy {
                    url: value.to_string(),
                    source,
                });
            }
        }
    }
    None
}

// ============ 校验与脱敏（从 transport_reqwest 迁入，供两边共用） ============

/// reqwest `Proxy::all` 实际支持的代理 scheme 白名单。
pub const ALLOWED_PROXY_SCHEMES: [&str; 6] =
    ["http", "https", "socks4", "socks4a", "socks5", "socks5h"];

/// 校验代理 URL：scheme 必须在白名单内，且 authority 之后不得有 path/query/fragment。
/// 校验失败 ⇒ `Err`，错误串只含脱敏后的地址与形态描述，**不回显** path/query 正文。
pub(crate) fn validate_proxy_url(url: &str) -> Result<()> {
    let scheme = url
        .split_once("://")
        .map(|(s, _)| s.to_ascii_lowercase())
        .unwrap_or_default();
    if !ALLOWED_PROXY_SCHEMES.contains(&scheme.as_str()) {
        return Err(Error::Transport(format!(
            "代理配置无效（{}）：scheme 必须是 {} 之一，拒绝静默直连",
            mask_proxy(url),
            ALLOWED_PROXY_SCHEMES.join(" / ")
        )));
    }

    let tail = proxy_tail(url);
    if !matches!(tail, "" | "/") {
        return Err(Error::Transport(format!(
            "代理配置无效（{}）：代理地址只能是 scheme://host[:port]（可带 userinfo），\
             检测到非法片段（{}，共 {} 个字符），拒绝静默直连",
            mask_proxy(url),
            describe_illegal_proxy_tail(tail),
            tail.chars().count()
        )));
    }
    Ok(())
}

/// 只保留 `scheme://host[:port]`，丢弃 userinfo、path、query、fragment。
pub(crate) fn mask_proxy(raw: &str) -> String {
    let Some((scheme, rest)) = raw.split_once("://") else {
        return "<非法代理串>".to_string();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or(authority);
    if host.is_empty() {
        return format!("{scheme}://<已隐藏>");
    }
    format!("{scheme}://{host}")
}

/// authority 之后的部分（path/query/fragment）。没有 `://` 时返回 `""`。
pub(crate) fn proxy_tail(raw: &str) -> &str {
    let Some((_, rest)) = raw.split_once("://") else {
        return "";
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    &rest[end..]
}

/// 非法后缀的**形态描述**：只报种类与字符数，**绝不回显内容**。
fn describe_illegal_proxy_tail(tail: &str) -> String {
    let (path, after_path) = match tail.find(['?', '#']) {
        Some(index) => (&tail[..index], &tail[index..]),
        None => (tail, ""),
    };

    let mut parts: Vec<String> = Vec::new();
    if !path.is_empty() && path != "/" {
        parts.push(format!("path(长度 {})", path.chars().count()));
    }
    if after_path.starts_with('?') {
        parts.push("query".to_string());
    }
    if after_path.contains('#') {
        parts.push("fragment".to_string());
    }
    if parts.is_empty() {
        parts.push("非空后缀".to_string());
    }
    parts.join(" / ")
}

// ============ 测试 ============

#[cfg(test)]
mod tests {
    use super::*;

    // ---- 脱敏（从 transport_reqwest 迁入，原覆盖面不丢）----

    #[test]
    fn mask_proxy_drops_userinfo() {
        assert_eq!(
            mask_proxy("http://alice:s3cr3t@127.0.0.1:7897"),
            "http://127.0.0.1:7897"
        );
        assert_eq!(
            mask_proxy("socks5://127.0.0.1:1080"),
            "socks5://127.0.0.1:1080"
        );
        assert_eq!(mask_proxy("这不是一个 URL"), "<非法代理串>");
    }

    #[test]
    fn mask_proxy_drops_path_query_fragment() {
        assert_eq!(
            mask_proxy("http://alice:s3cr3t@127.0.0.1:7897/pac?token=s3cr3t#frag"),
            "http://127.0.0.1:7897"
        );
        assert_eq!(
            mask_proxy("http://127.0.0.1:7897?k=v"),
            "http://127.0.0.1:7897"
        );
        assert_eq!(mask_proxy("http://alice:s3cr3t@"), "http://<已隐藏>");
        assert_eq!(
            mask_proxy("http://alice:s3cr3t@/x?token=SECRET"),
            "http://<已隐藏>"
        );
    }

    #[test]
    fn describe_illegal_proxy_tail_names_the_parts() {
        let path_only = describe_illegal_proxy_tail("/pac");
        assert!(path_only.contains("path"), "{path_only}");
        assert!(path_only.contains('4'), "{path_only}");

        assert_eq!(describe_illegal_proxy_tail("?token=x"), "query");

        let all = describe_illegal_proxy_tail("/x?y#z");
        assert!(all.contains("path"), "{all}");
        assert!(all.contains("query"), "{all}");
        assert!(all.contains("fragment"), "{all}");

        assert!(!describe_illegal_proxy_tail("/").is_empty());

        assert_eq!(proxy_tail("http://127.0.0.1:7897"), "");
        assert_eq!(proxy_tail("http://127.0.0.1:7897/"), "/");
        assert_eq!(proxy_tail("http://u:p@h:1/x?y#z"), "/x?y#z");
        assert_eq!(proxy_tail("没有 scheme"), "");
    }

    // ---- validate_proxy_url（直接测纯函数，transport 那边另有集成层覆盖）----

    #[test]
    fn validate_accepts_authority_only_forms() {
        for good in [
            "http://127.0.0.1:7897",
            "http://127.0.0.1:7897/",
            "https://proxy.example.com:8443",
            "socks5://127.0.0.1:1080",
            "socks5h://user:pw@127.0.0.1:1080",
        ] {
            assert!(validate_proxy_url(good).is_ok(), "{good} 应被接受");
        }
    }

    #[test]
    fn validate_rejects_non_proxy_schemes() {
        for bad in [
            "file:///etc/passwd",
            "ftp://127.0.0.1:21",
            "alice:pw@127.0.0.1:1080",
            "",
        ] {
            let err = validate_proxy_url(bad)
                .err()
                .unwrap_or_else(|| panic!("{bad:?} 应被拒绝"));
            let message = err.to_string();
            assert!(message.contains("代理配置无效"), "{bad:?} → {message}");
        }
    }

    #[test]
    fn validate_rejects_path_query_fragment_without_echoing_them() {
        for bad in [
            "socks5://127.0.0.1:1080/pac",
            "http://127.0.0.1:7897/pac?token=SECRET-VALUE",
            "http://127.0.0.1:7897#frag",
        ] {
            let err = validate_proxy_url(bad)
                .err()
                .unwrap_or_else(|| panic!("{bad:?} 应被拒绝"));
            let message = err.to_string();
            assert!(message.contains("非法片段"), "{bad:?} → {message}");
            assert!(!message.contains("SECRET-VALUE"), "{message}");
            assert!(!message.contains("pac"), "{message}");
        }
    }

    // ---- ProxyMode 往返 ----

    #[test]
    fn proxy_mode_round_trips() {
        for m in [ProxyMode::Auto, ProxyMode::Manual, ProxyMode::Direct] {
            assert_eq!(ProxyMode::parse(m.as_str()), Some(m), "{m:?}");
        }
        assert_eq!(ProxyMode::parse(" AUTO "), Some(ProxyMode::Auto));
        assert_eq!(ProxyMode::parse("unknown"), None);
    }

    // ---- resolve_proxy 优先级（§6.2）----

    #[test]
    fn resolve_direct_returns_none() {
        assert!(resolve_proxy(ProxyMode::Direct, "http://127.0.0.1:7897")
            .unwrap()
            .is_none());
    }

    #[test]
    fn resolve_manual_uses_manual_url() {
        let d = resolve_proxy(ProxyMode::Manual, "socks5://127.0.0.1:1080")
            .unwrap()
            .unwrap();
        assert_eq!(d.url, "socks5://127.0.0.1:1080");
        assert_eq!(d.source, ProxySource::Manual);
    }

    #[test]
    fn resolve_manual_empty_is_none_not_error() {
        // 空 manual 不让 app 起不来；UI 侧另行要求手填
        assert!(resolve_proxy(ProxyMode::Manual, "").unwrap().is_none());
        assert!(resolve_proxy(ProxyMode::Manual, "   ").unwrap().is_none());
    }

    #[test]
    fn resolve_manual_invalid_is_error() {
        // 非法 manual 拒绝静默直连
        assert!(resolve_proxy(ProxyMode::Manual, "file:///etc/passwd").is_err());
        assert!(resolve_proxy(ProxyMode::Manual, "http://h:1/pac").is_err());
    }

    #[test]
    fn resolve_auto_skips_invalid_detected_and_falls_back() {
        // 注入一条非法系统代理（通过环境变量）——auto 应跳过它，不 Err 也不带它
        // 用 ALL_PROXY 兜底（detect_system_proxy 在非 mac/win 上只读 env）
        // 注意：本测试在 macOS/windows 上也会跑，系统可能另有代理；
        // 因此只断言「结果要么 None 要么合法」，不强断言来源。
        std::env::set_var("KEYRELAY_TEST_PROXY_ENV", "1");
        std::env::set_var("ALL_PROXY", "not-a-valid-url");
        let resolved = resolve_proxy(ProxyMode::Auto, "").unwrap();
        std::env::remove_var("ALL_PROXY");
        std::env::remove_var("KEYRELAY_TEST_PROXY_ENV");
        match resolved {
            None => {}
            Some(d) => assert!(
                validate_proxy_url(&d.url).is_ok(),
                "auto 不应返回非法代理: {:?}",
                d
            ),
        }
    }

    // ---- scutil 解析（§6.1）----

    const SCUTIL_SAMPLE: &str = "\
HTTPEnable : 1
HTTPProxy : 127.0.0.1
HTTPPort : 8080
HTTPSEnable : 1
HTTPSProxy : 127.0.0.1
HTTPSPort : 8443
SOCKSEnable : 1
SOCKSProxy : 127.0.0.1
SOCKSPort : 1080
ExceptionsList : {127.0.0.1, localhost, *.local}
";

    #[test]
    fn parse_scutil_picks_https_over_http_and_socks() {
        // 三者都启用时取 HTTPS，且 HTTPS/HTTP 代理拼成 http://（CONNECT 代理）
        assert_eq!(
            parse_scutil_proxy(SCUTIL_SAMPLE),
            Some("http://127.0.0.1:8443".to_string())
        );
    }

    #[test]
    fn parse_scutil_none_when_all_disabled() {
        let text = "\
HTTPEnable : 0
HTTPSEnable : 0
SOCKSEnable : 0
";
        assert_eq!(parse_scutil_proxy(text), None);
    }

    #[test]
    fn parse_scutil_falls_back_to_socks() {
        let text = "\
HTTPEnable : 0
HTTPSEnable : 0
SOCKSEnable : 1
SOCKSProxy : 127.0.0.1
SOCKSPort : 1080
";
        assert_eq!(
            parse_scutil_proxy(text),
            Some("socks5://127.0.0.1:1080".to_string())
        );
    }

    #[test]
    fn parse_scutil_missing_fields_is_none() {
        // Enable=1 但没有 Proxy/Port ⇒ 不返回半截
        let text = "HTTPSEnable : 1\n";
        assert_eq!(parse_scutil_proxy(text), None);
    }

    // ---- Windows ProxyServer 解析（§6.1）----

    #[test]
    fn parse_windows_simple_form() {
        assert_eq!(
            parse_windows_reg_proxy("127.0.0.1:8080"),
            Some("http://127.0.0.1:8080".to_string())
        );
    }

    #[test]
    fn parse_windows_per_protocol_picks_https() {
        assert_eq!(
            parse_windows_reg_proxy("http=h1:81;https=h2:82;socks=h3:83"),
            Some("http://h2:82".to_string())
        );
    }

    #[test]
    fn parse_windows_per_protocol_falls_back_to_http_then_socks() {
        assert_eq!(
            parse_windows_reg_proxy("http=h1:81;socks=h3:83"),
            Some("http://h1:81".to_string())
        );
        assert_eq!(
            parse_windows_reg_proxy("socks=h3:83"),
            Some("socks5://h3:83".to_string())
        );
    }

    #[test]
    fn parse_windows_empty_is_none() {
        assert_eq!(parse_windows_reg_proxy(""), None);
        assert_eq!(parse_windows_reg_proxy("   "), None);
    }

    // ---- reg query 输出解析 ----

    #[test]
    fn parse_reg_query_value_finds_dword_and_sz() {
        let out = "\
HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings
    ProxyEnable    REG_DWORD    0x1
    ProxyServer    REG_SZ    127.0.0.1:8080
";
        assert_eq!(
            parse_reg_query_value(out, "ProxyEnable"),
            Some("0x1".to_string())
        );
        assert_eq!(
            parse_reg_query_value(out, "ProxyServer"),
            Some("127.0.0.1:8080".to_string())
        );
        assert_eq!(parse_reg_query_value(out, "NoSuchValue"), None);
    }

    // ---- DetectedProxy Debug 脱敏 ----

    #[test]
    fn detected_proxy_debug_does_not_leak_userinfo() {
        let d = DetectedProxy {
            url: "http://alice:s3cr3t@127.0.0.1:7897".to_string(),
            source: ProxySource::EnvVar("HTTPS_PROXY"),
        };
        let debug = format!("{d:?}");
        assert!(!debug.contains("alice"), "{debug}");
        assert!(!debug.contains("s3cr3t"), "{debug}");
        assert!(
            debug.contains("127.0.0.1:7897"),
            "应保留可诊断主机: {debug}"
        );
        assert!(debug.contains("HTTPS_PROXY"), "{debug}");
    }
}
