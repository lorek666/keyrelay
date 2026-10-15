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

impl DetectedProxy {
    /// 脱敏后的 URL（给 UI 展示用）。含 userinfo 时完全丢弃，只显示 `scheme://host:port`。
    ///
    /// 前端**不拿原始 URL**：`mask_proxy` 在核心层完成，明文不过 IPC 边界。
    pub fn masked_url(&self) -> String {
        mask_proxy(&self.url)
    }
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

/// 探测系统代理：收集所有候选（macOS scutil 三协议 / Windows 注册表三协议 / 环境变量六变量），
/// 按优先级遍历，返回**首个合法**的（`validate_proxy_url` 通过）。全非法或无候选 ⇒ `None`。
///
/// 不读 settings、不联网。IPC（`detect_system_proxy` 命令）与 `resolve_proxy` Auto 分支共用
/// 此函数 ⇒ UI 展示的「检测到」即 auto 模式实际会使用的代理。
///
/// 「首个合法」而非「首个命中」：系统配的代理可能带 path/非法 scheme（垃圾值），auto 模式
/// 跳过它继续找下一个候选，全非法才直连——系统是垃圾不该让 app 起不来（与 manual「非法即 Err」
/// 的区别在于用户没有显式配置 auto 探测到的值）。
pub fn detect_system_proxy() -> Option<DetectedProxy> {
    pick_first_valid(collect_proxy_candidates())
}

/// 从候选列表中取首个合法的（`validate_proxy_url` 通过）。全非法或空 ⇒ `None`。
/// auto 模式「跳过非法继续找下一个」的核心，抽出为纯函数便于确定性测试。
fn pick_first_valid(candidates: Vec<DetectedProxy>) -> Option<DetectedProxy> {
    candidates
        .into_iter()
        .find(|d| validate_proxy_url(&d.url).is_ok())
}

/// 收集所有探测候选，按优先级排序（平台优先于环境变量；平台内 HTTPS>HTTP>SOCKS；
/// 环境变量内 `HTTPS_PROXY`>`https_proxy`>`HTTP_PROXY`>`http_proxy`>`ALL_PROXY`>`all_proxy`）。
/// 不做校验——校验在 `pick_first_valid` 遍历时做。
fn collect_proxy_candidates() -> Vec<DetectedProxy> {
    let mut out = Vec::new();
    #[cfg(target_os = "macos")]
    out.extend(detect_macos_candidates());
    #[cfg(target_os = "windows")]
    out.extend(detect_windows_candidates());
    out.extend(env_proxy_candidates());
    out
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
            // detect_system_proxy 内部已遍历所有候选取首个合法的；全非法 ⇒ None（直连）。
            // 与 manual「非法即 Err」的区别见 detect_system_proxy 文档。
            Ok(detect_system_proxy())
        }
    }
}

// ============ macOS：scutil --proxy ============

#[cfg(target_os = "macos")]
fn detect_macos_candidates() -> Vec<DetectedProxy> {
    let Ok(output) = Command::new("scutil").arg("--proxy").output() else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    parse_scutil_proxy_all(&text)
        .into_iter()
        .map(|url| DetectedProxy {
            url,
            source: ProxySource::MacSystem,
        })
        .collect()
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

/// 解析 `scutil --proxy`，返回所有启用的代理（按 HTTPS > HTTP > SOCKS 顺序）。
/// 纯函数，跨平台可测。供 `detect_macos_candidates` 收集全部候选；
/// `parse_scutil_proxy` 是其「取首个」的便捷视图。
pub fn parse_scutil_proxy_all(text: &str) -> Vec<String> {
    let kv = scutil_kv(text);
    let mut out = Vec::new();
    for (proto, scheme) in [("HTTPS", "http"), ("HTTP", "http"), ("SOCKS", "socks5")] {
        if kv.get(&format!("{proto}Enable")).map(|v| v.as_str()) != Some("1") {
            continue;
        }
        let Some(host) = kv.get(&format!("{proto}Proxy")) else {
            continue;
        };
        let Some(port) = kv.get(&format!("{proto}Port")) else {
            continue;
        };
        if host.is_empty() || port.is_empty() {
            continue;
        }
        out.push(format!("{scheme}://{host}:{port}"));
    }
    out
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
fn detect_windows_candidates() -> Vec<DetectedProxy> {
    let Some(enable_raw) = reg_query_value(WIN_INET_SETTINGS, "ProxyEnable") else {
        return Vec::new();
    };
    let Ok(enable) = u32::from_str_radix(enable_raw.trim_start_matches("0x"), 16) else {
        return Vec::new();
    };
    if enable != 1 {
        return Vec::new();
    }
    let Some(server) = reg_query_value(WIN_INET_SETTINGS, "ProxyServer") else {
        return Vec::new();
    };
    parse_windows_reg_proxy_all(&server)
        .into_iter()
        .map(|url| DetectedProxy {
            url,
            source: ProxySource::WindowsRegistry,
        })
        .collect()
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

/// 解析 `ProxyServer`，返回所有按协议列出的代理（`https` > `http` > `socks` 顺序）。
/// 纯函数，跨平台可测。`parse_windows_reg_proxy` 是其「取首个」的便捷视图。
pub fn parse_windows_reg_proxy_all(server: &str) -> Vec<String> {
    let server = server.trim();
    if server.is_empty() {
        return Vec::new();
    }
    if server.contains('=') {
        let entries: std::collections::HashMap<&str, &str> = server
            .split(';')
            .filter_map(|e| e.split_once('='))
            .map(|(k, v)| (k.trim(), v.trim()))
            .collect();
        let mut out = Vec::new();
        for (key, scheme) in [("https", "http"), ("http", "http"), ("socks", "socks5")] {
            if let Some(v) = entries.get(key) {
                out.push(format!("{scheme}://{v}"));
            }
        }
        out
    } else {
        vec![format!("http://{server}")]
    }
}

// ============ 环境变量（全平台兜底） ============

/// 读 `HTTPS_PROXY`/`https_proxy`/`HTTP_PROXY`/`http_proxy`/`ALL_PROXY`/`all_proxy`。
/// 原样收集所有非空值（校验在 `pick_first_valid` 遍历时做）。供 `collect_proxy_candidates`。
fn env_proxy_candidates() -> Vec<DetectedProxy> {
    const NAMES: [(&str, ProxySource); 6] = [
        ("HTTPS_PROXY", ProxySource::EnvVar("HTTPS_PROXY")),
        ("https_proxy", ProxySource::EnvVar("https_proxy")),
        ("HTTP_PROXY", ProxySource::EnvVar("HTTP_PROXY")),
        ("http_proxy", ProxySource::EnvVar("http_proxy")),
        ("ALL_PROXY", ProxySource::EnvVar("ALL_PROXY")),
        ("all_proxy", ProxySource::EnvVar("all_proxy")),
    ];
    let mut out = Vec::new();
    for (name, source) in NAMES {
        if let Ok(value) = std::env::var(name) {
            let value = value.trim();
            if !value.is_empty() {
                out.push(DetectedProxy {
                    url: value.to_string(),
                    source,
                });
            }
        }
    }
    out
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

    // ---- parse_scutil_proxy_all：收集全部启用协议（§6.1）----

    #[test]
    fn parse_scutil_proxy_all_returns_all_enabled_in_priority_order() {
        let all = parse_scutil_proxy_all(SCUTIL_SAMPLE);
        assert_eq!(
            all,
            vec![
                "http://127.0.0.1:8443".to_string(),   // HTTPS
                "http://127.0.0.1:8080".to_string(),   // HTTP
                "socks5://127.0.0.1:1080".to_string(), // SOCKS
            ]
        );
    }

    #[test]
    fn parse_scutil_proxy_all_skips_disabled_protocols() {
        let text = "\
HTTPSEnable : 0
HTTPEnable : 1
HTTPProxy : 127.0.0.1
HTTPPort : 8080
SOCKSEnable : 0
";
        assert_eq!(
            parse_scutil_proxy_all(text),
            vec!["http://127.0.0.1:8080".to_string()]
        );
    }

    #[test]
    fn parse_scutil_proxy_all_empty_when_all_disabled() {
        assert!(
            parse_scutil_proxy_all("HTTPSEnable : 0\nHTTPEnable : 0\nSOCKSEnable : 0\n").is_empty()
        );
    }

    // ---- parse_windows_reg_proxy_all：收集全部按协议代理 ----

    #[test]
    fn parse_windows_reg_proxy_all_per_protocol_in_priority_order() {
        assert_eq!(
            parse_windows_reg_proxy_all("http=h1:81;https=h2:82;socks=h3:83"),
            vec![
                "http://h2:82".to_string(),   // https 先
                "http://h1:81".to_string(),   // http
                "socks5://h3:83".to_string(), // socks
            ]
        );
    }

    #[test]
    fn parse_windows_reg_proxy_all_simple_form_yields_single() {
        assert_eq!(
            parse_windows_reg_proxy_all("127.0.0.1:8080"),
            vec!["http://127.0.0.1:8080".to_string()]
        );
    }

    #[test]
    fn parse_windows_reg_proxy_all_empty_when_blank() {
        assert!(parse_windows_reg_proxy_all("").is_empty());
        assert!(parse_windows_reg_proxy_all("   ").is_empty());
    }

    // ---- pick_first_valid：auto「跳过非法继续找」的核心（P2-1 guard）----

    #[test]
    fn pick_first_valid_skips_invalid_and_returns_first_valid() {
        // 模拟「HTTPS_PROXY 非法 + HTTP_PROXY 非法 + ALL_PROXY 合法」：
        // auto 应跳过前两个非法候选，取第三个合法的，而非首个命中即直连。
        let cands = vec![
            DetectedProxy {
                url: "file:///etc/passwd".into(),
                source: ProxySource::EnvVar("HTTPS_PROXY"),
            },
            DetectedProxy {
                url: "http://h:1/pac".into(),
                source: ProxySource::EnvVar("HTTP_PROXY"),
            },
            DetectedProxy {
                url: "socks5://127.0.0.1:1080".into(),
                source: ProxySource::EnvVar("ALL_PROXY"),
            },
        ];
        let picked = pick_first_valid(cands).expect("应跳过两个非法取第三个");
        assert_eq!(picked.url, "socks5://127.0.0.1:1080");
        assert_eq!(picked.source, ProxySource::EnvVar("ALL_PROXY"));
    }

    #[test]
    fn pick_first_valid_none_when_all_invalid() {
        let cands = vec![
            DetectedProxy {
                url: "file:///etc/passwd".into(),
                source: ProxySource::EnvVar("HTTPS_PROXY"),
            },
            DetectedProxy {
                url: "http://h:1/pac".into(),
                source: ProxySource::EnvVar("HTTP_PROXY"),
            },
        ];
        assert!(pick_first_valid(cands).is_none());
    }

    #[test]
    fn pick_first_valid_none_when_empty() {
        assert!(pick_first_valid(Vec::new()).is_none());
    }

    #[test]
    fn pick_first_valid_returns_first_when_all_valid() {
        let cands = vec![
            DetectedProxy {
                url: "http://a:1".into(),
                source: ProxySource::EnvVar("HTTPS_PROXY"),
            },
            DetectedProxy {
                url: "http://b:2".into(),
                source: ProxySource::EnvVar("HTTP_PROXY"),
            },
        ];
        let picked = pick_first_valid(cands).expect("全合法应取首个");
        assert_eq!(picked.url, "http://a:1");
    }
}
