//! B 路凭据通道（M28-S1 / B-191）：Sub2API 的 WebView 登录页把 `auth_token` 写进
//! `localStorage`，本模块负责把这份凭据**安全地接回核心层**。
//!
//! # 这条通道在做什么（以及不做什么）
//!
//! 用户自己在官方页面里完成登录 / 验证码；脚本**只读**站点 SPA 自己写入的 `auth_token`，
//! 通过一次顶层导航 `keyrelay-creds://ok?d=<base64url>` 回传给壳层。不读 DOM、不改表单、
//! 不提交登录、不识别验证码 —— **不是**「自动解题」，是「用户已经登进去了，把凭据接回来」。
//!
//! # 秘密面
//!
//! - [`WebviewCredentials`] 手写 `Debug`（隐藏 token / cf_clearance 值）；
//! - 所有错误文案只描述**形态**（长度 / 字符集 / 缺哪个字段），从不回显值；
//! - 本模块是**纯函数**：无 IO、无日志、不碰钥匙串（落点是调用方的事）。
//!
//! # 与 `captcha.rs` 的关系
//!
//! origin 解析**复用** [`super::captcha`] 的 `origin_of`（M16-S3 起走 WHATWG 同源判定）。
//! 两处 origin 口径必须同源 —— 这是安全不变式：凭据回传的「本站」与验证码页面的
//! 「本站」若是两套解析，就会出现「页面地址认 A 站、凭据回传认 B 站」的缝。

use base64::Engine as _;
use serde_json::Value;

use super::{captcha, Session};
use crate::error::{Error, Result};

/// 凭据回传用的自定义 scheme。选一个绝不会被真实站点用到的值。
pub const CREDS_SCHEME: &str = "keyrelay-creds";
/// 回传 URL 的 host 标记。
pub const CREDS_CALLBACK_HOST: &str = "ok";
/// Sub2API 存 access token 的 localStorage 键名（前端 `stores/auth.ts:11`）。
pub const AUTH_TOKEN_KEY: &str = "auth_token";
/// 续期键（只用于回传后删除，不读取、不持久化）。
pub const REFRESH_TOKEN_KEY: &str = "refresh_token";
/// 续期键（同上）。
pub const TOKEN_EXPIRES_AT_KEY: &str = "token_expires_at";

/// 回传 URL 的最大字节数（超过一律拒绝，不解析）。
pub const MAX_CREDS_URL_BYTES: usize = 16 * 1024;
/// access token 的最大字节数。
pub const MAX_ACCESS_TOKEN_BYTES: usize = 8192;
/// user agent 的最大字节数。
pub const MAX_USER_AGENT_BYTES: usize = 512;
/// `cf_clearance` 的最大字节数。
pub const MAX_CF_CLEARANCE_BYTES: usize = 4096;

/// 从 WebView 登录页回传的凭据。
///
/// **禁止 derive Debug**（会泄露 token / cf_clearance），手写实现见下。
#[derive(Clone, PartialEq, Eq, Default)]
pub struct WebviewCredentials {
    pub access_token: String,
    pub user_agent: Option<String>,
    /// 由 Tauri 层从 `window.cookies()` 补上（HttpOnly，JS 读不到）。
    pub cf_clearance: Option<String>,
}

impl std::fmt::Debug for WebviewCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebviewCredentials")
            // 值一律不打印：只报「有没有」。
            .field("access_token", &"<已设置>")
            .field("user_agent", &self.user_agent.as_ref().map(|_| "<已设置>"))
            .field(
                "cf_clearance",
                &self.cf_clearance.as_ref().map(|_| "<已设置>"),
            )
            .finish()
    }
}

/// 站点 origin（`scheme://host[:port]`，小写 / IDN punycode / 默认端口省略）。
///
/// 复用 [`captcha::origin_of`]：两处 origin 口径必须同源（见模块文档）。
/// 解析不出 ⇒ `Error::Transport`，文案与 `captcha::captcha_page_url` 同口径（不含任何凭据值）。
pub fn site_origin(base_url: &str) -> Result<String> {
    captcha::origin_of(base_url).ok_or_else(|| {
        Error::Transport(format!(
            "站点地址无法解析出主机名：无法确定凭据回传的 origin（{}）",
            super::display_url(base_url)
        ))
    })
}

/// 判断一次导航是不是凭据回传。
///
/// - 非本 scheme / 非 `ok` host ⇒ `None`（普通导航，调用方放行）；
/// - 本 scheme 但缺 `d` / base64url 解不开 / JSON 不合法 / token 形态非法 ⇒ `Some(Err(_))`
///   （调用方**拦下**，不放行）；
/// - 合法 ⇒ `Some(Ok(creds))`。
///
/// **顺序要紧**：先判 scheme/host（不是我们的 URL 就 `None`），再判长度 / base64 / JSON /
/// 形态（我们的 URL 但坏了必须 `Some(Err)` —— 返回 `None` 会被壳层放行）。
pub fn parse_creds_navigation(url: &str) -> Option<Result<WebviewCredentials>> {
    // scheme 大小写不敏感（RFC 3986 §3.1）。前缀必须逐字是 `keyrelay-creds://`。
    //
    // **必须用 `get(..)` 而不是 `split_at`**（P1）：`split_at` 的字节下标若落在 UTF-8
    // 字符中间会 **panic**（例如 `"中中中中中中"` 的第 14 字节在第 5 个汉字里）。
    // 这是公开纯函数，库内不得 panic —— 壳层虽然拿到的是 `Url` 的 ASCII 序列化，
    // 但不能靠调用方保证。越界 / 非边界 ⇒ `None`（不是我们的 scheme，按普通导航放行）。
    let scheme = url.get(..CREDS_SCHEME.len())?;
    if !scheme.eq_ignore_ascii_case(CREDS_SCHEME) {
        return None;
    }
    let rest = url.get(CREDS_SCHEME.len()..)?;
    let after_scheme = rest.strip_prefix("://")?;
    // host 段：到 `/` `?` `#` 为止。
    let host_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let host = &after_scheme[..host_end];
    if !host.eq_ignore_ascii_case(CREDS_CALLBACK_HOST) {
        // 本 scheme、host 不对 ⇒ 不是我们的回传（页面自己报错去），放行。
        return None;
    }

    // 到这里一定是「我们的回传 URL」⇒ 任何毛病都要 `Some(Err)`（壳层必须拦下）。
    if url.len() > MAX_CREDS_URL_BYTES {
        return Some(Err(Error::AuthFailed(
            "凭据回传 URL 过长，已拒绝".to_string(),
        )));
    }
    let query = {
        let q = after_scheme[host_end..].trim_start_matches(['/', '?', '#']);
        // 允许 `ok/?d=` 与 `ok?d=` 两种形态。
        q.split('#').next().unwrap_or("")
    };
    let Some(d) = query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == "d").then_some(v)
    }) else {
        return Some(Err(Error::AuthFailed(
            "凭据回传缺少数据段（d）".to_string(),
        )));
    };
    if d.is_empty() {
        return Some(Err(Error::AuthFailed("凭据回传的数据段为空".to_string())));
    }

    Some(decode_payload(d))
}

/// base64url 解码 + JSON 解析 + 形态校验。失败一律 `AuthFailed`（文案不含数据）。
fn decode_payload(d: &str) -> Result<WebviewCredentials> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(d)
        // 容忍带 padding 的写法（有些环境会补 `=`）
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(d))
        .map_err(|_| Error::AuthFailed("凭据回传的数据段不是合法 base64url".to_string()))?;
    let text = String::from_utf8(bytes)
        .map_err(|_| Error::AuthFailed("凭据回传的数据段不是 UTF-8 文本".to_string()))?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|_| Error::AuthFailed("凭据回传的 JSON 无法解析".to_string()))?;
    let Some(token) = value.get(AUTH_TOKEN_KEY).and_then(|v| v.as_str()) else {
        return Err(Error::AuthFailed(
            "凭据回传缺少 auth_token（或不是字符串）".to_string(),
        ));
    };
    validate_access_token(token)?;

    // UA：非法 ⇒ 按 `None` 处理（不阻断登录 —— 站点没给 UA 也能用，只是 cf_clearance 可能不匹配）。
    let user_agent = value
        .get("user_agent")
        .and_then(|v| v.as_str())
        .filter(|ua| validate_user_agent(ua).is_ok())
        .map(str::to_string);

    Ok(WebviewCredentials {
        access_token: token.to_string(),
        user_agent,
        cf_clearance: None, // 由壳层从 window.cookies() 补
    })
}

/// access token 形态：非空、≤ 8192 字节、全部可见 ASCII（0x21..=0x7E，禁止空白/控制字符）。
pub fn validate_access_token(token: &str) -> Result<()> {
    if token.is_empty() {
        return Err(Error::AuthFailed("access token 为空".to_string()));
    }
    if token.len() > MAX_ACCESS_TOKEN_BYTES {
        return Err(Error::AuthFailed(format!(
            "access token 过长（{} 字节，上限 {MAX_ACCESS_TOKEN_BYTES}）",
            token.len()
        )));
    }
    if !token.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(Error::AuthFailed(
            "access token 含空白 / 控制字符 / 非 ASCII".to_string(),
        ));
    }
    Ok(())
}

/// user agent 形态：非空、≤ 512 字节、全部可见 ASCII（0x20..=0x7E，禁止 CR/LF/控制字符）。
/// 不合法 ⇒ 调用方按 `None` 处理（不阻断登录）。
pub fn validate_user_agent(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::AuthFailed("user agent 为空".to_string()));
    }
    if value.len() > MAX_USER_AGENT_BYTES {
        return Err(Error::AuthFailed(format!(
            "user agent 过长（{} 字节，上限 {MAX_USER_AGENT_BYTES}）",
            value.len()
        )));
    }
    if !value.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(Error::AuthFailed(
            "user agent 含控制字符 / 非 ASCII".to_string(),
        ));
    }
    Ok(())
}

/// `cf_clearance` 形态：非空、≤ 4096 字节、可见 ASCII（0x21..=0x7E），禁止 `;` / `,`。
pub fn validate_cf_clearance(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::AuthFailed("cf_clearance 为空".to_string()));
    }
    if value.len() > MAX_CF_CLEARANCE_BYTES {
        return Err(Error::AuthFailed(format!(
            "cf_clearance 过长（{} 字节，上限 {MAX_CF_CLEARANCE_BYTES}）",
            value.len()
        )));
    }
    if !value.bytes().all(|b| (0x21..=0x7e).contains(&b))
        || value.contains(';')
        || value.contains(',')
    {
        return Err(Error::AuthFailed(
            "cf_clearance 含非法字符（空白 / 控制字符 / `;` / `,`）".to_string(),
        ));
    }
    Ok(())
}

/// 从 `(name, value)` 列表里挑出第一条合法的 `cf_clearance`；没有 ⇒ `None`。
pub fn extract_cf_clearance(cookies: &[(String, String)]) -> Option<String> {
    cookies
        .iter()
        .filter(|(name, _)| name == "cf_clearance")
        .map(|(_, value)| value)
        .find(|value| validate_cf_clearance(value).is_ok())
        .cloned()
}

/// 生成注入脚本。`base_url` 只用于算 origin；脚本只在该 origin、只在该顶层 frame 生效。
///
/// 占位符替换规则：全部用 `serde_json::to_string` 的字面量（**不是**字符串拼接），
/// **origin 最后替换** —— origin 来自用户输入，若它本身含 `__CREDS_SCHEME__` 这样的字样，
/// 先替换就会被二次扫描。
pub fn login_script(base_url: &str) -> Result<String> {
    let origin = site_origin(base_url)?;
    let literal = |s: &str| serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string());

    let mut script = include_str!("login_script.js")
        .replace("__CREDS_SCHEME__", &literal(CREDS_SCHEME))
        .replace("__CREDS_HOST__", &literal(CREDS_CALLBACK_HOST))
        .replace("__AUTH_TOKEN_KEY__", &literal(AUTH_TOKEN_KEY));
    // **最后**替换 origin（防二次扫描）。
    script = script.replace("__ALLOWED_ORIGIN__", &literal(&origin));

    // 兜底断言：模板里不许留任何未替换的占位符。
    if script.contains("__CREDS_SCHEME__")
        || script.contains("__CREDS_HOST__")
        || script.contains("__AUTH_TOKEN_KEY__")
        || script.contains("__ALLOWED_ORIGIN__")
    {
        return Err(Error::Transport("注入脚本模板有未替换的占位符".to_string()));
    }
    Ok(script)
}

/// 回传成功后从页面里删掉两个续期键（`refresh_token` / `token_expires_at`）。
///
/// 理由：本产品没有 refresh 流程（多存一份续期凭据只扩大秘密面）。窗口关掉 + incognito
/// 是双保险，但**下线那一刻**就该把续期能力交出去。
pub fn strip_refresh_keys_js() -> String {
    format!(
        "(function(){{try{{var s=window.localStorage;s.removeItem({refresh});s.removeItem({expires});}}catch(e){{}}}})();",
        refresh = serde_json::to_string(REFRESH_TOKEN_KEY).unwrap_or_else(|_| "\"\"".to_string()),
        expires = serde_json::to_string(TOKEN_EXPIRES_AT_KEY).unwrap_or_else(|_| "\"\"".to_string()),
    )
}

/// 把已校验的凭据变成会话：`access_token = Some`，`cookies = [("cf_clearance", v)]`
/// （没有则空），`user_agent` 原样带上。**不落库、不打日志**（调用方纪律）。
pub fn session_from_webview_credentials(creds: &WebviewCredentials) -> Result<Session> {
    validate_access_token(&creds.access_token)?;
    if let Some(ua) = &creds.user_agent {
        validate_user_agent(ua)?;
    }
    if let Some(cf) = &creds.cf_clearance {
        validate_cf_clearance(cf)?;
    }
    Ok(Session {
        cookies: creds
            .cf_clearance
            .as_ref()
            .map(|cf| vec![("cf_clearance".to_string(), cf.clone())])
            .unwrap_or_default(),
        access_token: Some(creds.access_token.clone()),
        user_id: None,
        user_agent: creds.user_agent.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64url(text: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(text.as_bytes())
    }

    fn nav(payload: &str) -> String {
        format!(
            "{CREDS_SCHEME}://{CREDS_CALLBACK_HOST}?d={}",
            b64url(payload)
        )
    }

    // ============================================================ 解析：合法

    #[test]
    fn parses_a_valid_callback_url() {
        let url = nav(r#"{"auth_token":"tok-abc","user_agent":"Mozilla/5.0 (Macintosh)"}"#);
        let creds = parse_creds_navigation(&url)
            .expect("应当认出是本 scheme")
            .expect("应当解析成功");
        assert_eq!(creds.access_token, "tok-abc");
        assert_eq!(creds.user_agent.as_deref(), Some("Mozilla/5.0 (Macintosh)"));
        assert_eq!(creds.cf_clearance, None, "cf_clearance 只由壳层补");
    }

    #[test]
    fn parses_without_user_agent() {
        let url = nav(r#"{"auth_token":"tok-abc"}"#);
        let creds = parse_creds_navigation(&url).unwrap().unwrap();
        assert_eq!(creds.user_agent, None);
    }

    #[test]
    fn tolerates_padded_base64url_and_extra_query_keys() {
        // 带 padding + 额外 query 参数 + 末尾 fragment：都应当能解出 token。
        let padded =
            base64::engine::general_purpose::URL_SAFE.encode(br#"{"auth_token":"tok-abc"}"#);
        let url = format!("{CREDS_SCHEME}://{CREDS_CALLBACK_HOST}?x=1&d={padded}#frag");
        let creds = parse_creds_navigation(&url).unwrap().unwrap();
        assert_eq!(creds.access_token, "tok-abc");
    }

    // ============================================================ 解析：None

    /// P1 回归（M28-S1 复审）：**非 ASCII 输入不得 panic**。
    ///
    /// `"中中中中中中"` 是 18 字节，旧的 `split_at(14)` 落在第 5 个汉字中间 ⇒ panic。
    /// 现在走 `get(..)` ⇒ 非边界返回 `None`（按普通导航放行）。
    #[test]
    fn non_ascii_input_never_panics() {
        for input in [
            "中中中中中中",
            "keyrelay-creds://ok?d=中文",
            "🦀🦀🦀🦀🦀",
            "keyrelay-🦀",
            "é",
        ] {
            // 只要不 panic 即可；返回值按实现语义：非本 scheme ⇒ None。
            let out = parse_creds_navigation(input);
            assert!(
                out.is_none() || matches!(out, Some(Err(_))),
                "非 ASCII 输入不得 panic，且不得返回 Ok：{input}"
            );
        }
        // 明确的形态：前缀都不是 ASCII ⇒ None
        assert!(parse_creds_navigation("中中中中中中").is_none());
    }

    #[test]
    fn ordinary_navigation_is_none() {
        assert!(parse_creds_navigation("https://h.example.com/login").is_none());
        assert!(parse_creds_navigation("about:blank").is_none());
        assert!(parse_creds_navigation("").is_none());
        assert!(parse_creds_navigation("keyrelay-creds").is_none());
    }

    #[test]
    fn wrong_host_is_none() {
        let url = format!(
            "{CREDS_SCHEME}://other?d={}",
            b64url(r#"{"auth_token":"t"}"#)
        );
        assert!(parse_creds_navigation(&url).is_none(), "host 不对 ⇒ 放行");
    }

    // ============================================================ 解析：Some(Err)

    fn assert_auth_failed(url: &str, label: &str) {
        match parse_creds_navigation(url) {
            Some(Err(Error::AuthFailed(_))) => {}
            other => panic!("{label}：期望 Some(Err(AuthFailed))，实际 {other:?}"),
        }
    }

    #[test]
    fn malformed_callbacks_are_some_err() {
        let base = format!("{CREDS_SCHEME}://{CREDS_CALLBACK_HOST}");
        assert_auth_failed(&format!("{base}?x=1"), "缺 d");
        assert_auth_failed(&format!("{base}?d="), "空 d");
        assert_auth_failed(&format!("{base}?d=!!!not-base64!!!"), "坏 base64");
        assert_auth_failed(&format!("{base}?d={}", b64url("not json")), "非 JSON");
        // 非 UTF-8：0xFF 不是合法 UTF-8 序列
        let bad_utf8 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xff, 0xfe, 0xfd]);
        assert_auth_failed(&format!("{base}?d={bad_utf8}"), "非 UTF-8");
        assert_auth_failed(
            &format!("{base}?d={}", b64url(r#"{"x":1}"#)),
            "缺 auth_token",
        );
        assert_auth_failed(
            &format!("{base}?d={}", b64url(r#"{"auth_token":""}"#)),
            "空 token",
        );
        assert_auth_failed(
            &format!("{base}?d={}", b64url(r#"{"auth_token":"a\r\nb"}"#)),
            "token 含 CRLF",
        );
        assert_auth_failed(
            &format!("{base}?d={}", b64url(r#"{"auth_token":"中文"}"#)),
            "token 非 ASCII",
        );
        let too_long = "a".repeat(MAX_ACCESS_TOKEN_BYTES + 1);
        assert_auth_failed(
            &format!(
                "{base}?d={}",
                b64url(&format!(r#"{{"auth_token":"{too_long}"}}"#))
            ),
            "token 超长",
        );
    }

    #[test]
    fn oversized_url_is_rejected_without_parsing() {
        let url = format!(
            "{CREDS_SCHEME}://{CREDS_CALLBACK_HOST}?d={}",
            "A".repeat(MAX_CREDS_URL_BYTES)
        );
        assert_auth_failed(&url, "URL 超长");
    }

    // ============================================================ UA / cf_clearance

    #[test]
    fn invalid_user_agent_becomes_none_but_login_continues() {
        for bad in [
            "",
            "a\r\nb",
            "中文 UA",
            &"u".repeat(MAX_USER_AGENT_BYTES + 1),
        ] {
            let url = nav(&format!(
                r#"{{"auth_token":"tok","user_agent":{}}}"#,
                serde_json::to_string(bad).unwrap()
            ));
            let creds = parse_creds_navigation(&url).unwrap().unwrap();
            assert_eq!(creds.user_agent, None, "非法 UA 应按 None 处理：{bad:?}");
            assert_eq!(creds.access_token, "tok", "登录不得因 UA 失败");
        }
    }

    #[test]
    fn cf_clearance_picks_the_first_valid_one() {
        let cookies = vec![
            ("other".to_string(), "x".to_string()),
            ("cf_clearance".to_string(), "bad;value".to_string()), // 非法（含 `;`）
            ("cf_clearance".to_string(), "good-value_1".to_string()),
            ("cf_clearance".to_string(), "second".to_string()),
        ];
        assert_eq!(
            extract_cf_clearance(&cookies).as_deref(),
            Some("good-value_1")
        );
        assert_eq!(extract_cf_clearance(&[]), None);
        assert_eq!(
            extract_cf_clearance(&[("cf_clearance".to_string(), "a,b".to_string())]),
            None,
            "含 `,` 非法"
        );
        assert_eq!(
            extract_cf_clearance(&[("cf_clearance".to_string(), "".to_string())]),
            None,
            "空值非法"
        );
    }

    // ============================================================ 会话构造

    #[test]
    fn session_carries_token_ua_and_cf_clearance() {
        let creds = WebviewCredentials {
            access_token: "tok-abc".to_string(),
            user_agent: Some("UA/1.0".to_string()),
            cf_clearance: Some("cf-value".to_string()),
        };
        let session = session_from_webview_credentials(&creds).expect("构造会话");
        assert_eq!(session.access_token.as_deref(), Some("tok-abc"));
        assert_eq!(session.user_agent.as_deref(), Some("UA/1.0"));
        assert_eq!(
            session.cookies,
            vec![("cf_clearance".to_string(), "cf-value".to_string())]
        );
        assert_eq!(session.user_id, None);

        let no_cf = WebviewCredentials {
            access_token: "tok".to_string(),
            ..Default::default()
        };
        assert!(session_from_webview_credentials(&no_cf)
            .expect("构造会话")
            .cookies
            .is_empty());
    }

    #[test]
    fn invalid_token_is_rejected_by_session_construction() {
        let creds = WebviewCredentials {
            access_token: "bad\r\ntoken".to_string(),
            ..Default::default()
        };
        assert!(matches!(
            session_from_webview_credentials(&creds),
            Err(Error::AuthFailed(_))
        ));
    }

    // ============================================================ Debug / 秘密面

    #[test]
    fn debug_never_prints_secret_values() {
        let creds = WebviewCredentials {
            access_token: "SUPER-SECRET-TOKEN".to_string(),
            user_agent: Some("UA-VALUE".to_string()),
            cf_clearance: Some("CF-SECRET".to_string()),
        };
        let text = format!("{creds:?}");
        for secret in ["SUPER-SECRET-TOKEN", "UA-VALUE", "CF-SECRET"] {
            assert!(!text.contains(secret), "Debug 泄露了值：{text}");
        }
        assert!(text.contains("<已设置>"), "{text}");
    }

    // ============================================================ 脚本

    #[test]
    fn login_script_has_origin_keys_and_no_leftover_placeholders() {
        let script = login_script("https://Sub.Example.com/path").expect("生成脚本");
        assert!(script.contains("\"keyrelay-creds\""), "含 scheme");
        assert!(script.contains("\"auth_token\""), "含 token 键");
        assert!(
            script.contains("\"https://sub.example.com\""),
            "origin 已规范化并用 JSON 字面量"
        );
        assert!(
            script.contains("window.top !== window.self"),
            "顶层 frame 守卫"
        );
        assert!(
            script.contains("window.location.origin !== ALLOWED_ORIGIN"),
            "origin 守卫"
        );
        for marker in [
            "__ALLOWED_ORIGIN__",
            "__CREDS_SCHEME__",
            "__CREDS_HOST__",
            "__AUTH_TOKEN_KEY__",
        ] {
            assert!(!script.contains(marker), "残留占位符：{marker}");
        }
    }

    #[test]
    fn login_script_escapes_hostile_origins() {
        // origin 里出现引号 / 反斜杠 / 占位符字样时，脚本仍是合法 JS（Node vm 测试兜底）
        let script =
            login_script("https://h.example.com/?q=\"__CREDS_SCHEME__\"").expect("生成脚本");
        assert!(
            script.contains("\"https://h.example.com\""),
            "origin 只取 origin 段"
        );
        assert!(
            script.contains("\"keyrelay-creds\""),
            "占位符替换不该被 origin 内容干扰"
        );
    }

    #[test]
    fn site_origin_requires_a_parseable_http_url() {
        assert_eq!(
            site_origin("HTTPS://H.Example.com:443/x").unwrap(),
            "https://h.example.com"
        );
        assert_eq!(
            site_origin("http://127.0.0.1:8787").unwrap(),
            "http://127.0.0.1:8787"
        );
        for bad in ["", "not a url", "file:///etc/passwd", "javascript:alert(1)"] {
            assert!(
                matches!(site_origin(bad), Err(Error::Transport(_))),
                "应当拒绝：{bad}"
            );
        }
    }

    #[test]
    fn strip_refresh_keys_script_targets_both_rotation_keys() {
        let js = strip_refresh_keys_js();
        assert!(js.contains("\"refresh_token\""), "{js}");
        assert!(js.contains("\"token_expires_at\""), "{js}");
        assert!(js.contains("removeItem"), "{js}");
    }
}
