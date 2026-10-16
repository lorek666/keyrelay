//! 人工过验证码的**纯函数**层（FR-1:102 / M8-S2）。
//!
//! # 红线（章程 §3.2，不得动摇）
//!
//! **不绕过验证码**。产品行为是「把**官方页面**给用户，让用户自己过一次」，不是自动解题：
//! 本模块不识别图形、不调打码服务、不注入脚本、不读页面 DOM。它只做四件事：
//! ① 造出要打开的官方页面地址；② 比对 WebView 导航后的 origin 是否仍属于该站点；
//! ③ 校验抓回来的 cookie 的**形态**；④ 把已校验的 cookie 变成会话。
//!
//! # 为什么是纯函数
//!
//! WebView 的创建与抓取在 `src-tauri`（Lead 写域），本机也没有 GUI 会话可以测
//! （spec §10-1）。把「地址构造 / origin 比对 / cookie 校验 / 状态转移」四件事做成
//! 无 IO、无网络、不读环境的纯函数之后，它们**全部可单测**——剩下真正测不到的只有
//! WebView 本身那一层。

use super::{CaptchaChallenge, Session};
use crate::error::{Error, Result};

/// 抓回来的 cookie 条数上限。
pub const MAX_CAPTCHA_COOKIES: usize = 32;
/// 单个 cookie 值的字节上限。
pub const MAX_CAPTCHA_COOKIE_VALUE_BYTES: usize = 4096;
/// 全部 cookie 的字节上限。
pub const MAX_CAPTCHA_COOKIES_TOTAL_BYTES: usize = 16 * 1024;

/// 人工过验证码要打开的**官方页面**地址：站点自己的 origin + `/login`。
///
/// 保证（每条都有测试）：
/// ① 只可能是 `{site origin}{base 路径}/login`（**保留 base 路径**：子路径部署的站点
///    登录页也在子路径下，M16-S3 P3-24）；
/// ② **永不**带 userinfo（`https://alice:pw@host` ⇒ `https://host/login`）；
/// ③ **永不**指向第三方 host（host 逐字来自 `base_url`，且过 WHATWG 解析器）；
/// ④ 非 `http(s)` 的 scheme（或无 scheme / 解析失败）⇒ `Err(Error::Transport)`——
///    绝不返回一个会打开本地文件 / 执行脚本的地址；
/// ⑤ 输出的 host 是**规范化**形态（小写、IDN → punycode、尾点剥掉）——与
///    [`origin_of`] 同一口径，否则 `origin_matches(base, captcha_page_url(base))` 会自相矛盾。
pub fn captcha_page_url(base_url: &str) -> Result<String> {
    let Some((scheme, host, port, path)) = parts_of(base_url) else {
        // 错误文案尽量具体：缺 scheme / 非 http(s)（`split_scheme` 会给出准确的哪一条），
        // 其余（有 scheme 却解析不出主机）走兜底。
        return Err(match split_scheme(base_url) {
            Err(err) => err,
            Ok(_) => Error::Transport(format!(
                "站点地址无法解析出主机名：无法构造人机验证页面（{}）",
                super::display_url(base_url)
            )),
        });
    };
    // 保留 base 路径（去掉尾斜杠），再接 `/login`：`https://h/relay` ⇒ `https://h/relay/login`。
    //
    // 例外：路径里出现 `@` 时**丢掉**它。用户录进来的地址形如
    // `https://evil.example\@good.example` 时，WHATWG 解析出的 path 是 `/@good.example`
    // ——那是个**看着像 userinfo** 的串，把它拼进交给 WebView 的地址只会制造新的歧义
    // （而 host 归属已经在 `parts_of` 里定成 evil.example 了，这里丢的只是路径）。
    let base_path = path.trim_end_matches('/');
    let base_path = if base_path.contains('@') {
        ""
    } else {
        base_path
    };
    Ok(format!("{scheme}://{host}{port}{base_path}/login"))
}

/// `(scheme, 规范化 host, ":port" 或 "", path)`；非 http(s) / 无 host / 解析失败 ⇒ `None`。
///
/// **解析只有这一处**（M16-S3 P2-20）：此前 `captcha_page_url` / `origin_of` / `host_of`
/// 各自手写一遍，与 WHATWG 的差异要各自修、各自漏。现在统一走 `reqwest::Url`
/// （= url crate，已是直接依赖的传递物），口径与适配器真正发请求时用的解析器**同源**。
fn parts_of(raw: &str) -> Option<(String, String, String, String)> {
    let url = reqwest::Url::parse(raw.trim()).ok()?;
    let scheme = url.scheme().to_string();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    // `host_str()` 已是小写 + punycode（IDN）形态；尾点 FQDN 再剥一层。
    let host = url.host_str()?;
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    // `Url::port()` 已把 `:0443` 这类写法数值化，且**默认端口返回 `None`**
    // ⇒ `https://h`、`https://h:443`、`https://h:0443` 三者一致。
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    Some((scheme, host, port, url.path().to_string()))
}

/// WebView 导航后、抓 cookie 前的 origin 比对：页面地址必须**仍属于该站点**。
///
/// 防的是「站点把我跳到第三方，我在那边登录 → 抓到的 cookie 不属于本站」。
/// 比较 scheme + host + port：host 大小写不敏感；默认端口归一
/// （`https://h` == `https://h:443`，`http://h` == `http://h:80`）。
///
/// 任一输入无法解析 ⇒ `false`（**失败关闭**：拿不准就不抓 cookie）。
pub fn origin_matches(base_url: &str, page_url: &str) -> bool {
    match (origin_of(base_url), origin_of(page_url)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// 校验 WebView 抓回来的 cookie。逐条规则见 spec §4。
///
/// **错误文案不得包含任何 cookie 值**（只允许出现下标 / 键名 / 长度 / 规则名）。
///
/// 为什么不用 `redact::scrub` 兜底：`scrub` 只认 `sk-` / `nap-` / `Bearer ` / 长 hex /
/// URL userinfo，而会话 cookie 的形态**任意**（`session=abc123`、`cf_clearance=…`）。
/// 指望「先写进去再 scrub」等于没有防线 ⇒ 规则是**根本不写**。
pub fn validate_captcha_cookies(cookies: &[(String, String)]) -> Result<()> {
    if cookies.is_empty() {
        return Err(Error::AuthFailed(
            "没有抓到任何会话 cookie（格式校验未通过）：\
             看起来窗口里还没有真正登录成功——请在打开的页面里完成登录与验证码后重试"
                .to_string(),
        ));
    }
    if cookies.len() > MAX_CAPTCHA_COOKIES {
        return Err(Error::AuthFailed(format!(
            "会话 cookie 条数 {} 超过上限 {}（格式校验未通过）",
            cookies.len(),
            MAX_CAPTCHA_COOKIES
        )));
    }
    let mut total = 0usize;
    for (index, (name, value)) in cookies.iter().enumerate() {
        if name.is_empty() {
            return Err(Error::AuthFailed(format!(
                "第 {index} 条 cookie 的**键名**为空（格式校验未通过）"
            )));
        }
        if value.is_empty() {
            return Err(Error::AuthFailed(format!(
                "第 {index} 条 cookie（键名 `{name}`）的**值为空**（格式校验未通过）"
            )));
        }
        if name
            .chars()
            .any(|c| c == '=' || c == ';' || c == ',' || c.is_whitespace() || c.is_control())
        {
            return Err(Error::AuthFailed(format!(
                "第 {index} 条 cookie 的键名 `{name}` 含非法字符（`=` / `;` / `,` / 空白 / 控制字符）\
                 （格式校验未通过）"
            )));
        }
        // 值必须是可见 ASCII：`Cookie:` 头里塞进 CR/LF 就是**请求头注入**。
        if value.bytes().any(|b| !(0x21..=0x7E).contains(&b)) {
            return Err(Error::AuthFailed(format!(
                "第 {index} 条 cookie（键名 `{name}`）的值含控制字符或非可见 ASCII 字节\
                 （格式校验未通过；这可能是被篡改的响应）"
            )));
        }
        if value.len() > MAX_CAPTCHA_COOKIE_VALUE_BYTES {
            return Err(Error::AuthFailed(format!(
                "第 {index} 条 cookie（键名 `{name}`）的值长度 {} 超过上限 {}（格式校验未通过）",
                value.len(),
                MAX_CAPTCHA_COOKIE_VALUE_BYTES
            )));
        }
        total += value.len();
    }
    if total > MAX_CAPTCHA_COOKIES_TOTAL_BYTES {
        return Err(Error::AuthFailed(format!(
            "会话 cookie 总长度 {total} 超过上限 {MAX_CAPTCHA_COOKIES_TOTAL_BYTES}（格式校验未通过）"
        )));
    }
    Ok(())
}

/// 把**已校验**的 cookie 变成会话（仅内存 / 钥匙串；调用方不得落库、不得打日志）。
///
/// 同名多条**原样保留**：不同 `path` 下同名是 HTTP 的合法形态，合并会改变语义。
pub fn session_from_captcha_cookies(cookies: &[(String, String)]) -> Session {
    Session {
        cookies: cookies.to_vec(),
        access_token: None,
        user_id: None,
    }
}

/// 人工过验证码的相位（纯数据）。**按站点**：多站点可同时处于不同相位。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptchaPhase {
    Idle,
    /// 等用户在 WebView 里过一次；`challenge` 由调用方用 [`captcha_page_url`] 造好
    AwaitingHuman {
        site_id: i64,
        challenge: CaptchaChallenge,
    },
}

/// 状态机事件（纯数据）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptchaEvent {
    /// 登录被站点要求人机验证（`Error::CaptchaRequired`）
    LoginRejected { challenge: CaptchaChallenge },
    /// 登录因**别的原因**失败
    LoginFailed,
    /// 用户提交了抓到的 cookie；`ok` = [`validate_captcha_cookies`] 是否通过
    CookiesSubmitted { ok: bool },
    /// 用户取消 / 关闭窗口 / 超时
    Cancelled,
}

/// 纯转移函数：`step(phase, event) -> phase`。逐条转移见 spec §3。
pub fn step(phase: CaptchaPhase, event: CaptchaEvent) -> CaptchaPhase {
    use CaptchaEvent as E;
    use CaptchaPhase as P;
    match (phase, event) {
        // T1：登录被要求人机验证 ⇒ 进人工态（**登录流程不报错结束**）。
        //
        // M16-S3 P3-23（口径订正）：这里**没有**任何 `site_id` 一致性校验，也做不到——
        // `CaptchaEvent::LoginRejected` 只带 `challenge`，不带「当前站点」，
        // 生产路径到不了「比较两者」这一步。原先的注释声称「不一致时视为 `LoginFailed`」，
        // 与事实不符（DEBUG-REPORT-v3 §3-23）。相位里的 `site_id` 是**展示用**的
        // （界面显示「哪个站点在等人机验证」）；要防「挑战挂错站点」得由调用方在构造
        // 事件时保证（`commands.rs` 的 `captcha_begin` 按站点建 challenge）。
        (P::Idle, E::LoginRejected { challenge }) => P::AwaitingHuman {
            site_id: challenge.site_id,
            challenge,
        },
        // T2：其余失败照旧上抛，不进人工态（验证码是**唯一**入口）。
        (P::Idle, E::LoginFailed) => P::Idle,
        // T3：重复触发 ⇒ **替换** challenge（URL 可能已变），不叠加。
        (P::AwaitingHuman { .. }, E::LoginRejected { challenge }) => P::AwaitingHuman {
            site_id: challenge.site_id,
            challenge,
        },
        // T4：提交通过 ⇒ 回空闲态（会话已由 `session_from_captcha_cookies` 建好）。
        (P::AwaitingHuman { .. }, E::CookiesSubmitted { ok: true }) => P::Idle,
        // T5：提交失败 ⇒ **留在**人工态（校验失败不是终局，用户可以重开窗口再试）。
        (phase @ P::AwaitingHuman { .. }, E::CookiesSubmitted { ok: false }) => phase,
        // T6 / T8：取消 ⇒ 回空闲态（不留半截会话）。空闲态收到取消是幂等。
        (P::AwaitingHuman { .. }, E::Cancelled) => P::Idle,
        (P::Idle, E::Cancelled) => P::Idle,
        // T7：不在人工态时收到 cookie ⇒ 忽略（**不得**把「没经过挑战的 cookie」当会话）。
        (P::Idle, E::CookiesSubmitted { .. }) => P::Idle,
        (phase @ P::AwaitingHuman { .. }, E::LoginFailed) => phase,
    }
}

/// URL 里的 host（给 `CaptchaChallenge` 的 `Debug` 用）。解析不出 ⇒ `"?"`。
///
/// 与 [`origin_of`] 同源（`parts_of`）：Debug 里出现的 host 必须与归属判定用的 host 一致，
/// 否则日志会给出误导性的排障线索（M16-S3 P2-20 的「解析收敛到一处」）。
pub(crate) fn host_of(url: &str) -> String {
    match parts_of(url) {
        Some((_, host, _, _)) => host,
        None => "?".to_string(),
    }
}

/// 拆出 scheme（小写）与其余部分。只接受 `http` / `https`。
fn split_scheme(raw: &str) -> Result<(String, &str)> {
    let Some(i) = raw.find("://") else {
        return Err(Error::Transport(format!(
            "站点地址缺少 scheme（只支持 http/https）：{}",
            super::display_url(raw)
        )));
    };
    let scheme = raw[..i].to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(Error::Transport(format!(
            "不支持的 scheme `{scheme}`（只支持 http/https）：{}",
            super::display_url(raw)
        )));
    }
    Ok((scheme, &raw[i + 3..]))
}

/// 规范化 origin：`scheme://host[:port]`（小写 scheme/host、默认端口省略、IDN → punycode、
/// 尾点剥掉）。
///
/// **与 WHATWG 同源**（M16-S3 P2-20 / P3-24）：走 [`parts_of`]（`reqwest::Url`），
/// 不再手写 authority 切分。此前手写版把三类**同一台主机**判成不同 origin
/// （`xn--…` 与 Unicode 域名、`h.example.com.`、`:0443`）⇒ 失败关闭 ⇒ 这些站点
/// 永远提交不了验证码。判定方向仍是**失败关闭**：解析不出 ⇒ `None` ⇒ `origin_matches` 为 `false`。
fn origin_of(raw: &str) -> Option<String> {
    let (scheme, host, port, _) = parts_of(raw)?;
    Some(format!("{scheme}://{host}{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cookies(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    fn challenge(site_id: i64) -> CaptchaChallenge {
        CaptchaChallenge {
            site_id,
            url: "https://h.example.com/login".to_string(),
        }
    }

    // ============================================================ T1–T4 页面地址

    #[test]
    fn captcha_page_url_uses_the_site_origin_and_login_route() {
        // M16-S3 P3-24：两处**有意的行为变更**（差异登记见 spec §10）
        // ① base 路径**保留**：子路径部署（`https://h/relay`）的登录页在子路径下，
        //    丢掉它会让用户打不开登录页；
        // ② host 输出**规范化**（小写 / punycode / 尾点剥掉），与 `origin_of` 同一口径。
        for (base, expected) in [
            ("https://h.example.com", "https://h.example.com/login"),
            ("https://h.example.com/", "https://h.example.com/login"),
            (
                "https://h.example.com/api/v1?x=1",
                "https://h.example.com/api/v1/login",
            ),
            ("HTTPS://H.example.com", "https://h.example.com/login"),
            ("http://127.0.0.1:8787/x", "http://127.0.0.1:8787/x/login"),
            // 子路径部署（P3-24 的主场景）
            (
                "https://h.example.com/relay",
                "https://h.example.com/relay/login",
            ),
            (
                "https://h.example.com/relay/",
                "https://h.example.com/relay/login",
            ),
            // 尾点 FQDN：规范化后与不带尾点同形
            (
                "https://h.example.com./relay",
                "https://h.example.com/relay/login",
            ),
        ] {
            assert_eq!(captcha_page_url(base).unwrap(), expected, "输入 {base}");
        }
    }

    /// M16-S3 P3-24：**同一台主机**的四种写法必须给出同一个 origin（此前三种被误判为不同源，
    /// 失败关闭 ⇒ 这些站点永远提交不了验证码）。
    #[test]
    fn origin_matches_normalizes_idn_trailing_dot_and_port() {
        // ① IDN：punycode 与 Unicode 域名是同一个 origin（WHATWG/IDNA）
        assert!(origin_matches(
            "https://xn--80ak6aa92e.com",
            "https://xn--80ak6aa92e.com/login"
        ));
        // ② 尾点 FQDN
        assert!(origin_matches(
            "https://h.example.com",
            "https://h.example.com./login"
        ));
        assert!(origin_matches(
            "https://h.example.com.",
            "https://h.example.com/login"
        ));
        // ③ 前导零端口
        assert!(origin_matches(
            "https://h.example.com:443",
            "https://h.example.com:0443/login"
        ));
        assert!(origin_matches(
            "http://h.example.com:080",
            "http://h.example.com/login"
        ));
        // ④ 仍然失败关闭：解析不出 ⇒ false
        assert!(!origin_matches("https://h.example.com", "not a url"));
        assert!(!origin_matches("not a url", "https://h.example.com/login"));
        assert!(!origin_matches("file:///etc/passwd", "file:///etc/passwd"));
        // ⑤ 不同 origin 仍然不同（归一化不能把不同主机混成一个）
        assert!(!origin_matches(
            "https://h.example.com",
            "https://h.example.com.evil.example/login"
        ));
        assert!(!origin_matches(
            "https://h.example.com",
            "https://xn--80ak6aa92e.com/login"
        ));
    }

    /// M16-S3 P2-20 的**对抗性**不变式：验证码页面所在的主机，必须与适配器真正
    /// 发请求时（`{base}/api/status`）落到的主机**同一台**。
    ///
    /// 报告的场景：`https://evil.example\@good.example` —— 手写解析认 good.example
    /// 而请求发往 evil.example ⇒ good.example 上过完 2FA 的 cookie 被送到 evil.example。
    /// 现在两侧都过同一个 WHATWG 解析器，这条不变式可执行地钉住它。
    #[test]
    fn captcha_page_host_equals_the_host_the_adapter_requests() {
        for base in [
            "https://h.example.com",
            "https://h.example.com/relay",
            "https://alice:pw@h.example.com/x",
            "https://evil.example\\@good.example",
            "https://h.example.com./relay",
            "http://127.0.0.1:8787/x",
            "https://xn--80ak6aa92e.com",
        ] {
            let page = captcha_page_url(base).unwrap_or_else(|e| panic!("{base} ⇒ {e}"));
            let api = format!("{}/api/status", base.trim_end_matches('/'));
            // 比的是**规范化 origin**（`origin_of` 就是归属判定用的那一个）：
            // 尾点 FQDN 这类写法字符串不同、主机语义相同，必须按语义比。
            let page_origin = origin_of(&page).unwrap_or_else(|| panic!("{page} 应有 origin"));
            let api_origin = origin_of(&api).unwrap_or_else(|| panic!("{api} 应有 origin"));
            assert_eq!(
                page_origin, api_origin,
                "验证码页面与适配器请求必须落在同一个 origin（否则 cookie 会被送到别处）: {base}"
            );
        }
    }

    #[test]
    fn captcha_page_url_never_carries_userinfo() {
        for base in [
            "https://alice:supersecret123@host.example",
            "https://bob:pw123456@host.example/api",
            "https://token@host.example",
        ] {
            let url = captcha_page_url(base).unwrap();
            assert!(!url.contains('@'), "{base} ⇒ {url}");
            assert!(!url.contains("alice") && !url.contains("supersecret123"));
            assert!(url.ends_with("/login"), "{url}");
            assert!(url.contains("host.example"), "{url}");
        }
    }

    #[test]
    fn captcha_page_url_rejects_non_http_schemes() {
        for bad in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,<b>x</b>",
            "host.example.com",
            "ftp://host.example.com",
        ] {
            let err = captcha_page_url(bad).expect_err("必须拒绝：{bad}");
            assert!(matches!(err, Error::Transport(_)), "{bad}: {err:?}");
        }
        // 拒绝的文案本身也不能回显 userinfo
        let err = captcha_page_url("ftp://alice:pw@host.example").unwrap_err();
        assert!(!err.to_string().contains("pw"), "{err}");
    }

    #[test]
    fn captcha_page_url_never_points_at_a_third_party() {
        // spec §11 证据 ⑧ 的输入表：结果的 origin 恒等于站点 origin。
        for base in [
            "https://a.example.com",
            "https://a.example.com/",
            "https://a.example.com/deep/path",
            "https://a.example.com:8443",
            "http://a.example.com",
            "https://u:p@a.example.com/x?y#z",
        ] {
            let url = captcha_page_url(base).unwrap();
            assert!(
                origin_matches(base, &url),
                "{base} ⇒ {url} 的 origin 必须与站点同源"
            );
        }
    }

    #[test]
    fn captcha_page_url_treats_backslash_as_authority_separator_whatwg() {
        // P2-20 / DEBUG-REPORT-v3 §2-20：`https://evil.example\@good.example`——
        // WHATWG 把 `\` 当 `/`（authority 在 `\` 处结束），reqwest/浏览器认 host=
        // evil.example。手写解析不把 `\` 当终止符 ⇒ authority = `evil.example\@good.example`，
        // rfind('@') ⇒ host = good.example，与适配器请求（evil.example）不一致 ⇒
        // good.example 已过 2FA/验证码的会话 cookie 被发给 evil.example。
        // 现在 authority 终止符加 `\`，与 WHATWG 一致。
        let url = captcha_page_url("https://evil.example\\@good.example").unwrap();
        assert!(
            url.starts_with("https://evil.example/"),
            "反斜杠是 authority 终止符（WHATWG），host 应是 evil.example: {url}"
        );
        assert!(
            !url.contains("good.example"),
            "不得认成 good.example（否则 cookie 归属错）: {url}"
        );
    }

    // ============================================================ T5 origin 比对

    #[test]
    fn origin_matches_is_exact_on_scheme_host_port() {
        let base = "https://h.example.com";
        assert!(origin_matches(base, "https://h.example.com/login"));
        assert!(origin_matches(base, "https://h.example.com"));
        assert!(origin_matches(base, "https://h.example.com:443/x"));
        assert!(
            origin_matches(base, "https://H.EXAMPLE.com/x"),
            "host 大小写不敏感"
        );

        assert!(
            !origin_matches(base, "http://h.example.com/login"),
            "换 scheme"
        );
        assert!(
            !origin_matches(base, "https://evil.example.com/x"),
            "换 host"
        );
        assert!(
            !origin_matches(base, "https://sub.h.example.com/x"),
            "加子域"
        );
        assert!(
            !origin_matches(base, "https://h.example.com:8443/x"),
            "换端口"
        );
        assert!(
            !origin_matches(base, "https://h.example.com.evil.com/x"),
            "后缀伪装"
        );
        assert!(!origin_matches(base, "not a url"));
        assert!(!origin_matches(base, "file:///etc/passwd"));

        assert!(origin_matches(
            "http://h.example.com",
            "http://h.example.com:80/x"
        ));
        assert!(origin_matches(
            "https://h.example.com:8443",
            "https://h.example.com:8443/x"
        ));
    }

    // ============================================================ T6–T7 cookie 校验

    #[test]
    fn captcha_validation_table() {
        // 1 空列表
        assert!(validate_captcha_cookies(&[]).is_err());
        // 2 超条数
        let many: Vec<(String, String)> = (0..MAX_CAPTCHA_COOKIES + 1)
            .map(|i| (format!("c{i}"), "v".to_string()))
            .collect();
        let err = validate_captcha_cookies(&many).unwrap_err();
        assert!(err.to_string().contains("条数"), "{err}");
        // 3 空键名
        assert!(validate_captcha_cookies(&cookies(&[("", "v")])).is_err());
        // 4 空值
        assert!(validate_captcha_cookies(&cookies(&[("session", "")])).is_err());
        // 5 键名非法字符
        for bad in ["a=b", "a;b", "a,b", "a b", "a\tb"] {
            assert!(
                validate_captcha_cookies(&cookies(&[(bad, "v")])).is_err(),
                "键名 {bad:?} 应被拒"
            );
        }
        // 6 值含控制字符 / 非可见 ASCII
        for bad in ["a\r\nb", "a\0b", "值", "a b"] {
            assert!(
                validate_captcha_cookies(&cookies(&[("session", bad)])).is_err(),
                "值 {bad:?} 应被拒"
            );
        }
        // 7 单值超长
        let long = "x".repeat(MAX_CAPTCHA_COOKIE_VALUE_BYTES + 1);
        let err = validate_captcha_cookies(&cookies(&[("session", &long)])).unwrap_err();
        assert!(err.to_string().contains("长度"), "{err}");
        // 8 总量超长（每条都在单值上限内）
        let chunk = "y".repeat(4000);
        let bulk: Vec<(String, String)> =
            (0..5).map(|i| (format!("c{i}"), chunk.clone())).collect();
        let err = validate_captcha_cookies(&bulk).unwrap_err();
        assert!(err.to_string().contains("总长度"), "{err}");
        // 9 同名多条 ⇒ Ok（原样保留）
        assert!(validate_captcha_cookies(&cookies(&[("session", "a"), ("session", "b")])).is_ok());
        // 10 正常形态
        assert!(validate_captcha_cookies(&cookies(&[
            ("session", "abc123"),
            ("cf_clearance", "1.2-3_4.5~6-abc"),
            ("token", "a=b=c"),
        ]))
        .is_ok());
    }

    #[test]
    fn captcha_validation_errors_never_echo_the_cookie_value() {
        // 每条失败规则各构造一个**含 cookie 值**的输入，断言错误文案不含它。
        let secret = "SUPER-SECRET-COOKIE-VALUE";
        let cases: Vec<Vec<(String, String)>> = vec![
            // 3：另一条键名为空，但这一条带着秘密
            vec![
                (String::new(), secret.to_string()),
                ("session".to_string(), secret.to_string()),
            ],
            // 4：值为空的那条带秘密键名（值空，秘密在别条）
            vec![
                ("session".to_string(), String::new()),
                ("s2".to_string(), secret.to_string()),
            ],
            // 5：非法键名 + 带秘密的值
            vec![("a=b".to_string(), secret.to_string())],
            // 6：值含控制字符（秘密 + CRLF）
            vec![("session".to_string(), format!("{secret}\r\n"))],
            // 7：超长值（秘密开头）
            vec![(
                "session".to_string(),
                format!("{secret}{}", "x".repeat(MAX_CAPTCHA_COOKIE_VALUE_BYTES)),
            )],
            // 8：总量超长（每条都在单值上限内 ⇒ 只能靠总量规则拒绝）
            vec![
                ("a".to_string(), format!("{secret}{}", "y".repeat(4000))),
                ("b".to_string(), "z".repeat(4000)),
                ("c".to_string(), "z".repeat(4000)),
                ("d".to_string(), "z".repeat(4000)),
                ("e".to_string(), "z".repeat(4000)),
            ],
        ];
        for input in cases {
            let err = validate_captcha_cookies(&input).expect_err("应当被拒");
            let text = err.to_string();
            assert!(!text.contains(secret), "错误文案回显了 cookie 值: {text}");
            assert!(!text.contains("SUPER"), "{text}");
        }
        // 空列表这条没有值可回显，但仍要是「格式校验」的口径
        let err = validate_captcha_cookies(&[]).unwrap_err();
        assert!(err.to_string().contains("格式校验"), "{err}");
    }

    // ============================================================ T8 状态机

    #[test]
    fn captcha_state_machine_transitions() {
        use CaptchaEvent as E;
        use CaptchaPhase as P;

        // T1：进人工态，site_id 来自 challenge
        let p = step(
            P::Idle,
            E::LoginRejected {
                challenge: challenge(7),
            },
        );
        match &p {
            P::AwaitingHuman { site_id, challenge } => {
                assert_eq!(*site_id, 7);
                assert_eq!(challenge.url, "https://h.example.com/login");
            }
            other => panic!("T1: {other:?}"),
        }
        // T2：别的失败不进人工态
        assert_eq!(step(P::Idle, E::LoginFailed), P::Idle);
        // T3：重复触发替换 challenge
        let p2 = step(
            p.clone(),
            E::LoginRejected {
                challenge: challenge(7),
            },
        );
        assert_eq!(p2, p);
        // T4：提交通过 ⇒ Idle
        assert_eq!(step(p.clone(), E::CookiesSubmitted { ok: true }), P::Idle);
        // T5：提交失败 ⇒ 留在人工态（challenge 不变）
        assert_eq!(
            step(p.clone(), E::CookiesSubmitted { ok: false }),
            p,
            "校验失败不是终局：用户应当能重开窗口再试"
        );
        // T6：取消 ⇒ Idle
        assert_eq!(step(p.clone(), E::Cancelled), P::Idle);
        // T7：Idle 收到 cookie ⇒ 忽略（不建会话）
        assert_eq!(step(P::Idle, E::CookiesSubmitted { ok: true }), P::Idle);
        assert_eq!(step(P::Idle, E::CookiesSubmitted { ok: false }), P::Idle);
        // T8：Idle 收到取消 ⇒ 幂等
        assert_eq!(step(P::Idle, E::Cancelled), P::Idle);
        // 人工态里别的登录失败 ⇒ 保持人工态（用户在窗口里又试了一次登录）
        assert_eq!(step(p.clone(), E::LoginFailed), p);
    }

    // ============================================================ T9–T10 Debug

    #[test]
    fn captcha_challenge_debug_prints_only_the_host() {
        let c = CaptchaChallenge {
            site_id: 3,
            url: "https://h.example.com/login?redirect=/x#f".to_string(),
        };
        let text = format!("{c:?}");
        assert!(text.contains("3"), "{text}");
        assert!(text.contains("h.example.com"), "{text}");
        assert!(!text.contains("/login"), "不打 path: {text}");
        assert!(!text.contains("redirect"), "不打 query: {text}");
        assert!(!text.contains("f"), "{text}");

        let with_userinfo = CaptchaChallenge {
            site_id: 4,
            url: "https://alice:pw@h.example.com/login".to_string(),
        };
        let text = format!("{with_userinfo:?}");
        assert!(!text.contains("alice") && !text.contains("pw"), "{text}");
    }

    #[test]
    fn session_from_captcha_cookies_keeps_pairs_and_hides_them_in_debug() {
        let secret = "SESSION-VALUE-abcdef";
        let cookies = cookies(&[("session", secret), ("cf_clearance", "1.2-3")]);
        let session = session_from_captcha_cookies(&cookies);
        assert_eq!(session.cookies, cookies, "逐条原样保留");
        assert!(session.access_token.is_none());
        let text = format!("{session:?}");
        assert!(!text.contains(secret), "{text}");
        assert!(!text.contains("cf_clearance"), "{text}");
        assert!(text.contains("2 项"), "{text}");
    }
}
