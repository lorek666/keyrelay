//! Webhook 通知渠道：`POST <url>` + JSON 报文。
//!
//! 冻结语义（章程 §4.3）：
//! - `Content-Type: application/json`，body 为
//!   `{"kind":"<snake_case>","site_id":<n|null>,"title":"…","body":"…","ts":<unix秒>}`；
//! - body 发送前**必须**过 [`crate::redact::scrub`]（含 title 与 body）；
//! - 非 2xx → `Err`；**不重试**；超时用 [`super::NotifyConfig::timeout`]。
//!
//! # 为什么传输抽象是**同步**的
//!
//! [`Notifier::send`] 是同步方法，而 S5 会在**异步的** `refresh_all` 之后调用它
//! （`M6-S5-接线与运行时.md` §4）。在调用线程里 `block_on` 会 panic
//! （`Cannot start a runtime from within a runtime`），因此真实实现
//! （[`ReqwestWebhookTransport`]）把 tokio 运行时建在**独立工作线程**上。
//! 传输抽象做成同步的，注入式假传输就不需要碰运行时——测试里没有异步、没有网络。

use std::time::Duration;

use crate::error::{Error, Result};
use crate::redact::{mask_url_userinfo_in_json, scrub, strip_url_userinfo};
use crate::site::transport::{HttpRequest, HttpTransport, Method};
use crate::site::transport_reqwest::{ReqwestTransport, TransportConfig};

use super::{Notification, Notifier, NotifyConfig};

/// Webhook 的传输抽象（同步）。返回 HTTP 状态码。
pub trait WebhookTransport: Send + Sync {
    fn post(&self, url: &str, body: &[u8], timeout: Duration) -> Result<u16>;
}

/// 生产实现：复用站点侧的 [`ReqwestTransport`]（同一套 UA / 重定向策略 / 错误映射）。
///
/// 每次发送：起一个工作线程 → 在**该线程里**建 current-thread 运行时 → 发请求 → join。
/// 通知是低频事件（一轮刷新最多几条），一次一个线程是可以接受的代价；
/// 换来的是「在异步上下文里调用也不会 panic」这条硬保证。
#[derive(Clone, Copy, Debug, Default)]
pub struct ReqwestWebhookTransport;

impl WebhookTransport for ReqwestWebhookTransport {
    fn post(&self, url: &str, body: &[u8], timeout: Duration) -> Result<u16> {
        let url = url.to_string();
        let body = body.to_vec();
        let worker = std::thread::spawn(move || -> Result<u16> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| Error::Transport(format!("构建 webhook 运行时失败: {e}")))?;
            runtime.block_on(async move {
                let transport = ReqwestTransport::new(TransportConfig {
                    // 总超时与连接超时都取配置值：S5 的 `notify_timeout_secs` 上限是 60s，
                    // 不该被 8s 的默认连接超时悄悄截断
                    timeout,
                    connect_timeout: timeout,
                    ..TransportConfig::default()
                })?;
                let mut request = HttpRequest::new(Method::Post, url);
                request
                    .headers
                    .push(("Content-Type".to_string(), "application/json".to_string()));
                request.body = Some(body);
                let response = transport.request(request).await?;
                Ok(response.status)
            })
        });
        match worker.join() {
            Ok(result) => result,
            // 工作线程 panic 时 `join` 返回 Err：绝不能把「没发出去」当成功
            Err(_) => Err(Error::Transport("webhook 发送线程异常终止".to_string())),
        }
    }
}

/// Webhook 渠道。
pub struct WebhookNotifier {
    config: NotifyConfig,
    transport: Box<dyn WebhookTransport>,
}

impl WebhookNotifier {
    pub fn new(config: NotifyConfig) -> Self {
        Self {
            config,
            transport: Box::new(ReqwestWebhookTransport),
        }
    }

    /// 注入式构造（测试用；生产走 [`WebhookNotifier::new`]）。
    pub fn with_transport(config: NotifyConfig, transport: Box<dyn WebhookTransport>) -> Self {
        Self { config, transport }
    }

    /// 生效中的 URL：`None` / 空串 / 纯空白都算「未启用」。
    ///
    /// 空串必须当未启用：S5 的设置项 `notify_webhook_url` 默认就是 `""`（空 = 不启用），
    /// 若把它当非法 URL，用户一开通知就会收到一条「webhook 地址非法」的错误。
    fn active_url(&self) -> Option<&str> {
        self.config
            .webhook_url
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty())
    }
}

impl Notifier for WebhookNotifier {
    fn send(&self, n: &Notification) -> Result<()> {
        let Some(url) = self.active_url() else {
            // 未配置 = 渠道未启用，不是错误
            return Ok(());
        };
        if !is_http_url(url) {
            return Err(Error::Transport(format!(
                "webhook 地址必须是 http(s) URL，收到的是 {}",
                safe_endpoint(url)
            )));
        }

        // 发送侧兜底脱敏（字段级）→ 序列化 → 整串脱敏（见 `webhook_payload`）
        let payload = webhook_payload(&n.scrubbed());

        let status = self
            .transport
            .post(url, payload.as_bytes(), self.config.timeout)
            .map_err(|e| {
                // 传输层错误的**原文**可能带完整 URL —— reqwest 的 Display 就是
                // `error sending request for url (http://user:pass@host/?token=…)`，
                // 而这条错误最终会进事件表（S5 章程 §4.1 的红线：webhook URL 的凭据
                // 不得进事件与导出）。所以只回显「可安全的主机 + 错误种类」，不转发原文。
                Error::Transport(format!(
                    "webhook {}（{}）",
                    transport_failure_kind(&e),
                    safe_endpoint(url)
                ))
            })?;

        if (200..300).contains(&status) {
            Ok(())
        } else {
            // 只报状态码：响应体是上游自由文本，不进错误串
            Err(Error::Transport(format!("webhook 返回 HTTP {status}")))
        }
    }
}

/// 纯函数：构造 Webhook 报文。
///
/// # 脱敏是两层，两层都留（§3.5-7 / M8-S3 §9）
///
/// 1. **结构化层**（先跑）：对 [`serde_json::Value`] 调 [`mask_url_userinfo_in_json`]——
///    按**值**的边界找 authority，密码里的引号 / 反斜杠 / 空白都算在 authority 之内，
///    且**不要求整个值就是 URL**（句内 URL 也掩）；
/// 2. **文本层**（后跑）：整段 JSON 文本过 [`scrub`]——按文本规则猜 authority 边界
///    （authority 止于 `"` `\` 空白 ⇒ 带引号的密码它掩不住，这正是第 1 层存在的理由），
///    并兜住 `sk-` / `nap-` / 长 hex 这些 URL 之外的凭证形态。
///
/// 两层都不会破坏 JSON：结构化层只改字符串值的内容，`scrub` 的 token 字符集不含 `"`，
/// 掩码只能发生在字符串字面量内部；未加引号的数字只有 `site_id` / `ts`，
/// 数量级远小于「≥32 位 hex」的阈值。
///
/// # 已知边界（M8-S3 独立复审 P1-3，已修但记在这里）
///
/// 结构化层的 authority 只止于 `/` `?` `#` 与值结尾，**不校验** `://` 之后是不是真
/// authority ⇒ 正常句子里的 `foo://bar@baz` 也会被掩成 `foo://***@baz`。方向取
/// 「宁可多掩」：它只影响显示，而漏一个密码的代价不可撤销。
pub fn webhook_payload(n: &Notification) -> String {
    let mut value = serde_json::json!({
        "kind": n.kind.as_str(),
        "site_id": n.site_id,
        "title": n.title,
        "body": n.body,
        "ts": n.ts,
    });
    // 第一层：结构化 URL 掩码（在序列化之前，那时值还是未转义的原样）
    mask_url_userinfo_in_json(&mut value);
    match serde_json::to_string(&value) {
        // 第二层：整串脱敏（含 URL 文本规则 + 前缀型凭证 + 长 hex）
        Ok(text) => scrub(&text),
        // 不可达（`Value` 一定能序列化）。真出问题也绝不把未脱敏的内容发出去。
        Err(_) => scrub(r#"{"kind":"unknown","site_id":null,"title":"","body":"","ts":0}"#),
    }
}

fn is_http_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// 可安全回显的地址：`scheme://host[:port]`，**userinfo / path / query / fragment 一律丢掉**。
///
/// 先过冻结口径的 [`strip_url_userinfo`]（剥 userinfo），再收窄到 authority：
/// `transport_reqwest::mask_proxy` 的复核 N-1 已经确认 —— `@` 之后的 path / query / fragment
/// 同样可能是秘密（`?token=…`），只剥 userinfo 不够。
fn safe_endpoint(url: &str) -> String {
    let stripped = strip_url_userinfo(url);
    let Some((scheme, rest)) = stripped.split_once("://") else {
        return "<无 scheme>".to_string();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return format!("{scheme}://<已隐藏>");
    }
    format!("{scheme}://{authority}")
}

/// 传输层错误的**种类**（只保留种类，不保留原文）。
///
/// 分类靠 `ReqwestTransport::describe` 的既有文案（「请求超时」/「连接失败」/「请求失败」）；
/// 认不出来一律归到「请求失败」——**兜底方向是「少说」而不是「多说」**，因为多说就等于把
/// 原文转发出去，而原文里可能带着 URL 上的凭据。
fn transport_failure_kind(err: &Error) -> &'static str {
    let text = err.to_string();
    if text.contains("超时") {
        "请求超时"
    } else if text.contains("连接失败") {
        "连接失败"
    } else {
        "请求失败"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::{Notification, NotifyKind};
    use std::sync::{Arc, Mutex};

    const SECRET: &str = "sk-0123456789abcdef";
    const PAT: &str = "0123456789abcdef0123456789abcdef";

    fn note() -> Notification {
        Notification {
            kind: NotifyKind::BalanceLow,
            site_id: Some(7),
            title: "余额不足".to_string(),
            body: "测试站点: 剩余 3.5 USD，低于阈值 15".to_string(),
            ts: 1_700_000_000,
        }
    }

    fn config(url: Option<&str>) -> NotifyConfig {
        NotifyConfig {
            webhook_url: url.map(str::to_string),
            ..NotifyConfig::default()
        }
    }

    /// 记录到的 `(url, body, timeout)` 调用。
    type CallLog = Arc<Mutex<Vec<(String, Vec<u8>, Duration)>>>;

    /// 记录调用的假传输：不碰网络，可注入返回状态或错误。
    #[derive(Default, Clone)]
    struct FakeTransport {
        seen: CallLog,
        status: u16,
        error: Option<String>,
    }

    impl FakeTransport {
        fn ok(status: u16) -> Self {
            Self {
                status,
                ..Self::default()
            }
        }

        fn failing(message: &str) -> Self {
            Self {
                error: Some(message.to_string()),
                ..Self::default()
            }
        }

        fn calls(&self) -> Vec<(String, Vec<u8>, Duration)> {
            self.seen.lock().map(|s| s.clone()).unwrap_or_default()
        }
    }

    impl WebhookTransport for FakeTransport {
        fn post(&self, url: &str, body: &[u8], timeout: Duration) -> Result<u16> {
            self.seen
                .lock()
                .map_err(|_| Error::Transport("记录锁中毒".into()))?
                .push((url.to_string(), body.to_vec(), timeout));
            match &self.error {
                Some(message) => Err(Error::Transport(message.clone())),
                None => Ok(self.status),
            }
        }
    }

    #[test]
    fn payload_is_verbatim() {
        assert_eq!(
            webhook_payload(&note()),
            r#"{"kind":"balance_low","site_id":7,"title":"余额不足","body":"测试站点: 剩余 3.5 USD，低于阈值 15","ts":1700000000}"#
        );
    }

    #[test]
    fn payload_uses_null_for_a_missing_site() {
        let mut n = note();
        n.site_id = None;
        assert!(webhook_payload(&n).contains(r#""site_id":null"#));
    }

    #[test]
    fn payload_masks_secrets_in_a_hand_built_notification() {
        // 绕过构造侧：发送侧必须兜住（`send` 里先 `scrubbed()`，`payload` 再整串脱敏）
        let mut n = note();
        n.title = format!("t {SECRET}");
        n.body = format!("b {PAT}");
        let text = webhook_payload(&n.scrubbed());
        assert!(!text.contains(SECRET), "{text}");
        assert!(!text.contains(PAT), "{text}");
        assert!(text.contains("sk-***"), "{text}");
    }

    #[test]
    fn payload_masks_url_userinfo_on_both_layers() {
        // 两个形态各测一个：① 整个值就是 URL（带引号的密码）② URL 嵌在句子里。
        // 两层都留的理由见 `webhook_payload` 的文档。
        let mut n = note();
        n.title = "https://alice:p\"w@hook.example.com/x".to_string();
        n.body = "详见 https://bob:pw2@other.example.com/y 已下线".to_string();

        let text = webhook_payload(&n);
        assert!(!text.contains("alice"), "用户名漏了: {text}");
        assert!(!text.contains("p\"w"), "带引号的密码漏了: {text}");
        assert!(!text.contains("bob"), "句内 URL 的用户名漏了: {text}");
        assert!(!text.contains("pw2"), "句内 URL 的密码漏了: {text}");
        // 可诊断性要留着：主机不丢
        assert!(text.contains("hook.example.com"), "{text}");
        assert!(text.contains("other.example.com"), "{text}");

        // ① 证明文本层**掩不住带引号的密码**：只跑旧的文本层（序列化后整串 scrub），
        //    带引号的密码会因为 `\` 被当成 authority 终止符而整段漏掉。
        let mut value = serde_json::json!({
            "kind": n.kind.as_str(),
            "site_id": n.site_id,
            "title": n.title,
            "body": n.body,
            "ts": n.ts,
        });
        let text_only = scrub(&serde_json::to_string(&value).expect("可序列化"));
        assert!(
            text_only.contains("alice") && text_only.contains("p\\\"w"),
            "文本层本该漏掉带引号的密码（这正是结构化层要补的）: {text_only}"
        );

        // ② 证明文本层**掩不住句内 URL** 的那一半（简单密码它其实掩得住，见下）；
        //    结构化层则两种都掩 —— 它不把 `"` `\` 空白当 authority 终止符。
        mask_url_userinfo_in_json(&mut value);
        let structured_only = serde_json::to_string(&value).expect("可序列化");
        assert!(
            !structured_only.contains("alice"),
            "结构化层必须掩掉整个值是 URL 的那种: {structured_only}"
        );
        assert!(
            !structured_only.contains("bob") && !structured_only.contains("pw2"),
            "结构化层也必须掩掉句内 URL（M8-S3 复审 P1-3 修的正是这个）: {structured_only}"
        );
    }

    #[test]
    fn payload_masks_an_embedded_url_with_an_escaped_password() {
        // M8-S3 独立复审 P1-3 的最小反例：URL **不在值的开头**、且密码含引号。
        // 修前两层全漏——结构化层要求「整个值是 URL」，文本层把 `\` 当 authority 终止符。
        let mut n = note();
        n.title = "见 https://alice:p\"w@hook.example.com/x 已失效".to_string();

        let text = webhook_payload(&n);
        assert!(!text.contains("alice"), "用户名漏了: {text}");
        assert!(!text.contains("p\\\"w"), "带引号的密码漏了: {text}");
        assert!(
            text.contains("hook.example.com"),
            "主机要留着（可诊断性）: {text}"
        );
        // 报文仍是合法 JSON
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("合法 JSON");
        assert_eq!(parsed["kind"], "balance_low");
    }

    #[test]
    fn payload_masks_a_url_whose_password_holds_whitespace_or_angle_brackets() {
        // 同一族的其它终止符：空白、`<`、`>`、反引号。文本层的 authority 在第一个
        // 这类字符处断掉 ⇒ 找不到 `@` ⇒ 漏。结构化层一路读到 `/` `?` `#`。
        for password in ["p w", "p<w", "p>w", "p`w", "p\\\\w"] {
            let mut n = note();
            n.title = format!("站 https://alice:{password}@hook.example.com/x 挂了");
            let text = webhook_payload(&n);
            assert!(
                !text.contains("alice"),
                "密码 {password:?} 的用户名漏了: {text}"
            );
            assert!(
                !text.contains(&format!(":{password}@")),
                "密码 {password:?} 漏了: {text}"
            );
        }
    }

    #[test]
    fn payload_stays_valid_json_with_quotes_newlines_and_control_chars() {
        // 正文里可能出现引号 / 换行 / 制表 / 控制字符（漂移路径、Windows 路径、上游显示名）。
        // serde 会把它们转义；随后的整串 scrub 不得把转义序列弄坏。
        let mut n = note();
        n.title = "带\"引号\"的标题".to_string();
        n.body = "第一行\n第二行\t制表\u{7}响铃\\反斜杠".to_string();
        let text = webhook_payload(&n.scrubbed());
        let parsed: serde_json::Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("报文不是合法 JSON: {e} / {text}"));
        assert_eq!(parsed["title"], "带\"引号\"的标题");
        assert_eq!(parsed["body"], "第一行\n第二行\t制表\u{7}响铃\\反斜杠");
        assert!(text.contains("\\u0007"), "控制字符必须被转义: {text}");
    }

    #[test]
    fn payload_stays_valid_json_under_adversarial_input() {
        // 整串 scrub 不能把 JSON 弄坏：字符串值里的长 hex / 长数字只在引号内被掩，
        // 未加引号的 `site_id` / `ts` 不受影响
        let mut n = note();
        n.body = format!("hex={PAT} digits=1234567890123456789012345678901234");
        let text = webhook_payload(&n.scrubbed());
        let parsed: serde_json::Value = serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("报文不是合法 JSON: {e} / {text}"));
        assert_eq!(parsed["kind"], "balance_low");
        assert_eq!(parsed["site_id"], 7);
        assert_eq!(parsed["ts"], 1_700_000_000);
        assert!(!parsed["body"].as_str().unwrap().contains(PAT));
    }

    #[test]
    fn send_posts_the_payload_with_the_configured_timeout() {
        let transport = FakeTransport::ok(204);
        let cfg = NotifyConfig {
            timeout: Duration::from_millis(1234),
            ..config(Some("https://hook.example.com/x"))
        };
        let notifier = WebhookNotifier::with_transport(cfg, Box::new(transport.clone()));
        notifier.send(&note()).expect("2xx 即成功");

        let calls = transport.calls();
        assert_eq!(calls.len(), 1, "不重试：恰好一次");
        assert_eq!(calls[0].0, "https://hook.example.com/x");
        assert_eq!(calls[0].2, Duration::from_millis(1234), "超时必须透传");
        assert_eq!(
            String::from_utf8(calls[0].1.clone()).unwrap(),
            webhook_payload(&note())
        );
    }

    #[test]
    fn send_accepts_the_whole_2xx_range_and_rejects_everything_else() {
        for status in [200u16, 201, 202, 204, 299] {
            let transport = FakeTransport::ok(status);
            let notifier = WebhookNotifier::with_transport(
                config(Some("http://127.0.0.1:1/hook")),
                Box::new(transport),
            );
            assert!(notifier.send(&note()).is_ok(), "{status} 应视为成功");
        }
        for status in [199u16, 300, 301, 302, 400, 401, 403, 429, 500, 503] {
            let transport = FakeTransport::ok(status);
            let notifier = WebhookNotifier::with_transport(
                config(Some("http://127.0.0.1:1/hook")),
                Box::new(transport.clone()),
            );
            let err = notifier
                .send(&note())
                .expect_err(&format!("{status} 必须失败"));
            assert!(err.to_string().contains(&format!("HTTP {status}")), "{err}");
            assert_eq!(transport.calls().len(), 1, "不重试：每次 send 只发一次");
        }
    }

    #[test]
    fn send_is_a_noop_when_not_configured() {
        for url in [None, Some(""), Some("   ")] {
            let transport = FakeTransport::ok(500);
            let notifier =
                WebhookNotifier::with_transport(config(url), Box::new(transport.clone()));
            notifier.send(&note()).expect("未启用不是错误");
            assert!(transport.calls().is_empty(), "{url:?} 不该发请求");
        }
    }

    #[test]
    fn send_rejects_non_http_urls_without_sending() {
        for url in [
            "file:///etc/passwd",
            "hook.example.com/x",
            "ftp://hook.example.com/x",
        ] {
            let transport = FakeTransport::ok(200);
            let notifier =
                WebhookNotifier::with_transport(config(Some(url)), Box::new(transport.clone()));
            let err = notifier.send(&note()).unwrap_err();
            assert!(matches!(err, Error::Transport(_)), "{url} → {err:?}");
            assert!(transport.calls().is_empty(), "{url} 不该发请求");
        }
    }

    #[test]
    fn send_never_leaks_webhook_credentials_in_errors() {
        // ① 非法 URL 的错误串：只剩 scheme://host
        let notifier = WebhookNotifier::with_transport(
            config(Some("hook://alice:s3cr3t@example.com/x?token=s3cr3t")),
            Box::new(FakeTransport::ok(200)),
        );
        let message = notifier.send(&note()).unwrap_err().to_string();
        assert!(!message.contains("s3cr3t"), "错误串泄漏凭据: {message}");
        assert!(!message.contains("alice"), "错误串泄漏用户名: {message}");
        assert!(
            message.contains("hook://example.com"),
            "应保留可诊断的主机: {message}"
        );
        assert!(!message.contains("/x"), "path 不该回显: {message}");

        // ② 传输层错误里带着完整 URL（reqwest 的 Display 就是这种形态）→ 不转发原文
        let raw =
            "error sending request for url (http://alice:s3cr3t@hook.example.com/x?token=s3cr3t)";
        let notifier = WebhookNotifier::with_transport(
            config(Some("http://alice:s3cr3t@hook.example.com/x?token=s3cr3t")),
            Box::new(FakeTransport::failing(raw)),
        );
        let message = notifier.send(&note()).unwrap_err().to_string();
        assert!(!message.contains("s3cr3t"), "错误串泄漏凭据: {message}");
        assert!(!message.contains("alice"), "错误串泄漏用户名: {message}");
        assert!(!message.contains("token="), "query 不该回显: {message}");
        assert!(
            message.contains("hook.example.com"),
            "应保留可诊断的主机: {message}"
        );
        assert_eq!(
            message,
            "传输错误: webhook 请求失败（http://hook.example.com）"
        );
    }

    #[test]
    fn safe_endpoint_keeps_only_scheme_and_host() {
        assert_eq!(
            safe_endpoint("https://hook.example.com/x?token=SECRET#frag"),
            "https://hook.example.com"
        );
        assert_eq!(
            safe_endpoint("http://alice:pw@127.0.0.1:8080/hook"),
            "http://127.0.0.1:8080"
        );
        assert_eq!(safe_endpoint("http://alice:pw@"), "http://<已隐藏>");
        assert_eq!(safe_endpoint("hook.example.com/x"), "<无 scheme>");
        assert_eq!(safe_endpoint(""), "<无 scheme>");
    }

    #[test]
    fn transport_failure_kind_classifies_without_forwarding_text() {
        let timeout =
            Error::Transport("请求超时: error sending request for url (http://x/)".into());
        assert_eq!(transport_failure_kind(&timeout), "请求超时");
        let refused = Error::Transport("连接失败: tcp connect error".into());
        assert_eq!(transport_failure_kind(&refused), "连接失败");
        let other = Error::Transport("读取响应体失败: 意外 EOF".into());
        assert_eq!(transport_failure_kind(&other), "请求失败");
    }

    #[test]
    fn http_url_check_is_case_insensitive() {
        assert!(is_http_url("http://x"));
        assert!(is_http_url("HTTPS://x"));
        assert!(is_http_url("https://x"));
        assert!(!is_http_url("httpx://x"));
        assert!(!is_http_url(""));
    }
}
