//! M6-S3 通知渠道的集成测试：**本地假 HTTP 端点 + 注入式 runner**。
//!
//! 硬约束（`docs/specs/M6-S3-通知渠道.md` §8）：
//! - 全部走 `127.0.0.1` 上的极简假服务器，**不打外网**；
//! - 系统通知走注入式 `CommandRunner`，**不弹真实通知、不起真实进程**；
//! - 断言的是「最终产物里没有密钥」，而不是「我信任上游已经脱敏了」。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use keyrelay_core::drift::DriftState;
use keyrelay_core::error::{Error, Result};
use keyrelay_core::notify::{
    evaluate, BalanceSnapshot, CommandRunner, DriftFact, Notification, Notifier, NotifyConfig,
    NotifyKind, NotifyPlatform, RotationDueFact, SiteSnapshot, Snapshot, SystemNotifier,
    WebhookNotifier, WebhookTransport,
};

const SECRET: &str = "sk-0123456789abcdefSECRET";
const NAP: &str = "nap-0123456789abcdefNAP";
const PAT: &str = "0123456789abcdef0123456789abcdef";
const NOW: i64 = 1_700_000_000;

// ---------------------------------------------------------------- 假 HTTP 端点

struct FakeServer {
    base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
}

fn http_response(status_line: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn read_request(stream: &mut TcpStream) -> String {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf).to_string();
                if let Some(head_end) = text.find("\r\n\r\n") {
                    let content_length = text[..head_end]
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            if name.eq_ignore_ascii_case("content-length") {
                                value.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    if buf.len() >= head_end + 4 + content_length {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

/// 起一个只会应答 `responses` 的假端点（**回环、明文 HTTP**）。
fn spawn_server(responses: Vec<String>) -> FakeServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取本地地址");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&requests);

    thread::spawn(move || {
        for response in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let raw = read_request(&mut stream);
            if let Ok(mut recorded) = recorder.lock() {
                recorded.push(raw);
            }
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    FakeServer {
        base_url: format!("http://{addr}"),
        requests,
    }
}

/// 接受连接但**永不响应**：用于验证超时被遵守。
fn spawn_silent_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取本地地址");
    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            thread::sleep(Duration::from_secs(3));
            drop(stream);
        }
    });
    format!("http://{addr}")
}

fn requests_of(server: &FakeServer) -> Vec<String> {
    server
        .requests
        .lock()
        .map(|r| r.clone())
        .unwrap_or_default()
}

/// 取出原始请求里的 body 部分（假端点是明文 HTTP，直接按 `\r\n\r\n` 切）。
fn body_of(raw: &str) -> String {
    raw.split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default()
}

/// 最长的十六进制连续段长度。复审的探针会扫「32 位 hex」，这里用同一条规则自检。
fn longest_hex_run(text: &str) -> usize {
    let mut longest = 0usize;
    let mut current = 0usize;
    for c in text.chars() {
        if c.is_ascii_hexdigit() {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

// ---------------------------------------------------------------- 假 runner / 假传输

/// 记录到的 `(program, args)` 调用。
type CallLog = Arc<Mutex<Vec<(String, Vec<String>)>>>;
/// 记录到的 `(url, body, timeout)` 调用。
type PostLog = Arc<Mutex<Vec<(String, Vec<u8>, Duration)>>>;

/// 记录 argv 的假 runner：**不执行任何进程**。
#[derive(Default, Clone)]
struct RecordingRunner {
    calls: CallLog,
}

impl RecordingRunner {
    fn calls(&self) -> Vec<(String, Vec<String>)> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

impl CommandRunner for RecordingRunner {
    fn run(&self, program: &str, args: &[String]) -> Result<String> {
        self.calls
            .lock()
            .map_err(|_| Error::Transport("记录锁中毒".into()))?
            .push((program.to_string(), args.to_vec()));
        Ok(String::new())
    }
}

/// 记录调用的假传输：不碰网络。
#[derive(Default, Clone)]
struct RecordingTransport {
    seen: PostLog,
    status: u16,
}

impl WebhookTransport for RecordingTransport {
    fn post(&self, url: &str, body: &[u8], timeout: Duration) -> Result<u16> {
        self.seen
            .lock()
            .map_err(|_| Error::Transport("记录锁中毒".into()))?
            .push((url.to_string(), body.to_vec(), timeout));
        Ok(self.status)
    }
}

// ---------------------------------------------------------------- 测试数据

fn config(url: Option<&str>) -> NotifyConfig {
    NotifyConfig {
        webhook_url: url.map(str::to_string),
        timeout: Duration::from_secs(5),
        ..NotifyConfig::default()
    }
}

fn balance(remaining: f64, used: f64) -> Option<BalanceSnapshot> {
    Some(BalanceSnapshot {
        remaining,
        used,
        currency: "USD".to_string(),
    })
}

fn site(id: i64, name: &str) -> SiteSnapshot {
    SiteSnapshot {
        site_id: id,
        display_name: name.to_string(),
        ..SiteSnapshot::default()
    }
}

/// 一轮里 7 条规则全部命中的快照对（含密钥形态的对抗性输入）。
fn round_trip_snapshots() -> (Snapshot, Snapshot) {
    let prev = Snapshot {
        sites: vec![SiteSnapshot {
            balance: balance(30.0, 5.0),
            models: Some(vec!["gpt-4".to_string()]),
            ..site(1, "测试站点")
        }],
    };
    let curr = Snapshot {
        sites: vec![SiteSnapshot {
            // 站点显示名与货币字段都塞成密钥形态：构造侧必须掩掉
            display_name: SECRET.to_string(),
            balance: Some(BalanceSnapshot {
                remaining: 1.5,
                used: 20.0,
                currency: NAP.to_string(),
            }),
            needs_login: true,
            quota_exceeded: true,
            models: Some(vec!["gpt-4".to_string(), SECRET.to_string()]),
            drift: vec![DriftFact {
                target_path: format!("/Users/me/.codex/auth.json?k={PAT}"),
                agent_id: "codex".to_string(),
                channel: "codex-auth-json".to_string(),
                state: DriftState::Modified,
            }],
            rotation_due: vec![RotationDueFact {
                key_id: 7,
                name: SECRET.to_string(),
                due_at: NOW - 1,
            }],
            ..site(1, "测试站点")
        }],
    };
    (prev, curr)
}

fn assert_no_secret(label: &str, text: &str) {
    for needle in [SECRET, NAP, PAT] {
        assert!(!text.contains(needle), "{label} 里出现明文凭据: {text}");
    }
    assert!(
        longest_hex_run(text) < 32,
        "{label} 里出现 32 位以上的 hex 段（len={}）: {text}",
        longest_hex_run(text)
    );
}

// ---------------------------------------------------------------- 真栈 + 假端点

#[test]
fn webhook_posts_json_with_the_documented_shape() {
    let server = spawn_server(vec![http_response("200 OK", "application/json", "{}")]);
    let notifier = WebhookNotifier::new(config(Some(&format!("{}/hook", server.base_url))));

    let notification = Notification::new(
        NotifyKind::BalanceLow,
        Some(7),
        "余额不足",
        "测试站点: 剩余 3.5 USD，低于阈值 15",
        NOW,
    );
    notifier.send(&notification).expect("200 → 成功");

    let raw = requests_of(&server);
    assert_eq!(raw.len(), 1, "恰好一次请求");
    let request = &raw[0];
    assert!(
        request.starts_with("POST /hook HTTP/1.1"),
        "实际请求: {request}"
    );
    assert!(
        request
            .to_lowercase()
            .contains("content-type: application/json"),
        "缺少 Content-Type: {request}"
    );

    let body = body_of(request);
    assert_eq!(
        body,
        r#"{"kind":"balance_low","site_id":7,"title":"余额不足","body":"测试站点: 剩余 3.5 USD，低于阈值 15","ts":1700000000}"#
    );
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("body 必须是合法 JSON");
    assert_eq!(parsed["kind"], "balance_low");
    assert_eq!(parsed["site_id"], 7);
    assert_eq!(parsed["ts"], NOW);
}

#[test]
fn webhook_body_never_carries_a_secret_on_the_wire() {
    let server = spawn_server(vec![http_response("200 OK", "application/json", "{}")]);
    let notifier = WebhookNotifier::new(config(Some(&format!("{}/hook", server.base_url))));

    // 手工拼一个**绕过构造侧**的通知：发送侧必须兜住
    let raw_notification = Notification {
        kind: NotifyKind::Drift,
        site_id: Some(1),
        title: format!("标题 {SECRET}"),
        body: format!("正文 {NAP} 与 {PAT}"),
        ts: NOW,
    };
    notifier.send(&raw_notification).expect("200 → 成功");

    let request = requests_of(&server).remove(0);
    let body = body_of(&request);
    assert_no_secret("webhook 报文", &body);

    // 结构不能被脱敏破坏
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("body 必须是合法 JSON");
    assert_eq!(parsed["kind"], "drift");
    assert_eq!(parsed["title"], "标题 sk-***");
    assert_eq!(parsed["body"], "正文 nap-*** 与 ***");
}

#[test]
fn webhook_does_not_retry_on_5xx() {
    let server = spawn_server(vec![http_response(
        "500 Internal Server Error",
        "application/json",
        r#"{"error":{"message":"upstream sk-0123456789abcdefSECRET"}}"#,
    )]);
    let notifier = WebhookNotifier::new(config(Some(&format!("{}/hook", server.base_url))));

    let err = notifier
        .send(&Notification::new(
            NotifyKind::NeedsLogin,
            Some(1),
            "登录态失效",
            "测试站点: 会话已失效，需要重新登录",
            NOW,
        ))
        .expect_err("500 必须失败");
    assert!(err.to_string().contains("HTTP 500"), "{err}");
    assert_eq!(requests_of(&server).len(), 1, "不重试：只发一次");
    // 响应体是上游自由文本，不进错误串
    assert!(!err.to_string().contains("sk-"), "{err}");
}

#[test]
fn webhook_does_not_follow_redirects() {
    let server = spawn_server(vec![
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/hook\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_string(),
    ]);
    let notifier = WebhookNotifier::new(config(Some(&format!("{}/hook", server.base_url))));

    let err = notifier
        .send(&Notification::new(
            NotifyKind::Drift,
            Some(1),
            "配置漂移",
            "x",
            NOW,
        ))
        .expect_err("3xx 不是 2xx");
    assert!(err.to_string().contains("HTTP 302"), "{err}");
    assert_eq!(requests_of(&server).len(), 1, "不得跟随重定向");
}

#[test]
fn webhook_obeys_the_configured_timeout() {
    let base_url = spawn_silent_server();
    let notifier = WebhookNotifier::with_transport(
        NotifyConfig {
            timeout: Duration::from_millis(300),
            ..config(Some(&format!("{base_url}/hook")))
        },
        Box::new(keyrelay_core::notify::ReqwestWebhookTransport),
    );

    let started = Instant::now();
    let err = notifier
        .send(&Notification::new(
            NotifyKind::Drift,
            Some(1),
            "配置漂移",
            "x",
            NOW,
        ))
        .expect_err("静默端点必须超时");
    let elapsed = started.elapsed();

    assert!(
        err.to_string().contains("超时"),
        "超时必须被如实报告: {err}"
    );
    assert!(
        elapsed >= Duration::from_millis(250),
        "耗时 {elapsed:?} 太短：像是立刻失败而不是等超时"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "耗时 {elapsed:?}：超时没有被遵守（配置是 300ms）"
    );
}

#[test]
fn webhook_with_zero_timeout_is_a_race_but_never_hangs() {
    // `timeout` 由调用方保证 > 0（S5 的 `notify_timeout_secs` 默认 10、上限 60）。
    //
    // 实测（本机 macOS aarch64 + reqwest 0.13，本地假端点）：`Duration::ZERO` **不是**
    // 「不限时」，而是一个零期限 —— 谁先完成谁赢。同一个二进制里**两种结果都出现过**：
    //   `Ok(())`（547µs）与 `Err("webhook 请求超时（http://127.0.0.1:…）")`（4.9ms）。
    // 所以 `timeout = 0` 是**竞态**、不可依赖 → 给 S5 的结论：`Settings::validate`
    // 应当拒绝 0（或映射时兜到 ≥ 1s），否则用户把超时设成 0 会得到「时灵时不灵」的 webhook。
    //
    // 这条测试只钉住**确定性**的那部分：不挂死，且结果只能是这两种之一。
    let mut outcomes: Vec<&'static str> = Vec::new();
    for _ in 0..5 {
        let server = spawn_server(vec![http_response("200 OK", "application/json", "{}")]);
        let notifier = WebhookNotifier::with_transport(
            NotifyConfig {
                timeout: Duration::ZERO,
                ..config(Some(&format!("{}/hook", server.base_url)))
            },
            Box::new(keyrelay_core::notify::ReqwestWebhookTransport),
        );

        let started = Instant::now();
        let outcome = notifier.send(&Notification::new(
            NotifyKind::Drift,
            Some(1),
            "配置漂移",
            "x",
            NOW,
        ));
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(5),
            "耗时 {elapsed:?}：`timeout = 0` 挂死了（调用方必须传 > 0）"
        );
        outcomes.push(match outcome {
            Ok(()) => "ok",
            Err(e) => {
                let text = e.to_string();
                assert!(
                    text.contains("请求超时"),
                    "`timeout = 0` 只应产出「超时」错误，实测: {text}"
                );
                "timeout"
            }
        });
    }
    println!("timeout=0 的五次实测: {outcomes:?}");
}

#[test]
fn webhook_error_does_not_leak_url_credentials_on_a_dead_port() {
    // 端口 1 上不会有服务：真实 reqwest 错误里会带完整 URL
    let notifier = WebhookNotifier::new(config(Some(
        "http://alice:s3cr3t-token@127.0.0.1:1/hook?token=s3cr3t-token",
    )));
    let err = notifier
        .send(&Notification::new(
            NotifyKind::Drift,
            Some(1),
            "配置漂移",
            "x",
            NOW,
        ))
        .expect_err("连不上必须失败");
    let message = err.to_string();
    assert!(!message.contains("s3cr3t-token"), "泄漏凭据: {message}");
    assert!(!message.contains("alice"), "泄漏用户名: {message}");
    assert!(
        message.contains("127.0.0.1:1"),
        "应保留可诊断的主机: {message}"
    );
}

#[test]
fn webhook_passes_url_and_timeout_through_the_transport() {
    let transport = RecordingTransport {
        status: 204,
        ..RecordingTransport::default()
    };
    let notifier = WebhookNotifier::with_transport(
        NotifyConfig {
            timeout: Duration::from_millis(4321),
            ..config(Some("https://hook.example.com/notify"))
        },
        Box::new(transport.clone()),
    );

    notifier
        .send(&Notification::new(
            NotifyKind::Drift,
            Some(1),
            "配置漂移",
            "x",
            NOW,
        ))
        .expect("204 → 成功");

    let calls = transport.seen.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "https://hook.example.com/notify");
    assert_eq!(calls[0].2, Duration::from_millis(4321));
}

// ---------------------------------------------------------------- 端到端：判定 → 两条渠道

#[test]
fn evaluate_then_dispatch_keeps_both_channels_clean() {
    let (prev, curr) = round_trip_snapshots();
    let cfg = NotifyConfig {
        balance_threshold: 15.0,
        ..config(None)
    };
    let notifications = evaluate(Some(&prev), &curr, &cfg, NOW);

    // 7 条规则各命中一次（含被掩掉的对抗性输入）
    assert_eq!(
        notifications.iter().map(|n| n.kind).collect::<Vec<_>>(),
        vec![
            NotifyKind::BalanceLow,
            NotifyKind::UsageSpike,
            NotifyKind::NeedsLogin,
            NotifyKind::ModelsChanged,
            NotifyKind::QuotaExceeded,
            NotifyKind::Drift,
            NotifyKind::RotationDue,
        ]
    );

    // ① 系统通知出口：argv 里不得有明文
    let runner = RecordingRunner::default();
    let system = SystemNotifier::with_platform(Box::new(runner.clone()), NotifyPlatform::MacOs);
    for n in &notifications {
        system.send(n).expect("假 runner 必定成功");
    }
    let calls = runner.calls();
    assert_eq!(calls.len(), 7, "7 条通知各发一次系统通知");
    for (program, args) in &calls {
        assert_eq!(program, "osascript");
        assert_no_secret("系统通知 argv", &args.join(" "));
    }
    assert!(
        calls
            .iter()
            .any(|(_, args)| args[1].contains("密钥 #7 已到期")),
        "轮换通知必须带 key_id 而不是密钥名: {calls:?}"
    );

    // ② Webhook 出口：线上原始字节里不得有明文
    let server = spawn_server(
        (0..7)
            .map(|_| http_response("200 OK", "application/json", "{}"))
            .collect(),
    );
    let webhook = WebhookNotifier::new(config(Some(&format!("{}/notify", server.base_url))));
    for n in &notifications {
        webhook.send(n).expect("200 → 成功");
    }
    let requests = requests_of(&server);
    assert_eq!(requests.len(), 7);
    for request in &requests {
        assert!(request.starts_with("POST /notify HTTP/1.1"), "{request}");
        let body = body_of(request);
        assert_no_secret("webhook 报文", &body);
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("合法 JSON");
        assert!(parsed["kind"].is_string(), "{body}");
        assert_eq!(parsed["site_id"], 1, "{body}");
    }
}

#[test]
fn a_site_whose_display_name_is_a_secret_still_produces_clean_notifications() {
    // 构造侧脱敏的**独立**验证：不经过 `Notification::new` 的手工拼装走的是发送侧，
    // 这条走的是 `evaluate` → 构造侧。
    let curr = Snapshot {
        sites: vec![SiteSnapshot {
            balance: balance(1.0, 0.0),
            display_name: SECRET.to_string(),
            ..site(1, "测试站点")
        }],
    };
    let notes = evaluate(
        None,
        &curr,
        &NotifyConfig {
            balance_threshold: 15.0,
            ..config(None)
        },
        NOW,
    );
    assert_eq!(notes.len(), 1);
    assert_no_secret("构造侧产物", &notes[0].title);
    assert_no_secret("构造侧产物", &notes[0].body);
    assert_eq!(notes[0].body, "sk-***: 剩余 1 USD，低于阈值 15");
}
