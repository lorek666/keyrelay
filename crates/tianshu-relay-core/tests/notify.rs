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

use tianshu_relay_core::drift::DriftState;
use tianshu_relay_core::error::{Error, Result};
use tianshu_relay_core::notify::{
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

/// 接受连接但**过了 `keep_open` 才关闭**：用于验证超时被遵守。
///
/// `keep_open` 必须由调用方的**配置超时**推导，而且必须比它**长**：
/// - 比超时长 ⇒ 客户端一定先超时，测的才是「超时生效」；
/// - 写成裸 3 秒（本步之前的样子）⇒ 换任何别的超时值来测，夹具可能比客户端先松手，
///   于是客户端收到的是「连接被关闭」而不是「超时」，用例名与实测行为对不上。
fn spawn_silent_server(keep_open: Duration) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取本地地址");
    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            thread::sleep(keep_open);
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
    let notifier = WebhookNotifier::new(config(Some(&format!("{}/hook", server.base_url))), None);

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
    let notifier = WebhookNotifier::new(config(Some(&format!("{}/hook", server.base_url))), None);

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
    let notifier = WebhookNotifier::new(config(Some(&format!("{}/hook", server.base_url))), None);

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
    let notifier = WebhookNotifier::new(config(Some(&format!("{}/hook", server.base_url))), None);

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
    // M21-S1 / B-163：**删掉墙上时钟的绝对上界**，把「超时有没有被遵守」换成错误种类判据。
    //
    // 原来的写法是 `elapsed < 5s`（配置超时才 300ms，等于 16 倍），满载时实测 14.36s 直接红
    // ⇒「机器慢」被误报成「产品没遵守超时」。
    //
    // 本步先试过「把上界改成配置值的 4 倍」，**注入实测证明那救不了**：在 `started` 之后
    // 插 14s 睡眠（等价于满载时线程被推迟调度），新上界照样报「耗时 14.31s」。
    // 原因在结构上：`elapsed` 从 `Instant::now()` 算起，而 reqwest 的超时从**请求发出**才计时。
    // 中间那段——`send()` 里的 `webhook_payload(&n.scrubbed())`、`post()` 里的
    // `thread::spawn` + 从零建一个 tokio 运行时——**超时管不到**，却又被量到了。
    // 所以任何以 `elapsed` 为判据的上界都必然被满载误伤，只能换判据。
    //
    // 换成的判据：错误**种类**。实测锚点——把配置超时改大、让夹具先松手，客户端等不到超时，
    // 收到的是 `webhook 请求失败（host）` 而不是 `webhook 请求超时（host）`。
    // 所以「含超时」这一条同时表达了：① 超时真的触发了；② 它短于夹具握持时长。
    // 它是确定性的，与机器负载无关。
    //
    // 旧上界想防的回归（超时形同不存在 ⇒ 一路等到对端关连接）已被这一条覆盖：
    // 那种情形下错误是「请求失败」，不含「超时」⇒ 立刻红。
    const CONFIGURED: Duration = Duration::from_millis(300);
    /// 夹具比对端配置超时多握这么久，保证客户端一定先超时（而不是收到「连接被关闭」）。
    const SLACK: Duration = Duration::from_millis(2_700);

    let base_url = spawn_silent_server(CONFIGURED + SLACK);
    let notifier = WebhookNotifier::with_transport(
        NotifyConfig {
            timeout: CONFIGURED,
            ..config(Some(&format!("{base_url}/hook")))
        },
        Box::new(tianshu_relay_core::notify::ReqwestWebhookTransport::default()),
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

    // 判据一（主判据，负载无关）：错误必须是**超时**。
    assert!(
        err.to_string().contains("超时"),
        "超时必须被如实报告: {err}"
    );
    // 判据二（下界）：真的在等。删掉它会放过「压根没发请求、立刻失败」这类更危险的回归。
    // 放宽到 3/4：`send()` 在请求发出前还有序列化 + 线程派生，没必要卡着满值。
    assert!(
        elapsed >= CONFIGURED * 3 / 4,
        "耗时 {elapsed:?} 太短：像是立刻失败而不是等超时"
    );
    // 这里**故意没有**上界。原因见上面的注释：`elapsed` 含一段超时管不到的时间，
    // 任何绝对或相对的上界都会被满载误伤。要防的回归已由判据一覆盖。
}

#[test]
fn webhook_with_zero_timeout_is_refused_before_it_reaches_the_transport() {
    // M22-S3 / B-174：把 M21-S1 留下的最后一条墙上时钟上界换成**可判定**判据。
    //
    // 为什么上界必然被误伤（不是「选个更宽的值」能救的）：`Duration::ZERO` 在
    // reqwest + tokio 里没有任何可用语义。总超时（`reqwest/client.rs:2675`）与连接层
    // `TimeoutLayer`（`reqwest/connect.rs:147`；接线是 `tower-0.5.3/src/timeout/mod.rs:66`，
    // **不是** `tower-http`）都调 `tokio::time::sleep`，而零期限最迟在注册当轮就被 fire
    // （`tokio/.../time/wheel/mod.rs:94` ⇒ `runtime/time/mod.rs:438` `entry.fire(Ok(()))`）
    // ⇒ 两个 sleep 都立刻 Ready，**结果取决于谁先 poll**：
    // `tower/timeout/future.rs:40-53` 先 poll sleep、Ready 就返回 `Elapsed`（inner 一次不 poll）；
    // `client.rs:3097-3103` 先 poll `total_timeout`、Ready 直接 Err。旧用例观测到的
    // 「真 200 / 假超时」两种结果就是这么来的。
    //
    // 实测（M22-S2 与本步）：单跑 40 次、隔离 30 次、本目标内 20 次全绿；
    // `cargo test --workspace` 那一轮红在 22.45s。
    // **22s 的成因本步没能复现**：该机制本身实测只值毫秒级（绕开本守卫直打传输层
    // 最坏 4.936ms），剂量-反应曲线 0→16 个 `yes` 只把最坏值从 0.86ms 推到 1.08ms
    // （本机 10 核 M4——`nproc` 因 `OMP_NUM_THREADS=2` 谎报 2 核），外部卷 I/O 压力下
    // 仍 0.31s 稳定。所以成因另记 B-178；本判据**不依赖**那个解释。
    //
    // M21-S1 当年的 250ms 上界护的就是这个病态输入。本步改判据：
    // **零超时在入口被拒绝，且一个请求都不发**。
    // 这样「时成时败」在产品侧不可能发生，也不需要墙上时钟。
    let transport = RecordingTransport {
        status: 200,
        ..RecordingTransport::default()
    };
    let notifier = WebhookNotifier::with_transport(
        NotifyConfig {
            timeout: Duration::ZERO,
            ..config(Some("http://127.0.0.1:9/hook"))
        },
        Box::new(transport.clone()),
    );

    let err = notifier
        .send(&Notification::new(
            NotifyKind::Drift,
            Some(1),
            "配置漂移",
            "x",
            NOW,
        ))
        .expect_err("零超时必须被拒绝，不能带着竞态发出去");

    let text = err.to_string();
    assert!(
        text.contains("不能为 0"),
        "拒绝的原因要说清是「零」而不是别的失败: {text}"
    );
    // 关键：连传输层都没碰到。若这里发出过请求，说明守卫装在了错误的位置
    //（比如只在 `post()` 里判，那时请求已经离开发送方）。
    let calls = transport.seen.lock().unwrap().clone();
    assert!(calls.is_empty(), "零超时不该产生任何请求: {calls:?}");
}

#[test]
fn webhook_with_a_nonzero_timeout_still_reaches_the_transport() {
    // 对照组：守卫只挡 0，不碰合法值。删掉这条，把上面那条的判据误写成
    // 「无条件拒绝」也会全绿——那是另一个方向的假绿。
    let transport = RecordingTransport {
        status: 204,
        ..RecordingTransport::default()
    };
    let notifier = WebhookNotifier::with_transport(
        NotifyConfig {
            timeout: Duration::from_millis(1),
            ..config(Some("http://127.0.0.1:9/hook"))
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
        .expect("1ms 是合法超时，应照常发出");

    let calls = transport.seen.lock().unwrap().clone();
    assert_eq!(calls.len(), 1, "非零超时必须照常调用传输层: {calls:?}");
    assert_eq!(calls[0].2, Duration::from_millis(1), "超时值要原样透传");
}

#[test]
fn webhook_error_does_not_leak_url_credentials_on_a_dead_port() {
    // 端口 1 上不会有服务：真实 reqwest 错误里会带完整 URL
    let notifier = WebhookNotifier::new(
        config(Some(
            "http://alice:s3cr3t-token@127.0.0.1:1/hook?token=s3cr3t-token",
        )),
        None,
    );
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
    let webhook = WebhookNotifier::new(config(Some(&format!("{}/notify", server.base_url))), None);
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
