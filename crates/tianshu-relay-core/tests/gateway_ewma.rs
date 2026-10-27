//! M46-S2：延迟感知选路（EWMA）。
//!
//! 假上游是本地 `TcpListener`（不联网），与 `gateway_balance.rs` 同款夹具。
//! 主用例的 cursor 算表见 `docs/specs/M46-S2-延迟感知选路.md` §7.1：
//! 双站同倍率（1.0）同余额同静态延迟（10ms），`top_n = 2`，
//! 实测 site1 = 200ms、site2 ≈ 0ms；4 次预热 + 第 5 次断言打 site2
//! （无 EWMA 时第 5 次必打 site1，cursor 4 ⇒ 静态顺序槽位 0）。

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tianshu_relay_core::gateway::{start, GatewayConfig, GatewayHandle, UpstreamTimeout};
use tianshu_relay_core::routing::{BreakerPolicy, RouteTable, SiteGuardPolicy, Upstream};
use zeroize::Zeroizing;

const MODEL: &str = "m46-model";
const REF_A: &str = "kr/key/1/secret";
const REF_B: &str = "kr/key/2/secret";
const KEY_A: &str = "sk-test-ewma-a";
const KEY_B: &str = "sk-test-ewma-b";

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

/// 假上游：按 `statuses` 顺序回放状态行（用完后重复最后一个），可延迟、可计数。
/// 延迟在写响应头之前睡，所以 TTFB ≈ 延迟（与网关的 TTFB 口径对齐）。
struct FakeUpstream {
    base_url: String,
    seen: Arc<AtomicUsize>,
}

impl FakeUpstream {
    fn count(&self) -> usize {
        self.seen.load(Ordering::SeqCst)
    }
}

fn spawn_upstream(site_id: i64, statuses: &[&str], delay: Duration) -> FakeUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取地址");
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    let statuses: Vec<String> = statuses.iter().map(|s| (*s).to_string()).collect();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = read_request(&mut stream);
            counter.fetch_add(1, Ordering::SeqCst);
            if !delay.is_zero() {
                thread::sleep(delay);
            }
            let idx = counter.load(Ordering::SeqCst).saturating_sub(1);
            let status = statuses
                .get(idx)
                .or_else(|| statuses.last())
                .map(|s| s.as_str())
                .unwrap_or("200 OK");
            let body = format!(r#"{{"from":"site{site_id}"}}"#);
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    FakeUpstream {
        base_url: format!("http://{addr}"),
        seen,
    }
}

fn http_post(url: &str, tok: &str, path: &str, body: &str) -> (u16, String) {
    let without_scheme = url.trim_start_matches("http://");
    let mut stream = TcpStream::connect(without_scheme).expect("连接网关");
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {without_scheme}\r\nAuthorization: Bearer {tok}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("发送请求");
    stream.flush().ok();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("读响应");
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let (_, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    (status, body.to_string())
}

async fn post(handle: &GatewayHandle, tok: &str) -> (u16, String) {
    let url = handle.local_url();
    let tok = tok.to_string();
    let body = format!(r#"{{"model":"{MODEL}","messages":[]}}"#);
    tokio::task::spawn_blocking(move || http_post(&url, &tok, "/v1/chat/completions", &body))
        .await
        .expect("阻塞任务")
}

fn upstream(
    site_id: i64,
    base_url: &str,
    key_ref: &str,
    rate: f64,
    latency_ms: Option<u64>,
) -> Upstream {
    Upstream {
        site_id,
        key_id: None,
        base_url: base_url.to_string(),
        key_ref: key_ref.to_string(),
        models: vec![MODEL.to_string()],
        rate: Some(rate),
        balance_usd: Some(10.0),
        latency_ms,
        timeout_ms: None,
    }
}

fn keys(pairs: &[(&str, &str)]) -> HashMap<String, Zeroizing<String>> {
    let mut map = HashMap::new();
    for (reference, plain) in pairs {
        map.insert(reference.to_string(), Zeroizing::new(plain.to_string()));
    }
    map
}

fn config(
    route: Vec<Upstream>,
    keys_by_ref: HashMap<String, Zeroizing<String>>,
    top_n: usize,
) -> GatewayConfig {
    GatewayConfig {
        catalog: None,
        port: 0,
        token: "local-token-for-ewma-tests".to_string(),
        key_id: None,
        site_id: 0,
        base_url: String::new(),
        api_key: Zeroizing::new(String::new()),
        site_display_name: "EWMA 测试".to_string(),
        route: RouteTable::new(route),
        breaker: BreakerPolicy::default(),
        lb_top_n: top_n,
        max_attempts: 0,
        session_affinity: false,
        upstream_protocol: tianshu_relay_core::gateway::session::UpstreamProtocol::OpenAiChat,
        routing_preset: tianshu_relay_core::routing::RoutingPreset::Balanced,
        key_quotas: std::collections::HashMap::new(),
        guard_policy: SiteGuardPolicy {
            max_concurrency: 0,
            rate_limit_per_sec: 0,
            rate_burst: 0, // M46-S3：机械补字段，行为不变
        },
        keys_by_ref,
        upstream_timeout: UpstreamTimeout::default(),
        revoked_refs: None,
        on_failure: None,
        on_observation: None,
        on_usage: None,
        budget_check: None,
        on_budget_breach: None,
        routing_rules: Vec::new(),
        upstream_proxy: None,
        legacy_key_ref: None,
        max_request_bytes: tianshu_relay_core::gateway::DEFAULT_MAX_REQUEST_BYTES,
        runtime: None,
    }
}

/// 主用例（spec §7.1 算表）：4 次预热 + 第 5 次断言打 site2。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ewma_flips_first_pick_under_weighted_rotation() {
    let a = spawn_upstream(1, &["200 OK"], Duration::from_millis(200));
    let b = spawn_upstream(2, &["200 OK"], Duration::ZERO);
    let handle = start(config(
        vec![
            upstream(1, &a.base_url, REF_A, 1.0, Some(10)),
            upstream(2, &b.base_url, REF_B, 1.0, Some(10)),
        ],
        keys(&[(REF_A, KEY_A), (REF_B, KEY_B)]),
        2,
    ))
    .await
    .expect("网关应能启动");
    let tok = handle.token.clone();

    // 预热 4 次，逐次命中见 spec §7.1：1、1、2、1（逐条断言 body，
    // 而不是只看最终计数——计数相同但顺序不同的序列会被漏网）。
    for expected in ["site1", "site1", "site2", "site1"] {
        let (status, body) = post(&handle, &tok).await;
        assert_eq!(status, 200, "预热请求应成功");
        assert!(
            body.contains(expected),
            "预热应打 {expected}，实测 body={body}"
        );
    }
    assert_eq!(a.count(), 3, "预热后 site1 应被打 3 次");
    assert_eq!(b.count(), 1, "预热后 site2 应被打 1 次");

    // 第 5 次：cursor 4，翻转后槽位 0 是 site2；无 EWMA 时必是 site1。
    let (status, body) = post(&handle, &tok).await;
    assert_eq!(status, 200, "第 5 次应成功");
    assert!(
        body.contains("site2"),
        "第 5 次必须打 site2（EWMA 已翻转顺序），实测 body={body}"
    );
    assert_eq!(a.count(), 3, "第 5 次不该再打 site1");
    assert_eq!(b.count(), 2, "第 5 次应打 site2");

    // EWMA 本身可见：site1 慢、site2 快。断言口径必须是「下限 + 分离度」，
    // 不能是 150–250ms 绝对窗口：TTFB 从 send_once 前计时，含上游 200ms
    // 睡眠（下限）与网关调度/排队开销（无上限）——CI 负载下样本膨胀到
    // 300ms+ 是合理解释（实测 318.48），不是选路 bug；翻转行为本身已由
    // 上面的 body/count 断言钉住，这里只钉「慢站显著慢于快站」这一信号。
    let snap = handle.metrics();
    let ewma_a = snap.per_site[&1i64]
        .ewma_latency_ms
        .expect("site1 应有 EWMA");
    let ewma_b = snap.per_site[&2i64]
        .ewma_latency_ms
        .expect("site2 应有 EWMA");
    assert!(
        ewma_a >= 150.0,
        "site1 EWMA 应反映 200ms 上游延迟的下限，实测 {ewma_a}"
    );
    assert!(ewma_b < 50.0, "site2 EWMA 应很小，实测 {ewma_b}");
    assert!(
        ewma_a > ewma_b + 100.0,
        "site1 EWMA 应显著大于 site2（翻转信号），实测 {ewma_a} vs {ewma_b}"
    );

    handle.shutdown_and_wait().await;
}

/// `top_n = 1` 下的翻转：不需要 cursor 算表，首选即全部。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ewma_flips_top1_first_pick() {
    let a = spawn_upstream(1, &["200 OK"], Duration::from_millis(200));
    let b = spawn_upstream(2, &["200 OK"], Duration::ZERO);
    let handle = start(config(
        vec![
            upstream(1, &a.base_url, REF_A, 1.0, Some(10)),
            upstream(2, &b.base_url, REF_B, 1.0, Some(10)),
        ],
        keys(&[(REF_A, KEY_A), (REF_B, KEY_B)]),
        1,
    ))
    .await
    .expect("网关应能启动");
    let tok = handle.token.clone();

    let (_, body) = post(&handle, &tok).await;
    assert!(body.contains("site1"), "静态平局下首选 site1，实测 {body}");
    // 第 1 次后 site1 EWMA = 200 > site2 静态 10 ⇒ 顺序翻转。
    for _ in 0..2 {
        let (status, body) = post(&handle, &tok).await;
        assert_eq!(status, 200);
        assert!(body.contains("site2"), "翻转后应打 site2，实测 {body}");
    }
    assert_eq!(a.count(), 1, "翻转后 site1 不应再被打");
    assert_eq!(b.count(), 2);

    handle.shutdown_and_wait().await;
}

/// 回退用例（端到端版）：无 EWMA 时顺序与今天逐字一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_ewma_keeps_static_order() {
    let a = spawn_upstream(1, &["200 OK"], Duration::ZERO);
    let b = spawn_upstream(2, &["200 OK"], Duration::from_millis(200));
    let handle = start(config(
        vec![
            upstream(1, &a.base_url, REF_A, 1.0, Some(10)),
            upstream(2, &b.base_url, REF_B, 1.0, Some(200)),
        ],
        keys(&[(REF_A, KEY_A), (REF_B, KEY_B)]),
        1,
    ))
    .await
    .expect("网关应能启动");
    let tok = handle.token.clone();

    for _ in 0..3 {
        let (status, body) = post(&handle, &tok).await;
        assert_eq!(status, 200);
        assert!(body.contains("site1"), "静态首选 site1，实测 {body}");
    }
    assert_eq!(a.count(), 3);
    assert_eq!(b.count(), 0, "site2 从未被打到");
    assert!(
        !handle.metrics().per_site.contains_key(&2i64),
        "site2 从未被尝试，快照里不应有它的条目"
    );

    handle.shutdown_and_wait().await;
}

/// 失败不污染：site1 恒 429（可重放 ⇒ 切到 site2 成功），其 EWMA 保持 None。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_attempts_do_not_pollute_ewma() {
    let a = spawn_upstream(1, &["429 Too Many Requests"], Duration::ZERO);
    let b = spawn_upstream(2, &["200 OK"], Duration::ZERO);
    let handle = start(config(
        vec![
            upstream(1, &a.base_url, REF_A, 1.0, Some(10)),
            upstream(2, &b.base_url, REF_B, 1.0, Some(10)),
        ],
        keys(&[(REF_A, KEY_A), (REF_B, KEY_B)]),
        2,
    ))
    .await
    .expect("网关应能启动");
    let tok = handle.token.clone();

    let (status, body) = post(&handle, &tok).await;
    assert_eq!(status, 200, "429 应切到 site2 成功返回");
    assert!(body.contains("site2"), "响应应来自 site2，实测 {body}");
    assert_eq!(a.count(), 1, "site1 确实被尝试过（429）");
    assert_eq!(b.count(), 1);

    let snap = handle.metrics();
    assert_eq!(
        snap.per_site[&1i64].last_status,
        Some(429),
        "site1 的尝试应被记为 429"
    );
    assert_eq!(
        snap.per_site[&1i64].ewma_latency_ms, None,
        "失败尝试不得写 EWMA"
    );
    assert!(
        snap.per_site[&2i64].ewma_latency_ms.is_some(),
        "成功站应有 EWMA"
    );

    handle.shutdown_and_wait().await;
}

/// DEBUG P1-1：非 2xx 的非熔断状态（401）既不算成功、也不算失败。
/// 序列：500、500（熔断计数 2/3，仍 Closed）→ 401 → 500。
/// 若 401 被当成成功，它会清零计数，第 4 个 500 后计数仅为 1、熔断不开；
/// 正确行为是第 4 个 500 后计数满 3、熔断打开，第 5 个请求由 site2 承接。
/// 全程 site1 无 2xx，故其 EWMA 恒为 None（快速拒绝延迟不得喂进 EWMA）。
/// 429 口径不受此改动影响（见 `failed_attempts_do_not_pollute_ewma`，仍全绿）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_failover_401_neither_clears_breaker_nor_feeds_ewma() {
    let a = spawn_upstream(
        1,
        &[
            "500 Internal Server Error",
            "500 Internal Server Error",
            "401 Unauthorized",
            "500 Internal Server Error",
        ],
        Duration::ZERO,
    );
    let b = spawn_upstream(2, &["200 OK"], Duration::ZERO);
    let handle = start(config(
        vec![
            upstream(1, &a.base_url, REF_A, 1.0, Some(10)),
            upstream(2, &b.base_url, REF_B, 1.0, Some(10)),
        ],
        keys(&[(REF_A, KEY_A), (REF_B, KEY_B)]),
        1,
    ))
    .await
    .expect("网关应能启动");
    let tok = handle.token.clone();

    assert_eq!(post(&handle, &tok).await.0, 500, "第 1 个 500 原样返回");
    assert_eq!(post(&handle, &tok).await.0, 500, "第 2 个 500 原样返回");
    assert_eq!(post(&handle, &tok).await.0, 401, "401 原样返回（不切换）");
    assert_eq!(
        handle.metrics().per_site[&1i64].ewma_latency_ms,
        None,
        "401 的快速拒绝延迟不得喂进 EWMA"
    );
    let breaker_after_401 = handle
        .candidates()
        .into_iter()
        .find(|c| c.site_id == 1)
        .expect("site1 应在候选里")
        .breaker;
    assert_eq!(
        breaker_after_401, "closed",
        "401 后熔断仍为 Closed（计数 2/3 未被清零也未被攒满）"
    );
    assert_eq!(
        post(&handle, &tok).await.0,
        500,
        "第 4 个 500 原样返回并攒满阈值"
    );
    let breaker_after_third_failure = handle
        .candidates()
        .into_iter()
        .find(|c| c.site_id == 1)
        .expect("site1 应在候选里")
        .breaker;
    assert_eq!(
        breaker_after_third_failure, "open",
        "401 未清零时，第 4 个 500 应使熔断打开；若 401 清过零，此处仍为 closed"
    );
    let (status, body) = post(&handle, &tok).await;
    assert_eq!(status, 200, "熔断打开后应由 site2 承接");
    assert!(body.contains("site2"), "实测 {body}");
    assert_eq!(a.count(), 4, "熔断打开后 site1 不应再被打");
    assert_eq!(
        handle.metrics().per_site[&1i64].ewma_latency_ms,
        None,
        "site1 全程无 2xx，EWMA 恒为 None"
    );

    handle.shutdown_and_wait().await;
}

/// DEBUG P2-1（P1-1 × P1-2 联动）：HalfOpen 探针返回 401 后，下一次请求
/// 必须可再次取探针，且熔断计数与 EWMA 均未被该 401 改变。
/// 序列：500（threshold=1 ⇒ Open）→ 冷却 300ms 过后探针 401 → 立即再请求。
/// 若 401 不释放探针标记，第二次请求会在 eligible 里跳过 site1、改打 site2
/// （200，b=1，a 停在 2），本用例即红；若 401 被误当失败/成功，探针后熔断
/// 会是 open（冷却被刷新）或 closed（计数被清零），halfOpen 断言即红。
/// 正确行为：两次探针都打 site1（401 原样返回），EWMA 恒为 None，熔断恒为
/// HalfOpen——P1-1 的「4xx 两者都不做」仍成立，变的只是探针标记被释放。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn half_open_probe_401_releases_probe_without_touching_breaker_or_ewma() {
    let a = spawn_upstream(
        1,
        &[
            "500 Internal Server Error",
            "401 Unauthorized",
            "401 Unauthorized",
        ],
        Duration::ZERO,
    );
    let b = spawn_upstream(2, &["200 OK"], Duration::ZERO);
    let mut cfg = config(
        vec![
            upstream(1, &a.base_url, REF_A, 1.0, Some(10)),
            upstream(2, &b.base_url, REF_B, 1.0, Some(10)),
        ],
        keys(&[(REF_A, KEY_A), (REF_B, KEY_B)]),
        1,
    );
    cfg.breaker = BreakerPolicy {
        threshold: 1,
        cooldown: Duration::from_millis(300),
    };
    let handle = start(cfg).await.expect("网关应能启动");
    let tok = handle.token.clone();

    assert_eq!(post(&handle, &tok).await.0, 500, "第 1 个 500 应打开熔断");
    assert_eq!(a.count(), 1);
    tokio::time::sleep(Duration::from_millis(350)).await;

    let (status, body) = post(&handle, &tok).await;
    assert_eq!(status, 401, "探针 401 应原样返回");
    assert!(body.contains("site1"), "探针应打 site1，实测 {body}");
    assert_eq!(a.count(), 2, "探针应打到 site1");
    assert_eq!(b.count(), 0, "探针在场时 site2 不应被打");
    assert_eq!(
        handle.metrics().per_site[&1i64].ewma_latency_ms,
        None,
        "探针 401 不得喂进 EWMA"
    );
    let breaker_after_probe = handle
        .candidates()
        .into_iter()
        .find(|c| c.site_id == 1)
        .expect("site1 应在候选里")
        .breaker;
    assert_eq!(
        breaker_after_probe, "halfOpen",
        "探针 401 后熔断仍为 HalfOpen（既未清零成 Closed，也未刷新冷却成 Open）"
    );

    // 立即再请求（远在 600s TTL 内）：若标记未释放，此处必改打 site2。
    let (status, body) = post(&handle, &tok).await;
    assert_eq!(status, 401, "第二次探针 401 应原样返回");
    assert!(
        body.contains("site1"),
        "释放后下一次请求应再次取探针打 site1，实测 {body}"
    );
    assert_eq!(a.count(), 3, "第二次探针应再次打到 site1");
    assert_eq!(b.count(), 0, "标记已释放时 site2 仍不应被打");
    assert_eq!(
        handle.metrics().per_site[&1i64].ewma_latency_ms,
        None,
        "两次探针 401 均不得喂进 EWMA"
    );
    let breaker_after_second_probe = handle
        .candidates()
        .into_iter()
        .find(|c| c.site_id == 1)
        .expect("site1 应在候选里")
        .breaker;
    assert_eq!(
        breaker_after_second_probe, "halfOpen",
        "第二次探针 401 后熔断仍为 HalfOpen"
    );

    handle.shutdown_and_wait().await;
}
