//! M46-S7：按 agent 路由规则（spec §7 的网关端到端）。
//!
//! 假上游是本地 `TcpListener`（不联网），与 `gateway_ewma.rs` 同款夹具。
//! 带 label 的令牌用 `handle.set_tokens()` 播种（M43-S1 测试的既有形态）；
//! 未命中对照用 legacy 单令牌（`handle.token`，label 为空）。

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tianshu_relay_core::gateway::{
    sha256_hex, start, GatewayConfig, GatewayHandle, GatewayTokenEntry, UpstreamTimeout,
};
use tianshu_relay_core::routing::{
    BreakerPolicy, RouteTable, RoutingRule, SiteGuardPolicy, Upstream,
};
use zeroize::Zeroizing;

const MODEL: &str = "m46s7-model";
const REF_A: &str = "kr/key/1/secret";
const REF_B: &str = "kr/key/2/secret";
const REF_C: &str = "kr/key/3/secret";
const KEY_A: &str = "kr-key-s7-a";
const KEY_B: &str = "kr-key-s7-b";
const KEY_C: &str = "kr-key-s7-c";
const LABELED_TOKEN: &str = "kr-gw-s7-codex-plaintext";

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

struct FakeUpstream {
    base_url: String,
    seen: Arc<AtomicUsize>,
}

impl FakeUpstream {
    fn count(&self) -> usize {
        self.seen.load(Ordering::SeqCst)
    }
}

fn spawn_upstream(site_id: i64, statuses: &[&str]) -> FakeUpstream {
    spawn_upstream_delayed(site_id, statuses, Duration::from_millis(0))
}

/// 带固定响应延迟的假上游：延迟计入网关实测 TTFB，从而固定 EWMA 顺序。
/// 回环 TTFB 本身是亚毫秒级、毫秒取整后在 0/1ms 间抖动，见
/// `routing_rule_hit_only_uses_listed_sites` 的注释。
fn spawn_upstream_delayed(site_id: i64, statuses: &[&str], delay: Duration) -> FakeUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定本地端口");
    let addr = listener.local_addr().expect("读取地址");
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    let statuses: Vec<String> = statuses.iter().map(|s| (*s).to_string()).collect();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = read_request(&mut stream);
            if !delay.is_zero() {
                thread::sleep(delay);
            }
            counter.fetch_add(1, Ordering::SeqCst);
            let idx = counter.load(Ordering::SeqCst).saturating_sub(1);
            let status = statuses
                .get(idx)
                .or_else(|| statuses.last())
                .map(|s| s.as_str())
                .unwrap_or("200 OK");
            let body = format!(r#"{{"from":"site{site_id}"}}"#);
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
        "POST {path} HTTP/1.1\r\nHost: {without_scheme}\r\nAuthorization: Bearer {tok}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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

fn upstream(site_id: i64, base_url: &str, key_ref: &str) -> Upstream {
    Upstream {
        site_id,
        key_id: None,
        base_url: base_url.to_string(),
        key_ref: key_ref.to_string(),
        models: vec![MODEL.to_string()],
        rate: Some(1.0),
        balance_usd: Some(10.0),
        latency_ms: None,
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

fn three_site_config(
    a: &FakeUpstream,
    b: &FakeUpstream,
    c: &FakeUpstream,
    breaker: BreakerPolicy,
) -> GatewayConfig {
    GatewayConfig {
        catalog: None,
        port: 0,
        token: "kr-gw-s7-legacy".to_string(),
        key_id: None,
        site_id: 0,
        base_url: String::new(),
        api_key: Zeroizing::new("kr-key-s7-legacy".to_string()),
        site_display_name: "S7 测试".to_string(),
        route: RouteTable::new(vec![
            upstream(1, &a.base_url, REF_A),
            upstream(2, &b.base_url, REF_B),
            upstream(3, &c.base_url, REF_C),
        ]),
        breaker,
        lb_top_n: 3,
        max_attempts: 0,
        session_affinity: false,
        upstream_protocol: tianshu_relay_core::gateway::session::UpstreamProtocol::OpenAiChat,
        routing_preset: tianshu_relay_core::routing::RoutingPreset::Balanced,
        key_quotas: std::collections::HashMap::new(),
        guard_policy: SiteGuardPolicy {
            max_concurrency: 0,
            rate_limit_per_sec: 0,
            rate_burst: 0,
        },
        keys_by_ref: keys(&[(REF_A, KEY_A), (REF_B, KEY_B), (REF_C, KEY_C)]),
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

fn rule(label: &str, sites: &[i64]) -> RoutingRule {
    RoutingRule {
        agent_label: label.to_string(),
        site_ids: sites.to_vec(),
    }
}

fn seed_labeled_token(handle: &GatewayHandle) {
    handle.set_tokens(vec![GatewayTokenEntry {
        id: 1,
        token_hash: sha256_hex(LABELED_TOKEN),
        label: "codex".to_string(),
        grace_until: None,
    }]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn routing_rule_hit_only_uses_listed_sites() {
    let a = spawn_upstream(1, &["200 OK"]);
    let b = spawn_upstream(2, &["200 OK"]);
    // DEBUG 收尾（m46s7_routing 抖动，选 (a) 改测试不断言、不动网关语义）：
    // 本测试曾在 main 上偶发失败（站点 2 被打 1 次而非 2 次）。根因是网关
    // `reorder_by_effective_latency`：请求 1、2 之后 2、3 号站都有 EWMA，
    // 回环 TTFB 是亚毫秒级、毫秒取整后在 0/1ms 间抖动，head 顺序 [2, 3] 与
    // [3, 2] 之间翻转，cursor 2 命中的槽位随之翻转，2/1 分配变成 1/2。
    // 规则本身保证的只是“只用 listed 站点”，不是“毫秒级延迟下每站精确
    // 命中几次”——原测试对每站精确计数的断言属于过度断言。
    // 本测试改用固定延迟固定 EWMA 顺序（3 号站固定 100ms，远大于回环抖动），
    // 保留精确计数断言：固定延迟下 EWMA 顺序确定，精确计数不再是过度
    // 断言，而是对槽位轮转的确定性校验；网关语义一字未动。EWMA 重排与
    // 已声明顺序之间的张力本身未消除，见 BACKLOG B-305（后续项）。
    let c = spawn_upstream_delayed(3, &["200 OK"], Duration::from_millis(100));
    let mut cfg = three_site_config(&a, &b, &c, BreakerPolicy::default());
    cfg.routing_rules = vec![rule("codex", &[2, 3])];
    let handle = start(cfg).await.expect("网关应能启动");
    seed_labeled_token(&handle);

    // 等权重三站、top_n=3：过滤后子集 [2, 3] 的槽位表为 [2, 3]，
    // 3 次请求依次打 2、3、2（cursor 0、1、2）。
    for _ in 0..3 {
        let (status, body) = post(&handle, LABELED_TOKEN).await;
        assert_eq!(status, 200, "命中规则的请求应成功: {body}");
    }
    assert_eq!(a.count(), 0, "规则外站点 1 必须见 0 次");
    assert_eq!(b.count(), 2, "规则内站点 2 应被打 2 次");
    assert_eq!(c.count(), 1, "规则内站点 3 应被打 1 次");
    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn routing_rule_miss_uses_global_weighting() {
    let a = spawn_upstream(1, &["200 OK"]);
    let b = spawn_upstream(2, &["200 OK"]);
    let c = spawn_upstream(3, &["200 OK"]);
    let mut cfg = three_site_config(&a, &b, &c, BreakerPolicy::default());
    cfg.routing_rules = vec![rule("codex", &[2, 3])];
    let handle = start(cfg).await.expect("网关应能启动");
    // legacy 单令牌（label 为空）恒不命中规则：不播种带 label 的令牌，
    // 直接用 handle.token（legacy 回退路径）。
    let tok = handle.token.clone();

    // 等权重、top_n=3：全局槽位表为 [1, 2, 3]，3 次请求依次打 1、2、3。
    for expected in ["site1", "site2", "site3"] {
        let (status, body) = post(&handle, &tok).await;
        assert_eq!(status, 200, "未命中规则的请求应成功: {body}");
        assert!(
            body.contains(expected),
            "全局加权应打 {expected}，实测 body={body}"
        );
    }
    assert_eq!(a.count(), 1);
    assert_eq!(b.count(), 1);
    assert_eq!(c.count(), 1);
    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn routing_rule_unknown_site_is_ignored_without_failing_request() {
    let a = spawn_upstream(1, &["200 OK"]);
    let b = spawn_upstream(2, &["200 OK"]);
    let c = spawn_upstream(3, &["200 OK"]);
    let mut cfg = three_site_config(&a, &b, &c, BreakerPolicy::default());
    // 99 不在路由内：handler 层自然匹配不到候选（service 层剥离由纯函数用例覆盖）。
    cfg.routing_rules = vec![rule("codex", &[2, 99])];
    let handle = start(cfg).await.expect("网关应能启动");
    seed_labeled_token(&handle);

    let (status, body) = post(&handle, LABELED_TOKEN).await;
    assert_eq!(status, 200, "含未知站点的规则不应炸请求: {body}");
    assert!(
        body.contains("site2"),
        "应只打规则内且路由内的站点 2: {body}"
    );
    assert_eq!(a.count(), 0);
    assert_eq!(b.count(), 1);
    assert_eq!(c.count(), 0);
    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn routing_rule_empty_allowlist_returns_model_not_found() {
    let a = spawn_upstream(1, &["200 OK"]);
    let b = spawn_upstream(2, &["200 OK"]);
    let c = spawn_upstream(3, &["200 OK"]);
    let mut cfg = three_site_config(&a, &b, &c, BreakerPolicy::default());
    cfg.routing_rules = vec![rule("codex", &[99])];
    let handle = start(cfg).await.expect("网关应能启动");
    seed_labeled_token(&handle);

    let (status, body) = post(&handle, LABELED_TOKEN).await;
    assert_eq!(
        status, 404,
        "空 allowlist 应为 404 而非 502/全局放行: {body}"
    );
    assert!(
        body.contains("model_not_found"),
        "kind 应与既有 404 相同: {body}"
    );
    assert!(
        body.contains("路由规则"),
        "文案应点名路由规则，与全局 404 可区分: {body}"
    );
    assert_eq!(a.count(), 0);
    assert_eq!(b.count(), 0);
    assert_eq!(c.count(), 0);
    handle.shutdown_and_wait().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn routing_rule_does_not_confuse_breaker_exclusion() {
    // 规则限定 [1, 2]；1、2 号站回 429（可重放 ⇒ 一次请求里切完两站、
    // 阈值 1 ⇒ 两站熔断器均打开），3 号站健康。
    let a = spawn_upstream(1, &["429 Too Many Requests"]);
    let b = spawn_upstream(2, &["429 Too Many Requests"]);
    let c = spawn_upstream(3, &["200 OK"]);
    let mut cfg = three_site_config(
        &a,
        &b,
        &c,
        BreakerPolicy {
            threshold: 1,
            cooldown: Duration::from_secs(3600),
        },
    );
    cfg.routing_rules = vec![rule("codex", &[1, 2])];
    let handle = start(cfg).await.expect("网关应能启动");
    seed_labeled_token(&handle);

    // 请求 1：1 号站 429（可重放，留作 pending）→ 切 2 号站 429（最后一个，
    // 直接返回）；两站熔断器均打开。
    let (status, _) = post(&handle, LABELED_TOKEN).await;
    assert_eq!(status, 429, "两站均 429 时应返回最后一条真实 429");
    assert_eq!(a.count(), 1);
    assert_eq!(b.count(), 1);
    assert_eq!(c.count(), 0, "规则外站点 3 在请求 1 就不该被打到");

    // 请求 2：规则内站点全在熔断冷却中 ⇒ 既有 503 breaker_open；
    // 健康的 3 号站仍因规则排除而见 0 次（规则排除 ≠ 熔断排除的区分点）。
    let (status, body) = post(&handle, LABELED_TOKEN).await;
    assert_eq!(status, 503, "规则内全熔断时应为 503: {body}");
    assert!(
        body.contains("breaker_open"),
        "应为熔断尾巴，不是规则 404: {body}"
    );
    assert_eq!(c.count(), 0, "规则外站点 3 在请求 2 仍必须见 0 次");
    handle.shutdown_and_wait().await;
}
