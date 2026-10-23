//! M43-S1：Agent 级令牌与归因（spec §7 的 core 层断言）。
//!
//! 这里覆盖 T1 / T3 / T3b / T6 / T8 / T10 / T11 / T12；
//! T2 / T4 / T4c / T4e / T5 / T7 / T9 / T13 在 `src-tauri/tests/commands.rs` 的 IPC 层
//! （需要 AppState 与命令）；T14 是前端纯函数，UI 暂缓（见报告）。
//!
//! 假上游是本地 `TcpListener`（不联网），网关只绑回环。

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tianshu_relay_core::gateway::{start, GatewayConfig, GatewayTokenEntry, GatewayUsage};
use tianshu_relay_core::store::Store;
use zeroize::Zeroizing;

const FALLBACK: &str = "kr-gw-fallback-token";

/// 最小假上游：任何请求都回 200 + 带 usage 的 JSON。
fn spawn_upstream() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定假上游");
    let addr = listener.local_addr().expect("读地址");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let body = r#"{"id":"x","object":"chat.completion","usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7},"choices":[]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://{addr}")
}

fn config() -> GatewayConfig {
    GatewayConfig::single_upstream(
        0,
        FALLBACK.to_string(),
        spawn_upstream(),
        Zeroizing::new("sk-upstream-0123456789abcdef".to_string()),
        "M43 测试站".to_string(),
    )
}

fn entry(id: i64, token: &str, label: &str) -> GatewayTokenEntry {
    GatewayTokenEntry {
        id,
        token_hash: tianshu_relay_core::gateway::sha256_hex(token),
        label: label.to_string(),
        grace_until: None,
    }
}

async fn get(url: &str, token: &str) -> reqwest::StatusCode {
    reqwest::Client::new()
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .expect("请求网关")
        .status()
}

// ============================================================ T1：只存 hash

#[test]
fn t1_created_token_is_stored_as_hash_only() {
    let dir = tempfile::tempdir().expect("临时目录");
    let db = dir.path().join("t.db");
    let plaintext = "kr-gw-t1-plaintext-0123456789abcdef";
    let store = Store::open(&db).expect("打开库");
    store
        .insert_gateway_token(
            &tianshu_relay_core::gateway::sha256_hex(plaintext),
            "agent-t1",
            false,
        )
        .expect("插入");

    let rows = store.list_gateway_tokens().expect("列表");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].token_hash,
        tianshu_relay_core::gateway::sha256_hex(plaintext),
        "库里必须是 sha256(明文)"
    );
    // 扫库文件字节（含 -wal / -shm）：明文零命中。
    for suffix in ["", "-wal", "-shm"] {
        let path = format!("{}{suffix}", db.display());
        if let Ok(bytes) = std::fs::read(&path) {
            assert!(
                !contains(&bytes, plaintext.as_bytes()),
                "{path} 里不得出现明文"
            );
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ============================================================ T10：last_used_at 每分钟最多一次

#[test]
fn t10_last_used_at_is_throttled_to_once_per_minute() {
    let dir = tempfile::tempdir().expect("临时目录");
    let store = Store::open(&dir.path().join("t.db")).expect("打开库");
    let id = store
        .insert_gateway_token(
            &tianshu_relay_core::gateway::sha256_hex("kr-gw-t10"),
            "t10",
            false,
        )
        .expect("插入");

    let now = 1_700_000_000;
    assert!(
        store
            .touch_gateway_token_throttled(id, now)
            .expect("第一次"),
        "首次应写"
    );
    // 同一分钟内连续 9 次 ⇒ 都不写。
    for offset in 1..10 {
        assert!(
            !store
                .touch_gateway_token_throttled(id, now + offset)
                .expect("节流内"),
            "同一分钟内不该再写"
        );
    }
    let row = store.gateway_token_by_id(id).expect("查").expect("行");
    assert_eq!(row.last_used_at, Some(now), "10 次请求只写 1 次");
    // 超过 60 秒 ⇒ 再写一次。
    assert!(
        store
            .touch_gateway_token_throttled(id, now + 61)
            .expect("跨分钟后"),
        "超过一分钟应再写"
    );
    let row = store.gateway_token_by_id(id).expect("查").expect("行");
    assert_eq!(row.last_used_at, Some(now + 61));
}

// ============================================================ T12：registry 空 ⇒ 回退 config.token

#[tokio::test]
async fn t12_empty_registry_falls_back_to_the_legacy_token() {
    let handle = start(config()).await.expect("启动网关");
    let base = handle.local_url();
    // 未 set_tokens ⇒ 集合空 ⇒ 只认 config.token。
    assert_eq!(get(&format!("{base}/health"), FALLBACK).await, 200);
    assert_eq!(
        get(&format!("{base}/health"), "kr-gw-not-a-token").await,
        401
    );
    handle.shutdown_and_wait().await;
}

// ============================================================ T3 / T3b：多令牌 + 吊销即时生效

#[tokio::test]
async fn t3_t3b_revoked_token_is_rejected_on_the_next_request() {
    let handle = start(config()).await.expect("启动网关");
    let base = handle.local_url();
    handle.set_tokens(vec![entry(7, "kr-gw-agent-seven", "seven")]);

    // T3b：per-agent 令牌对 /health 也 200（与 /proxy 共用 authenticate）。
    assert_eq!(
        get(&format!("{base}/health"), "kr-gw-agent-seven").await,
        200
    );
    // 非集合令牌（含 config.token）在集合非空后**不**再被接受。
    assert_eq!(get(&format!("{base}/health"), FALLBACK).await, 401);

    // T3：吊销 = 从运行态集合移除 ⇒ 下一请求立即 401（不重启）。
    {
        let registry = handle.token_registry();
        let mut guard = registry.write().expect("写锁");
        guard.retain(|t| t.id != 7);
    }
    assert_eq!(
        get(&format!("{base}/health"), "kr-gw-agent-seven").await,
        401
    );
    handle.shutdown_and_wait().await;
}

// ============================================================ T11：宽限期

#[tokio::test]
async fn t11_grace_window_keeps_the_old_token_usable_until_expiry() {
    let handle = start(config()).await.expect("启动网关");
    let base = handle.local_url();
    let now = Instant::now();
    handle.set_tokens(vec![
        entry(1, "kr-gw-new-token", "agent"),
        GatewayTokenEntry {
            id: 2,
            token_hash: tianshu_relay_core::gateway::sha256_hex("kr-gw-old-token"),
            label: "agent".to_string(),
            grace_until: Some(now + Duration::from_secs(60)),
        },
    ]);
    assert_eq!(get(&format!("{base}/health"), "kr-gw-new-token").await, 200);
    assert_eq!(
        get(&format!("{base}/health"), "kr-gw-old-token").await,
        200,
        "宽限期内旧令牌仍可用"
    );

    // 把宽限改成已过期 ⇒ 立即 401（同一请求路径，不重启）。
    {
        let registry = handle.token_registry();
        let mut guard = registry.write().expect("写锁");
        if let Some(item) = guard.iter_mut().find(|t| t.id == 2) {
            item.grace_until = Some(Instant::now() - Duration::from_secs(1));
        }
    }
    assert_eq!(
        get(&format!("{base}/health"), "kr-gw-old-token").await,
        401,
        "宽限到期后旧令牌必须 401"
    );
    assert_eq!(get(&format!("{base}/health"), "kr-gw-new-token").await, 200);
    handle.shutdown_and_wait().await;
}

// ============================================================ T6 / T8：用量归因

#[tokio::test]
async fn t6_t8_usage_rows_carry_the_authenticated_token_and_label() {
    let seen: Arc<Mutex<Vec<GatewayUsage>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let mut cfg = config();
    cfg.on_usage = Some(Arc::new(move |usage: GatewayUsage| {
        if let Ok(mut log) = sink.lock() {
            log.push(usage);
        }
    }));
    let handle = start(cfg).await.expect("启动网关");
    let base = handle.local_url();
    handle.set_tokens(vec![
        entry(11, "kr-gw-eleven", "agent-eleven"),
        entry(12, "kr-gw-twelve", "agent-twelve"),
        entry(13, "kr-gw-thirteen", "agent-thirteen"),
    ]);

    let client = reqwest::Client::new();
    for token in ["kr-gw-eleven", "kr-gw-twelve", "kr-gw-thirteen"] {
        let response = client
            .post(format!("{base}/v1/chat/completions"))
            .bearer_auth(token)
            .json(&serde_json::json!({"model": "m43", "messages": []}))
            .send()
            .await
            .expect("请求");
        assert_eq!(response.status(), 200);
        let _ = response.text().await;
    }

    let usages = seen.lock().expect("读").clone();
    assert_eq!(usages.len(), 3, "三次 2xx 各产生一条 usage: {usages:?}");
    let mut ids: Vec<Option<i64>> = usages.iter().map(|u| u.token_id).collect();
    ids.sort();
    assert_eq!(
        ids,
        vec![Some(11), Some(12), Some(13)],
        "每个令牌命中自己的 id"
    );
    let mut labels: Vec<String> = usages.iter().map(|u| u.agent_label.clone()).collect();
    labels.sort();
    assert_eq!(
        labels,
        vec!["agent-eleven", "agent-thirteen", "agent-twelve"],
        "标签快照正确"
    );
    handle.shutdown_and_wait().await;
}

// ============================================================ T4d：最多一个默认行

#[test]
fn t4d_partial_unique_index_allows_only_one_default_row() {
    let dir = tempfile::tempdir().expect("临时目录");
    let store = Store::open(&dir.path().join("t.db")).expect("打开库");
    let hash = |s: &str| tianshu_relay_core::gateway::sha256_hex(s);
    store
        .insert_gateway_token(&hash("kr-gw-a"), "默认（迁移）", true)
        .expect("第一个默认行");
    let err = store
        .insert_gateway_token(&hash("kr-gw-b"), "第二个默认", true)
        .expect_err("第二个 is_default=1 必须被部分唯一索引拒绝");
    let text = err.to_string();
    assert!(
        text.contains("UNIQUE") || text.contains("唯一"),
        "应是唯一约束错误: {text}"
    );
    // 非默认行可以有多行（label 不同）。
    store
        .insert_gateway_token(&hash("kr-gw-c"), "agent-c", false)
        .expect("普通行");
    assert_eq!(store.list_gateway_tokens().unwrap().len(), 2);
}
