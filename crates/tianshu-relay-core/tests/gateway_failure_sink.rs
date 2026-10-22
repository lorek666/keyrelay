//! 网关失败事件的**落库形状**验证（M7-S5 / FR-5:160 + M7-S1 复审 P1-1）。
//!
//! 分工：`tests/gateway_failover.rs`（M7-S1）证明「上游 503 时真的会切换、并且真的
//! 调了 `on_failure`」；本文件证明**另一段**——从回调到事件表那一段。
//! 两段之间没有任何测试覆盖过，而复审 P1-1 正是在这个缝里发现的：
//! 网关把义务判给「S5 的出口」，而那个出口当时还不存在。

use std::fs;
use std::sync::Arc;

use tianshu_relay_core::gateway::GatewayFailure;
use tianshu_relay_core::service::{ServiceConfig, TianshuRelayService};
use tianshu_relay_core::site::transport::MockTransport;
use tianshu_relay_core::store::Store;
use tianshu_relay_core::vault::MemoryVault;

/// 密钥形状的模型名：它必须**不可能**原样出现在事件表里。
const KEY_SHAPED_MODEL: &str = "sk-sinkleak-0123456789abcdef";

fn service() -> (tempfile::TempDir, TianshuRelayService<MockTransport>) {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let store = Store::open(&dir.path().join("tianshu-relay.db")).expect("文件库");
    let service = TianshuRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault: Arc::new(MemoryVault::new()),
            home,
            backup_dir: dir.path().join("backups"),
        },
    );
    (dir, service)
}

#[tokio::test]
async fn a_gateway_failure_becomes_an_event_with_exactly_three_metadata_fields() {
    let (_dir, service) = service();
    service.record_gateway_failure_for_test(GatewayFailure {
        site_id: 7,
        status: 503,
        model: "gpt-5.6".into(),
        reason: "上游返回可切换状态码 HTTP 503".into(),
    });

    // 事件是**下一次刷新**时落的（网关回调不碰存储层，见 `service.rs` 的说明）。
    service.refresh_all().await.expect("刷新应成功");

    let events = service.recent_events(50).expect("读事件");
    let gateway_events: Vec<_> = events.iter().filter(|e| e.source == "gateway").collect();
    assert_eq!(gateway_events.len(), 1, "一条失败应恰好落一条事件");

    let event = gateway_events[0];
    assert_eq!(event.level, "warn");
    let payload: serde_json::Value =
        serde_json::from_str(event.payload.as_deref().expect("有 payload"))
            .expect("payload 是 JSON");
    let mut keys: Vec<String> = payload
        .as_object()
        .expect("payload 是对象")
        .keys()
        .cloned()
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        vec!["model", "site_id", "status"],
        "payload 只许有这三个键——多一个键就可能是 prompt 正文或密钥"
    );
    assert_eq!(payload["site_id"], 7);
    assert_eq!(payload["status"], 503);
}

/// **P1-1 的下游兜底**：即使网关侧漏了脱敏（复审实测过的那种形态），
/// 事件表这一层也不许留下密钥形状的原文。
///
/// 为什么这条要独立存在：源头脱敏（`report_failure` 里 `scrub(model)`）是 M7-S1 的修，
/// 而「值被创造的地方」与「值被持久化的地方」是两处——只钉源头的话，
/// 将来有人加第二条出口（比如 webhook 或诊断包）就又漏一次。
#[tokio::test]
async fn a_key_shaped_model_never_reaches_the_event_table_verbatim() {
    let (_dir, service) = service();
    service.record_gateway_failure_for_test(GatewayFailure {
        site_id: 7,
        status: 503,
        model: KEY_SHAPED_MODEL.into(),
        reason: "上游返回可切换状态码 HTTP 503".into(),
    });
    service.refresh_all().await.expect("刷新应成功");

    // `EventRow` 没有 `Serialize`（它是存储层类型），用 `Debug` 形态全文扫描即可。
    let dumped = format!("{:?}", service.recent_events(50).expect("读事件"));
    assert!(
        !dumped.contains(KEY_SHAPED_MODEL),
        "事件表里出现了密钥形状的模型名原文：{dumped}"
    );
}

/// 缓冲有上限：一个持续失败的上游不许把内存吃光（丢最旧的一条）。
#[tokio::test]
async fn the_failure_buffer_is_bounded() {
    let (_dir, service) = service();
    for i in 0..(tianshu_relay_core::service::MAX_BUFFERED_GATEWAY_FAILURES + 10) {
        service.record_gateway_failure_for_test(GatewayFailure {
            site_id: i as i64,
            status: 503,
            model: "m".into(),
            reason: "上游返回可切换状态码 HTTP 503".into(),
        });
    }
    // 落库时最多写出上限条数——多出来的那些在 push 时就被丢掉了。
    let written = service.drain_gateway_failures();
    assert_eq!(
        written,
        tianshu_relay_core::service::MAX_BUFFERED_GATEWAY_FAILURES
    );
    assert_eq!(service.drain_gateway_failures(), 0, "抽干后应为空");
}

/// P3-7 / §11.3：缓冲满丢弃时只记计数——drain 时随事件报出「丢弃 N 条」，
/// 否则用户看到的失败是不完整的而没有任何提示。
#[tokio::test]
async fn a_full_buffer_reports_how_many_were_dropped() {
    let (_dir, service) = service();
    let overflow = 10;
    for i in 0..(tianshu_relay_core::service::MAX_BUFFERED_GATEWAY_FAILURES + overflow) {
        service.record_gateway_failure_for_test(GatewayFailure {
            site_id: i as i64,
            status: 503,
            model: "m".into(),
            reason: "上游返回可切换状态码 HTTP 503".into(),
        });
    }
    let written = service.drain_gateway_failures();
    assert_eq!(
        written,
        tianshu_relay_core::service::MAX_BUFFERED_GATEWAY_FAILURES
    );
    let events = service.recent_events(100).expect("读事件");
    let dumped = format!("{:?}", events);
    assert!(
        dumped.contains(&format!("丢弃 {overflow} 条")),
        "缓冲满丢弃 {overflow} 条要在事件里报出（P3-7）: {dumped}"
    );
}

/// P2-11 / DEBUG-REPORT-v3 §2-11：status=0 的三种原因（全部熔断 / 缺明文 / 已回收）
/// 必须在事件文案里分得开——之前都挤在「网关没有可用的上游（site {}）」一条里。
#[tokio::test]
async fn the_event_message_distinguishes_the_three_status_zero_causes() {
    let (_dir, service) = service();
    service.record_gateway_failure_for_test(GatewayFailure {
        site_id: 1,
        status: 0,
        model: "gpt-5.6".into(),
        reason: "所有候选上游都在熔断冷却中".into(),
    });
    service.record_gateway_failure_for_test(GatewayFailure {
        site_id: 2,
        status: 0,
        model: "gpt-5.6".into(),
        reason: "密钥引用没有对应的明文".into(),
    });
    service.record_gateway_failure_for_test(GatewayFailure {
        site_id: 3,
        status: 0,
        model: "gpt-5.6".into(),
        reason: "该密钥已被回收，不再使用".into(),
    });
    service.refresh_all().await.expect("刷新落库");
    let events = service.recent_events(50).expect("读事件");
    let messages: Vec<&str> = events
        .iter()
        .filter(|e| e.source == "gateway")
        .map(|e| e.message.as_str())
        .collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("所有候选上游都在熔断冷却中")),
        "全熔断原因要进文案: {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("密钥引用没有对应的明文")),
        "缺明文原因要进文案: {messages:?}"
    );
    assert!(
        messages.iter().any(|m| m.contains("该密钥已被回收")),
        "已回收原因要进文案: {messages:?}"
    );
}

/// P2-10 / DEBUG-REPORT-v3 §2-10：传输层失败（超时 / 连不上）与上游真回 502 都是
/// status=502，必须在事件文案里分得开——之前都挤在「网关放弃上游（HTTP 502）」里。
#[tokio::test]
async fn the_event_message_distinguishes_transport_failure_from_an_upstream_502() {
    let (_dir, service) = service();
    service.record_gateway_failure_for_test(GatewayFailure {
        site_id: 1,
        status: 502,
        model: "gpt-5.6".into(),
        reason: "传输层失败（连不上 / 超时）: connection refused".into(),
    });
    service.record_gateway_failure_for_test(GatewayFailure {
        site_id: 2,
        status: 502,
        model: "gpt-5.6".into(),
        reason: "上游返回可切换状态码 HTTP 502".into(),
    });
    service.refresh_all().await.expect("刷新落库");
    let events = service.recent_events(50).expect("读事件");
    let messages: Vec<&str> = events
        .iter()
        .filter(|e| e.source == "gateway")
        .map(|e| e.message.as_str())
        .collect();
    assert!(
        messages.iter().any(|m| m.contains("传输层失败")),
        "传输层失败原因要进文案: {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("上游返回可切换状态码 HTTP 502")),
        "上游真回 502 原因要进文案: {messages:?}"
    );
}
