//! `refresh_all` 的**逐站点隔离**（M3-S1 spec §8-3）。
//!
//! 为什么单独一个文件：复审 P1-1 实测——把 `service.rs` 里逐站点的
//! `match (&balance, &keys)` 换成 `?` 上抛之后，既有的四条 `refresh_all` 测试
//! **全部照过**。它们测的都是「没有会话的站点被 `continue` 跳过」这条旁路，
//! 而 `continue` 发生在 `balance()` / `list_keys()` **之前**，隔离逻辑本身
//! 从未被任何测试走到。
//!
//! 本文件把复审探针 P7 / P7b 的场景钉成正式用例，覆盖三件事：
//! 1. 中间站点的传输层失败**不得**中断整轮（后面两个站点照常刷新）；
//! 2. 失败事件的原因分类正确，且只记一次；
//! 3. 认证失败会清掉会话缓存，下一轮该站点按「未登录」静默跳过。

use keyrelay_core::error::Error;
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::settings::Settings;
use keyrelay_core::site::transport::{HttpResponse, MockTransport};
use keyrelay_core::site::Credentials;
use keyrelay_core::store::Store;
use serde_json::json;

const QUOTA_PER_UNIT: i64 = 500_000;

fn service_on(path: &std::path::Path) -> (KeyRelayService<MockTransport>, MockTransport) {
    let store = Store::open(path).expect("文件库");
    let mock = MockTransport::new(vec![]);
    let service = KeyRelayService::new(
        store,
        mock.clone(),
        ServiceConfig::in_memory(path.parent().unwrap().join("home")),
    );
    (service, mock)
}

/// 站点未启用登录加密（`fetch_encryption_key` 的 fail-open 分支）
fn encryption_disabled() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": {"enabled": false}})).expect("构造响应")
}

fn login_ok() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": {"id": 7}}))
        .expect("构造响应")
        .with_header("Set-Cookie", "session=abc; Path=/")
}

/// 余额 = quota / quota_per_unit（USD）
fn balance_ok(quota: i64) -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"success": true, "data": {"quota": quota, "used_quota": 0, "quota_per_unit": QUOTA_PER_UNIT}}),
    )
    .expect("构造响应")
}

fn keys_ok() -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"success": true, "data": {"items": [], "total": 0}}),
    )
    .expect("构造响应")
}

/// 登录三个站点：每个站点两次请求（① 加密探测 ② 登录）
async fn login_all(service: &KeyRelayService<MockTransport>, mock: &MockTransport, ids: &[i64]) {
    for _ in ids {
        mock.push(encryption_disabled());
        mock.push(login_ok());
    }
    for id in ids {
        service
            .login(*id, Credentials::new("me", "pw"))
            .await
            .unwrap_or_else(|e| panic!("登录站点 {id} 失败: {e}"));
    }
}

fn request_lines(mock: &MockTransport, from: usize) -> Vec<String> {
    mock.requests()
        .into_iter()
        .skip(from)
        .map(|r| format!("{} {}", r.method.as_str(), r.url))
        .collect()
}

fn messages_containing(service: &KeyRelayService<MockTransport>, needle: &str) -> Vec<String> {
    service
        .recent_events(200)
        .expect("读事件")
        .into_iter()
        .filter(|e| e.message.contains(needle))
        .map(|e| e.message)
        .collect()
}

#[tokio::test]
async fn a_failing_site_in_the_middle_does_not_abort_the_others() {
    let dir = tempfile::tempdir().unwrap();
    let (service, mock) = service_on(&dir.path().join("keyrelay.db"));

    let a = service
        .store()
        .upsert_site("newapi", "https://a.example.com", "甲")
        .expect("写站点");
    let b = service
        .store()
        .upsert_site("newapi", "https://b.example.com", "乙")
        .expect("写站点");
    let c = service
        .store()
        .upsert_site("newapi", "https://c.example.com", "丙")
        .expect("写站点");
    assert_eq!(
        (a, b, c),
        (1, 2, 3),
        "站点按 id 升序刷新，顺序是这条测试的前提"
    );

    // 阈值 3.0 USD：甲 2.0 触发告警，丙 4.0 不触发
    service
        .update_settings(&Settings {
            balance_alert_threshold: 3.0,
            ..Settings::default()
        })
        .expect("写设置");

    login_all(&service, &mock, &[a, b, c]).await;
    let after_login = mock.request_count();
    assert_eq!(after_login, 6, "每个站点两次登录请求");

    // 刷新：每站点两次请求（① 余额 ② 令牌列表）。**乙的余额请求直接炸传输层**。
    mock.push(balance_ok(1_000_000));
    mock.push(keys_ok());
    mock.push_error(Error::Transport("模拟断网".into()));
    mock.push(keys_ok());
    mock.push(balance_ok(2_000_000));
    mock.push(keys_ok());

    let summary = service
        .refresh_all()
        .await
        .expect("单站失败必须被隔离，整轮仍应 Ok");

    assert_eq!(summary.sites_total, 3);
    assert_eq!(summary.sites_ok, 2, "乙前后两个站点都应刷新成功");
    assert_eq!(summary.sites_failed, 1);
    assert_eq!(summary.keys_total, 0);
    assert_eq!(summary.balance_alerts, vec![a], "只有甲的余额低于阈值");

    // 隔离的**直接**证据：乙失败之后，丙的两个请求照样发出去了
    assert_eq!(
        request_lines(&mock, after_login),
        vec![
            "GET https://a.example.com/api/user/self",
            "GET https://a.example.com/api/token/?p=1&page_size=100",
            "GET https://b.example.com/api/user/self",
            "GET https://b.example.com/api/token/?p=1&page_size=100",
            "GET https://c.example.com/api/user/self",
            "GET https://c.example.com/api/token/?p=1&page_size=100",
        ],
        "中间站点失败不得让后面的站点静默消失"
    );

    let failures = messages_containing(&service, "刷新站点失败");
    assert_eq!(
        failures,
        vec!["刷新站点失败: 网络/协议错误"],
        "失败只记一次且分类正确"
    );
    let failed_event = service
        .recent_events(200)
        .expect("读事件")
        .into_iter()
        .find(|e| e.message == failures[0])
        .expect("失败事件在场");
    assert!(
        failed_event
            .payload
            .as_deref()
            .unwrap_or("")
            .contains(&format!("\"site_id\":{b}")),
        "失败事件必须指向乙: {:?}",
        failed_event.payload
    );
}

#[tokio::test]
async fn an_auth_failure_is_classified_and_invalidates_the_session() {
    let dir = tempfile::tempdir().unwrap();
    let (service, mock) = service_on(&dir.path().join("keyrelay.db"));

    let a = service
        .store()
        .upsert_site("newapi", "https://a.example.com", "甲")
        .expect("写站点");
    let b = service
        .store()
        .upsert_site("newapi", "https://b.example.com", "乙")
        .expect("写站点");

    login_all(&service, &mock, &[a, b]).await;

    // 甲回 401：余额请求一次，随后会话被清，令牌列表**不再发请求**
    mock.push(HttpResponse::new(401, b"{}".to_vec()));
    mock.push(balance_ok(2_000_000));
    mock.push(keys_ok());

    let first = service.refresh_all().await.expect("整轮仍应 Ok");
    assert_eq!(
        (first.sites_total, first.sites_ok, first.sites_failed),
        (2, 1, 1)
    );
    assert_eq!(
        messages_containing(&service, "刷新站点失败"),
        vec!["刷新站点失败: 认证失败"],
        "401 必须分类成认证失败，而不是网络/协议错误"
    );

    let requests_after_round_one = mock.request_count();

    // 第二轮：甲已无会话 → 静默跳过（不算失败，也不再打站点）
    mock.push(balance_ok(2_000_000));
    mock.push(keys_ok());

    let second = service.refresh_all().await.expect("整轮仍应 Ok");
    assert_eq!(
        (second.sites_total, second.sites_ok, second.sites_failed),
        (2, 1, 0),
        "会话被清掉的站点在下一轮按「未登录」跳过，不该继续算失败"
    );
    assert_eq!(
        messages_containing(&service, "刷新站点失败").len(),
        1,
        "第二轮不得再产生失败事件"
    );
    assert_eq!(
        request_lines(&mock, requests_after_round_one),
        vec![
            "GET https://b.example.com/api/user/self",
            "GET https://b.example.com/api/token/?p=1&page_size=100",
        ],
        "甲在第二轮不得被再次请求"
    );
}
