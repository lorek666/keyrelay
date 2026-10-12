//! 「会话失效可见性」（M5-S2 / BACKLOG B-61）。
//!
//! 病灶：第一轮能正确把站点分类成「认证失败」并清掉会话缓存，但**第二轮**该站点
//! 变成「没有会话」→ 被 `refresh_all` 当成「用户从没登录过」静默跳过，
//! `RefreshSummary` 里既不算成功也不算失败。用户永远看不到「这个站需要重新登录」。
//!
//! 修复：把该状态**落库**（`sites.health = "needs_login"`）并在每轮汇总里带出来。
//! 本文件按 M5-S0 章程 §4.1 的 5 条判定规则逐条钉住，另加健康状态的生命周期、
//! 完成事件 payload，以及「重启后仍看得见」这条**判别测试**——内存标志位过不了它。
//!
//! 为什么另开一个文件而不是塞进 `refresh_isolation.rs`：那个文件钉的是「逐站点隔离」
//! （M3-S1），与这里的「状态可见性」是两件事；混在一起会让回退任一条修复时
//! 分不清红的是哪一类行为。

use std::path::Path;

use keyrelay_core::error::Error;
use keyrelay_core::service::{
    KeyRelayService, RefreshSummary, ServiceConfig, HEALTH_NEEDS_LOGIN, HEALTH_OK, HEALTH_UNKNOWN,
};
use keyrelay_core::site::transport::{HttpResponse, MockTransport};
use keyrelay_core::site::Credentials;
use keyrelay_core::store::Store;
use serde_json::json;

const QUOTA_PER_UNIT: i64 = 500_000;

fn service_on(path: &Path) -> (KeyRelayService<MockTransport>, MockTransport) {
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

fn site(service: &KeyRelayService<MockTransport>, base_url: &str, name: &str) -> i64 {
    service
        .store()
        .upsert_site("newapi", base_url, name)
        .expect("写站点")
}

/// 登录一个站点：两次请求（① 加密探测 ② 登录）
async fn login_site(service: &KeyRelayService<MockTransport>, mock: &MockTransport, id: i64) {
    mock.push(encryption_disabled());
    mock.push(login_ok());
    service
        .login(id, Credentials::new("me", "pw"))
        .await
        .unwrap_or_else(|e| panic!("登录站点 {id} 失败: {e}"));
}

async fn refresh(service: &KeyRelayService<MockTransport>) -> RefreshSummary {
    service
        .refresh_all()
        .await
        .expect("单站失败必须被隔离，整轮仍应 Ok")
}

/// 落库的健康状态（复审要点：不许只看内存）。
fn health_of(service: &KeyRelayService<MockTransport>, site_id: i64) -> String {
    service
        .store()
        .get_site(site_id)
        .expect("读站点")
        .expect("站点存在")
        .health
}

// ==================================================== 规则 1：有会话且本轮成功

#[tokio::test]
async fn a_healthy_site_is_not_reported_as_needing_a_login() {
    let dir = tempfile::tempdir().unwrap();
    let (service, mock) = service_on(&dir.path().join("keyrelay.db"));
    let a = site(&service, "https://a.example.com", "甲");

    login_site(&service, &mock, a).await;
    assert_eq!(
        health_of(&service, a),
        HEALTH_OK,
        "登录成功必须把状态落库成 ok，否则上一轮的 needs_login 永远消不掉"
    );

    mock.push(balance_ok(1_000_000));
    mock.push(keys_ok());

    let summary = refresh(&service).await;
    assert_eq!(summary.sites_total, 1);
    assert_eq!(summary.sites_ok, 1);
    assert_eq!(summary.sites_failed, 0);
    assert_eq!(
        summary.needs_login,
        Vec::<i64>::new(),
        "刷新成功的站点不该被要求重登"
    );
}

/// 规则 1 的边界：**成功就是成功**。
///
/// 库里可能留着陈旧的 `needs_login`（例如状态写成功之后用户又在别处重登过），
/// 只要本轮有会话且刷新成功，就不该进列表。
#[tokio::test]
async fn a_successful_refresh_does_not_put_a_stale_needs_login_site_back_in_the_list() {
    let dir = tempfile::tempdir().unwrap();
    let (service, mock) = service_on(&dir.path().join("keyrelay.db"));
    let a = site(&service, "https://a.example.com", "甲");

    login_site(&service, &mock, a).await;
    service
        .store()
        .set_site_health(a, HEALTH_NEEDS_LOGIN)
        .expect("造一个陈旧状态");

    mock.push(balance_ok(1_000_000));
    mock.push(keys_ok());

    let summary = refresh(&service).await;
    assert_eq!((summary.sites_ok, summary.sites_failed), (1, 0));
    assert_eq!(
        summary.needs_login,
        Vec::<i64>::new(),
        "有会话且刷新成功 → 不得出现在 needs_login 里"
    );
}

// ==================================================== 规则 2：有会话但本轮失败

#[tokio::test]
async fn an_auth_failure_lands_in_both_sites_failed_and_needs_login() {
    let dir = tempfile::tempdir().unwrap();
    let (service, mock) = service_on(&dir.path().join("keyrelay.db"));
    let a = site(&service, "https://a.example.com", "甲");

    login_site(&service, &mock, a).await;
    let after_login = mock.request_count();

    // 甲回 401：余额请求一次，随后会话被清，令牌列表**不再发请求**
    mock.push(HttpResponse::new(401, b"{}".to_vec()));

    let summary = refresh(&service).await;
    assert_eq!(
        (summary.sites_total, summary.sites_ok, summary.sites_failed),
        (1, 0, 1),
        "认证失败既要算失败，也要能被要求重登"
    );
    assert_eq!(summary.needs_login, vec![a]);
    assert_eq!(
        mock.request_count(),
        after_login + 1,
        "会话已失效的站点不得再被请求"
    );
}

#[tokio::test]
async fn an_auth_failure_persists_the_needs_login_state() {
    let dir = tempfile::tempdir().unwrap();
    let (service, mock) = service_on(&dir.path().join("keyrelay.db"));
    let a = site(&service, "https://a.example.com", "甲");

    login_site(&service, &mock, a).await;
    assert_eq!(health_of(&service, a), HEALTH_OK);

    mock.push(HttpResponse::new(401, b"{}".to_vec()));
    refresh(&service).await;

    assert_eq!(
        health_of(&service, a),
        HEALTH_NEEDS_LOGIN,
        "认证失败必须落库：只放内存的话，重启后这条提示就没了"
    );
}

/// 规则 2b：**非**认证类的失败不得要求用户重登（否则是假提示）。
#[tokio::test]
async fn a_transport_failure_does_not_ask_the_user_to_log_in_again() {
    let dir = tempfile::tempdir().unwrap();
    let (service, mock) = service_on(&dir.path().join("keyrelay.db"));
    let a = site(&service, "https://a.example.com", "甲");

    login_site(&service, &mock, a).await;

    mock.push_error(Error::Transport("模拟断网".into()));
    mock.push(keys_ok());

    let summary = refresh(&service).await;
    assert_eq!((summary.sites_ok, summary.sites_failed), (0, 1));
    assert_eq!(
        summary.needs_login,
        Vec::<i64>::new(),
        "断网不是会话失效，不该弹「请重新登录」"
    );
    assert_eq!(health_of(&service, a), HEALTH_OK, "状态不得被网络错误改写");

    // 会话还在的直接证据：下一轮网络恢复，站点照常刷新成功
    mock.push(balance_ok(1_000_000));
    mock.push(keys_ok());
    let second = refresh(&service).await;
    assert_eq!(
        (second.sites_ok, second.sites_failed),
        (1, 0),
        "断网不该把会话也清掉"
    );
}

/// 规则 2 的边界：人机验证 / 二次验证**不算**会话失效。
///
/// 站点只是要人再过一道验证，会话未必死了；标成 `needs_login` 就是一条假提示。
#[tokio::test]
async fn a_captcha_challenge_is_not_a_dead_session() {
    let dir = tempfile::tempdir().unwrap();
    let (service, mock) = service_on(&dir.path().join("keyrelay.db"));
    let a = site(&service, "https://a.example.com", "甲");

    login_site(&service, &mock, a).await;

    mock.push_error(Error::CaptchaRequired);
    mock.push(keys_ok());

    let summary = refresh(&service).await;
    assert_eq!((summary.sites_ok, summary.sites_failed), (0, 1));
    assert_eq!(
        summary.needs_login,
        Vec::<i64>::new(),
        "人机验证 ≠ 会话失效"
    );
    assert_eq!(health_of(&service, a), HEALTH_OK);
}

// ==================================================== 规则 3 / 4：无会话

#[tokio::test]
async fn a_site_that_needs_a_login_is_visible_every_round() {
    let dir = tempfile::tempdir().unwrap();
    let (service, mock) = service_on(&dir.path().join("keyrelay.db"));
    let a = site(&service, "https://a.example.com", "甲");

    // 模拟「上一轮判过需要重登、应用重启后会话缓存是空的」
    service
        .store()
        .set_site_health(a, HEALTH_NEEDS_LOGIN)
        .expect("造状态");

    for round in 1..=2 {
        let summary = refresh(&service).await;
        assert_eq!(summary.sites_total, 1);
        assert_eq!(
            (summary.sites_ok, summary.sites_failed),
            (0, 0),
            "第 {round} 轮：需要重登的站点既不算成功也不算失败"
        );
        assert_eq!(
            summary.needs_login,
            vec![a],
            "第 {round} 轮：这条提示必须每轮都在"
        );
    }

    assert_eq!(mock.request_count(), 0, "纯本地判定，不得联网");
}

#[tokio::test]
async fn a_site_that_was_never_logged_into_stays_invisible() {
    let dir = tempfile::tempdir().unwrap();
    let (service, mock) = service_on(&dir.path().join("keyrelay.db"));
    let a = site(&service, "https://a.example.com", "从没登录过");
    let b = site(&service, "https://b.example.com", "状态是 ok 但没会话");

    assert_eq!(health_of(&service, a), HEALTH_UNKNOWN, "建站默认值");
    service
        .store()
        .set_site_health(b, HEALTH_OK)
        .expect("造状态");

    let summary = refresh(&service).await;
    assert_eq!(summary.sites_total, 2);
    assert_eq!((summary.sites_ok, summary.sites_failed), (0, 0));
    assert_eq!(
        summary.needs_login,
        Vec::<i64>::new(),
        "从没登录过的站点不得凭空冒出来要求重登"
    );
    assert_eq!(mock.request_count(), 0, "无会话的站点一律不发请求");
}

// ==================================================== 规则 5：顺序与不变量

#[tokio::test]
async fn needs_login_is_ascending_and_the_counters_never_exceed_the_total() {
    let dir = tempfile::tempdir().unwrap();
    let (service, mock) = service_on(&dir.path().join("keyrelay.db"));
    let a = site(&service, "https://a.example.com", "甲");
    let b = site(&service, "https://b.example.com", "乙");
    let c = site(&service, "https://c.example.com", "丙");
    let d = site(&service, "https://d.example.com", "丁");
    assert_eq!((a, b, c, d), (1, 2, 3, 4), "站点按 id 升序处理");

    // 甲：登录后本轮 401；乙 / 丙：无会话 + needs_login；丁：登录且本轮成功
    login_site(&service, &mock, a).await;
    login_site(&service, &mock, d).await;
    service
        .store()
        .set_site_health(b, HEALTH_NEEDS_LOGIN)
        .expect("造状态");
    service
        .store()
        .set_site_health(c, HEALTH_NEEDS_LOGIN)
        .expect("造状态");

    mock.push(HttpResponse::new(401, b"{}".to_vec())); // 甲的余额请求
    mock.push(balance_ok(1_000_000)); // 丁
    mock.push(keys_ok()); // 丁

    let summary = refresh(&service).await;
    assert_eq!(summary.sites_total, 4);
    assert_eq!((summary.sites_ok, summary.sites_failed), (1, 1));
    assert_eq!(summary.needs_login, vec![a, b, c], "升序、去重、不含密钥");
    assert!(
        summary.sites_ok + summary.sites_failed <= summary.sites_total,
        "成功 + 失败不得超过总数"
    );
}

// ==================================================== 完成事件

#[tokio::test]
async fn the_completion_event_carries_the_needs_login_list_without_anything_else() {
    let dir = tempfile::tempdir().unwrap();
    let (service, _mock) = service_on(&dir.path().join("keyrelay.db"));
    let a = site(&service, "https://a.example.com", "甲");
    service
        .store()
        .set_site_health(a, HEALTH_NEEDS_LOGIN)
        .expect("造状态");

    refresh(&service).await;

    let event = service
        .recent_events(200)
        .expect("读事件")
        .into_iter()
        .find(|e| e.message.starts_with("刷新完成"))
        .expect("完成事件在场");
    let text = event.payload.as_deref().expect("完成事件必须带 payload");
    let payload: serde_json::Value = serde_json::from_str(text).expect("payload 是 JSON");

    assert_eq!(payload["needs_login"], json!([a]));
    assert_eq!(payload["sites_total"], json!(1));
    assert_eq!(
        (payload["sites_ok"].clone(), payload["sites_failed"].clone()),
        (json!(0), json!(0)),
        "需要重登的站点不得被算进成功或失败"
    );

    let keys: Vec<&str> = payload
        .as_object()
        .expect("payload 是对象")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys.len(), 5, "完成事件不得夹带别的字段: {keys:?}");
    for expected in [
        "sites_total",
        "sites_ok",
        "sites_failed",
        "keys_total",
        "needs_login",
    ] {
        assert!(keys.contains(&expected), "缺字段 {expected}: {keys:?}");
    }
    assert!(
        !text.contains("a.example.com"),
        "完成事件不得带出站点地址: {text}"
    );
}

// ==================================================== 生命周期

#[tokio::test]
async fn logging_in_clears_the_needs_login_state() {
    let dir = tempfile::tempdir().unwrap();
    let (service, mock) = service_on(&dir.path().join("keyrelay.db"));
    let a = site(&service, "https://a.example.com", "甲");

    login_site(&service, &mock, a).await;
    assert_eq!(health_of(&service, a), HEALTH_OK);

    mock.push(HttpResponse::new(401, b"{}".to_vec()));
    refresh(&service).await;
    assert_eq!(health_of(&service, a), HEALTH_NEEDS_LOGIN);

    login_site(&service, &mock, a).await;
    assert_eq!(
        health_of(&service, a),
        HEALTH_OK,
        "重新登录必须把状态改回 ok"
    );
}

/// 端到端：失效 → 看得见 → 重登 → 不再要求重登。
#[tokio::test]
async fn re_login_removes_the_site_from_the_next_summary() {
    let dir = tempfile::tempdir().unwrap();
    let (service, mock) = service_on(&dir.path().join("keyrelay.db"));
    let a = site(&service, "https://a.example.com", "甲");

    login_site(&service, &mock, a).await;
    mock.push(HttpResponse::new(401, b"{}".to_vec()));
    let first = refresh(&service).await;
    assert_eq!(first.needs_login, vec![a], "第一轮就该看得见");

    login_site(&service, &mock, a).await;
    mock.push(balance_ok(1_000_000));
    mock.push(keys_ok());

    let second = refresh(&service).await;
    assert_eq!(
        (second.sites_ok, second.sites_failed),
        (1, 0),
        "重登之后站点恢复正常"
    );
    assert_eq!(
        second.needs_login,
        Vec::<i64>::new(),
        "重登之后提示必须消失"
    );
}

/// **判别测试**：会话缓存只在进程内，状态必须落库。
///
/// 换一个全新的 service（等价于用户重开应用）后，该站点仍要被带出来；
/// 任何「只加个内存标志位」的实现都过不了这条。
#[tokio::test]
async fn a_fresh_service_still_sees_a_persisted_needs_login_site() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("keyrelay.db");

    let a = {
        let (service, mock) = service_on(&db);
        let a = site(&service, "https://a.example.com", "甲");
        login_site(&service, &mock, a).await;
        mock.push(HttpResponse::new(401, b"{}".to_vec()));
        let summary = refresh(&service).await;
        assert_eq!(summary.needs_login, vec![a]);
        a
        // service 在这里出作用域：会话缓存随之消失
    };

    let (restarted, fresh_mock) = service_on(&db);
    let summary = refresh(&restarted).await;
    assert_eq!(summary.sites_total, 1);
    assert_eq!(
        (summary.sites_ok, summary.sites_failed),
        (0, 0),
        "重启后无会话，既不算成功也不算失败"
    );
    assert_eq!(
        summary.needs_login,
        vec![a],
        "重启后仍要看得见「这个站需要重新登录」"
    );
    assert_eq!(fresh_mock.request_count(), 0, "不得联网");
}
