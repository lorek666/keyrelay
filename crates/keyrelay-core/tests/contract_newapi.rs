//! NewAPI 适配器契约测试：断言**请求内容**与响应解析，而非只断言返回值。

use keyrelay_core::error::Error;
use keyrelay_core::site::newapi::NewApi;
use keyrelay_core::site::transport::{HttpResponse, MockTransport};
use keyrelay_core::site::{Credentials, KeySpec, KeyStatus, Session, SiteAdapter, SiteKind};
use serde_json::json;

const BASE: &str = "https://relay.example.com/";

fn session() -> Session {
    Session {
        cookies: vec![("session".into(), "abc123".into())],
        access_token: None,
        user_id: Some("7".into()),
    }
}

fn header_of<'a>(
    req: &'a keyrelay_core::site::transport::HttpRequest,
    name: &str,
) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// 测试用响应构造器：`HttpResponse::json` 现在返回 `Result`（不再静默降级为空 body）
fn json_resp(status: u16, value: serde_json::Value) -> HttpResponse {
    HttpResponse::json(status, value).expect("测试响应构造失败")
}

/// 站点未启用登录加密（登录前会先探一次该端点）
fn encryption_disabled() -> HttpResponse {
    json_resp(200, json!({"success": true, "data": {"enabled": false}}))
}

#[tokio::test]
async fn detect_identifies_newapi_and_reads_version() {
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"version": "v0.9.1", "quota_per_unit": 500000, "system_name": "中转站"}}),
    )]);
    let adapter = NewApi::new(transport);

    let fp = adapter.detect(BASE).await.unwrap();
    assert_eq!(fp.kind, SiteKind::NewApi);
    assert_eq!(fp.display_name, "中转站");
    assert_eq!(fp.version.as_deref(), Some("v0.9.1"));

    let req = adapter.transport().nth_request(0).unwrap();
    assert_eq!(req.method.as_str(), "GET");
    assert_eq!(req.url, "https://relay.example.com/api/status");
}

#[tokio::test]
async fn detect_rejects_non_newapi_site() {
    let transport = MockTransport::new(vec![json_resp(200, json!({"hello": "world"}))]);
    let adapter = NewApi::new(transport);
    let err = adapter.detect(BASE).await.unwrap_err();
    assert!(matches!(err, Error::FingerprintMismatch(_)));
}

#[tokio::test]
async fn login_captures_session_cookie_and_user_id() {
    // 请求序列：① 加密键探测 ② 登录
    let transport = MockTransport::new(vec![
        encryption_disabled(),
        json_resp(
            200,
            json!({"success": true, "message": "", "data": {"id": 42, "username": "me"}}),
        )
        .with_header("Set-Cookie", "session=s3cr3t; Path=/; HttpOnly"),
    ]);
    let adapter = NewApi::new(transport);

    let session = adapter
        .login(BASE, Credentials::new("me", "pw"))
        .await
        .unwrap();
    assert_eq!(session.user_id.as_deref(), Some("42"));
    assert_eq!(
        session.cookies,
        vec![("session".to_string(), "s3cr3t".to_string())]
    );
    assert_eq!(session.cookie_header().as_deref(), Some("session=s3cr3t"));

    let probe = adapter.transport().nth_request(0).unwrap();
    assert_eq!(
        probe.url,
        "https://relay.example.com/api/user/login/encryption-key"
    );

    let req = adapter.transport().nth_request(1).unwrap();
    assert_eq!(req.method.as_str(), "POST");
    assert_eq!(req.url, "https://relay.example.com/api/user/login");
    let body: serde_json::Value = serde_json::from_slice(req.body.as_ref().unwrap()).unwrap();
    assert_eq!(body["username"], "me");
    assert_eq!(body["password"], "pw");
}

#[tokio::test]
async fn login_maps_turnstile_to_captcha_required() {
    let transport = MockTransport::new(vec![
        encryption_disabled(),
        json_resp(
            200,
            json!({"success": false, "message": "Turnstile 验证失败，请重试"}),
        ),
    ]);
    let adapter = NewApi::new(transport);
    let err = adapter
        .login(BASE, Credentials::new("me", "pw"))
        .await
        .unwrap_err();
    assert_eq!(err, Error::CaptchaRequired);
}

#[tokio::test]
async fn login_maps_2fa_message_to_second_factor() {
    let transport = MockTransport::new(vec![
        encryption_disabled(),
        json_resp(200, json!({"success": false, "message": "需要二次验证"})),
    ]);
    let adapter = NewApi::new(transport);
    let err = adapter
        .login(BASE, Credentials::new("me", "pw"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::SecondFactorRequired { .. }));
}

#[tokio::test]
async fn login_maps_rate_limit_with_retry_after() {
    let transport = MockTransport::new(vec![
        encryption_disabled(),
        HttpResponse::new(429, b"{}".to_vec()).with_header("Retry-After", "30"),
    ]);
    let adapter = NewApi::new(transport);
    let err = adapter
        .login(BASE, Credentials::new("me", "pw"))
        .await
        .unwrap_err();
    assert_eq!(
        err,
        Error::RateLimited {
            retry_after_secs: 30
        }
    );
}

#[tokio::test]
async fn login_encrypts_password_when_site_requires_it() {
    use base64::Engine as _;
    use rsa::pkcs8::{EncodePublicKey, LineEnding};
    use rsa::rand_core::OsRng;
    use rsa::sha2::Sha256;
    use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};

    let private = RsaPrivateKey::new(&mut OsRng, 2048).expect("生成测试密钥");
    let public_pem = RsaPublicKey::from(&private)
        .to_public_key_pem(LineEnding::LF)
        .expect("导出 PEM");

    let transport = MockTransport::new(vec![
        json_resp(
            200,
            json!({"success": true, "data": {"enabled": true, "kid": "kid-1", "public_key": public_pem}}),
        ),
        json_resp(200, json!({"success": true, "data": {"id": 42}})),
    ]);
    let adapter = NewApi::new(transport);

    adapter
        .login(BASE, Credentials::new("me", "hunter2"))
        .await
        .unwrap();

    let req = adapter.transport().nth_request(1).unwrap();
    let body: serde_json::Value = serde_json::from_slice(req.body.as_ref().unwrap()).unwrap();

    // 启用加密时绝不出现明文字段
    assert!(body.get("password").is_none(), "不得发送明文密码: {body}");
    assert_eq!(body["encryption_key_id"], "kid-1");
    assert_eq!(body["username"], "me");

    // 密文必须能被站点私钥按 RSA-OAEP(SHA-256) 解回原文
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(body["password_encrypted"].as_str().unwrap())
        .expect("base64 解码");
    let plaintext = private
        .decrypt(Oaep::new::<Sha256>(), &ciphertext)
        .expect("私钥解密");
    assert_eq!(plaintext, b"hunter2");
}

#[tokio::test]
async fn login_falls_back_to_plaintext_when_encryption_endpoint_missing() {
    // 旧版本 NewAPI 没有该端点 → 404 → 按未启用处理
    let transport = MockTransport::new(vec![
        HttpResponse::new(404, b"404 page not found".to_vec()),
        json_resp(200, json!({"success": true, "data": {"id": 42}})),
    ]);
    let adapter = NewApi::new(transport);

    adapter
        .login(BASE, Credentials::new("me", "pw"))
        .await
        .unwrap();

    let body: serde_json::Value = serde_json::from_slice(
        adapter
            .transport()
            .nth_request(1)
            .unwrap()
            .body
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["password"], "pw");
    assert!(body.get("password_encrypted").is_none());
}

#[tokio::test]
async fn login_rejects_overlong_password_instead_of_sending_plaintext() {
    use rsa::pkcs8::{EncodePublicKey, LineEnding};
    use rsa::rand_core::OsRng;
    use rsa::{RsaPrivateKey, RsaPublicKey};

    let private = RsaPrivateKey::new(&mut OsRng, 2048).expect("生成测试密钥");
    let public_pem = RsaPublicKey::from(&private)
        .to_public_key_pem(LineEnding::LF)
        .expect("导出 PEM");

    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"enabled": true, "kid": "kid-1", "public_key": public_pem}}),
    )]);
    let adapter = NewApi::new(transport);

    let err = adapter
        .login(BASE, Credentials::new("me", "a".repeat(200)))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::AuthFailed(_)), "实际: {err:?}");
    assert_eq!(
        adapter.transport().request_count(),
        1,
        "超长密码不得再发登录请求（更不得降级明文）"
    );
}

#[tokio::test]
async fn list_keys_parses_paginated_shape() {
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"items": [
            {"id": 12, "name": "codex/daily", "group": "default", "status": 1, "created_time": 1700000000, "accessed_time": 1700000100},
            {"id": 13, "name": "claude/old", "status": 2}
        ], "total": 2}}),
    )]);
    let adapter = NewApi::new(transport);
    let keys = adapter.list_keys(BASE, &session()).await.unwrap();

    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].remote_id, "12");
    assert_eq!(keys[0].name, "codex/daily");
    assert_eq!(keys[0].group.as_deref(), Some("default"));
    assert_eq!(keys[0].status, KeyStatus::Enabled);
    assert_eq!(keys[0].last_used_at, Some(1700000100));
    assert_eq!(keys[1].status, KeyStatus::Disabled);

    let req = adapter.transport().nth_request(0).unwrap();
    assert!(
        req.url.starts_with("https://relay.example.com/api/token/?"),
        "列表请求应带分页参数: {}",
        req.url
    );
    assert!(req.url.contains("page_size="), "实际: {}", req.url);
    assert_eq!(
        req.headers
            .iter()
            .find(|(k, _)| k == "Cookie")
            .map(|(_, v)| v.as_str()),
        Some("session=abc123")
    );
}

#[tokio::test]
async fn create_key_flow_is_create_then_list_then_reveal() {
    let transport = MockTransport::new(vec![
        // 1) 创建
        json_resp(200, json!({"success": true, "message": ""})),
        // 2) 列表定位
        json_resp(
            200,
            json!({"success": true, "data": {"items": [
                {"id": 11, "name": "codex/daily", "status": 1, "created_time": 1},
                {"id": 12, "name": "codex/daily", "status": 1, "created_time": 2}
            ]}}),
        ),
        // 3) 站点未声明 total → 必须再探一页才能确认取全（空页即到底）
        json_resp(200, json!({"success": true, "data": {"items": []}})),
        // 4) 读明文
        json_resp(
            200,
            json!({"success": true, "data": {"key": "sk-abcdefgh12345678"}}),
        ),
    ]);
    let adapter = NewApi::new(transport);

    let material = adapter
        .create_key(BASE, &session(), KeySpec::named("codex/daily"))
        .await
        .unwrap();

    // 取 created_time 最大的那条（即最新创建）
    assert_eq!(material.remote_id, "12");
    assert_eq!(material.secret, "sk-abcdefgh12345678");

    let requests = adapter.transport().requests();
    // 创建 + 列表第 1 页 + 列表第 2 页（空页，用于确认到底）+ 读明文
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].url, "https://relay.example.com/api/token/");
    assert!(requests[1]
        .url
        .starts_with("https://relay.example.com/api/token/?"));
    assert_eq!(requests[2].url, "https://relay.example.com/api/token/?p=2&page_size=100");
    assert_eq!(
        requests[3].url,
        "https://relay.example.com/api/token/12/key"
    );
    let create_body: serde_json::Value =
        serde_json::from_slice(requests[0].body.as_ref().unwrap()).unwrap();
    assert_eq!(create_body["name"], "codex/daily");
    assert_eq!(create_body["unlimited_quota"], true);
    assert_eq!(create_body["expired_time"], -1);

    // 认证头必须与其它动作一致（复审 P1-2：曾漏掉 Authorization/Accept 并发出空 Cookie）
    for req in &requests {
        assert_eq!(header_of(req, "Accept"), Some("application/json"));
        assert_eq!(header_of(req, "Cookie"), Some("session=abc123"));
        assert!(
            !req.headers
                .iter()
                .any(|(k, v)| k == "Cookie" && v.is_empty()),
            "不得发出空 Cookie 头"
        );
    }
}

#[tokio::test]
async fn create_key_sends_bearer_when_session_has_access_token() {
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"id": 5, "key": "sk-inline12345678"}}),
    )]);
    let adapter = NewApi::new(transport);
    let token_session = Session {
        cookies: vec![],
        access_token: Some("pat-abcdefghijklmnop".into()),
        user_id: None,
    };

    adapter
        .create_key(BASE, &token_session, KeySpec::named("codex/daily"))
        .await
        .unwrap();

    let req = adapter.transport().nth_request(0).unwrap();
    assert_eq!(
        header_of(&req, "Authorization"),
        Some("Bearer pat-abcdefghijklmnop")
    );
    assert!(
        !req.headers.iter().any(|(k, _)| k == "Cookie"),
        "无 cookie 时不应带 Cookie 头"
    );
}

#[tokio::test]
async fn create_key_uses_key_from_create_response_when_present() {
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"id": 99, "key": "sk-inline12345678"}}),
    )]);
    let adapter = NewApi::new(transport);
    let material = adapter
        .create_key(BASE, &session(), KeySpec::named("inline"))
        .await
        .unwrap();
    assert_eq!(material.remote_id, "99");
    assert_eq!(material.secret, "sk-inline12345678");
    assert_eq!(adapter.transport().request_count(), 1);
}

#[tokio::test]
async fn balance_converts_quota_to_usd() {
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"quota": 1234567, "used_quota": 500000, "quota_per_unit": 500000}}),
    )]);
    let adapter = NewApi::new(transport);
    let balance = adapter.balance(BASE, &session()).await.unwrap();

    assert_eq!(balance.currency, "USD");
    assert_eq!(balance.raw_quota, Some(1234567));
    assert!((balance.remaining - 2.469134).abs() < 1e-6);
    assert!((balance.used - 1.0).abs() < 1e-6);
}

#[tokio::test]
async fn quota_error_is_mapped_on_key_operations() {
    let transport = MockTransport::new(vec![json_resp(
        403,
        json!({"error": {"code": "insufficient_user_quota", "message": "额度不足"}}),
    )]);
    let adapter = NewApi::new(transport);
    let err = adapter.list_keys(BASE, &session()).await.unwrap_err();
    assert_eq!(err, Error::QuotaExhausted);
}

#[tokio::test]
async fn revoke_key_hits_delete_endpoint() {
    let transport = MockTransport::new(vec![json_resp(200, json!({"success": true}))]);
    let adapter = NewApi::new(transport);
    adapter.revoke_key(BASE, &session(), "12").await.unwrap();

    let req = adapter.transport().nth_request(0).unwrap();
    assert_eq!(req.method.as_str(), "DELETE");
    assert_eq!(req.url, "https://relay.example.com/api/token/12");
}

#[tokio::test]
async fn mock_queue_exhaustion_is_reported() {
    let transport = MockTransport::new(vec![]);
    let adapter = NewApi::new(transport);
    let err = adapter.detect(BASE).await.unwrap_err();
    assert!(matches!(err, Error::Transport(_)));
}

// ---------- M1-S1 复审修复：fail-closed、定位、归一化、分页 ----------

#[tokio::test]
async fn encryption_enabled_without_public_key_fails_closed() {
    // 复审 P1-1 ①：站点声明启用加密但载荷缺失 → 必须报错，绝不退回明文
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"enabled": true, "kid": "kid-1"}}),
    )]);
    let adapter = NewApi::new(transport);

    let err = adapter
        .login(BASE, Credentials::new("me", "hunter2"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Transport(_)), "实际: {err:?}");
    assert_eq!(
        adapter.transport().request_count(),
        1,
        "探测失败后不得再发登录请求"
    );
}

#[tokio::test]
async fn encryption_enabled_with_wrong_type_fails_closed() {
    // 复审 P1-1 ②：enabled 非布尔（字符串 "true"）→ 报错
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"enabled": "true", "kid": "k", "public_key": "p"}}),
    )]);
    let adapter = NewApi::new(transport);

    let err = adapter
        .login(BASE, Credentials::new("me", "hunter2"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Transport(_)), "实际: {err:?}");
}

#[tokio::test]
async fn encryption_probe_server_error_fails_closed() {
    // 复审 P1-1 ③：探测端点 500 → 报错，不降级
    let transport = MockTransport::new(vec![HttpResponse::new(500, b"boom".to_vec())]);
    let adapter = NewApi::new(transport);

    let err = adapter
        .login(BASE, Credentials::new("me", "hunter2"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Transport(_)), "实际: {err:?}");
    assert_eq!(adapter.transport().request_count(), 1);
}

#[tokio::test]
async fn encryption_probe_rate_limited_fails_closed() {
    // 复审 P1-1 ④：探测端点 429 → 报 RateLimited，不降级
    let transport = MockTransport::new(vec![
        HttpResponse::new(429, b"{}".to_vec()).with_header("Retry-After", "9")
    ]);
    let adapter = NewApi::new(transport);

    let err = adapter
        .login(BASE, Credentials::new("me", "hunter2"))
        .await
        .unwrap_err();
    assert_eq!(
        err,
        Error::RateLimited {
            retry_after_secs: 9
        }
    );
}

#[tokio::test]
async fn create_key_prefers_highest_id_when_timestamps_missing() {
    // 复审 P2-1：同名令牌且列表无 created_time 时，必须取 id 最大者（最新），而不是末位元素
    let transport = MockTransport::new(vec![
        json_resp(200, json!({"success": true, "message": ""})),
        json_resp(
            200,
            json!({"success": true, "data": {"items": [
                {"id": 12, "name": "dup", "status": 1},
                {"id": 11, "name": "dup", "status": 1}
            ], "total": 2}}),
        ),
        json_resp(
            200,
            json!({"success": true, "data": {"key": "sk-newest12345678"}}),
        ),
    ]);
    let adapter = NewApi::new(transport);

    let material = adapter
        .create_key(BASE, &session(), KeySpec::named("dup"))
        .await
        .unwrap();

    assert_eq!(material.remote_id, "12", "必须定位到 id 最大的同名令牌");
    assert_eq!(
        adapter.transport().nth_request(2).unwrap().url,
        "https://relay.example.com/api/token/12/key"
    );
}

#[tokio::test]
async fn inline_key_response_normalizes_string_id() {
    // 复审 P2-3：data.id 为字符串时不得带引号
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"id": "99", "key": "sk-inline12345678"}}),
    )]);
    let adapter = NewApi::new(transport);

    let material = adapter
        .create_key(BASE, &session(), KeySpec::named("inline"))
        .await
        .unwrap();
    assert_eq!(
        material.remote_id, "99",
        "不得出现引号: {:?}",
        material.remote_id
    );
}

#[tokio::test]
async fn list_keys_follows_pagination() {
    // 复审 P2-2：首页满页且 total 更大时必须继续翻页
    let page1: Vec<serde_json::Value> = (1..=100)
        .map(|i| json!({"id": i, "name": format!("bulk-{i}"), "status": 1}))
        .collect();
    let transport = MockTransport::new(vec![
        json_resp(
            200,
            json!({"success": true, "data": {"items": page1, "total": 101}}),
        ),
        json_resp(
            200,
            json!({"success": true, "data": {"items": [{"id": 101, "name": "codex/daily", "status": 1}], "total": 101}}),
        ),
    ]);
    let adapter = NewApi::new(transport);

    let keys = adapter.list_keys(BASE, &session()).await.unwrap();
    assert_eq!(keys.len(), 101);
    assert!(keys.iter().any(|k| k.name == "codex/daily"));

    let requests = adapter.transport().requests();
    assert_eq!(requests.len(), 2, "应请求两页");
    assert!(requests[0].url.contains("p=1"));
    assert!(requests[1].url.contains("p=2"));
}

// ================================================================ M1-S1 复核 N-1…N-4 回归

#[tokio::test]
async fn encryption_probe_missing_enabled_field_fails_closed() {
    // 复核 N-2：端点存在且返回 JSON 信封，但没有 `enabled` 字段 → 不得按「未启用」放行
    let transport = MockTransport::new(vec![json_resp(200, json!({"success": true, "data": {}}))]);
    let adapter = NewApi::new(transport);

    let err = adapter
        .login(BASE, Credentials::new("me", "hunter2-probe-pw"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Transport(ref m) if m.contains("缺少 enabled")),
        "{err:?}"
    );
    let requests = adapter.transport().requests();
    assert_eq!(requests.len(), 1, "只应发生加密探测，不得发出登录请求");
    assert_eq!(
        requests[0].url,
        format!("{BASE}api/user/login/encryption-key")
    );
}

#[tokio::test]
async fn encryption_probe_failure_envelope_keeps_site_message() {
    // 复核 P2：上游真实存在的 `{"success":false,"message":"Database error…"}`（HTTP 200）
    // 方向是 fail-closed，但站点原文必须带出来，否则用户无法排障
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": false, "message": "Database error while fetching key"}),
    )]);
    let adapter = NewApi::new(transport);

    let err = adapter
        .login(BASE, Credentials::new("me", "pw-12345678"))
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(text.contains("缺少 enabled"), "{text}");
    assert!(text.contains("Database error"), "站点原文被丢弃: {text}");
    assert_eq!(adapter.transport().requests().len(), 1, "不得发出登录请求");
}

#[tokio::test]
async fn list_keys_does_not_assume_the_server_honors_page_size() {
    // 第二轮复核 P1：站点忽略 `page_size`（旧版默认每页 10 条）时，
    // 「本页不满 100 即收工」会把首页 10 条当成全部 → 静默交付截断列表
    let page = |offset: i64, count: i64| -> HttpResponse {
        let items: Vec<serde_json::Value> = (0..count)
            .map(|i| {
                let id = offset + i + 1;
                json!({"id": id, "name": format!("bulk-{id}"), "status": 1})
            })
            .collect();
        json_resp(
            200,
            json!({"success": true, "data": {"items": items, "total": 25}}),
        )
    };
    let transport = MockTransport::new(vec![
        page(0, 10),
        page(10, 10),
        page(20, 5),
    ]);
    let adapter = NewApi::new(transport);

    let keys = adapter.list_keys(BASE, &session()).await.unwrap();
    assert_eq!(keys.len(), 25, "必须按 total 翻到底，而不是首页不满就收工");
    assert_eq!(adapter.transport().requests().len(), 3);
}

#[tokio::test]
async fn create_key_finds_token_beyond_the_first_short_page() {
    // 与上一条同源：站点每页只给 10 条时，刚建好的令牌在第 3 页
    let page = |offset: i64, count: i64| -> HttpResponse {
        let items: Vec<serde_json::Value> = (0..count)
            .map(|i| {
                let id = offset + i + 1;
                let name = if id == 25 { "codex/daily" } else { "bulk" };
                json!({"id": id, "name": name, "status": 1})
            })
            .collect();
        json_resp(
            200,
            json!({"success": true, "data": {"items": items, "total": 25}}),
        )
    };
    let transport = MockTransport::new(vec![
        json_resp(200, json!({"success": true, "data": {}})), // 创建
        page(0, 10),
        page(10, 10),
        page(20, 5),
        json_resp(200, json!({"success": true, "data": {"key": "sk-fresh"}})), // 读明文
    ]);
    let adapter = NewApi::new(transport);

    let material = adapter
        .create_key(
            BASE,
            &session(),
            KeySpec {
                name: "codex/daily".into(),
                quota_limit: None,
                expires_at: None,
                group: None,
            },
        )
        .await
        .expect("不得因短页误报 NotFound");
    assert_eq!(material.remote_id, "25");
    assert_eq!(material.secret, "sk-fresh");
}

#[tokio::test]
async fn list_keys_errors_when_a_page_has_items_but_no_usable_id() {
    // 第二轮复核 P2：有条目却解析不出 id 是解析异常，不能被当成「翻到底了」
    let items: Vec<serde_json::Value> = (0..100)
        .map(|i| json!({"name": format!("no-id-{i}"), "status": 1}))
        .collect();
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"items": items, "total": 500}}),
    )]);
    let adapter = NewApi::new(transport);

    let err = adapter.list_keys(BASE, &session()).await.unwrap_err();
    assert!(
        matches!(err, Error::Transport(ref m) if m.contains("缺少可用的 id")),
        "{err:?}"
    );
}

#[tokio::test]
async fn list_keys_errors_on_empty_page_that_contradicts_total() {
    // 声明 total=1500 却给空页：不能假装取全了
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"items": [], "total": 1500}}),
    )]);
    let adapter = NewApi::new(transport);

    let err = adapter.list_keys(BASE, &session()).await.unwrap_err();
    assert!(
        matches!(err, Error::Transport(ref m) if m.contains("空列表")),
        "{err:?}"
    );
}

#[tokio::test]
async fn list_keys_accepts_empty_account_with_zero_total() {
    // 反例保护：一把令牌都没有的账号必须正常返回空列表，不能报错
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"items": [], "total": 0}}),
    )]);
    let adapter = NewApi::new(transport);
    assert!(adapter.list_keys(BASE, &session()).await.unwrap().is_empty());

    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"items": []}}),
    )]);
    let adapter = NewApi::new(transport);
    assert!(adapter.list_keys(BASE, &session()).await.unwrap().is_empty());
}

#[tokio::test]
async fn list_keys_keeps_paging_when_total_is_not_a_number() {
    // 复核 N-3：`total` 非数字时曾按「本页条数」处理 → 首页满页就静默停住
    let page1: Vec<serde_json::Value> = (1..=100)
        .map(|i| json!({"id": i, "name": format!("bulk-{i}"), "status": 1}))
        .collect();
    let transport = MockTransport::new(vec![
        json_resp(
            200,
            json!({"success": true, "data": {"items": page1, "total": "many"}}),
        ),
        json_resp(
            200,
            json!({"success": true, "data": {"items": [{"id": 101, "name": "codex/daily", "status": 1}]}}),
        ),
        json_resp(200, json!({"success": true, "data": {"items": []}})),
    ]);
    let adapter = NewApi::new(transport);

    let keys = adapter.list_keys(BASE, &session()).await.unwrap();
    assert_eq!(keys.len(), 101, "total 不可用时必须继续翻页直到空页");
    assert_eq!(adapter.transport().requests().len(), 3);
}

#[tokio::test]
async fn list_keys_stops_when_site_ignores_pagination() {
    // 复核 N-3 反例：站点忽略 `p` 参数时不得无限翻页或产出重复项
    let page: Vec<serde_json::Value> = (1..=100)
        .map(|i| json!({"id": i, "name": format!("bulk-{i}"), "status": 1}))
        .collect();
    let same_page = || {
        json_resp(
            200,
            json!({"success": true, "data": {"items": page, "total": 500}}),
        )
    };
    let transport = MockTransport::new(vec![same_page(), same_page()]);
    let adapter = NewApi::new(transport);

    let keys = adapter.list_keys(BASE, &session()).await.unwrap();
    assert_eq!(keys.len(), 100, "同一页重复返回时不得重复计入");
    assert_eq!(
        adapter.transport().requests().len(),
        2,
        "第二页无新增即应停止"
    );
}

#[tokio::test]
async fn list_keys_reports_truncation_instead_of_silently_capping() {
    // 复核 N-3：命中页数上限且可能还有更多 → 显式报错，不交付被截断的列表
    let full_page: Vec<serde_json::Value> = (0..100)
        .map(|i| json!({"id": i, "name": format!("bulk-{i}"), "status": 1}))
        .collect();
    let pages: Vec<HttpResponse> = (0..100)
        .map(|p| {
            let items: Vec<serde_json::Value> = full_page
                .iter()
                .map(|item| {
                    let mut item = item.clone();
                    let id = item.get("id").unwrap().as_i64().unwrap() + p * 100;
                    item["id"] = json!(id);
                    item["name"] = json!(format!("bulk-{id}"));
                    item
                })
                .collect();
            json_resp(
                200,
                json!({"success": true, "data": {"items": items, "total": 20000}}),
            )
        })
        .collect();
    let adapter = NewApi::new(MockTransport::new(pages));

    let err = adapter.list_keys(BASE, &session()).await.unwrap_err();
    assert!(
        matches!(err, Error::Transport(ref m) if m.contains("仍未取全")),
        "{err:?}"
    );
}

#[tokio::test]
async fn reveal_key_rejects_remote_id_that_escapes_the_path_segment() {
    // 复核 N-4：站点返回的 id 被直接拼进路径 → `../user/self` 会打到别的端点
    for hostile in ["../user/self", "1/../user/self", "1?x=2", "1#f", "a b", ""] {
        let adapter = NewApi::new(MockTransport::new(vec![]));
        let err = adapter
            .reveal_key(BASE, &session(), hostile)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Transport(ref m) if m.contains("路径段")),
            "id={hostile:?} → {err:?}"
        );
        assert!(
            adapter.transport().requests().is_empty(),
            "id={hostile:?} 不得发出任何请求"
        );
    }
}

#[tokio::test]
async fn revoke_key_rejects_remote_id_that_escapes_the_path_segment() {
    let adapter = NewApi::new(MockTransport::new(vec![]));
    let err = adapter
        .revoke_key(BASE, &session(), "../../user/self")
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Transport(ref m) if m.contains("路径段")),
        "{err:?}"
    );
    assert!(adapter.transport().requests().is_empty());
}
