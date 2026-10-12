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
    assert_eq!(req.url, "https://relay.example.com/api/token/");
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
        // 3) 读明文
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
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].url, "https://relay.example.com/api/token/");
    assert_eq!(requests[1].url, "https://relay.example.com/api/token/");
    assert_eq!(
        requests[2].url,
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
