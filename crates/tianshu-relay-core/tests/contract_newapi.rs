//! NewAPI 适配器契约测试：断言**请求内容**与响应解析，而非只断言返回值。

use serde_json::json;
use tianshu_relay_core::error::Error;
use tianshu_relay_core::site::newapi::NewApi;
use tianshu_relay_core::site::transport::{HttpResponse, MockTransport};
use tianshu_relay_core::site::{Credentials, KeySpec, KeyStatus, Session, SiteAdapter, SiteKind};

const BASE: &str = "https://relay.example.com/";

fn session() -> Session {
    Session {
        cookies: vec![("session".into(), "abc123".into())],
        access_token: None,
        user_id: Some("7".into()),
        user_agent: None,
    }
}

fn header_of<'a>(
    req: &'a tianshu_relay_core::site::transport::HttpRequest,
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
    assert_eq!(session.access_token, None);

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

/// M9-S1：真实站点（`newapi.example.com`）**不发 Set-Cookie 之外的会话**，
/// 只在响应体 `data.access_token` 里给 JWT。早先的实现把 `access_token` 写死 `None`，
/// 于是登录返回 200、拿到空会话、随后每个请求 401（真实复现，见
/// `docs/evidence/real-site-login-2026-10-14.md`）。
///
/// fixture 的字段名与形态逐字取自真实响应（JWT 值用占位串，其余一致）。
#[tokio::test]
async fn login_captures_body_access_token_when_no_cookie_is_set() {
    let transport = MockTransport::new(vec![
        encryption_disabled(),
        json_resp(
            200,
            json!({
                "success": true,
                "message": "",
                "data": {
                    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.placeholder.sig",
                    "token_type": "Bearer",
                    "user": {"id": 207, "username": "USER_PLACEHOLDER", "quota": 0}
                }
            }),
        ),
    ]);
    let adapter = NewApi::new(transport);

    let session = adapter
        .login(BASE, Credentials::new("USER_PLACEHOLDER", "pw"))
        .await
        .unwrap();

    // `user_id` 落在 `data.user.id`（旧版是 `data.id`）——两个落点都要认，
    // 真实站点这条路径只给后者，只读前者会静默丢掉 user_id。
    assert_eq!(session.user_id.as_deref(), Some("207"));
    assert_eq!(
        session.access_token.as_deref(),
        Some("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.placeholder.sig")
    );
    assert!(
        session.cookies.is_empty(),
        "真实站点这条路径没有 Set-Cookie"
    );

    // 关键在下一次请求：Bearer 必须真的发出去。用一个真实读操作（列举令牌）
    // 驱动，断言落在它发出的请求上——`request()` 是私有 helper，集成测试
    // 不直接碰它，否则测的是 helper 而不是产品行为。
    let _ = adapter.list_keys(BASE, &session).await;
    let list_req = adapter.transport().requests().last().cloned().unwrap();
    assert!(
        list_req.url.contains("/api/token/"),
        "应是列举令牌请求，实际: {}",
        list_req.url
    );
    assert_eq!(
        header_of(&list_req, "Authorization"),
        Some("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.placeholder.sig")
    );
}

/// M9-S1：两个来源同时存在时**都保留**——token 走 `Authorization`，
/// cookie 留给仍依赖会话的端点。真实站点同时回 `new_api_refresh` 与
/// `new_api_has_session` 两条 cookie（见留档）。
#[tokio::test]
async fn login_keeps_both_body_token_and_cookies_when_both_exist() {
    let transport = MockTransport::new(vec![
        encryption_disabled(),
        json_resp(
            200,
            json!({
                "success": true,
                "message": "",
                "data": {"access_token": "tok_1234567890", "id": 42}
            }),
        )
        .with_header(
            "Set-Cookie",
            "new_api_refresh=52d13bc5-x; Path=/api/user/auth; HttpOnly",
        )
        .with_header("Set-Cookie", "new_api_has_session=1; Path=/"),
    ]);
    let adapter = NewApi::new(transport);

    let session = adapter
        .login(BASE, Credentials::new("me", "pw"))
        .await
        .unwrap();

    assert_eq!(session.access_token.as_deref(), Some("tok_1234567890"));
    assert_eq!(
        session.cookies,
        vec![
            ("new_api_refresh".to_string(), "52d13bc5-x".to_string()),
            ("new_api_has_session".to_string(), "1".to_string()),
        ]
    );
}

/// M9-S1：两个来源都没有时**明确失败**。返回空会话会让「登录成功」和
/// 「什么都做不了」同时成立，而用户看到的是下一跳的 401。
#[tokio::test]
async fn login_without_token_or_cookie_is_an_error_not_an_empty_session() {
    let transport = MockTransport::new(vec![
        encryption_disabled(),
        json_resp(
            200,
            json!({"success": true, "message": "", "data": {"id": 42, "username": "me"}}),
        ),
    ]);
    let adapter = NewApi::new(transport);

    let err = adapter
        .login(BASE, Credentials::new("me", "pw"))
        .await
        .expect_err("既无 token 也无 cookie 必须报错");
    assert!(
        matches!(err, Error::AuthFailed(ref m) if m.contains("access_token") && m.contains("Set-Cookie")),
        "错误文案要说清两个来源都没有，实际: {err}"
    );
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
        // M9-S1：带上 `access_token`——真实站点（含启用密码加密的那些）
        // 登录成功后会在 body 里给 token，早先 fixture 只给 `id` 是形态不全。
        json_resp(
            200,
            json!({"success": true, "data": {"id": 42, "access_token": "tok-42"}}),
        ),
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
        // M9-S1：同批补上 body token（真实站点两条路径都给）
        json_resp(
            200,
            json!({"success": true, "data": {"id": 42, "access_token": "tok-42"}}),
        ),
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
    assert_eq!(
        requests[2].url,
        "https://relay.example.com/api/token/?p=2&page_size=100"
    );
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
        user_agent: None,
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
async fn balance_without_a_quota_field_is_unknown_not_zero() {
    // DEBUG 报告 §1.7：字段缺失时 `unwrap_or(0)` + 硬写 `known: true`，
    // 于是 `notify/rules.rs` 的 BalanceLow 会拿 0 去比阈值，产出一条假告警。
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"used_quota": 500000, "quota_per_unit": 500000}}),
    )]);
    let adapter = NewApi::new(transport);
    let balance = adapter.balance(BASE, &session()).await.unwrap();

    assert!(!balance.known, "缺 quota ⇒ 不可观测，不是 0");
    assert_eq!(balance.raw_quota, None);
    assert_eq!(balance.quota_per_unit, None);
    assert_eq!(balance.remaining, 0.0, "占位值，判据是 known");
}

#[tokio::test]
async fn a_float_quota_is_unknown_not_truncated_to_zero() {
    // 浮点 quota：`as_i64()` 拿不到。修复前这里显示 0.00。
    // 没有证据说站点会这么返回，所以**不猜**——「解析不出来」如实报成不可观测。
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"quota": 1.5, "used_quota": 0}}),
    )]);
    let adapter = NewApi::new(transport);
    let balance = adapter.balance(BASE, &session()).await.unwrap();
    assert!(!balance.known, "浮点 quota ⇒ 不可观测");
}

#[tokio::test]
async fn a_missing_used_quota_is_unknown_too() {
    // 同一响应体里读到一半 = 没读到。给 `used` 编一个 0.0 是同一个错误换了个字段。
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"quota": 1234567}}),
    )]);
    let adapter = NewApi::new(transport);
    let balance = adapter.balance(BASE, &session()).await.unwrap();
    assert!(!balance.known, "缺 used_quota ⇒ 同样不可观测");
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
    let transport = MockTransport::new(vec![page(0, 10), page(10, 10), page(20, 5)]);
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
                group_label: None,
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
    assert!(adapter
        .list_keys(BASE, &session())
        .await
        .unwrap()
        .is_empty());

    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"items": []}}),
    )]);
    let adapter = NewApi::new(transport);
    assert!(adapter
        .list_keys(BASE, &session())
        .await
        .unwrap()
        .is_empty());
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
    // M5-S3（差异登记 D-3）：id 从 1 起。旧夹具用 `(0..100)`，首条 id 为 0——
    // B-35 之后 0 不再是合法主键（本测试关心的是「页数上限」，不是 id 语义）。
    let full_page: Vec<serde_json::Value> = (1..=100)
        .map(|i| json!({"id": i, "name": format!("bulk-{i}"), "status": 1}))
        .collect();
    // 第 101 页仍有新数据 → 上限保护才应触发（第 100 页之后允许一次探测）
    let pages: Vec<HttpResponse> = (0..101)
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
async fn list_keys_ignores_a_negative_total_instead_of_truncating() {
    // M1-S3/S4 复审 P2-1：`total: -5` 曾让 `collected.len() >= total` 在第一页就成立，
    // 于是只发 1 次请求、静默交付被截断的列表。负数必须被当作「没给可用总数」。
    let page = |offset: i64, count: i64| -> HttpResponse {
        let items: Vec<serde_json::Value> = (0..count)
            .map(|i| {
                let id = offset + i + 1;
                json!({"id": id, "name": format!("bulk-{id}"), "status": 1})
            })
            .collect();
        json_resp(
            200,
            json!({"success": true, "data": {"items": items, "total": -5}}),
        )
    };
    // total 被当作「缺失」后，靠空页收尾 → 需要第 4 次请求
    let transport = MockTransport::new(vec![
        page(0, 10),
        page(10, 10),
        page(20, 5),
        json_resp(
            200,
            json!({"success": true, "data": {"items": [], "total": -5}}),
        ),
    ]);
    let adapter = NewApi::new(transport);

    let keys = adapter.list_keys(BASE, &session()).await.unwrap();
    assert_eq!(keys.len(), 25, "负数 total 不得导致提前收工");
    assert_eq!(adapter.transport().requests().len(), 4);
}

#[tokio::test]
async fn list_keys_reaches_the_last_page_without_a_total_field() {
    // 第三轮复核 P2-2：站点忽略 `page_size`（每页 10 条）+ 恰好 1000 条 + 响应无 `total`。
    // 第 100 页取满 1000 条后还需要一次探测才能确认到底，不能在这里误报「取不全」。
    let page = |offset: i64| -> HttpResponse {
        let items: Vec<serde_json::Value> = (0..10)
            .map(|i| {
                let id = offset + i + 1;
                json!({"id": id, "name": format!("bulk-{id}"), "status": 1})
            })
            .collect();
        json_resp(200, json!({"success": true, "data": {"items": items}}))
    };
    let mut pages: Vec<HttpResponse> = (0..100).map(|p| page(p * 10)).collect();
    pages.push(json_resp(
        200,
        json!({"success": true, "data": {"items": []}}),
    ));
    let adapter = NewApi::new(MockTransport::new(pages));

    let keys = adapter.list_keys(BASE, &session()).await.unwrap();
    assert_eq!(keys.len(), 1000, "恰好 1000 条必须取全，不得误报上限");
    assert_eq!(
        adapter.transport().requests().len(),
        101,
        "含一次收尾探测请求"
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

// ================================================================ M5-S3：B-35 令牌 id 收紧

#[tokio::test]
async fn list_keys_rejects_a_fractional_token_id() {
    // BACKLOG B-35：`id: 1.5` 曾被归一成 `"1.5"` 塞进 DTO，
    // 而 `numeric_id()` 解析失败退化为 0，会让「同名取 id 最大者」选错令牌。
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"items": [
            {"id": 12, "name": "ok", "status": 1},
            {"id": 1.5, "name": "float-id", "status": 1}
        ], "total": 2}}),
    )]);
    let adapter = NewApi::new(transport);

    let err = adapter.list_keys(BASE, &session()).await.unwrap_err();
    assert!(matches!(err, Error::Transport(_)), "{err:?}");
    let message = err.to_string();
    assert!(message.contains("令牌 id"), "{message}");
    assert!(message.contains("1.5"), "应能看出站点给了什么: {message}");
}

#[tokio::test]
async fn list_keys_rejects_zero_or_negative_token_id() {
    // BACKLOG B-35：`id: 0` 与「解析失败」在 `pick_newest_token` 里不可区分
    for bad in [json!(0), json!(-1), json!(2.0)] {
        let transport = MockTransport::new(vec![json_resp(
            200,
            json!({"success": true, "data": {"items": [
                {"id": bad, "name": "bad-id", "status": 1}
            ], "total": 1}}),
        )]);
        let adapter = NewApi::new(transport);

        let err = adapter.list_keys(BASE, &session()).await.unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "id={bad} → {err:?}");
        assert!(err.to_string().contains("令牌 id"), "id={bad} → {err}",);
    }
}

#[tokio::test]
async fn list_keys_keeps_integer_and_integer_string_token_ids() {
    // 反例保护：整数与整数字符串照常，`null` 仍按「站点没给 id」跳过
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"items": [
            {"id": 12, "name": "int", "status": 1},
            {"id": null, "name": "null-id", "status": 1},
            {"id": "99", "name": "str", "status": 1}
        ], "total": 2}}),
    )]);
    let adapter = NewApi::new(transport);

    let keys = adapter.list_keys(BASE, &session()).await.unwrap();
    assert_eq!(keys.len(), 2, "null id 的条目应被跳过");
    assert_eq!(keys[0].remote_id, "12");
    assert_eq!(keys[1].remote_id, "99");
}

#[tokio::test]
async fn create_key_rejects_an_invalid_id_in_the_inline_key_response() {
    // 内联明文路径下 id 非法 → 报错，而不是产出既定位不了也吊销不了的空 remote_id
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"id": 0, "key": "sk-inline12345678"}}),
    )]);
    let adapter = NewApi::new(transport);

    let err = adapter
        .create_key(BASE, &session(), KeySpec::named("inline"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Transport(_)), "{err:?}");
    assert!(err.to_string().contains("令牌 id"), "{err}");
    assert_eq!(
        adapter.transport().request_count(),
        1,
        "不得退回「创建 → 列表定位」路径"
    );
}

// ================================================================ M5-S3：B-41 total 宽松解析

#[tokio::test]
async fn list_keys_uses_a_string_total_to_stop_without_an_extra_probe() {
    // BACKLOG B-41：`total: "2"` 若被当成「缺失」，结果仍然对，但会白白多探一页。
    // 请求数停在 1 次才能证明字符串 total 真的被采纳。
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"items": [
            {"id": 1, "name": "a", "status": 1},
            {"id": 2, "name": "b", "status": 1}
        ], "total": "2"}}),
    )]);
    let adapter = NewApi::new(transport);

    let keys = adapter.list_keys(BASE, &session()).await.unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(
        adapter.transport().requests().len(),
        1,
        "字符串 total 必须被采纳"
    );
}

#[tokio::test]
async fn list_keys_uses_an_integral_float_total() {
    // 浮点 `2.0` 与字符串同理：整数值必须被采纳，不该多探一页
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"items": [
            {"id": 1, "name": "a", "status": 1},
            {"id": 2, "name": "b", "status": 1}
        ], "total": 2.0}}),
    )]);
    let adapter = NewApi::new(transport);

    let keys = adapter.list_keys(BASE, &session()).await.unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(
        adapter.transport().requests().len(),
        1,
        "整数值浮点 total 必须被采纳"
    );
}

#[tokio::test]
async fn list_keys_treats_a_boolean_total_as_missing() {
    // 布尔不是总数 → 视为「站点没给总数」，靠空页终止（必须发第 2 次请求）
    let transport = MockTransport::new(vec![
        json_resp(
            200,
            json!({"success": true, "data": {"items": [
                {"id": 1, "name": "a", "status": 1}
            ], "total": true}}),
        ),
        json_resp(
            200,
            json!({"success": true, "data": {"items": [], "total": true}}),
        ),
    ]);
    let adapter = NewApi::new(transport);

    let keys = adapter.list_keys(BASE, &session()).await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(
        adapter.transport().requests().len(),
        2,
        "布尔 total 必须被当作缺失，靠空页收尾"
    );
}

#[tokio::test]
async fn list_keys_does_not_truncate_on_a_fractional_total() {
    // 反例保护：`total: 2.5` 不得被当成 2（否则会在第二页还没取时就静默收工）
    let transport = MockTransport::new(vec![
        json_resp(
            200,
            json!({"success": true, "data": {"items": [
                {"id": 1, "name": "a", "status": 1},
                {"id": 2, "name": "b", "status": 1}
            ], "total": 2.5}}),
        ),
        json_resp(
            200,
            json!({"success": true, "data": {"items": [], "total": 2.5}}),
        ),
    ]);
    let adapter = NewApi::new(transport);

    let keys = adapter.list_keys(BASE, &session()).await.unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(
        adapter.transport().requests().len(),
        2,
        "小数 total 不得被截断成整数"
    );
}

// ============================================================ M29-S1：续期（B-193）

fn refresh_session_with(refresh: &str) -> Session {
    Session {
        cookies: vec![
            ("new_api_refresh".into(), refresh.into()),
            ("new_api_has_session".into(), "1".into()),
        ],
        access_token: Some("old-token".into()),
        user_id: Some("7".into()),
        user_agent: Some("UA/1.0".into()),
    }
}

#[tokio::test]
async fn refresh_session_sends_the_expected_request() {
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"access_token": "new-token", "user": {"id": 42}}}),
    )]);
    let adapter = NewApi::new(transport.clone());
    let session = refresh_session_with("sid-1.secret-part");

    adapter.refresh_session(BASE, &session).await.expect("续期");

    let requests = transport.requests();
    assert_eq!(requests.len(), 1);
    let req = &requests[0];
    assert_eq!(req.url, "https://relay.example.com/api/user/auth/refresh");
    assert_eq!(
        req.method.as_str(),
        "POST",
        "续期必须是 POST（M29-S1 复审 P2-2）"
    );
    assert_eq!(
        header_of(req, "Cookie"),
        Some("new_api_refresh=sid-1.secret-part"),
        "Cookie 头只许带续期凭据一条"
    );
    assert_eq!(header_of(req, "Origin"), Some("https://relay.example.com"));
    assert_eq!(
        header_of(req, "Referer"),
        Some("https://relay.example.com/")
    );
    assert_eq!(header_of(req, "X-Auth-Session"), Some("sid-1"));
    assert_eq!(header_of(req, "Accept"), Some("application/json"));
}

#[tokio::test]
async fn refresh_session_parses_token_and_rotates_cookies() {
    let mut resp = json_resp(
        200,
        json!({
            "success": true,
            "data": {"access_token": "  new-token  ", "token_type": "Bearer", "user": {"id": 42}}
        }),
    );
    resp.headers.push((
        "Set-Cookie".into(),
        "new_api_refresh=rotated.secret-2; Path=/; HttpOnly".into(),
    ));
    resp.headers
        .push(("Set-Cookie".into(), "new_api_session_hint=1; Path=/".into()));
    let transport = MockTransport::new(vec![resp]);
    let adapter = NewApi::new(transport);

    let new = adapter
        .refresh_session(BASE, &refresh_session_with("old.secret-1"))
        .await
        .expect("续期")
        .expect("应当返回新会话");

    assert_eq!(
        new.access_token.as_deref(),
        Some("new-token"),
        "token 需 trim"
    );
    assert_eq!(new.user_id.as_deref(), Some("42"));
    assert_eq!(new.user_agent.as_deref(), Some("UA/1.0"), "UA 沿用入参");
    // 同名覆盖
    assert_eq!(
        new.cookie_value("new_api_refresh"),
        Some("rotated.secret-2"),
        "轮换后的 refresh cookie 必须覆盖旧值"
    );
    // 未变的其余 cookie 保留
    assert_eq!(new.cookie_value("new_api_has_session"), Some("1"));
    // 新 cookie 追加
    assert_eq!(new.cookie_value("new_api_session_hint"), Some("1"));
    assert_eq!(
        new.cookies.len(),
        3,
        "同名覆盖不新增条目：{:?}",
        new.cookies.len()
    );
}

#[tokio::test]
async fn refresh_session_with_empty_token_is_a_transport_error() {
    for data in [
        json!({}),
        json!({"access_token": ""}),
        json!({"access_token": "   "}),
    ] {
        let transport =
            MockTransport::new(vec![json_resp(200, json!({"success": true, "data": data}))]);
        let adapter = NewApi::new(transport);
        let err = adapter
            .refresh_session(BASE, &refresh_session_with("r.s"))
            .await
            .expect_err("缺 token 必须报错");
        assert!(
            matches!(&err, Error::Transport(m) if m.contains("续期响应缺少 access_token")),
            "{err:?}"
        );
    }
}

#[tokio::test]
async fn refresh_session_404_is_none() {
    let transport = MockTransport::new(vec![json_resp(404, json!({"message": "not found"}))]);
    let adapter = NewApi::new(transport);
    let out = adapter
        .refresh_session(BASE, &refresh_session_with("r.s"))
        .await
        .expect("404 不是错误");
    assert!(
        out.is_none(),
        "旧版无端点 ⇒ Ok(None)，调用方走 cookie-only 兜底"
    );
}

#[tokio::test]
async fn refresh_session_401_is_auth_failed_without_secrets() {
    let transport = MockTransport::new(vec![json_resp(
        401,
        json!({"message": "echo sid-1.secret-part old-token"}),
    )]);
    let adapter = NewApi::new(transport);
    let err = adapter
        .refresh_session(BASE, &refresh_session_with("sid-1.secret-part"))
        .await
        .expect_err("401 必须报 AuthFailed");
    assert!(matches!(err, Error::AuthFailed(_)), "{err:?}");
    let text = err.to_string();
    assert!(!text.contains("secret-part"), "错误文案不得含凭据：{text}");
    assert!(!text.contains("old-token"), "错误文案不得含 token：{text}");
}

#[tokio::test]
async fn refresh_session_without_refresh_cookie_makes_no_request() {
    // 空 MockTransport：任何请求都会 panic（队列为空 ⇒ MockTransport 失败）
    let transport = MockTransport::new(vec![]);
    let adapter = NewApi::new(transport.clone());
    let mut s = session(); // 只有 `session` cookie，没有 `new_api_refresh`
    s.access_token = Some("old".into());

    let out = adapter
        .refresh_session(BASE, &s)
        .await
        .expect("应当 Ok(None)");
    assert!(out.is_none());
    assert!(transport.requests().is_empty(), "没有续期凭据时不得发请求");
}

#[tokio::test]
async fn list_keys_excludes_refresh_cookie_from_api_requests() {
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": [], "total": 0}),
    )]);
    let adapter = NewApi::new(transport.clone());
    let session = refresh_session_with("sid-1.secret-part");

    let keys = adapter.list_keys(BASE, &session).await.expect("列举令牌");
    assert!(keys.is_empty());

    let req = &transport.requests()[0];
    let cookie = header_of(req, "Cookie").unwrap_or_default();
    assert!(
        cookie.contains("new_api_has_session=1"),
        "普通 cookie 应照常发送: {cookie}"
    );
    assert!(
        !cookie.contains("new_api_refresh"),
        "续期凭据只应发给续期端点，不得出现在普通 API 请求: {cookie}"
    );
}
