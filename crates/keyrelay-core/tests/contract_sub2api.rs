//! Sub2API 适配器契约测试（M2-S1 spec §7）。
//!
//! 契约字段全部来自本地源码实测，见 `crates/keyrelay-core/src/site/sub2api.rs` 的模块文档。

use keyrelay_core::error::{Error, SecondFactorKind};
use keyrelay_core::site::sub2api::Sub2Api;
use keyrelay_core::site::transport::{HttpResponse, MockTransport};
use keyrelay_core::site::{Credentials, KeySpec, KeyStatus, Session, SiteAdapter, SiteKind};
use serde_json::{json, Value};

const BASE: &str = "https://sub.example.com/";
const SECRET: &str = "sk-SUB2API-PLAINTEXT-000000000000";

fn json_resp(status: u16, value: Value) -> HttpResponse {
    HttpResponse::json(status, value).expect("构造响应")
}

/// Sub2API 的成功信封：`{code: 0, message: "success", data: ...}`
fn ok(data: Value) -> HttpResponse {
    json_resp(200, json!({"code": 0, "message": "success", "data": data}))
}

fn session() -> Session {
    Session {
        cookies: Vec::new(),
        access_token: Some("tok-abc".to_string()),
        user_id: Some("7".to_string()),
    }
}

fn body_of(req: &keyrelay_core::site::transport::HttpRequest) -> Value {
    serde_json::from_slice(req.body.as_ref().expect("有请求体")).unwrap_or(Value::Null)
}

// ================================================================ 指纹识别

#[tokio::test]
async fn detect_identifies_sub2api_from_public_settings() {
    let transport = MockTransport::new(vec![ok(json!({
        "site_name": "示例 Sub2API",
        "api_base_url": "https://sub.example.com",
        "totp_enabled": true,
    }))]);
    let adapter = Sub2Api::new(transport);

    let fingerprint = adapter.detect(BASE).await.unwrap();
    assert_eq!(fingerprint.kind, SiteKind::Sub2Api);
    assert_eq!(fingerprint.display_name, "示例 Sub2API");
    assert!(fingerprint.version.is_none());

    let requests = adapter.transport().requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].url,
        "https://sub.example.com/api/v1/settings/public"
    );
}

#[tokio::test]
async fn detect_rejects_newapi_envelope() {
    // NewAPI 的信封没有 `code` 字段 → 必须拒绝
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": true, "data": {"version": "v0.9.1", "quota_per_unit": 500000}}),
    )]);
    let adapter = Sub2Api::new(transport);
    let err = adapter.detect(BASE).await.unwrap_err();
    assert!(matches!(err, Error::FingerprintMismatch(_)), "{err:?}");
}

#[tokio::test]
async fn detect_rejects_envelope_without_sub2api_fields() {
    let transport = MockTransport::new(vec![ok(json!({"some": "thing"}))]);
    let adapter = Sub2Api::new(transport);
    let err = adapter.detect(BASE).await.unwrap_err();
    assert!(
        matches!(err, Error::FingerprintMismatch(ref m) if m.contains("Sub2API 特征")),
        "{err:?}"
    );
}

// ================================================================ 登录

#[tokio::test]
async fn login_sends_email_not_username() {
    let transport = MockTransport::new(vec![ok(json!({
        "access_token": "tok-abc",
        "token_type": "Bearer",
        "user": {"id": 7, "email": "me@example.com"},
    }))]);
    let adapter = Sub2Api::new(transport);

    let session = adapter
        .login(BASE, Credentials::new("me@example.com", "pw-12345678"))
        .await
        .unwrap();

    assert_eq!(session.access_token.as_deref(), Some("tok-abc"));
    assert_eq!(session.user_id.as_deref(), Some("7"));
    assert!(session.cookies.is_empty(), "Sub2API 用 Bearer，不用 Cookie");

    let requests = adapter.transport().requests();
    assert_eq!(requests[0].url, "https://sub.example.com/api/v1/auth/login");
    let body = body_of(&requests[0]);
    assert_eq!(body["email"], "me@example.com");
    assert_eq!(body["password"], "pw-12345678");
    assert!(
        body.get("username").is_none(),
        "字段名必须是 email，不能是 username: {body}"
    );
}

#[tokio::test]
async fn login_with_2fa_challenge_then_completes() {
    let transport = MockTransport::new(vec![
        // 第一次：站点要求二次验证
        ok(json!({"requires_2fa": true, "temp_token": "temp-xyz"})),
        // 第二次：带 TOTP 完成
        ok(json!({"access_token": "tok-after-2fa", "user": {"id": 9}})),
    ]);
    let adapter = Sub2Api::new(transport);

    let err = adapter
        .login(BASE, Credentials::new("me@example.com", "pw"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::SecondFactorRequired {
                kind: SecondFactorKind::Totp
            }
        ),
        "{err:?}"
    );

    let session = adapter
        .login(
            BASE,
            Credentials::new("me@example.com", "pw").with_second_factor("123456"),
        )
        .await
        .expect("带验证码应完成登录");
    assert_eq!(session.access_token.as_deref(), Some("tok-after-2fa"));

    let requests = adapter.transport().requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[1].url,
        "https://sub.example.com/api/v1/auth/login/2fa"
    );
    let body = body_of(&requests[1]);
    assert_eq!(body["temp_token"], "temp-xyz");
    assert_eq!(body["totp_code"], "123456");
}

#[tokio::test]
async fn login_2fa_without_cached_token_relogs_first() {
    // 模拟「应用重启 / 缓存过期」：直接带验证码登录 → 先重新拿 temp_token
    let transport = MockTransport::new(vec![
        ok(json!({"requires_2fa": true, "temp_token": "fresh-token"})),
        ok(json!({"access_token": "tok-ok", "user": {"id": 1}})),
    ]);
    let adapter = Sub2Api::new(transport);

    let session = adapter
        .login(
            BASE,
            Credentials::new("me@example.com", "pw").with_second_factor("654321"),
        )
        .await
        .expect("应能自动补一次登录再完成 2FA");
    assert_eq!(session.access_token.as_deref(), Some("tok-ok"));

    let requests = adapter.transport().requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(body_of(&requests[0])["email"], "me@example.com");
    assert_eq!(body_of(&requests[1])["temp_token"], "fresh-token");
}

#[tokio::test]
async fn login_2fa_with_bad_code_length_is_rejected_locally() {
    let transport = MockTransport::new(vec![]);
    let adapter = Sub2Api::new(transport);

    for bad in ["12345", "1234567", "abcdef", ""] {
        let err = adapter
            .login(
                BASE,
                Credentials::new("me@example.com", "pw").with_second_factor(bad),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::AuthFailed(_)), "{bad:?} → {err:?}");
    }
    assert_eq!(
        adapter.transport().request_count(),
        0,
        "本地校验失败时不得发请求"
    );
}

#[tokio::test]
async fn login_2fa_challenge_without_temp_token_is_an_error() {
    let transport = MockTransport::new(vec![ok(json!({"requires_2fa": true}))]);
    let adapter = Sub2Api::new(transport);
    let err = adapter
        .login(BASE, Credentials::new("me@example.com", "pw"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Transport(ref m) if m.contains("temp_token")),
        "{err:?}"
    );
}

#[tokio::test]
async fn login_maps_rate_limit_and_auth_failures() {
    let transport = MockTransport::new(vec![json_resp(
        429,
        json!({"code": 429, "message": "too many requests"}),
    )]);
    let adapter = Sub2Api::new(transport);
    let err = adapter
        .login(BASE, Credentials::new("me@example.com", "pw"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::RateLimited { .. }), "{err:?}");

    let transport = MockTransport::new(vec![json_resp(
        401,
        json!({"code": 401, "message": "invalid credentials"}),
    )]);
    let adapter = Sub2Api::new(transport);
    let err = adapter
        .login(BASE, Credentials::new("me@example.com", "pw"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::AuthFailed(_)), "{err:?}");
}

/// M9-S1：400 必须把站点原文带出来。
///
/// 真实复现（`api.example.com`）：用户名 `testuser`（非邮箱）登录 →
/// HTTP 400 + `{"code":400,"message":"Invalid request: Key: 'LoginRequest.Email'
/// Error:Field validation for 'Email' failed on the 'email' tag"}`。
/// 早先 `map_http_error` 没有 400 分支，落到「未预期的状态码 400」兜底支——
/// 站点把「你的邮箱字段格式不对」说得清清楚楚，用户却只看到一句状态码，
/// 没有任何线索知道要把账号改成**邮箱形态**。
#[tokio::test]
async fn login_400_carries_the_site_message() {
    let transport = MockTransport::new(vec![json_resp(
        400,
        json!({"code": 400, "message": "Invalid request: Key: 'LoginRequest.Email' Error:Field validation for 'Email' failed on the 'email' tag"}),
    )]);
    let adapter = Sub2Api::new(transport);
    let err = adapter
        .login(BASE, Credentials::new("testuser", "pw-12345678"))
        .await
        .unwrap_err();

    let text = err.to_string();
    assert!(
        text.contains("LoginRequest.Email"),
        "站点原文必须可见，实际: {text}"
    );
    assert!(
        text.contains("Field validation"),
        "站点原文必须可见，实际: {text}"
    );
    // 归 `Transport` 而不是 `AuthFailed`：400 是请求形态问题，
    // 归认证错误会把 UI 引到「请重新登录」——用户真正要做的是改输入。
    assert!(
        matches!(err, Error::Transport(_)),
        "400 不该被当成认证失败，实际: {err:?}"
    );
}

/// M9-S1：400 但站点没给 message（非 JSON body）时用本产品自己的兜底文案，
/// 而不是把空串当原文抛给用户。
#[tokio::test]
async fn login_400_without_message_falls_back_to_our_own_wording() {
    let transport = MockTransport::new(vec![HttpResponse::new(
        400,
        b"<html>Bad Request</html>".to_vec(),
    )]);
    let adapter = Sub2Api::new(transport);
    let err = adapter
        .login(BASE, Credentials::new("me@example.com", "pw"))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, Error::Transport(m) if m.contains("400")),
        "兜底文案要能认出是 400，实际: {err}"
    );
}

// ================================================================ 密钥（红线：明文剥离）

#[tokio::test]
async fn list_keys_strips_the_plaintext_key_field() {
    // **真实形态**：`response.Paginated` → `data = {items, total, page, page_size, pages}`
    let transport = MockTransport::new(vec![ok(json!({
        "items": [
            {
                "id": 12, "user_id": 3, "key": SECRET, "name": "codex/daily",
                "group_id": 1, "status": "active",
                "created_at": "2026-07-27T05:03:01.628Z", "last_used_at": null,
                "quota": 10.0, "quota_used": 2.5
            },
            {
                "id": 13, "key": "sk-ANOTHER-LEAK-0000000000", "name": "claude/daily",
                "status": "inactive"
            }
        ],
        "total": 2, "page": 1, "page_size": 100, "pages": 1
    }))]);
    let adapter = Sub2Api::new(transport);

    let keys = adapter.list_keys(BASE, &session()).await.unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].remote_id, "12");
    assert_eq!(keys[0].name, "codex/daily");
    assert_eq!(keys[0].group.as_deref(), Some("1"));
    assert_eq!(keys[0].status, KeyStatus::Enabled);
    assert_eq!(keys[1].status, KeyStatus::Disabled);
    assert!(keys[0].created_at.is_some(), "created_at 应被解析出来");

    // 红线：整份 Debug 输出里不得出现任何明文密钥
    let debug = format!("{keys:?}");
    assert!(!debug.contains(SECRET), "KeyMeta 泄漏明文: {debug}");
    assert!(!debug.contains("sk-ANOTHER"), "KeyMeta 泄漏明文: {debug}");
    assert!(!debug.contains("sk-"), "KeyMeta 出现密钥形态: {debug}");

    // 列表请求必须带 Bearer
    let requests = adapter.transport().requests();
    assert_eq!(
        requests[0].url,
        "https://sub.example.com/api/v1/keys?page=1&page_size=100"
    );
    assert!(
        requests[0]
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("authorization") && v == "Bearer tok-abc"),
        "{:?}",
        requests[0].headers
    );
}

#[tokio::test]
async fn list_keys_accepts_empty_paginated_result() {
    let transport = MockTransport::new(vec![ok(json!({
        "items": [], "total": 0, "page": 1, "page_size": 100, "pages": 1
    }))]);
    let adapter = Sub2Api::new(transport);
    assert!(adapter
        .list_keys(BASE, &session())
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn list_keys_still_accepts_a_bare_array() {
    // 兼容老版本/异常部署：裸数组形态也认。
    // 裸数组没有 total，因此会多探一页（空页即到底）。
    let transport = MockTransport::new(vec![
        ok(json!([{"id": 1, "key": "sk-x", "name": "a", "status": "active"}])),
        ok(json!([])),
    ]);
    let adapter = Sub2Api::new(transport);
    assert_eq!(adapter.list_keys(BASE, &session()).await.unwrap().len(), 1);
}

#[tokio::test]
async fn list_keys_errors_on_unrecognized_shape_instead_of_silently_empty() {
    // 复审 P1-1 的教训：认不出的形态**必须报错**，不能静默返回空列表
    let transport = MockTransport::new(vec![ok(json!({"something": "else"}))]);
    let adapter = Sub2Api::new(transport);
    let err = adapter.list_keys(BASE, &session()).await.unwrap_err();
    assert!(
        matches!(err, Error::Transport(ref m) if m.contains("形态无法识别")),
        "{err:?}"
    );
}

#[tokio::test]
async fn list_keys_follows_pagination() {
    let page = |page: u32, ids: &[i64]| -> HttpResponse {
        let items: Vec<Value> = ids
            .iter()
            .map(
                |id| json!({"id": id, "key": "sk-x", "name": format!("k{id}"), "status": "active"}),
            )
            .collect();
        ok(json!({"items": items, "total": 3, "page": page, "page_size": 2, "pages": 2}))
    };
    let transport = MockTransport::new(vec![page(1, &[1, 2]), page(2, &[3])]);
    let adapter = Sub2Api::new(transport);

    let keys = adapter.list_keys(BASE, &session()).await.unwrap();
    assert_eq!(keys.len(), 3);
    let requests = adapter.transport().requests();
    assert_eq!(requests.len(), 2);
    assert!(
        requests[1].url.ends_with("page=2&page_size=100"),
        "{}",
        requests[1].url
    );
}

#[tokio::test]
async fn create_key_sends_an_idempotency_key() {
    // 复审 P1-2：`observe_only=false` 的部署会强制要求该头
    let transport = MockTransport::new(vec![json_resp(
        201,
        json!({"code": 0, "message": "success", "data": {"id": 21, "key": SECRET, "name": "k"}}),
    )]);
    let adapter = Sub2Api::new(transport);
    adapter
        .create_key(BASE, &session(), KeySpec::named("k"))
        .await
        .unwrap();

    let requests = adapter.transport().requests();
    let key = requests[0]
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("idempotency-key"))
        .map(|(_, v)| v.clone());
    assert!(!key.expect("必须带 Idempotency-Key").is_empty());
}

#[tokio::test]
async fn create_key_reads_plaintext_from_the_create_response() {
    let transport = MockTransport::new(vec![json_resp(
        201,
        json!({"code": 0, "message": "success", "data": {"id": 21, "key": SECRET, "name": "codex/daily"}}),
    )]);
    let adapter = Sub2Api::new(transport);

    let material = adapter
        .create_key(BASE, &session(), KeySpec::named("codex/daily"))
        .await
        .unwrap();
    assert_eq!(material.remote_id, "21");
    assert_eq!(material.secret, SECRET);

    let requests = adapter.transport().requests();
    assert_eq!(requests[0].url, "https://sub.example.com/api/v1/keys");
    assert_eq!(body_of(&requests[0])["name"], "codex/daily");
}

#[tokio::test]
async fn reveal_key_fetches_by_id() {
    let transport = MockTransport::new(vec![ok(json!({"id": 12, "key": SECRET}))]);
    let adapter = Sub2Api::new(transport);

    let material = adapter.reveal_key(BASE, &session(), "12").await.unwrap();
    assert_eq!(material.secret, SECRET);
    assert_eq!(
        adapter.transport().requests()[0].url,
        "https://sub.example.com/api/v1/keys/12"
    );
}

#[tokio::test]
async fn reveal_key_rejects_path_traversal_ids() {
    for hostile in ["../user/profile", "1/2", ".", "..", "", "1?x=2"] {
        let transport = MockTransport::new(vec![]);
        let adapter = Sub2Api::new(transport);
        let err = adapter
            .reveal_key(BASE, &session(), hostile)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Transport(ref m) if m.contains("路径段")),
            "{hostile:?} → {err:?}"
        );
        assert_eq!(
            adapter.transport().request_count(),
            0,
            "{hostile:?} 不得发出请求"
        );
    }
}

#[tokio::test]
async fn revoke_key_hits_delete_endpoint() {
    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"code": 0, "message": "success", "data": null}),
    )]);
    let adapter = Sub2Api::new(transport);

    adapter.revoke_key(BASE, &session(), "12").await.unwrap();
    let requests = adapter.transport().requests();
    assert_eq!(requests[0].url, "https://sub.example.com/api/v1/keys/12");
    assert_eq!(
        requests[0].method,
        keyrelay_core::site::transport::Method::Delete
    );
}

// ================================================================ 余额

#[tokio::test]
async fn balance_reads_profile_and_derives_used() {
    let transport = MockTransport::new(vec![ok(json!({
        "id": 7, "email": "me@example.com", "balance": 12.5, "total_recharged": 20.0,
    }))]);
    let adapter = Sub2Api::new(transport);

    let balance = adapter.balance(BASE, &session()).await.unwrap();
    assert_eq!(balance.currency, "USD");
    assert!((balance.remaining - 12.5).abs() < f64::EPSILON);
    assert!((balance.used - 7.5).abs() < f64::EPSILON, "推导的已用额度");
    assert_eq!(
        adapter.transport().requests()[0].url,
        "https://sub.example.com/api/v1/user/profile"
    );
}

#[tokio::test]
async fn balance_never_reports_negative_used() {
    // 赠送额度会让「累计充值 - 余额」为负 → 必须夹到 0
    let transport = MockTransport::new(vec![ok(json!({
        "balance": 30.0, "total_recharged": 20.0,
    }))]);
    let adapter = Sub2Api::new(transport);
    let balance = adapter.balance(BASE, &session()).await.unwrap();
    assert!(balance.used >= 0.0, "已用额度不得为负: {}", balance.used);
}

#[tokio::test]
async fn balance_missing_field_is_an_error() {
    let transport = MockTransport::new(vec![ok(json!({"id": 7}))]);
    let adapter = Sub2Api::new(transport);
    let err = adapter.balance(BASE, &session()).await.unwrap_err();
    assert!(
        matches!(err, Error::Transport(ref m) if m.contains("balance")),
        "{err:?}"
    );
}
