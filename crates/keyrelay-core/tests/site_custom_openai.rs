//! M7-S2 契约测试：`custom-openai-compatible` 站点类型与能力集。
//!
//! 断言清单与目标测试名的对照见 `docs/specs/M7-S2-站点类型与能力集.md` §7（T1–T16）。
//! 全部走**假 transport**：真实兼容端点本机不存在（spec §10 未验证边界），
//! 因此本文件**不声称**真实站点已验证。

use std::fs;

use keyrelay_core::error::Error;
use keyrelay_core::site::capability::capabilities;
use keyrelay_core::site::custom_openai::{CustomOpenAi, UNSUPPORTED_MESSAGE};
use keyrelay_core::site::registry::SiteRegistry;
use keyrelay_core::site::transport::{HttpResponse, Method, MockTransport};
use keyrelay_core::site::{
    parse_rate, Balance, Credentials, KeySpec, Session, SiteAdapter, SiteKind,
};
use serde_json::{json, Value};

const BASE: &str = "https://relay.example.com";

fn ok(value: Value) -> HttpResponse {
    HttpResponse::json(200, value).expect("构造响应")
}

fn session() -> Session {
    Session {
        cookies: Vec::new(),
        access_token: Some("tok-probe".to_string()),
        user_id: Some("1".to_string()),
    }
}

// ============================================================ T1 / T2 站点类型

#[test]
fn custom_kind_strings_are_exact() {
    assert_eq!(
        SiteKind::CustomOpenAiCompatible.as_str(),
        "custom-openai-compatible"
    );
    // 既有两条通道的字符串**不变**（回归）
    assert_eq!(SiteKind::NewApi.as_str(), "newapi");
    assert_eq!(SiteKind::Sub2Api.as_str(), "sub2api");
}

#[test]
fn custom_kind_parse_accepts_three_spellings_case_insensitively() {
    for spelling in [
        "custom-openai-compatible",
        "custom-openai",
        "openai-compatible",
        "CUSTOM-OPENAI-COMPATIBLE",
        "Custom-OpenAI",
        "OpenAI-Compatible",
    ] {
        assert_eq!(
            SiteKind::parse(spelling),
            Some(SiteKind::CustomOpenAiCompatible),
            "{spelling:?} 应被识别"
        );
    }
    // 既有别名不变（回归）
    assert_eq!(SiteKind::parse("new-api"), Some(SiteKind::NewApi));
    assert_eq!(SiteKind::parse("SUB2-API"), Some(SiteKind::Sub2Api));
    // 不接受的写法：不猜
    for hostile in [
        "custom_openai",
        "openai_compatible",
        "custom",
        "compatible",
        "",
        " nope ",
    ] {
        assert_eq!(SiteKind::parse(hostile), None, "{hostile:?} 不应被识别");
    }
}

// ============================================================ T5 parse_rate 边界表

#[test]
fn parse_rate_boundary_table() {
    let cases: Vec<(&str, Value, Option<f64>)> = vec![
        ("整数", json!(2), Some(2.0)),
        ("浮点", json!(0.8), Some(0.8)),
        ("0 必须保留（免费分组）", json!(0), Some(0.0)),
        ("-0.0 归一成 0.0", json!(-0.0), Some(0.0)),
        ("负数 ⇒ None", json!(-1), None),
        ("负小数 ⇒ None", json!(-0.5), None),
        ("科学计数法数字", json!(1e-3), Some(0.001)),
        ("字符串数字", json!("0.8"), Some(0.8)),
        ("字符串整数", json!("2"), Some(2.0)),
        ("字符串 0", json!("0"), Some(0.0)),
        ("字符串负数 ⇒ None", json!("-1"), None),
        ("字符串带空白", json!(" 0.5 "), Some(0.5)),
        ("纯空白字符串 ⇒ None", json!(" "), None),
        ("字符串溢出 ⇒ None", json!("1e400"), None),
        ("字符串 inf ⇒ None", json!("inf"), None),
        ("字符串 -inf ⇒ None", json!("-inf"), None),
        ("字符串 NaN ⇒ None", json!("NaN"), None),
        ("字符串 infinity ⇒ None", json!("infinity"), None),
        ("非数字串 ⇒ None", json!("abc"), None),
        ("空串 ⇒ None", json!(""), None),
        ("十六进制串 ⇒ None", json!("0x10"), None),
        ("本地化小数逗号 ⇒ None", json!("1,5"), None),
        ("布尔 ⇒ None", json!(true), None),
        ("null ⇒ None", json!(null), None),
        ("数组 ⇒ None", json!([1.0]), None),
        ("对象 ⇒ None", json!({"rate": 1.0}), None),
    ];

    for (label, input, expected) in cases {
        assert_eq!(parse_rate(&input), expected, "{label}：{input}");
    }
}

#[test]
fn parse_rate_keeps_zero_and_rejects_unknown_shapes() {
    // 单独再钉一遍 B-91 的两个要点：0 保留、不可用一律 None（绝不回落 1.0）
    assert_eq!(parse_rate(&json!(0)), Some(0.0));
    assert_eq!(parse_rate(&json!("0")), Some(0.0));
    assert_ne!(parse_rate(&json!("nope")), Some(1.0));
}

// ============================================================ T6 / T7 / T8 detect

#[tokio::test]
async fn custom_detect_accepts_openai_models_shape() {
    // 空数组也是合法兼容端点
    let transport = MockTransport::new(vec![ok(json!({"object": "list", "data": []}))]);
    let adapter = CustomOpenAi::new(transport);
    let fp = adapter.detect(BASE).await.expect("空 data 数组应命中");
    assert_eq!(fp.kind, SiteKind::CustomOpenAiCompatible);
    assert_eq!(fp.display_name, "relay.example.com");
    assert!(fp.version.is_none());

    // 非空：display_name 取 owned_by
    let transport = MockTransport::new(vec![ok(json!({
        "object": "list",
        "data": [{"id": "gpt-4o", "owned_by": "自建中转"}],
    }))]);
    let adapter = CustomOpenAi::new(transport);
    assert_eq!(adapter.detect(BASE).await.unwrap().display_name, "自建中转");

    // owned_by 缺失 → 回落 host
    let transport = MockTransport::new(vec![ok(json!({"data": [{"id": "gpt-4o"}]}))]);
    let adapter = CustomOpenAi::new(transport);
    assert_eq!(
        adapter.detect(BASE).await.unwrap().display_name,
        "relay.example.com"
    );
}

#[tokio::test]
async fn custom_detect_rejects_unrecognized_shapes() {
    let cases: Vec<(&str, HttpResponse, &str)> = vec![
        (
            "非 2xx",
            HttpResponse::new(404, b"nope".to_vec()),
            "返回 404",
        ),
        (
            "不是 JSON",
            HttpResponse::new(200, b"<html>SPA</html>".to_vec()),
            "不是 JSON",
        ),
        (
            "JSON 不是对象（数组）",
            ok(json!([{"id": "x"}])),
            "不是对象",
        ),
        ("JSON 不是对象（字符串）", ok(json!("nope")), "不是对象"),
        ("缺少 data", ok(json!({"object": "list"})), "缺少 data"),
        (
            "data 是对象",
            ok(json!({"data": {"items": []}})),
            "不是数组",
        ),
        ("data 是字符串", ok(json!({"data": "nope"})), "不是数组"),
    ];

    for (label, response, needle) in cases {
        let transport = MockTransport::new(vec![response]);
        let adapter = CustomOpenAi::new(transport);
        let err = adapter.detect(BASE).await.expect_err(label);
        assert!(
            matches!(err, Error::FingerprintMismatch(_)),
            "{label} → {err:?}"
        );
        assert!(
            err.to_string().contains(needle),
            "{label} 的文案应含 {needle:?}：{err}"
        );
    }
}

#[tokio::test]
async fn custom_detect_never_sends_credentials() {
    let transport = MockTransport::new(vec![ok(json!({"data": []}))]);
    let adapter = CustomOpenAi::new(transport.clone());
    adapter.detect(BASE).await.expect("命中");

    let requests = transport.requests();
    assert_eq!(requests.len(), 1, "只允许一次探测请求");
    assert_eq!(requests[0].url, "https://relay.example.com/v1/models");
    assert_eq!(requests[0].method, Method::Get);
    for (name, _) in &requests[0].headers {
        let lower = name.to_ascii_lowercase();
        assert!(
            !matches!(
                lower.as_str(),
                "authorization" | "cookie" | "x-api-key" | "x-goog-api-key" | "proxy-authorization"
            ),
            "探测不得携带凭证头: {name}"
        );
    }
    assert!(
        requests[0].headers.is_empty(),
        "探测请求头集合应为空: {:?}",
        requests[0].headers
    );
}

// ============================================================ T9 / T10 / T11 / T12

#[tokio::test]
async fn custom_login_returns_empty_session_without_request() {
    let transport = MockTransport::new(vec![]);
    let adapter = CustomOpenAi::new(transport.clone());
    let session = adapter
        .login(BASE, Credentials::new("probe@example.com", "pw-probe"))
        .await
        .expect("login 不应失败");
    assert_eq!(session, Session::default());
    assert!(session.cookies.is_empty());
    assert!(session.access_token.is_none());
    assert!(session.user_id.is_none());
    assert_eq!(transport.request_count(), 0, "login 不得发请求");
}

fn assert_unsupported(err: &Error, label: &str) {
    match err {
        Error::Unsupported(message) => {
            assert_eq!(message, UNSUPPORTED_MESSAGE, "{label} 的文案必须逐字一致");
            assert_eq!(message, "custom-openai-compatible 站点没有令牌管理端点");
        }
        other => panic!("{label} 应返回 Unsupported，实际 {other:?}"),
    }
}

#[tokio::test]
async fn custom_write_methods_return_unsupported_without_request() {
    // 每个方法都用**空响应队列**：一旦真的发请求，MockTransport 会报 Transport 错误，
    // 下面的 `Unsupported` 断言就会失败——「零请求」因此是被证伪的。
    let s = session();

    let adapter = CustomOpenAi::new(MockTransport::new(vec![]));
    let err = adapter.list_keys(BASE, &s).await.unwrap_err();
    assert_unsupported(&err, "list_keys");
    assert_eq!(adapter.transport().request_count(), 0);

    let adapter = CustomOpenAi::new(MockTransport::new(vec![]));
    let err = adapter
        .create_key(BASE, &s, KeySpec::named("probe"))
        .await
        .unwrap_err();
    assert_unsupported(&err, "create_key");
    assert_eq!(adapter.transport().request_count(), 0);

    let adapter = CustomOpenAi::new(MockTransport::new(vec![]));
    let err = adapter.reveal_key(BASE, &s, "1").await.unwrap_err();
    assert_unsupported(&err, "reveal_key");
    assert_eq!(adapter.transport().request_count(), 0);

    let adapter = CustomOpenAi::new(MockTransport::new(vec![]));
    let err = adapter.revoke_key(BASE, &s, "1").await.unwrap_err();
    assert_unsupported(&err, "revoke_key");
    assert_eq!(adapter.transport().request_count(), 0);

    let adapter = CustomOpenAi::new(MockTransport::new(vec![]));
    let err = adapter.available_groups(BASE, &s).await.unwrap_err();
    assert_unsupported(&err, "available_groups");
    assert_eq!(adapter.transport().request_count(), 0);
}

#[tokio::test]
async fn custom_balance_reports_unknown_not_zero() {
    let adapter = CustomOpenAi::new(MockTransport::new(vec![]));
    let balance = adapter.balance(BASE, &session()).await.expect("不应报错");

    assert!(!balance.known, "未知态必须 known == false");
    assert_eq!(balance.raw_quota, None);
    assert_eq!(balance.quota_per_unit, None);
    // 未知态被钉成常量：防「顺手改成 0 / 1.0」
    assert_eq!(balance, Balance::unknown("USD"));
    assert_eq!(balance.currency, "USD");
    // 连续两次都一样：不会「第二次就有数了」
    let again = adapter.balance(BASE, &session()).await.unwrap();
    assert_eq!(again, Balance::unknown("USD"));
}

#[tokio::test]
async fn custom_balance_sends_no_request() {
    let adapter = CustomOpenAi::new(MockTransport::new(vec![]));
    adapter.balance(BASE, &session()).await.unwrap();
    assert_eq!(
        adapter.transport().request_count(),
        0,
        "未知余额不得靠「猜一个端点」得来"
    );
}

// ============================================================ T13 / T15 / T16

#[test]
fn custom_adapter_kind_is_custom() {
    let adapter = CustomOpenAi::new(MockTransport::new(vec![]));
    assert_eq!(adapter.kind(), SiteKind::CustomOpenAiCompatible);
}

#[tokio::test]
async fn custom_detect_does_not_touch_the_disk() {
    // 本适配器的构造函数只吃 transport（没有 home / 路径参数）→ 类型层面就够不着文件系统。
    // 运行时再钉一遍：探测前后，一个旁观目录的内容逐项相同。
    let dir = tempfile::tempdir().expect("临时目录");
    fs::write(dir.path().join("sentinel"), b"unchanged").expect("写哨兵");
    let before: Vec<_> = fs::read_dir(dir.path())
        .expect("读目录")
        .map(|entry| entry.expect("项").file_name())
        .collect();

    let transport = MockTransport::new(vec![ok(json!({"data": []}))]);
    let adapter = CustomOpenAi::new(transport);
    adapter.detect(BASE).await.expect("命中");

    let after: Vec<_> = fs::read_dir(dir.path())
        .expect("读目录")
        .map(|entry| entry.expect("项").file_name())
        .collect();
    assert_eq!(before, after, "探测不得创建/删除任何文件");
    assert_eq!(
        fs::read(dir.path().join("sentinel")).expect("读哨兵"),
        b"unchanged"
    );
}

#[tokio::test]
async fn custom_adapter_is_reachable_from_the_registry() {
    // ① 直接取适配器
    let registry = SiteRegistry::new(MockTransport::new(vec![]));
    assert_eq!(
        registry.adapter(SiteKind::CustomOpenAiCompatible).kind(),
        SiteKind::CustomOpenAiCompatible
    );
    // 既有两类不受影响（回归）
    assert_eq!(registry.adapter(SiteKind::NewApi).kind(), SiteKind::NewApi);
    assert_eq!(
        registry.adapter(SiteKind::Sub2Api).kind(),
        SiteKind::Sub2Api
    );

    // ② 端到端探测：前两类各自落空后，第三类认领（证明 probe_order 里它在**最后**且可达）
    let transport = MockTransport::new(vec![
        HttpResponse::new(404, b"".to_vec()), // NewAPI: GET /api/status
        HttpResponse::new(404, b"".to_vec()), // Sub2API: GET /api/v1/settings/public
        ok(json!({"object": "list", "data": []})), // custom: GET /v1/models
    ]);
    let registry = SiteRegistry::new(transport);
    let fingerprint = registry.detect(BASE).await.expect("应被第三类认领");
    assert_eq!(fingerprint.kind, SiteKind::CustomOpenAiCompatible);
}

// ============================================================ 能力集（集成侧复核）

#[test]
fn capabilities_match_the_frozen_table() {
    let custom = capabilities(SiteKind::CustomOpenAiCompatible);
    assert!(!custom.login && !custom.list_keys && !custom.create_key);
    assert!(!custom.reveal_key && !custom.revoke_key && !custom.balance);
    assert!(!custom.groups && !custom.key_usage);

    for kind in [SiteKind::NewApi, SiteKind::Sub2Api] {
        let caps = capabilities(kind);
        assert!(caps.login && caps.list_keys && caps.create_key);
        assert!(caps.reveal_key && caps.revoke_key && caps.balance && caps.groups);
        // M14-S3：list_keys 带用量，key_usage=true（B-96 已接）
        assert!(caps.key_usage, "{} 的 key_usage 应为 true", kind.as_str());
    }
}
