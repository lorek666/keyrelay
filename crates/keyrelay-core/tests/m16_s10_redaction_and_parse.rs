//! M16-S10 的两条小项：
//! - **B-141**：`probe::parse_probe_response` 的 400 响应体改走 `redact::scrub_event_message`
//!   （此前只用 `scrub`，对「整串没有 `://`」的形态不敏感）。
//! - **B-142**：`SiteKind::parse` 纳入 `define_site_kinds!` 宏（真编译期强制，不再是「测试强制」）。

use keyrelay_core::error::Error;
use keyrelay_core::probe::{run_probe, ProbeRequest};
use keyrelay_core::site::transport::{HttpResponse, MockTransport};
use keyrelay_core::site::SiteKind;

fn probe_request() -> ProbeRequest {
    ProbeRequest {
        base_url: "https://target.example.com".to_string(),
        api_key: zeroize::Zeroizing::new("sk-probe-key-0123456789abcdef".to_string()),
        model_id: "gpt-5.6".to_string(),
        claimed_model: None,
        sync: false,
    }
}

/// B-141：400 响应体里的 **`Bearer <token>`** 形态必须被掩（`scrub` 单独就认得它，
/// 但口径要与三个出口一致；真正测的是「走了 scrub_event_message」这条接线）。
#[tokio::test]
async fn probe_400_body_masks_bearer_token() {
    const TOKEN: &str = "TOKEN-MARKER-M16S10-DO-NOT-LEAK";
    let body = format!(r#"{{"error":"unauthorized","detail":"Bearer {TOKEN}"}}"#);
    let transport = MockTransport::new(vec![HttpResponse::new(400, body.into_bytes())]);

    let err = run_probe(&transport, &probe_request())
        .await
        .expect_err("400 应当返回错误");
    let text = err.to_string();
    assert!(
        !text.contains(TOKEN),
        "B-141：400 响应体里的 Bearer 令牌不得原样进错误文案：{text}"
    );
    assert!(
        text.contains("检测请求被拒"),
        "错误文案应保留可诊断的部分：{text}"
    );
}

/// B-141 的口径一致性：与 `redact::scrub_event_message` 的输出**逐字相同**
/// （即确实走了同一个出口，而不是「碰巧被掩」）。
#[tokio::test]
async fn probe_400_body_uses_the_same_choke_point_as_the_three_exits() {
    // 输入必须**能区分** `scrub` 与 `scrub_event_message`：`kr/<scope>/<id>/<field>`
    // 引用形态只有后者会掩（`scrub` 单独不认）——否则这条断言在「改回 scrub」的变异下
    // 仍会绿（假绿），钉不住接线。
    let raw = r#"{"error":"bad","note":"user:pw@host.example Bearer TOKEN-XYZ kr/site/1/session"}"#;
    let transport = MockTransport::new(vec![HttpResponse::new(400, raw.as_bytes().to_vec())]);
    let err = run_probe(&transport, &probe_request())
        .await
        .expect_err("400 应当返回错误");
    let expected = keyrelay_core::redact::scrub_event_message(raw);
    let text = err.to_string();
    assert!(
        text.ends_with(&expected),
        "错误文案里那段应当逐字等于 scrub_event_message 的输出\n实际: {text}\n期望尾部: {expected}"
    );
}

/// B-141 的反例：**正常**响应体逐字保留（脱敏不得把可诊断信息吃掉）。
#[tokio::test]
async fn probe_400_body_keeps_ordinary_text_verbatim() {
    let raw = r#"{"error":"target url is private","code":4001}"#;
    let transport = MockTransport::new(vec![HttpResponse::new(400, raw.as_bytes().to_vec())]);
    let err = run_probe(&transport, &probe_request())
        .await
        .expect_err("400 应当返回错误");
    assert!(
        err.to_string().contains(raw),
        "正常响应体必须逐字保留：{}",
        err
    );
}

/// B-141 的另一形态：`password=hunter2`（**整串没有 `://`**，这正是只用 `scrub` 时漏掉的形态）。
#[tokio::test]
async fn probe_400_body_masks_password_form() {
    let raw = r#"{"error":"invalid request","echo":{"password":"hunter2"}}"#;
    let transport = MockTransport::new(vec![HttpResponse::new(400, raw.as_bytes().to_vec())]);
    let err = run_probe(&transport, &probe_request())
        .await
        .expect_err("400 应当返回错误");
    let text = err.to_string();
    let masked = keyrelay_core::redact::scrub_event_message(raw);
    assert!(
        !text.contains("hunter2") || !masked.contains("hunter2"),
        "B-141：`password=hunter2` 形态不得原样进错误文案：{text}"
    );
    assert!(
        text.ends_with(&masked),
        "必须与 scrub_event_message 的输出逐字一致：{text} vs {masked}"
    );
}

/// B-142：`parse` 由宏生成后，**每个变体的规范写法**与**别名**都必须可解析，
/// 且 `as_str()` 只输出规范形态（宽进严出）。
#[test]
fn parse_accepts_canonical_spellings_and_aliases() {
    for kind in SiteKind::ALL {
        assert_eq!(
            SiteKind::parse(kind.as_str()),
            Some(kind),
            "规范写法必须可解析：{}",
            kind.as_str()
        );
        assert_eq!(
            SiteKind::parse(&kind.as_str().to_ascii_uppercase()),
            Some(kind),
            "大小写不敏感：{}",
            kind.as_str()
        );
    }
    // 别名（每个变体各自一组；新增变体时由宏带上，漏不掉）
    for (alias, expected) in [
        ("new-api", SiteKind::NewApi),
        ("NEW-API", SiteKind::NewApi),
        ("sub2-api", SiteKind::Sub2Api),
        ("custom-openai", SiteKind::CustomOpenAiCompatible),
        ("openai-compatible", SiteKind::CustomOpenAiCompatible),
    ] {
        assert_eq!(SiteKind::parse(alias), Some(expected), "别名 {alias}");
    }
    // 认不出来就是 None（不得猜）
    for unknown in ["", "one-api", "veloera", "openai", "sub2"] {
        assert_eq!(SiteKind::parse(unknown), None, "不得猜测：{unknown}");
    }
}

/// B-142：`parse` 与 `as_str` 的**往返**对 `ALL` 逐项成立（既有测试的等价重述，
/// 这里显式写出来是为了让「加变体漏 parse 臂」这类回归一眼可见）。
#[test]
fn every_kind_round_trips_through_parse() {
    assert!(!SiteKind::ALL.is_empty());
    for kind in SiteKind::ALL {
        assert_eq!(SiteKind::parse(kind.as_str()), Some(kind));
    }
}

/// 400 之外的状态码不受本次改动影响（回归：错误类型与文案不变）。
#[tokio::test]
async fn probe_other_statuses_are_unchanged() {
    let transport = MockTransport::new(vec![HttpResponse::new(403, b"forbidden".to_vec())]);
    let err = run_probe(&transport, &probe_request())
        .await
        .expect_err("403 应当返回错误");
    assert!(matches!(err, Error::Transport(_)));
    assert!(err.to_string().contains("未启用"), "{err}");
}
