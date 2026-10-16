//! M16-S2 / P3-19 的「形态覆盖」半：**裸 JWT** 与**文本形态的明文口令**（`password=…`）。
//!
//! 复跑：
//! ```text
//! CARGO_TARGET_DIR=/Volumes/Date/kr-t-redact CARGO_BUILD_JOBS=4 \
//!   cargo test -p keyrelay-core --test redact_credential_forms
//! ```
//!
//! 背景（DEBUG-REPORT-v3 §3-19）：站点 400 正文会原样进错误文案，而 `scrub` 只认
//! `sk-` / `nap-` / `Bearer ` / ≥32 位 hex —— JWT 不是这些形态（base64url 含 `-` `_`，
//! 还被 `.` 打断），表单式的 `password=…` 也不是。道③ 做了截断与控制字符剥离，
//! 形态覆盖这一半在本文件对应的实现里。
//!
//! **已知边界（如实钉住）**：没有键名、没有 URL 上下文的**裸口令**不可判定 ——
//! `hunter2` 单独出现时不会被掩（任何「看起来像口令」的启发式都会把正常文本吃成 `***`）。

use keyrelay_core::redact::{scrub, scrub_event_message};

const JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// 裸 JWT（没有 `Bearer ` 前缀）必须被掩。
#[test]
fn p3_19_bare_jwt_is_masked() {
    let out = scrub(JWT);
    assert!(!out.contains("eyJhbGciOi"), "JWT 头部泄漏: {out}");
    assert!(!out.contains("dBjftJeZ"), "JWT 签名段泄漏: {out}");
    assert!(out.contains("***"), "{out}");

    // 站点 400 正文那种「一段话里嵌着 JWT」的形态
    let body = format!(r#"{{"error":"invalid token {JWT} for model gpt-4"}}"#);
    let out = scrub(&body);
    assert!(!out.contains("eyJhbGciOi"), "{out}");
    assert!(out.contains("gpt-4"), "非凭证文本要留着: {out}");

    // 事件出口（三出口共用）同样掩
    assert!(!scrub_event_message(JWT).contains("eyJhbGciOi"));
}

/// 短 JWT（段更短）也要掩：判据是第一段 ≥8、后两段 ≥4。
#[test]
fn p3_19_short_jwt_is_masked() {
    let out = scrub("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123");
    assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"), "{out}");
}

/// 文本形态的敏感键：`password=…` / `token: …` / `pwd=…`。
#[test]
fn p3_19_key_value_text_forms_are_masked() {
    for (input, secret) in [
        ("password=hunter2", "hunter2"),
        ("password: hunter2", "hunter2"),
        ("passwd=hunter2&user=x", "hunter2"),
        ("pwd=hunter2,", "hunter2"),
        ("token=abc123def456", "abc123def456"),
        ("access_token=abc123def456", "abc123def456"),
        ("api_key=abc123def456", "abc123def456"),
        ("client_secret=abc123def456", "abc123def456"),
        ("session=abc123def456", "abc123def456"),
        ("cookie=abc123def456", "abc123def456"),
        ("private_key=abc123def456", "abc123def456"),
        ("credential=abc123def456", "abc123def456"),
    ] {
        let out = scrub(input);
        assert!(!out.contains(secret), "「{input}」的值没被掩: {out}");
        assert!(out.contains("***"), "「{input}」应出现掩码: {out}");
    }
}

/// 反例：不该被掩的键与文本要原样 —— 过度脱敏会毁掉可读性。
#[test]
fn p3_19_reverse_cases_are_untouched() {
    for clean in [
        "Model gpt-4: 不支持",
        "key_id=7",
        "remaining=1.5",
        "bytes=12",
        "path=/tmp/x.json",
        "idempotency_key=abc123",
        "站点 task-scheduler 正常",
        // `Authorization: Bearer <token>` 的值是**方案名**，不能被当成凭证掩掉
        "Authorization: Bearer eyJhbGciOi.payload.sig",
    ] {
        let out = scrub(clean);
        if clean.starts_with("Authorization") {
            assert_eq!(out, "Authorization: Bearer ***", "Bearer 形态应保持原口径");
        } else {
            assert_eq!(out, clean, "「{clean}」不该被改动");
        }
    }
}

/// 已知边界：没有键名/URL 上下文的裸口令不可判定（钉住，不假装覆盖）。
#[test]
fn p3_19_bare_password_without_context_is_a_known_boundary() {
    for bare in ["hunter2", "correct horse battery staple"] {
        assert_eq!(
            scrub(bare),
            bare,
            "「{bare}」没有上下文，无法判定成口令（已知边界，见文件头）"
        );
    }
}

/// 幂等：新规则叠加后连跑两遍不变。
#[test]
fn p3_19_rules_are_idempotent() {
    for input in [
        JWT,
        "password=hunter2&token=abc123def456",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123 与 password=x",
    ] {
        let once = scrub(input);
        assert_eq!(scrub(&once), once, "幂等破了: {input} → {once}");
    }
}
