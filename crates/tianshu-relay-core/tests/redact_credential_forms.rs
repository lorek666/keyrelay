//! M16-S2 / P3-19 的「形态覆盖」半：**裸 JWT** 与**文本形态的明文口令**（`password=…`）。
//!
//! 复跑：
//! ```text
//! CARGO_TARGET_DIR=/tmp/kr-t-redact CARGO_BUILD_JOBS=4 \
//!   cargo test -p tianshu-relay-core --test redact_credential_forms
//! ```
//!
//! 背景（DEBUG-REPORT-v3 §3-19）：站点 400 正文会原样进错误文案，而 `scrub` 只认
//! `sk-` / `nap-` / `Bearer ` / ≥32 位 hex —— JWT 不是这些形态（base64url 含 `-` `_`，
//! 还被 `.` 打断），表单式的 `password=…` 也不是。道③ 做了截断与控制字符剥离，
//! 形态覆盖这一半在本文件对应的实现里。
//!
//! **已知边界（如实钉住）**：没有键名、没有 URL 上下文的**裸口令**不可判定 ——
//! `hunter2` 单独出现时不会被掩（任何「看起来像口令」的启发式都会把正常文本吃成 `***`）。

use tianshu_relay_core::redact::{scrub, scrub_event_message, scrub_event_payload};

const JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

// ============================================================ P1（S2 复审）

/// **P1（S2 复审）**：非法 JSON 载荷 —— 首遍漏掩 + 不幂等。
///
/// 复审者的最小复现（两条形态）：
/// ① `{"password":"hunter2","x":"a"b"}`：整串非法 ⇒ 走文本层兜底，而文本层的键名规则
///    以前要求键名**紧贴**分隔符，`"password":"…"` 中间隔了一个 `"` ⇒ 不命中 ⇒ 两遍都不掩；
/// ② `{"password":"hunter2","url":"见 https://carol:p"w@h/y"}`：首遍只掩 URL、**不掩口令**，
///    而掩掉 URL 里的引号之后整串**变成合法 JSON** ⇒ 第二遍才走结构化路径掩上 ⇒ 两遍不一致。
///
/// 修法（Lead 选定 ①）：文本层键名规则允许键名与分隔符之间出现**一个 `"`** ——
/// `"password":"x"` 是**可判定**形态（键名精确命中集合 + 紧跟分隔符），不属于
/// 「裸口令不可判定」那一类；同时在 `scrub_event_payload` 的兜底之后再收敛一次
/// （兜底结果若已合法，就走第二遍会走的那条路径），保证两遍逐字节相同。
#[test]
fn p1_illegal_json_payload_masks_on_the_first_pass_and_is_idempotent() {
    let cases = [
        // ① 复审者的最小复现：整串非法，两遍都不掩（修复前）
        r#"{"password":"hunter2","x":"a"b"}"#,
        // ② 复审者的第二形态：首遍漏掩 + 不幂等（修复前）
        "{\"password\":\"hunter2\",\"url\":\"见 https://carol:p\"w@h/y\"}",
        // ③ 带空格的非法 JSON：钉住「兜底后再收敛」这条（否则第一遍保留原格式、第二遍重排）
        "{ \"password\" : \"hunter2\", \"x\" : \"a\"b\" }",
        // ④ 其它敏感键名
        r#"{"refresh_token":"abc123def456","x":"a"b"}"#,
        // ⑤ **只有它真正走「兜底 → 收敛」分支**：带空格 + 掩完变成合法 JSON。
        //    去掉收敛（变异 I）时，第一遍会返回带空格的文本、第二遍重排成紧凑形态 ⇒ 不幂等。
        "{ \"password\" : \"hunter2\", \"url\" : \"见 https://carol:p\"w@h/y\" }",
    ];
    for raw in cases {
        let once = scrub_event_payload(Some(raw)).expect("payload 应保留");
        assert!(
            !once.contains("hunter2") && !once.contains("abc123def456"),
            "首遍就漏掩了（P1 回归）:\n  in  ={raw}\n  out ={once}"
        );
        let twice = scrub_event_payload(Some(&once)).expect("payload 应保留");
        assert_eq!(once, twice, "两遍不一致（P1 回归）:\n  {once}\n  {twice}");
    }
}

/// P1 的**反例**：值里是普通文本、`@` 在路径里 ⇒ 整串原样（不许因为修 P1 而过度掩）。
#[test]
fn p1_reverse_case_ordinary_value_is_untouched() {
    for clean in [
        r#"{"note":"见 https://host/a@b"}"#,
        r#"{"key_id":7,"remaining":1.5}"#,
    ] {
        assert_eq!(
            scrub_event_payload(Some(clean)).as_deref(),
            Some(clean),
            "「{clean}」不该被改动"
        );
    }
}

/// P1 的**变体**：非法 JSON 但敏感键出现在**文本中间**（不是串首）也要命中。
#[test]
fn p1_illegal_json_mid_string_sensitive_key_is_masked() {
    let raw = r#"prefix {"password":"hunter2"} suffix "broken"#;
    let once = scrub_event_payload(Some(raw)).expect("payload 应保留");
    assert!(!once.contains("hunter2"), "{once}");
    assert!(once.contains(r#""password":"***""#), "{once}");
    assert_eq!(
        scrub_event_payload(Some(&once)).as_deref(),
        Some(once.as_str())
    );
}

// ============================================================ P2（S2 复审）

/// **P2（S2 复审）**：`email=a@b` 以前被掩成 `***@b` —— 键名被一起吃掉了，排障看不出原字段。
///
/// 处置（Lead 允许二选一，本处选「**保留键名**」）：掩码从同一个无空白 token 里
/// `@` 之前最后一个 `键名=` 的**值**开始 ⇒ `email=***@b`。理由：
/// 值照掩（不放松安全面）、键名可读（排障需要），且改动只在 scheme-less 的 authority 层，
/// 不碰 `://` 路径与既有反例。
#[test]
fn p2_key_name_before_the_at_sign_is_preserved() {
    assert_eq!(scrub_event_message("email=a@b"), "email=***@b");
    assert_eq!(
        scrub_event_message("见 email=a@b 失败"),
        "见 email=***@b 失败"
    );
    // 没有键名的形态保持原行为（从 span 起点掩）
    assert_eq!(scrub_event_message("carol:p/ss@host"), "***@host");
    // 反例：`@` 在路径里 ⇒ 原样
    assert_eq!(scrub_event_message("https://host/a@b"), "https://host/a@b");
    // 幂等
    let once = scrub_event_message("见 email=a@b 失败");
    assert_eq!(scrub_event_message(&once), once);
}

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
