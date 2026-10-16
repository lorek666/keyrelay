//! M16-S2 / P2-24 + P2-25：句内 URL 的两种漏掩形态与口令形态。
//!
//! 复跑：
//! ```text
//! CARGO_TARGET_DIR=/Volumes/Date/kr-t-redact CARGO_BUILD_JOBS=4 \
//!   cargo test -p keyrelay-core --test redact_url_forms
//! ```
//!
//! **规模说明（诚实边界）**：DEBUG-REPORT-v3 P2-24 的原始证据是「模糊 5 万条漏 7380 条」。
//! 这里缩到 **72 条**（8 前置 × 9 粘连）—— 这两类形态的失败不是概率性的：形态① 只要
//! 「前置 URL 不带路径且紧贴下一个 URL」就必漏，形态② 只要「scheme 前紧贴数字 / `.` /
//! `-` / `+`」就必漏。缩小后覆盖的是**同一批等价类**，不是抽样。
//!
//! 口令形态（引号 / 空格 / `#`）另成一组：那里有**语法上不可判定**的边界（裸 `#` `/`），
//! 因此断言的是「两层/三出口一致」而不是「一定掩掉」——见 `p2_25_*`。

use keyrelay_core::redact::{
    mask_authority_userinfo, mask_url_userinfo_in_json, scrub, scrub_event_message,
};

const HOST: &str = "relay.example.com";
const USER: &str = "carol";
/// 普通口令：与口令形态解耦 —— 这一组若漏，只能是 URL 形态的问题。
const PW: &str = "s3cretpw";
/// 掩码标记。
const MASK_MARK: &str = "***";

/// 泄漏判据：输出里还出现 `carol:s3cretpw` 或口令本体。
fn leaks(out: &str) -> bool {
    out.contains(&format!("{USER}:{PW}")) || out.contains(PW)
}

/// 结构化层（事件 payload 的「值内任意位置 URL」那一层）的结果。
fn json_layer(input: &str) -> String {
    let mut value = serde_json::Value::String(input.to_string());
    mask_url_userinfo_in_json(&mut value);
    scrub(value.as_str().expect("字符串值"))
}

/// **只有**结构化层的结果（后面不跟文本层 `scrub`）。
///
/// 为什么需要它：`json_layer` 末尾的 `scrub` 是文本层，会把不少形态顺带掩掉 ——
/// 只断言 `json_layer` 会让「结构化层单独退化」逃逸（变异探针 B 实测逃逸过一次）。
/// 结构化层在**带引号口令**这类形态上是唯一的防线，所以必须单独钉。
fn structured_only(input: &str) -> String {
    let mut value = serde_json::Value::String(input.to_string());
    mask_url_userinfo_in_json(&mut value);
    value.as_str().expect("字符串值").to_string()
}

/// 形态①：前面有一个**不带路径**的 URL（是否带分隔符各来一条）。
const LEAD_URLS: [&str; 8] = [
    "",
    "见 ",
    "https://a.example.com ",
    "https://a.example.com",
    "https://a.example.com,",
    "http://a.example.com ",
    "见 https://a.example.com 和 ",
    "https://a.example.com 见 ",
];

/// 形态②：scheme 前紧贴数字、`.`、`-`、`+`。
const GLUE_PREFIXES: [&str; 9] = ["", "1", "42", ".", "-", "+", "v1.2-", "a1", "x+"];

const TAILS: [&str; 5] = ["", "/x", "/v1/chat", "?q=1", "#f"];

fn case(lead: &str, glue: &str, pw: &str, tail: &str) -> String {
    format!("{lead}{glue}https://{USER}:{pw}@{HOST}{tail}")
}

// ============================================================ 形态①

/// 形态①：authority 扫描必须在**内嵌的下一个 `://`** 处收口。
///
/// 漏的根因：第一个 URL 没有路径时，authority 会一路吃到第二个 URL 的 `//`，把它的
/// `://` 一起吞掉 —— 之后串里再没有 `://`，第二个 URL 永远不被识别。
#[test]
fn p2_24_form1_pathless_url_before_the_target() {
    let mut checked = 0usize;
    for lead in LEAD_URLS {
        for glue in GLUE_PREFIXES {
            for tail in TAILS {
                let input = case(lead, glue, PW, tail);
                let text = scrub(&input);
                let json = json_layer(&input);
                assert!(
                    !leaks(&text),
                    "文本层漏掩（lead={lead:?} glue={glue:?} tail={tail:?}）:\n  in  ={input}\n  out ={text}"
                );
                assert!(
                    !leaks(&json),
                    "结构化层漏掩（lead={lead:?} glue={glue:?} tail={tail:?}）:\n  in  ={input}\n  out ={json}"
                );
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 8 * 9 * 5, "矩阵规模：8 前置 × 9 粘连 × 5 尾部");
}

/// 形态① 的最小例：逐字断言输出，钉住「第二个 URL 的 userinfo 被掩、第一个 URL 原样」。
#[test]
fn p2_24_form1_minimal_case_is_byte_pinned() {
    let input = format!("https://a.example.comhttps://{USER}:{PW}@{HOST}/x");
    assert_eq!(
        scrub(&input),
        format!("https://a.example.comhttps://***@{HOST}/x"),
        "第一个 URL 无 userinfo ⇒ 原样；第二个 URL 的 userinfo 必须掩"
    );
    assert_eq!(
        json_layer(&input),
        format!("https://a.example.comhttps://***@{HOST}/x"),
        "两层必须同口径"
    );

    // 带逗号分隔（报告里那类「句内 URL」的常见形态）
    let comma = format!("https://a.example.com,https://{USER}:{PW}@{HOST}/x");
    assert!(!leaks(&scrub(&comma)), "{comma}");
    assert!(!leaks(&json_layer(&comma)), "{comma}");
}

// ============================================================ 形态②

/// 形态②：scheme 前紧贴数字 / `.` / `-` / `+`。
///
/// 以前结构化层要求 scheme 以**字母**开头，`1https` / `v1.2-https` 这类形态会被短路掉，
/// 于是结构化层漏掩、文本层掩了 —— 两层不一致。现在不校验 scheme，两层同口径。
#[test]
fn p2_24_form2_scheme_glued_to_digit_dot_dash_plus() {
    for glue in ["1", "42", ".", "-", "+", "v1.2-", "a1", "x+"] {
        let input = case("", glue, PW, "/x");
        let text = scrub(&input);
        let json = json_layer(&input);
        assert!(!leaks(&text), "文本层漏掩（glue={glue:?}）: {text}");
        assert!(!leaks(&json), "结构化层漏掩（glue={glue:?}）: {json}");
        assert!(
            json.contains("***@"),
            "结构化层必须真的掩掉 userinfo（glue={glue:?}）: {json}"
        );
    }
}

/// 形态② **且**带引号口令：这一格只有结构化层能挡（文本层的 authority 止于 `"`）。
///
/// 这是形态② 的**真判据**：只断言普通口令会被文本层顺带掩掉，结构化层退化了也看不出来
/// （变异探针 B 第一次就是这么逃逸的）。
#[test]
fn p2_24_form2_with_a_quoted_password_needs_the_structured_layer() {
    for glue in ["1", ".", "-", "+", "v1.2-"] {
        let input = format!("{glue}https://{USER}:p\"ass@{HOST}/x");
        let only = structured_only(&input);
        assert!(
            !only.contains("p\"ass") && !only.contains(&format!("{USER}:p")),
            "结构化层漏掩（glue={glue:?}）: {only}"
        );
        assert!(
            only.contains("***@"),
            "结构化层必须掩（glue={glue:?}）: {only}"
        );
    }
}

/// 形态① **且**带引号口令：同上，只有结构化层能挡。
#[test]
fn p2_24_form1_with_a_quoted_password_needs_the_structured_layer() {
    let input = format!("https://a.example.comhttps://{USER}:p\"ass@{HOST}/x");
    let only = structured_only(&input);
    assert!(
        !only.contains("p\"ass") && !only.contains(&format!("{USER}:p")),
        "结构化层漏掩: {only}"
    );
    assert!(
        only.contains(&format!("https://***@{HOST}")),
        "第二个 URL 的 userinfo 必须掩: {only}"
    );
}

// ============================================================ 反例（过度脱敏）

/// 反例：不该被掩的必须原样 —— 过度脱敏会毁掉可读性，也是缺陷。
#[test]
fn p2_24_reverse_cases_are_untouched() {
    for clean in [
        "https://relay.example.com/v1/chat?x=1#frag",
        "正常一句话，没有 URL",
        "Model gpt-4: 不支持",
        "站点 task-scheduler 与 desk-assistant 都正常",
        // `@` 在 query 里，不是 userinfo
        "https://relay.example.com/v1?email=a@b.com",
        // 键名不是密钥形态
        r#"{"key_id":7,"remaining":1.5,"bytes":12,"path":"/tmp/x.json"}"#,
    ] {
        assert_eq!(scrub(clean), clean, "「{clean}」不该被改动");
        assert_eq!(
            json_layer(clean),
            clean,
            "「{clean}」不该被改动（结构化层）"
        );
    }
}

/// 反例：`@` 在路径/query 里时不许掩（与 `strip_url_userinfo` 同口径）。
#[test]
fn p2_24_at_sign_outside_the_authority_is_not_userinfo() {
    for clean in [
        "https://relay.example.com/path/a@b",
        "https://relay.example.com/v1?email=a@b.com",
        "https://relay.example.com#a@b",
    ] {
        assert_eq!(scrub(clean), clean, "「{clean}」不该被改动");
    }
}

// ============================================================ P2-25 口令形态

/// P2-25：**带引号**的口令在自由文本里必须被掩（事件文案的原始症状）。
///
/// 文本层的 authority 止于 `"`（JSON 文本安全），所以这一条靠
/// `mask_authority_userinfo`（authority 只止于 `/ ? #`）兜住 —— 三个出口都调它。
#[test]
fn p2_25_quoted_password_in_free_text_is_masked() {
    for pw in ["p\"ass", "'p@ss'", "p\\ass"] {
        let input = format!("登录失败：见 https://{USER}:{pw}@{HOST}/x");
        let out = scrub_event_message(&input);
        assert!(
            !out.contains(&format!("{USER}:{pw}")),
            "带引号/反斜杠口令必须被掩（pw={pw:?}）: {out}"
        );
        assert!(out.contains(HOST), "主机名仍要点出来（pw={pw:?}）: {out}");
    }
}

/// P2-25/P3-22 的**已知边界**（如实钉住，不假装覆盖）。
///
/// 口令里含裸 `#` 时：URL 语法上 authority 真的在 `#` 处结束，但 P3-22 的 R1 会把
/// 「候选段里没有 `@`、后面有」这种畸形形态延长掩掉 ⇒ 现在两层都掩。
///
/// 口令里含**空格**时：文本层的 authority 止于空白（它没法把 `carol:a b/c@host` 与
/// 一句普通的话区分开），因此**裸文本层**仍不掩；而三个出口走的都是结构化层
/// （`scrub_event_message` 的最后一层 / `mask_url_userinfo_in_json`），那里知道值的边界，
/// 会掩。这条差异是**有意的**，也是「三出口一致」能成立的原因。
#[test]
fn p2_25_hash_or_slash_in_a_password_is_a_known_boundary() {
    // 裸 `#`：两层都掩（P3-22 的 R1 覆盖）
    let hash_input = format!("见 https://{USER}:p#w@{HOST}/x");
    assert!(
        !scrub(&hash_input).contains("p#w"),
        "{}",
        scrub(&hash_input)
    );
    assert!(
        !structured_only(&hash_input).contains("p#w"),
        "{}",
        structured_only(&hash_input)
    );

    // 空格：文本层不掩（空白是 authority 的终止符），结构化层与出口掩
    let space_input = format!("见 https://{USER}:a b/c@{HOST}/x");
    assert!(
        scrub(&space_input).contains("a b/c"),
        "文本层对含空格的口令是已知边界: {}",
        scrub(&space_input)
    );
    assert!(
        !structured_only(&space_input).contains("a b/c"),
        "结构化层必须掩: {}",
        structured_only(&space_input)
    );
    assert!(
        !scrub_event_message(&space_input).contains("a b/c"),
        "三个出口共用的统一出口必须掩: {}",
        scrub_event_message(&space_input)
    );
}

/// 幂等：两层叠加（写入路径掩一次 + 出口再掩一次）不得二次改写。
#[test]
fn p2_25_and_p2_24_are_idempotent_across_layers() {
    let inputs = [
        format!("https://a.example.comhttps://{USER}:{PW}@{HOST}/x"),
        format!("1https://{USER}:p\"ass@{HOST}/x"),
        format!("登录失败：见 https://{USER}:p\"ass@{HOST}/x"),
        "钥匙串引用 kr/key/1/secret 不在".to_string(),
    ];
    for input in inputs {
        let once = scrub_event_message(&input);
        assert_eq!(
            scrub_event_message(&once),
            once,
            "统一出口必须幂等: {input} → {once}"
        );
        // 写入路径与出口的叠加（同一个函数，等价于再跑一遍）
        assert_eq!(scrub_event_message(&once), once);
    }
}

// ============================================================ P3-22 根因

/// P3-22 第一种形态：口令里有**未编码**的 `/` `?` `#`。
///
/// 按 URL 语法 authority 真的在 `/` 处结束，但那是畸形输入（口令本该 percent-encode），
/// 结果是 `display_url` / 错误文案把口令原样显示出来。修法：候选段里没有 `@` 时，
/// 若候选段含 `:`（且其后不是纯数字，排除端口），把 authority 延长到同一个 token 里的 `@`。
#[test]
fn p3_22_password_with_unencoded_separators_is_masked() {
    let cases = [
        format!("{USER}:p/ss@{HOST}"),
        format!("https://{USER}:p/ss@{HOST}"),
        format!("{USER}:p?ss@{HOST}"),
        format!("{USER}:p#ss@{HOST}"),
        format!("https://{USER}:p#ss@{HOST}/x"),
        format!("{USER}:p/ss@{HOST}/x/y"),
    ];
    for input in cases {
        // 三个出口共用的两层 + 文本层，都必须掩住
        for (layer, out) in [
            ("scrub", scrub(&input)),
            ("结构化", structured_only(&input)),
            ("authority", mask_authority_userinfo(&input)),
            ("事件出口", scrub_event_message(&input)),
        ] {
            assert!(
                !out.contains("p/ss") && !out.contains("p?ss") && !out.contains("p#ss"),
                "{layer} 层漏掩口令: {input} → {out}"
            );
            assert!(out.contains(MASK_MARK), "{layer} 层必须掩: {input} → {out}");
        }
    }
}

/// P3-22 第二种形态：无 scheme 地址的 query 里带 URL。
///
/// `mask_urls` 的循环只认 `://`，`://` **之前**那一段（自己就是地址）以前从不被扫描，
/// 于是 `carol:pw@host/path?next=https://…` 里的第一段 userinfo 原样留下。
#[test]
fn p3_22_scheme_less_prefix_before_a_url_is_masked() {
    let cases = [
        format!("{HOST}/path?next=https://{USER}:{PW}@hook.example.com/x"),
        format!("{USER}:{PW}@{HOST}/path?next=https://bob:secret@hook.example.com/x"),
        format!("https://{USER}:{PW}@{HOST}/path?next=https://bob:secret@hook.example.com/x"),
    ];
    for input in cases {
        for (layer, out) in [
            ("scrub", scrub(&input)),
            ("结构化", structured_only(&input)),
            ("authority", mask_authority_userinfo(&input)),
            ("事件出口", scrub_event_message(&input)),
        ] {
            assert!(
                !out.contains(&format!("{USER}:{PW}")) && !out.contains("bob:secret"),
                "{layer} 层漏掩: {input} → {out}"
            );
        }
        assert!(
            scrub(&input).contains("https://***@hook.example.com"),
            "内层 URL 的 userinfo 也必须掩: {}",
            scrub(&input)
        );
    }
}

/// P3-22 反例：`@` 在路径 / query / 端口里时**不许**掩（否则排障时认不出站点与端口）。
#[test]
fn p3_22_reverse_cases_are_untouched() {
    for clean in [
        "https://relay.example.com/v1?email=a@b.com",
        "https://relay.example.com/path/a@b",
        "https://host:8080/path/a@b",
        "relay.example.com:8080/path/a@b",
        "relay.example.com/v1?email=a@b.com",
        "https://relay.example.com",
        "站点 relay.example.com 正常",
    ] {
        assert_eq!(scrub(clean), clean, "「{clean}」不该被改动（文本层）");
        assert_eq!(
            structured_only(clean),
            clean,
            "「{clean}」不该被改动（结构化层）"
        );
        assert_eq!(
            mask_authority_userinfo(clean),
            clean,
            "「{clean}」不该被改动（authority 层）"
        );
    }
}
