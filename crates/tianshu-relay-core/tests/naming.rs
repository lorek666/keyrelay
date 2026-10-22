//! M7-S4 集成测试：**密钥命名规范**（`crates/tianshu-relay-core/src/naming.rs`）。
//!
//! 与模块内单测的分工：模块内测「单点形状」，这里测**往返性质**与**拒绝面**
//! （spec §8.2 的 T-N1…T-N5 逐条对应）。
//!
//! 本文件不碰任何真实密钥：名字是标识，不是凭据。

use tianshu_relay_core::naming::{default_key_name, parse_key_name, DEFAULT_APP_ID};

/// 段长度上限（`naming.rs` 的私有常量；spec §4.2 规则 3 冻结为 64 字节）。
const MAX_SEGMENT_LEN: usize = 64;

/// 一条往返用例：`(app_id, agent_id, date, 期望名字)`。
type NameCase<'a> = (&'a str, &'a str, (i32, u32, u32), &'a str);

fn seg(len: usize) -> String {
    "a".repeat(len)
}

#[test]
fn generated_names_parse_back_verbatim() {
    let cases: [NameCase; 6] = [
        (
            "tianshu-relay",
            "codex",
            (2026, 10, 13),
            "tianshu-relay/codex/20261013",
        ),
        (
            "tianshu-relay",
            "claude-code",
            (2026, 1, 3),
            "tianshu-relay/claude-code/20260103",
        ),
        (
            "tianshu-relay",
            "gemini-cli",
            (999, 1, 1),
            "tianshu-relay/gemini-cli/09990101",
        ),
        (
            "tickflow.ai",
            "opencode",
            (2026, 12, 31),
            "tickflow.ai/opencode/20261231",
        ),
        (
            "my_app-2",
            "openclaw",
            (1970, 1, 1),
            "my_app-2/openclaw/19700101",
        ),
        // 边界：段恰好 64 字节
        (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "codex",
            (2026, 10, 13),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/codex/20261013",
        ),
    ];

    for (app_id, agent_id, date, expected) in cases {
        let generated = default_key_name(app_id, agent_id, date)
            .unwrap_or_else(|| panic!("({app_id}, {agent_id}, {date:?}) 应能生成"));
        assert_eq!(generated, expected, "生成形态不符");
        assert_eq!(
            parse_key_name(&generated),
            Some((
                app_id.to_string(),
                agent_id.to_string(),
                expected[expected.len() - 8..].to_string()
            )),
            "往返必须逐字一致"
        );
    }
}

#[test]
fn malformed_names_are_rejected() {
    // I1 段数不对 / I2 第三段不是 8 位数字 / I3 空段 / I4 段内非法字符 / I5 超长 / I6 非 ASCII 数字
    let cases: [(&str, &str); 16] = [
        ("tianshu-relay/20261013", "I1 只有两段"),
        ("tianshu-relay/codex/x/20261013", "I1 四段"),
        ("tianshu-relay/codex/20261013/", "I1 尾随斜杠"),
        ("tianshu-relay/codex/2026101", "I2 七位"),
        ("tianshu-relay/codex/202610131", "I2 九位"),
        ("tianshu-relay/codex/2026-10-13", "I2 带分隔符"),
        ("tianshu-relay/codex/abcdefgh", "I2 字母"),
        ("tianshu-relay//20261013", "I3 中间空段"),
        ("//20261013", "I3 前两段空"),
        ("tianshu-relay/codex/", "I3 第三段空"),
        ("", "I3 全空"),
        ("my app/codex/20261013", "I4 空格"),
        ("密钥/codex/20261013", "I4 非 ASCII"),
        ("tianshu-relay/co:dex/20261013", "I4 冒号"),
        ("tianshu-relay/codex/２０２６１０１３", "I6 全角数字"),
        ("tianshu-relay/codex/٢٠٢٦١٠١٣", "I6 非 ASCII 数字"),
    ];
    for (name, why) in cases {
        assert!(parse_key_name(name).is_none(), "{why}: 「{name}」应被拒绝");
    }

    let over = seg(MAX_SEGMENT_LEN + 1);
    assert!(
        parse_key_name(&format!("{over}/codex/20261013")).is_none(),
        "I5 65 字节段应被拒绝"
    );
}

#[test]
fn invalid_parts_are_rejected_by_the_generator() {
    let date = (2026, 10, 13);

    // 段：空 / 含 `/` / 含空格 / 非 ASCII / 冒号 / 超长
    for bad in ["", "a/b", "my app", "密钥", "co:dex", "a?b"] {
        assert!(
            default_key_name(bad, "codex", date).is_none(),
            "app_id「{bad}」应被拒绝"
        );
        assert!(
            default_key_name("tianshu-relay", bad, date).is_none(),
            "agent_id「{bad}」应被拒绝"
        );
    }
    assert!(
        default_key_name(&seg(MAX_SEGMENT_LEN + 1), "codex", date).is_none(),
        "65 字节段应被拒绝"
    );

    // 日期：渲染不出 8 位数字
    for bad in [(10_000, 1, 1), (-1, 1, 1), (2026, 100, 1), (2026, 1, 100)] {
        assert!(
            default_key_name("tianshu-relay", "codex", bad).is_none(),
            "日期 {bad:?} 应被拒绝"
        );
    }

    // 反面对照：合法入参必须能生成（否则上面那堆断言可能是「全都拒」的假绿）
    assert!(default_key_name("tianshu-relay", "codex", date).is_some());
}

#[test]
fn segment_length_boundary_is_inclusive_at_64() {
    let date = (2026, 10, 13);
    let at_limit = seg(MAX_SEGMENT_LEN);
    let over_limit = seg(MAX_SEGMENT_LEN + 1);

    let name = default_key_name(&at_limit, "codex", date).expect("恰好 64 字节应可生成");
    assert_eq!(parse_key_name(&name).map(|(a, _, _)| a.len()), Some(64));

    assert!(default_key_name(&over_limit, "codex", date).is_none());
    assert!(parse_key_name(&format!("{over_limit}/codex/20261013")).is_none());

    // 空段是 0 字节：下限侧同样拒绝
    assert!(default_key_name("", "codex", date).is_none());
    assert!(parse_key_name("/codex/20261013").is_none());
}

#[test]
fn parse_key_name_returns_owned_segments() {
    let owned = {
        let name = String::from("tianshu-relay/codex/20261013");
        parse_key_name(&name).expect("合法名字")
    };
    // `name` 已在此处 drop：仍能读到内容 ⇒ 返回的是拥有所有权的 `String`，不是借用
    assert_eq!(owned.0, "tianshu-relay");
    assert_eq!(owned.1, "codex");
    assert_eq!(owned.2, "20261013");
}

#[test]
fn default_app_id_is_the_product_id() {
    assert_eq!(DEFAULT_APP_ID, "tianshu-relay");
    assert!(
        default_key_name(DEFAULT_APP_ID, "codex", (2026, 10, 13)).is_some(),
        "DEFAULT_APP_ID 本身必须是合法段"
    );
}
