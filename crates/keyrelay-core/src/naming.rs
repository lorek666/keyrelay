//! 站点侧密钥命名规范（M7-S4 / PRD FR-2）。
//!
//! 形状：`<app-id>/<agent-id>/<yyyymmdd>`——三段、`/` 分隔、第三段**恰好 8 位 ASCII 数字**。
//! 生成（[`default_key_name`]）与解析（[`parse_key_name`]）是**一对**：合法入参生成的名字
//! 一定能被解析回原三元组（往返性质，`docs/specs/M7-S4-密钥生命周期与命名.md` §4.2 规则 5）。
//!
//! 设计约束：
//!
//! - **纯函数**：不读时钟（日期由调用方给）、不读环境变量、不读文件、无网络、无内部状态。
//!   日期若由函数自己取「今天」，跨零点的测试会闪断，spec 的例子表也无法逐字复现（spec §7）。
//! - **只校验形状，不校验日历**：`(2026, 13, 45)` 渲染成 `20261345`，解析也照样接受——
//!   日历合法性由调用方负责（它才知道「今天」），生成与解析两侧对称，往返不丢（spec D-5）。
//! - **不接触密钥**：名字是标识，不是凭据；本模块没有任何 `Error` / IO / 存储依赖。

/// 默认应用标识（PRD FR-2 的 `<app-id>`）。取**产品名**而不是包名。
pub const DEFAULT_APP_ID: &str = "keyrelay";

/// 段长度上限（**字节**）。段只允许 ASCII，因此字节数 == 字符数。
///
/// 上限是**防御性**的：站点侧 token name 的真实上限未知（spec §11 未验证边界），
/// 64 远大于现有取值（`keyrelay` / `codex` / `claude-code` / `opencode` / `gemini-cli` / `continue`）。
/// 整名上限由分段上限推出（≤ 64 + 1 + 64 + 1 + 8 = 138 字节），不另设总长规则。
const MAX_SEGMENT_LEN: usize = 64;

/// 日期的渲染宽度：`yyyymmdd`。
const DATE_LEN: usize = 8;

/// 生成 `<app-id>/<agent-id>/<yyyymmdd>`。
///
/// **日期由调用方给**（本函数不读时钟）。任一段不满足下面两条、或日期渲染不出 8 位数字 ⇒ `None`：
///
/// - 段非空、只含 `[A-Za-z0-9._-]`、长度 ≤ [`MAX_SEGMENT_LEN`] 字节；
/// - 年 ∈ `0..=9999`、月 ∈ `0..=99`、日 ∈ `0..=99`（渲染成 4 + 2 + 2 位，**不做日历校验**）。
///
/// 返回 `Option` 而不是 `String`（章程 §3.4 v1.1 裁决 / O-1）：把「拒绝非法入参」写进类型，
/// 否则生成器会产出**它自己的解析器都拒绝**的名字（`"a/b"` → 4 段 → `parse` ⇒ `None`），
/// 往返性质对「本该被拒的输入」就不成立。
pub fn default_key_name(app_id: &str, agent_id: &str, date: (i32, u32, u32)) -> Option<String> {
    if !is_valid_segment(app_id) || !is_valid_segment(agent_id) {
        return None;
    }
    let rendered = render_date(date)?;
    // 冗余但刻意：范围检查已经保证 8 位，这里让「生成的名字必然可被解析」成为**结构性**事实，
    // 而不是一条需要读者自己推的结论（改坏 `render_date` 时这里会先拦住）。
    if !is_eight_ascii_digits(&rendered) {
        return None;
    }
    Some(format!("{app_id}/{agent_id}/{rendered}"))
}

/// 逆解析：`<app-id>/<agent-id>/<yyyymmdd>` → `(app_id, agent_id, yyyymmdd)`。
///
/// **只接受恰好三段**、前两段满足段规则、第三段恰好 8 位 ASCII 数字；其余一律 `None`。
/// 第三段按**原样字符串**返回（不拆成数字、不校验日历）：调用方要展示就展示，要比较就逐字比较。
pub fn parse_key_name(name: &str) -> Option<(String, String, String)> {
    let mut parts = name.split('/');
    let app_id = parts.next()?;
    let agent_id = parts.next()?;
    let date = parts.next()?;
    // 多一段都算不是本规范的名字（`split` 的第四段哪怕是空串也要拒）
    if parts.next().is_some() {
        return None;
    }
    if !is_valid_segment(app_id) || !is_valid_segment(agent_id) || !is_eight_ascii_digits(date) {
        return None;
    }
    Some((app_id.to_string(), agent_id.to_string(), date.to_string()))
}

/// 段规则：非空、只含 `[A-Za-z0-9._-]`、字节长度 ≤ [`MAX_SEGMENT_LEN`]。
///
/// 字符集是**刻意收窄**的（spec D-3）：名字会进站点侧 token name 与日志，ASCII 子集避免编码歧义；
/// 非 ASCII 的 app-id 会被**显式拒绝**（而不是静默产出一个到处乱码的名字）。
fn is_valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= MAX_SEGMENT_LEN
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// 把 `(年, 月, 日)` 渲染成恰好 8 位数字。范围检查只保证**形状**（见模块文档）。
fn render_date(date: (i32, u32, u32)) -> Option<String> {
    let (year, month, day) = date;
    if !(0..=9999).contains(&year) || month > 99 || day > 99 {
        return None;
    }
    Some(format!("{year:04}{month:02}{day:02}"))
}

/// 恰好 [`DATE_LEN`] 位 ASCII 数字。**只认 ASCII**：全角数字（`２０２６`）与其它数字系统一律不算。
fn is_eight_ascii_digits(value: &str) -> bool {
    value.len() == DATE_LEN && value.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_app_id_is_the_product_id() {
        assert_eq!(DEFAULT_APP_ID, "keyrelay");
        assert!(is_valid_segment(DEFAULT_APP_ID), "常量本身必须满足段规则");
    }

    #[test]
    fn default_key_name_renders_the_frozen_shape() {
        assert_eq!(
            default_key_name("keyrelay", "codex", (2026, 10, 13)).unwrap(),
            "keyrelay/codex/20261013"
        );
        assert_eq!(
            default_key_name("keyrelay", "claude-code", (2026, 1, 3)).unwrap(),
            "keyrelay/claude-code/20260103"
        );
        assert_eq!(
            default_key_name("tickflow.ai", "opencode", (2026, 12, 31)).unwrap(),
            "tickflow.ai/opencode/20261231"
        );
        assert_eq!(
            default_key_name("my_app-2", "continue", (1970, 1, 1)).unwrap(),
            "my_app-2/continue/19700101"
        );
    }

    #[test]
    fn default_key_name_pads_the_year_to_four_digits() {
        assert_eq!(
            default_key_name("keyrelay", "gemini-cli", (999, 1, 1)).unwrap(),
            "keyrelay/gemini-cli/09990101"
        );
        assert_eq!(
            default_key_name("keyrelay", "gemini-cli", (0, 0, 0)).unwrap(),
            "keyrelay/gemini-cli/00000000"
        );
    }

    /// 「不读时钟」的可证伪测试：产出**只**跟 `date` 参数走。
    ///
    /// 若实现偷读系统时钟，两条断言都会变成「今天」而必红——「今天」不可能是 1970-01-01，
    /// 也不可能是 2999-12-31，所以这里不需要在测试里另算一遍「今天」。
    #[test]
    fn default_key_name_never_reads_the_clock() {
        assert_eq!(
            default_key_name("keyrelay", "codex", (1970, 1, 1)).unwrap(),
            "keyrelay/codex/19700101"
        );
        assert_eq!(
            default_key_name("keyrelay", "codex", (2999, 12, 31)).unwrap(),
            "keyrelay/codex/29991231"
        );
    }

    /// 纯函数性：同输入同输出。
    #[test]
    fn default_key_name_is_deterministic() {
        let a = default_key_name("keyrelay", "codex", (2026, 10, 13));
        let b = default_key_name("keyrelay", "codex", (2026, 10, 13));
        assert_eq!(a, b);
        assert!(a.is_some());
    }

    #[test]
    fn parse_key_name_requires_eight_ascii_digits() {
        assert!(parse_key_name("keyrelay/codex/2026101").is_none(), "7 位");
        assert!(parse_key_name("keyrelay/codex/202610131").is_none(), "9 位");
        assert!(
            parse_key_name("keyrelay/codex/2026-10-13").is_none(),
            "带分隔符"
        );
        assert!(parse_key_name("keyrelay/codex/abcdefgh").is_none(), "字母");
        assert!(
            parse_key_name("keyrelay/codex/２０２６１０１３").is_none(),
            "全角数字"
        );
        assert!(
            parse_key_name("keyrelay/codex/٢٠٢٦١٠١٣").is_none(),
            "非 ASCII 数字"
        );
        assert_eq!(
            parse_key_name("keyrelay/codex/20261013"),
            Some(("keyrelay".into(), "codex".into(), "20261013".into()))
        );
    }

    #[test]
    fn parse_key_name_rejects_empty_segments() {
        for name in ["keyrelay//20261013", "//20261013", "keyrelay/codex/", ""] {
            assert!(parse_key_name(name).is_none(), "「{name}」不该被接受");
        }
    }

    #[test]
    fn parse_key_name_requires_exactly_three_segments() {
        for name in [
            "keyrelay/20261013",
            "keyrelay/codex/x/20261013",
            "keyrelay/codex/20261013/",
        ] {
            assert!(parse_key_name(name).is_none(), "「{name}」段数不对");
        }
    }

    #[test]
    fn parse_key_name_enforces_the_segment_charset_and_length() {
        assert!(parse_key_name("my app/codex/20261013").is_none(), "空格");
        assert!(parse_key_name("密钥/codex/20261013").is_none(), "非 ASCII");
        assert!(parse_key_name("keyrelay/co:dex/20261013").is_none(), "冒号");
        assert!(
            parse_key_name("keyrelay/co/dex/20261013").is_none(),
            "多一段"
        );

        let exactly_64 = "a".repeat(MAX_SEGMENT_LEN);
        assert!(
            parse_key_name(&format!("{exactly_64}/codex/20261013")).is_some(),
            "恰好 64 字节必须接受"
        );
        let over = "a".repeat(MAX_SEGMENT_LEN + 1);
        assert!(
            parse_key_name(&format!("{over}/codex/20261013")).is_none(),
            "65 字节必须拒绝"
        );
    }

    /// 日历不校验是**有意**的（spec D-5）：生成与解析两侧对称，往返不丢。
    #[test]
    fn parse_key_name_does_not_validate_calendar_dates() {
        assert_eq!(
            parse_key_name("keyrelay/codex/20261345"),
            Some(("keyrelay".into(), "codex".into(), "20261345".into())),
            "13 月 45 日：形状合法即接受（日历不是本模块的职责）"
        );
    }

    #[test]
    fn render_date_always_produces_eight_digits_within_range() {
        for date in [
            (0, 0, 0),
            (999, 1, 1),
            (2026, 10, 13),
            (9999, 99, 99),
            (2026, 1, 31),
        ] {
            let rendered = render_date(date).unwrap_or_else(|| panic!("{date:?} 应可渲染"));
            assert!(is_eight_ascii_digits(&rendered), "{date:?} → {rendered}");
        }
        for bad in [(10_000, 1, 1), (-1, 1, 1), (2026, 100, 1), (2026, 1, 100)] {
            assert!(render_date(bad).is_none(), "{bad:?} 应被拒绝");
        }
    }
}
