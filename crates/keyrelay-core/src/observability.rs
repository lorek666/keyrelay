//! 可观测性：**唯一**的事件写入入口，所有文本先过脱敏。
//!
//! 设计约束（BACKLOG B-11 / B-31 / B-36）：
//! - 本模块是 `events` 表的**唯一**写入方；其它模块不得直接 `INSERT INTO events`。
//! - `message` 与 `payload` 在**构造时**就过 [`crate::redact::scrub`]，构造后无法再改。
//! - `payload` 先序列化成 JSON 文本再整体脱敏，因此**嵌套深层**的密钥也会被替换。
//! - 密钥本体永远不会进入事件：投递路径只记录 `journal_id` / `target_path` 这类元数据。

use serde_json::Value;

use crate::error::{Error, Result};
use crate::redact::scrub;

/// `source` 的约定取值（同时用于 UI 过滤）。
///
/// `"gateway"` 是 M7-S5 加的：网关的失败事件（FR-5:160）此前**无处可去**——
/// `normalize_source` 会把认不出的来源归一到 `"app"`，于是「网关为什么切换了上游」
/// 会混在应用事件里，按来源过滤就找不到它。加进白名单而不是改用 `"app"`，
/// 是因为这条事件需要能**单独被筛出来**：它是「请求失败」而不是「应用做了什么」。
///
/// `"probe"` 是 M15-S1 加的：模型检测（bazaarlink）的完成/失败事件同理，需要能单独
/// 筛出（否则混在 `app` 里，用户按来源筛「检测」看不到）。独立复审 M4 发现
/// `probe_model` 的 `source: "probe"` 不在白名单、被归一成 `app`——顺带修掉。
pub const SOURCES: [&str; 8] = [
    "app", "site", "key", "delivery", "vault", "store", "gateway", "probe",
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "debug" => Ok(Level::Debug),
            "info" => Ok(Level::Info),
            "warn" => Ok(Level::Warn),
            "error" => Ok(Level::Error),
            other => Err(Error::Store(format!("未知的事件级别: {other}"))),
        }
    }
}

/// 一条**已脱敏**的事件。
#[derive(Clone, PartialEq, Eq)]
pub struct Event {
    pub ts: i64,
    pub level: Level,
    pub source: String,
    /// 已过 `scrub`
    pub message: String,
    /// 已过 `scrub` 的 JSON 文本；`None` 表示无载荷
    pub payload: Option<String>,
}

/// 手写 `Debug`：只打印长度与来源，避免 `{:?}` 顺手把正文带进日志。
impl std::fmt::Debug for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Event")
            .field("ts", &self.ts)
            .field("level", &self.level)
            .field("source", &self.source)
            .field("message_len", &self.message.len())
            .field("has_payload", &self.payload.is_some())
            .finish()
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 唯一入口（无载荷）。
pub fn event(level: Level, source: &str, message: impl AsRef<str>) -> Event {
    let scrubbed = scrub(message.as_ref());
    Event {
        ts: now_secs(),
        level,
        source: normalize_source(source),
        // P2-25 / DEBUG-REPORT-v3 §2-25：message 再过一遍 mask_authority_userinfo——
        // scrub 的 mask_url_userinfo 为 JSON 文本安全把 `"` 当 authority 终止符，
        // 自由文本里「带引号密码的 URL」会在 `"` 处截断、找不到 `@` ⇒ 原样落库。
        // mask_authority_userinfo 不把引号当终止符，能掩住。宁可多掩（email 本地部分
        // 也会被掩成 `***@host`）——漏一个密码的代价不可撤销。
        message: crate::redact::mask_authority_userinfo(&scrubbed),
        payload: None,
    }
}

/// 唯一入口（带载荷）。载荷整体序列化后过 `scrub`，嵌套深层的密钥同样会被替换。
///
/// 序列化**之前**先把「整个值就是 URL」的字符串按 URL 口径掩掉 userinfo：序列化后的
/// 文本里，密码中的 `"` 已变成 `\"`，文本规则找不到 authority 的真实边界（独立复审 P2-1）。
pub fn event_with_payload(
    level: Level,
    source: &str,
    message: impl AsRef<str>,
    mut payload: Value,
) -> Event {
    crate::redact::mask_url_userinfo_in_json(&mut payload);
    let mut e = event(level, source, message);
    // `serde_json::to_string` 对 `Value` 不会失败；失败时退化为不带载荷而不是 panic。
    e.payload = serde_json::to_string(&payload).ok().map(|s| scrub(&s));
    e
}

/// 未知 `source` 归一到 `"app"`，避免事件表里出现任意字符串。
fn normalize_source(source: &str) -> String {
    if SOURCES.contains(&source) {
        source.to_string()
    } else {
        "app".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "sk-0123456789abcdef";

    #[test]
    fn level_roundtrip() {
        for level in [Level::Debug, Level::Info, Level::Warn, Level::Error] {
            assert_eq!(Level::parse(level.as_str()).unwrap(), level);
        }
        assert!(matches!(Level::parse("nope"), Err(Error::Store(_))));
    }

    #[test]
    fn scrubs_message_at_construction() {
        let e = event(Level::Info, "key", format!("已获取密钥 {SECRET}"));
        assert!(!e.message.contains(SECRET), "{}", e.message);
        assert!(e.message.contains("sk-***"), "{}", e.message);
    }

    #[test]
    fn scrubs_a_url_with_a_quoted_password_in_the_message() {
        // P2-25 / DEBUG-REPORT-v3 §2-25：带引号密码的 URL 在自由文本里——scrub 的
        // mask_url_userinfo 把 `"` 当 authority 终止符（为 JSON 文本安全），在 `"` 处
        // 截断找不到 `@` ⇒ 原样落库。event() 的 message 再过 mask_authority_userinfo
        //（不把引号当终止符）掩住。
        let pw = "p\"ass";
        let e = event(
            Level::Info,
            "site",
            format!("登录失败：见 https://carol:{pw}@relay.example.com/x"),
        );
        assert!(
            !e.message.contains("ass"),
            "带引号密码的 URL 不得原样进文案: {}",
            e.message
        );
        assert!(
            e.message.contains("relay.example.com"),
            "主机名仍要点出: {}",
            e.message
        );
    }

    #[test]
    fn scrubs_nested_payload() {
        let e = event_with_payload(
            Level::Info,
            "delivery",
            "投递完成",
            json!({
                "outer": { "inner": { "token": SECRET } },
                "list": [SECRET, "safe"],
                "ok": 1
            }),
        );
        let payload = e.payload.expect("有载荷");
        assert!(!payload.contains(SECRET), "{payload}");
        assert!(!payload.contains("0123456789"), "{payload}");
        assert!(payload.contains("\"ok\":1"), "{payload}");
    }

    #[test]
    fn debug_does_not_print_body() {
        let e = event(Level::Warn, "site", "站点返回了一个很长的诊断文本");
        let text = format!("{e:?}");
        assert!(!text.contains("很长的诊断文本"), "{text}");
        assert!(text.contains("message_len"), "{text}");
    }

    #[test]
    fn unknown_source_is_normalized() {
        let e = event(Level::Info, "随便写的来源", "x");
        assert_eq!(e.source, "app");
    }

    #[test]
    fn keeps_normal_text_intact() {
        let e = event(Level::Info, "site", "站点已识别: newapi 测试站点");
        assert_eq!(e.message, "站点已识别: newapi 测试站点");
    }
}
