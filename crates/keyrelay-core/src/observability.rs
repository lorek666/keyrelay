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
pub const SOURCES: [&str; 6] = ["app", "site", "key", "delivery", "vault", "store"];

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
    Event {
        ts: now_secs(),
        level,
        source: normalize_source(source),
        message: scrub(message.as_ref()),
        payload: None,
    }
}

/// 唯一入口（带载荷）。载荷整体序列化后过 `scrub`，嵌套深层的密钥同样会被替换。
pub fn event_with_payload(
    level: Level,
    source: &str,
    message: impl AsRef<str>,
    payload: Value,
) -> Event {
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
