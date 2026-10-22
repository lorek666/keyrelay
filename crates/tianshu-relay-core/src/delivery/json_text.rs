//! JSON 配置文件的**保格式改写**公共逻辑。
//!
//! `~/.codex/auth.json` 与 `~/.claude/settings.json` 都要「只改几个键、其余保留」，
//! 且都要尽量维持原有的缩进与尾随换行风格。这里把这份逻辑抽出来，避免两处各写一遍。
//!
//! **已知取舍**（BACKLOG B-45）：改写是「重新序列化」而不是文本级替换，
//! 因此键序与缩进风格保留、**值语义保留**，但数值与转义会按 JSON 规范规范化
//! （`1.50` → `1.5`、`\u00e9` → `é`）。对这两个由 CLI 自己生成的文件，
//! 语义保真足够；文本级替换要自己处理转义与嵌套，风险更高。

use std::path::Path;

use serde::Serialize;
use serde_json::{Map, Value};

use crate::error::{Error, Result};

/// 读取文本；文件不存在返回空串（表示「将新建」）。
pub fn read_text_or_empty(path: &Path) -> Result<String> {
    match std::fs::read(path) {
        Ok(bytes) => String::from_utf8(bytes)
            .map_err(|_| Error::inject(path, "文件不是合法 UTF-8，拒绝改写")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(Error::inject(path, format!("读取失败: {e}"))),
    }
}

/// JSON 文本风格。保留它是为了不把用户的文件整份重排。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonStyle {
    /// `Some(b"  ")` = 两空格缩进；`None` = 单行紧凑
    pub indent: Option<Vec<u8>>,
    pub trailing_newline: bool,
}

impl JsonStyle {
    pub fn detect(before: &str) -> Self {
        if before.trim().is_empty() {
            // 新建：两空格缩进、无尾随换行（与两个 CLI 的实际产物一致）
            return Self {
                indent: Some(b"  ".to_vec()),
                trailing_newline: false,
            };
        }
        let trailing_newline = before.ends_with('\n');
        let body = before.trim_end_matches('\n');

        // 单行文件保持单行
        let indent = if !body.contains('\n') {
            None
        } else {
            body.lines()
                .skip(1)
                .find_map(|line| {
                    let ws: String = line
                        .chars()
                        .take_while(|c| *c == ' ' || *c == '\t')
                        .collect();
                    (!ws.is_empty()).then_some(ws.into_bytes())
                })
                .or_else(|| Some(b"  ".to_vec()))
        };

        Self {
            indent,
            trailing_newline,
        }
    }

    pub fn serialize(&self, map: &Map<String, Value>) -> Result<String> {
        let mut out = match &self.indent {
            Some(indent) => {
                let formatter = serde_json::ser::PrettyFormatter::with_indent(indent);
                let mut buf = Vec::new();
                let mut serializer = serde_json::Serializer::with_formatter(&mut buf, formatter);
                map.serialize(&mut serializer)
                    .map_err(|e| Error::Store(format!("序列化 JSON 失败: {e}")))?;
                String::from_utf8(buf)
                    .map_err(|_| Error::Store("序列化 JSON 产出非法 UTF-8".into()))?
            }
            None => serde_json::to_string(map)
                .map_err(|e| Error::Store(format!("序列化 JSON 失败: {e}")))?,
        };
        if self.trailing_newline {
            out.push('\n');
        }
        Ok(out)
    }
}

/// 解析出顶层对象；非法 JSON 或顶层不是对象时给出**可操作**的错误。
pub fn parse_object(before: &str, path: &Path) -> Result<Map<String, Value>> {
    if before.trim().is_empty() {
        return Ok(Map::new());
    }
    let parsed: Value = serde_json::from_str(before)
        .map_err(|e| Error::inject(path, format!("不是合法 JSON，拒绝改写: {e}")))?;
    match parsed {
        Value::Object(map) => Ok(map),
        _ => Err(Error::inject(path, "顶层不是 JSON 对象，拒绝改写")),
    }
}

/// 取（或按需创建）一个**对象**类型的子键。
///
/// 子键存在但不是对象时拒绝改写——那种文件不是我们能安全维护的形态。
pub fn object_entry<'a>(
    root: &'a mut Map<String, Value>,
    key: &str,
    path: &Path,
) -> Result<&'a mut Map<String, Value>> {
    // 先补齐、再取借用：写成一次 `match root.get_mut(key)` 会因为
    // 「插入分支也要可变借用」而同时持有两个可变借用。
    if !root.contains_key(key) {
        root.insert(key.to_string(), Value::Object(Map::new()));
    }
    match root.get_mut(key) {
        Some(Value::Object(inner)) => Ok(inner),
        Some(other) => Err(Error::inject(
            path,
            format!(
                "键 {key} 已存在但不是对象（是 {}），拒绝改写",
                kind_name(other)
            ),
        )),
        // 刚插进去的一定是对象；走到这里说明逻辑被改坏了，明确报错而不是 panic
        None => Err(Error::Store(format!("创建键 {key} 失败"))),
    }
}

pub fn kind_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detects_indent_and_trailing_newline() {
        assert_eq!(
            JsonStyle::detect("{\n  \"a\": 1\n}"),
            JsonStyle {
                indent: Some(b"  ".to_vec()),
                trailing_newline: false
            }
        );
        assert_eq!(
            JsonStyle::detect("{\n    \"a\": 1\n}\n"),
            JsonStyle {
                indent: Some(b"    ".to_vec()),
                trailing_newline: true
            }
        );
        assert_eq!(
            JsonStyle::detect("{\"a\":1}"),
            JsonStyle {
                indent: None,
                trailing_newline: false
            }
        );
        assert_eq!(
            JsonStyle::detect(""),
            JsonStyle {
                indent: Some(b"  ".to_vec()),
                trailing_newline: false
            }
        );
    }

    #[test]
    fn object_entry_rejects_non_object() {
        let mut root: Map<String, Value> = serde_json::from_value(json!({"env": [1, 2]})).unwrap();
        let err = object_entry(&mut root, "env", Path::new("/tmp/x")).unwrap_err();
        assert!(err.to_string().contains("不是对象"), "{err}");
    }

    #[test]
    fn object_entry_creates_missing_key() {
        let mut root: Map<String, Value> = Map::new();
        let inner = object_entry(&mut root, "env", Path::new("/tmp/x")).unwrap();
        inner.insert("k".into(), json!("v"));
        assert_eq!(root["env"]["k"], "v");
    }

    #[test]
    fn parse_object_rejects_bad_input() {
        assert!(parse_object("nope", Path::new("/tmp/x")).is_err());
        assert!(parse_object("[1,2]", Path::new("/tmp/x")).is_err());
        assert!(parse_object("", Path::new("/tmp/x")).unwrap().is_empty());
    }
}
