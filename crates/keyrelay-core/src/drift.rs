//! 漂移检测：投递出去的文件有没有被外部改过。
//!
//! 只做**只读**检查：读文件、算 sha256、跟投递时记录的哈希比。
//! 不做任何自动修复——「文件被改过」是需要用户决定的事（可能是用户自己改的，
//! 也可能是别的工具改的），静默覆盖是错的。

use std::path::{Path, PathBuf};

use crate::inject::sha256_hex;
use crate::store::BindingDriftRow;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DriftState {
    /// 内容与投递时一致
    Intact,
    /// 文件存在但内容被改过
    Modified,
    /// 文件不存在了
    Missing,
    /// 记录里没有 `after_sha256`（历史数据），无法判定
    Unknown,
}

impl DriftState {
    pub fn as_str(self) -> &'static str {
        match self {
            DriftState::Intact => "intact",
            DriftState::Modified => "modified",
            DriftState::Missing => "missing",
            DriftState::Unknown => "unknown",
        }
    }

    /// 是否需要用户注意（用于 UI 高亮与事件级别）。
    pub fn needs_attention(self) -> bool {
        matches!(self, DriftState::Modified | DriftState::Missing)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DriftReport {
    pub target_path: PathBuf,
    pub agent_id: String,
    pub channel: String,
    pub state: DriftState,
    pub journal_id: String,
    /// 被改动时给出当前哈希，便于用户判断
    pub current_sha256: Option<String>,
    /// 投递时记录的哈希
    pub expected_sha256: Option<String>,
}

/// 纯函数：给定「期望哈希 + 文件当前哈希」，判定漂移状态。
///
/// `current == None` 表示文件不存在。`expected == None` 表示记录里没有哈希——
/// 那种情况一律 `Unknown`，**不猜**（把老库数据猜成 `Modified` 会让用户白跑一趟）。
pub fn classify(expected: Option<&str>, current: Option<&str>) -> DriftState {
    match (expected, current) {
        (None, _) => DriftState::Unknown,
        (Some(_), None) => DriftState::Missing,
        (Some(e), Some(c)) => {
            if e.eq_ignore_ascii_case(c) {
                DriftState::Intact
            } else {
                DriftState::Modified
            }
        }
    }
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

/// 读文件并算哈希；文件不存在返回 `None`。
///
/// 读取失败（权限、目录等）也返回 `None`——对用户而言「读不到」与「不存在」
/// 都意味着「这个投递现在不可用」，但会在报告里体现为 `Missing`，
/// 因此额外提供 [`current_hash_strict`] 供需要区分时使用。
pub fn current_hash(path: &Path) -> Option<String> {
    std::fs::read(path).ok().map(|bytes| hash_bytes(&bytes))
}

/// 与 [`current_hash`] 相同，但把「不存在」与「读失败」分开。
pub fn current_hash_strict(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(hash_bytes(&bytes))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("读取 {} 失败: {e}", path.display())),
    }
}

/// 由「绑定行 + 磁盘现状」生成一条报告。
pub fn report_for(row: &BindingDriftRow) -> DriftReport {
    let path = PathBuf::from(&row.target_path);
    let current = current_hash(&path);
    let state = classify(row.expected_sha256.as_deref(), current.as_deref());
    DriftReport {
        target_path: path,
        agent_id: row.agent_id.clone(),
        channel: crate::delivery::DeliveryChannel::from_agent_id(&row.agent_id)
            .map(|c| c.as_str().to_string())
            .unwrap_or_else(|| row.agent_id.clone()),
        state,
        journal_id: row.journal_id.clone(),
        current_sha256: current,
        expected_sha256: row.expected_sha256.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_covers_all_four_states() {
        assert_eq!(classify(Some("aa"), Some("aa")), DriftState::Intact);
        assert_eq!(classify(Some("aa"), Some("bb")), DriftState::Modified);
        assert_eq!(classify(Some("aa"), None), DriftState::Missing);
        assert_eq!(classify(None, Some("aa")), DriftState::Unknown);
        assert_eq!(classify(None, None), DriftState::Unknown);
    }

    #[test]
    fn classify_is_case_insensitive_on_hex() {
        assert_eq!(classify(Some("AABB"), Some("aabb")), DriftState::Intact);
    }

    #[test]
    fn state_helpers() {
        assert!(DriftState::Modified.needs_attention());
        assert!(DriftState::Missing.needs_attention());
        assert!(!DriftState::Intact.needs_attention());
        assert!(!DriftState::Unknown.needs_attention());
        assert_eq!(DriftState::Intact.as_str(), "intact");
    }

    #[test]
    fn current_hash_distinguishes_missing_from_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        assert_eq!(current_hash(&missing), None);
        assert_eq!(current_hash_strict(&missing).unwrap(), None);

        let file = dir.path().join("f");
        std::fs::write(&file, "hi").unwrap();
        assert_eq!(
            current_hash(&file),
            Some(hash_bytes(b"hi")),
            "应算出内容哈希"
        );
    }

    #[test]
    fn report_for_uses_expected_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.json");
        std::fs::write(&path, "content").unwrap();
        let expected = hash_bytes(b"content");

        let row = BindingDriftRow {
            agent_id: "codex".into(),
            target_path: path.display().to_string(),
            journal_id: "j1".into(),
            expected_sha256: Some(expected.clone()),
        };
        let report = report_for(&row);
        assert_eq!(report.state, DriftState::Intact);
        assert_eq!(report.channel, "codex-auth-json");
        assert_eq!(report.current_sha256.as_deref(), Some(expected.as_str()));

        // 改一个字节
        std::fs::write(&path, "contenT").unwrap();
        assert_eq!(report_for(&row).state, DriftState::Modified);

        // 删掉
        std::fs::remove_file(&path).unwrap();
        assert_eq!(report_for(&row).state, DriftState::Missing);
    }

    #[test]
    fn report_for_marks_old_rows_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.json");
        std::fs::write(&path, "x").unwrap();
        let row = BindingDriftRow {
            agent_id: "codex".into(),
            target_path: path.display().to_string(),
            journal_id: "j1".into(),
            expected_sha256: None,
        };
        assert_eq!(report_for(&row).state, DriftState::Unknown);
    }
}
