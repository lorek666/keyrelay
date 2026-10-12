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
    /// 文件**存在但读不到**（权限、或路径变成了目录）——与「被删了」是两回事，
    /// 处理方式也不同，所以单独一态（复审 P2-4）。
    Unreadable,
    /// 记录里没有 `after_sha256`（历史数据），无法判定
    Unknown,
}

impl DriftState {
    pub fn as_str(self) -> &'static str {
        match self {
            DriftState::Intact => "intact",
            DriftState::Modified => "modified",
            DriftState::Missing => "missing",
            DriftState::Unreadable => "unreadable",
            DriftState::Unknown => "unknown",
        }
    }

    /// 是否需要用户注意（用于 UI 高亮与事件级别）。
    pub fn needs_attention(self) -> bool {
        matches!(
            self,
            DriftState::Modified | DriftState::Missing | DriftState::Unreadable
        )
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

/// 读文件并算哈希，把「不存在」与「读失败」**分开**。
///
/// 不再提供「两者都返回 `None`」的便捷版本（复审 P2-4）：那个版本让
/// 「文件存在但 `chmod 000`」被报成「文件被删了」，指错了用户的下一步动作。
/// 只有这一个入口，就没有再走错的余地。
pub fn current_hash_strict(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(hash_bytes(&bytes))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("读取 {} 失败: {e}", path.display())),
    }
}

/// 由「绑定行 + 磁盘现状」生成一条报告。
///
/// 「存在但读不到」报成 [`DriftState::Unreadable`]，不混进 [`DriftState::Missing`]——
/// 前者要用户去查权限，后者要用户去重新投递，指错方向等于没报（复审 P2-4）。
pub fn report_for(row: &BindingDriftRow) -> DriftReport {
    let path = PathBuf::from(&row.target_path);
    let read = current_hash_strict(&path);
    let current = read.as_ref().ok().cloned().flatten();
    let state = match (&row.expected_sha256, &read) {
        // 老库行：没有 `after_sha256`，连「该是什么内容」都不知道，
        // 读得到读不到都判不了 → `Unknown`（与 `classify` 的 `(None, _)` 一致）
        (None, _) => DriftState::Unknown,
        // 有期望哈希但读不到：是「读不到」，不是「被删了」
        (Some(_), Err(_)) => DriftState::Unreadable,
        (Some(expected), Ok(current)) => classify(Some(expected.as_str()), current.as_deref()),
    };
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
        assert!(DriftState::Unreadable.needs_attention());
        assert!(!DriftState::Intact.needs_attention());
        assert!(!DriftState::Unknown.needs_attention());
        assert_eq!(DriftState::Intact.as_str(), "intact");
        assert_eq!(DriftState::Unreadable.as_str(), "unreadable");
    }

    #[test]
    fn current_hash_distinguishes_missing_from_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        assert_eq!(
            current_hash_strict(&missing).unwrap(),
            None,
            "不存在 → Ok(None)"
        );

        let file = dir.path().join("f");
        std::fs::write(&file, "hi").unwrap();
        assert_eq!(current_hash_strict(&file).unwrap(), Some(hash_bytes(b"hi")));

        // 「存在但读不到」必须报错，不能退化成 `None`（那会被当成「被删了」）
        let dir_as_file = dir.path().join("a_directory");
        std::fs::create_dir(&dir_as_file).unwrap();
        assert!(
            current_hash_strict(&dir_as_file).is_err(),
            "目录不是文件，读它会失败，必须如实报错"
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
            site_id: 7,
            key_id: 11,
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
    fn report_for_reports_an_unreadable_target_as_unreadable_not_missing() {
        // 复审 P2-4 的原始场景：文件**在**，只是读不到 → 不能告诉用户「被删了」
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.json");
        std::fs::write(&path, "content").unwrap();
        let row = BindingDriftRow {
            agent_id: "codex".into(),
            target_path: path.display().to_string(),
            journal_id: "j1".into(),
            expected_sha256: Some(hash_bytes(b"content")),
            site_id: 7,
            key_id: 11,
        };

        // 用「路径变成了目录」来稳定制造「存在但读不到」，不依赖 chmod（在 root 下会失效）
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();

        let report = report_for(&row);
        assert_eq!(report.state, DriftState::Unreadable);
        assert_eq!(report.current_sha256, None, "读不到就没有当前哈希可给");
        assert!(report.state.needs_attention(), "读不到需要用户处理");
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
            site_id: 7,
            key_id: 11,
        };
        assert_eq!(report_for(&row).state, DriftState::Unknown);
    }

    #[test]
    fn unknown_still_wins_over_an_unreadable_target() {
        // 两个条件同时成立时（老库 + 读不到）报 `Unknown`：
        // 没有 `after_sha256` 时连「该是什么内容」都不知道，说 `Unreadable` 会误导。
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.json");
        std::fs::create_dir(&path).unwrap();
        let row = BindingDriftRow {
            agent_id: "codex".into(),
            target_path: path.display().to_string(),
            journal_id: "j1".into(),
            expected_sha256: None,
            site_id: 7,
            key_id: 11,
        };
        assert_eq!(report_for(&row).state, DriftState::Unknown);
    }
}
