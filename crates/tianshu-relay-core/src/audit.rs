//! 脱敏审计（PRD M4「脱敏审计」）。
//!
//! 目的：**自证**本产品的落盘产物里没有明文凭证。
//! 与「事件表零明文」那条守护的区别是覆盖面——这里扫的是**磁盘上的字节**：
//! 数据库（含 WAL/SHM）、备份目录、诊断导出。
//!
//! 判定复用 `redact` 的规则，但用的是**忽略 64 位 hex** 的那个变体：
//! 本产品自己的数据库里合法地存着 sha256 哈希（`journals` 表），
//! 它们会被「≥32 位 hex」规则误报。代价与理由见 `redact::contains_secret_outside_hashes`。

use std::path::{Path, PathBuf};

use crate::redact::{contains_secret_outside_hashes, contains_secret_prefix_only};
use crate::store::ExportRecord;

/// 一条审计发现。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AuditFinding {
    /// 某个文件里发现了疑似明文凭证
    PlaintextInFile { path: PathBuf, hits: usize },
    /// 某个路径读不了（权限/占用/是特殊文件）
    Unreadable { path: PathBuf, reason: String },
    /// 事件表里有疑似未脱敏的行
    PlaintextInEvents { rows: i64 },
}

impl AuditFinding {
    /// 是否属于「有明文」这类**必须处理**的发现（`Unreadable` 只是信息）。
    pub fn is_plaintext(&self) -> bool {
        matches!(
            self,
            AuditFinding::PlaintextInFile { .. } | AuditFinding::PlaintextInEvents { .. }
        )
    }

    pub fn describe(&self) -> String {
        match self {
            AuditFinding::PlaintextInFile { path, hits } => {
                format!("{} 中发现 {hits} 处疑似明文凭证", path.display())
            }
            AuditFinding::Unreadable { path, reason } => {
                format!("{} 无法读取：{reason}", path.display())
            }
            AuditFinding::PlaintextInEvents { rows } => {
                format!("事件表中有 {rows} 行疑似未脱敏")
            }
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditReport {
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub findings: Vec<AuditFinding>,
}

impl AuditReport {
    /// 有没有**必须处理**的发现。`Unreadable` 不算（读不到 ≠ 有明文）。
    pub fn is_clean(&self) -> bool {
        !self.findings.iter().any(AuditFinding::is_plaintext)
    }

    pub fn plaintext_findings(&self) -> usize {
        self.findings.iter().filter(|f| f.is_plaintext()).count()
    }

    /// 一段人话结论。
    ///
    /// **覆盖面缺口必须出现在这里**（M5-S2 复审 P2-3）：`Unreadable` 不是
    /// 「有明文」，所以它不影响 [`is_clean`]；但「自称干净、其实没扫全」正是
    /// B-60 要修的那类谎言。缺口只在 `findings` 里时，主文案仍然写
    /// 「未发现明文凭证」，用户读到的就是过度承诺。这里把它追加在结论**后面**，
    /// 既让缺口可见，又不改变「有没有明文」这个判断本身。
    pub fn summary(&self) -> String {
        let gaps: Vec<String> = self
            .findings
            .iter()
            .filter(|f| !f.is_plaintext())
            .map(AuditFinding::describe)
            .collect();
        let gap_note = if gaps.is_empty() {
            String::new()
        } else {
            format!(
                "；注意：覆盖面不完整（{} 处）：{}",
                gaps.len(),
                gaps.join("；")
            )
        };

        if self.is_clean() {
            format!(
                "已扫描 {} 个文件 / {} 字节，未发现明文凭证{}",
                self.files_scanned, self.bytes_scanned, gap_note
            )
        } else {
            let detail: Vec<String> = self
                .findings
                .iter()
                .filter(|f| f.is_plaintext())
                .map(AuditFinding::describe)
                .collect();
            format!(
                "已扫描 {} 个文件 / {} 字节，发现 {} 处问题：{}{}",
                self.files_scanned,
                self.bytes_scanned,
                self.plaintext_findings(),
                detail.join("；"),
                gap_note
            )
        }
    }
}

/// 扫描一组路径（文件或目录，目录递归）里的明文凭证。
pub fn scan_paths(paths: &[PathBuf]) -> AuditReport {
    let mut report = AuditReport::default();
    for path in paths {
        scan_one(path, &mut report, 0);
    }
    report
}

/// 把「已知导出物」登记表（`Store::list_exports()`）里的路径**逐个**并入扫描集合（M5-S1 / 关闭 B-60）。
///
/// 背景：用户自选的导出路径不在任何固定目录里，审计原本看不到它们 ——
/// 而「自我证明落盘产物零明文」恰恰是审计存在的理由。
///
/// 语义：
/// - **并集去重**：与已有路径重复时不重复添加。否则同一文件被扫两遍，`files_scanned`
///   会虚高 —— 那是审计报告里唯一的「覆盖面」证据，不能被注水。
/// - **不做存在性检查**：用户随时可能删掉导出文件。`scan_paths` 对 `NotFound` 本来就静默跳过
///   （不计 `files_scanned`、不产生 `Unreadable`），在这里先 `exists()` 只会引入 TOCTOU
///   与「文件被删了就不再扫」的假绿。
/// - 空路径字符串也照收：`scan_paths` 会把它当 `NotFound` 跳过，不会 panic。
pub fn merge_export_registry(paths: &mut Vec<PathBuf>, records: &[ExportRecord]) {
    // M16-S6a：去重必须按**规范化后的真实路径**比，不能按字符串比。
    //
    // 修前的两个漏口（都会让 `files_scanned` 注水——那是审计报告里唯一的「覆盖面」证据）：
    // 1. **目录 vs 文件**：扫描集合里有 `<home>/.tianshu-relay/exports`（目录），而登记表里是
    //    该目录下的某个文件 ⇒ 字符串永不相等 ⇒ 同一个文件被计两次（目录遍历一次 + 登记一次）。
    //    实测：一个文件让 `files_scanned` 从 0 变成 2。
    // 2. **同一路径的不同写法**：macOS 上 `/var/…` 与 `/private/var/…` 是同一个地方，
    //    符号链接与相对段同理 ⇒ 字符串比较会把同一个文件当两个。
    //
    // 判据：`canonicalize` 能成功就用真实路径（顺带把符号链接与 `..` 归一），
    // 失败（文件已被删）退回原串——**不做存在性检查**（那会引入 TOCTOU 与「文件被删了就不再扫」）。
    fn real(path: &Path) -> PathBuf {
        std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    }

    // `existing` 要**随循环增长**：登记表内部也可能有重复项（同一路径登记两次），
    // 只跟「进来时的集合」比会漏掉批内重复（既有集成测试钉着这一条）。
    let mut existing: Vec<PathBuf> = paths.iter().map(|p| real(p)).collect();
    for record in records {
        let path = PathBuf::from(record.path.as_str());
        let real_path = real(&path);
        // 已被覆盖 ⇒ 跳过：`==` 挡「同一个文件的不同写法」，`starts_with` 挡
        // 「登记路径落在某个被扫描目录里」（遍历会扫到它）。
        let covered = existing
            .iter()
            .any(|entry| real_path == *entry || real_path.starts_with(entry));
        if covered {
            continue;
        }
        existing.push(real_path);
        paths.push(path);
    }
}

/// 递归深度上限：本产品的产物只有两三层，加个上限防止误传根目录时炸栈。
const MAX_DEPTH: usize = 8;

fn scan_one(path: &Path, report: &mut AuditReport, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            report.findings.push(AuditFinding::Unreadable {
                path: path.to_path_buf(),
                reason: e.to_string(),
            });
            return;
        }
    };

    if meta.is_dir() {
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(e) => {
                report.findings.push(AuditFinding::Unreadable {
                    path: path.to_path_buf(),
                    reason: e.to_string(),
                });
                return;
            }
        };
        for entry in entries.flatten() {
            scan_one(&entry.path(), report, depth + 1);
        }
        return;
    }

    if !meta.is_file() {
        return;
    }

    match std::fs::read(path) {
        Ok(bytes) => {
            report.files_scanned += 1;
            report.bytes_scanned += bytes.len() as u64;
            let text = String::from_utf8_lossy(&bytes);
            // 二进制产物（数据库 / WAL / SHM）里哈希与相邻字节会拼成任意长度的 hex run，
            // 任何基于长度的规则都会误报，因此只按前缀规则判；文本产物用完整规则。
            let is_binary = bytes.contains(&0u8);
            let hits = count_secret_hits(&text, is_binary);
            if hits > 0 {
                report.findings.push(AuditFinding::PlaintextInFile {
                    path: path.to_path_buf(),
                    hits,
                });
            }
        }
        Err(e) => report.findings.push(AuditFinding::Unreadable {
            path: path.to_path_buf(),
            reason: e.to_string(),
        }),
    }
}

/// 数一行文本里有多少处会被判定成疑似凭证。
///
/// 用「逐行 scrub 后与原行比较」来计数：规则与 `redact` 完全同源。
fn count_secret_hits(text: &str, is_binary: bool) -> usize {
    text.lines()
        .filter(|line| {
            if is_binary {
                contains_secret_prefix_only(line)
            } else {
                contains_secret_outside_hashes(line)
            }
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const SECRET: &str = "sk-audit-0123456789abcdef";

    /// M16-S6a：登记表去重按**规范化真实路径**，不按字符串。
    ///
    /// 两个漏口各一条断言（修前都会让 `files_scanned` 注水）：
    /// ① 登记路径落在**被扫描目录**里 ⇒ 遍历已经会扫到它，不得再 push；
    /// ② 同一文件的**不同写法**（这里用符号链接；macOS 的 `/var` ↔ `/private/var` 同理）
    ///    ⇒ 不得当成两个。
    #[test]
    fn export_registry_dedupes_by_real_path_not_by_string() {
        let dir = tempfile::tempdir().unwrap();
        let exports = dir.path().join("exports");
        fs::create_dir_all(&exports).unwrap();
        let file = exports.join("tianshu-relay-export-1.json");
        fs::write(&file, "{}\n").unwrap();

        let record = |path: &std::path::Path| crate::store::ExportRecord {
            path: path.display().to_string(),
            encrypted: false,
            bytes: 3,
            exported_at: 0,
        };

        // ① 扫描集合里是**目录**，登记表里是该目录下的文件 ⇒ 不重复添加
        let mut paths = vec![exports.clone()];
        merge_export_registry(&mut paths, &[record(&file)]);
        assert_eq!(paths.len(), 1, "目录已覆盖该文件，不得再 push: {paths:?}");

        // ② 同一文件的不同写法（符号链接）⇒ 不重复添加
        #[cfg(unix)]
        {
            let link = dir.path().join("link.json");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            let mut paths = vec![file.clone()];
            merge_export_registry(&mut paths, &[record(&link)]);
            assert_eq!(paths.len(), 1, "同一文件的不同写法不得当成两个: {paths:?}");
        }

        // ③ 正向对照：真正**不相干**的路径必须照收（防「一律跳过」的假修复）
        let outside = dir.path().join("other.json");
        fs::write(&outside, "{}\n").unwrap();
        let mut paths = vec![exports.clone()];
        merge_export_registry(&mut paths, &[record(&outside)]);
        assert_eq!(paths.len(), 2, "目录外的登记路径必须收: {paths:?}");
    }

    #[test]
    fn clean_directory_reports_clean() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "hello world\n").unwrap();
        fs::write(dir.path().join("b.txt"), "站点 example 余额 12.5 USD\n").unwrap();

        let report = scan_paths(&[dir.path().to_path_buf()]);
        assert!(report.is_clean(), "{}", report.summary());
        assert_eq!(report.files_scanned, 2);
        assert!(report.bytes_scanned > 0);
        assert!(report.summary().contains("未发现明文"));
    }

    #[test]
    fn plaintext_is_found_in_a_text_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("leak.txt"), format!("key={SECRET}\n")).unwrap();

        let report = scan_paths(&[dir.path().to_path_buf()]);
        assert!(!report.is_clean());
        assert_eq!(report.plaintext_findings(), 1);
        assert!(report.summary().contains("leak.txt"));
    }

    #[test]
    fn plaintext_is_found_inside_a_binary_file() {
        // 数据库是二进制；`from_utf8_lossy` 之后仍要能命中
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = vec![0u8, 1, 2, 255, 254];
        bytes.extend_from_slice(format!("secret_ref=kr/key/1/secret {SECRET}").as_bytes());
        bytes.extend_from_slice(&[0u8, 3, 4]);
        fs::write(dir.path().join("tianshu-relay.db"), &bytes).unwrap();

        let report = scan_paths(&[dir.path().to_path_buf()]);
        assert!(!report.is_clean(), "二进制文件里的明文必须被发现");
    }

    #[test]
    fn missing_paths_are_skipped_not_reported() {
        let dir = tempfile::tempdir().unwrap();
        let report = scan_paths(&[dir.path().join("nope.db")]);
        assert!(report.is_clean());
        assert_eq!(report.files_scanned, 0);
        assert!(report.findings.is_empty(), "不存在不该算 Unreadable");
    }

    #[test]
    fn nested_directories_are_scanned() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("backups/j1");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("0-auth.json"), format!("{SECRET}\n")).unwrap();

        let report = scan_paths(&[dir.path().to_path_buf()]);
        assert!(!report.is_clean());
        assert_eq!(report.files_scanned, 1);
    }

    #[test]
    fn unreadable_is_reported_but_does_not_stop_the_scan() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let locked = dir.path().join("locked.txt");
            fs::write(&locked, "x").unwrap();
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
            fs::write(dir.path().join("ok.txt"), "fine").unwrap();

            let report = scan_paths(&[dir.path().to_path_buf()]);
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o600)).unwrap();

            // 以 root 运行时 0o000 仍可读，所以只在「确实读不到」时断言
            if report
                .findings
                .iter()
                .any(|f| matches!(f, AuditFinding::Unreadable { .. }))
            {
                assert!(
                    report.is_clean(),
                    "Unreadable 不应被当成「有明文」: {}",
                    report.summary()
                );
                assert_eq!(report.files_scanned, 1, "其余文件仍应被扫描");
            }
        }
    }

    #[test]
    fn finding_descriptions_are_human_readable() {
        let finding = AuditFinding::PlaintextInFile {
            path: PathBuf::from("/tmp/x"),
            hits: 3,
        };
        assert!(finding.describe().contains("3 处"));
        assert!(finding.is_plaintext());

        let unreadable = AuditFinding::Unreadable {
            path: PathBuf::from("/tmp/y"),
            reason: "权限不足".into(),
        };
        assert!(!unreadable.is_plaintext());
    }

    #[test]
    fn binary_files_do_not_flag_sha256_hashes() {
        // 回归：`journals.after_sha256`（64 位 hex）紧邻下一列的 serial-type 字节时
        // 会拼成 65/66 位的 hex run；二进制分支必须放过它，否则数据库天天误报
        // （M4-S1 实测：`tests/audit.rs` 的 WAL 扫描就是这么抓出来的）。
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = vec![0u8, 0u8];
        bytes.extend_from_slice(b"/home/me/.zshrc");
        bytes.extend_from_slice("c5756062698276330b9b79ddbf8691c688d441cd".as_bytes());
        bytes.extend_from_slice(&[0u8; 8]);
        fs::write(dir.path().join("tianshu-relay.db-wal"), &bytes).unwrap();

        let report = scan_paths(&[dir.path().to_path_buf()]);
        assert!(
            report.is_clean(),
            "哈希与相邻字节拼成的 hex run 不该被当成凭证: {}",
            report.summary()
        );
    }

    #[test]
    fn hit_counting_is_per_line() {
        let text = format!("{SECRET}\n{SECRET}\nclean line\n");
        assert_eq!(count_secret_hits(&text, false), 2);
        assert_eq!(count_secret_hits("nothing here", false), 0);
        assert_eq!(count_secret_hits(&text, true), 2, "二进制模式也认前缀密钥");
        // 二进制模式放过裸 hex（哈希会与相邻字节拼成任意长度）
        assert_eq!(count_secret_hits(&"a".repeat(70), true), 0);
        assert_eq!(count_secret_hits(&"a".repeat(40), true), 0);
    }
}
