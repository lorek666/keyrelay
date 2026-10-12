//! agent 配置注入：计划（plan）→ 应用（apply）→ 回滚（rollback）。
//!
//! 安全约定：
//! - `apply` 前必须备份，写入必须原子（同目录临时文件 + rename）
//! - `apply` 会校验目标文件当前内容与计划中的 `before` 一致，防止覆盖并发修改
//! - `rollback` 会校验文件未被外部改动，拒绝静默覆盖
//! - 本模块**不**负责密钥投递：受管文件里只出现 base_url / provider / env 变量名

pub mod claude_code;
pub mod codex;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// 一次文件改写：`before` / `after` 用于生成 diff 与校验
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Patch {
    pub path: PathBuf,
    pub before: String,
    pub after: String,
}

/// 回滚凭据。`backup` 为 `None` 表示该文件在应用前不存在（回滚时应删除）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalEntry {
    pub path: PathBuf,
    pub backup: Option<PathBuf>,
    pub before_sha256: Option<String>,
    pub after_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Journal {
    pub id: String,
    pub entries: Vec<JournalEntry>,
}

/// 注入上下文：agent 需要知道「连哪里、用哪个 provider、模型叫什么」。
///
/// 注意 `api_key` 字段在本阶段**不会**写入受管文件（密钥投递见 M1-S2 的授权流程）。
#[derive(Clone, PartialEq, Eq)]
pub struct Binding {
    pub base_url: String,
    pub api_key: String,
    pub model: Option<String>,
    pub provider_id: String,
}

impl std::fmt::Debug for Binding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Binding")
            .field("base_url", &self.base_url)
            .field("api_key", &"<已脱敏>")
            .field("model", &self.model)
            .field("provider_id", &self.provider_id)
            .finish()
    }
}

pub trait Injector: Send + Sync {
    /// 注入器标识，与 `bindings.agent_id` 对应
    fn id(&self) -> &'static str;

    /// 只计算、不落盘。要求是纯函数：同样的输入产出同样的补丁。
    fn plan(&self, binding: &Binding) -> Result<Vec<Patch>>;
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn read_or_empty(path: &Path) -> Result<String> {
    match fs::read(path) {
        Ok(bytes) => String::from_utf8(bytes)
            .map_err(|_| Error::inject(path, "文件不是合法 UTF-8，拒绝改写")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(Error::inject(path, format!("读取失败: {e}"))),
    }
}

fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::inject(path, "路径没有父目录"))?;
    fs::create_dir_all(parent).map_err(|e| Error::inject(parent, format!("创建目录失败: {e}")))?;

    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "config".to_string());
    let tmp = parent.join(format!(".{file_name}.keyrelay.tmp"));

    fs::write(&tmp, contents).map_err(|e| Error::inject(&tmp, format!("写临时文件失败: {e}")))?;

    // 继承原文件权限位：临时文件按 umask 生成（常见 0644），
    // 会把 0600 的配置放宽成同机其他用户可读，必须在 rename 前回设。
    if let Ok(meta) = fs::metadata(path) {
        let _ = fs::set_permissions(&tmp, meta.permissions());
    }

    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        Error::inject(path, format!("原子替换失败: {e}"))
    })
}

/// 写入并回读校验，返回**磁盘上实际内容**的 sha256。
///
/// 对应 spec §6「注入后回读失败 → 自动回滚并报错」：若落盘内容与预期不符，
/// journal 记录的哈希就会与磁盘不一致，后续 `rollback` 会误判为「外部改动」而拒绝，
/// 因此必须在写入当步发现并补偿。
fn write_verified(path: &Path, contents: &str) -> Result<String> {
    write_atomic(path, contents)?;
    let read_back =
        fs::read(path).map_err(|e| Error::inject(path, format!("写入后回读失败: {e}")))?;
    let text = String::from_utf8(read_back)
        .map_err(|_| Error::inject(path, "写入后回读不是合法 UTF-8"))?;
    if text != contents {
        return Err(Error::inject(path, "写入后回读内容与预期不一致"));
    }
    Ok(sha256_hex(text.as_bytes()))
}

fn new_journal_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};

    // 毫秒级时间戳会在同一毫秒内的连续调用上碰撞，故追加进程内自增序号。
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("j{nanos}-{seq}")
}

/// 应用补丁：预检 → 备份 → 原子写 + 回读校验 → 记账。
///
/// 两处保证：
/// 1. **先全量预检再写入**：任一目标文件的当前内容与计划的 `before` 不一致时，
///    在动任何文件之前就失败，不会留下「改了一半」的中间态。
/// 2. **写入失败即补偿**：若第 N 个补丁写入或回读失败，已写入的条目与当前条目
///    会按逆序用备份还原，磁盘回到调用前状态。
///
/// 备份落在 `backup_dir/<journal_id>/` 下：每次 apply 一个独立目录，
/// 避免同一目标文件被多次注入时后一次覆盖前一次的备份（那样会导致回滚链断裂）。
pub fn apply(patches: &[Patch], backup_dir: &Path) -> Result<Journal> {
    let mut current_contents = Vec::with_capacity(patches.len());
    for patch in patches {
        let current = read_or_empty(&patch.path)?;
        if current != patch.before {
            return Err(Error::inject(
                &patch.path,
                "文件内容与计划不一致（可能被外部修改），请重新生成计划",
            ));
        }
        current_contents.push(current);
    }

    let journal_id = new_journal_id();
    let journal_backup_dir = backup_dir.join(&journal_id);
    fs::create_dir_all(&journal_backup_dir)
        .map_err(|e| Error::inject(&journal_backup_dir, format!("创建备份目录失败: {e}")))?;

    let mut entries: Vec<JournalEntry> = Vec::with_capacity(patches.len());
    for (index, (patch, current)) in patches.iter().zip(current_contents).enumerate() {
        let existed = !current.is_empty() || patch.path.exists();
        let backup = if existed {
            let file_name = patch
                .path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "config".to_string());
            let backup_path = journal_backup_dir.join(format!("{index}-{file_name}"));
            fs::copy(&patch.path, &backup_path)
                .map_err(|e| Error::inject(&backup_path, format!("备份失败: {e}")))?;
            Some(backup_path)
        } else {
            None
        };

        match write_verified(&patch.path, &patch.after) {
            Ok(after_sha256) => entries.push(JournalEntry {
                path: patch.path.clone(),
                backup,
                before_sha256: existed.then(|| sha256_hex(current.as_bytes())),
                after_sha256,
            }),
            Err(err) => {
                // 2) 补偿：把当前文件（若已被改写）与之前所有已写入的文件还原，
                //    保证 apply 失败后磁盘回到调用前状态。
                //    注意：当前文件未被改写时不加入补偿列表——否则会在「目录不可写」
                //    这类失败场景里，对一个本就无需还原的文件做无谓写入而拖垮整轮补偿。
                let mut compensation = entries.clone();
                let disk_now = read_or_empty(&patch.path)?;
                if disk_now != current {
                    compensation.push(JournalEntry {
                        path: patch.path.clone(),
                        backup: backup.clone(),
                        before_sha256: existed.then(|| sha256_hex(current.as_bytes())),
                        // 用磁盘现状计算，保证补偿回滚的校验必然通过
                        after_sha256: sha256_hex(disk_now.as_bytes()),
                    });
                }
                return match rollback(&Journal {
                    id: journal_id.clone(),
                    entries: compensation,
                }) {
                    Ok(()) => Err(err),
                    Err(rollback_err) => Err(Error::inject(
                        &patch.path,
                        format!("写入失败且自动补偿失败（需人工介入）: {err} / {rollback_err}"),
                    )),
                };
            }
        }
    }

    Ok(Journal {
        id: journal_id,
        entries,
    })
}

/// 回滚：校验文件未被外部改动后还原（或删除原本不存在的文件）。
///
/// **尽力而为**：逐个条目尝试还原，单个失败（例如该文件被外部改过、或目录不可写）
/// 不会中断其余条目的还原；只要有一条失败，整体返回 `Err` 并列出全部失败原因。
/// 这样一次失败不会把其他文件永久留在「已注入」状态。
pub fn rollback(journal: &Journal) -> Result<()> {
    let mut failures: Vec<String> = Vec::new();
    for entry in journal.entries.iter().rev() {
        if let Err(err) = restore_entry(entry) {
            failures.push(err.to_string());
        }
    }

    if failures.is_empty() {
        return Ok(());
    }
    Err(Error::Inject {
        path: format!("journal {}", journal.id),
        reason: format!(
            "{} 个文件未能还原: {}",
            failures.len(),
            failures.join(" | ")
        ),
    })
}

fn restore_entry(entry: &JournalEntry) -> Result<()> {
    if entry.path.exists() {
        let current = fs::read(&entry.path)
            .map_err(|e| Error::inject(&entry.path, format!("读取失败: {e}")))?;
        if sha256_hex(&current) != entry.after_sha256 {
            return Err(Error::inject(
                &entry.path,
                "文件已被外部修改，拒绝覆盖（请手工处理后重试）",
            ));
        }
    }

    match &entry.backup {
        Some(backup) => {
            let bytes = fs::read(backup)
                .map_err(|e| Error::inject(backup, format!("读取备份失败: {e}")))?;
            let contents = String::from_utf8(bytes)
                .map_err(|_| Error::inject(backup, "备份不是合法 UTF-8"))?;
            write_atomic(&entry.path, &contents)?;
        }
        None => {
            if entry.path.exists() {
                fs::remove_file(&entry.path)
                    .map_err(|e| Error::inject(&entry.path, format!("删除失败: {e}")))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn patch_for(dir: &Path, before: &str, after: &str) -> Patch {
        Patch {
            path: dir.join("config.toml"),
            before: before.to_string(),
            after: after.to_string(),
        }
    }

    #[test]
    fn apply_then_rollback_restores_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let original = "# 注释保留\nmodel = \"old\"\n";
        let target = dir.path().join("config.toml");
        fs::write(&target, original).unwrap();

        let patch = patch_for(dir.path(), original, "model = \"new\"\n");
        let journal = apply(&[patch], &dir.path().join("backups")).unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "model = \"new\"\n");
        assert!(journal.entries[0].backup.is_some());

        rollback(&journal).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), original);
        assert_eq!(
            sha256_hex(original.as_bytes()),
            journal.entries[0].before_sha256.clone().unwrap()
        );
    }

    #[test]
    fn apply_rejects_concurrent_change() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        fs::write(&target, "changed by user").unwrap();

        let patch = patch_for(dir.path(), "expected content", "new");
        let err = apply(&[patch], &dir.path().join("backups")).unwrap_err();
        assert!(matches!(err, Error::Inject { .. }));
        // 未通过校验时不得改写文件
        assert_eq!(fs::read_to_string(&target).unwrap(), "changed by user");
    }

    #[test]
    fn rollback_refuses_when_file_modified_after_apply() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        fs::write(&target, "before").unwrap();

        let patch = patch_for(dir.path(), "before", "after");
        let journal = apply(&[patch], &dir.path().join("backups")).unwrap();

        fs::write(&target, "after but edited by user").unwrap();
        let err = rollback(&journal).unwrap_err();
        assert!(matches!(err, Error::Inject { .. }));
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "after but edited by user"
        );
    }

    #[test]
    fn rollback_deletes_file_that_did_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("brand-new.toml");
        let patch = Patch {
            path: target.clone(),
            before: String::new(),
            after: "created".to_string(),
        };
        let journal = apply(&[patch], &dir.path().join("backups")).unwrap();
        assert!(target.exists());
        assert!(journal.entries[0].backup.is_none());

        rollback(&journal).unwrap();
        assert!(!target.exists());
    }

    #[test]
    fn consecutive_applies_use_separate_backups_and_roll_back_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        fs::write(&target, "v0").unwrap();

        let j1 = apply(
            &[patch_for(dir.path(), "v0", "v1")],
            &dir.path().join("backups"),
        )
        .unwrap();
        let j2 = apply(
            &[patch_for(dir.path(), "v1", "v2")],
            &dir.path().join("backups"),
        )
        .unwrap();

        assert_ne!(j1.id, j2.id, "journal id 必须唯一");
        assert_ne!(
            j1.entries[0].backup, j2.entries[0].backup,
            "两次注入的备份必须落在不同文件，否则回滚链会断裂"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "v2");

        rollback(&j2).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "v1");
        rollback(&j1).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "v0");
    }

    #[test]
    fn multi_patch_preflight_failure_touches_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.toml");
        fs::write(&a, "A0").unwrap();
        let b = dir.path().join("b.toml");
        fs::write(&b, "B0").unwrap();

        let patches = vec![
            Patch {
                path: a.clone(),
                before: "A0".into(),
                after: "A1".into(),
            },
            Patch {
                path: b.clone(),
                before: "与磁盘不符的前置内容".into(),
                after: "B1".into(),
            },
        ];

        let err = apply(&patches, &dir.path().join("backups")).unwrap_err();
        assert!(matches!(err, Error::Inject { .. }));
        // 预检失败必须在动任何文件之前发生
        assert_eq!(fs::read_to_string(&a).unwrap(), "A0");
        assert_eq!(fs::read_to_string(&b).unwrap(), "B0");
    }

    #[cfg(unix)]
    #[test]
    fn multi_patch_write_failure_compensates_written_files() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.toml");
        fs::write(&a, "A0").unwrap();

        let readonly = dir.path().join("ro");
        fs::create_dir(&readonly).unwrap();
        let b = readonly.join("b.toml");
        fs::write(&b, "B0").unwrap();

        // 目录只读 → 第 2 个补丁写临时文件必然失败，触发补偿路径
        let mut perm = fs::metadata(&readonly).unwrap().permissions();
        perm.set_mode(0o500);
        fs::set_permissions(&readonly, perm).unwrap();

        let patches = vec![
            Patch {
                path: a.clone(),
                before: "A0".into(),
                after: "A1".into(),
            },
            Patch {
                path: b.clone(),
                before: "B0".into(),
                after: "B1".into(),
            },
        ];

        let err = apply(&patches, &dir.path().join("backups")).unwrap_err();
        assert!(matches!(err, Error::Inject { .. }));
        // 已写入的第 1 个文件必须被补偿还原
        assert_eq!(fs::read_to_string(&a).unwrap(), "A0");
        assert_eq!(fs::read_to_string(&b).unwrap(), "B0");

        let mut perm = fs::metadata(&readonly).unwrap().permissions();
        perm.set_mode(0o700);
        fs::set_permissions(&readonly, perm).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn apply_and_rollback_preserve_file_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        fs::write(&target, "v0").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();

        let journal = apply(
            &[patch_for(dir.path(), "v0", "v1")],
            &dir.path().join("backups"),
        )
        .unwrap();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600,
            "注入后权限位不得被放宽"
        );

        rollback(&journal).unwrap();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600,
            "回滚后权限位必须保持"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "v0");
    }

    #[test]
    fn write_is_atomic_no_temp_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        fs::write(&target, "a").unwrap();
        let patch = patch_for(dir.path(), "a", "b");
        apply(&[patch], &dir.path().join("backups")).unwrap();

        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".keyrelay.tmp"))
            .collect();
        assert!(leftovers.is_empty(), "临时文件未清理: {leftovers:?}");
    }
}
