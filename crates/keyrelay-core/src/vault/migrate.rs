//! 一次性迁移：系统钥匙串 → 本地加密保险库。
//!
//! 顺序是**先校验后删除**：`source.get` → `target.put` → `target.get` 比对一致，
//! 才 `source.delete`。任何一步失败都保留钥匙串条目，下次启动重试。
//! 这比「迁移完统一删」慢一点，但换个方向就是不可逆的数据丢失。

use zeroize::Zeroizing;

use super::local::LocalVault;
use super::Vault;
use crate::error::Result;

/// 迁移完成标记（写在 `vault_meta` 里）。有值就不再跑，避免每次启动 probe 钥匙串。
pub const MIGRATION_MARKER: &str = "migrated_from_keychain";

#[derive(Debug, Default, PartialEq, Eq)]
pub struct MigrationReport {
    pub imported: usize,
    pub skipped: usize,
    /// (引用, 原因)。原因里**不含密钥材料**。
    pub failed: Vec<(String, String)>,
}

#[derive(Debug)]
pub struct MigrationOutcome {
    pub report: MigrationReport,
    /// 之前已经迁移过（本次什么都没做）。
    pub already_done: bool,
}

/// 逐条搬运。`source` 通常是 `KeychainVault`，`target` 是 `LocalVault`。
pub fn import_refs(
    source: &dyn Vault,
    target: &dyn Vault,
    refs: &[String],
) -> Result<MigrationReport> {
    let mut report = MigrationReport::default();
    for reference in refs {
        match source.get(reference) {
            Ok(None) => report.skipped += 1,
            Ok(Some(value)) => {
                // 明文只在栈上活很短一段，用完清零。
                let value = Zeroizing::new(value);
                if let Err(err) = target.put(reference, value.as_str()) {
                    report
                        .failed
                        .push((reference.clone(), format!("写入失败: {err}")));
                    continue;
                }
                match target.get(reference) {
                    Ok(Some(back)) if back == *value => {
                        if let Err(err) = source.delete(reference) {
                            // 已经写进新库了，只是旧条目没删掉；下次启动会再删一次（put 幂等）。
                            report.failed.push((
                                reference.clone(),
                                format!("已写入但删除源条目失败: {err}"),
                            ));
                        } else {
                            report.imported += 1;
                        }
                    }
                    Ok(_) => report.failed.push((reference.clone(), "回读不一致".into())),
                    Err(err) => report
                        .failed
                        .push((reference.clone(), format!("回读失败: {err}"))),
                }
            }
            Err(err) => report
                .failed
                .push((reference.clone(), format!("读取源条目失败: {err}"))),
        }
    }
    Ok(report)
}

/// 带完成标记的迁移入口：标记存在即跳过；只有**全成功**才写标记。
pub fn migrate_once(
    source: &dyn Vault,
    target: &LocalVault,
    refs: Vec<String>,
) -> Result<MigrationOutcome> {
    if target.meta_get(MIGRATION_MARKER)?.is_some() {
        return Ok(MigrationOutcome {
            report: MigrationReport::default(),
            already_done: true,
        });
    }
    let report = import_refs(source, target, &refs)?;
    if report.failed.is_empty() {
        target.meta_set(MIGRATION_MARKER, &now_secs().to_string())?;
    }
    Ok(MigrationOutcome {
        report,
        already_done: false,
    })
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
