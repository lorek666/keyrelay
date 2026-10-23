//! 一次性迁移：系统钥匙串 → 本地加密保险库。
//!
//! 顺序是**先校验后删除**：`source.get` → `target.put` → `target.get` 比对一致，
//! 才 `source.delete`。任何一步失败都保留钥匙串条目，下次启动重试。
//! 这比「迁移完统一删」慢一点，但换个方向就是不可逆的数据丢失。
//!
//! M38-S2（B-219）：迁移从「每次启动静默重试」变成**可控动作**——
//! 每次尝试把 attempts / last_at / last_error / failures 写进 `vault_meta`（**不含密钥材料**），
//! 自动重试有硬上限（[`MIGRATION_MAX_AUTO_ATTEMPTS`]），用户可在设置页显式重试或放弃。
//! 「已写入目标、只差删除源条目」进 [`MigrationReport::cleanup_pending`]，**不阻塞**完成标记。

use zeroize::Zeroizing;

use super::local::LocalVault;
use super::Vault;
use crate::error::Result;
use crate::service::GATEWAY_TOKEN_REF;
use crate::store::Store;

/// 迁移完成标记（写在 `vault_meta` 里）。有值就不再跑，避免每次启动 probe 钥匙串。
/// 值有两种：完成时的 unix 秒，或放弃时的 `abandoned:<unix>`。
pub const MIGRATION_MARKER: &str = "migrated_from_keychain";
/// 累计尝试次数（十进制整数）。
pub const MIGRATION_ATTEMPTS: &str = "keychain_migration_attempts";
/// 最近一次尝试的 unix 秒。
pub const MIGRATION_LAST_AT: &str = "keychain_migration_last_at";
/// 失败摘要（自建文案，**不含明文**）。
pub const MIGRATION_LAST_ERROR: &str = "keychain_migration_last_error";
/// 未写入目标的失败明细 JSON：`[{reference,reason}]`。
pub const MIGRATION_FAILURES: &str = "keychain_migration_failures";
/// 「已写入、只差删除源」的诊断明细 JSON（不阻塞完成标记）。
pub const MIGRATION_CLEANUP_PENDING: &str = "keychain_migration_cleanup_pending";
/// 自动重试的硬上限：到上限后启动路径**不再碰钥匙串**。
pub const MIGRATION_MAX_AUTO_ATTEMPTS: u32 = 2;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct MigrationReport {
    pub imported: usize,
    pub skipped: usize,
    /// 已写入目标、但删除源条目失败：数据安全，不阻塞完成标记。
    pub cleanup_pending: Vec<(String, String)>,
    /// 未写入目标：阻塞完成标记。
    pub failed: Vec<(String, String)>,
}

#[derive(Debug)]
pub struct MigrationOutcome {
    pub report: MigrationReport,
    /// 之前已经迁移过（本次什么都没做）。
    pub already_done: bool,
}

/// 一条失败明细：只存**引用**与**自建原因**（不含密钥材料）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationFailure {
    pub reference: String,
    pub reason: String,
}

/// 迁移状态（只读投影，给设置页 / CLI 看）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationStatus {
    /// `"done" | "pending" | "retry_exhausted" | "abandoned"`
    pub phase: &'static str,
    pub attempts: u32,
    pub last_at: Option<i64>,
    pub last_error: Option<String>,
    pub failures: Vec<MigrationFailure>,
    pub cleanup_pending: Vec<MigrationFailure>,
}

/// 迁移要覆盖的引用集合 = 库里的引用 + 网关本地令牌。
///
/// 网关令牌（`kr/gateway/local/token`）没有 `keys` 行、不在任何表里，但它是
/// `owned_secret_refs()` 明确承认的「本产品拥有的条目」（复审 P1-2）。漏掉它，
/// 升级后 `gateway_token()` 会生成新令牌，已有 agent 配置全部 401。
pub fn refs_for_migration(store: &Store) -> Result<Vec<String>> {
    let mut refs = store.all_secret_refs()?;
    refs.push(GATEWAY_TOKEN_REF.to_string());
    refs.sort();
    refs.dedup();
    Ok(refs)
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
                            // 已经写进新库了，只是旧条目没删掉。**数据安全** ⇒ 进 cleanup_pending，
                            // 不阻塞完成标记（M38-S2：否则每次启动都会重试这条注定删不掉的条目）。
                            report.cleanup_pending.push((
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

/// 迁移状态（四态：done / pending / retry_exhausted / abandoned）。
pub fn status_for(target: &LocalVault) -> Result<MigrationStatus> {
    let marker = target.meta_get(MIGRATION_MARKER)?;
    let attempts = parse_attempts(target)?;
    let last_at = parse_last_at(target)?;
    let last_error = target.meta_get(MIGRATION_LAST_ERROR)?;
    let failures = parse_failures(target.meta_get(MIGRATION_FAILURES)?.as_deref());
    let cleanup_pending = parse_failures(target.meta_get(MIGRATION_CLEANUP_PENDING)?.as_deref());
    let phase = if marker.is_some() {
        if is_abandoned(marker.as_deref()) {
            "abandoned"
        } else {
            "done"
        }
    } else if attempts >= MIGRATION_MAX_AUTO_ATTEMPTS {
        "retry_exhausted"
    } else {
        "pending"
    };
    Ok(MigrationStatus {
        phase,
        attempts,
        last_at,
        last_error,
        failures,
        cleanup_pending,
    })
}

/// 启动路径是否还该自动重试：**无标记**且 `attempts < 上限` 才 true。
///
/// 已完成 / 已放弃 / 达到上限 ⇒ false（启动路径据此**不 probe、不枚举、不迁移**）。
pub fn should_auto_retry(target: &LocalVault) -> Result<bool> {
    if target.meta_get(MIGRATION_MARKER)?.is_some() {
        return Ok(false);
    }
    Ok(parse_attempts(target)? < MIGRATION_MAX_AUTO_ATTEMPTS)
}

/// 用户显式放弃：写 `abandoned:<unix>`，**不删源条目**。幂等。
///
/// 已完成（marker 有非 `abandoned:` 值）⇒ **不改写**：放弃只能用于尚未完成的迁移，
/// 否则会把「已完成」覆盖成「已放弃」，让设置页和后续启动都误判。
pub fn abandon_migration(target: &LocalVault) -> Result<()> {
    if target.meta_get(MIGRATION_MARKER)?.is_some() {
        return Ok(());
    }
    target.meta_set(MIGRATION_MARKER, &format!("abandoned:{}", now_secs()))
}

/// 用户显式重试：忽略自动重试上限；若是 `abandoned:` 先清标记再跑；已完成则 `already_done`。
pub fn retry_migration(
    source: &dyn Vault,
    target: &LocalVault,
    refs: Vec<String>,
) -> Result<MigrationOutcome> {
    if is_abandoned(target.meta_get(MIGRATION_MARKER)?.as_deref()) {
        target.meta_delete(MIGRATION_MARKER)?;
    }
    migrate_once(source, target, refs)
}

/// 带完成标记的迁移入口：标记存在即跳过；只有 `failed` 为空才写标记。
///
/// 每次尝试都**先**持久化 attempts / last_at（哪怕随后崩溃也留痕），失败时再写
/// last_error / failures / cleanup_pending。`cleanup_pending` **不**阻塞完成标记。
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
    let attempts = parse_attempts(target)?.saturating_add(1);
    target.meta_set(MIGRATION_ATTEMPTS, &attempts.to_string())?;
    let at = now_secs();
    target.meta_set(MIGRATION_LAST_AT, &at.to_string())?;

    let report = import_refs(source, target, &refs)?;

    // 明细先落（诊断用；失败也不影响主结果）。
    target.meta_set(MIGRATION_FAILURES, &failures_json(&report.failed))?;
    target.meta_set(
        MIGRATION_CLEANUP_PENDING,
        &failures_json(&report.cleanup_pending),
    )?;

    if report.failed.is_empty() {
        target.meta_set(MIGRATION_MARKER, &at.to_string())?;
        // 成功后清掉上一轮的失败摘要：否则「已完成」卡片上还挂着旧的失败原因。
        target.meta_delete(MIGRATION_LAST_ERROR)?;
    } else {
        let first = &report.failed[0];
        let summary = format!(
            "{} 条未迁移；首条：{} {}",
            report.failed.len(),
            first.0,
            first.1
        );
        // 原因由我们自建（引用 + 错误串），再过一遍 scrub 兜底：绝不含明文。
        target.meta_set(MIGRATION_LAST_ERROR, &crate::redact::scrub(&summary))?;
    }

    Ok(MigrationOutcome {
        report,
        already_done: false,
    })
}

fn is_abandoned(marker: Option<&str>) -> bool {
    marker.is_some_and(|m| m.starts_with("abandoned:"))
}

fn parse_attempts(target: &LocalVault) -> Result<u32> {
    Ok(target
        .meta_get(MIGRATION_ATTEMPTS)?
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(0))
}

fn parse_last_at(target: &LocalVault) -> Result<Option<i64>> {
    Ok(target
        .meta_get(MIGRATION_LAST_AT)?
        .and_then(|v| v.trim().parse::<i64>().ok()))
}

/// 解析失败明细 JSON。坏数据一律当空（诊断不是关键路径，绝不能因此挡住状态查询）。
fn parse_failures(raw: Option<&str>) -> Vec<MigrationFailure> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    let Some(items) = value.as_array() else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            Some(MigrationFailure {
                reference: item.get("reference")?.as_str()?.to_string(),
                reason: item.get("reason")?.as_str()?.to_string(),
            })
        })
        .collect()
}

fn failures_json(pairs: &[(String, String)]) -> String {
    let items: Vec<serde_json::Value> = pairs
        .iter()
        .map(|(reference, reason)| {
            // 失败原因可能拼接了底层错误串（第三方库/系统），这里再过一次 scrub 兜底：
            // `vault_meta` 只允许出现引用与自建原因。
            serde_json::json!({ "reference": reference, "reason": crate::redact::scrub(reason) })
        })
        .collect();
    serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string())
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
