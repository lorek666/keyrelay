//! 密钥轮换判定（M6-S4 / PRD FR-7）。
//!
//! 本模块只做两件事：**判定**哪些 key 该轮换（[`due_keys`]，纯函数），以及**定义**轮换三连的
//! 顺序（[`rotation_steps`]）。真正的编排（新 key → 全量重注入 → 旧 key 回收）由 M6-S5 接线
//! （章程 §4.5）。
//!
//! 边界：
//! - **不读时钟**：`now` 由调用方传入，因此 `due_keys` 可复现、可测试；
//! - **不碰钥匙串、不含密钥**：输入输出只有 id / 名称 / 时间戳；
//! - **零跨模块依赖**（只用 `std`）：`lib.rs` 的 `pub mod rotation;` 是 Lead 写域（章程 §3），
//!   在它落地之前本文件由 `tests/rotation.rs` 以 `#[path]` 方式包含编译，见该测试文件顶部说明。
//!
//! 与 `crate::store::KeyRow` 的关系见 M6-S4 spec §4.4（接口异议 O-2）：`store::KeyRow`
//! 没有 `created_at` 字段，而判定必须知道创建时间，故本模块自带输入行类型。

const SECONDS_PER_DAY: i64 = 86_400;

/// 轮换策略。
///
/// `max_age_days == 0` 表示**关闭**轮换提醒（与 M6-S5 §2.1 的设置语义一致）；
/// `warn_before_days` 是提前提醒的天数。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationPolicy {
    pub max_age_days: u32,
    pub warn_before_days: u32,
}

impl Default for RotationPolicy {
    /// 与 M6-S5 §2.1 的设置默认一致：30 天到期、提前 7 天提醒。
    fn default() -> Self {
        Self {
            max_age_days: 30,
            warn_before_days: 7,
        }
    }
}

/// 判定输入行。
///
/// **不是** `crate::store::KeyRow`（见模块文档）：本类型只需要判定用得到的四个字段，
/// 且 `created_at` 必须是 `Option<i64>`——「缺失」与「1970-01-01」是两件事。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRow {
    pub id: i64,
    pub site_id: i64,
    pub name: String,
    /// 站点给出的创建时间（unix 秒）。`None` = 无法判定到期。
    pub created_at: Option<i64>,
}

impl KeyRow {
    pub fn new(id: i64, site_id: i64, name: impl Into<String>, created_at: Option<i64>) -> Self {
        Self {
            id,
            site_id,
            name: name.into(),
            created_at,
        }
    }
}

/// 一条「该轮换了」的判定结果。只含 id / 名称 / 时间戳，**不含密钥或钥匙串引用**。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationDue {
    pub key_id: i64,
    pub site_id: i64,
    pub name: String,
    pub created_at: i64,
    pub due_at: i64,
}

/// 判定哪些 key 到期（或已进入提醒窗口）。纯函数：同输入同输出，不读时钟、不读环境。
///
/// 规则（全部有测试钉住，见 M6-S4 spec §4.2）：
///
/// - `policy.max_age_days == 0` → 关闭轮换 → 返回空 `Vec`；
/// - `created_at` 缺失（`None`）→ **不进入结果**（无法判定到期，章程 §4.4 冻结语义）；
/// - `due_at = created_at + max_age_days * 86400`（饱和运算，极端时间戳不溢出）；
/// - `warn_at = max(due_at - warn_before_days * 86400, created_at)` —— 提醒窗口**钳到创建
///   时刻**，不会早于 key 的诞生时间。`warn_before_days > max_age_days` 时窗口覆盖整个
///   生命周期，于是 `now >= created_at` 的行全部进入结果；这是该配置的**显式后果**
///   （S5 §2.2 的 `Settings::validate` 在入口就拒绝该组合）；
/// - `now >= warn_at` → 进入结果（**含**边界：`now == warn_at`、`now == due_at` 都算）；
/// - 结果按 `(due_at, key_id)` 升序 —— 全序、确定。
pub fn due_keys(rows: &[KeyRow], policy: RotationPolicy, now: i64) -> Vec<RotationDue> {
    if policy.max_age_days == 0 {
        return Vec::new();
    }
    let lifetime = (policy.max_age_days as i64).saturating_mul(SECONDS_PER_DAY);
    let warn = (policy.warn_before_days as i64).saturating_mul(SECONDS_PER_DAY);

    let mut out: Vec<RotationDue> = rows
        .iter()
        .filter_map(|row| {
            let created_at = row.created_at?;
            let due_at = created_at.saturating_add(lifetime);
            let warn_at = due_at.saturating_sub(warn).max(created_at);
            if now < warn_at {
                return None;
            }
            Some(RotationDue {
                key_id: row.id,
                site_id: row.site_id,
                name: row.name.clone(),
                created_at,
                due_at,
            })
        })
        .collect();

    out.sort_by_key(|due| (due.due_at, due.key_id));
    out
}

/// 轮换三连的一步。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RotationStep {
    /// 建一把新 key
    CreateNew,
    /// 把新 key 注入到全部绑定
    ReinjectAll,
    /// 回收旧 key（破坏性操作，S5 要求 diff 预览 + 二次确认）
    RevokeOld,
}

impl RotationStep {
    /// 事件与 UI 用的稳定标识（附加 API，非章程冻结项）。
    pub fn as_str(self) -> &'static str {
        match self {
            RotationStep::CreateNew => "create_new",
            RotationStep::ReinjectAll => "reinject_all",
            RotationStep::RevokeOld => "revoke_old",
        }
    }
}

/// 轮换的固定顺序：新 key → 全量重注入 → 旧 key 回收。
///
/// 顺序**不可重排**（M6-S5 §4.1）：先回收旧 key 会造出「旧 key 已废、新 key 未注入」的死局。
pub fn rotation_steps() -> [RotationStep; 3] {
    [
        RotationStep::CreateNew,
        RotationStep::ReinjectAll,
        RotationStep::RevokeOld,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;

    fn row(id: i64, created_at: Option<i64>) -> KeyRow {
        KeyRow::new(id, 7, format!("key-{id}"), created_at)
    }

    #[test]
    fn due_keys_skips_rows_without_created_at() {
        let rows = vec![row(1, Some(0)), row(2, None), row(3, None)];
        let due = due_keys(
            &rows,
            RotationPolicy {
                max_age_days: 30,
                warn_before_days: 7,
            },
            40 * DAY,
        );
        assert_eq!(due.len(), 1, "只有带 created_at 的行能判定: {due:?}");
        assert_eq!(due[0].key_id, 1);
    }

    #[test]
    fn due_keys_boundary_is_inclusive() {
        let policy = RotationPolicy {
            max_age_days: 30,
            warn_before_days: 7,
        };
        let created = 1_000_000_i64;
        let warn_at = created + 23 * DAY; // 30 - 7
        let due_at = created + 30 * DAY;
        let rows = vec![row(1, Some(created))];

        assert!(
            due_keys(&rows, policy, warn_at - 1).is_empty(),
            "窗口前一天不得进入结果"
        );
        assert_eq!(
            due_keys(&rows, policy, warn_at).len(),
            1,
            "now == warn_at 必须进入结果（含边界）"
        );
        assert_eq!(due_keys(&rows, policy, due_at).len(), 1, "now == due_at");
        assert_eq!(
            due_keys(&rows, policy, due_at + 10 * DAY).len(),
            1,
            "已过期"
        );
    }

    #[test]
    fn due_keys_warn_window_never_starts_before_creation() {
        // warn > max：窗口被钳到 created_at —— 这是显式定义，不是「顺手」的行为。
        let policy = RotationPolicy {
            max_age_days: 30,
            warn_before_days: 45,
        };
        let now = 5_000_000_i64;

        let fresh = vec![row(1, Some(now))];
        let due = due_keys(&fresh, policy, now);
        assert_eq!(due.len(), 1, "窗口覆盖整个生命周期 → 刚建的 key 也在结果里");
        assert_eq!(due[0].created_at, now);
        assert_eq!(due[0].due_at, now + 30 * DAY);

        // 未来时间戳（站点时钟偏差）仍然不算到期
        let future = vec![row(2, Some(now + 1))];
        assert!(
            due_keys(&future, policy, now).is_empty(),
            "created_at 在未来时不得判定到期"
        );

        // warn == max 同样钳到 created_at
        let equal = RotationPolicy {
            max_age_days: 30,
            warn_before_days: 30,
        };
        assert_eq!(due_keys(&fresh, equal, now).len(), 1);
    }

    #[test]
    fn due_keys_disabled_when_max_age_is_zero() {
        let rows = vec![row(1, Some(0)), row(2, Some(0))];
        for warn in [0u32, 7, 999] {
            let due = due_keys(
                &rows,
                RotationPolicy {
                    max_age_days: 0,
                    warn_before_days: warn,
                },
                10 * 365 * DAY,
            );
            assert!(due.is_empty(), "max_age_days == 0 表示关闭轮换");
        }
    }

    #[test]
    fn due_keys_is_sorted_and_deterministic() {
        let policy = RotationPolicy {
            max_age_days: 30,
            warn_before_days: 7,
        };
        let now = 1_000 * DAY;
        let rows = vec![
            row(9, Some(now - 40 * DAY)), // due_at 最早
            row(3, Some(now - 25 * DAY)), // 同 due_at
            row(1, Some(now - 25 * DAY)), // 同 due_at，id 更小 → 排前
            row(7, Some(now)),            // 未到期
        ];
        let due = due_keys(&rows, policy, now);
        let ids: Vec<i64> = due.iter().map(|d| d.key_id).collect();
        assert_eq!(ids, vec![9, 1, 3], "按 (due_at, key_id) 升序");

        // 同输入同输出（输入顺序打乱也一样）
        let mut shuffled = rows.clone();
        shuffled.reverse();
        let again = due_keys(&shuffled, policy, now);
        assert_eq!(due, again, "结果与输入顺序无关");
    }

    #[test]
    fn due_keys_saturates_on_extreme_timestamps() {
        let policy = RotationPolicy {
            max_age_days: u32::MAX,
            warn_before_days: u32::MAX,
        };
        let rows = vec![
            row(1, Some(i64::MAX - 1)),
            row(2, Some(i64::MIN)),
            row(3, Some(i64::MAX)),
        ];
        let due = due_keys(&rows, policy, i64::MAX);
        // 不 panic、不溢出；i64::MIN 那行必然早就过期
        assert!(due.iter().any(|d| d.key_id == 2));
        assert!(due.iter().all(|d| d.due_at >= d.created_at));
    }

    #[test]
    fn rotation_steps_order_is_frozen() {
        assert_eq!(
            rotation_steps(),
            [
                RotationStep::CreateNew,
                RotationStep::ReinjectAll,
                RotationStep::RevokeOld
            ]
        );
        assert_eq!(RotationStep::CreateNew.as_str(), "create_new");
        assert_eq!(RotationStep::ReinjectAll.as_str(), "reinject_all");
        assert_eq!(RotationStep::RevokeOld.as_str(), "revoke_old");
    }

    #[test]
    fn rotation_policy_default_matches_settings_defaults() {
        let policy = RotationPolicy::default();
        assert_eq!(policy.max_age_days, 30);
        assert_eq!(policy.warn_before_days, 7);
    }

    #[test]
    fn key_row_new_keeps_fields_verbatim() {
        let r = KeyRow::new(11, 3, "codex/daily", Some(123));
        assert_eq!(
            r,
            KeyRow {
                id: 11,
                site_id: 3,
                name: "codex/daily".to_string(),
                created_at: Some(123),
            }
        );
    }

    #[test]
    fn rotation_never_carries_a_secret() {
        let rows = vec![row(1, Some(0))];
        let due = due_keys(&rows, RotationPolicy::default(), 100 * DAY);
        let text = format!("{rows:?} {due:?}");
        assert!(!text.contains("sk-"), "轮换判定不得携带密钥: {text}");
        assert!(!text.contains("nap-"));
        assert!(!text.contains("kr/"), "也不得携带钥匙串引用: {text}");
    }
}
