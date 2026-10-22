//! M6-S4 集成测试：**密钥轮换判定**（`crates/tianshu-relay-core/src/rotation.rs`）。
//!
//! M6-S4 交付时 `rotation.rs` 还没被 `lib.rs` 导出，本文件用 `#[path = "../src/rotation.rs"]`
//! 把源文件编进测试 crate 才跑得起来。S5 已经加了 `pub mod rotation;`（`lib.rs:20`），
//! 因此 **task-17 / P2-3** 把桥拆掉、改成常规的 `tianshu_relay_core::rotation` import：
//!
//! - `#[path]` 会让模块内 10 条单测每轮跑两遍（`--test rotation` = 20 条）；
//! - 更要紧的是：桥不引用库里的模块，于是「`lib.rs` 的导出被删/改名」这类缺陷**测不出来**
//!   ——本文件会照常全绿，而产品里那个模块已不可达。改成常规 import 后这件事由编译器强制。
//!
//! 模块内的 `#[cfg(test)] mod tests` 覆盖同一套规则（跑在 lib 单测里）；这里放**边界探针**。

use tianshu_relay_core::rotation::{
    due_keys, rotation_steps, KeyRow, RotationPolicy, RotationStep,
};

const DAY: i64 = 86_400;

fn row(id: i64, site_id: i64, created_at: Option<i64>) -> KeyRow {
    KeyRow::new(id, site_id, format!("key-{id}"), created_at)
}

#[test]
fn due_keys_probe_created_at_none_is_skipped() {
    // 复审探针：`created_at = None` 的行**不**进入结果，哪怕 now 已经是「永远之后」。
    let rows = vec![
        row(1, 7, Some(0)),
        row(2, 7, None),
        row(3, 8, Some(0)),
        row(4, 8, None),
    ];
    let due = due_keys(
        &rows,
        RotationPolicy {
            max_age_days: 30,
            warn_before_days: 7,
        },
        i64::MAX,
    );
    let ids: Vec<i64> = due.iter().map(|d| d.key_id).collect();
    assert_eq!(ids, vec![1, 3], "只有带 created_at 的行能判定到期");
    assert!(
        due.iter().all(|d| d.created_at >= 0),
        "结果里的 created_at 必须来自输入行"
    );
}

#[test]
fn due_keys_probe_boundary_is_inclusive() {
    let policy = RotationPolicy {
        max_age_days: 30,
        warn_before_days: 7,
    };
    let created = 1_700_000_000_i64;
    let warn_at = created + 23 * DAY;
    let due_at = created + 30 * DAY;
    let rows = vec![row(1, 7, Some(created))];

    assert!(due_keys(&rows, policy, warn_at - 1).is_empty());
    assert_eq!(
        due_keys(&rows, policy, warn_at).len(),
        1,
        "now == warn_at 含"
    );
    assert_eq!(due_keys(&rows, policy, warn_at + 1).len(), 1);
    assert_eq!(due_keys(&rows, policy, due_at).len(), 1, "now == due_at 含");
    assert_eq!(due_keys(&rows, policy, due_at + DAY).len(), 1, "过期仍含");

    let only = due_keys(&rows, policy, warn_at);
    assert_eq!(only[0].due_at, due_at, "due_at = created_at + max_age");
    assert_eq!(only[0].site_id, 7);
    assert_eq!(only[0].name, "key-1");
}

#[test]
fn due_keys_probe_warn_zero_waits_for_the_deadline() {
    // `warn_before_days = 0`：窗口退化成「到期那一刻」，边界仍是闭区间。
    let policy = RotationPolicy {
        max_age_days: 30,
        warn_before_days: 0,
    };
    let created = 1_000_000_i64;
    let due_at = created + 30 * DAY;
    let rows = vec![row(1, 7, Some(created))];

    assert!(due_keys(&rows, policy, due_at - 1).is_empty());
    assert_eq!(due_keys(&rows, policy, due_at).len(), 1);
}

#[test]
fn due_keys_probe_warn_gt_max_clamps_to_creation() {
    // 复审探针：`warn_before_days > max_age_days` 的定义 —— 窗口钳到 created_at。
    let policy = RotationPolicy {
        max_age_days: 30,
        warn_before_days: 45,
    };
    let now = 1_800_000_000_i64;

    let fresh = vec![row(1, 7, Some(now))];
    assert_eq!(
        due_keys(&fresh, policy, now).len(),
        1,
        "窗口覆盖整个生命周期 → 刚建的 key 也在结果里（显式定义）"
    );
    assert!(
        due_keys(&fresh, policy, now - 1).is_empty(),
        "窗口不早于 created_at"
    );

    // 站点时钟偏差：created_at 在未来
    let future = vec![row(2, 7, Some(now + DAY))];
    assert!(due_keys(&future, policy, now).is_empty());

    // warn == max 等价于钳到 created_at
    let equal = RotationPolicy {
        max_age_days: 30,
        warn_before_days: 30,
    };
    assert_eq!(due_keys(&fresh, equal, now).len(), 1);
}

#[test]
fn due_keys_probe_disabled_when_max_age_is_zero() {
    // S5 §2.2：`max_age_days == 0` = 关闭轮换提醒。此时 warn 怎么填都不判定。
    let rows = vec![row(1, 7, Some(0)), row(2, 8, Some(0))];
    for warn in [0u32, 1, 30, u32::MAX] {
        let due = due_keys(
            &rows,
            RotationPolicy {
                max_age_days: 0,
                warn_before_days: warn,
            },
            100 * 365 * DAY,
        );
        assert!(due.is_empty(), "warn={warn} 时仍不得判定到期");
    }
}

#[test]
fn due_keys_probe_is_a_total_order_and_deterministic() {
    let policy = RotationPolicy {
        max_age_days: 10,
        warn_before_days: 2,
    };
    let now = 500 * DAY;
    let rows = vec![
        row(5, 1, Some(now - 20 * DAY)),
        row(2, 2, Some(now - 12 * DAY)),
        row(1, 3, Some(now - 12 * DAY)),
        row(9, 4, Some(now)), // 未到期
        row(7, 5, None),
    ];
    let due = due_keys(&rows, policy, now);
    let ids: Vec<i64> = due.iter().map(|d| d.key_id).collect();
    assert_eq!(ids, vec![5, 1, 2], "按 (due_at, key_id) 升序");

    // 输入顺序不影响输出
    let mut reversed = rows.clone();
    reversed.reverse();
    assert_eq!(due, due_keys(&reversed, policy, now));

    // 重复调用同结果
    assert_eq!(due, due_keys(&rows, policy, now));
}

#[test]
fn due_keys_probe_saturates_instead_of_panicking() {
    let policy = RotationPolicy {
        max_age_days: u32::MAX,
        warn_before_days: u32::MAX,
    };
    let rows = vec![
        row(1, 7, Some(i64::MAX)),
        row(2, 7, Some(i64::MIN)),
        row(3, 7, Some(i64::MAX / 2)),
    ];
    let due = due_keys(&rows, policy, i64::MAX);
    assert!(due.iter().any(|d| d.key_id == 2), "i64::MIN 必然过期");
    assert!(due.iter().all(|d| d.due_at >= d.created_at), "{due:?}");
}

#[test]
fn rotation_steps_probe_order_is_frozen() {
    assert_eq!(
        rotation_steps(),
        [
            RotationStep::CreateNew,
            RotationStep::ReinjectAll,
            RotationStep::RevokeOld
        ],
        "顺序不可重排（S5 §4.1：任一环失败即停）"
    );
    let labels: Vec<&str> = rotation_steps().iter().map(|s| s.as_str()).collect();
    assert_eq!(labels, vec!["create_new", "reinject_all", "revoke_old"]);
}

#[test]
fn rotation_policy_probe_defaults_match_settings() {
    let policy = RotationPolicy::default();
    assert_eq!(policy.max_age_days, 30, "S5 §2.1 的 rotation_max_age_days");
    assert_eq!(
        policy.warn_before_days, 7,
        "S5 §2.1 的 rotation_warn_before_days"
    );
}

#[test]
fn rotation_probe_never_carries_a_secret() {
    let rows = vec![row(1, 7, Some(0))];
    let due = due_keys(&rows, RotationPolicy::default(), 100 * DAY);
    let text = format!("{rows:?} {due:?} {:?}", rotation_steps());
    assert!(!text.contains("sk-"), "不得携带密钥: {text}");
    assert!(!text.contains("nap-"), "不得携带密钥: {text}");
    assert!(!text.contains("kr/"), "不得携带钥匙串引用: {text}");
}
