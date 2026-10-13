//! 模型列表采集策略（B-80）。
//!
//! **为什么默认关**：采集模型清单要用某一把站点 key 调 `/v1/models`——那是
//! 「每站每轮一次**额外的带密钥请求**」：
//!
//! - 站点侧：多一条可被站点记录的调用（带 `Authorization`）；
//! - 本机侧：多一次网络往返（20 站点 = 20 次额外请求），与「20 站点刷新 ≤ 15s」
//!   的预算直接竞争；
//! - 配额侧：部分站点按调用计费/限流，用户没要求的功能不该消耗它。
//!
//! 因此默认 `enabled == false`，开启后**仍有节流**
//! （同一站点两次采集之间至少 [`ModelsPolicy::min_interval_secs`] 秒）。
//!
//! # 本模块只交付「决策」，不交付「采集」
//!
//! 这里的三个符号全是**纯函数**（不读时钟、不读环境、不碰网络）；
//! 真实的 `/v1/models` 请求走 `site/**` 的适配器。未接线声明见
//! `docs/specs/M8-S3-非功能基线与验收矩阵.md` §6.3（去向：M8-S5）。

/// 采集策略。**默认关**（`enabled == false`）——见模块文档的代价说明。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelsPolicy {
    pub enabled: bool,
    /// 同一站点两次采集之间的最小间隔（秒）。
    ///
    /// `0` 表示不节流（**不推荐**，仅测试用）——它让「每站每轮一次额外请求」
    /// 这个代价全额发生。
    pub min_interval_secs: u64,
}

impl Default for ModelsPolicy {
    /// 与 `Settings::default()` 的口径一致：功能默认关；开启后默认 1 小时一次。
    fn default() -> Self {
        Self {
            enabled: false,
            min_interval_secs: 3600,
        }
    }
}

/// **纯函数**：该站点本轮是否该采集模型列表。
///
/// 判定顺序（先关后节流）：
/// 1. `policy.enabled == false` ⇒ `false`（默认关，`last_collected_at` 是什么都不看）；
/// 2. `last_collected_at == None`（从没采过）⇒ `true`；
/// 3. `now < last`（**时钟回拨**）⇒ `false`——宁可少采一次，
///    也不在回拨后连采（回拨会让「距上次多久」这个量失去意义）；
/// 4. `now - last < min_interval_secs` ⇒ `false`（节流，**边界含**：
///    `now - last == min_interval_secs` 时采）；
/// 5. 其余 ⇒ `true`。
///
/// `min_interval_secs == 0` 时第 4 步恒过 ⇒ 不节流（第 5 条规则的显式用例）。
pub fn should_collect_models(
    policy: ModelsPolicy,
    last_collected_at: Option<i64>,
    now: i64,
) -> bool {
    if !policy.enabled {
        return false;
    }
    let Some(last) = last_collected_at else {
        return true;
    };
    if now < last {
        return false;
    }
    // `u64` 化之前先减：`now >= last` 已由上面保证，差值非负。
    (now - last) as u64 >= policy.min_interval_secs
}

/// 合并新旧模型清单。
///
/// 三条性质（按重要性排）：
/// 1. **失败即无变化**：`fetched == None`（本轮采集失败）⇒ 原样返回 `previous`，
///    **不清空**。站点临时少报/报错都不该让路由丢掉上游；
/// 2. **只增不删**：`previous` 的每一项都保留（哪怕本轮已经没有了）；
/// 3. **保序去重**：先按 `previous` 的顺序，再按 `fetched` 里**新出现**的顺序，
///    已存在的项不重复插入。
pub fn merge_models(previous: &[String], fetched: Option<&[String]>) -> Vec<String> {
    let Some(fetched) = fetched else {
        return previous.to_vec();
    };
    let mut out: Vec<String> = Vec::with_capacity(previous.len() + fetched.len());
    for name in previous.iter().chain(fetched.iter()) {
        if !out.iter().any(|kept| kept == name) {
            out.push(name.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(enabled: bool, min_interval_secs: u64) -> ModelsPolicy {
        ModelsPolicy {
            enabled,
            min_interval_secs,
        }
    }

    #[test]
    fn models_policy_defaults_to_disabled() {
        let default = ModelsPolicy::default();
        assert!(!default.enabled, "B-80：默认必须是关");
        assert_eq!(default.min_interval_secs, 3600, "开启后的默认节流是 1 小时");
    }

    #[test]
    fn disabled_policy_never_collects() {
        // 关的时候连「从没采过」都不采——默认关的口径不能被绕过
        assert!(!should_collect_models(ModelsPolicy::default(), None, 1_000));
        // 间隔再大也不采（`last` 与 `now` 都无所谓）
        assert!(!should_collect_models(policy(false, 0), Some(1), 1_000));
    }

    #[test]
    fn first_collection_always_allowed_when_enabled() {
        assert!(should_collect_models(policy(true, 3600), None, 1_000));
    }

    #[test]
    fn throttle_boundary_is_inclusive() {
        // `now - last == min_interval` ⇒ 采（边界含）；少一秒 ⇒ 不采
        assert!(should_collect_models(policy(true, 100), Some(1_000), 1_100));
        assert!(!should_collect_models(
            policy(true, 100),
            Some(1_000),
            1_099
        ));
    }

    #[test]
    fn zero_interval_disables_throttling() {
        assert!(should_collect_models(policy(true, 0), Some(1_000), 1_000));
        assert!(should_collect_models(policy(true, 0), Some(1_000), 1_001));
    }

    #[test]
    fn clock_rollback_does_not_trigger_collection() {
        // 时钟回拨（`now < last`）⇒ 不采：回拨后「距上次多久」没有意义，
        // 连采会让站点侧多出一次带密钥请求，而用户什么都没变。
        assert!(!should_collect_models(policy(true, 1), Some(2_000), 1_999));
        assert!(!should_collect_models(policy(true, 0), Some(2_000), 0));
        // 回拨**之后**再走到正间隔，仍然要等满 min_interval（不是从 0 重新算）
        assert!(!should_collect_models(
            policy(true, 100),
            Some(2_000),
            2_050
        ));
        assert!(should_collect_models(policy(true, 100), Some(2_000), 2_100));
    }

    #[test]
    fn merge_models_keeps_order_dedupes_and_never_drops() {
        let previous = vec!["gpt-4".to_string(), "gpt-4o".to_string()];
        let fetched = vec![
            "gpt-4o".to_string(),   // 已存在：不重复插入
            "claude-3".to_string(), // 新项：追加在后面
            "gpt-4".to_string(),    // 旧项又出现：仍然不重复
        ];
        assert_eq!(
            merge_models(&previous, Some(&fetched)),
            vec![
                "gpt-4".to_string(),
                "gpt-4o".to_string(),
                "claude-3".to_string()
            ],
            "顺序 = previous 的旧序 + fetched 的新序；重复项只留第一次"
        );

        // 只增不删：本轮少报的旧项仍在
        assert_eq!(
            merge_models(&previous, Some(&["gpt-4".to_string()])),
            vec!["gpt-4".to_string(), "gpt-4o".to_string()],
            "站点临时少报不该让路由丢掉上游"
        );
    }

    #[test]
    fn merge_models_treats_failure_as_no_change() {
        let previous = vec!["gpt-4".to_string()];
        // 采集失败 ⇒ 原样返回（不清空、不补空 vec）
        assert_eq!(merge_models(&previous, None), previous);
        // 显式空列表 ≠ 失败：它是「站点说一个都没有」，仍然不清空 previous
        assert_eq!(merge_models(&previous, Some(&[])), previous);
        // previous 本来就是空：失败仍是空
        assert_eq!(merge_models(&[], None), Vec::<String>::new());
    }
}
