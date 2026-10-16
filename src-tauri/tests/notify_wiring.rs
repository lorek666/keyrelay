//! M16-S9：`with_notify` 的生产接线（S5 复审 P1-1）。
//!
//! 复审的发现：`KeyRelayService::with_notify` **零生产调用点** ⇒ `self.notify` 恒 `None`
//! ⇒ `dispatch_notifications` 在早退处返回 ⇒ **基线永不落库、`ModelsChanged` 永不触发**，
//! 而 spec §9 写的是「未接线：无」。
//!
//! 这组测试钉三件事：
//! 1. **开关开着时装配真的接上了**（`init_state_in_memory_with_settings` 预置
//!    `Settings::notify_enabled` 对应的设置键）⇒ 一轮 `refresh_all` 之后基线**落库**；
//! 2. **开关缺省（关）时与今天逐字相同** ⇒ 不落库（既有用户行为零变化）；
//! 3. **基线跨实例可见**（B-81 的判据，对齐复审探针 `rev_b81_baseline_survives_a_new_instance`）。
//!
//! 变异（能变红）：把 `lib.rs` 装配里的 `service.with_notify(config)` 去掉 ⇒ 测试 1 红。

use keyrelay_core::notify::BASELINE_SETTING_KEY;

/// 开关开着 ⇒ 装配把 `with_notify` 接上 ⇒ `refresh_all` 之后基线落库。
///
/// 开关走的是 **`Settings::notify_enabled`**（M16-S9 第二步：它不再是独立的 KV 兜底路径，
/// 而是设置结构体自己的字段；测试预置的就是它读的那个键 ⇒ 单一事实来源）。
///
/// `notify_system_enabled=false` + 无 webhook ⇒ 只跑 `evaluate` 与基线落库，
/// **不构造任何通知器**（不会真的弹系统通知、也不会发网络请求）。
#[test]
fn notify_enabled_wires_the_service_and_persists_a_baseline() {
    let state = keyrelay_lib::init_state_in_memory_with_settings(&[
        ("notify_enabled", "true"),
        ("notify_system_enabled", "false"),
    ]);
    let store = state.service.store();

    assert_eq!(
        store.get_setting(BASELINE_SETTING_KEY).expect("读设置"),
        None,
        "前置：还没跑过刷新，不应有基线"
    );

    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(state.service.refresh_all())
        .expect("refresh_all 应成功");

    let baseline = store
        .get_setting(BASELINE_SETTING_KEY)
        .expect("读设置")
        .expect("开关开着时，一轮刷新之后基线必须落库（P1-1 的判据）");
    assert!(
        baseline.contains("\"v\":1"),
        "落库形态应带格式版本: {baseline}"
    );
}

/// 开关**缺省**（关）⇒ 与今天逐字相同：`with_notify` 不被调用 ⇒ 基线不落库。
///
/// 这条是「不得改变既有用户行为」的守护：今天 `self.notify` 恒 `None`，
/// 早退之后什么都不发生。
#[test]
fn notify_disabled_by_default_changes_nothing() {
    let state = keyrelay_lib::init_state_in_memory();
    let store = state.service.store();

    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(state.service.refresh_all())
        .expect("refresh_all 应成功");

    assert_eq!(
        store.get_setting(BASELINE_SETTING_KEY).expect("读设置"),
        None,
        "总开关没开 ⇒ 不得落库（行为与今天逐字相同）"
    );
}

/// B-81 的判据（对齐复审探针 `rev_b81_baseline_survives_a_new_instance`）：
/// 基线落库后，**同库的新实例**仍看得到它。
#[test]
fn baseline_survives_a_new_instance_on_the_same_db() {
    let dir = tempfile::tempdir().expect("临时目录");
    let db = dir.path().join("keyrelay.db");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("home");

    let config = || keyrelay_core::service::ServiceConfig::in_memory(home.clone());
    let service_with_notify = || {
        let store = keyrelay_core::store::Store::open(&db).expect("开库");
        keyrelay_core::service::KeyRelayService::new(
            store,
            keyrelay_core::site::transport::MockTransport::default(),
            config(),
        )
        .with_notify(keyrelay_core::notify::NotifyConfig {
            system_enabled: false,
            webhook_url: None,
            balance_threshold: 0.0,
            timeout: std::time::Duration::from_secs(10),
        })
    };

    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime
        .block_on(service_with_notify().refresh_all())
        .expect("第一轮刷新");

    // 新实例（同库）：读得到上一轮落下的基线
    let second = service_with_notify();
    let baseline = second
        .store()
        .get_setting(BASELINE_SETTING_KEY)
        .expect("读设置")
        .expect("新实例应看得到落库的基线");
    assert!(baseline.contains("\"v\":1"), "形态: {baseline}");
}
