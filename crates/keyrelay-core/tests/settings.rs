//! 设置的持久化与回退（M3-S1 spec §7）。

use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::settings::{Settings, MAX_REFRESH_INTERVAL_SECS};
use keyrelay_core::site::transport::MockTransport;
use keyrelay_core::store::Store;

fn service_on(path: &std::path::Path) -> KeyRelayService<MockTransport> {
    let store = Store::open(path).expect("文件库");
    KeyRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig::in_memory(path.parent().unwrap().join("home")),
    )
}

#[test]
fn defaults_are_returned_on_a_fresh_database() {
    let dir = tempfile::tempdir().unwrap();
    let service = service_on(&dir.path().join("keyrelay.db"));
    assert_eq!(service.settings().unwrap(), Settings::default());
    assert!(
        !service.settings().unwrap().scheduler_enabled(),
        "定时刷新必须默认关闭"
    );
}

#[test]
fn settings_survive_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keyrelay.db");

    let wanted = Settings {
        refresh_interval_secs: 900,
        balance_alert_threshold: 5.5,
        drift_check_on_start: false,
        gateway_enabled: true,
        gateway_port: 9999,
    };
    service_on(&path).update_settings(&wanted).unwrap();

    // 新连接（模拟重启）
    let reopened = service_on(&path);
    assert_eq!(reopened.settings().unwrap(), wanted);
}

#[test]
fn invalid_settings_are_rejected_before_touching_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keyrelay.db");
    let service = service_on(&path);

    let bad_interval = Settings {
        refresh_interval_secs: MAX_REFRESH_INTERVAL_SECS + 1,
        ..Settings::default()
    };
    assert!(service.update_settings(&bad_interval).is_err());

    let bad_threshold = Settings {
        balance_alert_threshold: -1.0,
        ..Settings::default()
    };
    assert!(service.update_settings(&bad_threshold).is_err());

    // 拒绝之后库里仍然是默认值
    assert_eq!(service.settings().unwrap(), Settings::default());
}

#[test]
fn hand_edited_garbage_falls_back_to_defaults() {
    // 直接往 settings 表里塞垃圾（模拟手工改库 / 老版本写入）
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keyrelay.db");
    {
        let store = Store::open(&path).unwrap();
        store
            .set_setting("refresh_interval_secs", "not-a-number")
            .unwrap();
        store
            .set_setting("balance_alert_threshold", "99999999999")
            .unwrap();
        store.set_setting("drift_check_on_start", "maybe").unwrap();
    }

    let service = service_on(&path);
    let settings = service.settings().unwrap();
    assert_eq!(settings.refresh_interval_secs, 0, "非法间隔应回退默认");
    assert_eq!(
        settings.balance_alert_threshold, 99999999999.0,
        "合法但很大的阈值应保留"
    );
    assert!(settings.drift_check_on_start, "非法布尔应回退默认");
}

#[test]
fn updating_settings_writes_an_event_without_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let service = service_on(&dir.path().join("keyrelay.db"));
    service
        .update_settings(&Settings {
            refresh_interval_secs: 60,
            ..Settings::default()
        })
        .unwrap();

    let events = service.recent_events(50).unwrap();
    let updated: Vec<_> = events
        .iter()
        .filter(|e| e.message.contains("设置已更新"))
        .collect();
    assert_eq!(updated.len(), 1);
    assert!(updated[0]
        .payload
        .as_deref()
        .unwrap_or("")
        .contains("refresh_interval_secs"));
}

#[tokio::test]
async fn refresh_all_on_an_empty_installation_is_a_noop() {
    let dir = tempfile::tempdir().unwrap();
    let service = service_on(&dir.path().join("keyrelay.db"));
    let summary = service.refresh_all().await.expect("空安装应正常返回");
    assert_eq!(summary.sites_total, 0);
    assert_eq!(summary.sites_ok, 0);
    assert_eq!(summary.sites_failed, 0);
    assert!(summary.balance_alerts.is_empty());
}

#[tokio::test]
async fn refresh_all_skips_sites_without_a_session() {
    // 有站点但没登录 → 既不算成功也不算失败（用户可能压根没登录过它）
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keyrelay.db");
    let service = service_on(&path);
    service
        .store()
        .upsert_site("newapi", "https://relay.example.com", "没登录的站")
        .expect("写站点");

    let summary = service.refresh_all().await.expect("应正常返回");
    assert_eq!(summary.sites_total, 1);
    assert_eq!(summary.sites_ok, 0);
    assert_eq!(summary.sites_failed, 0, "未登录的站点不该算失败");
}
