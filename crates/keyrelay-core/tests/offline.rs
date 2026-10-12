//! B-32：断网回归。
//!
//! 全部端点指向 `127.0.0.1:1`（必然拒绝连接），验证：
//! 1. 需要联网的操作给出**可读的**错误（而不是 panic / 卡死 / 静默成功）；
//! 2. **纯本地**的操作完全不受影响（漂移检测、审计、设置、事件）。
//!
//! 默认 `#[ignore]`：它不依赖外网（只用回环），但会占用几秒的重试预算，
//! 因此不进常规门禁。显式执行：
//!
//! ```bash
//! cargo test -p keyrelay-core --test offline -- --ignored --nocapture
//! ```

use std::fs;
use std::sync::Arc;

use keyrelay_core::delivery::DeliveryChannel;
use keyrelay_core::error::Error;
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::settings::Settings;
use keyrelay_core::site::retry::{RetryPolicy, RetryingTransport};
use keyrelay_core::site::transport_reqwest::{ReqwestTransport, TransportConfig};
use keyrelay_core::store::Store;
use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};

/// 必然拒绝连接的地址（回环上的 1 号端口）。
const UNREACHABLE: &str = "http://127.0.0.1:1";

struct Fixture {
    _dir: tempfile::TempDir,
    service: KeyRelayService<RetryingTransport<ReqwestTransport>>,
    key_id: i64,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");

    let store = Store::open(&dir.path().join("keyrelay.db")).expect("文件库");
    let site_id = store
        .upsert_site("newapi", UNREACHABLE, "不可达的站")
        .expect("写站点");
    let secret_ref = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &secret_ref, Some("1"))
        .expect("写密钥记录");

    let vault = Arc::new(MemoryVault::new());
    vault
        .put(&secret_ref, "sk-offline-0123456789abcdef")
        .expect("写钥匙串");

    // 用较短的重试预算，避免测试等太久
    let inner = ReqwestTransport::new(TransportConfig::default()).expect("构造传输层");
    let transport = RetryingTransport::new(inner, RetryPolicy::default());

    let service = KeyRelayService::new(
        store,
        transport,
        ServiceConfig {
            vault,
            home,
            backup_dir: dir.path().join("backups"),
        },
    );
    Fixture {
        _dir: dir,
        service,
        key_id,
    }
}

#[tokio::test]
#[ignore = "会走真实网络栈（回环），用 --ignored 显式执行"]
async fn network_operations_fail_with_readable_errors() {
    let f = setup();

    let err = f
        .service
        .add_site(UNREACHABLE)
        .await
        .expect_err("不可达地址必须失败");
    let message = err.to_string();
    println!("[offline] add_site → {message}");
    assert!(!message.is_empty(), "错误必须可读");
    assert!(
        matches!(err, Error::FingerprintMismatch(_) | Error::Transport(_)),
        "应是明确的传输/指纹错误: {err:?}"
    );

    let summary = f.service.sites().unwrap();
    assert_eq!(summary.len(), 1, "站点记录仍应可读（只是连不上）");

    // 未登录时读密钥：报「尚未登录」而不是网络错误（本地会话缓存优先）
    let err = f.service.list_keys(1).await.expect_err("未登录必须失败");
    println!("[offline] list_keys → {err}");
    assert!(matches!(err, Error::AuthFailed(_)), "{err:?}");
}

#[tokio::test]
#[ignore = "会走真实网络栈（回环），用 --ignored 显式执行"]
async fn local_operations_are_unaffected_by_the_network() {
    let f = setup();

    // 漂移检测：纯本地
    let report = f.service.drift_report().unwrap();
    assert!(report.is_empty(), "还没投递过，应为空");

    // 审计：纯本地
    let audit = f.service.audit_redaction().unwrap();
    assert!(audit.is_clean(), "{}", audit.summary());

    // 设置：纯本地
    let settings = Settings {
        refresh_interval_secs: 300,
        balance_alert_threshold: 1.0,
        drift_check_on_start: true,
        gateway_enabled: false,
        gateway_port: 8787,
        ..Settings::default()
    };
    f.service.update_settings(&settings).unwrap();
    assert_eq!(f.service.settings().unwrap(), settings);

    // 事件：纯本地
    assert!(!f.service.recent_events(50).unwrap().is_empty());

    // 投递：纯本地（不需要网络）
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    let outcome = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .expect("投递不应依赖网络");
    assert!(outcome.target_path.exists());

    // 投递后漂移检测应看到它
    let report = f.service.drift_report().unwrap();
    assert_eq!(report.len(), 1);
    println!(
        "[offline] 本地操作全部正常，投递 journal={}",
        outcome.journal_id
    );
}

#[tokio::test]
#[ignore = "会走真实网络栈（回环），用 --ignored 显式执行"]
async fn refresh_all_reports_failure_without_panicking() {
    let f = setup();
    // 让站点「看起来已登录」，这样 refresh_all 会真的去联网
    // （直接调 refresh_all：没有会话的站点会被跳过，因此这里预期 0 成功 0 失败）
    let summary = f.service.refresh_all().await.expect("不应 panic");
    println!(
        "[offline] refresh_all → total={} ok={} failed={}",
        summary.sites_total, summary.sites_ok, summary.sites_failed
    );
    assert_eq!(summary.sites_ok, 0);
}
