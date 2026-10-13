//! 站点地址里的 `user:pass@`（URL userinfo）不得出现在任何出口（B-63 的另一半）。
//!
//! B-63 当初只剥了导出物里的 `sites[].base_url`，`export.rs` 那条回归测试又是用
//! `upsert_site` 直接建站、显示名硬编码——既不经过 `add_site`，也不产生事件，
//! 所以下面两条泄漏路径它都看不见（P-5：测试与实现共享同一个盲区）：
//!
//! 1. `add_site` 把原始 `base_url` 写进事件 payload（所有站点类型，M1-S3 起）；
//!    事件随后原样进入配置导出与诊断包；
//! 2. 自定义 OpenAI 兼容站点用 URL 的 host 兜底显示名，host 里带着 userinfo（M7-S2）。
//!
//! 所以这里一律走 `add_site` 这条**生产路径**，再检查全部出口。

use std::fs;
use std::sync::Arc;

use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::transport::{HttpResponse, MockTransport};
use keyrelay_core::store::Store;
use keyrelay_core::vault::MemoryVault;
use serde_json::json;

const URL_WITH_CREDS: &str = "https://alice:s3cretPW@relay.example.com";
const PASSWORD: &str = "s3cretPW";

struct Fixture {
    dir: tempfile::TempDir,
    service: KeyRelayService<MockTransport>,
}

fn setup(responses: Vec<HttpResponse>) -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let service = KeyRelayService::new(
        Store::open(&dir.path().join("keyrelay.db")).expect("文件库"),
        MockTransport::new(responses),
        ServiceConfig {
            vault: Arc::new(MemoryVault::new()),
            home,
            backup_dir: dir.path().join("backups"),
        },
    );
    Fixture { dir, service }
}

/// 逐个出口检查：事件表、明文导出、诊断包。
fn assert_no_password_in_any_outlet(f: &Fixture) {
    for event in f.service.recent_events(100).unwrap() {
        assert!(
            !event.message.contains(PASSWORD),
            "事件文案带出了 URL 密码: {}",
            event.message
        );
        assert!(
            !event.payload.as_deref().unwrap_or("").contains(PASSWORD),
            "事件 payload 带出了 URL 密码: {:?}",
            event.payload
        );
    }

    let plain_path = f.dir.path().join("plain.json");
    f.service.export_to_file(&plain_path, None).unwrap();
    let plain = fs::read_to_string(&plain_path).unwrap();
    assert!(
        !plain.contains(PASSWORD),
        "明文导出带出了 URL 密码:\n{plain}"
    );

    let diagnostics = f.service.export_diagnostics(100).unwrap();
    assert!(
        !diagnostics.contains(PASSWORD),
        "诊断包带出了 URL 密码:\n{diagnostics}"
    );
}

#[tokio::test]
async fn newapi_site_url_credentials_reach_no_outlet() {
    let f = setup(vec![HttpResponse::json(
        200,
        json!({"success": true, "data": {"version": "v0.9.1", "quota_per_unit": 500000, "system_name": "中转站"}}),
    )
    .unwrap()]);

    let summary = f.service.add_site(URL_WITH_CREDS).await.unwrap();
    assert_eq!(summary.kind, "newapi");

    assert_no_password_in_any_outlet(&f);
}

#[tokio::test]
async fn custom_site_display_name_carries_no_url_credentials() {
    let f = setup(vec![
        HttpResponse::new(404, b"".to_vec()), // NewAPI: GET /api/status
        HttpResponse::new(404, b"".to_vec()), // Sub2API: GET /api/v1/settings/public
        HttpResponse::json(200, json!({"object": "list", "data": []})).unwrap(), // 自定义兼容端点
    ]);

    let summary = f.service.add_site(URL_WITH_CREDS).await.unwrap();
    assert_eq!(summary.kind, "custom-openai-compatible");
    assert_eq!(
        summary.display_name, "relay.example.com",
        "显示名用 host 兜底时不得带 userinfo"
    );

    assert_no_password_in_any_outlet(&f);
}
