//! DSH 凭据引用校验的端到端验证（DELIVERY-P0-3）。
//!
//! 全部把 `home` 指向临时目录，绝不触碰用户真实的 `~/.dsh`。
//! 校验只读 profile 文件：每条用例都断言 profile 文件在投递前后字节一致。

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use tianshu_relay_core::delivery::DeliveryChannel;
use tianshu_relay_core::service::{ServiceConfig, TianshuRelayService};
use tianshu_relay_core::site::transport::MockTransport;
use tianshu_relay_core::store::Store;
use tianshu_relay_core::vault::{secret_ref, MemoryVault, Vault};

const SECRET: &str = "<redacted>";
const BASE_URL: &str = "https://relay.example.com";
const CHANNEL: DeliveryChannel = DeliveryChannel::DeepSeekHarness;

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    service: TianshuRelayService<MockTransport>,
    key_id: i64,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let db_path = dir.path().join("tianshu-relay.db");

    let store = Store::open(&db_path).expect("文件库");
    let site_id = store
        .upsert_site("newapi", BASE_URL, "测试站")
        .expect("写站点");
    let secret = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "dsh/daily", &secret, Some("1"), None)
        .expect("写密钥记录");

    let vault = Arc::new(MemoryVault::new());
    vault.put(&secret, SECRET).expect("写钥匙串");

    let service = TianshuRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault,
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
        },
    );

    Fixture {
        _dir: dir,
        home,
        service,
        key_id,
    }
}

fn profile_path(f: &Fixture, profile: &str) -> PathBuf {
    f.home
        .join(".dsh")
        .join("profiles")
        .join(profile)
        .join("cordis.patch.yml")
}

fn write_profile(f: &Fixture, profile: &str, content: &str) -> PathBuf {
    let path = profile_path(f, profile);
    fs::create_dir_all(path.parent().unwrap()).expect("建 profile 目录");
    fs::write(&path, content).expect("写 profile");
    path
}

fn credentials_path(f: &Fixture) -> PathBuf {
    f.home.join(".dsh").join(".credentials.yaml")
}

#[test]
fn referenced_profile_passes_plan_and_apply_and_leaves_profile_untouched() {
    let f = setup();
    let profile = write_profile(
        &f,
        "desktop",
        "providers:\n  keyrelay:\n    apiKeyEnv: KEYRELAY_API_KEY\n    baseURL: https://relay.example.com/v1\n",
    );
    let before = fs::read(&profile).unwrap();

    let plan = f.service.delivery_plan(f.key_id, CHANNEL).expect("预览");
    let check = plan
        .dsh_credential_reference
        .expect("DSH 预览应带引用校验结果");
    assert!(check.is_referenced(), "已引用的预览应为已引用：{check:?}");
    assert_eq!(check.referencing_files, vec![profile.clone()]);

    f.service.grant_consent(f.key_id, CHANNEL).expect("同意");
    let outcome = f
        .service
        .apply_delivery(f.key_id, CHANNEL)
        .expect("已引用时投递应通过");
    assert_eq!(outcome.target_path, credentials_path(&f));
    assert!(
        fs::read_to_string(credentials_path(&f))
            .unwrap()
            .contains(SECRET),
        "凭据应已写进 credentials.yaml"
    );
    assert_eq!(
        fs::read(&profile).unwrap(),
        before,
        "校验不得改写 profile 文件"
    );
}

#[test]
fn unreferenced_profile_rejects_apply_before_any_write() {
    let f = setup();
    let profile = write_profile(
        &f,
        "desktop",
        "providers:\n  keyrelay:\n    apiKeyEnv: TIANSHU_API_KEY\n",
    );
    let before = fs::read(&profile).unwrap();

    // 预览不直接报错，但必须展示“未引用及去向”。
    let plan = f.service.delivery_plan(f.key_id, CHANNEL).expect("预览");
    let check = plan
        .dsh_credential_reference
        .expect("DSH 预览应带引用校验结果");
    assert!(!check.is_referenced(), "未引用的预览不得报已引用");
    assert_eq!(check.checked_files, vec![profile.clone()]);

    f.service.grant_consent(f.key_id, CHANNEL).expect("同意");
    let err = f
        .service
        .apply_delivery(f.key_id, CHANNEL)
        .unwrap_err()
        .to_string();
    assert!(err.contains("dsh"), "{err}");
    assert!(err.contains("KEYRELAY_API_KEY"), "{err}");
    assert!(err.contains("cordis.patch.yml"), "{err}");
    assert!(err.contains("apiKeyEnv"), "{err}");
    assert!(
        !credentials_path(&f).exists(),
        "整单拒绝时凭据文件一个字节都不应写"
    );
    assert_eq!(
        fs::read(&profile).unwrap(),
        before,
        "拒绝不得改写 profile 文件"
    );
}

#[test]
fn no_profile_files_reject_with_distinct_guidance() {
    let f = setup();
    let plan = f.service.delivery_plan(f.key_id, CHANNEL).expect("预览");
    let check = plan
        .dsh_credential_reference
        .expect("DSH 预览应带引用校验结果");
    assert!(check.has_no_profiles(), "无 profile 时应为无 profile 状态");
    assert!(!check.is_referenced());

    f.service.grant_consent(f.key_id, CHANNEL).expect("同意");
    let err = f
        .service
        .apply_delivery(f.key_id, CHANNEL)
        .unwrap_err()
        .to_string();
    assert!(err.contains("未找到任何 profile patch 文件"), "{err}");
    assert!(err.contains("profiles"), "{err}");
    assert!(err.contains("apiKeyEnv: KEYRELAY_API_KEY"), "{err}");
    assert!(!credentials_path(&f).exists(), "无 profile 时同样不得写盘");
}

#[test]
fn multi_profile_any_one_reference_passes() {
    let f = setup();
    write_profile(&f, "desktop", "apiKeyEnv: TIANSHU_API_KEY\n");
    write_profile(&f, "work", "apiKeyEnv: KEYRELAY_API_KEY\n");
    f.service.grant_consent(f.key_id, CHANNEL).expect("同意");
    f.service
        .apply_delivery(f.key_id, CHANNEL)
        .expect("多 profile 时至少一个引用即应通过");
    assert!(credentials_path(&f).exists());
}

#[test]
fn removing_the_reference_flips_delivery_to_rejection_and_restoring_passes() {
    // 反向验证：同一单先通过 → 删掉引用 → 被拒绝且文案含去向 → 恢复引用 → 再通过。
    let f = setup();
    let profile = write_profile(&f, "desktop", "apiKeyEnv: KEYRELAY_API_KEY\n");
    f.service.grant_consent(f.key_id, CHANNEL).expect("同意");
    f.service
        .apply_delivery(f.key_id, CHANNEL)
        .expect("有引用时应通过");

    fs::write(&profile, "apiKeyEnv: TIANSHU_API_KEY\n").expect("删掉引用");
    let err = f
        .service
        .apply_delivery(f.key_id, CHANNEL)
        .unwrap_err()
        .to_string();
    assert!(err.contains("cordis.patch.yml"), "{err}");
    assert!(err.contains("apiKeyEnv"), "{err}");

    fs::write(&profile, "apiKeyEnv: KEYRELAY_API_KEY\n").expect("恢复引用");
    f.service
        .apply_delivery(f.key_id, CHANNEL)
        .expect("恢复引用后应重新通过");
}

#[test]
fn non_dsh_channel_plan_carries_no_reference_check() {
    let f = setup();
    let plan = f
        .service
        .delivery_plan(f.key_id, DeliveryChannel::CodexAuthJson)
        .expect("预览");
    assert!(
        plan.dsh_credential_reference.is_none(),
        "非 DSH 通道的预览不得带 DSH 引用校验结果"
    );
}
