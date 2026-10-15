//! 轮换预检（M8-S4 §9-8 / P2-3）：**建新 key 之前**先证明每个通道都写得进去。
//!
//! 复现 P2-3 要看的数字：目标写不进时（用户删了 `config.yaml` 的受管块、文件被重置成
//! `models: []` 之类），旧实现会**先建好新 key**、再在重注入那一步停下 ⇒
//! **每重试一次，站点上就多一把没人用的 key**。本文件钉的就是那个数字：预检失败 ⇒
//! 站点上**一把新 key 都没有**。

use std::fs;
use std::sync::Arc;

use keyrelay_core::delivery::DeliveryChannel;
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::transport::{HttpResponse, MockTransport};
use keyrelay_core::site::{Credentials, KeySpec};
use keyrelay_core::store::Store;
use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};
use serde_json::json;

const SECRET: &str = "sk-rot-0123456789abcdef";
const NEW_SECRET: &str = "sk-rot-newkey0123456789";
const BASE: &str = "https://relay.example.com";

struct Fixture {
    _dir: tempfile::TempDir,
    service: KeyRelayService<MockTransport>,
    mock: MockTransport,
    key_id: i64,
    home: std::path::PathBuf,
}

fn encryption_disabled() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": {"enabled": false}})).unwrap()
}

fn login_ok() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": {"id": 7}}))
        .unwrap()
        .with_header("Set-Cookie", "session=abc; Path=/")
}

fn create_key_ok() -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"success": true, "data": {"key": NEW_SECRET, "id": 2}}),
    )
    .unwrap()
}

fn delete_ok() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "message": ""})).unwrap()
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let store = Store::open(&dir.path().join("keyrelay.db")).unwrap();
    let site_id = store.upsert_site("newapi", BASE, "测试站").unwrap();
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &reference, Some("1"), None)
        .unwrap();
    let vault = Arc::new(MemoryVault::new());
    vault.put(&reference, SECRET).unwrap();
    let mock = MockTransport::new(vec![]);
    let service = KeyRelayService::new(
        store,
        mock.clone(),
        ServiceConfig {
            vault,
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
        },
    );
    mock.push(encryption_disabled());
    mock.push(login_ok());
    service
        .login(site_id, Credentials::new("me", "pw"))
        .await
        .unwrap();
    Fixture {
        _dir: dir,
        service,
        mock,
        key_id,
        home,
    }
}

/// 站点侧有多少把 key（用假传输数「创建」请求数：预检失败时必须是 **0**）。
fn created_on_site(f: &Fixture) -> usize {
    f.mock
        .requests()
        .iter()
        .filter(|r| {
            r.url.contains("/api/token/")
                && r.method == keyrelay_core::site::transport::Method::Post
        })
        .count()
}

/// 让 Continue 的落点**写不进去**：文件里有一个残缺的受管块（只有开始标记）。
fn break_continue_target(f: &Fixture) {
    let path = f.home.join(".continue").join("config.yaml");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        format!(
            "name: mine\nversion: 1.0.0\nmodels:\n  {}\n",
            keyrelay_core::delivery::continue_yaml::BLOCK_BEGIN
        ),
    )
    .unwrap();
}

#[tokio::test]
async fn a_broken_target_blocks_the_rotation_before_a_new_key_exists() {
    let f = setup().await;
    // 前提：这个 agent 有绑定的通道（轮换的目标集合来自已投递的绑定）
    f.service
        .grant_consent(f.key_id, DeliveryChannel::Continue)
        .unwrap();
    f.service
        .apply_delivery_with_model(f.key_id, DeliveryChannel::Continue, Some("gpt-4o"))
        .unwrap();
    assert_eq!(created_on_site(&f), 0, "前提：还没建过 key");

    break_continue_target(&f);

    let err = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/rotated"))
        .await
        .expect_err("目标写不进去时必须在建新 key 之前拒绝");

    let text = err.to_string();
    assert!(text.contains("continue"), "{text}");
    assert!(
        text.contains("多一把") || text.contains("新密钥已建好之后"),
        "文案必须说清代价：{text}"
    );
    assert_eq!(
        created_on_site(&f),
        0,
        "预检失败 ⇒ 站点上**一把新 key 都没有**（这正是 P2-3 的判据）"
    );
}

#[tokio::test]
async fn a_healthy_target_lets_the_rotation_proceed() {
    let f = setup().await;
    f.service
        .grant_consent(f.key_id, DeliveryChannel::Continue)
        .unwrap();
    f.service
        .apply_delivery_with_model(f.key_id, DeliveryChannel::Continue, Some("gpt-4o"))
        .unwrap();

    f.mock.push(create_key_ok());
    f.mock.push(delete_ok());
    let run = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/rotated"))
        .await
        .expect("落点健康时轮换照常");

    assert!(run.completed(), "{:?}", run.stop_reason);
    assert_eq!(created_on_site(&f), 1, "只建了一把");
}

/// `models: []`（Continue 自己生成的默认模板形态）不再是**结构性**拒绝的理由，
/// 但它仍然过不了「必须有模型名」那道门——而**这一点是诚实的**：
/// 轮换的重新注入走 `model = None`（沿用受管块里已有的名字），块被清掉之后
/// 没有任何地方能取到模型名，KeyRelay 不编造（§9-12）。
///
/// 本波次的改进不是「让这种情况能轮换」，而是**在烧掉一把新 key 之前**就拒绝，
/// 并且给的理由是「要填模型名」而不是「`models:` 是行内值」。
#[tokio::test]
async fn an_empty_flow_models_block_fails_for_the_model_reason_not_the_shape() {
    let f = setup().await;
    f.service
        .grant_consent(f.key_id, DeliveryChannel::Continue)
        .unwrap();
    f.service
        .apply_delivery_with_model(f.key_id, DeliveryChannel::Continue, Some("gpt-4o"))
        .unwrap();

    // Continue 的默认模板形态：受管块被清掉、`models: []` 回来了。
    let path = f.home.join(".continue").join("config.yaml");
    fs::write(&path, "name: mine\nversion: 1.0.0\nmodels: []\n").unwrap();

    let err = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/rotated"))
        .await
        .expect_err("块被清掉之后没有模型名可沿用 ⇒ 必须在建新 key 之前拒绝");
    let text = err.to_string();
    assert!(text.contains("模型名"), "{text}");
    assert!(
        !text.contains("行内值"),
        "`models: []` 已不是「行内值」那条理由：{text}"
    );
    assert_eq!(
        created_on_site(&f),
        0,
        "拒绝发生在建新 key 之前（这正是 P2-3 的修复）"
    );
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "name: mine\nversion: 1.0.0\nmodels: []\n",
        "预检不落盘：文件一个字节都不该动"
    );
}

/// P2-2 / DEBUG-REPORT-v3 §2-2：同意被撤销的通道，`plan()` 仍然跑得通（它不读同意），
/// 于是旧实现会在建新 key **之后**的重注入步才停 ⇒ 每重试一次站点多一把。预检现在
/// 就地查 `consent_state`，在建 key 之前拒绝。
#[tokio::test]
async fn a_revoked_consent_blocks_the_rotation_before_a_new_key_exists() {
    let f = setup().await;
    f.service
        .grant_consent(f.key_id, DeliveryChannel::Continue)
        .unwrap();
    f.service
        .apply_delivery_with_model(f.key_id, DeliveryChannel::Continue, Some("gpt-4o"))
        .unwrap();
    assert_eq!(created_on_site(&f), 0, "前提：还没建过 key");

    // 撤销同意：绑定仍在（轮换目标集合来自绑定），但投递会失败
    f.service
        .revoke_consent(f.key_id, DeliveryChannel::Continue)
        .unwrap();

    let err = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/rotated"))
        .await
        .expect_err("同意被撤销时必须在建新 key 之前拒绝");
    let text = err.to_string();
    assert!(text.contains("同意已被撤销"), "文案必须点出原因: {text}");
    assert_eq!(
        created_on_site(&f),
        0,
        "预检失败 ⇒ 站点上一把新 key 都没有（P2-2）"
    );
}

/// P2-2：落点是符号链接时，`plan()` 跟着链接读到目标、跑得通，但写入会出问题；
/// 旧实现同样在建新 key 之后才停。预检现在就地查 `is_symlink`。
#[tokio::test]
#[cfg(unix)]
async fn a_symlink_target_blocks_the_rotation_before_a_new_key_exists() {
    let f = setup().await;
    f.service
        .grant_consent(f.key_id, DeliveryChannel::Continue)
        .unwrap();
    f.service
        .apply_delivery_with_model(f.key_id, DeliveryChannel::Continue, Some("gpt-4o"))
        .unwrap();
    assert_eq!(created_on_site(&f), 0);

    // 把落点换成符号链接（指向一个普通文件），同意与绑定都不动
    let path = f.home.join(".continue").join("config.yaml");
    let real = f.home.join(".continue").join("real_config.yaml");
    fs::remove_file(&path).ok();
    fs::write(&real, "name: mine\nversion: 1.0.0\nmodels:\n  - gpt-4o\n").unwrap();
    std::os::unix::fs::symlink(&real, &path).unwrap();

    let err = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/rotated"))
        .await
        .expect_err("落点是符号链接时必须在建新 key 之前拒绝");
    let text = err.to_string();
    assert!(text.contains("符号链接"), "文案必须点出原因: {text}");
    assert_eq!(
        created_on_site(&f),
        0,
        "预检失败 ⇒ 站点上一把新 key 都没有（P2-2）"
    );
}
