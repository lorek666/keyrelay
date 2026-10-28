//! DEBUG 修复波次第 3 组（轮换组）验收：P1-11 / P1-12 / P1-13 / P1-14。
//!
//! 全部测试把 `home` 指向临时目录，绝不触碰用户真实配置；密钥只用
//! `sk-` 开头的测试串，不读任何真实钥匙串。

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::json;
use tianshu_relay_core::delivery::DeliveryChannel;
use tianshu_relay_core::drift::DriftState;
use tianshu_relay_core::inject::lock::FileLock;
use tianshu_relay_core::rotation::RotationStep;
use tianshu_relay_core::service::{RevokeOutcome, ServiceConfig, TianshuRelayService};
use tianshu_relay_core::site::transport::{HttpResponse, MockTransport};
use tianshu_relay_core::site::{Credentials, KeySpec};
use tianshu_relay_core::store::Store;
use tianshu_relay_core::vault::{secret_ref, MemoryVault, Vault};

const OLD_SECRET: &str = "sk-old-0123456789abcdef";
const NEW_SECRET: &str = "sk-rot-newkey0123456789";
const BASE: &str = "https://relay.example.com";
const MODEL: &str = "gpt-5-test-model";

struct Fixture {
    _dir: tempfile::TempDir,
    db_path: PathBuf,
    home: PathBuf,
    service: TianshuRelayService<MockTransport>,
    mock: MockTransport,
    vault: Arc<MemoryVault>,
    key_id: i64,
}

/// 建站 + 登录 + 一把带站点侧 id 的旧密钥（轮换用；与 `rotation_run.rs` 同口径）。
async fn setup_rotatable() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let db_path = dir.path().join("tianshu-relay.db");

    let store = Store::open(&db_path).expect("文件库");
    let site_id = store.upsert_site("newapi", BASE, "测试站").expect("写站点");
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &reference, Some("1"), None)
        .expect("写密钥记录");

    let vault = Arc::new(MemoryVault::new());
    vault.put(&reference, OLD_SECRET).expect("写钥匙串");

    let mock = MockTransport::new(vec![]);
    let service = TianshuRelayService::new(
        store,
        mock.clone(),
        ServiceConfig {
            vault: vault.clone(),
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
            data_dir: None,
        },
    );

    mock.push(
        HttpResponse::json(200, json!({"success": true, "data": {"enabled": false}}))
            .expect("构造响应"),
    );
    mock.push(
        HttpResponse::json(200, json!({"success": true, "data": {"id": 7}}))
            .expect("构造响应")
            .with_header("Set-Cookie", "session=abc; Path=/"),
    );
    service
        .login(site_id, Credentials::new("me", "pw"))
        .await
        .expect("登录");

    Fixture {
        _dir: dir,
        db_path,
        home,
        service,
        mock,
        vault,
        key_id,
    }
}

/// 不登录的轻量夹具（P1-11 单通道记账失败用；投递本身不联网）。
fn setup_plain() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let db_path = dir.path().join("tianshu-relay.db");

    let store = Store::open(&db_path).expect("文件库");
    let site_id = store.upsert_site("newapi", BASE, "测试站").expect("写站点");
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &reference, Some("1"), None)
        .expect("写密钥记录");

    let vault = Arc::new(MemoryVault::new());
    vault.put(&reference, OLD_SECRET).expect("写钥匙串");

    let mock = MockTransport::new(vec![]);
    let service = TianshuRelayService::new(
        store,
        mock.clone(),
        ServiceConfig {
            vault: vault.clone(),
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
            data_dir: None,
        },
    );

    Fixture {
        _dir: dir,
        db_path,
        home,
        service,
        mock,
        vault,
        key_id,
    }
}

fn create_key_ok() -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"success": true, "data": {"key": NEW_SECRET, "id": 2}}),
    )
    .expect("构造响应")
}

fn delete_ok() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "message": ""})).expect("构造响应")
}

fn codex_auth_target(f: &Fixture) -> PathBuf {
    f.home.join(".codex").join("auth.json")
}

fn codex_config_target(f: &Fixture) -> PathBuf {
    f.home.join(".codex").join("config.toml")
}

fn journal_status_by_prefix(db_path: &PathBuf) -> HashMap<String, String> {
    let conn = rusqlite::Connection::open(db_path).expect("直连库");
    let mut stmt = conn
        .prepare("SELECT id, status FROM journals")
        .expect("查 journals");
    let rows = stmt
        .query_map([], |row| {
            let id: String = row.get(0)?;
            let status: String = row.get(1)?;
            Ok((id, status))
        })
        .expect("读行");
    let mut out: HashMap<String, String> = HashMap::new();
    for row in rows {
        let (id, status) = row.expect("行");
        let prefix = id.split(':').next().unwrap_or("").to_string();
        out.insert(prefix, status);
    }
    out
}

fn journal_row_count(db_path: &PathBuf) -> i64 {
    let conn = rusqlite::Connection::open(db_path).expect("直连库");
    conn.query_row("SELECT COUNT(*) FROM journals", [], |row| row.get(0))
        .expect("计数")
}

// ============================================================ P1-11

#[test]
fn p1_11_single_channel_accounting_failure_marks_journal_rolled_back() {
    let f = setup_plain();
    let target = codex_auth_target(&f);
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    f.service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    let before = fs::read_to_string(&target).unwrap();
    let first_journal = f.service.delivery_history(10).unwrap()[0]
        .journal_id
        .clone();

    // 换一把密钥，保证第二次投递真的会改动文件——否则「内容没变」可能是两次
    // 写入本来就相同，滚回断言为空。滚回点就是第一次投递的内容（before），
    // 因此滚回后漂移按第一次投递的 after 哈希比对，应为 Intact 而非 Modified。
    f.vault
        .put(&secret_ref("key", 1, "secret"), "sk-rotated-999999999999")
        .unwrap();
    let before_second = fs::read_to_string(&target).unwrap();
    assert_eq!(
        before_second, before,
        "第二次投递的起点应为第一次投递的内容"
    );

    // 只让 `record_binding` 失败：触发器在 bindings 插入时 abort，
    // `record_journal` 在它之前已成功，恰好复现 P1-11 的分支条件。
    let escaped = target.display().to_string().replace('\'', "''");
    let conn = rusqlite::Connection::open(&f.db_path).expect("直连库");
    conn.execute_batch(&format!(
        "CREATE TRIGGER p1_11_fail_binding BEFORE INSERT ON bindings \
         WHEN NEW.target_path = '{escaped}' \
         BEGIN SELECT RAISE(ABORT, 'injected binding failure'); END;"
    ))
    .expect("建触发器");

    let err = f
        .service
        .apply_delivery(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap_err();
    assert!(
        matches!(err, tianshu_relay_core::error::Error::Store(_)),
        "记账失败应报 Store: {err:?}"
    );
    assert_eq!(
        fs::read_to_string(&target).unwrap(),
        before_second,
        "记账失败必须把文件滚回投递前"
    );

    // 核心断言：失败那单的 journals 行已记为 rolled_back，而不是 applied。
    let statuses = journal_status_by_prefix(&f.db_path);
    assert!(
        statuses.values().any(|s| s == "rolled_back"),
        "应有 rolled_back 的 journal 行: {statuses:?}"
    );
    for (prefix, status) in &statuses {
        if prefix != &first_journal {
            assert_eq!(
                status, "rolled_back",
                "失败单 {prefix} 的 journal 状态必须为 rolled_back，实际 {status}"
            );
        }
    }

    // 漂移不再报假 Modified：删触发器后，最新绑定仍是第一次投递，
    // 其 after 哈希与已滚回的文件一致，应为 Intact。
    conn.execute_batch("DROP TRIGGER p1_11_fail_binding;")
        .expect("删触发器");
    let reports = f.service.drift_report().expect("漂移报告");
    let report = reports
        .iter()
        .find(|r| r.target_path == target)
        .expect("目标应在漂移报告里");
    assert_eq!(
        report.state,
        DriftState::Intact,
        "记账失败滚回后漂移不得报假 Modified: {report:?}"
    );
}

// ============================================================ P1-12

#[tokio::test]
async fn p1_12_rotation_keeps_the_codex_model() {
    let f = setup_rotatable().await;
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexConfig)
        .unwrap();
    f.service.apply_codex(f.key_id, Some(MODEL), false).unwrap();
    let config_before = fs::read_to_string(codex_config_target(&f)).unwrap();
    assert!(
        config_before.contains(&format!("model = \"{MODEL}\"")),
        "初始投递必须写下模型: {config_before}"
    );

    f.mock.push(create_key_ok());
    f.mock.push(delete_ok());
    let run = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/rotated"))
        .await
        .expect("轮换");
    assert!(run.completed(), "轮换应走完: {:?}", run.stop_reason);
    assert_eq!(
        run.reinjected,
        vec!["codex-auth-json", "codex-config"],
        "双单轮换应同时报两文件"
    );

    let config_after = fs::read_to_string(codex_config_target(&f)).unwrap();
    assert!(
        config_after.contains(&format!("model = \"{MODEL}\"")),
        "轮换后顶层模型必须仍在（P1-12 的回归点）: {config_after}"
    );
    let auth_after = fs::read_to_string(codex_auth_target(&f)).unwrap();
    assert!(
        auth_after.contains(NEW_SECRET),
        "轮换后 auth 应为新密钥: {auth_after}"
    );
    assert!(!auth_after.contains(OLD_SECRET), "旧密钥必须从 auth 里消失");
}

// ============================================================ P1-15（新通道轮换）

/// 这些通道的 writer 在 `model=None` 时 fail-closed（schema 要求条目必须有
/// 模型），轮换必须从现盘目标文件把模型读回来，而不是先建新 key、再停在
/// 第②步。测试同时覆盖五个落点与各自的模型字段位置。
#[tokio::test]
async fn p1_15_rotation_keeps_models_for_schema_required_channels() {
    let f = setup_rotatable().await;
    let channels = [
        DeliveryChannel::Droid,
        DeliveryChannel::CodeBuddy,
        DeliveryChannel::WorkBuddy,
        DeliveryChannel::WorkBuddyAi,
        DeliveryChannel::Crush,
    ];
    for channel in channels {
        f.service.grant_consent(f.key_id, channel).unwrap();
        f.service
            .apply_delivery_with_model(f.key_id, channel, Some(MODEL))
            .unwrap();
    }

    f.mock.push(create_key_ok());
    f.mock.push(delete_ok());
    let run = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/rotated"))
        .await
        .expect("轮换");
    assert!(run.completed(), "轮换应走完: {:?}", run.stop_reason);
    let mut got = run.reinjected.clone();
    got.sort();
    let mut want: Vec<String> = channels.iter().map(|c| c.as_str().to_string()).collect();
    want.sort();
    assert_eq!(got, want, "五个通道都必须重注入");

    for channel in channels {
        let path = f.home.join(channel.relative_target());
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains(NEW_SECRET), "{} 应拿到新密钥", path.display());
        assert!(
            !text.contains(OLD_SECRET),
            "{} 的旧密钥应消失",
            path.display()
        );
        let model_path = if channel == DeliveryChannel::Crush {
            tianshu_relay_core::delivery::crush::CrushWriter::data_path(&f.home)
        } else {
            path.clone()
        };
        let model_text = fs::read_to_string(&model_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&model_text).unwrap();
        let model = match channel {
            DeliveryChannel::Droid => parsed["customModels"]
                .as_array()
                .and_then(|arr| {
                    arr.iter().find(|entry| {
                        entry["id"]
                            .as_str()
                            .is_some_and(|id| id.starts_with("custom:keyrelay/"))
                    })
                })
                .and_then(|entry| entry["model"].as_str()),
            DeliveryChannel::CodeBuddy
            | DeliveryChannel::WorkBuddy
            | DeliveryChannel::WorkBuddyAi => {
                let models = match &parsed {
                    serde_json::Value::Array(items) => Some(items),
                    serde_json::Value::Object(map) => map.get("models").and_then(|v| v.as_array()),
                    _ => None,
                };
                models
                    .and_then(|arr| {
                        arr.iter()
                            .find(|entry| entry["vendor"].as_str() == Some("keyrelay"))
                    })
                    .and_then(|entry| entry["id"].as_str())
            }
            DeliveryChannel::Crush => parsed["models"]["large"]["model"].as_str(),
            _ => unreachable!(),
        };
        assert_eq!(
            model,
            Some(MODEL),
            "{} 轮换后必须保留模型名: {model_text}",
            channel.as_str()
        );
    }
}

// ============================================================ P1-13

#[tokio::test]
async fn p1_13_rotation_keeps_the_cline_insiders_variant_in_place() {
    let f = setup_rotatable().await;
    let insiders = f
        .service
        .delivery_preview_in(
            f.key_id,
            DeliveryChannel::Cline,
            None,
            tianshu_relay_core::delivery::DeliverySource::Site,
            Some("code-insiders"),
        )
        .unwrap();
    assert_eq!(insiders.target_variant, "code-insiders");
    let default_path = f
        .service
        .delivery_plan(f.key_id, DeliveryChannel::Cline)
        .unwrap()
        .target_path;

    f.service
        .grant_consent_with_variant(f.key_id, DeliveryChannel::Cline, Some("code-insiders"))
        .unwrap();
    f.service
        .apply_delivery_in_with_variant(
            f.key_id,
            DeliveryChannel::Cline,
            None,
            tianshu_relay_core::delivery::DeliverySource::Site,
            Some("code-insiders"),
        )
        .unwrap();
    assert!(
        fs::read_to_string(&insiders.target_path)
            .unwrap()
            .contains(OLD_SECRET),
        "初始 Insiders 投递应含旧密钥"
    );

    let plan = f.service.rotation_plan(f.key_id).expect("预览");
    assert_eq!(
        plan.channels,
        vec!["cline (code-insiders)"],
        "预览必须提变体，不能只写 cline: {:?}",
        plan.channels
    );

    f.mock.push(create_key_ok());
    f.mock.push(delete_ok());
    let run = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/rotated"))
        .await
        .expect("轮换");
    assert!(run.completed(), "轮换应走完: {:?}", run.stop_reason);
    assert_eq!(
        run.reinjected,
        vec!["cline (code-insiders)"],
        "报告必须提变体: {:?}",
        run.reinjected
    );
    let insiders_after = fs::read_to_string(&insiders.target_path).unwrap();
    assert!(
        insiders_after.contains(NEW_SECRET),
        "Insiders 变体文件必须拿到新密钥: {insiders_after}"
    );
    assert!(
        !insiders_after.contains(OLD_SECRET),
        "Insiders 文件里的旧密钥必须消失"
    );
    assert!(
        !default_path.exists(),
        "轮换不得顺带写默认 Code 路径（旧 bug 的落点）"
    );
}

#[tokio::test]
async fn p1_13_rotation_handles_both_cline_variants_as_separate_targets() {
    let f = setup_rotatable().await;
    for variant in [None, Some("code-insiders")] {
        f.service
            .grant_consent_with_variant(f.key_id, DeliveryChannel::Cline, variant)
            .unwrap();
        f.service
            .apply_delivery_in_with_variant(
                f.key_id,
                DeliveryChannel::Cline,
                None,
                tianshu_relay_core::delivery::DeliverySource::Site,
                variant,
            )
            .unwrap();
    }
    let code_path = f
        .service
        .delivery_plan(f.key_id, DeliveryChannel::Cline)
        .unwrap()
        .target_path;
    let insiders_path = f
        .service
        .delivery_preview_in(
            f.key_id,
            DeliveryChannel::Cline,
            None,
            tianshu_relay_core::delivery::DeliverySource::Site,
            Some("code-insiders"),
        )
        .unwrap()
        .target_path;

    f.mock.push(create_key_ok());
    f.mock.push(delete_ok());
    let run = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/rotated"))
        .await
        .expect("轮换");
    assert!(run.completed(), "轮换应走完: {:?}", run.stop_reason);
    let mut reinjected = run.reinjected.clone();
    reinjected.sort();
    assert_eq!(
        reinjected,
        vec!["cline", "cline (code-insiders)"],
        "同一通道的两个变体必须各写各的文件: {:?}",
        run.reinjected
    );
    for path in [&code_path, &insiders_path] {
        let text = fs::read_to_string(path).unwrap();
        assert!(text.contains(NEW_SECRET), "{} 应含新密钥", path.display());
        assert!(
            !text.contains(OLD_SECRET),
            "{} 旧密钥应消失",
            path.display()
        );
    }
}

// ============================================================ P1-14

#[tokio::test]
async fn p1_14_rotation_bundles_codex_into_one_shared_journal() {
    let f = setup_rotatable().await;
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexConfig)
        .unwrap();
    f.service.apply_codex(f.key_id, None, false).unwrap();

    f.mock.push(create_key_ok());
    f.mock.push(delete_ok());
    let run = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/rotated"))
        .await
        .expect("轮换");
    assert!(run.completed(), "轮换应走完: {:?}", run.stop_reason);

    let history = f.service.delivery_history(10).unwrap();
    let new_rows: Vec<_> = history
        .iter()
        .filter(|row| row.key_id == run.new_key.id)
        .collect();
    assert_eq!(
        new_rows.len(),
        2,
        "新 key 应有 auth/config 两条绑定: {new_rows:?}"
    );
    assert_eq!(
        new_rows[0].journal_id, new_rows[1].journal_id,
        "双单轮换的两条绑定必须共享同一个 journal（P1-14 的回归点）"
    );
    assert!(
        !new_rows[0].journal_id.is_empty(),
        "共享 journal_id 不得为空"
    );
    assert!(
        fs::read_to_string(codex_auth_target(&f))
            .unwrap()
            .contains(NEW_SECRET),
        "auth 应为新密钥"
    );
    assert!(
        fs::read_to_string(codex_config_target(&f))
            .unwrap()
            .contains("model_provider = \"custom\""),
        "config 应已重注入"
    );
}

#[tokio::test]
async fn p1_14_rotation_config_write_failure_leaves_auth_untouched() {
    let f = setup_rotatable().await;
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexAuthJson)
        .unwrap();
    f.service
        .grant_consent(f.key_id, DeliveryChannel::CodexConfig)
        .unwrap();
    f.service.apply_codex(f.key_id, None, false).unwrap();
    let auth_before = fs::read_to_string(codex_auth_target(&f)).unwrap();
    let config_before = fs::read_to_string(codex_config_target(&f)).unwrap();
    let journals_before = journal_row_count(&f.db_path);

    // 写盘失败注入：占住 config 的写锁。预检不取锁所以能通过，轮换的双单在
    // 取第二把锁时失败——auth 一个字节都还没写，整单直接失败。
    let lock_dir = tianshu_relay_core::inject::default_lock_dir();
    let _held = FileLock::acquire(&codex_config_target(&f), &lock_dir).expect("占 config 锁");

    let after_login = f.mock.request_count();
    f.mock.push(create_key_ok());
    let run = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/rotated"))
        .await
        .expect("轮换");
    assert!(!run.completed(), "双单失败时轮换不得报完成");
    assert_eq!(run.stopped_at, Some(RotationStep::ReinjectAll));
    assert_eq!(run.revoke, RevokeOutcome::NotAttempted, "旧 key 不得被回收");
    assert!(
        run.stop_reason
            .as_deref()
            .is_some_and(|r| r.contains("codex")),
        "停下原因要点名 codex 双单: {:?}",
        run.stop_reason
    );
    assert_eq!(
        fs::read_to_string(codex_auth_target(&f)).unwrap(),
        auth_before,
        "config 写盘失败时 auth 必须未换（整体回滚 / 未动）"
    );
    assert_eq!(
        fs::read_to_string(codex_config_target(&f)).unwrap(),
        config_before,
        "config 本身也必须未动"
    );
    assert_eq!(
        journal_row_count(&f.db_path),
        journals_before,
        "双单在取锁阶段失败时不得产生新 journal（更不得产生两个各记一单的 journal）"
    );
    assert_eq!(
        f.mock.request_count() - after_login,
        1,
        "只发了建新 key 的请求，没有发删旧 key 的请求"
    );
}
