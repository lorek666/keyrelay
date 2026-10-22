//! 轮换编排的端到端验证（M6-S5 / FR-7，PRD §176「一键三连」）。
//!
//! 钉住的是**顺序与停在哪儿**，不是三步各自能不能跑通——那三块
//! （`create_key` / `apply_delivery` / `revoke_key`）各有自己的契约测试。
//! 编排唯一能出错的地方就是顺序和「失败之后还继续往下走」，
//! 而后者会造出一个用户无法自救的状态：旧 key 已回收、新 key 没注入。

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::json;
use tianshu_relay_core::delivery::DeliveryChannel;
use tianshu_relay_core::service::{RevokeOutcome, ServiceConfig, TianshuRelayService};
use tianshu_relay_core::site::transport::{HttpResponse, MockTransport};
use tianshu_relay_core::site::{Credentials, KeySpec};
use tianshu_relay_core::store::Store;
use tianshu_relay_core::vault::{secret_ref, MemoryVault, Vault};

const OLD_SECRET: &str = "sk-old-0123456789abcdef";
const NEW_SECRET: &str = "sk-rot-newkey0123456789";
const BASE: &str = "https://relay.example.com";
const DAY: i64 = 86_400;

struct Fixture {
    _dir: tempfile::TempDir,
    db: PathBuf,
    service: TianshuRelayService<MockTransport>,
    mock: MockTransport,
    key_id: i64,
}

/// 建站 + 登录 + 一把带站点侧 id 的旧密钥。
///
/// `remote_id` 传 `None` 用来构造「老库里的行」——那种行回收不了，编排必须**跳过**
/// 而不是失败或假装做过。
async fn setup(remote_id: Option<&str>) -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let db = dir.path().join("tianshu-relay.db");

    let store = Store::open(&db).expect("文件库");
    let site_id = store.upsert_site("newapi", BASE, "测试站").expect("写站点");
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &reference, remote_id, None)
        .expect("写密钥记录");

    let vault = Arc::new(MemoryVault::new());
    vault.put(&reference, OLD_SECRET).expect("写钥匙串");

    let mock = MockTransport::new(vec![]);
    let service = TianshuRelayService::new(
        store,
        mock.clone(),
        ServiceConfig {
            vault,
            home,
            backup_dir: dir.path().join("backups"),
        },
    );

    mock.push(encryption_disabled());
    mock.push(login_ok());
    service
        .login(site_id, Credentials::new("me", "pw"))
        .await
        .expect("登录");

    Fixture {
        _dir: dir,
        db,
        service,
        mock,
        key_id,
    }
}

/// 建新密钥的成功响应。**带 `/data/id`**：NewAPI 少数版本直接在创建响应里回明文，
/// 这条路径只需一次请求，测试里就不必再摆一个令牌列表。
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

fn request_lines(mock: &MockTransport, from: usize) -> Vec<String> {
    mock.requests()
        .into_iter()
        .skip(from)
        .map(|request| format!("{} {}", request.method.as_str(), request.url))
        .collect()
}

/// 真投递一次并返回目标文件路径。
fn deliver(f: &Fixture, key_id: i64, channel: DeliveryChannel) -> PathBuf {
    f.service.grant_consent(key_id, channel).expect("授权");
    f.service.apply_delivery(key_id, channel).expect("投递");
    f.service
        .delivery_plan(key_id, channel)
        .expect("取计划")
        .target_path
}

// ============================================================ 三步的完整路径

#[tokio::test]
async fn the_three_steps_run_in_order_and_the_new_key_is_what_lands() {
    let f = setup(Some("1")).await;
    let target = deliver(&f, f.key_id, DeliveryChannel::CodexAuthJson);
    let after_login = f.mock.request_count();

    // 创建 → 回收。重注入是纯本地文件操作，不占请求。
    f.mock.push(create_key_ok());
    f.mock.push(delete_ok());

    let run = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/rotated"))
        .await
        .expect("轮换");

    assert!(run.completed(), "三步应当全部走完: {:?}", run.stop_reason);
    assert_eq!(run.reinjected, vec!["codex-auth-json"]);
    assert_eq!(run.revoke, RevokeOutcome::Revoked);
    assert_eq!(run.new_key.remote_id, "2");
    assert_eq!(run.new_key.masked, "…6789", "只暴露末 4 位");

    // 请求顺序：先建新、后删旧。反过来就是死局的第一步。
    assert_eq!(
        request_lines(&f.mock, after_login),
        vec![
            format!("POST {BASE}/api/token/"),
            format!("DELETE {BASE}/api/token/1"),
        ],
        "必须是「先建新 → 后删旧」"
    );

    // 真正落地的是新密钥，旧密钥从文件里消失
    let written = fs::read_to_string(&target).expect("读目标");
    assert!(
        written.contains(NEW_SECRET),
        "重注入必须把**新**密钥写进目标: {written}"
    );
    assert!(
        !written.contains(OLD_SECRET),
        "旧密钥必须从目标里消失: {written}"
    );

    // 漂移检测不得因为轮换而失明：绑定已经指到新 key，目标仍然在监视范围内
    let reports = f.service.drift_report().expect("漂移报告");
    assert_eq!(reports.len(), 1, "轮换之后目标仍在监视范围内");
}

// ============================================================ 失败即停（T10）

#[tokio::test]
async fn an_unwritable_target_refuses_the_rotation_before_a_key_is_created() {
    // M8-S4 §9-8（P2-3）：**这条测试原先断言的是「建好新 key、再停在第②步」**。
    // 那个行为本身就是 P2-3 的缺陷：每重试一次，站点上就多一把没人用的密钥。
    // 现在 `rotate_key` 在建 key **之前**用占位密钥空跑每个通道的 `plan()`，
    // 任何一条写不进去就整体拒绝——所以本测试断言的是「一个请求都不发」。
    //
    // 「不回收旧密钥」这条不变式因此变得**更强**了：连创建请求都没有，自然也没有 DELETE。
    // 中途失败的形态仍然可能（预检与真正写入之间有时间差），但那时不会留下多余的 key。
    let f = setup(Some("1")).await;
    deliver(&f, f.key_id, DeliveryChannel::CodexAuthJson);
    let gemini = deliver(&f, f.key_id, DeliveryChannel::GeminiCli);

    // 前置：这把 key 确实服务两个通道。
    let plan = f.service.rotation_plan(f.key_id).expect("预览");
    assert_eq!(
        plan.channels,
        vec!["codex-auth-json", "gemini-cli"],
        "两个通道都要在轮换范围里"
    );

    // 把第二个目标弄成**目录**：`plan()` 读不到它就必然失败。
    // 不依赖 chmod（以 root 跑时 chmod 无效），与 `drift.rs` 造「存在但读不到」同一手法。
    fs::remove_file(&gemini).expect("删文件");
    fs::create_dir(&gemini).expect("建同名目录");

    let after_login = f.mock.request_count();
    let err = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/rotated"))
        .await
        .expect_err("目标写不进去时必须在建新 key 之前拒绝");

    let text = err.to_string();
    assert!(text.contains("gemini-cli"), "要点名是哪个通道: {text}");
    assert!(
        text.contains("多一把"),
        "文案必须说清代价（否则用户只会觉得轮换坏了）: {text}"
    );
    assert_eq!(
        request_lines(&f.mock, after_login),
        Vec::<String>::new(),
        "预检失败 ⇒ 一个请求都不发（没有 POST、更没有 DELETE）"
    );

    // 旧密钥仍然可用：站点上那把没被删，本地状态也没动
    assert_ne!(
        f.service.store().key_status(f.key_id).unwrap().as_deref(),
        Some("revoked")
    );
}

#[tokio::test]
async fn a_failed_revoke_reports_the_run_as_incomplete() {
    let f = setup(Some("1")).await;
    deliver(&f, f.key_id, DeliveryChannel::CodexAuthJson);

    let after_login = f.mock.request_count();
    f.mock.push(create_key_ok());
    f.mock
        .push_error(tianshu_relay_core::error::Error::Transport(
            "模拟断网".into(),
        ));

    let run = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/rotated"))
        .await
        .expect("轮换");

    assert!(!run.completed(), "回收失败必须如实反映成「没走完」");
    assert_eq!(
        run.stopped_at,
        Some(tianshu_relay_core::rotation::RotationStep::RevokeOld)
    );
    assert!(
        matches!(run.revoke, RevokeOutcome::Failed(_)),
        "回收失败是一个独立的结局，不能和「跳过」混为一谈: {:?}",
        run.revoke
    );
    assert!(
        run.stop_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("回收旧密钥失败")),
        "停下的原因要说人话: {:?}",
        run.stop_reason
    );
    assert_eq!(
        run.reinjected,
        vec!["codex-auth-json"],
        "回收失败不影响已经做完的重注入"
    );
    assert_eq!(
        request_lines(&f.mock, after_login).len(),
        2,
        "创建 + 回收各一次请求"
    );
}

// ============================================================ 两种「不做第三步」

#[tokio::test]
async fn a_key_without_a_remote_id_skips_the_revoke_instead_of_faking_it() {
    let f = setup(None).await;
    deliver(&f, f.key_id, DeliveryChannel::CodexAuthJson);

    let after_login = f.mock.request_count();
    f.mock.push(create_key_ok());

    let run = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/rotated"))
        .await
        .expect("轮换");

    assert!(
        run.completed(),
        "没有站点侧 id 是「本来就没得回收」，不是失败"
    );
    assert_eq!(run.revoke, RevokeOutcome::SkippedNoRemoteId);
    assert_eq!(
        request_lines(&f.mock, after_login),
        vec![format!("POST {BASE}/api/token/")],
        "没有 remote_id 就不该发出删除请求"
    );
}

/// 反例保护：认不出通道的目标必须**在动手之前**拒绝轮换。
///
/// 少了这一步，实现会「照常建新 key、跳过那个目标、把旧 key 删掉」——
/// 于是那个目标永久停在已经作废的密钥上，而整个操作回报成功。
#[tokio::test]
async fn an_unrecognised_target_refuses_the_rotation_before_anything_happens() {
    let f = setup(Some("1")).await;
    deliver(&f, f.key_id, DeliveryChannel::CodexAuthJson);

    // 手工插一行「本产品认不出通道」的绑定（模拟通道改名/被删之后留下的历史行）
    {
        let conn = rusqlite::Connection::open(&f.db).expect("开库");
        conn.execute(
            "INSERT INTO bindings(agent_id, key_id, target_path, managed_json, applied_at, journal_id)
             VALUES ('mystery-agent', ?1, '/tmp/mystery-agent.json', NULL, 1, NULL)",
            rusqlite::params![f.key_id],
        )
        .expect("插绑定");
    }

    let plan = f.service.rotation_plan(f.key_id).expect("预览");
    assert_eq!(
        plan.unmapped_targets,
        vec!["mystery-agent"],
        "认不出的目标必须出现在预览里，而不是被 filter_map 悄悄滤掉"
    );

    let after_login = f.mock.request_count();
    let err = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/rotated"))
        .await
        .expect_err("有认不出通道的目标时必须拒绝轮换");

    assert!(
        err.to_string().contains("mystery-agent"),
        "拒绝的文案要点名是哪个目标: {err}"
    );
    assert_eq!(
        f.mock.request_count(),
        after_login,
        "拒绝发生在**动手之前**：一个请求都不该发出去"
    );
}

// ============================================================ 预览

#[tokio::test]
async fn the_plan_is_local_and_lists_the_fixed_three_steps() {
    let f = setup(Some("1")).await;
    let after_login = f.mock.request_count();

    let plan = f.service.rotation_plan(f.key_id).expect("预览");

    assert_eq!(
        plan.steps,
        tianshu_relay_core::rotation::rotation_steps().to_vec(),
        "预览展示的就是实际执行的顺序（同一个来源，不允许各写一份）"
    );
    assert!(plan.channels.is_empty(), "还没投递过，没有要重注入的目标");
    assert_eq!(plan.old_remote_id.as_deref(), Some("1"));
    assert_eq!(plan.key_name, "codex/daily");
    assert_eq!(
        f.mock.request_count(),
        after_login,
        "预览是纯本地的：一个请求都不发"
    );

    // 顺带确认「前拨创建时间」这条夹具能力仍然有效（轮换判定依赖它）
    let conn = rusqlite::Connection::open(&f.db).expect("开库");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("时钟")
        .as_secs() as i64;
    conn.execute(
        "UPDATE keys SET created_at = ?1 WHERE id = ?2",
        rusqlite::params![now - 40 * DAY, f.key_id],
    )
    .expect("改创建时间");
    let due = f.service.rotation_due().expect("判定到期");
    assert_eq!(due.len(), 1, "40 天前建的密钥应当在默认 30 天策略下到期");
}

// ============================================================ 夹具

/// 站点未启用登录加密（`fetch_encryption_key` 的 fail-open 分支）
fn encryption_disabled() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": {"enabled": false}})).expect("构造响应")
}

fn login_ok() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": {"id": 7}}))
        .expect("构造响应")
        .with_header("Set-Cookie", "session=abc; Path=/")
}
