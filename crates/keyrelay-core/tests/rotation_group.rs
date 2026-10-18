//! M20-S1 / B-166：**轮换必须继承旧密钥的分组**。
//!
//! 为什么这条测试独立成一个文件：它钉的不是「适配器能不能建带分组的 key」（那是
//! `contract_sub2api.rs` / `groups.rs` 的事），而是**编排顺序**——
//!
//! - 分组解析必须发生在 `create_key` **之前**；
//! - 解析不到时必须**在动手前**停下，站点上连一把多余的 key 都不该有；
//! - 旧 key 没绑分组时，轮换行为必须与改动前逐字一致（不许「顺手给所有人绑个 default」）。
//!
//! 全部走 MockTransport，不代表真实站点已验证（spec §8.3 已把真机复测列为可选）。

use std::fs;
use std::sync::Arc;

use keyrelay_core::error::Error;
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::transport::{HttpResponse, MockTransport};
use keyrelay_core::site::{Credentials, KeySpec, SiteKind};
use keyrelay_core::store::Store;
use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};
use serde_json::{json, Value};

const BASE: &str = "https://sub.example.com";
const OLD_SECRET: &str = "sk-old-0123456789abcdef";
const NEW_SECRET: &str = "sk-new-0123456789abcdef";

struct Fixture {
    _dir: tempfile::TempDir,
    service: KeyRelayService<MockTransport>,
    mock: MockTransport,
    key_id: i64,
}

/// Sub2API 的成功信封：`{code: 0, message: "success", data: ...}`
fn ok(data: Value) -> HttpResponse {
    HttpResponse::json(200, json!({"code": 0, "message": "success", "data": data}))
        .expect("构造响应")
}

/// 登录成功的响应体（没有 `requires_2fa` ⇒ 一次请求拿到会话）。
fn login_ok() -> HttpResponse {
    ok(json!({"access_token": "tok-abc", "token_type": "Bearer", "user": {"id": 7}}))
}

/// 站点侧分组列表（`/api/v1/groups/available`）。「gpt plus」的数字主键是 **2**。
fn groups_available() -> HttpResponse {
    ok(json!([
        {"id": 1, "name": "default", "description": "默认分组"},
        {"id": 2, "name": "gpt plus", "description": "GPT 专用"}
    ]))
}

/// `/api/v1/groups/rates`：`{"<group_id>": 倍率}`。
fn groups_rates() -> HttpResponse {
    ok(json!({"1": 1.0, "2": 0.5}))
}

fn create_key_ok() -> HttpResponse {
    HttpResponse::json(
        201,
        json!({"code": 0, "message": "success", "data": {"id": 21, "key": NEW_SECRET}}),
    )
    .expect("构造响应")
}

fn delete_ok() -> HttpResponse {
    HttpResponse::json(200, json!({"code": 0, "message": "success", "data": null}))
        .expect("构造响应")
}

/// 建站 + 写一把带分组显示名的旧密钥。`kind` 默认可换（用来构造「站点没有 groups
/// 能力」的夹具），`login` 用来跳过登录流程。
async fn setup(kind: &str, group: Option<&str>, login: bool) -> Fixture {
    setup_full(kind, group, None, login).await
}

/// 同上，但额外写 `keys.group_id`（M22-S1：按 id 认定分组的那条路径要用）。
///
/// 单独一层是因为 `insert_key` 有 65 处调用点、**刻意没有**给它加参数（见 spec §2）；
/// 这里用窄方法 `set_key_group` 补写，与生产路径 `create_key` 的做法一致。
async fn setup_full(
    kind: &str,
    group: Option<&str>,
    group_id: Option<&str>,
    login: bool,
) -> Fixture {
    setup_with_login(kind, group, group_id, login, vec![login_ok()]).await
}

/// 同上，但由调用方给**登录阶段的响应队列**。
///
/// NewAPI 与 Sub2API 的登录时序不同：NewAPI 先 `GET /api/user/login/encryption-key`
/// （404 = 站点未启用加密登录）再 `POST /api/user/login`，信封是 `{success, data}`；
/// Sub2API 一次 `POST /api/v1/auth/login`，信封是 `{code, message, data}`。
/// 把队列做成参数，避免为 NewAPI 复制一整套 setup。
async fn setup_with_login(
    kind: &str,
    group: Option<&str>,
    group_id: Option<&str>,
    login: bool,
    login_responses: Vec<HttpResponse>,
) -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");

    let store = Store::open(&dir.path().join("keyrelay.db")).expect("文件库");
    let site_id = store.upsert_site(kind, BASE, "测试站").expect("写站点");
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &reference, Some("9"), group)
        .expect("写密钥记录");
    if group_id.is_some() {
        store
            .set_key_group(key_id, group_id, group)
            .expect("写分组 id");
    }

    let vault = Arc::new(MemoryVault::new());
    vault.put(&reference, OLD_SECRET).expect("写钥匙串");

    let mock = MockTransport::new(login_responses);
    let service = KeyRelayService::new(
        store,
        mock.clone(),
        ServiceConfig {
            vault,
            home,
            backup_dir: dir.path().join("backups"),
        },
    );
    if login {
        service
            .login(site_id, Credentials::new("me@example.com", "pw"))
            .await
            .expect("登录");
    }

    Fixture {
        _dir: dir,
        service,
        mock,
        key_id,
    }
}

/// 轮换之后站点侧收到的请求（跳过登录那一次）。
fn site_requests(mock: &MockTransport) -> Vec<String> {
    mock.requests()
        .into_iter()
        .skip(1)
        .map(|request| {
            let body = request
                .body
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).to_string())
                .unwrap_or_default();
            format!("{} {} {}", request.method.as_str(), request.url, body)
        })
        .collect()
}

// ============================================================ 继承

/// 主路径：旧 key 绑了「gpt plus」，新 key 必须带着同一个分组建出来。
///
/// 判据是请求体里的 `group_id == 2`（Sub2API 要的是数字主键）——只断言语义上的
/// 「继承了」是不够的，那正是 B-161 里 `GroupInfo.id` 被丢掉时的假象。
#[tokio::test]
async fn rotation_inherits_the_old_keys_group() {
    let f = setup(SiteKind::Sub2Api.as_str(), Some("gpt plus"), true).await;
    f.mock.push(groups_available());
    f.mock.push(groups_rates());
    f.mock.push(create_key_ok());
    f.mock.push(delete_ok());

    let run = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/daily-2"))
        .await
        .expect("轮换应成功");

    let created = site_requests(&f.mock)
        .into_iter()
        .find(|line| line.contains("/api/v1/keys") && line.starts_with("POST"))
        .expect("应有一次建密钥请求");
    assert!(
        created.contains("\"group_id\":2"),
        "新密钥必须绑定同一分组（数字主键 2）：{created}"
    );

    // 本地库里新 key 记的是**显示名**（M19-S1 的口径），与旧 key 一致
    let stored = f
        .service
        .stored_keys()
        .expect("列本地密钥")
        .into_iter()
        .find(|k| k.id == run.new_key.id)
        .expect("新 key 应已落库");
    assert_eq!(stored.group_name.as_deref(), Some("gpt plus"));
}

/// 旧行落库的是**站点原生标识**（CLI/测试建的行：M19-S1 的回落路径）时也要继承。
///
/// 判据与 `available_groups` 查倍率那处同源（名字或 id 命中）。只按名字匹配的话，
/// 这种行会被误判成「分组已不存在」——用户看到的是轮换被拒，而他什么都没改。
#[tokio::test]
async fn rotation_inherits_the_group_when_the_row_stored_the_native_id() {
    let f = setup(SiteKind::Sub2Api.as_str(), Some("2"), true).await;
    f.mock.push(groups_available());
    f.mock.push(groups_rates());
    f.mock.push(create_key_ok());
    f.mock.push(delete_ok());

    f.service
        .rotate_key(f.key_id, KeySpec::named("codex/daily-2"))
        .await
        .expect("按 id 存的分组也应能解析");

    let created = site_requests(&f.mock)
        .into_iter()
        .find(|line| line.starts_with("POST") && line.contains("/api/v1/keys"))
        .expect("应有一次建密钥请求");
    assert!(
        created.contains("\"group_id\":2"),
        "仍应绑回同一个分组：{created}"
    );

    // 落库必须是**显示名**，不能是按 id 命中的那个原值。
    //
    // 这条断言是第二轮独立复审逼出来的（P4-1）：把 id 分支的 `group_label` 改成 `None`，
    // 作者原有 9 条**全绿**，而实测落库从 `Some("gpt plus")` 退化成 `Some("2")`——正是
    // M19-S1 踩过又修掉的那个后果（密钥表显示无意义数字 + `refresh` 按名查倍率落空），
    // 却发生在唯一没有被断言覆盖的支路上。主路径早就钉了同一件事（见上面那条用例），
    // 这里补齐。
    let stored = f
        .service
        .stored_keys()
        .expect("列本地密钥")
        .into_iter()
        .find(|k| k.name == "codex/daily-2")
        .expect("新 key 应已落库");
    assert_eq!(
        stored.group_name.as_deref(),
        Some("gpt plus"),
        "按 id 命中也要把显示名落库，而不是把 \"2\" 存进去"
    );
}

/// 站点上已经没有那个分组 ⇒ **动手前拒绝**，且整轮零创建请求、旧 key 原样不动。
///
/// 「零 `POST /api/v1/keys`」是判据：一旦先建后拒，站点上就多出一把不带分组的 key
/// （在那个站点上根本不能用），而用户看到的是一条错误。
#[tokio::test]
async fn rotation_is_refused_when_the_group_no_longer_exists() {
    let f = setup(SiteKind::Sub2Api.as_str(), Some("gpt plus"), true).await;
    // 站点上只剩 default：解析不出「gpt plus」
    f.mock.push(ok(json!([{"id": 1, "name": "default"}])));
    f.mock.push(ok(json!({"1": 1.0})));

    let err = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/daily-2"))
        .await
        .expect_err("分组不存在时必须拒绝轮换");

    // 点名「是轮换这一步拒绝的」——只断言论文里出现分组名是不够的：把这里的拒绝换成
    // 「照旧把分组名传下去」，适配器（B-161）也会抛一条带分组名的 `InvalidInput`，
    // 于是这条用例照样绿，而站点上已经多了一把不带分组的 key。
    assert!(
        matches!(&err, Error::InvalidInput(m) if m.contains("在站点上已经不存在")),
        "拒绝理由必须说明是轮换时解析不到该分组：{err:?}"
    );
    assert!(
        !site_requests(&f.mock)
            .iter()
            .any(|line| line.starts_with("POST") && line.contains("/api/v1/keys")),
        "一把多余的 key 都不该建：{:?}",
        site_requests(&f.mock)
    );

    // 旧 key 还在本地、也没被回收
    let stored = f.service.stored_keys().expect("列本地密钥");
    assert_eq!(stored.len(), 1, "旧 key 必须原样留在本地");
    assert!(
        !site_requests(&f.mock)
            .iter()
            .any(|line| line.starts_with("DELETE")),
        "旧 key 不应被回收：{:?}",
        site_requests(&f.mock)
    );
}

/// 拉分组本身失败 ⇒ 轮换失败，**不**静默降级成「新 key 不带分组」。
#[tokio::test]
async fn rotation_fails_when_the_group_list_cannot_be_fetched() {
    let f = setup(SiteKind::Sub2Api.as_str(), Some("gpt plus"), true).await;
    f.mock.push_error(Error::Transport("连接被重置".into()));

    let err = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/daily-2"))
        .await
        .expect_err("拉不到分组时必须失败");

    assert!(matches!(err, Error::Transport(_)), "{err:?}");
    assert!(
        !site_requests(&f.mock)
            .iter()
            .any(|line| line.starts_with("POST") && line.contains("/api/v1/keys")),
        "没建任何 key：{:?}",
        site_requests(&f.mock)
    );
}

// ============================================================ 站点没有 groups 能力

/// 站点没有 `groups` 能力（`custom-openai-compatible`）⇒ 轮换被拒，且**文案要说清因果**。
///
/// 这是三条「解析不到」路径里唯一一条会被 `capability_gate` 原话接住的：那句只说到
/// 「不支持读取分组」。用户真正想知道的是后半句——旧密钥有没有被回收。所以这里除了
/// 断言类型，还必须断言 `Unsupported` 的文案里有「轮换已取消」与「未被回收」
/// （M20-S1 独立复审 P1-1）。
///
/// 注意夹具**不登录**：`custom-openai-compatible` 没有登录流程，而能力门本来就该在
/// 取会话之前生效（`capability_gate.rs` 的 S-1 钉的就是这件事）。
#[tokio::test]
async fn a_site_without_the_groups_capability_refuses_with_the_consequence() {
    let f = setup(
        SiteKind::CustomOpenAiCompatible.as_str(),
        Some("gpt plus"),
        false,
    )
    .await;

    let err = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/daily-2"))
        .await
        .expect_err("站点读不了分组时必须拒绝轮换");

    let msg = match &err {
        Error::Unsupported(m) => m,
        other => panic!("应是 Unsupported，实际 {other:?}"),
    };
    assert!(
        msg.contains("轮换已取消"),
        "必须告诉用户轮换被取消了：{msg}"
    );
    assert!(
        msg.contains("旧密钥未被回收"),
        "必须告诉用户旧密钥没动（RevokeOld 不可逆，这是他真正担心的）：{msg}"
    );
    // 两条断言各钉一件事，别只看其中一条（第二轮独立复审的认知澄清）：
    //
    // - 上面 `match` 的**类型**判据钉「能力门早于取会话」：把 `session()` 提到
    //   `capability_gate` 之前，这里立刻变成 `AuthFailed` 并 panic——因为夹具没登录。
    // - 下面这个**计数**钉「没发过任何请求」这个结果。它**不能**单独证明「早于发请求」：
    //   `session()` 是纯缓存读（零请求），所以即便它被提前，计数仍然是 0。
    assert_eq!(
        f.mock.request_count(),
        0,
        "拒绝发生在任何请求之前（含登录那一次都没有）"
    );
}

// ============================================================ 存的是空白

/// 落库值是纯空格 ⇒ 当作**没有分组**，且**不去站点上查**。
///
/// 纯空格在 SQL 里既不是 `NULL` 也不是空串，历史上可能由外部写入方（导入、别的版本）
/// 留下。把它当成「有分组」会让轮换去站点上找一个名字为空串的分组，然后拒绝——
/// 用户看到的是一条跟他操作无关的错误。
#[tokio::test]
async fn a_whitespace_only_group_name_is_treated_as_no_group() {
    let f = setup(SiteKind::Sub2Api.as_str(), Some("   "), true).await;
    f.mock.push(create_key_ok());
    f.mock.push(delete_ok());

    f.service
        .rotate_key(f.key_id, KeySpec::named("codex/daily-2"))
        .await
        .expect("纯空格分组应按「没有分组」处理");

    let requests = site_requests(&f.mock);
    assert!(
        !requests
            .iter()
            .any(|line| line.contains("groups/available")),
        "不该为空白分组名去站点上查：{requests:?}"
    );
    let created = requests
        .iter()
        .find(|line| line.starts_with("POST") && line.contains("/api/v1/keys"))
        .expect("应有一次建密钥请求");
    assert!(
        !created.contains("group_id"),
        "空白分组名不该变成分组：{created}"
    );
}

// ============================================================ 行为不变

/// 旧 key 没绑分组 ⇒ 新 key 也不带分组，行为与改动前一致。
///
/// 这条是**回归防线**：继承逻辑一旦写成「总给绑一个分组」，第一个受害的就是
/// NewAPI 上那些刻意「跟随用户自己分组」的 key。
#[tokio::test]
async fn a_key_without_a_group_stays_without_one() {
    let f = setup(SiteKind::Sub2Api.as_str(), None, true).await;
    f.mock.push(create_key_ok());
    f.mock.push(delete_ok());

    f.service
        .rotate_key(f.key_id, KeySpec::named("codex/daily-2"))
        .await
        .expect("轮换应成功");

    let requests = site_requests(&f.mock);
    assert!(
        !requests
            .iter()
            .any(|line| line.contains("groups/available")),
        "旧 key 没分组时不该去拉分组列表：{requests:?}"
    );
    let created = requests
        .iter()
        .find(|line| line.starts_with("POST") && line.contains("/api/v1/keys"))
        .expect("应有一次建密钥请求");
    assert!(
        !created.contains("group_id"),
        "不该凭空绑一个分组：{created}"
    );
}

/// 调用方显式给了分组 ⇒ **不被**旧分组覆盖（显式优先）。
///
/// 否则「将来 UI 让用户在轮换时改分组」这条路会被悄悄堵死，而且不会有任何提示。
#[tokio::test]
async fn an_explicit_group_is_not_overwritten_by_the_inherited_one() {
    let f = setup(SiteKind::Sub2Api.as_str(), Some("gpt plus"), true).await;
    f.mock.push(create_key_ok());
    f.mock.push(delete_ok());

    f.service
        .rotate_key(
            f.key_id,
            KeySpec {
                group: Some("1".into()),
                ..KeySpec::named("codex/daily-2")
            },
        )
        .await
        .expect("轮换应成功");

    let created = site_requests(&f.mock)
        .into_iter()
        .find(|line| line.starts_with("POST") && line.contains("/api/v1/keys"))
        .expect("应有一次建密钥请求");
    assert!(
        created.contains("\"group_id\":1"),
        "显式给的 1 不该被继承的 2 覆盖：{created}"
    );
    assert!(
        !site_requests(&f.mock)
            .iter()
            .any(|line| line.contains("groups/available")),
        "显式给了分组就不该再去站点上查：{:?}",
        site_requests(&f.mock)
    );
}

// ============================================================ 预览

/// 预览带出旧分组的显示名，且**一个请求都不发**（PRD §7：预览必须是纯本地的）。
#[tokio::test]
async fn the_plan_carries_the_group_name_without_any_request() {
    let f = setup(SiteKind::Sub2Api.as_str(), Some("gpt plus"), true).await;

    let plan = f.service.rotation_plan(f.key_id).expect("取预览");
    assert_eq!(plan.old_group_name.as_deref(), Some("gpt plus"));
    assert_eq!(f.mock.request_count(), 1, "预览之后仍只有登录那一次请求");
}

// ============================================================ 按 id 认定（M22-S1 / B-168）

/// 站点侧**改了名**：本地记的是「gpt plus」+ id 2，站点上 id 2 现在叫「gpt plus v2」。
///
/// 这是 B-168 的正例：id 是站点主键，改名不改变它。旧实现在这里会拒绝轮换，用户被迫
/// 手动重建密钥。判据必须钉**两件事**：轮换成功，且新 key 记的是**站点当前的名字**。
#[tokio::test]
async fn rotation_accepts_a_group_that_was_renamed_on_the_site() {
    let f = setup_full(
        SiteKind::Sub2Api.as_str(),
        Some("gpt plus"),
        Some("2"),
        true,
    )
    .await;
    f.mock.push(ok(json!([
        {"id": 1, "name": "default"},
        {"id": 2, "name": "gpt plus v2"}
    ])));
    f.mock.push(ok(json!({"1": 1.0, "2": 0.5})));
    f.mock.push(create_key_ok());
    f.mock.push(delete_ok());

    let run = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/daily-2"))
        .await
        .expect("按 id 认出是同一分组，轮换应成功");

    let created = site_requests(&f.mock)
        .into_iter()
        .find(|line| line.starts_with("POST") && line.contains("/api/v1/keys"))
        .expect("应有一次建密钥请求");
    assert!(
        created.contains("\"group_id\":2"),
        "新密钥必须绑定同一个数字主键 2：{created}"
    );

    // 新 key 落库的是**站点当前**的名字（不是本地那个旧名）
    let plan = f
        .service
        .rotation_plan(run.new_key.id)
        .expect("取新 key 的预览");
    assert_eq!(
        plan.old_group_name.as_deref(),
        Some("gpt plus v2"),
        "改名后必须记新名字，否则下次轮换又认不出来"
    );
    assert_eq!(plan.old_group_id.as_deref(), Some("2"));
}

/// 按 id 找时，id **不在**列表里 ⇒ 只可能是被删了（改名不会改变 id），必须拒绝。
#[tokio::test]
async fn rotation_is_refused_when_the_stored_group_id_is_gone() {
    let f = setup_full(
        SiteKind::Sub2Api.as_str(),
        Some("gpt plus"),
        Some("9"),
        true,
    )
    .await;
    // 站点上 id 2 还在、名字也叫 gpt plus，但本地记的 id 是 9
    f.mock.push(groups_available());
    f.mock.push(groups_rates());

    let err = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/daily-2"))
        .await
        .expect_err("id 不在站点列表里必须拒绝");

    // 钉「按 id 那条分支」的文案：它说的是「可能被删除」，而按名字那条会带上
    // 「可能被删除或改名」。两条分支的文案必须能分开，否则测试分不清走了哪条。
    assert!(
        matches!(&err, Error::InvalidInput(m)
            if m.contains("id=9") && m.contains("在站点上已经不存在") && !m.contains("或改名")),
        "必须走「按 id 找不到」那条分支：{err:?}"
    );
    assert!(
        !site_requests(&f.mock)
            .iter()
            .any(|line| line.starts_with("POST") && line.contains("/api/v1/keys")),
        "一把多余的 key 都不该建：{:?}",
        site_requests(&f.mock)
    );
}

/// 没有 `group_id` 的旧行（M22-S1 之前建的）仍按名字匹配 —— 回归 M20-S1 的行为。
#[tokio::test]
async fn a_row_without_a_group_id_still_matches_by_name() {
    let f = setup(SiteKind::Sub2Api.as_str(), Some("gpt plus"), true).await;
    f.mock.push(groups_available());
    f.mock.push(groups_rates());
    f.mock.push(create_key_ok());
    f.mock.push(delete_ok());

    let run = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/daily-2"))
        .await
        .expect("旧行按名字命中，轮换应成功");

    let plan = f
        .service
        .rotation_plan(run.new_key.id)
        .expect("取新 key 的预览");
    assert_eq!(plan.old_group_name.as_deref(), Some("gpt plus"));
    assert_eq!(
        plan.old_group_id.as_deref(),
        Some("2"),
        "新建时应当补上站点原生 id（M22-S1）"
    );
}

/// 没有 `group_id` 且名字找不到 ⇒ 文案必须**说清为什么认不出来**（没有 id 只能按名字比），
/// 而不是让用户以为分组一定被删了。
#[tokio::test]
async fn a_row_without_a_group_id_says_why_it_cannot_recognise_a_rename() {
    let f = setup(SiteKind::Sub2Api.as_str(), Some("gpt plus"), true).await;
    f.mock.push(ok(json!([{"id": 1, "name": "default"}])));
    f.mock.push(ok(json!({"1": 1.0})));

    let err = f
        .service
        .rotate_key(f.key_id, KeySpec::named("codex/daily-2"))
        .await
        .expect_err("按名字找不到时必须拒绝");

    assert!(
        matches!(&err, Error::InvalidInput(m)
            if m.contains("没有站点侧的分组 id") && m.contains("只能按名字比对")),
        "文案必须点明「没有 id、只能按名字比」这条限制：{err:?}"
    );
}

/// `create_key` 带分组时要把**站点原生 id** 落库（`keys.group_id`），
/// 否则下次轮换又只能按名字比（B-168 原地复发）。
#[tokio::test]
async fn create_key_stores_the_native_group_id() {
    let f = setup(SiteKind::Sub2Api.as_str(), None, true).await;
    f.mock.push(create_key_ok());

    let spec = KeySpec {
        group: Some("2".into()),
        group_label: Some("gpt plus".into()),
        ..KeySpec::named("codex/new")
    };
    let created = f.service.create_key(1, spec).await.expect("建密钥应成功");

    let plan = f.service.rotation_plan(created.id).expect("取预览");
    assert_eq!(
        plan.old_group_id.as_deref(),
        Some("2"),
        "站点原生 id 必须落库，否则改名后认不出来"
    );
    assert_eq!(plan.old_group_name.as_deref(), Some("gpt plus"));
}

// ============================================================ NewAPI（无主键）回归（M22-S1 复审 P1-1）

/// NewAPI 的成功信封：`{success: true, data: ...}`（与 Sub2API 的 `{code, message, data}` 不同）。
fn newapi_ok(data: Value) -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": data})).expect("构造响应")
}

/// NewAPI 的登录响应队列：先 404（站点未启用加密登录），再登录成功。
fn newapi_login() -> Vec<HttpResponse> {
    vec![
        HttpResponse::new(404, b"not found".to_vec()),
        newapi_ok(json!({"access_token": "tok-abc", "user": {"id": 7}})),
    ]
}

/// **NewAPI 的分组没有主键**，所以 `keys.group_id` 必须是 NULL。
///
/// 这条是 M22-S1 复审 P1-1 的回归：第一版把 `spec.group` 无条件当原生 id 落库，而 NewAPI
/// 的 `spec.group` 是**分组名**（`"vip"`）⇒ 下次轮换走「有 id 只按 id 找」而 NewAPI 的
/// `id` 全是 `None` ⇒ **永远找不到**，站点没改名也照样拒绝。
#[tokio::test]
async fn newapi_groups_have_no_primary_key_so_group_id_stays_null() {
    let f = setup_with_login(SiteKind::NewApi.as_str(), None, None, true, newapi_login()).await;
    f.mock.push(newapi_ok(json!({"id": 77, "key": NEW_SECRET})));

    let created = f
        .service
        .create_key(
            1,
            KeySpec {
                group: Some("vip".into()),
                group_label: Some("vip".into()),
                ..KeySpec::named("codex/new")
            },
        )
        .await
        .expect("NewAPI 建密钥应成功");

    let plan = f.service.rotation_plan(created.id).expect("取预览");
    assert_eq!(
        plan.old_group_id, None,
        "NewAPI 的分组名不是主键，不能落进 group_id —— 否则下次轮换按 id 找必然落空"
    );
    assert_eq!(
        plan.old_group_name.as_deref(),
        Some("vip"),
        "名字仍要落库（那是 NewAPI 唯一的分组标识）"
    );
}

/// 上一条的用户可见后果：NewAPI 上带分组的 key **立刻就能轮换**，不需要站点改过名。
///
/// 判据两件事：① 轮换成功；② `POST /api/token/` 的 body 里 `group == "vip"`（名字，不是 id）。
#[tokio::test]
async fn newapi_rotation_works_right_after_creating_a_grouped_key() {
    let f = setup_with_login(SiteKind::NewApi.as_str(), None, None, true, newapi_login()).await;
    f.mock.push(newapi_ok(json!({"id": 77, "key": NEW_SECRET})));
    let created = f
        .service
        .create_key(
            1,
            KeySpec {
                group: Some("vip".into()),
                group_label: Some("vip".into()),
                ..KeySpec::named("codex/new")
            },
        )
        .await
        .expect("建密钥应成功");

    // 轮换：拉分组（NewAPI 是「以名字为键的对象」）→ 建新 → 回收旧
    f.mock.push(newapi_ok(json!({"vip": {"ratio": 0.5}})));
    f.mock.push(newapi_ok(json!({"id": 78, "key": NEW_SECRET})));
    f.mock.push(newapi_ok(json!(null)));

    let run = f
        .service
        .rotate_key(created.id, KeySpec::named("codex/new-2"))
        .await
        .expect("站点没改名，NewAPI 的轮换必须成功（P1-1 的回归点）");

    let posts: Vec<String> = site_requests(&f.mock)
        .into_iter()
        .filter(|line| line.starts_with("POST") && line.contains("/api/token/"))
        .collect();
    assert_eq!(
        posts.len(),
        2,
        "建原始 key + 轮换建新 key，共两次：{posts:?}"
    );
    assert!(
        posts[1].contains("\"group\":\"vip\""),
        "NewAPI 建令牌收的是**分组名**：{}",
        posts[1]
    );

    let plan = f
        .service
        .rotation_plan(run.new_key.id)
        .expect("取新 key 的预览");
    assert_eq!(plan.old_group_id, None, "新 key 同样不该有 group_id");
    assert_eq!(plan.old_group_name.as_deref(), Some("vip"));
}
