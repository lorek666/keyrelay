//! 密钥对齐（FR-2 `sync_site_keys`）的端到端测试。
//!
//! **这一层原本不存在**——`sync_site_keys` 此前只有命令层的一条「不存在的站点会报错」，
//! 主路径一条端到端用例都没有。DEBUG 报告 §1.9 的缺陷（清空钥匙串后界面给的恢复路径走不通）
//! 就是在这种覆盖下活下来的：它需要「行在、秘密没了」这个**中间态**，而没有任何用例造过它。
//!
//! 这里用**按 URL 路由的假 transport**（不是响应队列）：对齐过程要跨两次调用
//! （`list_keys` → `reveal_keys`），队列式夹具的响应顺序与实现的请求顺序耦合，
//! 一改实现就得重排整串响应。

use std::fs;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{json, Value};
use tianshu_relay_core::error::Result;
use tianshu_relay_core::service::{ServiceConfig, TianshuRelayService};
use tianshu_relay_core::site::transport::{HttpRequest, HttpResponse, HttpTransport};
use tianshu_relay_core::site::Credentials;
use tianshu_relay_core::store::Store;
use tianshu_relay_core::vault::{secret_ref, MemoryVault, Vault};

const BASE: &str = "https://relay.example.com";
const SECRET: &str = "sk-sync-0123456789abcdef";

fn json_resp(status: u16, value: Value) -> HttpResponse {
    HttpResponse::json(status, value).expect("构造响应")
}

/// 按 URL 路由的假 transport。
#[derive(Clone)]
struct Router {
    seen: Arc<Mutex<Vec<HttpRequest>>>,
    /// 站点侧当前有几把 key（用来构造 `list_keys` 的响应）
    tokens: Arc<Mutex<Vec<(i64, String)>>>,
}

impl Router {
    fn new(tokens: Vec<(i64, String)>) -> Self {
        Self {
            seen: Arc::new(Mutex::new(Vec::new())),
            tokens: Arc::new(Mutex::new(tokens)),
        }
    }

    fn urls(&self) -> Vec<String> {
        self.seen
            .lock()
            .expect("锁")
            .iter()
            .map(|r| r.url.clone())
            .collect()
    }
}

#[async_trait]
impl HttpTransport for Router {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse> {
        self.seen.lock().expect("锁").push(req.clone());
        let url = req.url.as_str();

        // 登录前的加密探测。**必须先于 `/api/user/login` 判断**——
        // 这个端点的路径是 `/api/user/login/encryption-key`，前缀相同，
        // 顺序写反会把登录响应喂给加密探测（实测：fail-closed 报「缺少 enabled 字段」）。
        if url.contains("/api/user/login/encryption-key") {
            return Ok(json_resp(
                200,
                json!({"success": true, "data": {"enabled": false}}),
            ));
        }
        if url.contains("/api/user/login") {
            return Ok(json_resp(200, json!({"success": true, "data": {"id": 7}}))
                .with_header("Set-Cookie", "session=abc; Path=/"));
        }
        // 批量读明文
        if url.contains("/api/token/batch/keys") {
            let ids: Vec<i64> =
                serde_json::from_slice::<Value>(req.body.as_ref().expect("有请求体").as_ref())
                    .ok()
                    .and_then(|v| {
                        v.get("ids")
                            .and_then(Value::as_array)
                            .map(|a| a.iter().filter_map(Value::as_i64).collect())
                    })
                    .unwrap_or_default();
            let tokens = self.tokens.lock().expect("锁").clone();
            let mut keys = serde_json::Map::new();
            for id in ids {
                if let Some((_, secret)) = tokens.iter().find(|(t, _)| *t == id) {
                    keys.insert(id.to_string(), json!(secret));
                }
            }
            return Ok(json_resp(
                200,
                json!({"success": true, "message": "", "data": {"keys": keys}}),
            ));
        }
        // 列举令牌（分页）
        if url.contains("/api/token/?") || url.contains("/api/token/?p=") {
            let tokens = self.tokens.lock().expect("锁").clone();
            let items: Vec<Value> = tokens
                .iter()
                .map(|(id, _)| json!({"id": id, "name": format!("key-{id}"), "status": 1}))
                .collect();
            return Ok(json_resp(
                200,
                json!({"success": true, "message": "", "data": {"items": items, "total": items.len()}}),
            ));
        }
        panic!("夹具没有为这个 URL 准备响应: {url}");
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    service: TianshuRelayService<Router>,
    vault: Arc<MemoryVault>,
    router: Router,
    key_id: i64,
    reference: String,
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let store = Store::open(&dir.path().join("tianshu-relay.db")).unwrap();
    let site_id = store.upsert_site("newapi", BASE, "测试站").unwrap();
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &reference, Some("1"), None)
        .unwrap();
    let vault = Arc::new(MemoryVault::new());
    vault.put(&reference, SECRET).unwrap();
    let router = Router::new(vec![(1, SECRET.to_string())]);
    let service = TianshuRelayService::new(
        store,
        router.clone(),
        ServiceConfig {
            // 保留一个具体类型的句柄给夹具用（`delete` / `get`），
            // 同时把 trait object 交给 service——两者指向同一个 vault。
            vault: Arc::clone(&vault) as Arc<dyn Vault>,
            home,
            backup_dir: dir.path().join("backups"),
        },
    );
    service
        .login(site_id, Credentials::new("me", "pw"))
        .await
        .unwrap();
    Fixture {
        _dir: dir,
        service,
        vault,
        router,
        key_id,
        reference,
    }
}

#[tokio::test]
async fn an_intact_keychain_entry_is_not_re_imported() {
    // **对照组**（防过度修正）：钥匙串条目还在时，一条也不该被重新取回——
    // 否则每轮对齐都会打一次带密钥的 `reveal_keys` 请求，白花配额。
    let f = setup().await;
    let reveals = |f: &Fixture| {
        f.router
            .urls()
            .iter()
            .filter(|u| u.contains("batch/keys"))
            .count()
    };
    let before = reveals(&f);

    let summary = f.service.sync_site_keys(1).await.expect("对齐");

    assert_eq!(summary.site_total, 1);
    assert_eq!(summary.already_local, 1);
    assert_eq!(summary.restored, 0);
    assert_eq!(summary.imported, 0);
    assert!(summary.unreadable.is_empty());
    // 对齐本身当然要列举一次（那是它的输入）；不该发生的是**带密钥的 reveal**——
    // 每多打一次就多一次把明文拉到内存里的机会，也白花站点配额。
    assert_eq!(
        reveals(&f),
        before,
        "钥匙串完好时不该再发 reveal 请求: {:?}",
        f.router.urls()
    );
}

#[tokio::test]
async fn a_purged_keychain_entry_makes_the_key_restorable() {
    // DEBUG 报告 §1.9：`purge_keychain` 删掉秘密但**保留行**（刻意的，bindings 靠它存活）。
    // 修复前这里报「本地已有 1 / 新导入 0」，用户按界面提示「重新取一次密钥即可恢复」
    // 却取不回来——投递与网关随后全部失败。
    let f = setup().await;
    f.vault.delete(&f.reference).unwrap();
    assert!(
        f.vault.get(&f.reference).unwrap().is_none(),
        "前提：秘密已清掉"
    );

    let summary = f.service.sync_site_keys(1).await.expect("对齐");

    assert_eq!(summary.already_local, 0, "秘密没了就不算「本地已有」");
    assert_eq!(summary.restored, 1, "应当**恢复**进原来那一行");
    assert_eq!(summary.imported, 0, "不是新建");
    assert_eq!(
        f.vault.get(&f.reference).unwrap().as_deref(),
        Some(SECRET),
        "恢复之后必须真的取回明文"
    );
    // 端到端：恢复出来的明文能通过投递路径读出来（那是恢复的意义）。
    assert_eq!(
        f.service.key_secret_for_test(f.key_id).unwrap().as_str(),
        SECRET
    );
}

#[tokio::test]
async fn restoring_does_not_create_a_second_row_for_the_same_remote_id() {
    // `keys` 表上**没有** (site_id, remote_id) 唯一约束，所以「恢复」如果走成「新建」，
    // 就会留下两条同 remote_id 的记录——之后每一处按 remote_id 判重的地方都会分叉。
    let f = setup().await;
    f.vault.delete(&f.reference).unwrap();
    f.service.sync_site_keys(1).await.expect("对齐");

    let rows = f.service.store().list_keys().unwrap();
    assert_eq!(rows.len(), 1, "恢复不得新增行: {rows:?}");
    assert_eq!(rows[0].id, f.key_id, "必须还是原来那一行");
}

#[tokio::test]
async fn a_key_that_is_only_on_the_site_is_imported() {
    // 真正的「新导入」路径不能被上面的修正压死：站点上多了一把，本地没有。
    let f = setup().await;
    f.router
        .tokens
        .lock()
        .unwrap()
        .push((2, "sk-new-999".into()));

    let summary = f.service.sync_site_keys(1).await.expect("对齐");

    assert_eq!(summary.site_total, 2);
    assert_eq!(summary.already_local, 1);
    assert_eq!(summary.restored, 0);
    assert_eq!(summary.imported, 1, "本地完全没有的那把走新建");
    assert_eq!(f.service.store().list_keys().unwrap().len(), 2);
}

#[tokio::test]
async fn a_site_that_gives_no_plaintext_is_reported_not_silently_skipped() {
    // 「站点不提供密钥明文回读」是 PRD §10 风险表里的一条。站点给了条目、没给明文时，
    // 既不能算已有、也不能算导入——要列进 `unreadable` 让界面引导用户新建。
    let f = setup().await;
    f.router.tokens.lock().unwrap().push((2, String::new()));

    let summary = f.service.sync_site_keys(1).await.expect("对齐");

    assert_eq!(summary.imported, 0);
    assert_eq!(summary.unreadable, vec!["2".to_string()]);
}
