//! 模型目录持久化与热更新（M39-S1）。
//!
//! 覆盖：启动加载（表 → 路由）/ 替换 / 连续空才清空 / 失败不变 / 有界并发（**实际在途** ≤ 2）/
//! 只受 `collect_models` 控制（与 `gateway_multi_site` 解耦）/ 发布快照 / 镜像语义。
//!
//! 全部用 `MockTransport` 或本地计数传输层，**不联网**。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;
use tianshu_relay_core::error::Result;
use tianshu_relay_core::service::{ServiceConfig, TianshuRelayService};
use tianshu_relay_core::site::transport::{
    HttpRequest, HttpResponse, HttpTransport, MockTransport,
};
use tianshu_relay_core::store::Store;
use tianshu_relay_core::vault::{secret_ref, MemoryVault, Vault};

const KEY: &str = "sk-catalog-0123456789abcdef";
const BASE: &str = "https://relay.example.com";

fn models_response(ids: &[&str]) -> HttpResponse {
    let data: Vec<_> = ids.iter().map(|id| json!({ "id": id })).collect();
    HttpResponse::json(200, json!({ "data": data })).expect("构造响应")
}

fn models(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// 会「停留」一小段的传输层：把并发变成可观测的**在途峰值**（M39-S1 §12 的硬要求）。
#[derive(Clone)]
struct CountingTransport {
    inner: MockTransport,
    delay: Duration,
    in_flight: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

impl CountingTransport {
    fn new(delay: Duration) -> Self {
        Self {
            inner: MockTransport::new(vec![]),
            delay,
            in_flight: Arc::new(AtomicUsize::new(0)),
            peak: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn push(&self, response: HttpResponse) {
        self.inner.push(response);
    }

    fn requests(&self) -> usize {
        self.inner.request_count()
    }

    /// 观察到的**同时**在途上限。
    fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl HttpTransport for CountingTransport {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse> {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        // 停留一会儿，让并发真的重叠（否则瞬间返回永远测不出峰值）。
        tokio::time::sleep(self.delay).await;
        let out = self.inner.request(req).await;
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        out
    }
}

struct Svc {
    _dir: tempfile::TempDir,
    service: TianshuRelayService<CountingTransport>,
    transport: CountingTransport,
}

/// 建 `site_count` 个站点（各一把 key + 明文）。不 login（无 session）。
fn setup(site_count: usize, delay: Duration) -> Svc {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let store = Store::open(&dir.path().join("tianshu-relay.db")).expect("建库");
    let vault = Arc::new(MemoryVault::new());
    for i in 1..=site_count {
        let site_id = store
            .upsert_site("newapi", &format!("{BASE}/s{i}"), &format!("站{i}"))
            .expect("写站点");
        let reference = secret_ref("key", i, "secret");
        store
            .insert_key(
                site_id,
                &format!("k{i}"),
                &reference,
                Some(&i.to_string()),
                None,
            )
            .expect("写密钥");
        vault.put(&reference, KEY).expect("写明文");
    }
    let transport = CountingTransport::new(delay);
    let service = TianshuRelayService::new(
        store,
        transport.clone(),
        ServiceConfig {
            vault,
            home,
            backup_dir: dir.path().join("backups"),
        },
    );
    Svc {
        _dir: dir,
        service,
        transport,
    }
}

fn enable_collect(svc: &Svc) {
    svc.service
        .store()
        .set_setting("collect_models", "true")
        .expect("开采集");
}

fn enable_multi_site(svc: &Svc) {
    svc.service
        .store()
        .set_setting("gateway_multi_site", "true")
        .expect("开多站");
}

fn first_key(svc: &Svc) -> (i64, i64) {
    let row = svc
        .service
        .store()
        .list_keys()
        .expect("列密钥")
        .into_iter()
        .next()
        .expect("有密钥");
    (row.site_id, row.id)
}

// ============================================================ 启动加载 / 替换

/// 目录在表里 ⇒ 路由就有它（这就是「重启后模型仍在」：不需要任何采集）。
#[test]
fn startup_route_comes_from_the_persisted_catalog() {
    let svc = setup(1, Duration::ZERO);
    let (site, key_id) = first_key(&svc);
    // 直接往表里写（模拟「上一次运行采集过」）
    svc.service
        .store()
        .replace_site_models(site, &models(&["alpha", "beta"]), 100)
        .expect("写目录");
    enable_multi_site(&svc);

    let config = svc
        .service
        .gateway_config(site, key_id, 0)
        .expect("装配网关配置");

    let hit: Vec<i64> = config
        .route
        .candidates("alpha")
        .iter()
        .map(|u| u.site_id)
        .collect();
    assert!(hit.contains(&site), "目录里的模型必须能选到该站：{hit:?}");
    assert!(
        config
            .route
            .candidates("nonexistent-model")
            .iter()
            .all(|u| u.site_id != site),
        "**没有**通配：目录存在时按精确匹配（空=通配只用于未知）"
    );
}

/// 成功非空 ⇒ **替换**（下架模型必须消失）。
#[tokio::test]
async fn a_successful_collection_replaces_the_previous_set() {
    let svc = setup(1, Duration::ZERO);
    enable_collect(&svc);
    svc.transport.push(models_response(&["a", "b"]));
    svc.service
        .refresh_model_catalog_once()
        .await
        .expect("第一趟");

    let (site, _) = first_key(&svc);
    assert_eq!(
        svc.service.store().site_models(site).unwrap(),
        models(&["a", "b"])
    );

    // 第二趟只报 [b, c] ⇒ a 必须消失
    svc.transport.push(models_response(&["b", "c"]));
    svc.service
        .store()
        .set_setting("models_min_interval_secs", "0")
        .expect("不节流");
    svc.service
        .refresh_model_catalog_once()
        .await
        .expect("第二趟");

    assert_eq!(
        svc.service.store().site_models(site).unwrap(),
        models(&["b", "c"]),
        "替换语义：下架的 a 必须消失"
    );
}

// ============================================================ 空 / 失败

/// 成功但空：**连续两次**才清空（一次空只是 streak=1）。
#[tokio::test]
async fn an_empty_response_clears_only_after_two_consecutive_passes() {
    let svc = setup(1, Duration::ZERO);
    enable_collect(&svc);
    svc.service
        .store()
        .set_setting("models_min_interval_secs", "0")
        .expect("不节流");
    let (site, _) = first_key(&svc);
    svc.service
        .store()
        .replace_site_models(site, &models(&["a"]), 1)
        .expect("预置目录");

    svc.transport.push(models_response(&[]));
    let first = svc
        .service
        .refresh_model_catalog_once()
        .await
        .expect("第一趟");
    assert_eq!(first.empty, 1);
    assert!(first.cleared.is_empty());
    assert_eq!(
        svc.service.store().site_models(site).unwrap(),
        models(&["a"]),
        "一次空不得清空"
    );

    svc.transport.push(models_response(&[]));
    let second = svc
        .service
        .refresh_model_catalog_once()
        .await
        .expect("第二趟");
    assert_eq!(second.empty, 1);
    assert_eq!(second.cleared, vec![site], "连续两次空必须清空");
    assert_eq!(
        svc.service.store().site_models(site).unwrap(),
        Vec::<String>::new()
    );
}

/// 失败：目录与 streak 不变，只记 last_attempt_at / last_error（已脱敏）。
#[tokio::test]
async fn a_failed_collection_changes_nothing_but_the_error_column() {
    let svc = setup(1, Duration::ZERO);
    enable_collect(&svc);
    svc.service
        .store()
        .set_setting("models_min_interval_secs", "0")
        .expect("不节流");
    let (site, _) = first_key(&svc);
    svc.service
        .store()
        .replace_site_models(site, &models(&["a"]), 1)
        .expect("预置目录");

    svc.transport
        .push(HttpResponse::json(500, json!({ "error": "boom" })).unwrap());
    let summary = svc
        .service
        .refresh_model_catalog_once()
        .await
        .expect("失败不报错");
    assert_eq!(summary.failed, 1);
    assert_eq!(
        svc.service.store().site_models(site).unwrap(),
        models(&["a"]),
        "失败不得动目录"
    );
    let sync = svc
        .service
        .store()
        .site_model_sync(site)
        .unwrap()
        .expect("有行");
    assert_eq!(sync.empty_streak, 0);
    assert!(sync.last_error.is_some(), "失败必须留痕");
    assert!(sync.last_attempt_at.is_some());
}

// ============================================================ 有界并发

/// **实际在途** ≤ 2，且峰值确实到过 2（只测「≤2」会漏掉「其实串行」的假实现）。
#[tokio::test]
async fn collection_is_bounded_to_two_concurrent_sites() {
    let svc = setup(4, Duration::from_millis(40));
    enable_collect(&svc);
    for _ in 0..4 {
        svc.transport.push(models_response(&["m"]));
    }
    let summary = svc
        .service
        .refresh_model_catalog_once()
        .await
        .expect("采集");
    assert_eq!(summary.attempted, 4, "4 个站都要采");
    assert_eq!(
        svc.transport.peak(),
        2,
        "同时在途必须恰好 2（上限，且不是串行）"
    );
}

// ============================================================ 开关 / 解耦

/// 采集的**唯一**门槛是 `collect_models`：关 ⇒ 0 请求 0 写入；
/// `gateway_multi_site=false` **不影响采集**（它只决定网关要不要用目录）。
#[tokio::test]
async fn collection_requires_collect_models_only() {
    let svc = setup(1, Duration::ZERO);
    // 两个开关都关（默认）
    let summary = svc
        .service
        .refresh_model_catalog_once()
        .await
        .expect("空转");
    assert_eq!(svc.transport.requests(), 0, "collect_models=false ⇒ 0 请求");
    assert_eq!(summary.attempted, 0);
    let (site, _) = first_key(&svc);
    assert_eq!(
        svc.service.store().site_models(site).unwrap(),
        Vec::<String>::new()
    );

    // 只开 collect_models，多站仍然关 ⇒ 照常采集（M14-S1 的独立开关，服务通知）
    enable_collect(&svc);
    svc.transport.push(models_response(&["a"]));
    let summary = svc
        .service
        .refresh_model_catalog_once()
        .await
        .expect("采集");
    assert_eq!(summary.attempted, 1, "多站关着也要采");
    assert_eq!(
        svc.service.store().site_models(site).unwrap(),
        models(&["a"])
    );
}

/// 采集与 `refresh_all` 解耦：不调 `refresh_all` 也能采到并发布。
#[tokio::test]
async fn collection_is_independent_of_refresh_all() {
    let svc = setup(1, Duration::ZERO);
    enable_collect(&svc);
    enable_multi_site(&svc);
    let (site, key_id) = first_key(&svc);
    let config = svc.service.gateway_config(site, key_id, 0).expect("装配");

    svc.transport.push(models_response(&["a"]));
    let summary = svc
        .service
        .refresh_model_catalog_once()
        .await
        .expect("采集");
    assert_eq!(summary.attempted, 1);
    assert!(summary.published, "目录变了就该发布");
    assert_eq!(
        svc.service.gateway_snapshot_generation(),
        2,
        "首个快照 1 → 发布后 2"
    );

    // 新快照里能选到新模型
    let snapshot = config
        .runtime
        .as_ref()
        .expect("有 runtime")
        .read()
        .unwrap()
        .clone();
    assert!(snapshot
        .route
        .candidates("a")
        .iter()
        .any(|u| u.site_id == site));
}

/// 多站关着 ⇒ 采集照常，但**不建 runtime**（网关仍走 legacy）。
#[tokio::test]
async fn collecting_without_multi_site_does_not_build_a_runtime() {
    let svc = setup(1, Duration::ZERO);
    enable_collect(&svc); // 只开采集
    svc.transport.push(models_response(&["a"]));
    svc.service
        .refresh_model_catalog_once()
        .await
        .expect("采集");
    let (site, _) = first_key(&svc);
    assert_eq!(
        svc.service.store().site_models(site).unwrap(),
        models(&["a"]),
        "目录照常更新（通知要用）"
    );

    let (site, key_id) = first_key(&svc);
    let config = svc.service.gateway_config(site, key_id, 0).expect("装配");
    assert!(config.runtime.is_none(), "多站关着不得建 runtime");
    assert!(config.route.is_empty(), "多站关着走 legacy 单上游");
    assert_eq!(svc.service.gateway_snapshot_generation(), 0);
}

// ============================================================ 发布 / 节流 / 镜像

/// 没有运行态时发布是 no-op（返回 0），不报错。
#[tokio::test]
async fn publishing_without_a_running_gateway_is_a_no_op() {
    let svc = setup(1, Duration::ZERO);
    assert_eq!(svc.service.publish_gateway_snapshot().expect("no-op"), 0);
    assert_eq!(svc.service.gateway_snapshot_generation(), 0);
}

/// 节流锚点是 `last_attempt_at`（**失败也算一次尝试**），不是 `last_success_at`。
///
/// 用「last_success 很旧、last_attempt 刚刚」的夹具区分两个锚点（不靠 sleep）：
/// 正确实现在这种状态下必须**继续节流**；若把锚点写成 `last_success_at`，就会立刻再打一次。
#[tokio::test]
async fn a_throttled_site_is_skipped_using_last_attempt_at() {
    let svc = setup(1, Duration::ZERO);
    enable_collect(&svc);
    let (site, _) = first_key(&svc);

    // 夹具：成功发生在 4000 秒前（远超过默认 1800s 的节流窗），随后刚刚失败过一次。
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("时钟")
        .as_secs() as i64;
    svc.service
        .store()
        .replace_site_models(site, &models(&["a"]), now - 4000)
        .expect("预置目录");
    svc.service
        .store()
        .record_site_models_failure(site, now, "boom")
        .expect("刚刚失败过");
    let sync = svc
        .service
        .store()
        .site_model_sync(site)
        .unwrap()
        .expect("有行");
    assert_eq!(sync.last_success_at, Some(now - 4000), "成功是旧的");
    assert_eq!(sync.last_attempt_at, Some(now), "尝试是刚刚的");

    // 默认 models_min_interval_secs = 1800 ⇒ 按 last_attempt 必须被节流（0 请求）
    svc.transport.push(models_response(&["b"]));
    let summary = svc
        .service
        .refresh_model_catalog_once()
        .await
        .expect("被节流");
    assert_eq!(
        summary.attempted, 0,
        "节流期内不得发请求（锚点是 last_attempt_at）"
    );
    assert_eq!(svc.transport.requests(), 0);

    // 正向对照：把间隔放开 ⇒ 该采（证明上一条不是「永远不采」的假绿）
    svc.service
        .store()
        .set_setting("models_min_interval_secs", "0")
        .expect("放开");
    svc.transport.push(models_response(&["b"]));
    let summary = svc
        .service
        .refresh_model_catalog_once()
        .await
        .expect("放开后应采");
    assert_eq!(summary.attempted, 1);
    assert_eq!(svc.transport.requests(), 1);
}

/// 通知侧的镜像跟随目录：采到就同步，清空才清空。
#[tokio::test]
async fn the_mirror_follows_the_catalog_and_clears_only_with_it() {
    let svc = setup(1, Duration::ZERO);
    enable_collect(&svc);
    svc.service
        .store()
        .set_setting("models_min_interval_secs", "0")
        .expect("不节流");
    let (site, _) = first_key(&svc);

    svc.transport.push(models_response(&["a"]));
    svc.service
        .refresh_model_catalog_once()
        .await
        .expect("采集");
    assert_eq!(
        svc.service.site_model_mirror().get(&site),
        Some(&models(&["a"]))
    );

    // 一次空：目录与镜像都还在
    svc.transport.push(models_response(&[]));
    svc.service
        .refresh_model_catalog_once()
        .await
        .expect("空一次");
    assert_eq!(
        svc.service.site_model_mirror().get(&site),
        Some(&models(&["a"]))
    );

    // 第二次空：目录清空 ⇒ 镜像跟着清空
    svc.transport.push(models_response(&[]));
    svc.service
        .refresh_model_catalog_once()
        .await
        .expect("空两次");
    assert_eq!(
        svc.service.site_model_mirror().get(&site),
        Some(&Vec::<String>::new())
    );
}
