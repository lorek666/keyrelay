//! 第 5 章非功能基线的**可复跑测量**（`docs/specs/M8-S3-非功能基线与验收矩阵.md` §3）。
//!
//! 口径（spec §3.1，**先读它再看数字**）：
//! - 假站点是**注入式、零网络**的：这里自带的 `SlowTransport` / `MockTransport`
//!   按 URL 路由，不发任何真实请求；
//! - 时钟用 [`std::time::Instant`]，**单进程内**，不测跨进程/跨机；
//! - 每次跑都打印原始行（`--nocapture` 才看得见）；**不写死阈值断言**——
//!   门槛判定写在 spec 表里由人读，把机器差异变成 CI 噪声没有意义；
//! - 唯一带断言的性能用例是 F-6：它断的是**结构性质**（并发度 ≤ N、且不丢站点），
//!   不是耗时数字。
//!
//! 本机不可测的（spec §3.3，**不得**写进「已验证」）：GUI 冷启动、真实网络下的刷新、
//! Universal 打包、Windows 安装包与冷启动、真实站点版本兼容、真实崩溃场景。

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::json;
use tianshu_relay_core::delivery::DeliveryChannel;
use tianshu_relay_core::error::Result;
use tianshu_relay_core::service::{ServiceConfig, TianshuRelayService, MAX_REFRESH_CONCURRENCY};
use tianshu_relay_core::site::transport::{
    HttpRequest, HttpResponse, HttpTransport, MockTransport,
};
use tianshu_relay_core::site::Credentials;
use tianshu_relay_core::store::Store;
use tianshu_relay_core::vault::{MemoryVault, Vault};

const QUOTA_PER_UNIT: i64 = 500_000;
const SITES_FOR_CONCURRENCY: usize = 20;

// ---------------------------------------------------------------- 夹具（与 refresh_isolation.rs 同源）

fn balance_ok(quota: i64) -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"success": true, "data": {"quota": quota, "used_quota": 0, "quota_per_unit": QUOTA_PER_UNIT}}),
    )
    .expect("构造响应")
}

fn keys_ok() -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"success": true, "data": {"items": [], "total": 0}}),
    )
    .expect("构造响应")
}

fn encryption_disabled() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": {"enabled": false}})).expect("构造响应")
}

fn login_ok() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": {"id": 7}}))
        .expect("构造响应")
        .with_header("Set-Cookie", "session=abc; Path=/")
}

/// 建一个「已登录 n 个站点」的服务（注入式、零网络）。
///
/// 返回服务与**响应队列句柄**：调用方要自己往队列里补每轮的刷新响应
/// （`refresh_all` 每个站点要两次：余额 + 令牌列表）。
async fn service_with_sites(
    dir: &Path,
    count: usize,
) -> (TianshuRelayService<MockTransport>, MockTransport, Vec<i64>) {
    let store = Store::open(&dir.join("tianshu-relay.db")).expect("文件库");
    let mock = MockTransport::new(vec![]);
    let service = TianshuRelayService::new(
        store,
        mock.clone(),
        ServiceConfig::in_memory(dir.join("home")),
    );
    let mut ids = Vec::with_capacity(count);
    for n in 0..count {
        let id = service
            .store()
            .upsert_site(
                "newapi",
                &format!("https://s{n}.example.com"),
                &format!("站{n}"),
            )
            .expect("写站点");
        ids.push(id);
    }
    // 每个站点两次登录请求（① 加密探测 ② 登录）
    for _ in 0..count {
        mock.push(encryption_disabled());
        mock.push(login_ok());
    }
    for id in &ids {
        service
            .login(*id, Credentials::new("me", "pw"))
            .await
            .unwrap_or_else(|e| panic!("登录站点 {id} 失败: {e}"));
    }
    (service, mock, ids)
}

// ---------------------------------------------------------------- 统计助手（口径写在这里，免得每处各写一遍）

fn stats(samples: &[f64]) -> (f64, f64, f64) {
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).expect("样本里没有 NaN"));
    let median = sorted[sorted.len() / 2];
    (median, sorted[0], sorted[sorted.len() - 1])
}

/// 就近取秩（nearest-rank）分位数：`p(q) = sorted[ceil(q * n) - 1]`。
fn percentile(samples: &[f64], q: f64) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).expect("样本里没有 NaN"));
    let rank = ((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

// ---------------------------------------------------------------- F-1：冷启动（核心层代理）

#[test]
fn cold_start_baseline() {
    // 口径：`Store::open` + `TianshuRelayService::new` + **首次** `sites()`，n=5 取中位。
    // 注意这是**核心层代理**：不含 Tauri 窗口、WebView、前端加载 ⇒ GUI 冷启动未验证（spec §3.3 N1）。
    let dir = tempfile::tempdir().expect("临时目录");
    let mut samples = Vec::new();
    for n in 0..5 {
        let sub = dir.path().join(format!("cold{n}"));
        fs::create_dir_all(&sub).expect("子目录");
        let started = Instant::now();
        let store = Store::open(&sub.join("tianshu-relay.db")).expect("文件库");
        let service = TianshuRelayService::new(
            store,
            MockTransport::new(vec![]),
            ServiceConfig::in_memory(sub.join("home")),
        );
        let sites = service.sites().expect("首次读站点");
        let elapsed = started.elapsed();
        assert!(sites.is_empty(), "空库的首帧应为空");
        samples.push(ms(elapsed));
    }
    let (median, min, max) = stats(&samples);
    println!(
        "F1 冷启动（核心层代理：Store::open + new + 首次 sites()，n=5）: \
         中位 {median:.2}ms / 最小 {min:.2}ms / 最大 {max:.2}ms"
    );
    println!("   PRD 门槛：冷启动 ≤ 1.5s（**GUI 那条本机不可测**，见 spec §3.3 N1）");
    // 结构性下限：冷启动不可能快到 0（库要建表）。给一个极宽的下界，
    // 只为抓「测量坏了」（比如循环没跑、Instant 用错），不是性能门槛。
    assert!(median > 0.0, "样本必须真的计时了: {samples:?}");
}

// ---------------------------------------------------------------- F-2 / F-3：刷新

#[tokio::test]
async fn single_site_refresh_baseline() {
    let dir = tempfile::tempdir().expect("临时目录");
    let (service, mock, ids) = service_with_sites(dir.path(), 1).await;
    assert_eq!(ids.len(), 1);

    let mut samples = Vec::new();
    for _ in 0..5 {
        // 每轮两次请求（① 余额 ② 令牌列表）
        mock.push(balance_ok(2_000_000));
        mock.push(keys_ok());
        let started = Instant::now();
        let summary = service.refresh_all().await.expect("整轮应 Ok");
        let elapsed = started.elapsed();
        assert_eq!((summary.sites_total, summary.sites_ok), (1, 1));
        samples.push(ms(elapsed));
    }
    let (median, min, max) = stats(&samples);
    println!(
        "F2 单站点刷新（注入式，零网络，n=5）: 中位 {median:.2}ms / 最小 {min:.2}ms / 最大 {max:.2}ms"
    );
    println!("   PRD 门槛：单站点刷新 ≤ 2s（本地网络）。**这是零网络下界**，真实 RTT 未计入（spec §3.3 N2）");
    assert!(median > 0.0, "样本必须真的计时了: {samples:?}");
}

#[tokio::test]
async fn twenty_site_refresh_baseline() {
    let dir = tempfile::tempdir().expect("临时目录");
    let (service, mock, ids) = service_with_sites(dir.path(), 20).await;
    assert_eq!(ids.len(), 20);

    let mut samples = Vec::new();
    for _ in 0..5 {
        for _ in 0..20 {
            mock.push(balance_ok(2_000_000));
            mock.push(keys_ok());
        }
        let started = Instant::now();
        let summary = service.refresh_all().await.expect("整轮应 Ok");
        let elapsed = started.elapsed();
        assert_eq!(
            (summary.sites_total, summary.sites_ok),
            (20, 20),
            "有界并发不得丢站点"
        );
        samples.push(ms(elapsed));
    }
    let (median, min, max) = stats(&samples);
    println!(
        "F3 20 站点刷新（注入式，零网络，n=5）: 中位 {median:.2}ms / 最小 {min:.2}ms / 最大 {max:.2}ms（每站点均摊 {:.3}ms）",
        median / 20.0
    );
    println!(
        "   PRD 门槛：20 个站点并发刷新 ≤ 15s。并发度 = {}（MAX_REFRESH_CONCURRENCY），形态见 F6",
        MAX_REFRESH_CONCURRENCY
    );
    assert!(median > 0.0, "样本必须真的计时了: {samples:?}");
}

// ---------------------------------------------------------------- F-4：注入耗时

#[test]
fn injection_latency_p95() {
    // 口径：20 次 `delivery_plan_with_model` + `apply_delivery_with_model`，
    // 只测 `CodexAuthJson` 一条通道（spec §14：其余 6 条同源但未逐条计时）。
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let store = Store::open(&dir.path().join("tianshu-relay.db")).expect("文件库");
    let site_id = store
        .upsert_site("newapi", "https://relay.example.com", "测试站")
        .expect("写站点");
    let secret_ref = tianshu_relay_core::vault::secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &secret_ref, Some("1"), None)
        .expect("写密钥记录");
    let vault = Arc::new(MemoryVault::new());
    vault
        .put(&secret_ref, "sk-0123456789abcdefSECRET")
        .expect("写钥匙串");

    let service = TianshuRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault,
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
            data_dir: None,
        },
    );
    service
        .grant_consent(key_id, DeliveryChannel::CodexAuthJson)
        .expect("记录同意");
    assert!(
        service
            .delivery_plan(key_id, DeliveryChannel::CodexAuthJson)
            .expect("计划")
            .consent
            .is_granted(),
        "同意必须被记下来，否则下面的 apply 全是 ConsentRequired"
    );

    let mut plan_samples = Vec::new();
    let mut apply_samples = Vec::new();
    for _ in 0..20 {
        let started = Instant::now();
        let plan = service
            .delivery_plan(key_id, DeliveryChannel::CodexAuthJson)
            .expect("计划");
        let plan_elapsed = started.elapsed();

        let started = Instant::now();
        service
            .apply_delivery(key_id, DeliveryChannel::CodexAuthJson)
            .expect("注入");
        let apply_elapsed = started.elapsed();

        assert!(
            !plan.preview.contains("sk-0123456789abcdefSECRET"),
            "预览不得含密钥"
        );
        plan_samples.push(ms(plan_elapsed));
        apply_samples.push(ms(apply_elapsed));
    }
    // 合计按**同一次迭代的 plan + apply** 相加（不是两个分位数相加）
    let totals: Vec<f64> = plan_samples
        .iter()
        .zip(&apply_samples)
        .map(|(p, a)| p + a)
        .collect();
    println!(
        "F4 注入耗时（n=20，CodexAuthJson）: plan p50 {:.3}ms / p95 {:.3}ms；apply p50 {:.3}ms / p95 {:.3}ms；合计 p50 {:.3}ms / p95 {:.3}ms",
        percentile(&plan_samples, 0.5),
        percentile(&plan_samples, 0.95),
        percentile(&apply_samples, 0.5),
        percentile(&apply_samples, 0.95),
        percentile(&totals, 0.5),
        percentile(&totals, 0.95),
    );
    println!("   PRD 门槛：注入操作 p95 ≤ 300ms（不含 agent 重启）");
    assert!(percentile(&totals, 0.95) > 0.0, "样本必须真的计时了");
}

// ---------------------------------------------------------------- F-5：产物体量

#[test]
fn artifact_sizes_baseline() {
    // 口径：`dist/` 全量字节 + 每个文件的字节；release 二进制与 aarch64 DMG 的字节。
    // **不存在就跳过并打印「未构建」**——CI 上没跑 `pnpm build` / `cargo tauri build` 是正常的，
    // 不该因此红。Universal 与 Windows 产物**不测**（spec §3.3 N3 / N4）。
    let root = workspace_root();

    let dist = root.join("dist");
    if dist.is_dir() {
        let mut files: Vec<(u64, PathBuf)> = Vec::new();
        let mut total = 0u64;
        collect_files(&dist, &mut files, &mut total);
        // 按字节数降序：大的在前，读起来就是「谁占了体积」
        files.sort_by_key(|(size, _)| std::cmp::Reverse(*size));
        println!("F5 前端产物（dist/）: 总计 {total} B");
        for (size, path) in &files {
            println!(
                "   {} B  {}",
                size,
                path.strip_prefix(&root).unwrap_or(path).display()
            );
            assert!(*size > 0, "空文件意味着构建坏了: {}", path.display());
        }
    } else {
        println!("F5 前端产物（dist/）: 未构建（跳过）");
    }

    for (label, path) in [
        ("release 二进制", root.join("target/release/tianshu-relay")),
        (
            "macOS 安装包（aarch64）",
            root.join("target/release/bundle/dmg/天枢 Relay_0.1.0_aarch64.dmg"),
        ),
    ] {
        match fs::metadata(&path) {
            Ok(meta) => {
                println!("F5 {label}: {} B", meta.len());
                assert!(meta.len() > 0, "{label} 是空文件: {}", path.display());
            }
            Err(_) => println!("F5 {label}: 未构建（跳过）"),
        }
    }
    println!("   PRD 门槛：安装包 ≤ 30 MB（macOS **Universal**）/ ≤ 15 MB（Windows）——两者本机均**未验证**");
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("工作区根")
        .to_path_buf()
}

fn collect_files(dir: &Path, out: &mut Vec<(u64, PathBuf)>, total: &mut u64) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("读目录 {} 失败: {e}", dir.display()));
    for entry in entries {
        let entry = entry.expect("目录项");
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out, total);
        } else if let Ok(meta) = entry.metadata() {
            *total += meta.len();
            out.push((meta.len(), path));
        }
    }
}

// ---------------------------------------------------------------- F-6：有界并发 + 不丢站点（O-1 裁决 ①）

/// **会真的睡**的假传输层：用来把「并发」变成可观测的墙钟时间。
///
/// 登录路径（`/api/user/login*`）**不睡**：装配 20 个站点的会话不该也花 4 秒。
/// 睡眠只发生在刷新路径（余额 / 令牌列表）——那正是要测并发度的区间。
#[derive(Clone)]
struct SlowTransport {
    delay: Duration,
    /// 当前「在途」的请求数（模拟 RTT 的睡眠区间内）
    in_flight: Arc<AtomicUsize>,
    /// 观测到的在途峰值 = 实际同时刷新的站点数上限
    max_in_flight: Arc<AtomicUsize>,
    /// 每个 URL 被请求了几次（用来证明「每站恰好两次、不重不漏」）
    per_url: Arc<Mutex<HashMap<String, usize>>>,
}

impl SlowTransport {
    fn new(delay: Duration) -> Self {
        Self {
            delay,
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight: Arc::new(AtomicUsize::new(0)),
            per_url: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn enter(&self) {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
    }

    fn leave(&self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }

    fn hits(&self, url: &str) -> usize {
        self.per_url
            .lock()
            .ok()
            .and_then(|map| map.get(url).copied())
            .unwrap_or(0)
    }
}

#[async_trait]
impl HttpTransport for SlowTransport {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse> {
        let url = req.url.clone();
        if let Ok(mut map) = self.per_url.lock() {
            *map.entry(url.clone()).or_insert(0) += 1;
        }

        // 加密探测必须先于登录判断：前者的路径是后者的前缀
        let response = if url.contains("/api/user/login/encryption-key") {
            encryption_disabled()
        } else if url.contains("/api/user/login") {
            login_ok()
        } else if url.contains("/api/user/self") {
            balance_ok(2_000_000)
        } else if url.contains("/api/token/") {
            keys_ok()
        } else {
            return Err(tianshu_relay_core::error::Error::Transport(format!(
                "夹具没有为这个 URL 准备响应: {url}"
            )));
        };

        if url.contains("/api/user/login") {
            // 装配阶段不睡（否则光登录就要 20 × 2 × 100ms）
            return Ok(response);
        }
        self.enter();
        tokio::time::sleep(self.delay).await;
        self.leave();
        Ok(response)
    }
}

#[tokio::test]
async fn refresh_all_is_bounded_concurrent_and_loses_no_site() {
    // O-1 裁决 ①（spec §3.4）：`refresh_all` 是**有界并发**，不是顺序循环。
    // 这条用例钉住三件事，任何一条被改坏都会红：
    //   ① 并发度 ≤ MAX_REFRESH_CONCURRENCY（不会一次打爆站点）；
    //   ② 并发度 ≥ 2（**不是**顺序循环——否则退回 O-1 异议状态）；
    //   ③ 20 个站点一个不丢（每站恰好两次请求：余额 + 令牌列表）。
    // 判据全部来自**测量**（在途计数器 + 墙钟），不是 grep 源码。
    let delay = Duration::from_millis(100);
    let dir = tempfile::tempdir().expect("临时目录");
    let store = Store::open(&dir.path().join("tianshu-relay.db")).expect("文件库");
    let transport = SlowTransport::new(delay);
    let service = TianshuRelayService::new(
        store,
        transport.clone(),
        ServiceConfig::in_memory(dir.path().join("home")),
    );
    for n in 0..SITES_FOR_CONCURRENCY {
        service
            .store()
            .upsert_site(
                "newapi",
                &format!("https://s{n}.example.com"),
                &format!("站{n}"),
            )
            .expect("写站点");
    }
    let ids: Vec<i64> = service
        .sites()
        .expect("读站点")
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(ids.len(), SITES_FOR_CONCURRENCY);
    for id in &ids {
        service
            .login(*id, Credentials::new("me", "pw"))
            .await
            .unwrap_or_else(|e| panic!("登录站点 {id} 失败: {e}"));
    }

    let started = Instant::now();
    let summary = service.refresh_all().await.expect("整轮应 Ok");
    let wall = started.elapsed();

    // ③ 不丢站点
    assert_eq!(summary.sites_total, SITES_FOR_CONCURRENCY);
    assert_eq!(
        summary.sites_ok, SITES_FOR_CONCURRENCY,
        "有界并发把站点弄丢了：{summary:?}"
    );
    for n in 0..SITES_FOR_CONCURRENCY {
        let host = format!("s{n}.example.com");
        assert_eq!(
            transport.hits(&format!("https://{host}/api/user/self")),
            1,
            "{host} 的余额请求不是恰好一次"
        );
        assert_eq!(
            transport.hits(&format!("https://{host}/api/token/?p=1&page_size=100")),
            1,
            "{host} 的令牌列表请求不是恰好一次"
        );
    }

    // ①② 并发度
    let peak = transport.max_in_flight.load(Ordering::SeqCst);
    assert!(
        peak <= MAX_REFRESH_CONCURRENCY,
        "并发度 {peak} 越过上限 {}——一次打爆站点就是这个后果",
        MAX_REFRESH_CONCURRENCY
    );
    assert!(
        peak >= 2,
        "峰值在途只有 {peak}：这不是并发，是顺序循环（O-1 的异议状态）"
    );

    // 墙钟：每站 2 × 100ms = 200ms 的工作量。
    //   顺序   ⇒ ≥ 20 × 200ms = 4000ms
    //   有界(4) ⇒ ≥ ceil(20/4) × 200ms = 1000ms，且远小于 4000ms
    // 给「顺序量级的 90%」上界 / 0.9s 下界：两侧都留足调度余量，
    // 但足以把「顺序」与「无界」分开。
    let wall_ms = ms(wall);
    println!(
        "F6 有界并发刷新: {} 站点 × 2 × 100ms，墙钟 {wall_ms:.0}ms，峰值在途 {peak}/{}",
        SITES_FOR_CONCURRENCY, MAX_REFRESH_CONCURRENCY
    );
    println!(
        "   （顺序循环会是 ≥ {}ms；无界并发会是 ≈ {}ms）",
        SITES_FOR_CONCURRENCY * 2 * 100,
        2 * 100
    );
    // 上界挂在「顺序量级」上而不是拍死一个常数：顺序循环是
    // `SITES × 2 × delay`（4000ms），阈值取它的 90%。负载只会让墙钟变大，
    // 而有界并发本来就该远小于顺序量级 ⇒ 慢机器 / CI 上不会假红
    // （独立复审 P3-3：写死 3000ms 在全量并行 + 负载下余量只有 2.9×）。
    let sequential_floor_ms = (SITES_FOR_CONCURRENCY * 2 * delay.as_millis() as usize) as f64;
    assert!(
        wall_ms < sequential_floor_ms * 0.9,
        "墙钟 {wall_ms:.0}ms 已接近顺序循环的量级（{sequential_floor_ms:.0}ms）——并发没生效？"
    );
    assert!(
        wall_ms >= 900.0,
        "墙钟 {wall_ms:.0}ms 太小：要么睡眠没生效，要么并发没有上界"
    );
}
