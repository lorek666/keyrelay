//! Tauri 桌面壳：只做「命令注册 + 状态管理 + 平台胶水」。
//!
//! 业务逻辑一律在 `keyrelay-core`，本 crate 不出现 SQL、HTTP、文件改写逻辑。
//!
//! `configure` / `configure_with_state` 之所以单独暴露，是为了让 IPC 测试
//! （`tests/commands.rs`）能用 Tauri 官方 mock runtime 复用同一套命令注册。

mod commands;
pub mod commands_list;
pub mod tray;

use std::path::PathBuf;

use tauri::Manager;

use keyrelay_core::proxy::{self, ProxyMode};
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::settings::Settings;
use keyrelay_core::site::registry::SiteRegistry;
use keyrelay_core::site::retry::{RetryPolicy, RetryingTransport};
use keyrelay_core::site::transport_reqwest::{ReqwestTransport, TransportConfig};
use keyrelay_core::site::SiteFingerprint;
use keyrelay_core::store::Store;
use keyrelay_core::Result;

/// 生产装配：真实 reqwest + 重试装饰器
pub type AppTransport = RetryingTransport<ReqwestTransport>;

pub struct AppState {
    pub service: KeyRelayService<AppTransport>,
    pub db_path: PathBuf,
    /// 数据库打开失败时的原因（用于在 UI 上明确提示，而不是静默降级）
    pub db_error: Option<String>,
    /// 正在运行的本地网关（同一时刻只允许一个）。
    ///
    /// 存的是 [`commands::GatewayRunning`]（handle + 启动时绑定的 site_id / key_id），
    /// 不是裸 `GatewayHandle`：P1-6 —— 令牌轮换要从这里读 site/key，而不是用可能
    /// 被切页污染成默认值的命令参数。
    pub gateway: std::sync::Mutex<Option<crate::commands::GatewayRunning>>,
    /// 把「停旧 → 绑新」整个序列串起来（M5-S5 / 关闭 B-64 的命令层那一半）。
    ///
    /// 必须是**异步**锁：`gateway_start` 里要 `await` `shutdown_and_wait()`，
    /// 而 `std::sync::MutexGuard` 不能跨 `await`（不是 `Send`）。
    /// 用 std 锁只在取 `Option` 时上锁，等于没修 —— 两个并发启动仍会各自 bind。
    pub gateway_op: tokio::sync::Mutex<()>,
    /// 把人工验证的三个命令（`captcha_begin` / `captcha_complete` / `captcha_cancel`）串起来
    /// （P3-15）。
    ///
    /// 修前的问题：`captcha_complete` 要抓一次 WebView cookie（毫秒级，但**跨 await**），
    /// 期间 `captcha_cancel` 可以把相位打回 `Idle`——于是「用户点了取消，会话却接上了」，
    /// 或者反过来「取消被提交覆盖」。相位在 `service.rs` 里是「读一次、写一次」两把锁，
    /// 而命令层是**唯一的并发入口**：把它串行化就消除了这条竞态。
    ///
    /// 与 `gateway_op` 同款（必须是异步锁：要跨 `await` 持有）。
    pub captcha_op: tokio::sync::Mutex<()>,
    /// 托盘图标是否真的建起来了（M6-S5）。
    ///
    /// 这个标志位决定「能不能隐藏窗口」：托盘不可用时隐藏窗口会把应用变成
    /// 用户碰不到的后台进程。无 GUI 会话（CI / SSH / headless）下建不出托盘是**正常**结果，
    /// 所以默认 `false`，由 `setup` 里的真实结果覆盖。
    pub tray_available: std::sync::atomic::AtomicBool,
}

/// 用户主目录。解析逻辑在 `keyrelay_core::platform`（按平台处理 `KEYRELAY_HOME` /
/// `USERPROFILE` / `HOMEDRIVE`+`HOMEPATH` / `HOME`）。
///
/// 壳层这里只做「解析不出来就明确退出」——**不静默退化成当前目录**
/// （否则在 Windows 上会把密钥写到 `C:\Program Files\...`，用户找不到）。
pub fn home_dir() -> PathBuf {
    match keyrelay_core::platform::home_dir() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("[keyrelay] {err}");
            std::process::exit(1);
        }
    }
}

/// `~/.keyrelay/keyrelay.db`
pub fn default_db_path() -> PathBuf {
    home_dir().join(".keyrelay").join("keyrelay.db")
}

fn build_transport_with_proxy(proxy: Option<String>) -> AppTransport {
    let config = TransportConfig {
        proxy,
        ..TransportConfig::default()
    };
    match ReqwestTransport::new(config) {
        Ok(inner) => RetryingTransport::new(inner, RetryPolicy::default()),
        Err(err) => {
            // 默认配置理论上不会失败；真失败说明构建环境异常，明确退出而不是静默降级
            eprintln!("[keyrelay] 构造 HTTP 传输层失败: {err}");
            std::process::exit(1);
        }
    }
}

/// M15-S1 复审 H1+M2 / B-160：probe 专用 transport。
///
/// 与站点 transport 的两点差异：
/// - **不套 `RetryingTransport`**：429 由 probe 层自己映射成 `RateLimited` 告诉用户，
///   不该被站点重试策略抢着重试（Retry-After 被 cap 到 5s，白打 + 等 10s）。
/// - **timeout 120s**：这是「单次请求挂死的上界」，**不是**检测总时长。B-160 起 probe 主路径
///   是 `sync=false` 提交（真机 0.75s 返回）加轮询，每条连接都是短请求；整轮检测要等多久
///   由 `PollPolicy::budget` 决定（默认 900s）。旧实现把 120s 当检测总时长用，而真机实测
///   一次重模型要 **360.53s** ⇒ 必然超时、丢掉服务端已经给出的判定。
fn build_probe_transport(proxy: Option<String>) -> ReqwestTransport {
    let config = TransportConfig {
        timeout: std::time::Duration::from_secs(120),
        proxy,
        ..TransportConfig::default()
    };
    match ReqwestTransport::new(config) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("[keyrelay] 构造 probe 传输层失败: {err}");
            std::process::exit(1);
        }
    }
}

/// M14-S7 §4.2：models.dev 在线补全专用 transport。
///
/// 与站点 transport 的差异只有一点：**不套 `RetryingTransport`**。models.dev 是第三方
/// 服务，重试策略会把「网络不通」放大成 3 次尝试 × 15s，而这笔开销挂在**投递预览**的
/// 关键路径上。这里要的是「一次、短、失败就当没查到」——在线补全失败只退化成
/// 「只写模型名」，绝不该让用户等 45 秒。
///
/// timeout 用 `TransportConfig::default()` 的 15s（spec §4.2 写的就是 15s）。
fn build_meta_transport(proxy: Option<String>) -> ReqwestTransport {
    let config = TransportConfig {
        proxy,
        ..TransportConfig::default()
    };
    match ReqwestTransport::new(config) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("[keyrelay] 构造模型元数据传输层失败: {err}");
            std::process::exit(1);
        }
    }
}

/// 从 store 读 settings，按 `proxy_mode` 解析出最终代理 URL（M10-S2）。
///
/// 站点适配器 transport 在启动时构造一次、不可变（与 B-54 同口径：代理变更需重启 app）。
/// 解析失败（manual 非法）⇒ 返回 None 并打印告警，**不让 app 因为代理配置非法而退出**——
/// 用户还能进设置页改掉它；auto 模式探测失败自然就是 None（直连）。
pub fn resolved_proxy_url(store: &Store) -> Option<String> {
    let settings = Settings::load_from_store(store).ok()?;
    let mode = ProxyMode::parse(&settings.proxy_mode).unwrap_or(ProxyMode::Auto);
    match proxy::resolve_proxy(mode, &settings.proxy_url) {
        Ok(Some(d)) => Some(d.url),
        Ok(None) => None,
        Err(err) => {
            // manual 非法：不退出，告警并直连，让用户能进设置页修
            eprintln!("[keyrelay] 代理配置非法，本次直连: {err}");
            None
        }
    }
}

/// 仅做指纹识别（不落库），供前端「测试连接」按钮使用。
///
/// 代理从 `state.service` 的 settings 解析（与生产 transport 同一份逻辑），保证
/// 「测试连接能过 ⇔ 实际请求能过」——不再各走各的（M10-S2 关闭计划书 §2 的死配置）。
pub async fn detect_only(base_url: &str, proxy: Option<String>) -> Result<SiteFingerprint> {
    SiteRegistry::new(build_transport_with_proxy(proxy))
        .detect(base_url)
        .await
}

fn state_from_store(store: Store, db_path: PathBuf, db_error: Option<String>) -> AppState {
    state_with_config(
        store,
        db_path,
        db_error,
        ServiceConfig::production(home_dir()),
        OnlineModelMeta::Enabled,
    )
}

/// 测试用：内存钥匙串，绝不触碰用户真实钥匙串与 `~/.keyrelay`。
fn state_in_memory(store: Store, db_path: PathBuf) -> AppState {
    // **每个 app 一个独立目录**（进程内自增序号）。
    //
    // 原先只用 pid：一个测试进程里所有 app 共享同一个 `keyrelay-test-<pid>`，
    // 于是「另一个测试写进 `exports` / `backups` 的文件」会被本测试的审计扫描到——
    // `export_diagnostics_writes_a_package_and_registers_it_for_the_audit` 的
    // 「文件数必须 +1」因此变成一条**看时序**的断言（并发跑时偶发红）。
    // 隔离目录之后，扫描集合只由本 app 自己写过的东西决定。
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let tmp = std::env::temp_dir().join(format!("keyrelay-test-{}-{seq}", std::process::id()));
    state_with_config(
        store,
        db_path,
        None,
        ServiceConfig::in_memory(tmp),
        OnlineModelMeta::Disabled,
    )
}

/// 是否给服务装配「models.dev 在线补全」的传输层（M14-S7 §4.2）。
///
/// 生产要装：用户在投递页填模型名时要能在线补上下文/输出参数。
/// **测试装配不装**：投递命令会在预览时预热模型元数据，装了真传输层就会真的去打
/// models.dev（实测把 `tests/commands.rs` 从 2.8s 拖到 10.9s，并连带影响同轮其它网络用例）。
/// 用枚举而不是 `bool` 是为了让两个调用点自解释。
#[derive(Clone, Copy, PartialEq, Eq)]
enum OnlineModelMeta {
    Enabled,
    Disabled,
}

/// 从设置构造 `NotifyConfig`；**总开关没开就返回 `None`**（⇒ 不调 `with_notify`）。
///
/// 判据（S5 复审 P1-1）：`with_notify` 零生产调用点 ⇒ `self.notify` 恒 `None` ⇒
/// `dispatch_notifications` 在早退处返回 ⇒ **基线永不落库、`ModelsChanged` 永不触发**。
/// 这条桥把「设置」接到「服务」上，同时保证默认关。
///
/// **单一事实来源**（M16-S9 第二步）：总开关是 `Settings::notify_enabled`（默认 `false`）。
/// 早先那版从裸 KV 键读的兜底路径已删除——留两条路径就会出现「设置页显示关、实际开着」这类
/// 不可归因的状态。
fn build_notify_config(store: &Store) -> Option<keyrelay_core::notify::NotifyConfig> {
    // 读不出来（老库/损坏）就退回 `None`：不让 app 因为设置读不出来而起不来，
    // 也不静默打开通知（`None` = 不接线 = 与「通知从未接线」逐字相同）。
    let settings = keyrelay_core::settings::Settings::load_from_store(store).ok()?;
    if !settings.notify_enabled {
        return None;
    }
    Some(keyrelay_core::notify::NotifyConfig {
        system_enabled: settings.notify_system_enabled,
        webhook_url: {
            let url = settings.notify_webhook_url.trim();
            if url.is_empty() {
                None
            } else {
                Some(url.to_string())
            }
        },
        balance_threshold: 0.0,
        timeout: std::time::Duration::from_secs(settings.notify_timeout_secs),
    })
}

fn state_with_config(
    store: Store,
    db_path: PathBuf,
    db_error: Option<String>,
    config: ServiceConfig,
    online_model_meta: OnlineModelMeta,
) -> AppState {
    // 钥匙串可用性只在启动时探测一次并明确告警；不可用时投递相关能力会各自失败，
    // **不会**静默换成内存实现（ADR-0002）。
    if let Err(err) = config.vault.probe() {
        eprintln!("[keyrelay] 系统钥匙串不可用，密钥投递将被禁用: {err}");
    }
    // 先借用 store 解析代理（M10-S2），再把 store move 进 service——Store 不是 Clone，
    // 顺序不能反。代理非法时 resolved_proxy_url 已 eprintln 告警并返回 None（直连），
    // 不让 app 因此退出。
    let proxy = resolved_proxy_url(&store);
    let proxy_for_probe = proxy.clone();
    let proxy_for_meta = proxy.clone();
    // M16-S9 / S5 复审 P1-1：通知装配。**必须在 `store` move 进 service 之前**读
    // （`Store` 不是 `Clone`，与上面解析代理同一个理由）。
    let notify = build_notify_config(&store);
    let service = KeyRelayService::new(store, build_transport_with_proxy(proxy), config)
        .with_probe_transport(build_probe_transport(proxy_for_probe));
    // 总开关关着 ⇒ **不调** `with_notify`（`self.notify` 保持 `None`，与今天逐字相同）。
    let service = match notify {
        Some(config) => service.with_notify(config),
        None => service,
    };
    let service = match online_model_meta {
        OnlineModelMeta::Enabled => {
            service.with_meta_transport(build_meta_transport(proxy_for_meta))
        }
        OnlineModelMeta::Disabled => service,
    };
    AppState {
        service,
        db_path,
        db_error,
        gateway: std::sync::Mutex::new(None),
        gateway_op: tokio::sync::Mutex::new(()),
        captcha_op: tokio::sync::Mutex::new(()),
        // 真实结果由 `setup` 里的 `tray::build` 覆盖；测试里永远保持 false
        tray_available: std::sync::atomic::AtomicBool::new(false),
    }
}

/// 打开真实数据库；失败时回退内存库并把原因带进状态（不静默降级）。
pub fn init_state() -> AppState {
    let db_path = default_db_path();
    match Store::open(&db_path) {
        Ok(store) => state_from_store(store, db_path, None),
        Err(err) => {
            eprintln!("[keyrelay] 打开本地数据库失败，回退到内存库: {err}");
            match Store::open_in_memory() {
                Ok(store) => state_from_store(store, db_path, Some(err.to_string())),
                Err(fatal) => {
                    eprintln!("[keyrelay] 内存库也不可用，退出: {fatal}");
                    std::process::exit(1);
                }
            }
        }
    }
}

/// 测试用：纯内存状态，不触碰用户 `~/.keyrelay`。
/// 测试用：内存库 + **预置设置**（`pairs` 先落 `settings` 表，再装配）。
///
/// 存在的理由（M16-S9 / S5 复审 P1-1）：通知总开关是在**装配时**读的
/// （[`build_notify_config`]），所以「开关开着时装配真的把 `with_notify` 接上了」
/// 只能在**构造之前**把设置写好才测得到——否则测试要么测不到装配，要么只能测
/// 「服务层机制」（那正是复审用来发现本缺陷时缺的那一环）。
pub fn init_state_in_memory_with_settings(pairs: &[(&str, &str)]) -> AppState {
    match Store::open_in_memory() {
        Ok(store) => {
            for (key, value) in pairs {
                if let Err(err) = store.set_setting(key, value) {
                    eprintln!("[keyrelay] 预置设置失败 {key}: {err}");
                }
            }
            state_in_memory(store, PathBuf::from(":memory:"))
        }
        Err(fatal) => {
            eprintln!("[keyrelay] 内存库不可用: {fatal}");
            std::process::exit(1);
        }
    }
}

pub fn init_state_in_memory() -> AppState {
    match Store::open_in_memory() {
        Ok(store) => state_in_memory(store, PathBuf::from(":memory:")),
        Err(fatal) => {
            eprintln!("[keyrelay] 内存库不可用: {fatal}");
            std::process::exit(1);
        }
    }
}

/// 注册命令与状态（对任意 Runtime 通用，便于 mock runtime 测试）。
pub fn configure_with_state<R: tauri::Runtime>(
    builder: tauri::Builder<R>,
    state: AppState,
) -> tauri::Builder<R> {
    builder
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::list_sites,
            commands::app_info,
            commands::detect_site,
            commands::add_site,
            commands::login_site,
            commands::list_keys,
            commands::create_key,
            commands::site_balance,
            commands::delivery_plan,
            commands::grant_consent,
            commands::revoke_consent,
            commands::list_channel_bindings,
            commands::list_consents,
            commands::apply_delivery,
            commands::rollback_delivery,
            commands::list_deliveries,
            commands::recent_events,
            commands::list_stored_keys,
            commands::drift_report,
            commands::get_settings,
            commands::update_settings,
            commands::detect_system_proxy,
            commands::refresh_all,
            commands::audit_redaction,
            commands::report_ui_ready,
            commands::gateway_status,
            commands::gateway_start,
            commands::gateway_stop,
            commands::export_bundle,
            commands::prune_backups,
            // M8-S5A：FR-9:196 诊断包
            commands::export_diagnostics,
            // M6-S5：FR-2 / FR-7 接线
            commands::available_groups,
            commands::sync_site_keys,
            commands::rotation_due,
            commands::rotation_plan,
            commands::rotate_key,
            commands::autostart_status,
            commands::autostart_set,
            // M7-S5：FR-2 回收（B-82）、FR-8 钥匙串清理、FR-4 未托管落点探测（R-7）
            commands::revoke_key,
            commands::purge_keychain,
            commands::detect_unmanaged_targets,
            commands::detect_agents,
            commands::list_key_models,
            commands::suggest_key_name,
            // M8-S4：解绑（FR-2:115）、网关令牌轮换（§6.4）
            commands::unbind_agent,
            commands::gateway_rotate_token,
            // M8-S2：人工过验证码（FR-1:102）
            commands::captcha_begin,
            commands::captcha_complete,
            commands::captcha_cancel,
            // M13-S1：Token 消耗统计
            commands::recent_gateway_usage,
            commands::recent_usage_snapshots,
            // M14-S3：per-key 用量采样（Sub2API usage/daily）
            commands::recent_key_usage,
            // M14-S1：模型别名映射（B-110）
            commands::list_alias_map,
            commands::upsert_alias,
            commands::delete_alias,
            // M15-S1：模型检测（bazaarlink probe）
            commands::probe_run,
            commands::list_probe_runs,
            commands::get_probe_run
        ])
}

pub fn configure<R: tauri::Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
    configure_with_state(builder, init_state())
}

/// 启动时的运维任务（M3-S1）。
///
/// 两条硬约束：
/// 1. **定时刷新默认关闭**（`refresh_interval_secs == 0`）：不替用户决定要不要定时联网；
/// 2. 任务体里**不出现 `unwrap`**：任何失败都转成事件，绝不 panic、绝不退出循环。
///
/// 漂移检测只读本地文件，默认在启动时跑一次。
pub fn spawn_maintenance_tasks<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    use tauri::Manager;

    let Some(state) = app.try_state::<AppState>() else {
        eprintln!("[keyrelay] 拿不到应用状态，跳过运维任务");
        return;
    };
    let settings = match state.service.settings() {
        Ok(settings) => settings,
        Err(err) => {
            eprintln!("[keyrelay] 读取设置失败，使用默认值: {err}");
            Default::default()
        }
    };

    if settings.drift_check_on_start {
        match state.service.drift_report() {
            Ok(reports) => {
                let drifted = reports.iter().filter(|r| r.state.needs_attention()).count();
                if drifted > 0 {
                    eprintln!("[keyrelay] 有 {drifted} 个投递目标被外部改动，详见「变更历史」");
                }
            }
            Err(err) => eprintln!("[keyrelay] 漂移检测失败: {err}"),
        }
    }

    // M29-S1 / B-193：NewAPI 的 access token 只有 15 分钟寿命（`AccessTokenTTL`），
    // 必须**持续**用 `new_api_refresh` 续期，否则 15 分钟后所有请求 401。
    //
    // 这个循环放在 `scheduler_enabled` 早退**之前**：它是「会话保活」，与「定时刷新
    // 余额/密钥」是两个独立开关——关掉定时刷新不该让会话 15 分钟后失效。
    //
    // 首轮**立即执行**（不先 sleep）：启动时恢复出的会话可能是「token 已过期但 refresh
    // cookie 还在」（`restore_sessions` 刻意保留），应当马上换一份新 token。
    // 续期失败不 panic：最坏后果是「下一次请求可能 401」，下一轮（60s 后）还会再试。
    let refresh_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            match refresh_handle.try_state::<AppState>() {
                Some(state) => {
                    if let Err(err) = state.service.refresh_sessions_if_needed().await {
                        // 服务层已按「401 误判 / 网络失败」分流并落了事件；这里只留一行运维日志。
                        eprintln!("[keyrelay] 会话续期失败（下一轮重试）: {err}");
                    }
                }
                None => {
                    // 应用正在退出（或状态尚未装配）：不退出循环，等下一轮再看。
                    eprintln!("[keyrelay] 会话续期：拿不到应用状态（下一轮重试）");
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });

    if !settings.scheduler_enabled() {
        return;
    }
    let interval = std::time::Duration::from_secs(settings.refresh_interval_secs);
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            let Some(state) = handle.try_state::<AppState>() else {
                eprintln!("[keyrelay] 后台刷新：拿不到应用状态，退出循环");
                return;
            };
            match state.service.refresh_all().await {
                Ok(summary) => {
                    eprintln!(
                        "[keyrelay] 后台刷新完成: 成功 {} / 失败 {} / 密钥 {} / 告警 {}",
                        summary.sites_ok,
                        summary.sites_failed,
                        summary.keys_total,
                        summary.balance_alerts.len()
                    );
                }
                Err(err) => eprintln!("[keyrelay] 后台刷新失败（下一轮继续）: {err}"),
            }
        }
    });
}

pub fn run() {
    let result = configure(tauri::Builder::default())
        .setup(|app| {
            spawn_maintenance_tasks(app.handle());

            // 托盘（M6-S5 / B-53）。**失败不阻断启动**：无 GUI 会话的环境
            // （CI、SSH、headless）建不出托盘图标，但那不该让整个应用起不来。
            let tray_available = match tray::build(app.handle()) {
                Ok(()) => true,
                Err(err) => {
                    eprintln!("[keyrelay] 托盘图标创建失败（应用继续运行）: {err}");
                    false
                }
            };
            if let Some(state) = app.try_state::<AppState>() {
                state
                    .tray_available
                    .store(tray_available, std::sync::atomic::Ordering::Relaxed);
            }

            // 启动隐藏：命令行 `--hidden` 与设置项 `start_hidden` 任一为真。
            // **托盘不可用时降级为显示窗口**（`should_start_hidden` 的语义）——
            // 否则用户会以为应用根本没启动，而实际上它只是没有入口。
            let hidden_flag = tray::has_hidden_flag(std::env::args());
            let settings = app
                .try_state::<AppState>()
                .and_then(|state| state.service.settings().ok());
            let want_hidden = settings
                .as_ref()
                .map(|s| s.should_start_hidden(hidden_flag, tray_available))
                .unwrap_or(false);
            if want_hidden {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            } else if hidden_flag || settings.map(|s| s.start_hidden).unwrap_or(false) {
                eprintln!(
                    "[keyrelay] 托盘不可用，已忽略「启动时隐藏窗口」的请求：\
                     隐藏之后没有任何入口能把窗口调回来"
                );
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // 关窗 → 隐藏到托盘（默认），除非用户在设置里关掉了 `close_to_tray`，
            // 或托盘压根没建起来（此时隐藏 = 应用不可达）。
            //
            // 为什么每次读设置而不是读一个启动时快照：用户可能在运行中改这个开关，
            // 而关窗行为要立刻跟着变。读库失败时**放行关闭**（fail-open）——
            // 让用户关得掉窗口，比让他关不掉更不容易出事。
            let tauri::WindowEvent::CloseRequested { api, .. } = event else {
                return;
            };
            // 只对主窗口拦截关闭（隐藏到托盘）；验证码等辅助窗口允许关（P1-7）。
            // 旧实现对所有窗口 prevent_close+hide，验证码窗口关闭后只是隐藏，
            // 再打开时 set_focus 对不可见窗口是空操作 ⇒ 本次运行内再也打不开。
            if window.label() != "main" {
                return;
            }
            let handle = window.app_handle();
            let tray_ok = handle
                .try_state::<AppState>()
                .map(|state| {
                    state
                        .tray_available
                        .load(std::sync::atomic::Ordering::Relaxed)
                })
                .unwrap_or(false);
            let hide = handle
                .try_state::<AppState>()
                .and_then(|state| state.service.settings().ok())
                .map(|settings| settings.should_hide_on_close(tray_ok))
                .unwrap_or(false);
            if hide {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!());

    if let Err(err) = result {
        eprintln!("[keyrelay] 应用退出: {err}");
        std::process::exit(1);
    }
}
