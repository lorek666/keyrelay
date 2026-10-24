//! Tauri 桌面壳：只做「命令注册 + 状态管理 + 平台胶水」。
//!
//! 业务逻辑一律在 `tianshu-relay-core`，本 crate 不出现 SQL、HTTP、文件改写逻辑。
//!
//! `configure` / `configure_with_state` 之所以单独暴露，是为了让 IPC 测试
//! （`tests/commands.rs`）能用 Tauri 官方 mock runtime 复用同一套命令注册。

mod commands;
pub mod commands_list;
pub mod tray;

use std::path::PathBuf;

use tauri::Manager;

use tianshu_relay_core::proxy::{self, ProxyMode};
use tianshu_relay_core::service::{ServiceConfig, TianshuRelayService};
use tianshu_relay_core::settings::Settings;
use tianshu_relay_core::site::registry::SiteRegistry;
use tianshu_relay_core::site::retry::{RetryPolicy, RetryingTransport};
use tianshu_relay_core::site::transport_reqwest::{ReqwestTransport, TransportConfig};
use tianshu_relay_core::site::SiteFingerprint;
use tianshu_relay_core::store::Store;
use tianshu_relay_core::Result;

/// 生产装配：真实 reqwest + 重试装饰器
pub type AppTransport = RetryingTransport<ReqwestTransport>;

pub struct AppState {
    pub service: TianshuRelayService<AppTransport>,
    pub db_path: PathBuf,
    /// 本次启动**实际使用**的数据目录（迁移成功 ⇒ 新目录；失败 ⇒ 旧目录）。
    pub data_dir: PathBuf,
    /// 旧数据迁移结果。供 `app_info` 展示，不影响服务本身。
    pub rebrand: tianshu_relay_core::rebrand::RebrandReport,
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

/// 用户主目录。解析逻辑在 `tianshu_relay_core::platform`（按平台处理 `TIANSHU_RELAY_HOME` /
/// `USERPROFILE` / `HOMEDRIVE`+`HOMEPATH` / `HOME`）。
///
/// 壳层这里只做「解析不出来就明确退出」——**不静默退化成当前目录**
/// （否则在 Windows 上会把密钥写到 `C:\Program Files\...`，用户找不到）。
pub fn home_dir() -> PathBuf {
    match tianshu_relay_core::platform::home_dir() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("[tianshu-relay] {err}");
            std::process::exit(1);
        }
    }
}

/// `~/.tianshu-relay/tianshu-relay.db`
pub fn default_data_dir() -> PathBuf {
    home_dir().join(tianshu_relay_core::rebrand::APP_DIR_NAME)
}

/// 某一数据目录下的主库路径。
pub fn default_db_path_in(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join(tianshu_relay_core::rebrand::DB_FILE_NAME)
}

pub fn default_db_path() -> PathBuf {
    default_db_path_in(&default_data_dir())
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
            eprintln!("[tianshu-relay] 构造 HTTP 传输层失败: {err}");
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
            eprintln!("[tianshu-relay] 构造 probe 传输层失败: {err}");
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
            eprintln!("[tianshu-relay] 构造模型元数据传输层失败: {err}");
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
            eprintln!("[tianshu-relay] 代理配置非法，本次直连: {err}");
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

fn state_from_store(
    store: Store,
    db_path: PathBuf,
    db_error: Option<String>,
    data_dir: PathBuf,
    rebrand: tianshu_relay_core::rebrand::RebrandReport,
) -> AppState {
    let home = home_dir();
    // 主库降级时不要跑迁移：空的内存库枚举不出引用，会把「已完成」标记写死，
    // 真实库恢复后迁移就被永久跳过了（复审 P1-3）。
    let config = build_service_config(home, &data_dir, &store, db_error.is_some());
    state_with_config(
        store,
        db_path,
        db_error,
        config,
        OnlineModelMeta::Enabled,
        data_dir,
        rebrand,
    )
}

/// 生产保险库装配 + 一次性钥匙串迁移（ADR-0003 / M33-S1）。
///
/// 顺序不能反：**先**迁移、**再**把 vault 交给 service——迁移要用 store 的引用索引，
/// 而 store 一旦 move 进 `TianshuRelayService` 就拿不到了。
fn build_service_config(
    home: PathBuf,
    data_dir: &std::path::Path,
    store: &Store,
    db_degraded: bool,
) -> ServiceConfig {
    let (vault_db, key_file) = tianshu_relay_core::vault::local::default_paths_in(data_dir);
    match tianshu_relay_core::vault::LocalVault::open(&vault_db, &key_file) {
        Ok(vault) => {
            if !vault.is_device_bound() {
                eprintln!(
                    "[tianshu-relay] 保险库未绑定设备（取不到设备标识）：密钥文件只受文件权限保护"
                );
            }
            if db_degraded {
                eprintln!("[tianshu-relay] 主库已降级为内存库，本次跳过钥匙串迁移");
            } else {
                run_keychain_migration(&vault, store);
            }
            ServiceConfig::with_vault_at(std::sync::Arc::new(vault), home, data_dir)
        }
        Err(err) => {
            // 不静默：vaultBackend 会变成 "memory"，Overview 页有红色告警。
            eprintln!(
                "[tianshu-relay] 本地保险库不可用（{}），密钥将只存在内存里: {err}",
                vault_db.display()
            );
            // 保险库打不开时退回内存实现，但备份目录仍必须跟随**本次实际数据目录**：
            // 迁移失败回退旧目录时，硬拼新目录会让备份与审计跑到另一个目录。
            ServiceConfig::with_vault_at(
                std::sync::Arc::new(tianshu_relay_core::vault::MemoryVault::new()),
                home,
                data_dir,
            )
        }
    }
}

/// 把钥匙串里的旧条目搬进加密库，校验一致后删除旧条目。
///
/// 只在真机启动路径上跑：钥匙串不可用（用户拒绝、平台不支持）就整体跳过，
/// 下一次启动再试——**不会**因为迁移失败而阻止 App 启动。
pub(crate) fn keychain_migration_source() -> tianshu_relay_core::vault::KeychainVault {
    // M35-S1：生产迁移必须从**旧** service 读。单独抽成函数，让测试能钉住这条不变量；
    // 直接用 `KeychainVault::new()` 会读新 service、得到空集合，然后把完成标记写死。
    tianshu_relay_core::vault::KeychainVault::with_service(
        tianshu_relay_core::vault::KeychainVault::LEGACY_SERVICE,
    )
}

fn run_keychain_migration(vault: &tianshu_relay_core::vault::LocalVault, store: &Store) {
    use tianshu_relay_core::vault::migrate::refs_for_migration;
    use tianshu_relay_core::vault::{migrate_once, Vault, MIGRATION_MARKER};

    match vault.meta_get(MIGRATION_MARKER) {
        Ok(Some(_)) => return,
        Ok(None) => {}
        Err(err) => {
            eprintln!("[tianshu-relay] 读迁移标记失败，跳过迁移: {err}");
            return;
        }
    }

    // M38-S2（B-219）：自动重试有硬上限。达到上限 / 已放弃 ⇒ **不碰钥匙串**——
    // 不 probe、不枚举、不迁移。用户可在设置页显式重试或放弃。
    let attempts = tianshu_relay_core::vault::status_for(vault)
        .map(|s| s.attempts)
        .unwrap_or(0);
    match tianshu_relay_core::vault::should_auto_retry(vault) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!(
                "[tianshu-relay] 钥匙串迁移已失败 {attempts} 次，跳过自动重试；请在设置页重试或放弃"
            );
            return;
        }
        Err(err) => {
            eprintln!("[tianshu-relay] 读迁移状态失败，跳过自动重试: {err}");
            return;
        }
    }

    let refs = match refs_for_migration(store) {
        Ok(refs) => refs,
        Err(err) => {
            eprintln!("[tianshu-relay] 枚举密钥引用失败，跳过迁移: {err}");
            return;
        }
    };

    // M35-S1：**显式**用旧 service 读。用 `new()`（新 service）会读到空集合，
    // 然后把「已完成」标记写死 ⇒ 旧条目永远迁不过来（spec §7 明确要求）。
    let keychain = keychain_migration_source();
    if let Err(err) = keychain.probe() {
        eprintln!("[tianshu-relay] 系统钥匙串不可用，跳过一次性迁移: {err}");
        return;
    }

    match migrate_once(&keychain, vault, refs) {
        Ok(outcome) if !outcome.already_done => {
            let report = outcome.report;
            eprintln!(
                "[tianshu-relay] 钥匙串迁移：导入 {} 条，跳过 {} 条，失败 {} 条",
                report.imported,
                report.skipped,
                report.failed.len()
            );
            for (reference, reason) in report.failed {
                // 引用不是密钥，可以打；原因由我们自建，也不含密钥材料。
                eprintln!("[tianshu-relay] 迁移失败 {reference}: {reason}");
            }
        }
        Ok(_) => {}
        Err(err) => eprintln!("[tianshu-relay] 钥匙串迁移出错（下次启动重试）: {err}"),
    }
}

/// 测试用：内存钥匙串，绝不触碰用户真实钥匙串与 `~/.tianshu-relay`。
fn state_in_memory(store: Store, db_path: PathBuf) -> AppState {
    // **每个 app 一个独立目录**（进程内自增序号）。
    //
    // 原先只用 pid：一个测试进程里所有 app 共享同一个 `tianshu-relay-test-<pid>`，
    // 于是「另一个测试写进 `exports` / `backups` 的文件」会被本测试的审计扫描到——
    // `export_diagnostics_writes_a_package_and_registers_it_for_the_audit` 的
    // 「文件数必须 +1」因此变成一条**看时序**的断言（并发跑时偶发红）。
    // 隔离目录之后，扫描集合只由本 app 自己写过的东西决定。
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let tmp = std::env::temp_dir().join(format!("tianshu-relay-test-{}-{seq}", std::process::id()));
    // 内存态：库路径记作 `:memory:`，迁移状态 `noLegacy`（没有真实旧目录可迁）。
    let rebrand = tianshu_relay_core::rebrand::RebrandReport {
        status: tianshu_relay_core::rebrand::RebrandStatus::NoLegacy,
        from: None,
        to: tmp.clone(),
        files: 0,
        bytes: 0,
        warnings: Vec::new(),
        error: None,
    };
    state_with_config(
        store,
        db_path,
        None,
        ServiceConfig::in_memory(tmp.clone()),
        OnlineModelMeta::Disabled,
        tmp,
        rebrand,
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
fn build_notify_config(store: &Store) -> Option<tianshu_relay_core::notify::NotifyConfig> {
    // 读不出来（老库/损坏）就退回 `None`：不让 app 因为设置读不出来而起不来，
    // 也不静默打开通知（`None` = 不接线 = 与「通知从未接线」逐字相同）。
    let settings = tianshu_relay_core::settings::Settings::load_from_store(store).ok()?;
    if !settings.notify_enabled {
        return None;
    }
    Some(tianshu_relay_core::notify::NotifyConfig {
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
    data_dir: PathBuf,
    rebrand: tianshu_relay_core::rebrand::RebrandReport,
) -> AppState {
    // 保险库可用性只在启动时探测一次并明确告警；不可用时投递相关能力会各自失败，
    // **不会**静默换成内存实现（ADR-0003）。
    if let Err(err) = config.vault.probe() {
        eprintln!("[tianshu-relay] 本地保险库不可用，密钥投递将被禁用: {err}");
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
    let service = TianshuRelayService::new(store, build_transport_with_proxy(proxy), config)
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
        data_dir,
        rebrand,
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
    let home = home_dir();
    // M35-S1：**先**解析数据目录（必要时把旧 `~/.keyrelay` 复制成 `~/.tianshu-relay`），
    // 再拿解析结果去开库。顺序不能反——反了就会先在旧目录旁边建一个新库。
    let (data_dir, mut rebrand) = tianshu_relay_core::rebrand::resolve_app_home(&home);

    // 旧版登录自启项：启动时停用一次。**失败不能让启动失败**，只记 warning。
    //
    // 迁移失败时**不碰**旧自启项：`apply_files` 的备份 journal 会落进 `data_dir/backups`，
    // 而失败时 `data_dir` 就是旧目录 `~/.keyrelay`——那会破坏「旧目录只读」的承诺，
    // 也会让下一次迁移的 `quick_check` 面对一个被我们改过的目录。旧自启项留给用户手动处理，
    // 这里只把「没停用」如实写进 warning。
    match rebrand.status {
        tianshu_relay_core::rebrand::RebrandStatus::Failed => rebrand
            .warnings
            .push("旧数据迁移失败，旧版登录自启项未停用（请手动检查）".to_string()),
        _ => match tianshu_relay_core::rebrand::retire_legacy_autostart(&home, &data_dir) {
            Ok(Some(warning)) => rebrand.warnings.push(warning),
            Ok(None) => {}
            Err(err) => rebrand
                .warnings
                .push(format!("停用旧版登录自启项失败: {err}")),
        },
    }

    if let Err(err) = std::fs::create_dir_all(&data_dir) {
        eprintln!(
            "[tianshu-relay] 创建数据目录失败（{}）: {err}",
            data_dir.display()
        );
    }

    let db_path = default_db_path_in(&data_dir);
    match Store::open(&db_path) {
        Ok(store) => state_from_store(store, db_path, None, data_dir, rebrand),
        Err(err) => {
            eprintln!("[tianshu-relay] 打开本地数据库失败，回退到内存库: {err}");
            match Store::open_in_memory() {
                Ok(store) => {
                    state_from_store(store, db_path, Some(err.to_string()), data_dir, rebrand)
                }
                Err(fatal) => {
                    eprintln!("[tianshu-relay] 内存库也不可用，退出: {fatal}");
                    std::process::exit(1);
                }
            }
        }
    }
}

/// 测试用：纯内存状态，不触碰用户 `~/.tianshu-relay`。
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
                    eprintln!("[tianshu-relay] 预置设置失败 {key}: {err}");
                }
            }
            state_in_memory(store, PathBuf::from(":memory:"))
        }
        Err(fatal) => {
            eprintln!("[tianshu-relay] 内存库不可用: {fatal}");
            std::process::exit(1);
        }
    }
}

pub fn init_state_in_memory() -> AppState {
    match Store::open_in_memory() {
        Ok(store) => state_in_memory(store, PathBuf::from(":memory:")),
        Err(fatal) => {
            eprintln!("[tianshu-relay] 内存库不可用: {fatal}");
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
            commands::logout_site,
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
            commands::gateway_token_create,
            commands::gateway_token_list,
            commands::gateway_token_revoke,
            commands::vault_migration_status,
            commands::vault_migration_retry,
            commands::vault_migration_abandon,
            commands::check_agent_updates,
            commands::update_agent,
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
            // M34-S1：用量看板（站点 / 模型 / 天聚合，只读）
            commands::usage_dashboard,
            commands::model_price_list,
            commands::model_price_upsert,
            commands::model_price_delete,
            // M46-S5：站点 / key 硬预算
            commands::site_budget_list,
            commands::site_budget_create,
            commands::site_budget_delete,
            commands::site_bill_probe,
            commands::site_bill_import,
            commands::site_bills,
            // M46-S6：多源账单对账（只读）
            commands::bill_reconciliation,
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
/// 模型目录采集循环的醒来间隔（M39-S1）。真正的节流在每站的 `should_collect_models`。
const MODEL_CATALOG_TICK: std::time::Duration = std::time::Duration::from_secs(60);

/// 密钥健康巡检循环的醒来间隔（M46-S1）。只是「醒来看看」：真正的节流是
/// `gateway_key_health_interval_secs`（任务内记 `last_run`），改间隔不重启循环。
const KEY_HEALTH_TICK_SECS: std::time::Duration = std::time::Duration::from_secs(60);

/// M41-S1：`gateway_auto_start` 的启动期尝试（只跑一次，失败**不阻断启动**）。
///
/// 选组规则见 [`crate::commands::auto_start_target`]：优先「上次成功运行」的 site/key
/// （四项校验全过才用），否则回退「第一个 health=ok 站点 + 其第一把 enabled key」，
/// 都没有就跳过并记一行日志——**不自动重试、不循环**。
///
/// B-224 P2 补充：首选组**启动失败**时，按 [`crate::commands::auto_start_targets`]
/// 的有序清单依次试其余健康组（首个成功即停）；此前首选失败只记一行日志就
/// 结束，网关停在「未运行」。清单内每个组仍只试一次，全部失败才放弃。
fn maybe_auto_start_gateway<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    use tauri::Manager as _;
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let Ok(settings) = state.service.settings() else {
        return;
    };
    if !settings.gateway_auto_start || !settings.gateway_enabled {
        return;
    }
    let Ok(sites) = state.service.sites() else {
        return;
    };
    let Ok(keys) = state.service.stored_keys() else {
        return;
    };
    let targets = commands::auto_start_targets(
        &sites,
        &keys,
        settings.gateway_last_site_id,
        settings.gateway_last_key_id,
    );
    if targets.is_empty() {
        eprintln!("[tianshu-relay] 自动启动网关：没有可用的健康站点 / 启用密钥，跳过（不重试）");
        return;
    }
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let Some(state) = app_handle.try_state::<AppState>() else {
            return;
        };
        // 与手动启动共用同一把串行锁；auto-start 只在这里 spawn 一次。
        let _op = state.gateway_op.lock().await;
        for (site_id, key_id) in targets {
            match commands::start_gateway_locked(&state, site_id, key_id).await {
                Ok(()) => return,
                Err(err) => {
                    eprintln!(
                        "[tianshu-relay] 自动启动网关：站点 {site_id} / 密钥 {key_id} 启动失败，尝试下一组（不影响应用启动）: {err}"
                    );
                }
            }
        }
        eprintln!("[tianshu-relay] 自动启动网关：全部候选组均启动失败，网关未运行");
    });
}

pub fn spawn_maintenance_tasks<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    use tauri::Manager;

    let Some(state) = app.try_state::<AppState>() else {
        eprintln!("[tianshu-relay] 拿不到应用状态，跳过运维任务");
        return;
    };
    let settings = match state.service.settings() {
        Ok(settings) => settings,
        Err(err) => {
            eprintln!("[tianshu-relay] 读取设置失败，使用默认值: {err}");
            Default::default()
        }
    };

    if settings.drift_check_on_start {
        match state.service.drift_report() {
            Ok(reports) => {
                let drifted = reports.iter().filter(|r| r.state.needs_attention()).count();
                if drifted > 0 {
                    eprintln!(
                        "[tianshu-relay] 有 {drifted} 个投递目标被外部改动，详见「变更历史」"
                    );
                }
            }
            Err(err) => eprintln!("[tianshu-relay] 漂移检测失败: {err}"),
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
                        eprintln!("[tianshu-relay] 会话续期失败（下一轮重试）: {err}");
                    }
                }
                None => {
                    // 应用正在退出（或状态尚未装配）：不退出循环，等下一轮再看。
                    eprintln!("[tianshu-relay] 会话续期：拿不到应用状态（下一轮重试）");
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });

    // M39-S1：模型目录采集循环（**独立于**上面的刷新定时器）。
    //
    // 60s tick 只是「醒来看看」，真正的节流是逐站的 `should_collect_models`
    // （锚点 = `site_model_sync.last_attempt_at`）——所以改 `models_min_interval_secs`
    // 不需要重启循环。
    //
    // 门槛只有 `collect_models` 一个：循环里先判一次，不满足就**连一趟空转都不调**；
    // 单趟采集内部还会再判一次（纵深防御，开关关时 0 请求 0 写入）。
    // `gateway_multi_site` **不在此列**：它只决定网关路由用不用目录（见 `gateway_config`）。
    let catalog_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(MODEL_CATALOG_TICK).await;
            let Some(state) = catalog_handle.try_state::<AppState>() else {
                continue;
            };
            let Ok(settings) = state.service.settings() else {
                continue;
            };
            // 只看 `collect_models`：它是 M14-S1 的**独立**开关（服务 `ModelsChanged` 通知），
            // 与「网关是否用目录」(`gateway_multi_site`) 解耦——绑定会让只开采集的用户
            // 收不到通知（行为回归）。
            if !settings.collect_models {
                continue;
            }
            match state.service.refresh_model_catalog_once().await {
                Ok(summary) => {
                    if summary.attempted > 0 {
                        eprintln!(
                            "[tianshu-relay] 模型目录采集: 尝试 {} / 替换 {} / 空 {} / 失败 {} / 清空 {} / 发布 {}（代号 {}）",
                            summary.attempted,
                            summary.replaced,
                            summary.empty,
                            summary.failed,
                            summary.cleared.len(),
                            summary.published,
                            summary.generation
                        );
                    }
                }
                Err(err) => {
                    eprintln!("[tianshu-relay] 模型目录采集失败（下一轮继续）: {err}")
                }
            }
        }
    });

    // M46-S1：密钥健康巡检循环（与目录采集循环并列的独立任务）。
    //
    // 醒来间隔固定 60 秒（`KEY_HEALTH_TICK_SECS`）；真正的节流是设置间隔本身
    // （任务内记 `last_run`，未到间隔即跳过；失败轮次同样锚定——与目录采集
    // 「失败也节流」的口径一致）。间隔为 0 ⇒ 连 `check_key_health_once` 都不调。
    //
    // 喂入时只在锁内取运行句柄（不跨 await 持壳层锁）；网关没在跑 / 已停 ⇒
    // 只记事件、不喂（重启后熔断归零，下一轮会重新探活）。
    // 循环体内无 unwrap：任何失败转 eprintln，不 panic、不退出循环。
    let health_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut last_run: Option<std::time::Instant> = None;
        loop {
            tokio::time::sleep(KEY_HEALTH_TICK_SECS).await;
            let Some(state) = health_handle.try_state::<AppState>() else {
                continue;
            };
            let Ok(settings) = state.service.settings() else {
                continue;
            };
            let interval = settings.gateway_key_health_interval_secs;
            if interval == 0 {
                continue;
            }
            let now = std::time::Instant::now();
            if let Some(last) = last_run {
                if now.duration_since(last).as_secs() < interval {
                    continue;
                }
            }
            // 跑前先锚定：本轮无论成败，下一轮都要等满间隔。
            last_run = Some(now);
            match state.service.check_key_health_once().await {
                Ok(summary) => {
                    if summary.attempted > 0 {
                        eprintln!(
                            "[tianshu-relay] 密钥健康巡检: 尝试 {} / 健康 {} / 死 key {} / 额度空 {} / 站点故障 {} / 未知 {}",
                            summary.attempted,
                            summary.healthy,
                            summary.dead,
                            summary.quota,
                            summary.fault,
                            summary.unknown
                        );
                        // 喂入运行中网关的 Breaker（同步操作，不跨 await 持锁）。
                        if let Ok(guard) = state.gateway.lock() {
                            if let Some(running) = guard.as_ref() {
                                if running.handle.alive() {
                                    for outcome in &summary.outcomes {
                                        running.handle.record_probe_outcome(
                                            outcome.site_id,
                                            &outcome.models,
                                            outcome.verdict,
                                            std::time::Instant::now(),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    eprintln!("[tianshu-relay] 密钥健康巡检失败（下一轮继续）: {err}")
                }
            }
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
                eprintln!("[tianshu-relay] 后台刷新：拿不到应用状态，退出循环");
                return;
            };
            match state.service.refresh_all().await {
                Ok(summary) => {
                    eprintln!(
                        "[tianshu-relay] 后台刷新完成: 成功 {} / 失败 {} / 密钥 {} / 告警 {}",
                        summary.sites_ok,
                        summary.sites_failed,
                        summary.keys_total,
                        summary.balance_alerts.len()
                    );
                }
                Err(err) => eprintln!("[tianshu-relay] 后台刷新失败（下一轮继续）: {err}"),
            }
        }
    });
}

pub fn run() {
    let result = configure(tauri::Builder::default())
        .setup(|app| {
            spawn_maintenance_tasks(app.handle());
            // M41-S1：应用启动时的 auto-start（默认关）。只尝试一次、不阻塞启动、失败只记日志。
            maybe_auto_start_gateway(app.handle());

            // 托盘（M6-S5 / B-53）。**失败不阻断启动**：无 GUI 会话的环境
            // （CI、SSH、headless）建不出托盘图标，但那不该让整个应用起不来。
            let tray_available = match tray::build(app.handle()) {
                Ok(()) => true,
                Err(err) => {
                    eprintln!("[tianshu-relay] 托盘图标创建失败（应用继续运行）: {err}");
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
                    "[tianshu-relay] 托盘不可用，已忽略「启动时隐藏窗口」的请求：\
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
        .build(tauri::generate_context!())
        .map(|app| {
            // M40-S1：应用退出前把网关缓冲里的**用量**与失败落库（best-effort）。
            // 关窗到托盘不会走到这里；只有真正退出（Cmd+Q / 托盘「退出」）才触发。
            // 拿不到 state（已在拆解）就跳过——退出路径不允许因为落库失败被阻断。
            app.run(|app_handle, event| {
                if let tauri::RunEvent::Exit = event {
                    if let Some(state) = app_handle.try_state::<AppState>() {
                        state.service.drain_gateway_usage();
                        state.service.drain_gateway_failures();
                    }
                }
            });
        });

    if let Err(err) = result {
        eprintln!("[tianshu-relay] 应用退出: {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod rebrand_wiring_tests {
    use super::*;

    #[test]
    fn keychain_migration_reads_the_legacy_service() {
        let source = keychain_migration_source();
        assert_eq!(
            source.service(),
            tianshu_relay_core::vault::KeychainVault::LEGACY_SERVICE
        );
        assert_ne!(
            source.service(),
            tianshu_relay_core::vault::KeychainVault::DEFAULT_SERVICE
        );
    }
}
