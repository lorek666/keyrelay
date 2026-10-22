//! tianshu-relay-cli：把 `TianshuRelayService::apply_delivery` / `rollback_delivery` 包成
//! 可脚本化入口（B-118 / M14-S4）。
//!
//! 手动 argv 解析（零新依赖，章程 §3.3 规则 3 纪律）。退出码：
//! - 0 成功（apply 打印 journal_id；rollback 无 stdout；mock-agent 打印 ok）
//! - 1 运行失败（投递/回滚/校验失败）
//! - 2 前置不满足或参数错误（**没跑**，不是失败）
//!
//! 子命令见 `docs/specs/M14-S4-冒烟CLI.md` §4.1。

mod mock_agent;
mod service_build;
mod smoke_seed;

use std::path::PathBuf;
use std::process::ExitCode;

use tianshu_relay_core::delivery::DeliveryChannel;
use tianshu_relay_core::redact;
use tianshu_relay_core::store::Store;

use service_build::{build_service, default_backup_dir, default_home, default_store, VaultChoice};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{}", e.message());
            ExitCode::from(e.code())
        }
    }
}

/// CLI 错误：携带退出码与已脱敏的文案。
struct CliError {
    code: u8,
    message: String,
}

impl CliError {
    fn code(&self) -> u8 {
        self.code
    }
    fn message(&self) -> &str {
        &self.message
    }
    /// exit 2：参数/前置不满足。
    fn usage(msg: impl Into<String>) -> Self {
        CliError {
            code: 2,
            message: msg.into(),
        }
    }
    /// exit 1：运行失败。文案先过 `redact::scrub`，绝不带密钥形态。
    fn runtime(msg: impl Into<String>) -> Self {
        CliError {
            code: 1,
            message: redact::scrub(&msg.into()),
        }
    }
}

const USAGE: &str = "用法:\n\
  tianshu-relay-cli apply-delivery --key-id <N> --channel <C> [--model <M>] [--home <H>] [--store <S>] [--backup-dir <B>] [--vault local|memory|keychain]\n\
  tianshu-relay-cli apply-delivery --channel <C> [--model <M>] --smoke [--home <H>] [--store <S>] [--backup-dir <B>] [--i-know-this-is-real-home]\n\
  tianshu-relay-cli rollback-delivery --journal <J> [--store <S>]\n\
  tianshu-relay-cli grant-consent --key-id <N> --channel <C> [--home <H>] [--store <S>]\n\
  tianshu-relay-cli list-channels\n\
  tianshu-relay-cli list-keys [--store <S>]\n\
  tianshu-relay-cli mock-agent --channel <C> [--home <H>]";

fn run(args: &[String]) -> Result<(), CliError> {
    if args.len() < 2 {
        return Err(CliError::usage(format!("未给子命令。\n{USAGE}")));
    }
    let cmd = &args[1];
    let rest = &args[2..];
    match cmd.as_str() {
        "apply-delivery" => apply_delivery(rest),
        "rollback-delivery" => rollback_delivery(rest),
        "grant-consent" => grant_consent(rest),
        "list-channels" => list_channels(rest),
        "list-keys" => list_keys(rest),
        "mock-agent" => mock_agent(rest),
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            Ok(())
        }
        other => Err(CliError::usage(format!("未知子命令: {other}\n{USAGE}"))),
    }
}

// ================================================================ apply-delivery

fn apply_delivery(args: &[String]) -> Result<(), CliError> {
    let flags = Flags::parse(args)?;
    let channel = parse_channel(&flags)?;
    let model = flags.value("model");
    let smoke = flags.bool("smoke");
    let key_id_flag = flags.value("key-id");

    // 互斥：--smoke 与 --key-id 不能同时给。
    if smoke && key_id_flag.is_some() {
        return Err(CliError::usage(
            "--smoke 与 --key-id 互斥（一个是自包含冒烟，一个是薄路径）",
        ));
    }
    if !smoke && key_id_flag.is_none() {
        return Err(CliError::usage(
            "apply-delivery 需要 --key-id <N>（薄路径）或 --smoke（自包含冒烟）",
        ));
    }

    let home = resolve_home(&flags, smoke)?;
    let store = resolve_store(&flags, &home);
    let backup_dir = resolve_backup_dir(&flags, &home);

    if smoke {
        // --smoke：读 TIANSHU_RELAY_REAL_KEY env，MemoryVault 内联 seed → grant → apply。
        let real_key = std::env::var("TIANSHU_RELAY_REAL_KEY").map_err(|_| {
            CliError::usage(
                "apply-delivery --smoke 需要 TIANSHU_RELAY_REAL_KEY 环境变量（sk- 形态，不进 argv）",
            )
        })?;
        smoke_seed::validate_real_key(&real_key)
            .map_err(|e| CliError::usage(format!("TIANSHU_RELAY_REAL_KEY 形态不符: {e}")))?;
        let base_url = smoke_seed::smoke_base_url();

        // vault 先建好、放密钥，再构造 service（service 会 move 掉 store）。
        let vault = std::sync::Arc::new(tianshu_relay_core::vault::MemoryVault::new())
            as std::sync::Arc<dyn tianshu_relay_core::vault::Vault>;
        let store_obj =
            Store::open(&store).map_err(|e| CliError::runtime(format!("打开本地库失败: {e}")))?;
        let key_id = smoke_seed::seed_store(&store_obj, &*vault, &base_url, &real_key)
            .map_err(|e| CliError::runtime(format!("smoke seeding 失败: {e}")))?;
        let service = build_service_with_vault(&home, store_obj, &backup_dir, vault);
        let journal_id = smoke_seed::grant_and_apply(&service, key_id, channel, model.as_deref())
            .map_err(|e| CliError::runtime(format!("smoke 投递失败: {e}")))?;
        println!("{journal_id}");
        Ok(())
    } else {
        // --key-id 薄路径：真 store + 真钥匙串（默认）或 memory（--vault memory）。
        let key_id: i64 = key_id_flag
            .unwrap()
            .parse()
            .map_err(|_| CliError::usage("--key-id 必须是整数"))?;
        let vault_choice = parse_vault(&flags);
        let service = build_service(&home, &store, &backup_dir, vault_choice)
            .map_err(|e| CliError::runtime(e.to_string()))?;
        let outcome = service
            .apply_delivery_with_model(key_id, channel, model.as_deref())
            .map_err(|e| CliError::runtime(format!("投递失败: {e}")))?;
        println!("{}", outcome.journal_id);
        Ok(())
    }
}

/// `--smoke` 路径：vault 已在 CLI 侧建好（MemoryVault + put 了密钥），直接装配 service。
fn build_service_with_vault(
    home: &std::path::Path,
    store: Store,
    backup_dir: &std::path::Path,
    vault: std::sync::Arc<dyn tianshu_relay_core::vault::Vault>,
) -> tianshu_relay_core::service::TianshuRelayService<
    tianshu_relay_core::site::transport::MockTransport,
> {
    tianshu_relay_core::service::TianshuRelayService::new(
        store,
        tianshu_relay_core::site::transport::MockTransport::new(vec![]),
        tianshu_relay_core::service::ServiceConfig {
            vault,
            home: home.to_path_buf(),
            backup_dir: backup_dir.to_path_buf(),
        },
    )
}

// ================================================================ rollback-delivery

fn rollback_delivery(args: &[String]) -> Result<(), CliError> {
    let flags = Flags::parse(args)?;
    let journal = flags
        .value("journal")
        .ok_or_else(|| CliError::usage("rollback-delivery 需要 --journal <J>"))?;
    let home = resolve_home(&flags, false)?;
    let store = resolve_store(&flags, &home);
    // rollback 不读 vault：用 MemoryVault，避免无谓碰真钥匙串。
    let service = build_service(
        &home,
        &store,
        &home.join(".tianshu-relay").join("backups"),
        VaultChoice::Memory,
    )
    .map_err(|e| CliError::runtime(e.to_string()))?;
    service
        .rollback_delivery(&journal)
        .map_err(|e| CliError::runtime(format!("回滚失败: {e}")))?;
    Ok(())
}

// ================================================================ grant-consent

fn grant_consent(args: &[String]) -> Result<(), CliError> {
    let flags = Flags::parse(args)?;
    let channel = parse_channel(&flags)?;
    let key_id: i64 = flags
        .value("key-id")
        .ok_or_else(|| CliError::usage("grant-consent 需要 --key-id <N>"))?
        .parse()
        .map_err(|_| CliError::usage("--key-id 必须是整数"))?;
    let home = resolve_home(&flags, false)?;
    let store = resolve_store(&flags, &home);
    let backup_dir = resolve_backup_dir(&flags, &home);
    // grant_consent 不读 vault：用 MemoryVault。
    let service = build_service(&home, &store, &backup_dir, VaultChoice::Memory)
        .map_err(|e| CliError::runtime(e.to_string()))?;
    service
        .grant_consent(key_id, channel)
        .map_err(|e| CliError::runtime(format!("授予同意失败: {e}")))?;
    Ok(())
}

// ================================================================ list-channels / list-keys

fn list_channels(_args: &[String]) -> Result<(), CliError> {
    for c in DeliveryChannel::ALL {
        println!("{}", c.as_str());
    }
    Ok(())
}

fn list_keys(args: &[String]) -> Result<(), CliError> {
    let flags = Flags::parse(args)?;
    // list-keys 只需 store；--store 直给时不必解 home（不碰钥匙串、不需要 backup）。
    let store = match flags.value("store") {
        Some(s) => PathBuf::from(s),
        None => {
            let home = resolve_home(&flags, false)?;
            default_store(&home)
        }
    };
    let store_obj =
        Store::open(&store).map_err(|e| CliError::runtime(format!("打开本地库失败: {e}")))?;
    let rows = store_obj
        .list_keys()
        .map_err(|e| CliError::runtime(format!("列举密钥失败: {e}")))?;
    // 不读钥匙串（不碰真 keychain、也不报 masked）；masked 需 vault 读，辅助场景省略。
    println!("id\tname\tsite_id\tstatus\tcreated_at");
    for row in rows {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            row.id, row.name, row.site_id, row.status, row.created_at
        );
    }
    Ok(())
}

// ================================================================ mock-agent

fn mock_agent(args: &[String]) -> Result<(), CliError> {
    let flags = Flags::parse(args)?;
    let channel = parse_channel(&flags)?;
    let home = resolve_home(&flags, false)?;
    match mock_agent::check(channel, &home) {
        mock_agent::MockOutcome::Ok => {
            println!("ok");
            Ok(())
        }
        mock_agent::MockOutcome::KeyMissing(m) => {
            Err(CliError::runtime(format!("密钥字段缺失: {m}")))
        }
        mock_agent::MockOutcome::Fatal(m) => {
            Err(CliError::usage(format!("mock-agent 解析失败: {m}")))
        }
    }
}

// ================================================================ 参数解析 helpers

/// 解析 `--flag value` 与 `--bool` 标志。未知 `--x` ⇒ exit 2。
struct Flags {
    map: std::collections::HashMap<String, String>,
    bools: std::collections::HashSet<String>,
}

impl Flags {
    fn parse(args: &[String]) -> Result<Self, CliError> {
        let mut map = std::collections::HashMap::new();
        let mut bools = std::collections::HashSet::new();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if let Some(name) = a.strip_prefix("--") {
                if name == "smoke" || name == "i-know-this-is-real-home" {
                    bools.insert(name.to_string());
                    i += 1;
                    continue;
                }
                // --flag value
                if i + 1 >= args.len() {
                    return Err(CliError::usage(format!("--{name} 缺值")));
                }
                map.insert(name.to_string(), args[i + 1].clone());
                i += 2;
            } else {
                return Err(CliError::usage(format!("无法识别的参数: {a}\n{USAGE}")));
            }
        }
        Ok(Flags { map, bools })
    }

    fn value(&self, name: &str) -> Option<String> {
        self.map.get(name).cloned()
    }

    fn bool(&self, name: &str) -> bool {
        self.bools.contains(name)
    }
}

fn parse_channel(flags: &Flags) -> Result<DeliveryChannel, CliError> {
    let raw = flags
        .value("channel")
        .ok_or_else(|| CliError::usage("需要 --channel <C>（见 list-channels）"))?;
    DeliveryChannel::parse(&raw).map_err(|e| CliError::usage(format!("未知通道: {e}")))
}

fn parse_vault(flags: &Flags) -> VaultChoice {
    match flags.value("vault").as_deref() {
        Some("memory") => VaultChoice::Memory,
        // 一个版本内的回退/对照路径；生产默认已经换成本地加密保险库（ADR-0003）。
        Some("keychain") => VaultChoice::Keychain,
        _ => VaultChoice::Local,
    }
}

/// 解析 home。
///
/// **--smoke 防呆**（P2-1 强化）：解析出的 home **等于 `$HOME`**（真实 home）时
/// **硬拒 exit 2**，除非显式 `--i-know-this-is-real-home`（逃逸阀）。覆盖三种形态：
/// ① 未给 `--home` 且无 `TIANSHU_RELAY_HOME` ⇒ 落到 `$HOME`；② 显式 `--home "$HOME"`；
/// ③ `TIANSHU_RELAY_HOME` 等于 `$HOME`。`smoke-inject.mjs` 用 tmpdir + `--home <temp>`，
/// temp ≠ `$HOME` ⇒ 放行。
fn resolve_home(flags: &Flags, smoke: bool) -> Result<PathBuf, CliError> {
    let resolved = if let Some(h) = flags.value("home") {
        PathBuf::from(h)
    } else if let Some(h) = std::env::var_os("TIANSHU_RELAY_HOME") {
        PathBuf::from(h)
    } else {
        default_home().ok_or_else(|| {
            CliError::usage("无法确定 home：未给 --home，且 $TIANSHU_RELAY_HOME/$HOME 均未设置")
        })?
    };
    if smoke && !flags.bool("i-know-this-is-real-home") && is_real_home(&resolved) {
        return Err(CliError::usage(
            "apply-delivery --smoke 拒绝写真实 home（等于 $HOME）；冒烟应指向临时目录。\
             如确需写真实 home，加 --i-know-this-is-real-home",
        ));
    }
    Ok(resolved)
}

/// 解析出的 home 是否等于真实 `$HOME`（冒烟绝不能写真实 agent 配置）。
///
/// `HOME` 未设时返回 `false`（无真实 home 可 wreck）。
fn is_real_home(path: &std::path::Path) -> bool {
    match std::env::var_os("HOME") {
        Some(h) => path == std::path::Path::new(&h),
        None => false,
    }
}

fn resolve_store(flags: &Flags, home: &std::path::Path) -> PathBuf {
    flags
        .value("store")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_store(home))
}

fn resolve_backup_dir(flags: &Flags, home: &std::path::Path) -> PathBuf {
    flags
        .value("backup-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_backup_dir(home))
}
