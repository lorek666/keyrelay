//! M34-S1：Agent 更新检查与白名单一键更新的**集成**测试。
//!
//! 默认 `cargo test` 只跑不联网的部分（静态表、公共版本比较、拒绝路径）。
//! 真实网络与真实更新分别由两个 `#[ignore]` 用例承载，其中**真实更新**必须
//! 同时满足两个闸门才执行：
//!
//! ```text
//! TIANSHU_RELAY_REAL_AGENT_UPDATE=1 cargo test -p tianshu-relay-core --test agent_updates -- --ignored
//! ```
//!
//! 只有 `--ignored`（会真的跑被忽略的用例）而没设环境变量时，真实更新用例会
//! 直接返回、不碰系统——避免「顺手 --ignored 就把用户机器上的 codex 更新了」。

use std::path::{Path, PathBuf};

use tianshu_relay_core::agent_updates::{self, compare_versions, VersionDiff};
use tianshu_relay_core::agents;

fn home() -> PathBuf {
    // 不存在的 HOME：find_bin 仍会查 PATH，但不会碰到用户家目录里的 bin。
    Path::new("/nonexistent-tianshu-relay-m34-it-home").to_path_buf()
}

/// 真实 HOME：只给 `#[ignore]` 的真机用例用（要看到本机已装 agent 的当前/最新版本）。
///
/// 非 `#[ignore]` 的用例一律用上面的假 HOME——否则「本机装了什么」会污染断言。
fn real_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

#[test]
fn specs_cover_the_twenty_eight_channels_in_agents_order() {
    let update_channels: Vec<&str> = agent_updates::specs()
        .iter()
        .map(|spec| spec.channel)
        .collect();
    let agent_channels: Vec<&str> = agents::specs().iter().map(|spec| spec.channel).collect();

    assert_eq!(update_channels.len(), 28, "更新表必须是 28 条");
    assert_eq!(agent_channels.len(), 28);
    assert_eq!(
        update_channels, agent_channels,
        "更新表的 channel 顺序必须与 agents::specs() 逐位一致"
    );
}

#[test]
fn every_channel_has_a_manual_url() {
    for spec in agent_updates::specs() {
        assert!(
            spec.manual_url.starts_with("https://"),
            "{} 的 manual_url 必须是 https 地址",
            spec.channel
        );
    }
}

#[test]
fn compare_versions_is_public_and_monotonic() {
    assert_eq!(compare_versions("1.2.3", "1.2.3"), VersionDiff::UpToDate);
    assert_eq!(
        compare_versions("0.162.1", "0.163.0"),
        VersionDiff::UpdateAvailable
    );
    assert_eq!(
        compare_versions("2.0.0", "1.0.0"),
        VersionDiff::InstalledNewer
    );
    assert_eq!(
        compare_versions("garbage", "1.0.0"),
        VersionDiff::Unparsable
    );
}

#[test]
fn update_agent_rejects_channels_without_strategies() {
    for channel in ["grok-build", "dsh", "no-such-channel"] {
        let error =
            agent_updates::update_agent(&home(), channel).expect_err("无策略/未知通道必须被拒绝");
        let text = error.to_string();
        assert!(
            text.contains("不支持一键更新") || text.contains("未知的投递通道"),
            "{channel} 的拒绝文案不对: {text}"
        );
    }
}

/// 真实网络检查（**只读**）：npm / brew / marketplace 可达时返回版本，
/// 不可达时逐条 error、不 panic。
#[test]
#[ignore = "真实网络：需要联网；用 --ignored 单独跑"]
fn real_network_check_returns_statuses_without_panicking() {
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    // 用**真实 HOME**：否则所有通道都是 notInstalled，`latest_version` 恒为 None，
    // 这条用例就证明不了「真实网络能拿到版本」。
    let real_home = real_home();
    let statuses = agents::detect_agents(&real_home);
    let result = runtime.block_on(agent_updates::check_agent_updates(
        &real_home, &statuses, None,
    ));

    assert_eq!(result.len(), 28, "检查结果必须 28 条");
    let channels: Vec<&str> = result.iter().map(|row| row.channel.as_str()).collect();
    let expected: Vec<&str> = agent_updates::specs()
        .iter()
        .map(|spec| spec.channel)
        .collect();
    assert_eq!(channels, expected);

    // 不假设网络一定可用：只要每条都有合法 state、且非未安装的通道给出 source 即可。
    for row in &result {
        assert!(
            matches!(
                row.state.as_str(),
                "available" | "upToDate" | "unknown" | "unsupported" | "error" | "notInstalled"
            ),
            "{} 的 state 不合法: {}",
            row.channel,
            row.state
        );
        assert!(
            matches!(
                row.source.as_str(),
                "npm" | "brewCask" | "marketplace" | "none"
            ),
            "{} 的 source 不合法: {}",
            row.channel,
            row.source
        );
    }

    // 真实网络下至少要有一个 npm 通道能拿到版本（本机有网时），拿不到也不失败，
    // 但要把「全 error」这种情况打印出来便于证据记录。
    let with_latest = result
        .iter()
        .filter(|row| row.latest_version.is_some())
        .count();
    println!("真实检查：{with_latest}/28 个通道拿到了最新版本");
    for row in result
        .iter()
        .filter(|row| row.installed || row.latest_version.is_some() || row.state == "error")
    {
        println!(
            "{}: current={:?} latest={:?} state={} autoUpdate={} message={:?}",
            row.channel,
            row.current_version,
            row.latest_version,
            row.state,
            row.auto_update,
            row.message
        );
    }
}

/// 真实更新（**双闸**）：`--ignored` **且** `TIANSHU_RELAY_REAL_AGENT_UPDATE=1` 才执行。
///
/// 会真的跑 `codex update` / `npm install -g @openai/codex@latest`，改动用户机器上的
/// 第三方程序——所以默认永远不跑。
#[test]
#[ignore = "真实更新：会执行更新命令；必须 --ignored + TIANSHU_RELAY_REAL_AGENT_UPDATE=1 双闸"]
fn real_update_codex_only_with_explicit_env_gate() {
    if std::env::var("TIANSHU_RELAY_REAL_AGENT_UPDATE").as_deref() != Ok("1") {
        println!(
            "跳过真实更新：没有设置 TIANSHU_RELAY_REAL_AGENT_UPDATE=1（双闸只满足 --ignored）"
        );
        return;
    }

    let outcome = agent_updates::update_agent(&real_home(), "codex-auth-json")
        .expect("codex-auth-json 支持一键更新");

    println!(
        "codex 更新：success={} before={:?} after={:?} changed={}",
        outcome.success, outcome.version_before, outcome.version_after, outcome.version_changed
    );
    for attempt in &outcome.attempts {
        println!(
            "  [{}] {} skipped={} success={} exit={:?} timeout={}",
            attempt.label,
            attempt.command,
            attempt.skipped,
            attempt.success,
            attempt.exit_code,
            attempt.timed_out
        );
        if !attempt.output_tail.is_empty() {
            println!("  output: {}", attempt.output_tail);
        }
    }

    // 不断言「一定成功」：本机可能没装 codex / 没网 / npm 前缀不可写。
    // 断言的是**不 panic、结构完整、失败有输出可展示**。
    assert_eq!(outcome.channel, "codex-auth-json");
    assert!(!outcome.attempts.is_empty(), "至少要记录一次尝试");
    if !outcome.success {
        assert!(outcome.message.is_some(), "失败时必须给出人话说明");
    }
}
