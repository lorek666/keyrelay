//! M7-S3 集成测试 · 生效策略（`restart_hint` 七通道）与 Cline/Roo 只读探测。
//!
//! 两条硬约束：
//! 1. `restart_hint` 是**纯函数**，且七个通道都有取值（表逐字钉住）；
//! 2. `detect_unmanaged_targets` **只读**——递归快照证明它不创建目录、不写盘（章程 R-7）。

use std::fs;
use std::path::{Path, PathBuf};

use tianshu_relay_core::delivery::{
    detect_unmanaged_targets, restart_hint, restart_hint_detail, DeliveryChannel, RestartAction,
    RestartHint, RestartHintSource,
};

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().expect("临时目录")
}

/// 递归列出 `root` 下的所有路径（含目录），用于「零副作用」比对。
fn tree_snapshot(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path.clone());
            }
            out.push(path);
        }
    }
    out.sort();
    out
}

#[test]
fn tree_snapshot_detects_changes() {
    // 防假绿：快照函数必须真的能观测到新增目录/文件，否则下面那条「零副作用」断言是空跑。
    let dir = tmp();
    let empty = tree_snapshot(dir.path());
    assert!(empty.is_empty());
    fs::create_dir_all(dir.path().join("a/b")).unwrap();
    fs::write(dir.path().join("a/b/c"), "x").unwrap();
    let after = tree_snapshot(dir.path());
    assert_ne!(after, empty);
    assert_eq!(after.len(), 3, "{after:?}");
}

// ============================================================ restart_hint

#[test]
fn restart_hint_covers_every_channel() {
    assert_eq!(
        DeliveryChannel::ALL.len(),
        20,
        "M14-S3：ALL 由 17 变 19（M25-S1 加 codex-config 变 20）"
    );
    // 穷举 match 由编译器保证「每个变体都有取值」；这里钉住「七个通道各不相同地可达」
    let mut hints: Vec<&'static str> = Vec::new();
    for channel in DeliveryChannel::ALL {
        hints.push(match restart_hint(channel) {
            RestartHint::NotNeeded => "not-needed",
            RestartHint::Needed => "needed",
            RestartHint::DependsOnNewSession => "new-session",
        });
    }
    assert_eq!(hints.len(), 20);
}

#[test]
fn restart_hint_table_is_verbatim() {
    // P1-6 生效分表：Claude Code 新会话即生效，其余 19 条仍标 Needed。
    // （旧 M14-S1 “所有通道都标 Needed” 一说已作废。）
    assert_eq!(
        restart_hint(DeliveryChannel::ClaudeCodeSettings),
        RestartHint::DependsOnNewSession,
        "claude-code-settings 应为新会话即生效"
    );
    assert_eq!(restart_hint(DeliveryChannel::Hermes), RestartHint::Needed);
    for channel in [
        DeliveryChannel::CodexAuthJson,
        DeliveryChannel::OpenCode,
        DeliveryChannel::GeminiCli,
        DeliveryChannel::OpenCodeJsonc,
        DeliveryChannel::OpenClaw,
    ] {
        assert_eq!(
            restart_hint(channel),
            RestartHint::Needed,
            "{} 应按「进程启动时读配置」保守标注",
            channel.as_str()
        );
    }
}

/// P1-6：分表逐条钉住（取值 + 来源标注 + 动作），三者缺一不可。
///
/// 三分法对照：抄 cc-switch（未实测）4 条通道——Claude Code、Gemini、Grok、
/// Claude Desktop；已实测 0 条；未实测 16 条通道（含 Codex 两条：其桌面按钮 /
/// 终端手动 / daemon 三分法是本项目 P1-5 结论、不是 cc-switch 原话，故不标抄表）。
#[test]
fn restart_hint_detail_table_is_verbatim() {
    use RestartAction as Action;
    use RestartHint as Hint;
    use RestartHintSource as Source;
    let table: [(DeliveryChannel, Hint, Source, Action); 20] = [
        (
            DeliveryChannel::CodexAuthJson,
            Hint::Needed,
            Source::Unverified,
            Action::CodexSplit,
        ),
        (
            DeliveryChannel::CodexConfig,
            Hint::Needed,
            Source::Unverified,
            Action::CodexSplit,
        ),
        (
            DeliveryChannel::ClaudeCodeSettings,
            Hint::DependsOnNewSession,
            Source::CcSwitchUnverified,
            Action::NewSession,
        ),
        (
            DeliveryChannel::OpenCode,
            Hint::Needed,
            Source::Unverified,
            Action::RestartAgent,
        ),
        (
            DeliveryChannel::GeminiCli,
            Hint::Needed,
            Source::CcSwitchUnverified,
            Action::RestartTerminalOrCli,
        ),
        (
            DeliveryChannel::OpenCodeJsonc,
            Hint::Needed,
            Source::Unverified,
            Action::RestartAgent,
        ),
        (
            DeliveryChannel::ClaudeDesktop,
            Hint::Needed,
            Source::CcSwitchUnverified,
            Action::RelaunchDesktopApp,
        ),
        (
            DeliveryChannel::GrokBuild,
            Hint::Needed,
            Source::CcSwitchUnverified,
            Action::RestartTerminalOrCli,
        ),
        (
            DeliveryChannel::OpenClaw,
            Hint::Needed,
            Source::Unverified,
            Action::RestartAgent,
        ),
        (
            DeliveryChannel::Hermes,
            Hint::Needed,
            Source::Unverified,
            Action::RestartAgent,
        ),
        (
            DeliveryChannel::MCode,
            Hint::Needed,
            Source::Unverified,
            Action::RestartAgent,
        ),
        (
            DeliveryChannel::Pi,
            Hint::Needed,
            Source::Unverified,
            Action::RestartAgent,
        ),
        (
            DeliveryChannel::Cursor,
            Hint::Needed,
            Source::Unverified,
            Action::RestartAgent,
        ),
        // Cline 两条按任务范围留给 P2-9：本项不动其动作，只钉住“仍为通用 + 未实测”。
        (
            DeliveryChannel::Cline,
            Hint::Needed,
            Source::Unverified,
            Action::RestartAgent,
        ),
        (
            DeliveryChannel::QwenCode,
            Hint::Needed,
            Source::Unverified,
            Action::RestartAgent,
        ),
        (
            DeliveryChannel::DeepSeek,
            Hint::Needed,
            Source::Unverified,
            Action::RestartAgent,
        ),
        (
            DeliveryChannel::Trae,
            Hint::Needed,
            Source::Unverified,
            Action::RestartAgent,
        ),
        (
            DeliveryChannel::MiMoCode,
            Hint::Needed,
            Source::Unverified,
            Action::RestartAgent,
        ),
        (
            DeliveryChannel::ClineDesktop,
            Hint::Needed,
            Source::Unverified,
            Action::RestartAgent,
        ),
        (
            DeliveryChannel::DeepSeekHarness,
            Hint::Needed,
            Source::Unverified,
            Action::RestartAgent,
        ),
    ];
    assert_eq!(table.len(), DeliveryChannel::ALL.len());
    for (channel, hint, source, action) in table {
        let detail = restart_hint_detail(channel);
        assert_eq!(detail.hint, hint, "{}: 取值", channel.as_str());
        assert_eq!(detail.source, source, "{}: 来源标注", channel.as_str());
        assert_eq!(detail.action, action, "{}: 动作", channel.as_str());
        // 分表不得与取值函数自相矛盾。
        assert_eq!(
            detail.hint,
            restart_hint(channel),
            "{}: 分表取值必须等于 restart_hint",
            channel.as_str()
        );
    }
    // 诚实线：没有任何通道敢标“已实测”——先有真机证据再改这条断言。
    assert!(
        DeliveryChannel::ALL
            .iter()
            .all(|c| restart_hint_detail(*c).source != RestartHintSource::Verified),
        "当前没有任何通道做过真机生效验证，不得出现 Verified"
    );
    // 线格式键集合（前端按这三个键取文案，改键名必须同步改 DTO/TS/i18n）。
    assert_eq!(
        RestartHintSource::CcSwitchUnverified.as_str(),
        "ccSwitchUnverified"
    );
    assert_eq!(RestartHintSource::Verified.as_str(), "verified");
    assert_eq!(RestartHintSource::Unverified.as_str(), "unverified");
    assert_eq!(RestartAction::NewSession.as_str(), "newSession");
    assert_eq!(
        RestartAction::RestartTerminalOrCli.as_str(),
        "restartTerminalOrCli"
    );
    assert_eq!(
        RestartAction::RelaunchDesktopApp.as_str(),
        "relaunchDesktopApp"
    );
    assert_eq!(RestartAction::CodexSplit.as_str(), "codexSplit");
    assert_eq!(RestartAction::RestartAgent.as_str(), "restartAgent");
}

#[test]
fn restart_hint_is_pure() {
    for channel in DeliveryChannel::ALL {
        let first = restart_hint(channel);
        let first_detail = restart_hint_detail(channel);
        let saved = std::env::var("HOME").ok();
        std::env::set_var("HOME", "/tmp/tianshu-relay-not-this-home");
        let second = restart_hint(channel);
        let second_detail = restart_hint_detail(channel);
        match saved {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
        assert_eq!(first, second, "{}: 纯函数不得依赖环境", channel.as_str());
        assert_eq!(
            first_detail,
            second_detail,
            "{}: 分表同样是纯函数，不得依赖环境",
            channel.as_str()
        );
    }
}

// ============================================================ Cline / Roo 探测

#[test]
fn lists_cline_and_roo_in_a_stable_order() {
    let dir = tmp();
    let items = detect_unmanaged_targets(dir.path());
    assert_eq!(items.len(), 2, "宿主平台各一条");
    assert_eq!(items[0].label, "Cline");
    assert_eq!(items[1].label, "Roo Code");
    for item in &items {
        assert!(
            item.path.starts_with(dir.path()),
            "{} 的路径必须落在 home 内: {}",
            item.label,
            item.path.display()
        );
        assert!(!item.exists, "临时 home 下不该存在");
    }
}

#[test]
fn notes_are_verbatim() {
    let dir = tmp();
    let items = detect_unmanaged_targets(dir.path());
    assert_eq!(
        items[0].note,
        "本版本不向 Cline 写入：它的配置落点尚未核实，写错文件会让你以为投递成功。"
    );
    assert_eq!(
        items[1].note,
        "本版本不向 Roo Code 写入：它的配置落点尚未核实，写错文件会让你以为投递成功。"
    );
}

#[test]
fn reports_existence_without_touching_anything() {
    let dir = tmp();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();

    let before = tree_snapshot(&home);
    let items = detect_unmanaged_targets(&home);
    assert_eq!(tree_snapshot(&home), before, "探测不得写盘 / 建目录");

    // 造出 Cline 的候选目录 → exists 变 true，仍然不写盘
    fs::create_dir_all(&items[0].path).unwrap();
    let with_dir = tree_snapshot(&home);
    let again = detect_unmanaged_targets(&home);
    assert!(again[0].exists);
    assert!(!again[1].exists);
    assert_eq!(tree_snapshot(&home), with_dir, "探测不得写盘 / 建目录");
}

#[test]
fn survives_a_missing_home() {
    let dir = tmp();
    let missing = dir.path().join("no-such-home");
    let items = detect_unmanaged_targets(&missing);
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|t| !t.exists));
    assert!(!missing.exists(), "探测不得创建 home");
}
