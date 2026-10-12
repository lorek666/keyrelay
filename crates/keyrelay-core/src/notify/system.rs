//! 系统通知渠道（macOS `osascript` / Windows PowerShell Toast）。
//!
//! 两条设计线：
//!
//! 1. **命令拼装是纯函数**（[`system_command`]）：给定平台与通知，产出 `(program, args)`。
//!    于是「转义对不对」这件事可以在 macOS 上断言，不必真的在 Windows 上跑一遍。
//! 2. **执行走注入式 [`CommandRunner`]**：测试里**不会**真的弹通知，也不会真的起进程。
//!    生产用的 [`StdCommandRunner`] 本包测试不调用（本机无 GUI 会话，弹通知也无从观察）。
//!
//! **走 argv，不经 shell**：章程里写的 `osascript -e 'display notification …'` 是 shell 形态的
//! 说明；实现用 `Command::new(program).args(args)`，因此单引号不需要转义，也不存在 shell 注入
//! —— `'; rm -rf /` 只会是 argv 里的普通字符。

use std::process::Command;

use crate::error::{Error, Result};

use super::{CommandRunner, Notification, Notifier};

/// 应用标识。Windows Toast 的 `AppUserModelID` 位置用它。
const APP_ID: &str = "KeyRelay";

/// 平台分支。
///
/// 生产取 [`NotifyPlatform::current`]；测试显式传入，这样 macOS 上也能断言 Windows 分支的 argv。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NotifyPlatform {
    MacOs,
    Windows,
    /// 其它平台：不发系统通知（只写事件，由调用方负责）。
    Other,
}

impl NotifyPlatform {
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            NotifyPlatform::MacOs
        } else if cfg!(target_os = "windows") {
            NotifyPlatform::Windows
        } else {
            NotifyPlatform::Other
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NotifyPlatform::MacOs => "macos",
            NotifyPlatform::Windows => "windows",
            NotifyPlatform::Other => "other",
        }
    }
}

/// 系统通知渠道。
///
/// **冻结签名 `new(runner)` 拿不到 [`super::NotifyConfig`]**，所以 `system_enabled` 由调用方
/// 判定；本类型只负责「怎么发」，不负责「该不该发」。
pub struct SystemNotifier {
    runner: Box<dyn CommandRunner>,
    platform: NotifyPlatform,
}

impl SystemNotifier {
    pub fn new(runner: Box<dyn CommandRunner>) -> Self {
        Self::with_platform(runner, NotifyPlatform::current())
    }

    /// 显式指定平台（测试用；生产走 [`SystemNotifier::new`]）。
    pub fn with_platform(runner: Box<dyn CommandRunner>, platform: NotifyPlatform) -> Self {
        Self { runner, platform }
    }

    pub fn platform(&self) -> NotifyPlatform {
        self.platform
    }
}

impl Notifier for SystemNotifier {
    fn send(&self, n: &Notification) -> Result<()> {
        // 发送侧兜底脱敏（幂等）：调用方可能绕过了 `Notification::new`
        let n = n.scrubbed();
        let Some((program, args)) = system_command(self.platform, &n) else {
            // 其它平台：不发系统通知。「只写事件」由调用方补（本模块没有 store 句柄）
            return Ok(());
        };
        self.runner.run(&program, &args).map(|_| ())
    }
}

/// 纯函数：产出 `(program, args)`；`None` = 该平台不发系统通知。
///
/// - macOS：`osascript -e 'display notification "<body>" with title "<title>"'`
/// - Windows：`powershell -NoProfile -NonInteractive -Command <Toast 脚本>`
pub fn system_command(platform: NotifyPlatform, n: &Notification) -> Option<(String, Vec<String>)> {
    match platform {
        NotifyPlatform::MacOs => Some((
            "osascript".to_string(),
            vec!["-e".to_string(), apple_script(n)],
        )),
        NotifyPlatform::Windows => Some((
            "powershell".to_string(),
            vec![
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                toast_script(n),
            ],
        )),
        NotifyPlatform::Other => None,
    }
}

fn apple_script(n: &Notification) -> String {
    format!(
        "display notification \"{}\" with title \"{}\"",
        escape_apple_script(&n.body),
        escape_apple_script(&n.title)
    )
}

/// AppleScript 字符串字面量转义。
///
/// 反斜杠必须**先**转义，否则后面补出来的 `\"` 会被二次转义成 `\\"`（引号没关住，
/// 脚本语法直接坏掉）。
fn escape_apple_script(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

fn toast_script(n: &Notification) -> String {
    format!(
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; \
         $t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); \
         $t.GetElementsByTagName('text')[0].AppendChild($t.CreateTextNode({title})) | Out-Null; \
         $t.GetElementsByTagName('text')[1].AppendChild($t.CreateTextNode({body})) | Out-Null; \
         [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{app}').Show([Windows.UI.Notifications.ToastNotification]::new($t))",
        title = ps_literal(&n.title),
        body = ps_literal(&n.body),
        app = APP_ID,
    )
}

/// PowerShell **单引号**字面量：`'` 翻倍，其余原样。
///
/// 用单引号而不是双引号是刻意的：单引号字面量**不做变量插值**，
/// 因此通知正文里的 `$env:PATH` / `$(...)` 不会被求值（有测试）。
fn ps_literal(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

/// 生产用 runner：`std::process::Command`。
///
/// **本包测试不调用它**（无 GUI 会话，弹通知也无从观察）；只验证命令拼装。
/// 错误信息里**只带程序名**：args 里是通知正文，不该进错误串。
pub struct StdCommandRunner;

impl CommandRunner for StdCommandRunner {
    fn run(&self, program: &str, args: &[String]) -> Result<String> {
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|e| Error::Transport(format!("执行 {program} 失败: {e}")))?;
        if !output.status.success() {
            return Err(Error::Transport(format!(
                "{program} 退出码 {:?}",
                output.status.code()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::{Notification, NotifyKind};
    use std::sync::{Arc, Mutex};

    const SECRET: &str = "sk-0123456789abcdef";

    fn note(title: &str, body: &str) -> Notification {
        Notification {
            kind: NotifyKind::BalanceLow,
            site_id: Some(1),
            title: title.to_string(),
            body: body.to_string(),
            ts: 1,
        }
    }

    /// 记录到的 `(program, args)` 调用。
    type CallLog = Arc<Mutex<Vec<(String, Vec<String>)>>>;

    /// 记录 argv 的假 runner。**不执行任何进程**。
    #[derive(Default, Clone)]
    struct RecordingRunner {
        calls: CallLog,
        fail: bool,
    }

    impl RecordingRunner {
        fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().map(|c| c.clone()).unwrap_or_default()
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, program: &str, args: &[String]) -> Result<String> {
            self.calls
                .lock()
                .map_err(|_| Error::Transport("记录锁中毒".into()))?
                .push((program.to_string(), args.to_vec()));
            if self.fail {
                return Err(Error::Transport("命令执行失败".into()));
            }
            Ok(String::new())
        }
    }

    #[test]
    fn macos_argv_is_verbatim() {
        let n = note("余额不足", "测试站点: 剩余 3.5 USD，低于阈值 15");
        let (program, args) = system_command(NotifyPlatform::MacOs, &n).expect("macOS 有命令");
        assert_eq!(program, "osascript");
        assert_eq!(
            args,
            vec![
                "-e".to_string(),
                "display notification \"测试站点: 剩余 3.5 USD，低于阈值 15\" with title \"余额不足\""
                    .to_string()
            ]
        );
    }

    #[test]
    fn macos_escapes_quotes_backslashes_and_newlines() {
        let n = note("带\"引号\"的标题", "第一行\n第二行\t制表\\反斜杠\r回车");
        let (_, args) = system_command(NotifyPlatform::MacOs, &n).unwrap();
        assert_eq!(
            args[1],
            "display notification \"第一行\\n第二行\\t制表\\\\反斜杠\\r回车\" with title \"带\\\"引号\\\"的标题\""
        );
        // 引号总数：脚本骨架里的 4 个字面引号 + 标题里被转义成 `\"` 的 2 个
        assert_eq!(args[1].matches('"').count(), 6, "{}", args[1]);
        assert!(args[1].contains("带\\\"引号\\\"的标题"), "{}", args[1]);
    }

    #[test]
    fn macos_does_not_escape_single_quotes_and_cannot_be_shell_injected() {
        // 走 argv 不经 shell：单引号原样保留，且**不会**多出 argv 元素
        let n = note("t", "'; rm -rf / #");
        let (program, args) = system_command(NotifyPlatform::MacOs, &n).unwrap();
        assert_eq!(program, "osascript");
        assert_eq!(args.len(), 2, "参数个数不得被注入内容改变: {args:?}");
        assert!(args[1].contains("'; rm -rf / #"), "{}", args[1]);
        assert!(!args[1].contains("\\'"), "单引号不该被转义: {}", args[1]);
    }

    #[test]
    fn windows_argv_uses_single_quoted_literals() {
        let n = note("余额不足", "测试站点: 剩余 3.5 USD");
        let (program, args) = system_command(NotifyPlatform::Windows, &n).unwrap();
        assert_eq!(program, "powershell");
        assert_eq!(args[0], "-NoProfile");
        assert_eq!(args[1], "-NonInteractive");
        assert_eq!(args[2], "-Command");
        assert_eq!(args.len(), 4);
        let script = &args[3];
        assert!(
            script.contains("CreateTextNode('余额不足')"),
            "标题必须是单引号字面量: {script}"
        );
        assert!(
            script.contains("CreateTextNode('测试站点: 剩余 3.5 USD')"),
            "正文必须是单引号字面量: {script}"
        );
        assert!(script.contains("ToastNotificationManager"), "{script}");
    }

    #[test]
    fn windows_doubles_single_quotes_and_never_interpolates() {
        let n = note("it's", "$env:PATH $(rm -rf /)");
        let (_, args) = system_command(NotifyPlatform::Windows, &n).unwrap();
        let script = &args[3];
        assert!(
            script.contains("CreateTextNode('it''s')"),
            "单引号必须翻倍: {script}"
        );
        assert!(
            script.contains("CreateTextNode('$env:PATH $(rm -rf /)')"),
            "单引号字面量不做变量插值: {script}"
        );
        // 通知内容之外不出现裸的双引号包裹（避免调用方误以为被插值）
        assert_eq!(script.matches("it''s").count(), 1, "{script}");
    }

    #[test]
    fn other_platforms_have_no_command() {
        assert!(system_command(NotifyPlatform::Other, &note("t", "b")).is_none());
        assert_eq!(NotifyPlatform::Other.as_str(), "other");
        assert_eq!(NotifyPlatform::MacOs.as_str(), "macos");
        assert_eq!(NotifyPlatform::Windows.as_str(), "windows");
    }

    #[test]
    fn current_platform_matches_the_build_target() {
        let expected = if cfg!(target_os = "macos") {
            NotifyPlatform::MacOs
        } else if cfg!(target_os = "windows") {
            NotifyPlatform::Windows
        } else {
            NotifyPlatform::Other
        };
        assert_eq!(NotifyPlatform::current(), expected);
    }

    #[test]
    fn send_hands_the_argv_to_the_runner_and_never_spawns_anything() {
        let runner = RecordingRunner::default();
        let notifier =
            SystemNotifier::with_platform(Box::new(runner.clone()), NotifyPlatform::MacOs);
        assert_eq!(notifier.platform(), NotifyPlatform::MacOs);

        notifier
            .send(&note("余额不足", "测试站点: 剩余 3.5 USD"))
            .expect("假 runner 必定成功");

        let calls = runner.calls();
        assert_eq!(calls.len(), 1, "必须恰好调用一次");
        assert_eq!(calls[0].0, "osascript");
        assert_eq!(calls[0].1.len(), 2);
        assert_eq!(
            calls[0].1[1],
            "display notification \"测试站点: 剩余 3.5 USD\" with title \"余额不足\""
        );
    }

    #[test]
    fn send_scrubs_a_hand_built_notification() {
        // 绕过 `Notification::new` 直接拼结构体：发送侧必须兜住
        let runner = RecordingRunner::default();
        let notifier =
            SystemNotifier::with_platform(Box::new(runner.clone()), NotifyPlatform::MacOs);
        notifier
            .send(&note("t sk-0123456789abcdef", "b nap-0123456789abcdef"))
            .expect("成功");

        let argv = runner.calls()[0].1[1].clone();
        assert!(!argv.contains(SECRET), "{argv}");
        assert!(!argv.contains("nap-0123"), "{argv}");
        assert!(argv.contains("sk-***"), "{argv}");
    }

    #[test]
    fn send_is_a_noop_on_other_platforms() {
        let runner = RecordingRunner::default();
        let notifier =
            SystemNotifier::with_platform(Box::new(runner.clone()), NotifyPlatform::Other);
        notifier.send(&note("t", "b")).expect("不发命令也是成功");
        assert!(
            runner.calls().is_empty(),
            "非 mac/win 平台不得执行任何命令（事件由调用方写）"
        );
    }

    #[test]
    fn send_propagates_runner_failures() {
        let runner = RecordingRunner {
            fail: true,
            ..RecordingRunner::default()
        };
        let notifier = SystemNotifier::with_platform(Box::new(runner), NotifyPlatform::MacOs);
        let err = notifier.send(&note("t", "b")).unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
    }

    #[test]
    fn new_uses_the_current_platform() {
        let runner = RecordingRunner::default();
        let notifier = SystemNotifier::new(Box::new(runner));
        assert_eq!(notifier.platform(), NotifyPlatform::current());
    }
}
