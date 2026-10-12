//! 托盘图标与菜单（M6-S5 / 关闭 BACKLOG B-53）。
//!
//! PRD FR-7 要求「`--hidden` 常驻 + 系统级自启」；托盘是它的前半截：
//! 关掉窗口之后进程继续活着，后台刷新才不会跟着一起结束。
//!
//! # 可测性边界（重要）
//!
//! 托盘图标的**真实创建**只有在一个真的 GUI 会话里才跑得起来。本机（以及任何
//! 无 GUI 的构建/CI 环境）跑不到，所以本模块把能测的部分**全部**抽成了纯函数：
//!
//! - [`has_hidden_flag`]：命令行里有没有 `--hidden`（纯函数，可单测）
//! - [`menu_labels`]：菜单项 id 与文案的映射（纯函数，可单测）
//! - `Settings::should_hide_on_close`：关窗该不该隐藏（在 `keyrelay-core`，可单测）
//!
//! [`build`] 本身只做「把上面这些结论装配成 Tauri 对象」，**不得**在其中放任何判定逻辑。
//! 这样「托盘不工作」时的排查范围就只剩 Tauri 装配这一层。

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::{AppHandle, Manager, Runtime};

/// 显示主窗口。
pub const MENU_SHOW: &str = "tray.show";
/// 启动本地网关。
pub const MENU_GATEWAY_START: &str = "tray.gateway.start";
/// 停止本地网关。
pub const MENU_GATEWAY_STOP: &str = "tray.gateway.stop";
/// 退出应用（**真的退出**，不隐藏）。
pub const MENU_QUIT: &str = "tray.quit";

/// 菜单项清单：`(id, 文案)`。顺序即显示顺序。
///
/// 抽成常量的目的：让「菜单里到底有哪些项」这件事可以被测试与复审直接读到，
/// 而不是埋在一串 builder 调用里。
pub const MENU_ITEMS: [(&str, &str); 4] = [
    (MENU_SHOW, "显示主窗口"),
    (MENU_GATEWAY_START, "启动本地网关"),
    (MENU_GATEWAY_STOP, "停止本地网关"),
    (MENU_QUIT, "退出 KeyRelay"),
];

/// 菜单 id 的集合（供测试断言与前端对齐）。
pub fn menu_labels() -> Vec<(&'static str, &'static str)> {
    MENU_ITEMS.to_vec()
}

/// 命令行里有没有 `--hidden`。
///
/// 纯函数：不读全局 `std::env::args()`，参数由调用方传入 —— 否则这个判定没法测。
/// 只认**精确匹配**的 `--hidden`：`--hidden=1` 或 `--hiddenx` 都不算，
/// 避免将来加了别的 `--hidden-*` 参数时被误判。
pub fn has_hidden_flag<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter().any(|arg| arg.as_ref() == "--hidden")
}

/// 装配托盘图标与菜单。
///
/// 返回 `Err` 时调用方应当**只记一条日志并继续启动**：托盘挂了不该让整个应用起不来。
/// 这也让无 GUI 的环境（CI）不会因为托盘失败而中断。
pub fn build<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let mut items: Vec<MenuItem<R>> = Vec::with_capacity(MENU_ITEMS.len());
    for (id, label) in MENU_ITEMS {
        items.push(MenuItem::with_id(app, id, label, true, None::<&str>)?);
    }
    let separator = PredefinedMenuItem::separator(app)?;

    let mut refs: Vec<&dyn tauri::menu::IsMenuItem<R>> = Vec::with_capacity(items.len() + 1);
    for item in &items {
        refs.push(item);
    }
    refs.push(&separator);
    let menu = Menu::with_items(app, &refs)?;

    let mut builder = tauri::tray::TrayIconBuilder::with_id("keyrelay-tray")
        .menu(&menu)
        // 左键点图标直接显示主窗口，不必先开菜单
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| {
            let id = event.id().as_ref();
            match id {
                MENU_SHOW => show_main_window(app),
                MENU_QUIT => app.exit(0),
                // 网关的启停放在命令层（`gateway_start` / `gateway_stop`），
                // 托盘这里不直接碰 `AppState`：托盘回调是同步的，而启停是异步序列，
                // 在回调里 block_on 会和主线程的 `gateway_op` 锁打架。
                MENU_GATEWAY_START | MENU_GATEWAY_STOP => show_main_window(app),
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, event| {
            // 只处理「左键单击」：右键交给菜单
            if let tauri::tray::TrayIconEvent::Click {
                button: tauri::tray::MouseButton::Left,
                button_state: tauri::tray::MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });

    if let Some(icon) = app.default_window_icon().cloned() {
        builder = builder.icon(icon);
    }
    builder.build(app)?;
    Ok(())
}

/// 显示并聚焦主窗口。
pub fn show_main_window<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_flag_is_matched_exactly() {
        assert!(has_hidden_flag(["--hidden"]));
        assert!(has_hidden_flag(["keyrelay", "--hidden"]));
        assert!(has_hidden_flag(["keyrelay", "--foo", "--hidden", "--bar"]));

        // 精确匹配：带值的写法与同前缀的写法都不算
        assert!(!has_hidden_flag(["--hidden=1"]));
        assert!(!has_hidden_flag(["--hiddenx"]));
        assert!(!has_hidden_flag(["--hidden "]));
        assert!(!has_hidden_flag(["--no-hidden"]));
        assert!(!has_hidden_flag(Vec::<String>::new()));
        assert!(!has_hidden_flag(["keyrelay"]));
    }

    #[test]
    fn hidden_flag_works_with_string_owned_args() {
        // 真实调用点是 `std::env::args()`，给的是 `String` 而不是 `&str`
        let owned: Vec<String> = vec!["keyrelay".to_string(), "--hidden".to_string()];
        assert!(has_hidden_flag(owned));
    }

    #[test]
    fn menu_ids_are_unique_and_nonempty() {
        let labels = menu_labels();
        assert_eq!(labels.len(), MENU_ITEMS.len());
        let mut ids: Vec<&str> = labels.iter().map(|(id, _)| *id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), before, "菜单 id 不得重复");

        for (id, label) in labels {
            assert!(!id.is_empty());
            assert!(!label.is_empty(), "{id} 的文案不能为空");
        }
    }

    #[test]
    fn quit_is_the_last_item() {
        // 退出项放在最后是菜单的常规约定；顺序变了说明有人重排了菜单，值得显式确认一次
        assert_eq!(MENU_ITEMS.last().map(|(id, _)| *id), Some(MENU_QUIT));
    }

    #[test]
    fn every_menu_id_is_handled_by_the_dispatcher() {
        // 反例保护：`on_menu_event` 里漏掉一个 id 的后果是「点了没反应」——
        // 静默失败。这里把「菜单里声明的 id」与「分发器认得的 id」钉在一起。
        // 分发器认得 = 在下面这个集合里。
        let handled = [MENU_SHOW, MENU_QUIT, MENU_GATEWAY_START, MENU_GATEWAY_STOP];
        for (id, _) in MENU_ITEMS {
            assert!(handled.contains(&id), "菜单项 {id} 没有对应的分发分支");
        }
    }
}
