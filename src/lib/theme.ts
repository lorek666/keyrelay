import { useEffect } from "react";
import { applyNativeWindowTheme } from "./api";

/**
 * 是否跟随系统外观（M9-S4 / F）。
 *
 * `"system"` 与**认不出的取值**都算跟随系统——后端将来新增取值时，界面退到「跟随系统」
 * 而不是随便挑一个（与 `loginFieldHint` 的「不猜」同一口径）。
 */
function followsSystem(setting: string): boolean {
  return setting !== "light" && setting !== "dark";
}

const DARK_QUERY = "(prefers-color-scheme: dark)";

/**
 * 把主题写到 `<html data-theme>` 上。`setting` 还没读出来（`undefined`）时沿用
 * index.html 内联引导写入的系统外观；不在此处再猜一次或回到固定深色。
 *
 * 只有「跟随系统」时才订阅系统外观变化：只在打开窗口那一刻读一次的话，用户切了系统外观之后
 * 界面不跟，那就不叫跟随系统；而固定了浅色 / 深色之后还订阅，就是一个永远不该生效的监听。
 *
 * **B-127**：网页内容之外，原生窗口的**外框**（标题栏/红绿灯）也要跟着变。
 * 那一步走 Tauri 的 `setTheme`，只能在 api.ts 里调（`check-commands.mjs` §3 规定
 * 只有 api.ts 可以引用 `@tauri-apps/api`）。失败**必须吞掉**：外框不跟随是观感问题，
 * 不该让界面报错或中断——所以这里只 `catch` 不 `throw`。
 */
export function useApplyTheme(setting: string | undefined) {
  useEffect(() => {
    if (setting === undefined) return;
    if (!followsSystem(setting)) {
      document.documentElement.dataset.theme = setting;
      // 这个分支里 `setting` 只可能是 "light" / "dark"（`followsSystem` 的定义）
      void applyNativeWindowTheme(setting === "dark" ? "dark" : "light").catch(() => {
        // 外框不跟随主题：静默降级（网页内容已经按 setting 上色了）
      });
      return;
    }
    const media = window.matchMedia(DARK_QUERY);
    const apply = () => {
      const resolved = media.matches ? "dark" : "light";
      document.documentElement.dataset.theme = resolved;
      void applyNativeWindowTheme(resolved).catch(() => {
        // 同上：静默降级
      });
    };
    apply();
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [setting]);
}
