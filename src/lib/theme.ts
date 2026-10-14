import { useEffect } from "react";

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
 * 把主题写到 `<html data-theme>` 上。`setting` 还没读出来（`undefined`）时什么都不做：
 * 样式表的缺省就是深色——也就是本步之前一直以来的样子。
 *
 * 只有「跟随系统」时才订阅系统外观变化：只在打开窗口那一刻读一次的话，用户切了系统外观之后
 * 界面不跟，那就不叫跟随系统；而固定了浅色 / 深色之后还订阅，就是一个永远不该生效的监听。
 */
export function useApplyTheme(setting: string | undefined) {
  useEffect(() => {
    if (setting === undefined) return;
    if (!followsSystem(setting)) {
      document.documentElement.dataset.theme = setting;
      return;
    }
    const media = window.matchMedia(DARK_QUERY);
    const apply = () => {
      document.documentElement.dataset.theme = media.matches ? "dark" : "light";
    };
    apply();
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [setting]);
}
