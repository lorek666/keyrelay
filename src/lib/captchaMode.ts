import type { SiteCapabilities } from "./api";

/**
 * 人工验证面板的**三态**（M28-S2 / B-191 B 路，spec §2.1-6）。
 *
 * - `cookie`：会话走 Set-Cookie，`window.cookies()` 抓得到（NewAPI）；
 * - `bearer`：会话是响应体里的 access token，走「WebView localStorage →
 *   `keyrelay-creds://`」回传（Sub2API）；
 * - `unsupported`：该类型没有任何 WebView 兜底（Custom / 未知类型）。
 *
 * 判据**只来自后端能力表**（`SiteCapabilities`），页面里**不得**按 `kind` 硬编码——
 * 与 M7-S2 §3.3 同一条纪律：按类型名写判断，新增站点类型时必然漏一处。
 */
export type CaptchaPanelMode = "cookie" | "bearer" | "unsupported";

/**
 * 能力位 → 面板三态。**cookie 优先**：两者都为 true 的站点目前不存在，但若将来出现，
 * 抓 cookie 比注入脚本更保守（与壳层 `captcha_capture_mode` 同一口径）。
 *
 * 注意：这里只决定**渲染哪个面板**；真正决定「用哪条取数路径」的是后端
 * （`commands.rs::captcha_capture_mode`）。两边读的是**同一张能力表**，所以不会分叉。
 */
export function captchaPanelMode(caps: SiteCapabilities): CaptchaPanelMode {
  if (caps.webviewCaptchaSupported) return "cookie";
  if (caps.webviewBearerSupported) return "bearer";
  return "unsupported";
}
