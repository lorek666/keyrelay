import { describe, it, expect } from "vitest";
import { isClineDesktopDelistedError, localizeDelistedError } from "../lib/api";
import { translate, getCurrentDict } from "../i18n";

// DEBUG-G7 P2-F2：下线错误本地化映射必须有前端用例钉住——映射靠后端原文
// 子串“暂不支持文件直写”触发，后端改措辞会静默失效（英文界面直接露出中文
// 原文）。`deliveryPlan` 与 `applyDelivery` 的 catch 块共用 `localizeDelistedError`，
// 故本用例钉住该共享映射函数本身（谓词 + 本地化输出 + 非下线原样透传）；
// 两路的 catch 接线与本函数逐字相同，改漏一路会在复审 diff 里可见。
//
// 刻意不走 Tauri invoke 全链路：仓库门禁规定只有 `src/lib/api.ts` 可直接引用
// Tauri 包，测试文件 mock invoke 会触犯 `scripts/check-commands.mjs` 第 3 条；
// 映射函数是两路唯一的脆弱点，钉住它即钉住失效模式。
//
// 后端原文取自 delivery/mod.rs 的 ClineDesktop 下线错误（B-292）：
// “暂不支持文件直写，请走 cline auth CLI”（Error::inject 会在前面拼路径，
// 这里用带路径前缀的完整形态，确认子串匹配而非全等匹配）。
const BACKEND_DELISTED =
  "/home/you/.config/cline: 暂不支持文件直写，请走 cline auth CLI";

describe("下线错误本地化映射（DEBUG-G7 P2-F2）", () => {
  it("isClineDesktopDelistedError 只认后端下线子串，不认其它错误", () => {
    expect(isClineDesktopDelistedError(new Error(BACKEND_DELISTED))).toBe(true);
    expect(isClineDesktopDelistedError(new Error("写入失败：权限不足"))).toBe(false);
    expect(isClineDesktopDelistedError("暂不支持文件直写")).toBe(false);
    expect(isClineDesktopDelistedError(null)).toBe(false);
  });

  it("localizeDelistedError：下线错误 → 本地化文案（两路共用）", () => {
    const expected = translate(
      getCurrentDict(),
      "agents.delivery.clineDesktopDelisted",
    );
    expect(localizeDelistedError(new Error(BACKEND_DELISTED))).toBe(expected);
  });

  it("localizeDelistedError：非下线错误 → null（调用方原样透传）", () => {
    expect(localizeDelistedError(new Error("站点不可达"))).toBe(null);
    expect(localizeDelistedError(new Error("写入失败：权限不足"))).toBe(null);
  });
});
