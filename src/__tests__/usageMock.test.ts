import { describe, expect, it } from "vitest";
import { usageDashboard } from "../lib/api";

/**
 * M34-S1：浏览器预览（无 Tauri 运行时）的 mock 数据。
 *
 * 这条不是「测 mock 长得对不对」，而是钉住预览路径的**可用性**：
 * `pnpm dev` 是唯一能肉眼核界面的路径，mock 里一个 undefined 就会让整页白屏，
 * 而 Tauri 模式下的测试完全覆盖不到它。顺带钉住 mock 与能力表的一致性——
 * 3 号站点 `keyUsage=false`，mock 不得给它造 per-key 行。
 */
describe("用量看板 mock（浏览器预览路径）", () => {
  it("默认 30 天：三个站点、30 个日期、两种币种、key 行只给有能力的站点", async () => {
    const data = await usageDashboard(30, null);
    expect(data.rangeDays).toBe(30);
    expect(data.siteId).toBeNull();
    expect(new Set(data.daily.map((row) => row.siteId))).toEqual(
      new Set([1, 2, 3]),
    );
    expect(new Set(data.daily.map((row) => row.date)).size).toBe(30);
    expect(new Set(data.snapshots.map((row) => row.currency))).toEqual(
      new Set(["USD", "CNY"]),
    );
    expect(data.keyUsage.some((row) => row.siteId === 1)).toBe(true);
    expect(data.keyUsage.some((row) => row.siteId === 2)).toBe(true);
    expect(data.keyUsage.some((row) => row.siteId === 3)).toBe(false);
  });

  it("天数夹取与站点筛选在 mock 里也生效（与后端契约一致）", async () => {
    const data = await usageDashboard(0, 2);
    expect(data.rangeDays).toBe(1);
    expect(data.siteId).toBe(2);
    expect(data.daily).toHaveLength(1);
    expect(data.daily.every((row) => row.siteId === 2)).toBe(true);
    expect(data.snapshots.every((row) => row.siteId === 2)).toBe(true);
  });
});
