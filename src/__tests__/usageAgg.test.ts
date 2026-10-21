import { describe, expect, it } from "vitest";
import {
  emptyTotals,
  formatShare,
  formatTokens,
  groupByDay,
  groupByModel,
  groupBySite,
  snapshotsByCurrency,
  stackByDayAndSite,
  sumTotals,
  unionDates,
} from "../lib/usageAgg";
import type { UsageDaily, UsageSnapshotDaily } from "../lib/api";

/**
 * M34-S1：用量聚合纯函数。
 *
 * 这些函数决定页面上的数字与图表形状；组件测试里数字算错很难定位，
 * 所以每条判据都在这里用最小夹具钉住（排序平局、缺日补 0、币种分组）。
 */

const daily = (over: Partial<UsageDaily> = {}): UsageDaily => ({
  date: "2026-10-21",
  siteId: 1,
  model: "gpt-4",
  requests: 1,
  promptTokens: 10,
  completionTokens: 5,
  totalTokens: 15,
  ...over,
});

const snapshot = (
  over: Partial<UsageSnapshotDaily> = {},
): UsageSnapshotDaily => ({
  date: "2026-10-21",
  siteId: 1,
  used: 1,
  remaining: 9,
  currency: "USD",
  samples: 1,
  ...over,
});

describe("usageAgg.sumTotals", () => {
  it("空数组返回全 0（不是 undefined）", () => {
    expect(sumTotals([])).toEqual(emptyTotals());
  });

  it("逐列求和", () => {
    const totals = sumTotals([
      daily({ requests: 2, promptTokens: 100, completionTokens: 50, totalTokens: 150 }),
      daily({ requests: 3, promptTokens: 200, completionTokens: 100, totalTokens: 300 }),
    ]);
    expect(totals).toEqual({
      requests: 5,
      promptTokens: 300,
      completionTokens: 150,
      totalTokens: 450,
    });
  });
});

describe("usageAgg.groupBySite", () => {
  it("按站点汇总，totalTokens 降序；同值按 siteId 升序", () => {
    const rows = groupBySite([
      daily({ siteId: 2, totalTokens: 100, requests: 1 }),
      daily({ siteId: 1, totalTokens: 15, requests: 1 }),
      daily({ siteId: 1, totalTokens: 30, requests: 2 }),
      daily({ siteId: 3, totalTokens: 100, requests: 1 }),
    ]);
    expect(rows.map((row) => row.siteId)).toEqual([2, 3, 1]);
    const site1 = rows.find((row) => row.siteId === 1)!;
    expect(site1.totalTokens).toBe(45);
    expect(site1.requests).toBe(3);
  });
});

describe("usageAgg.groupByModel", () => {
  it("空模型名是独立分组，且排序确定", () => {
    const rows = groupByModel([
      daily({ model: "", totalTokens: 5 }),
      daily({ model: "gpt-4", totalTokens: 100 }),
      daily({ model: "gpt-4", totalTokens: 50 }),
    ]);
    expect(rows.map((row) => row.model)).toEqual(["gpt-4", ""]);
    expect(rows[0].totalTokens).toBe(150);
    expect(rows[1].totalTokens).toBe(5);
  });
});

describe("usageAgg.groupByDay", () => {
  it("按日期升序（字符串序即日期序）", () => {
    const rows = groupByDay([
      daily({ date: "2026-10-21", totalTokens: 5 }),
      daily({ date: "2026-10-19", totalTokens: 1 }),
      daily({ date: "2026-10-20", totalTokens: 2 }),
    ]);
    expect(rows.map((row) => row.date)).toEqual([
      "2026-10-19",
      "2026-10-20",
      "2026-10-21",
    ]);
    expect(rows.map((row) => row.totalTokens)).toEqual([1, 2, 5]);
  });
});

describe("usageAgg.stackByDayAndSite", () => {
  it("日期与站点都升序，缺日补 0（不是缺项）", () => {
    const { dates, series } = stackByDayAndSite([
      daily({ date: "2026-10-21", siteId: 2, totalTokens: 7 }),
      daily({ date: "2026-10-20", siteId: 1, totalTokens: 3 }),
      daily({ date: "2026-10-21", siteId: 1, totalTokens: 4 }),
    ]);
    expect(dates).toEqual(["2026-10-20", "2026-10-21"]);
    expect(series).toHaveLength(2);
    const site1 = series.find((item) => item.siteId === 1)!;
    const site2 = series.find((item) => item.siteId === 2)!;
    expect(site1.values).toEqual([3, 4]);
    expect(site2.values).toEqual([0, 7]);
  });
});

describe("usageAgg.snapshotsByCurrency", () => {
  it("不同币种分组，组内按站点、日期升序", () => {
    const groups = snapshotsByCurrency([
      snapshot({ currency: "USD", siteId: 2, date: "2026-10-21" }),
      snapshot({ currency: "USD", siteId: 1, date: "2026-10-21", remaining: 8 }),
      snapshot({ currency: "CNY", siteId: 3, date: "2026-10-20", remaining: 30 }),
      snapshot({ currency: "USD", siteId: 1, date: "2026-10-20", remaining: 9 }),
    ]);
    expect(groups.map((group) => group.currency)).toEqual(["CNY", "USD"]);
    const usd = groups.find((group) => group.currency === "USD")!;
    expect(usd.series.map((item) => item.siteId)).toEqual([1, 2]);
    const site1 = usd.series.find((item) => item.siteId === 1)!;
    expect(site1.points).toEqual([
      { date: "2026-10-20", remaining: 9 },
      { date: "2026-10-21", remaining: 8 },
    ]);
  });

  it("同一（币种, 站点, 日）出现多行时后者覆盖前者（防御性）", () => {
    const groups = snapshotsByCurrency([
      snapshot({ currency: "USD", siteId: 1, date: "2026-10-21", remaining: 1 }),
      snapshot({ currency: "USD", siteId: 1, date: "2026-10-21", remaining: 2 }),
    ]);
    expect(groups[0].series[0].points).toEqual([
      { date: "2026-10-21", remaining: 2 },
    ]);
  });
});

describe("usageAgg.unionDates", () => {
  it("并集去重且升序", () => {
    expect(
      unionDates([
        { points: [{ date: "2026-10-21" }, { date: "2026-10-19" }] },
        { points: [{ date: "2026-10-20" }, { date: "2026-10-21" }] },
      ]),
    ).toEqual(["2026-10-19", "2026-10-20", "2026-10-21"]);
  });
});

describe("usageAgg.formatTokens", () => {
  it("不足 1000 原样，K/M 保留一位小数", () => {
    expect(formatTokens(0)).toBe("0");
    expect(formatTokens(999)).toBe("999");
    expect(formatTokens(1_500)).toBe("1.5K");
    expect(formatTokens(2_000_000)).toBe("2.0M");
  });

  it("非有限数返回占位符（不渲染 NaN）", () => {
    expect(formatTokens(Number.NaN)).toBe("—");
  });
});

describe("usageAgg.formatShare", () => {
  it("正常占比保留一位小数", () => {
    expect(formatShare(25, 100)).toBe("25.0%");
  });

  it("总数为 0 时返回占位符，不当成 0%", () => {
    expect(formatShare(0, 0)).toBe("—");
    expect(formatShare(1, 0)).toBe("—");
  });
});
