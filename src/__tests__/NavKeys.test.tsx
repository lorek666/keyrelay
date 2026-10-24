import { describe, expect, it } from "vitest";
import zhCN from "../i18n/zh-CN.json";
import enUS from "../i18n/en-US.json";

/**
 * M45-S8（B-232）：删除类验收的显式断言。
 * 导航块键集合必须恰为品牌/分组/七中心，不含已 retire 的 overview/usage/probe/sites/keys/agents/history；
 * `overview.*` 内容键必须完好（指挥舱复用 runState 与 stat），防止后续有人误删内容键或恢复旧总览入口。
 * 本测试不渲染组件：键集合是字典静态事实，直接断言字典即可。
 */
const EXPECTED_NAV_KEYS = [
  "brand",
  "group",
  "cockpit",
  "traffic",
  "cost",
  "health",
  "assets",
  "delivery",
  "settings",
];

const RETIRED_NAV_KEYS = ["overview", "usage", "probe", "sites", "keys", "agents", "history"];

describe("NavKeys", () => {
  it("中英导航块键集合一致且恰为七中心", () => {
    const zhNav = (zhCN as unknown as { nav: Record<string, unknown> }).nav;
    const enNav = (enUS as unknown as { nav: Record<string, unknown> }).nav;
    expect(Object.keys(zhNav).sort()).toEqual([...EXPECTED_NAV_KEYS].sort());
    expect(Object.keys(enNav).sort()).toEqual([...EXPECTED_NAV_KEYS].sort());
    for (const key of RETIRED_NAV_KEYS) {
      expect(zhNav).not.toHaveProperty(key);
      expect(enNav).not.toHaveProperty(key);
    }
  });

  it("overview.* 内容键完好（指挥舱仍在用）", () => {
    const zhOverview = (zhCN as unknown as { overview: Record<string, unknown> }).overview;
    const enOverview = (enUS as unknown as { overview: Record<string, unknown> }).overview;
    expect(zhOverview).toHaveProperty("runState");
    expect(zhOverview).toHaveProperty("stat");
    expect(enOverview).toHaveProperty("runState");
    expect(enOverview).toHaveProperty("stat");
  });
});
