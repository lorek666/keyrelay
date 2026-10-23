import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import Usage from "../pages/Usage";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M43-S2：成本卡片与「未知 ≠ 0」的渲染判据。
 *
 * 这条用例存在的理由：`estimatedCost: null` 与 `0` 在 JSON 里长得像，
 * 但界面上必须是「未知（未定价）」而不是 `0.0000`（spec §4.6 红线）。
 */

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    listSites: vi.fn(async () => []),
    usageDashboard: vi.fn(),
    siteBills: vi.fn(async () => []),
  };
});

import { usageDashboard, type UsageDashboard } from "../lib/api";

const dashboard = (daily: UsageDashboard["daily"]): UsageDashboard => ({
  rangeDays: 30,
  siteId: null,
  daily,
  snapshots: [],
  keyUsage: [],
  byAgent: [],
});

function wrap(children: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <I18nProvider
        initialLocale="zh-CN"
        // 测试里直接用中文包（与 UsagePage.test 同口径）
        dict={zhCN as never}
      >
        {children}
      </I18nProvider>
    </QueryClientProvider>
  );
}

describe("M43-S2 成本卡片", () => {
  beforeEach(() => {
    vi.mocked(usageDashboard).mockReset();
  });

  it("有价 + 部分未定价：显示估算金额与「另有 N 条未定价」", async () => {
    vi.mocked(usageDashboard).mockResolvedValue(
      dashboard([
        {
          date: "2026-10-23",
          siteId: 1,
          model: "gpt-4o",
          requests: 3,
          promptTokens: 100,
          completionTokens: 50,
          totalTokens: 150,
          currency: "USD",
          estimatedCost: 1.5,
          unpricedRequests: 1,
          unpricedTokens: 20,
        },
      ]),
    );
    render(wrap(<Usage />));
    expect(await screen.findByText("1.5 USD")).toBeInTheDocument();
    expect(screen.getByText("另有 1 条未定价")).toBeInTheDocument();
  });

  it("无价格：显示「未知（未定价）」，绝不显示 0", async () => {
    vi.mocked(usageDashboard).mockResolvedValue(
      dashboard([
        {
          date: "2026-10-23",
          siteId: 1,
          model: "o3",
          requests: 2,
          promptTokens: 10,
          completionTokens: 5,
          totalTokens: 15,
          currency: null,
          estimatedCost: null,
          unpricedRequests: 2,
          unpricedTokens: 15,
        },
      ]),
    );
    render(wrap(<Usage />));
    expect(await screen.findByText("未知（未定价）")).toBeInTheDocument();
    expect(screen.queryByText("0 USD")).toBeNull();
    expect(screen.getByText("2 条全部未定价")).toBeInTheDocument();
  });
});
