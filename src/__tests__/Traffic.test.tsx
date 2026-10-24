import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import Traffic from "../pages/Traffic";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M45-S2：流量中心的渲染判据（口径必须与 Usage.tsx / GatewayMetricsPanel 一致）。
 * 重点是四件会静默错的事：
 * 1. QPS 空态：未运行只显示占位、绝不渲染假数字；刚启动（requestsTotal < 3）QPS 显示 `—`；
 * 2. 汇总卡加载中/出错显示 `—` 而不是 0；
 * 3. 按密钥表能力位门控：无能力站点的密钥行不得出现；
 * 4. 站点表「可观测」列：无能力站点标「不提供」，不是空白。
 */
vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    listSites: vi.fn(),
    usageDashboard: vi.fn(),
    gatewayStatus: vi.fn(),
  };
});

import {
  gatewayStatus,
  listSites,
  usageDashboard,
  type GatewayStatus,
  type SiteRow,
  type UsageDashboard,
} from "../lib/api";

const caps = (keyUsage: boolean): SiteRow["capabilities"] => ({
  login: true,
  listKeys: true,
  createKey: true,
  revealKey: true,
  revokeKey: true,
  balance: true,
  groups: true,
  keyUsage,
  webviewCaptchaSupported: false,
  webviewBearerSupported: false,
});

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={client}>
      <I18nProvider lang="zh-CN" initialDict={zhCN as unknown as Record<string, unknown>}>
        {children}
      </I18nProvider>
    </QueryClientProvider>
  );
}

const dashboardFixture = (): UsageDashboard => ({
  rangeDays: 30,
  siteId: null,
  daily: [
    {
      date: "2026-10-20", siteId: 1, model: "m1", requests: 10,
      promptTokens: 100, completionTokens: 50, totalTokens: 150,
      currency: "USD", estimatedCost: 1, unpricedRequests: 0, unpricedTokens: 0,
    },
    {
      date: "2026-10-20", siteId: 2, model: "m1", requests: 5,
      promptTokens: 30, completionTokens: 20, totalTokens: 50,
      currency: "USD", estimatedCost: 1, unpricedRequests: 0, unpricedTokens: 0,
    },
  ],
  snapshots: [
    { date: "2026-10-19", siteId: 1, used: 1, remaining: 9, currency: "USD", samples: 1 },
    { date: "2026-10-20", siteId: 1, used: 2, remaining: 8, currency: "USD", samples: 1 },
  ],
  keyUsage: [
    {
      keyId: 11, siteId: 1, keyName: "alpha-key", requests: 10,
      inputTokens: 100, outputTokens: 50, totalTokens: 150, cost: null, currency: null,
    },
    {
      keyId: 22, siteId: 2, keyName: "beta-key", requests: 5,
      inputTokens: 30, outputTokens: 20, totalTokens: 50, cost: null, currency: null,
    },
  ],
  byAgent: [],
});

const gatewayFixture = (over: Partial<GatewayStatus>): GatewayStatus => ({
  running: true,
  phase: "running",
  tokenPersistent: true,
  mode: "single",
  candidates: [
    { siteId: 1, displayName: "Alpha", keyId: 11, health: "healthy", breaker: "closed" },
  ],
  qps: 12.5,
  requestsTotal: 100,
  inflight: 2,
  failoversTotal: 1,
  lastError: null,
  generation: 7,
  ...over,
});

beforeEach(() => {
  vi.mocked(listSites).mockResolvedValue([
    {
      id: 1, kind: "newapi", baseUrl: "https://alpha.example.test", displayName: "Alpha",
      health: "ok", loginField: "username", capabilities: caps(true),
    },
    {
      id: 2, kind: "sub2api", baseUrl: "https://beta.example.test", displayName: "Beta",
      health: "ok", loginField: "email", capabilities: caps(false),
    },
  ] satisfies SiteRow[]);
  vi.mocked(usageDashboard).mockResolvedValue(dashboardFixture());
  vi.mocked(gatewayStatus).mockResolvedValue(gatewayFixture({}));
});

describe("Traffic", () => {
  it("汇总卡与站点表数值与用量口径一致", async () => {
    render(<Traffic />, { wrapper });
    await waitFor(() => {
      // Token 200（150 + 50）、请求 15、站点 2、模型 1
      expect(screen.getByText("Token 总量").closest(".hm-card")).toHaveTextContent("200");
      expect(screen.getByText("请求数").closest(".hm-card")).toHaveTextContent("15");
      expect(screen.getByText("活跃站点").closest(".hm-card")).toHaveTextContent("2");
      expect(screen.getByText("活跃模型").closest(".hm-card")).toHaveTextContent("1");
    });
  });

  it("网关运行时 QPS 与候选表正常渲染", async () => {
    render(<Traffic />, { wrapper });
    await waitFor(() => {
      expect(document.querySelector("[data-gateway-qps]")).toHaveTextContent("12.5");
    });
    // 候选表行：以 QPS 面板卡片为作用域，徽章（表头同名文本不算）应为健康/正常
    const qpsCard = document
      .querySelector("[data-gateway-qps]")
      ?.closest(".hm-card") as HTMLElement;
    const badges = qpsCard.querySelectorAll("span.badge");
    expect(badges).toHaveLength(2);
    expect(badges[0]).toHaveTextContent("健康");
    expect(badges[1]).toHaveTextContent("正常");
  });

  it("网关刚启动（requestsTotal < 3）时 QPS 显示 —", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(gatewayFixture({ requestsTotal: 2, qps: 0 }));
    render(<Traffic />, { wrapper });
    await waitFor(() => {
      expect(document.querySelector("[data-gateway-qps]")).toHaveTextContent("—");
    });
  });

  it("网关未运行时只显示占位，不渲染假数字与候选表", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(
      gatewayFixture({ running: false, phase: "stopped", mode: "stopped", candidates: [] }),
    );
    render(<Traffic />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("网关未运行，暂无指标。")).toBeTruthy();
    });
    expect(document.querySelector("[data-gateway-qps]")).toBeNull();
  });

  it("按密钥表只显示有能力站点的密钥行", async () => {
    render(<Traffic />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("alpha-key")).toBeTruthy();
    });
    expect(screen.queryByText("beta-key")).toBeNull();
  });

  it("站点表无能力站点标「不提供」", async () => {
    render(<Traffic />, { wrapper });
    await waitFor(() => {
      // 以「站点汇总」卡片为作用域，避免命中站点筛选 <option> 里的同名文本
      const sitesCard = screen.getByText("站点汇总").closest(".hm-card");
      const betaRow = within(sitesCard as HTMLElement).getByText("Beta").closest("tr");
      expect(betaRow).toHaveTextContent("不提供");
    });
  });

  // ---- M45-S8（B-228/B-229）：此前缺失的分支断言 ----

  it("B-228：仪表盘加载中时汇总卡显示 — 而不是 0", async () => {
    vi.mocked(usageDashboard).mockImplementation(() => new Promise(() => {}));
    render(<Traffic />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("Token 总量").closest(".hm-card")).toHaveTextContent("—");
    });
  });

  it("B-228/B-229：仪表盘出错时红行带真实原因", async () => {
    vi.mocked(usageDashboard).mockRejectedValue(new Error("boom"));
    render(<Traffic />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("读取用量失败：boom")).toBeTruthy();
    });
    // S8 复审 P2-1：error 输入的汇总卡 — 也要有直接断言，不能只靠红行
    expect(screen.getByText("Token 总量").closest(".hm-card")).toHaveTextContent("—");
  });

  it("B-229：所选范围无用量时显示空态文案", async () => {
    vi.mocked(usageDashboard).mockResolvedValue({
      rangeDays: 30,
      siteId: null,
      daily: [],
      snapshots: [],
      keyUsage: [],
      byAgent: [],
    });
    render(<Traffic />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText(/所选范围内还没有用量数据/)).toBeTruthy();
    });
  });

  it("B-229：全部站点都无能力时按密钥表显示 noCapability 文案", async () => {
    vi.mocked(listSites).mockResolvedValue([
      {
        id: 2, kind: "sub2api", baseUrl: "https://beta.example.test", displayName: "Beta",
        health: "ok", loginField: "email", capabilities: caps(false),
      },
    ] satisfies SiteRow[]);
    render(<Traffic />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("所有站点都不提供每密钥用量（能力位 keyUsage = false）。")).toBeTruthy();
    });
  });

  it("B-229：按密钥表成本为 null 时显示未定价而非 0", async () => {
    vi.mocked(usageDashboard).mockResolvedValue({
      ...dashboardFixture(),
      keyUsage: [
        {
          keyId: 11, siteId: 1, keyName: "alpha-key", requests: 10,
          inputTokens: 100, outputTokens: 50, totalTokens: 150, cost: null, currency: null,
        },
      ],
    });
    render(<Traffic />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("alpha-key")).toBeTruthy();
    });
    const keyRow = screen.getByText("alpha-key").closest("tr");
    expect(keyRow).toHaveTextContent("未知（未定价）");
    expect(keyRow).not.toHaveTextContent("0.00");
  });
});
