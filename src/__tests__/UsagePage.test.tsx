import { describe, expect, it, vi, afterEach, beforeEach } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import Usage from "../pages/Usage";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M34-S1：用量页的渲染判据。
 *
 * 重点不在「画得好不好看」，而在三件会静默错的事：
 * 1. 汇总数字是否等于 daily 行之和；
 * 2. `SiteCapabilities.keyUsage` 是否真的按**每行所属站点**门控（不是只看当前选中站点）；
 * 3. 空数据 / 空能力位时是否给出可读的空态而不是白屏。
 */

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    listSites: vi.fn(),
    usageDashboard: vi.fn(),
  };
});

import {
  listSites,
  usageDashboard,
  type SiteRow,
  type UsageDashboard,
} from "../lib/api";

const caps = (over: Partial<SiteRow["capabilities"]>): SiteRow["capabilities"] => ({
  login: true,
  listKeys: true,
  createKey: true,
  revealKey: true,
  revokeKey: true,
  balance: true,
  groups: true,
  keyUsage: true,
  webviewCaptchaSupported: false,
  webviewBearerSupported: false,
  ...over,
});

const SITE_A: SiteRow = {
  id: 1,
  kind: "newapi",
  baseUrl: "https://alpha.example.test",
  displayName: "Alpha",
  health: "ok",
  loginField: "username",
  capabilities: caps({}),
};

const SITE_B: SiteRow = {
  id: 2,
  kind: "sub2api",
  baseUrl: "https://beta.example.test",
  displayName: "Beta",
  health: "ok",
  loginField: "email",
  capabilities: caps({}),
};

/** 无密钥管理能力（`keyUsage=false`）：按密钥表必须把它挡在外面。 */
const SITE_C: SiteRow = {
  id: 3,
  kind: "custom-openai-compatible",
  baseUrl: "https://gamma.example.test",
  displayName: "Gamma",
  health: "ok",
  loginField: null,
  capabilities: caps({
    login: false,
    listKeys: false,
    createKey: false,
    revealKey: false,
    revokeKey: false,
    balance: false,
    groups: false,
    keyUsage: false,
  }),
};

const DASHBOARD: UsageDashboard = {
  rangeDays: 30,
  siteId: null,
  daily: [
    {
      date: "2026-10-20",
      siteId: 1,
      model: "gpt-4o-mini",
      requests: 2,
      promptTokens: 100,
      completionTokens: 50,
      totalTokens: 150,
    },
    {
      date: "2026-10-21",
      siteId: 1,
      model: "gpt-4o-mini",
      requests: 3,
      promptTokens: 200,
      completionTokens: 100,
      totalTokens: 300,
    },
    {
      date: "2026-10-21",
      siteId: 3,
      model: "",
      requests: 1,
      promptTokens: 10,
      completionTokens: 5,
      totalTokens: 15,
    },
  ],
  snapshots: [
    {
      date: "2026-10-20",
      siteId: 1,
      used: 1,
      remaining: 9,
      currency: "USD",
      samples: 1,
    },
    {
      date: "2026-10-21",
      siteId: 1,
      used: 2,
      remaining: 8,
      currency: "USD",
      samples: 2,
    },
    {
      date: "2026-10-21",
      siteId: 2,
      used: 3,
      remaining: 27,
      currency: "CNY",
      samples: 1,
    },
  ],
  keyUsage: [
    {
      keyId: 11,
      siteId: 1,
      keyName: "key-alpha",
      requests: 5,
      inputTokens: 300,
      outputTokens: 150,
      totalTokens: 450,
      cost: 0.12,
      currency: "USD",
    },
    // 能力位 false 的站点即使后端返回了行，界面也必须挡掉（门控在界面层）。
    {
      keyId: 13,
      siteId: 3,
      keyName: "key-gamma",
      requests: 1,
      inputTokens: 10,
      outputTokens: 5,
      totalTokens: 15,
      cost: 0.01,
      currency: null,
    },
  ],
};

function renderUsage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity, gcTime: Infinity } },
  });
  return render(<Usage />, {
    wrapper: ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={qc}>
        <I18nProvider lang="zh-CN" initialDict={zhCN}>
          {children}
        </I18nProvider>
      </QueryClientProvider>
    ),
  });
}

describe("Usage 页（M34-S1）", () => {
  beforeEach(() => {
    vi.mocked(listSites).mockResolvedValue([SITE_A, SITE_B, SITE_C]);
    vi.mocked(usageDashboard).mockResolvedValue(DASHBOARD);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("有数据：汇总、站点/模型/币种与按密钥表（keyUsage 门控）", async () => {
    renderUsage();

    // 汇总卡：450 + 15 = 465 tokens（不是 450——Gamma 的流量也要计入总量）
    expect(await screen.findByText("465")).toBeTruthy();
    expect(screen.getByText(zhCN.usage.cards.tokens)).toBeTruthy();
    expect(screen.getByText(zhCN.usage.cards.requests)).toBeTruthy();

    // 站点汇总表：三个站点都有网关流量
    expect(screen.getAllByText("Alpha").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Beta").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Gamma").length).toBeGreaterThan(0);

    // 模型分布（空模型名显示「未知模型」）
    expect(screen.getByText("gpt-4o-mini")).toBeTruthy();
    expect(screen.getByText(zhCN.usage.unknownModel)).toBeTruthy();

    // 余额按币种分图：USD 与 CNY 不混算
    expect(screen.getByText("USD 余额")).toBeTruthy();
    expect(screen.getByText("CNY 余额")).toBeTruthy();

    // 按密钥：Alpha 的行在；Gamma（keyUsage=false）的行被挡掉
    expect(screen.getByText("key-alpha")).toBeTruthy();
    expect(screen.queryByText("key-gamma")).toBeNull();
    // 且明确告知哪些站点不提供
    expect(
      screen.getByText(zhCN.usage.keys.partial.replace("{sites}", "Gamma")),
    ).toBeTruthy();
  });

  it("全部站点 keyUsage=false：不渲染按密钥表，给出「不提供」说明", async () => {
    vi.mocked(listSites).mockResolvedValue([SITE_C]);
    renderUsage();

    expect(await screen.findByText(zhCN.usage.keys.noCapability)).toBeTruthy();
    expect(screen.queryByText("key-alpha")).toBeNull();
    expect(screen.queryByText("key-gamma")).toBeNull();
  });

  it("空数据：显示空态文案，不白屏也不报错", async () => {
    vi.mocked(usageDashboard).mockResolvedValue({
      rangeDays: 30,
      siteId: null,
      daily: [],
      snapshots: [],
      keyUsage: [],
    });
    renderUsage();

    expect(await screen.findByText(zhCN.usage.empty)).toBeTruthy();
    // Token 趋势 / 站点汇总 / 模型分布三张卡共用同一句空态文案
    expect(
      screen.getAllByText(zhCN.usage.trend.empty).length,
    ).toBeGreaterThan(0);
    expect(screen.getByText(zhCN.usage.balance.empty)).toBeTruthy();
  });

  it("切换范围 / 站点筛选会重新请求，参数与选择一致", async () => {
    renderUsage();
    await screen.findByText("465");

    await act(async () => {
      fireEvent.click(
        screen.getByRole("button", { name: zhCN.usage.range.d90 }),
      );
    });
    await waitFor(() =>
      expect(vi.mocked(usageDashboard)).toHaveBeenLastCalledWith(90, null),
    );

    await act(async () => {
      fireEvent.change(screen.getByLabelText(zhCN.usage.siteFilter), {
        target: { value: "2" },
      });
    });
    await waitFor(() =>
      expect(vi.mocked(usageDashboard)).toHaveBeenLastCalledWith(90, 2),
    );
  });
});
