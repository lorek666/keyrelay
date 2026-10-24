import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import Cost from "../pages/Cost";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M45-S3：成本中心的口径判据（与已删除的 Usage.tsx 逐项一致；UsagePage/UsageCost
 * 两个直接 import Usage 页的测试文件在本步一并删除，其成本断言迁移到此）。
 * 重点是三件会静默错的事：
 * 1. 跨币种永不合并、未知币种单独一桶；部分未定价只标注条数、不把「未知」写成 0；
 * 2. Agent 空标签显示「未归因（旧数据）」，未定价成本列显示「未知（未定价）」而非 0；
 * 3. 账单探测/导入按钮在未选站点时禁用（误点会调错站点）。
 */
vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    listSites: vi.fn(),
    usageDashboard: vi.fn(),
    siteBills: vi.fn(),
    siteBillProbe: vi.fn(),
    siteBillImport: vi.fn(),
    modelPriceList: vi.fn(),
    modelPriceUpsert: vi.fn(),
    modelPriceDelete: vi.fn(),
  };
});

import {
  listSites,
  modelPriceList,
  siteBillImport,
  siteBillProbe,
  siteBills,
  usageDashboard,
  type SiteRow,
  type UsageDashboard,
} from "../lib/api";

const caps = (): SiteRow["capabilities"] => ({
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

beforeEach(() => {
  vi.mocked(listSites).mockResolvedValue([
    {
      id: 1, kind: "newapi", baseUrl: "https://alpha.example.test", displayName: "Alpha",
      health: "ok", loginField: "username", capabilities: caps(),
    },
  ] satisfies SiteRow[]);
  vi.mocked(usageDashboard).mockResolvedValue({
    rangeDays: 30,
    siteId: null,
    daily: [
      {
        date: "2026-10-20", siteId: 1, model: "m1", requests: 10,
        promptTokens: 100, completionTokens: 50, totalTokens: 150,
        currency: "USD", estimatedCost: 2, unpricedRequests: 0, unpricedTokens: 0,
      },
      {
        date: "2026-10-20", siteId: 1, model: "m2", requests: 5,
        promptTokens: 30, completionTokens: 20, totalTokens: 50,
        currency: "USD", estimatedCost: 1, unpricedRequests: 3, unpricedTokens: 30,
      },
      {
        date: "2026-10-20", siteId: 1, model: "m3", requests: 4,
        promptTokens: 10, completionTokens: 10, totalTokens: 20,
        currency: null, estimatedCost: null, unpricedRequests: 4, unpricedTokens: 20,
      },
    ],
    snapshots: [],
    keyUsage: [],
    byAgent: [
      {
        agentLabel: "", currency: "USD", requests: 7, totalTokens: 700,
        estimatedCost: null, unpricedRequests: 7,
      },
      {
        agentLabel: "claude-code", currency: "USD", requests: 8, totalTokens: 800,
        estimatedCost: 1.5, unpricedRequests: 0,
      },
    ],
  } satisfies UsageDashboard);
  vi.mocked(siteBills).mockResolvedValue([
    {
      id: 1, day: "2026-10-20", siteId: 1, amount: 5, currency: "USD",
      requests: 100, source: "probe",
    },
  ]);
  vi.mocked(modelPriceList).mockResolvedValue([
    {
      id: 1, model: "m1", inputPerMtok: 1, outputPerMtok: 2,
      currency: "USD", effectiveFrom: 1760000000, createdAt: 0,
    },
  ]);
});

describe("Cost", () => {
  it("成本桶：USD 合并为 3 并标注 3 条未定价，未知币种单独一桶且全部未定价", async () => {
    render(<Cost />, { wrapper });
    await waitFor(() => {
      const usdCard = screen.getByText("估算成本（USD）").closest(".hm-card");
      expect(usdCard).toHaveTextContent("3 USD");
      expect(usdCard).toHaveTextContent("另有 3 条未定价");
      const unknownCard = screen.getByText("未知币种").closest(".hm-card");
      expect(unknownCard).toHaveTextContent("未知（未定价）");
      expect(unknownCard).toHaveTextContent("4 条全部未定价");
    });
  });

  it("Agent 表：空标签显示未归因，未定价成本不写成 0", async () => {
    render(<Cost />, { wrapper });
    await waitFor(() => {
      const agentsCard = screen.getByText("按 Agent 成本").closest(".hm-card");
      const unattributedRow = within(agentsCard as HTMLElement)
        .getByText("未归因（旧数据）")
        .closest("tr");
      expect(unattributedRow).toHaveTextContent("未知（未定价）");
      expect(unattributedRow).not.toHaveTextContent("0 USD");
      expect(within(agentsCard as HTMLElement).getByText("claude-code")).toBeTruthy();
    });
  });

  it("账单表渲染行，未选站点时探测/导入按钮禁用", async () => {
    render(<Cost />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("2026-10-20")).toBeTruthy();
    });
    expect(screen.getByText("probe")).toBeTruthy();
    expect(screen.getByRole("button", { name: "探测能力" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "只读导入" })).toBeDisabled();
  });

  it("单价表渲染行（由设置页原样搬出）", async () => {
    render(<Cost />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("m1")).toBeTruthy();
    });
  });

  // ---- M45-S8（B-230）：此前缺失的分支断言 ----

  function billsCard() {
    return screen.getByText("站点账单（站点自报）").closest(".hm-card") as HTMLElement;
  }

  async function selectBillSite(card: HTMLElement) {
    // 必须等站点查询返回、选项出现后再改值；否则 select 里没有 value="1" 的选项，
    // 改值会被忽略、探测按钮仍禁用（此前 3 个账单测试就是这么失败的，测试自身 bug）。
    await waitFor(() => {
      expect(within(card).getByRole("option", { name: "Alpha" })).toBeTruthy();
    });
    const selects = within(card).getAllByRole("combobox");
    fireEvent.change(selects[0], { target: { value: "1" } });
  }

  it("B-230：账单探测四态文案各不相同", async () => {
    const cases: Array<[string, string]> = [
      ["supported", "该站点支持账单导入。"],
      ["needsLogin", "需要先登录该站点。"],
      ["unsupported", "该站点不支持账单导入。"],
      ["failed", "探测失败：nope"],
    ];
    for (const [status, text] of cases) {
      vi.mocked(siteBillProbe).mockResolvedValue({
        status: status as "supported" | "needsLogin" | "unsupported" | "failed",
        currency: null,
        reason: status === "failed" ? "nope" : null,
      });
      const { unmount } = render(<Cost />, { wrapper });
      await waitFor(() => {
        expect(screen.getByText("站点账单（站点自报）")).toBeTruthy();
      });
      const card = billsCard();
      await selectBillSite(card);
      fireEvent.click(within(card).getByRole("button", { name: "探测能力" }));
      await waitFor(() => {
        expect(screen.getByText(text)).toBeTruthy();
      });
      unmount();
    }
  });

  it("B-230：导入 partial 时必须警告只导入了最近 N 页", async () => {
    vi.mocked(siteBillImport).mockResolvedValue({
      imported: 5, pages: 2, partial: true, currency: null, currencyOverrideUsed: false,
    });
    render(<Cost />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("站点账单（站点自报）")).toBeTruthy();
    });
    const card = billsCard();
    await selectBillSite(card);
    fireEvent.click(within(card).getByRole("button", { name: "只读导入" }));
    await waitFor(() => {
      expect(screen.getByText(/注意：只导入了最近 2 页/)).toBeTruthy();
    });
  });

  it("B-230：导入币种覆盖时标注所用币种", async () => {
    vi.mocked(siteBillImport).mockResolvedValue({
      imported: 5, pages: 1, partial: false, currency: "CNY", currencyOverrideUsed: true,
    });
    render(<Cost />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("站点账单（站点自报）")).toBeTruthy();
    });
    const card = billsCard();
    await selectBillSite(card);
    fireEvent.click(within(card).getByRole("button", { name: "只读导入" }));
    await waitFor(() => {
      expect(screen.getByText(/按你指定的 CNY 记录/)).toBeTruthy();
    });
  });

  it("B-230：仪表盘出错时红行带真实原因", async () => {
    vi.mocked(usageDashboard).mockRejectedValue(new Error("boom"));
    render(<Cost />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("读取用量失败：boom")).toBeTruthy();
    });
  });

  it("B-230：成本空态与账单空态", async () => {
    vi.mocked(usageDashboard).mockResolvedValue({
      rangeDays: 30,
      siteId: null,
      daily: [],
      snapshots: [],
      keyUsage: [],
      byAgent: [],
    });
    vi.mocked(siteBills).mockResolvedValue([]);
    render(<Cost />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText(/还没有可估算的用量/)).toBeTruthy();
      expect(screen.getByText("还没有导入过账单。")).toBeTruthy();
    });
  });

  it("B-230：成本为 null 的桶显示未定价而非 0", async () => {
    vi.mocked(usageDashboard).mockResolvedValue({
      rangeDays: 30,
      siteId: null,
      daily: [
        {
          date: "2026-10-20", siteId: 1, model: "m1", requests: 4,
          promptTokens: 10, completionTokens: 10, totalTokens: 20,
          currency: "USD", estimatedCost: null, unpricedRequests: 4, unpricedTokens: 20,
        },
      ],
      snapshots: [],
      keyUsage: [],
      byAgent: [],
    });
    render(<Cost />, { wrapper });
    await waitFor(() => {
      const bucket = screen.getByText("估算成本（USD）").closest(".hm-card");
      expect(bucket).toHaveTextContent("未知（未定价）");
      expect(bucket).toHaveTextContent("4 条全部未定价");
      expect(bucket).not.toHaveTextContent("0 USD");
    });
  });
});
