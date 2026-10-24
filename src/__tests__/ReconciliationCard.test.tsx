import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import ReconciliationCard from "../components/ReconciliationCard";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M46-UI B-251：成本中心对账卡。
 * - 列表渲染：日期 / 站点 / 网关成本 / 站点账单 / 差异 / 存在分区 / 标记；
 * - B-253：不可比行（diffUsd === null）单独立组，不挂「超阈值」标记，
 *   「仅看超阈值」筛选只作用于可比表；
 * - 窗口切换重新请求；空态文案。
 */
vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    listSites: vi.fn(),
    billReconciliation: vi.fn(),
  };
});

import { listSites, billReconciliation } from "../lib/api";

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

const rows = () => [
  {
    siteId: 1, day: "2026-10-24", gatewayUsd: 10, billUsd: 10, diffUsd: 0,
    flagged: false, kind: "matched", source: "newapi-log-self",
  },
  {
    siteId: 1, day: "2026-10-23", gatewayUsd: 10, billUsd: 20, diffUsd: -10,
    flagged: true, kind: "matched", source: "newapi-log-self",
  },
  {
    siteId: 1, day: "2026-10-22", gatewayUsd: 5, billUsd: null, diffUsd: null,
    flagged: true, kind: "matched", source: "newapi-log-self",
  },
];

beforeEach(() => {
  vi.mocked(listSites).mockResolvedValue([
    { id: 1, displayName: "Alpha" } as never,
  ]);
  vi.mocked(billReconciliation).mockResolvedValue(rows() as never);
});

describe("ReconciliationCard（M46-UI B-251）", () => {
  it("列表渲染 + 覆盖度文案 + 超阈值标记", async () => {
    render(<ReconciliationCard />, { wrapper });
    expect(await screen.findByText("账单对账（网关成本 vs 站点账单）")).toBeInTheDocument();
    expect(screen.getByText(/目前账单来源基本只有 NewAPI 系导入/)).toBeInTheDocument();
    // 行来自 react-query 异步查询，必须等首行出现再断言其余行。
    expect(await screen.findByText("2026-10-24")).toBeInTheDocument();
    expect(screen.getByText("2026-10-23")).toBeInTheDocument();
    expect(screen.getByText("超阈值")).toBeInTheDocument();
    // 未超阈值的可比行不挂标记（其行内标记格为 —）。
    const okRow = screen.getByText("2026-10-24").closest("tr") as HTMLElement;
    expect(within(okRow).getByText("—")).toBeInTheDocument();
    expect(within(okRow).queryByText("超阈值")).toBeNull();
  });

  it("B-253：仅看超阈值隐藏未超阈值可比行，但不可比组仍独立可见且不挂标记", async () => {
    render(<ReconciliationCard />, { wrapper });
    await screen.findByText("2026-10-24");
    fireEvent.click(screen.getByLabelText("仅看超阈值"));
    await waitFor(() => {
      expect(screen.queryByText("2026-10-24")).toBeNull();
    });
    expect(screen.getByText("2026-10-23")).toBeInTheDocument();
    // 不可比行仍在独立组里，且行内不挂「超阈值」标记（IPC 里它 flagged=true）。
    expect(screen.getByText("不可比行")).toBeInTheDocument();
    expect(screen.getByText("2026-10-22")).toBeInTheDocument();
    const incRow = screen.getByText("2026-10-22").closest("tr") as HTMLElement;
    expect(within(incRow).queryByText("超阈值")).toBeNull();
    // 不可比行的账单与差异格显示 —，不是 0。
    const cells = within(incRow).getAllByText("—");
    expect(cells.length).toBeGreaterThanOrEqual(2);
  });

  it("窗口切换按新天数重新请求", async () => {
    render(<ReconciliationCard />, { wrapper });
    await screen.findByText("2026-10-24");
    expect(billReconciliation).toHaveBeenCalledWith(undefined, 30);
    fireEvent.change(screen.getByLabelText("窗口（天）"), { target: { value: "7" } });
    await waitFor(() => {
      expect(billReconciliation).toHaveBeenCalledWith(undefined, 7);
    });
  });

  it("空态文案", async () => {
    vi.mocked(billReconciliation).mockResolvedValue([]);
    render(<ReconciliationCard />, { wrapper });
    expect(await screen.findByText("该窗口内没有对账行。")).toBeInTheDocument();
  });
});
