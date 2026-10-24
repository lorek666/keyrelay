import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import BudgetsCard from "../components/BudgetsCard";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M46-S5：硬预算卡（成本中心）。
 * - 列表渲染：站点名 / 密钥名 / 周期 / 上限 / 当期已花；
 * - 非法上限（0 / 负数）时保存按钮禁用、不调创建；
 * - 删除调删除回调；合法新增调创建回调（key 为空 = 全站合计 null）。
 */
vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    listSites: vi.fn(),
    listStoredKeys: vi.fn(),
    siteBudgetList: vi.fn(),
    siteBudgetCreate: vi.fn(),
    siteBudgetDelete: vi.fn(),
  };
});

import {
  listSites,
  listStoredKeys,
  siteBudgetCreate,
  siteBudgetDelete,
  siteBudgetList,
} from "../lib/api";

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
    { id: 1, displayName: "Alpha" } as never,
  ]);
  vi.mocked(listStoredKeys).mockResolvedValue([
    { id: 7, siteId: 1, name: "k1" } as never,
  ]);
  vi.mocked(siteBudgetList).mockResolvedValue([
    {
      id: 3, siteId: 1, keyId: 7, period: "day",
      limitUsd: 10, createdAt: 0, spentUsd: 4,
    },
  ]);
  vi.mocked(siteBudgetCreate).mockResolvedValue({
    id: 4, siteId: 1, keyId: null, period: "month",
    limitUsd: 20, createdAt: 0, spentUsd: 0,
  });
  vi.mocked(siteBudgetDelete).mockResolvedValue(true);
});

describe("BudgetsCard", () => {
  it("renders the budget list with site, key, period, limit and spent", async () => {
    render(<BudgetsCard />, { wrapper });
    // 站点名同时出现在下拉选项与表格行里，故在表格内断言。
    await waitFor(() => expect(screen.getByText("10 USD")).toBeTruthy());
    const table = screen.getByRole("table");
    expect(within(table).getByText("Alpha")).toBeTruthy();
    expect(within(table).getByText("k1")).toBeTruthy();
    expect(within(table).getByText("按日")).toBeTruthy();
    expect(within(table).getByText("4 USD")).toBeTruthy();
  });

  it("does not call create when the limit is zero or negative", async () => {
    render(<BudgetsCard />, { wrapper });
    await waitFor(() => expect(screen.getByText("10 USD")).toBeTruthy());
    fireEvent.change(screen.getByLabelText("站点"), { target: { value: "1" } });
    fireEvent.change(screen.getByPlaceholderText("上限（USD）"), { target: { value: "0" } });
    const save = screen.getByText("保存");
    expect((save as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(save);
    expect(siteBudgetCreate).not.toHaveBeenCalled();
    fireEvent.change(screen.getByPlaceholderText("上限（USD）"), { target: { value: "-5" } });
    expect((save as HTMLButtonElement).disabled).toBe(true);
  });

  it("creates a site-level budget and deletes a row", async () => {
    render(<BudgetsCard />, { wrapper });
    await waitFor(() => expect(screen.getByText("10 USD")).toBeTruthy());
    fireEvent.change(screen.getByLabelText("站点"), { target: { value: "1" } });
    fireEvent.change(screen.getByLabelText("周期"), { target: { value: "month" } });
    fireEvent.change(screen.getByPlaceholderText("上限（USD）"), { target: { value: "20" } });
    fireEvent.click(screen.getByText("保存"));
    await waitFor(() =>
      expect(siteBudgetCreate).toHaveBeenCalledWith({
        siteId: 1, keyId: null, period: "month", limitUsd: 20,
      }),
    );
    fireEvent.click(screen.getByText("删除"));
    await waitFor(() => expect(siteBudgetDelete).toHaveBeenCalledWith(3));
  });
});
