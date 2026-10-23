import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import Sites from "../pages/Sites";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M38-S1：站点会话持久化徽标与「退出登录」。
 *
 * 钉死四件事：
 * ① `sessionPersisted===true` ⇒ 显示「已保存会话 · 重启免登」+「退出登录」；
 * ② `sessionPersisted!==true`（含缺省/false）⇒ 两者都不显示；
 * ③ 点退出 → 确认 ⇒ `logoutSite` **只调一次**，成功后重新拉取站点列表；
 * ④ 退出接口 reject ⇒ 显示错误，行内按钮恢复可用（不卡在 pending）。
 */

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    listSites: vi.fn(),
    logoutSite: vi.fn(),
    siteBalance: vi.fn(),
  };
});

import { listSites, logoutSite, siteBalance, type SiteRow } from "../lib/api";

const caps = (over: Partial<SiteRow["capabilities"]> = {}): SiteRow["capabilities"] => ({
  login: true,
  listKeys: true,
  createKey: true,
  revealKey: true,
  revokeKey: true,
  balance: true,
  groups: true,
  keyUsage: true,
  webviewCaptchaSupported: true,
  webviewBearerSupported: false,
  ...over,
});

const PERSISTED: SiteRow = {
  id: 1,
  kind: "newapi",
  baseUrl: "https://saved.example.test",
  displayName: "已保存站",
  health: "ok",
  loginField: "username",
  capabilities: caps(),
  sessionPersisted: true,
  sessionExpiresAt: 9_999_999_999,
};

const NOT_PERSISTED: SiteRow = {
  id: 2,
  kind: "newapi",
  baseUrl: "https://fresh.example.test",
  displayName: "未保存站",
  health: "unknown",
  loginField: "username",
  capabilities: caps(),
  sessionPersisted: false,
};

beforeEach(() => {
  vi.clearAllMocks();
});

function renderSites(sites: SiteRow[]) {
  vi.mocked(listSites).mockResolvedValue(sites);
  vi.mocked(siteBalance).mockResolvedValue({
    currency: "USD",
    known: true,
    remaining: 10,
    used: 2,
  });
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity, gcTime: Infinity } },
  });
  qc.setQueryData(["sites"], sites);
  render(<Sites />, {
    wrapper: ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={qc}>
        <I18nProvider lang="zh-CN" initialDict={zhCN}>
          {children}
        </I18nProvider>
      </QueryClientProvider>
    ),
  });
  return qc;
}

const rowOf = (name: string) => screen.getByText(name).closest("tr") as HTMLTableRowElement;

describe("Sites 会话持久化徽标与退出登录（M38-S1）", () => {
  it("① sessionPersisted=true ⇒ 徽标 + 退出登录；false ⇒ 两者都不显示", async () => {
    renderSites([PERSISTED, NOT_PERSISTED]);

    const saved = rowOf("已保存站");
    expect(within(saved).getByText(zhCN.sites.session.persisted)).toBeTruthy();
    expect(
      within(saved).getByRole("button", { name: zhCN.sites.btn.logout }),
    ).toBeTruthy();

    const fresh = rowOf("未保存站");
    expect(within(fresh).queryByText(zhCN.sites.session.persisted)).toBeNull();
    expect(within(fresh).queryByRole("button", { name: zhCN.sites.btn.logout })).toBeNull();
    // 普通「登录」按钮仍在（不受影响）
    expect(within(fresh).getByRole("button", { name: zhCN.sites.btn.login })).toBeTruthy();
  });

  it("② 点退出 → 确认 ⇒ logoutSite 只调一次，成功后重新拉取站点列表", async () => {
    renderSites([PERSISTED]);

    // 初始数据来自 `setQueryData`（staleTime=Infinity）⇒ 挂载时不会调用 listSites；
    // 记下基线，断言「退出成功后确实发生了一次真实 refetch」。
    const before = vi.mocked(listSites).mock.calls.length;
    fireEvent.click(
      within(rowOf("已保存站")).getByRole("button", { name: zhCN.sites.btn.logout }),
    );
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(zhCN.sites.logout.body)).toBeTruthy();

    fireEvent.click(within(dialog).getByRole("button", { name: zhCN.sites.logout.confirm }));

    await waitFor(() => expect(logoutSite).toHaveBeenCalledTimes(1));
    expect(logoutSite).toHaveBeenCalledWith(PERSISTED.id);
    // 成功后失效 `sites` ⇒ 触发一次真实 refetch（调用数必须比基线多）
    await waitFor(() =>
      expect(vi.mocked(listSites).mock.calls.length).toBeGreaterThan(before),
    );
  });

  it("③ 取消确认不发请求", async () => {
    renderSites([PERSISTED]);

    fireEvent.click(
      within(rowOf("已保存站")).getByRole("button", { name: zhCN.sites.btn.logout }),
    );
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: zhCN.common.cancel }));

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(logoutSite).not.toHaveBeenCalled();
  });

  it("④ 退出接口 reject ⇒ 显示错误，行内按钮恢复可用", async () => {
    vi.mocked(logoutSite).mockRejectedValueOnce(new Error("删除本地会话失败（示例）"));
    renderSites([PERSISTED]);

    fireEvent.click(
      within(rowOf("已保存站")).getByRole("button", { name: zhCN.sites.btn.logout }),
    );
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: zhCN.sites.logout.confirm }));

    await waitFor(() => {
      expect(screen.getByRole("alert").textContent).toContain("删除本地会话失败（示例）");
    });
    // 确认框已关闭；行内「退出登录」仍可点（不卡 pending）
    expect(screen.queryByRole("dialog")).toBeNull();
    const button = within(rowOf("已保存站")).getByRole("button", {
      name: zhCN.sites.btn.logout,
    }) as HTMLButtonElement;
    expect(button.disabled).toBe(false);
  });
});
