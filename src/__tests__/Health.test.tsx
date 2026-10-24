import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import Health from "../pages/Health";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M45-S4：健康中心的口径判据（与旧页逐项一致）。
 * 重点是三件会静默错的事：
 * 1. 余额四态：无能力站点不发请求且显示「不可观测」；失败分型只认凭证问题为「需登录」，
 *    其余为「查询失败」；未知绝不当成 0；
 * 2. 漂移过滤：只列 modified/missing/unreadable，ok 行不得出现；
 * 3. 事件表：200 条口径、级别徽章映射（info → ok）。
 */
vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    listSites: vi.fn(),
    listStoredKeys: vi.fn(),
    listProbeRuns: vi.fn(),
    siteBalance: vi.fn(),
    driftReport: vi.fn(),
    recentEvents: vi.fn(),
  };
});

import {
  driftReport,
  listProbeRuns,
  listSites,
  listStoredKeys,
  recentEvents,
  siteBalance,
  type SiteRow,
} from "../lib/api";

const caps = (balance: boolean): SiteRow["capabilities"] => ({
  login: true,
  listKeys: true,
  createKey: true,
  revealKey: true,
  revokeKey: true,
  balance,
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
      health: "ok", loginField: "username", capabilities: caps(true),
    },
    {
      id: 2, kind: "sub2api", baseUrl: "https://beta.example.test", displayName: "Beta",
      health: "ok", loginField: "email", capabilities: caps(false),
    },
    {
      id: 3, kind: "newapi", baseUrl: "https://gamma.example.test", displayName: "Gamma",
      health: "ok", loginField: "username", capabilities: caps(true),
    },
  ] satisfies SiteRow[]);
  vi.mocked(listStoredKeys).mockResolvedValue([]);
  vi.mocked(listProbeRuns).mockResolvedValue([]);
  vi.mocked(siteBalance).mockImplementation((id: number) =>
    id === 1
      ? Promise.resolve({ currency: "USD", known: true, remaining: 12.5, used: 1 })
      : Promise.reject(new Error("boom")),
  );
  vi.mocked(driftReport).mockResolvedValue([
    {
      targetPath: "/a/b.json", agentId: "codex", channel: "codex-config",
      state: "modified", journalId: "j1",
    },
    {
      targetPath: "/c/d.json", agentId: "codex", channel: "codex-config",
      state: "ok", journalId: "j2",
    },
  ]);
  vi.mocked(recentEvents).mockResolvedValue([
    {
      id: 1, ts: 1760000000, level: "info", source: "gateway",
      message: "started", payload: null,
    },
  ]);
});

describe("Health", () => {
  it("余额四态：有值显示数值、无能力显示不可观测、失败显示查询失败", async () => {
    render(<Health />, { wrapper });
    await waitFor(() => {
      // 以余额卡的说明文案为作用域：标题「余额」与表头「余额」同名，getByText 会歧义
      const balanceCard = screen
        .getByText("各站点的余额总览；未知绝不当成 0。")
        .closest(".hm-card");
      const alphaRow = within(balanceCard as HTMLElement).getByText("Alpha").closest("tr");
      expect(alphaRow).toHaveTextContent("12.50 USD");
      const betaRow = within(balanceCard as HTMLElement).getByText("Beta").closest("tr");
      expect(betaRow).toHaveTextContent("不可观测");
      const gammaRow = within(balanceCard as HTMLElement).getByText("Gamma").closest("tr");
      expect(gammaRow).toHaveTextContent("（查询失败）");
    });
    // 无能力站点连请求都不发：siteBalance 只被 Alpha 与 Gamma 调用
    expect(vi.mocked(siteBalance).mock.calls.map((c) => c[0]).sort()).toEqual([1, 3]);
  });

  it("漂移只列 modified 行，ok 行不在列", async () => {
    render(<Health />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("/a/b.json")).toBeTruthy();
    });
    expect(screen.queryByText("/c/d.json")).toBeNull();
  });

  it("事件行渲染且级别徽章为 ok", async () => {
    render(<Health />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("started")).toBeTruthy();
    });
    const row = screen.getByText("started").closest("tr");
    expect(row?.querySelector("span.badge-ok")).toHaveTextContent("info");
  });

  it("探针区仍在健康中心内", async () => {
    render(<Health />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("检测目标")).toBeTruthy();
      expect(screen.getByText("检测历史")).toBeTruthy();
    });
  });

  // ---- M45-S8（B-231）：此前缺失的分支断言 ----

  function balanceCard() {
    return screen
      .getByText("各站点的余额总览；未知绝不当成 0。")
      .closest(".hm-card") as HTMLElement;
  }

  it("B-231：余额失败分型——凭证问题显示需登录而非查询失败", async () => {
    vi.mocked(siteBalance).mockImplementation((id: number) =>
      id === 1
        ? Promise.resolve({ currency: "USD", known: true, remaining: 12.5, used: 1 })
        : Promise.reject(new Error("认证失败")),
    );
    render(<Health />, { wrapper });
    await waitFor(() => {
      const gammaRow = within(balanceCard()).getByText("Gamma").closest("tr");
      expect(gammaRow).toHaveTextContent("（需登录）");
    });
  });

  it("B-231：余额未知——known 为 false 与 remaining 为 null 都显示不可观测", async () => {
    vi.mocked(siteBalance).mockImplementation((id: number) =>
      id === 1
        ? Promise.resolve({ currency: "USD", known: false, remaining: null, used: 0 })
        : Promise.reject(new Error("boom")),
    );
    const { unmount: unmountFirst } = render(<Health />, { wrapper });
    await waitFor(() => {
      const alphaRow = within(balanceCard()).getByText("Alpha").closest("tr");
      expect(alphaRow).toHaveTextContent("不可观测");
      expect(alphaRow).not.toHaveTextContent("0.00");
    });
    unmountFirst();
    vi.mocked(siteBalance).mockImplementation((id: number) =>
      id === 1
        ? Promise.resolve({ currency: "USD", known: true, remaining: null, used: 0 })
        : Promise.reject(new Error("boom")),
    );
    const { unmount } = render(<Health />, { wrapper });
    await waitFor(() => {
      const alphaRow = within(balanceCard()).getByText("Alpha").closest("tr");
      expect(alphaRow).toHaveTextContent("不可观测");
    });
    unmount();
  });

  it("B-231：余额查询进行中时单元格显示 …", async () => {
    vi.mocked(siteBalance).mockImplementation((id: number) =>
      id === 1 ? new Promise(() => {}) : Promise.reject(new Error("boom")),
    );
    render(<Health />, { wrapper });
    await waitFor(() => {
      const alphaRow = within(balanceCard()).getByText("Alpha").closest("tr");
      expect(alphaRow).toHaveTextContent("…");
    });
  });

  it("B-231：余额区加载中/出错/空态", async () => {
    vi.mocked(listSites).mockImplementation(() => new Promise(() => {}));
    const { unmount } = render(<Health />, { wrapper });
    await waitFor(() => {
      expect(within(balanceCard()).getByText("加载中…")).toBeTruthy();
    });
    unmount();
    vi.mocked(listSites).mockRejectedValue(new Error("boom"));
    const { unmount: unmountErr } = render(<Health />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("加载站点失败：boom")).toBeTruthy();
    });
    unmountErr();
    vi.mocked(listSites).mockResolvedValue([]);
    render(<Health />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("还没有站点。")).toBeTruthy();
    });
  });

  it("B-231：漂移 missing/unreadable 行在列且 hint3 出现", async () => {
    vi.mocked(driftReport).mockResolvedValue([
      { targetPath: "/m.json", agentId: "codex", channel: "codex-config", state: "missing", journalId: "j1" },
      { targetPath: "/u.json", agentId: "codex", channel: "codex-config", state: "unreadable", journalId: "j2" },
    ]);
    render(<Health />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("/m.json")).toBeTruthy();
      expect(screen.getByText("/u.json")).toBeTruthy();
    });
    const driftCard = screen.getByText("/u.json").closest(".hm-card");
    expect(driftCard).toHaveTextContent("文件还在");
    expect(driftCard).toHaveTextContent("只是读不到");
  });

  it("B-231：事件空态与出错红行", async () => {
    vi.mocked(recentEvents).mockResolvedValue([]);
    const { unmount } = render(<Health />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText(/还没有事件/)).toBeTruthy();
    });
    unmount();
    vi.mocked(recentEvents).mockRejectedValue(new Error("boom"));
    render(<Health />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("读取失败：boom")).toBeTruthy();
    });
  });

  it("B-231：事件其余级别徽章（warn/error/debug）", async () => {
    vi.mocked(recentEvents).mockResolvedValue([
      { id: 1, ts: 1, level: "warn", source: "gateway", message: "wmsg", payload: null },
      { id: 2, ts: 2, level: "error", source: "gateway", message: "emsg", payload: null },
      { id: 3, ts: 3, level: "debug", source: "gateway", message: "dmsg", payload: null },
    ]);
    render(<Health />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("wmsg")).toBeTruthy();
    });
    expect(screen.getByText("wmsg").closest("tr")?.querySelector("span.badge-warn")).toHaveTextContent("warn");
    expect(screen.getByText("emsg").closest("tr")?.querySelector("span.badge-danger")).toHaveTextContent("error");
    expect(screen.getByText("dmsg").closest("tr")?.querySelector("span.badge-muted")).toHaveTextContent("debug");
  });
});
