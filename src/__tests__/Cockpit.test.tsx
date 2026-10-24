import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import Cockpit from "../pages/Cockpit";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M45-S1：指挥舱的渲染判据（口径必须与 Overview.tsx 一致）。
 * 重点是三件会静默错的事：
 * 1. 5 指标是否按既有定义计数（有效同意只计未回收、告警只计 warn/error、漂移只计三态）；
 * 2. 漂移卡是否只列三态行（intact 行不得出现）；
 * 3. 用量速览 24h 是否按站点汇总（两行同一站点要加总，不是各列一行）。
 */
vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    appInfo: vi.fn(),
    listSites: vi.fn(),
    listStoredKeys: vi.fn(),
    listConsents: vi.fn(),
    recentEvents: vi.fn(),
    driftReport: vi.fn(),
    recentGatewayUsage: vi.fn(),
    recentUsageSnapshots: vi.fn(),
    refreshAll: vi.fn(),
  };
});

import {
  appInfo,
  listSites,
  listStoredKeys,
  listConsents,
  recentEvents,
  driftReport,
  recentGatewayUsage,
  recentUsageSnapshots,
  refreshAll,
  type AppInfo,
  type ConsentRow,
  type DriftReport,
  type EventRow,
  type GatewayUsageRow,
  type SiteRow,
  type StoredKeyRow,
  type UsageSnapshotRow,
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
  vi.mocked(appInfo).mockResolvedValue({
    name: "Tianshu Relay",
    version: "9.9.9-test",
    dbPath: "/tmp/test.db",
    dataDir: "/tmp/test-data",
    siteCount: 2,
    vaultBackend: "local-sqlite",
    rebrand: { status: "noLegacy", to: "/tmp/test-data", files: 0, bytes: 0, warnings: [] },
  } satisfies AppInfo);
  vi.mocked(listSites).mockResolvedValue([
    {
      id: 1, kind: "newapi", baseUrl: "https://alpha.example.test", displayName: "Alpha",
      health: "ok", loginField: "username", capabilities: caps(),
    },
    {
      id: 2, kind: "sub2api", baseUrl: "https://beta.example.test", displayName: "Beta",
      health: "needs_login", loginField: "email", capabilities: caps(),
    },
  ] satisfies SiteRow[]);
  vi.mocked(listStoredKeys).mockResolvedValue([
    { id: 1, siteId: 1, name: "k1", status: "enabled" },
    { id: 2, siteId: 1, name: "k2", status: "enabled" },
    { id: 3, siteId: 2, name: "k3", status: "revoked" },
  ] as unknown as StoredKeyRow[]);
  vi.mocked(listConsents).mockResolvedValue([
    { agentId: "claude-code", channel: "claude-code", targetPath: "/tmp/a", fields: "[]", grantedAt: 1, revokedAt: null },
    { agentId: "cline", channel: "cline", targetPath: "/tmp/b", fields: "[]", grantedAt: 1, revokedAt: 2 },
  ] satisfies ConsentRow[]);
  vi.mocked(recentEvents).mockResolvedValue([
    { id: 1, ts: 1, level: "warn", source: "gateway", message: "breaker opened" },
    { id: 2, ts: 2, level: "error", source: "gateway", message: "upstream failed" },
    { id: 3, ts: 3, level: "info", source: "gateway", message: "all good" },
  ] satisfies EventRow[]);
  vi.mocked(driftReport).mockResolvedValue([
    { targetPath: "/tmp/drifted.json", agentId: "claude-code", channel: "claude-code", state: "modified", journalId: "j1" },
    { targetPath: "/tmp/intact.json", agentId: "cline", channel: "cline", state: "intact", journalId: "j2" },
  ] satisfies DriftReport[]);
  vi.mocked(recentGatewayUsage).mockResolvedValue([
    { id: 1, ts: 1, siteId: 1, model: "m", promptTokens: 60, completionTokens: 40, totalTokens: 100 },
    { id: 2, ts: 2, siteId: 1, model: "m", promptTokens: 30, completionTokens: 20, totalTokens: 50 },
  ] satisfies GatewayUsageRow[]);
  vi.mocked(recentUsageSnapshots).mockResolvedValue([] satisfies UsageSnapshotRow[]);
});

describe("Cockpit", () => {
  it("5 指标按既有口径计数", async () => {
    render(<Cockpit />, { wrapper });
    await waitFor(() => {
      // 站点 2 / 本地密钥 3 / 有效同意 1（已回收的不计）/ 告警 2（info 不计）/ 漂移 1（intact 不计）
      expect(screen.getByText("站点").closest(".hm-card")).toHaveTextContent("2");
      expect(screen.getByText("本地密钥").closest(".hm-card")).toHaveTextContent("3");
      expect(screen.getByText("有效同意").closest(".hm-card")).toHaveTextContent("1");
      expect(screen.getByText("告警事件").closest(".hm-card")).toHaveTextContent("2");
      expect(screen.getByText("配置漂移").closest(".hm-card")).toHaveTextContent("1");
    });
  });

  it("运行状态与需登录卡渲染真实值", async () => {
    render(<Cockpit />, { wrapper });
    await waitFor(() => {
      // 版本同时出现在英雄卡与运行状态卡（两处同值是设计，不是重复渲染 bug）
      expect(screen.getAllByText(/9\.9\.9-test/)).toHaveLength(2);
      expect(screen.getByText("/tmp/test-data")).toBeTruthy();
      expect(screen.getByText("Beta")).toBeTruthy();
    });
  });

  it("漂移卡只列三态行，intact 行不得出现", async () => {
    render(<Cockpit />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("/tmp/drifted.json")).toBeTruthy();
    });
    expect(screen.queryByText("/tmp/intact.json")).toBeNull();
  });

  it("用量速览按站点汇总 24h Token", async () => {
    render(<Cockpit />, { wrapper });
    await waitFor(() => {
      // Alpha 两行 100 + 50 = 150；输入 90 / 输出 60
      expect(screen.getByText(/Alpha: 150 tokens/, { exact: false })).toBeTruthy();
    });
  });

  // ---- M45-S8（B-227）：此前缺失的四类断言 ----

  it("告警卡只列 top5，6 条告警时第 6 条不得出现", async () => {
    vi.mocked(recentEvents).mockResolvedValue(
      [1, 2, 3, 4, 5, 6].map((i) => ({
        id: i, ts: i, level: "warn", source: "gateway", message: `msg-${i}`,
      })) as unknown as EventRow[],
    );
    render(<Cockpit />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("msg-5")).toBeTruthy();
    });
    expect(screen.queryByText("msg-6")).toBeNull();
    // 指标仍计 6 条（截断只影响卡片行数，不影响计数）
    expect(screen.getByText("告警事件").closest(".hm-card")).toHaveTextContent("6");
  });

  it("刷新失败时红行带真实原因", async () => {
    vi.mocked(refreshAll).mockRejectedValue(new Error("boom"));
    render(<Cockpit />, { wrapper });
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "立即刷新全部站点" })).toBeTruthy();
    });
    fireEvent.click(screen.getByRole("button", { name: "立即刷新全部站点" }));
    await waitFor(() => {
      expect(screen.getByText(/刷新失败：boom/)).toBeTruthy();
    });
  });

  it("内存 vault 时警告红行在列", async () => {
    vi.mocked(appInfo).mockResolvedValue({
      name: "Tianshu Relay",
      version: "9.9.9-test",
      dbPath: "/tmp/test.db",
      dataDir: "/tmp/test-data",
      siteCount: 2,
      vaultBackend: "memory",
      rebrand: { status: "noLegacy", to: "/tmp/test-data", files: 0, bytes: 0, warnings: [] },
    } satisfies AppInfo);
    render(<Cockpit />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText(/内存保险库/)).toBeTruthy();
    });
  });

  it("7d 快照 delta 按最新减上一条计算", async () => {
    vi.mocked(recentUsageSnapshots).mockResolvedValue([
      { id: 1, ts: 2, siteId: 1, used: 10, remaining: 90, currency: "USD", known: true },
      { id: 2, ts: 1, siteId: 1, used: 8, remaining: 92, currency: "USD", known: true },
    ] satisfies UsageSnapshotRow[]);
    render(<Cockpit />, { wrapper });
    await waitFor(() => {
      // 最新 10 - 上一条 8 = +2.00
      expect(screen.getByText(/\+2\.00/, { exact: false })).toBeTruthy();
    });
  });

  it("B-225：事件/漂移查询加载中时指标显示 — 而不是 0", async () => {
    vi.mocked(recentEvents).mockImplementation(() => new Promise(() => {}));
    vi.mocked(driftReport).mockImplementation(() => new Promise(() => {}));
    render(<Cockpit />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("告警事件").closest(".hm-card")).toHaveTextContent("—");
      expect(screen.getByText("配置漂移").closest(".hm-card")).toHaveTextContent("—");
    });
  });
});
