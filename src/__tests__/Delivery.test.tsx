import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import Delivery from "../pages/Delivery";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M45-S6：投递中心只是把 Agent 页与历史页（现仅含投递记录）合流为一个入口，两组件零改动。
 * 本测试只断言合流本身：两区同时在列；两区各自的行为由其既有单测覆盖。
 */
vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    listSites: vi.fn(),
    listStoredKeys: vi.fn(),
    detectAgents: vi.fn(),
    checkAgentUpdates: vi.fn(),
    listConsents: vi.fn(),
    detectUnmanagedTargets: vi.fn(),
    listDeliveries: vi.fn(),
  };
});

import {
  checkAgentUpdates,
  detectAgents,
  detectUnmanagedTargets,
  listConsents,
  listDeliveries,
  listSites,
  listStoredKeys,
  type SiteRow,
} from "../lib/api";

const caps = (): SiteRow["capabilities"] => ({
  login: true,
  listKeys: true,
  createKey: true,
  revealKey: true,
  revokeKey: true,
  balance: false,
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
  vi.mocked(listStoredKeys).mockResolvedValue([]);
  vi.mocked(detectAgents).mockResolvedValue([]);
  vi.mocked(checkAgentUpdates).mockResolvedValue([]);
  vi.mocked(listConsents).mockResolvedValue([]);
  vi.mocked(detectUnmanagedTargets).mockResolvedValue([]);
  vi.mocked(listDeliveries).mockResolvedValue([
    {
      bindingId: 1, appliedAt: 1760000000, agentId: "codex", targetPath: "/a/b.json",
      keyId: 1, rolledBack: false, hasJournal: true, superseded: false,
      unboundAt: null, journalId: "j1", backupPath: null,
    },
  ]);
});

describe("Delivery", () => {
  it("Agent 通道区与投递记录区同时在列", async () => {
    render(<Delivery />, { wrapper });
    await waitFor(() => {
      // 通道区标题的 count 是 CHANNELS 常量（19 条，B-292 下线 Cline Desktop 后），与探测结果无关
      // B-292：Cline Desktop 已下线，工作台标题计数随 CHANNELS 变为 19。
      expect(screen.getByText("支持的 Agent（19）")).toBeTruthy();
    });
    // 投递记录区是异步查询渲染的，需等它出现（通道区标题先出现不代表记录行已出现）
    await waitFor(() => {
      expect(screen.getByText("投递记录（1）")).toBeTruthy();
    });
    expect(screen.getByText("/a/b.json")).toBeTruthy();
  });
});
