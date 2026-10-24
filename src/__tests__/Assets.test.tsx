import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import Assets from "../pages/Assets";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M45-S5：资产中心只是把站点页与密钥页合流为一个入口，两组件零改动。
 * 本测试只断言合流本身：两区同时在列；两区各自的行为由其既有单测覆盖。
 */
vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    listSites: vi.fn(),
    listStoredKeys: vi.fn(),
  };
});

import { listSites, listStoredKeys, type SiteRow } from "../lib/api";

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
});

describe("Assets", () => {
  it("站点区与密钥区同时在列", async () => {
    render(<Assets />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("接入新站点")).toBeTruthy();
    });
    expect(screen.getByText("站点上的令牌（只读对照）")).toBeTruthy();
    // 站点列表行是异步查询渲染的，需等它出现（标题先出现不代表行已出现）
    await waitFor(() => {
      expect(screen.getAllByText("Alpha").length).toBeGreaterThan(0);
    });
  });
});
