import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import Delivery from "../pages/Delivery";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * 投递中心把主任务与历史回滚拆成两个工作区。
 * 本测试覆盖视图切换与键盘导航；授权、写入、更新和回滚仍由原组件测试覆盖。
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
  it("配置与历史分视图；历史仍完整展示记录与回滚入口", async () => {
    render(<Delivery />, { wrapper });
    const configure = screen.getByRole("tab", { name: "配置投递" });
    const history = screen.getByRole("tab", { name: "记录与回滚" });
    expect(configure).toHaveAttribute("aria-selected", "true");
    expect(history).toHaveAttribute("aria-selected", "false");
    expect(screen.getByText("支持的 Agent（19）")).toBeTruthy();
    expect(screen.queryByText("/a/b.json")).toBeNull();

    fireEvent.click(history);
    await waitFor(() => expect(screen.getByText("投递记录（1）")).toBeTruthy());
    expect(screen.getByText("/a/b.json")).toBeTruthy();
    expect(screen.getByText("支持的 Agent（19）")).not.toBeVisible();
    expect(history).toHaveAttribute("aria-selected", "true");

    fireEvent.click(configure);
    expect(screen.getByText("支持的 Agent（19）")).toBeVisible();
    expect(screen.getByText("/a/b.json")).not.toBeVisible();
  });

  it("标签支持方向键切换，并移动焦点到当前标签", () => {
    render(<Delivery />, { wrapper });
    const configure = screen.getByRole("tab", { name: "配置投递" });
    configure.focus();
    fireEvent.keyDown(configure, { key: "ArrowRight" });
    expect(screen.getByRole("tab", { name: "记录与回滚" })).toHaveFocus();
    expect(screen.getByRole("tab", { name: "记录与回滚" })).toHaveAttribute("aria-selected", "true");
    fireEvent.keyDown(document.activeElement!, { key: "ArrowLeft" });
    expect(configure).toHaveFocus();
    expect(configure).toHaveAttribute("aria-selected", "true");
  });

  it("往返历史保留未确认的筛选、密钥与预览状态", async () => {
    vi.mocked(detectAgents).mockResolvedValue([
      { channel: "codex-auth-json", installed: true, version: "1.0.0", source: null, detail: null, installCommands: [], installUrl: null },
    ]);
    vi.mocked(listStoredKeys).mockResolvedValue([
      { id: 1, siteId: 1, remoteId: "1", name: "local-key", group: null, status: "enabled" },
    ]);
    render(<Delivery />, { wrapper });
    const search = screen.getByRole("searchbox", { name: "搜索 Agent" });
    fireEvent.change(search, { target: { value: "codex-auth" } });
    const row = document.querySelector<HTMLElement>("[data-agent-channel='codex-auth-json']")!;
    await waitFor(() => expect(row.querySelector<HTMLSelectElement>(".agent-row-key")).not.toBeNull());
    const key = row.querySelector<HTMLSelectElement>(".agent-row-key")!;
    await waitFor(() => expect(key.querySelector("option[value='1']")).not.toBeNull());
    fireEvent.change(key, { target: { value: "1" } });
    fireEvent.click(row.querySelector<HTMLButtonElement>(".agent-row-toggle")!);
    await waitFor(() => expect(row.querySelector(".agent-row-plan")?.textContent).toContain("投递预览"));

    fireEvent.click(screen.getByRole("tab", { name: "记录与回滚" }));
    await waitFor(() => expect(screen.getByText("投递记录（1）")).toBeVisible());
    fireEvent.click(screen.getByRole("tab", { name: "配置投递" }));
    expect(search).toHaveValue("codex-auth");
    expect(key).toHaveValue("1");
    expect(row.querySelector(".agent-row-plan")?.textContent).toContain("投递预览");
    expect(row.querySelector<HTMLButtonElement>(".agent-row-toggle")).toHaveAttribute("aria-expanded", "true");
  });

  it("Agent 搜索与已安装筛选只改变展示，不改变通道定义", async () => {
    vi.mocked(detectAgents).mockResolvedValue([
      { channel: "codex-auth-json", installed: true, version: "1.0.0", source: null, detail: null, installCommands: [], installUrl: null },
    ]);
    render(<Delivery />, { wrapper });
    const search = screen.getByRole("searchbox", { name: "搜索 Agent" });
    fireEvent.change(search, { target: { value: "Codex Config" } });
    expect(document.querySelectorAll("[data-agent-channel]")).toHaveLength(1);
    expect(document.querySelector("[data-agent-channel='codex-config']")).not.toBeNull();
    expect(screen.getByText("支持的 Agent（19）")).toBeTruthy();

    fireEvent.change(search, { target: { value: "" } });
    fireEvent.click(screen.getByRole("checkbox", { name: "只看已安装" }));
    await waitFor(() => expect(document.querySelectorAll("[data-agent-channel]")).toHaveLength(1));
    expect(document.querySelector("[data-agent-channel='codex-auth-json']")).not.toBeNull();

    fireEvent.change(search, { target: { value: "not-an-agent" } });
    const panel = screen.getByRole("tabpanel", { name: "配置投递" });
    expect(within(panel).getByText(/没有匹配的 Agent/)).toBeTruthy();
    fireEvent.click(within(panel).getByRole("button", { name: "清除筛选" }));
    expect(search).toHaveValue("");
    expect(screen.getByRole("checkbox", { name: "只看已安装" })).not.toBeChecked();
    expect(document.querySelectorAll("[data-agent-channel]")).toHaveLength(19);
  });
});
