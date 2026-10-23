import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import GatewayCard from "../components/GatewayCard";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M43-S1：网关卡片里的「Agent 令牌」区块。
 *
 * 钉死：列表字段（label / 创建 / 最近使用 / 默认标记）、空态、
 * 创建后明文只显示一次（关掉后不可再看）、吊销要二次确认（取消不发请求）、
 * 默认行不提供吊销按钮、只提示用轮换。
 */

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    gatewayStatus: vi.fn(),
    gatewayStart: vi.fn(),
    gatewayStop: vi.fn(),
    gatewayRotateToken: vi.fn(),
    gatewayTokenList: vi.fn(),
    gatewayTokenCreate: vi.fn(),
    gatewayTokenRevoke: vi.fn(),
    listSites: vi.fn(),
    listStoredKeys: vi.fn(),
    listChannelBindings: vi.fn(),
  };
});

import {
  gatewayStatus,
  gatewayTokenCreate,
  gatewayTokenList,
  gatewayTokenRevoke,
  listChannelBindings,
  listSites,
  listStoredKeys,
  type GatewayStatus,
  type GatewayToken,
} from "../lib/api";

const status = (): GatewayStatus => ({
  running: false,
  phase: "stopped",
  url: null,
  token: null,
  site: null,
  tokenPersistent: false,
  lastExit: null,
  tokens: [],
});

const token = (over: Partial<GatewayToken> = {}): GatewayToken => ({
  id: 1,
  label: "codex",
  createdAt: 1_700_000_000,
  revokedAt: null,
  lastUsedAt: null,
  active: true,
  isDefault: false,
  ...over,
});

function renderCard() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>
      <I18nProvider lang="zh-CN" initialDict={zhCN}>
        {children}
      </I18nProvider>
    </QueryClientProvider>
  );
  return render(
    <GatewayCard
      enabled
      port={8787}
      multiSite={false}
      collectModels={false}
      modelsMinIntervalSecs={1800}
      onToggle={vi.fn()}
      onPortChange={vi.fn()}
      onMultiSiteChange={vi.fn()}
      onCollectModelsChange={vi.fn()}
      onModelsIntervalChange={vi.fn()}
      settingsDirty={false}
    />,
    { wrapper },
  );
}

const section = () =>
  screen.getByText(zhCN.gateway.tokens.title).closest(".card") as HTMLElement;

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(gatewayStatus).mockResolvedValue(status());
  vi.mocked(listSites).mockResolvedValue([]);
  vi.mocked(listStoredKeys).mockResolvedValue([]);
  vi.mocked(listChannelBindings).mockResolvedValue([]);
});

describe("GatewayCard · Agent 令牌（M43-S1）", () => {
  it("空态：显示「还没有 Agent 令牌」", async () => {
    vi.mocked(gatewayTokenList).mockResolvedValue([]);
    renderCard();
    await waitFor(() =>
      expect(screen.getByText(zhCN.gateway.tokens.empty)).toBeTruthy(),
    );
  });

  it("列表：label / 默认标记 / 从未使用 / 默认行无吊销按钮且有轮换提示", async () => {
    vi.mocked(gatewayTokenList).mockResolvedValue([
      token({ id: 1, label: "默认（迁移）", isDefault: true }),
      token({ id: 2, label: "codex", lastUsedAt: 1_700_000_100 }),
    ]);
    renderCard();
    await waitFor(() => expect(screen.getByText("默认（迁移）")).toBeTruthy());
    expect(screen.getByText(zhCN.gateway.tokens.defaultBadge)).toBeTruthy();
    expect(screen.getAllByText(/从未使用/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/默认令牌不能吊销/).length).toBeGreaterThan(0);
    // 默认行没有吊销按钮；agent 行有一个。
    const buttons = within(section()).getAllByRole("button", {
      name: zhCN.gateway.tokens.revoke,
    });
    expect(buttons).toHaveLength(1);
  });

  it("创建：明文只显示一次，点「我已保存」后消失", async () => {
    vi.mocked(gatewayTokenList).mockResolvedValue([]);
    vi.mocked(gatewayTokenCreate).mockResolvedValue({
      id: 9,
      label: "new-agent",
      token: "kr-gw-once-0123456789abcdef",
      createdAt: 1_700_000_000,
    });
    renderCard();
    const input = await screen.findByPlaceholderText(
      zhCN.gateway.tokens.labelPlaceholder,
    );
    fireEvent.change(input, { target: { value: "new-agent" } });
    fireEvent.click(
      screen.getByRole("button", { name: zhCN.gateway.tokens.create }),
    );
    await waitFor(() =>
      expect(screen.getByText("kr-gw-once-0123456789abcdef")).toBeTruthy(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: zhCN.gateway.tokens.savedIt }),
    );
    await waitFor(() =>
      expect(screen.queryByText("kr-gw-once-0123456789abcdef")).toBeNull(),
    );
  });

  it("轮换宽限：tokenGraceUntil 有值时显示截止提示（M41-S2）", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue({
      ...status(),
      // 必须是**未来**时间：过期提示按 spec 不显示（避免展示已过去的时间）。
      tokenGraceUntil: Math.floor(Date.now() / 1000) + 300,
    });
    vi.mocked(gatewayTokenList).mockResolvedValue([]);
    renderCard();
    await waitFor(() =>
      expect(document.querySelector("[data-token-grace]")).toBeTruthy(),
    );
    expect(document.querySelector("[data-token-grace]")!.textContent).toContain(
      "旧令牌仍可用至",
    );
  });

  it("吊销：取消不发请求；确认后调用 revoke", async () => {
    vi.mocked(gatewayTokenList).mockResolvedValue([token({ id: 2, label: "codex" })]);
    vi.mocked(gatewayTokenRevoke).mockResolvedValue(
      token({ id: 2, label: "codex", active: false, revokedAt: 1_700_000_200 }),
    );
    renderCard();
    await waitFor(() => expect(screen.getByText("codex")).toBeTruthy());
    fireEvent.click(
      screen.getByRole("button", { name: zhCN.gateway.tokens.revoke }),
    );
    await screen.findByRole("dialog");
    fireEvent.click(screen.getByRole("button", { name: zhCN.confirm.cancel }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(gatewayTokenRevoke).not.toHaveBeenCalled();

    fireEvent.click(
      screen.getByRole("button", { name: zhCN.gateway.tokens.revoke }),
    );
    await screen.findByRole("dialog");
    fireEvent.click(
      screen.getByRole("button", { name: zhCN.gateway.tokens.revokeConfirm }),
    );
    await waitFor(() => expect(gatewayTokenRevoke).toHaveBeenCalledWith(2));
  });
});
