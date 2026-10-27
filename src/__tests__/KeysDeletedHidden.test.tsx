import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

/**
 * M47-S1：资产里的「回收」改成「删除」，并且**删除后的密钥不再显示**。
 *
 * 钉死五件事：
 * ① 文案换词：行内按钮是「删除」（不是「回收」）；
 * ② 二次确认框同样走删除口径，且必须**勾选**才能提交；
 * ③ `status === "revoked"` 的行**不渲染**（旧版本留下的历史行也不显示）；
 * ④ 删除成功后该行从表里消失（后端物理删行 + 前端 invalidate 重新取）；
 * ⑤ 全部删完后的空状态单独一句话，不能与「本地还没有密钥」混成一句。
 */
vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    listSites: vi.fn(),
    listStoredKeys: vi.fn(),
    listKeys: vi.fn(),
    rotationDue: vi.fn(),
    availableGroups: vi.fn(),
    suggestKeyName: vi.fn(),
    revokeKey: vi.fn(),
  };
});

import {
  availableGroups,
  listKeys,
  listSites,
  listStoredKeys,
  revokeKey,
  rotationDue,
  suggestKeyName,
  type SiteRow,
  type StoredKeyRow,
} from "../lib/api";
import Keys from "../pages/Keys";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

const SITE_ID = 1;

const SITES: SiteRow[] = [
  {
    id: SITE_ID,
    kind: "sub2api",
    baseUrl: "https://relay.example.test",
    displayName: "示例中转站",
    health: "ok",
    loginField: "username",
    capabilities: {
      login: true,
      listKeys: true,
      createKey: true,
      revealKey: true,
      revokeKey: true,
      balance: false,
      groups: false,
      keyUsage: false,
      webviewCaptchaSupported: false,
      webviewBearerSupported: true,
    },
  },
];

function storedKey(id: number, name: string, status: string): StoredKeyRow {
  return {
    id,
    siteId: SITE_ID,
    name,
    group: null,
    remoteId: String(id),
    status,
    quotaUsed: null,
    quotaLimit: null,
    currency: null,
  };
}

/** 当前服务端「库里还有什么」——删除成功后这份数据会少一行。 */
let liveRows: StoredKeyRow[] = [];

function renderKeys() {
  vi.mocked(suggestKeyName).mockResolvedValue("codex/agent/20261027");
  vi.mocked(availableGroups).mockResolvedValue([]);
  vi.mocked(rotationDue).mockResolvedValue([]);
  vi.mocked(listKeys).mockResolvedValue([]);
  vi.mocked(listStoredKeys).mockImplementation(async () => liveRows);
  vi.mocked(listSites).mockResolvedValue(SITES);

  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: 0, gcTime: Infinity } },
  });
  return render(<Keys />, {
    wrapper: ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={qc}>
        <I18nProvider lang="zh-CN" initialDict={zhCN}>
          {children}
        </I18nProvider>
      </QueryClientProvider>
    ),
  });
}

beforeEach(() => {
  vi.mocked(revokeKey).mockReset();
  liveRows = [
    storedKey(1, "codex/prod/20261001", "enabled"),
    storedKey(2, "claude/prod/20261002", "revoked"),
    storedKey(3, "gemini/prod/20261003", "enabled"),
  ];
});

describe("资产 · 删除密钥（M47-S1）", () => {
  it("① 行内动作按钮叫「删除」，不再是「回收」", async () => {
    renderKeys();
    await screen.findByText("codex/prod/20261001");
    const buttons = screen.getAllByRole("button", { name: /删除/ });
    expect(buttons.length).toBeGreaterThan(0);
    expect(screen.queryByText("回收")).toBeNull();
  });

  it("③ 已删除（revoked）的密钥不渲染，哪怕后端还返回它", async () => {
    renderKeys();
    await screen.findByText("codex/prod/20261001");
    expect(screen.getByText("gemini/prod/20261003")).toBeTruthy();
    expect(screen.queryByText("claude/prod/20261002")).toBeNull();
    // 连徽章也不出现：这一行整个不渲染
    expect(screen.queryByText("已删除")).toBeNull();
  });

  it("② 二次确认用删除口径，且勾选「我确认删除」之前点不动", async () => {
    renderKeys();
    await screen.findByText("codex/prod/20261001");
    fireEvent.click(screen.getAllByRole("button", { name: /删除/ })[0]);

    const dialog = await screen.findByRole("dialog");
    expect(dialog.textContent).toContain("删除站点上的密钥");
    expect(dialog.textContent).toContain("被一起删除");

    const confirm = screen.getByRole("button", { name: "确认删除" }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);

    fireEvent.click(screen.getByRole("checkbox"));
    expect(confirm.disabled).toBe(false);
  });

  it("④ 删除成功后这一行从表里消失", async () => {
    vi.mocked(revokeKey).mockImplementation(async () => {
      // 后端物理删行：下一次 `listStoredKeys` 就没有它了
      liveRows = liveRows.filter((row) => row.id !== 1);
      return {
        siteId: SITE_ID,
        remoteId: "1",
        revoked: true,
        localRowDeleted: true,
        vaultDeleted: true,
        note: null,
      };
    });

    renderKeys();
    await screen.findByText("codex/prod/20261001");
    fireEvent.click(screen.getAllByRole("button", { name: /删除/ })[0]);
    fireEvent.click(await screen.findByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "确认删除" }));

    await waitFor(() => expect(screen.queryByText("codex/prod/20261001")).toBeNull());
    expect(screen.getByText("gemini/prod/20261003")).toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain("不会再出现在列表里");
  });

  it("⑤ 本地全部删完之后单独给出空状态，不与「一把都没有」混淆", async () => {
    liveRows = [storedKey(2, "claude/prod/20261002", "revoked")];
    renderKeys();
    const empty = await screen.findByText(/本地剩下的密钥都已删除/);
    expect(empty.textContent).toContain("不再显示");
    expect(screen.queryByText("claude/prod/20261002")).toBeNull();
  });
});
