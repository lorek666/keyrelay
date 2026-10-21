import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import Agents, { CHANNELS } from "../pages/Agents";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M34-S1：Agent 更新提醒与一键更新（前端）。
 *
 * 钉死 spec §7.3 的六类用例：
 * ① 汇总卡显示可更新数量；可更新行有徽标与「更新」按钮；未安装 / 已最新 / 不支持的行没有更新控件。
 * ② 点「更新」→ 弹窗展示 0.162.1 → 0.163.0 与命令 `codex update`；未勾选同意时确认禁用；
 *    勾选后确认调用 `updateAgent("codex-auth-json")`。
 * ③ 成功：提示含新旧版本；重取后徽标消失、版本更新；`updateAgent` 只调用一次（pending 防重复）。
 * ④ 失败：展示 attempts 的退出码与 `outputTail`；行仍显示可更新；不崩溃。
 * ⑤ `autoUpdate:false` 的可更新行只有徽标，没有可点击的「更新」按钮。
 * ⑥ `checkAgentUpdates` 失败：汇总卡显示错误 + 重试按钮，工作台 20 行照常渲染。
 *
 * 不依赖网络：所有查询都 mock 成固定数据；`updateAgent` 在用例内按需换实现。
 */

const SITE_A = 11;

/** 更新检查是否已经「更新完成」（让重取后的数据变新，用来验证徽标消失）。 */
let codexUpdated = false;

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  const notInstalled = (channel: string) => ({
    channel,
    installed: false,
    version: null,
    source: null,
    detail: null,
    installCommands: [{ via: "npm", command: `npm i -g ${channel}` }],
    installUrl: "https://example.test/install",
  });
  const installed = (channel: string, version: string) => ({
    channel,
    installed: true,
    version,
    source: `/usr/local/bin/${channel}`,
    detail: null,
    installCommands: [{ via: "npm", command: `npm i -g ${channel}` }],
    installUrl: "https://example.test/install",
  });
  const notInstalledUpdate = (channel: string) => ({
    channel,
    installed: false,
    currentVersion: null,
    latestVersion: null,
    state: "notInstalled",
    source: "none",
    autoUpdate: false,
    command: null,
    manualUrl: null,
    message: null,
  });
  const available = (channel: string, current: string, latest: string, autoUpdate: boolean) => ({
    channel,
    installed: true,
    currentVersion: current,
    latestVersion: latest,
    state: "available",
    source: "npm",
    autoUpdate,
    command: autoUpdate ? "codex update" : null,
    manualUrl: "https://example.test/install",
    message: autoUpdate ? null : "该通道需手动更新",
  });

  return {
    ...actual,
    listSites: vi.fn(async () => [
      {
        id: SITE_A,
        kind: "newapi",
        baseUrl: "https://a.example.test",
        displayName: "站点A",
        health: "ok",
        loginField: "username",
        capabilities: {
          login: true,
          listKeys: true,
          createKey: true,
          revealKey: true,
          revokeKey: true,
          balance: true,
          groups: true,
          keyUsage: false,
        },
      },
    ]),
    listStoredKeys: vi.fn(async () => []),
    listConsents: vi.fn(async () => []),
    detectUnmanagedTargets: vi.fn(async () => []),
    listKeyModels: vi.fn(async () => []),
    detectAgents: vi.fn(async () =>
      CHANNELS.map((c) => {
        if (c.id === "codex-auth-json") return installed(c.id, codexUpdated ? "0.163.0" : "0.162.1");
        if (c.id === "claude-code-settings") return installed(c.id, "2.1.296");
        if (c.id === "dsh") return installed(c.id, "0.2.1-rc.2");
        if (c.id === "opencode") return installed(c.id, "1.4.0");
        return notInstalled(c.id);
      }),
    ),
    checkAgentUpdates: vi.fn(async () =>
      CHANNELS.map((c) => {
        if (c.id === "codex-auth-json") {
          return codexUpdated
            ? { ...available(c.id, "0.163.0", "0.163.0", true), state: "upToDate", command: null }
            : available(c.id, "0.162.1", "0.163.0", true);
        }
        if (c.id === "claude-code-settings") return available(c.id, "2.1.296", "2.1.306", true);
        // ⑤：有新版但不能一键更新 ⇒ 只显示徽标
        if (c.id === "dsh") return available(c.id, "0.2.1-rc.2", "0.2.2", false);
        // ①：已最新 / 不支持检查 ⇒ 不显示更新控件
        if (c.id === "opencode") {
          return { ...available(c.id, "1.4.0", "1.4.0", true), state: "upToDate", command: null };
        }
        if (c.id === "grok-build") {
          return { ...notInstalledUpdate(c.id), state: "unsupported", manualUrl: "https://example.test/grok" };
        }
        return notInstalledUpdate(c.id);
      }),
    ),
    updateAgent: vi.fn(async () => ({
      channel: "codex-auth-json",
      success: true,
      attempts: [
        {
          label: "自更新",
          command: "codex update",
          skipped: false,
          success: true,
          exitCode: 0,
          timedOut: false,
          outputTail: "",
        },
      ],
      versionBefore: "0.162.1",
      versionAfter: "0.163.0",
      versionChanged: true,
      message: null,
    })),
  };
});

import { updateAgent } from "../lib/api";

const rows = () => Array.from(document.querySelectorAll<HTMLElement>("[data-agent-channel]"));
const row = (id: string) => document.querySelector<HTMLElement>(`[data-agent-channel="${id}"]`)!;
const dialog = () => document.querySelector<HTMLDialogElement>("dialog[open]");
const confirmButton = () => document.querySelector<HTMLButtonElement>("dialog[open] .dialog-actions .btn-primary")!;
const agreeBox = () => document.querySelector<HTMLInputElement>("dialog[open] .checkline input[type=checkbox]")!;

function renderPage() {
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
  return render(<Agents />, { wrapper });
}

/**
 * 等两个查询都落定：`detect_agents` 成功后 `check_agent_updates` 才会启用
 * （`enabled: agentsQuery.isSuccess`）⇒ 判据取「行上已有更新状态」而不是汇总卡出现。
 */
async function waitForUpdates() {
  await waitFor(() => {
    expect(row("codex-auth-json").getAttribute("data-agent-update-state")).toBe("available");
  });
}

beforeEach(() => {
  codexUpdated = false;
  vi.clearAllMocks();
});

describe("M34-S1 Agent 更新", () => {
  it("① 汇总卡显示可更新数量；可更新行有徽标与按钮；未安装/已最新/不支持行没有更新控件", async () => {
    renderPage();
    await waitForUpdates();

    const summary = document.querySelector(".agent-updates-summary")!;
    // mock：available = codex-auth-json / claude-code-settings / dsh（3 个），upToDate = opencode（1 个）
    expect(summary.textContent).toContain("可更新 3");
    expect(summary.textContent).toContain("已最新 1");
    expect(summary.textContent).toContain("暂不支持 1");

    // 可更新 + autoUpdate：徽标 + 更新按钮
    const codex = row("codex-auth-json");
    expect(codex.getAttribute("data-agent-update-state")).toBe("available");
    expect(codex.querySelector(".agent-update-badge")?.textContent).toContain("0.163.0");
    expect(codex.querySelector(".agent-row-update")).not.toBeNull();

    // 已最新：没有徽标/按钮
    expect(row("opencode").getAttribute("data-agent-update-state")).toBe("upToDate");
    expect(row("opencode").querySelector(".agent-update-badge")).toBeNull();
    expect(row("opencode").querySelector(".agent-row-update")).toBeNull();

    // 不支持检查：没有徽标/按钮
    expect(row("grok-build").getAttribute("data-agent-update-state")).toBe("unsupported");
    expect(row("grok-build").querySelector(".agent-update-badge")).toBeNull();

    // 未安装：没有徽标/按钮
    expect(row("gemini-cli").getAttribute("data-agent-update-state")).toBe("notInstalled");
    expect(row("gemini-cli").querySelector(".agent-update-badge")).toBeNull();
  });

  it("② 弹窗展示版本与命令；未勾选同意时确认禁用；勾选后调用 updateAgent(channel)", async () => {
    renderPage();
    await waitForUpdates();

    fireEvent.click(row("codex-auth-json").querySelector(".agent-row-update")!);
    await waitFor(() => expect(dialog()).not.toBeNull());

    const body = dialog()!.textContent ?? "";
    expect(body).toContain("0.162.1");
    expect(body).toContain("0.163.0");
    expect(body).toContain("codex update");

    // 未勾选 ⇒ 确认禁用
    expect(confirmButton().disabled).toBe(true);
    fireEvent.click(confirmButton());
    expect(updateAgent).not.toHaveBeenCalled();

    fireEvent.click(agreeBox());
    await waitFor(() => expect(confirmButton().disabled).toBe(false));
    fireEvent.click(confirmButton());

    await waitFor(() => expect(updateAgent).toHaveBeenCalledTimes(1));
    expect(updateAgent).toHaveBeenCalledWith("codex-auth-json");
  });

  it("③ 成功：提示含新旧版本；重取后徽标消失、版本更新；pending 时重复点击只调用一次", async () => {
    // 让 updateAgent 卡在 pending，验证「重复点击不会再次调用」
    let release: (() => void) | null = null;
    (updateAgent as unknown as { mockImplementationOnce: (fn: () => Promise<unknown>) => void })
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            release = () => {
              codexUpdated = true;
              resolve({
                channel: "codex-auth-json",
                success: true,
                attempts: [
                  {
                    label: "自更新",
                    command: "codex update",
                    skipped: false,
                    success: true,
                    exitCode: 0,
                    timedOut: false,
                    outputTail: "",
                  },
                ],
                versionBefore: "0.162.1",
                versionAfter: "0.163.0",
                versionChanged: true,
                message: null,
              });
            };
          }),
      );

    renderPage();
    await waitForUpdates();
    fireEvent.click(row("codex-auth-json").querySelector(".agent-row-update")!);
    await waitFor(() => expect(dialog()).not.toBeNull());
    fireEvent.click(agreeBox());
    await waitFor(() => expect(confirmButton().disabled).toBe(false));

    fireEvent.click(confirmButton());
    await waitFor(() => expect(updateAgent).toHaveBeenCalledTimes(1));
    // pending：确认按钮变「更新中…」且禁用，再点一次不会再次调用
    await waitFor(() => expect(confirmButton().textContent).toContain("更新中"));
    expect(confirmButton().disabled).toBe(true);
    fireEvent.click(confirmButton());
    expect(updateAgent).toHaveBeenCalledTimes(1);

    release!();
    // 成功提示含新旧版本
    await waitFor(() => {
      const ok = document.querySelector('p.ok[role="status"]');
      expect(ok?.textContent ?? "").toContain("0.162.1");
      expect(ok?.textContent ?? "").toContain("0.163.0");
    });
    // 重取后徽标消失、版本变新
    await waitFor(() => {
      expect(row("codex-auth-json").querySelector(".agent-update-badge")).toBeNull();
    });
    expect(row("codex-auth-json").textContent).toContain("0.163.0");
    expect(updateAgent).toHaveBeenCalledTimes(1);
  });

  it("④ 失败：展示 attempts 的退出码与 outputTail；行仍可更新；不崩溃", async () => {
    (updateAgent as unknown as { mockImplementationOnce: (fn: () => Promise<unknown>) => void })
      .mockImplementationOnce(async () => ({
        channel: "codex-auth-json",
        success: false,
        attempts: [
          {
            label: "自更新",
            command: "codex update",
            skipped: false,
            success: false,
            exitCode: 1,
            timedOut: false,
            outputTail: "npm ERR! 404 Not Found",
          },
          {
            label: "npm",
            command: "npm install -g @openai/codex@latest",
            skipped: true,
            success: false,
            exitCode: null,
            timedOut: false,
            outputTail: "",
          },
        ],
        versionBefore: "0.162.1",
        versionAfter: "0.162.1",
        versionChanged: false,
        message: "所有策略都失败",
      }));

    renderPage();
    await waitForUpdates();
    fireEvent.click(row("codex-auth-json").querySelector(".agent-row-update")!);
    await waitFor(() => expect(dialog()).not.toBeNull());
    fireEvent.click(agreeBox());
    await waitFor(() => expect(confirmButton().disabled).toBe(false));
    fireEvent.click(confirmButton());

    await waitFor(() => {
      const box = document.querySelector(".warnbox");
      expect(box).not.toBeNull();
      const text = box!.textContent ?? "";
      expect(text).toContain("退出码 1");
      expect(text).toContain("npm ERR! 404 Not Found");
      expect(text).toContain("已跳过");
    });
    // 行仍可更新（徽标还在），页面没崩
    expect(row("codex-auth-json").querySelector(".agent-update-badge")).not.toBeNull();
    expect(rows().length).toBe(CHANNELS.length);
  });

  it("⑤ autoUpdate:false 的可更新行只有徽标，没有可点击的「更新」按钮", async () => {
    renderPage();
    await waitForUpdates();

    const dsh = row("dsh");
    expect(dsh.getAttribute("data-agent-update-state")).toBe("available");
    const badge = dsh.querySelector(".agent-update-badge");
    expect(badge?.textContent).toContain("0.2.2");
    expect(badge?.textContent).toContain("手动");
    expect(badge?.getAttribute("title")).toBe("该通道需手动更新");
    expect(dsh.querySelector(".agent-row-update")).toBeNull();
  });

  it("⑦ 命令成功但版本未变化：如实提示「版本没有变化」，不谎报升级", async () => {
    (updateAgent as unknown as { mockImplementationOnce: (fn: () => Promise<unknown>) => void })
      .mockImplementationOnce(async () => ({
        channel: "codex-auth-json",
        success: true,
        attempts: [
          {
            label: "自更新",
            command: "codex update",
            skipped: false,
            success: true,
            exitCode: 0,
            timedOut: false,
            outputTail: "already up to date",
          },
        ],
        versionBefore: "0.162.1",
        versionAfter: "0.162.1",
        versionChanged: false,
        message: null,
      }));

    renderPage();
    await waitForUpdates();
    fireEvent.click(row("codex-auth-json").querySelector(".agent-row-update")!);
    await waitFor(() => expect(dialog()).not.toBeNull());
    fireEvent.click(agreeBox());
    await waitFor(() => expect(confirmButton().disabled).toBe(false));
    fireEvent.click(confirmButton());

    await waitFor(() => {
      const ok = document.querySelector('p.ok[role="status"]');
      expect(ok?.textContent ?? "").toContain("版本没有变化");
    });
    // 不得出现「已从 A 更新到 B」的谎报
    expect(document.querySelector('p.ok[role="status"]')!.textContent).not.toContain("更新到");
  });

  it("⑥ checkAgentUpdates 失败：汇总卡显示错误 + 重试，20 行照常渲染", async () => {
    const { checkAgentUpdates } = await import("../lib/api");
    (checkAgentUpdates as unknown as { mockRejectedValueOnce: (e: Error) => void }).mockRejectedValueOnce(
      new Error("网络不可用"),
    );

    renderPage();
    await waitFor(() => {
      const card = document.querySelector(".agent-updates");
      expect(card?.textContent ?? "").toContain("网络不可用");
    });
    const card = document.querySelector(".agent-updates")!;
    expect(card.querySelector(".error")).not.toBeNull();
    // 重试按钮存在（重新触发检查）
    expect(Array.from(card.querySelectorAll("button")).some((b) => (b.textContent ?? "").includes("重试"))).toBe(
      true,
    );
    // 工作台 20 行照常渲染
    expect(rows().length).toBe(CHANNELS.length);
  });
});
