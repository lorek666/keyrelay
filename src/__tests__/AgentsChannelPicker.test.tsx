import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import Agents, { CHANNELS } from "../pages/Agents";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M31-S1：本文件从「卡片网格」改成「单列工作台」的行列表断言。
 *
 * **不是删掉旧断言，而是换成等价强度的行断言**：
 * ① 20 行且顺序与 `CHANNELS` 一致（旧断言：20 张卡片）；
 * ② 每行有 `data-agent-channel` 与 `data-agent-name`，并显示名称与目标文件（旧断言：每张卡含 label + agent）；
 * ③ 页面不再有旧的「通道」下拉（旧断言：无 combobox）；
 * ④ 旧 M30 的卡片网格 `.agent-grid` / `[data-agent-channel]` 按钮形态已被行列表取代。
 */

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  const allMissing = (channel: string) => ({
    channel,
    installed: false,
    version: null,
    source: null,
    detail: null,
    installCommands: [{ via: "npm", command: `npm i -g ${channel}` }],
    installUrl: "https://example.test/install",
  });
  return {
    ...actual,
    listSites: vi.fn(async () => [
      {
        id: 1,
        kind: "newapi",
        baseUrl: "https://relay.example.test",
        displayName: "示例站",
        health: "ok",
        loginField: "username",
        capabilities: {
          login: true, listKeys: true, createKey: true, revealKey: true,
          revokeKey: true, balance: true, groups: true, keyUsage: false,
        },
      },
    ]),
    listStoredKeys: vi.fn(async () => []),
    listConsents: vi.fn(async () => []),
    detectUnmanagedTargets: vi.fn(async () => []),
    detectAgents: vi.fn(async () => CHANNEL_IDS.map(allMissing)),
  };
});

import { detectAgents } from "../lib/api";
import { CHANNELS as ALL } from "../pages/Agents";

const CHANNEL_IDS = ALL.map((c) => c.id);

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>
      <I18nProvider lang="zh-CN" initialDict={zhCN}>
        {children}
      </I18nProvider>
    </QueryClientProvider>
  );
  return render(<Agents />, { wrapper });
}

const rows = () =>
  Array.from(document.querySelectorAll<HTMLElement>("[data-agent-channel]"));

describe("M31-S1 Agent 工作台（行列表）", () => {
  it("① 20 行且顺序与 CHANNELS 完全一致", async () => {
    renderPage();
    await waitFor(() => expect(rows().length).toBe(CHANNELS.length));
    expect(CHANNELS.length).toBe(20);
    expect(rows().map((r) => r.getAttribute("data-agent-channel"))).toEqual(
      CHANNELS.map((c) => c.id),
    );
  });

  it("② 每行都有 data-agent-name，并显示名称与目标文件", async () => {
    renderPage();
    await waitFor(() => expect(rows().length).toBe(CHANNELS.length));
    for (const c of CHANNELS) {
      const el = document.querySelector<HTMLElement>(`[data-agent-channel="${c.id}"]`)!;
      expect(el.getAttribute("data-agent-name")).toBe(c.agent);
      // 名称与目标文件分开显示（目标文件在 `.agent-row-target` 里）
      expect(el.querySelector(".agent-row-name")?.textContent).toBeTruthy();
      expect(el.querySelector(".agent-row-target")?.textContent).toBeTruthy();
    }
  });

  it("③ 旧「通道」下拉已不存在", async () => {
    renderPage();
    await waitFor(() => expect(rows().length).toBe(CHANNELS.length));
    // 用可及性树而不是字面 `[role="combobox"]`：原生 `<select>` 没有 role 属性，
    // 旧写法恒真（M30-S2 P2-2 复发，M31 复审 P2-3）。旧实现有站点/密钥两个
    // select（通道是卡片按钮，不是 select），这里会是 2；新实现只剩顶部站点一个
    // select（mock 的所有行未安装，所以行内 key 下拉也不出现）。
    expect(screen.queryAllByRole("combobox")).toHaveLength(1);
    expect(Object.prototype.hasOwnProperty.call(zhCN.agents.select, "channel")).toBe(false);
    const labelled = Array.from(document.querySelectorAll("label")).filter(
      (l) => l.querySelector("span")?.textContent?.trim() === "通道",
    );
    expect(labelled.length).toBe(0);
  });

  it("④ 旧 M30 卡片网格样式类不再出现", async () => {
    renderPage();
    await waitFor(() => expect(rows().length).toBe(CHANNELS.length));
    expect(document.querySelector(".agent-grid")).toBeNull();
    expect(document.querySelector(".agent-choice")).toBeNull();
    expect(document.querySelector(".agent-list")).not.toBeNull();
    expect(detectAgents).toHaveBeenCalled();
  });
});
