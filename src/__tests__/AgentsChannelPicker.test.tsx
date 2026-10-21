import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import Agents, { CHANNELS } from "../pages/Agents";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M30-S2：Agent 投递页把全部落点铺开成卡片。
 *
 * 钉死四件事：
 * ① 卡片数量与 `CHANNELS` **严格相等**（不合并同 agent 的多个落点）；
 * ② 默认第一张选中；
 * ③ 点另一张能切换选中态；
 * ④ 原「通道」下拉框**不再存在**（否则用户仍可能只看到被下拉藏起来的一个落点）。
 *
 * 不依赖网络：所有查询都 mock 成空数组，`deliveryPlan` 因未选密钥而不会启用。
 */

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    listSites: vi.fn(async () => []),
    listStoredKeys: vi.fn(async () => []),
    listConsents: vi.fn(async () => []),
    detectUnmanagedTargets: vi.fn(async () => []),
    deliveryPlan: vi.fn(async () => {
      throw new Error("deliveryPlan 不该在未选密钥时被调用");
    }),
  };
});

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

/** 全部落点卡片（按 DOM 顺序）。 */
function cards(): HTMLElement[] {
  return Array.from(document.querySelectorAll<HTMLElement>("[data-agent-channel]"));
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("M30-S2 Agent 落点卡片", () => {
  it("① 每个落点一张卡，数量与 CHANNELS 相等且 20 个 id 全在", async () => {
    renderPage();

    // 等首屏查询落定（三个 useQuery 都是 async）
    await waitFor(() => expect(screen.getByText(zhCN.agents.picker.hint)).toBeTruthy());

    const all = cards();
    expect(all.length).toBe(CHANNELS.length);
    expect(CHANNELS.length).toBe(20);

    const renderedIds = all.map((el) => el.getAttribute("data-agent-channel"));
    expect(new Set(renderedIds).size).toBe(CHANNELS.length);
    for (const c of CHANNELS) {
      expect(renderedIds).toContain(c.id);
    }

    // 每张卡都同时显示落点标签与稳定 agent id
    for (const c of CHANNELS) {
      const el = document.querySelector<HTMLElement>(`[data-agent-channel="${c.id}"]`)!;
      expect(el.textContent).toContain(c.label);
      expect(el.textContent).toContain(c.agent);
    }
  });

  it("② 默认第一张卡片 aria-pressed=true，其余为 false", async () => {
    renderPage();
    await waitFor(() => expect(cards().length).toBe(CHANNELS.length));

    const all = cards();
    expect(all[0].getAttribute("aria-pressed")).toBe("true");
    expect(all[0].classList.contains("selected")).toBe(true);

    for (const el of all.slice(1)) {
      expect(el.getAttribute("aria-pressed")).toBe("false");
      expect(el.classList.contains("selected")).toBe(false);
    }
  });

  it("③ 点「Gemini CLI」后它选中、第一张取消选中", async () => {
    renderPage();
    await waitFor(() => expect(cards().length).toBe(CHANNELS.length));

    const first = cards()[0];
    const gemini = document.querySelector<HTMLElement>('[data-agent-channel="gemini-cli"]')!;
    expect(gemini.textContent).toContain("Gemini CLI");

    fireEvent.click(gemini);

    await waitFor(() => expect(gemini.getAttribute("aria-pressed")).toBe("true"));
    expect(gemini.classList.contains("selected")).toBe(true);
    expect(first.getAttribute("aria-pressed")).toBe("false");
    expect(first.classList.contains("selected")).toBe(false);
  });

  it("④ 页面不再有「通道」下拉框", async () => {
    renderPage();
    await waitFor(() => expect(cards().length).toBe(CHANNELS.length));

    // 页面上不应残留任何 combobox（旧实现是 <select>）
    // 注意：站点 / 密钥两个下拉仍在（M30-S2 不动它们），所以不能断言「页面上没有 select」
    expect(document.querySelectorAll('[role="combobox"]').length).toBe(0);

    // i18n 的 `agents.select.channel` 已删除
    expect(Object.prototype.hasOwnProperty.call(zhCN.agents.select, "channel")).toBe(false);

    // 也不该有以「通道」为**标签**的字段（注意：正文里出现「向该通道投递」是合法文案，
    // 所以不能对整页文本做 blanket 断言——那会把正常文案一起判红）
    const labelled = Array.from(document.querySelectorAll("label")).filter(
      (l) => l.querySelector("span")?.textContent?.trim() === "通道",
    );
    expect(labelled.length).toBe(0);
  });
});
