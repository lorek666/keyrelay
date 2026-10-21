import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import Agents, { CHANNELS } from "../pages/Agents";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M31-S1：Agent 单列工作台的行为。
 *
 * 钉死：20 行顺序、已安装显示版本、未安装显示「未安装」+「安装」、
 * 安装弹窗展示命令、每行 key/model **互不影响**、localStorage 恢复、
 * 切换站点不串台、展开行把**自己的**参数交给 deliveryPlan、未安装行不调 deliveryPlan。
 */

const SITE_A = 11;
const SITE_B = 22;

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    listSites: vi.fn(async () => [
      {
        id: SITE_A, kind: "newapi", baseUrl: "https://a.example.test", displayName: "站点A",
        health: "ok", loginField: "username",
        capabilities: { login: true, listKeys: true, createKey: true, revealKey: true, revokeKey: true, balance: true, groups: true, keyUsage: false },
      },
      {
        id: SITE_B, kind: "newapi", baseUrl: "https://b.example.test", displayName: "站点B",
        health: "ok", loginField: "username",
        capabilities: { login: true, listKeys: true, createKey: true, revealKey: true, revokeKey: true, balance: true, groups: true, keyUsage: false },
      },
    ]),
    listStoredKeys: vi.fn(async () => [
      { id: 101, siteId: SITE_A, name: "a-key", status: "enabled" },
      { id: 102, siteId: SITE_A, name: "a-key-2", status: "enabled" },
      { id: 201, siteId: SITE_B, name: "b-key", status: "enabled" },
    ]),
    listConsents: vi.fn(async () => []),
    detectUnmanagedTargets: vi.fn(async () => []),
    detectAgents: vi.fn(async () => {
      // spec §4.2：mock 至少 3 个已安装（codex-auth-json / claude-code-settings / dsh），
      // 其余未安装。两个已安装行是「每行 key/model 隔离」的必要夹具。
      const INSTALLED: Record<string, string> = {
        "codex-auth-json": "0.162.1",
        "claude-code-settings": "2.1.296",
        dsh: "0.2.1-rc.2",
        opencode: "1.4.0",
      };
      return CHANNELS.map((c) =>
        INSTALLED[c.id]
          ? { channel: c.id, installed: true, version: INSTALLED[c.id], source: `/usr/local/bin/${c.agent}`, detail: null,
              installCommands: [{ via: "npm", command: `npm i -g ${c.id}` }], installUrl: "https://example.test/install" }
          : { channel: c.id, installed: false, version: null, source: null, detail: null,
              installCommands: [{ via: "npm", command: `npm i -g ${c.id}` }], installUrl: "https://example.test/install" },
      );
    }),
    deliveryPlan: vi.fn(async () => ({
      agentId: "codex", channel: "codex-auth-json", targetPath: "/home/u/.codex/auth.json",
      targetExists: true, mode: "site", fields: [], endpointInChannel: false,
      preview: "@@ -1 +1 @@\n-A\n+B\n", consent: "granted", restartHint: "none", warnings: [],
    })),
  };
});

import { deliveryPlan } from "../lib/api";

const rows = () => Array.from(document.querySelectorAll<HTMLElement>("[data-agent-channel]"));
const row = (id: string) => document.querySelector<HTMLElement>(`[data-agent-channel="${id}"]`)!;
const keySelect = (id: string) => row(id).querySelector<HTMLSelectElement>(".agent-row-key")!;
const modelInput = (id: string) => row(id).querySelector<HTMLInputElement>(".agent-row-model")!;

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

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
});

describe("M31-S1 Agent 工作台", () => {
  it("① 20 行、顺序与 CHANNELS 一致", async () => {
    renderPage();
    await waitFor(() => expect(rows().length).toBe(20));
    expect(rows().map((r) => r.getAttribute("data-agent-channel"))).toEqual(CHANNELS.map((c) => c.id));
  });

  it("② 已安装行显示版本；未安装行显示「未安装」+「安装」且没有密钥下拉", async () => {
    renderPage();
    await waitFor(() => expect(rows().length).toBe(20));
    await waitFor(() => expect(row("codex-auth-json").textContent).toContain("0.162.1"));

    expect(keySelect("codex-auth-json")).not.toBeNull();

    const gemini = row("gemini-cli");
    expect(gemini.textContent).toContain(zhCN.agents.row.notInstalled);
    expect(gemini.querySelector(".agent-row-install")).not.toBeNull();
    expect(gemini.querySelector(".agent-row-key")).toBeNull();
    expect(gemini.querySelector(".agent-row-model")).toBeNull();
  });

  it("③ 点「安装」弹窗显示命令与复制按钮", async () => {
    renderPage();
    await waitFor(() => expect(row("gemini-cli").querySelector(".agent-row-install")).not.toBeNull());
    fireEvent.click(row("gemini-cli").querySelector(".agent-row-install")!);

    await waitFor(() => expect(document.querySelector("dialog[open]")).not.toBeNull());
    const dialog = document.querySelector("dialog[open]")!;
    expect(dialog.textContent).toContain("npm i -g gemini-cli");
    expect(dialog.textContent).toContain(zhCN.agents.install.copy);
    expect(dialog.textContent).toContain(zhCN.agents.install.redetect);

    // Esc（原生 dialog 的 cancel）必须把 React 的 open 一起关掉；
    // 否则元素关了、state 还是 true，再点「安装」不会重新 showModal。
    fireEvent(dialog, new Event("cancel", { cancelable: true }));
    await waitFor(() => expect(document.querySelector("dialog[open]")).toBeNull());
    fireEvent.click(row("gemini-cli").querySelector(".agent-row-install")!);
    await waitFor(() => expect(document.querySelector("dialog[open]")).not.toBeNull());
  });

  it("④ 两行的 key/model 互不影响，且写入 localStorage", async () => {
    renderPage();
    await waitFor(() => expect(keySelect("claude-code-settings")).not.toBeNull());
    await waitFor(() => expect(keySelect("opencode")).not.toBeNull());

    // 第 1 行：key=101 / model=model-a
    fireEvent.change(keySelect("claude-code-settings"), { target: { value: "101" } });
    fireEvent.change(modelInput("claude-code-settings"), { target: { value: "model-a" } });

    // 第 2 行：key=102 / model=model-b
    fireEvent.change(keySelect("opencode"), { target: { value: "102" } });
    fireEvent.change(modelInput("opencode"), { target: { value: "model-b" } });

    await waitFor(() => expect(keySelect("claude-code-settings").value).toBe("101"));
    expect(keySelect("opencode").value).toBe("102");

    // 隔离：改第 2 行的 key 不影响第 1 行
    fireEvent.change(keySelect("opencode"), { target: { value: "101" } });
    expect(keySelect("claude-code-settings").value).toBe("101");
    expect(keySelect("opencode").value).toBe("101");

    // 模型各自独立（等 400ms 防抖落盘）
    await waitFor(
      () => {
        const raw = localStorage.getItem(`keyrelay.agentPrefs.v1.${SITE_A}`);
        expect(raw).toBeTruthy();
        const parsed = JSON.parse(raw!);
        expect(parsed["claude-code-settings"].model).toBe("model-a");
        expect(parsed.opencode.model).toBe("model-b");
      },
      { timeout: 2000 },
    );
  });

  it("⑤ 同一站点重新渲染时从 localStorage 恢复", async () => {
    localStorage.setItem(
      `keyrelay.agentPrefs.v1.${SITE_A}`,
      JSON.stringify({ "claude-code-settings": { keyId: 102, model: "restored-model" } }),
    );
    renderPage();
    await waitFor(() => expect(keySelect("claude-code-settings")).not.toBeNull());
    await waitFor(() => expect(keySelect("claude-code-settings").value).toBe("102"));
    expect(modelInput("claude-code-settings").value).toBe("restored-model");
  });

  it("⑥ 切换站点加载该站点偏好，不串台", async () => {
    localStorage.setItem(
      `keyrelay.agentPrefs.v1.${SITE_A}`,
      JSON.stringify({ "claude-code-settings": { keyId: 101, model: "a" } }),
    );
    localStorage.setItem(
      `keyrelay.agentPrefs.v1.${SITE_B}`,
      JSON.stringify({ "claude-code-settings": { keyId: 201, model: "b" } }),
    );
    renderPage();
    await waitFor(() => expect(keySelect("claude-code-settings").value).toBe("101"));

    const siteSelect = document.querySelector<HTMLSelectElement>("select")!;
    fireEvent.change(siteSelect, { target: { value: String(SITE_B) } });

    await waitFor(() => expect(keySelect("claude-code-settings").value).toBe("201"));
    expect(modelInput("claude-code-settings").value).toBe("b");
  });

  it("⑦ 展开行把该行参数交给 deliveryPlan；未安装行不调用", async () => {
    renderPage();
    await waitFor(() => expect(keySelect("codex-auth-json")).not.toBeNull());

    // 未展开任何行时不该有调用
    expect(deliveryPlan).not.toHaveBeenCalled();

    fireEvent.change(keySelect("codex-auth-json"), { target: { value: "101" } });
    fireEvent.click(row("codex-auth-json").querySelector(".agent-row-toggle")!);

    await waitFor(() => expect(deliveryPlan).toHaveBeenCalled());
    const arg = (deliveryPlan as unknown as { mock: { calls: unknown[][] } }).mock.calls.at(-1)![0];
    expect(arg).toMatchObject({ keyId: 101, channel: "codex-auth-json" });

    // 未安装行没有展开按钮 ⇒ 不可能触发查询
    expect(row("gemini-cli").querySelector(".agent-row-toggle")).toBeNull();
  });

  it("⑧ 不写模型的落点显示说明、没有 model 输入", async () => {
    renderPage();
    await waitFor(() => expect(keySelect("codex-auth-json")).not.toBeNull());
    expect(row("codex-auth-json").querySelector(".agent-row-model")).toBeNull();
    expect(row("codex-auth-json").textContent).toContain(zhCN.agents.row.noModel);
  });

  it("⑨ 展开行的 model 与网关模式都进 deliveryPlan 参数（不是全局旧值）", async () => {
    renderPage();
    await waitFor(() => expect(keySelect("opencode")).not.toBeNull());

    fireEvent.change(keySelect("opencode"), { target: { value: "102" } });
    fireEvent.change(modelInput("opencode"), { target: { value: "gpt-x" } });
    // 模型输入有 400ms 防抖；等它进查询键后再展开，否则 plan 拿到的是空 model。
    await new Promise((resolve) => setTimeout(resolve, 450));
    // 页面上唯一的 checkbox 是顶部「指向本地网关」
    fireEvent.click(document.querySelector<HTMLInputElement>('input[type="checkbox"]')!);
    fireEvent.click(row("opencode").querySelector(".agent-row-toggle")!);

    await waitFor(() => expect(deliveryPlan).toHaveBeenCalled());
    const arg = (deliveryPlan as unknown as { mock: { calls: unknown[][] } }).mock.calls.at(-1)![0];
    expect(arg).toMatchObject({
      keyId: 102,
      channel: "opencode",
      model: "gpt-x",
      mode: "gateway",
    });
  });

  it("⑩ 已回收/不存在的 keyId 不拿去查预览", async () => {
    localStorage.setItem(
      `keyrelay.agentPrefs.v1.${SITE_A}`,
      JSON.stringify({ "claude-code-settings": { keyId: 999, model: "stale" } }),
    );
    renderPage();
    await waitFor(() => expect(keySelect("claude-code-settings")).not.toBeNull());
    expect(keySelect("claude-code-settings").value).toBe("");

    fireEvent.click(row("claude-code-settings").querySelector(".agent-row-toggle")!);
    await waitFor(() => expect(document.querySelector(".agent-row-plan")).not.toBeNull());
    expect(deliveryPlan).not.toHaveBeenCalled();
  });

  it("⑪ 切换站点会收起展开行并清空同意勾选", async () => {
    localStorage.setItem(
      `keyrelay.agentPrefs.v1.${SITE_A}`,
      JSON.stringify({ "codex-auth-json": { keyId: 101, model: "" } }),
    );
    localStorage.setItem(
      `keyrelay.agentPrefs.v1.${SITE_B}`,
      JSON.stringify({ "codex-auth-json": { keyId: 201, model: "" } }),
    );
    renderPage();
    await waitFor(() => expect(keySelect("codex-auth-json").value).toBe("101"));

    fireEvent.click(row("codex-auth-json").querySelector(".agent-row-toggle")!);
    await waitFor(() => expect(document.querySelector(".agent-row-plan")).not.toBeNull());
    const consent = () =>
      document.querySelector<HTMLInputElement>(".agent-row-plan .checkline input[type=checkbox]");
    await waitFor(() => expect(consent()).not.toBeNull());
    fireEvent.click(consent()!);
    expect(consent()!.checked).toBe(true);

    // 切站：prefs 换成 B 的 key，展开行收起，同意勾选重置。
    fireEvent.change(document.querySelector<HTMLSelectElement>("select")!, {
      target: { value: String(SITE_B) },
    });
    await waitFor(() => expect(keySelect("codex-auth-json").value).toBe("201"));
    expect(document.querySelector(".agent-row-plan")).toBeNull();

    fireEvent.click(row("codex-auth-json").querySelector(".agent-row-toggle")!);
    await waitFor(() => expect(consent()).not.toBeNull());
    expect(consent()!.checked).toBe(false);
  });
});
