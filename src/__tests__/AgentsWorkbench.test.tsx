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
 * 钉死：19 行顺序（B-292：Cline Desktop 已下线）、已安装显示版本、未安装显示「未安装」+「安装」、
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
    // M32-S1：模型清单按 keyId 返回（与任务书一致）
    listKeyModels: vi.fn(async (keyId: number) => {
      if (keyId === 101) return ["model-a", "model-b"];
      if (keyId === 102) return ["model-c", "gpt-x"];
      if (keyId === 201) return ["model-b"];
      return [];
    }),
    deliveryPlan: vi.fn(async () => ({
      agentId: "codex", channel: "codex-auth-json", targetPath: "/home/u/.codex/auth.json",
      targetExists: true, mode: "site", fields: [], endpointInChannel: false,
      preview: "@@ -1 +1 @@\n-A\n+B\n", consent: "granted", restartHint: "none", warnings: [],
    })),
    // P1-5：一键重启 mock（daemon 状态恒为 unverified，前端不得画成已通过）。
    restartCodex: vi.fn(async () => ({
      target: "codex", wasRunning: true, quitMethod: "pkill", forceKilled: false,
      relaunched: true, appeared: true, manualLaunchCommand: "codex",
      appServerDaemonStatus: "unverified", appServerDaemonNote: "后端 daemon 说明",
    })),
    restartClaudeDesktop: vi.fn(async () => ({
      target: "claude-desktop", wasRunning: false, quitMethod: "none", forceKilled: false,
      relaunched: true, appeared: true, manualLaunchCommand: null,
      appServerDaemonStatus: "unverified", appServerDaemonNote: "",
    })),
  };
});

import { deliveryPlan, listKeyModels, restartCodex } from "../lib/api";

const rows = () => Array.from(document.querySelectorAll<HTMLElement>("[data-agent-channel]"));
const row = (id: string) => document.querySelector<HTMLElement>(`[data-agent-channel="${id}"]`)!;
const keySelect = (id: string) => row(id).querySelector<HTMLSelectElement>(".agent-row-key")!;
/** 模型控件：有清单时是 <select>，回退时是 <input>。两者都用同一个 class。 */
const modelControl = (id: string) =>
  row(id).querySelector<HTMLSelectElement | HTMLInputElement>(".agent-row-model")!;
const modelSelect = (id: string) => row(id).querySelector<HTMLSelectElement>("select.agent-row-model")!;
/** 当前模型下拉的全部 option value（loading 时只有占位项 ''）。 */
const optionValues = (id: string) =>
  Array.from(row(id).querySelector<HTMLSelectElement>("select.agent-row-model")?.options ?? []).map(
    (o) => o.value,
  );

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
  it("① 19 行、顺序与 CHANNELS 一致", async () => {
    renderPage();
    await waitFor(() => expect(rows().length).toBe(19));
    expect(rows().map((r) => r.getAttribute("data-agent-channel"))).toEqual(CHANNELS.map((c) => c.id));
  });

  it("② 已安装行显示版本；未安装行显示「未安装」+「安装」且没有密钥下拉", async () => {
    renderPage();
    await waitFor(() => expect(rows().length).toBe(19));
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
    await waitFor(() =>
      expect(optionValues("claude-code-settings")).toContain("model-a"),
    );
    fireEvent.change(modelSelect("claude-code-settings"), { target: { value: "model-a" } });

    // 第 2 行：key=102 / model=model-b
    fireEvent.change(keySelect("opencode"), { target: { value: "102" } });
    await waitFor(() => expect(optionValues("opencode")).toContain("model-c"));
    fireEvent.change(modelSelect("opencode"), { target: { value: "model-c" } });

    await waitFor(() => expect(keySelect("claude-code-settings").value).toBe("101"));
    expect(keySelect("opencode").value).toBe("102");

    // 隔离：改第 2 行的 key 不影响第 1 行
    fireEvent.change(keySelect("opencode"), { target: { value: "101" } });
    expect(keySelect("claude-code-settings").value).toBe("101");
    expect(keySelect("opencode").value).toBe("101");

    // 模型各自独立（等 400ms 防抖落盘）
    await waitFor(
      () => {
        const raw = localStorage.getItem(`tianshu-relay.agentPrefs.v1.${SITE_A}`);
        expect(raw).toBeTruthy();
        const parsed = JSON.parse(raw!);
        expect(parsed["claude-code-settings"].model).toBe("model-a");
        expect(parsed.opencode.model).toBe("model-c");
      },
      { timeout: 2000 },
    );
  });

  it("⑤ 同一站点重新渲染时从 localStorage 恢复", async () => {
    localStorage.setItem(
      `tianshu-relay.agentPrefs.v1.${SITE_A}`,
      JSON.stringify({ "claude-code-settings": { keyId: 102, model: "restored-model" } }),
    );
    renderPage();
    await waitFor(() => expect(keySelect("claude-code-settings")).not.toBeNull());
    await waitFor(() => expect(keySelect("claude-code-settings").value).toBe("102"));
    // 102 的清单是 ["model-c","gpt-x"]，"restored-model" 不在里面
    // ⇒ 必须追加为同值 option 并保持选中（不得静默清空）
    await waitFor(() => expect(modelSelect("claude-code-settings")).not.toBeNull());
    expect(modelSelect("claude-code-settings").value).toBe("restored-model");
  });

  it("⑥ 切换站点加载该站点偏好，不串台", async () => {
    localStorage.setItem(
      `tianshu-relay.agentPrefs.v1.${SITE_A}`,
      JSON.stringify({ "claude-code-settings": { keyId: 101, model: "a" } }),
    );
    localStorage.setItem(
      `tianshu-relay.agentPrefs.v1.${SITE_B}`,
      JSON.stringify({ "claude-code-settings": { keyId: 201, model: "b" } }),
    );
    renderPage();
    await waitFor(() => expect(keySelect("claude-code-settings").value).toBe("101"));

    const siteSelect = document.querySelector<HTMLSelectElement>("select")!;
    fireEvent.change(siteSelect, { target: { value: String(SITE_B) } });

    await waitFor(() => expect(keySelect("claude-code-settings").value).toBe("201"));
    expect(modelSelect("claude-code-settings").value).toBe("b");
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
    await waitFor(() => expect(optionValues("opencode")).toContain("gpt-x"));
    fireEvent.change(modelSelect("opencode"), { target: { value: "gpt-x" } });
    // 模型输入有 400ms 防抖；等它进查询键后再展开，否则 plan 拿到的是空 model。
    await new Promise((resolve) => setTimeout(resolve, 450));
    // P0-4：投递方式默认就是网关（双单选的第一项、带「推荐」），无需再点选；
    // 展开后首次 plan 即应为 gateway，直连是次选、默认不选中。
    const radios = document.querySelectorAll<HTMLInputElement>('input[type="radio"]');
    expect(radios.length).toBe(2);
    expect(radios[0].checked).toBe(true);
    expect(radios[1].checked).toBe(false);
    fireEvent.click(row("opencode").querySelector(".agent-row-toggle")!);

    await waitFor(() => expect(deliveryPlan).toHaveBeenCalled());
    const arg = (deliveryPlan as unknown as { mock: { calls: unknown[][] } }).mock.calls.at(-1)![0];
    expect(arg).toMatchObject({
      keyId: 102,
      channel: "opencode",
      model: "gpt-x",
      mode: "gateway",
    });

    // 切到次选的站点直连后，plan 参数随之变为 site（仍可选，只是不默认）。
    fireEvent.click(radios[1]);
    await waitFor(() => {
      const last = (deliveryPlan as unknown as { mock: { calls: unknown[][] } }).mock.calls.at(-1)![0];
      expect(last).toMatchObject({ mode: "site" });
    });
  });

  // ------------------------------------------------------------------ M32-S1

  it("⑫ 19 行都没有 .agent-row-target，页面文本不含 ~/.mimocode/", async () => {
    renderPage();
    await waitFor(() => expect(rows().length).toBe(19));

    expect(document.querySelectorAll(".agent-row-target").length).toBe(0);
    expect(document.body.textContent ?? "").not.toContain("~/.mimocode/");
    // 顺带确认名称仍然正确（去掉路径不能把名称也弄丢）
    expect(row("mimo-code").querySelector(".agent-row-name")?.textContent).toBe("MiMo Code");
    // 未选密钥时不应发模型清单请求（enabled: keyId !== null）
    expect(listKeyModels).not.toHaveBeenCalled();

    // 安装弹窗标题/aria-label 也不能把路径带回来（复审 P2-1）
    await waitFor(() => expect(row("mimo-code").querySelector(".agent-row-install")).not.toBeNull());
    fireEvent.click(row("mimo-code").querySelector(".agent-row-install")!);
    await waitFor(() => expect(document.querySelector("dialog[open]")).not.toBeNull());
    const dialog = document.querySelector("dialog[open]")!;
    expect(dialog.textContent).toContain("MiMo Code");
    expect(dialog.textContent ?? "").not.toContain("~/.mimocode/");
    expect(dialog.getAttribute("aria-label") ?? "").not.toContain("~/.mimocode/");
    fireEvent(dialog, new Event("cancel", { cancelable: true }));
  });

  it("⑬ 选 key 101 后下拉含 model-a/model-b；换 key 102 后变成该 key 的清单", async () => {
    renderPage();
    await waitFor(() => expect(keySelect("claude-code-settings")).not.toBeNull());

    fireEvent.change(keySelect("claude-code-settings"), { target: { value: "101" } });
    await waitFor(() => expect(optionValues("claude-code-settings")).toContain("model-a"));
    let opts = optionValues("claude-code-settings");
    expect(opts).toContain("model-a");
    expect(opts).toContain("model-b");

    fireEvent.change(keySelect("claude-code-settings"), { target: { value: "102" } });
    await waitFor(() => expect(optionValues("claude-code-settings")).toContain("model-c"));
    opts = optionValues("claude-code-settings");
    expect(opts).not.toContain("model-a");
  });

  it("⑭ 已保存但不在清单的 model 仍作为选中项出现", async () => {
    localStorage.setItem(
      `tianshu-relay.agentPrefs.v1.${SITE_A}`,
      JSON.stringify({ "claude-code-settings": { keyId: 101, model: "legacy-model" } }),
    );
    renderPage();
    await waitFor(() => expect(modelSelect("claude-code-settings")?.value).toBe("legacy-model"));
    const sel = modelSelect("claude-code-settings");
    expect(sel.value).toBe("legacy-model");
    expect(Array.from(sel.options).map((o) => o.value)).toContain("legacy-model");
  });

  it("⑮ listKeyModels 失败 ⇒ 回退 input + 提示，手输值能进 deliveryPlan", async () => {
    const { listKeyModels } = await import("../lib/api");
    (listKeyModels as unknown as { mockRejectedValueOnce: (e: Error) => void })
      .mockRejectedValueOnce(new Error("boom"));

    renderPage();
    await waitFor(() => expect(keySelect("claude-code-settings")).not.toBeNull());
    fireEvent.change(keySelect("claude-code-settings"), { target: { value: "101" } });

    await waitFor(() =>
      expect(row("claude-code-settings").textContent).toContain(zhCN.agents.select.modelFetchFailed),
    );
    const input = row("claude-code-settings").querySelector<HTMLInputElement>("input.agent-row-model")!;
    expect(input).not.toBeNull();
    fireEvent.change(input, { target: { value: "manual-model" } });

    // 等 400ms 防抖进查询键，再展开
    await new Promise((r) => setTimeout(r, 450));
    fireEvent.click(row("claude-code-settings").querySelector(".agent-row-toggle")!);

    await waitFor(() => expect(deliveryPlan).toHaveBeenCalled());
    const arg = (deliveryPlan as unknown as { mock: { calls: unknown[][] } }).mock.calls.at(-1)![0];
    expect(arg).toMatchObject({ keyId: 101, channel: "claude-code-settings", model: "manual-model" });
  });

  it("⑯ 失败态点重试 ⇒ 查询中禁用并显示「重试中…」，成功后出现下拉（M37-S1）", async () => {
    const { listKeyModels } = await import("../lib/api");
    const mock = listKeyModels as unknown as {
      mockRejectedValueOnce: (e: Error) => void;
      mockImplementationOnce: (fn: () => Promise<string[]>) => void;
    };
    mock.mockRejectedValueOnce(new Error("boom"));
    // 第二次调用挂起，直到测试手动放行 ⇒ 能确定性地断言「重试中」状态
    let resolveRetry: (models: string[]) => void = () => {};
    mock.mockImplementationOnce(
      () =>
        new Promise<string[]>((resolve) => {
          resolveRetry = resolve;
        }),
    );

    renderPage();
    await waitFor(() => expect(keySelect("claude-code-settings")).not.toBeNull());
    fireEvent.change(keySelect("claude-code-settings"), { target: { value: "101" } });

    // 失败态：输入框 + 提示 + 「重试」按钮
    await waitFor(() =>
      expect(row("claude-code-settings").textContent).toContain(zhCN.agents.select.modelFetchFailed),
    );
    expect(row("claude-code-settings").querySelector("input.agent-row-model")).not.toBeNull();
    // 每次重新查询 DOM（重渲染可能换节点，持有旧引用会读到过期的 disabled）
    const retryButton = () =>
      row("claude-code-settings").querySelector<HTMLButtonElement>(".agent-row-model-retry");
    expect(retryButton()).not.toBeNull();
    expect(retryButton()!.textContent).toContain(zhCN.agents.select.modelRetry);
    expect(retryButton()!.disabled).toBe(false);

    fireEvent.click(retryButton()!);

    // 重试进行中：按钮禁用 + 文案变「重试中…」
    await waitFor(() => expect(retryButton()!.disabled).toBe(true));
    expect(retryButton()!.textContent).toContain(zhCN.agents.select.modelRetrying);

    // 放行第二次请求 ⇒ 下拉出现且选项正确（不再停在手填）
    resolveRetry(["model-a", "model-b"]);
    await waitFor(() => expect(modelSelect("claude-code-settings")).not.toBeNull());
    expect(optionValues("claude-code-settings")).toEqual(["", "model-a", "model-b"]);
    expect(row("claude-code-settings").querySelector(".agent-row-model-retry")).toBeNull();
  });

  it("⑩ 已回收/不存在的 keyId 不拿去查预览", async () => {
    localStorage.setItem(
      `tianshu-relay.agentPrefs.v1.${SITE_A}`,
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
      `tianshu-relay.agentPrefs.v1.${SITE_A}`,
      JSON.stringify({ "codex-auth-json": { keyId: 101, model: "" } }),
    );
    localStorage.setItem(
      `tianshu-relay.agentPrefs.v1.${SITE_B}`,
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

  it("⑫ P1-5：Codex 行有重启按钮，确认框先说明中断、确认后才调重启", async () => {
    renderPage();
    await waitFor(() => expect(keySelect("codex-auth-json")).not.toBeNull());
    fireEvent.click(row("codex-auth-json").querySelector(".agent-row-toggle")!);
    await waitFor(() => expect(document.querySelector(".agent-row-plan")).not.toBeNull());

    const plan = document.querySelector(".agent-row-plan")!;
    expect(plan.textContent).toContain(zhCN.agents.restart.codexTitle);
    expect(plan.textContent).toContain(zhCN.agents.restart.button);
    expect(plan.textContent).toContain(zhCN.agents.restart.daemonUnverified);

    // 点重启按钮只开确认框，不调后端。
    const restartBtn = Array.from(plan.querySelectorAll("button")).find((b) =>
      b.textContent?.includes(zhCN.agents.restart.button),
    )!;
    fireEvent.click(restartBtn);
    await waitFor(() => expect(document.querySelector("dialog[open]")).not.toBeNull());
    expect(restartCodex).not.toHaveBeenCalled();
    const dialog = document.querySelector("dialog[open]")!;
    expect(dialog.textContent).toContain(zhCN.agents.restart.codexConfirmBody);
    expect(dialog.textContent).toContain(zhCN.agents.restart.codexConfirmCliNote);

    // 点确认才调重启；结果渲染「ChatGPT 桌面应用已退出并重新拉起」与 daemon 未验证项，
    // 且成功文案只说桌面应用已出现、不暗示终端 codex 会话已重读新配置。
    const confirmBtn = Array.from(dialog.querySelectorAll("button")).find((b) =>
      b.textContent?.includes(zhCN.agents.restart.confirm),
    )!;
    fireEvent.click(confirmBtn);
    await waitFor(() => expect(restartCodex).toHaveBeenCalled());
    await waitFor(() => expect(plan.textContent).toContain(zhCN.agents.restart.codexResultWasRunning));
    await waitFor(() => expect(plan.textContent).toContain(zhCN.agents.restart.codexResultAppeared));
    expect(plan.textContent).toContain("后端 daemon 说明");
  });

  it("⑬ P1-5：CLI 行没有重启按钮，只有可复制启动命令", async () => {
    renderPage();
    await waitFor(() => expect(keySelect("claude-code-settings")).not.toBeNull());
    fireEvent.click(row("claude-code-settings").querySelector(".agent-row-toggle")!);
    await waitFor(() => expect(document.querySelector(".agent-row-plan")).not.toBeNull());
    const plan = document.querySelector(".agent-row-plan")!;
    expect(plan.textContent).not.toContain(zhCN.agents.restart.button);
    expect(plan.textContent).toContain(zhCN.agents.restart.cliTitle);
    expect(plan.textContent).toContain("claude");
  });
});

describe("P1-7 首次导入 + 预览模式 + 落点变体", () => {
  // 本 describe 只测 UI 接线（DTO 驱动渲染）：plan 由 mock 按入参回填，
  // 后端变体白名单与只读导入的语义由核心层集成测试钉住，不在这里复测。
  const fullPlan = (args: {
    previewOnly?: boolean;
    targetVariant?: string;
    targetVariants?: string[];
    importedFields?: { key: string; masked: string }[];
    isFirstDelivery?: boolean;
  }) => ({
    agentId: "codex",
    channel: "codex-auth-json",
    targetPath: "/home/u/.codex/auth.json",
    targetExists: true,
    mode: "site",
    fields: [{ key: "OPENAI_API_KEY", masked: "…9999" }],
    endpointInChannel: false,
    preview: '- "OPENAI_API_KEY": "…0000"\n+ "OPENAI_API_KEY": "…9999"\n',
    consent: "missing",
    consentGrantedAt: null,
    consentRevokedAt: null,
    warnings: [],
    restartHint: "needed",
    restartHintSource: "unverified",
    restartHintAction: "codexSplit",
    preserveAuth: false,
    files: [
      {
        channel: "codex-auth-json",
        targetPath: "/home/u/.codex/auth.json",
        targetExists: true,
        fields: [{ key: "OPENAI_API_KEY", masked: "…9999" }],
        preview: '- "OPENAI_API_KEY": "…0000"\n+ "OPENAI_API_KEY": "…9999"\n',
        consent: "missing",
        consentGrantedAt: null,
        consentRevokedAt: null,
        isFirstDelivery: args.isFirstDelivery ?? false,
        importedFields: args.importedFields ?? [],
      },
    ],
    dshCredentialReference: null,
    previewOnly: args.previewOnly ?? false,
    isFirstDelivery: args.isFirstDelivery ?? false,
    importedFields: args.importedFields ?? [],
    targetVariant: args.targetVariant ?? "default",
    targetVariants: args.targetVariants ?? ["default"],
    // P2-8：工作台 mock 默认无模型输入 ⇒ 静态不适用、探针跳过、不拦；
    // PlanView 的验证段按此渲染，不影响既有用例的按钮状态。
    modelValidation: {
      model: null,
      staticOutcome: "not_applicable",
      staticCode: "no_model",
      probeOutcome: "skipped",
      probeCode: "skipped",
      probeStatus: null,
      blocksDelivery: false,
    },
  });

  const lastPlanArg = () =>
    (deliveryPlan as unknown as { mock: { calls: unknown[][] } }).mock.calls.at(-1)![0] as Record<
      string,
      unknown
    >;

  const previewToggle = () =>
    Array.from(document.querySelectorAll<HTMLInputElement>("input[type=checkbox]")).find((c) =>
      c.closest("label")?.textContent?.includes(zhCN.agents.plan.previewOnlyToggle),
    )!;

  it("仅预览开关：plan 参数带 previewOnly，横幅出现、投递按钮消失", async () => {
    vi.mocked(deliveryPlan).mockImplementation(async (args: {
      previewOnly?: boolean;
    }) => fullPlan({ previewOnly: args.previewOnly === true }) as never);
    renderPage();
    await waitFor(() => expect(keySelect("codex-auth-json")).not.toBeNull());
    // 先选密钥，否则预览查询因 activeKey 为空而不启用（见测试⑩）。
    fireEvent.change(keySelect("codex-auth-json"), { target: { value: "101" } });
    fireEvent.click(row("codex-auth-json").querySelector(".agent-row-toggle")!);
    await waitFor(() => expect(document.querySelector(".agent-row-plan")).not.toBeNull());

    fireEvent.click(previewToggle());
    await waitFor(() => expect(lastPlanArg()).toMatchObject({ previewOnly: true }));
    await waitFor(() =>
      expect(document.querySelector(".agent-row-plan")!.textContent).toContain(
        zhCN.agents.plan.previewOnlyBanner,
      ),
    );
    const planEl = document.querySelector(".agent-row-plan")!;
    // 预览模式下投递按钮仍渲染、但被禁用（不是悄悄藏起来让用户以为没这功能）。
    const applyBtn = Array.from(planEl.querySelectorAll("button")).find((b) =>
      b.textContent?.includes(zhCN.agents.btn.apply),
    )!;
    expect(applyBtn).not.toBeUndefined();
    expect(applyBtn.disabled).toBe(true);
    // 单变体通道不出现变体下拉（清单长度 1 时不渲染）。
    expect(document.body.textContent).not.toContain(zhCN.agents.plan.variantLabel);
  });

  it("变体下拉与导入块都由 DTO 驱动：选变体进参数，导入值只展示不进投递栏", async () => {
    vi.mocked(deliveryPlan).mockImplementation(async (args: {
      targetVariant?: string;
    }) =>
      fullPlan({
        targetVariant: args.targetVariant ?? "code",
        targetVariants: ["code", "code-insiders", "cursor"],
        isFirstDelivery: true,
        importedFields: [{ key: "OPENAI_API_KEY", masked: "…1111" }],
      }) as never,
    );
    renderPage();
    await waitFor(() => expect(keySelect("codex-auth-json")).not.toBeNull());
    // 先选密钥，否则预览查询因 activeKey 为空而不启用（见测试⑩）。
    fireEvent.change(keySelect("codex-auth-json"), { target: { value: "101" } });
    fireEvent.click(row("codex-auth-json").querySelector(".agent-row-toggle")!);
    // .agent-row-plan 在加载态就已渲染，必须等到导入块出现才算 plan 数据已到
    // （否则变体下拉还没渲染，查找会误报不存在）。
    await waitFor(() =>
      expect(document.querySelector(".agent-row-plan")!.textContent).toContain(
        zhCN.agents.plan.importedTitle,
      ),
    );

    const variantSelect = Array.from(document.querySelectorAll("select")).find((s) =>
      Array.from(s.options).some((o) => o.value === "cursor"),
    )!;
    expect(variantSelect).not.toBeUndefined();
    // P1-7 修复（复审 P1-1）：Insiders / Cursor 下拉选项名后必须带“未实测”
    // 后缀，默认 code 变体不带（它是 P1-7 前已有的默认落点）。
    const optionText = (v: string) =>
      Array.from(variantSelect.options).find((o) => o.value === v)?.textContent ?? "";
    expect(optionText("code-insiders")).toContain(zhCN.agents.plan.variant.unverifiedSuffix);
    expect(optionText("cursor")).toContain(zhCN.agents.plan.variant.unverifiedSuffix);
    expect(optionText("code")).not.toContain(zhCN.agents.plan.variant.unverifiedSuffix);
    fireEvent.change(variantSelect, { target: { value: "cursor" } });
    await waitFor(() => expect(lastPlanArg()).toMatchObject({ targetVariant: "cursor" }));
    // 变体切换触发预览重取：等重取落定（导入块重现）后再断言，
    // 否则读到的是加载态文本。
    await waitFor(() =>
      expect(document.querySelector(".agent-row-plan")!.textContent).toContain(
        zhCN.agents.plan.importedTitle,
      ),
    );

    const planEl = document.querySelector(".agent-row-plan")!;
    expect(planEl.textContent).toContain(zhCN.agents.plan.importedTitle);
    expect(planEl.textContent).toContain("…1111");
    expect(planEl.textContent).toContain(zhCN.agents.plan.importedHint);
    // 导入的旧值只出现在导入块，不会混进「将写入」栏的投递值（…9999 仍是新值）。
    expect(planEl.textContent).toContain("…9999");
    // P1-7 修复（复审 P1-1）：选 cursor 后计划视图里当前变体名后必须挂
    // badge-warn“未实测”徽标（只断言徽标本身，不连带断言下拉后缀文本）。
    expect(
      Array.from(planEl.querySelectorAll("span.badge-warn")).some(
        (s) => s.textContent === zhCN.agents.plan.variant.unverified,
      ),
    ).toBe(true);
  });
});

describe("DEBUG-G6 诚实性：停进程提示 + DSH 引用校验渲染", () => {
  // 与 P1-7 的 fullPlan 同口径的最小完整计划：PlanView 读 files / modelValidation /
  // dshCredentialReference，缺字段会按“旧二进制”静默跳段，测不到东西。
  const g6Plan = (over: Record<string, unknown>) => ({
    agentId: "dsh",
    channel: "dsh",
    targetPath: "/home/u/.dsh/.credentials.yaml",
    targetExists: true,
    mode: "site",
    fields: [{ key: "KEYRELAY_API_KEY", masked: "…9999" }],
    endpointInChannel: true,
    preview: '- "KEYRELAY_API_KEY": "…0000"\n+ "KEYRELAY_API_KEY": "…9999"\n',
    consent: "granted",
    consentGrantedAt: null,
    consentRevokedAt: null,
    warnings: [],
    restartHint: "needed",
    restartHintSource: "unverified",
    restartHintAction: "restartAgent",
    preserveAuth: false,
    files: [
      {
        channel: "dsh",
        targetPath: "/home/u/.dsh/.credentials.yaml",
        targetExists: true,
        fields: [{ key: "KEYRELAY_API_KEY", masked: "…9999" }],
        preview: '- "KEYRELAY_API_KEY": "…0000"\n+ "KEYRELAY_API_KEY": "…9999"\n',
        consent: "granted",
        consentGrantedAt: null,
        consentRevokedAt: null,
        isFirstDelivery: false,
        importedFields: [],
      },
    ],
    previewOnly: false,
    isFirstDelivery: false,
    importedFields: [],
    targetVariant: "default",
    targetVariants: ["default"],
    modelValidation: {
      model: null,
      staticOutcome: "not_applicable",
      staticCode: "no_model",
      probeOutcome: "skipped",
      probeCode: "skipped",
      probeStatus: null,
      blocksDelivery: false,
    },
    ...over,
  });

  const openPlan = async (channelId: string) => {
    renderPage();
    await waitFor(() => expect(keySelect(channelId)).not.toBeNull());
    fireEvent.change(keySelect(channelId), { target: { value: "101" } });
    fireEvent.click(row(channelId).querySelector(".agent-row-toggle")!);
    // .agent-row-plan 在加载态就已存在（“生成预览…”），必须等 PlanView 真正
    // 落定（标题“投递预览”出现）再断言，否则读到的是加载态文本。
    await waitFor(() =>
      expect(document.querySelector(".agent-row-plan")?.textContent).toContain(
        zhCN.agents.plan.title,
      ),
    );
    return document.querySelector(".agent-row-plan")!;
  };

  const agreeAndOpenConfirm = async (planEl: Element) => {
    const consent = planEl.querySelector<HTMLInputElement>(".checkline input[type=checkbox]")!;
    fireEvent.click(consent);
    const applyBtn = Array.from(planEl.querySelectorAll("button")).find((b) =>
      b.textContent?.includes(zhCN.agents.btn.apply),
    )!;
    fireEvent.click(applyBtn);
    await waitFor(() => expect(document.querySelector("dialog[open]")).not.toBeNull());
    return document.querySelector("dialog[open]")!;
  };

  it("P1-19：Codex 确认框写出“先停掉正在跑的 Codex（含终端会话）”", async () => {
    vi.mocked(deliveryPlan).mockImplementation(async () =>
      g6Plan({ agentId: "codex", channel: "codex-auth-json", dshCredentialReference: null }) as never,
    );
    const planEl = await openPlan("codex-auth-json");
    const dialog = await agreeAndOpenConfirm(planEl);
    expect(dialog.textContent).toContain(zhCN.agents.confirmDialog.stopCodex);
  });

  it("P1-19：非 Codex 通道确认框不出现停 Codex 文案（钩子只对 Codex 生效）", async () => {
    vi.mocked(deliveryPlan).mockImplementation(async () =>
      g6Plan({ agentId: "claude-code", channel: "claude-code-settings", dshCredentialReference: null }) as never,
    );
    const planEl = await openPlan("claude-code-settings");
    const dialog = await agreeAndOpenConfirm(planEl);
    expect(dialog.textContent).not.toContain(zhCN.agents.confirmDialog.stopCodex);
  });

  it("P1-20：DSH 引用通过态渲染凭据名、引用文件与 fail-closed 说明", async () => {
    vi.mocked(deliveryPlan).mockImplementation(async () =>
      g6Plan({
        dshCredentialReference: {
          credentialName: "KEYRELAY_API_KEY",
          profilesDir: "/home/u/.dsh/profiles",
          checkedFiles: ["/home/u/.dsh/profiles/a.patch.yml", "/home/u/.dsh/profiles/b.patch.yml"],
          referencingFiles: ["/home/u/.dsh/profiles/a.patch.yml"],
          unreadableFiles: [],
        },
      }) as never,
    );
    const planEl = await openPlan("dsh");
    expect(planEl.textContent).toContain(zhCN.agents.plan.dshReference.title);
    expect(planEl.textContent).toContain("KEYRELAY_API_KEY");
    expect(planEl.textContent).toContain("/home/u/.dsh/profiles/a.patch.yml");
    expect(planEl.textContent).toContain(zhCN.agents.plan.dshReference.failClosed);
  });

  it("P1-20：DSH 有 profile 未引用态明确展示", async () => {
    vi.mocked(deliveryPlan).mockImplementation(async () =>
      g6Plan({
        dshCredentialReference: {
          credentialName: "KEYRELAY_API_KEY",
          profilesDir: "/home/u/.dsh/profiles",
          checkedFiles: ["/home/u/.dsh/profiles/a.patch.yml"],
          referencingFiles: [],
          unreadableFiles: [],
        },
      }) as never,
    );
    const planEl = await openPlan("dsh");
    expect(planEl.textContent).toContain(
      zhCN.agents.plan.dshReference.unreferenced.replaceAll("{name}", "KEYRELAY_API_KEY").replace("{count}", "1"),
    );
    expect(planEl.textContent).toContain(zhCN.agents.plan.dshReference.failClosed);
  });

  it("P1-20：DSH 无 profile 态明确展示扫描目录", async () => {
    vi.mocked(deliveryPlan).mockImplementation(async () =>
      g6Plan({
        dshCredentialReference: {
          credentialName: "KEYRELAY_API_KEY",
          profilesDir: "/home/u/.dsh/profiles",
          checkedFiles: [],
          referencingFiles: [],
          unreadableFiles: [],
        },
      }) as never,
    );
    const planEl = await openPlan("dsh");
    expect(planEl.textContent).toContain("/home/u/.dsh/profiles");
    expect(planEl.textContent).toContain(zhCN.agents.plan.dshReference.failClosed);
  });

  it("P1-20：dshCredentialReference 为 null 时不渲染引用段（不画假状态）", async () => {
    vi.mocked(deliveryPlan).mockImplementation(async () =>
      g6Plan({ dshCredentialReference: null }) as never,
    );
    const planEl = await openPlan("dsh");
    expect(planEl.textContent).not.toContain(zhCN.agents.plan.dshReference.title);
  });
});
