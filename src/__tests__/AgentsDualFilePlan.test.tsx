import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import Agents, { CHANNELS } from "../pages/Agents";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * P0-2 复审 P1-2：Agents 确认区必须按 `plan.files` 渲染整单，而不是只读顶层
 * （入口文件）——双文件时两份 diff 都要看得见，保留模式只有 config 一份时只
 * 展示一份，noChange 按全部文件判定，成功提示列出全部写盘路径。
 *
 * 夹具与 AgentsWorkbench.test.tsx 同源（站点/密钥/已安装行），只把 deliveryPlan
 * 换成双文件形态；每条用例在渲染前用 mockImplementation 定死当次 plan，
 * 避免 once 语义被查询重跑（投递成功后的 invalidate）吃掉。
 */

const SITE_A = 11;
const AUTH_PATH = "/home/u/.codex/auth.json";
const CONFIG_PATH = "/home/u/.codex/config.toml";

const AUTH_FILE = {
  channel: "codex-auth-json",
  targetPath: AUTH_PATH,
  targetExists: true,
  fields: [
    { key: "auth_mode", masked: "apikey" },
    { key: "OPENAI_API_KEY", masked: "…cdef" },
  ],
  preview: "@@ auth @@\n+NEW-AUTH\n",
  consent: "granted",
  consentGrantedAt: null,
  consentRevokedAt: null,
};
const CONFIG_FILE = {
  channel: "codex-config",
  targetPath: CONFIG_PATH,
  targetExists: true,
  fields: [
    { key: "base_url", masked: "https://relay.example.test" },
    { key: "model", masked: "gpt-x" },
  ],
  preview: "@@ config @@\n+NEW-CONFIG\n",
  consent: "missing",
  consentGrantedAt: null,
  consentRevokedAt: null,
};

const DUAL_PLAN = {
  agentId: "codex",
  channel: "codex-auth-json",
  targetPath: AUTH_PATH,
  targetExists: true,
  mode: "site",
  fields: AUTH_FILE.fields,
  endpointInChannel: false,
  preview: AUTH_FILE.preview,
  consent: "granted",
  restartHint: "none",
  warnings: [],
  preserveAuth: false,
  files: [AUTH_FILE, CONFIG_FILE],
};

const PRESERVE_PLAN = {
  agentId: "codex",
  channel: "codex-auth-json",
  targetPath: CONFIG_PATH,
  targetExists: true,
  mode: "site",
  fields: CONFIG_FILE.fields,
  endpointInChannel: false,
  preview: CONFIG_FILE.preview,
  consent: "granted",
  restartHint: "none",
  warnings: [],
  preserveAuth: true,
  files: [CONFIG_FILE],
};

const MIXED_PLAN = {
  ...DUAL_PLAN,
  preview: "(无变化)\n",
  files: [
    { ...AUTH_FILE, preview: "(无变化)\n" },
    CONFIG_FILE,
  ],
};

const DUAL_OUTCOME = {
  channel: "codex-auth-json",
  targetPath: AUTH_PATH,
  journalId: "j-dual-1",
  backupPath: null,
  preserveAuth: false,
  files: [
    { channel: "codex-auth-json", targetPath: AUTH_PATH, backupPath: null },
    { channel: "codex-config", targetPath: CONFIG_PATH, backupPath: null },
  ],
};

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
    ]),
    listStoredKeys: vi.fn(async () => [
      { id: 101, siteId: SITE_A, name: "a-key", status: "enabled" },
    ]),
    listConsents: vi.fn(async () => []),
    detectUnmanagedTargets: vi.fn(async () => []),
    detectAgents: vi.fn(async () => {
      const INSTALLED: Record<string, string> = { "codex-auth-json": "0.162.1" };
      return CHANNELS.map((c) =>
        INSTALLED[c.id]
          ? { channel: c.id, installed: true, version: INSTALLED[c.id], source: `/usr/local/bin/${c.agent}`, detail: null,
              installCommands: [{ via: "npm", command: `npm i -g ${c.id}` }], installUrl: "https://example.test/install" }
          : { channel: c.id, installed: false, version: null, source: null, detail: null,
              installCommands: [{ via: "npm", command: `npm i -g ${c.id}` }], installUrl: "https://example.test/install" },
      );
    }),
    listKeyModels: vi.fn(async () => []),
    deliveryPlan: vi.fn(async () => DUAL_PLAN),
    grantConsent: vi.fn(async () => {}),
    applyDelivery: vi.fn(async () => DUAL_OUTCOME),
  };
});

import { deliveryPlan } from "../lib/api";

const row = (id: string) => document.querySelector<HTMLElement>(`[data-agent-channel="${id}"]`)!;
const keySelect = (id: string) => row(id).querySelector<HTMLSelectElement>(".agent-row-key")!;
const planBox = () => document.querySelector<HTMLElement>(".agent-row-plan")!;

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

async function expandCodexRow() {
  renderPage();
  await waitFor(() => expect(keySelect("codex-auth-json")).not.toBeNull());
  fireEvent.change(keySelect("codex-auth-json"), { target: { value: "101" } });
  fireEvent.click(row("codex-auth-json").querySelector(".agent-row-toggle")!);
  await waitFor(() => expect(planBox()).not.toBeNull());
}

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  (deliveryPlan as unknown as { mockImplementation: (fn: () => Promise<unknown>) => void })
    .mockImplementation(async () => DUAL_PLAN);
});

describe("P0-2 P1-2 Agents 双文件确认", () => {
  it("① 双文件 plan 渲染两份 diff、两文件目标与各自同意状态，同意文案为全部文件口径", async () => {
    await expandCodexRow();
    const box = planBox();
    await waitFor(() => expect(box.textContent).toContain("NEW-CONFIG"));
    expect(box.textContent).toContain(AUTH_PATH);
    expect(box.textContent).toContain(CONFIG_PATH);
    expect(box.textContent).toContain("NEW-AUTH");
    expect(box.textContent).toContain("NEW-CONFIG");
    // 每文件各自的同意徽标：auth 已同意、config 未同意，两者都要看得见。
    expect(box.textContent).toContain(zhCN.agents.plan.consentGranted);
    expect(box.textContent).toContain(zhCN.agents.plan.consentMissing);
    // 双文件时同意勾选的含义是「看过全部写盘文件」，不是单文件旧文案。
    expect(box.textContent).toContain(zhCN.agents.plan.agreeAll);
  });

  it("② 保留模式 files 只有 config 一份时只展示一份，不凭空补 auth", async () => {
    (deliveryPlan as unknown as { mockImplementation: (fn: () => Promise<unknown>) => void })
      .mockImplementation(async () => PRESERVE_PLAN);
    await expandCodexRow();
    const box = planBox();
    await waitFor(() => expect(box.textContent).toContain("NEW-CONFIG"));
    expect(box.textContent).toContain(CONFIG_PATH);
    // 计划区里不得出现 auth：行标题本身含 ~/.codex/auth.json，故只在计划区内断言。
    expect(box.textContent).not.toContain(AUTH_PATH);
    expect(box.textContent).not.toContain("NEW-AUTH");
  });

  it("③ 入口无变化、另一文件有变化时不算无变化：复选框出现且勾选后投递按钮可用", async () => {
    (deliveryPlan as unknown as { mockImplementation: (fn: () => Promise<unknown>) => void })
      .mockImplementation(async () => MIXED_PLAN);
    await expandCodexRow();
    const box = planBox();
    await waitFor(() => expect(box.textContent).toContain("NEW-CONFIG"));
    // 旧逻辑（只看入口预览）会在这里判 noChange、禁用投递；新逻辑按全部文件判。
    expect(box.textContent).not.toContain(zhCN.agents.plan.noChange);
    const checkbox = box.querySelector<HTMLInputElement>(".checkline input[type=checkbox]")!;
    expect(checkbox).not.toBeNull();
    const applyButton = Array.from(box.querySelectorAll<HTMLButtonElement>("button")).find((b) =>
      b.textContent?.includes(zhCN.agents.btn.apply),
    )!;
    expect(applyButton.disabled).toBe(true);
    fireEvent.click(checkbox);
    expect(applyButton.disabled).toBe(false);
  });

  it("④ 投递成功提示列出全部写盘路径（确认弹窗里同样列出两文件）", async () => {
    await expandCodexRow();
    const box = planBox();
    await waitFor(() => expect(box.textContent).toContain("NEW-CONFIG"));
    const checkbox = box.querySelector<HTMLInputElement>(".checkline input[type=checkbox]")!;
    fireEvent.click(checkbox);
    const applyButton = Array.from(box.querySelectorAll<HTMLButtonElement>("button")).find((b) =>
      b.textContent?.includes(zhCN.agents.btn.apply),
    )!;
    fireEvent.click(applyButton);

    await waitFor(() => expect(document.querySelector("dialog[open]")).not.toBeNull());
    const dialog = document.querySelector("dialog[open]")!;
    expect(dialog.textContent).toContain(AUTH_PATH);
    expect(dialog.textContent).toContain(CONFIG_PATH);
    const confirmButton = Array.from(dialog.querySelectorAll<HTMLButtonElement>("button")).find((b) =>
      b.textContent?.includes(zhCN.agents.confirmDialog.applyConfirm),
    )!;
    fireEvent.click(confirmButton);

    await waitFor(() => expect(document.querySelector("p.ok")).not.toBeNull());
    const notice = document.querySelector("p.ok")!.textContent ?? "";
    expect(notice).toContain(AUTH_PATH);
    expect(notice).toContain(CONFIG_PATH);
    expect(notice).toContain("j-dual-1");
  });
});
