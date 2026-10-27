import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

/**
 * M47-S2：内置模型名单卡。
 *
 * 钉住四件事：
 * ① 来源必须明示（GitHub / 内置 / 空）——用户要能判断这份数据是哪来的；
 * ② 同步失败**不清空表格**（旧缓存还在），错误以提示形式出现；
 * ③ 每行显示名单带入的上下文/输出/思考档位与价格；未定价显示「未定价」而不是 0；
 * ④ 覆盖行会标「本机覆盖」，保存后重新取名单。
 */
vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    catalogStatus: vi.fn(),
    catalogSyncNow: vi.fn(),
    catalogSetOverride: vi.fn(),
    getSettings: vi.fn(),
    updateSettings: vi.fn(),
  };
});

import {
  catalogStatus,
  catalogSyncNow,
  catalogSetOverride,
  getSettings,
  updateSettings,
  type CatalogStatus,
  type Settings,
} from "../lib/api";
import ModelCatalogCard from "../components/ModelCatalogCard";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

function status(overrides: Partial<CatalogStatus> = {}): CatalogStatus {
  return {
    source: "remote",
    schemaVersion: 1,
    generatedAt: "2026-10-27T00:00:00Z",
    entries: 2,
    overrides: 0,
    lastSuccessAt: 1_790_000_000,
    lastError: null,
    url: "https://example.com/models.json",
    autoSync: true,
    models: [
      {
        id: "glm-5.3-flash",
        displayName: "GLM-5.3-Flash",
        vendor: "zhipu",
        protocol: "openai_chat",
        anthropicCompatible: true,
        contextWindow: 1_000_000,
        maxOutputTokens: 128_000,
        thinkingUnsupported: false,
        thinking: {
          param: "reasoning_effort",
          maxLevel: "high",
          defaultLevel: "medium",
          budgetLow: 1024,
          budgetMedium: 8192,
          budgetHigh: 32768,
          budgetXhigh: 0,
        },
        prices: [
          { currency: "USD", inputPerMtok: 0.5, outputPerMtok: 2, cacheReadPerMtok: null },
        ],
        deprecated: false,
        overridden: false,
      },
      {
        id: "plain-model",
        displayName: "Plain Model",
        vendor: "other",
        protocol: "openai_chat",
        anthropicCompatible: false,
        contextWindow: 32_768,
        maxOutputTokens: 4_096,
        thinking: null,
        thinkingUnsupported: false,
        prices: [],
        deprecated: false,
        overridden: false,
      },
    ],
    ...overrides,
  };
}

const settings = {
  catalogAutoSync: true,
  catalogUrl: "",
} as unknown as Settings;

function renderCard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<ModelCatalogCard />, {
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
  vi.mocked(getSettings).mockResolvedValue(settings);
  vi.mocked(catalogStatus).mockResolvedValue(status());
  vi.mocked(catalogSetOverride).mockResolvedValue(status());
  vi.mocked(catalogSyncNow).mockResolvedValue({
    bytes: 100,
    accepted: 2,
    skipped: 1,
    generatedAt: "2026-10-27T00:00:00Z",
    unchanged: false,
    status: status(),
  });
  vi.mocked(updateSettings).mockResolvedValue({
    settings,
    gateway: {} as never,
    gatewayError: null,
  });
});

describe("模型名单卡（M47-S2）", () => {
  it("① 明示来源、条数与生成时间", async () => {
    renderCard();
    expect(await screen.findByText("来自 GitHub")).toBeTruthy();
    expect(screen.getByText(/2 条/)).toBeTruthy();
    expect(screen.getByText(/2026-10-27T00:00:00Z/)).toBeTruthy();
  });

  it("支持按模型名 / 厂商筛选，并显示匹配条数", async () => {
    renderCard();
    await screen.findByText("GLM-5.3-Flash");
    const filter = screen.getByRole("searchbox", { name: "筛选模型名 / 厂商" });
    fireEvent.change(filter, { target: { value: "plain" } });
    expect(screen.getByText("Plain Model")).toBeTruthy();
    expect(screen.queryByText("GLM-5.3-Flash")).toBeNull();
    expect(screen.getByText("显示 1 / 2 条")).toBeTruthy();
  });

  it("③ 带入上下文/输出/思考档位；无价显示「未定价」", async () => {
    renderCard();
    await screen.findByText("GLM-5.3-Flash");
    expect(screen.getByText("1,000,000")).toBeTruthy();
    expect(screen.getByText("128,000")).toBeTruthy();
    expect(screen.getByText("支持到 high")).toBeTruthy();
    expect(screen.getByText("0.5 / 2 USD")).toBeTruthy();
    expect(screen.getByText("未定价")).toBeTruthy();
    expect(screen.getByText("未声明（不自动带入）")).toBeTruthy();
    expect(screen.queryByText("明确不支持")).toBeNull();
  });

  it("② 同步失败只报错，不清空表格", async () => {
    vi.mocked(catalogSyncNow).mockRejectedValue(new Error("HTTP 404"));
    renderCard();
    await screen.findByText("GLM-5.3-Flash");
    fireEvent.click(screen.getByRole("button", { name: /立即同步/ }));
    await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("HTTP 404"));
    expect(screen.getByText("GLM-5.3-Flash")).toBeTruthy();
  });

  it("④b 只填价格时，patch 只带价格那两项（其余留空 = 不改）", async () => {
    const { container } = renderCard();
    await screen.findByText("GLM-5.3-Flash");
    const details = container.querySelector("details") as HTMLDetailsElement;
    details.open = true;
    const inside = within(details);
    // textbox 顺序：上下文、最大输出、输入价、输出价
    const inputs = inside.getAllByRole("textbox");
    fireEvent.change(inputs[2], { target: { value: "0.3" } });
    fireEvent.change(inputs[3], { target: { value: "1.2" } });
    fireEvent.click(inside.getByRole("button", { name: /保存覆盖/ }));
    await waitFor(() => expect(vi.mocked(catalogSetOverride).mock.calls.length).toBe(1));
    expect(vi.mocked(catalogSetOverride).mock.calls[0][1]).toEqual({
      priceInputPerMtok: 0.3,
      priceOutputPerMtok: 1.2,
      priceCurrency: "USD",
    });
  });

  it("④c 一格都没填时保存按钮不可用（避免提交一条空覆盖）", async () => {
    const { container } = renderCard();
    await screen.findByText("GLM-5.3-Flash");
    const details = container.querySelector("details") as HTMLDetailsElement;
    details.open = true;
    const save = within(details).getByRole("button", { name: /保存覆盖/ }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.change(within(details).getAllByRole("textbox")[0], {
      target: { value: "200000" },
    });
    expect(save.disabled).toBe(false);
  });

  it("上下文缩小到低于既有最大输出时拒绝提交", async () => {
    const { container } = renderCard();
    await screen.findByText("GLM-5.3-Flash");
    const details = container.querySelector("details") as HTMLDetailsElement;
    details.open = true;
    const inside = within(details);
    fireEvent.change(inside.getAllByRole("textbox")[0], { target: { value: "1000" } });
    fireEvent.click(inside.getByRole("button", { name: /保存覆盖/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent("最大输出不能超过上下文窗口");
    expect(catalogSetOverride).not.toHaveBeenCalled();
  });

  it("地址未保存时不隐式覆盖设置；关闭思考与价格同次提交", async () => {
    renderCard();
    await screen.findByText("GLM-5.3-Flash");
    const url = screen.getByLabelText("名单地址");
    fireEvent.change(url, { target: { value: "https://mirror.example.com/models.json" } });
    fireEvent.click(screen.getByRole("button", { name: /立即同步/ }));
    await screen.findByText(/请先保存名单同步设置/);
    expect(updateSettings).not.toHaveBeenCalled();
    expect(catalogSyncNow).not.toHaveBeenCalled();

    const details = document.querySelector("details") as HTMLDetailsElement;
    details.open = true;
    const inside = within(details);
    fireEvent.change(inside.getByRole("combobox"), { target: { value: "off" } });
    const inputs = inside.getAllByRole("textbox");
    fireEvent.change(inputs[2], { target: { value: "0.3" } });
    fireEvent.change(inputs[3], { target: { value: "1.2" } });
    fireEvent.click(inside.getByRole("button", { name: /保存覆盖/ }));
    await waitFor(() => expect(vi.mocked(catalogSetOverride).mock.calls.length).toBe(1));
    expect(vi.mocked(catalogSetOverride).mock.calls[0][1]).toEqual({
      thinkingLevel: "off", priceInputPerMtok: 0.3, priceOutputPerMtok: 1.2, priceCurrency: "USD",
    });
  });

  it("⑤ 名单状态读取失败时报错，而不是装成「名单是空的」", async () => {
    vi.mocked(catalogStatus).mockRejectedValue(new Error("IPC 不可用"));
    renderCard();
    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toContain("读不到名单状态"),
    );
    expect(screen.queryByText(/名单是空的/)).toBeNull();
  });

  it("④ 覆盖保存走 catalogSetOverride，并重新取名单", async () => {
    const { container } = renderCard();
    await screen.findByText("GLM-5.3-Flash");
    // jsdom 不会因为点 summary 就把 `<details>` 打开，也不会把关闭状态下的子节点
    // 暴露给 role 查询——这里直接打开它（等价于用户展开）。
    const details = container.querySelector("details") as HTMLDetailsElement;
    details.open = true;
    const inside = within(details);
    const inputs = inside.getAllByRole("textbox");
    fireEvent.change(inputs[0], { target: { value: "200000" } });
    fireEvent.click(inside.getByRole("button", { name: /保存覆盖/ }));
    await waitFor(() => expect(vi.mocked(catalogSetOverride).mock.calls.length).toBe(1));
    const [modelId, patch] = vi.mocked(catalogSetOverride).mock.calls[0];
    expect(modelId).toBe("glm-5.3-flash");
    // **精确**断言：只提交用户填过的那一格。整包提交会把窗口/输出/档位/价格一起钉死，
    // 名单以后更新也压不过旧覆盖（复审 BLOCKER）。
    expect(patch).toEqual({ contextWindow: 200000 });
    await waitFor(() =>
      expect(vi.mocked(catalogStatus).mock.calls.length).toBeGreaterThan(1),
    );
  });
});
