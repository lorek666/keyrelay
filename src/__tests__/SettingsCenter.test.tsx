import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import SettingsPage from "../pages/Settings";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";
import ModelCatalogCard from "../components/ModelCatalogCard";
import { MOCK_SETTINGS, type Settings } from "../lib/api";

const catalogApi = vi.hoisted(() => ({
  status: vi.fn(),
  saveSettings: vi.fn(),
  update: vi.fn(),
}));

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    getSettings: catalogApi.saveSettings,
    updateSettings: catalogApi.update,
    catalogStatus: catalogApi.status,
    catalogSyncNow: vi.fn(),
    catalogSetOverride: vi.fn(),
  };
});

/**
 * M45-S7：设置中心收口冒烟。设置页即设置中心，网关卡已在其位（Settings.tsx 的
 * `<GatewayCard .../>` 渲染点）；本测试只断言网关卡标题在列，其余设置卡片行为由
 * 既有单测覆盖（GatewayCard.test.tsx、GatewayTokens.test.tsx、SettingsModels.test.tsx）。
 * 注意：jsdom 下无 Tauri，api 层走 mock 回退，故本测试无需 mock 传输层。
 */
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

describe("SettingsCenter", () => {
  beforeEach(() => {
    catalogApi.saveSettings.mockImplementation(async () => MOCK_SETTINGS);
    catalogApi.update.mockImplementation(async (settings: Settings) => ({
      settings, gateway: {}, gatewayError: null,
    }));
    catalogApi.status.mockResolvedValue({
      source: "bundled", schemaVersion: 1, generatedAt: "", entries: 0, overrides: 0,
      lastSuccessAt: 0, lastError: null, url: "", autoSync: true, models: [],
    });
  });

  it("设置页渲染后网关卡在位", async () => {
    render(<SettingsPage />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("本地网关")).toBeTruthy();
    });
  });

  it("成本页保存名单设置后，设置页保存不会用旧草稿覆盖它", async () => {
    let current: Settings = { ...MOCK_SETTINGS, catalogAutoSync: true, catalogUrl: "" };
    catalogApi.saveSettings.mockImplementation(async () => current);
    catalogApi.update.mockImplementation(async (next: Settings) => {
      current = next;
      return { settings: next, gateway: {}, gatewayError: null };
    });
    catalogApi.status.mockResolvedValue({
      source: "bundled", schemaVersion: 1, generatedAt: "", entries: 0, overrides: 0,
      lastSuccessAt: 0, lastError: null, url: "", autoSync: true, models: [],
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <I18nProvider lang="zh-CN" initialDict={zhCN as unknown as Record<string, unknown>}>
          <SettingsPage />
          <ModelCatalogCard />
        </I18nProvider>
      </QueryClientProvider>,
    );
    const interval = await screen.findByLabelText(zhCN.gateway.modelsIntervalLabel);
    fireEvent.change(interval, { target: { value: "1900" } });
    fireEvent.blur(interval);
    const url = await screen.findByLabelText(zhCN.catalog.urlLabel);
    fireEvent.change(url, { target: { value: "https://mirror.example.com/models.json" } });
    fireEvent.click(screen.getByRole("checkbox", { name: zhCN.catalog.autoSync }));
    fireEvent.click(screen.getByRole("button", { name: zhCN.catalog.saveSettings }));
    await waitFor(() => expect(current.catalogUrl).toBe("https://mirror.example.com/models.json"));
    expect(current.catalogAutoSync).toBe(false);
    await waitFor(() => expect(url).toHaveValue("https://mirror.example.com/models.json"));

    fireEvent.click(screen.getByRole("button", { name: zhCN.settings.save.btn }));
    await waitFor(() => expect(current.modelsMinIntervalSecs).toBe(1900));
    expect(current.catalogUrl).toBe("https://mirror.example.com/models.json");
    expect(current.catalogAutoSync).toBe(false);
  });

  it("高级设置折叠与分类导航不卸载草稿；保存栏覆盖整个设置页", async () => {
    render(<SettingsPage />, { wrapper });
    await waitFor(() => expect(screen.getByText("本地网关")).toBeTruthy());
    const advanced = document.querySelector<HTMLDetailsElement>(".gateway-advanced")!;
    expect(advanced.open).toBe(false);
    fireEvent.click(screen.getByText(zhCN.gateway.sections.advanced));
    const input = screen.getByLabelText(zhCN.gateway.maxRequestLabel);
    fireEvent.change(input, { target: { value: "32" } });
    expect(input).toHaveValue(32);

    fireEvent.click(screen.getByText(zhCN.gateway.sections.advanced));
    expect(advanced.open).toBe(false);
    expect(input).toHaveValue(32);
    fireEvent.click(screen.getByRole("link", { name: "数据与安全" }));
    fireEvent.click(screen.getByRole("link", { name: "网关与路由" }));
    expect(input).toHaveValue(32);

    const savebar = document.querySelector(".settings-savebar")!;
    expect(savebar.compareDocumentPosition(document.querySelector(".settings-data-grid")!) & Node.DOCUMENT_POSITION_PRECEDING).toBeTruthy();
    expect(screen.getByRole("button", { name: "放弃修改" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "放弃修改" }));
    expect(input).toHaveValue(16);
  });
});
