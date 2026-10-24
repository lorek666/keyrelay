import { describe, expect, it } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import SettingsPage from "../pages/Settings";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

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
  it("设置页渲染后网关卡在位", async () => {
    render(<SettingsPage />, { wrapper });
    await waitFor(() => {
      expect(screen.getByText("本地网关")).toBeTruthy();
    });
  });
});
