import { describe, expect, it } from "vitest";
import { render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import SettingsPage from "../pages/Settings";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * DEBUG-G6 P1-21：悬空 i18n 键回归（回退会把 key 本身打到界面上）。
 *
 * 钉死两处曾悬空的引用现在解析成真实文案，且钥匙串段不再出现
 * `settings.keychain.localKeepPre` 字面量：
 * - 令牌宽限期走 `settings.gatewayAutoStart.gatewayTokenGrace.*`；
 * - 钥匙串“本地记录”段只剩 Strong + Post（Strong 本身就是完整句首，
 *   不补错键、不复用回收对话框的 Pre 去拼重复句）。
 * 设置页渲染走既有 SettingsCenter 同款 mock 回退（无 Tauri）。
 */
describe("Settings 悬空键", () => {
  it("宽限期标签与钥匙串段均为真实文案，不含悬空 key 字面量", async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={qc}>
        <I18nProvider lang="zh-CN" initialDict={zhCN as unknown as Record<string, unknown>}>
          {children}
        </I18nProvider>
      </QueryClientProvider>
    );
    render(<SettingsPage />, { wrapper });
    await waitFor(() =>
      expect(document.body.textContent).toContain(
        zhCN.settings.gatewayAutoStart.gatewayTokenGrace.label,
      ),
    );
    expect(document.body.textContent).toContain(zhCN.settings.keychain.localKeepStrong);
    expect(document.body.textContent).not.toContain("settings.keychain.localKeepPre");
    expect(document.body.textContent).not.toContain("settings.gatewayTokenGrace.label");
    expect(document.body.textContent).not.toContain("settings.gatewayTokenGrace.hint");
  });
});
