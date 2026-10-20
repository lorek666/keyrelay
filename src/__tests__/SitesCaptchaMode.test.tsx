import { describe, it, expect, vi } from "vitest";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import Sites from "../pages/Sites";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M28-S2 / B-191 B 路：人工验证面板的**三态**。
 *
 * 判据只来自 `SiteCapabilities`（`webviewCaptchaSupported` / `webviewBearerSupported`），
 * 页面里不得按 `kind` 硬编码。这里逐态渲染并断言**关键文案与按钮**——
 * 删掉 `captchaPanelMode` 的 bearer 分支会让「bearer 站点」那条红。
 *
 * 触发方式：让 `loginSite` 以「需要人工完成验证码」拒绝（`isCaptchaRequired` 认得这句），
 * 页面就会从登录框切到人工验证面板。**不 mock 组件内部状态**，走真实用户路径。
 */

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    listSites: vi.fn(),
    loginSite: vi.fn(),
    siteBalance: vi.fn(),
    captchaBegin: vi.fn(),
    captchaComplete: vi.fn(),
    captchaCancel: vi.fn(),
  };
});

import { listSites, loginSite, siteBalance, type SiteRow } from "../lib/api";

const caps = (over: Partial<SiteRow["capabilities"]>): SiteRow["capabilities"] => ({
  login: true,
  listKeys: true,
  createKey: true,
  revealKey: true,
  revokeKey: true,
  balance: true,
  groups: true,
  keyUsage: true,
  webviewCaptchaSupported: false,
  webviewBearerSupported: false,
  ...over,
});

const SITE_COOKIE: SiteRow = {
  id: 1,
  kind: "newapi",
  baseUrl: "https://cookie.example.test",
  displayName: "Cookie 站",
  health: "ok",
  loginField: "username",
  capabilities: caps({ webviewCaptchaSupported: true }),
};

const SITE_BEARER: SiteRow = {
  id: 2,
  kind: "sub2api",
  baseUrl: "https://bearer.example.test",
  displayName: "Bearer 站",
  health: "ok",
  loginField: "email",
  capabilities: caps({ webviewBearerSupported: true }),
};

/**
 * 夹具：**可登录但两种 WebView 兜底都不支持**的站点（现实中当前没有这种类型，
 * 但面板要按 fail-closed 渲染——判据是能力位，不是「现实里有没有」）。
 */
const SITE_UNSUPPORTED: SiteRow = {
  id: 3,
  kind: "newapi",
  baseUrl: "https://unsupported.example.test",
  displayName: "无兜底站",
  health: "ok",
  loginField: "username",
  capabilities: caps({}),
};

/** 渲染 → 点站点行的「登录」→ 填账号密码 → 点对话框的「登录」→ 让 loginSite 以验证码错误拒绝。 */
async function renderAndTriggerCaptcha(site: SiteRow) {
  vi.mocked(listSites).mockResolvedValue([site]);
  vi.mocked(siteBalance).mockRejectedValue(new Error("未登录"));
  vi.mocked(loginSite).mockRejectedValue(new Error("需要人工完成验证码"));

  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity, gcTime: Infinity } },
  });
  qc.setQueryData(["sites"], [site]);

  render(<Sites />, {
    wrapper: ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={qc}>
        <I18nProvider lang="zh-CN" initialDict={zhCN}>
          {children}
        </I18nProvider>
      </QueryClientProvider>
    ),
  });

  // 站点行的「登录」（对话框没开时全页只有这一个）。
  const rowLogin = await screen.findByRole("button", { name: zhCN.sites.btn.login });
  await act(async () => {
    fireEvent.click(rowLogin);
  });

  const dialog = await screen.findByRole("dialog");
  const inputs = dialog.querySelectorAll("input");
  await act(async () => {
    fireEvent.change(inputs[0], { target: { value: "me@example.test" } });
    fireEvent.change(inputs[1], { target: { value: "pw-12345678" } });
  });
  const confirm = within(dialog).getByRole("button", {
    name: zhCN.sites.loginDialog.confirm,
  });
  await act(async () => {
    fireEvent.click(confirm);
  });
}

describe("Sites 的人工验证面板（M28-S2：三态来自能力表）", () => {
  it("cookie 站点：渲染 HEAD 的文案与「我已过完」，不渲染 bearer 文案", async () => {
    await renderAndTriggerCaptcha(SITE_COOKIE);

    expect(
      await screen.findByText(zhCN.sites.hint.captchaBody),
    ).toBeTruthy();
    expect(
      screen.getByRole("button", { name: zhCN.sites.btn.finishCaptcha }),
    ).toBeTruthy();
    expect(screen.queryByText(zhCN.sites.hint.captchaBearerBody)).toBeNull();
    expect(
      screen.queryByRole("button", { name: zhCN.sites.btn.finishLogin }),
    ).toBeNull();
  });

  it("bearer 站点：渲染 bearer 文案与「我已登录」，不出现「我已过完」", async () => {
    await renderAndTriggerCaptcha(SITE_BEARER);

    expect(
      await screen.findByText(zhCN.sites.hint.captchaBearerBody),
    ).toBeTruthy();
    expect(
      screen.getByRole("button", { name: zhCN.sites.btn.finishLogin }),
    ).toBeTruthy();
    // 「打开官方页面过一次」在 bearer 面板里同样要有（用户要去官方页登录）
    expect(
      screen.getByRole("button", { name: zhCN.sites.btn.openOfficial }),
    ).toBeTruthy();
    expect(
      screen.queryByRole("button", { name: zhCN.sites.btn.finishCaptcha }),
    ).toBeNull();
    expect(screen.queryByText(zhCN.sites.hint.captchaBody)).toBeNull();
  });

  it("unsupported 站点：只渲染「不适用」文案与取消，不渲染任何取数按钮", async () => {
    await renderAndTriggerCaptcha(SITE_UNSUPPORTED);

    expect(
      await screen.findByText(zhCN.sites.hint.captchaUnsupportedBody),
    ).toBeTruthy();
    expect(screen.queryByRole("button", { name: zhCN.sites.btn.openOfficial })).toBeNull();
    expect(screen.queryByRole("button", { name: zhCN.sites.btn.finishCaptcha })).toBeNull();
    expect(screen.queryByRole("button", { name: zhCN.sites.btn.finishLogin })).toBeNull();
    expect(screen.getByRole("button", { name: zhCN.common.cancel })).toBeTruthy();
  });
});
