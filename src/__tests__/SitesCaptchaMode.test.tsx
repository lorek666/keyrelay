import { beforeEach, describe, it, expect, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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

/** M36-S1：组件挂载时订阅的「自动完成」处理器（测试里手动触发事件）。 */
let autoHandler:
  | ((event: { siteId: number; status: "completed" | "failed"; message: string | null }) => void)
  | null = null;

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
    onCaptchaAutoFinished: vi.fn(
      async (
        handler: (event: { siteId: number; status: "completed" | "failed"; message: string | null }) => void,
      ) => {
        autoHandler = handler;
        return () => {
          autoHandler = null;
        };
      },
    ),
  };
});

import { captchaBegin, listSites, loginSite, siteBalance, type SiteRow } from "../lib/api";

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
async function renderAndTriggerCaptcha(site: SiteRow, options: { beginError?: Error } = {}) {
  vi.mocked(listSites).mockResolvedValue([site]);
  vi.mocked(siteBalance).mockRejectedValue(new Error("未登录"));
  vi.mocked(loginSite).mockRejectedValue(new Error("需要人工完成验证码"));
  vi.mocked(captchaBegin).mockResolvedValue({ siteId: site.id, url: "https://example.test/login" });
  if (options.beginError) {
    vi.mocked(captchaBegin).mockRejectedValueOnce(options.beginError);
  }
  autoHandler = null;

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
  return { qc };
}

beforeEach(() => {
  // 每个用例从干净的调用计数开始：否则 `not.toHaveBeenCalled()` 会被上一条用例污染
  // （captchaBegin 的累计调用会让 unsupported 那条假红）。
  vi.clearAllMocks();
  autoHandler = null;
});

describe("Sites 的人工验证面板（M28-S2：三态来自能力表）", () => {
  it("cookie 站点：渲染自动文案与「手动接入」，并自动打开一次验证窗口", async () => {
    await renderAndTriggerCaptcha(SITE_COOKIE);

    expect(await screen.findByText(zhCN.sites.hint.captchaAutoBody)).toBeTruthy();
    expect(
      screen.getByRole("button", { name: zhCN.sites.btn.manualFinish }),
    ).toBeTruthy();
    // M36-S1：登录以 captcha 拒绝后**自动**调用一次 captchaBegin（不用再点「打开」）
    await waitFor(() => expect(captchaBegin).toHaveBeenCalledTimes(1));
    expect(captchaBegin).toHaveBeenCalledWith(SITE_COOKIE.id);
    // 兜底按钮仍在：重新打开 + 手动接入 + 取消
    expect(
      screen.getByRole("button", { name: zhCN.sites.btn.reopenCaptcha }),
    ).toBeTruthy();
    expect(screen.getByRole("button", { name: zhCN.common.cancel })).toBeTruthy();
  });

  it("bearer 站点：渲染自动文案与兜底按钮，并自动打开一次验证窗口", async () => {
    await renderAndTriggerCaptcha(SITE_BEARER);

    expect(await screen.findByText(zhCN.sites.hint.captchaAutoBody)).toBeTruthy();
    expect(
      screen.getByRole("button", { name: zhCN.sites.btn.manualFinish }),
    ).toBeTruthy();
    expect(
      screen.getByRole("button", { name: zhCN.sites.btn.reopenCaptcha }),
    ).toBeTruthy();
    await waitFor(() => expect(captchaBegin).toHaveBeenCalledTimes(1));
    expect(captchaBegin).toHaveBeenCalledWith(SITE_BEARER.id);
  });

  it("unsupported 站点：只渲染「不适用」文案与取消，**不自动打开**窗口", async () => {
    await renderAndTriggerCaptcha(SITE_UNSUPPORTED);

    expect(
      await screen.findByText(zhCN.sites.hint.captchaUnsupportedBody),
    ).toBeTruthy();
    expect(screen.queryByRole("button", { name: zhCN.sites.btn.reopenCaptcha })).toBeNull();
    expect(screen.queryByRole("button", { name: zhCN.sites.btn.manualFinish })).toBeNull();
    expect(screen.getByRole("button", { name: zhCN.common.cancel })).toBeTruthy();
    // unsupported 不自动打开（判据只来自能力位）
    expect(captchaBegin).not.toHaveBeenCalled();
  });

  // ============================================================ M36-S1：自动完成事件

  it("自动打开失败：面板保留、显示可读错误、「重新打开」仍可用（P3-3）", async () => {
    await renderAndTriggerCaptcha(SITE_COOKIE, { beginError: new Error("打开人机验证窗口失败（示例）") });

    // 自动打开被调用了一次，并失败
    await waitFor(() => expect(captchaBegin).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toContain("打开人机验证窗口失败（示例）"),
    );
    // 面板仍在（文案 + 三个兜底动作都在）
    expect(screen.getByText(zhCN.sites.hint.captchaAutoBody)).toBeTruthy();
    expect(
      screen.getByRole("button", { name: zhCN.sites.btn.reopenCaptcha }),
    ).toBeTruthy();
    expect(
      screen.getByRole("button", { name: zhCN.sites.btn.manualFinish }),
    ).toBeTruthy();
    expect(screen.getByRole("button", { name: zhCN.common.cancel })).toBeTruthy();
    // 「重新打开」可点：点一次会再发起一次 captchaBegin（用户手动重试，不算自动那一轮）
    fireEvent.click(screen.getByRole("button", { name: zhCN.sites.btn.reopenCaptcha }));
    await waitFor(() => expect(captchaBegin).toHaveBeenCalledTimes(2));
  });

  it("completed 事件：清面板、成功提示、失效四组 query；他站事件忽略", async () => {
    const { qc } = await renderAndTriggerCaptcha(SITE_COOKIE);
    await waitFor(() => expect(autoHandler).not.toBeNull());
    const spy = vi.spyOn(qc, "invalidateQueries");

    // 他站事件：忽略（面板不动）
    act(() => {
      autoHandler!({ siteId: 999, status: "completed", message: null });
    });
    expect(screen.getByText(zhCN.sites.hint.captchaAutoBody)).toBeTruthy();

    act(() => {
      autoHandler!({ siteId: SITE_COOKIE.id, status: "completed", message: null });
    });
    await waitFor(() =>
      expect(screen.queryByText(zhCN.sites.hint.captchaAutoBody)).toBeNull(),
    );
    expect(screen.getByText(/验证完成/)).toBeTruthy();
    for (const key of ["sites", "stored-keys", "remote-keys", "balance"]) {
      expect(spy).toHaveBeenCalledWith({ queryKey: [key] });
    }
  });

  it("failed 事件：保留面板并显示可读错误；重复的 completed 幂等", async () => {
    await renderAndTriggerCaptcha(SITE_COOKIE);
    await waitFor(() => expect(autoHandler).not.toBeNull());

    act(() => {
      autoHandler!({ siteId: SITE_COOKIE.id, status: "failed", message: "自动接入失败（示例原因）" });
    });
    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toContain("自动接入失败（示例原因）"),
    );
    // 面板保留（还能手动接入/取消）
    expect(screen.getByText(zhCN.sites.hint.captchaAutoBody)).toBeTruthy();

    // 之后再来一次 completed：正常清面板
    act(() => {
      autoHandler!({ siteId: SITE_COOKIE.id, status: "completed", message: null });
    });
    await waitFor(() =>
      expect(screen.queryByText(zhCN.sites.hint.captchaAutoBody)).toBeNull(),
    );

    // 迟到的重复 completed：面板已关 ⇒ 幂等忽略（不抛错、不再改状态）
    const noticeText = screen.getByText(/验证完成/).textContent;
    act(() => {
      autoHandler!({ siteId: SITE_COOKIE.id, status: "completed", message: null });
    });
    expect(screen.getByText(/验证完成/).textContent).toBe(noticeText);
    expect(screen.queryByText(zhCN.sites.hint.captchaAutoBody)).toBeNull();

    // P2-1：Bearer 二次回传可能让后端补发一条 failed（第二个 spawn 看到相位已 Idle）。
    // 面板已经清了，这类迟到失败**不得**再把用户吓一跳。
    act(() => {
      autoHandler!({ siteId: SITE_COOKIE.id, status: "failed", message: "该站点当前已不在等待人工验证" });
    });
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByText(/验证完成/).textContent).toBe(noticeText);
  });
});
