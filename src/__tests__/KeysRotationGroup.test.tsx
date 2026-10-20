import { describe, it, expect, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import Keys from "../pages/Keys";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M20-S1 / B-166：轮换预览必须把「新密钥会继承旧密钥的分组」说在动手之前。
 *
 * 背景：`rotate_key` 此前用 `KeySpec::named(name)` 建新 key ⇒ 一个分组都不带。
 * 轮换的顺序是 `建新 → 重注入 → 回收旧`，所以在「未分组 key 一律 403」的站点上，
 * 三步走完用户手里两把 key 全不能用，而界面显示的是「轮换完成」。
 *
 * 这里钉两件事：① 旧 key 有分组 ⇒ 预览里出现那一行；② 没有 ⇒ 不出现
 * （NewAPI 上「不指定分组 = 跟随用户自己分组」是有意语义，不能弹出误导文案）。
 */

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    listSites: vi.fn(),
    listStoredKeys: vi.fn(),
    listKeys: vi.fn(),
    rotationDue: vi.fn(),
    rotationPlan: vi.fn(),
    rotateKey: vi.fn(),
    suggestKeyName: vi.fn(),
    availableGroups: vi.fn(),
  };
});

import {
  availableGroups,
  rotationDue,
  rotationPlan,
  suggestKeyName,
  type RotationPlan,
  type SiteRow,
} from "../lib/api";

const SITE_ID = 1;

const SITES: SiteRow[] = [
  {
    id: SITE_ID,
    kind: "sub2api",
    baseUrl: "https://relay.example.test",
    displayName: "示例中转站",
    health: "ok",
    loginField: "username",
    capabilities: {
      login: true,
      listKeys: true,
      createKey: true,
      revealKey: true,
      revokeKey: true,
      balance: true,
      groups: true,
      keyUsage: false,
      // M28-S2：两种 WebView 兜底都是 false（夹具不跑验证码面板）。
      webviewCaptchaSupported: false,
      webviewBearerSupported: false,
    },
  },
];

const DUE = [
  {
    keyId: 9,
    siteId: SITE_ID,
    name: "codex/daily",
    createdAt: 1,
    dueAt: 2,
  },
];

function plan(
  oldGroupName: string | null,
  oldGroupId: string | null = null,
): RotationPlan {
  return {
    keyId: 9,
    siteId: SITE_ID,
    keyName: "codex/daily",
    steps: ["create_new", "reinject_all", "revoke_old"],
    channels: [],
    unmappedTargets: [],
    oldRemoteId: "9",
    oldGroupName,
    oldGroupId,
  };
}

function renderKeys() {
  vi.mocked(suggestKeyName).mockResolvedValue("codex/agent/20261018");
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity, gcTime: Infinity } },
  });
  qc.setQueryData(["sites"], SITES);
  qc.setQueryData(["stored-keys"], []);
  qc.setQueryData(["remote-keys", SITE_ID], []);
  // 轮换表是按「该轮换的密钥」渲染的，所以这里必须有一条到期的
  qc.setQueryData(["rotation-due"], DUE);
  return render(<Keys />, {
    wrapper: ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={qc}>
        <I18nProvider lang="zh-CN" initialDict={zhCN}>
          {children}
        </I18nProvider>
      </QueryClientProvider>
    ),
  });
}

/** 打开轮换预览对话框。必须 `await`：建议名回来前界面还在中间态。 */
async function openRotationDialog(): Promise<void> {
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /轮换/ }));
  });
}

describe("M20-S1 轮换继承分组", () => {
  it("旧 key 绑了分组 ⇒ 预览里说明新密钥会继续绑同一个分组", async () => {
    vi.mocked(rotationDue).mockResolvedValue(DUE);
    vi.mocked(rotationPlan).mockResolvedValue(plan("gpt plus"));

    renderKeys();
    await openRotationDialog();

    expect(
      screen.getByText(/新密钥会继续绑定旧密钥所在的分组「gpt plus」/),
    ).toBeDefined();
  });

  it("旧 key 没有分组 ⇒ 不显示那一行（不误导用户）", async () => {
    vi.mocked(rotationDue).mockResolvedValue(DUE);
    vi.mocked(rotationPlan).mockResolvedValue(plan(null));

    renderKeys();
    await openRotationDialog();

    expect(screen.queryByText(/新密钥会继续绑定旧密钥所在的分组/)).toBeNull();
    // 三步本身仍然要在：分组那一行是**补充**，不是替代
    expect(screen.getByText(/在站点上新建一把密钥/)).toBeDefined();
  });

  it("分组名是纯空格 ⇒ 也不显示（与后端 trim 判据同源）", async () => {
    vi.mocked(rotationDue).mockResolvedValue(DUE);
    vi.mocked(rotationPlan).mockResolvedValue(plan("   "));

    renderKeys();
    await openRotationDialog();

    expect(screen.queryByText(/新密钥会继续绑定旧密钥所在的分组/)).toBeNull();
  });
});

/**
 * M22-S1 / B-167：预览必须零请求（PRD §7），所以「站点上还有没有这个分组」只能靠用户
 * **主动点一下**。这里钉三件事：不点就零请求；点了按 **id** 精确比；id 命中而名字变了
 * 要报「已改名」而不是「不存在」（改名不是猜——id 是站点主键）。
 */
describe("M22-S1 轮换分组按需在线校验", () => {
  const GP = { id: "2", name: "gpt plus", rate: 1.5, description: null };

  it("不点「校验分组」⇒ 一个请求都不发（预览仍是纯本地的）", async () => {
    vi.mocked(rotationDue).mockResolvedValue(DUE);
    vi.mocked(rotationPlan).mockResolvedValue(plan("gpt plus", "2"));
    vi.mocked(availableGroups).mockClear();

    renderKeys();
    await openRotationDialog();

    expect(screen.getByRole("button", { name: "校验分组" })).toBeDefined();
    expect(availableGroups).toHaveBeenCalledTimes(0);
  });

  it("按 id 命中且名字一致 ⇒ 报「站点上仍有这个分组」", async () => {
    vi.mocked(rotationDue).mockResolvedValue(DUE);
    vi.mocked(rotationPlan).mockResolvedValue(plan("gpt plus", "2"));
    vi.mocked(availableGroups).mockClear();
    vi.mocked(availableGroups).mockResolvedValue([GP]);

    renderKeys();
    await openRotationDialog();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "校验分组" }));
    });

    expect(availableGroups).toHaveBeenCalledTimes(1);
    expect(screen.getByText(/站点上仍有分组「gpt plus」/)).toBeDefined();
  });

  it("按 id 命中但名字变了 ⇒ 报「已改名」，不是「不存在」", async () => {
    vi.mocked(rotationDue).mockResolvedValue(DUE);
    vi.mocked(rotationPlan).mockResolvedValue(plan("gpt plus", "2"));
    vi.mocked(availableGroups).mockClear();
    vi.mocked(availableGroups).mockResolvedValue([{ ...GP, name: "gpt plus v2" }]);

    renderKeys();
    await openRotationDialog();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "校验分组" }));
    });

    expect(
      screen.getByText(/分组已在站点上改名：「gpt plus」→「gpt plus v2」/),
    ).toBeDefined();
    // 负向断言必须钉**校验结果那一句**，不能用「站点上已经没有这个分组」这种共有词：
    // 预览里那句静态文案 `groupInherit` 也含这几个字，会假通过（M20-S1 复审踩过的同一个坑）。
    expect(screen.queryByText(/站点上已经没有这个分组「gpt plus」。/)).toBeNull();
  });

  it("没有 id、名字也找不到 ⇒ 文案点明「只能按名字比对，改过名就认不出来」", async () => {
    vi.mocked(rotationDue).mockResolvedValue(DUE);
    vi.mocked(rotationPlan).mockResolvedValue(plan("gpt plus", null));
    vi.mocked(availableGroups).mockClear();
    vi.mocked(availableGroups).mockResolvedValue([{ ...GP, id: "7", name: "other" }]);

    renderKeys();
    await openRotationDialog();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "校验分组" }));
    });

    expect(
      screen.getByText(/没有站点侧的分组 id，只能按名字比对/),
    ).toBeDefined();
  });
});
