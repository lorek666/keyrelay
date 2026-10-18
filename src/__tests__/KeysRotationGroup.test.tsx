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

function plan(oldGroupName: string | null): RotationPlan {
  return {
    keyId: 9,
    siteId: SITE_ID,
    keyName: "codex/daily",
    steps: ["create_new", "reinject_all", "revoke_old"],
    channels: [],
    unmappedTargets: [],
    oldRemoteId: "9",
    oldGroupName,
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
