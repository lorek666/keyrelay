import { describe, it, expect, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import Keys from "../pages/Keys";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M19-S1 / B-161：分组下拉的 `value` 必须是**站点原生标识**。
 *
 * 背景（真机 + 源码双向确认）：Sub2API 的分组有数字主键（`groups.id`），建密钥的接口
 * 收的是 `group_id`（整数），而分组名是给人看的（`"gpt plus"` / `"自用"`）。产品此前
 * 把 `GroupInfo.id` 丢在适配器里，界面只能拿名字当 `value` 往下传；`create_key` 又把
 * 「解析成整数失败」写成 `and_then(...ok())` ⇒ **静默丢弃**。结果是：用户明明选了分组，
 * 密钥建出来却不带 `group_id`，直到 agent 收到 `403 API key is not assigned to any group`
 * 才发现。
 *
 * 这里钉死两件事：① 有 id 时 `value` 用 id、没有时回落名字；② 没选分组时把后果说出来。
 */

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    listSites: vi.fn(),
    listStoredKeys: vi.fn(),
    listKeys: vi.fn(),
    rotationDue: vi.fn(),
    suggestKeyName: vi.fn(),
    createKey: vi.fn(),
    availableGroups: vi.fn(),
  };
});

import {
  createKey,
  groupKeyOf,
  suggestKeyName,
  type Group,
  type SiteRow,
  type StoredKeyRow,
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

const KEYS: StoredKeyRow[] = [];

/** Sub2API 形态：数字主键 + 人类可读名字，两者**不同**。 */
const SUB2API_GROUPS: Group[] = [
  { id: "2", name: "gpt plus", rate: 0.085, description: null },
  { id: "3", name: "自用", rate: 1, description: null },
];

/** NewAPI 形态：没有独立主键，名字即标识。 */
const NEWAPI_GROUPS: Group[] = [
  { id: null, name: "default", rate: 1, description: null },
  { id: null, name: "vip", rate: 0.5, description: null },
];

function renderKeys(groups: Group[], sites: SiteRow[] = SITES) {
  // 给两个 mutation/query 函数一个**确定的返回值**：不设的话 `openCreateDialog` 里的
  // `await suggestKeyName(...)` 会以 `undefined` 落地，React Query 在测试之外更新状态
  // （act 警告），噪声会盖住真正的失败（独立复审闭环 P3-6）。
  vi.mocked(suggestKeyName).mockResolvedValue("codex/agent/20261018");
  vi.mocked(createKey).mockResolvedValue({
    id: 1,
    remoteId: "21",
    name: "codex/agent/20261018",
    masked: "…abcd",
  });
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity, gcTime: Infinity } },
  });
  qc.setQueryData(["sites"], sites);
  qc.setQueryData(["stored-keys"], KEYS);
  qc.setQueryData(["rotation-due"], []);
  qc.setQueryData(["remote-keys", SITE_ID], []);
  qc.setQueryData(["groups", SITE_ID], groups);
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

/**
 * 打开「新建密钥」对话框，返回分组下拉。
 *
 * 必须 `await`：`openCreateDialog` 里有一次 `await suggestKeyName(...)`，它回来后会
 * `setName`。不把它等干净，React 会在测试之外更新状态（act 警告），
 * 断言就可能跑在「对话框开了但还没填名字」的中间态上。
 */
async function openCreateDialog(): Promise<HTMLSelectElement> {
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /新建密钥/ }));
  });
  return screen.getByLabelText("分组（可选）") as HTMLSelectElement;
}

function optionValues(select: HTMLSelectElement): string[] {
  return Array.from(select.querySelectorAll("option")).map((o) => o.value);
}

describe("M19-S1 密钥分组绑定", () => {
  it("有站点原生 id 时，下拉的 value 用 id（Sub2API）", async () => {
    renderKeys(SUB2API_GROUPS);
    const select = await openCreateDialog();

    expect(optionValues(select)).toEqual(["", "2", "3"]);
    // 显示给人看的仍然是名字，不是 id
    const labels = Array.from(select.querySelectorAll("option")).map((o) => o.textContent ?? "");
    expect(labels[1]).toContain("gpt plus");
    expect(labels[1]).not.toContain("2 ·");
  });

  it("没有 id 时回落到分组名（NewAPI 行为不变）", async () => {
    renderKeys(NEWAPI_GROUPS);
    const select = await openCreateDialog();

    expect(optionValues(select)).toEqual(["", "default", "vip"]);
  });

  it("没选分组时提示后果；选了就不提示", async () => {
    renderKeys(SUB2API_GROUPS);
    const select = await openCreateDialog();

    expect(screen.getByText(/没有选择分组/)).toBeTruthy();

    fireEvent.change(select, { target: { value: "2" } });
    expect(screen.queryByText(/没有选择分组/)).toBeNull();
  });

  it("站点没有可选分组时不误报（列表为空就没有可选项，提示没有意义）", async () => {
    renderKeys([]);
    await openCreateDialog();
    expect(screen.queryByText(/没有选择分组/)).toBeNull();
  });

  it("NewAPI（分组无原生 id）不误报：不传分组等于跟随用户自己的分组，是安全默认", async () => {
    // 独立复审 P2-3：提示的结论是「未绑定的密钥会被 403」，那只在**按 id 绑定**的
    // 站点上成立。NewAPI 上弹这条会把用户推向 spec §2 明确不做的「随便选一个」。
    renderKeys(NEWAPI_GROUPS);
    const select = await openCreateDialog();
    expect(select.value).toBe("");
    expect(screen.queryByText(/没有选择分组/)).toBeNull();
  });

  it("站点没有分组概念（caps.groups=false）时不误报", async () => {
    // 独立复审 P2-4：这条守卫此前没有用例——把 `(caps?.groups ?? false) &&` 删掉
    // 整套用例仍全绿。这里用「缓存里有带 id 的分组、但能力集说不支持」的形态钉住它：
    // 分组概念来自能力集，不是「缓存里恰好有数据」。
    const noGroups: SiteRow[] = [
      {
        ...SITES[0],
        capabilities: { ...SITES[0].capabilities, groups: false },
      },
    ];
    renderKeys(SUB2API_GROUPS, noGroups);
    const select = await openCreateDialog();
    expect(select.disabled).toBe(true);
    expect(screen.queryByText(/没有选择分组/)).toBeNull();
    expect(screen.getByText(/没有分组概念/)).toBeTruthy();
  });

  it("提交时把「站点标识」和「显示名」分别传下去", async () => {
    // 标识发给站点（Sub2API 要数字主键），名字落本地（密钥表显示 + 按名查倍率）。
    // 合成一个字段的后果在 M19-S1 的 spec §6 里写清了：显示成数字、倍率查不到。
    vi.mocked(suggestKeyName).mockResolvedValue("codex/agent/20261018");
    vi.mocked(createKey).mockResolvedValue({
      id: 1,
      remoteId: "21",
      name: "codex/agent/20261018",
      masked: "…abcd",
    });

    renderKeys(SUB2API_GROUPS);
    const select = await openCreateDialog();
    fireEvent.change(select, { target: { value: "2" } });

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "创建" }));
    });

    expect(vi.mocked(createKey)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(createKey).mock.calls[0][0]).toEqual({
      siteId: SITE_ID,
      name: "codex/agent/20261018",
      group: "2",
      groupLabel: "gpt plus",
    });
  });

  it("groupKeyOf：id 优先，空串/空白按没有 id 处理", () => {
    expect(groupKeyOf({ id: "2", name: "gpt plus", rate: null, description: null })).toBe("2");
    expect(groupKeyOf({ id: null, name: "vip", rate: null, description: null })).toBe("vip");
    expect(groupKeyOf({ id: "", name: "vip", rate: null, description: null })).toBe("vip");
    expect(groupKeyOf({ id: "  ", name: "vip", rate: null, description: null })).toBe("vip");
  });
});
