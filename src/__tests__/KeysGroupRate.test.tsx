import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

/**
 * M30-S1：密钥页的「当前分组倍率」列。
 *
 * 钉死四件事（spec §7）：
 * ① `formatGroupRate` 的口径：0 = 免费、正数 = `{rate}×`、null / NaN / 负数 = 倍率未知；
 * ② 本地密钥表：没有「远端 id」列、有「当前分组倍率」列；0 倍率显示免费、0.085 显示 `0.085×`、无分组显示 `—`；
 * ③ 站点侧只读对照表同样替换列，并按**分组名**匹配倍率；
 * ④ 分组查询失败时表格仍渲染、倍率列显示 `—`（不猜测、不回落 1×）。
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
  availableGroups,
  formatGroupRate,
  listKeys,
  listSites,
  listStoredKeys,
  rotationDue,
  suggestKeyName,
  type Group,
  type KeyRow,
  type SiteRow,
  type StoredKeyRow,
} from "../lib/api";
import Keys from "../pages/Keys";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

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
      webviewCaptchaSupported: false,
      webviewBearerSupported: true,
    },
  },
];

/** 三个分组：0 倍率（免费）、0.085 倍率、1 倍率。`id` 与 `name` **不同**（Sub2API 形态）。 */
const GROUPS: Group[] = [
  { id: "2", name: "gpt plus", rate: 0.085, description: null },
  { id: "3", name: "free", rate: 0, description: null },
  { id: "4", name: "自用", rate: 1, description: null },
  { id: "5", name: "未定价", rate: null, description: null }, // i18n:skip
];

function storedKey(
  id: number,
  name: string,
  group: string | null,
  remoteId: string,
): StoredKeyRow {
  return {
    id,
    siteId: SITE_ID,
    name,
    group,
    remoteId,
    status: "enabled",
    quotaUsed: null,
    quotaLimit: null,
    currency: null,
  };
}

const KEYS: StoredKeyRow[] = [
  storedKey(1, "k-free", "free", "21"),
  storedKey(2, "k-plus", "gpt plus", "22"),
  storedKey(3, "k-nogroup", null, "23"),
  storedKey(4, "k-unknown-group", "已删除的分组", "24"),
  storedKey(5, "k-null-rate", "未定价", "25"), // i18n:skip
];

const REMOTE: KeyRow[] = [
  { remoteId: "21", name: "k-free", group: "free", status: "enabled" },
  { remoteId: "22", name: "k-plus", group: "gpt plus", status: "enabled" },
];

function renderKeys({
  groups = GROUPS,
  groupsReject = false,
  preloadGroups = true,
  sites = SITES,
}: {
  groups?: Group[];
  groupsReject?: boolean;
  /** `false` ⇒ 不预置缓存，用来证明页面挂载时真的会去站点拉分组（M30-S1 复审 P2-1）。 */
  preloadGroups?: boolean;
  sites?: SiteRow[];
} = {}) {
  vi.mocked(suggestKeyName).mockResolvedValue("codex/agent/20261021");
  vi.mocked(availableGroups).mockClear();
  vi.mocked(availableGroups).mockImplementation(async () => {
    if (groupsReject) throw new Error("站点不可用（测试注入）");
    return groups;
  });
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity, gcTime: Infinity } },
  });
  qc.setQueryData(["sites"], sites);
  qc.setQueryData(["stored-keys"], KEYS);
  qc.setQueryData(["rotation-due"], []);
  qc.setQueryData(["remote-keys", SITE_ID], REMOTE);
  if (!groupsReject && preloadGroups) qc.setQueryData(["groups", SITE_ID], groups);
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

/** 取某个表头所在的表格（`th` 文本 → 最近的 `table`）。 */
function tableWithHeader(text: string): HTMLTableElement {
  const th = screen.getAllByText(text).find((el) => el.tagName === "TH");
  expect(th, `找不到表头「${text}」`).toBeTruthy();
  return th!.closest("table") as HTMLTableElement;
}

/** 某一行里「k-xxx」名字对应的所有单元格文本。 */
function rowCellsOf(table: HTMLTableElement, name: string): string[] {
  const row = Array.from(table.querySelectorAll("tbody tr")).find((tr) =>
    (tr.textContent ?? "").includes(name),
  );
  expect(row, `找不到行 ${name}`).toBeTruthy();
  return Array.from(row!.querySelectorAll("td")).map((td) => td.textContent?.trim() ?? "");
}

describe("M30-S1 分组倍率展示", () => {
  it("formatGroupRate：0 = 免费、正数 = {rate}×、null / NaN / 负数 = 倍率未知", () => {
    // 先渲染一次 provider：`formatGroupRate` 读的是模块级 currentDict。
    render(
      <I18nProvider lang="zh-CN" initialDict={zhCN}>
        <span>x</span>
      </I18nProvider>,
    );
    expect(formatGroupRate(0)).toBe(zhCN.common.rateFree);
    expect(formatGroupRate(0.5)).toBe("0.5×");
    expect(formatGroupRate(0.085)).toBe("0.085×");
    for (const bad of [null, Number.NaN, -1]) {
      expect(formatGroupRate(bad)).toBe(zhCN.common.rateUnknown);
    }
  });

  it("本地密钥表：没有「远端 id」列，有「当前分组倍率」列", () => {
    renderKeys();
    const table = tableWithHeader(zhCN.keys.table.groupRate);
    const headers = Array.from(table.querySelectorAll("thead th")).map((th) => th.textContent);
    expect(headers).not.toContain(zhCN.keys.table.remoteId);
    expect(headers).toContain(zhCN.keys.table.groupRate);
  });

  it("本地密钥表：0 倍率显示免费、0.085 显示 0.085×、无分组 / 找不到 / 未定价显示对应值", () => {
    renderKeys();
    const table = tableWithHeader(zhCN.keys.table.groupRate);

    // 「分组」列在前、倍率列紧随其后：取该行倒数第 4 个单元格之前不好维护，
    // 这里直接断言「这一行里含有期望文本」。
    expect(rowCellsOf(table, "k-free")).toContain(zhCN.common.rateFree);
    expect(rowCellsOf(table, "k-free")).not.toContain("21"); // 远端 id 不再展示
    expect(rowCellsOf(table, "k-plus")).toContain("0.085×");
    expect(rowCellsOf(table, "k-nogroup")).toContain("—");
    expect(rowCellsOf(table, "k-unknown-group")).toContain("—");
    // 分组存在但站点没给倍率 ⇒ 未知，不是「免费」，也不是 1×。
    expect(rowCellsOf(table, "k-null-rate")).toContain(zhCN.common.rateUnknown);
    // 绝不回落 1×
    expect(rowCellsOf(table, "k-unknown-group")).not.toContain("1×");
  });

  it("页面打开即加载分组倍率（不需要先点「新建密钥」）", async () => {
    renderKeys({ preloadGroups: false });
    const table = tableWithHeader(zhCN.keys.table.groupRate);
    await waitFor(() => expect(rowCellsOf(table, "k-plus")).toContain("0.085×"));
    expect(availableGroups).toHaveBeenCalledTimes(1);
  });

  it("站点侧对照表：同样按分组名匹配倍率、无「远端 id」列", () => {
    renderKeys();
    const tables = screen.getAllByText(zhCN.keys.table.groupRate).filter((el) => el.tagName === "TH");
    expect(tables.length).toBe(2, "两张表都应有「当前分组倍率」表头");

    const remoteTable = tables[1].closest("table") as HTMLTableElement;
    const headers = Array.from(remoteTable.querySelectorAll("thead th")).map((th) => th.textContent);
    expect(headers).not.toContain(zhCN.keys.table.remoteId);
    expect(rowCellsOf(remoteTable, "k-free")).toContain(zhCN.common.rateFree);
    expect(rowCellsOf(remoteTable, "k-plus")).toContain("0.085×");
  });

  it("分组查询失败时表格照常渲染，倍率列显示 —（不猜测）", async () => {
    renderKeys({ groupsReject: true });
    const table = tableWithHeader(zhCN.keys.table.groupRate);
    expect(table).toBeTruthy();
    expect(rowCellsOf(table, "k-plus")).toContain("—");
    expect(rowCellsOf(table, "k-plus")).not.toContain("1×");
    // 表格本体的其它列还在（失败只影响倍率列）
    expect(rowCellsOf(table, "k-plus")).toContain("k-plus");
  });
});
