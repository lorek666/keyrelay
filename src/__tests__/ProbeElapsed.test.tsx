import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import Probe from "../pages/Probe";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M18-S1：probe 主路径从「一次性同步 POST」改成「异步提交 + 轮询到终态」，一次检测的
 * 整体等待从秒级变成**可达 15 分钟**（真机实测单次 187–360s）。界面只转一个圈的话，
 * 用户会把一段正常的等待当成卡死。
 *
 * 这里只钉死一件事：**进行中看得见已等待时长**，且这个时长自点击起算、随秒自增、
 * 请求结束或组件卸载时把定时器收干净。时间靠假时钟推进，不真等 1 秒。
 */

vi.mock("../lib/api", () => ({
  listSites: vi.fn(),
  listStoredKeys: vi.fn(),
  listProbeRuns: vi.fn(),
  probeRun: vi.fn(),
}));

import {
  listSites,
  listStoredKeys,
  listProbeRuns,
  probeRun,
  type ProbeRun,
  type SiteRow,
  type StoredKeyRow,
} from "../lib/api";

const mockedSites = vi.mocked(listSites);
const mockedKeys = vi.mocked(listStoredKeys);
const mockedHistory = vi.mocked(listProbeRuns);
const mockedProbe = vi.mocked(probeRun);

const SITE_ID = 1;
const KEY_ID = 7;

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
      groups: false,
      keyUsage: false,
    },
  },
];

const KEYS: StoredKeyRow[] = [
  {
    id: KEY_ID,
    siteId: SITE_ID,
    remoteId: "remote-1",
    name: "keyrelay/test/20261017",
    status: "enabled",
  },
];

const RUN: ProbeRun = {
  runId: "run-1",
  status: "completed",
  identityStatus: "match",
  verdictStatus: "clean_match",
  trueFamily: "openai",
  trueModel: "gpt-4o",
  spoofMethod: null,
  confidence: "high",
  warningsCount: 0,
  reportUrl: null,
  createdAt: 1700000000,
  completedAt: 1700000060,
};

/** 永不落地的检测请求：把界面**钉在**「进行中」，好检查这一段的渲染。 */
const NEVER: Promise<ProbeRun> = new Promise<ProbeRun>(() => {});

const ELAPSED_0 = "已等待 0:00";
const HINT = "重模型检测需要数分钟，请保持窗口打开、勿重复提交。";

/** 数据先灌进 query cache：首屏即成功态，不必等异步加载（假时钟下等起来更绕）。 */
function renderProbe() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity, gcTime: Infinity } },
  });
  qc.setQueryData(["sites"], SITES);
  qc.setQueryData(["stored-keys"], KEYS);
  qc.setQueryData(["probe-runs"], []);
  return render(<Probe />, {
    wrapper: ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={qc}>
        <I18nProvider lang="zh-CN" initialDict={zhCN}>
          {children}
        </I18nProvider>
      </QueryClientProvider>
    ),
  });
}

/** 填到可提交，然后点「开始检测」。 */
function startProbe() {
  fireEvent.change(screen.getAllByRole("combobox")[1], {
    target: { value: String(KEY_ID) },
  });
  fireEvent.change(screen.getAllByRole("textbox")[0], {
    target: { value: "openai/gpt-4o" },
  });
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByText("开始检测"));
}

/** 推假时钟（顺带把这次推进引起的渲染包进 act）。 */
async function advance(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

/**
 * 盯住计时器本身：延时 1000ms 的那个 `setInterval` 就是本页的「已等待」走表器
 * （React / react-query 都不起 1s 定时器）。用来断言它在收尾时被 `clearInterval` 掉。
 *
 * 必须在 `vi.useFakeTimers()` **之后**再 spy：反过来的话，假时钟会把 spy 整个换掉，
 * 间谍一次都记不到。
 */
function spyTimers() {
  const setSpy = vi.spyOn(globalThis, "setInterval");
  const clearSpy = vi.spyOn(globalThis, "clearInterval");
  return {
    intervalId(): number {
      const i = setSpy.mock.calls.findIndex((call) => call[1] === 1000);
      expect(i).toBeGreaterThanOrEqual(0);
      return setSpy.mock.results[i].value as number;
    },
    clearedIds(): unknown[] {
      return clearSpy.mock.calls.map((call) => call[0]);
    },
  };
}

describe("Probe 检测进行中的已等待时长（M18-S1）", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    mockedSites.mockResolvedValue(SITES);
    mockedKeys.mockResolvedValue(KEYS);
    mockedHistory.mockResolvedValue([]);
    mockedProbe.mockReturnValue(NEVER);
  });

  afterEach(() => {
    // 先还原 spy（回到假时钟那套），再卸载假时钟——顺序反了会把假 setInterval 留在全局。
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("点击「开始检测」后立刻可见已等待时长与预期提示", () => {
    renderProbe();
    startProbe();

    expect(screen.getByText("检测中…")).toBeInTheDocument();
    expect(screen.getByText(ELAPSED_0)).toBeInTheDocument();
    expect(screen.getByText(HINT)).toBeInTheDocument();
  });

  it("时长随秒自增：3 秒 → 0:03，再过 4 分钟 → 4:03（分:秒 进位）", async () => {
    renderProbe();
    startProbe();

    await advance(3000);
    expect(screen.getByText("已等待 0:03")).toBeInTheDocument();

    await advance(240_000);
    expect(screen.getByText("已等待 4:03")).toBeInTheDocument();
    expect(screen.queryByText("已等待 0:03")).toBeNull();
  });

  it("计时自点击那一刻起算：挂载后先空转 5 秒再点，1 秒后是 0:01 而不是 0:06", async () => {
    renderProbe();

    // 表单填好但没点：这一段不该被算进等待时长。
    fireEvent.change(screen.getAllByRole("combobox")[1], {
      target: { value: String(KEY_ID) },
    });
    fireEvent.change(screen.getAllByRole("textbox")[0], {
      target: { value: "openai/gpt-4o" },
    });
    fireEvent.click(screen.getByRole("checkbox"));
    await advance(5000);

    fireEvent.click(screen.getByText("开始检测"));
    expect(screen.getByText(ELAPSED_0)).toBeInTheDocument();

    // 关键一步：如果起算点被记成了「挂载时刻」，这里会是 0:06。
    await advance(1000);
    expect(screen.getByText("已等待 0:01")).toBeInTheDocument();
  });

  it("请求落地后不再显示时长，且计时器被清掉", async () => {
    mockedProbe.mockResolvedValue(RUN);
    const timers = spyTimers();
    renderProbe();
    startProbe();

    expect(screen.getByText(ELAPSED_0)).toBeInTheDocument();
    const id = timers.intervalId();

    await advance(0); // 让已 resolve 的 mutation 收尾
    expect(screen.queryByText(/已等待/)).toBeNull();
    expect(timers.clearedIds()).toContain(id);
  });

  it("组件卸载时计时器被清掉（不残留每秒 tick）", () => {
    const timers = spyTimers();
    const { unmount } = renderProbe();
    startProbe();

    const id = timers.intervalId();
    expect(timers.clearedIds()).not.toContain(id);

    unmount();
    expect(timers.clearedIds()).toContain(id);
  });
});
