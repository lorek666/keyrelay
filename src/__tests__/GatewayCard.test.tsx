import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import GatewayCard from "../components/GatewayCard";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M41-S1：网关卡片的三态 + `lastExit` 展示。
 *
 * 钉死：running / stopped / crashed（crashed 显示时间 + 原因）；
 * 空态（lastExit 为 null）不得渲染出 `0` / 假时间。
 */

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    gatewayStatus: vi.fn(),
    listSites: vi.fn(),
    listStoredKeys: vi.fn(),
    listChannelBindings: vi.fn(),
  };
});

import {
  gatewayStatus,
  listChannelBindings,
  listSites,
  listStoredKeys,
  type GatewayStatus,
} from "../lib/api";

const status = (over: Partial<GatewayStatus> = {}): GatewayStatus => ({
  running: false,
  phase: "stopped",
  url: null,
  token: null,
  site: null,
  tokenPersistent: false,
  lastExit: null,
  // M40-S2：未运行 ⇒ 结构性空值（UI 不显示它们）
  mode: "stopped",
  candidates: [],
  qps: 0,
  requestsTotal: 0,
  inflight: 0,
  failoversTotal: 0,
  lastError: null,
  generation: 0,
  ...over,
});

function renderCard() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>
      <I18nProvider lang="zh-CN" initialDict={zhCN}>
        {children}
      </I18nProvider>
    </QueryClientProvider>
  );
  return render(
    <GatewayCard
      enabled
      port={8787}
      multiSite={false}
      collectModels={false}
      modelsMinIntervalSecs={1800}
      onToggle={vi.fn()}
      onPortChange={vi.fn()}
      onMultiSiteChange={vi.fn()}
      onCollectModelsChange={vi.fn()}
      onModelsIntervalChange={vi.fn()}
      settingsDirty={false}
    />,
    { wrapper },
  );
}

const phaseLine = () =>
  document.querySelector("[data-gateway-phase]") as HTMLElement | null;

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(listSites).mockResolvedValue([]);
  vi.mocked(listStoredKeys).mockResolvedValue([]);
  vi.mocked(listChannelBindings).mockResolvedValue([]);
});

describe("GatewayCard 三态（M41-S1）", () => {
  it("running：显示「运行中」，data-gateway-phase=running", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(
      status({
        running: true,
        phase: "running",
        url: "http://127.0.0.1:8787",
        token: "kr-gw-test",
        site: "示例站",
        tokenPersistent: true,
      }),
    );
    renderCard();
    await waitFor(() => expect(phaseLine()?.dataset.gatewayPhase).toBe("running"));
    expect(screen.getAllByText(zhCN.gateway.phase.running).length).toBeGreaterThan(0);
  });

  it("stopped：显示「已停止」，不渲染 time/原因（空态不显示 0）", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(status({ phase: "stopped" }));
    renderCard();
    await waitFor(() => expect(phaseLine()?.dataset.gatewayPhase).toBe("stopped"));
    const line = phaseLine()!;
    expect(line.textContent).toBe(zhCN.gateway.phase.stopped);
    expect(line.textContent).not.toContain("0");
  });

  it("crashed(panicked)：显示异常退出 + 时间 + 「任务崩溃」", async () => {
    const at = 1_700_000_000;
    vi.mocked(gatewayStatus).mockResolvedValue(
      status({ phase: "crashed", lastExit: { at, reason: "panicked" } }),
    );
    renderCard();
    await waitFor(() => expect(phaseLine()?.dataset.gatewayPhase).toBe("crashed"));
    const line = phaseLine()!;
    expect(line.textContent).toContain("异常退出");
    expect(line.textContent).toContain(
      new Date(at * 1000).toLocaleString(),
    );
    expect(line.textContent).toContain(zhCN.gateway.phase.reasonPanicked);
  });

  it("crashed(unexpected)：原因显示「任务提前结束」", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(
      status({ phase: "crashed", lastExit: { at: 1_700_000_100, reason: "unexpected" } }),
    );
    renderCard();
    await waitFor(() => expect(phaseLine()?.dataset.gatewayPhase).toBe("crashed"));
    expect(phaseLine()!.textContent).toContain(
      zhCN.gateway.phase.reasonUnexpected,
    );
  });
});

describe("M40-S2 网关指标面板", () => {
  it("U1 未运行只显示占位，不渲染 0/空表（空态不显示假数据）", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(status());
    renderCard();
    expect(await screen.findByText("网关未运行，暂无指标。")).toBeInTheDocument();
    expect(screen.queryByText("QPS（最近 60 秒）")).toBeNull();
    expect(screen.queryByText("总请求数")).toBeNull();
  });

  it("U3 刚启动（requestsTotal<3）时 QPS 显示 —，不显示 0.0", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(
      status({ running: true, phase: "running", requestsTotal: 1, qps: 0, mode: "single" }),
    );
    renderCard();
    expect(await screen.findByText("QPS（最近 60 秒）")).toBeInTheDocument();
    expect(screen.getByText("—")).toBeInTheDocument();
  });

  it("U5 运行中但无候选 ⇒ 显示「单上游模式」，不渲染空表", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(
      status({ running: true, phase: "running", mode: "single", requestsTotal: 10, qps: 2.5 }),
    );
    renderCard();
    expect(await screen.findByText("单上游模式：无候选列表。")).toBeInTheDocument();
    expect(screen.queryByRole("table")).toBeNull();
  });
});
