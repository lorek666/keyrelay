import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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

function renderCard(
  over: {
    maxRequestMib?: number;
    onMaxRequestMibChange?: () => void;
    perSiteBurst?: number;
    onPerSiteBurstChange?: (burst: number) => void;
    maxAttempts?: number;
    onMaxAttemptsChange?: (n: number) => void;
    keyHealthIntervalSecs?: number;
    onKeyHealthIntervalChange?: (secs: number) => void;
    routingRules?: string;
    onRoutingRulesChange?: (text: string) => void;
  } = {},
) {
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
      maxRequestMib={over.maxRequestMib ?? 16}
      perSiteBurst={over.perSiteBurst ?? 0}
      maxAttempts={over.maxAttempts ?? 0}
      keyHealthIntervalSecs={over.keyHealthIntervalSecs ?? 0}
      routingRules={over.routingRules ?? ""}
      onToggle={vi.fn()}
      onPortChange={vi.fn()}
      onMultiSiteChange={vi.fn()}
      onCollectModelsChange={vi.fn()}
      onModelsIntervalChange={vi.fn()}
      onMaxRequestMibChange={over.onMaxRequestMibChange ?? vi.fn()}
      onPerSiteBurstChange={over.onPerSiteBurstChange ?? vi.fn()}
      onMaxAttemptsChange={over.onMaxAttemptsChange ?? vi.fn()}
      onKeyHealthIntervalChange={over.onKeyHealthIntervalChange ?? vi.fn()}
      onRoutingRulesChange={over.onRoutingRulesChange ?? vi.fn()}
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

describe("M42-S1：监听地址 / IPv6 降级 / 请求体上限", () => {
  it("running：显示监听地址行；未降级时不显示降级提示", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(
      status({
        running: true,
        phase: "running",
        url: "http://127.0.0.1:8787",
        token: "kr-gw-test",
        site: "示例站",
        tokenPersistent: true,
        listenAddrs: ["127.0.0.1:8787", "[::1]:8787"],
        ipv6Degraded: false,
        ipv6Note: null,
      }),
    );
    renderCard();
    await waitFor(() => expect(phaseLine()?.dataset.gatewayPhase).toBe("running"));
    const row = document.querySelector("[data-gateway-listen-addrs]");
    expect(row?.textContent).toContain("127.0.0.1:8787");
    expect(row?.textContent).toContain("[::1]:8787");
    expect(document.querySelector("[data-gateway-ipv6='degraded']")).toBeNull();
  });

  it("running + ipv6Degraded：显示降级文案（含原因），且不是 role=alert 的错误条", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(
      status({
        running: true,
        phase: "running",
        url: "http://127.0.0.1:8787",
        token: "kr-gw-test",
        site: "示例站",
        tokenPersistent: true,
        listenAddrs: ["127.0.0.1:8787"],
        ipv6Degraded: true,
        ipv6Note: "IPv6 回环端口被占用，仅监听 127.0.0.1",
      }),
    );
    renderCard();
    await waitFor(() => expect(phaseLine()?.dataset.gatewayPhase).toBe("running"));
    const warn = document.querySelector("[data-gateway-ipv6='degraded']");
    expect(warn).not.toBeNull();
    expect(warn!.textContent).toContain("IPv6 回环端口被占用");
    expect(warn!.getAttribute("role")).not.toBe("alert");
  });

  it("请求体上限：输入 65 不触发回调；输入 32 触发一次", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(status({ phase: "stopped" }));
    const onChange = vi.fn();
    renderCard({ onMaxRequestMibChange: onChange });
    const input = screen.getByLabelText(
      zhCN.gateway.maxRequestLabel,
    ) as HTMLInputElement;
    expect(input.value).toBe("16");
    fireEvent.change(input, { target: { value: "65" } });
    expect(onChange).not.toHaveBeenCalled();
    fireEvent.change(input, { target: { value: "32" } });
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith(32);
  });

  it("M46-S4 maxAttempts：输入 65 不触发回调；输入 3 触发一次", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(status({ phase: "stopped" }));
    const onChange = vi.fn();
    renderCard({ maxAttempts: 0, onMaxAttemptsChange: onChange });
    const input = screen.getByLabelText(
      zhCN.gateway.maxAttemptsLabel,
    ) as HTMLInputElement;
    expect(input.value).toBe("0");
    fireEvent.change(input, { target: { value: "65" } });
    expect(onChange).not.toHaveBeenCalled();
    fireEvent.change(input, { target: { value: "3" } });
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith(3);
  });

  it("M46-S3 burst：输入 10001 不触发回调；输入 5 触发一次", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(status({ phase: "stopped" }));
    const onChange = vi.fn();
    renderCard({ perSiteBurst: 0, onPerSiteBurstChange: onChange });
    const input = screen.getByLabelText(
      zhCN.gateway.perSiteBurstLabel,
    ) as HTMLInputElement;
    expect(input.value).toBe("0");
    fireEvent.change(input, { target: { value: "10001" } });
    expect(onChange).not.toHaveBeenCalled();
    fireEvent.change(input, { target: { value: "5" } });
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith(5);
  });

  it("M46-S7 routingRules：文本域输入直传回调（前端不解析）", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(status({ phase: "stopped" }));
    const onChange = vi.fn();
    renderCard({ routingRules: "", onRoutingRulesChange: onChange });
    const input = screen.getByLabelText(
      zhCN.gateway.routingRulesLabel,
    ) as HTMLTextAreaElement;
    expect(input.value).toBe("");
    const text = '[{"agentLabel": "codex", "siteIds": [1, 2]}]';
    fireEvent.change(input, { target: { value: text } });
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith(text);
    // 非法 JSON 也不在前端拦截：解析权威在后端 validate。
    fireEvent.change(input, { target: { value: "{not json" } });
    expect(onChange).toHaveBeenCalledTimes(2);
    expect(onChange).toHaveBeenCalledWith("{not json");
  });

  it("M46-UI B-237 巡检间隔：输入 30 失焦钳制到 60 并回调一次 + 提示", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(status({ phase: "stopped" }));
    const onChange = vi.fn();
    renderCard({ keyHealthIntervalSecs: 0, onKeyHealthIntervalChange: onChange });
    const input = screen.getByLabelText(
      zhCN.gateway.keyHealthIntervalLabel,
    ) as HTMLInputElement;
    expect(input.value).toBe("0");
    // 草稿阶段不回调（允许用户先输 `6` 再输 `60`）。
    fireEvent.change(input, { target: { value: "30" } });
    expect(onChange).not.toHaveBeenCalled();
    fireEvent.blur(input);
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith(60);
    expect(input.value).toBe("60");
    expect(
      screen.getByText(zhCN.gateway.keyHealthIntervalClamped),
    ).toBeInTheDocument();
  });

  it("M46-UI B-237 巡检间隔：0 = 关（清空失焦回调 0）；99999 钳制到 86400", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(status({ phase: "stopped" }));
    const onChange = vi.fn();
    renderCard({ keyHealthIntervalSecs: 300, onKeyHealthIntervalChange: onChange });
    const input = screen.getByLabelText(
      zhCN.gateway.keyHealthIntervalLabel,
    ) as HTMLInputElement;
    expect(input.value).toBe("300");
    fireEvent.change(input, { target: { value: "" } });
    fireEvent.blur(input);
    expect(onChange).toHaveBeenCalledWith(0);
    expect(input.value).toBe("0");
    fireEvent.change(input, { target: { value: "99999" } });
    fireEvent.blur(input);
    expect(onChange).toHaveBeenCalledWith(86400);
    expect(input.value).toBe("86400");
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
    expect(document.querySelector("[data-gateway-qps]")?.textContent).toBe("—");
  });

  it("U3b 样本不足以后端 uptimeSecs 为准（请求数多也不显示 QPS）", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(
      status({
        running: true,
        phase: "running",
        requestsTotal: 10,
        qps: 2.5,
        uptimeSecs: 1,
        mode: "single",
      }),
    );
    renderCard();
    expect(await screen.findByText("QPS（最近 60 秒）")).toBeInTheDocument();
    expect(document.querySelector("[data-gateway-qps]")?.textContent).toBe("—");
  });

  it("U3c uptimeSecs 已够时即使请求数 < 3 也显示 QPS", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(
      status({
        running: true,
        phase: "running",
        requestsTotal: 1,
        qps: 2.5,
        uptimeSecs: 10,
        mode: "single",
      }),
    );
    renderCard();
    expect(await screen.findByText("QPS（最近 60 秒）")).toBeInTheDocument();
    expect(document.querySelector("[data-gateway-qps]")?.textContent).toBe("2.5");
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
