import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
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
    gatewayTokenList: vi.fn(),
  };
});

import {
  gatewayStatus,
  gatewayTokenList,
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
    perSiteConcurrency?: number;
    onPerSiteConcurrencyChange?: (n: number) => void;
    perSiteRateLimit?: number;
    onPerSiteRateLimitChange?: (n: number) => void;
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
      perSiteConcurrency={over.perSiteConcurrency ?? 8}
      perSiteRateLimit={over.perSiteRateLimit ?? 0}
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
      onPerSiteConcurrencyChange={over.onPerSiteConcurrencyChange ?? vi.fn()}
      onPerSiteRateLimitChange={over.onPerSiteRateLimitChange ?? vi.fn()}
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
  vi.mocked(gatewayTokenList).mockResolvedValue([]);
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

  it("M46-UI B-241 每站并发：输入 0 与 129 不触发回调；输入 16 触发一次", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(status({ phase: "stopped" }));
    const onChange = vi.fn();
    renderCard({ perSiteConcurrency: 8, onPerSiteConcurrencyChange: onChange });
    const input = screen.getByLabelText(
      zhCN.gateway.perSiteConcurrencyLabel,
    ) as HTMLInputElement;
    expect(input.value).toBe("8");
    fireEvent.change(input, { target: { value: "0" } });
    expect(onChange).not.toHaveBeenCalled();
    fireEvent.change(input, { target: { value: "129" } });
    expect(onChange).not.toHaveBeenCalled();
    fireEvent.change(input, { target: { value: "16" } });
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith(16);
  });

  it("M46-UI B-241 每站每秒上限：输入 10001 不触发回调；输入 10 触发一次", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(status({ phase: "stopped" }));
    const onChange = vi.fn();
    renderCard({ perSiteRateLimit: 0, onPerSiteRateLimitChange: onChange });
    const input = screen.getByLabelText(
      zhCN.gateway.perSiteRateLimitLabel,
    ) as HTMLInputElement;
    expect(input.value).toBe("0");
    fireEvent.change(input, { target: { value: "10001" } });
    expect(onChange).not.toHaveBeenCalled();
    fireEvent.change(input, { target: { value: "10" } });
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith(10);
  });

  it("M46-S7 routingRules：回退原文模式下输入直传回调（前端不解析）", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(status({ phase: "stopped" }));
    const onChange = vi.fn();
    // M46-UI B-255：空规则走结构化视图；不可解析文本才走原文 textarea，
    // 原文模式下输入仍直传、不在前端拦截（解析权威在后端 validate）。
    renderCard({ routingRules: "{not json", onRoutingRulesChange: onChange });
    const input = screen.getByLabelText(
      zhCN.gateway.routingRulesLabel,
    ) as HTMLTextAreaElement;
    expect(input.value).toBe("{not json");
    const text = '[{"agentLabel": "codex", "siteIds": [1, 2]}]';
    fireEvent.change(input, { target: { value: text } });
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith(text);
    fireEvent.change(input, { target: { value: "{still bad" } });
    expect(onChange).toHaveBeenCalledTimes(2);
    expect(onChange).toHaveBeenCalledWith("{still bad");
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

describe("M46-UI B-240 EWMA 列", () => {
  const runningWithCandidate = (over: Record<string, unknown> = {}) =>
    status({
      running: true,
      phase: "running",
      mode: "multi",
      requestsTotal: 10,
      qps: 2.5,
      candidates: [
        {
          siteId: 7,
          displayName: "站A",
          keyId: 1,
          health: "healthy",
          breaker: "closed",
        },
      ],
      ...over,
    });

  it("有样本显示毫秒数", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(
      runningWithCandidate({ ewmaLatencyMs: { 7: 42 } }),
    );
    renderCard();
    expect(await screen.findByText("EWMA 延迟")).toBeInTheDocument();
    expect(screen.getByText("42 ms")).toBeInTheDocument();
  });

  it("无样本显示 —，不画成 0（空 map 与旧后端缺字段两种情形）", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(
      runningWithCandidate({ ewmaLatencyMs: {} }),
    );
    const { unmount } = renderCard();
    await screen.findByText("EWMA 延迟");
    const table = document.querySelector("table");
    expect(table?.textContent).toContain("—");
    expect(table?.textContent).not.toContain("0 ms");
    unmount();
    // 旧后端：ewmaLatencyMs 字段本身缺失（undefined），同样回退到 —。
    vi.mocked(gatewayStatus).mockResolvedValue(runningWithCandidate());
    renderCard();
    await screen.findByText("EWMA 延迟");
    const table2 = document.querySelector("table");
    expect(table2?.textContent).toContain("—");
    expect(table2?.textContent).not.toContain("0 ms");
  });

  it("红线：EWMA 真为 0ms 时显示 0 ms，不得被真值判断吞成 —", async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(
      runningWithCandidate({ ewmaLatencyMs: { 7: 0 } }),
    );
    renderCard();
    await screen.findByText("EWMA 延迟");
    expect(screen.getByText("0 ms")).toBeInTheDocument();
  });
});

describe("M46-UI B-255 结构化路由规则编辑器", () => {
  const site = (id: number, displayName: string) => ({
    id,
    kind: "newapi",
    baseUrl: "https://example.invalid",
    displayName,
    health: "unknown",
  });
  const tok = (id: number, label: string, active = true) => ({
    id,
    label,
    createdAt: 0,
    revokedAt: null,
    lastUsedAt: null,
    active,
    isDefault: false,
  });
  const setup = async (routingRules: string) => {
    vi.mocked(gatewayStatus).mockResolvedValue(status({ phase: "stopped" }));
    vi.mocked(listSites).mockResolvedValue([site(1, "Alpha"), site(2, "Beta")]);
    vi.mocked(gatewayTokenList).mockResolvedValue([
      tok(1, "codex"),
      tok(2, "opencode"),
    ]);
    const onChange = vi.fn();
    renderCard({ routingRules, onRoutingRulesChange: onChange });
    // 等令牌查询回落（令牌列表 <ul> 出现才说明 mock 查询已解析；只等标题
    // 不够——标题是同步渲染的，查询回落前编辑器里还没有站点复选框与令牌选项）。
    await waitFor(() =>
      expect(document.querySelector(".gateway-token-list")).toBeInTheDocument(),
    );
    return onChange;
  };
  const row = (i: number) =>
    document.querySelector(`[data-routing-row="${i}"]`) as HTMLElement;

  it("已有规则渲染为行：agent 下拉选中 + 站点多选勾选", async () => {
    await setup('[{"agentLabel":"codex","siteIds":[1,2]}]');
    await waitFor(() =>
      expect(row(0).querySelectorAll('input[type="checkbox"]')).toHaveLength(2),
    );
    const r = row(0);
    expect(r).toBeInTheDocument();
    const select = r.querySelector("select") as HTMLSelectElement;
    expect(select.value).toBe("codex");
    const boxes = r.querySelectorAll('input[type="checkbox"]');
    expect(boxes).toHaveLength(2);
    expect((boxes[0] as HTMLInputElement).checked).toBe(true);
    expect((boxes[1] as HTMLInputElement).checked).toBe(true);
  });

  it("增行 + 选 agent + 勾站点：每次变更都把整表 JSON 回调出去", async () => {
    const onChange = await setup("");
    fireEvent.click(screen.getByText(zhCN.gateway.routingRulesAddRow));
    expect(onChange).toHaveBeenLastCalledWith(
      '[{"agentLabel":"","siteIds":[]}]',
    );
    await waitFor(() =>
      expect(row(0).querySelectorAll('input[type="checkbox"]')).toHaveLength(2),
    );
    const r = row(0);
    fireEvent.change(r.querySelector("select") as HTMLSelectElement, {
      target: { value: "opencode" },
    });
    expect(onChange).toHaveBeenLastCalledWith(
      '[{"agentLabel":"opencode","siteIds":[]}]',
    );
    fireEvent.click(r.querySelectorAll('input[type="checkbox"]')[0]);
    expect(onChange).toHaveBeenLastCalledWith(
      '[{"agentLabel":"opencode","siteIds":[1]}]',
    );
  });

  it("删行：回调只剩剩余行", async () => {
    const onChange = await setup(
      '[{"agentLabel":"codex","siteIds":[1]},{"agentLabel":"opencode","siteIds":[2]}]',
    );
    fireEvent.click(
      row(0).querySelector("button") as HTMLButtonElement,
    );
    expect(onChange).toHaveBeenLastCalledWith(
      '[{"agentLabel":"opencode","siteIds":[2]}]',
    );
  });

  it("未填完整的行挂提示（不拦截：提示只是提示，保存由后端裁决）", async () => {
    await setup('[{"agentLabel":"","siteIds":[]}]');
    expect(
      screen.getByText(zhCN.gateway.routingRulesRowIncomplete),
    ).toBeInTheDocument();
  });

  it("不可解析文本回退原文编辑 + 提示，不丢文本", async () => {
    const onChange = await setup('{"agentLabel": "codex"}');
    expect(
      screen.getByText(zhCN.gateway.routingRulesFallbackNote),
    ).toBeInTheDocument();
    expect(document.querySelector("[data-routing-row]")).toBeNull();
    const input = screen.getByLabelText(
      zhCN.gateway.routingRulesLabel,
    ) as HTMLTextAreaElement;
    expect(input.value).toBe('{"agentLabel": "codex"}');
    fireEvent.change(input, { target: { value: "{still bad" } });
    expect(onChange).toHaveBeenCalledWith("{still bad");
  });
});

describe("M46-UI B-255 回流（复审 P1-1 回归）", () => {
  // 模拟真实 Settings：onChange 写回父级 state 再以 prop 回流，而非静态 mock。
  const renderReflowCard = (initial: string) => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    });
    const Harness = () => {
      const [rules, setRules] = useState(initial);
      return (
        <QueryClientProvider client={qc}>
          <I18nProvider lang="zh-CN" initialDict={zhCN}>
            <GatewayCard
              enabled
              port={8787}
              multiSite={false}
              collectModels={false}
              modelsMinIntervalSecs={1800}
              maxRequestMib={16}
              perSiteBurst={0}
              perSiteConcurrency={8}
              perSiteRateLimit={0}
              maxAttempts={0}
              keyHealthIntervalSecs={0}
              routingRules={rules}
              onToggle={vi.fn()}
              onPortChange={vi.fn()}
              onMultiSiteChange={vi.fn()}
              onCollectModelsChange={vi.fn()}
              onModelsIntervalChange={vi.fn()}
              onMaxRequestMibChange={vi.fn()}
              onPerSiteBurstChange={vi.fn()}
              onPerSiteConcurrencyChange={vi.fn()}
              onPerSiteRateLimitChange={vi.fn()}
              onMaxAttemptsChange={vi.fn()}
              onKeyHealthIntervalChange={vi.fn()}
              onRoutingRulesChange={setRules}
              settingsDirty={false}
            />
          </I18nProvider>
        </QueryClientProvider>
      );
    };
    return render(<Harness />);
  };
  const site = (id: number, displayName: string) => ({
    id,
    kind: "newapi",
    baseUrl: "https://example.invalid",
    displayName,
    health: "unknown",
  });
  const tok = (id: number, label: string) => ({
    id,
    label,
    createdAt: 0,
    revokedAt: null,
    lastUsedAt: null,
    active: true,
    isDefault: false,
  });
  const setupReflow = async (initial: string) => {
    vi.mocked(gatewayStatus).mockResolvedValue(status({ phase: "stopped" }));
    vi.mocked(listSites).mockResolvedValue([site(1, "Alpha"), site(2, "Beta")]);
    vi.mocked(gatewayTokenList).mockResolvedValue([tok(1, "codex")]);
    renderReflowCard(initial);
    await waitFor(() =>
      expect(document.querySelector(".gateway-token-list")).toBeInTheDocument(),
    );
  };

  it("回退文本在 textarea 里改合法后，父级回流即翻回结构化（不粘住）", async () => {
    await setupReflow("{not json");
    const input = screen.getByLabelText(
      zhCN.gateway.routingRulesLabel,
    ) as HTMLTextAreaElement;
    expect(input.value).toBe("{not json");
    fireEvent.change(input, {
      target: { value: '[{"agentLabel":"codex","siteIds":[1]}]' },
    });
    await waitFor(() =>
      expect(document.querySelector('[data-routing-row="0"]')).toBeInTheDocument(),
    );
    // 原文 textarea 已卸载，行内解析结果与输入一致（非空翻）。
    expect(screen.queryByLabelText(zhCN.gateway.routingRulesLabel)).toBeNull();
    const r = document.querySelector('[data-routing-row="0"]') as HTMLElement;
    expect((r.querySelector("select") as HTMLSelectElement).value).toBe("codex");
    expect(
      (r.querySelectorAll('input[type="checkbox"]')[0] as HTMLInputElement).checked,
    ).toBe(true);
  });

  it("结构化增行后父级回流不重置行", async () => {
    await setupReflow('[{"agentLabel":"codex","siteIds":[1]}]');
    await waitFor(() =>
      expect(
        document.querySelector('[data-routing-row="0"]'),
      ).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByText(zhCN.gateway.routingRulesAddRow));
    // 回流后的 prop 是增行后的整表 JSON；行数仍为 2（未被重解析冲掉），
    // 第 0 行 agent 仍为 codex。
    await waitFor(() =>
      expect(
        document.querySelector('[data-routing-row="1"]'),
      ).toBeInTheDocument(),
    );
    const r0 = document.querySelector('[data-routing-row="0"]') as HTMLElement;
    expect((r0.querySelector("select") as HTMLSelectElement).value).toBe("codex");
  });
});

describe("合并回归（main ← feat-m46-ui）：老调用方不传 routingRules 不炸卡", () => {
  it("routingRules 缺省时按空规则渲染，不在 parseRoutingRules 的 trim 上崩", async () => {
    // M46-UI-5 之前没有 routingRules 这个 prop；老用例（GatewayTokens、
    // SettingsModels）渲染 GatewayCard 时不传它。编辑器缺省 "" 后应按
    // 空规则进结构化视图（增行按钮在），而不是整卡白屏。
    vi.mocked(gatewayStatus).mockResolvedValue(status({ phase: "stopped" }));
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    });
    const props = {
      enabled: true,
      port: 8787,
      multiSite: false,
      collectModels: false,
      modelsMinIntervalSecs: 1800,
      maxRequestMib: 16,
      perSiteBurst: 0,
      perSiteConcurrency: 8,
      perSiteRateLimit: 0,
      maxAttempts: 0,
      keyHealthIntervalSecs: 0,
      onToggle: vi.fn(),
      onPortChange: vi.fn(),
      onMultiSiteChange: vi.fn(),
      onCollectModelsChange: vi.fn(),
      onModelsIntervalChange: vi.fn(),
      onMaxRequestMibChange: vi.fn(),
      onPerSiteBurstChange: vi.fn(),
      onPerSiteConcurrencyChange: vi.fn(),
      onPerSiteRateLimitChange: vi.fn(),
      onMaxAttemptsChange: vi.fn(),
      onKeyHealthIntervalChange: vi.fn(),
      onRoutingRulesChange: vi.fn(),
      settingsDirty: false,
    } as unknown as Parameters<typeof GatewayCard>[0];
    render(
      <QueryClientProvider client={qc}>
        <I18nProvider lang="zh-CN" initialDict={zhCN}>
          <GatewayCard {...props} />
        </I18nProvider>
      </QueryClientProvider>,
    );
    // 空令牌列表时 .gateway-token-list 不渲染（只有空态文案），不能拿它
    // 当渲染完成的信号；直接等结构化视图的增行按钮：它在，说明编辑器
    // 按空规则进了结构化视图、没有在 trim 上崩、卡片也渲染出来了。
    await waitFor(() =>
      expect(screen.getByText(zhCN.gateway.routingRulesAddRow)).toBeInTheDocument(),
    );
  });
});

describe("DEBUG-G6 P2-F1 批量改指：下线与未知行分流", () => {
  const openBatch = async () => {
    vi.mocked(gatewayStatus).mockResolvedValue(
      status({
        running: true,
        phase: "running",
        url: "http://127.0.0.1:8787",
        site: "示例站",
        tokenPersistent: true,
      }),
    );
    vi.mocked(listChannelBindings).mockResolvedValue([
      { bindingId: 1, agentId: "cline-desktop", keyId: 7, targetPath: "/home/u/.config/claude-desktop.json", siteId: 0 },
      { bindingId: 2, agentId: "weird-old", keyId: 7, targetPath: "/home/u/.weird/config.json", siteId: 0 },
      { bindingId: 3, agentId: "codex", keyId: 7, targetPath: "/home/u/.codex/auth.json", siteId: 0 },
    ]);
    renderCard();
    await waitFor(() => expect(phaseLine()?.dataset.gatewayPhase).toBe("running"));
    const batchBtn = Array.from(document.querySelectorAll("button")).find((b) =>
      b.textContent?.includes(zhCN.gateway.batch.btn),
    )!;
    fireEvent.click(batchBtn);
    await waitFor(() =>
      expect(document.body.textContent).toContain("/home/u/.config/claude-desktop.json"),
    );
  };

  const rowCheckbox = (path: string) => {
    const label = Array.from(document.querySelectorAll("label")).find((l) =>
      l.textContent?.includes(path),
    )!;
    return label.querySelector<HTMLInputElement>("input[type=checkbox]")!;
  };

  it("cline-desktop 行指向 cline auth CLI，未知行不再说“勾了也会失败”", async () => {
    await openBatch();
    expect(document.body.textContent).toContain("cline auth CLI");
    expect(document.body.textContent).toContain(zhCN.gateway.batch.delistedPost);
    expect(document.body.textContent).toContain(zhCN.gateway.batch.unmappedPost);
    expect(document.body.textContent).not.toContain("勾了也会失败");
  });

  it("勾选未映射/下线行并预览后，执行按钮被禁用（不是“勾选后失败”）", async () => {
    await openBatch();
    fireEvent.click(rowCheckbox("/home/u/.config/claude-desktop.json"));
    fireEvent.click(rowCheckbox("/home/u/.weird/config.json"));
    const previewBtn = Array.from(document.querySelectorAll("button")).find((b) =>
      b.textContent?.includes(zhCN.gateway.batch.previewBtnIdle),
    )!;
    fireEvent.click(previewBtn);
    await waitFor(() =>
      expect(document.body.textContent).toContain(zhCN.gateway.batch.delistedFull),
    );
    const applyBtn = Array.from(document.querySelectorAll("button")).find((b) =>
      b.textContent?.includes(zhCN.gateway.batch.applyBtnIdle),
    )!;
    expect(applyBtn.disabled).toBe(true);
  });
});
