import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

/**
 * M39-S2：设置页的模型采集两个控件。
 *
 * 钉死三件事（spec §4.4/§7.3）：
 * ① `collect_models` 的勾选状态来自 DTO，改动会回调（多站关闭时**仍可编辑**，不静默禁用）；
 * ② 采集间隔越界/非数字 ⇒ **失焦钳制**到 30..=86400 并回调；
 * ③ 提示文案写明「多站关闭仍采集」，不是「仅多站模式下生效」。
 */

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    gatewayStatus: vi.fn(),
    listSites: vi.fn(),
    listStoredKeys: vi.fn(),
  };
});

import GatewayCard from "../components/GatewayCard";
import { gatewayStatus, listSites, listStoredKeys } from "../lib/api";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

type Props = Parameters<typeof GatewayCard>[0];

function renderCard(overrides: Partial<Props> = {}) {
  const props: Props = {
    enabled: true,
    port: 8787,
    multiSite: false,
    collectModels: false,
    modelsMinIntervalSecs: 1800,
    onToggle: vi.fn(),
    onPortChange: vi.fn(),
    onMultiSiteChange: vi.fn(),
    onCollectModelsChange: vi.fn(),
    onModelsIntervalChange: vi.fn(),
    settingsDirty: false,
    ...overrides,
  };
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity, gcTime: Infinity } },
  });
  qc.setQueryData(["gateway"], { running: false });
  qc.setQueryData(["sites"], []);
  qc.setQueryData(["stored-keys"], []);
  const uiWith = (p: Props) => <GatewayCard {...p} />;
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>
      <I18nProvider lang="zh-CN" initialDict={zhCN}>
        {children}
      </I18nProvider>
    </QueryClientProvider>
  );
  const { rerender } = render(uiWith(props), { wrapper });
  return {
    props,
    /** 用新的 props 重渲染（模拟后端重新加载 / 保存后 DTO 变化）。 */
    rerender: (next: Partial<Props>) => rerender(uiWith({ ...props, ...next })),
  };
}

beforeEach(() => {
  vi.mocked(gatewayStatus).mockResolvedValue({ running: false } as never);
  vi.mocked(listSites).mockResolvedValue([]);
  vi.mocked(listStoredKeys).mockResolvedValue([]);
});

describe("M39-S2 模型采集设置", () => {
  it("collectModels 勾选状态来自 props；勾选会回调", () => {
    const { props } = renderCard({ collectModels: false });
    const checkbox = screen.getByLabelText(zhCN.gateway.collectModelsLabel) as HTMLInputElement;
    expect(checkbox.checked).toBe(false);
    fireEvent.click(checkbox);
    expect(props.onCollectModelsChange).toHaveBeenCalledWith(true);
  });

  it("多站关闭时 collectModels 仍可编辑，并显示「仍会采集」的提示", () => {
    renderCard({ multiSite: false, collectModels: false });
    const checkbox = screen.getByLabelText(zhCN.gateway.collectModelsLabel) as HTMLInputElement;
    expect(checkbox.disabled).toBe(false);
    expect(screen.getByText(zhCN.gateway.collectModelsHint)).toBeTruthy();
    expect(zhCN.gateway.collectModelsHint).toContain("仍会采集");
    expect(zhCN.gateway.collectModelsHint).not.toContain("仅多站模式下生效");
  });

  it("采集间隔：5 ⇒ 失焦钳制到 30 并回调", () => {
    const { props } = renderCard({ modelsMinIntervalSecs: 1800 });
    const input = screen.getByLabelText(zhCN.gateway.modelsIntervalLabel) as HTMLInputElement;
    fireEvent.change(input, { target: { value: "5" } });
    fireEvent.blur(input);
    expect(input.value).toBe("30");
    expect(props.onModelsIntervalChange).toHaveBeenCalledWith(30);
    expect(screen.getByText(zhCN.gateway.modelsIntervalClamped)).toBeTruthy();
  });

  it("后端重新加载后 modelsMinIntervalSecs 变化 ⇒ 输入框跟着变", () => {
    const { rerender } = renderCard({ modelsMinIntervalSecs: 1800 });
    const input = screen.getByLabelText(zhCN.gateway.modelsIntervalLabel) as HTMLInputElement;
    expect(input.value).toBe("1800");

    rerender({ modelsMinIntervalSecs: 600 });
    expect(input.value).toBe("600", "props 变化必须同步进输入框");
  });

  it("采集间隔：999999 ⇒ 失焦钳制到 86400；正常值不提示", () => {
    const { props } = renderCard({ modelsMinIntervalSecs: 1800 });
    const input = screen.getByLabelText(zhCN.gateway.modelsIntervalLabel) as HTMLInputElement;
    fireEvent.change(input, { target: { value: "999999" } });
    fireEvent.blur(input);
    expect(input.value).toBe("86400");
    expect(props.onModelsIntervalChange).toHaveBeenCalledWith(86400);

    fireEvent.change(input, { target: { value: "600" } });
    fireEvent.blur(input);
    expect(input.value).toBe("600");
    expect(props.onModelsIntervalChange).toHaveBeenLastCalledWith(600);
  });
});
