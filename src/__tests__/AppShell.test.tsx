import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import App from "../App";
import zhCN from "../i18n/zh-CN.json";

vi.mock("../lib/theme", () => ({ useApplyTheme: vi.fn() }));

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  Object.defineProperty(HTMLElement.prototype, "scrollTo", { configurable: true, value: vi.fn() });
});

describe("App shell", () => {
  it("七中心只有一个当前项，标题跟随导航且可键盘操作", async () => {
    render(<App initialDict={zhCN} />, { wrapper });
    await waitFor(() => expect(screen.getByRole("button", { name: "指挥舱", exact: true })).toHaveAttribute("aria-current", "page"));
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "流量", exact: true }));
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("流量");
    expect(screen.getByRole("button", { name: "流量", exact: true })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("button", { name: "指挥舱", exact: true })).not.toHaveAttribute("aria-current");
    expect(screen.getAllByRole("button", { name: /^(指挥舱|流量|成本|健康|资产|投递|设置)$/ })).toHaveLength(7);
    fireEvent.keyDown(screen.getByRole("button", { name: "流量", exact: true }), { key: "Tab" });
    expect(document.activeElement).not.toBeNull();
  });

  it("网关状态只读展示，可跳到设置而不调用启停", async () => {
    const api = await import("../lib/api");
    const start = vi.spyOn(api, "gatewayStart");
    const stop = vi.spyOn(api, "gatewayStop");
    render(<App initialDict={zhCN} />, { wrapper });
    await waitFor(() => expect(screen.getByRole("button", { name: "打开网关设置" })).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "打开网关设置" }));
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("设置");
    expect(start).not.toHaveBeenCalled();
    expect(stop).not.toHaveBeenCalled();
    start.mockRestore();
    stop.mockRestore();
  });
});
