import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import VaultMigrationCard from "../components/VaultMigrationCard";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

/**
 * M38-S2 / B-219：设置页「钥匙串迁移」卡片。
 *
 * 钉死：四态渲染、重试成功、重试失败不清状态、放弃需确认、取消不发请求、done 禁用重试。
 */

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    vaultMigrationStatus: vi.fn(),
    vaultMigrationRetry: vi.fn(),
    vaultMigrationAbandon: vi.fn(),
  };
});

import {
  vaultMigrationAbandon,
  vaultMigrationRetry,
  vaultMigrationStatus,
  type VaultMigrationStatus,
} from "../lib/api";

const status = (over: Partial<VaultMigrationStatus> = {}): VaultMigrationStatus => ({
  phase: "pending",
  attempts: 0,
  lastAt: null,
  lastError: null,
  failures: [],
  cleanupPending: [],
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
  return render(<VaultMigrationCard />, { wrapper });
}

const retryBtn = () => screen.getByRole("button", { name: new RegExp(zhCN.settings.vaultMigration.retry) });
const abandonBtn = () => screen.getByRole("button", { name: new RegExp(zhCN.settings.vaultMigration.abandon) });

beforeEach(() => {
  vi.clearAllMocks();
});

describe("VaultMigrationCard（M38-S2）", () => {
  it("pending：显示待迁移、attempts、失败数与首条原因，重试/放弃可用", async () => {
    vi.mocked(vaultMigrationStatus).mockResolvedValue(
      status({
        attempts: 1,
        lastAt: 1_700_000_000,
        failures: [{ reference: "kr/key/1/secret", reason: "读取源条目失败: 模拟" }],
      }),
    );
    renderCard();
    await waitFor(() => expect(screen.getByText(zhCN.settings.vaultMigration.phasePending)).toBeTruthy());
    expect(screen.getByText(/已尝试 1 次/)).toBeTruthy();
    expect(screen.getByText(/1 条未迁移/)).toBeTruthy();
    expect(screen.getByText(/kr\/key\/1\/secret/)).toBeTruthy();
    expect(retryBtn().disabled).toBe(false);
    expect(abandonBtn().disabled).toBe(false);
  });

  it("retryExhausted：显示「自动重试次数已用尽」，重试仍可用", async () => {
    vi.mocked(vaultMigrationStatus).mockResolvedValue(status({ phase: "retryExhausted", attempts: 2 }));
    renderCard();
    await waitFor(() =>
      expect(screen.getByText(zhCN.settings.vaultMigration.phaseRetryExhausted)).toBeTruthy(),
    );
    expect(retryBtn().disabled).toBe(false);
  });

  it("done：重试与放弃都禁用", async () => {
    vi.mocked(vaultMigrationStatus).mockResolvedValue(status({ phase: "done", attempts: 1 }));
    renderCard();
    await waitFor(() => expect(screen.getByText(zhCN.settings.vaultMigration.phaseDone)).toBeTruthy());
    expect(retryBtn().disabled).toBe(true);
    expect(abandonBtn().disabled).toBe(true);
  });

  it("重试成功（failed 为空）：显示 retryDone 并刷新状态", async () => {
    vi.mocked(vaultMigrationStatus)
      .mockResolvedValueOnce(status({ attempts: 1 }))
      .mockResolvedValueOnce(status({ phase: "done", attempts: 2 }));
    vi.mocked(vaultMigrationRetry).mockResolvedValue({
      imported: 1,
      skipped: 0,
      cleanupPending: [],
      failed: [],
      status: status({ phase: "done", attempts: 2 }),
    });
    renderCard();
    await waitFor(() => expect(retryBtn().disabled).toBe(false));
    fireEvent.click(retryBtn());
    await waitFor(() =>
      expect(screen.getByText(zhCN.settings.vaultMigration.retryDone)).toBeTruthy(),
    );
    await waitFor(() => expect(screen.getByText(zhCN.settings.vaultMigration.phaseDone)).toBeTruthy());
    expect(vaultMigrationStatus).toHaveBeenCalledTimes(2);
  });

  it("重试失败（有 failed）：显示 retryFailed，且不清空已展示的状态", async () => {
    vi.mocked(vaultMigrationStatus).mockResolvedValue(
      status({ attempts: 1, failures: [{ reference: "kr/key/2/secret", reason: "读取失败" }] }),
    );
    vi.mocked(vaultMigrationRetry).mockResolvedValue({
      imported: 0,
      skipped: 0,
      cleanupPending: [],
      failed: [{ reference: "kr/key/2/secret", reason: "读取失败" }],
      status: status({ attempts: 2, failures: [{ reference: "kr/key/2/secret", reason: "读取失败" }] }),
    });
    renderCard();
    await waitFor(() => expect(screen.getByText(/kr\/key\/2\/secret/)).toBeTruthy());
    fireEvent.click(retryBtn());
    await waitFor(() =>
      expect(screen.getByText(zhCN.settings.vaultMigration.retryFailed)).toBeTruthy(),
    );
    // 状态没被清空：phase / 失败原因仍在
    expect(screen.getByText(zhCN.settings.vaultMigration.phasePending)).toBeTruthy();
    expect(screen.getByText(/kr\/key\/2\/secret/)).toBeTruthy();
  });

  it("放弃：需二次确认；取消不发请求；确认后调用 abandon 并显示已放弃", async () => {
    vi.mocked(vaultMigrationStatus).mockResolvedValue(status());
    vi.mocked(vaultMigrationAbandon).mockResolvedValue(status({ phase: "abandoned" }));
    renderCard();
    await waitFor(() => expect(abandonBtn().disabled).toBe(false));

    fireEvent.click(abandonBtn());
    const dialog = await screen.findByRole("dialog");
    expect(dialog.textContent).toContain(zhCN.settings.vaultMigration.abandonTitle);
    // 取消：不发请求，弹窗关闭
    fireEvent.click(screen.getByRole("button", { name: zhCN.confirm.cancel }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(vaultMigrationAbandon).not.toHaveBeenCalled();

    // 再打开并确认
    fireEvent.click(abandonBtn());
    await screen.findByRole("dialog");
    fireEvent.click(screen.getByRole("button", { name: zhCN.settings.vaultMigration.abandonConfirm }));
    await waitFor(() => expect(vaultMigrationAbandon).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(screen.getByText(zhCN.settings.vaultMigration.abandoned)).toBeTruthy(),
    );
  });
});
