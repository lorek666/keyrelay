import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import UpdateChecker from "../components/UpdateChecker";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";

vi.mock("../lib/api", () => ({
  checkForUpdates: vi.fn(),
  downloadAndInstallUpdate: vi.fn(),
  relaunchApp: vi.fn(),
}));

import { checkForUpdates, downloadAndInstallUpdate, relaunchApp } from "../lib/api";

const mockedCheck = vi.mocked(checkForUpdates);
const mockedInstall = vi.mocked(downloadAndInstallUpdate);
const mockedRelaunch = vi.mocked(relaunchApp);

// M14-S2：UpdateChecker 现在用 useTranslation，渲染时需包 I18nProvider。
// 默认 zh-CN + 预加载字典，断言不变（spec §10 复审要点：既有断言仍绿）。
function renderComponent() {
  return render(
    <I18nProvider lang="zh-CN" initialDict={zhCN}>
      <UpdateChecker />
    </I18nProvider>,
  );
}

describe("UpdateChecker", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedCheck.mockResolvedValue(null);
    mockedInstall.mockResolvedValue(undefined);
    mockedRelaunch.mockResolvedValue(undefined);
  });

  it("idle: 初始渲染显示「检查更新」按钮", () => {
    renderComponent();
    expect(screen.getByText("检查更新")).toBeInTheDocument();
  });

  it("checking: 点击按钮后显示「检查中…」", () => {
    mockedCheck.mockReturnValue(new Promise(() => {}));
    renderComponent();
    fireEvent.click(screen.getByText("检查更新"));
    expect(screen.getByText("检查中…")).toBeInTheDocument();
  });

  it("available: 有更新时显示新版本号和「下载并安装」按钮", async () => {
    mockedCheck.mockResolvedValue({
      version: "0.2.0",
      currentVersion: "0.1.0",
      body: "修复若干问题",
    });
    renderComponent();
    fireEvent.click(screen.getByText("检查更新"));
    await waitFor(() => {
      expect(screen.getByText(/新版本 0\.2\.0/)).toBeInTheDocument();
      expect(screen.getByText("下载并安装")).toBeInTheDocument();
    });
  });

  it("not-available: 无更新时显示「当前已是最新版本」", async () => {
    mockedCheck.mockResolvedValue(null);
    renderComponent();
    fireEvent.click(screen.getByText("检查更新"));
    await waitFor(() => {
      expect(screen.getByText("当前已是最新版本")).toBeInTheDocument();
    });
  });

  it("error: 检查失败时显示脱敏后的错误摘要和重试按钮", async () => {
    mockedCheck.mockRejectedValue(new Error("网络超时"));
    renderComponent();
    fireEvent.click(screen.getByText("检查更新"));
    await waitFor(() => {
      // U6：原始 err.message 不直接展示，归一到通用文案
      expect(screen.getByText(/更新检查失败/)).toBeInTheDocument();
      expect(screen.queryByText(/网络超时/)).not.toBeInTheDocument();
      expect(screen.getByText("重试")).toBeInTheDocument();
    });
  });

  it("downloading: 点击「下载并安装」后显示「下载中…」", async () => {
    mockedCheck.mockResolvedValue({
      version: "0.2.0",
      currentVersion: "0.1.0",
    });
    mockedInstall.mockReturnValue(new Promise(() => {}));
    renderComponent();
    fireEvent.click(screen.getByText("检查更新"));
    await waitFor(() => screen.getByText("下载并安装"));
    fireEvent.click(screen.getByText("下载并安装"));
    await waitFor(() => {
      expect(screen.getByText("下载中…")).toBeInTheDocument();
    });
  });

  it("downloading-progress: 有 Content-Length 时显示百分比", async () => {
    mockedCheck.mockResolvedValue({
      version: "0.2.3",
      currentVersion: "0.2.2",
    });
    mockedInstall.mockImplementation(async (onProgress) => {
      onProgress?.({ downloaded: 5, total: 10 });
      await new Promise(() => {});
    });
    renderComponent();
    fireEvent.click(screen.getByText("检查更新"));
    await waitFor(() => screen.getByText("下载并安装"));
    fireEvent.click(screen.getByText("下载并安装"));
    await waitFor(() => {
      expect(screen.getByText("下载中 50%")).toBeInTheDocument();
    });
  });

  it("installed: 安装完成后显示应用内重启确认，不依赖 window.confirm", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
    mockedCheck.mockResolvedValue({
      version: "0.2.3",
      currentVersion: "0.2.2",
    });
    renderComponent();
    fireEvent.click(screen.getByText("检查更新"));
    await waitFor(() => screen.getByText("下载并安装"));
    fireEvent.click(screen.getByText("下载并安装"));

    const dialog = await screen.findByRole("dialog", { name: zhCN.update.installedTitle });
    expect(confirmSpy).not.toHaveBeenCalled();
    expect(
      within(dialog).getByText(zhCN.update.installedBody.replace("{version}", "0.2.3")),
    ).toBeInTheDocument();

    fireEvent.click(
      within(dialog).getByRole("button", { name: zhCN.update.restartNow }),
    );
    await waitFor(() => expect(mockedRelaunch).toHaveBeenCalledTimes(1));
    confirmSpy.mockRestore();
  });

  it("installed: 取消重启后保留「重启后生效」提示，并可再次打开确认框", async () => {
    mockedCheck.mockResolvedValue({
      version: "0.2.3",
      currentVersion: "0.2.2",
    });
    renderComponent();
    fireEvent.click(screen.getByText("检查更新"));
    await waitFor(() => screen.getByText("下载并安装"));
    fireEvent.click(screen.getByText("下载并安装"));

    const dialog = await screen.findByRole("dialog", { name: zhCN.update.installedTitle });
    fireEvent.click(within(dialog).getByRole("button", { name: zhCN.confirm.cancel }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(
      screen.getByText(zhCN.update.installedHint.replace("{version}", "0.2.3")),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: zhCN.update.restartNow }));
    expect(
      await screen.findByRole("dialog", { name: zhCN.update.installedTitle }),
    ).toBeInTheDocument();
  });

  it("installed: 自动重启失败时显示可操作的错误提示", async () => {
    mockedCheck.mockResolvedValue({
      version: "0.2.3",
      currentVersion: "0.2.2",
    });
    mockedRelaunch.mockRejectedValue(new Error("spawn failed"));
    renderComponent();
    fireEvent.click(screen.getByText("检查更新"));
    await waitFor(() => screen.getByText("下载并安装"));
    fireEvent.click(screen.getByText("下载并安装"));

    const dialog = await screen.findByRole("dialog", { name: zhCN.update.installedTitle });
    fireEvent.click(
      within(dialog).getByRole("button", { name: zhCN.update.restartNow }),
    );
    await waitFor(() => {
      expect(screen.getByText(zhCN.update.restartFailed)).toBeInTheDocument();
    });
  });

  it("endpoint-unconfigured: endpoint 不可达时显示脱敏错误而非「最新版本」", async () => {
    mockedCheck.mockRejectedValue(new Error("failed to fetch"));
    renderComponent();
    fireEvent.click(screen.getByText("检查更新"));
    await waitFor(() => {
      // U6：网络/404/fetch 类错误归一到「无法连接更新服务器」，原始 message 不展示
      expect(screen.getByText(/无法连接更新服务器/)).toBeInTheDocument();
      expect(screen.queryByText(/failed to fetch/)).not.toBeInTheDocument();
      expect(screen.queryByText("当前已是最新版本")).not.toBeInTheDocument();
    });
  });
});
