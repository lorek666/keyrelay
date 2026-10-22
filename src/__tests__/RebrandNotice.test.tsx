import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import RebrandNotice from "../components/RebrandNotice";
import { I18nProvider } from "../i18n";
import zhCN from "../i18n/zh-CN.json";
import type { RebrandInfo } from "../lib/api";

/**
 * M35-S1：迁移提示三态。
 *
 * `noLegacy` 必须完全不占版面；`failed` 必须是 `role="alert"`（否则「为什么还是旧数据」
 * 会被用户当成功能没生效）；`migrated` 要给出文件数、来源与目标路径。
 */

function renderNotice(rebrand: RebrandInfo | null, dataDir = "~/.tianshu-relay") {
  return render(
    <I18nProvider lang="zh-CN" initialDict={zhCN}>
      <RebrandNotice rebrand={rebrand} dataDir={dataDir} />
    </I18nProvider>,
  );
}

const base: RebrandInfo = {
  status: "noLegacy",
  from: null,
  to: "~/.tianshu-relay",
  files: 0,
  bytes: 0,
  warnings: [],
  error: null,
};

describe("RebrandNotice", () => {
  it("noLegacy 不渲染", () => {
    const { container } = renderNotice(base);
    expect(container).toBeEmptyDOMElement();
  });

  it("migrated 显示文件数、来源与目标路径", () => {
    renderNotice({
      ...base,
      status: "migrated",
      from: "~/.keyrelay",
      files: 7,
      bytes: 1024,
      warnings: ["旧版登录自启已停用，请在设置中重新开启。"],
    });
    expect(screen.getByRole("status")).toHaveTextContent("已从旧版迁移数据");
    expect(screen.getByRole("status")).toHaveTextContent("7 个文件");
    expect(screen.getByRole("status")).toHaveTextContent("~/.keyrelay");
    expect(screen.getByRole("status")).toHaveTextContent("~/.tianshu-relay");
    expect(screen.getByRole("status")).toHaveTextContent("旧版登录自启已停用");
  });

  it("failed 是 alert，并说明本次仍使用旧目录", () => {
    renderNotice(
      {
        ...base,
        status: "failed",
        from: "~/.keyrelay",
        error: "磁盘空间不足",
      },
      "~/.keyrelay",
    );
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("旧数据迁移失败");
    expect(alert).toHaveTextContent("磁盘空间不足");
    expect(alert).toHaveTextContent("~/.keyrelay");
    expect(alert).toHaveTextContent("没有改动任何旧文件");
  });

  it("targetExists 显示新目录已有内容且不覆盖", () => {
    renderNotice({ ...base, status: "targetExists" });
    expect(screen.getByRole("status")).toHaveTextContent("新数据目录已有内容");
    expect(screen.getByRole("status")).toHaveTextContent("~/.tianshu-relay");
    expect(screen.getByRole("status")).toHaveTextContent("旧目录保持原样");
  });
});
