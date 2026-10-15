import type { ReactNode } from "react";
import { describe, it, expect } from "vitest";
import { renderHook } from "@testing-library/react";
import { I18nProvider, useTranslation } from "../i18n";
import zhCN from "../i18n/zh-CN.json";
import enUS from "../i18n/en-US.json";

/** 收集嵌套字典的叶子 key 路径（点号分隔）。 */
function leaves(o: unknown, p = "", out: Record<string, true> = {}): Record<string, true> {
  if (o && typeof o === "object" && !Array.isArray(o)) {
    for (const k in o as Record<string, unknown>) {
      const v = (o as Record<string, unknown>)[k];
      const path = p ? `${p}.${k}` : k;
      if (v && typeof v === "object" && !Array.isArray(v)) leaves(v, path, out);
      else out[path] = true;
    }
  }
  return out;
}

function withProvider(lang: "zh-CN" | "en-US", dict: unknown) {
  return ({ children }: { children: ReactNode }) => (
    <I18nProvider lang={lang} initialDict={dict as Record<string, unknown>}>{children}</I18nProvider>
  );
}

describe("i18n", () => {
  it("zh-CN 与 en-US 叶子 key 集合完全相等（无中英缺失）", () => {
    const z = Object.keys(leaves(zhCN)).sort();
    const e = Object.keys(leaves(enUS)).sort();
    expect(z).toEqual(e);
  });

  it("en 切换：nav.settings 返回英文 Settings", () => {
    const { result } = renderHook(() => useTranslation(), {
      wrapper: withProvider("en-US", enUS),
    });
    expect(result.current.t("nav.settings")).toBe("Settings");
    expect(result.current.lang).toBe("en-US");
  });

  it("zh 切换：nav.settings 返回中文 设置", () => {
    const { result } = renderHook(() => useTranslation(), {
      wrapper: withProvider("zh-CN", zhCN),
    });
    expect(result.current.t("nav.settings")).toBe("设置");
  });

  it("插值：{var} 被实参替换", () => {
    const { result } = renderHook(() => useTranslation(), {
      wrapper: withProvider("zh-CN", zhCN),
    });
    const s = result.current.t("sites.notice.added", { name: "测试站" });
    expect(s).toContain("测试站");
    expect(s).not.toContain("{name}");
  });

  it("缺 key 回退 key 本身（不返回空串）", () => {
    const { result } = renderHook(() => useTranslation(), {
      wrapper: withProvider("zh-CN", zhCN),
    });
    expect(result.current.t("no.such.key")).toBe("no.such.key");
  });

  it("未传插值实参：{var} 占位符保留（不崩）", () => {
    const { result } = renderHook(() => useTranslation(), {
      wrapper: withProvider("zh-CN", zhCN),
    });
    const s = result.current.t("sites.notice.added");
    expect(s).toContain("{name}");
  });
});
