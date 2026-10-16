import { describe, it, expect } from "vitest";
import { maskRemovedValues, shouldWarnEndpointOutOfScope } from "../lib/deliveryView";
import * as deliveryView from "../lib/deliveryView";

const PH = "…（旧值已隐去）";

describe("shouldWarnEndpointOutOfScope（P2-3 前端半：判据只来自后端字段）", () => {
  it("网关模式 + 后端说该通道不写 endpoint ⇒ 提示", () => {
    expect(shouldWarnEndpointOutOfScope("gateway", false)).toBe(true);
  });

  it("反例：后端说该通道**写** endpoint ⇒ 不提示（不该提示的通道不提示）", () => {
    expect(shouldWarnEndpointOutOfScope("gateway", true)).toBe(false);
  });

  it("站点模式下一律不提示（那时不存在「写的是网关地址」这件事）", () => {
    expect(shouldWarnEndpointOutOfScope("site", false)).toBe(false);
    expect(shouldWarnEndpointOutOfScope("site", true)).toBe(false);
  });

  it("字段缺失（旧二进制）⇒ 不提示：宁可不提示，也不给一条可能错的提示", () => {
    expect(shouldWarnEndpointOutOfScope("gateway", undefined)).toBe(false);
  });

  it("判据**不含**任何按字段名推导的逻辑（旧实现的形态必须已经不存在）", () => {
    // 这条是防回归：曾经的 `planWritesEndpoint(fields)` 按 base_url/endpoint 正则猜；
    // 若有人把它加回来当兜底，两套机制又会分叉。这里直接断言模块不再导出它。
    expect(Object.keys(deliveryView)).not.toContain("planWritesEndpoint");
  });
});

describe("maskRemovedValues（P2-5 前端半）", () => {
  it("删除行的值被掩掉，键名与结构保留", () => {
    const preview = '- "OPENAI_API_KEY": "sk-old-shape-not-recognized"\n';
    const out = maskRemovedValues(preview, PH);
    expect(out).toBe(`- "OPENAI_API_KEY": ${PH}\n`);
    expect(out).not.toContain("sk-old-shape-not-recognized");
  });

  it("新增行（+）逐字节不变——那是「将要写进去什么」，掩掉等于掩盖改动", () => {
    const preview = '+ "OPENAI_API_KEY": "…cdef"\n';
    expect(maskRemovedValues(preview, PH)).toBe(preview);
  });

  it("非 diff 行（(无变化) / 空行）逐字节不变", () => {
    expect(maskRemovedValues("(无变化)\n", PH)).toBe("(无变化)\n");
    expect(maskRemovedValues("\n", PH)).toBe("\n");
    expect(maskRemovedValues("", PH)).toBe("");
  });

  it("`---` 分隔行不被当成删除行", () => {
    const preview = "--- a/config\n- key: secret-value\n";
    const out = maskRemovedValues(preview, PH);
    expect(out.split("\n")[0]).toBe("--- a/config");
    expect(out).not.toContain("secret-value");
  });

  it("等号形态（KEY=VALUE）也掩值、留键", () => {
    expect(maskRemovedValues("- OPENAI_API_KEY=sk-x\n", PH)).toBe(`- OPENAI_API_KEY=${PH}\n`);
  });

  it("没有分隔符的删除行整行换成占位（宁可少显示，不可多泄露）", () => {
    expect(maskRemovedValues("- sk-bare-value\n", PH)).toBe(`- ${PH}\n`);
  });

  it("多次调用结果相同（幂等）", () => {
    const preview = '- "A": "1"\n+ "A": "2"\n- B=3\n';
    const once = maskRemovedValues(preview, PH);
    expect(maskRemovedValues(once, PH)).toBe(once);
  });
});
