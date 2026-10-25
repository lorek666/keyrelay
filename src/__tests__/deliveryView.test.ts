import { describe, it, expect } from "vitest";
import {
  maskRemovedValues,
  modelValidationBlocks,
  modelValidationProbeKey,
  modelValidationStaticKey,
  shouldWarnEndpointOutOfScope,
} from "../lib/deliveryView";
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

describe("modelValidation key mapping（P2-8 前端半：code → i18n 键）", () => {
  it("静态层：全部已知 code 都有键，未知 code 回落通用文案（不把键名当文案）", () => {
    expect(modelValidationStaticKey("no_model")).toBe(
      "agents.plan.modelValidation.static.noModel",
    );
    expect(modelValidationStaticKey("channel_no_model")).toBe(
      "agents.plan.modelValidation.static.channelNoModel",
    );
    expect(modelValidationStaticKey("malformed")).toBe(
      "agents.plan.modelValidation.static.malformed",
    );
    expect(modelValidationStaticKey("unchecked")).toBe(
      "agents.plan.modelValidation.static.unchecked",
    );
    expect(modelValidationStaticKey("future-code")).toBe(
      "agents.plan.modelValidation.static.unchecked",
    );
    expect(modelValidationStaticKey(undefined)).toBe(
      "agents.plan.modelValidation.static.unchecked",
    );
  });

  it("探针层：全部已知 code 都有键，401 与模型不在目录各有自己的键", () => {
    expect(modelValidationProbeKey("passed")).toBe(
      "agents.plan.modelValidation.probe.passed",
    );
    expect(modelValidationProbeKey("unauthorized")).toBe(
      "agents.plan.modelValidation.probe.unauthorized",
    );
    expect(modelValidationProbeKey("not_in_catalog")).toBe(
      "agents.plan.modelValidation.probe.notInCatalog",
    );
    expect(modelValidationProbeKey("timeout")).toBe(
      "agents.plan.modelValidation.probe.timeout",
    );
    expect(modelValidationProbeKey("unreachable")).toBe(
      "agents.plan.modelValidation.probe.unreachable",
    );
    expect(modelValidationProbeKey("skipped")).toBe(
      "agents.plan.modelValidation.probe.skipped",
    );
    expect(modelValidationProbeKey("future-code")).toBe(
      "agents.plan.modelValidation.probe.unresolved",
    );
  });

  it("网关专属 code（P2-8 复审 P1）显式映射，不落入 default 的 unresolved", () => {
    // not_in_gateway_catalog 是警告：文案必须写清聚合/透传口径，不能被
    // default 成「没能向端点发问」；passed_gateway_catalog 同理，文案限定
    // 为本地网关目录口径，不代表逐站核对。
    expect(modelValidationProbeKey("not_in_gateway_catalog")).toBe(
      "agents.plan.modelValidation.probe.notInGatewayCatalog",
    );
    expect(modelValidationProbeKey("passed_gateway_catalog")).toBe(
      "agents.plan.modelValidation.probe.passedGatewayCatalog",
    );
  });
});

describe("modelValidationBlocks（P2-8 前端半：硬拦判据只来自后端字段）", () => {
  it("后端说拦 ⇒ 拦；后端说不拦 ⇒ 不拦", () => {
    expect(modelValidationBlocks({ blocksDelivery: true })).toBe(true);
    expect(modelValidationBlocks({ blocksDelivery: false })).toBe(false);
  });

  it("网关警告 code 不另算硬拦：判据只认后端 blocksDelivery 字段", () => {
    // modelValidationBlocks 不收 code 参数：后端把 not_in_gateway_catalog
    // 定为 blocksDelivery: false，前端原样放行；若将来有人按 code 重算
    // 硬拦表，新 code 的默认分支（拦/放行）都会错，所以这里钉住「只认字段」。
    expect(modelValidationBlocks({ blocksDelivery: false })).toBe(false);
  });

  it("字段缺失（旧二进制）⇒ 不拦：宁可不拦，也不给一条可能错的拦截", () => {
    expect(modelValidationBlocks(null)).toBe(false);
    expect(modelValidationBlocks(undefined)).toBe(false);
    expect(modelValidationBlocks({})).toBe(false);
  });
});
