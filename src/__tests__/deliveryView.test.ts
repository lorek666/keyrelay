import { describe, it, expect } from "vitest";
import { maskRemovedValues, planWritesEndpoint } from "../lib/deliveryView";
import type { DeliveryField } from "../lib/api";

const field = (key: string): DeliveryField => ({ key, masked: "…abcd" });
const PH = "…（旧值已隐去）";

describe("planWritesEndpoint（P2-3 前端半的判据）", () => {
  it("认得所有 endpoint 形态的字段名（后端 19 条通道实际用到的）", () => {
    for (const key of [
      "base_url",
      "baseUrl",
      "baseURL",
      "OPENAI_BASE_URL",
      "ANTHROPIC_BASE_URL",
      "GOOGLE_GEMINI_BASE_URL",
      "apiBase",
      "endpoint",
    ]) {
      expect(planWritesEndpoint([field(key)]), key).toBe(true);
    }
  });

  it("不写 endpoint 的通道判为 false（codex-auth-json / dsh 的真实字段）", () => {
    // codex：~/.codex/auth.json 只有这两个键
    expect(planWritesEndpoint([field("auth_mode"), field("OPENAI_API_KEY")])).toBe(false);
    // dsh：只有一把 key
    expect(planWritesEndpoint([field("KEYRELAY_API_KEY")])).toBe(false);
    expect(planWritesEndpoint([])).toBe(false);
  });

  it("字段名里的其它词不会误判（例如 contextWindow / model）", () => {
    expect(
      planWritesEndpoint([
        field("api_key"),
        field("model"),
        field("context_window"),
        field("maxTokens"),
      ]),
    ).toBe(false);
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
