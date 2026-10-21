import { describe, it, expect, beforeEach } from "vitest";
import { loadAgentPrefs, saveAgentPrefs } from "../lib/agentPrefs";

/**
 * M31-S1 §4.3：每行偏好的 localStorage 读写。
 *
 * 钉死四件事：正常往返、非法 JSON 回空、结构不合法按默认、站点之间互不影响。
 * 偏好不是关键路径 ⇒ 任何坏数据都**只影响那一行**，不许抛。
 */

beforeEach(() => {
  localStorage.clear();
});

describe("agentPrefs", () => {
  it("save → load 往返", () => {
    saveAgentPrefs(7, {
      "codex-auth-json": { keyId: 3, model: "gpt-5.6" },
      "gemini-cli": { keyId: null, model: "" },
    });
    expect(loadAgentPrefs(7)).toEqual({
      "codex-auth-json": { keyId: 3, model: "gpt-5.6" },
      "gemini-cli": { keyId: null, model: "" },
    });
  });

  it("非法 JSON 回空对象，不抛", () => {
    localStorage.setItem("keyrelay.agentPrefs.v1.7", "{not json");
    expect(loadAgentPrefs(7)).toEqual({});
  });

  it("结构不合法时逐字段回落（非对象 / 负 keyId / 非字符串 model）", () => {
    localStorage.setItem(
      "keyrelay.agentPrefs.v1.7",
      JSON.stringify({
        a: "nope",
        b: { keyId: -5, model: 42 },
        c: { keyId: 2.5, model: "ok" },
        d: { keyId: 4, model: "m" },
      }),
    );
    expect(loadAgentPrefs(7)).toEqual({
      a: { keyId: null, model: "" },
      b: { keyId: null, model: "" },
      c: { keyId: null, model: "ok" },
      d: { keyId: 4, model: "m" },
    });
  });

  it("站点隔离：写 A 不影响 B", () => {
    saveAgentPrefs(1, { x: { keyId: 1, model: "a" } });
    saveAgentPrefs(2, { x: { keyId: 2, model: "b" } });
    expect(loadAgentPrefs(1).x).toEqual({ keyId: 1, model: "a" });
    expect(loadAgentPrefs(2).x).toEqual({ keyId: 2, model: "b" });
    expect(loadAgentPrefs(3)).toEqual({});
  });
});
