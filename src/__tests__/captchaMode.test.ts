import { describe, it, expect } from "vitest";
import { captchaPanelMode } from "../lib/captchaMode";
import type { SiteCapabilities } from "../lib/api";

const caps = (over: Partial<SiteCapabilities>): SiteCapabilities => ({
  login: true,
  listKeys: true,
  createKey: true,
  revealKey: true,
  revokeKey: true,
  balance: true,
  groups: true,
  keyUsage: true,
  webviewCaptchaSupported: false,
  webviewBearerSupported: false,
  ...over,
});

describe("captchaPanelMode（M28-S2：三态只来自能力表）", () => {
  it("cookie 站点 ⇒ cookie 面板", () => {
    expect(captchaPanelMode(caps({ webviewCaptchaSupported: true }))).toBe("cookie");
  });

  it("Bearer 站点 ⇒ bearer 面板（Sub2API 的形态）", () => {
    expect(captchaPanelMode(caps({ webviewBearerSupported: true }))).toBe("bearer");
  });

  it("两者都不支持 ⇒ unsupported 面板（fail-closed）", () => {
    expect(captchaPanelMode(caps({}))).toBe("unsupported");
  });

  it("两者同时为 true ⇒ **cookie 优先**（与壳层 captcha_capture_mode 同一口径）", () => {
    expect(
      captchaPanelMode(
        caps({ webviewCaptchaSupported: true, webviewBearerSupported: true }),
      ),
    ).toBe("cookie");
  });
});
