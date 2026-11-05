import { afterEach, describe, expect, it, vi } from "vitest";
import { localDateInputValue, localDateStartUnixSeconds } from "../lib/localDate";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("本地日历日期转换", () => {
  it("Asia/Shanghai：UTC 仍是前一天时，默认值使用本地次日", () => {
    vi.stubEnv("TZ", "Asia/Shanghai");
    const now = new Date("2025-01-01T16:30:00.000Z");

    expect(now.toISOString().slice(0, 10)).toBe("2025-01-01");
    expect(localDateInputValue(now)).toBe("2025-01-02");
    const start = new Date(localDateStartUnixSeconds("2025-01-02") * 1000);
    expect(start.getTime()).toBe(Date.UTC(2025, 0, 1, 16, 0, 0));
    expect([
      start.getFullYear(),
      start.getMonth() + 1,
      start.getDate(),
      start.getHours(),
      start.getMinutes(),
      start.getSeconds(),
    ]).toEqual([2025, 1, 2, 0, 0, 0]);
  });

  it("America/Los_Angeles：UTC 已是次日时，默认值仍使用本地前一天", () => {
    vi.stubEnv("TZ", "America/Los_Angeles");
    const now = new Date("2025-01-01T07:30:00.000Z");

    expect(now.toISOString().slice(0, 10)).toBe("2025-01-01");
    expect(localDateInputValue(now)).toBe("2024-12-31");
    const start = new Date(localDateStartUnixSeconds("2024-12-31") * 1000);
    expect(start.getTime()).toBe(Date.UTC(2024, 11, 31, 8, 0, 0));
    expect([
      start.getFullYear(),
      start.getMonth() + 1,
      start.getDate(),
      start.getHours(),
      start.getMinutes(),
      start.getSeconds(),
    ]).toEqual([2024, 12, 31, 0, 0, 0]);
  });

  it("拒绝格式错误或不存在的日期", () => {
    expect(() => localDateStartUnixSeconds("2025-2-03")).toThrow(RangeError);
    expect(() => localDateStartUnixSeconds("2025-02-30")).toThrow(RangeError);
  });
});
