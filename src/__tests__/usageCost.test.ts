import { describe, expect, it } from "vitest";
import {
  formatEstimate,
  isFullyUnpriced,
  isPartiallyPriced,
  sumByCurrency,
  type CostRow,
} from "../lib/usageCost";

const row = (over: Partial<CostRow>): CostRow => ({
  currency: "USD",
  estimatedCost: 1,
  requests: 1,
  unpricedRequests: 0,
  ...over,
});

describe("formatCost（M43-S2 §4.6）", () => {
  it("未知（null）显示 —，不显示 0", () => {
    expect(formatEstimate(null)).toBe("—");
    expect(formatEstimate(null, "USD")).toBe("—");
  });

  it("小于 0.0001（含 0）显示 <0.0001，不显示 0", () => {
    expect(formatEstimate(0, "USD")).toBe("<0.0001 USD");
    expect(formatEstimate(0.00009, "CNY")).toBe("<0.0001 CNY");
  });

  it("正常金额保留最多 4 位并去掉尾零", () => {
    expect(formatEstimate(1.23456, "USD")).toBe("1.2346 USD");
    expect(formatEstimate(2, "CNY")).toBe("2 CNY");
    expect(formatEstimate(0.5)).toBe("0.5");
  });
});

describe("sumByCurrency（币种不混算）", () => {
  it("USD 与 CNY 各自汇总，绝不合并", () => {
    const buckets = sumByCurrency([
      row({ currency: "USD", estimatedCost: 1 }),
      row({ currency: "USD", estimatedCost: 2 }),
      row({ currency: "CNY", estimatedCost: 10 }),
    ]);
    expect(buckets.map((b) => [b.currency, b.estimated])).toEqual([
      ["CNY", 10],
      ["USD", 3],
    ]);
  });

  it("未知币种单独成桶、排最后，且不并入任何已知币种", () => {
    const buckets = sumByCurrency([row({ currency: null }), row({ currency: "USD" })]);
    expect(buckets[0].currency).toBe("USD");
    expect(buckets[1].currency).toBeNull();
    expect(buckets[1].estimated).toBe(0);
  });

  it("部分未定价：金额只含有价部分，计数如实", () => {
    const [bucket] = sumByCurrency([
      row({ currency: "USD", estimatedCost: 2, requests: 2 }),
      row({ currency: "USD", estimatedCost: null, requests: 1, unpricedRequests: 1 }),
    ]);
    expect(bucket.estimated).toBe(2);
    expect(bucket.unpricedRequests).toBe(1);
    expect(isPartiallyPriced(bucket)).toBe(true);
    expect(isFullyUnpriced(bucket)).toBe(false);
  });

  it("完全未定价：estimated 为 0 但界面必须显示「未定价」而不是 0", () => {
    const [bucket] = sumByCurrency([row({ currency: null, estimatedCost: null, unpricedRequests: 2, requests: 2 })]);
    expect(isFullyUnpriced(bucket)).toBe(true);
  });
});
