/**
 * M43-S2：成本展示的**纯函数**（金额格式化 + 按币种汇总）。
 *
 * 三条规则（spec §4.6）：
 * 1. **未知 ≠ 0**：`null` 一律渲染 `—`；不得用 `0` 冒充「没有价格 / 站点没给」。
 * 2. **币种不混算**：`sumByCurrency` 以 `currency` 为键分组，**跨币种求和不实现**。
 * 3. **小于 0.0001 显示 `<0.0001`**（不显示 `0`，避免「花过钱」看起来像「没花钱」）。
 */

export type CostRow = {
  currency: string | null;
  estimatedCost: number | null;
  requests: number;
  unpricedRequests: number;
};

export type CostBucket = {
  currency: string | null;
  /** 能定价部分的合计（同一币种内） */
  estimated: number;
  /** 未定价的请求数（>0 ⇒ 界面标「部分未定价」） */
  unpricedRequests: number;
  totalRequests: number;
};

const MIN_VISIBLE = 0.0001;

/** 金额格式化（4 位精度，与 M34 的 `usageAgg.formatCost` 区分）：`null` ⇒ `—`；`0 < v < 0.0001`（含 0）⇒ `<0.0001`。 */
export function formatEstimate(value: number | null, currency?: string | null): string {
  if (value === null || !Number.isFinite(value)) return "—";
  const unit = currency && currency.trim() ? ` ${currency.trim().toUpperCase()}` : "";
  if (value <= 0 || value < MIN_VISIBLE) return `<0.0001${unit}`;
  const fixed = value.toFixed(4);
  // 去掉无意义的尾零：1.2300 → 1.23；2.0000 → 2
  const trimmed = fixed.replace(/\.?0+$/, "");
  return `${trimmed}${unit}`;
}

/**
 * 按币种汇总。`currency === null` 归到「未知币种」桶（`currency: null`），
 * **不与任何已知币种合并**，也不参与已知币种的合计。
 */
export function sumByCurrency(rows: CostRow[]): CostBucket[] {
  const buckets = new Map<string | null, CostBucket>();
  for (const row of rows) {
    const key = row.currency && row.currency.trim() ? row.currency.trim().toUpperCase() : null;
    const bucket = buckets.get(key) ?? {
      currency: key,
      estimated: 0,
      unpricedRequests: 0,
      totalRequests: 0,
    };
    // 只有**有价格**的行才累加金额；未定价行只计计数（绝不把未知当 0 计入合计）。
    if (key !== null) bucket.estimated += row.estimatedCost ?? 0;
    bucket.unpricedRequests += row.unpricedRequests;
    bucket.totalRequests += row.requests;
    buckets.set(key, bucket);
  }
  return [...buckets.values()].sort((a, b) => {
    if (a.currency === b.currency) return 0;
    if (a.currency === null) return 1; // 未知币种排最后
    if (b.currency === null) return -1;
    return a.currency.localeCompare(b.currency);
  });
}

/** 该桶是否「部分未定价」（界面必须显示提示）。 */
export function isPartiallyPriced(bucket: CostBucket): boolean {
  return bucket.unpricedRequests > 0 && bucket.totalRequests > bucket.unpricedRequests;
}

/** 该桶是否「完全未定价」。 */
export function isFullyUnpriced(bucket: CostBucket): boolean {
  return bucket.totalRequests > 0 && bucket.unpricedRequests >= bucket.totalRequests;
}
