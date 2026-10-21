import type { UsageDaily, UsageSnapshotDaily } from "./api";

/**
 * M34-S1：用量看板的**纯函数聚合**。
 *
 * 后端只做 SQL 级聚合（按 日 × 站点 × 模型 分组的行），页面需要再从这些行导出
 * 「按站点 / 按模型 / 按天」三种视图与图表序列。把这段逻辑放在独立模块里而不是
 * 塞进组件，是为了能直接单测（组件测试里数字算错很难定位）。
 *
 * 所有函数**不修改入参**，返回新数组；排序一律显式给出（不依赖 `Array.sort` 的稳定性，
 * 虽然现代引擎稳定，但平局时的顺序应当由我们自己钉死）。
 */

export type UsageTotals = {
  requests: number;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
};

export function emptyTotals(): UsageTotals {
  return { requests: 0, promptTokens: 0, completionTokens: 0, totalTokens: 0 };
}

function accumulate(target: UsageTotals, row: UsageDaily): void {
  target.requests += row.requests;
  target.promptTokens += row.promptTokens;
  target.completionTokens += row.completionTokens;
  target.totalTokens += row.totalTokens;
}

/** 汇总一组行。 */
export function sumTotals(rows: UsageDaily[]): UsageTotals {
  const totals = emptyTotals();
  for (const row of rows) accumulate(totals, row);
  return totals;
}

/** 按站点汇总：`totalTokens` 降序，同值按 `siteId` 升序。 */
export function groupBySite(
  rows: UsageDaily[],
): Array<{ siteId: number } & UsageTotals> {
  const bySite = new Map<number, UsageTotals>();
  for (const row of rows) {
    let totals = bySite.get(row.siteId);
    if (!totals) {
      totals = emptyTotals();
      bySite.set(row.siteId, totals);
    }
    accumulate(totals, row);
  }
  return [...bySite.entries()]
    .map(([siteId, totals]) => ({ siteId, ...totals }))
    .sort((a, b) => b.totalTokens - a.totalTokens || a.siteId - b.siteId);
}

/** 按模型汇总：`totalTokens` 降序，同值按模型名升序（空串是独立分组）。 */
export function groupByModel(
  rows: UsageDaily[],
): Array<{ model: string } & UsageTotals> {
  const byModel = new Map<string, UsageTotals>();
  for (const row of rows) {
    let totals = byModel.get(row.model);
    if (!totals) {
      totals = emptyTotals();
      byModel.set(row.model, totals);
    }
    accumulate(totals, row);
  }
  return [...byModel.entries()]
    .map(([model, totals]) => ({ model, ...totals }))
    .sort((a, b) => b.totalTokens - a.totalTokens || a.model.localeCompare(b.model));
}

/** 按本地日汇总：日期升序（`YYYY-MM-DD` 字符串序即日期序）。 */
export function groupByDay(
  rows: UsageDaily[],
): Array<{ date: string } & UsageTotals> {
  const byDay = new Map<string, UsageTotals>();
  for (const row of rows) {
    let totals = byDay.get(row.date);
    if (!totals) {
      totals = emptyTotals();
      byDay.set(row.date, totals);
    }
    accumulate(totals, row);
  }
  return [...byDay.entries()]
    .map(([date, totals]) => ({ date, ...totals }))
    .sort((a, b) => a.date.localeCompare(b.date));
}

/**
 * 堆叠柱图数据：日期升序 × 站点序列。
 *
 * 每个站点一列、长度与 `dates` 对齐；某站点当天没有流量 ⇒ 补 0（不是缺项，
 * 否则堆叠图的列会错位）。
 */
export function stackByDayAndSite(rows: UsageDaily[]): {
  dates: string[];
  series: Array<{ siteId: number; values: number[] }>;
} {
  const dates = [...new Set(rows.map((row) => row.date))].sort();
  const siteIds = [...new Set(rows.map((row) => row.siteId))].sort(
    (a, b) => a - b,
  );
  const dateIndex = new Map(dates.map((date, index) => [date, index]));
  const series = siteIds.map((siteId) => ({
    siteId,
    values: new Array<number>(dates.length).fill(0),
  }));
  const seriesBySite = new Map(series.map((item) => [item.siteId, item]));
  for (const row of rows) {
    const target = seriesBySite.get(row.siteId);
    const index = dateIndex.get(row.date);
    if (!target || index === undefined) continue;
    target.values[index] += row.totalTokens;
  }
  return { dates, series };
}

/**
 * 余额快照按**币种**分组：不同币种不混算、不画在同一坐标系。
 *
 * 每组内按站点分序列、日期升序；同一（币种, 站点, 日）若出现多行，后者覆盖前者
 * （后端已保证每天只有一行，这里只是防御）。
 */
export function snapshotsByCurrency(rows: UsageSnapshotDaily[]): Array<{
  currency: string;
  series: Array<{
    siteId: number;
    points: Array<{ date: string; remaining: number }>;
  }>;
}> {
  const byCurrency = new Map<string, Map<number, Map<string, number>>>();
  for (const row of rows) {
    let bySite = byCurrency.get(row.currency);
    if (!bySite) {
      bySite = new Map();
      byCurrency.set(row.currency, bySite);
    }
    let byDate = bySite.get(row.siteId);
    if (!byDate) {
      byDate = new Map();
      bySite.set(row.siteId, byDate);
    }
    byDate.set(row.date, row.remaining);
  }
  return [...byCurrency.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([currency, bySite]) => ({
      currency,
      series: [...bySite.entries()]
        .sort(([a], [b]) => a - b)
        .map(([siteId, byDate]) => ({
          siteId,
          points: [...byDate.entries()]
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([date, remaining]) => ({ date, remaining })),
        })),
    }));
}

/** 折线图横轴的日期并集（升序）。 */
export function unionDates(
  series: Array<{ points: Array<{ date: string }> }>,
): string[] {
  return [...new Set(series.flatMap((item) => item.points.map((p) => p.date)))].sort();
}

/** 紧凑 token 数：`999` / `1.5K` / `2.0M`（不足 1000 原样取整）。 */
export function formatTokens(n: number): string {
  if (!Number.isFinite(n)) return "—";
  const abs = Math.abs(n);
  if (abs >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (abs >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return `${Math.round(n)}`;
}

/** 占比文案：`25.0%`；总数 ≤ 0 时返回 `—`（「不知道」不当成 0%，与余额同纪律）。 */
export function formatShare(part: number, total: number): string {
  if (!Number.isFinite(part) || !Number.isFinite(total) || total <= 0) {
    return "—";
  }
  return `${((part / total) * 100).toFixed(1)}%`;
}
