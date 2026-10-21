import { formatTokens } from "../lib/usageAgg";

/**
 * M34-S1：用量页的手写 SVG 图表。
 *
 * 为什么不用图表库：主 bundle 余量有限，且本仓库对新增依赖有硬纪律（见 spec §2）。
 * 这里只画两种最必要的形态——按天堆叠柱（token 趋势）与折线（余额趋势）——
 * 轴刻度、图例、空态由页面负责；组件本身假定入参非空。
 *
 * 交互只有原生 `<title>` 悬浮提示：没有缩放/框选，90 天时柱宽会变窄但不会失真。
 */

/** 站点序列配色（与站点在列表中的顺序绑定，由页面决定下标）。 */
export const SERIES_COLORS = [
  "#4f8cff",
  "#f2a93b",
  "#3ecf8e",
  "#e5566a",
  "#a78bfa",
  "#22b8cf",
];

export function seriesColor(index: number): string {
  return SERIES_COLORS[index % SERIES_COLORS.length];
}

const WIDTH = 640;
const HEIGHT = 220;
const PAD = { top: 12, right: 10, bottom: 26, left: 54 };

const PLOT_WIDTH = WIDTH - PAD.left - PAD.right;
const PLOT_HEIGHT = HEIGHT - PAD.top - PAD.bottom;

/** `2026-10-21` → `10-21`（横轴标签只保留月日，年份在窗口内没有信息量）。 */
function shortDate(date: string): string {
  return date.length >= 10 ? date.slice(5) : date;
}

/** 横轴标签稀疏化：最多约 7 个刻度，避免 90 天时文字重叠。 */
function labelStep(count: number): number {
  return Math.max(1, Math.ceil(count / 7));
}

export type StackSeries = {
  siteId: number;
  label: string;
  color: string;
  /** 与 `dates` 等长；缺日补 0。 */
  values: number[];
};

/** 按天堆叠柱图：每根柱是当天所有站点 token 之和，段色区分站点。 */
export function StackedBarChart({
  dates,
  series,
  ariaLabel,
}: {
  dates: string[];
  series: StackSeries[];
  ariaLabel: string;
}) {
  const totals = dates.map((_, index) =>
    series.reduce((sum, item) => sum + (item.values[index] ?? 0), 0),
  );
  const max = Math.max(1, ...totals);
  const slot = PLOT_WIDTH / Math.max(dates.length, 1);
  const barWidth = Math.max(1, Math.min(slot * 0.72, 16));
  const step = labelStep(dates.length);
  const ticks = [0, 0.5, 1].map((ratio) => max * ratio);

  return (
    <div>
      <svg
        className="usage-chart"
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        role="img"
        aria-label={ariaLabel}
      >
        {ticks.map((tick, index) => {
          const y = PAD.top + PLOT_HEIGHT - (tick / max) * PLOT_HEIGHT;
          return (
            <g key={`tick-${index}`}>
              <line
                x1={PAD.left}
                x2={WIDTH - PAD.right}
                y1={y}
                y2={y}
                stroke="var(--line-soft)"
                strokeWidth={1}
              />
              <text x={PAD.left - 6} y={y + 3} textAnchor="end">
                {formatTokens(tick)}
              </text>
            </g>
          );
        })}
        {dates.map((date, index) => {
          let y = PAD.top + PLOT_HEIGHT;
          const x = PAD.left + index * slot + (slot - barWidth) / 2;
          return (
            <g key={`bar-${date}`}>
              {series.map((item) => {
                const value = item.values[index] ?? 0;
                const height = (value / max) * PLOT_HEIGHT;
                if (height <= 0) return null;
                y -= height;
                return (
                  <rect
                    key={item.siteId}
                    x={x}
                    y={y}
                    width={barWidth}
                    height={height}
                    fill={item.color}
                  >
                    <title>{`${item.label} · ${date} · ${value.toLocaleString()} tokens`}</title>
                  </rect>
                );
              })}
            </g>
          );
        })}
        {dates.map((date, index) =>
          index % step === 0 ? (
            <text
              key={`x-${date}`}
              x={PAD.left + index * slot + slot / 2}
              y={HEIGHT - 8}
              textAnchor="middle"
            >
              {shortDate(date)}
            </text>
          ) : null,
        )}
      </svg>
      <ChartLegend
        items={series.map((item) => ({ label: item.label, color: item.color }))}
      />
    </div>
  );
}

export type LineSeries = {
  siteId: number;
  label: string;
  color: string;
  points: Array<{ date: string; remaining: number }>;
};

/** 金额刻度：小额保留两位小数，大额压缩成 K/M。 */
function formatAmount(value: number): string {
  const abs = Math.abs(value);
  if (abs >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (abs >= 10_000) return `${(value / 1_000).toFixed(1)}K`;
  return value.toFixed(2);
}

/** 余额折线图（单一币种；不同币种由页面拆成多张图）。 */
export function LineChart({
  dates,
  series,
  currency,
  ariaLabel,
}: {
  dates: string[];
  series: LineSeries[];
  currency: string;
  ariaLabel: string;
}) {
  const values = series.flatMap((item) => item.points.map((p) => p.remaining));
  const rawMin = values.length > 0 ? Math.min(...values) : 0;
  const rawMax = values.length > 0 ? Math.max(...values) : 1;
  const span = rawMax - rawMin;
  const padding = span > 0 ? span * 0.15 : Math.max(1, Math.abs(rawMax) * 0.1);
  const low = Math.max(0, rawMin - padding);
  const high = rawMax + padding;
  const dateIndex = new Map(dates.map((date, index) => [date, index]));
  const step = labelStep(dates.length);

  const xFor = (date: string): number => {
    if (dates.length <= 1) return PAD.left + PLOT_WIDTH / 2;
    const index = dateIndex.get(date) ?? 0;
    return PAD.left + (index / (dates.length - 1)) * PLOT_WIDTH;
  };
  const yFor = (value: number): number =>
    PAD.top + PLOT_HEIGHT - ((value - low) / (high - low || 1)) * PLOT_HEIGHT;

  const ticks = [low, (low + high) / 2, high];

  return (
    <div>
      <svg
        className="usage-chart"
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        role="img"
        aria-label={ariaLabel}
      >
        {ticks.map((tick, index) => {
          const y = yFor(tick);
          return (
            <g key={`tick-${index}`}>
              <line
                x1={PAD.left}
                x2={WIDTH - PAD.right}
                y1={y}
                y2={y}
                stroke="var(--line-soft)"
                strokeWidth={1}
              />
              <text x={PAD.left - 6} y={y + 3} textAnchor="end">
                {formatAmount(tick)}
              </text>
            </g>
          );
        })}
        {series.map((item) => (
          <g key={`series-${item.siteId}`}>
            {item.points.length > 1 ? (
              <polyline
                fill="none"
                stroke={item.color}
                strokeWidth={2}
                points={item.points
                  .map((point) => `${xFor(point.date)},${yFor(point.remaining)}`)
                  .join(" ")}
              />
            ) : null}
            {item.points.map((point) => (
              <circle
                key={`${item.siteId}-${point.date}`}
                cx={xFor(point.date)}
                cy={yFor(point.remaining)}
                r={3}
                fill={item.color}
              >
                <title>{`${item.label} · ${point.date} · ${point.remaining.toFixed(2)} ${currency}`}</title>
              </circle>
            ))}
          </g>
        ))}
        {dates.map((date, index) =>
          index % step === 0 ? (
            <text
              key={`x-${date}`}
              x={xFor(date)}
              y={HEIGHT - 8}
              textAnchor="middle"
            >
              {shortDate(date)}
            </text>
          ) : null,
        )}
      </svg>
      <ChartLegend
        items={series.map((item) => ({ label: item.label, color: item.color }))}
      />
    </div>
  );
}

/** 图例：色块 + 站点名。 */
export function ChartLegend({
  items,
}: {
  items: Array<{ label: string; color: string }>;
}) {
  return (
    <div className="usage-legend">
      {items.map((item, index) => (
        <span className="usage-legend-item" key={`${item.label}-${index}`}>
          <span
            className="usage-legend-dot"
            style={{ background: item.color }}
            aria-hidden
          />
          {item.label}
        </span>
      ))}
    </div>
  );
}
