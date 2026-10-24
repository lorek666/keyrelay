import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { gatewayStatus, listSites, usageDashboard } from "../lib/api";
import {
  formatCost,
  formatShare,
  formatTokens,
  groupByModel,
  groupBySite,
  snapshotsByCurrency,
  stackByDayAndSite,
  sumTotals,
  unionDates,
} from "../lib/usageAgg";
import {
  LineChart,
  SERIES_COLORS,
  StackedBarChart,
  seriesColor,
} from "../components/UsageCharts";
import { GatewayMetricsPanel } from "../components/GatewayCard";
import { useTranslation } from "../i18n";

/**
 * 流量中心（M45-S2）：用量页的流量部分，只换 Harmony 呈现。
 * 口径与 Usage.tsx 逐项一致：汇总卡 `—` 纪律、站点表能力位列、按密钥表能力位门控、
 * QPS 空态规则（见 GatewayMetricsPanel）。成本桶、Agent 表、账单、单价表不在本页，
 * 属成本步骤；用量入口本步保留，成本步骤再 retire。
 */
const RANGES = [7, 30, 90] as const;
type RangeDays = (typeof RANGES)[number];

const RANGE_LABEL_KEYS: Record<RangeDays, string> = {
  7: "usage.range.d7",
  30: "usage.range.d30",
  90: "usage.range.d90",
};

export default function Traffic() {
  const { t } = useTranslation();
  const [days, setDays] = useState<RangeDays>(30);
  const [siteId, setSiteId] = useState<number | null>(null);

  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });
  const dashboard = useQuery({
    queryKey: ["usage-dashboard", days, siteId],
    queryFn: () => usageDashboard(days, siteId),
    staleTime: 30_000,
  });
  const gateway = useQuery({ queryKey: ["gateway"], queryFn: gatewayStatus });

  const siteList = sites.data ?? [];
  const siteName = (id: number) =>
    siteList.find((site) => site.id === id)?.displayName ||
    t("usage.siteFallback", { id });
  const siteColor = (id: number) => {
    const index = siteList.findIndex((site) => site.id === id);
    return index >= 0 ? seriesColor(index) : SERIES_COLORS[id % SERIES_COLORS.length];
  };
  const capsOf = (id: number) =>
    siteList.find((site) => site.id === id)?.capabilities;

  const daily = dashboard.data?.daily ?? [];
  const bySite = groupBySite(daily);
  const byModel = groupByModel(daily);
  const stack = stackByDayAndSite(daily);
  const snapshots = dashboard.data?.snapshots ?? [];
  const keyUsage = dashboard.data?.keyUsage ?? [];
  const totals = sumTotals(daily);
  const balanceGroups = snapshotsByCurrency(snapshots);

  const selectedSite =
    siteId === null ? null : siteList.find((site) => site.id === siteId);
  const capableSites = selectedSite
    ? selectedSite.capabilities.keyUsage
      ? [selectedSite]
      : []
    : siteList.filter((site) => site.capabilities.keyUsage);
  const incapableSites = selectedSite
    ? selectedSite.capabilities.keyUsage
      ? []
      : [selectedSite]
    : siteList.filter((site) => !site.capabilities.keyUsage);
  const visibleKeyUsage = keyUsage.filter((row) =>
    capableSites.some((site) => site.id === row.siteId),
  );
  const capsReady = sites.isSuccess;
  const cardValue = (value: string | number) =>
    dashboard.isLoading || dashboard.isError ? "—" : value;
  const noData =
    !dashboard.isLoading &&
    !dashboard.isError &&
    daily.length === 0 &&
    snapshots.length === 0 &&
    keyUsage.length === 0;

  return (
    <section className="page">
      <div className="hm-card">
        <div className="usage-toolbar">
          <div
            className="usage-range"
            role="group"
            aria-label={t("usage.rangeLabel")}
          >
            {RANGES.map((range) => (
              <button
                key={range}
                type="button"
                className={range === days ? "btn btn-primary" : "btn"}
                aria-pressed={range === days}
                onClick={() => setDays(range)}
              >
                {t(RANGE_LABEL_KEYS[range])}
              </button>
            ))}
          </div>
          <label className="usage-site-filter">
            <span>{t("usage.siteFilter")}</span>
            <select
              value={siteId ?? ""}
              onChange={(event) =>
                setSiteId(event.target.value ? Number(event.target.value) : null)
              }
            >
              <option value="">{t("usage.allSites")}</option>
              {siteList.map((site) => (
                <option key={site.id} value={site.id}>
                  {site.displayName || site.baseUrl}
                </option>
              ))}
            </select>
          </label>
        </div>
        <p className="muted usage-note">{t("usage.scopeHint")}</p>
      </div>

      {dashboard.isError ? (
        <p className="error" role="alert">
          {t("usage.error", { error: (dashboard.error as Error).message })}
        </p>
      ) : null}

      {noData ? (
        <div className="hm-card">
          <p className="muted">{t("usage.empty")}</p>
        </div>
      ) : null}

      <div className="hm-grid8">
        <div className="hm-card hm-metric" style={{ margin: 0 }}>
          <div className="hm-label">{t("usage.cards.tokens")}</div>
          <div className="hm-num">{cardValue(formatTokens(totals.totalTokens))}</div>
        </div>
        <div className="hm-card hm-metric" style={{ margin: 0 }}>
          <div className="hm-label">{t("usage.cards.requests")}</div>
          <div className="hm-num">{cardValue(totals.requests.toLocaleString())}</div>
        </div>
        <div className="hm-card hm-metric" style={{ margin: 0 }}>
          <div className="hm-label">{t("usage.cards.sites")}</div>
          <div className="hm-num">{cardValue(bySite.length)}</div>
        </div>
        <div className="hm-card hm-metric" style={{ margin: 0 }}>
          <div className="hm-label">{t("usage.cards.models")}</div>
          <div className="hm-num">{cardValue(byModel.length)}</div>
        </div>
      </div>

      <div className="hm-card">
        <GatewayMetricsPanel status={gateway.data} />
      </div>

      <div className="hm-card">
        <h3>{t("usage.trend.title")}</h3>
        {dashboard.isLoading ? (
          <p className="muted">{t("usage.loading")}</p>
        ) : daily.length === 0 ? (
          <p className="muted">{t("usage.trend.empty")}</p>
        ) : (
          <StackedBarChart
            dates={stack.dates}
            series={stack.series.map((item) => ({
              siteId: item.siteId,
              label: siteName(item.siteId),
              color: siteColor(item.siteId),
              values: item.values,
            }))}
            ariaLabel={t("usage.trend.title")}
          />
        )}
      </div>

      <div className="hm-card">
        <h3>{t("usage.balance.title")}</h3>
        <p className="muted usage-note">{t("usage.balance.note")}</p>
        {snapshots.length === 0 ? (
          <p className="muted">{t("usage.balance.empty")}</p>
        ) : (
          balanceGroups.map((group) => (
            <div className="usage-balance-block" key={group.currency}>
              <h4>
                {t("usage.balance.currency", { currency: group.currency })}
              </h4>
              <LineChart
                dates={unionDates(group.series)}
                series={group.series.map((item) => ({
                  siteId: item.siteId,
                  label: siteName(item.siteId),
                  color: siteColor(item.siteId),
                  points: item.points,
                }))}
                currency={group.currency}
                ariaLabel={t("usage.balance.currency", {
                  currency: group.currency,
                })}
              />
            </div>
          ))
        )}
      </div>

      <div className="hm-card">
        <h3>{t("usage.models.title")}</h3>
        {byModel.length === 0 ? (
          <p className="muted">{t("usage.models.empty")}</p>
        ) : (
          byModel.map((row) => {
            const percent =
              totals.totalTokens > 0
                ? (row.totalTokens / totals.totalTokens) * 100
                : 0;
            return (
              <div
                className="usage-bar-row"
                key={row.model === "" ? "__unknown__" : row.model}
              >
                <span className="usage-bar-label" title={row.model}>
                  {row.model === "" ? t("usage.unknownModel") : row.model}
                </span>
                <span className="usage-bar-track">
                  <span
                    className="usage-bar-fill"
                    style={{ width: `${percent}%` }}
                  />
                </span>
                <span className="usage-bar-value mono">
                  {formatTokens(row.totalTokens)} ·{" "}
                  {formatShare(row.totalTokens, totals.totalTokens)}
                </span>
              </div>
            );
          })
        )}
      </div>

      <div className="hm-card">
        <h3>{t("usage.sites.title")}</h3>
        {bySite.length === 0 ? (
          <p className="muted">{t("usage.sites.empty")}</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>{t("usage.sites.colSite")}</th>
                <th>{t("usage.sites.colRequests")}</th>
                <th>{t("usage.sites.colPrompt")}</th>
                <th>{t("usage.sites.colCompletion")}</th>
                <th>{t("usage.sites.colTotal")}</th>
                <th>{t("usage.sites.colShare")}</th>
                <th>{t("usage.sites.colKeyUsage")}</th>
              </tr>
            </thead>
            <tbody>
              {bySite.map((row) => {
                const capable = capsReady ? capsOf(row.siteId)?.keyUsage : undefined;
                return (
                  <tr key={row.siteId}>
                    <td>{siteName(row.siteId)}</td>
                    <td className="mono">{row.requests.toLocaleString()}</td>
                    <td className="mono">{formatTokens(row.promptTokens)}</td>
                    <td className="mono">
                      {formatTokens(row.completionTokens)}
                    </td>
                    <td className="mono">{formatTokens(row.totalTokens)}</td>
                    <td className="mono">
                      {formatShare(row.totalTokens, totals.totalTokens)}
                    </td>
                    <td>
                      {!capsReady
                        ? "—"
                        : capable
                          ? t("usage.sites.keyUsageYes")
                          : t("usage.sites.keyUsageNo")}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      <div className="hm-card">
        <h3>{t("usage.keys.title", { days: dashboard.data?.rangeDays ?? days })}</h3>
        <p className="muted usage-note">{t("usage.keys.note")}</p>
        {!capsReady ? (
          <p className="muted">{t("usage.loading")}</p>
        ) : capableSites.length === 0 ? (
          <p className="muted">{t("usage.keys.noCapability")}</p>
        ) : visibleKeyUsage.length === 0 ? (
          <p className="muted">{t("usage.keys.empty")}</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>{t("usage.keys.colSite")}</th>
                <th>{t("usage.keys.colKey")}</th>
                <th>{t("usage.keys.colRequests")}</th>
                <th>{t("usage.keys.colTokens")}</th>
                <th>{t("usage.keys.colCost")}</th>
              </tr>
            </thead>
            <tbody>
              {visibleKeyUsage.map((row) => (
                <tr key={`${row.siteId}-${row.keyId}`}>
                  <td>{siteName(row.siteId)}</td>
                  <td>{row.keyName}</td>
                  <td className="mono">{row.requests.toLocaleString()}</td>
                  <td className="mono">
                    {formatTokens(row.inputTokens)} /{" "}
                    {formatTokens(row.outputTokens)}
                  </td>
                  <td className="mono">
                    {row.cost === null ? (
                      t("usage.cost.unpriced")
                    ) : row.currency ? (
                      `${formatCost(row.cost)} ${row.currency}`
                    ) : (
                      formatCost(row.cost)
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {capsReady && capableSites.length > 0 && incapableSites.length > 0 ? (
          <p className="muted usage-note">
            {t("usage.keys.partial", {
              sites: incapableSites
                .map((site) => site.displayName || site.baseUrl)
                .join(", "),
            })}
          </p>
        ) : null}
      </div>
    </section>
  );
}
