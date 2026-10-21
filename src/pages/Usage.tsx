import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { listSites, usageDashboard } from "../lib/api";
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
import { useTranslation } from "../i18n";

/**
 * M34-S1：独立用量页。
 *
 * 数据只有两个来源，口径必须写清楚（spec §9）：
 * - Token：**只统计经本地网关转发**的请求（`gateway_usage_log`）；
 * - 余额：每轮刷新写入的快照（`usage_snapshots`），每站点每天取最后一条。
 *
 * `SiteCapabilities.keyUsage` 在这里有**第二个消费点**：按密钥表只显示能力位为
 * true 的站点，站点汇总表也用同一能力位标注「可观测 / 不提供」——后端不判能力位
 * （它不知道界面语义），门控全部在界面这一层。
 */

const RANGES = [7, 30, 90] as const;
type RangeDays = (typeof RANGES)[number];

const RANGE_LABEL_KEYS: Record<RangeDays, string> = {
  7: "usage.range.d7",
  30: "usage.range.d30",
  90: "usage.range.d90",
};

export default function Usage() {
  const { t } = useTranslation();
  const [days, setDays] = useState<RangeDays>(30);
  const [siteId, setSiteId] = useState<number | null>(null);

  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });
  const dashboard = useQuery({
    queryKey: ["usage-dashboard", days, siteId],
    queryFn: () => usageDashboard(days, siteId),
    staleTime: 30_000,
  });

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
  const snapshots = dashboard.data?.snapshots ?? [];
  const keyUsage = dashboard.data?.keyUsage ?? [];
  const totals = sumTotals(daily);
  const bySite = groupBySite(daily);
  const byModel = groupByModel(daily);
  const stack = stackByDayAndSite(daily);
  const balanceGroups = snapshotsByCurrency(snapshots);

  // keyUsage 能力位消费：只有 true 的站点可以出现在按密钥表里。
  // 站点筛选生效时，只看**被选中的那个站点**——否则筛到一个没有能力的站点，
  // 页面会显示「还没有采样」而不是「这个站点不提供」（复审 P3-5）。
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
  // 汇总卡在加载 / 出错时显示「—」而不是 0：0 是「确实没有流量」，与「还没读到」是两件事。
  const cardValue = (value: string | number) =>
    dashboard.isLoading || dashboard.isError ? "—" : value;
  const noData =
    !dashboard.isLoading &&
    !dashboard.isError &&
    daily.length === 0 &&
    snapshots.length === 0 &&
    keyUsage.length === 0;

  return (
    <section className="page usage-page">
      <div className="card">
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
        <div className="card">
          <p className="muted">{t("usage.empty")}</p>
        </div>
      ) : null}

      <div className="cards">
        <Stat
          label={t("usage.cards.tokens")}
          value={cardValue(formatTokens(totals.totalTokens))}
        />
        <Stat
          label={t("usage.cards.requests")}
          value={cardValue(totals.requests.toLocaleString())}
        />
        <Stat
          label={t("usage.cards.sites")}
          value={cardValue(bySite.length)}
        />
        <Stat
          label={t("usage.cards.models")}
          value={cardValue(byModel.length)}
        />
      </div>

      <div className="card">
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

      <div className="card">
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

      <div className="card">
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
                // 站点列表还没读回来时不能断言「不提供」——那是把「不知道」当成事实
                // （与 Balance.known 同纪律，复审 P2-3）。
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

      <div className="card">
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
                  {row.model === ""
                    ? t("usage.unknownModel")
                    : row.model}
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

      <div className="card">
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
                    {row.currency
                      ? `${formatCost(row.cost)} ${row.currency}`
                      : formatCost(row.cost)}
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

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="stat">
      <div className="stat-label">
        <span>{label}</span>
      </div>
      <div className="stat-value">{value}</div>
    </div>
  );
}
