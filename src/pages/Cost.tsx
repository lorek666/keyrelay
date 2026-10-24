import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  listSites,
  siteBillImport,
  siteBillProbe,
  siteBills,
  usageDashboard,
} from "../lib/api";
import {
  formatEstimate,
  isFullyUnpriced,
  isPartiallyPriced,
  sumByCurrency,
} from "../lib/usageCost";
import { formatTokens } from "../lib/usageAgg";
import ModelPricesCard from "../components/ModelPricesCard";
import BudgetsCard from "../components/BudgetsCard";
import ReconciliationCard from "../components/ReconciliationCard";
import { useTranslation } from "../i18n";

/**
 * 成本中心（M45-S3）：用量页的成本部分 + 设置页搬出的单价表，只换 Harmony 呈现。
 * 口径与 Usage.tsx 逐项一致：成本桶按币种分桶（跨币种永不合并，未知币种单独一桶）、
 * 未定价分型、Agent 表未归因标签与未定价列、账单探测四态与 partial 警告、币种覆盖标注。
 * 用量入口在本步 retire，`Usage.tsx` 已删除。
 */
const RANGES = [7, 30, 90] as const;
type RangeDays = (typeof RANGES)[number];

const RANGE_LABEL_KEYS: Record<RangeDays, string> = {
  7: "usage.range.d7",
  30: "usage.range.d30",
  90: "usage.range.d90",
};

export default function Cost() {
  const { t } = useTranslation();
  const [days, setDays] = useState<RangeDays>(30);
  const [siteId, setSiteId] = useState<number | null>(null);

  const qc = useQueryClient();
  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });
  const dashboard = useQuery({
    queryKey: ["usage-dashboard", days, siteId],
    queryFn: () => usageDashboard(days, siteId),
    staleTime: 30_000,
  });

  const [billSite, setBillSite] = useState<number | null>(null);
  const [billCurrency, setBillCurrency] = useState("");
  const [billMsg, setBillMsg] = useState<string | null>(null);
  const bills = useQuery({ queryKey: ["site-bills", days], queryFn: () => siteBills(days) });
  const probe = useMutation({
    mutationFn: () => siteBillProbe(billSite!),
    onSuccess: (p) =>
      setBillMsg(
        p.status === "supported"
          ? t("usage.bills.probeSupported")
          : p.status === "needsLogin"
            ? t("usage.bills.probeNeedsLogin")
            : p.status === "unsupported"
              ? t("usage.bills.probeUnsupported")
              : t("usage.bills.probeFailed", { reason: p.reason ?? "" }),
      ),
    onError: (err: Error) => setBillMsg(err.message),
  });
  const importBill = useMutation({
    mutationFn: () =>
      siteBillImport(billSite!, undefined, billCurrency === "" ? undefined : billCurrency),
    onSuccess: async (o) => {
      setBillMsg(
        t("usage.bills.imported", { days: o.imported, pages: o.pages }) +
          (o.partial ? t("usage.bills.partial", { pages: o.pages }) : "") +
          (o.currencyOverrideUsed && o.currency
            ? t("usage.bills.currencyUsed", { currency: o.currency })
            : ""),
      );
      await qc.invalidateQueries({ queryKey: ["site-bills"] });
    },
    onError: (err: Error) => setBillMsg(err.message),
  });

  const siteList = sites.data ?? [];
  const siteName = (id: number) =>
    siteList.find((site) => site.id === id)?.displayName ||
    t("usage.siteFallback", { id });
  const daily = dashboard.data?.daily ?? [];
  const byAgent = dashboard.data?.byAgent ?? [];
  const costBuckets = sumByCurrency(
    daily.map((row) => ({
      currency: row.currency,
      estimatedCost: row.estimatedCost,
      requests: row.requests,
      unpricedRequests: row.unpricedRequests,
    })),
  );

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

      <div className="hm-card">
        <h3>{t("usage.cost.title")}</h3>
        <p className="muted usage-note">{t("usage.cost.note")}</p>
        {costBuckets.length === 0 ? (
          <p className="muted">{t("usage.cost.empty")}</p>
        ) : (
          <div className="hm-grid8">
            {costBuckets.map((bucket) => (
              <div className="hm-card hm-metric" style={{ margin: 0 }} key={bucket.currency ?? "__unknown__"}>
                <div className="hm-label">
                  {bucket.currency
                    ? t("usage.cost.bucket", { currency: bucket.currency })
                    : t("usage.cost.unknownCurrency")}
                </div>
                <div className="hm-num-sm">
                  {isFullyUnpriced(bucket)
                    ? t("usage.cost.unpriced")
                    : formatEstimate(bucket.estimated, bucket.currency)}
                </div>
                {isPartiallyPriced(bucket) ? (
                  <div className="hm-sub">
                    {t("usage.cost.partial", { count: bucket.unpricedRequests })}
                  </div>
                ) : isFullyUnpriced(bucket) ? (
                  <div className="hm-sub">
                    {t("usage.cost.allUnpriced", { count: bucket.unpricedRequests })}
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="hm-card">
        <h3>{t("usage.agents.title")}</h3>
        <p className="muted usage-note">{t("usage.agents.note")}</p>
        {byAgent.length === 0 ? (
          <p className="muted">{t("usage.agents.empty")}</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>{t("usage.agents.agent")}</th>
                <th>{t("usage.agents.currency")}</th>
                <th>{t("usage.agents.requests")}</th>
                <th>{t("usage.agents.tokens")}</th>
                <th>{t("usage.agents.cost")}</th>
              </tr>
            </thead>
            <tbody>
              {byAgent.map((row) => (
                <tr key={`${row.agentLabel}-${row.currency ?? "?"}`}>
                  <td>
                    {row.agentLabel === ""
                      ? t("usage.agents.unattributed")
                      : row.agentLabel}
                  </td>
                  <td>{row.currency ?? t("usage.cost.unknownCurrency")}</td>
                  <td className="mono">{row.requests.toLocaleString()}</td>
                  <td className="mono">{formatTokens(row.totalTokens)}</td>
                  <td>
                    {row.estimatedCost === null
                      ? t("usage.cost.unpriced")
                      : formatEstimate(row.estimatedCost, row.currency)}
                    {row.unpricedRequests > 0 ? (
                      <span className="muted">
                        {" "}
                        {t("usage.cost.partial", { count: row.unpricedRequests })}
                      </span>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="hm-card">
        <h3>{t("usage.bills.title")}</h3>
        <p className="muted usage-note">{t("usage.bills.note")}</p>
        <div className="row">
          <label className="field-inline">
            <span>{t("usage.bills.siteLabel")}</span>
            <select
              className="input"
              value={billSite ?? ""}
              onChange={(e) => {
                setBillMsg(null);
                setBillSite(e.target.value === "" ? null : Number(e.target.value));
              }}
            >
              <option value="">{t("usage.bills.sitePlaceholder")}</option>
              {siteList.map((site) => (
                <option key={site.id} value={site.id}>
                  {site.displayName}
                </option>
              ))}
            </select>
          </label>
          <label className="field-inline">
            <span>{t("usage.bills.currency")}</span>
            <select
              className="input"
              value={billCurrency}
              onChange={(e) => setBillCurrency(e.target.value)}
            >
              <option value="">{t("usage.bills.currencyAuto")}</option>
              <option value="USD">USD</option>
              <option value="CNY">CNY</option>
            </select>
          </label>
          <button
            type="button"
            className="btn"
            disabled={billSite === null || probe.isPending}
            onClick={() => probe.mutate()}
          >
            {t("usage.bills.probe")}
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={billSite === null || importBill.isPending}
            title={t("usage.bills.importHint")}
            onClick={() => importBill.mutate()}
          >
            {importBill.isPending ? t("usage.bills.importing") : t("usage.bills.import")}
          </button>
        </div>
        {billMsg ? <p className="muted">{billMsg}</p> : null}
        {bills.data && bills.data.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>{t("usage.bills.day")}</th>
                <th>{t("usage.bills.siteCol")}</th>
                <th>{t("usage.bills.amount")}</th>
                <th>{t("usage.bills.currencyCol")}</th>
                <th>{t("usage.bills.requests")}</th>
                <th>{t("usage.bills.source")}</th>
              </tr>
            </thead>
            <tbody>
              {bills.data.map((row) => (
                <tr key={row.id}>
                  <td className="mono">{row.day}</td>
                  <td>{siteName(row.siteId)}</td>
                  <td>{row.amount === null ? t("usage.cost.unpriced") : formatEstimate(row.amount, row.currency)}</td>
                  <td>{row.currency ?? t("usage.cost.unknownCurrency")}</td>
                  <td>{row.requests === null ? t("usage.cost.unpriced") : row.requests.toLocaleString()}</td>
                  <td className="mono">{row.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="muted">{t("usage.bills.empty")}</p>
        )}
      </div>

      <ModelPricesCard />
      <BudgetsCard />
      <ReconciliationCard />
    </section>
  );
}
