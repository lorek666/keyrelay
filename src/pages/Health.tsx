import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, RefreshCw } from "lucide-react";
import {
  driftReport,
  isAuthError,
  listSites,
  recentEvents,
  siteBalance,
  type SiteRow,
} from "../lib/api";
import Probe from "./Probe";
import { useTranslation } from "../i18n";

const LEVEL_TONE: Record<string, string> = {
  debug: "muted",
  info: "ok",
  warn: "warn",
  error: "danger",
};

/**
 * 健康中心（M45-S4）：余额矩阵 + 探针 + 漂移 + 事件，只换 Harmony 呈现。
 * 余额四态映射与站点页余额列逐行一致（能力门控、加载、失败分型、未知处理、数值格式）；
 * 漂移过滤与总览页一致（modified / missing / unreadable）；事件表与历史页一致（200 条）。
 * 探针入口在本步 retire，`Probe.tsx` 保留为本页的探针区组件；历史页的事件区同步移出（投递记录区保留）。
 */
export default function Health() {
  const { t } = useTranslation();
  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });
  const drift = useQuery({ queryKey: ["drift"], queryFn: driftReport });
  const events = useQuery({ queryKey: ["events"], queryFn: () => recentEvents(200) });

  const drifted = (drift.data ?? []).filter(
    (r) =>
      r.state === "modified" ||
      r.state === "missing" ||
      r.state === "unreadable",
  );
  const hasUnreadable = drifted.some((r) => r.state === "unreadable");

  return (
    <section className="page">
      <div className="hm-card">
        <h3>{t("health.balance.title")}</h3>
        <p className="muted">{t("health.balance.note")}</p>
        {sites.isLoading ? (
          <p className="muted">{t("common.loading")}</p>
        ) : sites.isError ? (
          <p className="error" role="alert">
            {t("health.balance.error", { error: (sites.error as Error).message })}
          </p>
        ) : (sites.data ?? []).length === 0 ? (
          <p className="muted">{t("health.balance.empty")}</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>{t("health.balance.site")}</th>
                <th>{t("health.balance.balance")}</th>
              </tr>
            </thead>
            <tbody>
              {(sites.data ?? []).map((site) => (
                <BalanceRow key={site.id} site={site} />
              ))}
            </tbody>
          </table>
        )}
      </div>

      <Probe />

      {drifted.length ? (
        <div className="hm-card">
          <h3>
            <AlertTriangle size={15} aria-hidden /> {t("overview.drift.title", { count: drifted.length })}
          </h3>
          <ul className="list">
            {drifted.map((r) => (
              <li key={r.targetPath}>
                <span className="badge badge-warn">{r.state}</span>{" "}
                <span className="mono">{r.agentId}</span>{" "}
                <span className="mono ellipsis" title={r.targetPath}>
                  {r.targetPath}
                </span>
              </li>
            ))}
          </ul>
          <p className="muted">
            {t("overview.drift.hint1Pre")}
            <span className="mono">missing</span>
            {t("overview.drift.hint1Mid")}
            <span className="mono">modified</span>
            {t("overview.drift.hint1Post")}
          </p>
          <p className="muted">
            <strong>{t("overview.drift.hint2Pre")}</strong>
            {t("overview.drift.hint2Post")}
          </p>
          {hasUnreadable ? (
            <p className="muted">
              {t("overview.drift.hint3Pre")}
              <span className="mono">unreadable</span>
              {t("overview.drift.hint3Mid1")}
              <strong>{t("overview.drift.hint3Mid2")}</strong>
              {t("overview.drift.hint3Post")}
            </p>
          ) : null}
        </div>
      ) : null}

      <div className="hm-card">
        <div className="row row-between">
          <h3>{t("history.events.title", { count: events.data?.length ?? 0 })}</h3>
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => events.refetch()}
            disabled={events.isFetching}
          >
            <RefreshCw size={14} aria-hidden /> {t("common.refresh")}
          </button>
        </div>
        {events.isLoading ? <p className="muted">{t("common.loading")}</p> : null}
        {events.isError ? (
          <p className="error" role="alert">
            {t("history.events.error", { error: (events.error as Error).message })}
          </p>
        ) : null}
        {events.data?.length === 0 ? (
          <p className="muted empty">{t("history.events.empty")}</p>
        ) : null}
        {events.data?.length ? (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>{t("history.events.table.time")}</th>
                  <th>{t("history.events.table.level")}</th>
                  <th>{t("history.events.table.source")}</th>
                  <th>{t("history.events.table.message")}</th>
                  <th>{t("history.events.table.payload")}</th>
                </tr>
              </thead>
              <tbody>
                {events.data.map((row) => (
                  <tr key={row.id}>
                    <td className="mono">{formatTs(row.ts)}</td>
                    <td>
                      <span className={`badge badge-${LEVEL_TONE[row.level] ?? "muted"}`}>
                        {row.level}
                      </span>
                    </td>
                    <td className="mono">{row.source}</td>
                    <td>{row.message}</td>
                    <td className="mono ellipsis" title={row.payload ?? ""}>
                      {row.payload ?? "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </div>
    </section>
  );
}

/**
 * 余额行：映射与 `Sites.tsx` 余额列逐行一致。
 * 能力集为 false 的站点连请求都不发；未知绝不当成 0；失败分型只认凭证问题为「需登录」。
 */
function BalanceRow({ site }: { site: SiteRow }) {
  const { t } = useTranslation();
  const balance = useQuery({
    queryKey: ["balance", site.id],
    queryFn: () => siteBalance(site.id),
    enabled: site.capabilities.balance,
    retry: false,
  });

  const balanceText = !site.capabilities.balance
    ? t("sites.balanceText.unobservable")
    : balance.isLoading
      ? "…"
      : balance.isError
        ? isAuthError(balance.error)
          ? t("sites.balanceText.needLogin")
          : t("sites.balanceText.queryFailed")
        : balance.data
          ? !balance.data.known || balance.data.remaining === null
            ? t("sites.balanceText.unobservable")
            : `${balance.data.remaining.toFixed(2)} ${balance.data.currency}`
          : "—";

  return (
    <tr>
      <td>{site.displayName}</td>
      <td className="mono">{balanceText}</td>
    </tr>
  );
}

function formatTs(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}
