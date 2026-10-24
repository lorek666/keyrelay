import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { AlertTriangle } from "lucide-react";
import {
  appInfo,
  driftReport,
  listConsents,
  listSites,
  listStoredKeys,
  recentEvents,
  recentGatewayUsage,
  recentUsageSnapshots,
  refreshAll,
  runtimeMode,
} from "../lib/api";
import { useTranslation } from "../i18n";
import RebrandNotice from "../components/RebrandNotice";

/**
 * 指挥舱（M45-S1）：总览页的数据逻辑，只换 Harmony 呈现。
 * 口径与 Overview.tsx 逐项一致：5 指标定义、漂移三态过滤、告警 top5 截断、
 * 用量 24h 分站点汇总与 7d 余额快照 delta——改任一口径都必须同步改单测。
 */
export default function Cockpit() {
  const { t } = useTranslation();
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const info = useQuery({ queryKey: ["app-info"], queryFn: appInfo });
  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });
  const keys = useQuery({ queryKey: ["stored-keys"], queryFn: listStoredKeys });
  const consents = useQuery({ queryKey: ["consents"], queryFn: listConsents });
  const events = useQuery({ queryKey: ["events"], queryFn: () => recentEvents(20) });
  const gatewayUsage = useQuery({ queryKey: ["gateway-usage"], queryFn: () => recentGatewayUsage(24) });
  const usageSnapshots = useQuery({ queryKey: ["usage-snapshots"], queryFn: () => recentUsageSnapshots(168) });
  const drift = useQuery({ queryKey: ["drift"], queryFn: driftReport });

  const refresh = useMutation({
    mutationFn: refreshAll,
    onSuccess: async () => {
      await events.refetch();
      await sites.refetch();
      await keys.refetch();
    },
  });

  const drifted = (drift.data ?? []).filter(
    (r) => r.state === "modified" || r.state === "missing" || r.state === "unreadable",
  );
  const hasUnreadable = drifted.some((r) => r.state === "unreadable");
  const needsLogin = (sites.data ?? []).filter((s) => s.health === "needs_login");
  const warnings = (events.data ?? []).filter((e) => e.level === "warn" || e.level === "error");

  return (
    <section className="page">
      <div className="hm-hero">
        <div>
          <h1>
            {t("nav.brand")} <span>Relay</span>
          </h1>
          <p>
            {info.data ? `${t("nav.brand")} ${info.data.version}` : "…"} · {t("overview.runState.mode")}
            :{" "}
            {runtimeMode === "tauri"
              ? t("overview.runState.modeTauri")
              : t("overview.runState.modeBrowser")}
          </p>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <span className="hm-pill">
            {t("cockpit.live")} {now.toTimeString().slice(0, 8)}
          </span>
        </div>
      </div>

      <div className="hm-grid8">
        <div className="hm-card hm-metric" style={{ margin: 0 }}>
          <div className="hm-label">{t("overview.stat.sites")}</div>
          <div className="hm-num">{sites.data?.length ?? "—"}</div>
        </div>
        <div className="hm-card hm-metric" style={{ margin: 0 }}>
          <div className="hm-label">{t("overview.stat.keys")}</div>
          <div className="hm-num">{keys.data?.length ?? "—"}</div>
        </div>
        <div className="hm-card hm-metric" style={{ margin: 0 }}>
          <div className="hm-label">{t("overview.stat.consents")}</div>
          <div className="hm-num">
            {consents.data ? consents.data.filter((c) => !c.revokedAt).length : "—"}
          </div>
        </div>
        <div className="hm-card hm-metric" style={{ margin: 0 }}>
          <div className="hm-label">{t("overview.stat.alerts")}</div>
          <div className="hm-num">{warnings.length}</div>
        </div>
        <div className="hm-card hm-metric" style={{ margin: 0 }}>
          <div className="hm-label">{t("overview.stat.drift")}</div>
          <div className="hm-num">{drifted.length}</div>
        </div>
        <div className="hm-card hm-metric" style={{ margin: 0 }}>
          <div className="hm-label">{t("overview.runState.dataDir")}</div>
          <div className="hm-num-sm mono ellipsis" title={info.data?.dataDir}>
            {info.data?.dataDir ?? "…"}
          </div>
        </div>
        <div className="hm-card hm-metric" style={{ margin: 0 }}>
          <div className="hm-label">{t("overview.runState.db")}</div>
          <div className="hm-num-sm mono ellipsis" title={info.data?.dbPath}>
            {info.data?.dbPath ?? "…"}
          </div>
        </div>
        <div className="hm-card hm-metric" style={{ margin: 0 }}>
          <div className="hm-label">{t("overview.runState.vault")}</div>
          <div className="hm-num-sm mono">{info.data?.vaultBackend ?? "…"}</div>
        </div>
      </div>

      <div className="hm-card">
        <h3>{t("overview.runState.title")}</h3>
        <dl className="kv">
          <dt>{t("overview.runState.mode")}</dt>
          <dd className="mono">
            {runtimeMode === "tauri"
              ? t("overview.runState.modeTauri")
              : t("overview.runState.modeBrowser")}
          </dd>
          <dt>{t("overview.runState.version")}</dt>
          <dd className="mono">{info.data ? `${t("nav.brand")} ${info.data.version}` : "…"}</dd>
        </dl>
        <button
          type="button"
          className="btn"
          disabled={refresh.isPending}
          onClick={() => refresh.mutate()}
        >
          {refresh.isPending ? t("overview.btn.refreshing") : t("overview.btn.refreshNow")}
        </button>
        {refresh.data ? (
          <p className="muted">
            {t("overview.refreshResult.base", {
              ok: refresh.data.sitesOk,
              failed: refresh.data.sitesFailed,
              keys: refresh.data.keysTotal,
            })}
            {refresh.data.balanceAlerts.length
              ? t("overview.refreshResult.balanceAlerts", { count: refresh.data.balanceAlerts.length })
              : ""}
            {refresh.data.needsLogin.length
              ? t("overview.refreshResult.needsLogin", { count: refresh.data.needsLogin.length })
              : ""}
          </p>
        ) : null}
        {refresh.isError ? (
          <p className="error" role="alert">
            <AlertTriangle size={14} aria-hidden />{" "}
            {t("overview.error.refreshFailed", { error: refresh.error.message })}
          </p>
        ) : null}
        {info.data?.vaultBackend === "memory" ? (
          <p className="error" role="alert">
            <AlertTriangle size={14} aria-hidden /> {t("overview.error.memoryVaultPre")}
            {t("overview.error.memoryVaultPost")}
          </p>
        ) : null}
        {runtimeMode === "browser" ? (
          <p className="warn" role="status">
            {t("overview.warn.browserPreviewPre")}
            <span className="mono">pnpm tauri dev</span>
            {t("overview.warn.browserPreviewPost")}
          </p>
        ) : null}
      </div>

      <RebrandNotice rebrand={info.data?.rebrand} dataDir={info.data?.dataDir} />

      {needsLogin.length ? (
        <div className="hm-card">
          <h3>
            <AlertTriangle size={15} aria-hidden />{" "}
            {t("overview.needsLogin.title", { count: needsLogin.length })}
          </h3>
          <ul className="list">
            {needsLogin.map((s) => (
              <li key={s.id}>
                <span className="badge badge-warn">needs_login</span>{" "}
                <span className="mono ellipsis" title={s.baseUrl}>
                  {s.displayName || s.baseUrl}
                </span>
              </li>
            ))}
          </ul>
          <p className="muted">{t("overview.needsLogin.hint")}</p>
        </div>
      ) : null}

      {drifted.length ? (
        <div className="hm-card">
          <h3>
            <AlertTriangle size={15} aria-hidden />{" "}
            {t("overview.drift.title", { count: drifted.length })}
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

      {warnings.length ? (
        <div className="hm-card">
          <h3>{t("overview.alerts.title")}</h3>
          <ul className="list">
            {warnings.slice(0, 5).map((row) => (
              <li key={row.id}>
                <span className={`badge badge-${row.level === "error" ? "danger" : "warn"}`}>
                  {row.level}
                </span>{" "}
                <span className="mono">{row.source}</span> {row.message}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {gatewayUsage.data?.length || usageSnapshots.data?.length ? (
        <div className="hm-card">
          <h3>{t("overview.usage.title")}</h3>
          {(() => {
            const siteName = (id: number) =>
              sites.data?.find((s) => s.id === id)?.displayName ??
              t("overview.usage.siteFallback", { id });
            const usageBySite = new Map<number, { prompt: number; completion: number; total: number }>();
            for (const row of gatewayUsage.data ?? []) {
              const cur = usageBySite.get(row.siteId) ?? { prompt: 0, completion: 0, total: 0 };
              cur.prompt += row.promptTokens;
              cur.completion += row.completionTokens;
              cur.total += row.totalTokens;
              usageBySite.set(row.siteId, cur);
            }
            return (
              <>
                {gatewayUsage.data?.length ? (
                  <dl className="kv">
                    <dt>{t("overview.usage.gateway24h")}</dt>
                    <dd className="mono">
                      {Array.from(usageBySite.entries()).map(([siteId, v], i) => (
                        <span key={siteId}>
                          {i > 0 ? " / " : ""}
                          {t("overview.usage.tokens", {
                            site: siteName(siteId),
                            total: v.total.toLocaleString(),
                            prompt: v.prompt.toLocaleString(),
                            completion: v.completion.toLocaleString(),
                          })}
                        </span>
                      ))}
                    </dd>
                  </dl>
                ) : null}
                {usageSnapshots.data?.length ? (
                  <dl className="kv">
                    <dt>{t("overview.usage.snapshot7d")}</dt>
                    <dd className="mono">
                      {(() => {
                        const bySite = new Map<number, typeof usageSnapshots.data>();
                        for (const s of usageSnapshots.data) {
                          if (!bySite.has(s.siteId)) bySite.set(s.siteId, []);
                          bySite.get(s.siteId)!.push(s);
                        }
                        return Array.from(bySite.entries()).map(([siteId, snaps], i) => {
                          const latest = snaps[0];
                          const prev = snaps[1];
                          const delta = prev ? latest.used - prev.used : null;
                          return (
                            <span key={siteId}>
                              {i > 0 ? " / " : ""}
                              {t("overview.usage.balance", {
                                site: siteName(siteId),
                                used: latest.used.toFixed(2),
                                currency: latest.currency,
                                remaining: latest.remaining.toFixed(2),
                                delta:
                                  delta !== null
                                    ? t("overview.usage.delta", {
                                        delta: `${delta > 0 ? "+" : ""}${delta.toFixed(2)}`,
                                      })
                                    : "",
                              })}
                            </span>
                          );
                        });
                      })()}
                    </dd>
                  </dl>
                ) : null}
              </>
            );
          })()}
        </div>
      ) : null}
    </section>
  );
}
