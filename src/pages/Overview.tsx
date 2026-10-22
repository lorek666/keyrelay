import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, KeyRound, Server, ShieldCheck } from "lucide-react";
import { useMutation } from "@tanstack/react-query";
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

export default function Overview() {
  const { t } = useTranslation();
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
    (r) =>
      r.state === "modified" ||
      r.state === "missing" ||
      // 文件存在但读不到：不是「被删了」，但同样要用户处理（复审 P2-4）
      r.state === "unreadable",
  );
  const hasUnreadable = drifted.some((r) => r.state === "unreadable");

  // 会话已失效、需要重新登录的站点（B-61）。从站点表读，而不是只看上一轮刷新结果：
  // 一轮刷新只反映那一刻，而这个状态是**持久**的——用户不重新登录就一直存在。
  const needsLogin = (sites.data ?? []).filter((s) => s.health === "needs_login");

  const warnings = (events.data ?? []).filter(
    (e) => e.level === "warn" || e.level === "error",
  );

  return (
    <section className="page">
      <div className="cards">
        <Stat
          icon={<Server size={16} aria-hidden />}
          label={t("overview.stat.sites")}
          value={sites.data?.length ?? "—"}
        />
        <Stat
          icon={<KeyRound size={16} aria-hidden />}
          label={t("overview.stat.keys")}
          value={keys.data?.length ?? "—"}
        />
        <Stat
          icon={<ShieldCheck size={16} aria-hidden />}
          label={t("overview.stat.consents")}
          value={consents.data?.filter((c) => !c.revokedAt).length ?? "—"}
        />
        <Stat
          icon={<AlertTriangle size={16} aria-hidden />}
          label={t("overview.stat.alerts")}
          value={warnings.length}
          tone={warnings.length > 0 ? "warn" : undefined}
        />
        <Stat
          icon={<ShieldCheck size={16} aria-hidden />}
          label={t("overview.stat.drift")}
          value={drifted.length}
          tone={drifted.length > 0 ? "warn" : undefined}
        />
      </div>

      <div className="card run-state">
        <h3>{t("overview.runState.title")}</h3>
        <dl className="kv">
          <dt>{t("overview.runState.mode")}</dt>
          <dd className="mono">
            {runtimeMode === "tauri"
              ? t("overview.runState.modeTauri")
              : t("overview.runState.modeBrowser")}
          </dd>
          <dt>{t("overview.runState.dataDir")}</dt>
          <dd className="mono ellipsis" title={info.data?.dataDir}>
            {info.data?.dataDir ?? "…"}
          </dd>
          <dt>{t("overview.runState.db")}</dt>
          <dd className="mono ellipsis" title={info.data?.dbPath}>
            {info.data?.dbPath ?? "…"}
          </dd>
          <dt>{t("overview.runState.version")}</dt>
          <dd className="mono">
            {info.data ? `${t("nav.brand")} ${info.data.version}` : "…"}
          </dd>
          <dt>{t("overview.runState.vault")}</dt>
          <dd className="mono">{info.data?.vaultBackend ?? "…"}</dd>
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
        {/* 刷新失败必须说出来（M8-S5B §6.8）：`refresh_all` 出错时整个 mutation 走
            onError，而这里原本只渲染 `refresh.data`（成功分支）⇒ 界面上「成功」与
            「失败」看不出差别，用户会以为刷新成功了。 */}
        {refresh.isError ? (
          <p className="error" role="alert">
            <AlertTriangle size={14} aria-hidden /> {t("overview.error.refreshFailed", { error: refresh.error.message })}
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
        <div className="card">
          <h3>
            <AlertTriangle size={15} aria-hidden /> {t("overview.needsLogin.title", { count: needsLogin.length })}
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
        <div className="card">
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
          {/* 回滚只还原文件、不动绑定 ⇒ 用户自己回滚过的目标也会被报在这里（M3-S1 既定语义，B-126）。
              不说这一句，上面「重新投递」那条会把用户引去撤销他刚做的回滚（复审 P2-1）。 */}
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
        <div className="card">
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
        <div className="card">
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

function Stat({
  icon,
  label,
  value,
  tone,
}: {
  icon: React.ReactNode;
  label: string;
  value: number | string;
  /** M33-S1：>0 的告警类指标给告警色调（中性时不传，样式与文案都不变）。 */
  tone?: "warn" | "danger";
}) {
  return (
    <div className={tone ? `stat stat-${tone}` : "stat"}>
      <span className="stat-icon">{icon}</span>
      <div className="stat-label">
        <span>{label}</span>
      </div>
      <div className="stat-value">{value}</div>
    </div>
  );
}
