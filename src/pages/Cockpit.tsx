import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  CheckCircle2,
  ChevronDown,
  CircleAlert,
  FileWarning,
  KeyRound,
  Layers3,
  Plug,
  RefreshCw,
  Server,
  Settings2,
  ShieldCheck,
  Zap,
} from "lucide-react";
import {
  appInfo,
  driftReport,
  gatewayStatus,
  listConsents,
  listSites,
  listStoredKeys,
  recentEvents,
  recentGatewayUsage,
  recentUsageSnapshots,
  refreshAll,
  runtimeMode,
  type EventRow,
  type SiteRow,
} from "../lib/api";
import { useTranslation } from "../i18n";
import { formatTokens } from "../lib/usageAgg";
import RebrandNotice from "../components/RebrandNotice";
import { BusyLabel, InlineNotice, MetricCard, SectionHeader, StatusDot } from "../components/Ui";

type Destination = "traffic" | "health" | "assets" | "delivery" | "settings";

/** 指挥舱只组织既有只读数据；跳转由 App 注入，独立渲染时操作安全地退化为无动作。 */
export default function Cockpit({ onNavigate }: { onNavigate?: (page: Destination) => void }) {
  const { t } = useTranslation();
  const navigate = onNavigate ?? (() => {});
  const info = useQuery({ queryKey: ["app-info"], queryFn: appInfo });
  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });
  const keys = useQuery({ queryKey: ["stored-keys"], queryFn: listStoredKeys });
  const consents = useQuery({ queryKey: ["consents"], queryFn: listConsents });
  const events = useQuery({ queryKey: ["events"], queryFn: () => recentEvents(20) });
  const gatewayUsage = useQuery({ queryKey: ["gateway-usage"], queryFn: () => recentGatewayUsage(24) });
  const usageSnapshots = useQuery({ queryKey: ["usage-snapshots"], queryFn: () => recentUsageSnapshots(168) });
  const drift = useQuery({ queryKey: ["drift"], queryFn: driftReport });
  const gateway = useQuery({ queryKey: ["gateway"], queryFn: gatewayStatus });

  const refresh = useMutation({
    mutationFn: refreshAll,
    onSuccess: async () => {
      await Promise.all([
        events.refetch(),
        sites.refetch(),
        keys.refetch(),
        gatewayUsage.refetch(),
        usageSnapshots.refetch(),
      ]);
    },
  });

  const drifted = (drift.data ?? []).filter(
    (r) => r.state === "modified" || r.state === "missing" || r.state === "unreadable",
  );
  const hasUnreadable = drifted.some((r) => r.state === "unreadable");
  const needsLogin = (sites.data ?? []).filter((s) => s.health === "needs_login");
  const warnings = (events.data ?? []).filter((e) => e.level === "warn" || e.level === "error");
  const issueCount = warnings.length + needsLogin.length + drifted.length;
  const gatewayPhase = gateway.data?.phase;
  const gatewayTone = gatewayPhase === "running" ? "ok" : gatewayPhase === "crashed" ? "danger" : "muted";
  const healthySites = (sites.data ?? []).filter((site) => site.health === "ok").length;

  const usageBySite = new Map<number, { prompt: number; completion: number; total: number }>();
  for (const row of gatewayUsage.data ?? []) {
    const current = usageBySite.get(row.siteId) ?? { prompt: 0, completion: 0, total: 0 };
    current.prompt += row.promptTokens;
    current.completion += row.completionTokens;
    current.total += row.totalTokens;
    usageBySite.set(row.siteId, current);
  }
  const totalTokens = [...usageBySite.values()].reduce((sum, row) => sum + row.total, 0);
  const siteName = (id: number) =>
    sites.data?.find((site) => site.id === id)?.displayName ?? t("overview.usage.siteFallback", { id });

  return (
    <section className="page cockpit-page">
      <div className="cockpit-hero">
        <div className="cockpit-hero-copy">
          <div className="eyebrow"><ShieldCheck size={14} aria-hidden="true" />{t("cockpit.heroEyebrow")}</div>
          <h2>{t("cockpit.heroTitle")}</h2>
          <p>{t("cockpit.heroBody")}</p>
          <div className="cockpit-hero-meta">
            <span><StatusDot tone={info.data?.vaultBackend === "memory" ? "danger" : "ok"} />{t("cockpit.localData")}</span>
            <span className="hero-meta-divider" aria-hidden="true" />
            <span>{runtimeMode === "tauri" ? t("overview.runState.modeTauri") : t("overview.runState.modeBrowser")}</span>
          </div>
        </div>
        <div className="gateway-overview">
          <div className="gateway-overview-heading">
            <span className="gateway-symbol"><Zap size={19} aria-hidden="true" /></span>
            <span>{t("gateway.title")}</span>
            <StatusDot tone={gatewayTone} />
          </div>
          <strong>{gatewayPhase ? t(`shell.gatewayPhase.${gatewayPhase}`) : gateway.isError ? t("gateway.statusUnknown") : t("common.loading")}</strong>
          <span className="gateway-overview-url">{gateway.data?.url ?? t("cockpit.gatewayIdle")}</span>
          <button type="button" className="text-button" onClick={() => navigate("settings")}>
            {t("cockpit.manageGateway")}<ArrowUpRight size={14} aria-hidden="true" />
          </button>
        </div>
        <button type="button" className="btn btn-primary cockpit-refresh" disabled={refresh.isPending} onClick={() => refresh.mutate()}>
          <BusyLabel busy={refresh.isPending}>{!refresh.isPending ? <RefreshCw size={15} aria-hidden="true" /> : null}{t(refresh.isPending ? "overview.btn.refreshing" : "overview.btn.refreshNow")}</BusyLabel>
        </button>
      </div>

      {refresh.data ? (
        <InlineNotice tone="success">
          <CheckCircle2 size={16} aria-hidden="true" />
          <span>{t("overview.refreshResult.base", { ok: refresh.data.sitesOk, failed: refresh.data.sitesFailed, keys: refresh.data.keysTotal })}{refresh.data.balanceAlerts.length ? t("overview.refreshResult.balanceAlerts", { count: refresh.data.balanceAlerts.length }) : ""}{refresh.data.needsLogin.length ? t("overview.refreshResult.needsLogin", { count: refresh.data.needsLogin.length }) : ""}</span>
        </InlineNotice>
      ) : null}
      {refresh.isError ? <InlineNotice tone="danger"><AlertTriangle size={16} aria-hidden="true" />{t("overview.error.refreshFailed", { error: refresh.error.message })}</InlineNotice> : null}
      {info.data?.vaultBackend === "memory" ? <InlineNotice tone="danger"><AlertTriangle size={16} aria-hidden="true" /><span>{t("overview.error.memoryVaultPre")}{t("overview.error.memoryVaultPost")}</span></InlineNotice> : null}
      {runtimeMode === "browser" ? <InlineNotice tone="info"><ShieldCheck size={16} aria-hidden="true" /><span>{t("overview.warn.browserPreviewPre")}<span className="mono">pnpm tauri dev</span>{t("overview.warn.browserPreviewPost")}</span></InlineNotice> : null}

      <div className="overview-metrics" aria-label={t("cockpit.summary")}>
        <MetricCard label={t("overview.stat.sites")} value={sites.data?.length ?? "—"} detail={t("cockpit.healthySites", { count: healthySites })} icon={<Server size={18} aria-hidden="true" />} tone="accent" onClick={() => navigate("assets")} />
        <MetricCard label={t("overview.stat.keys")} value={keys.data ? keys.data.filter((key) => key.status !== "revoked").length : "—"} detail={t("cockpit.keyStorage")} icon={<KeyRound size={18} aria-hidden="true" />} onClick={() => navigate("assets")} />
        <MetricCard label={t("overview.stat.consents")} value={consents.data ? consents.data.filter((c) => !c.revokedAt).length : "—"} detail={t("cockpit.agentAccess")} icon={<Plug size={18} aria-hidden="true" />} onClick={() => navigate("delivery")} />
        <MetricCard label={t("overview.stat.alerts")} value={events.isLoading ? "—" : warnings.length} detail={t("cockpit.recentEvents")} icon={<CircleAlert size={18} aria-hidden="true" />} tone={warnings.length ? "warn" : "ok"} onClick={() => navigate("health")} />
        <MetricCard label={t("overview.stat.drift")} value={drift.isLoading ? "—" : drifted.length} detail={t("cockpit.externalChanges")} icon={<FileWarning size={18} aria-hidden="true" />} tone={drifted.length ? "warn" : "ok"} onClick={() => navigate("delivery")} />
      </div>

      {sites.data?.length === 0 ? (
        <div className="onboarding-panel">
          <div><span className="eyebrow">{t("cockpit.getStarted")}</span><h2>{t("cockpit.onboardingTitle")}</h2><p>{t("cockpit.onboardingBody")}</p></div>
          <div className="onboarding-steps">
            {(["assets", "delivery", "settings"] as const).map((destination, index) => (
              <button type="button" className="onboarding-step" key={destination} onClick={() => navigate(destination)}>
                <span className="step-number">0{index + 1}</span><span><strong>{t(`cockpit.steps.${destination}`)}</strong><small>{t(`cockpit.stepBodies.${destination}`)}</small></span><ArrowRight size={16} aria-hidden="true" />
              </button>
            ))}
          </div>
        </div>
      ) : null}

      <div className="cockpit-workspace">
        <section className="attention-panel" aria-labelledby="attention-title">
          <SectionHeader title={<span id="attention-title">{t("cockpit.attentionTitle")}</span>} description={t("cockpit.attentionBody")} action={<span className={`count-badge${issueCount ? " has-issues" : ""}`}>{sites.isLoading || drift.isLoading || events.isLoading ? "—" : issueCount}</span>} />
          {issueCount === 0 && sites.data && drift.data && events.data ? (
            <div className="healthy-empty"><span className="healthy-empty-icon"><CheckCircle2 size={23} aria-hidden="true" /></span><h3>{t("cockpit.allClear")}</h3><p>{t("cockpit.allClearBody")}</p></div>
          ) : (
            <div className="issue-list">
              {needsLogin.map((site: SiteRow) => <IssueRow key={`login-${site.id}`} tone="warn" icon={<KeyRound size={16} aria-hidden="true" />} title={site.displayName || site.baseUrl} detail={t("cockpit.loginNeeded")} badge="needs_login" action={() => navigate("assets")} actionLabel={t("cockpit.viewAssets")} />)}
              {drifted.map((row) => <IssueRow key={`drift-${row.journalId}`} tone="warn" icon={<FileWarning size={16} aria-hidden="true" />} title={row.targetPath} detail={row.agentId} badge={row.state} action={() => navigate("delivery")} actionLabel={t("cockpit.reviewDelivery")} />)}
              {warnings.slice(0, 5).map((row: EventRow) => <IssueRow key={`event-${row.id}`} tone={row.level === "error" ? "danger" : "warn"} icon={<CircleAlert size={16} aria-hidden="true" />} title={row.message} detail={row.source} badge={row.level} action={() => navigate("health")} actionLabel={t("cockpit.viewHealth")} />)}
            </div>
          )}
          {issueCount > 0 ? <button type="button" className="panel-footer-link" onClick={() => navigate("health")}>{t("cockpit.allHealth")}<ArrowRight size={15} aria-hidden="true" /></button> : null}
          {needsLogin.length ? <p className="panel-footnote">{t("overview.needsLogin.hint")}</p> : null}
          {drifted.length ? <details className="drift-help"><summary>{t("cockpit.driftHelp")}</summary><p>{t("overview.drift.hint1Pre")}<span className="mono">missing</span>{t("overview.drift.hint1Mid")}<span className="mono">modified</span>{t("overview.drift.hint1Post")}</p><p><strong>{t("overview.drift.hint2Pre")}</strong>{t("overview.drift.hint2Post")}</p>{hasUnreadable ? <p>{t("overview.drift.hint3Pre")}<span className="mono">unreadable</span>{t("overview.drift.hint3Mid1")}<strong>{t("overview.drift.hint3Mid2")}</strong>{t("overview.drift.hint3Post")}</p> : null}</details> : null}
        </section>

        <section className="activity-panel" aria-labelledby="activity-title">
          <SectionHeader title={<span id="activity-title">{t("cockpit.activityTitle")}</span>} description={t("cockpit.activityBody")} action={<button type="button" className="icon-button" title={t("cockpit.viewTraffic")} aria-label={t("cockpit.viewTraffic")} onClick={() => navigate("traffic")}><ArrowUpRight size={17} aria-hidden="true" /></button>} />
          <div className="usage-highlight"><div><span>{t("overview.usage.gateway24h")}</span><strong>{gatewayUsage.data ? (gatewayUsage.data.length ? formatTokens(totalTokens) : "0") : "—"}</strong></div><span className="usage-highlight-icon"><Activity size={22} aria-hidden="true" /></span></div>
          {usageBySite.size ? <div className="usage-site-list">{[...usageBySite.entries()].map(([siteId, usage]) => <div className="usage-site-row" key={siteId}><span className="usage-site-name"><StatusDot tone="accent" />{siteName(siteId)}</span><span className="usage-site-total">{usage.total.toLocaleString()}<small> tokens</small></span><span className="usage-site-detail">{t("overview.usage.tokens", { site: siteName(siteId), total: usage.total.toLocaleString(), prompt: usage.prompt.toLocaleString(), completion: usage.completion.toLocaleString() })}</span></div>)}</div> : <div className="activity-empty"><Activity size={22} aria-hidden="true" /><p>{t("cockpit.noActivity")}</p></div>}
          {usageSnapshots.data?.length ? <BalanceSnapshots snapshots={usageSnapshots.data} siteName={siteName} /> : null}
          <button type="button" className="panel-footer-link" onClick={() => navigate("traffic")}>{t("cockpit.viewTraffic")}<ArrowRight size={15} aria-hidden="true" /></button>
        </section>
      </div>

      <RebrandNotice rebrand={info.data?.rebrand} dataDir={info.data?.dataDir} />

      <div className="quick-actions" aria-label={t("cockpit.quickActions")}>
        <QuickAction icon={<Layers3 size={18} aria-hidden="true" />} title={t("cockpit.quickAssets")} body={t("cockpit.quickAssetsBody")} onClick={() => navigate("assets")} />
        <QuickAction icon={<Plug size={18} aria-hidden="true" />} title={t("cockpit.quickDelivery")} body={t("cockpit.quickDeliveryBody")} onClick={() => navigate("delivery")} />
        <QuickAction icon={<Settings2 size={18} aria-hidden="true" />} title={t("cockpit.quickSettings")} body={t("cockpit.quickSettingsBody")} onClick={() => navigate("settings")} />
      </div>

      <details className="system-details">
        <summary><span><Settings2 size={15} aria-hidden="true" />{t("cockpit.systemDetails")}</span><ChevronDown size={15} aria-hidden="true" /></summary>
        <dl className="system-details-grid">
          <div><dt>{t("overview.runState.mode")}</dt><dd>{runtimeMode === "tauri" ? t("overview.runState.modeTauri") : t("overview.runState.modeBrowser")}</dd></div>
          <div><dt>{t("overview.runState.version")}</dt><dd className="mono">{info.data ? `${t("nav.brand")} ${info.data.version}` : "—"}</dd></div>
          <div><dt>{t("overview.runState.vault")}</dt><dd className="mono">{info.data?.vaultBackend ?? "—"}</dd></div>
          <div><dt>{t("overview.runState.dataDir")}</dt><dd className="mono" title={info.data?.dataDir}>{info.data?.dataDir ?? "—"}</dd></div>
          <div><dt>{t("overview.runState.db")}</dt><dd className="mono" title={info.data?.dbPath}>{info.data?.dbPath ?? "—"}</dd></div>
        </dl>
      </details>
    </section>
  );
}

function IssueRow({ tone, icon, title, detail, badge, action, actionLabel }: { tone: "warn" | "danger"; icon: React.ReactNode; title: string; detail: string; badge: string; action: () => void; actionLabel: string }) {
  return <div className={`issue-row issue-${tone}`}><span className="issue-icon">{icon}</span><div className="issue-copy"><strong title={title}>{title}</strong><span><code>{badge}</code>{detail}</span></div><button type="button" className="icon-button" title={actionLabel} aria-label={actionLabel} onClick={action}><ArrowUpRight size={16} aria-hidden="true" /></button></div>;
}

function QuickAction({ icon, title, body, onClick }: { icon: React.ReactNode; title: string; body: string; onClick: () => void }) {
  return <button type="button" className="quick-action" onClick={onClick}><span className="quick-action-icon">{icon}</span><span><strong>{title}</strong><small>{body}</small></span><ArrowUpRight size={15} aria-hidden="true" /></button>;
}

function BalanceSnapshots({ snapshots, siteName }: { snapshots: Array<{ siteId: number; ts: number; used: number; remaining: number; currency: string }>; siteName: (id: number) => string }) {
  const { t } = useTranslation();
  const bySite = new Map<number, typeof snapshots>();
  for (const snapshot of snapshots) {
    if (!bySite.has(snapshot.siteId)) bySite.set(snapshot.siteId, []);
    bySite.get(snapshot.siteId)!.push(snapshot);
  }
  return <div className="balance-snapshots"><h3>{t("overview.usage.snapshot7d")}</h3>{[...bySite.entries()].map(([siteId, rows]) => { const latest = rows[0]; const previous = rows[1]; const delta = previous ? latest.used - previous.used : null; return <p key={siteId}>{t("overview.usage.balance", { site: siteName(siteId), used: latest.used.toFixed(2), currency: latest.currency, remaining: latest.remaining.toFixed(2), delta: delta !== null ? t("overview.usage.delta", { delta: `${delta > 0 ? "+" : ""}${delta.toFixed(2)}` }) : "" })}</p>; })}</div>;
}
