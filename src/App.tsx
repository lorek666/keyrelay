import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  ChevronRight,
  HeartPulse,
  Layers,
  LayoutDashboard,
  Plug,
  Settings as SettingsIcon,
  ShieldCheck,
  Wallet,
} from "lucide-react";
import Cockpit from "./pages/Cockpit";
import Traffic from "./pages/Traffic";
import Cost from "./pages/Cost";
import Health from "./pages/Health";
import Assets from "./pages/Assets";
import Delivery from "./pages/Delivery";
import SettingsPage from "./pages/Settings";
import {
  appInfo,
  gatewayStatus,
  getSettings,
  reportUiReady,
  runtimeMode,
} from "./lib/api";
import { useApplyTheme } from "./lib/theme";
import { I18nProvider, normalizeLang, useTranslation, type Lang } from "./i18n";
import BrandMark from "./components/BrandMark";
import { StatusDot } from "./components/Ui";

const NAV_GROUPS = ["nav.group.daily", "nav.group.asset", "nav.group.delivery", "nav.group.system"] as const;

const PAGES = [
  { id: "cockpit", labelKey: "nav.cockpit", descriptionKey: "shell.pages.cockpit", icon: LayoutDashboard, group: "nav.group.daily", render: () => <Cockpit /> },
  { id: "traffic", labelKey: "nav.traffic", descriptionKey: "shell.pages.traffic", icon: Activity, group: "nav.group.daily", render: () => <Traffic /> },
  { id: "cost", labelKey: "nav.cost", descriptionKey: "shell.pages.cost", icon: Wallet, group: "nav.group.daily", render: () => <Cost /> },
  { id: "health", labelKey: "nav.health", descriptionKey: "shell.pages.health", icon: HeartPulse, group: "nav.group.daily", render: () => <Health /> },
  { id: "assets", labelKey: "nav.assets", descriptionKey: "shell.pages.assets", icon: Layers, group: "nav.group.asset", render: () => <Assets /> },
  { id: "delivery", labelKey: "nav.delivery", descriptionKey: "shell.pages.delivery", icon: Plug, group: "nav.group.delivery", render: () => <Delivery /> },
  { id: "settings", labelKey: "nav.settings", descriptionKey: "shell.pages.settings", icon: SettingsIcon, group: "nav.group.system", render: () => <SettingsPage /> },
] as const;

type PageId = (typeof PAGES)[number]["id"];

let uiReadyReported = false;

export default function App({ initialDict }: { initialDict?: Record<string, unknown> | null }) {
  const { data: settings } = useQuery({ queryKey: ["settings"], queryFn: getSettings });
  useApplyTheme(settings?.theme);
  const lang: Lang = normalizeLang(settings?.language);
  return (
    <I18nProvider lang={lang} initialDict={initialDict}>
      <AppInner />
    </I18nProvider>
  );
}

function AppInner() {
  const { t } = useTranslation();
  const [page, setPage] = useState<PageId>("cockpit");
  const { data: info } = useQuery({ queryKey: ["app-info"], queryFn: appInfo });
  const gatewayQuery = useQuery({ queryKey: ["gateway"], queryFn: gatewayStatus });
  const gateway = gatewayQuery.data;
  const current = PAGES.find((p) => p.id === page) ?? PAGES[0];
  const gatewayTone = gatewayQuery.isError ? "warn" : gateway?.phase === "running" ? "ok" : gateway?.phase === "crashed" ? "danger" : "muted";

  useEffect(() => {
    if (uiReadyReported) return;
    uiReadyReported = true;
    void reportUiReady().catch(() => {});
  }, []);

  const openPage = (next: PageId) => {
    setPage(next);
    document.querySelector(".content")?.scrollTo({ top: 0, behavior: "auto" });
  };

  return (
    <div className="app harmony">
      <aside className="sidebar" aria-label={t("shell.navigation")}>
        <div className="brand">
          <BrandMark />
          <div className="brand-copy">
            <span className="brand-name">{t("nav.brand")}</span>
            <span className="brand-subtitle">{t("shell.tagline")}</span>
          </div>
        </div>
        <nav className="sidebar-nav">
          {NAV_GROUPS.map((group) => (
            <div className="nav-group" key={group}>
              <p className="nav-group-label">{t(group)}</p>
              {PAGES.filter((item) => item.group === group).map((item) => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    type="button"
                    className={item.id === page ? "nav-item active" : "nav-item"}
                    aria-current={item.id === page ? "page" : undefined}
                    aria-label={t(item.labelKey)}
                    title={t(item.labelKey)}
                    onClick={() => openPage(item.id)}
                  >
                    <Icon size={17} strokeWidth={1.8} aria-hidden="true" />
                    <span>{t(item.labelKey)}</span>
                    {item.id === page ? <ChevronRight className="nav-current-icon" size={14} aria-hidden="true" /> : null}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
        <div className="sidebar-footer">
          <button type="button" className="sidebar-gateway" onClick={() => openPage("settings")} aria-label={t("shell.gatewaySettings")}>
            <span className="sidebar-gateway-icon"><StatusDot tone={gatewayTone} /></span>
            <span className="sidebar-gateway-copy">
              <strong>{t("gateway.title")}</strong>
              <span>{gateway ? t(`shell.gatewayPhase.${gateway.phase}`) : gatewayQuery.isError ? t("gateway.statusUnknown") : t("common.loading")}</span>
            </span>
            <ArrowUpRight size={14} aria-hidden="true" />
          </button>
          <div className="sidebar-local"><ShieldCheck size={13} aria-hidden="true" /><span>{t("shell.localOnly")}</span></div>
          {runtimeMode === "browser" ? <p className="sidebar-note">{t("app.browserPreviewNote")}</p> : null}
        </div>
      </aside>

      <main className="content">
        <header className="topbar">
          <div className="topbar-heading">
            <div className="topbar-eyebrow"><span>{t("shell.workspace")}</span><span className="topbar-separator">/</span><span>{t(current.labelKey)}</span></div>
            <h1>{t(current.labelKey)}</h1>
            <p>{t(current.descriptionKey)}</p>
          </div>
          <div className="topbar-meta">
            {info ? <span className="version-badge">v{info.version}</span> : null}
            <span className="local-badge"><ShieldCheck size={14} aria-hidden="true" />{t("shell.localWorkspace")}</span>
          </div>
        </header>

        {info?.dbError ? (
          <p className="error" role="alert"><AlertTriangle size={14} aria-hidden="true" /> {t("app.dbError", { error: info.dbError })}</p>
        ) : null}

        <div className="page-stage" key={page}>
          {page === "cockpit" ? <Cockpit onNavigate={openPage} /> : current.render()}
        </div>
      </main>
    </div>
  );
}
