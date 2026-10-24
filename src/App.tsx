import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  Wallet,
  HeartPulse,
  History as HistoryIcon,
  KeyRound,
  LayoutDashboard,
  Plug,
  Server,
  Settings as SettingsIcon,
} from "lucide-react";
import Cockpit from "./pages/Cockpit";
import Traffic from "./pages/Traffic";
import Cost from "./pages/Cost";
import Health from "./pages/Health";
import Sites from "./pages/Sites";
import Keys from "./pages/Keys";
import Agents from "./pages/Agents";
import History from "./pages/History";
import SettingsPage from "./pages/Settings";
import { appInfo, getSettings, reportUiReady, runtimeMode } from "./lib/api";
import { useApplyTheme } from "./lib/theme";
import { I18nProvider, normalizeLang, useTranslation, type Lang } from "./i18n";

// 侧栏分组（M11-S1 §2）：日常 / 资产 / 投递 / 系统。
// `group` 只影响侧栏的归类与标题，不改页面组件、不改切换逻辑（本地 state 切换六个原页面）。
// M14-S2：分组标签改成 i18n key，渲染时 `t(group)`。
const NAV_GROUPS = [
  "nav.group.daily",
  "nav.group.asset",
  "nav.group.delivery",
  "nav.group.system",
] as const;

const PAGES = [
  { id: "cockpit", labelKey: "nav.cockpit", icon: LayoutDashboard, group: "nav.group.daily", render: () => <Cockpit /> },
  { id: "traffic", labelKey: "nav.traffic", icon: Activity, group: "nav.group.daily", render: () => <Traffic /> },
  { id: "cost", labelKey: "nav.cost", icon: Wallet, group: "nav.group.daily", render: () => <Cost /> },
  { id: "health", labelKey: "nav.health", icon: HeartPulse, group: "nav.group.daily", render: () => <Health /> },
  { id: "sites", labelKey: "nav.sites", icon: Server, group: "nav.group.asset", render: () => <Sites /> },
  { id: "keys", labelKey: "nav.keys", icon: KeyRound, group: "nav.group.asset", render: () => <Keys /> },
  { id: "agents", labelKey: "nav.agents", icon: Plug, group: "nav.group.delivery", render: () => <Agents /> },
  { id: "history", labelKey: "nav.history", icon: HistoryIcon, group: "nav.group.daily", render: () => <History /> },
  { id: "settings", labelKey: "nav.settings", icon: SettingsIcon, group: "nav.group.system", render: () => <SettingsPage /> },
] as const;

type PageId = (typeof PAGES)[number]["id"];

/**
 * App：挂 `I18nProvider`。语言来自 `settings.language`（与主题同一 query），未知值回落 zh-CN。
 * `initialDict` 由 `main.tsx` 预加载 zh-CN 传入，保证默认语言首屏不空（M14-S2 §9.2）。
 */
/** M16-S9 接线补丁：首屏就绪信号的一次性守卫（模块级，跨重挂载只报一次）。 */
let uiReadyReported = false;

export default function App({ initialDict }: { initialDict?: Record<string, unknown> | null }) {
  // 与设置页共用 `["settings"]`：设置页保存后会失效这个键，主题随之立即生效（M9-S4 / F）
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
  const current = PAGES.find((p) => p.id === page) ?? PAGES[0];

  // M16-S9 接线补丁：首屏渲染完成后**一次性**回报「界面就绪」（M16-S7 的可观测判据）。
  // 它是观测信号，**绝不能**影响界面 ⇒ 一次性守卫 + 吞掉失败。
  useEffect(() => {
    if (uiReadyReported) return;
    uiReadyReported = true;
    void reportUiReady().catch(() => {});
  }, []);

  return (
    <div className="app harmony">
      <aside className="sidebar">
        <div className="brand">
          <KeyRound size={18} aria-hidden />
          <span>{t("nav.brand")}</span>
        </div>
        <nav>
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
                    onClick={() => setPage(item.id)}
                  >
                    <Icon size={15} aria-hidden />
                    <span>{t(item.labelKey)}</span>
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
        {runtimeMode === "browser" ? (
          <p className="sidebar-note">{t("app.browserPreviewNote")}</p>
        ) : null}
      </aside>

      <main className="content">
        <header className="topbar">
          <h1>{t(current.labelKey)}</h1>
          <span className="muted mono">
            {info ? `${info.name} ${info.version}` : ""}
          </span>
        </header>

        {info?.dbError ? (
          <p className="error" role="alert">
            <AlertTriangle size={14} aria-hidden /> {t("app.dbError", { error: info.dbError })}
          </p>
        ) : null}

        {/* M33-S1：key={page} ⇒ 切页时容器重挂载，一次性淡入/上移动效只播一次 */}
        <div className="page-stage" key={page}>
          {current.render()}
        </div>
      </main>
    </div>
  );
}
