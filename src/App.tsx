import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  History as HistoryIcon,
  KeyRound,
  LayoutDashboard,
  Plug,
  Server,
  Settings as SettingsIcon,
} from "lucide-react";
import Overview from "./pages/Overview";
import Sites from "./pages/Sites";
import Keys from "./pages/Keys";
import Agents from "./pages/Agents";
import History from "./pages/History";
import SettingsPage from "./pages/Settings";
import { appInfo, getSettings, runtimeMode } from "./lib/api";
import { useApplyTheme } from "./lib/theme";

// 侧栏分组（M11-S1 §2）：日常 / 资产 / 投递 / 系统。
// `group` 只影响侧栏的归类与标题，不改页面组件、不改切换逻辑（本地 state 切换六个原页面）。
const NAV_GROUPS = ["日常", "资产", "投递", "系统"] as const;

const PAGES = [
  { id: "overview", label: "总览", icon: LayoutDashboard, group: "日常", render: () => <Overview /> },
  { id: "sites", label: "站点", icon: Server, group: "资产", render: () => <Sites /> },
  { id: "keys", label: "密钥", icon: KeyRound, group: "资产", render: () => <Keys /> },
  { id: "agents", label: "Agent 投递", icon: Plug, group: "投递", render: () => <Agents /> },
  { id: "history", label: "变更历史", icon: HistoryIcon, group: "日常", render: () => <History /> },
  { id: "settings", label: "设置", icon: SettingsIcon, group: "系统", render: () => <SettingsPage /> },
] as const;

type PageId = (typeof PAGES)[number]["id"];

export default function App() {
  const [page, setPage] = useState<PageId>("overview");
  const { data: info } = useQuery({ queryKey: ["app-info"], queryFn: appInfo });
  // 与设置页共用 `["settings"]`：设置页保存后会失效这个键，主题随之立即生效（M9-S4 / F）
  const { data: settings } = useQuery({ queryKey: ["settings"], queryFn: getSettings });
  useApplyTheme(settings?.theme);
  const current = PAGES.find((p) => p.id === page) ?? PAGES[0];

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <KeyRound size={18} aria-hidden />
          <span>KeyRelay</span>
        </div>
        <nav>
          {NAV_GROUPS.map((group) => (
            <div className="nav-group" key={group}>
              <p className="nav-group-label">{group}</p>
              {PAGES.filter((item) => item.group === group).map((item) => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    type="button"
                    className={item.id === page ? "nav-item active" : "nav-item"}
                    onClick={() => setPage(item.id)}
                  >
                    <Icon size={15} aria-hidden />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
        {runtimeMode === "browser" ? (
          <p className="sidebar-note">浏览器预览模式（示例数据）</p>
        ) : null}
      </aside>

      <main className="content">
        <header className="topbar">
          <h1>{current.label}</h1>
          <span className="muted mono">
            {info ? `${info.name} ${info.version}` : ""}
          </span>
        </header>

        {info?.dbError ? (
          <p className="error" role="alert">
            <AlertTriangle size={14} aria-hidden /> 本地数据库降级：{info.dbError}
            （当前数据仅存内存，重启即丢失）
          </p>
        ) : null}

        {current.render()}
      </main>
    </div>
  );
}
