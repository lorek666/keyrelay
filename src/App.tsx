import { useQuery } from "@tanstack/react-query";
import { KeyRound } from "lucide-react";
import Overview from "./pages/Overview";
import { appInfo } from "./lib/api";

export default function App() {
  const { data: info } = useQuery({ queryKey: ["app-info"], queryFn: appInfo });

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <KeyRound size={18} aria-hidden />
          <span>KeyRelay</span>
        </div>
        <nav>
          <a className="nav-item active" href="#overview">
            总览
          </a>
          <span className="nav-item disabled">密钥（M1）</span>
          <span className="nav-item disabled">Agent（M1）</span>
          <span className="nav-item disabled">变更历史（M2）</span>
          <span className="nav-item disabled">设置（M1）</span>
        </nav>
      </aside>

      <main className="content">
        <header className="topbar">
          <h1>总览</h1>
          <span className="muted mono">
            {info ? `${info.name} ${info.version}` : ""}
          </span>
        </header>
        {info?.dbError ? (
          <p className="error" role="alert">
            本地数据库降级：{info.dbError}（当前数据仅存内存，重启即丢失）
          </p>
        ) : null}
        <Overview />
      </main>
    </div>
  );
}
