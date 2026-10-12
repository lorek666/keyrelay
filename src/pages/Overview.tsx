import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, KeyRound, Server, ShieldCheck } from "lucide-react";
import {
  appInfo,
  listConsents,
  listSites,
  listStoredKeys,
  recentEvents,
  runtimeMode,
} from "../lib/api";

export default function Overview() {
  const info = useQuery({ queryKey: ["app-info"], queryFn: appInfo });
  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });
  const keys = useQuery({ queryKey: ["stored-keys"], queryFn: listStoredKeys });
  const consents = useQuery({ queryKey: ["consents"], queryFn: listConsents });
  const events = useQuery({ queryKey: ["events"], queryFn: () => recentEvents(20) });

  const warnings = (events.data ?? []).filter(
    (e) => e.level === "warn" || e.level === "error",
  );

  return (
    <section>
      <div className="cards">
        <Stat
          icon={<Server size={16} aria-hidden />}
          label="站点"
          value={sites.data?.length ?? "—"}
        />
        <Stat
          icon={<KeyRound size={16} aria-hidden />}
          label="本地密钥"
          value={keys.data?.length ?? "—"}
        />
        <Stat
          icon={<ShieldCheck size={16} aria-hidden />}
          label="有效同意"
          value={consents.data?.filter((c) => !c.revokedAt).length ?? "—"}
        />
        <Stat
          icon={<AlertTriangle size={16} aria-hidden />}
          label="告警事件"
          value={warnings.length}
        />
      </div>

      <div className="card">
        <h3>运行状态</h3>
        <dl className="kv">
          <dt>运行模式</dt>
          <dd className="mono">
            {runtimeMode === "tauri" ? "Tauri（已连接后端）" : "浏览器预览（未连接后端）"}
          </dd>
          <dt>本地数据库</dt>
          <dd className="mono ellipsis" title={info.data?.dbPath}>
            {info.data?.dbPath ?? "…"}
          </dd>
          <dt>版本</dt>
          <dd className="mono">
            {info.data ? `${info.data.name} ${info.data.version}` : "…"}
          </dd>
        </dl>

        {runtimeMode === "browser" ? (
          <p className="warn" role="status">
            当前是浏览器预览模式：所有数据都是示例，写操作不会生效。
            要连真实后端请用 <span className="mono">pnpm tauri dev</span>。
          </p>
        ) : null}
      </div>

      {warnings.length ? (
        <div className="card">
          <h3>最近告警</h3>
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
    </section>
  );
}

function Stat({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: number | string;
}) {
  return (
    <div className="stat">
      <div className="stat-label">
        {icon}
        <span>{label}</span>
      </div>
      <div className="stat-value">{value}</div>
    </div>
  );
}
