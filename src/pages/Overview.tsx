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
  refreshAll,
  runtimeMode,
} from "../lib/api";

export default function Overview() {
  const info = useQuery({ queryKey: ["app-info"], queryFn: appInfo });
  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });
  const keys = useQuery({ queryKey: ["stored-keys"], queryFn: listStoredKeys });
  const consents = useQuery({ queryKey: ["consents"], queryFn: listConsents });
  const events = useQuery({ queryKey: ["events"], queryFn: () => recentEvents(20) });
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
        <Stat
          icon={<ShieldCheck size={16} aria-hidden />}
          label="配置漂移"
          value={drifted.length}
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
          <dt>系统钥匙串</dt>
          <dd className="mono">{info.data?.vaultBackend ?? "…"}</dd>
        </dl>

        <button
          type="button"
          className="btn"
          disabled={refresh.isPending}
          onClick={() => refresh.mutate()}
        >
          {refresh.isPending ? "刷新中…" : "立即刷新全部站点"}
        </button>
        {refresh.data ? (
          <p className="muted">
            成功 {refresh.data.sitesOk} / 失败 {refresh.data.sitesFailed} /
            密钥 {refresh.data.keysTotal}
            {refresh.data.balanceAlerts.length
              ? ` / 余额告警 ${refresh.data.balanceAlerts.length} 个站点`
              : ""}
            {refresh.data.needsLogin.length
              ? ` / 需要重新登录 ${refresh.data.needsLogin.length} 个站点`
              : ""}
          </p>
        ) : null}
        {/* 刷新失败必须说出来（M8-S5B §6.8）：`refresh_all` 出错时整个 mutation 走
            onError，而这里原本只渲染 `refresh.data`（成功分支）⇒ 界面上「成功」与
            「失败」看不出差别，用户会以为刷新成功了。 */}
        {refresh.isError ? (
          <p className="error" role="alert">
            <AlertTriangle size={14} aria-hidden /> 刷新失败：{refresh.error.message}
          </p>
        ) : null}

        {info.data?.vaultBackend === "memory" ? (
          <p className="error" role="alert">
            <AlertTriangle size={14} aria-hidden /> 当前用的是内存钥匙串：
            密钥不会进系统钥匙串，进程退出即丢失。真实运行里出现这个后端即为缺陷。
          </p>
        ) : null}

        {runtimeMode === "browser" ? (
          <p className="warn" role="status">
            当前是浏览器预览模式：所有数据都是示例，写操作不会生效。
            要连真实后端请用 <span className="mono">pnpm tauri dev</span>。
          </p>
        ) : null}
      </div>

      {needsLogin.length ? (
        <div className="card">
          <h3>
            <AlertTriangle size={15} aria-hidden /> 需要重新登录（{needsLogin.length}）
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
          <p className="muted">
            这些站点的会话已经失效，刷新时会被跳过——既不算成功也不算失败，
            所以不会出现在上面的「失败」计数里。请到「站点」页重新登录。
          </p>
        </div>
      ) : null}

      {drifted.length ? (
        <div className="card">
          <h3>
            <AlertTriangle size={15} aria-hidden /> 投递目标需要处理（{drifted.length}）
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
            KeyRelay 不会自动覆盖外部改动。要恢复请到「Agent 投递」页重新投递。
            被删掉的目标（<span className="mono">missing</span>）也可以到「变更历史」页回滚那次投递，
            恢复成投递之前的内容；被外部改过的（<span className="mono">modified</span>）回滚会被拒绝——
            回滚不会覆盖别人的改动。
          </p>
          {hasUnreadable ? (
            <p className="muted">
              标记为 <span className="mono">unreadable</span> 的目标
              <strong>文件还在</strong>，只是读不到（权限或路径类型问题）。
              这不是「被删了」——请先检查文件权限，不要直接重新投递。
            </p>
          ) : null}
        </div>
      ) : null}

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
