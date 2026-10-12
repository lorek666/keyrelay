import { useQuery } from "@tanstack/react-query";
import { RefreshCw } from "lucide-react";
import { recentEvents } from "../lib/api";

const LEVEL_TONE: Record<string, string> = {
  debug: "muted",
  info: "ok",
  warn: "warn",
  error: "danger",
};

export default function History() {
  const events = useQuery({
    queryKey: ["events"],
    queryFn: () => recentEvents(200),
  });

  return (
    <section>
      <h2>变更历史</h2>
      <p className="muted">
        事件流。所有文本在写入数据库前都经过脱敏——这里不会出现密钥明文。
      </p>

      <div className="card">
        <div className="row row-between">
          <h3>最近事件（{events.data?.length ?? 0}）</h3>
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => events.refetch()}
            disabled={events.isFetching}
          >
            <RefreshCw size={14} aria-hidden /> 刷新
          </button>
        </div>

        {events.isLoading ? <p className="muted">加载中…</p> : null}
        {events.isError ? (
          <p className="error" role="alert">
            {(events.error as Error).message}
          </p>
        ) : null}
        {events.data?.length === 0 ? (
          <p className="muted">还没有事件。做一次站点识别或投递就会出现在这里。</p>
        ) : null}

        {events.data?.length ? (
          <table className="table">
            <thead>
              <tr>
                <th>时间</th>
                <th>级别</th>
                <th>来源</th>
                <th>内容</th>
                <th>载荷</th>
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
        ) : null}
      </div>

      <p className="muted">
        回滚入口在「Agent 投递」页：投递完成后会显示该次变更的 journal 与备份路径。
      </p>
    </section>
  );
}

function formatTs(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}
