import { useQuery } from "@tanstack/react-query";
import { AlertCircle, Globe, KeyRound, RefreshCw } from "lucide-react";
import { listSites, runtimeMode, type SiteRow } from "../lib/api";

function SiteCard({ site }: { site: SiteRow }) {
  return (
    <article className="card">
      <header className="card-head">
        <Globe size={16} aria-hidden />
        <span className="card-title">{site.displayName || site.baseUrl}</span>
        <span className={`badge badge-${site.kind}`}>{site.kind}</span>
      </header>
      <p className="muted mono">{site.baseUrl}</p>
      <p className="muted">
        登录态：<span className={`health health-${site.health}`}>{site.health}</span>
      </p>
      <button className="ghost" disabled title="M1 接入后可用">
        <KeyRound size={14} aria-hidden /> 获取密钥（M1）
      </button>
    </article>
  );
}

export default function Overview() {
  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["sites"],
    queryFn: listSites,
  });

  return (
    <section>
      <div className="row-between">
        <h2>站点</h2>
        <button className="ghost" onClick={() => void refetch()} disabled={isFetching}>
          <RefreshCw size={14} aria-hidden /> 刷新
        </button>
      </div>

      {isLoading && <p className="muted">正在读取本地站点…</p>}

      {isError && (
        <p className="error">
          <AlertCircle size={14} aria-hidden /> 读取失败：{String(error)}
        </p>
      )}

      {data && data.length === 0 && (
        <p className="muted">
          还没有站点。M1 起可在「新增站点」里填入中转站地址并登录（当前为骨架版本）。
        </p>
      )}

      <div className="grid">
        {data?.map((site) => (
          <SiteCard key={site.id} site={site} />
        ))}
      </div>

      <p className="muted footnote">
        运行模式：<span className="mono">{runtimeMode}</span>
        {runtimeMode === "browser" && "（浏览器预览使用示例数据）"}
      </p>
    </section>
  );
}
