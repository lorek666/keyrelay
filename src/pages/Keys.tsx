import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plus, RefreshCw } from "lucide-react";
import { createKey, listKeys, listSites, type KeyRow } from "../lib/api";
import ConfirmDialog from "../components/ConfirmDialog";

export default function Keys() {
  const qc = useQueryClient();
  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });
  const [siteId, setSiteId] = useState<number | null>(null);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("codex/daily");
  const [group, setGroup] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const activeSite = siteId ?? sites.data?.[0]?.id ?? null;

  const keys = useQuery({
    queryKey: ["keys", activeSite],
    queryFn: () => listKeys(activeSite!),
    enabled: activeSite !== null,
    retry: false,
  });

  const create = useMutation({
    mutationFn: () =>
      createKey({
        siteId: activeSite!,
        name,
        group: group || undefined,
      }),
    onSuccess: async (key) => {
      setError(null);
      // 只显示掩码，明文从不出现在界面上
      setNotice(`已创建 ${key.name}（${key.masked}），密钥已存入系统钥匙串`);
      setCreating(false);
      await qc.invalidateQueries({ queryKey: ["keys", activeSite] });
    },
    onError: (err: Error) => {
      setError(err.message);
    },
  });

  return (
    <section>
      <h2>密钥</h2>

      {sites.data?.length === 0 ? (
        <p className="muted">先去「站点」页接入一个中转站。</p>
      ) : null}

      <div className="card">
        <div className="row row-between">
          <div className="row">
            <label className="field-inline">
              <span>站点</span>
              <select
                className="input"
                value={activeSite ?? ""}
                onChange={(e) => setSiteId(Number(e.target.value))}
              >
                {(sites.data ?? []).map((site) => (
                  <option key={site.id} value={site.id}>
                    {site.displayName}
                  </option>
                ))}
              </select>
            </label>
            <button
              type="button"
              className="btn btn-ghost"
              onClick={() => keys.refetch()}
              disabled={activeSite === null || keys.isFetching}
            >
              <RefreshCw size={14} aria-hidden /> 刷新
            </button>
          </div>
          <button
            type="button"
            className="btn btn-primary"
            disabled={activeSite === null}
            onClick={() => {
              setError(null);
              setNotice(null);
              setCreating(true);
            }}
          >
            <Plus size={14} aria-hidden /> 新建密钥
          </button>
        </div>

        {notice ? <p className="ok" role="status">{notice}</p> : null}
        {error ? <p className="error" role="alert">{error}</p> : null}

        {keys.isLoading ? <p className="muted">加载中…</p> : null}
        {keys.isError ? (
          <p className="muted">读取失败：{(keys.error as Error).message}</p>
        ) : null}
        {keys.data?.length === 0 ? (
          <p className="muted">该站点下还没有密钥。点「新建密钥」开始。</p>
        ) : null}

        {keys.data?.length ? (
          <table className="table">
            <thead>
              <tr>
                <th>名称</th>
                <th>分组</th>
                <th>远端 id</th>
                <th>状态</th>
                <th>创建时间</th>
              </tr>
            </thead>
            <tbody>
              {keys.data.map((key) => (
                <tr key={key.remoteId}>
                  <td>
                    <KeyRound size={13} aria-hidden /> {key.name}
                  </td>
                  <td className="mono">{key.group ?? "—"}</td>
                  <td className="mono">{key.remoteId}</td>
                  <td>
                    <span className={`badge badge-${statusTone(key.status)}`}>
                      {key.status}
                    </span>
                  </td>
                  <td className="mono">{formatTs(key.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}

        <p className="muted">
          密钥明文只存在于系统钥匙串里；本页只显示名称与远端 id。
        </p>
      </div>

      <ConfirmDialog
        open={creating}
        title="新建密钥"
        confirmLabel={create.isPending ? "创建中…" : "创建"}
        confirmDisabled={!name || create.isPending}
        onCancel={() => setCreating(false)}
        onConfirm={() => create.mutate()}
      >
        <p className="muted">
          新建成功后密钥会**直接写入系统钥匙串**，界面只显示末 4 位。请自行确认这把钥匙的用途。
        </p>
        <label className="field">
          <span>名称</span>
          <input
            className="input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            spellCheck={false}
          />
        </label>
        <label className="field">
          <span>分组（可选）</span>
          <input
            className="input"
            value={group}
            onChange={(e) => setGroup(e.target.value)}
            spellCheck={false}
          />
        </label>
      </ConfirmDialog>
    </section>
  );
}

function statusTone(status: string): string {
  if (status === "enabled") return "ok";
  if (status === "disabled") return "warn";
  if (status === "exhausted") return "danger";
  return "muted";
}

function formatTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}
