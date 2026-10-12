import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Play, Square } from "lucide-react";
import {
  gatewayStart,
  gatewayStatus,
  gatewayStop,
  listSites,
  listStoredKeys,
} from "../lib/api";

type Props = {
  enabled: boolean;
  port: number;
  onToggle: (enabled: boolean) => void;
  onPortChange: (port: number) => void;
  /** 设置还没保存时提示用户先保存（端口要保存后才生效） */
  settingsDirty: boolean;
};

/**
 * 本地网关卡片。
 *
 * 网关只绑 `127.0.0.1`，并且**必须**带本地令牌——令牌只在启动后显示一次，
 * 用户拿它去配置 agent。站点密钥永远不会离开本机。
 */
export default function GatewayCard({
  enabled,
  port,
  onToggle,
  onPortChange,
  settingsDirty,
}: Props) {
  const qc = useQueryClient();
  const status = useQuery({ queryKey: ["gateway"], queryFn: gatewayStatus });
  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });
  const keys = useQuery({ queryKey: ["stored-keys"], queryFn: listStoredKeys });

  const [siteId, setSiteId] = useState<number | null>(null);
  const [keyId, setKeyId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const activeSite = siteId ?? sites.data?.[0]?.id ?? null;
  const siteKeys = (keys.data ?? []).filter((k) => k.siteId === activeSite);
  const activeKey = keyId ?? siteKeys[0]?.id ?? null;

  const start = useMutation({
    mutationFn: () => gatewayStart(activeSite!, activeKey!),
    onSuccess: async () => {
      setError(null);
      await qc.invalidateQueries({ queryKey: ["gateway"] });
    },
    onError: (err: Error) => setError(err.message),
  });

  const stop = useMutation({
    mutationFn: gatewayStop,
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["gateway"] });
    },
    onError: (err: Error) => setError(err.message),
  });

  const running = status.data?.running ?? false;

  return (
    <div className="card">
      <h3>本地网关</h3>
      <p className="muted">
        让任何支持 OpenAI 兼容接口的 agent 把 base_url 指向
        <span className="mono"> http://127.0.0.1:{port}/v1 </span>
        即可——密钥不必写进它们的配置里。只监听回环地址，并且**必须**带下面的本地令牌。
      </p>

      <label className="checkline">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => onToggle(e.target.checked)}
        />
        <span>
          允许启动本地网关（默认关闭；这个开关只控制「允不允许」，
          真正启动要点下面的按钮）
        </span>
      </label>

      <label className="field">
        <span>端口（1024–65535）</span>
        <input
          className="input"
          type="number"
          min={1024}
          max={65535}
          value={port}
          onChange={(e) => onPortChange(Number(e.target.value))}
        />
      </label>
      {settingsDirty ? (
        <p className="muted">端口改动需要先保存设置，并在下次启动网关时生效。</p>
      ) : null}

      {running ? (
        <>
          <dl className="kv">
            <dt>状态</dt>
            <dd className="ok">运行中</dd>
            <dt>地址</dt>
            <dd className="mono">{status.data?.url}</dd>
            <dt>上游</dt>
            <dd className="mono">{status.data?.site}</dd>
            <dt>本地令牌</dt>
            <dd className="mono ellipsis" title={status.data?.token ?? ""}>
              {status.data?.token}
            </dd>
          </dl>
          <p className="muted">
            把地址与令牌填进 agent 的配置即可。令牌每次启动都会重新生成，
            不会写进任何文件或日志。
          </p>
          <button
            type="button"
            className="btn btn-danger"
            disabled={stop.isPending}
            onClick={() => stop.mutate()}
          >
            <Square size={14} aria-hidden /> 停止网关
          </button>
        </>
      ) : (
        <>
          <div className="row">
            <label className="field-inline">
              <span>站点</span>
              <select
                className="input"
                value={activeSite ?? ""}
                onChange={(e) => {
                  setSiteId(Number(e.target.value));
                  setKeyId(null);
                }}
              >
                {(sites.data ?? []).map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.displayName}
                  </option>
                ))}
              </select>
            </label>
            <label className="field-inline">
              <span>密钥</span>
              <select
                className="input"
                value={activeKey ?? ""}
                onChange={(e) => setKeyId(Number(e.target.value))}
              >
                <option value="">（选择一把）</option>
                {siteKeys.map((k) => (
                  <option key={k.id} value={k.id}>
                    {k.name}（#{k.id}）
                  </option>
                ))}
              </select>
            </label>
          </div>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!enabled || activeSite === null || activeKey === null || start.isPending}
            onClick={() => start.mutate()}
          >
            <Play size={14} aria-hidden /> {start.isPending ? "启动中…" : "启动网关"}
          </button>
          {!enabled ? (
            <p className="muted">先勾选上面的开关。</p>
          ) : siteKeys.length === 0 ? (
            <p className="muted">该站点下还没有本地密钥，先去「密钥」页新建一把。</p>
          ) : null}
        </>
      )}

      {error ? <p className="error" role="alert">{error}</p> : null}
    </div>
  );
}
