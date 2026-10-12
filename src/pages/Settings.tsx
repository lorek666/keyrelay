import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Save } from "lucide-react";
import { ShieldCheck } from "lucide-react";
import {
  auditRedaction,
  exportBundle,
  getSettings,
  pruneBackups,
  updateSettings,
  type Settings,
} from "../lib/api";
import GatewayCard from "../components/GatewayCard";

const PRESETS = [
  { label: "关闭", value: 0 },
  { label: "5 分钟", value: 300 },
  { label: "15 分钟", value: 900 },
  { label: "1 小时", value: 3600 },
];

function ExportCard() {
  const [password, setPassword] = useState("");
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = useMutation({
    mutationFn: () => exportBundle(password || undefined),
    onSuccess: (r) => {
      setError(null);
      setResult(
        `已导出到 ${r.path}（${r.encrypted ? "已加密" : "明文"}，${r.bytes} 字节）` +
          (r.registered
            ? ""
            : "。注意：这个文件没能登记进「已知导出物」表，脱敏审计不会扫描它——请自行确认它里面没有明文凭证。"),
      );
    },
    onError: (err: Error) => {
      setResult(null);
      setError(err.message);
    },
  });

  const prune = useMutation({
    mutationFn: () => pruneBackups(10),
    onSuccess: (r) => setResult(`已清理 ${r.removed} 个历史备份（保留最近 10 个）`),
    onError: (err: Error) => setError(err.message),
  });

  return (
    <div className="card">
      <h3>导出与备份</h3>
      <p className="muted">
        导出的是站点、密钥**元数据**、同意记录与设置。
        <strong>密钥本体不在导出物里</strong>——它只存在于系统钥匙串。
        因此加密保护的是元数据（站点地址、密钥名称），不是密钥。
      </p>
      <label className="field">
        <span>导出密码（留空 = 明文导出）</span>
        <input
          className="input"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="off"
        />
      </label>
      <div className="row">
        <button
          type="button"
          className="btn btn-primary"
          disabled={run.isPending}
          onClick={() => run.mutate()}
        >
          {run.isPending ? "导出中…" : "导出配置"}
        </button>
        <button
          type="button"
          className="btn"
          disabled={prune.isPending}
          onClick={() => prune.mutate()}
        >
          {prune.isPending ? "清理中…" : "清理历史备份（保留最近 10 个）"}
        </button>
      </div>
      {result ? <p className="ok" role="status">{result}</p> : null}
      {error ? <p className="error" role="alert">{error}</p> : null}
    </div>
  );
}

function AuditCard() {
  const report = useQuery({
    queryKey: ["audit"],
    queryFn: auditRedaction,
    enabled: false,
  });

  return (
    <div className="card">
      <h3>
        <ShieldCheck size={15} aria-hidden /> 脱敏审计
      </h3>
      <p className="muted">
        扫描本产品的全部落盘产物（数据库、WAL、备份目录、事件表），确认没有明文凭证。
        只扫自己的产物，不做全盘扫描。
      </p>
      <button
        type="button"
        className="btn"
        disabled={report.isFetching}
        onClick={() => report.refetch()}
      >
        {report.isFetching ? "扫描中…" : "开始扫描"}
      </button>
      {report.data ? (
        <>
          <p className={report.data.clean ? "ok" : "error"}>
            {report.data.summary}
          </p>
          {report.data.findings.length ? (
            <ul className="list">
              {report.data.findings.map((f, i) => (
                <li key={`${f.kind}-${i}`}>
                  <span className="badge badge-warn">{f.kind}</span>{" "}
                  <span className="mono ellipsis">{f.path ?? "事件表"}</span>{" "}
                  {f.detail}
                </li>
              ))}
            </ul>
          ) : null}
        </>
      ) : null}
      {report.isError ? (
        <p className="error">{(report.error as Error).message}</p>
      ) : null}
    </div>
  );
}

export default function SettingsPage() {
  const qc = useQueryClient();
  const current = useQuery({ queryKey: ["settings"], queryFn: getSettings });
  const [draft, setDraft] = useState<Settings | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (current.data && draft === null) setDraft(current.data);
  }, [current.data, draft]);

  const save = useMutation({
    mutationFn: (settings: Settings) => updateSettings(settings),
    onSuccess: async (saved) => {
      setError(null);
      setNotice("已保存。定时刷新间隔的变更在**下次启动**生效。");
      setDraft(saved);
      await qc.invalidateQueries({ queryKey: ["settings"] });
    },
    onError: (err: Error) => {
      setNotice(null);
      setError(err.message);
    },
  });

  const dirty =
    draft !== null &&
    current.data !== undefined &&
    JSON.stringify(draft) !== JSON.stringify(current.data);

  return (
    <section>
      <h2>设置</h2>
      <p className="muted">
        所有设置都存在本地数据库里，不上传任何地方。
      </p>

      {notice ? <p className="ok" role="status">{notice}</p> : null}
      {error ? (
        <p className="error" role="alert">
          <AlertTriangle size={14} aria-hidden /> {error}
        </p>
      ) : null}

      {draft === null ? (
        <p className="muted">加载中…</p>
      ) : (
        <>
          <div className="card">
            <h3>自动刷新</h3>
            <p className="muted">
              默认关闭：KeyRelay 不会替你做任何定时联网。
              开启后会在后台按间隔刷新已登录站点的余额与密钥列表，失败只记事件、不打断循环。
            </p>
            <div className="row">
              {PRESETS.map((preset) => (
                <button
                  key={preset.value}
                  type="button"
                  className={
                    draft.refreshIntervalSecs === preset.value
                      ? "btn btn-primary"
                      : "btn"
                  }
                  onClick={() =>
                    setDraft({ ...draft, refreshIntervalSecs: preset.value })
                  }
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </div>

          <div className="card">
            <h3>余额告警</h3>
            <label className="field">
              <span>余额低于该值时告警（USD，0 = 不告警）</span>
              <input
                className="input"
                type="number"
                min={0}
                step="0.5"
                value={draft.balanceAlertThreshold}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    balanceAlertThreshold: Number(e.target.value),
                  })
                }
              />
            </label>
          </div>

          <div className="card">
            <h3>启动检查</h3>
            <label className="checkline">
              <input
                type="checkbox"
                checked={draft.driftCheckOnStart}
                onChange={(e) =>
                  setDraft({ ...draft, driftCheckOnStart: e.target.checked })
                }
              />
              <span>
                启动时检查投递目标是否被外部改动（只读本地文件，不联网）
              </span>
            </label>
          </div>

          <div className="row">
            <button
              type="button"
              className="btn btn-primary"
              disabled={!dirty || save.isPending}
              onClick={() => save.mutate(draft)}
            >
              <Save size={14} aria-hidden /> 保存
            </button>
            {dirty ? <span className="muted">有未保存的修改</span> : null}
          </div>

          <GatewayCard
            enabled={draft.gatewayEnabled}
            port={draft.gatewayPort}
            onToggle={(enabled) => setDraft({ ...draft, gatewayEnabled: enabled })}
            onPortChange={(port) => setDraft({ ...draft, gatewayPort: port })}
            settingsDirty={dirty}
          />

          <ExportCard />

          <AuditCard />
        </>
      )}
    </section>
  );
}
