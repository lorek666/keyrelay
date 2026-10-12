import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, RotateCcw, Send, ShieldCheck, Undo2 } from "lucide-react";
import {
  applyDelivery,
  deliveryPlan,
  grantConsent,
  listConsents,
  listStoredKeys,
  listSites,
  revokeConsent,
  rollbackDelivery,
  type DeliveryOutcome,
  type DeliveryPlan,
} from "../lib/api";
import ConfirmDialog from "../components/ConfirmDialog";

/** 目前只有 codex 通道实现了；其余通道后端会返回 Unimplemented。 */
const CHANNELS = [
  { id: "codex-auth-json", label: "Codex CLI（~/.codex/auth.json）", agent: "codex" },
  { id: "claude-code-settings", label: "Claude Code（M2 支持）", agent: "claude-code" },
  { id: "shell-block", label: "Shell 标记块（M2 支持）", agent: "shell" },
];

export default function Agents() {
  const qc = useQueryClient();
  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });
  const [siteId, setSiteId] = useState<number | null>(null);
  const activeSite = siteId ?? sites.data?.[0]?.id ?? null;

  // 投递需要**本地 key id**，所以用 stored keys 而不是站点侧列表
  const keys = useQuery({ queryKey: ["stored-keys"], queryFn: listStoredKeys });

  const [keyId, setKeyId] = useState<number | null>(null);
  const activeKey = keyId ?? null;
  const [channel, setChannel] = useState(CHANNELS[0].id);

  const [agreeChecked, setAgreeChecked] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastOutcome, setLastOutcome] = useState<DeliveryOutcome | null>(null);

  const consents = useQuery({ queryKey: ["consents"], queryFn: listConsents });

  const plan = useQuery({
    queryKey: ["plan", activeKey, channel],
    queryFn: () => deliveryPlan({ keyId: activeKey!, channel }),
    enabled: activeKey !== null,
    retry: false,
  });

  // 切换 key/通道时，同意勾选必须重置（避免「上次勾过了」的错觉）
  useEffect(() => {
    setAgreeChecked(false);
    setNotice(null);
    setError(null);
  }, [activeKey, channel]);

  const noChange = plan.data?.preview.trim() === "(无变化)";

  const grantAndApply = useMutation({
    mutationFn: async () => {
      await grantConsent({ keyId: activeKey!, channel });
      return applyDelivery({ keyId: activeKey!, channel });
    },
    onSuccess: async (outcome) => {
      setError(null);
      setLastOutcome(outcome);
      setNotice(
        `已投递到 ${outcome.targetPath}（变更 ${outcome.journalId}）`,
      );
      setConfirming(false);
      await qc.invalidateQueries({ queryKey: ["plan", activeKey, channel] });
      await qc.invalidateQueries({ queryKey: ["consents"] });
      await qc.invalidateQueries({ queryKey: ["events"] });
    },
    onError: (err: Error) => {
      setError(err.message);
      setConfirming(false);
    },
  });

  const revoke = useMutation({
    mutationFn: () => revokeConsent({ keyId: activeKey!, channel }),
    onSuccess: async () => {
      setNotice("已撤销同意。已写入的文件不会被自动回滚——如需还原请用「变更历史」页。");
      setRevoking(false);
      await qc.invalidateQueries({ queryKey: ["plan", activeKey, channel] });
      await qc.invalidateQueries({ queryKey: ["consents"] });
    },
    onError: (err: Error) => {
      setError(err.message);
      setRevoking(false);
    },
  });

  const rollback = useMutation({
    mutationFn: () => rollbackDelivery(lastOutcome!.journalId),
    onSuccess: async () => {
      setNotice(`已回滚 ${lastOutcome?.journalId}`);
      setLastOutcome(null);
      await qc.invalidateQueries({ queryKey: ["events"] });
    },
    onError: (err: Error) => setError(err.message),
  });

  const consentLabel = useMemo(() => {
    const state = plan.data?.consent;
    if (state === "granted") return "已同意";
    if (state === "revoked") return "已撤销";
    return "未同意";
  }, [plan.data?.consent]);

  return (
    <section>
      <h2>Agent 投递</h2>
      <p className="muted">
        投递会把钥匙串里的密钥写进所选 agent 的配置文件。
        **任何写入都必须先勾选同意**；写入前会展示脱敏后的差异预览。
      </p>

      {notice ? <p className="ok" role="status">{notice}</p> : null}
      {error ? (
        <p className="error" role="alert">
          <AlertTriangle size={14} aria-hidden /> {error}
        </p>
      ) : null}

      <div className="card">
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
              {(keys.data ?? []).map((k) => (
                <option key={k.id} value={k.id}>
                  {k.name}（#{k.id}）
                </option>
              ))}
            </select>
          </label>
          <label className="field-inline">
            <span>通道</span>
            <select
              className="input"
              value={channel}
              onChange={(e) => setChannel(e.target.value)}
            >
              {CHANNELS.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.label}
                </option>
              ))}
            </select>
          </label>
        </div>
      </div>

      {activeKey === null ? (
        <p className="muted">先选一把密钥。</p>
      ) : plan.isError ? (
        <p className="error" role="alert">
          {(plan.error as Error).message}
        </p>
      ) : plan.isLoading ? (
        <p className="muted">生成预览…</p>
      ) : plan.data ? (
        <PlanView
          plan={plan.data}
          consentLabel={consentLabel}
          noChange={!!noChange}
          agreeChecked={agreeChecked}
          onAgreeChange={setAgreeChecked}
          busy={grantAndApply.isPending}
          onApply={() => setConfirming(true)}
          onRevoke={() => setRevoking(true)}
        />
      ) : null}

      {lastOutcome ? (
        <div className="card">
          <h3>上次投递</h3>
          <p className="mono">
            {lastOutcome.channel} → {lastOutcome.targetPath}
          </p>
          <p className="muted mono">
            journal={lastOutcome.journalId}
            {lastOutcome.backupPath ? `　备份=${lastOutcome.backupPath}` : ""}
          </p>
          <button
            type="button"
            className="btn btn-danger"
            disabled={rollback.isPending}
            onClick={() => rollback.mutate()}
          >
            <Undo2 size={14} aria-hidden /> 回滚这次投递
          </button>
        </div>
      ) : null}

      <div className="card">
        <h3>已记录的同意（{consents.data?.length ?? 0}）</h3>
        {consents.data?.length ? (
          <table className="table">
            <thead>
              <tr>
                <th>Agent</th>
                <th>通道</th>
                <th>目标</th>
                <th>键</th>
                <th>状态</th>
              </tr>
            </thead>
            <tbody>
              {consents.data.map((row) => (
                <tr key={`${row.agentId}-${row.channel}-${row.targetPath}`}>
                  <td>{row.agentId}</td>
                  <td className="mono">{row.channel}</td>
                  <td className="mono ellipsis" title={row.targetPath}>
                    {row.targetPath}
                  </td>
                  <td className="mono">{row.fields}</td>
                  <td>
                    {row.revokedAt ? (
                      <span className="badge badge-warn">已撤销</span>
                    ) : (
                      <span className="badge badge-ok">有效</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="muted">还没有任何同意记录。</p>
        )}
      </div>

      <ConfirmDialog
        open={confirming}
        title="确认投递"
        confirmLabel={grantAndApply.isPending ? "写入中…" : "我同意，写入"}
        confirmDisabled={!agreeChecked || grantAndApply.isPending}
        onCancel={() => setConfirming(false)}
        onConfirm={() => grantAndApply.mutate()}
      >
        <p>
          即将把密钥写入 <span className="mono">{plan.data?.targetPath}</span>
          {plan.data?.targetExists ? "（文件已存在，将只改动下列键）" : "（文件不存在，将新建）"}。
        </p>
        <label className="checkline">
          <input
            type="checkbox"
            checked={agreeChecked}
            onChange={(e) => setAgreeChecked(e.target.checked)}
          />
          <span>
            我明白这会以<span className="mono"> 0600 </span>权限写入上述文件，且会先留一份备份。
          </span>
        </label>
      </ConfirmDialog>

      <ConfirmDialog
        open={revoking}
        title="撤销投递同意"
        danger
        confirmLabel="撤销"
        onCancel={() => setRevoking(false)}
        onConfirm={() => revoke.mutate()}
      >
        <p>
          撤销后无法再向该通道投递，**已经写入的文件不会被自动还原**。
          如需还原内容，请到「变更历史」页回滚。
        </p>
      </ConfirmDialog>
    </section>
  );
}

function PlanView({
  plan,
  consentLabel,
  noChange,
  agreeChecked,
  onAgreeChange,
  busy,
  onApply,
  onRevoke,
}: {
  plan: DeliveryPlan;
  consentLabel: string;
  noChange: boolean;
  agreeChecked: boolean;
  onAgreeChange: (v: boolean) => void;
  busy: boolean;
  onApply: () => void;
  onRevoke: () => void;
}) {
  return (
    <div className="card">
      <div className="row row-between">
        <h3>
          <ShieldCheck size={15} aria-hidden /> 投递预览
        </h3>
        <span className={`badge badge-${plan.consent === "granted" ? "ok" : "warn"}`}>
          {consentLabel}
        </span>
      </div>

      <dl className="kv">
        <dt>Agent</dt>
        <dd className="mono">{plan.agentId}</dd>
        <dt>目标文件</dt>
        <dd className="mono ellipsis" title={plan.targetPath}>
          {plan.targetPath} {plan.targetExists ? "（已存在）" : "（将新建）"}
        </dd>
        <dt>将写入</dt>
        <dd>
          {plan.fields.map((f) => (
            <span key={f.key} className="chip mono">
              {f.key} = {f.masked}
            </span>
          ))}
        </dd>
      </dl>

      <h4>差异预览（已脱敏）</h4>
      <pre className="diff">{plan.preview}</pre>

      {noChange ? (
        <p className="muted">配置已是最新，无需改动。</p>
      ) : (
        <label className="checkline">
          <input
            type="checkbox"
            checked={agreeChecked}
            onChange={(e) => onAgreeChange(e.target.checked)}
          />
          <span>
            我同意把上述密钥写入该 agent 的配置（写入前会备份，可回滚）
          </span>
        </label>
      )}

      <div className="row">
        <button
          type="button"
          className="btn btn-primary"
          disabled={!agreeChecked || busy || noChange}
          onClick={onApply}
        >
          <Send size={14} aria-hidden /> 投递
        </button>
        {plan.consent === "granted" ? (
          <button type="button" className="btn" onClick={onRevoke}>
            <RotateCcw size={14} aria-hidden /> 撤销同意
          </button>
        ) : null}
      </div>
    </div>
  );
}
