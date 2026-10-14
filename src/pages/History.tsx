import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, RefreshCw, Undo2 } from "lucide-react";
import {
  listDeliveries,
  listStoredKeys,
  recentEvents,
  rollbackDelivery,
  type DeliveryRecord,
} from "../lib/api";
import { rollbackAftermath } from "../lib/rollback";
import CapButton from "../components/CapButton";
import ConfirmDialog from "../components/ConfirmDialog";

const LEVEL_TONE: Record<string, string> = {
  debug: "muted",
  info: "ok",
  warn: "warn",
  error: "danger",
};

/**
 * 一次投递能不能回滚（M9-S4 / A）。判据来自后端的三个标志位；灰显必须说明原因——
 * 三种「不能」的处理方式各不相同，混成一句「不可用」等于没说。
 *
 * 已解绑的投递**照样能回滚**（M8-S4 §5.4）：解绑只是不再追踪，文件没动。
 */
function rollbackGate(row: DeliveryRecord): {
  allowed: boolean;
  reason: string;
  label: string;
  tone: string;
} {
  if (row.rolledBack) {
    return { allowed: false, reason: "这次投递已经回滚过了", label: "已回滚", tone: "muted" };
  }
  if (!row.hasJournal) {
    return {
      allowed: false,
      reason: "这次投递没有变更记录（老数据），无法回滚",
      label: "无变更记录",
      tone: "muted",
    };
  }
  if (row.superseded) {
    return {
      allowed: false,
      reason: "同一文件之后又投递过：要回到这次之前，先回滚更新的那次",
      label: "已被之后的投递覆盖",
      tone: "muted",
    };
  }
  return { allowed: true, reason: "", label: "当前生效", tone: "ok" };
}

export default function History() {
  const qc = useQueryClient();
  const events = useQuery({
    queryKey: ["events"],
    queryFn: () => recentEvents(200),
  });
  const deliveries = useQuery({ queryKey: ["deliveries"], queryFn: () => listDeliveries(100) });
  const keys = useQuery({ queryKey: ["stored-keys"], queryFn: listStoredKeys });
  const [target, setTarget] = useState<DeliveryRecord | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const rollback = useMutation({
    mutationFn: (row: DeliveryRecord) => rollbackDelivery(row.journalId),
    onSuccess: async (_, row) => {
      setError(null);
      // 要不要交代后果，看的是**这个目标**还有没有仍绑定的行，不是这一行自己（复审 N-3）：
      // 解绑之后又投递过的话，同一目标上会有一条更新的、仍绑定的行，漂移与轮换看的是它。
      // 按 `listDeliveries` 的 limit 语义，每个目标 id 最大的那行一定在列表里，这里算得出来。
      const bound = (deliveries.data ?? []).find(
        (d) => d.targetPath === row.targetPath && d.unboundAt === null,
      );
      setNotice(
        `已回滚 ${row.targetPath}（变更 ${row.journalId}）。` +
          (bound ? rollbackAftermath(bound.agentId) : ""),
      );
      setTarget(null);
      await qc.invalidateQueries({ queryKey: ["deliveries"] });
      await qc.invalidateQueries({ queryKey: ["drift"] });
      await qc.invalidateQueries({ queryKey: ["events"] });
    },
    onError: (err: Error) => {
      setNotice(null);
      setError(err.message);
      setTarget(null);
    },
  });

  const keyName = (keyId: number) => {
    const key = (keys.data ?? []).find((k) => k.id === keyId);
    return key ? `${key.name}（#${key.id}）` : `#${keyId}`;
  };

  return (
    <section>
      <p className="muted">
        当前生效的每一次投递都可以在这里回滚（更早、已被覆盖的历史只列最近 100 次）。
        事件流里的所有文本在写入数据库前都经过脱敏——这里不会出现密钥明文。
      </p>

      {notice ? <p className="ok" role="status">{notice}</p> : null}
      {error ? (
        <p className="error" role="alert">
          <AlertTriangle size={14} aria-hidden /> {error}
        </p>
      ) : null}

      <div className="card">
        <div className="row row-between">
          <h3>投递记录（{deliveries.data?.length ?? 0}）</h3>
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => deliveries.refetch()}
            disabled={deliveries.isFetching}
          >
            <RefreshCw size={14} aria-hidden /> 刷新
          </button>
        </div>

        {deliveries.isLoading ? <p className="muted">加载中…</p> : null}
        {deliveries.isError ? (
          <p className="error" role="alert">
            {(deliveries.error as Error).message}
          </p>
        ) : null}
        {deliveries.data?.length === 0 ? (
          <p className="muted">还没有投递过。到「Agent 投递」页投递一次，就会出现在这里。</p>
        ) : null}

        {deliveries.data?.length ? (
          <table className="table">
            <thead>
              <tr>
                <th>时间</th>
                <th>Agent</th>
                <th>目标文件</th>
                <th>密钥</th>
                <th>状态</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {deliveries.data.map((row) => {
                const gate = rollbackGate(row);
                return (
                  <tr key={row.bindingId}>
                    <td className="mono nowrap">{formatTs(row.appliedAt)}</td>
                    <td className="mono nowrap">{row.agentId}</td>
                    <td className="mono ellipsis" title={row.targetPath}>
                      {row.targetPath}
                    </td>
                    <td>{keyName(row.keyId)}</td>
                    <td className="nowrap">
                      <span className={`badge badge-${gate.tone}`} title={gate.reason || undefined}>
                        {gate.label}
                      </span>
                      {row.unboundAt ? (
                        <>
                          {" "}
                          <span className="badge badge-muted" title={formatTs(row.unboundAt)}>
                            已解绑
                          </span>
                        </>
                      ) : null}
                    </td>
                    <td className="nowrap">
                      <CapButton
                        allowed={gate.allowed}
                        reason={gate.reason}
                        busy={rollback.isPending}
                        className="btn btn-ghost"
                        onClick={() => {
                          setNotice(null);
                          setError(null);
                          setTarget(row);
                        }}
                      >
                        <Undo2 size={13} aria-hidden /> 回滚…
                      </CapButton>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : null}
        <p className="muted">
          「已解绑」的投递照样可以回滚：解绑只是不再追踪那个文件，文件内容没动过。
        </p>
      </div>

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

      <ConfirmDialog
        open={target !== null}
        title="回滚这次投递"
        danger
        confirmLabel={rollback.isPending ? "回滚中…" : "回滚"}
        confirmDisabled={rollback.isPending}
        onCancel={() => setTarget(null)}
        onConfirm={() => target && rollback.mutate(target)}
      >
        <p>
          会把目标文件还原到这次投递之前的内容（逐字节比对）。
          如果文件在那之后被别的程序改过，回滚会被拒绝，而不是覆盖掉别人的改动。
        </p>
        <p className="muted mono">{target?.targetPath}</p>
        {target?.backupPath ? (
          <p className="muted">
            用这份备份还原：<span className="mono">{target.backupPath}</span>
          </p>
        ) : (
          // 没有备份 = 投递之前这个文件不存在：回滚就是把它删掉。这件事必须在点之前说清楚。
          <p className="warn">这个文件是那次投递新建的：回滚会把它删掉。</p>
        )}
      </ConfirmDialog>
    </section>
  );
}

function formatTs(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}
