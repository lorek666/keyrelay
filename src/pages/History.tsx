import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, RefreshCw, Undo2 } from "lucide-react";
import {
  listDeliveries,
  listStoredKeys,
  rollbackDelivery,
  type DeliveryRecord,
} from "../lib/api";
import { rollbackAftermath, rollbackAftermathTitle } from "../lib/rollback";
import CapButton from "../components/CapButton";
import ConfirmDialog from "../components/ConfirmDialog";
import Skeleton from "../components/Skeleton";
import { useTranslation, translate, getCurrentDict } from "../i18n";

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
    return {
      allowed: false,
      reason: translate(getCurrentDict(), "history.deliveries.rolledBackReason"),
      label: translate(getCurrentDict(), "history.deliveries.rolledBack"),
      tone: "muted",
    };
  }
  if (!row.hasJournal) {
    return {
      allowed: false,
      reason: translate(getCurrentDict(), "history.deliveries.noJournalReason"),
      label: translate(getCurrentDict(), "history.deliveries.noJournal"),
      tone: "muted",
    };
  }
  if (row.superseded) {
    return {
      allowed: false,
      reason: translate(getCurrentDict(), "history.deliveries.supersededReason"),
      label: translate(getCurrentDict(), "history.deliveries.superseded"),
      tone: "muted",
    };
  }
  return {
    allowed: true,
    reason: "",
    label: translate(getCurrentDict(), "history.deliveries.current"),
    tone: "ok",
  };
}

export default function History() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const deliveries = useQuery({ queryKey: ["deliveries"], queryFn: () => listDeliveries(100) });
  const keys = useQuery({ queryKey: ["stored-keys"], queryFn: listStoredKeys });
  const [target, setTarget] = useState<DeliveryRecord | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  /** 回滚后的三条后果（B-129 J：分条渲染）。 */
  const [rollbackLines, setRollbackLines] = useState<string[]>([]);

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
        t("history.notice", {
          target: row.targetPath,
          journal: row.journalId,
        }),
      );
      // M16-S6b（B-129 J）：后果分条渲染，不再塞进上面那一句里
      setRollbackLines(bound ? rollbackAftermath(bound.agentId) : []);
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

  // keyName 拼接密钥名与 id（数据格式化，括号风格不抽——i18n:skip）
  const keyName = (keyId: number) => {
    const key = (keys.data ?? []).find((k) => k.id === keyId);
    return key ? `${key.name}（#${key.id}）` : `#${keyId}`;
  };

  return (
    <section className="page delivery-history">
      <p className="page-intro">{t("history.intro")}</p>

      {notice ? <p className="ok" role="status">{notice}</p> : null}

      {/* 回滚之后的后果（B-129 J：分条）。与投递页共用同一组文案。 */}
      {rollbackLines.length > 0 ? (
        <div className="warnbox" role="status">
          <p className="warnline">
            <AlertTriangle size={14} aria-hidden /> {rollbackAftermathTitle()}
          </p>
          <ul className="list">
            {rollbackLines.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {error ? (
        <p className="error" role="alert">
          <AlertTriangle size={14} aria-hidden /> {error}
        </p>
      ) : null}

      <div className="card">
        <div className="row row-between">
          <h3>{t("history.deliveries.title", { count: deliveries.data?.length ?? 0 })}</h3>
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => deliveries.refetch()}
            disabled={deliveries.isFetching}
          >
            <RefreshCw size={14} aria-hidden /> {t("common.refresh")}
          </button>
        </div>

        {deliveries.isLoading ? <Skeleton rows={4} /> : null}
        {deliveries.isError ? (
          <p className="error" role="alert">
            {t("history.deliveries.error", { error: (deliveries.error as Error).message })}
          </p>
        ) : null}
        {deliveries.data?.length === 0 ? (
          <p className="muted empty">{t("history.deliveries.empty")}</p>
        ) : null}

        {deliveries.data?.length ? (
          <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>{t("history.deliveries.table.time")}</th>
                <th>{t("history.deliveries.table.agent")}</th>
                <th>{t("history.deliveries.table.target")}</th>
                <th>{t("history.deliveries.table.key")}</th>
                <th>{t("history.deliveries.table.status")}</th>
                <th>{t("history.deliveries.table.action")}</th>
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
                            {t("history.deliveries.unbound")}
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
                        <Undo2 size={13} aria-hidden /> {t("history.deliveries.rollbackBtn")}
                      </CapButton>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          </div>
        ) : null}
        <p className="muted">{t("history.deliveries.hint")}</p>
      </div>

      <ConfirmDialog
        open={target !== null}
        title={t("history.rollbackDialog.title")}
        danger
        confirmLabel={rollback.isPending ? t("history.rollbackDialog.confirming") : t("history.rollbackDialog.confirm")}
        confirmDisabled={rollback.isPending}
        onCancel={() => setTarget(null)}
        onConfirm={() => target && rollback.mutate(target)}
      >
        <p>{t("history.rollbackDialog.body")}</p>
        <p className="muted mono">{target?.targetPath}</p>
        {target?.backupPath ? (
          <p className="muted">
            {t("history.rollbackDialog.backupHint")}<span className="mono">{target.backupPath}</span>
          </p>
        ) : (
          // 没有备份 = 投递之前这个文件不存在：回滚就是把它删掉。这件事必须在点之前说清楚。
          <p className="warn">{t("history.rollbackDialog.noBackupWarn")}</p>
        )}
      </ConfirmDialog>
    </section>
  );
}

function formatTs(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}
