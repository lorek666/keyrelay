import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, RefreshCw } from "lucide-react";
import ConfirmDialog from "./ConfirmDialog";
import { useTranslation } from "../i18n";
import {
  vaultMigrationAbandon,
  vaultMigrationRetry,
  vaultMigrationStatus,
  type VaultMigrationPhase,
} from "../lib/api";

/** 四态 → i18n 键（判据只来自后端给的 phase）。 */
function phaseLabelKey(phase: VaultMigrationPhase): string {
  switch (phase) {
    case "done":
      return "settings.vaultMigration.phaseDone";
    case "retryExhausted":
      return "settings.vaultMigration.phaseRetryExhausted";
    case "abandoned":
      return "settings.vaultMigration.phaseAbandoned";
    default:
      return "settings.vaultMigration.phasePending";
  }
}

/**
 * 设置页「钥匙串迁移」卡片（M38-S2 / B-219）。
 *
 * 只做三件事：展示状态（四态 + attempts/失败数/首条原因/上次尝试）、显式重试、显式放弃。
 * 放弃必须二次确认；重试中按钮禁用；**失败不清空已有状态**（只多一条错误）。
 * 卡片刻意从 Settings.tsx 抽出——便于单测（Settings 本身依赖太多查询）。
 */
export default function VaultMigrationCard() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const status = useQuery({
    queryKey: ["vault-migration"],
    queryFn: vaultMigrationStatus,
    retry: false,
  });
  const [confirming, setConfirming] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const retry = useMutation({
    mutationFn: vaultMigrationRetry,
    onSuccess: async (report) => {
      setError(null);
      setNotice(
        report.failed.length === 0
          ? t("settings.vaultMigration.retryDone")
          : t("settings.vaultMigration.retryFailed"),
      );
      await qc.invalidateQueries({ queryKey: ["vault-migration"] });
      await qc.invalidateQueries({ queryKey: ["app-info"] });
    },
    // 失败不清状态：只把错误追加显示，后面的 query 也不会被清。
    onError: (err: Error) => setError(err.message),
  });

  const abandon = useMutation({
    mutationFn: vaultMigrationAbandon,
    onSuccess: async () => {
      setError(null);
      setConfirming(false);
      setNotice(t("settings.vaultMigration.abandoned"));
      await qc.invalidateQueries({ queryKey: ["vault-migration"] });
    },
    onError: (err: Error) => {
      setError(err.message);
      setConfirming(false);
    },
  });

  const phase = status.data?.phase;
  const isDone = phase === "done";
  const isAbandoned = phase === "abandoned";
  const firstFailure =
    status.data?.failures[0] ?? status.data?.cleanupPending[0] ?? null;

  return (
    <div className="card vault-migration">
      <h3>{t("settings.vaultMigration.title")}</h3>
      <p className="muted">{t("settings.vaultMigration.body")}</p>

      {status.isLoading ? (
        <p className="muted">{t("settings.loading")}</p>
      ) : status.isError ? (
        <p className="error" role="alert">
          <AlertTriangle size={14} aria-hidden />{" "}
          {t("settings.vaultMigration.loadFailed", {
            error: (status.error as Error).message,
          })}
        </p>
      ) : status.data ? (
        <>
          <p className="vault-migration-phase" data-phase={status.data.phase}>
            <strong>{t(phaseLabelKey(status.data.phase))}</strong>
          </p>
          <ul className="vault-migration-meta muted">
            <li>{t("settings.vaultMigration.attempts", { count: status.data.attempts })}</li>
            <li>{t("settings.vaultMigration.failures", { count: status.data.failures.length })}</li>
            {status.data.cleanupPending.length > 0 ? (
              <li>
                {t("settings.vaultMigration.cleanupPending", {
                  count: status.data.cleanupPending.length,
                })}
              </li>
            ) : null}
            <li>
              {t("settings.vaultMigration.lastAt", {
                time: status.data.lastAt
                  ? new Date(status.data.lastAt * 1000).toLocaleString()
                  : "—",
              })}
            </li>
          </ul>
          {firstFailure ? (
            <p className="muted vault-migration-reason">
              {t("settings.vaultMigration.firstFailure", {
                reference: firstFailure.reference,
                reason: firstFailure.reason,
              })}
            </p>
          ) : null}
        </>
      ) : null}

      <div className="row">
        <button
          type="button"
          className="btn btn-primary"
          disabled={retry.isPending || isDone || status.isLoading}
          onClick={() => retry.mutate()}
        >
          <RefreshCw size={14} aria-hidden />{" "}
          {retry.isPending
            ? t("settings.vaultMigration.retrying")
            : t("settings.vaultMigration.retry")}
        </button>
        <button
          type="button"
          className="btn"
          disabled={abandon.isPending || isDone || isAbandoned || status.isLoading}
          onClick={() => setConfirming(true)}
        >
          {t("settings.vaultMigration.abandon")}
        </button>
      </div>

      {notice ? (
        <p className="ok" role="status">
          {notice}
        </p>
      ) : null}
      {error ? (
        <p className="error" role="alert">
          <AlertTriangle size={14} aria-hidden /> {error}
        </p>
      ) : null}

      <ConfirmDialog
        open={confirming}
        title={t("settings.vaultMigration.abandonTitle")}
        confirmLabel={t("settings.vaultMigration.abandonConfirm")}
        confirmDisabled={abandon.isPending}
        onCancel={() => setConfirming(false)}
        onConfirm={() => abandon.mutate()}
      >
        <p>{t("settings.vaultMigration.abandonBody")}</p>
      </ConfirmDialog>
    </div>
  );
}
