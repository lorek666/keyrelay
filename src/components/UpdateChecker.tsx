import { useEffect, useRef, useState } from "react";
import { Download, RefreshCw } from "lucide-react";
import {
  checkForUpdates,
  downloadAndInstallUpdate,
  relaunchApp,
  type UpdateDownloadProgress,
  type UpdateInfo,
} from "../lib/api";
import ConfirmDialog from "./ConfirmDialog";
import { useTranslation, translate, getCurrentDict } from "../i18n";

type Phase =
  | "idle"
  | "checking"
  | "available"
  | "not-available"
  | "downloading"
  | "installed"
  | "error";

// U6：不直接展示原始 err.message（可能含 URL/内部路径/主机名），按类别归一到通用文案。
// M14-S2：归一文案走 i18n；正则里的「校验」是匹配后端错误原文的串，不抽——i18n:skip
function scrubError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  if (/fetch|network|404|not found|failed to/i.test(msg)) return translate(getCurrentDict(), "update.scrub.network");
  if (/signature|verify|校验/i.test(msg)) return translate(getCurrentDict(), "update.scrub.signature");  // i18n:skip
  return translate(getCurrentDict(), "update.scrub.default");
}

export default function UpdateChecker({
  autoCheckOnMount = false,
}: {
  autoCheckOnMount?: boolean;
}) {
  const { t } = useTranslation();
  const [phase, setPhase] = useState<Phase>("idle");
  const [update, setUpdate] = useState<UpdateInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<UpdateDownloadProgress | null>(null);
  const [relaunchOpen, setRelaunchOpen] = useState(false);
  const [relaunching, setRelaunching] = useState(false);
  const [relaunchError, setRelaunchError] = useState<string | null>(null);
  // U3：防重入——快速双击「再检查一次/重试」时第二次直接 return，避免并发 setPhase 竞态。
  const inFlight = useRef(false);

  async function doCheck() {
    if (inFlight.current) return;
    inFlight.current = true;
    setPhase("checking");
    setError(null);
    setUpdate(null);
    setProgress(null);
    setRelaunchOpen(false);
    setRelaunchError(null);
    try {
      const info = await checkForUpdates();
      if (info) {
        setUpdate(info);
        setPhase("available");
      } else {
        setPhase("not-available");
      }
    } catch (err) {
      setError(scrubError(err));
      setPhase("error");
    } finally {
      inFlight.current = false;
    }
  }

  async function doInstall() {
    if (inFlight.current) return;
    inFlight.current = true;
    setPhase("downloading");
    setError(null);
    setProgress({ downloaded: 0, total: null });
    try {
      await downloadAndInstallUpdate(setProgress);
      // macOS/Linux 的 updater 只负责换包，不会替应用重启。这里必须用应用内弹窗
      // 询问；`window.confirm` 在 macOS WKWebView 里没有实现，会静默返回 false，
      // 导致「包已装好、进程还是旧版、界面却回到 idle」且没有任何提示。
      setPhase("installed");
      setRelaunchOpen(true);
    } catch (err) {
      setError(scrubError(err));
      setPhase("error");
    } finally {
      inFlight.current = false;
    }
  }

  async function doRelaunch() {
    if (relaunching) return;
    setRelaunching(true);
    setRelaunchError(null);
    try {
      await relaunchApp();
      setRelaunchOpen(false);
    } catch {
      setRelaunchOpen(false);
      setRelaunchError(t("update.restartFailed"));
    } finally {
      setRelaunching(false);
    }
  }

  useEffect(() => {
    if (autoCheckOnMount) {
      doCheck();
    }
    // mount-only：autoCheckOnMount 是 prop，开关变化由父组件控制（见 Settings.tsx）。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const percent =
    progress?.total && progress.total > 0
      ? Math.min(100, Math.floor((progress.downloaded / progress.total) * 100))
      : null;

  return (
    <div className="update-checker">
      {phase === "idle" && (
        <button type="button" className="btn btn-secondary" onClick={doCheck}>
          <RefreshCw size={14} /> {t("update.checkBtn")}
        </button>
      )}

      {phase === "checking" && (
        <button type="button" className="btn btn-secondary" disabled>
          <RefreshCw size={14} className="spinning" /> {t("update.checking")}
        </button>
      )}

      {phase === "not-available" && (
        <div className="update-status">
          <span>{t("update.latest")}</span>
          <button type="button" className="btn btn-secondary" onClick={doCheck}>
            {t("update.recheck")}
          </button>
        </div>
      )}

      {phase === "available" && update && (
        <div className="update-available">
          <div className="update-info">
            <strong>{t("update.newVersion", { version: update.version })}</strong>
            {update.body && <p className="update-body">{update.body}</p>}
          </div>
          <button type="button" className="btn btn-primary" onClick={doInstall}>
            <Download size={14} /> {t("update.downloadBtn")}
          </button>
        </div>
      )}

      {phase === "downloading" && (
        <div className="update-downloading" role="status" aria-live="polite">
          <span>
            {percent === null
              ? t("update.downloading")
              : t("update.downloadingProgress", { percent })}
          </span>
        </div>
      )}

      {phase === "installed" && update && (
        <div className="update-available" role="status">
          <div className="update-info">
            <strong>{t("update.installedTitle")}</strong>
            <p className="update-body">
              {t("update.installedHint", { version: update.version })}
            </p>
            {relaunchError ? <p className="warn">{relaunchError}</p> : null}
          </div>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => setRelaunchOpen(true)}
          >
            {t("update.restartNow")}
          </button>
        </div>
      )}

      {phase === "error" && (
        <div className="update-error">
          <span className="warn">{t("update.error", { error: error ?? "" })}</span>
          <button type="button" className="btn btn-secondary" onClick={doCheck}>
            {t("common.retry")}
          </button>
        </div>
      )}

      {phase === "installed" && update ? (
        <ConfirmDialog
          open={relaunchOpen}
          title={t("update.installedTitle")}
          confirmLabel={relaunching ? t("update.restarting") : t("update.restartNow")}
          confirmDisabled={relaunching}
          onCancel={() => {
            if (!relaunching) setRelaunchOpen(false);
          }}
          onConfirm={() => void doRelaunch()}
        >
          <p>{t("update.installedBody", { version: update.version })}</p>
        </ConfirmDialog>
      ) : null}
    </div>
  );
}
