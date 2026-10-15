import { useEffect, useRef, useState } from "react";
import { Download, RefreshCw } from "lucide-react";
import {
  checkForUpdates,
  downloadAndInstallUpdate,
  relaunchApp,
  type UpdateInfo,
} from "../lib/api";
import { useTranslation, translate, getCurrentDict } from "../i18n";

type Phase =
  | "idle"
  | "checking"
  | "available"
  | "not-available"
  | "downloading"
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
  // U3：防重入——快速双击「再检查一次/重试」时第二次直接 return，避免并发 setPhase 竞态。
  const inFlight = useRef(false);

  async function doCheck() {
    if (inFlight.current) return;
    inFlight.current = true;
    setPhase("checking");
    setError(null);
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
    try {
      await downloadAndInstallUpdate();
      // U4：安装完成，relaunch 前让用户确认——未保存的修改（站点表单/配置）会丢失。
      if (window.confirm(t("update.confirm"))) {
        await relaunchApp();
      } else {
        setPhase("idle");
      }
    } catch (err) {
      setError(scrubError(err));
      setPhase("error");
    } finally {
      inFlight.current = false;
    }
  }

  useEffect(() => {
    if (autoCheckOnMount) {
      doCheck();
    }
    // mount-only：autoCheckOnMount 是 prop，开关变化由父组件控制（见 Settings.tsx）。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
        <div className="update-downloading">
          <span>{t("update.downloading")}</span>
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
    </div>
  );
}
