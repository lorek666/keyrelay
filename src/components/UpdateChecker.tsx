import { useEffect, useState } from "react";
import { Download, RefreshCw } from "lucide-react";
import { checkForUpdates, downloadAndInstallUpdate, type UpdateInfo } from "../lib/api";

type Phase =
  | "idle"
  | "checking"
  | "available"
  | "not-available"
  | "downloading"
  | "error";

export default function UpdateChecker({
  autoCheckOnMount = false,
}: {
  autoCheckOnMount?: boolean;
}) {
  const [phase, setPhase] = useState<Phase>("idle");
  const [update, setUpdate] = useState<UpdateInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function doCheck() {
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
      setError(err instanceof Error ? err.message : String(err));
      setPhase("error");
    }
  }

  async function doInstall() {
    setPhase("downloading");
    setError(null);
    try {
      await downloadAndInstallUpdate();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setPhase("error");
    }
  }

  useEffect(() => {
    if (autoCheckOnMount) {
      doCheck();
    }
  }, []);

  return (
    <div className="update-checker">
      {phase === "idle" && (
        <button type="button" className="btn btn-secondary" onClick={doCheck}>
          <RefreshCw size={14} /> 检查更新
        </button>
      )}

      {phase === "checking" && (
        <button type="button" className="btn btn-secondary" disabled>
          <RefreshCw size={14} className="spinning" /> 检查中…
        </button>
      )}

      {phase === "not-available" && (
        <div className="update-status">
          <span>当前已是最新版本</span>
          <button type="button" className="btn btn-secondary" onClick={doCheck}>
            再检查一次
          </button>
        </div>
      )}

      {phase === "available" && update && (
        <div className="update-available">
          <div className="update-info">
            <strong>新版本 {update.version}</strong>
            {update.body && <p className="update-body">{update.body}</p>}
          </div>
          <button type="button" className="btn btn-primary" onClick={doInstall}>
            <Download size={14} /> 下载并安装
          </button>
        </div>
      )}

      {phase === "downloading" && (
        <div className="update-downloading">
          <span>下载中…</span>
        </div>
      )}

      {phase === "error" && (
        <div className="update-error">
          <span className="warn">更新检查失败：{error}</span>
          <button type="button" className="btn btn-secondary" onClick={doCheck}>
            重试
          </button>
        </div>
      )}
    </div>
  );
}
