import { useEffect, useRef, useState } from "react";
import { Download, RefreshCw } from "lucide-react";
import {
  checkForUpdates,
  downloadAndInstallUpdate,
  relaunchApp,
  type UpdateInfo,
} from "../lib/api";

type Phase =
  | "idle"
  | "checking"
  | "available"
  | "not-available"
  | "downloading"
  | "error";

// U6：不直接展示原始 err.message（可能含 URL/内部路径/主机名），按类别归一到通用文案。
function scrubError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  if (/fetch|network|404|not found|failed to/i.test(msg)) return "无法连接更新服务器";
  if (/signature|verify|校验/i.test(msg)) return "更新包签名校验失败";
  return "更新检查失败，请稍后重试";
}

export default function UpdateChecker({
  autoCheckOnMount = false,
}: {
  autoCheckOnMount?: boolean;
}) {
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
      if (
        window.confirm(
          "更新已下载完成，即将重启应用以生效。未保存的修改会丢失，是否现在重启？"
        )
      ) {
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
