import { AlertTriangle, CheckCircle2, Info } from "lucide-react";
import type { RebrandInfo } from "../lib/api";
import { useTranslation } from "../i18n";

/**
 * M35-S1：旧版数据目录迁移的可见性。
 *
 * 只在 `migrated` / `targetExists` / `failed` 三态渲染；`noLegacy`（全新安装或已经在新目录）
 * 不占任何版面。迁移失败必须是 `role="alert"` —— 用户需要知道「这次用的是旧目录」，
 * 否则「怎么还是旧数据」会被误判成功能没生效。
 */
export default function RebrandNotice({
  rebrand,
  dataDir,
}: {
  rebrand?: RebrandInfo | null;
  dataDir?: string | null;
}) {
  const { t } = useTranslation();
  if (!rebrand || rebrand.status === "noLegacy") return null;

  const warnings = rebrand.warnings.length ? (
    <>
      <p className="rebrand-warnings-title">{t("overview.rebrand.warningsTitle")}</p>
      <ul className="rebrand-warnings">
        {rebrand.warnings.map((warning) => (
          <li key={warning}>{warning}</li>
        ))}
      </ul>
    </>
  ) : null;

  if (rebrand.status === "migrated") {
    return (
      <div className="card rebrand-notice rebrand-migrated" role="status">
        <h3>
          <CheckCircle2 size={15} aria-hidden /> {t("overview.rebrand.migratedTitle")}
        </h3>
        <p>
          {t("overview.rebrand.migratedBody", {
            files: rebrand.files,
            bytes: rebrand.bytes,
            from: rebrand.from ?? "~/.keyrelay",
            to: rebrand.to,
          })}
        </p>
        {warnings}
      </div>
    );
  }

  if (rebrand.status === "failed") {
    return (
      <div className="card rebrand-notice rebrand-failed" role="alert">
        <h3>
          <AlertTriangle size={15} aria-hidden /> {t("overview.rebrand.failedTitle")}
        </h3>
        <p>
          {t("overview.rebrand.failedBody", {
            error: rebrand.error ?? "—",
            dataDir: dataDir ?? rebrand.to,
          })}
        </p>
        {warnings}
      </div>
    );
  }

  return (
    <div className="card rebrand-notice rebrand-target" role="status">
      <h3>
        <Info size={15} aria-hidden /> {t("overview.rebrand.targetTitle")}
      </h3>
      <p>{t("overview.rebrand.targetBody", { to: rebrand.to })}</p>
      {warnings}
    </div>
  );
}
