import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle } from "lucide-react";
import {
  billReconciliation,
  listSites,
  type BillReconciliation,
} from "../lib/api";
import { useTranslation } from "../i18n";

/**
 * M46-UI B-251：账单对账卡（成本中心，沿 BudgetsCard 的卡模式）。
 *
 * 只读报告卡，无写操作。数据源是 M46-S6 的 `bill_reconciliation` IPC（只读
 * `site_bills` + 网关用量 + 模型价，不改定价、不改预算判定、不发通知）。
 *
 * B-253（卡片侧处理，绝不改 IPC 语义）：`flagged=true` 在 IPC 里共用两种
 * 含义——超阈值行与不可比行（`diffUsd === null`）。卡片把两者分开：
 * - 可比表：只放 `diffUsd !== null` 的行；「仅看超阈值」筛选只作用于这张表；
 * - 不可比组：`diffUsd === null` 的行单独立组，永远不进可比表的 flagged
 *   筛选，也不挂「超阈值」标记（只挂「不可比」说明）。
 *
 * 覆盖度文案必须如实（B-251 要求）：目前账单来源基本只有 NewAPI 系导入，
 * 其它来源的账单只有被导入后才会出现；数据随导入节拍更新，有滞后——
 * 绝不写成实时全来源对账。
 */
export default function ReconciliationCard() {
  const { t } = useTranslation();
  const [days, setDays] = useState(30);
  const [flaggedOnly, setFlaggedOnly] = useState(false);
  const rows = useQuery({
    queryKey: ["bill-reconciliation", days],
    queryFn: () => billReconciliation(undefined, days),
  });
  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });

  const siteName = (id: number) =>
    sites.data?.find((s) => s.id === id)?.displayName ?? `Site ${id}`;
  const money = (v: number | null) => (v === null ? "—" : `${v.toFixed(2)} USD`);

  const all = rows.data ?? [];
  const comparable = all.filter((r) => r.diffUsd !== null);
  const incomparable = all.filter((r) => r.diffUsd === null);
  const shown = flaggedOnly ? comparable.filter((r) => r.flagged) : comparable;

  const renderRows = (list: BillReconciliation[], withFlag: boolean) =>
    list.map((row) => (
      <tr key={`${row.siteId}-${row.day}-${row.kind}`}>
        <td className="mono">{row.day}</td>
        <td>{siteName(row.siteId)}</td>
        <td className="mono">{money(row.gatewayUsd)}</td>
        <td className="mono">{money(row.billUsd)}</td>
        <td className="mono">{money(row.diffUsd)}</td>
        <td>{t(`usage.reconciliation.kindValues.${row.kind}`)}</td>
        <td>
          {withFlag && row.flagged ? t("usage.reconciliation.flaggedYes") : "—"}
        </td>
      </tr>
    ));

  return (
    <div className="hm-card">
      <h3>{t("usage.reconciliation.title")}</h3>
      <p className="muted">{t("usage.reconciliation.body")}</p>
      <div className="row">
        <select
          className="input"
          aria-label={t("usage.reconciliation.daysLabel")}
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
        >
          {[7, 30, 90].map((d) => (
            <option key={d} value={d}>
              {t("usage.reconciliation.daysOption", { days: d })}
            </option>
          ))}
        </select>
        <label className="checkline">
          <input
            type="checkbox"
            checked={flaggedOnly}
            onChange={(e) => setFlaggedOnly(e.target.checked)}
          />
          <span>{t("usage.reconciliation.flaggedOnly")}</span>
        </label>
      </div>
      {rows.isError ? (
        <p className="error" role="alert">
          <AlertTriangle size={14} aria-hidden /> {(rows.error as Error).message}
        </p>
      ) : null}
      {shown.length > 0 ? (
        <table className="table">
          <thead>
            <tr>
              <th>{t("usage.reconciliation.day")}</th>
              <th>{t("usage.reconciliation.site")}</th>
              <th>{t("usage.reconciliation.gateway")}</th>
              <th>{t("usage.reconciliation.bill")}</th>
              <th>{t("usage.reconciliation.diff")}</th>
              <th>{t("usage.reconciliation.kind")}</th>
              <th>{t("usage.reconciliation.flagged")}</th>
            </tr>
          </thead>
          <tbody>{renderRows(shown, true)}</tbody>
        </table>
      ) : (
        <p className="muted">
          {flaggedOnly
            ? t("usage.reconciliation.flaggedEmpty")
            : t("usage.reconciliation.empty")}
        </p>
      )}
      {incomparable.length > 0 ? (
        <div>
          <h4>{t("usage.reconciliation.incomparableTitle")}</h4>
          <p className="muted">{t("usage.reconciliation.incomparableNote")}</p>
          <table className="table">
            <thead>
              <tr>
                <th>{t("usage.reconciliation.day")}</th>
                <th>{t("usage.reconciliation.site")}</th>
                <th>{t("usage.reconciliation.gateway")}</th>
                <th>{t("usage.reconciliation.bill")}</th>
                <th>{t("usage.reconciliation.diff")}</th>
                <th>{t("usage.reconciliation.kind")}</th>
                <th>{t("usage.reconciliation.flagged")}</th>
              </tr>
            </thead>
            <tbody>{renderRows(incomparable, false)}</tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}
