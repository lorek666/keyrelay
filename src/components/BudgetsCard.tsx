import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle } from "lucide-react";
import {
  listSites,
  listStoredKeys,
  siteBudgetCreate,
  siteBudgetDelete,
  siteBudgetList,
  type SiteBudget,
} from "../lib/api";
import { useTranslation } from "../i18n";

/**
 * M46-S5：硬预算卡（成本中心，照搬 ModelPricesCard 的 CRUD 卡模式）。
 *
 * 落点说明（spec §4.6）：M45-S3 已把价格卡从设置页搬到成本中心，成本类配置
 * 归成本中心；设置页不硬塞。站点 / 密钥下拉复用既有 listSites / listStoredKeys
 * （密钥下拉取本地 stored keys 的 id——预算 key_id 是本地 keys.id，不是 remote_id）。
 */
export default function BudgetsCard() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const budgets = useQuery({ queryKey: ["site-budgets"], queryFn: siteBudgetList });
  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });
  const storedKeys = useQuery({ queryKey: ["stored-keys"], queryFn: listStoredKeys });
  const [siteId, setSiteId] = useState("");
  const [keyId, setKeyId] = useState("");
  const [period, setPeriod] = useState("day");
  const [limit, setLimit] = useState("");
  const [error, setError] = useState<string | null>(null);

  const limitNum = Number(limit);
  const canSave =
    siteId !== "" && limit !== "" && Number.isFinite(limitNum) && limitNum > 0 && !Number.isNaN(limitNum);

  const create = useMutation({
    mutationFn: () =>
      siteBudgetCreate({
        siteId: Number(siteId),
        keyId: keyId === "" ? null : Number(keyId),
        period,
        limitUsd: limitNum,
      }),
    onSuccess: async () => {
      setError(null);
      setSiteId("");
      setKeyId("");
      setPeriod("day");
      setLimit("");
      await qc.invalidateQueries({ queryKey: ["site-budgets"] });
    },
    onError: (err: Error) => setError(err.message),
  });
  const remove = useMutation({
    mutationFn: (id: number) => siteBudgetDelete(id),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["site-budgets"] });
    },
    onError: (err: Error) => setError(err.message),
  });

  const siteName = (id: number) =>
    sites.data?.find((s) => s.id === id)?.displayName ?? `Site ${id}`;
  const keyName = (id: number | null) =>
    id === null
      ? t("usage.budgets.keyAll")
      : (storedKeys.data?.find((k) => k.id === id)?.name ?? `Key ${id}`);
  const keysForSite = (storedKeys.data ?? []).filter(
    (k) => (siteId === "" || k.siteId === Number(siteId)) && k.status !== "revoked",
  );

  return (
    <div className="hm-card">
      <h3>{t("usage.budgets.title")}</h3>
      <p className="muted">{t("usage.budgets.body")}</p>
      <div className="row">
        <select
          className="input"
          aria-label={t("usage.budgets.site")}
          value={siteId}
          onChange={(e) => {
            setSiteId(e.target.value);
            setKeyId("");
          }}
        >
          <option value="">{t("usage.budgets.sitePlaceholder")}</option>
          {(sites.data ?? []).map((s) => (
            <option key={s.id} value={s.id}>
              {s.displayName}
            </option>
          ))}
        </select>
        <select
          className="input"
          aria-label={t("usage.budgets.key")}
          value={keyId}
          onChange={(e) => setKeyId(e.target.value)}
        >
          <option value="">{t("usage.budgets.keyAll")}</option>
          {keysForSite.map((k) => (
            <option key={k.id} value={k.id}>
              {k.name}
            </option>
          ))}
        </select>
        <select
          className="input"
          aria-label={t("usage.budgets.period")}
          value={period}
          onChange={(e) => setPeriod(e.target.value)}
        >
          <option value="day">{t("usage.budgets.periodDay")}</option>
          <option value="month">{t("usage.budgets.periodMonth")}</option>
        </select>
        <input
          className="input"
          type="number"
          step="0.01"
          min="0"
          placeholder={t("usage.budgets.limit")}
          value={limit}
          onChange={(e) => setLimit(e.target.value)}
        />
        <button
          type="button"
          className="btn btn-primary"
          disabled={!canSave || create.isPending}
          onClick={() => create.mutate()}
        >
          {t("usage.budgets.save")}
        </button>
      </div>
      <p className="muted">{t("usage.budgets.note")}</p>
      {error ? (
        <p className="error" role="alert">
          <AlertTriangle size={14} aria-hidden /> {error}
        </p>
      ) : null}
      {budgets.data && budgets.data.length > 0 ? (
        <table className="table">
          <thead>
            <tr>
              <th>{t("usage.budgets.site")}</th>
              <th>{t("usage.budgets.key")}</th>
              <th>{t("usage.budgets.period")}</th>
              <th>{t("usage.budgets.limit")}</th>
              <th>{t("usage.budgets.spent")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {budgets.data.map((row: SiteBudget) => (
              <tr key={row.id}>
                <td>{siteName(row.siteId)}</td>
                <td>{keyName(row.keyId)}</td>
                <td>
                  {row.period === "month"
                    ? t("usage.budgets.periodMonth")
                    : t("usage.budgets.periodDay")}
                </td>
                <td className="mono">{row.limitUsd} USD</td>
                <td className="mono">{row.spentUsd} USD</td>
                <td>
                  <button
                    type="button"
                    className="btn btn-ghost"
                    onClick={() => remove.mutate(row.id)}
                  >
                    {t("usage.budgets.delete")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="muted">{t("usage.budgets.empty")}</p>
      )}
    </div>
  );
}
