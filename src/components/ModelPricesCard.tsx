import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle } from "lucide-react";
import {
  modelPriceDelete,
  modelPriceList,
  modelPriceUpsert,
  type ModelPrice,
} from "../lib/api";
import { useTranslation } from "../i18n";

/**
 * M43-S2：模型单价表（M45-S3 由 Settings 页原样搬出，逻辑零改动）。
 *
 * 红线：**无价格 = 未知**。这里只负责「配置价格版本」，不在这里渲染任何成本；
 * 「为什么某段时间没有成本」由成本中心的「未定价」标注回答。
 */
export default function ModelPricesCard() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const prices = useQuery({ queryKey: ["model-prices"], queryFn: modelPriceList });
  const [model, setModel] = useState("");
  const [input, setInput] = useState("");
  const [output, setOutput] = useState("");
  const [currency, setCurrency] = useState("USD");
  const [date, setDate] = useState(() => new Date().toISOString().slice(0, 10));
  const [error, setError] = useState<string | null>(null);

  const upsert = useMutation({
    mutationFn: () =>
      modelPriceUpsert({
        model: model.trim(),
        inputPerMtok: Number(input),
        outputPerMtok: Number(output),
        currency,
        effectiveFrom: Math.floor(new Date(`${date}T00:00:00`).getTime() / 1000),
      }),
    onSuccess: async () => {
      setError(null);
      setModel("");
      setInput("");
      setOutput("");
      await qc.invalidateQueries({ queryKey: ["model-prices"] });
    },
    onError: (err: Error) => setError(err.message),
  });
  const remove = useMutation({
    mutationFn: (id: number) => modelPriceDelete(id),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["model-prices"] });
    },
    onError: (err: Error) => setError(err.message),
  });

  return (
    <div className="hm-card">
      <h3>{t("settings.prices.title")}</h3>
      <p className="muted">{t("settings.prices.body")}</p>
      <div className="row">
        <input
          className="input"
          placeholder={t("settings.prices.model")}
          value={model}
          onChange={(e) => setModel(e.target.value)}
          spellCheck={false}
        />
        <input
          className="input"
          type="number"
          step="0.0001"
          placeholder={t("settings.prices.input")}
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
        <input
          className="input"
          type="number"
          step="0.0001"
          placeholder={t("settings.prices.output")}
          value={output}
          onChange={(e) => setOutput(e.target.value)}
        />
        <select className="input" value={currency} onChange={(e) => setCurrency(e.target.value)}>
          <option value="USD">USD</option>
          <option value="CNY">CNY</option>
        </select>
        <input className="input" type="date" value={date} onChange={(e) => setDate(e.target.value)} />
        <button
          type="button"
          className="btn btn-primary"
          disabled={!model.trim() || !input || !output || upsert.isPending}
          onClick={() => upsert.mutate()}
        >
          {t("settings.prices.save")}
        </button>
      </div>
      <p className="muted">{t("settings.prices.hint")}</p>
      {error ? (
        <p className="error" role="alert">
          <AlertTriangle size={14} aria-hidden /> {error}
        </p>
      ) : null}
      {prices.data && prices.data.length > 0 ? (
        <table className="table">
          <thead>
            <tr>
              <th>{t("settings.prices.model")}</th>
              <th>{t("settings.prices.input")}</th>
              <th>{t("settings.prices.output")}</th>
              <th>{t("settings.prices.currency")}</th>
              <th>{t("settings.prices.effectiveFrom")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {prices.data.map((row: ModelPrice) => (
              <tr key={row.id}>
                <td className="mono">{row.model}</td>
                <td className="mono">{row.inputPerMtok}</td>
                <td className="mono">{row.outputPerMtok}</td>
                <td>{row.currency}</td>
                <td className="mono">{new Date(row.effectiveFrom * 1000).toLocaleDateString()}</td>
                <td>
                  <button
                    type="button"
                    className="btn btn-ghost"
                    onClick={() => remove.mutate(row.id)}
                  >
                    {t("settings.prices.delete")}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="muted">{t("settings.prices.empty")}</p>
      )}
    </div>
  );
}

