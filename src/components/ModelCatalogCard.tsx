import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CloudDownload, RotateCcw, Save } from "lucide-react";
import {
  catalogSetOverride,
  catalogStatus,
  catalogSyncNow,
  getSettings,
  updateSettings,
  type CatalogModel,
  type CatalogOverrideInput,
} from "../lib/api";
import { useTranslation } from "../i18n";

/**
 * M47-S2：内置模型名单（名称 / 价格 / 协议 / 上下文 / 最大输出 / 思考档位）。
 *
 * 三条红线都在界面上看得见：
 * 1. **来源**必须是明示的（GitHub 缓存 / 内置 / 空）——用户要能判断「这份数据是哪来的」；
 * 2. **同步失败保留旧缓存**——所以错误显示成提示，而不是把表格清空；
 * 3. **本机覆盖**逐条可撤销——覆盖后该行标出来，点一下就能回到名单值。
 */
export default function ModelCatalogCard() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const status = useQuery({ queryKey: ["catalog-status"], queryFn: catalogStatus });
  const settings = useQuery({ queryKey: ["settings"], queryFn: getSettings });

  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [autoSync, setAutoSync] = useState(true);
  const [url, setUrl] = useState("");

  useEffect(() => {
    if (!settings.data) return;
    setAutoSync(settings.data.catalogAutoSync);
    setUrl(settings.data.catalogUrl);
  }, [settings.data]);

  const sync = useMutation({
    mutationFn: async () => {
      // 同步使用服务端已保存地址；地址/开关草稿尚未保存时不能悄悄按旧地址拉取。
      const current = await getSettings();
      if (current.catalogUrl.trim() !== url.trim() || current.catalogAutoSync !== autoSync) {
        // 手动同步不隐式整包保存设置：那会绕过设置页的未保存草稿合并。
        throw new Error(t("catalog.saveBeforeSync"));
      }
      // 后端每次同步都重读已保存设置；这里绝不拿草稿地址直接联网。
      return catalogSyncNow();
    },
    onSuccess: async (result) => {
      setError(null);
      setNotice(
        result.unchanged
          ? t("catalog.syncUnchanged")
          : t("catalog.syncDone", {
              accepted: result.accepted,
              skipped: result.skipped,
            }),
      );
      await qc.invalidateQueries({ queryKey: ["catalog-status"] });
      // 同步会把名单价「补」进模型单价表（用户手输的价优先）——不刷新这两处，用户点完
      // 「立即同步」看到的还是旧价，会以为同步没生效。
      await qc.invalidateQueries({ queryKey: ["model-prices"] });
      await qc.invalidateQueries({ queryKey: ["usage-dashboard"] });
    },
    onError: (err: Error) => {
      setNotice(null);
      setError(t("catalog.syncFailed", { error: err.message }));
    },
  });

  const saveSettings = useMutation({
    mutationFn: async () => {
      const current = await getSettings();
      return updateSettings({
        ...current,
        catalogAutoSync: autoSync,
        catalogUrl: url.trim(),
      });
    },
    onSuccess: async () => {
      setError(null);
      setNotice(t("catalog.settingsSaved"));
      await qc.invalidateQueries({ queryKey: ["settings"] });
      await qc.invalidateQueries({ queryKey: ["catalog-status"] });
    },
    onError: (err: Error) => setError(err.message),
  });

  const models = useMemo(() => status.data?.models ?? [], [status.data]);
  const source = status.data?.source;

  return (
    <div className="hm-card">
      <h3>{t("catalog.title")}</h3>
      <p className="muted">{t("catalog.body")}</p>

      <div className="row row-between catalog-toolbar">
        <div className="row">
          {source ? <span className={`badge badge-${source === "remote" ? "ok" : source === "bundled" ? "warn" : "danger"}`}>
            {t(`catalog.source.${source}`)}
          </span> : null}
          {status.data ? <span className="muted">
            {t("catalog.summary", {
              entries: status.data.entries,
              overrides: status.data.overrides,
            })}
          </span> : null}
          {status.data?.generatedAt ? (
            <span className="muted mono">{t("catalog.generatedAt", { at: status.data.generatedAt })}</span>
          ) : null}
        </div>
        <button
          type="button"
          className="btn btn-ghost"
          onClick={() => sync.mutate()}
          disabled={sync.isPending}
        >
          <CloudDownload size={14} aria-hidden />{" "}
          {sync.isPending ? t("catalog.syncing") : t("catalog.syncNow")}
        </button>
      </div>

      {status.data?.lastError ? (
        <p className="muted">{t("catalog.lastError", { error: status.data.lastError })}</p>
      ) : null}
      {notice ? <p className="ok" role="status">{notice}</p> : null}
      {error ? <p className="error" role="alert">{error}</p> : null}

      <div className="row catalog-sync-settings">
        <label className="checkline">
          <input
            type="checkbox"
            checked={autoSync}
            onChange={(e) => setAutoSync(e.target.checked)}
          />
          <span>{t("catalog.autoSync")}</span>
        </label>
        <label className="field-inline">
          <span>{t("catalog.urlLabel")}</span>
          <input
            className="input mono"
            value={url}
            placeholder={status.data?.url ?? ""}
            onChange={(e) => setUrl(e.target.value)}
            spellCheck={false}
          />
        </label>
        <button
          type="button"
          className="btn btn-ghost"
          onClick={() => saveSettings.mutate()}
          disabled={saveSettings.isPending}
        >
          <Save size={14} aria-hidden /> {t("catalog.saveSettings")}
        </button>
      </div>
      <p className="muted">{t("catalog.urlHint")}</p>

      {status.isLoading ? <p className="muted">{t("common.loading")}</p> : null}
      {/* 查询失败必须说清楚是「读不到名单状态」，不能装成「名单是空的」——否则用户会去点
          同步或怀疑数据源，而真正的原因（IPC / 权限 / 后端报错）被藏起来了。 */}
      {status.isError ? (
        <p className="error" role="alert">
          {t("catalog.statusFailed", { error: (status.error as Error).message })}
        </p>
      ) : null}
      {status.isSuccess && models.length === 0 ? (
        <p className="muted empty">{t("catalog.empty")}</p>
      ) : null}

      {models.length > 0 ? (
        <div
          className="table-wrap"
          role="region"
          aria-label={t("catalog.title")}
          tabIndex={0}
        >
          <table className="table">
            <thead>
              <tr>
                <th scope="col">{t("catalog.table.name")}</th>
                <th scope="col">{t("catalog.table.protocol")}</th>
                <th scope="col">{t("catalog.table.context")}</th>
                <th scope="col">{t("catalog.table.output")}</th>
                <th scope="col">{t("catalog.table.price")}</th>
                <th scope="col">{t("catalog.table.thinking")}</th>
                <th scope="col">{t("catalog.table.actions")}</th>
              </tr>
            </thead>
            <tbody>
              {models.map((model) => (
                <CatalogRow
                  // key 带上「有效值指纹」：同步换了一份名单之后同一行的编辑器要重建，
                  // 否则输入框里留着旧名单的值，用户下一次保存会把旧值钉回覆盖里。
                  key={`${model.id}|${model.contextWindow}|${model.maxOutputTokens}|${
                    model.thinking?.defaultLevel ?? ""
                  }|${model.prices[0]?.inputPerMtok ?? ""}|${model.prices[0]?.outputPerMtok ?? ""}`}
                  model={model}
                  onError={setError}
                  onDone={setNotice}
                />
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      <p className="muted">{t("catalog.footnote")}</p>
    </div>
  );
}

/** 一行 + 行内覆盖编辑（`<details>` 展开，不弹窗：名单要能一次看全）。 */
function CatalogRow({
  model,
  onError,
  onDone,
}: {
  model: CatalogModel;
  onError: (message: string | null) => void;
  onDone: (message: string | null) => void;
}) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  // 输入框**留空 = 不改这一格**：只有用户真填了值才进 patch（后端按合并语义写入）。
  // 当前生效值放在 placeholder 里当参考——早先是把生效值预填进输入框再整包提交，
  // 于是「只改价格」的一次保存会顺手把窗口 / 档位 / 价格全部钉死，名单以后更新也压不过它。
  const [context, setContext] = useState("");
  const [output, setOutput] = useState("");
  const [level, setLevel] = useState("");
  const [priceIn, setPriceIn] = useState("");
  const [priceOut, setPriceOut] = useState("");

  const save = useMutation({
    mutationFn: (patch: CatalogOverrideInput | null) => catalogSetOverride(model.id, patch),
    onSuccess: async (_status, patch) => {
      onError(null);
      onDone(patch === null ? t("catalog.overrideCleared") : t("catalog.overrideSaved"));
      await qc.invalidateQueries({ queryKey: ["catalog-status"] });
      // 本机价格覆盖也会写当前生效的价格版本，成本估算和单价表必须同步刷新。
      await qc.invalidateQueries({ queryKey: ["model-prices"] });
      await qc.invalidateQueries({ queryKey: ["usage-dashboard"] });
    },
    onError: (err: Error) => onError(err.message),
  });

  const price = model.prices[0];
  const priceText = price
    ? `${price.inputPerMtok} / ${price.outputPerMtok} ${price.currency}`
    : t("catalog.priceUnknown");
  const hasEdit = [context, output, level, priceIn, priceOut].some((v) => v.trim() !== "");

  return (
    <>
      <tr>
        <td>
          <span className="key-name">
            {model.displayName}
            {model.overridden ? <span className="badge badge-warn">{t("catalog.overridden")}</span> : null}
          </span>
          <div className="muted mono">{model.id}</div>
        </td>
        <td className="mono">{t(`catalog.protocol.${model.protocol}`)}</td>
        <td className="mono">{model.contextWindow.toLocaleString()}</td>
        <td className="mono">{model.maxOutputTokens.toLocaleString()}</td>
        <td className="mono">{priceText}</td>
        <td>
          {model.thinking
            ? t("catalog.thinkingUpTo", { level: model.thinking.maxLevel })
            : t(model.thinkingUnsupported ? "catalog.thinkingNone" : "catalog.thinkingUnknown")}
        </td>
        <td>
          <details>
            <summary className="btn btn-ghost" aria-label={`${t("catalog.override.edit")} ${model.displayName}`}>
              {t("catalog.override.edit")}
            </summary>
            <div className="catalog-override">
              <label className="field-inline">
                <span>{t("catalog.table.context")}</span>
                <input
                  className="input mono"
                  inputMode="numeric"
                  value={context}
                  placeholder={model.contextWindow.toLocaleString()}
                  onChange={(e) => setContext(e.target.value)}
                />
              </label>
              <label className="field-inline">
                <span>{t("catalog.table.output")}</span>
                <input
                  className="input mono"
                  inputMode="numeric"
                  value={output}
                  placeholder={model.maxOutputTokens.toLocaleString()}
                  onChange={(e) => setOutput(e.target.value)}
                />
              </label>
              <label className="field-inline">
                <span>{t("catalog.override.level")}</span>
                <select className="input" value={level} onChange={(e) => setLevel(e.target.value)}>
                  <option value="">{t("catalog.override.levelKeep")}</option>
                  {["off", "low", "medium", "high", "xhigh"].map((value) => (
                    <option key={value} value={value}>
                      {t(`catalog.level.${value}`)}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field-inline">
                <span>{t("catalog.override.priceIn")}</span>
                <input
                  className="input mono"
                  inputMode="decimal"
                  value={priceIn}
                  placeholder={price?.inputPerMtok !== undefined ? String(price.inputPerMtok) : ""}
                  onChange={(e) => setPriceIn(e.target.value)}
                />
              </label>
              <label className="field-inline">
                <span>{t("catalog.override.priceOut")}</span>
                <input
                  className="input mono"
                  inputMode="decimal"
                  value={priceOut}
                  placeholder={price?.outputPerMtok !== undefined ? String(price.outputPerMtok) : ""}
                  onChange={(e) => setPriceOut(e.target.value)}
                />
              </label>
              <div className="row">
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={save.isPending || !hasEdit}
                  onClick={() => {
                    const built = buildPatch({
                      context,
                      output,
                      level,
                      priceIn,
                      priceOut,
                      price,
                      effectiveContext: model.contextWindow,
                      effectiveOutput: model.maxOutputTokens,
                      contextLabel: t("catalog.table.context"),
                      outputLabel: t("catalog.table.output"),
                    });
                    if (!built.ok) {
                      onError(t(built.key, built.params));
                      return;
                    }
                    save.mutate(built.patch);
                  }}
                >
                  <Save size={13} aria-hidden /> {t("catalog.override.save")}
                </button>
                <button
                  type="button"
                  className="btn btn-ghost"
                  disabled={save.isPending || !model.overridden}
                  onClick={() => save.mutate(null)}
                >
                  <RotateCcw size={13} aria-hidden /> {t("catalog.override.clear")}
                </button>
              </div>
              <p className="muted">{t("catalog.override.hint")}</p>
            </div>
          </details>
        </td>
      </tr>
    </>
  );
}

/**
 * 把「用户填了字的格子」翻译成一条覆盖 patch。
 *
 * 留空 = 不改；`ok: false` = 校验失败（带 i18n 键，由调用方翻译后原地报错，
 * 不提交半条脏数据）。号码一律按十进制解析：`parseInt("12abc")` 会悄悄得到 12，
 * 所以必须 `Number` + 整数校验。
 */
type PatchResult =
  | { ok: true; patch: CatalogOverrideInput }
  | { ok: false; key: string; params?: Record<string, string> };

function buildPatch(input: {
  context: string;
  output: string;
  level: string;
  priceIn: string;
  priceOut: string;
  price?: { currency: string };
  effectiveContext: number;
  effectiveOutput: number;
  contextLabel: string;
  outputLabel: string;
}): PatchResult {
  const patch: CatalogOverrideInput = {};
  const positive = (text: string, label: string): number | PatchResult => {
    const trimmed = text.trim();
    if (trimmed === "") return 0;
    const value = Number(trimmed);
    if (!Number.isInteger(value) || value <= 0) {
      return { ok: false, key: "catalog.override.errPositive", params: { field: label } };
    }
    if (value > 4_294_967_295) {
      return { ok: false, key: "catalog.override.errRange", params: { field: label } };
    }
    return value;
  };
  const window = positive(input.context, input.contextLabel);
  if (typeof window !== "number") return window;
  if (window > 0) patch.contextWindow = window;
  const output = positive(input.output, input.outputLabel);
  if (typeof output !== "number") return output;
  if (output > 0) patch.maxOutputTokens = output;
  if ((patch.contextWindow ?? input.effectiveContext) < (patch.maxOutputTokens ?? input.effectiveOutput)) {
    return { ok: false, key: "catalog.override.errWindow" };
  }
  if (input.level !== "") patch.thinkingLevel = input.level;

  const priceIn = input.priceIn.trim();
  const priceOut = input.priceOut.trim();
  if (priceIn !== "" || priceOut !== "") {
    // 单价是一对：只填一半 ⇒ 另一半按「未知」会把成本估算算成 0，所以必须两个都给。
    if (priceIn === "" || priceOut === "") {
      return { ok: false, key: "catalog.override.errPricePair" };
    }
    const a = Number(priceIn);
    const b = Number(priceOut);
    if (!Number.isFinite(a) || !Number.isFinite(b) || a <= 0 || b <= 0) {
      return { ok: false, key: "catalog.override.errPriceNegative" };
    }
    patch.priceInputPerMtok = a;
    patch.priceOutputPerMtok = b;
    patch.priceCurrency = input.price?.currency ?? "USD";
  }
  return { ok: true, patch };
}
