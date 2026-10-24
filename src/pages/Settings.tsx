import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Save } from "lucide-react";
import { ShieldCheck } from "lucide-react";
import {
  auditRedaction,
  autostartStatus,
  deleteAlias,
  detectSystemProxy,
  exportBundle,
  exportDiagnostics,
  getSettings,
  listAliasMap,
  pruneBackups,
  purgeKeychain,
  setAutostart,
  updateSettings,
  upsertAlias,
  type AliasEntry,
  type KeychainPurgeReport,
  type Settings,
} from "../lib/api";
import GatewayCard from "../components/GatewayCard";
import VaultMigrationCard from "../components/VaultMigrationCard";
import UpdateChecker from "../components/UpdateChecker";
import ConfirmDialog from "../components/ConfirmDialog";
import { useTranslation, translate, getCurrentDict } from "../i18n";

/** 「系统里的实际状态」的显示文案。`unknown` 是「读不出来」，不是「没开」——两者不能混。 */
function autostartStateLabel(state: string): string {
  switch (state) {
    case "enabled":
      return translate(getCurrentDict(), "settings.autostart.stateEnabled");
    case "disabled":
      return translate(getCurrentDict(), "settings.autostart.stateDisabled");
    default:
      return translate(getCurrentDict(), "settings.autostart.stateUnknown");
  }
}

/**
 * 数值字段的提交前校验（M8-S5B §6.6）。
 *
 * 为什么必须在前端拦：这些字段最终落进 Rust 的 `u32` / `u16`。`type="number"` 的
 * `min` / `max` 只是 HTML 属性——用户可以键入越界值，也可以提交（属性不阻止提交），
 * 于是后端反序列化失败，用户看到一句难懂的序列化错误，而界面刚刚还显示他填的值。
 *
 * 返回 `null` = 不合法；调用方据此**不发请求**并给出中文文案。
 */
function intInRange(raw: number, min: number, max: number): number | null {
  if (!Number.isInteger(raw) || raw < min || raw > max) return null;
  return raw;
}

/** 允许小数的字段（目前只有余额阈值）：有限数 + 落在区间内 + 非负。 */
function finiteNonNegative(raw: number, max: number): number | null {
  if (!Number.isFinite(raw) || raw < 0 || raw > max) return null;
  return raw;
}

/** M10-S2：把 `ProxySource::as_str` 的英文串翻成中文来源标签（仅展示）。
 *  后端返回的 source 取值，中英同形（系统标识），暂不抽——i18n:skip */
function proxySourceLabel(source: string): string {
  switch (source) {
    case "macos-system":
      return "macOS 系统设置";  // i18n:skip
    case "windows-registry":
      return "Windows 注册表";  // i18n:skip
    case "manual":
      return "手动";  // i18n:skip
    default:
      // 环境变量名（如 HTTPS_PROXY）原样展示
      return source;
  }
}

// M14-S2：preset 的 label 改成 i18n key，渲染时 `t(preset.labelKey)`
const PRESETS = [
  { labelKey: "settings.autorefresh.off", value: 0 },
  { labelKey: "settings.autorefresh.min5", value: 300 },
  { labelKey: "settings.autorefresh.min15", value: 900 },
  { labelKey: "settings.autorefresh.hour1", value: 3600 },
];

function ExportCard() {
  const { t } = useTranslation();
  const [password, setPassword] = useState("");
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = useMutation({
    mutationFn: () => exportBundle(password || undefined),
    onSuccess: (r) => {
      setError(null);
      setResult(
        t("settings.export.result", {
          path: r.path,
          encrypted: r.encrypted ? t("settings.export.encrypted") : t("settings.export.plaintext"),
          bytes: r.bytes,
        }) + (r.registered ? "" : t("settings.export.resultUnregistered")),
      );
    },
    onError: (err: Error) => {
      setResult(null);
      setError(err.message);
    },
  });

  const prune = useMutation({
    mutationFn: () => pruneBackups(10),
    onSuccess: (r) => setResult(t("settings.export.pruneResult", { count: r.removed })),
    onError: (err: Error) => setError(err.message),
  });

  // FR-9:196 诊断包。在此之前 `service::export_diagnostics` 只有测试在调，
  // 命令层与界面都没有入口——PRD 里算已交付，用户手里不存在。
  const diagnostics = useMutation({
    mutationFn: () => exportDiagnostics(),
    onSuccess: (r) => {
      setError(null);
      setResult(
        t("settings.export.diagResult", { path: r.path, events: r.events, bytes: r.bytes }) +
          (r.registered ? "" : t("settings.export.diagResultUnregistered")),
      );
    },
    onError: (err: Error) => {
      setResult(null);
      setError(err.message);
    },
  });

  return (
    <div className="card">
      <h3>{t("settings.export.title")}</h3>
      <p className="muted">
        {t("settings.export.bodyPre")}<strong>{t("settings.export.bodyStrong")}</strong>{t("settings.export.bodyPost")}
      </p>
      <p className="muted">
        {t("settings.export.diagBodyPre")}<strong>{t("settings.export.diagBodyStrong")}</strong>{t("settings.export.diagBodyPost")}
      </p>
      <label className="field">
        <span>{t("settings.export.passwordLabel")}</span>
        <input
          className="input"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="off"
        />
      </label>
      <div className="row">
        <button
          type="button"
          className="btn btn-primary"
          disabled={run.isPending}
          onClick={() => run.mutate()}
        >
          {run.isPending ? t("settings.export.exporting") : t("settings.export.exportBtn")}
        </button>
        <button
          type="button"
          className="btn"
          disabled={prune.isPending}
          onClick={() => prune.mutate()}
        >
          {prune.isPending ? t("settings.export.pruning") : t("settings.export.pruneBtn")}
        </button>
        <button
          type="button"
          className="btn"
          disabled={diagnostics.isPending}
          onClick={() => diagnostics.mutate()}
        >
          {diagnostics.isPending ? t("settings.export.exporting") : t("settings.export.diagBtn")}
        </button>
      </div>
      {result ? <p className="ok" role="status">{result}</p> : null}
      {error ? <p className="error" role="alert">{error}</p> : null}
    </div>
  );
}

/**
 * 钥匙串条目一键清理（FR-8:191）。
 *
 * 清理的是**系统钥匙串里的秘密**：删了就没了（站点侧那把 key 还在，但本地再也取不回明文）。
 * 本地 SQLite 记录**保留**——清理的是秘密，不是历史（`bindings` / 漂移追溯靠它存活）。
 *
 * `confirm=true` 只能来自下面的**明确勾选**：默认 false，不勾就点不动。
 * 后端同样会拒绝 `confirm=false`，两处都不提供「无参数即全删」的形态。
 */
function KeychainCard() {
  const { t } = useTranslation();
  const [confirming, setConfirming] = useState(false);
  const [agreed, setAgreed] = useState(false);
  const [report, setReport] = useState<KeychainPurgeReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const purge = useMutation({
    mutationFn: () => purgeKeychain(true),
    onSuccess: (r) => {
      setError(null);
      setReport(r);
      setAgreed(false);
      setConfirming(false);
    },
    onError: (err: Error) => {
      setReport(null);
      setError(err.message);
      setAgreed(false);
      setConfirming(false);
    },
  });

  return (
    <div className="card">
      <h3>{t("settings.keychain.title")}</h3>
      <p className="muted">
        {t("settings.keychain.bodyPre")}<strong>{t("settings.keychain.bodyStrong")}</strong>{t("settings.keychain.bodyPost")}
      </p>
      <p className="muted">
        {t("settings.keychain.localKeepPre")}<strong>{t("settings.keychain.localKeepStrong")}</strong>{t("settings.keychain.localKeepPost")}
      </p>
      <button
        type="button"
        className="btn btn-danger"
        disabled={purge.isPending}
        onClick={() => {
          setError(null);
          setAgreed(false);
          setConfirming(true);
        }}
      >
        {purge.isPending ? t("settings.keychain.cleaning") : t("settings.keychain.btn")}
      </button>

      {report ? (
        <>
          <p
            className={report.failed > 0 ? "error" : "ok"}
            role="status"
          >
            {t("settings.keychain.result", { attempted: report.attempted, removed: report.removed, failed: report.failed })}
          </p>
          {report.firstError ? (
            <p className="muted">{t("settings.keychain.firstError", { error: report.firstError })}</p>
          ) : null}
          {report.failed > 0 ? (
            <p className="muted">{t("settings.keychain.failHint")}</p>
          ) : null}
        </>
      ) : null}
      {error ? (
        <p className="error" role="alert">
          <AlertTriangle size={14} aria-hidden /> {error}
        </p>
      ) : null}

      <p className="muted">
        {t("settings.keychain.uninstallPre")}<strong>{t("settings.keychain.uninstallStrong1")}</strong>{t("settings.keychain.uninstallMid")}<strong>{t("settings.keychain.uninstallStrong2")}</strong>{t("settings.keychain.uninstallPost")}
      </p>

      <ConfirmDialog
        open={confirming}
        title={t("settings.keychain.dialogTitle")}
        danger
        confirmLabel={purge.isPending ? t("settings.keychain.cleaning") : t("settings.keychain.confirm")}
        confirmDisabled={!agreed || purge.isPending}
        onCancel={() => {
          setAgreed(false);
          setConfirming(false);
        }}
        onConfirm={() => purge.mutate()}
      >
        <p>
          {t("settings.keychain.dialogBodyPre")}<strong>{t("settings.keychain.dialogBodyStrong")}</strong>{t("settings.keychain.dialogBodyPost")}
        </p>
        <p className="muted">{t("settings.keychain.dialogLocalKeep")}</p>
        <label className="checkline">
          <input
            type="checkbox"
            checked={agreed}
            onChange={(e) => setAgreed(e.target.checked)}
          />
          <span>{t("settings.keychain.agree")}</span>
        </label>
      </ConfirmDialog>
    </div>
  );
}

/**
 * 模型别名映射（M14-S1 / B-110）。
 * agent 侧模型名 → 真实模型名。用户手填，落 SQLite，接进 RouteTable::with_alias。
 */
function AliasCard() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["alias-map"], queryFn: listAliasMap });
  const [alias, setAlias] = useState("");
  const [real, setReal] = useState("");
  const [error, setError] = useState<string | null>(null);

  const add = useMutation({
    mutationFn: () => upsertAlias(alias.trim(), real.trim()),
    onSuccess: async () => {
      setError(null);
      setAlias("");
      setReal("");
      await qc.invalidateQueries({ queryKey: ["alias-map"] });
    },
    onError: (err: Error) => setError(err.message),
  });

  const remove = useMutation({
    mutationFn: (a: string) => deleteAlias(a),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["alias-map"] });
    },
    onError: (err: Error) => setError(err.message),
  });

  const entries: AliasEntry[] = list.data ?? [];
  const canAdd = alias.trim().length > 0 && real.trim().length > 0 && !add.isPending;

  return (
    <div className="card">
      <h3>{t("settings.alias.title")}</h3>
      <p className="muted">{t("settings.alias.body")}</p>
      <div className="row">
        <label className="field-inline">
          <span>{t("settings.alias.agentModel")}</span>
          <input
            className="input"
            type="text"
            value={alias}
            onChange={(e) => setAlias(e.target.value)}
            placeholder="gpt-5.6"
          />
        </label>
        <label className="field-inline">
          <span>{t("settings.alias.realModel")}</span>
          <input
            className="input"
            type="text"
            value={real}
            onChange={(e) => setReal(e.target.value)}
            placeholder="gpt-5.6-2026"
          />
        </label>
        <button
          type="button"
          className="btn btn-primary"
          disabled={!canAdd}
          onClick={() => add.mutate()}
        >
          {add.isPending ? t("settings.alias.adding") : t("settings.alias.add")}
        </button>
      </div>
      {entries.length === 0 ? (
        <p className="muted">{t("settings.alias.empty")}</p>
      ) : (
        <ul className="list">
          {entries.map((e) => (
            <li key={e.alias} className="row">
              <span className="mono">{e.alias}</span>
              <span>→</span>
              <span className="mono">{e.realModel}</span>
              <button
                type="button"
                className="btn btn-ghost"
                disabled={remove.isPending}
                onClick={() => remove.mutate(e.alias)}
              >{t("common.delete")}</button>
            </li>
          ))}
        </ul>
      )}
      {error ? <p className="error" role="alert">{error}</p> : null}
    </div>
  );
}

function AuditCard() {
  const { t } = useTranslation();
  const report = useQuery({
    queryKey: ["audit"],
    queryFn: auditRedaction,
    enabled: false,
  });

  return (
    <div className="card">
      <h3>
        <ShieldCheck size={15} aria-hidden /> {t("settings.audit.title")}
      </h3>
      <p className="muted">{t("settings.audit.body")}</p>
      <button
        type="button"
        className="btn"
        disabled={report.isFetching}
        onClick={() => report.refetch()}
      >
        {report.isFetching ? t("settings.audit.scanning") : t("settings.audit.btn")}
      </button>
      {report.data ? (
        <>
          <p className={report.data.clean ? "ok" : "error"}>
            {report.data.summary}
          </p>
          {report.data.findings.length ? (
            <ul className="list">
              {report.data.findings.map((f, i) => (
                <li key={`${f.kind}-${i}`}>
                  <span className="badge badge-warn">{f.kind}</span>{" "}
                  <span className="mono ellipsis">{f.path ?? t("settings.audit.eventTable")}</span>{" "}
                  {f.detail}
                </li>
              ))}
            </ul>
          ) : null}
        </>
      ) : null}
      {report.isError ? (
        <p className="error">{(report.error as Error).message}</p>
      ) : null}
    </div>
  );
}

export default function SettingsPage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const current = useQuery({ queryKey: ["settings"], queryFn: getSettings });
  // 系统里自启的**实际**状态（不是设置里那个意愿）。见下方 autostartStateLabel 处的说明。
  const autostart = useQuery({
    queryKey: ["autostart-status"],
    queryFn: autostartStatus,
    retry: false,
  });
  const [draft, setDraft] = useState<Settings | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // M10-S2：auto 模式下展示「检测到的系统代理」。只读，不改设置。
  const detected = useQuery({
    queryKey: ["detect-system-proxy"],
    queryFn: detectSystemProxy,
    retry: false,
    // 不必轮询：系统代理变更很少；用户点「重新检测」手动 refetch。
    staleTime: Infinity,
  });

  useEffect(() => {
    if (current.data && draft === null) setDraft(current.data);
  }, [current.data, draft]);

  /**
   * 开关与系统实际状态不一致时的说明。`null` = 一致、或读不到、或用户还没动过草稿。
   *
   * 只在**两者都能确定**时才报：「unknown」是「读不出来」，把它当不一致会制造假警报。
   */
  const autostartMismatch = (() => {
    if (!autostart.data || !draft) return null;
    if (autostart.data.state === "unknown") return null;
    const wanted = draft.autostartEnabled ? "enabled" : "disabled";
    if (autostart.data.state === wanted) return null;
    return autostart.data.state === "enabled"
      ? t("settings.autostart.mismatchEnabled")
      : t("settings.autostart.mismatchDisabled");
  })();

  /**
   * 提交前的数值校验（M8-S5B §6.6）。
   *
   * 逐字段给出「不合法时说什么」。区间取的是**业务界，比后端类型更严**
   * （独立复审 P3-2：`refresh_interval_secs` / `notify_timeout_secs` 在 Rust 侧是
   * `u64`，这里限 0..86400 / 1..60；`rotation_*_days` 是 `u32`，这里限 0..36500）。
   * 方向是安全的：更严只会挡住越界值，不会漏放——`u32` / `u16` 反序列化失败那条
   * 风险已经闭合。
   *
   * **已知副作用**：若某个字段的存量值超出这些业务界（例如手工改过配置文件），
   * 用户会被挡住**任何**保存，直到把它改回界内。这是有意的——真放过去也是后端报错。
   * 任一字段不合法 ⇒ 直接 return，**不发请求**。
   */
  function validateDraft(draft: Settings): string | null {
    const refresh = intInRange(draft.refreshIntervalSecs, 0, 86_400);
    if (refresh === null) return t("settings.validate.refresh");
    const threshold = finiteNonNegative(draft.balanceAlertThreshold, 1_000_000);
    if (threshold === null) return t("settings.validate.threshold");
    const port = intInRange(draft.gatewayPort, 1, 65_535);
    if (port === null) return t("settings.validate.port");
    const timeout = intInRange(draft.notifyTimeoutSecs, 1, 60);
    if (timeout === null) return t("settings.validate.timeout");
    const maxAge = intInRange(draft.rotationMaxAgeDays, 0, 36_500);
    if (maxAge === null) return t("settings.validate.maxAge");
    const warn = intInRange(draft.rotationWarnBeforeDays, 0, 36_500);
    if (warn === null) return t("settings.validate.warnBefore");
    if (warn > maxAge && maxAge !== 0) {
      return t("settings.validate.warnGtMax");
    }
    return null;
  }

  const save = useMutation({
    mutationFn: async (settings: Settings) => {
      const result = await updateSettings(settings);
      // M41-S1：设置已保存 ≠ 网关已按新设置运行。gatewayError 有值时两件事都要说。
      const saved = result.settings;
      // 自启不是「存一个布尔值」就完事的：它要在磁盘上真写 / 真删一个 LaunchAgent，
      // 或者在 Windows 上动注册表。所以保存设置之后立刻把它同步成实际状态，
      // 并把实际状态带回来——否则界面显示「已开启」而系统里什么都没有。
      //
      // 自启失败**不**让整笔保存算失败（M8-S5B §6.10）：设置已经存进去了，
      // 把两件事的结果分别带回，界面分开说——否则用户以为设置没存，会重复保存。
      try {
        const autostart = await setAutostart(saved.autostartEnabled);
        return {
          saved,
          autostart,
          autostartError: null as string | null,
          gatewayError: result.gatewayError,
          gateway: result.gateway,
        };
      } catch (err) {
        return {
          saved,
          autostart: null,
          autostartError: (err as Error).message,
          gatewayError: result.gatewayError,
          gateway: result.gateway,
        };
      }
    },
    onSuccess: async ({ saved, autostart, autostartError, gatewayError, gateway }) => {
      setError(null);
      // M41-S1 复审 P1：网关动作失败也是「设置已保存」之后的事实，**必须**显示；
      // 同时把卡片缓存改成后端返回的当前状态，避免旧缓存继续显示「运行中/旧 URL」。
      qc.setQueryData(["gateway"], gateway);
      // 两件事分开说（M8-S5B §6.10）：设置**已保存**（这是事实，先讲清楚），
      // 自启/网关的同步结果是另一件事——失败或状态不一致都单独说一句。
      if (gatewayError !== null) {
        setNotice(t("settings.save.gatewayFail", { error: gatewayError }));
      } else if (autostartError !== null) {
        setNotice(t("settings.save.autostartFail", { error: autostartError }));
      } else if (autostart) {
        const wanted = saved.autostartEnabled ? "enabled" : "disabled";
        if (autostart.state !== wanted && autostart.state !== "unknown") {
          // 真实状态与用户意愿不一致时**必须说出来**，不能只显示「已保存」。
          setNotice(t("settings.save.autostartMismatch", { state: autostart.state }));
        } else {
          setNotice(t("settings.save.ok"));
        }
      } else {
        setNotice(t("settings.save.ok"));
      }
      setDraft(saved);
      await qc.invalidateQueries({ queryKey: ["settings"] });
      await qc.invalidateQueries({ queryKey: ["gateway"] });
      // 重读系统里的实际状态，让上面那句「系统里的实际状态」立刻跟上
      await qc.invalidateQueries({ queryKey: ["autostart-status"] });
    },
    onError: (err: Error) => {
      setNotice(null);
      setError(err.message);
    },
  });

  const dirty =
    draft !== null &&
    current.data !== undefined &&
    JSON.stringify(draft) !== JSON.stringify(current.data);

  return (
    <section className={dirty ? "page settings-page has-dirty" : "page settings-page"}>
      <p className="muted">{t("settings.intro")}</p>

      {notice ? <p className="ok" role="status">{notice}</p> : null}
      {error ? (
        <p className="error" role="alert">
          <AlertTriangle size={14} aria-hidden /> {error}
        </p>
      ) : null}

      {draft === null ? (
        <p className="muted">{t("settings.loading")}</p>
      ) : (
        <>
          <div className="settings-grid">
            <VaultMigrationCard />
            <div className="card">
              <h3>{t("settings.autorefresh.title")}</h3>
              <p className="muted">{t("settings.autorefresh.body")}</p>
              <div className="row">
                {PRESETS.map((preset) => (
                  <button
                    key={preset.value}
                    type="button"
                    className={
                      draft.refreshIntervalSecs === preset.value
                        ? "btn btn-primary"
                        : "btn"
                    }
                    onClick={() =>
                      setDraft({ ...draft, refreshIntervalSecs: preset.value })
                    }
                  >
                    {t(preset.labelKey)}
                  </button>
                ))}
              </div>
            </div>

            <div className="card">
              <h3>{t("settings.balanceAlert.title")}</h3>
              <label className="field">
                <span>{t("settings.balanceAlert.label")}</span>
                <input
                  className="input"
                  type="number"
                  min={0}
                  step="0.5"
                  value={draft.balanceAlertThreshold}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      balanceAlertThreshold: Number(e.target.value),
                    })
                  }
                />
              </label>
            </div>

            <div className="card">
              <h3>{t("settings.startupCheck.title")}</h3>
              <label className="checkline">
                <input
                  type="checkbox"
                  checked={draft.driftCheckOnStart}
                  onChange={(e) =>
                    setDraft({ ...draft, driftCheckOnStart: e.target.checked })
                  }
                />
                <span>{t("settings.startupCheck.label")}</span>
              </label>
            </div>

            <div className="card">
              <h3>{t("settings.ui.title")}</h3>
              <label className="field">
                <span>{t("settings.ui.theme")}</span>
                <select
                  className="input"
                  value={draft.theme}
                  onChange={(e) => setDraft({ ...draft, theme: e.target.value })}
                >
                  <option value="system">{t("settings.ui.themeSystem")}</option>
                  <option value="light">{t("settings.ui.themeLight")}</option>
                  <option value="dark">{t("settings.ui.themeDark")}</option>
                </select>
              </label>
              <label className="field">
                <span>{t("settings.ui.language")}</span>
                <select
                  className="input"
                  value={draft.language}
                  onChange={(e) => setDraft({ ...draft, language: e.target.value })}
                >
                  <option value="zh-CN">{t("settings.ui.languageZh")}</option>
                  <option value="en-US">{t("settings.ui.languageEn")}</option>
                </select>
              </label>
              {/* M14-S2：语言切换已做真（前端文案随语言切换）；后端返回文本仍原文，见 spec §11 D-1/D-2 */}
              <p className="muted">{t("settings.ui.languageNote")}</p>
              <label className="field">
                <span>{t("settings.ui.proxy")}</span>
                <div className="radio-row">
                  <label className="radio">
                    <input
                      type="radio"
                      name="proxy-mode"
                      value="auto"
                      checked={draft.proxyMode === "auto"}
                      onChange={() => setDraft({ ...draft, proxyMode: "auto" })}
                    />
                    {t("settings.ui.proxyAuto")}
                  </label>
                  <label className="radio">
                    <input
                      type="radio"
                      name="proxy-mode"
                      value="manual"
                      checked={draft.proxyMode === "manual"}
                      onChange={() => setDraft({ ...draft, proxyMode: "manual" })}
                    />
                    {t("settings.ui.proxyManual")}
                  </label>
                  <label className="radio">
                    <input
                      type="radio"
                      name="proxy-mode"
                      value="direct"
                      checked={draft.proxyMode === "direct"}
                      onChange={() => setDraft({ ...draft, proxyMode: "direct" })}
                    />
                    {t("settings.ui.proxyDirect")}
                  </label>
                </div>
              </label>
              {draft.proxyMode === "auto" && (
                <p className="muted">
                  {detected.data && detected.data.source ? (
                    <>
                      {t("settings.ui.proxyAutoDetectedPre")}<code>{detected.data.maskedUrl}</code>
                      {t("settings.ui.proxyAutoDetectedMid", { source: proxySourceLabel(detected.data.source) })}
                    </>
                  ) : (
                    t("settings.ui.proxyAutoNone")
                  )}{" "}
                  <button
                    type="button"
                    className="btn btn-ghost"
                    onClick={() => detected.refetch()}
                    disabled={detected.isFetching}
                  >
                    {detected.isFetching ? t("settings.ui.proxyDetecting") : t("settings.ui.proxyDetectBtn")}
                  </button>
                </p>
              )}
              {draft.proxyMode === "manual" && (
                <label className="field">
                  <span>{t("settings.ui.proxyManualLabel")}</span>
                  <input
                    className="input"
                    type="text"
                    placeholder={t("settings.ui.proxyManualPlaceholder")}
                    value={draft.proxyUrl}
                    onChange={(e) => setDraft({ ...draft, proxyUrl: e.target.value })}
                  />
                </label>
              )}
              {draft.proxyMode === "direct" && <p className="muted">{t("settings.ui.proxyDirectNote")}</p>}
              <p className="muted">{t("settings.ui.proxyHint")}</p>
            </div>

            <div className="card">
              <h3>{t("settings.notify.title")}</h3>
              <p className="muted">{t("settings.notify.body")}</p>
              {/*
                M16-S9：总开关。**默认关** —— 关着时服务层不装通知状态（不评估、不落基线、
                不弹通知、不发 webhook），与「通知功能从未接线」逐字相同。
                关着时下面三项**禁用**而不是隐藏：让用户看得见「功能存在、但被总开关关掉了」。
              */}
              <label className="checkline">
                <input
                  type="checkbox"
                  checked={draft.notifyEnabled}
                  onChange={(e) =>
                    setDraft({ ...draft, notifyEnabled: e.target.checked })
                  }
                />
                <span>{t("settings.notify.enabled")}</span>
              </label>
              {!draft.notifyEnabled ? (
                <p className="muted">{t("settings.notify.enabledHint")}</p>
              ) : null}
              <label className="checkline">
                <input
                  type="checkbox"
                  checked={draft.notifySystemEnabled}
                  disabled={!draft.notifyEnabled}
                  onChange={(e) =>
                    setDraft({ ...draft, notifySystemEnabled: e.target.checked })
                  }
                />
                <span>{t("settings.notify.system")}</span>
              </label>
              <label className="field">
                <span>{t("settings.notify.webhookUrl")}</span>
                <input
                  className="input"
                  type="text"
                  disabled={!draft.notifyEnabled}
                  placeholder={t("settings.notify.webhookPlaceholder")}
                  value={draft.notifyWebhookUrl}
                  onChange={(e) =>
                    setDraft({ ...draft, notifyWebhookUrl: e.target.value })
                  }
                />
              </label>
              <label className="field">
                <span>{t("settings.notify.webhookTimeout")}</span>
                <input
                  className="input"
                  type="number"
                  disabled={!draft.notifyEnabled}
                  min={1}
                  max={60}
                  value={draft.notifyTimeoutSecs}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      notifyTimeoutSecs: Number(e.target.value),
                    })
                  }
                />
              </label>
              <p className="muted">
                {t("settings.notify.webhookHintPre")}<code>{t("settings.notify.webhookHintCode")}</code>{t("settings.notify.webhookHintPost")}
              </p>
            </div>

            <div className="card">
              <h3>{t("settings.rotation.title")}</h3>
              <p className="muted">{t("settings.rotation.body")}</p>
              <label className="field">
                <span>{t("settings.rotation.maxAge")}</span>
                <input
                  className="input"
                  type="number"
                  min={0}
                  value={draft.rotationMaxAgeDays}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      rotationMaxAgeDays: Number(e.target.value),
                    })
                  }
                />
              </label>
              <label className="field">
                <span>{t("settings.rotation.warnBefore")}</span>
                <input
                  className="input"
                  type="number"
                  min={0}
                  value={draft.rotationWarnBeforeDays}
                  onChange={(e) =>
                    setDraft({
                      ...draft,
                      rotationWarnBeforeDays: Number(e.target.value),
                    })
                  }
                />
              </label>
              {draft.rotationMaxAgeDays > 0 &&
              draft.rotationWarnBeforeDays > draft.rotationMaxAgeDays ? (
                <p className="error" role="alert">
                  <AlertTriangle size={14} aria-hidden /> {t("settings.rotation.error")}
                </p>
              ) : null}
            </div>

            <div className="card">
              <h3>{t("settings.autostart.title")}</h3>
              <label className="checkline">
                <input
                  type="checkbox"
                  checked={draft.closeToTray}
                  onChange={(e) =>
                    setDraft({ ...draft, closeToTray: e.target.checked })
                  }
                />
                <span>{t("settings.autostart.closeToTray")}</span>
              </label>
              <label className="checkline">
                <input
                  type="checkbox"
                  checked={draft.startHidden}
                  onChange={(e) =>
                    setDraft({ ...draft, startHidden: e.target.checked })
                  }
                />
                <span>{t("settings.autostart.startHidden")}</span>
              </label>
              <label className="checkline">
                <input
                  type="checkbox"
                  checked={draft.autostartEnabled}
                  onChange={(e) =>
                    setDraft({ ...draft, autostartEnabled: e.target.checked })
                  }
                />
                <span>
                  {t("settings.autostart.autostartLabelPre")}<code>{t("settings.autostart.autostartLabelCode")}</code>{t("settings.autostart.autostartLabelPost")}
                </span>
              </label>
              {/*
                开关只是一个「意愿」，磁盘上的自启项才是事实（M6-S7 审计 §4-3）。
                只写不读会让界面长期显示一个已经不成立的结论——用户手工删掉 plist、
                系统清理了自启项、或写在别的用户目录下，界面都看不出来。
              */}
              <p className="muted">
                {t("settings.autostart.actualState")}
                {autostart.isLoading
                  ? t("settings.autostart.stateLoading")
                  : autostart.isError
                    ? t("settings.autostart.stateError", { error: (autostart.error as Error).message })
                    : ` ${autostartStateLabel(autostart.data!.state)}`}
              </p>
              {autostartMismatch ? (
                <p className="warnline" role="alert">
                  <AlertTriangle size={14} aria-hidden />
                  {t("settings.autostart.mismatchPre")}{autostartMismatch}{t("settings.autostart.mismatchPost")}
                </p>
              ) : null}
            </div>

            <div className="card">
              <h3>{t("settings.privacy.title")}</h3>
              <label className="checkline">
                <input
                  type="checkbox"
                  checked={draft.telemetryEnabled}
                  onChange={(e) =>
                    setDraft({ ...draft, telemetryEnabled: e.target.checked })
                  }
                />
                <span>
                  {t("settings.privacy.telemetryPre")}<strong>{t("settings.privacy.telemetryStrong")}</strong>{t("settings.privacy.telemetryPost")}
                </span>
              </label>
              <label className="checkline">
                <input
                  type="checkbox"
                  checked={draft.autoUpdateEnabled}
                  onChange={(e) =>
                    setDraft({ ...draft, autoUpdateEnabled: e.target.checked })
                  }
                />
                <span>{t("settings.privacy.autoUpdate")}</span>
              </label>
            </div>
          </div>
          <div className="row">
            <label style={{ fontWeight: 600, marginBottom: 4 }}>{t("settings.updateTitle")}</label>
            <UpdateChecker autoCheckOnMount={current.data?.autoUpdateEnabled ?? false} />
          </div>

          <div className={dirty ? "row settings-savebar floating" : "row settings-savebar"}>
            <button
              type="button"
              className="btn btn-primary"
              disabled={!dirty || save.isPending}
              onClick={() => {
                if (!draft) return;
                // 提交前校验（M8-S5B §6.6）：不合法就不发请求，并说清是哪一字段
                const problem = validateDraft(draft);
                if (problem !== null) {
                  setNotice(null);
                  setError(problem);
                  return;
                }
                setError(null);
                save.mutate(draft);
              }}
            >
              <Save size={14} aria-hidden /> {t("settings.save.btn")}
            </button>
            {dirty ? <span className="muted">{t("settings.save.dirty")}</span> : null}
          </div>

          <div className="card">
            <h3>{t("settings.gatewayAutoStart.title")}</h3>
            <label className="checkline">
              <input
                type="checkbox"
                checked={draft.gatewayAutoStart}
                onChange={(e) =>
                  setDraft({ ...draft, gatewayAutoStart: e.target.checked })
                }
              />
              <span>{t("settings.gatewayAutoStart.label")}</span>
            </label>
            <p className="muted">{t("settings.gatewayAutoStart.hint")}</p>
            <label className="field">
              <span>{t("settings.gatewayTokenGrace.label")}</span>
              <input
                type="number"
                min={0}
                max={3600}
                value={draft.gatewayTokenGraceSecs}
                onChange={(e) => {
                  const parsed = Number.parseInt(e.target.value, 10);
                  setDraft({
                    ...draft,
                    gatewayTokenGraceSecs: Number.isFinite(parsed)
                      ? Math.max(0, Math.min(3600, parsed))
                      : 0,
                  });
                }}
              />
            </label>
            <p className="muted">{t("settings.gatewayTokenGrace.hint")}</p>
          </div>
          <GatewayCard
            enabled={draft.gatewayEnabled}
            port={draft.gatewayPort}
            multiSite={draft.gatewayMultiSite}
            collectModels={draft.collectModels}
            modelsMinIntervalSecs={draft.modelsMinIntervalSecs}
            maxRequestMib={draft.gatewayMaxRequestMib}
            perSiteBurst={draft.gatewayPerSiteBurst}
            onToggle={(enabled) => setDraft({ ...draft, gatewayEnabled: enabled })}
            onPortChange={(port) => setDraft({ ...draft, gatewayPort: port })}
            onMultiSiteChange={(multiSite) =>
              setDraft({ ...draft, gatewayMultiSite: multiSite })
            }
            onCollectModelsChange={(collectModels) =>
              setDraft({ ...draft, collectModels })
            }
            onModelsIntervalChange={(modelsMinIntervalSecs) =>
              setDraft({ ...draft, modelsMinIntervalSecs })
            }
            onMaxRequestMibChange={(gatewayMaxRequestMib) =>
              setDraft({ ...draft, gatewayMaxRequestMib })
            }
            onPerSiteBurstChange={(gatewayPerSiteBurst) =>
              setDraft({ ...draft, gatewayPerSiteBurst })
            }
            settingsDirty={dirty}
          />

          <AliasCard />

          <ExportCard />

          <KeychainCard />

          <AuditCard />
        </>
      )}
    </section>
  );
}
