import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, FlaskConical, Loader2 } from "lucide-react";
import {
  listSites,
  listStoredKeys,
  probeRun,
  listProbeRuns,
  type ProbeRun,
  type ProbeRunRow,
  type StoredKeyRow,
} from "../lib/api";
import { useTranslation, translate, getCurrentDict } from "../i18n";

/**
 * 模型检测（M15-S1 / bazaarlink probe）。
 *
 * 把站点 key 发给第三方 bazaarlink.ai 检测模型真伪。**apiKey 外流**——必须勾选同意。
 * 结果摘要落本地历史（probe_runs），不落 items[].response 等敏感字段。
 *
 * M18-S1：主路径改为「异步提交 + 轮询到终态」，一次检测的整体等待时间从秒级变成
 * **可达 15 分钟**（真机实测单次 187–360s）。所以进行中除转圈外必须显示已等待时长，
 * 否则用户会把一段正常的等待当成卡死。
 */
export default function Probe() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });
  const keys = useQuery({ queryKey: ["stored-keys"], queryFn: listStoredKeys });
  const history = useQuery({ queryKey: ["probe-runs"], queryFn: () => listProbeRuns(50) });

  const [siteId, setSiteId] = useState<number | null>(null);
  const [keyId, setKeyId] = useState<number | null>(null);
  const [modelId, setModelId] = useState("");
  const [claimedModel, setClaimedModel] = useState("");
  const [baseUrlOverride, setBaseUrlOverride] = useState("");
  const [agreed, setAgreed] = useState(false);
  const [result, setResult] = useState<ProbeRun | null>(null);
  /** 本次检测已等待的毫秒数。未在检测中时恒为 0。 */
  const [elapsedMs, setElapsedMs] = useState(0);
  /** 本次检测的起算时刻（`Date.now()`）。计时自点击「开始检测」起算，**不是**自组件挂载。 */
  const startedAtRef = useRef(0);

  const activeSiteId = siteId ?? sites.data?.[0]?.id ?? null;
  const activeSite = (sites.data ?? []).find((s) => s.id === activeSiteId);
  // 已删除的密钥（`revoked`，只可能是旧版本留下的行）不列出来：拿它探测只会在
  // `ensure_not_revoked` 上被拒（M47-S1）。
  const siteKeys = (keys.data ?? []).filter(
    (k: StoredKeyRow) => k.siteId === activeSiteId && k.status !== "revoked",
  );

  const defaultBaseUrl = activeSite
    ? activeSite.baseUrl.replace(/\/+$/, "") +
      (activeSite.baseUrl.endsWith("/v1") ? "" : "/v1")
    : "";

  const mutation = useMutation({
    mutationFn: probeRun,
    onSuccess: (run) => {
      setResult(run);
      qc.invalidateQueries({ queryKey: ["probe-runs"] });
    },
  });

  // 只在检测进行中走表；请求一结束（成功/失败/中止）或组件卸载，必须把定时器清掉，
  // 否则它会一直对着已收尾的界面（或已卸载的组件）每秒 setState。
  const pending = mutation.isPending;
  useEffect(() => {
    if (!pending) return;
    const timer = window.setInterval(() => {
      setElapsedMs(Date.now() - startedAtRef.current);
    }, 1000);
    return () => window.clearInterval(timer);
  }, [pending]);

  const canSubmit =
    activeSiteId !== null &&
    keyId !== null &&
    modelId.trim() !== "" &&
    agreed;

  function submit() {
    if (!canSubmit || keyId === null) return;
    setResult(null);
    // M18-S1：计时归零并重设起算点。放这里而不是挂载时——挂载时刻与用户点「开始检测」
    // 之间可能隔着很久（填表单、翻历史），拿挂载时刻当起点会一上来就显示几分钟。
    startedAtRef.current = Date.now();
    setElapsedMs(0);
    mutation.mutate({
      keyId,
      modelId: modelId.trim(),
      claimedModel: claimedModel.trim() || null,
      baseUrlOverride: baseUrlOverride.trim() || null,
      confirm: true,
    });
  }

  return (
    <div className="page probe-page">
      <section className="card">
        <h2>{t("probe.target")}</h2>
        <div className="probe-form">
          <label className="probe-field">
            <span>{t("probe.site")}</span>
            <select
              className="input"
              value={activeSiteId ?? ""}
              onChange={(e) => {
                setSiteId(e.target.value ? Number(e.target.value) : null);
                setKeyId(null);
              }}
            >
              {(sites.data ?? []).map((s) => (
                <option key={s.id} value={s.id}>
                  {s.displayName || s.baseUrl}
                </option>
              ))}
            </select>
          </label>
          <label className="probe-field">
            <span>{t("probe.key")}</span>
            <select
              className="input"
              value={keyId ?? ""}
              onChange={(e) => setKeyId(e.target.value ? Number(e.target.value) : null)}
              disabled={siteKeys.length === 0}
            >
              <option value="">
                {siteKeys.length === 0 ? t("probe.noKey") : t("probe.selectKey")}
              </option>
              {siteKeys.map((k) => (
                <option key={k.id} value={k.id}>
                  {k.name}
                </option>
              ))}
            </select>
          </label>
          <label className="probe-field">
            <span>{t("probe.modelId")}</span>
            <input
              className="input"
              value={modelId}
              onChange={(e) => setModelId(e.target.value)}
              placeholder="vendor/model-name"
            />
          </label>
          <label className="probe-field">
            <span>{t("probe.claimedModel")}</span>
            <input
              className="input"
              value={claimedModel}
              onChange={(e) => setClaimedModel(e.target.value)}
              placeholder={modelId || "vendor/model-name"}
            />
          </label>
          <label className="probe-field probe-field-wide">
            <span>{t("probe.baseUrl")}</span>
            <input
              className="input"
              value={baseUrlOverride}
              onChange={(e) => setBaseUrlOverride(e.target.value)}
              placeholder={defaultBaseUrl}
            />
          </label>
          <label className="checkbox-row probe-field probe-field-wide probe-consent">
            <input
              type="checkbox"
              checked={agreed}
              onChange={(e) => setAgreed(e.target.checked)}
            />
            <span>{t("probe.consent")}</span>
          </label>
          <div className="probe-actions">
            {mutation.isPending ? (
              <button className="btn btn-primary" disabled>
                <Loader2 size={14} className="spinning" /> {t("probe.running")}
              </button>
            ) : (
              <button className="btn btn-primary" onClick={submit} disabled={!canSubmit}>
                <FlaskConical size={14} /> {t("probe.start")}
              </button>
            )}
          </div>
        </div>
        {mutation.isPending ? (
          <div className="probe-progress">
            <p className="mono">{t("probe.elapsed", { time: formatElapsed(elapsedMs) })}</p>
            <p className="muted">{t("probe.elapsedHint")}</p>
          </div>
        ) : null}
        {mutation.error ? (
          <p className="error" role="alert">
            <AlertTriangle size={14} aria-hidden />{" "}
            {(mutation.error as Error).message}
          </p>
        ) : null}
      </section>

      {result ? (
        <section className="card">
          <h2>{t("probe.result")}</h2>
          <VerdictCard run={result} />
        </section>
      ) : null}

      <section className="card">
        <h2>{t("probe.history")}</h2>
        {history.isLoading ? <p className="empty">{t("probe.loading")}</p> : null}
        {history.data && history.data.length === 0 ? (
          <p className="empty">{t("probe.empty")}</p>
        ) : null}
        {history.data && history.data.length > 0 ? (
          <div className="table-wrap">
            <table className="table probe-history-table">
              <thead>
                <tr>
                  <th>{t("probe.colTime")}</th>
                  <th>{t("probe.colSite")}</th>
                  <th>{t("probe.colModel")}</th>
                  <th>{t("probe.colVerdict")}</th>
                  <th>{t("probe.colStatus")}</th>
                  <th>{t("probe.colTrueModel")}</th>
                  <th>{t("probe.colConfidence")}</th>
                </tr>
              </thead>
              <tbody>
                {history.data.map((r: ProbeRunRow) => (
                  <tr key={r.id}>
                    <td>{new Date(r.recordedAt * 1000).toLocaleString()}</td>
                    <td>{siteName(sites.data, r.siteId)}</td>
                    <td className="mono">{r.modelId}</td>
                    <td>{verdictLabel(r.verdictStatus)}</td>
                    <td>{runStatusLabel(r.status)}</td>
                    <td className="mono">{r.trueModel ?? "—"}</td>
                    <td>{r.confidence ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>
    </div>
  );
}

function VerdictCard({ run }: { run: ProbeRun }) {
  const ok = run.identityStatus === "match";
  const bad = run.identityStatus === "mismatch";
  const d = getCurrentDict();
  return (
    <div className={"verdict-card " + (ok ? "ok" : bad ? "bad" : "uncertain")}>
      <div className="verdict-head">
        <span className="verdict-status">
          {verdictLabel(run.verdictStatus)}
        </span>
        <span className="verdict-identity">
          {identityLabel(run.identityStatus)}
        </span>
      </div>
      <dl className="verdict-grid">
        <dt>{translate(d, "probe.trueFamily")}</dt>
        <dd className="mono">{run.trueFamily ?? "—"}</dd>
        <dt>{translate(d, "probe.trueModel")}</dt>
        <dd className="mono">{run.trueModel ?? "—"}</dd>
        <dt>{translate(d, "probe.spoofMethod")}</dt>
        <dd className="mono">{run.spoofMethod ?? "—"}</dd>
        <dt>{translate(d, "probe.confidence")}</dt>
        <dd>{run.confidence ?? "—"}</dd>
        <dt>{translate(d, "probe.warningsCount")}</dt>
        <dd>{run.warningsCount}</dd>
        <dt>{translate(d, "probe.runStatus")}</dt>
        <dd>{runStatusLabel(run.status)}</dd>
        {run.reportUrl ? (
          <>
            <dt>{translate(d, "probe.report")}</dt>
            <dd className="mono">{run.reportUrl}</dd>
          </>
        ) : null}
      </dl>
    </div>
  );
}

function siteName(
  sites: { id: number; displayName: string; baseUrl: string }[] | undefined,
  id: number,
): string {
  const s = sites?.find((x) => x.id === id);
  return s ? s.displayName || s.baseUrl : `#${id}`;
}

/**
 * 毫秒 → `分:秒`（`3:21`）。秒固定补零，分钟不补——轮询预算 900s 就是 `15:00`，
 * 这个量级的读数不需要 `00:03` 那种前导零。负值（系统时钟回拨）钳到 `0:00`。
 */
function formatElapsed(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  return `${Math.floor(total / 60)}:${String(total % 60).padStart(2, "0")}`;
}

/**
 * 判定标签。`null` 不是「没有文案」，而是一个**真实结果**：bazaarlink 跑完了但没给出
 * 身份判定（真机实测：key 访问不了该模型时秒级返回 completed、无 identityAssessment）。
 * 旧实现返回空串 ⇒ 历史表整列空白、结果卡退回显示生命周期词 `completed`，两者都像成功。
 */
function verdictLabel(status?: string | null): string {
  if (!status) return translate(getCurrentDict(), "probe.verdict.none");
  return translate(getCurrentDict(), `probe.verdict.${status}`);
}

function identityLabel(status?: string | null): string {
  if (!status) return "—";
  return translate(getCurrentDict(), `probe.identity.${status}`);
}

/**
 * run 生命周期标签（B-135）。
 *
 * 这一列是为了让历史表能分开两种「判定为空」：
 * - `completed` + 判定空 = **跑完了但没给判定**（key 访问不了该模型）；
 * - `running` + 判定空 = **没跑完**（轮询兜底也用尽次数了）。
 * 只靠 verdict 一列，两者长得一模一样。
 *
 * `null` = 老库的行（status 列是 v6 才加的，没记过状态）——显示 "—"，不猜。
 */
function runStatusLabel(status?: string | null): string {
  if (!status) return "—";
  const key = `probe.status.${status}`;
  const label = translate(getCurrentDict(), key);
  // 词表外的状态原样显示（bazaarlink schema 自陈 may evolve）
  return label === key ? status : label;
}
