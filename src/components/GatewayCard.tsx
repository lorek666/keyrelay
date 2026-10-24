import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Copy, Play, RefreshCw, Square } from "lucide-react";
import {
  channelOfBinding,
  deliveryPlan,
  gatewayRotateToken,
  gatewayStart,
  gatewayStatus,
  gatewayStop,
  gatewayTokenCreate,
  gatewayTokenList,
  gatewayTokenRevoke,
  listChannelBindings,
  listSites,
  listStoredKeys,
  applyDelivery,
  type ChannelBinding,
  type DeliveryPlan,
  type GatewayStatus,
  type CreatedGatewayToken as GatewayTokenCreated,
  type GatewayToken,
} from "../lib/api";
import { maskRemovedValues } from "../lib/deliveryView";
import ConfirmDialog from "./ConfirmDialog";
import { useTranslation } from "../i18n";

type Props = {
  enabled: boolean;
  port: number;
  /** 跨站选路开关（M16-S6b：此前只有 DTO 字段，界面不可达）。 */
  multiSite: boolean;
  /** 模型目录采集开关（M39-S2）：独立于 multiSite，同时服务 ModelsChanged 通知与网关目录。 */
  collectModels: boolean;
  /** 采集节流间隔（秒，M39-S2）：30..=86400。 */
  modelsMinIntervalSecs: number;
  /** 网关**请求体**上限（MiB，M42-S1）：1..=64。 */
  maxRequestMib: number;
  /** 每站限流 burst（M46-S3）：令牌桶额外容量，0 = 关，0..=10000。 */
  perSiteBurst: number;
  /** 每站并发上限（M46-UI B-241）：1..=128，默认 8。 */
  perSiteConcurrency: number;
  /** 每站每秒上限（M46-UI B-241）：0 = 不限速，0..=10000。 */
  perSiteRateLimit: number;
  /** 每请求最多尝试候选数（M46-S4）：0 = 走全部候选，0..=64。 */
  maxAttempts: number;
  /** 密钥健康巡检间隔（秒，M46-UI B-237）：0 = 关，非 0 时 60..=86400。 */
  keyHealthIntervalSecs: number;
  /** 按 agent 路由规则 JSON（M46-S7）：空 = 无规则，走全局加权。 */
  routingRules: string;
  onToggle: (enabled: boolean) => void;
  onPortChange: (port: number) => void;
  onMultiSiteChange: (enabled: boolean) => void;
  onCollectModelsChange: (enabled: boolean) => void;
  onModelsIntervalChange: (secs: number) => void;
  onMaxRequestMibChange: (mib: number) => void;
  onPerSiteBurstChange: (burst: number) => void;
  onPerSiteConcurrencyChange: (n: number) => void;
  onPerSiteRateLimitChange: (n: number) => void;
  onMaxAttemptsChange: (n: number) => void;
  onKeyHealthIntervalChange: (secs: number) => void;
  /** M46-S7：路由规则 JSON 文本变更（直传，不在前端解析）。 */
  onRoutingRulesChange: (text: string) => void;
  /** 设置还没保存时提示用户先保存（端口要保存后才生效） */
  settingsDirty: boolean;
};

/**
 * 本地网关卡片。
 *
 * 网关只绑 `127.0.0.1`，并且**必须**带本地令牌——令牌在启动后显示给用户配置 agent，
 * 并**持久化在系统钥匙串**里（M8-S4 §6.4）：不持久化的话每次重启都作废 agent 配置，
 * 「换站零改动」（FR-5:158）就不成立。站点密钥永远不会离开本机。
 */
/**
 * M40-S2：网关内存指标面板。
 *
 * **空态规则（spec §4.3，违反即 bug）**：
 * - 未运行 ⇒ 只显示一行占位；**绝不**渲染 `0 req` / `0 QPS` / 空表格 / 灰色假候选。
 * - `candidates` 为空但运行中 ⇒ 「单上游模式」，不渲染空表。
 * - 刚启动（`uptimeSecs < 3`，缺失时回退 `requestsTotal < 3`）⇒ QPS 显示 `—`（样本不足，不拿 0.3 秒的窗口吹稳定值）。
 * - `lastError == null` ⇒ 显示「无」（不显示空白：读者分不清「没有」与「没加载」）。
 */
export function GatewayMetricsPanel({ status }: { status?: GatewayStatus }) {
  const { t } = useTranslation();
  if (!status || !status.running) {
    return (
      <div className="gateway-metrics">
        <p className="muted">{t("gateway.metrics.notRunning")}</p>
      </div>
    );
  }
  const candidates = status.candidates ?? [];
  const requestsTotal = status.requestsTotal ?? 0;
  // B-224（M40-S2 P2-2）：样本不足判据以后端为准（uptime < 3s）；旧
  // 客户端没给 uptimeSecs 时回退到 requestsTotal < 3，保持兼容。
  const sampleTooSmall =
    status.uptimeSecs !== undefined ? status.uptimeSecs < 3 : requestsTotal < 3;
  const qps = sampleTooSmall ? null : status.qps;
  const badge = (kind: "ok" | "warn" | "danger") => `badge badge-${kind}`;
  return (
    <div className="gateway-metrics">
      <h4>{t("gateway.metrics.title")}</h4>
      <dl className="kv">
        <dt>{t("gateway.metrics.mode")}</dt>
        <dd>{t(`gateway.metrics.modeValue.${status.mode}`)}</dd>
        <dt>{t("gateway.metrics.qps")}</dt>
        <dd className="mono" data-gateway-qps>
          {qps === null ? "—" : qps.toFixed(1)}
        </dd>
        <dt>{t("gateway.metrics.requests")}</dt>
        <dd className="mono">{requestsTotal}</dd>
        <dt>{t("gateway.metrics.inflight")}</dt>
        <dd className="mono">{status.inflight}</dd>
        <dt>{t("gateway.metrics.failovers")}</dt>
        <dd className="mono">{status.failoversTotal}</dd>
        <dt>{t("gateway.metrics.generation")}</dt>
        <dd className="mono">{status.generation}</dd>
        <dt>{t("gateway.metrics.lastError")}</dt>
        <dd>{status.lastError ?? t("gateway.metrics.none")}</dd>
      </dl>
      {candidates.length === 0 ? (
        <p className="muted">{t("gateway.metrics.singleUpstream")}</p>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>{t("gateway.metrics.candidate.site")}</th>
              <th>{t("gateway.metrics.candidate.key")}</th>
              <th>{t("gateway.metrics.candidate.health")}</th>
              <th>{t("gateway.metrics.candidate.breaker")}</th>
              <th>{t("gateway.metrics.candidate.ewmaLatency")}</th>
            </tr>
          </thead>
          <tbody>
            {candidates.map((c) => (
              <tr key={`${c.siteId}-${c.keyId ?? "none"}-${c.displayName}`}>
                <td>{c.displayName}</td>
                <td className="mono">{c.keyId ?? "—"}</td>
                <td>
                  <span
                    className={badge(
                      c.health === "healthy" ? "ok" : c.health === "exhausted" ? "danger" : "warn",
                    )}
                  >
                    {t(`gateway.metrics.health.${c.health}`)}
                  </span>
                </td>
                <td>
                  <span
                    className={badge(
                      c.breaker === "closed" ? "ok" : c.breaker === "open" ? "danger" : "warn",
                    )}
                  >
                    {t(`gateway.metrics.breaker.${c.breaker}`)}
                  </span>
                </td>
                {/*
                  M46-UI B-240：每站 EWMA 延迟（毫秒，键为站点 id，见 M46-S2）。
                  红线：无样本必须显示 `—`，绝不得画成 0——所以这里用 `== null`
                  判空，不用 `||` / 三元真值判断（EWMA 真为 0ms 时必须显示 `0 ms`，
                  不能被真值判断吞成 `—`）。旧后端无此字段时 map 为 undefined，
                  同样回退到 `—`。
                */}
                <td className="mono">
                  {(status.ewmaLatencyMs ?? {})[c.siteId] == null
                    ? "—"
                    : `${(status.ewmaLatencyMs ?? {})[c.siteId]} ms`}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

type RoutingRuleRow = {
  agentLabel: string;
  siteIds: number[];
};

/**
 * 解析路由规则 JSON 文本为结构化行（M46-UI B-255）。
 * - "" / "[]" ⇒ 空行表（结构化视图）。
 * - 非数组、行不是对象、agentLabel 不是字符串、siteIds 不是数组、站 id 不是
 *   正整数 ⇒ 不可解析（回退原文编辑，不丢用户文本）。
 * - 行内 siteIds 按序去重（与后端 validate 的归一方向一致，但这里只是展示
 *   归一，不拒传：解析权威仍在后端）。
 * - agent 为空或站点为空的行仍可解析（渲染时挂未填完整提示，保存时由后端
 *   拒绝整单并回显后端文案）。
 */
function parseRoutingRules(
  text: string,
): { ok: true; rows: RoutingRuleRow[] } | { ok: false } {
  const trimmed = text.trim();
  if (trimmed === "") return { ok: true, rows: [] };
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return { ok: false };
  }
  if (!Array.isArray(parsed)) return { ok: false };
  const rows: RoutingRuleRow[] = [];
  for (const entry of parsed) {
    if (typeof entry !== "object" || entry === null) return { ok: false };
    const { agentLabel, siteIds } = entry as {
      agentLabel?: unknown;
      siteIds?: unknown;
    };
    if (typeof agentLabel !== "string" || !Array.isArray(siteIds)) {
      return { ok: false };
    }
    const ids: number[] = [];
    for (const id of siteIds) {
      if (typeof id !== "number" || !Number.isInteger(id) || id <= 0) {
        return { ok: false };
      }
      if (!ids.includes(id)) ids.push(id);
    }
    rows.push({ agentLabel, siteIds: ids });
  }
  return { ok: true, rows };
}

/**
 * M46-UI B-255：按 agent 路由规则的结构化编辑器。
 *
 * 同步策略（关键，别改错）：行状态是本地 state，prop 变化时只有「外部变化」
 * 才重解析——结构化编辑器自己发出的文本经草稿回流到 prop 时（`=== lastEmitted`）
 * 必须跳过，否则每改一次都会把编辑中的行重置。保存重载、切页回来等外部
 * 变化会走到重解析分支。回退 textarea 是例外：它的值直接就是 prop，没有
 * 编辑中状态可言，故 onChange 故意不写 lastEmitted，每次回流都重解析——
 * 非法→仍回落（不丢文本），合法→立即翻回结构化视图。不可解析的文本不丢：
 * 回退到原文 textarea（即今天的行为）+ 一行提示。
 *
 * 校验分工：前端只做「未填完整」的行级提示（agent 为空或站点为空），不拦
 * 截、不拒传；解析权威与报错文案都在后端 validate——前端复写一套校验必然
 * 与后端分叉，还可能拒传合法规则。
 */
function RoutingRulesEditor({
  // 合并修复（main ← feat-m46-ui）：老用例渲染 GatewayCard 时不传
  // routingRules（M46-UI-5 之前不存在这个 prop），undefined 若直进
  // parseRoutingRules 会在 .trim() 上炸掉整卡。空 = 无规则，与后端
  // “空串 = 无规则”语义一致；这里缺省，不改 Props 的必填约定。
  routingRules = "",
  onRoutingRulesChange,
  sites,
  tokenLabels,
}: {
  routingRules: string;
  onRoutingRulesChange: (text: string) => void;
  sites: { id: number; displayName: string }[];
  tokenLabels: string[];
}) {
  const { t } = useTranslation();
  const initial = parseRoutingRules(routingRules);
  const [rows, setRows] = useState<RoutingRuleRow[]>(initial.ok ? initial.rows : []);
  const [fallback, setFallback] = useState(!initial.ok);
  const lastEmitted = useRef(routingRules);
  useEffect(() => {
    if (routingRules !== lastEmitted.current) {
      lastEmitted.current = routingRules;
      const parsed = parseRoutingRules(routingRules);
      setFallback(!parsed.ok);
      setRows(parsed.ok ? parsed.rows : []);
    }
  }, [routingRules]);

  const emit = (next: RoutingRuleRow[]) => {
    const text = JSON.stringify(next);
    lastEmitted.current = text;
    onRoutingRulesChange(text);
  };
  const updateRow = (index: number, patch: Partial<RoutingRuleRow>) => {
    const next = rows.map((r, i) => (i === index ? { ...r, ...patch } : r));
    setRows(next);
    emit(next);
  };
  const addRow = () => {
    const next = [...rows, { agentLabel: "", siteIds: [] }];
    setRows(next);
    emit(next);
  };
  const deleteRow = (index: number) => {
    const next = rows.filter((_, i) => i !== index);
    setRows(next);
    emit(next);
  };

  if (fallback) {
    return (
      <div>
        <p className="muted">{t("gateway.routingRulesFallbackNote")}</p>
        <textarea
          className="input"
          rows={4}
          aria-label={t("gateway.routingRulesLabel")}
          value={routingRules}
          onChange={(e) => {
            // M46-UI-5 复审 P1-1：回退 textarea 故意不写 lastEmitted。它的值
            // 直接就是 prop，没有“编辑中状态会被重解析冲掉”的风险；若也写
            // lastEmitted，保存重载回来的字符串与它相等，useEffect 永远
            // 跳过，fallback 会粘住、合法文本也回不到结构化视图。不写它，
            // 每次回流都会重解析：非法→仍回落（不丢文本），合法→立即翻回
            // 结构化视图（比文案承诺的“保存重载”更早，但不矛盾）。
            onRoutingRulesChange(e.target.value);
          }}
        />
      </div>
    );
  }

  // 下拉选项 = 可用令牌 label + 各行已有的 label（后者兜底：某行引用的令牌
  // 若已被吊销，选项里仍保留它，否则该行 agent 会显示空白、值还会被改写掉）。
  const options = [...new Set([...tokenLabels, ...rows.map((r) => r.agentLabel)])].filter(
    (l) => l !== "",
  );
  return (
    <div>
      {tokenLabels.length === 0 ? (
        <p className="muted">{t("gateway.routingRulesNoTokens")}</p>
      ) : null}
      {rows.map((row, i) => {
        const incomplete =
          row.agentLabel.trim() === "" || row.siteIds.length === 0;
        return (
          <div key={i} data-routing-row={i} className="row">
            <select
              className="input"
              aria-label={t("gateway.routingRulesAgent")}
              value={row.agentLabel}
              onChange={(e) => updateRow(i, { agentLabel: e.target.value })}
            >
              <option value="">{t("gateway.routingRulesAgentPlaceholder")}</option>
              {options.map((label) => (
                <option key={label} value={label}>
                  {label}
                </option>
              ))}
            </select>
            <span>{t("gateway.routingRulesSites")}</span>
            {sites.map((s) => (
              <label key={s.id} className="checkline">
                <input
                  type="checkbox"
                  checked={row.siteIds.includes(s.id)}
                  onChange={(e) => {
                    const next = e.target.checked
                      ? [...row.siteIds, s.id]
                      : row.siteIds.filter((id) => id !== s.id);
                    updateRow(i, { siteIds: next });
                  }}
                />
                <span>{s.displayName}</span>
              </label>
            ))}
            <button type="button" className="btn btn-ghost" onClick={() => deleteRow(i)}>
              {t("gateway.routingRulesDeleteRow")}
            </button>
            {incomplete ? (
              <p className="muted">{t("gateway.routingRulesRowIncomplete")}</p>
            ) : null}
          </div>
        );
      })}
      <button type="button" className="btn" onClick={addRow}>
        {t("gateway.routingRulesAddRow")}
      </button>
    </div>
  );
}

export default function GatewayCard({
  enabled,
  port,
  multiSite,
  collectModels,
  modelsMinIntervalSecs,
  maxRequestMib,
  perSiteBurst,
  perSiteConcurrency,
  perSiteRateLimit,
  maxAttempts,
  keyHealthIntervalSecs,
  routingRules,
  onToggle,
  onPortChange,
  onMultiSiteChange,
  onCollectModelsChange,
  onModelsIntervalChange,
  onMaxRequestMibChange,
  onPerSiteBurstChange,
  onPerSiteConcurrencyChange,
  onPerSiteRateLimitChange,
  onMaxAttemptsChange,
  onKeyHealthIntervalChange,
  onRoutingRulesChange,
  settingsDirty,
}: Props) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const status = useQuery({ queryKey: ["gateway"], queryFn: gatewayStatus });
  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });
  const keys = useQuery({ queryKey: ["stored-keys"], queryFn: listStoredKeys });

  const [siteId, setSiteId] = useState<number | null>(null);
  const [keyId, setKeyId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [rotated, setRotated] = useState(false);
  // 采集间隔的**输入框草稿**：允许用户先输 `5` 再输 `50`，失焦时才钳制到 [30, 86400]。
  const [intervalText, setIntervalText] = useState(String(modelsMinIntervalSecs));
  const [clamped, setClamped] = useState(false);
  // M39-S2 复审补充：后端重新加载 / 保存成功后 `modelsMinIntervalSecs` 会变，
  // 输入框必须跟着走（否则显示的是首次挂载时的旧值）。钳制提示同时复位。
  useEffect(() => {
    setIntervalText(String(modelsMinIntervalSecs));
    setClamped(false);
  }, [modelsMinIntervalSecs]);

  // M46-UI B-237：巡检间隔输入框草稿，口径与采集间隔输入框相同（先输草稿，
  // 失焦时才钳制）。合法值是 0（关）或 60..=86400：直接拒传会让用户输不出
  // 60（先输 `6` 即被拒），所以必须走草稿 + 失焦钳制。
  const [healthIntervalText, setHealthIntervalText] = useState(
    String(keyHealthIntervalSecs),
  );
  const [healthClamped, setHealthClamped] = useState(false);
  useEffect(() => {
    setHealthIntervalText(String(keyHealthIntervalSecs));
    setHealthClamped(false);
  }, [keyHealthIntervalSecs]);

  const token = status.data?.token ?? "";

  // 网关重启会换一个新令牌：把「已复制」的提示清掉，免得它对着一个过期的值显示。
  useEffect(() => {
    setCopied(false);
  }, [token]);

  /**
   * 复制本地令牌到剪贴板（PRD FR-8:189）。
   *
   * 这是本产品**唯一**把秘密放进剪贴板的地方：站点密钥的明文从不到达界面
   * （命令层没有一条命令返回过明文），所以不存在「复制 key」按钮。
   * 提示是必须的——用户有权知道这个值可能被剪贴板历史记录带走；
   * 而**不**自动清空剪贴板（那会跟用户的正常复制打架，且 macOS 上无法保证）。
   */
  async function copyToken() {
    try {
      await navigator.clipboard.writeText(token);
      setError(null);
      setCopied(true);
    } catch (err) {
      setCopied(false);
      setError(t("gateway.copyFail", { error: (err as Error).message }));
    }
  }

  const activeSite = siteId ?? sites.data?.[0]?.id ?? null;
  const siteKeys = (keys.data ?? []).filter((k) => k.siteId === activeSite);
  const activeKey = keyId ?? siteKeys[0]?.id ?? null;

  const start = useMutation({
    mutationFn: () => gatewayStart(activeSite!, activeKey!),
    onSuccess: async () => {
      setError(null);
      // P3-12：重新生成令牌后停启网关 ⇒ 新令牌已生效，rotated 提示该清掉。
      setRotated(false);
      await qc.invalidateQueries({ queryKey: ["gateway"] });
    },
    onError: (err: Error) => setError(err.message),
  });

  const stop = useMutation({
    mutationFn: gatewayStop,
    onSuccess: async () => {
      // P3-12：停网关也清掉 rotated 提示（网关已停，旧令牌失效与否不再相关）。
      setRotated(false);
      await qc.invalidateQueries({ queryKey: ["gateway"] });
    },
    onError: (err: Error) => setError(err.message),
  });

  /**
   * 显式轮换本地令牌（M8-S4 §6.4）。
   *
   * 后端把「换令牌 + 重启网关」合成一个动作：只换钥匙串会让运行中的网关与 agent
   * 配置不一致，只重启等于没轮换。轮换后**旧令牌立即失效** ⇒ 指向网关的通道需要重新投递，
   * 所以这里必须把这句话说出来（否则用户只会看到 agent 开始 401）。
   */
  const rotate = useMutation({
    mutationFn: () => gatewayRotateToken({ siteId: activeSite!, keyId: activeKey! }),
    onSuccess: async () => {
      setError(null);
      setRotated(true);
      await qc.invalidateQueries({ queryKey: ["gateway"] });
    },
    onError: (err: Error) => setError(err.message),
  });

  /**
   * 批量改指网关（M8-S7 / B-116）。
   *
   * 四条硬约束照抄 M8-S4 §6.2 的裁定，一条不放宽：
   * 1. **逐条预览**：每条通道单独出一次 `delivery_plan`，diff 给人看；
   * 2. **不得绕过同意**：每条一个复选框，**不提供「全选」**；
   * 3. **失败不中断**：某条失败记录原因、继续下一条，最后汇总；
   * 4. **网关必须在运行**：`apply_delivery(mode="gateway")` 要读网关令牌。
   */
  const [batchOpen, setBatchOpen] = useState(false);
  /** 每条候选的勾选状态，key 是**绑定行 id**（`binding.bindingId` 的字符串形式）。 */
  const [batchPicked, setBatchPicked] = useState<Record<string, boolean>>({});
  /**
   * 逐条预览的结果（硬约束 1）。key 同上；值是后端给的**已脱敏 diff**与提示项。
   *
   * 为什么要单独一步：预览的结果必须**显示给人看**才叫「逐条预览」。
   * 第一版在执行循环里 `await deliveryPlan(...)` 却把结果丢掉了——那只是触发了一次
   * 副作用，用户什么都没看见（独立复审前的自查发现）。
   */
  const [batchPreviews, setBatchPreviews] = useState<
    Record<string, DeliveryPlan | string>
  >({});
  const [batchResults, setBatchResults] = useState<
    { label: string; ok: boolean; detail: string }[]
  >([]);

  /**
   * 按预览 key 找回那条候选（渲染 diff 标题用）。
   *
   * key 是绑定行 id ⇒ 这是 O(n) 查找。批量面板一次最多十几条，不值得建 Map。
   */
  function planOf(key: string): { channel: string | null; targetPath: string } {
    const found = batchCandidates.find((c) => c.key === key);
    return {
      channel: found?.channel ?? null,
      targetPath: found?.binding.targetPath ?? "",
    };
  }

  // ---- M43-S1：Agent 令牌（创建 / 列表 / 吊销）----
  const tokenList = useQuery({
    queryKey: ["gateway-tokens"],
    queryFn: gatewayTokenList,
  });
  const [newTokenLabel, setNewTokenLabel] = useState("");
  const [createdToken, setCreatedToken] = useState<GatewayTokenCreated | null>(
    null,
  );
  const [revokeTarget, setRevokeTarget] = useState<GatewayToken | null>(null);
  const createToken = useMutation({
    mutationFn: (label: string) => gatewayTokenCreate(label),
    onSuccess: async (created) => {
      setNewTokenLabel("");
      setCreatedToken(created);
      await qc.invalidateQueries({ queryKey: ["gateway-tokens"] });
      await qc.invalidateQueries({ queryKey: ["gateway"] });
    },
    onError: (err: Error) => setError(err.message),
  });
  const revokeToken = useMutation({
    mutationFn: (id: number) => gatewayTokenRevoke(id),
    onSuccess: async () => {
      setRevokeTarget(null);
      await qc.invalidateQueries({ queryKey: ["gateway-tokens"] });
      await qc.invalidateQueries({ queryKey: ["gateway"] });
    },
    onError: (err: Error) => {
      setRevokeTarget(null);
      setError(err.message);
    },
  });

  const batchBindings = useQuery({
    queryKey: ["channel-bindings"],
    queryFn: listChannelBindings,
    enabled: batchOpen,
  });

  /** 一条 binding ⇒ 界面上的那一行（猜不出通道的也列出来，标「无法识别」）。 */
  const batchCandidates = (batchBindings.data ?? []).map((binding: ChannelBinding) => {
    const channel = channelOfBinding(binding.agentId);
    // key 用**绑定行 id**（M8-S7 P2-4）：`bindings` 没有 UNIQUE 约束，同一文件上可能
    // 有多条未解绑的行（换 key 后重投就会这样）。用 `${channel}::${targetPath}` 会让
    // 那两行共用一个复选框（勾一个等于勾两个）并报 React 重复 key。
    return { binding, channel, key: String(binding.bindingId) };
  });

  /** 逐条预览（硬约束 1）：把勾选的每条都问一次后端，diff 显示给人看后才让执行。 */
  const batchPreview = useMutation({
    mutationFn: async () => {
      const out: Record<string, DeliveryPlan | string> = {};
      for (const { binding, channel, key } of batchCandidates) {
        if (!batchPicked[key]) continue;
        if (channel === null) {
          out[key] = t("gateway.batch.unmappedFull");
          continue;
        }
        try {
          out[key] = await deliveryPlan({
            keyId: binding.keyId,
            channel,
            mode: "gateway",
          });
        } catch (err) {
          // 预览失败也记录下来：让人看见「这条问不出来」，而不是静默跳过
          out[key] = (err as Error).message;
        }
      }
      return out;
    },
    onSuccess: (previews) => setBatchPreviews(previews),
    onError: (err: Error) => setError(err.message),
  });

  const batchApply = useMutation({
    mutationFn: async () => {
      const results: { label: string; ok: boolean; detail: string }[] = [];
      for (const { binding, channel, key } of batchCandidates) {
        if (!batchPicked[key]) continue;
        if (channel === null) {
          results.push({
            label: binding.targetPath,
            ok: false,
            detail: t("gateway.batch.unmappedApplyDetail"),
          });
          continue;
        }
        const label = `${binding.agentId} → ${binding.targetPath}`;
        try {
          // 预览已经在下面那步做给用户看过了（`batchPreviews`）；这里直接写。
          // `model` 传 `undefined` = 「沿用受管块里已有的」，与轮换第②步同一口径。
          await applyDelivery({
            keyId: binding.keyId,
            channel,
            mode: "gateway",
          });
          results.push({ label, ok: true, detail: t("gateway.batch.appliedOk") });
        } catch (err) {
          // 失败不中断：记录原因，继续下一条（硬约束 3）
          results.push({ label, ok: false, detail: (err as Error).message });
        }
      }
      return results;
    },
    onSuccess: (results) => {
      setBatchResults(results);
      setBatchOpen(false);
      setBatchPicked({});
      setBatchPreviews({});
    },
    onError: (err: Error) => setError(err.message),
  });

  const running = status.data?.running ?? false;
  // M41-S1：三态 + 结束记录。`running` 只作兼容字段，展示以 `phase` 为准。
  const phase = status.data?.phase ?? "stopped";
  const lastExit = status.data?.lastExit ?? null;
  const lastExitReason = lastExit
    ? lastExit.reason === "panicked"
      ? t("gateway.phase.reasonPanicked")
      : lastExit.reason === "requested"
        ? t("gateway.phase.reasonRequested")
        : t("gateway.phase.reasonUnexpected")
    : null;

  return (
    <div className="card">
      <h3>{t("gateway.title")}</h3>
      <p className="muted" data-gateway-phase={phase}>
        {phase === "running"
          ? t("gateway.phase.running")
          : phase === "crashed"
            ? t("gateway.phase.crashed", {
                time: lastExit
                  ? new Date(lastExit.at * 1000).toLocaleString()
                  : "—",
                reason: lastExitReason ?? "",
              })
            : t("gateway.phase.stopped")}
      </p>
      <p className="muted">
        {t("gateway.bodyPre")}<span className="mono">{t("gateway.bodyMid", { port })}</span>{t("gateway.bodyPost")}
      </p>

      <label className="checkline">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => onToggle(e.target.checked)}
        />
        <span>{t("gateway.allowLabel")}</span>
      </label>

      {/*
        跨站选路（M16-S6b 新增接线）：`settings.gateway_multi_site` 是 B-99/B-109/B-110
        「按模型跨站选路 / 模型别名 / 上游摘除与冷却回归」的**唯一开关**，此前只有 DTO 字段、
        没有任何控件 ⇒ 那三个功能对用户实际不可达。
        **不改默认值**（默认仍是关）：改默认会破坏既有用户「只用一个站点」的逐字节语义。
      */}
      <label className="checkline">
        <input
          type="checkbox"
          checked={multiSite}
          onChange={(e) => onMultiSiteChange(e.target.checked)}
        />
        <span>{t("gateway.multiSiteLabel")}</span>
      </label>
      <p className="muted">{t("gateway.multiSiteHint")}</p>

      {/*
        模型目录采集（M39-S2）。**独立开关**：它同时服务两件事——
        ① `ModelsChanged` 通知（M14-S1 起就有）；② 网关的跨站选路目录（M39-S1）。
        所以多站关闭时**仍然采集**（只是网关不用目录），这里不静默禁用、也不写
        「仅多站模式下生效」——那会误导用户以为关掉多站就没必要采集。
      */}
      <label className="checkline">
        <input
          type="checkbox"
          checked={collectModels}
          onChange={(e) => onCollectModelsChange(e.target.checked)}
        />
        <span>{t("gateway.collectModelsLabel")}</span>
      </label>
      <p className="muted">{t("gateway.collectModelsHint")}</p>

      <label className="field">
        <span>{t("gateway.modelsIntervalLabel")}</span>
        <input
          className="input settings-inline-field"
          type="number"
          min={30}
          max={86400}
          step={1}
          value={intervalText}
          onChange={(e) => setIntervalText(e.target.value)}
          // 越界/非数字 ⇒ **失焦时钳制**并提示（不边打边改，否则用户输 `5` 想输 `50` 会被打断）
          onBlur={() => {
            const parsed = Number(intervalText);
            const clamped = Number.isFinite(parsed)
              ? Math.min(86400, Math.max(30, Math.trunc(parsed)))
              : 1800;
            setIntervalText(String(clamped));
            setClamped(clamped !== parsed || String(clamped) !== intervalText);
            if (clamped !== modelsMinIntervalSecs) onModelsIntervalChange(clamped);
          }}
        />
      </label>
      <p className="muted">{t("gateway.modelsIntervalHint")}</p>
      {clamped ? <p className="muted">{t("gateway.modelsIntervalClamped")}</p> : null}

      <label className="field">
        <span>{t("gateway.portLabel")}</span>
        <input
          className="input"
          type="number"
          min={1024}
          max={65535}
          value={port}
          onChange={(e) => {
            const n = Number(e.target.value);
            // P3-14 / DEBUG-REPORT-v3 §3-14：与后端口径一致（≥1024 ≤65535）——
            // min/max 是 HTML 提示，浏览器不强制，用户仍能输入 80 等特权端口；
            // 超出范围不调 onPortChange（受控 value 不更新，输入被拒）。
            if (Number.isFinite(n) && n >= 1024 && n <= 65535) {
              onPortChange(n);
            }
          }}
        />
      </label>
      {settingsDirty ? (
        <p className="muted">{t("gateway.portDirtyHint")}</p>
      ) : null}

      {/*
        M42-S1：请求体上限（MiB）。**只**限制请求体——响应体上限是固定 64 MiB 常量，
        与这里无关（两个 64 数值相同纯属巧合）。保存后下次启动网关生效。
      */}
      <label className="field">
        <span>{t("gateway.maxRequestLabel")}</span>
        <input
          className="input"
          type="number"
          min={1}
          max={64}
          step={1}
          value={maxRequestMib}
          onChange={(e) => {
            const n = Number(e.target.value);
            // 与端口输入框同口径：越界/非整数不更新受控值（后端 validate 是第二道）
            if (Number.isInteger(n) && n >= 1 && n <= 64) {
              onMaxRequestMibChange(n);
            }
          }}
        />
      </label>
      <p className="muted">{t("gateway.maxRequestHint")}</p>

      {/*
        M46-S3：每站限流 burst。口径与请求体上限输入框相同（受控 number，
        越界/非整数不调 onChange，后端 validate 是第二道）；保存后下次启动网关生效。
        注意：设置页此前没有任何 per-site 字段的渲染位置（见 spec §4.6），本字段是
        第一个落进网关卡的 per-site 字段；并发上限与每秒上限的控件仍缺，见 BACKLOG。
      */}
      <label className="field">
        <span>{t("gateway.perSiteBurstLabel")}</span>
        <input
          className="input"
          type="number"
          min={0}
          max={10000}
          step={1}
          value={perSiteBurst}
          onChange={(e) => {
            const n = Number(e.target.value);
            if (Number.isInteger(n) && n >= 0 && n <= 10000) {
              onPerSiteBurstChange(n);
            }
          }}
        />
      </label>
      <p className="muted">{t("gateway.perSiteBurstHint")}</p>

      {/*
        M46-UI B-241：每站并发上限与每秒上限。口径与 burst 输入框相同（受控
        number，越界/非整数不调 onChange，后端 validate 是第二道）；保存后
        下次启动网关生效。两个字段都是 burst 的生效前提字段：burst 只抬高
        令牌桶容量，不提高补充速率，且 rate = 0 时桶分支整体跳过、burst 无效。
      */}
      <label className="field">
        <span>{t("gateway.perSiteConcurrencyLabel")}</span>
        <input
          className="input"
          type="number"
          min={1}
          max={128}
          step={1}
          value={perSiteConcurrency}
          onChange={(e) => {
            const n = Number(e.target.value);
            if (Number.isInteger(n) && n >= 1 && n <= 128) {
              onPerSiteConcurrencyChange(n);
            }
          }}
        />
      </label>
      <p className="muted">{t("gateway.perSiteConcurrencyHint")}</p>

      <label className="field">
        <span>{t("gateway.perSiteRateLimitLabel")}</span>
        <input
          className="input"
          type="number"
          min={0}
          max={10000}
          step={1}
          value={perSiteRateLimit}
          onChange={(e) => {
            const n = Number(e.target.value);
            if (Number.isInteger(n) && n >= 0 && n <= 10000) {
              onPerSiteRateLimitChange(n);
            }
          }}
        />
      </label>
      <p className="muted">{t("gateway.perSiteRateLimitHint")}</p>

      {/*
        M46-S4：每请求最多尝试候选数。口径与 burst 输入框相同（受控 number，
        越界/非整数不调 onChange，后端 validate 是第二道）；保存后下次启动网关生效。
      */}
      <label className="field">
        <span>{t("gateway.maxAttemptsLabel")}</span>
        <input
          className="input"
          type="number"
          min={0}
          max={64}
          step={1}
          value={maxAttempts}
          onChange={(e) => {
            const n = Number(e.target.value);
            if (Number.isInteger(n) && n >= 0 && n <= 64) {
              onMaxAttemptsChange(n);
            }
          }}
        />
      </label>
      <p className="muted">{t("gateway.maxAttemptsHint")}</p>

      {/*
        M46-UI B-237：密钥健康巡检间隔。语义与 M46-S1 一致：0 = 关，非 0 时
        60..=86400 秒；失焦时钳制（1..59 钳到 60、>86400 钳到 86400、非数字/
        清空钳到 0 = 关），钳制后提示；与采集间隔输入框同口径，保存后下次
        启动网关生效，后端 validate 是第二道。
      */}
      <label className="field">
        <span>{t("gateway.keyHealthIntervalLabel")}</span>
        <input
          className="input"
          type="number"
          min={0}
          max={86400}
          step={1}
          value={healthIntervalText}
          onChange={(e) => setHealthIntervalText(e.target.value)}
          onBlur={() => {
            const parsed = Number(healthIntervalText);
            const clamped = !Number.isFinite(parsed)
              ? 0
              : Math.trunc(parsed) <= 0
                ? 0
                : Math.min(86400, Math.max(60, Math.trunc(parsed)));
            setHealthIntervalText(String(clamped));
            setHealthClamped(
              clamped !== parsed || String(clamped) !== healthIntervalText,
            );
            if (clamped !== keyHealthIntervalSecs) {
              onKeyHealthIntervalChange(clamped);
            }
          }}
        />
      </label>
      <p className="muted">{t("gateway.keyHealthIntervalHint")}</p>
      {healthClamped ? (
        <p className="muted">{t("gateway.keyHealthIntervalClamped")}</p>
      ) : null}

      {/*
        M46-UI B-255：按 agent 路由规则改为结构化编辑器（agent 下拉取令牌
        label、站点多选、增删行、逐条未填完整提示）。解析权威仍在后端
        validate：前端不复写解析、不拦截保存，非法时保存失败并由既有设置
        保存错误路径回显后端文案。不可解析的文本回退到原文 textarea（见
        RoutingRulesEditor）。保存后下次启动网关生效。
      */}
      <div className="field">
        <span>{t("gateway.routingRulesLabel")}</span>
        <RoutingRulesEditor
          routingRules={routingRules}
          onRoutingRulesChange={onRoutingRulesChange}
          sites={sites.data ?? []}
          tokenLabels={(tokenList.data ?? [])
            .filter((tok) => tok.active)
            .map((tok) => tok.label)}
        />
      </div>
      <p className="muted">{t("gateway.routingRulesHint")}</p>

      {/* M40-S2：指标面板（**所有相位都渲染**；未运行时由面板自己显示一行占位）。 */}
      <GatewayMetricsPanel status={status.data} />

      {running ? (
        <>
          <dl className="kv">
            <dt>{t("gateway.kv.status")}</dt>
            <dd className="ok">{t("gateway.status.running")}</dd>
            <dt>{t("gateway.kv.url")}</dt>
            <dd className="mono">{status.data?.url}</dd>
            <dt>{t("gateway.kv.upstream")}</dt>
            <dd className="mono">{status.data?.site}</dd>
            <dt>{t("gateway.kv.token")}</dt>
            <dd className="mono ellipsis" title={status.data?.token ?? ""}>
              {status.data?.token}
            </dd>
            <dt>{t("gateway.kv.listenAddrs")}</dt>
            <dd className="mono" data-gateway-listen-addrs>
              {(status.data?.listenAddrs ?? []).join("、") || "—"}
            </dd>
            <dt>{t("gateway.kv.tokenStorage")}</dt>
            <dd>
              {status.data?.tokenPersistent ? (
                <span className="badge badge-ok">{t("gateway.status.persistent")}</span>
              ) : (
                <span className="badge badge-warn">{t("gateway.status.temporary")}</span>
              )}
            </dd>
          </dl>
          {status.data?.ipv6Degraded ? (
            <p className="warn" data-gateway-ipv6="degraded">
              {t("gateway.ipv6Degraded", { note: status.data?.ipv6Note ?? "" })}
            </p>
          ) : null}
          <p className="muted">{t("gateway.hint")}</p>
          {status.data?.tokenPersistent ? (
            <p className="muted">{t("gateway.persistentHint")}</p>
          ) : (
            <p className="muted">
              {t("gateway.temporaryHintPre")}<strong>{t("gateway.temporaryHintStrong")}</strong>{t("gateway.temporaryHintPost")}
            </p>
          )}
          <div className="row">
            <button type="button" className="btn" onClick={copyToken}>
              <Copy size={14} aria-hidden /> {t("gateway.btn.copy")}
            </button>
            <button
              type="button"
              className="btn btn-danger"
              disabled={rotate.isPending}
              onClick={() => {
                // P3-12 / DEBUG-REPORT-v3 §3-12：重新生成令牌是危险操作（旧令牌
                // 立即失效，指向网关的通道要重投、agent 要重启）——二次确认，避免误点。
                if (window.confirm(t("gateway.rotateConfirm"))) {
                  rotate.mutate();
                }
              }}
            >
              <RefreshCw size={14} aria-hidden />{" "}
              {rotate.isPending ? t("gateway.btn.rotating") : t("gateway.btn.rotate")}
            </button>
            {copied ? (
              <span className="muted" role="status">{t("gateway.copied")}</span>
            ) : null}
          </div>
          {rotated ? (
            <p className="warnline" role="status">
              <AlertTriangle size={14} aria-hidden /> {t("gateway.rotatedWarn")}
            </p>
          ) : null}
          <button
            type="button"
            className="btn btn-danger"
            disabled={stop.isPending}
            onClick={() => stop.mutate()}
          >
            <Square size={14} aria-hidden /> {t("gateway.stopBtn")}
          </button>
        </>
      ) : (
        <>
          <div className="row">
            <label className="field-inline">
              <span>{t("keys.siteSelect")}</span>
              <select
                className="input"
                value={activeSite ?? ""}
                onChange={(e) => {
                  setSiteId(Number(e.target.value));
                  setKeyId(null);
                }}
              >
                {(sites.data ?? []).map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.displayName}
                  </option>
                ))}
              </select>
            </label>
            <label className="field-inline">
              <span>{t("agents.select.key")}</span>
              <select
                className="input"
                value={activeKey ?? ""}
                onChange={(e) =>
                  // 空选择是 `null`，**不是 0**（M8-S5B §6.7）：
                  // `Number("")` 恰好是 0，而 0 是一个看似合法的 key id，
                  // 下游会拿它去查一把不存在的 key，报「key 不存在」而不是「还没选」。
                  setKeyId(e.target.value === "" ? null : Number(e.target.value))
                }
              >
                <option value="">{t("agents.select.keyPlaceholder")}</option>
                {siteKeys.map((k) => (
                  <option key={k.id} value={k.id}>
                    {k.name}（#{k.id}）
                  </option>
                ))}
              </select>
            </label>
          </div>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!enabled || activeSite === null || activeKey === null || start.isPending}
            onClick={() => start.mutate()}
          >
            <Play size={14} aria-hidden /> {start.isPending ? t("gateway.btn.starting") : t("gateway.btn.start")}
          </button>
          {!enabled ? (
            <p className="muted">{t("gateway.startHint.notEnabled")}</p>
          ) : siteKeys.length === 0 ? (
            <p className="muted">{t("gateway.startHint.noKey")}</p>
          ) : null}
        </>
      )}

      {/* 批量改指网关（M8-S7 / B-116） */}
      <div className="row">
        <button
          type="button"
          className="btn"
          disabled={!running || batchApply.isPending}
          onClick={() => {
            setBatchOpen(true);
            setBatchResults([]);
            setBatchPicked({});
            setBatchPreviews({});
          }}
        >
          {t("gateway.batch.btn")}
        </button>
        {!running ? (
          <span className="muted">{t("gateway.batch.notRunning")}</span>
        ) : null}
      </div>

      {batchOpen ? (
        <div className="card">
          <h4>{t("gateway.batch.title")}</h4>
          <p className="muted">
            {t("gateway.batch.bodyPre")}<strong>{t("gateway.batch.bodyStrong")}</strong>{t("gateway.batch.bodyPost")}
          </p>
          {batchBindings.isLoading ? <p className="muted">{t("gateway.batch.loading")}</p> : null}
          {batchCandidates.length === 0 && !batchBindings.isLoading ? (
            <p className="muted">{t("gateway.batch.empty")}</p>
          ) : null}
          {batchCandidates.map(({ binding, channel, key }) => {
            const site = (sites.data ?? []).find((s) => s.id === binding.siteId);
            return (
              <label className="checkline" key={key}>
                <input
                  type="checkbox"
                  checked={batchPicked[key] ?? false}
                  // 预览期间禁用勾选（P2-3）：预览 mutation 在**启动时**快照 `batchPicked`，
                  // 期间新勾的条目不在那份快照里 ⇒ 不会被预览；而 `onSuccess` 会把整份
                  // 快照结果写回，执行按钮于是变可用，用户一点就写了一个没预览过的文件。
                  // 光靠「勾选即作废预览」挡不住这个时序（作废发生在 `onChange`，
                  // 而 `onSuccess` 随后覆盖它）⇒ 从源头禁掉。
                  disabled={batchPreview.isPending}
                  onChange={(e) => {
                    setBatchPicked({ ...batchPicked, [key]: e.target.checked });
                    // 勾选一变，上一轮预览就作废——否则用户能拿旧 diff 执行新勾选
                    setBatchPreviews({});
                  }}
                />
                <span>
                  {channel === null ? (
                    <>
                      {t("gateway.batch.unmappedPre")}{binding.targetPath}{t("gateway.batch.unmappedPost")}
                    </>
                  ) : (
                    <>
                      {/* 这里显示的是**绑定记录里的**路径（P3-13）。它可能与本次实际写入的
                          路径不同（例如那条绑定是另一个 TIANSHU_RELAY_HOME 下写的），所以显式
                          标成「记录时的路径」；实际写入路径在下面的逐条预览里给。 */}
                      {t("gateway.batch.mapped", {
                        channel,
                        path: binding.targetPath,
                        pathLabel: t("gateway.batch.recordedPathLabel"),
                        keyId: binding.keyId,
                        site: site ? ` · ${site.displayName}` : "",
                      })}
                    </>
                  )}
                </span>
              </label>
            );
          })}
          {/* 逐条预览的结果（硬约束 1）：不显示 diff 就不让执行 */}
          {Object.keys(batchPreviews).length > 0 ? (
            <div className="card">
              <h4>{t("gateway.batch.previewTitle")}</h4>
              {Object.entries(batchPreviews).map(([key, plan]) => (
                <div key={key}>
                  <strong>{planOf(key).channel ?? t("gateway.batch.unmappedStrong")}</strong>{" "}
                  {/* 这里是**本次实际写入**的路径（来自后端计划），与上面那一行的
                      「记录时的路径」可能不同（P3-13）：绑定是当年另一个 TIANSHU_RELAY_HOME
                      下写的时，两个路径就不一样。两个都标出来，用户才知道写的是哪个文件。 */}
                  <span className="mono">
                    {t("gateway.batch.actualPathLabel")}
                    {planOf(key).targetPath}
                  </span>
                  {typeof plan === "string" ? (
                    <p className="error" role="alert">
                      {t("gateway.batch.previewError", { error: plan })}
                    </p>
                  ) : (
                    <>
                      <p className="muted">
                        {plan.targetExists ? t("gateway.batch.previewRewrite") : t("gateway.batch.previewNew")}
                        {t("gateway.batch.previewModePre")}
                        <strong>{plan.mode === "gateway" ? t("gateway.batch.previewModeGateway") : t("gateway.batch.previewModeSite")}</strong>
                        {plan.warnings.length > 0 ? t("gateway.batch.previewWarnings", { count: plan.warnings.length }) : ""}
                      </p>
                      {/* 与投递页同一处理（P2-5）：删除行的旧值不渲染出来 */}
                      <pre className="mono">
                        {maskRemovedValues(plan.preview, t("agents.plan.removedValueMasked"))}
                      </pre>
                    </>
                  )}
                </div>
              ))}
            </div>
          ) : null}

          <div className="row">
            <button
              type="button"
              className="btn"
              disabled={
                batchPreview.isPending ||
                Object.values(batchPicked).every((v) => !v)
              }
              onClick={() => batchPreview.mutate()}
            >
              {batchPreview.isPending ? t("gateway.batch.previewBtn") : t("gateway.batch.previewBtnIdle")}
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={
                batchApply.isPending ||
                batchPreview.isPending ||
                // P2-15：一条都没勾 ⇒ 禁用（与预览按钮同一判据）。
                Object.values(batchPicked).every((v) => !v) ||
                // 勾选集必须是**预览集的子集**：有一条勾了却没预览过就不能执行
                // （P2-3：预览快照与渲染期勾选之间的竞态，单看「预览非空」挡不住）。
                // 只看**勾选的**（batchPicked[k]===true）——取消某个勾选不得永久禁用按钮。
                Object.keys(batchPicked).some((k) => batchPicked[k] && !(k in batchPreviews)) ||
                Object.values(batchPreviews).some((p) => typeof p === "string")
              }
              onClick={() => batchApply.mutate()}
            >
              {batchApply.isPending ? t("gateway.batch.applyBtn") : t("gateway.batch.applyBtnIdle")}
            </button>
            <button
              type="button"
              className="btn btn-ghost"
              disabled={batchApply.isPending}
              onClick={() => {
                setBatchOpen(false);
                setBatchPicked({});
              }}
            >
              {t("gateway.batch.cancelBtn")}
            </button>
          </div>
          <p className="muted">{t("gateway.batch.hint")}</p>
        </div>
      ) : null}

      {batchResults.length > 0 ? (
        <div className="card">
          <h4>{t("gateway.batch.resultTitle")}</h4>
          {batchResults.map((r) => (
            <p key={`${r.label}-${r.detail}`} className={r.ok ? "muted" : "error"} role={r.ok ? undefined : "alert"}>
              {r.ok ? "✓" : "✗"} {r.label} —— {r.detail}
            </p>
          ))}
        </div>
      ) : null}

      {/* M43-S1：Agent 令牌区块 */}
      <div className="card">
        <h4>{t("gateway.tokens.title")}</h4>
        <p className="muted">{t("gateway.tokens.body")}</p>
        {status.data?.tokenGraceUntil &&
        status.data.tokenGraceUntil * 1000 > Date.now() ? (
          <p className="muted" data-token-grace>
            {t("gateway.tokens.graceUntil", {
              time: new Date(status.data.tokenGraceUntil * 1000).toLocaleString(),
            })}
          </p>
        ) : null}
        {tokenList.isLoading ? (
          <p className="muted">{t("gateway.tokens.loading")}</p>
        ) : tokenList.isError ? (
          <p className="error" role="alert">
            {t("gateway.tokens.loadFailed", {
              error: (tokenList.error as Error).message,
            })}
          </p>
        ) : (tokenList.data ?? []).length === 0 ? (
          <p className="muted">{t("gateway.tokens.empty")}</p>
        ) : (
          <ul className="gateway-token-list">
            {(tokenList.data ?? []).map((token) => (
              <li key={token.id} className="gateway-token-row">
                <div className="gateway-token-head">
                  <strong>{token.label}</strong>
                  {token.isDefault ? (
                    <span className="badge">{t("gateway.tokens.defaultBadge")}</span>
                  ) : null}
                  {!token.active ? (
                    <span className="badge">{t("gateway.tokens.revokedBadge")}</span>
                  ) : null}
                </div>
                <div className="muted gateway-token-meta">
                  {t("gateway.tokens.createdAt", {
                    time: new Date(token.createdAt * 1000).toLocaleString(),
                  })}
                  {" · "}
                  {token.lastUsedAt
                    ? t("gateway.tokens.lastUsedAt", {
                        time: new Date(token.lastUsedAt * 1000).toLocaleString(),
                      })
                    : t("gateway.tokens.neverUsed")}
                </div>
                {token.isDefault ? (
                  <p className="muted">{t("gateway.tokens.defaultHint")}</p>
                ) : token.active ? (
                  <button
                    type="button"
                    className="btn btn-ghost"
                    disabled={revokeToken.isPending}
                    onClick={() => setRevokeTarget(token)}
                  >
                    {t("gateway.tokens.revoke")}
                  </button>
                ) : null}
              </li>
            ))}
          </ul>
        )}

        <div className="row">
          <input
            value={newTokenLabel}
            placeholder={t("gateway.tokens.labelPlaceholder")}
            onChange={(e) => setNewTokenLabel(e.target.value)}
            maxLength={64}
          />
          <button
            type="button"
            className="btn btn-primary"
            disabled={createToken.isPending || newTokenLabel.trim().length === 0}
            onClick={() => createToken.mutate(newTokenLabel.trim())}
          >
            {createToken.isPending
              ? t("gateway.tokens.creating")
              : t("gateway.tokens.create")}
          </button>
        </div>
      </div>

      {createdToken ? (
        <div className="card" data-created-token>
          <h4>{t("gateway.tokens.createdTitle")}</h4>
          <p className="muted">{t("gateway.tokens.createdHint")}</p>
          <p className="mono gateway-token-plaintext">{createdToken.token}</p>
          <div className="row">
            <button
              type="button"
              className="btn"
              onClick={() => {
                void navigator.clipboard?.writeText(createdToken.token);
              }}
            >
              {t("gateway.tokens.copy")}
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => setCreatedToken(null)}
            >
              {t("gateway.tokens.savedIt")}
            </button>
          </div>
        </div>
      ) : null}

      <ConfirmDialog
        open={revokeTarget !== null}
        title={t("gateway.tokens.revokeTitle")}
        danger
        confirmLabel={t("gateway.tokens.revokeConfirm")}
        confirmDisabled={revokeToken.isPending}
        onCancel={() => setRevokeTarget(null)}
        onConfirm={() => {
          if (revokeTarget) revokeToken.mutate(revokeTarget.id);
        }}
      >
        <p>{t("gateway.tokens.revokeBody", { label: revokeTarget?.label ?? "" })}</p>
      </ConfirmDialog>

      {error ? <p className="error" role="alert">{error}</p> : null}
    </div>
  );
}
