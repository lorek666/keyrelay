import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Copy,
  Download,
  RotateCcw,
  Send,
  ShieldCheck,
  Undo2,
  Unlink,
} from "lucide-react";
import {
  applyDelivery,
  deliveryPlan,
  detectAgents,
  detectUnmanagedTargets,
  grantConsent,
  listConsents,
  listStoredKeys,
  listSites,
  revokeConsent,
  rollbackDelivery,
  unbindAgent,
  type DeliveryMode,
  type AgentStatus,
  type DeliveryOutcome,
  type DeliveryPlan,
  type RestartHint,
  type UnbindOutcome,
} from "../lib/api";
import { rollbackAftermath, rollbackAftermathTitle } from "../lib/rollback";
import { maskRemovedValues, shouldWarnEndpointOutOfScope } from "../lib/deliveryView";
import ConfirmDialog from "../components/ConfirmDialog";
import AgentIcon from "../components/AgentIcon";
import { loadAgentPrefs, saveAgentPrefs, type AgentPref } from "../lib/agentPrefs";
import { useTranslation, translate, getCurrentDict } from "../i18n";

/**
 * 当前全部投递通道（M14-S1 删 Continue/Shell，新增 Claude Desktop/Grok/OpenClaw/Hermes/MCode/Pi；
 * M30-S2 把每个落点铺成独立卡片，不再用下拉框隐藏）。
 *
 * 这里的 `label` 是**给人看的落点提示**；能力判断不在这里——投递能不能做、
 * 改完要不要重启，一律由后端给（`plan.restartHint`），本文件不得按通道硬编码判断。
 *
 * M14-S2：`label` 含文件路径（技术描述），中英同形，暂不抽——i18n:skip
 */
export const CHANNELS = [
  { id: "codex-auth-json", label: "Codex CLI（~/.codex/auth.json）", agent: "codex" },
  { id: "codex-config", label: "Codex Config（~/.codex/config.toml）", agent: "codex-config" },
  { id: "claude-code-settings", label: "Claude Code（~/.claude/settings.json）", agent: "claude-code" },
  { id: "opencode", label: "OpenCode（~/.config/opencode/opencode.json）", agent: "opencode" },
  { id: "opencode-jsonc", label: "OpenCode JSONC（~/.config/opencode/opencode.jsonc）", agent: "opencode-jsonc" },
  { id: "gemini-cli", label: "Gemini CLI（~/.gemini/.env）", agent: "gemini-cli" },
  { id: "claude-desktop", label: "Claude Desktop（claude_desktop_config.json）", agent: "claude-desktop" },
  { id: "grok-build", label: "Grok Build（~/.grok/config.toml）", agent: "grok-build" },
  { id: "openclaw", label: "OpenClaw（~/.openclaw/openclaw.json）", agent: "openclaw" },
  { id: "hermes", label: "Hermes Agent（~/.hermes/config.yaml）", agent: "hermes" },
  { id: "mcode", label: "MiniMax Code（~/.minimax/config.yaml）", agent: "mcode" },
  { id: "pi", label: "Pi（~/.pi/agent/models.json）", agent: "pi" },
  { id: "cursor", label: "Cursor（~/.cursor/settings.json）", agent: "cursor" },
  { id: "cline", label: "Cline（VS Code globalStorage）", agent: "cline" },
  { id: "qwen-code", label: "Qwen Code（~/.qwen/settings.json）", agent: "qwen-code" },
  { id: "deepseek", label: "DeepSeek Reasonix（~/.reasonix/config.json）", agent: "deepseek" },
  { id: "trae", label: "Trae（~/.trae/config.json）", agent: "trae" },
  { id: "mimo-code", label: "MiMo Code（~/.mimocode/mimocode.json）", agent: "mimo-code" },
  { id: "cline-desktop", label: "Cline Desktop（~/.cline/data/settings/providers.json）", agent: "cline-desktop" },
  { id: "dsh", label: "DeepSeek Harness（~/.dsh/.credentials.yaml）", agent: "dsh" },
];

/** 生效策略文案（PRD FR-4:137 / M7-S3）。从 `restartHint` 取值派生，不按通道硬编码。 */
/**
 * 把 `"Codex CLI（~/.codex/auth.json）"` 拆成名称与目标文件。
 *
 * 落点标签本身就是「Agent 名（目标文件）」这一种形态（M14-S1 定的），
 * 拆分只用于**展示**（名称一行、目标一行小字），不参与任何判断。
 * 没有括号时整串当名称、目标留空。
 */
function splitChannelLabel(label: string): { name: string; target: string } {
  const i = label.indexOf("（");
  const j = label.lastIndexOf("）");
  if (i > 0 && j > i) return { name: label.slice(0, i), target: label.slice(i + 1, j) };
  return { name: label, target: "" };
}

function restartHintLabel(hint: RestartHint): string {
  if (hint === "notNeeded") return translate(getCurrentDict(), "agents.restartHint.notNeeded");
  if (hint === "needed") return translate(getCurrentDict(), "agents.restartHint.needed");
  return translate(getCurrentDict(), "agents.restartHint.dependsOnNewSession");
}

export default function Agents() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });
  const [siteId, setSiteId] = useState<number | null>(null);
  const activeSite = siteId ?? sites.data?.[0]?.id ?? null;

  // 投递需要**本地 key id**，所以用 stored keys 而不是站点侧列表
  const keys = useQuery({ queryKey: ["stored-keys"], queryFn: listStoredKeys });
  // 密钥下拉只列所选站点的（M9-S4 / C）：此前站点下拉只是摆设——选了站点 A，
  // 密钥下拉里照样是全部站点的密钥，选项文字又不带站点，用户分不出投的是哪个站的 key。
  //
  // 并**排除已回收的**（P3-11）：`revoked` 是本地状态「我把它在站点上删了」，
  // 那把 key 在站点侧已经不存在；投递它只会得到一个 401。轮换之后默认选中它
  // （id 最小的那把）正是 P1-6 的触发条件之一。
  const siteKeys = (keys.data ?? []).filter(
    (k) => k.siteId === activeSite && k.status !== "revoked",
  );
  const revokedHidden = (keys.data ?? []).filter(
    (k) => k.siteId === activeSite && k.status === "revoked",
  ).length;

  // ---- M31-S1：每行独立偏好（key + 模型），按站点持久化到 localStorage ----
  const [prefs, setPrefs] = useState<Record<string, AgentPref>>({});
  const [expanded, setExpanded] = useState<string | null>(null);
  const [modelDraft, setModelDraft] = useState<Record<string, string>>({});
  const [modelDebounced, setModelDebounced] = useState<Record<string, string>>({});

  // 站点变化 ⇒ 重新加载该站点的每行偏好，并收起展开行（不串台）
  useEffect(() => {
    if (activeSite === null) return;
    const loaded = loadAgentPrefs(activeSite);
    setPrefs(loaded);
    setModelDraft(Object.fromEntries(Object.entries(loaded).map(([k, v]) => [k, v.model])));
    setModelDebounced(Object.fromEntries(Object.entries(loaded).map(([k, v]) => [k, v.model])));
    setExpanded(null);
  }, [activeSite]);

  const updatePref = useCallback(
    (ch: string, patch: Partial<AgentPref>) => {
      // 在 updater **外面**算 next：React 18 的 StrictMode 会双调用 updater，
      // 把 localStorage 写入放进去会重复写（同值但仍是副作用），也会违反 updater 的纯函数约定。
      const next = {
        ...prefs,
        [ch]: { ...(prefs[ch] ?? { keyId: null, model: "" }), ...patch },
      };
      setPrefs(next);
      // 偏好不是关键路径：写失败静默（`saveAgentPrefs` 内部已 try/catch）
      if (activeSite !== null) saveAgentPrefs(activeSite, next);
    },
    [prefs, activeSite],
  );

  // 模型输入 400ms 防抖后才进查询键——每次预览都要读一次钥匙串，不该每敲一个字读一次。
  useEffect(() => {
    const timers: ReturnType<typeof setTimeout>[] = [];
    for (const c of CHANNELS) {
      const draft = (modelDraft[c.id] ?? "").trim();
      const committed = modelDebounced[c.id] ?? "";
      if (draft === committed) continue;
      timers.push(
        setTimeout(() => {
          setModelDebounced((prev) => ({ ...prev, [c.id]: draft }));
          updatePref(c.id, { model: draft });
        }, 400),
      );
    }
    return () => timers.forEach(clearTimeout);
  }, [modelDraft, modelDebounced, updatePref]);

  // 模型名：这几条落点的配置文件不含模型字段 ⇒ 不显示输入框（界面判断，不是能力判断）
  const NO_MODEL_CHANNELS = new Set([
    "claude-desktop",
    "cursor",
    "dsh",
    "codex-auth-json",
    "codex-config",
  ]);

  const rowPref = (ch: string): AgentPref => prefs[ch] ?? { keyId: null, model: "" };
  // 展开行决定预览的全部参数；未展开时下游的 mutation 不会被调用
  const channel = expanded ?? CHANNELS[0].id;
  // 保存的 keyId 可能在别处被回收/删除：此时必须按「未选」处理。
  // 直接拿旧 id 去查会得到一个 404/401，而不是一句「先选密钥」。
  const effectiveKeyId = (ch: string | null): number | null => {
    if (!ch) return null;
    const id = rowPref(ch).keyId;
    return id !== null && siteKeys.some((k) => k.id === id) ? id : null;
  };
  const activeKey = effectiveKeyId(expanded);
  // 解绑按 agent 做，不是按通道（多个落点可能属于同一个 agent）
  const activeAgent = CHANNELS.find((c) => c.id === expanded)?.agent ?? "";
  const model = (() => {
    if (!expanded || NO_MODEL_CHANNELS.has(expanded)) return undefined;
    const v = (modelDebounced[expanded] ?? "").trim();
    return v ? v : undefined;
  })();

  // ---- M31-S1：本机 Agent 发现（只读；安装命令只给用户复制，绝不自动执行）----
  const agentsQuery = useQuery({
    queryKey: ["agents"],
    queryFn: detectAgents,
    retry: false,
  });
  const agentByChannel = useMemo(
    () => new Map((agentsQuery.data ?? []).map((a) => [a.channel, a])),
    [agentsQuery.data],
  );
  const [installFor, setInstallFor] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const [agreeChecked, setAgreeChecked] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [confirmingRollback, setConfirmingRollback] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastOutcome, setLastOutcome] = useState<DeliveryOutcome | null>(null);
  /** 回滚后的三条后果（B-129 J：分条渲染，不再挤成一个长段落）。 */
  const [rollbackLines, setRollbackLines] = useState<string[]>([]);

  // 投递模式（M8-S4 §6.2）：指向站点，还是指向本地网关。
  // 这是**投递参数**，不是新通道——通道集合不变，只换写进去的那两个值。
  const [gatewayMode, setGatewayMode] = useState(false);
  const mode: DeliveryMode = gatewayMode ? "gateway" : "site";

  // 解绑（M8-S4 §5.4）。`alsoRevoke` **默认不勾**：默认路径纯本地、一个站点请求都不发。
  const [unbinding, setUnbinding] = useState(false);
  const [alsoRevoke, setAlsoRevoke] = useState(false);
  const [unbindResult, setUnbindResult] = useState<UnbindOutcome | null>(null);

  const consents = useQuery({ queryKey: ["consents"], queryFn: listConsents });

  // 未托管落点（Cline / Roo Code）：只读探测，永远不写盘
  const unmanaged = useQuery({
    queryKey: ["unmanaged-targets"],
    queryFn: detectUnmanagedTargets,
    retry: false,
  });

  const plan = useQuery({
    queryKey: ["plan", activeKey, channel, model, mode],
    queryFn: () => deliveryPlan({ keyId: activeKey!, channel, model, mode }),
    enabled: activeKey !== null,
    retry: false,
  });

  // 切换 key/通道/模型名/模式时，同意勾选必须重置（避免「上次勾过了」的错觉：预览已经变了）
  useEffect(() => {
    setAgreeChecked(false);
    setNotice(null);
    setError(null);
  }, [activeKey, channel, model, mode]);

  const noChange = plan.data?.preview.trim() === "(无变化)";  // i18n:skip

  const grantAndApply = useMutation({
    mutationFn: async () => {
      await grantConsent({ keyId: activeKey!, channel });
      return applyDelivery({ keyId: activeKey!, channel, model, mode });
    },
    onSuccess: async (outcome) => {
      setError(null);
      setLastOutcome(outcome);
      // 生效策略必须跟着结果一起说：用户最容易在这里以为「已经生效了」
      const hint = plan.data ? restartHintLabel(plan.data.restartHint) : "";
      setNotice(t("agents.notice.delivered", { path: outcome.targetPath, journal: outcome.journalId, hint }));
      setConfirming(false);
      await qc.invalidateQueries({ queryKey: ["plan", activeKey, channel] });
      await qc.invalidateQueries({ queryKey: ["consents"] });
      await qc.invalidateQueries({ queryKey: ["events"] });
    },
    onError: (err: Error) => {
      setError(err.message);
      setConfirming(false);
    },
  });

  const revoke = useMutation({
    mutationFn: () => revokeConsent({ keyId: activeKey!, channel }),
    onSuccess: async () => {
      setNotice(t("agents.notice.revoked"));
      setRevoking(false);
      await qc.invalidateQueries({ queryKey: ["plan", activeKey, channel] });
      await qc.invalidateQueries({ queryKey: ["consents"] });
    },
    onError: (err: Error) => {
      setError(err.message);
      setRevoking(false);
    },
  });

  const rollback = useMutation({
    mutationFn: () => rollbackDelivery(lastOutcome!.journalId),
    onSuccess: async () => {
      // 与历史页同一组文案（复审 P2-1）：此前这里只说了「已回滚」，对之后的漂移告警一个字都没提。
      // M16-S6b（B-129 J）：后果拆成**分条**渲染（见下方的 rollbackLines），不再挤成一个长段落。
      const agent =
        CHANNELS.find((c) => c.id === lastOutcome?.channel)?.agent ?? lastOutcome?.channel ?? "";
      setNotice(t("agents.notice.rolledBack", { journal: lastOutcome?.journalId ?? "" }));
      setRollbackLines(agent ? rollbackAftermath(agent) : []);
      setLastOutcome(null);
      setConfirmingRollback(false);
      await qc.invalidateQueries({ queryKey: ["events"] });
    },
    onError: (err: Error) => {
      setError(err.message);
      setConfirmingRollback(false);
    },
  });

  /**
   * 解绑（M8-S4 §5.4）。结果文案**逐态**给出，四件事互相独立：
   * 「这次新解开了几条」「本来就是解绑状态」「回收成功几把」「回收失败几把（附原因）」。
   */
  const unbind = useMutation({
    mutationFn: () => unbindAgent(activeAgent, alsoRevoke, alsoRevoke),
    onSuccess: async (outcome) => {
      setError(null);
      setUnbindResult(outcome);
      setUnbinding(false);
      await qc.invalidateQueries({ queryKey: ["drift"] });
      await qc.invalidateQueries({ queryKey: ["events"] });
      await qc.invalidateQueries({ queryKey: ["stored-keys"] });
    },
    onError: (err: Error) => {
      setError(err.message);
      setUnbinding(false);
    },
  });

  const consentLabel = useMemo(() => {
    const state = plan.data?.consent;
    if (state === "granted") return t("agents.plan.consentGranted");
    if (state === "revoked") return t("agents.plan.consentRevoked");
    return t("agents.plan.consentMissing");
  }, [plan.data?.consent, t]);

  return (
    <section>
      <p className="muted">{t("agents.intro")}</p>

      {notice ? <p className="ok" role="status">{notice}</p> : null}

      {/* 回滚之后的后果（B-129 J：分条）。三条互相独立：漂移会一直报、轮换/回收的行为、
          以及「不想再管它就解绑」——挤成一段时用户读不完，而每一条都会改变他接下来做什么。 */}
      {rollbackLines.length > 0 ? (
        <div className="warnbox" role="status">
          <p className="warnline">
            <AlertTriangle size={14} aria-hidden /> {rollbackAftermathTitle()}
          </p>
          <ul className="list">
            {rollbackLines.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {error ? (
        <p className="error" role="alert">
          <AlertTriangle size={14} aria-hidden /> {error}
        </p>
      ) : null}

      {/* 顶部：站点选择 + 网关模式（全局密钥/模型下拉已移除，改为每行独立） */}
      <div className="card">
        <div className="row">
          <label className="field-inline">
            <span>{t("agents.select.site")}</span>
            <select
              className="input"
              value={activeSite ?? ""}
              onChange={(e) => setSiteId(Number(e.target.value))}
            >
              {(sites.data ?? []).map((s) => (
                <option key={s.id} value={s.id}>
                  {s.displayName}
                </option>
              ))}
            </select>
          </label>
          <label className="checkline">
            <input
              type="checkbox"
              checked={gatewayMode}
              onChange={(e) => setGatewayMode(e.target.checked)}
            />
            <span>{t("agents.gatewayMode.label")}</span>
          </label>
        </div>
      </div>

      {agentsQuery.isError ? (
        <p className="error" role="alert">
          <AlertTriangle size={14} aria-hidden />{" "}
          {t("agents.workbench.detectFailed", { error: (agentsQuery.error as Error).message })}{" "}
          <button type="button" className="btn" onClick={() => agentsQuery.refetch()}>
            {t("agents.install.redetect")}
          </button>
        </p>
      ) : null}

      {/*
        M31-S1：单列工作台。一行一个落点——**不合并**同 agent 的多个目标文件
        （Codex / OpenCode / Cline 各有多处落点，合并会让用户看不到真实可投递面）。
      */}
      <div className="card">
        <h3>{t("agents.workbench.title", { count: CHANNELS.length })}</h3>
        <p className="muted">{t("agents.workbench.hint")}</p>
        {revokedHidden > 0 ? (
          <p className="muted">{t("agents.select.revokedHidden", { count: revokedHidden })}</p>
        ) : null}
        <ul className="agent-list">
          {CHANNELS.map((c) => {
            const status = agentByChannel.get(c.id);
            // 后端应返回 20 条；缺一条时是「状态未知」，绝不能当成「未安装」——
            // 那会给出一个装了也白装的安装按钮，且把已装环境说成没装。
            const known = status !== undefined;
            const installed = status?.installed === true;
            const detecting = agentsQuery.isLoading;
            const selectedKeyId = effectiveKeyId(c.id);
            const isOpen = expanded === c.id;
            const writingModel = !NO_MODEL_CHANNELS.has(c.id);
            const { name, target } = splitChannelLabel(c.label);
            return (
              <li
                key={c.id}
                className={"agent-row" + (isOpen ? " open" : "")}
                data-agent-channel={c.id}
                data-agent-name={c.agent}
              >
                <div className="agent-row-main">
                  <button
                    type="button"
                    className="agent-row-head"
                    onClick={() => setExpanded(isOpen ? null : c.id)}
                    aria-expanded={isOpen}
                    disabled={!installed || detecting}
                  >
                    <AgentIcon icon={c.agent} name={name} />
                    <span className="agent-row-text">
                      <span className="agent-row-name">{name}</span>
                      <span className="agent-row-target mono">{target}</span>
                    </span>
                  </button>

                  <span className={"agent-badge" + (installed ? " ok" : "")}>
                    {detecting
                      ? t("agents.row.detecting")
                      : agentsQuery.isError || !known
                        ? t("agents.row.unknown")
                        : installed
                          ? (status?.version ?? t("agents.row.installed"))
                          : t("agents.row.notInstalled")}
                  </span>

                  {detecting || (!known && !agentsQuery.isError) ? null : installed ? (
                    <div className="agent-row-controls">
                      <select
                        className="input agent-row-key"
                        aria-label={t("agents.select.key")}
                        value={selectedKeyId ?? ""}
                        onChange={(e) =>
                          updatePref(c.id, {
                            keyId: e.target.value === "" ? null : Number(e.target.value),
                          })
                        }
                      >
                        <option value="">{t("agents.select.keyPlaceholder")}</option>
                        {siteKeys.map((k) => (
                          <option key={k.id} value={k.id}>
                            {k.name}（#{k.id}）
                          </option>
                        ))}
                      </select>

                      {writingModel ? (
                        <input
                          className="input agent-row-model"
                          aria-label={t("agents.select.model")}
                          value={modelDraft[c.id] ?? ""}
                          placeholder={t("agents.select.modelPlaceholder")}
                          spellCheck={false}
                          onChange={(e) =>
                            setModelDraft((prev) => ({ ...prev, [c.id]: e.target.value }))
                          }
                        />
                      ) : (
                        <span className="muted agent-row-nomodel">{t("agents.row.noModel")}</span>
                      )}

                      <button
                        type="button"
                        className="btn agent-row-toggle"
                        aria-expanded={isOpen}
                        onClick={() => setExpanded(isOpen ? null : c.id)}
                      >
                        {isOpen ? <ChevronDown size={14} aria-hidden /> : <ChevronRight size={14} aria-hidden />}
                        {isOpen ? t("agents.row.collapse") : t("agents.row.expand")}
                      </button>
                    </div>
                  ) : (
                    <div className="agent-row-controls">
                      <button
                        type="button"
                        className="btn agent-row-install"
                        onClick={() => setInstallFor(c.id)}
                      >
                        <Download size={14} aria-hidden /> {t("agents.row.install")}
                      </button>
                    </div>
                  )}
                </div>

                {isOpen && installed ? (
                  <div className="agent-row-plan">
                    {activeKey === null ? (
                      <p className="muted">
                        {keys.data && siteKeys.length === 0
                          ? t("agents.emptyKey.noSiteKey")
                          : t("agents.emptyKey.selectKey")}
                      </p>
                    ) : plan.isError ? (
                      <p className="error" role="alert">
                        {(plan.error as Error).message}
                      </p>
                    ) : plan.isLoading ? (
                      <p className="muted">{t("agents.plan.generating")}</p>
                    ) : plan.data ? (
                      <PlanView
                        plan={plan.data}
                        consentLabel={consentLabel}
                        noChange={!!noChange}
                        agreeChecked={agreeChecked}
                        onAgreeChange={setAgreeChecked}
                        busy={grantAndApply.isPending}
                        onApply={() => setConfirming(true)}
                        onRevoke={() => setRevoking(true)}
                      />
                    ) : null}
                  </div>
                ) : null}
              </li>
            );
          })}
        </ul>
      </div>
      {lastOutcome ? (
        <div className="card">
          <h3>{t("agents.lastDelivery.title")}</h3>
          <p className="mono">
            {lastOutcome.channel} → {lastOutcome.targetPath}
          </p>
          <p className="muted mono">
            journal={lastOutcome.journalId}
            {lastOutcome.backupPath ? t("agents.lastDelivery.backup", { path: lastOutcome.backupPath }) : ""}
          </p>
          {/* 这张卡只活在本页（切页即卸载）；持久的回滚入口在历史页（M9-S4 / B） */}
          <p className="muted">{t("agents.lastDelivery.hint")}</p>
          <button
            type="button"
            className="btn btn-danger"
            disabled={rollback.isPending}
            onClick={() => setConfirmingRollback(true)}
          >
            <Undo2 size={14} aria-hidden /> {t("agents.btn.rollback")}
          </button>
        </div>
      ) : null}

      {/*
        未托管落点（M7-S3 / 章程 R-7）：只读探测。
        存在的理由是**不静默**——用户在 Cline / Roo Code 里配了中转站，本产品既不能
        帮他注入，也不该假装没这回事。`note` 是后端给的原文（为什么不写），
        界面**不得**改写它（改写等于替后端撒谎）。
      */}
      <div className="card">
        <h3>{t("agents.unmanaged.title")}</h3>
        <p className="muted">
          {t("agents.unmanaged.bodyPre")}<strong>{t("agents.unmanaged.bodyStrong")}</strong>{t("agents.unmanaged.bodyPost")}
        </p>
        {unmanaged.isLoading ? <p className="muted">{t("common.detecting")}</p> : null}
        {unmanaged.isError ? (
          <p className="muted">{t("agents.unmanaged.error", { error: (unmanaged.error as Error).message })}</p>
        ) : null}
        {unmanaged.data?.length ? (
          <ul className="list">
            {unmanaged.data.map((target) => (
              <li key={`${target.label}-${target.path}`}>
                <span
                  className={`badge badge-${target.exists ? "warn" : "muted"}`}
                >
                  {target.exists ? t("agents.unmanaged.detected") : t("agents.unmanaged.notDetected")}
                </span>{" "}
                <strong>{target.label}</strong>{" "}
                <span className="mono ellipsis" title={target.path}>
                  {target.path}
                </span>
                <div className="muted">{target.note}</div>
              </li>
            ))}
          </ul>
        ) : null}
        {unmanaged.data?.length === 0 ? (
          <p className="muted">{t("agents.unmanaged.empty")}</p>
        ) : null}
      </div>

      <div className="card">
        <h3>{t("agents.consents.title", { count: consents.data?.length ?? 0 })}</h3>
        {consents.data?.length ? (
          <table className="table">
            <thead>
              <tr>
                <th>{t("agents.consents.table.agent")}</th>
                <th>{t("agents.consents.table.channel")}</th>
                <th>{t("agents.consents.table.target")}</th>
                <th>{t("agents.consents.table.fields")}</th>
                <th>{t("agents.consents.table.state")}</th>
              </tr>
            </thead>
            <tbody>
              {consents.data.map((row) => (
                <tr key={`${row.agentId}-${row.channel}-${row.targetPath}`}>
                  <td>{row.agentId}</td>
                  <td className="mono">{row.channel}</td>
                  <td className="mono ellipsis" title={row.targetPath}>
                    {row.targetPath}
                  </td>
                  <td className="mono">{row.fields}</td>
                  <td>
                    {row.revokedAt ? (
                      <span className="badge badge-warn" title={formatTs(row.revokedAt)}>
                        {t("agents.consents.revoked", { ts: formatTs(row.revokedAt) })}
                      </span>
                    ) : (
                      <span className="badge badge-ok" title={formatTs(row.grantedAt)}>
                        {t("agents.consents.valid", { ts: formatTs(row.grantedAt) })}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="muted">{t("agents.consents.empty")}</p>
        )}
      </div>

      {/*
        解绑（M8-S4 §5.4 / FR-2:115）。「解绑」不是「删除」：
        `bindings` 的行是「哪个 agent 曾被哪个 key 写到哪个文件」的唯一记录，
        删掉它等于同时丢掉漂移追溯与「这把 key 服务过哪些目标」。
      */}
      <div className="card">
        <h3>{t("agents.unbind.title")}</h3>
        <p className="muted">
          {t("agents.unbind.bodyPre")}<strong>{t("agents.unbind.bodyStrong")}</strong>{t("agents.unbind.bodyPost")}
        </p>
        <p className="muted mono">{t("agents.unbind.agentLine", { agent: activeAgent })}</p>
        <button
          type="button"
          className="btn btn-danger"
          disabled={!activeAgent}
          onClick={() => {
            setAlsoRevoke(false);
            setUnbinding(true);
          }}
        >
          <Unlink size={14} aria-hidden /> {t("agents.btn.unbind", { agent: activeAgent || t("agents.unbind.defaultAgent") })}
        </button>

        {unbindResult ? (
          <div className="okbox" role="status">
            <p>
              {unbindResult.unbound > 0
                ? t("agents.unbindResult.unbound", { count: unbindResult.unbound })
                : t("agents.unbindResult.noneUnbound")}
              {unbindResult.alreadyUnbound > 0
                ? t("agents.unbindResult.alreadyUnbound", { count: unbindResult.alreadyUnbound })
                : ""}
            </p>
            {unbindResult.revoked.length > 0 ? (
              <ul className="list">
                {unbindResult.revoked.map((r) => (
                  <li key={`${r.siteId}-${r.remoteId ?? "local"}`}>
                    {r.revoked ? (
                      <span className="badge badge-ok">{t("agents.unbindResult.revokedOk")}</span>
                    ) : (
                      <span className="badge badge-warn">{t("agents.unbindResult.revokedFail")}</span>
                    )}{" "}
                    <span className="mono">
                      {t("agents.unbindResult.siteLine", { siteId: r.siteId, remoteId: r.remoteId ?? t("agents.unbindResult.localOnly") })}
                    </span>
                    {r.revoked && !r.localStatusUpdated ? (
                      <div className="muted">{t("agents.unbindResult.localFail")}</div>
                    ) : null}
                    {r.note ? <div className="muted">{r.note}</div> : null}
                  </li>
                ))}
              </ul>
            ) : null}
            {unbindResult.note ? (
              <p className="muted">{unbindResult.note}</p>
            ) : null}
          </div>
        ) : null}
      </div>

      <ConfirmDialog
        open={confirming}
        title={t("agents.confirmDialog.applyTitle")}
        confirmLabel={grantAndApply.isPending ? t("agents.confirmDialog.applyConfirmWriting") : t("agents.confirmDialog.applyConfirm")}
        confirmDisabled={!agreeChecked || grantAndApply.isPending}
        onCancel={() => setConfirming(false)}
        onConfirm={() => grantAndApply.mutate()}
      >
        <p>
          {t("agents.confirmDialog.applyBodyPre")}<span className="mono">{plan.data?.targetPath}</span>
          {plan.data?.targetExists ? t("agents.confirmDialog.applyBodyExists") : t("agents.confirmDialog.applyBodyNew")}
        </p>
        <label className="checkline">
          <input
            type="checkbox"
            checked={agreeChecked}
            onChange={(e) => setAgreeChecked(e.target.checked)}
          />
          <span>
            {t("agents.confirmDialog.applyAgreePre")}<span className="mono">{t("agents.confirmDialog.applyAgreeMid")}</span>{t("agents.confirmDialog.applyAgreePost")}
          </span>
        </label>
      </ConfirmDialog>

      <ConfirmDialog
        open={confirmingRollback}
        title={t("agents.rollbackDialog.title")}
        danger
        confirmLabel={rollback.isPending ? t("agents.rollbackDialog.confirming") : t("agents.rollbackDialog.confirm")}
        confirmDisabled={rollback.isPending}
        onCancel={() => setConfirmingRollback(false)}
        onConfirm={() => rollback.mutate()}
      >
        <p>{t("agents.rollbackDialog.body")}</p>
        <p className="muted mono">{lastOutcome?.targetPath}</p>
      </ConfirmDialog>

      <ConfirmDialog
        open={revoking}
        title={t("agents.revokeDialog.title")}
        danger
        confirmLabel={t("agents.revokeDialog.confirm")}
        confirmDisabled={revoke.isPending}
        onCancel={() => setRevoking(false)}
        onConfirm={() => revoke.mutate()}
      >
        <p>{t("agents.revokeDialog.body")}</p>
      </ConfirmDialog>

      <ConfirmDialog
        open={unbinding}
        title={t("agents.unbindDialog.title", { agent: activeAgent })}
        danger
        confirmLabel={unbind.isPending ? t("agents.unbindDialog.confirming") : t("agents.unbindDialog.confirm")}
        confirmDisabled={unbind.isPending}
        onCancel={() => setUnbinding(false)}
        onConfirm={() => unbind.mutate()}
      >
        <p>
          {t("agents.unbindDialog.bodyPre")}<strong>{t("agents.unbindDialog.bodyStrong")}</strong>{t("agents.unbindDialog.bodyPost")}
        </p>
        <label className="checkline">
          <input
            type="checkbox"
            checked={alsoRevoke}
            onChange={(e) => setAlsoRevoke(e.target.checked)}
          />
          <span>
            {t("agents.unbindDialog.alsoRevokePre")}<strong>{t("agents.unbindDialog.alsoRevokeStrong")}</strong>{t("agents.unbindDialog.alsoRevokePost")}
          </span>
        </label>
      </ConfirmDialog>
    
      {/*
        M31-S1：安装说明弹窗。
        **只展示与复制**：应用绝不自动执行这些命令（后端也只返回静态字符串）。
      */}
      <InstallDialog
        open={installFor !== null}
        status={installFor ? agentByChannel.get(installFor) : undefined}
        label={CHANNELS.find((c) => c.id === installFor)?.label ?? ""}
        copiedKey={copiedKey}
        onCopied={setCopiedKey}
        onClose={() => setInstallFor(null)}
        onRedetect={() => {
          agentsQuery.refetch();
        }}
      />

    </section>
  );
}

/**
 * 安装说明弹窗（M31-S1）。
 *
 * 只**展示与复制**：`installCommands` 是后端给的静态字符串，应用不执行、不安装。
 * 用原生 `<dialog>` 拿焦点陷阱与 Esc 关闭（与 `ConfirmDialog` 同源做法）。
 */
function InstallDialog({
  open,
  status,
  label,
  copiedKey,
  onCopied,
  onClose,
  onRedetect,
}: {
  open: boolean;
  status: AgentStatus | undefined;
  label: string;
  copiedKey: string | null;
  onCopied: (key: string | null) => void;
  onClose: () => void;
  onRedetect: () => void;
}) {
  const { t } = useTranslation();
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  // 原生 dialog 的 Esc 会直接关掉元素；不拦下来时 React 的 open 仍是 true，
  // 下一次点「安装」不会重新 showModal（状态没变）——弹窗就再也打不开了。
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    const onNativeCancel = (event: Event) => {
      event.preventDefault();
      onClose();
    };
    dialog.addEventListener("cancel", onNativeCancel);
    return () => dialog.removeEventListener("cancel", onNativeCancel);
  }, [onClose]);

  const commands = status?.installCommands ?? [];

  const copy = async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      onCopied(key);
      setTimeout(() => onCopied(null), 1500);
    } catch {
      onCopied("__failed__");
      setTimeout(() => onCopied(null), 1500);
    }
  };

  return (
    <dialog ref={ref} className="dialog" aria-label={t("agents.install.title", { name: label })}>
      <h2>{t("agents.install.title", { name: label })}</h2>
      <div className="dialog-body">
        <p className="muted">{t("agents.install.hint")}</p>
        {commands.length === 0 ? (
          <p className="muted">{t("agents.install.empty")}</p>
        ) : (
          <ul className="install-cmds">
            {commands.map((cmd) => {
              const key = `${cmd.via}:${cmd.command}`;
              return (
                <li key={key} className="install-cmd">
                  <span className="install-cmd-via mono">{cmd.via}</span>
                  <code className="install-cmd-text mono">{cmd.command}</code>
                  <button type="button" className="btn" onClick={() => copy(key, cmd.command)}>
                    <Copy size={14} aria-hidden />{" "}
                    {copiedKey === key
                      ? t("agents.install.copied")
                      : copiedKey === "__failed__"
                        ? t("agents.install.copyFailed")
                        : t("agents.install.copy")}
                  </button>
                </li>
              );
            })}
          </ul>
        )}
        {status?.installUrl ? (
          <p className="install-url">
            <span className="muted">{t("agents.install.url")}：</span>
            <code className="mono">{status.installUrl}</code>
            <button type="button" className="btn" onClick={() => copy("__url__", status.installUrl!)}>
              <Copy size={14} aria-hidden />{" "}
              {copiedKey === "__url__" ? t("agents.install.copied") : t("agents.install.copy")}
            </button>
          </p>
        ) : null}
        {status?.detail ? <p className="muted">{status.detail}</p> : null}
      </div>
      <div className="dialog-actions">
        <button type="button" className="btn" onClick={onRedetect}>
          <RotateCcw size={14} aria-hidden /> {t("agents.install.redetect")}
        </button>
        <button type="button" className="btn btn-primary" onClick={onClose}>
          {t("agents.install.close")}
        </button>
      </div>
    </dialog>
  );
}

function formatTs(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function PlanView({
  plan,
  consentLabel,
  noChange,
  agreeChecked,
  onAgreeChange,
  busy,
  onApply,
  onRevoke,
}: {
  plan: DeliveryPlan;
  consentLabel: string;
  noChange: boolean;
  agreeChecked: boolean;
  onAgreeChange: (v: boolean) => void;
  busy: boolean;
  onApply: () => void;
  onRevoke: () => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="card">
      <div className="row row-between">
        <h3>
          <ShieldCheck size={15} aria-hidden /> {t("agents.plan.title")}
        </h3>
        <span className={`badge badge-${plan.consent === "granted" ? "ok" : "warn"}`}>
          {consentLabel}
        </span>
      </div>

      <dl className="kv">
        <dt>{t("agents.plan.agent")}</dt>
        <dd className="mono">{plan.agentId}</dd>
        <dt>{t("agents.plan.target")}</dt>
        <dd className="mono ellipsis" title={plan.targetPath}>
          {plan.targetPath} {plan.targetExists ? t("agents.plan.targetExists") : t("agents.plan.targetNew")}
        </dd>
        {/* 模式必须显式说出来（M8-S4 §6.6）：两种模式的字段名一模一样
            （`apiKey` / `apiBase`），不说用户分不清写进去的是站点密钥还是本地令牌。 */}
        <dt>{t("agents.plan.writeWhat")}</dt>
        <dd>
          {plan.mode === "gateway" ? (
            <span className="badge badge-warn">{t("agents.gatewayMode.title")}</span>
          ) : plan.mode === "site" ? (
            <span className="badge badge-ok">{t("agents.gatewayMode.siteKey")}</span>
          ) : (
            <span className="badge badge-warn">{t("agents.gatewayMode.unknownMode", { mode: plan.mode })}</span>
          )}
        </dd>
        <dt>{t("agents.plan.willWrite")}</dt>
        <dd>
          {plan.fields.map((f) => (
            <span key={f.key} className="chip mono">
              {f.key} = {f.masked}
            </span>
          ))}
        </dd>
        {/* 生效策略：文案从 `restartHint` 取值派生，**不按通道硬编码**。
            认不出的取值原样显示（不静默留空——那会让用户以为「不需要重启」）。 */}
        <dt>{t("agents.plan.restart")}</dt>
        <dd>{restartHintLabel(plan.restartHint)}</dd>
      </dl>

      {plan.warnings.length > 0 ? (
        <div className="warnbox" role="status">
          {plan.warnings.map((w) => (
            <p key={w} className="warnline">
              <AlertTriangle size={14} aria-hidden /> {w}
            </p>
          ))}
        </div>
      ) : null}

      {/* 网关模式下，有的通道**只写令牌、不写 endpoint**（P2-3 前端半）：
          这种通道里打开「指向本地网关」时 agent 仍会请求站点，拿的是本地令牌 ⇒ 401。
          判据**只来自后端字段** `plan.endpointInChannel`（与 writer 装配表同源）——
          前端不再按字段名推导，也不判任何通道特例（S6b 复审 P2-1：两套机制会分叉，
          症状是「提示错了」而不是报错）。 */}
      {shouldWarnEndpointOutOfScope(plan.mode, plan.endpointInChannel) ? (
        <p className="warnline" role="alert">
          <AlertTriangle size={14} aria-hidden /> {t("agents.plan.endpointOutOfScope")}
        </p>
      ) : null}

      <h4>{t("agents.plan.diffTitle")}</h4>
      {/* 删除行的值侧掩掉（P2-5）：后端只对**已知的**密钥串做替换，旧站点密钥
          形态未必落在 scrub 认得的集合里；渲染层先保证不把旧值显示出来。
          `+` 行逐字节保留——那是「将要写进去什么」，掩掉等于掩盖改动。 */}
      <pre className="diff">
        {maskRemovedValues(plan.preview, t("agents.plan.removedValueMasked"))}
      </pre>

      {noChange ? (
        <p className="muted">{t("agents.plan.noChange")}</p>
      ) : (
        <label className="checkline">
          <input
            type="checkbox"
            checked={agreeChecked}
            onChange={(e) => onAgreeChange(e.target.checked)}
          />
          <span>{t("agents.plan.agree")}</span>
        </label>
      )}

      <div className="row">
        <button
          type="button"
          className="btn btn-primary"
          disabled={!agreeChecked || busy || noChange}
          onClick={onApply}
        >
          <Send size={14} aria-hidden /> {t("agents.btn.apply")}
        </button>
        {plan.consent === "granted" ? (
          <button type="button" className="btn" onClick={onRevoke}>
            <RotateCcw size={14} aria-hidden /> {t("agents.btn.revoke")}
          </button>
        ) : null}
      </div>
    </div>
  );
}
