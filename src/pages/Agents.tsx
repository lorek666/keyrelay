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
  checkAgentUpdates,
  updateAgent,
  restartCodex,
  restartClaudeDesktop,
  type DeliveryMode,
  type RestartOutcome,
  type AgentStatus,
  type DeliveryOutcome,
  type DeliveryPlan,
  type RestartHint,
  type UnbindOutcome,
  type AgentUpdateOutcome,
  type AgentUpdateStatus,
} from "../lib/api";
import { rollbackAftermath, rollbackAftermathTitle } from "../lib/rollback";
import {
  maskRemovedValues,
  modelValidationBlocks,
  modelValidationProbeKey,
  modelValidationStaticKey,
  shouldWarnEndpointOutOfScope,
} from "../lib/deliveryView";
import ConfirmDialog from "../components/ConfirmDialog";
import AgentIcon from "../components/AgentIcon";
import ModelPicker from "../components/ModelPicker";
import { loadAgentPrefs, saveAgentPrefs, type AgentPref } from "../lib/agentPrefs";
import { useTranslation, translate, getCurrentDict } from "../i18n";

/**
 * 当前全部投递通道（M14-S1 删 Continue/Shell，新增 Claude Desktop/Grok/OpenClaw/Hermes/MCode/Pi；
 * M30-S2 把每个落点铺成独立卡片，不再用下拉框隐藏）。
 *
 * B-292：Cline Desktop 已下线，不在本表——后端解析入口一律拒绝文件直写，
 * 检测探针与更新策略仍在后端保留（见 agents.rs / agent_updates.rs），只是投递面不再提供入口。
 *
 * 这里的 `label` 是**给人看的落点提示**；能力判断不在这里——投递能不能做、
 * 改完要不要重启，一律由后端给（`plan.restartHint`，P1-6 起连同动作
 * `plan.restartHintAction` 与来源标注 `plan.restartHintSource` 一起给），本文件不得按通道硬编码判断。
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
  { id: "dsh", label: "DeepSeek Harness（~/.dsh/.credentials.yaml）", agent: "dsh" },
];

/**
 * 从 `"Codex CLI（~/.codex/auth.json）"` 取展示名称（括号前）。
 *
 * 落点标签是「Agent 名（目标文件）」形态；M32-S1 起界面不再显示目标路径，
 * 因此只返回名称。没有括号时整串当名称。
 */
function channelName(label: string): string {
  const i = label.indexOf("（");
  return i > 0 ? label.slice(0, i) : label;
}

/** 生效策略文案（PRD FR-4:137 / M7-S3）。从 `restartHint` 取值派生，不按通道硬编码。 */
function restartHintLabel(hint: RestartHint): string {
  if (hint === "notNeeded") return translate(getCurrentDict(), "agents.restartHint.notNeeded");
  if (hint === "needed") return translate(getCurrentDict(), "agents.restartHint.needed");
  return translate(getCurrentDict(), "agents.restartHint.dependsOnNewSession");
}

/**
 * P1-6：生效动作文案。从后端给的 `restartHintAction` 取值派生，不按通道硬编码。
 * 缺失/未知一律回落通用“重启该 agent”，绝不静默留空（留空会被读成“无需重启”）。
 */
function restartHintActionLabel(action: string | undefined): string {
  switch (action) {
    case "newSession":
      return translate(getCurrentDict(), "agents.restartHint.action.newSession");
    case "restartTerminalOrCli":
      return translate(getCurrentDict(), "agents.restartHint.action.restartTerminalOrCli");
    case "relaunchDesktopApp":
      return translate(getCurrentDict(), "agents.restartHint.action.relaunchDesktopApp");
    case "codexSplit":
      return translate(getCurrentDict(), "agents.restartHint.action.codexSplit");
    default:
      return translate(getCurrentDict(), "agents.restartHint.action.restartAgent");
  }
}

/**
 * P1-6：来源标注文案。从后端给的 `restartHintSource` 取值派生，不按通道硬编码。
 * 缺失/未知一律按“未实测”呈现——绝不默认已实测；只有后端明确给 `verified`
 * 时才呈现已实测（当前没有任何通道取它）。
 */
function restartHintSourceLabel(source: string | undefined): string {
  if (source === "ccSwitchUnverified")
    return translate(getCurrentDict(), "agents.restartHint.source.ccSwitchUnverified");
  if (source === "verified")
    return translate(getCurrentDict(), "agents.restartHint.source.verified");
  return translate(getCurrentDict(), "agents.restartHint.source.unverified");
}

/**
 * P1-7：落点变体名 → 展示文案。取值只来自后端 `targetVariants` 清单，
 * 这里只做文案映射（未知取值回落默认文案，绝不静默留空）。
 */
function variantLabel(variant: string): string {
  switch (variant) {
    case "code":
      return translate(getCurrentDict(), "agents.plan.variant.code");
    case "code-insiders":
      return translate(getCurrentDict(), "agents.plan.variant.codeInsiders");
    case "cursor":
      return translate(getCurrentDict(), "agents.plan.variant.cursor");
    default:
      return translate(getCurrentDict(), "agents.plan.variant.default");
  }
}

/**
 * P1-7 修复（复审 P1-1）：未经实测的变体。
 *
 * Insiders / Cursor 两条写路径未经实测（代码注释自承 Cursor 只是候选落点），
 * 却曾与默认落点平等呈现。默认 `code` 不在本项范围内——它是 P1-7 前已有的
 * 默认落点，不动。判定只认这两个变体名，不按通道硬编码。
 */
function isUnverifiedVariant(variant: string): boolean {
  return variant === "code-insiders" || variant === "cursor";
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

  // ---- M34-S1：Agent 更新（检查只读；执行必须经过确认弹窗 + 勾选同意）----
  // `detect_agents` 成功后才检查：没有安装状态就没法判断「谁需要更新」，白跑一次网络。
  // 10 分钟缓存 + 不自动重试：更新检查是提示性的，失败就让用户手动重试（spec §6）。
  const updatesQuery = useQuery({
    queryKey: ["agent-updates"],
    queryFn: checkAgentUpdates,
    enabled: agentsQuery.isSuccess,
    staleTime: 10 * 60 * 1000,
    retry: false,
  });
  const updateByChannel = useMemo(
    () => new Map((updatesQuery.data ?? []).map((u) => [u.channel, u])),
    [updatesQuery.data],
  );
  const updateCounts = useMemo(() => {
    const rows = updatesQuery.data ?? [];
    return {
      available: rows.filter((u) => u.state === "available").length,
      upToDate: rows.filter((u) => u.state === "upToDate").length,
      unsupported: rows.filter((u) => u.state === "unsupported").length,
      failed: rows.filter((u) => u.state === "error").length,
    };
  }, [updatesQuery.data]);

  /** 确认弹窗对应的通道（null = 未打开）。 */
  const [updateFor, setUpdateFor] = useState<string | null>(null);
  /** 弹窗内「我同意执行该命令」——不勾选确认按钮不可用（spec §4.5）。 */
  const [updateAgree, setUpdateAgree] = useState(false);
  const [updateOutcome, setUpdateOutcome] = useState<AgentUpdateOutcome | null>(null);
  const [updateError, setUpdateError] = useState<string | null>(null);
  // 「上次检查时间」直接从 query 的 `dataUpdatedAt` 派生，不额外存 state：
  // 多一个 state + effect 只会在测试里制造一次 act() 之外的更新。
  const lastCheckedAt =
    updatesQuery.dataUpdatedAt > 0 ? new Date(updatesQuery.dataUpdatedAt) : null;

  const updateMutation = useMutation({
    mutationFn: (channel: string) => updateAgent(channel),
    onSuccess: async (outcome) => {
      setUpdateError(null);
      setUpdateOutcome(outcome);
      setUpdateFor(null);
      setUpdateAgree(false);
      // 两个通道可能共享同一二进制（Codex / OpenCode）：更新后**重新探测**再重新检查。
      await qc.invalidateQueries({ queryKey: ["agents"] });
      await qc.invalidateQueries({ queryKey: ["agent-updates"] });
    },
    onError: (err: Error) => {
      setUpdateOutcome(null);
      setUpdateError(err.message);
      setUpdateFor(null);
      setUpdateAgree(false);
    },
  });

  const openUpdateDialog = (channel: string) => {
    setUpdateOutcome(null);
    setUpdateError(null);
    setUpdateAgree(false);
    setUpdateFor(channel);
  };
  const confirmUpdate = () => {
    // 双保险：按钮已禁用，这里再挡一次，确保 pending 期间不会重复调用。
    if (updateFor === null || !updateAgree || updateMutation.isPending) return;
    updateMutation.mutate(updateFor);
  };
  /** 更新源类别的展示文案（`npm` / `brewCask` / `marketplace` / `none`）。 */
  const updateSourceLabel = (source: AgentUpdateStatus["source"]): string => {
    switch (source) {
      case "npm":
        return t("agents.update.sourceNpm");
      case "brewCask":
        return t("agents.update.sourceBrewCask");
      case "marketplace":
        return t("agents.update.sourceMarketplace");
      default:
        return t("agents.update.sourceNone");
    }
  };

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
  // P0-4：默认推荐网关模式（agent 文件只写本地端点 + 本地令牌），
  // 站点直连降级为次选、不预选。只改 UI 默认与呈现：后端缺省仍是站点
  // （见汇报），调用方不传 mode 时的行为不在本项改动范围内。
  const [gatewayMode, setGatewayMode] = useState(true);
  const mode: DeliveryMode = gatewayMode ? "gateway" : "site";

  // P1-7：只打印不写盘的预览模式（默认关）与落点变体选择（默认不选 =
  // 后端默认落点）。变体只在后端给出的清单长度 > 1 时才出现下拉
  // （目前只有 Cline 通道）；变体名一律来自后端 `targetVariants`，
  // 界面不得硬编码变体清单。
  const [previewOnly, setPreviewOnly] = useState(false);
  const [variantOverride, setVariantOverride] = useState<string | null>(null);

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
    queryKey: ["plan", activeKey, channel, model, mode, previewOnly, variantOverride],
    queryFn: () =>
      deliveryPlan({
        keyId: activeKey!,
        channel,
        model,
        mode,
        previewOnly: previewOnly ? true : undefined,
        targetVariant: variantOverride ?? undefined,
      }),
    enabled: activeKey !== null,
    retry: false,
  });

  // 切换 key/通道/模型名/模式/预览模式/变体时，同意勾选必须重置
  // （避免「上次勾过了」的错觉：预览已经变了）
  useEffect(() => {
    setAgreeChecked(false);
    setNotice(null);
    setError(null);
  }, [activeKey, channel, model, mode, previewOnly, variantOverride]);

  // 切换通道时变体选择复位（变体只对 Cline 有意义，上一通道的变体
  // 不得带到下一通道——带过去会在后端被直接拒绝，但复位更干净）。
  useEffect(() => {
    setVariantOverride(null);
  }, [channel]);

  // P0-2 复审 P1-2：noChange 按全部写盘文件判定——入口无变化但另一文件有变化时，
  // 投递按钮不得被禁用；files 为空（旧 mock）时回退顶层预览，保持单文件行为。
  const noChange =
    plan.data?.files?.length
      ? plan.data.files.every((f) => f.preview.trim() === "(无变化)") // i18n:skip
      : plan.data?.preview.trim() === "(无变化)"; // i18n:skip

  const grantAndApply = useMutation({
    mutationFn: async () => {
      await grantConsent({
        keyId: activeKey!,
        channel,
        targetVariant: variantOverride ?? undefined,
      });
      return applyDelivery({
        keyId: activeKey!,
        channel,
        model,
        mode,
        targetVariant: variantOverride ?? undefined,
      });
    },
    onSuccess: async (outcome) => {
      setError(null);
      setLastOutcome(outcome);
      // 生效策略必须跟着结果一起说：用户最容易在这里以为「已经生效了」
      const hint = plan.data ? restartHintLabel(plan.data.restartHint) : "";
      // P0-2 复审 P1-2：成功提示列出全部写盘路径（双文件时两条，单文件时沿用旧文案）。
      const writtenPaths = outcome.files?.length
        ? outcome.files.map((f) => f.targetPath)
        : [outcome.targetPath];
      setNotice(
        writtenPaths.length > 1
          ? t("agents.notice.deliveredFiles", { paths: writtenPaths.join(", "), journal: outcome.journalId, hint })
          : t("agents.notice.delivered", { path: outcome.targetPath, journal: outcome.journalId, hint }),
      );
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
    mutationFn: () =>
      revokeConsent({
        keyId: activeKey!,
        channel,
        targetVariant: variantOverride ?? undefined,
      }),
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

  return (
    <section className="page">
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
        </div>
        {/*
          P0-4：投递方式改成双单选、网关在前且带「推荐」徽标，直连在后且带
          「次选」徽标。只换呈现与默认选中：派生的 `mode`、预览查询键、
          同意门禁、投递/回滚调用一字不动；直连仍可选，只是不再是默认值。
        */}
        <div className="delivery-mode" role="radiogroup" aria-label={t("agents.gatewayMode.modeLabel")}>
          <span className="muted">{t("agents.gatewayMode.modeLabel")}</span>
          <div className="radio-row">
            <label className="radio">
              <input
                type="radio"
                name="delivery-mode"
                checked={gatewayMode}
                onChange={() => setGatewayMode(true)}
              />
              <span>{t("agents.gatewayMode.label")}</span>
              <span className="badge badge-ok">{t("agents.gatewayMode.recommended")}</span>
            </label>
            <label className="radio">
              <input
                type="radio"
                name="delivery-mode"
                checked={!gatewayMode}
                onChange={() => setGatewayMode(false)}
              />
              <span>{t("agents.gatewayMode.siteLabel")}</span>
              <span className="badge badge-muted">{t("agents.gatewayMode.secondary")}</span>
            </label>
          </div>
        </div>
        {/*
          P1-7：只打印不写盘的预览开关（默认关）。打开后预览查询走预览专用
          入口，PlanView 只渲染横幅、不给投递按钮；关掉才恢复正常投递流程。
          变体下拉只在后端清单长度 > 1 时出现（目前只有 Cline 通道），
          选项与当前值一律来自后端 plan，不在界面里硬编码清单。
        */}
        <label className="checkline">
          <input
            type="checkbox"
            checked={previewOnly}
            onChange={(e) => setPreviewOnly(e.target.checked)}
          />
          <span>{t("agents.plan.previewOnlyToggle")}</span>
        </label>
        {plan.data && plan.data.targetVariants && plan.data.targetVariants.length > 1 ? (
          <label className="checkline">
            <span>{t("agents.plan.variantLabel")}</span>
            <select
              value={variantOverride ?? plan.data.targetVariant}
              onChange={(e) => setVariantOverride(e.target.value)}
            >
              {plan.data.targetVariants.map((v) => (
                <option key={v} value={v}>
                  {/* 原生 <option> 放不下 badge 徽标，只能在文案后追加
                      “未实测”后缀；计划视图里同一变体另有 badge-warn 徽标。 */}
                  {variantLabel(v)}
                  {isUnverifiedVariant(v) ? t("agents.plan.variant.unverifiedSuffix") : ""}
                </option>
              ))}
            </select>
          </label>
        ) : null}
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
        M34-S1：Agent 更新汇总卡。**只提示，不动手**——真正的执行必须点开确认弹窗、
        勾选同意后才会调 `update_agent`（前端只传 channel，命令来自后端静态表）。
        检查失败不阻塞工作台：这里只多一条错误 + 重试。
      */}
      <div className="card agent-updates">
        <div className="agent-updates-head">
          <h3>{t("agents.update.title")}</h3>
          <button
            type="button"
            className="btn agent-updates-refresh"
            disabled={updatesQuery.isFetching || !agentsQuery.isSuccess}
            onClick={() => {
              void updatesQuery.refetch();
            }}
          >
            {updatesQuery.isFetching ? t("agents.update.checking") : t("agents.update.refresh")}
          </button>
        </div>
        {updatesQuery.isError ? (
          <p className="error" role="alert">
            <AlertTriangle size={14} aria-hidden />{" "}
            {t("agents.update.checkFailed", { error: (updatesQuery.error as Error).message })}{" "}
            <button type="button" className="btn" onClick={() => void updatesQuery.refetch()}>
              {t("agents.update.retry")}
            </button>
          </p>
        ) : (
          <p className="agent-updates-summary">
            {updatesQuery.isLoading
              ? t("agents.update.checking")
              : t("agents.update.summary", {
                  available: updateCounts.available,
                  upToDate: updateCounts.upToDate,
                  unsupported: updateCounts.unsupported,
                  error: updateCounts.failed,
                })}
          </p>
        )}
        {lastCheckedAt ? (
          <p className="muted">
            {t("agents.update.lastChecked", {
              time: lastCheckedAt.toLocaleTimeString(undefined, {
                hour: "2-digit",
                minute: "2-digit",
              }),
            })}
          </p>
        ) : null}

        {/* 结果：成功走 p.ok[role=status]（含 from → to），失败走 warnbox 逐条列 attempts。
            复审 P2-1：`versionAfter === null` 时**不得**说「已更新到未知」——后端已给了准确
            话术（「更新后无法读取版本」），这里用同义的 i18n 文案，不用 `versionUnknown` 拼接。 */}
        {updateOutcome ? (
          updateOutcome.success ? (
            <p className="ok" role="status">
              {updateOutcome.versionAfter === null
                ? t("agents.update.versionUnreadable")
                : updateOutcome.versionChanged
                  ? t("agents.update.success", {
                      from: updateOutcome.versionBefore ?? t("agents.update.versionUnknown"),
                      to: updateOutcome.versionAfter,
                    })
                  : t("agents.update.unchanged")}
            </p>
          ) : (
            <div className="warnbox" role="alert">
              <p>
                <AlertTriangle size={14} aria-hidden /> {t("agents.update.failed")}
                {updateOutcome.message ? `：${updateOutcome.message}` : ""}
              </p>
              <UpdateAttempts outcome={updateOutcome} />
            </div>
          )
        ) : null}
        {updateError ? (
          <div className="warnbox" role="alert">
            <p>
              <AlertTriangle size={14} aria-hidden /> {t("agents.update.failed")}：{updateError}
            </p>
          </div>
        ) : null}
      </div>

      {/*
        M31-S1：单列工作台。一行一个落点——**不合并**同 agent 的多个目标文件
        （Codex / OpenCode / Cline 各有多处落点，合并会让用户看不到真实可投递面）。
      */}
      <div className="card agents-workbench">
        <h3>{t("agents.workbench.title", { count: CHANNELS.length })}</h3>
        <p className="muted">{t("agents.workbench.hint")}</p>
        {revokedHidden > 0 ? (
          <p className="muted">{t("agents.select.revokedHidden", { count: revokedHidden })}</p>
        ) : null}
        <ul className="agent-list">
          {CHANNELS.map((c) => {
            const status = agentByChannel.get(c.id);
            // M34-S1：更新检查结果（没有检查结果时 `undefined`，行上不渲染任何更新控件）。
            const update = updateByChannel.get(c.id);
            // 后端应返回 20 条；缺一条时是「状态未知」，绝不能当成「未安装」——
            // 那会给出一个装了也白装的安装按钮，且把已装环境说成没装。
            const known = status !== undefined;
            const installed = status?.installed === true;
            const detecting = agentsQuery.isLoading;
            const selectedKeyId = effectiveKeyId(c.id);
            const isOpen = expanded === c.id;
            const writingModel = !NO_MODEL_CHANNELS.has(c.id);
            const name = channelName(c.label);
            return (
              <li
                key={c.id}
                className={"agent-row" + (isOpen ? " open" : "")}
                data-agent-channel={c.id}
                data-agent-name={c.agent}
                data-agent-update-state={update?.state}
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

                  {/* M34-S1：只有「已安装 + 有新版」才出现徽标；不可一键更新的只留徽标（title=message）。 */}
                  {update && installed && update.state === "available" ? (
                    <span
                      className="agent-update-badge"
                      title={update.autoUpdate ? undefined : (update.message ?? undefined)}
                    >
                      {update.autoUpdate
                        ? t("agents.update.badge", { version: update.latestVersion ?? "" })
                        : t("agents.update.badgeNoAuto", { version: update.latestVersion ?? "" })}
                    </span>
                  ) : null}

                  {update && installed && update.state === "available" && update.autoUpdate ? (
                    <button
                      type="button"
                      className="btn agent-row-update"
                      onClick={() => openUpdateDialog(c.id)}
                    >
                      {t("agents.update.update")}
                    </button>
                  ) : null}

                  {detecting || (!known && !agentsQuery.isError) ? null : installed ? (
                    <div className="agent-row-controls">
                      <select
                        className="input agent-row-key"
                        aria-label={`${name} ${t("agents.select.key")}`}
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
                        <ModelPicker
                          keyId={selectedKeyId}
                          value={modelDraft[c.id] ?? ""}
                          onChange={(next) =>
                            setModelDraft((prev) => ({ ...prev, [c.id]: next }))
                          }
                          ariaLabel={`${name} ${t("agents.select.model")}`}
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
                        noChange={!!noChange}
                        agreeChecked={agreeChecked}
                        onAgreeChange={setAgreeChecked}
                        busy={grantAndApply.isPending}
                        onApply={() => setConfirming(true)}
                        onRevoke={() => setRevoking(true)}
                      />
                    ) : null}
                    {/* P1-5：一键重启区。key 换通道即重置结果/错误，不串台。
                        放在预览条件之外：重启不需要先选 key，投递失败时也能用。 */}
                    <RestartSection key={channel} channel={channel} />
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
          <div className="table-wrap">
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
          </div>
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
        {/* P0-2 复审 P1-2：确认弹窗同样列出全部写盘文件，不只入口文件。 */}
        <p>{t("agents.confirmDialog.applyBodyPre")}</p>
        <ul className="list">
          {(plan.data?.files?.length
            ? plan.data.files
            : plan.data
              ? [{ targetPath: plan.data.targetPath, targetExists: plan.data.targetExists }]
              : []
          ).map((f) => (
            <li key={f.targetPath}>
              <span className="mono">{f.targetPath}</span>{" "}
              {f.targetExists ? t("agents.confirmDialog.applyBodyExists") : t("agents.confirmDialog.applyBodyNew")}
            </li>
          ))}
        </ul>
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
        label={installFor ? channelName(CHANNELS.find((c) => c.id === installFor)?.label ?? "") : ""}
        copiedKey={copiedKey}
        onCopied={setCopiedKey}
        onClose={() => setInstallFor(null)}
        onRedetect={() => {
          agentsQuery.refetch();
        }}
      />

      {/*
        M34-S1：更新确认弹窗。**只在这里**才会调 `update_agent`，且必须勾选同意；
        pending 期间确认按钮禁用（文案变「更新中…」），重复点击不会再次执行。
      */}
      <ConfirmDialog
        open={updateFor !== null}
        title={t("agents.update.confirmTitle", {
          name: updateFor
            ? channelName(CHANNELS.find((c) => c.id === updateFor)?.label ?? updateFor)
            : "",
        })}
        confirmLabel={updateMutation.isPending ? t("agents.update.updating") : t("agents.update.confirm")}
        confirmDisabled={!updateAgree || updateMutation.isPending}
        onCancel={() => {
          if (updateMutation.isPending) return;
          setUpdateFor(null);
          setUpdateAgree(false);
        }}
        onConfirm={confirmUpdate}
      >
        {(() => {
          const target = updateFor ? updateByChannel.get(updateFor) : undefined;
          return (
            <>
              <div className="agent-update-versions">
                <span>
                  {t("agents.update.confirmCurrent")}：
                  <code className="mono">{target?.currentVersion ?? t("agents.update.versionUnknown")}</code>
                </span>
                <span aria-hidden>→</span>
                <span>
                  {t("agents.update.confirmLatest")}：
                  <code className="mono">{target?.latestVersion ?? t("agents.update.versionUnknown")}</code>
                </span>
              </div>
              <p>
                {t("agents.update.confirmSource")}：
                {target ? updateSourceLabel(target.source) : ""}
              </p>
              <p>
                {t("agents.update.confirmCommand")}：
                <code className="mono agent-update-command">{target?.command ?? ""}</code>
              </p>
              <p className="muted">{t("agents.update.confirmRisk")}</p>
              <label className="checkline">
                <input
                  type="checkbox"
                  checked={updateAgree}
                  disabled={updateMutation.isPending}
                  onChange={(e) => setUpdateAgree(e.target.checked)}
                />
                <span>{t("agents.update.agree")}</span>
              </label>
            </>
          );
        })()}
      </ConfirmDialog>

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
      // 失败也按 key 记录：此前用全局 "__failed__" 会让**所有**复制按钮
      // 同时显示「复制失败」，用户分不清是哪一条没复制成功（复审 P3-1）。
      onCopied(`failed:${key}`);
      setTimeout(() => onCopied(null), 1500);
    }
  };

  return (
    <dialog ref={ref} className="dialog install-dialog" aria-label={t("agents.install.title", { name: label })}>
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
                      : copiedKey === `failed:${key}`
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
              {copiedKey === "__url__"
                ? t("agents.install.copied")
                : copiedKey === "failed:__url__"
                  ? t("agents.install.copyFailed")
                  : t("agents.install.copy")}
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

/**
 * 一次更新失败的「执行记录」（M34-S1 §4.5）：逐条列出每次尝试的 label / command /
 * exitCode / timedOut / skipped 与输出尾部。
 *
 * 输出尾部由后端去 ANSI + 脱敏 + 截断，这里只负责展示，**不做二次处理**。
 */
function UpdateAttempts({ outcome }: { outcome: AgentUpdateOutcome }) {
  const { t } = useTranslation();
  if (outcome.attempts.length === 0) return null;
  return (
    <div className="agent-update-result">
      <p className="muted">{t("agents.update.attemptsTitle")}</p>
      {outcome.attempts.map((attempt, index) => (
        <div className="agent-update-attempt" key={`${attempt.label}-${index}`}>
          <div className="agent-update-attempt-head">
            <span className="badge">{attempt.label}</span>
            <code className="mono agent-update-command">{attempt.command}</code>
            {attempt.skipped ? (
              <span className="badge badge-warn">{t("agents.update.attemptSkipped")}</span>
            ) : (
              <>
                <span className={attempt.success ? "badge badge-ok" : "badge badge-warn"}>
                  {attempt.success ? t("agents.update.attemptOk") : t("agents.update.attemptFail")}
                </span>
                {attempt.timedOut ? (
                  <span className="badge badge-warn">{t("agents.update.attemptTimeout")}</span>
                ) : null}
                {attempt.exitCode !== null ? (
                  <span className="muted mono">
                    {t("agents.update.attemptExit", { code: attempt.exitCode })}
                  </span>
                ) : null}
              </>
            )}
          </div>
          {attempt.outputTail ? (
            <pre className="mono">
              <span className="muted">{t("agents.update.attemptOutput")}</span>
              {"\n"}
              {attempt.outputTail}
            </pre>
          ) : null}
        </div>
      ))}
    </div>
  );
}

/**
 * 一键重启区（投递改进 P1-5）。
 *
 * 第一批只做两类目标：Codex（两条通道共用一个桌面重启）与 Claude Desktop，都是
 * 「完全退出重开」。Codex 行的标题/确认/结果文案必须点名实际目标 ChatGPT 桌面应用，
 * 不得复用「Codex CLI」之名；终端 codex 会话不受按钮影响，靠可复制命令自行重开。
 * 其余 CLI 类 agent 不给重启按钮，只给可复制的启动命令——
 * 应用绝不替用户拉终端进程（启动命令的 bin 名与后端 agents.rs 的探测 bin 同源）。
 * App / 扩展类通道（Cursor、Trae、Cline、Cline Desktop、DSH）既无重启按钮也无
 * 启动命令：本项不做它们，不给点了才报错的按钮。
 *
 * daemon 清单项永远是「未验证」：后端结果的 daemon 状态恒为 unverified，这里只负责
 * 原样渲染，不得把它画成已通过。只杀窗口可能不生效的说明见 i18n 文案。
 */
const RESTART_TARGET_BY_CHANNEL: Record<string, "codex" | "claude-desktop"> = {
  "codex-auth-json": "codex",
  "codex-config": "codex",
  "claude-desktop": "claude-desktop",
};

const CLI_LAUNCH_COMMANDS: Record<string, string> = {
  "claude-code-settings": "claude",
  opencode: "opencode",
  "opencode-jsonc": "opencode",
  "gemini-cli": "gemini",
  "grok-build": "grok",
  openclaw: "openclaw",
  hermes: "hermes",
  mcode: "mcode",
  pi: "pi",
  "qwen-code": "qwen",
  deepseek: "reasonix",
  "mimo-code": "mimocode",
};

function RestartSection({ channel }: { channel: string }) {
  const { t } = useTranslation();
  const target = RESTART_TARGET_BY_CHANNEL[channel];
  const cliCommand = CLI_LAUNCH_COMMANDS[channel];
  const [confirming, setConfirming] = useState(false);
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<RestartOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  if (!target && !cliCommand) return null;

  const name = channelName(CHANNELS.find((c) => c.id === channel)?.label ?? channel);

  const copy = async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      setCopied(`failed:${key}`);
      setTimeout(() => setCopied(null), 1500);
    }
  };

  const run = async () => {
    if (!target || pending) return;
    setPending(true);
    setError(null);
    try {
      const outcome =
        target === "codex" ? await restartCodex() : await restartClaudeDesktop();
      setResult(outcome);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setPending(false);
      setConfirming(false);
    }
  };

  const copyRow = (key: string, command: string) => (
    <p className="install-cmd">
      <code className="mono install-cmd-text">{command}</code>
      <button type="button" className="btn" onClick={() => copy(key, command)}>
        <Copy size={14} aria-hidden />{" "}
        {copied === key
          ? t("agents.install.copied")
          : copied === `failed:${key}`
            ? t("agents.install.copyFailed")
            : t("agents.install.copy")}
      </button>
    </p>
  );

  return (
    <div className="card">
      {target ? (
        <>
          <div className="row row-between">
            <h4>
              {target === "codex"
                ? t("agents.restart.codexTitle")
                : t("agents.restart.title", { name })}
            </h4>
          </div>
          <p className="muted">
            {target === "codex"
              ? t("agents.restart.codexHint")
              : t("agents.restart.hint")}
          </p>
          <div className="row">
            <button
              type="button"
              className="btn btn-danger"
              disabled={pending}
              onClick={() => {
                setError(null);
                setConfirming(true);
              }}
            >
              <RotateCcw size={14} aria-hidden /> {t("agents.restart.button")}
            </button>
          </div>
          {error ? (
            <p className="error" role="alert">
              <AlertTriangle size={14} aria-hidden /> {error}
            </p>
          ) : null}
          {result ? (
            <div role="status">
              <p className="ok">
                {result.wasRunning
                  ? target === "codex"
                    ? t("agents.restart.codexResultWasRunning")
                    : t("agents.restart.resultWasRunning")
                  : target === "codex"
                    ? t("agents.restart.codexResultWasNotRunning")
                    : t("agents.restart.resultWasNotRunning")}
              </p>
              {result.forceKilled ? (
                <p className="muted">{t("agents.restart.resultForceKilled")}</p>
              ) : null}
              <p className="muted">
                {result.relaunched && result.appeared
                  ? target === "codex"
                    ? t("agents.restart.codexResultAppeared")
                    : t("agents.restart.resultAppeared")
                  : result.relaunched
                    ? t("agents.restart.resultNotAppeared")
                    : t("agents.restart.resultNotLaunched")}
              </p>
            </div>
          ) : null}
          {/* daemon 独立验证项：状态只取后端给的 unverified 渲染，绝不画成已通过。 */}
          <ul className="list">
            <li>
              <span className="badge badge-warn">
                {t("agents.restart.daemonUnverified")}
              </span>{" "}
              <strong>{t("agents.restart.daemonTitle")}</strong>
              <div className="muted">{t("agents.restart.daemonNote")}</div>
              {result?.appServerDaemonNote ? (
                <div className="muted">{result.appServerDaemonNote}</div>
              ) : null}
            </li>
          </ul>
          {/* Codex 的终端会话不受桌面重启影响：可复制命令常驻，投递时停掉的 CLI
              会话也靠它重开。Claude Desktop 没有 CLI 命令，不渲染这一行。 */}
          {target === "codex" ? (
            <div>
              <p className="muted">{t("agents.restart.codexCliHint")}</p>
              {copyRow("restart-cli", result?.manualLaunchCommand ?? "codex")}
            </div>
          ) : null}
          <ConfirmDialog
            open={confirming}
            title={
              target === "codex"
                ? t("agents.restart.codexConfirmTitle")
                : t("agents.restart.confirmTitle", { name })
            }
            danger
            confirmLabel={pending ? t("agents.restart.restarting") : t("agents.restart.confirm")}
            confirmDisabled={pending}
            onCancel={() => {
              if (pending) return;
              setConfirming(false);
            }}
            onConfirm={run}
          >
            <p>
              {target === "codex"
                ? t("agents.restart.codexConfirmBody")
                : t("agents.restart.confirmBody", { name })}
            </p>
            <p className="muted">{t("agents.restart.confirmDaemon")}</p>
            {target === "codex" ? (
              <p className="muted">{t("agents.restart.codexConfirmCliNote")}</p>
            ) : null}
          </ConfirmDialog>
        </>
      ) : (
        <>
          <div className="row row-between">
            <h4>{t("agents.restart.cliTitle")}</h4>
          </div>
          <p className="muted">{t("agents.restart.cliHint")}</p>
          {cliCommand ? copyRow("restart-cli", cliCommand) : null}
        </>
      )}
    </div>
  );
}

function PlanView({
  plan,
  noChange,
  agreeChecked,
  onAgreeChange,
  busy,
  onApply,
  onRevoke,
}: {
  plan: DeliveryPlan;
  noChange: boolean;
  agreeChecked: boolean;
  onAgreeChange: (v: boolean) => void;
  busy: boolean;
  onApply: () => void;
  onRevoke: () => void;
}) {
  const { t } = useTranslation();
  // P0-2 复审 P1-2：确认区按 `plan.files` 渲染——份数由后端给（双文件 2 份、
  // 保留模式 1 份、单通道 1 份），不得写死「永远两份」；files 为空（旧 mock）
  // 时用顶层字段拼一份，保持单文件行为。顶层字段只作回退，不再是确认依据。
  const files = plan.files?.length
    ? plan.files
    : [
        {
          channel: plan.channel,
          targetPath: plan.targetPath,
          targetExists: plan.targetExists,
          fields: plan.fields,
          preview: plan.preview,
          consent: plan.consent,
          isFirstDelivery: plan.isFirstDelivery,
          importedFields: plan.importedFields,
        },
      ];
  // P1-7：预览模式下只展示、不给任何写入口（按钮禁用、撤销隐藏）。
  const previewOnly = plan.previewOnly === true;
  const fileConsentLabel = (consent: string) => {
    if (consent === "granted") return t("agents.plan.consentGranted");
    if (consent === "revoked") return t("agents.plan.consentRevoked");
    return t("agents.plan.consentMissing");
  };
  return (
    <div className="card">
      <div className="row row-between">
        <h3>
          <ShieldCheck size={15} aria-hidden /> {t("agents.plan.title")}
        </h3>
      </div>

      {previewOnly ? (
        <p className="warnline" role="status">
          <AlertTriangle size={14} aria-hidden /> {t("agents.plan.previewOnlyBanner")}
        </p>
      ) : null}

      <dl className="kv">
        <dt>{t("agents.plan.agent")}</dt>
        <dd className="mono">{plan.agentId}</dd>
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
        {/* 生效策略：文案从 `restartHint` 取值派生，**不按通道硬编码**。
            认不出的取值原样显示（不静默留空——那会让用户以为「不需要重启」）。
            顶层只此一份：DTO 的 files[] 条目暂无 per-file restart_hint（复审 P2-3，
            已登记 BACKLOG，不在这里顺手改 DTO）。
            P1-6：同一行补动作与来源标注——动作说“到底要动什么”，来源标注说
            “这话从哪来、有没有实测”；已实测徽标只在后端给 verified 时出现。 */}
        <dt>{t("agents.plan.restart")}</dt>
        <dd>
          {restartHintLabel(plan.restartHint)}
          <div className="muted">{restartHintActionLabel(plan.restartHintAction)}</div>
          <span
            className={
              plan.restartHintSource === "verified" ? "badge badge-ok" : "badge badge-warn"
            }
          >
            {restartHintSourceLabel(plan.restartHintSource)}
          </span>
        </dd>
        {/* P1-7 修复（复审 P1-1）：当前生效变体。只在多变体通道出现
            （与下拉同条件）；Insiders / Cursor 未经实测，名后挂 P1-6
            同款 badge-warn 徽标，不新增样式；默认 code 变体不挂。 */}
        {plan.targetVariants && plan.targetVariants.length > 1 ? (
          <>
            <dt>{t("agents.plan.variantLabel")}</dt>
            <dd>
              {variantLabel(plan.targetVariant)}{" "}
              {isUnverifiedVariant(plan.targetVariant) ? (
                <span className="badge badge-warn">{t("agents.plan.variant.unverified")}</span>
              ) : null}
            </dd>
          </>
        ) : null}
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

      {/* P2-8：投递前模型验证（静态配对 + /v1/models 探针），计划阶段产出。
          判据与硬拦结论只来自后端字段（`modelValidation`），页面不按
          outcome/code 自己算拦不拦（见 deliveryView.modelValidationBlocks）；
          字段缺失（旧二进制）时整段不渲染、不禁用投递。
          探针只读：这里展示的是「投递前问过端点」的结果，不是记账。 */}
      {plan.modelValidation ? (
        <section aria-label={t("agents.plan.modelValidation.title")}>
          <h4>{t("agents.plan.modelValidation.title")}</h4>
          <dl className="kv">
            <dt>{t("agents.plan.modelValidation.staticLabel")}</dt>
            <dd>{t(modelValidationStaticKey(plan.modelValidation.staticCode))}</dd>
            <dt>{t("agents.plan.modelValidation.probeLabel")}</dt>
            <dd>
              {t(modelValidationProbeKey(plan.modelValidation.probeCode), {
                status: plan.modelValidation.probeStatus ?? "",
              })}
            </dd>
          </dl>
          {modelValidationBlocks(plan.modelValidation) ? (
            <p className="warnline" role="alert">
              <AlertTriangle size={14} aria-hidden />{" "}
              {t("agents.plan.modelValidation.blocked")}
            </p>
          ) : null}
        </section>
      ) : null}

      {files.map((file, index) => (
        <section key={file.targetPath}>
          <div className="row row-between">
            <h4>{t("agents.plan.fileTitle", { index: index + 1, total: files.length })}</h4>
            <span className={`badge badge-${file.consent === "granted" ? "ok" : "warn"}`}>
              {fileConsentLabel(file.consent)}
            </span>
          </div>
          <dl className="kv">
            <dt>{t("agents.plan.target")}</dt>
            <dd className="mono ellipsis" title={file.targetPath}>
              {file.targetPath} {file.targetExists ? t("agents.plan.targetExists") : t("agents.plan.targetNew")}
            </dd>
            <dt>{t("agents.plan.willWrite")}</dt>
            <dd>
              {file.fields.map((f) => (
                <span key={f.key} className="chip mono">
                  {f.key} = {f.masked}
                </span>
              ))}
            </dd>
            {/*
              P1-7：首次导入展示（只读预览，不是投递内容）。只在该文件
              算首次且导入到了值时出现；导入值绝不自动成为投递内容，
              用户想沿用旧值必须自己填成投递参数并确认后才写盘。
            */}
            {file.isFirstDelivery && file.importedFields && file.importedFields.length > 0 ? (
              <>
                <dt>{t("agents.plan.importedTitle")}</dt>
                <dd>
                  {file.importedFields.map((f) => (
                    <span key={f.key} className="chip mono">
                      {f.key} = {f.masked}
                    </span>
                  ))}
                  <div className="muted">{t("agents.plan.importedHint")}</div>
                </dd>
              </>
            ) : null}
          </dl>
          <h4>{t("agents.plan.diffTitle")}</h4>
          {/* 删除行的值侧掩掉（P2-5）：后端只对**已知的**密钥串做替换，旧站点密钥
              形态未必落在 scrub 认得的集合里；渲染层先保证不把旧值显示出来。
              `+` 行逐字节保留——那是「将要写进去什么」，掩掉等于掩盖改动。 */}
          <pre className="diff">
            {maskRemovedValues(file.preview, t("agents.plan.removedValueMasked"))}
          </pre>
        </section>
      ))}

      {previewOnly ? null : noChange ? (
        <p className="muted">{t("agents.plan.noChange")}</p>
      ) : (
        <label className="checkline">
          <input
            type="checkbox"
            checked={agreeChecked}
            onChange={(e) => onAgreeChange(e.target.checked)}
          />
          {/* 同意门禁语义：勾选 = 看过本次全部写盘文件的差异。双文件时用 agreeAll，
              单文件时沿用旧文案——门禁本身仍是同一个 agreeChecked，不另设复选框。 */}
          <span>{files.length > 1 ? t("agents.plan.agreeAll") : t("agents.plan.agree")}</span>
        </label>
      )}

      <div className="row">
        <button
          type="button"
          className="btn btn-primary"
          // P2-8：验证硬拦时禁用投递（与 previewOnly / noChange 同列门禁）；
          // 后端 apply 还会再探一次并拒绝写盘，前端禁用只是第一层。
          disabled={
            previewOnly ||
            !agreeChecked ||
            busy ||
            noChange ||
            modelValidationBlocks(plan.modelValidation)
          }
          onClick={onApply}
        >
          <Send size={14} aria-hidden /> {t("agents.btn.apply")}
        </button>
        {previewOnly ? null : plan.consent === "granted" ? (
          <button type="button" className="btn" onClick={onRevoke}>
            <RotateCcw size={14} aria-hidden /> {t("agents.btn.revoke")}
          </button>
        ) : null}
      </div>
    </div>
  );
}
