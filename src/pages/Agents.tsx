import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, RotateCcw, Send, ShieldCheck, Undo2, Unlink } from "lucide-react";
import {
  applyDelivery,
  deliveryPlan,
  detectUnmanagedTargets,
  grantConsent,
  listConsents,
  listStoredKeys,
  listSites,
  revokeConsent,
  rollbackDelivery,
  unbindAgent,
  type DeliveryMode,
  type DeliveryOutcome,
  type DeliveryPlan,
  type RestartHint,
  type UnbindOutcome,
} from "../lib/api";
import { rollbackAftermath } from "../lib/rollback";
import ConfirmDialog from "../components/ConfirmDialog";

/**
 * 十七条投递通道（M14-S1 删 Continue/Shell，新增 Claude Desktop/Grok/OpenClaw/Hermes/MCode/Pi）。
 *
 * 这里的 `label` 是**给人看的落点提示**；能力判断不在这里——投递能不能做、
 * 改完要不要重启，一律由后端给（`plan.restartHint`），本文件不得按通道硬编码判断。
 */
const CHANNELS = [
  { id: "codex-auth-json", label: "Codex CLI（~/.codex/auth.json）", agent: "codex" },
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
];

/**
 * 生效策略文案（PRD FR-4:137 / M7-S3 的 `restart_hint`）。
 *
 * **从取值派生，不按通道硬编码**：新增一条通道时，后端那张表会给出新取值，
 * 界面这里照显；反过来，如果按通道写判断，新增通道必然漏一处，
 * 而漏掉的那处会给用户一个错的生效预期（以为改完就生效，其实要重启）。
 */
const RESTART_HINTS: Record<RestartHint, string> = {
  notNeeded: "改完即生效：该 agent 每次运行都会重新读这个文件。",
  needed: "需要重启该 agent 才能读到新配置——它只在启动时读一次。",
  dependsOnNewSession:
    "只对新开的会话生效：已经在跑的窗口读到的还是旧配置（例如 shell rc 文件）。",
};

export default function Agents() {
  const qc = useQueryClient();
  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });
  const [siteId, setSiteId] = useState<number | null>(null);
  const activeSite = siteId ?? sites.data?.[0]?.id ?? null;

  // 投递需要**本地 key id**，所以用 stored keys 而不是站点侧列表
  const keys = useQuery({ queryKey: ["stored-keys"], queryFn: listStoredKeys });
  // 密钥下拉只列所选站点的（M9-S4 / C）：此前站点下拉只是摆设——选了站点 A，
  // 密钥下拉里照样是全部站点的密钥，选项文字又不带站点，用户分不出投的是哪个站的 key。
  const siteKeys = (keys.data ?? []).filter((k) => k.siteId === activeSite);

  const [keyId, setKeyId] = useState<number | null>(null);
  const activeKey = keyId ?? null;
  const [channel, setChannel] = useState(CHANNELS[0].id);

  // 模型名：当前没有通道在界面层强制要求模型名（OpenCode 可选填）。
  // 这是**输入框显不显示**的界面判断，不是能力判断：要不要、缺了怎么办由后端决定并报错说明。
  // 防抖后再进查询键——每次预览都要读一次钥匙串，不该每敲一个字读一次。
  const needsModel = false;
  // 当前通道所属的 agent（解绑按 agent 做，不是按通道）。
  // `channel` 只可能来自 `CHANNELS`（初始值与下拉都在其中），所以这里的兜底不可达；
  // 用空串而不是 `!`：解绑命令对空 agent_id 只会返回 `{0, 0}`（幂等零报告），不会误伤。
  const activeAgent = CHANNELS.find((c) => c.id === channel)?.agent ?? "";
  const [modelInput, setModelInput] = useState("");
  const [modelTyped, setModelTyped] = useState("");
  useEffect(() => {
    const timer = setTimeout(() => setModelTyped(modelInput.trim()), 400);
    return () => clearTimeout(timer);
  }, [modelInput]);
  const model = needsModel && modelTyped ? modelTyped : undefined;

  const [agreeChecked, setAgreeChecked] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [confirmingRollback, setConfirmingRollback] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastOutcome, setLastOutcome] = useState<DeliveryOutcome | null>(null);

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

  const noChange = plan.data?.preview.trim() === "(无变化)";

  const grantAndApply = useMutation({
    mutationFn: async () => {
      await grantConsent({ keyId: activeKey!, channel });
      return applyDelivery({ keyId: activeKey!, channel, model, mode });
    },
    onSuccess: async (outcome) => {
      setError(null);
      setLastOutcome(outcome);
      // 生效策略必须跟着结果一起说：用户最容易在这里以为「已经生效了」
      const hint = plan.data ? RESTART_HINTS[plan.data.restartHint] : "";
      setNotice(
        `已投递到 ${outcome.targetPath}（变更 ${outcome.journalId}）。${hint}`,
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
    mutationFn: () => revokeConsent({ keyId: activeKey!, channel }),
    onSuccess: async () => {
      setNotice("已撤销同意。已写入的文件不会被自动回滚——如需还原请用「变更历史」页。");
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
      // 与历史页同一句（复审 P2-1）：此前这里只说了「已回滚」，对之后的漂移告警一个字都没提
      const agent =
        CHANNELS.find((c) => c.id === lastOutcome?.channel)?.agent ?? lastOutcome?.channel ?? "";
      setNotice(`已回滚 ${lastOutcome?.journalId}。${rollbackAftermath(agent)}`);
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
    if (state === "granted") return "已同意";
    if (state === "revoked") return "已撤销";
    return "未同意";
  }, [plan.data?.consent]);

  return (
    <section>
      <p className="muted">
        投递会把钥匙串里的密钥写进所选 agent 的配置文件。
        任何写入都必须先勾选同意；写入前会展示脱敏后的差异预览。
      </p>

      {notice ? <p className="ok" role="status">{notice}</p> : null}
      {error ? (
        <p className="error" role="alert">
          <AlertTriangle size={14} aria-hidden /> {error}
        </p>
      ) : null}

      <div className="card">
        <div className="row">
          <label className="field-inline">
            <span>站点</span>
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
            <span>密钥</span>
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
              <option value="">（选择一把）</option>
              {siteKeys.map((k) => (
                <option key={k.id} value={k.id}>
                  {k.name}（#{k.id}）
                </option>
              ))}
            </select>
          </label>
          <label className="field-inline">
            <span>通道</span>
            <select
              className="input"
              value={channel}
              onChange={(e) => setChannel(e.target.value)}
            >
              {CHANNELS.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.label}
                </option>
              ))}
            </select>
          </label>
          {needsModel ? (
            <label className="field-inline">
              <span>模型名</span>
              <input
                className="input"
                value={modelInput}
                onChange={(e) => setModelInput(e.target.value)}
                placeholder="例如 gpt-4o"
                spellCheck={false}
              />
            </label>
          ) : null}
        </div>

        {/*
          指向本地网关（M8-S4 §6.2）。这是**投递参数**，不是新通道：
          通道还是那七条，落点一字不变，只把写进去的 base_url 与密钥换成网关的。
          换站时靠它做到「agent 侧零改动」（FR-5:158）。
        */}
        <label className="checkline">
          <input
            type="checkbox"
            checked={gatewayMode}
            onChange={(e) => setGatewayMode(e.target.checked)}
          />
          <span>
            指向本地网关：写进去的是网关地址（<span className="mono">/v1</span>
            ）与<strong>本地令牌</strong>，不是站点密钥。之后换站只要重启网关，
            agent 侧不用改。需要网关正在运行。
          </span>
        </label>

        {needsModel ? (
          <p className="muted">
            OpenCode 通道可填模型名。
            KeyRelay 不替你猜：首次投递请填写；留空则沿用上次投递时写下的模型名。
          </p>
        ) : null}
      </div>

      {activeKey === null ? (
        <p className="muted">
          {keys.data && siteKeys.length === 0
            ? "该站点下还没有本地密钥，先去「密钥」页新建一把。"
            : "先选一把密钥。"}
        </p>
      ) : plan.isError ? (
        <p className="error" role="alert">
          {(plan.error as Error).message}
        </p>
      ) : plan.isLoading ? (
        <p className="muted">生成预览…</p>
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

      {lastOutcome ? (
        <div className="card">
          <h3>上次投递</h3>
          <p className="mono">
            {lastOutcome.channel} → {lastOutcome.targetPath}
          </p>
          <p className="muted mono">
            journal={lastOutcome.journalId}
            {lastOutcome.backupPath ? `　备份=${lastOutcome.backupPath}` : ""}
          </p>
          {/* 这张卡只活在本页（切页即卸载）；持久的回滚入口在历史页（M9-S4 / B） */}
          <p className="muted">离开本页后，这次投递仍可以在「变更历史」页找到并回滚。</p>
          <button
            type="button"
            className="btn btn-danger"
            disabled={rollback.isPending}
            onClick={() => setConfirmingRollback(true)}
          >
            <Undo2 size={14} aria-hidden /> 回滚这次投递
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
        <h3>不托管的落点（只读探测）</h3>
        <p className="muted">
          这些 agent 的配置落点本版本<strong>不写</strong>：往一个 agent 不会读的文件里
          写密钥，比不写更糟——你会以为投递成功了。下面是本机实际探测结果
          （只读：不创建目录、不写盘）。
        </p>
        {unmanaged.isLoading ? <p className="muted">探测中…</p> : null}
        {unmanaged.isError ? (
          <p className="muted">
            探测失败：{(unmanaged.error as Error).message}
          </p>
        ) : null}
        {unmanaged.data?.length ? (
          <ul className="list">
            {unmanaged.data.map((target) => (
              <li key={`${target.label}-${target.path}`}>
                <span
                  className={`badge badge-${target.exists ? "warn" : "muted"}`}
                >
                  {target.exists ? "检测到" : "未检测到"}
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
          <p className="muted">本版本没有已知的不托管落点。</p>
        ) : null}
      </div>

      <div className="card">
        <h3>已记录的同意（{consents.data?.length ?? 0}）</h3>
        {consents.data?.length ? (
          <table className="table">
            <thead>
              <tr>
                <th>Agent</th>
                <th>通道</th>
                <th>目标</th>
                <th>键</th>
                <th>状态</th>
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
                        已撤销 {formatTs(row.revokedAt)}
                      </span>
                    ) : (
                      <span className="badge badge-ok" title={formatTs(row.grantedAt)}>
                        有效 · 同意于 {formatTs(row.grantedAt)}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="muted">还没有任何同意记录。</p>
        )}
      </div>

      {/*
        解绑（M8-S4 §5.4 / FR-2:115）。「解绑」不是「删除」：
        `bindings` 的行是「哪个 agent 曾被哪个 key 写到哪个文件」的唯一记录，
        删掉它等于同时丢掉漂移追溯与「这把 key 服务过哪些目标」。
      */}
      <div className="card">
        <h3>解绑</h3>
        <p className="muted">
          解绑只解除 KeyRelay 与本机 agent 配置的绑定关系，
          <strong>不会</strong>动站点侧那把 key，也不会删除本地的密钥记录——
          解绑之后该目标不再出现在「配置漂移」里，历史仍可查。
        </p>
        <p className="muted mono">agent = {activeAgent}</p>
        <button
          type="button"
          className="btn btn-danger"
          disabled={!activeAgent}
          onClick={() => {
            setAlsoRevoke(false);
            setUnbinding(true);
          }}
        >
          <Unlink size={14} aria-hidden /> 解绑 {activeAgent || "该 agent"}
        </button>

        {unbindResult ? (
          <div className="okbox" role="status">
            <p>
              {unbindResult.unbound > 0
                ? `本次解绑了 ${unbindResult.unbound} 条绑定。`
                : "本次没有新解开任何绑定。"}
              {unbindResult.alreadyUnbound > 0
                ? `另有 ${unbindResult.alreadyUnbound} 条本来就是解绑状态。`
                : ""}
            </p>
            {unbindResult.revoked.length > 0 ? (
              <ul className="list">
                {unbindResult.revoked.map((r) => (
                  <li key={`${r.siteId}-${r.remoteId ?? "local"}`}>
                    {r.revoked ? (
                      <span className="badge badge-ok">已回收</span>
                    ) : (
                      <span className="badge badge-warn">回收失败</span>
                    )}{" "}
                    <span className="mono">
                      站点 #{r.siteId} · {r.remoteId ?? "（本地无站点侧 id）"}
                    </span>
                    {r.revoked && !r.localStatusUpdated ? (
                      <div className="muted">
                        站点侧已删除（不可逆），但本地状态没写上。
                      </div>
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
        title="确认投递"
        confirmLabel={grantAndApply.isPending ? "写入中…" : "我同意，写入"}
        confirmDisabled={!agreeChecked || grantAndApply.isPending}
        onCancel={() => setConfirming(false)}
        onConfirm={() => grantAndApply.mutate()}
      >
        <p>
          即将把密钥写入 <span className="mono">{plan.data?.targetPath}</span>
          {plan.data?.targetExists ? "（文件已存在，将只改动下列键）" : "（文件不存在，将新建）"}。
        </p>
        <label className="checkline">
          <input
            type="checkbox"
            checked={agreeChecked}
            onChange={(e) => setAgreeChecked(e.target.checked)}
          />
          <span>
            我明白这会以<span className="mono"> 0600 </span>权限写入上述文件，且会先留一份备份。
          </span>
        </label>
      </ConfirmDialog>

      <ConfirmDialog
        open={confirmingRollback}
        title="回滚这次投递"
        danger
        confirmLabel={rollback.isPending ? "回滚中…" : "回滚"}
        confirmDisabled={rollback.isPending}
        onCancel={() => setConfirmingRollback(false)}
        onConfirm={() => rollback.mutate()}
      >
        <p>
          会把目标文件还原到这次投递之前的内容（逐字节比对）。
          如果文件在那之后被别的程序改过，回滚会被拒绝，而不是覆盖掉别人的改动。
        </p>
        <p className="muted mono">{lastOutcome?.targetPath}</p>
      </ConfirmDialog>

      <ConfirmDialog
        open={revoking}
        title="撤销投递同意"
        danger
        confirmLabel="撤销"
        confirmDisabled={revoke.isPending}
        onCancel={() => setRevoking(false)}
        onConfirm={() => revoke.mutate()}
      >
        <p>
          撤销后无法再向该通道投递，已经写入的文件不会被自动还原。
          如需还原内容，请到「变更历史」页回滚。
        </p>
      </ConfirmDialog>

      <ConfirmDialog
        open={unbinding}
        title={`解绑 ${activeAgent}`}
        danger
        confirmLabel={unbind.isPending ? "处理中…" : "解绑"}
        confirmDisabled={unbind.isPending}
        onCancel={() => setUnbinding(false)}
        onConfirm={() => unbind.mutate()}
      >
        <p>
          解绑只解除 KeyRelay 与本机 agent 配置的绑定关系，
          <strong>不会</strong>动站点侧那把 key。已写入的文件内容保持不变，
          之后仍可用「变更历史」页回滚那次投递。
        </p>
        <label className="checkline">
          <input
            type="checkbox"
            checked={alsoRevoke}
            onChange={(e) => setAlsoRevoke(e.target.checked)}
          />
          <span>
            同时回收站点侧的这把 key（<strong>不可逆</strong>：站点上删掉就没有了，
            正在别处使用它的程序会立刻失效）
          </span>
        </label>
      </ConfirmDialog>
    </section>
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
  return (
    <div className="card">
      <div className="row row-between">
        <h3>
          <ShieldCheck size={15} aria-hidden /> 投递预览
        </h3>
        <span className={`badge badge-${plan.consent === "granted" ? "ok" : "warn"}`}>
          {consentLabel}
        </span>
      </div>

      <dl className="kv">
        <dt>Agent</dt>
        <dd className="mono">{plan.agentId}</dd>
        <dt>目标文件</dt>
        <dd className="mono ellipsis" title={plan.targetPath}>
          {plan.targetPath} {plan.targetExists ? "（已存在）" : "（将新建）"}
        </dd>
        {/* 模式必须显式说出来（M8-S4 §6.6）：两种模式的字段名一模一样
            （`apiKey` / `apiBase`），不说用户分不清写进去的是站点密钥还是本地令牌。 */}
        <dt>写入的是</dt>
        <dd>
          {plan.mode === "gateway" ? (
            <span className="badge badge-warn">
              本地网关令牌（不是站点密钥）
            </span>
          ) : plan.mode === "site" ? (
            <span className="badge badge-ok">站点密钥</span>
          ) : (
            <span className="badge badge-warn">
              未知的投递模式：{plan.mode}
            </span>
          )}
        </dd>
        <dt>将写入</dt>
        <dd>
          {plan.fields.map((f) => (
            <span key={f.key} className="chip mono">
              {f.key} = {f.masked}
            </span>
          ))}
        </dd>
        {/* 生效策略：文案从 `restartHint` 取值派生，**不按通道硬编码**。
            认不出的取值原样显示（不静默留空——那会让用户以为「不需要重启」）。 */}
        <dt>生效方式</dt>
        <dd>
          {RESTART_HINTS[plan.restartHint] ??
            `未知的生效策略：${plan.restartHint}`}
        </dd>
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

      <h4>差异预览（已脱敏）</h4>
      <pre className="diff">{plan.preview}</pre>

      {noChange ? (
        <p className="muted">配置已是最新，无需改动。</p>
      ) : (
        <label className="checkline">
          <input
            type="checkbox"
            checked={agreeChecked}
            onChange={(e) => onAgreeChange(e.target.checked)}
          />
          <span>
            我同意把上述密钥写入该 agent 的配置（写入前会备份，可回滚）
          </span>
        </label>
      )}

      <div className="row">
        <button
          type="button"
          className="btn btn-primary"
          disabled={!agreeChecked || busy || noChange}
          onClick={onApply}
        >
          <Send size={14} aria-hidden /> 投递
        </button>
        {plan.consent === "granted" ? (
          <button type="button" className="btn" onClick={onRevoke}>
            <RotateCcw size={14} aria-hidden /> 撤销同意
          </button>
        ) : null}
      </div>
    </div>
  );
}
