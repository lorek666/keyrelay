import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Copy, Play, RefreshCw, Square } from "lucide-react";
import {
  channelOfBinding,
  deliveryPlan,
  gatewayRotateToken,
  gatewayStart,
  gatewayStatus,
  gatewayStop,
  listChannelBindings,
  listSites,
  listStoredKeys,
  applyDelivery,
  type ChannelBinding,
  type DeliveryPlan,
} from "../lib/api";
import { maskRemovedValues } from "../lib/deliveryView";
import { useTranslation } from "../i18n";

type Props = {
  enabled: boolean;
  port: number;
  /** 跨站选路开关（M16-S6b：此前只有 DTO 字段，界面不可达）。 */
  multiSite: boolean;
  onToggle: (enabled: boolean) => void;
  onPortChange: (port: number) => void;
  onMultiSiteChange: (enabled: boolean) => void;
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
export default function GatewayCard({
  enabled,
  port,
  multiSite,
  onToggle,
  onPortChange,
  onMultiSiteChange,
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

  return (
    <div className="card">
      <h3>{t("gateway.title")}</h3>
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
            <dt>{t("gateway.kv.tokenStorage")}</dt>
            <dd>
              {status.data?.tokenPersistent ? (
                <span className="badge badge-ok">{t("gateway.status.persistent")}</span>
              ) : (
                <span className="badge badge-warn">{t("gateway.status.temporary")}</span>
              )}
            </dd>
          </dl>
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

      {error ? <p className="error" role="alert">{error}</p> : null}
    </div>
  );
}
