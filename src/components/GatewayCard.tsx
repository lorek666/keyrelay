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

type Props = {
  enabled: boolean;
  port: number;
  onToggle: (enabled: boolean) => void;
  onPortChange: (port: number) => void;
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
  onToggle,
  onPortChange,
  settingsDirty,
}: Props) {
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
      setError(
        `复制失败（${(err as Error).message}）——请手动选中上面的令牌文本。`,
      );
    }
  }

  const activeSite = siteId ?? sites.data?.[0]?.id ?? null;
  const siteKeys = (keys.data ?? []).filter((k) => k.siteId === activeSite);
  const activeKey = keyId ?? siteKeys[0]?.id ?? null;

  const start = useMutation({
    mutationFn: () => gatewayStart(activeSite!, activeKey!),
    onSuccess: async () => {
      setError(null);
      await qc.invalidateQueries({ queryKey: ["gateway"] });
    },
    onError: (err: Error) => setError(err.message),
  });

  const stop = useMutation({
    mutationFn: gatewayStop,
    onSuccess: async () => {
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
          out[key] = "无法识别通道（可能是另一个 home 下写的）";
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
            detail: "无法识别通道（可能是另一个 home 下写的），请到「Agent 投递」页手工处理",
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
          results.push({ label, ok: true, detail: "已改指网关" });
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
      <h3>本地网关</h3>
      <p className="muted">
        让任何支持 OpenAI 兼容接口的 agent 把 base_url 指向
        <span className="mono"> http://127.0.0.1:{port}/v1 </span>
        即可——密钥不必写进它们的配置里。只监听回环地址，并且必须带下面的本地令牌。
      </p>

      <label className="checkline">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => onToggle(e.target.checked)}
        />
        <span>
          允许启动本地网关（默认关闭；这个开关只控制「允不允许」，
          真正启动要点下面的按钮）
        </span>
      </label>

      <label className="field">
        <span>端口（1024–65535）</span>
        <input
          className="input"
          type="number"
          min={1024}
          max={65535}
          value={port}
          onChange={(e) => onPortChange(Number(e.target.value))}
        />
      </label>
      {settingsDirty ? (
        <p className="muted">端口改动需要先保存设置，并在下次启动网关时生效。</p>
      ) : null}

      {running ? (
        <>
          <dl className="kv">
            <dt>状态</dt>
            <dd className="ok">运行中</dd>
            <dt>地址</dt>
            <dd className="mono">{status.data?.url}</dd>
            <dt>上游</dt>
            <dd className="mono">{status.data?.site}</dd>
            <dt>本地令牌</dt>
            <dd className="mono ellipsis" title={status.data?.token ?? ""}>
              {status.data?.token}
            </dd>
            <dt>令牌存储</dt>
            <dd>
              {status.data?.tokenPersistent ? (
                <span className="badge badge-ok">已存入系统钥匙串</span>
              ) : (
                <span className="badge badge-warn">
                  临时（钥匙串不可用）——重启后会变
                </span>
              )}
            </dd>
          </dl>
          <p className="muted">
            把地址与令牌填进 agent 的配置即可；也可以到「Agent 投递」页把通道勾上
            「指向本地网关」，让 KeyRelay 替你写。
          </p>
          {status.data?.tokenPersistent ? (
            <p className="muted">
              令牌存在系统钥匙串里，<strong>跨重启不变</strong>——所以换站时只要重启网关，
              agent 侧不用改（它的配置里写的是网关地址与这个令牌）。
            </p>
          ) : (
            <p className="muted">
              这次用的是<strong>临时令牌</strong>：钥匙串不可用，重启后令牌会变，
              届时指向网关的通道需要重新投递。已写入 agent 配置的旧令牌会立刻失效。
            </p>
          )}
          <div className="row">
            <button type="button" className="btn" onClick={copyToken}>
              <Copy size={14} aria-hidden /> 复制令牌
            </button>
            <button
              type="button"
              className="btn btn-danger"
              disabled={rotate.isPending}
              onClick={() => rotate.mutate()}
            >
              <RefreshCw size={14} aria-hidden />{" "}
              {rotate.isPending ? "轮换中…" : "重新生成令牌"}
            </button>
            {copied ? (
              <span className="muted" role="status">
                已复制到剪贴板，可能被剪贴板历史记录（系统或其他应用）带走。
                KeyRelay 不会自动清空剪贴板——那会跟你自己的复制操作打架。
              </span>
            ) : null}
          </div>
          {rotated ? (
            <p className="warnline" role="status">
              <AlertTriangle size={14} aria-hidden /> 已换新令牌：旧令牌立即失效，
              指向网关的通道需要重新投递一次，agent 需要重启才能读到新配置。
            </p>
          ) : null}
          <button
            type="button"
            className="btn btn-danger"
            disabled={stop.isPending}
            onClick={() => stop.mutate()}
          >
            <Square size={14} aria-hidden /> 停止网关
          </button>
        </>
      ) : (
        <>
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
          </div>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!enabled || activeSite === null || activeKey === null || start.isPending}
            onClick={() => start.mutate()}
          >
            <Play size={14} aria-hidden /> {start.isPending ? "启动中…" : "启动网关"}
          </button>
          {!enabled ? (
            <p className="muted">先勾选上面的开关。</p>
          ) : siteKeys.length === 0 ? (
            <p className="muted">该站点下还没有本地密钥，先去「密钥」页新建一把。</p>
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
          把已投递的通道批量改指网关…
        </button>
        {!running ? (
          <span className="muted">网关没在运行：改指网关要读本地令牌，先启动网关。</span>
        ) : null}
      </div>

      {batchOpen ? (
        <div className="card">
          <h4>选择要改指网关的通道</h4>
          <p className="muted">
            只会列出<strong>已投递且没解绑</strong>的绑定。每条都要单独勾选——
            没有「全选」，因为每条都会真的改写一个 agent 的配置文件。
          </p>
          {batchBindings.isLoading ? <p className="muted">正在读绑定…</p> : null}
          {batchCandidates.length === 0 && !batchBindings.isLoading ? (
            <p className="muted">还没有任何已投递的通道。先去「Agent 投递」页投递一条。</p>
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
                      <strong>无法识别通道</strong>（{binding.targetPath}）——
                      可能是另一个 home 下写的，勾了也会失败并说明原因
                    </>
                  ) : (
                    <>
                      {channel} · <span className="mono">{binding.targetPath}</span> · key #{binding.keyId}
                      {site ? ` · ${site.displayName}` : ""}
                    </>
                  )}
                </span>
              </label>
            );
          })}
          {/* 逐条预览的结果（硬约束 1）：不显示 diff 就不让执行 */}
          {Object.keys(batchPreviews).length > 0 ? (
            <div className="card">
              <h4>逐条预览</h4>
              {Object.entries(batchPreviews).map(([key, plan]) => (
                <div key={key}>
                  <strong>{planOf(key).channel ?? "无法识别通道"}</strong>{" "}
                  <span className="mono">{planOf(key).targetPath}</span>
                  {typeof plan === "string" ? (
                    <p className="error" role="alert">
                      预览失败：{plan}
                    </p>
                  ) : (
                    <>
                      <p className="muted">
                        {plan.targetExists ? "改写已存在的文件" : "新建文件"} ·
                        模式：<strong>{plan.mode === "gateway" ? "指向本地网关" : "指向站点"}</strong>
                        {plan.warnings.length > 0 ? ` · 提示 ${plan.warnings.length} 条` : ""}
                      </p>
                      <pre className="mono">{plan.preview}</pre>
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
              {batchPreview.isPending ? "预览中…" : "预览勾选的条目"}
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={
                batchApply.isPending ||
                batchPreview.isPending ||
                // 勾选集必须是**预览集的子集**：有一条勾了却没预览过就不能执行
                // （P2-3：预览快照与渲染期勾选之间的竞态，单看「预览非空」挡不住）
                Object.keys(batchPicked).some((k) => !batchPicked[k] || !(k in batchPreviews)) ||
                Object.values(batchPreviews).some((p) => typeof p === "string")
              }
              onClick={() => batchApply.mutate()}
            >
              {batchApply.isPending ? "处理中…" : "按勾选改指"}
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
              取消
            </button>
          </div>
          <p className="muted">
            某一条失败不会中断其它条（例如目标文件正被别的程序占用）。
            已经改成功的那几条<strong>不会</strong>回滚——要的是「尽量都改掉」，
            不是「要么全成要么全不成」。
          </p>
        </div>
      ) : null}

      {batchResults.length > 0 ? (
        <div className="card">
          <h4>批量结果</h4>
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
