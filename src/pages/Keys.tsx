import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, KeyRound, Plus, RefreshCw, RotateCw } from "lucide-react";
import {
  availableGroups,
  createKey,
  formatGroupRate,
  listKeys,
  listSites,
  listStoredKeys,
  rotateKey,
  rotationDue,
  rotationPlan,
  syncSiteKeys,
  type RotationPlan,
  type RotationRun,
} from "../lib/api";
import ConfirmDialog from "../components/ConfirmDialog";

export default function Keys() {
  const qc = useQueryClient();
  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });
  const [siteId, setSiteId] = useState<number | null>(null);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("codex/daily");
  const [group, setGroup] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  // 轮换：先出预览（`rotating`），用户确认后才真的动手（PRD §7 危险操作二次确认）
  const [rotating, setRotating] = useState<RotationPlan | null>(null);
  const [rotationName, setRotationName] = useState("");
  const [rotationResult, setRotationResult] = useState<RotationRun | null>(null);

  const activeSite = siteId ?? sites.data?.[0]?.id ?? null;

  // 该轮换的密钥（FR-7）。纯本地判定：不联网、不读密钥。
  const rotation = useQuery({ queryKey: ["rotation-due"], queryFn: rotationDue });

  // 站点侧分组与倍率（FR-2）。只在真的要建密钥时才问站点。
  const groups = useQuery({
    queryKey: ["groups", activeSite],
    queryFn: () => availableGroups(activeSite!),
    enabled: creating && activeSite !== null,
    retry: false,
  });

  // 主表用**本地已存密钥**（投递需要它的本地 id）；站点侧列表只作对照
  const keys = useQuery({ queryKey: ["stored-keys"], queryFn: listStoredKeys });
  const remote = useQuery({
    queryKey: ["remote-keys", activeSite],
    queryFn: () => listKeys(activeSite!),
    enabled: activeSite !== null,
    retry: false,
  });

  const rotationPreview = useMutation({
    mutationFn: (keyId: number) => rotationPlan(keyId),
    onSuccess: (data) => {
      setError(null);
      setNotice(null);
      setRotationResult(null);
      setRotationName(`${data.keyName}-rotated`);
      setRotating(data);
    },
    onError: (err: Error) => setError(err.message),
  });

  const rotationExecute = useMutation({
    mutationFn: () => rotateKey(rotating!.keyId, rotationName),
    onSuccess: async (data) => {
      setRotating(null);
      setRotationResult(data);
      await qc.invalidateQueries({ queryKey: ["stored-keys"] });
      await qc.invalidateQueries({ queryKey: ["remote-keys", activeSite] });
      await qc.invalidateQueries({ queryKey: ["rotation-due"] });
    },
    onError: (err: Error) => {
      setRotating(null);
      setError(err.message);
    },
  });

  const create = useMutation({
    mutationFn: () =>
      createKey({
        siteId: activeSite!,
        name,
        group: group || undefined,
      }),
    onSuccess: async (key) => {
      setError(null);
      // 只显示掩码，明文从不出现在界面上
      setNotice(`已创建 ${key.name}（${key.masked}），密钥已存入系统钥匙串`);
      setCreating(false);
      await qc.invalidateQueries({ queryKey: ["stored-keys"] });
      await qc.invalidateQueries({ queryKey: ["remote-keys", activeSite] });
    },
    onError: (err: Error) => {
      setError(err.message);
    },
  });

  return (
    <section>
      <h2>密钥</h2>

      {sites.data?.length === 0 ? (
        <p className="muted">先去「站点」页接入一个中转站。</p>
      ) : null}

      <div className="card">
        <div className="row row-between">
          <div className="row">
            <label className="field-inline">
              <span>站点</span>
              <select
                className="input"
                value={activeSite ?? ""}
                onChange={(e) => setSiteId(Number(e.target.value))}
              >
                {(sites.data ?? []).map((site) => (
                  <option key={site.id} value={site.id}>
                    {site.displayName}
                  </option>
                ))}
              </select>
            </label>
            <button
              type="button"
              className="btn btn-ghost"
              onClick={() => keys.refetch()}
              disabled={keys.isFetching}
            >
              <RefreshCw size={14} aria-hidden /> 刷新
            </button>
          </div>
          <button
            type="button"
            className="btn btn-primary"
            disabled={activeSite === null}
            onClick={() => {
              setError(null);
              setNotice(null);
              setCreating(true);
            }}
          >
            <Plus size={14} aria-hidden /> 新建密钥
          </button>
        </div>

        {notice ? <p className="ok" role="status">{notice}</p> : null}
        {error ? <p className="error" role="alert">{error}</p> : null}

        {rotation.data && rotation.data.length > 0 ? (
          <div className="warnbox" role="status">
            <p className="warnline">
              <AlertTriangle size={14} aria-hidden />有 {rotation.data.length}{" "}
              把密钥已到轮换窗口。轮换是「新建 → 全量重注入 → 回收旧钥匙」三连，
              <strong>中间任何一步失败都会立刻停下</strong>
              ，不会留下「旧钥匙已回收但新钥匙没注入」的状态。
            </p>
            <table className="table">
              <thead>
                <tr>
                  <th>名称</th>
                  <th>到期时间</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {rotation.data.map((due) => (
                  <tr key={due.keyId}>
                    <td>{due.name}</td>
                    <td className="mono">{formatTs(due.dueAt)}</td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-ghost"
                        onClick={() => rotationPreview.mutate(due.keyId)}
                        disabled={rotationPreview.isPending || rotationExecute.isPending}
                      >
                        <RotateCw size={13} aria-hidden /> 轮换…
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="muted">
              「轮换…」会先给出预览（会波及哪些投递目标），确认之后才动手。
            </p>
          </div>
        ) : null}

        {rotationResult ? <div className="warnbox" role="status">{renderRun(rotationResult)}</div> : null}

        <div className="row">
          <button
            type="button"
            className="btn"
            disabled={activeSite === null || syncing}
            onClick={async () => {
              if (activeSite === null) return;
              setError(null);
              setNotice(null);
              setSyncing(true);
              try {
                const s = await syncSiteKeys(activeSite);
                const parts = [
                  `站点侧 ${s.siteTotal} 把`,
                  `本地已有 ${s.alreadyLocal}`,
                  `新导入 ${s.imported}`,
                ];
                if (s.unreadable.length > 0) {
                  // 「站点不提供明文回读」是 PRD §10 已登记的风险。必须说清楚，
                  // 不能让用户以为「对齐成功了」。
                  parts.push(
                    `站点未给明文 ${s.unreadable.length} 把（${s.unreadable.join(
                      ", ",
                    )}），这些只能删掉重建`,
                  );
                }
                setNotice(`密钥对齐完成：${parts.join(" / ")}。`);
                await qc.invalidateQueries({ queryKey: ["stored-keys"] });
              } catch (err) {
                setError((err as Error).message);
              } finally {
                setSyncing(false);
              }
            }}
          >
            <RefreshCw size={14} aria-hidden /> 对齐站点密钥
            {syncing ? "…" : ""}
          </button>
          <span className="muted">
            把站点侧已有密钥的明文取回本地钥匙串。明文**不会显示在这里**，
            也不会经过 IPC——命令层至今没有任何一条命令返回过密钥明文。
          </span>
        </div>

        {keys.isLoading ? <p className="muted">加载中…</p> : null}
        {keys.isError ? (
          <p className="muted">读取失败：{(keys.error as Error).message}</p>
        ) : null}
        {keys.data?.length === 0 ? (
          <p className="muted">
            KeyRelay 本地还没有密钥。点「新建密钥」——新建成功后密钥会直接进系统钥匙串。
          </p>
        ) : null}

        {keys.data?.length ? (
          <table className="table">
            <thead>
              <tr>
                <th>本地 id</th>
                <th>名称</th>
                <th>分组</th>
                <th>远端 id</th>
                <th>状态</th>
              </tr>
            </thead>
            <tbody>
              {keys.data.map((key) => (
                <tr key={key.id}>
                  <td className="mono">{key.id}</td>
                  <td>
                    <KeyRound size={13} aria-hidden /> {key.name}
                  </td>
                  <td className="mono">{key.group ?? "—"}</td>
                  <td className="mono">{key.remoteId ?? "—"}</td>
                  <td>
                    <span className={`badge badge-${statusTone(key.status)}`}>
                      {key.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}

        <p className="muted">
          密钥明文只存在于系统钥匙串里；后端**从不**把明文返回给界面。
          投递时用的是上表的「本地 id」。
        </p>
      </div>

      <div className="card">
        <h3>站点上的令牌（只读对照）</h3>
        {remote.isLoading ? <p className="muted">加载中…</p> : null}
        {remote.isError ? (
          <p className="muted">
            读取失败（可能需要先登录）：{(remote.error as Error).message}
          </p>
        ) : null}
        {remote.data?.length ? (
          <table className="table">
            <thead>
              <tr>
                <th>名称</th>
                <th>分组</th>
                <th>远端 id</th>
                <th>状态</th>
                <th>创建时间</th>
              </tr>
            </thead>
            <tbody>
              {remote.data.map((key) => (
                <tr key={key.remoteId}>
                  <td>{key.name}</td>
                  <td className="mono">{key.group ?? "—"}</td>
                  <td className="mono">{key.remoteId}</td>
                  <td>
                    <span className={`badge badge-${statusTone(key.status)}`}>
                      {key.status}
                    </span>
                  </td>
                  <td className="mono">{formatTs(key.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </div>

      <ConfirmDialog
        open={creating}
        title="新建密钥"
        confirmLabel={create.isPending ? "创建中…" : "创建"}
        confirmDisabled={!name || create.isPending}
        onCancel={() => setCreating(false)}
        onConfirm={() => create.mutate()}
      >
        <p className="muted">
          新建成功后密钥会**直接写入系统钥匙串**，界面只显示末 4 位。请自行确认这把钥匙的用途。
        </p>
        <label className="field">
          <span>名称</span>
          <input
            className="input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            spellCheck={false}
          />
        </label>
        <label className="field">
          <span>分组（可选）</span>
          <select
            className="input"
            value={group}
            onChange={(e) => setGroup(e.target.value)}
            disabled={groups.isLoading}
          >
            <option value="">不指定（跟随站点默认）</option>
            {(groups.data ?? []).map((option) => (
              <option key={option.name} value={option.name}>
                {option.name} · {formatGroupRate(option.rate)}
              </option>
            ))}
          </select>
        </label>
        {groups.isError ? (
          <p className="muted">
            读不到分组列表（{(groups.error as Error).message}），将按站点默认分组创建。
          </p>
        ) : null}
        {(groups.data ?? []).some(
          (option) => option.rate === null || !Number.isFinite(option.rate) || option.rate <= 0,
        ) ? (
          <p className="muted">
            站点对部分分组没有给出可用倍率，这些分组一律显示「倍率未知」——
            <strong>不会用 1× 兜底</strong>，免得你按错误的成本预期选分组。
          </p>
        ) : null}
      </ConfirmDialog>

      <ConfirmDialog
        open={rotating !== null}
        title="轮换密钥"
        confirmLabel={rotationExecute.isPending ? "轮换中…" : "开始轮换"}
        confirmDisabled={rotationExecute.isPending || !rotationName || (rotating?.unmappedTargets.length ?? 0) > 0}
        onCancel={() => setRotating(null)}
        onConfirm={() => rotationExecute.mutate()}
      >
        {rotating ? (
          <>
            <p className="muted">
              将对「{rotating.keyName}」（本地 id {rotating.keyId}）执行固定顺序的三步：
            </p>
            <ol>
              <li>在站点上新建一把密钥（明文直接进系统钥匙串）</li>
              <li>
                把新密钥重新投递到{" "}
                {rotating.channels.length === 0
                  ? "全部投递目标（当前没有绑定，这一步是空操作）"
                  : `${rotating.channels.length} 个目标：${rotating.channels.join("、")}`}
              </li>
              <li>
                {rotating.oldRemoteId
                  ? `回收站点侧的旧密钥（远端 id ${rotating.oldRemoteId}）—— 这一步不可逆`
                  : "旧密钥没有站点侧 id，这一步会被跳过（不是失败）"}
              </li>
            </ol>
            {rotating.unmappedTargets.length > 0 ? (
              <p className="error" role="alert">
                {rotating.unmappedTargets.join("、")} 这些投递目标的通道无法识别，轮换会漏掉它们；
                若继续并回收旧密钥，它们会永久停在旧密钥上。请先处理这些目标再轮换——
                <strong>此操作已被禁止</strong>。
              </p>
            ) : null}
            <label className="field">
              <span>新密钥的名称</span>
              <input
                className="input"
                value={rotationName}
                onChange={(e) => setRotationName(e.target.value)}
                spellCheck={false}
              />
            </label>
          </>
        ) : null}
      </ConfirmDialog>
    </section>
  );
}

/**
 * 轮换结果的四种结局必须**逐态给不同文案**。
 *
 * 把「跳过了」和「做了但失败」合并成一句「完成」会让用户以为旧密钥已经死了，
 * 而它其实还活着——这正是轮换功能最不能出的错。
 */
function renderRun(run: RotationRun) {
  const revokeText =
    run.revoke === "revoked"
      ? "旧密钥已在站点侧回收。"
      : run.revoke === "skippedNoRemoteId"
        ? "旧密钥没有站点侧 id，已跳过回收——请到站点上手动确认它是否需要删除。"
        : run.revoke === "failed"
          ? `旧密钥回收失败：${run.revokeReason ?? "原因未知"}。它仍然有效，请重试或到站点上手动删除。`
          : "旧密钥**未**回收（前一步失败就停下了）。旧密钥仍有效，可以直接继续使用。";

  if (run.completed) {
    return (
      <>
        <p className="warnline">
          <AlertTriangle size={14} aria-hidden />
          轮换已走完：新密钥 {run.newKeyMasked} 已投递到{" "}
          {run.reinjected.length === 0 ? "0 个目标（原本就没有绑定）" : run.reinjected.join("、")}。
        </p>
        <p className="muted">{revokeText}</p>
      </>
    );
  }

  return (
    <>
      <p className="warnline">
        <AlertTriangle size={14} aria-hidden />
        <strong>轮换中途停下</strong>（停在「{STEP_LABELS[run.stoppedAt ?? ""] ?? run.stoppedAt}」）：
        {run.stopReason ?? "原因未知"}。
      </p>
      <p className="muted">
        新密钥 {run.newKeyMasked} 已创建并投递到{" "}
        {run.reinjected.length === 0 ? "0 个目标" : run.reinjected.join("、")}。{revokeText}
      </p>
      <p className="muted">
        请先修复上面那个失败点，再决定重试；在那之前**不要**手动删除旧密钥。
      </p>
    </>
  );
}

const STEP_LABELS: Record<string, string> = {
  create_new: "新建密钥",
  reinject_all: "全量重注入",
  revoke_old: "回收旧密钥",
};

function statusTone(status: string): string {
  if (status === "enabled") return "ok";
  if (status === "disabled") return "warn";
  if (status === "exhausted") return "danger";
  return "muted";
}

function formatTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}
