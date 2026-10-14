import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, KeyRound, Plus, RefreshCw, RotateCw, Trash2 } from "lucide-react";
import {
  availableGroups,
  createKey,
  formatGroupRate,
  listKeys,
  listSites,
  listStoredKeys,
  revokeKey,
  rotateKey,
  rotationDue,
  rotationPlan,
  suggestKeyName,
  syncSiteKeys,
  type RotationPlan,
  type RotationRun,
  type SiteRow,
  type StoredKeyRow,
} from "../lib/api";
import ConfirmDialog from "../components/ConfirmDialog";
import CapButton from "../components/CapButton";

/**
 * 新建密钥时默认名里的 `agent-id` 段。
 *
 * 密钥页**没有** agent 上下文（agent 是在「Agent 投递」页选的），所以这里用一个
 * **中性值**，而不是猜一个具体 agent：写死 `codex` 会让每个站点、每个用户的密钥名
 * 都冒充 codex —— B-87 的根因正是这个「看着像规范、其实是占位」的默认名。
 * 名字只是给人看的标签，用户可以在输入框里改成真正的 agent。
 */
const DEFAULT_AGENT_SEGMENT = "unassigned";

export default function Keys() {
  const qc = useQueryClient();
  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });
  const [siteId, setSiteId] = useState<number | null>(null);
  const [creating, setCreating] = useState(false);
  // 默认名**不硬编码**：打开对话框时按 FR-2 的规范现算（`suggestKeyName`，日期用本地日期）。
  // 拿不到建议名时留空，绝不回退到写死的名字——那正是 B-87 要消灭的占位符。
  const [name, setName] = useState("");
  /** 用户是否手输过名字。手输过就**不再**用建议名覆盖他（见 `openCreateDialog`）。 */
  /**
   * 「用户是否手输过名字」（M8-S5B §6.4）。
   *
   * 为什么是 ref 而不是 state：`openCreateDialog` 在 `await suggestKeyName(...)`
   * **之后**才判断这件事。闭包捕获的是 `await` 之前的旧值，于是用户在建议名还在
   * 路上时敲的名字会被建议名覆盖。ref 读的是当前值，跨 await 也准确。
   *
   * 第一版在这里同时留了 state 与 ref，`tsc --noEmit` 直接报 TS6133「state 只写不读」
   * ——那就是答案：渲染根本不需要它，留着的那个必然在某天与 ref 漂移。
   */
  const nameEditedRef = useRef(false);
  /** 建议名正在路上：这期间不让提交，否则会创建出一个空名字的密钥。 */
  const [suggesting, setSuggesting] = useState(false);
  const [group, setGroup] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  // 轮换：先出预览（`rotating`），用户确认后才真的动手（PRD §7 危险操作二次确认）
  const [rotating, setRotating] = useState<RotationPlan | null>(null);
  const [rotationName, setRotationName] = useState("");
  /**
   * 轮换的建议名还在路上（M8-S5B 独立复审 P3-1）。
   *
   * 与创建路径的 `suggesting` 同一用途：对话框一打开就显示**上一次用过的名字**，
   * 而建议名要等一个 IPC 往返才回来。这期间不挡住确认，用户就可能用一个旧名字
   * 建出新 key。窗口是毫秒级，但创建路径正是为这个才有 `suggesting` 的。
   */
  const [rotationSuggesting, setRotationSuggesting] = useState(false);
  const [rotationResult, setRotationResult] = useState<RotationRun | null>(null);
  // 回收站点侧密钥（B-82）：先出二次确认，确认里还要**明确勾选**才会带 `confirm=true`
  const [revoking, setRevoking] = useState<StoredKeyRow | null>(null);
  const [revokeAgreed, setRevokeAgreed] = useState(false);

  const activeSite = siteId ?? sites.data?.[0]?.id ?? null;
  const activeSiteRow = (sites.data ?? []).find((s) => s.id === activeSite);
  /** 能力集：`undefined`（站点还没读出来）按「全不支持」处理，绝不乐观放行。 */
  const caps = activeSiteRow?.capabilities;

  /**
   * 按**指定站点**取能力集（M8-S5B §6.2）。
   *
   * 轮换列表里每一行是 `RotationDue`，它带自己的 `siteId`；用「当前选中站点」的
   * 能力去判另一把 key 的操作，会出现「按钮可点但后端拒绝」。语义与 `caps` 一致：
   * 取不到 ⇒ `undefined` ⇒ 按全不支持处理。
   */
  function capsFor(siteId: number): SiteRow["capabilities"] | undefined {
    return (sites.data ?? []).find((s) => s.id === siteId)?.capabilities;
  }

  /**
   * 切换站点时作废已选分组（M8-S5B §6.3）。
   *
   * 分组名是**站点侧**的概念：A 站选了「vip」后切到 B 站，B 站未必有同名分组，
   * 留着它只会让新建密钥带着一个来历不明的分组（建键失败，或建到错误分组）。
   */
  useEffect(() => {
    setGroup("");
  }, [activeSite]);

  // 该轮换的密钥（FR-7）。纯本地判定：不联网、不读密钥。
  const rotation = useQuery({ queryKey: ["rotation-due"], queryFn: rotationDue });

  // 站点侧分组与倍率（FR-2）。只在真的要建密钥时才问站点，且该站点类型得真有分组概念。
  const groups = useQuery({
    queryKey: ["groups", activeSite],
    queryFn: () => availableGroups(activeSite!),
    enabled: creating && activeSite !== null && (caps?.groups ?? false),
    retry: false,
  });

  // 主表用**本地已存密钥**（投递需要它的本地 id）；站点侧列表只作对照
  const keys = useQuery({ queryKey: ["stored-keys"], queryFn: listStoredKeys });
  // 主表跟随所选站点（M9-S4 / D）：此前站点下拉只管「新建 / 对齐 / 对照」，主表却列全部站点，
  // 表里又没有站点列——同名规范（`app-id/agent-id/日期`）下根本分不出哪把是哪个站的。
  const siteKeys = (keys.data ?? []).filter((k) => k.siteId === activeSite);
  const remote = useQuery({
    queryKey: ["remote-keys", activeSite],
    queryFn: () => listKeys(activeSite!),
    // 没有密钥列表端点就不发请求（后端也会拒，但先发一次注定失败的请求只会让
    // 这里显示一个错的原因）
    enabled: activeSite !== null && (caps?.listKeys ?? false),
    retry: false,
  });

  const revoke = useMutation({
    mutationFn: () => revokeKey(revoking!.siteId, revoking!.remoteId!, true),
    onSuccess: async (report) => {
      setError(null);
      // B-100：站点侧删掉了（不可逆）与本地记账写上了是**两件事**。本地状态没写上时
      // 整体仍然是成功——把不可逆的成功报成失败会让用户去重试一次注定失败的删除，
      // 所以这里说的是「已回收，但本地状态没记上」。
      setNotice(
        `已在站点侧回收「${revoking?.name ?? ""}」。本地记录被标成「已回收」并保留——` +
          `站点上那把 key 已经没了，这个动作不可逆。` +
          (report.localStatusUpdated
            ? ""
            : "注意：本地状态没能写上（原因见下），下次对账会再试。") +
          (report.note ? `\n${report.note}` : ""),
      );
      setRevokeAgreed(false);
      setRevoking(null);
      await qc.invalidateQueries({ queryKey: ["stored-keys"] });
      await qc.invalidateQueries({ queryKey: ["remote-keys", activeSite] });
      await qc.invalidateQueries({ queryKey: ["events"] });
    },
    onError: (err: Error) => {
      setError(err.message);
      setRevokeAgreed(false);
      setRevoking(null);
    },
  });

  const rotationPreview = useMutation({
    mutationFn: (keyId: number) => rotationPlan(keyId),
    onSuccess: async (data) => {
      setError(null);
      setNotice(null);
      setRotationResult(null);
      setRotating(data);
      // 先清空再取建议名（P3-1）：否则建议名回来前显示的是上一次轮换用过的名字
      setRotationName("");
      setRotationSuggesting(true);
      // 新 key 的默认名走**与新建同一条路径**（M8-S5B §6.12）：按 FR-2 的命名规范现算，
      // 不再 `${data.keyName}-rotated` 硬拼——二次轮换会拼出 `xxx-rotated-rotated`，
      // 而命名规范（`naming.rs`）在轮换路径上就被绕过去了。
      // 兜底用 `data.keyName`（原名）：拿不到建议名时**不**留空（空名会被确认按钮挡住），
      // 也**不**回退到写死的 `-rotated` 后缀（那正是要消灭的占位符）。
      const today = new Date();
      try {
        const suggested = await suggestKeyName(DEFAULT_AGENT_SEGMENT, {
          year: today.getFullYear(),
          month: today.getMonth() + 1,
          day: today.getDate(),
        });
        setRotationName(suggested ?? data.keyName);
      } catch {
        setRotationName(data.keyName);
      } finally {
        // 无论成功失败都要收尾：失败时用 `data.keyName` 兜底，名字仍然有效
        setRotationSuggesting(false);
      }
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
      // 名字用完就还回去：否则下一次「新建密钥」会**沿用上一把的名字**，
      // 站点侧就出现两把同名 key——那恰好废掉了命名规范存在的理由
      // （「在站点侧一眼看出这把 key 给谁用」）。手输标记也要一起清，
      // 否则用户改过一次名之后，后续每次新建都会重新填回他那个旧名字。
      setName("");
      nameEditedRef.current = false;
      await qc.invalidateQueries({ queryKey: ["stored-keys"] });
      await qc.invalidateQueries({ queryKey: ["remote-keys", activeSite] });
    },
    // 失败时**不**清名字：用户要拿着这个名字去改（例如站点说重名），
    // 清掉等于让他重打一遍
    onError: (err: Error) => {
      setError(err.message);
    },
  });

  /**
   * 打开「新建密钥」对话框，并按 FR-2 的命名规范预填一个默认名。
   *
   * 三条纪律（B-87 / M7-S5 D-5）：
   * 1. **日期由界面给**：Rust 侧不读时钟也不做时区，用户看到的「今天」必须是他本地的今天
   *    （`getMonth()` 从 0 开始，所以要 `+1`）；
   * 2. 返回 `null`（入参不合法）⇒ **留空**，绝不回退到硬编码默认名；
   * 3. 用户已经手输过名字 ⇒ **不覆盖**。
   */
  async function openCreateDialog() {
    setError(null);
    setNotice(null);
    setCreating(true);
    if (nameEditedRef.current) return;

    const today = new Date();
    setSuggesting(true);
    try {
      const suggested = await suggestKeyName(DEFAULT_AGENT_SEGMENT, {
        year: today.getFullYear(),
        month: today.getMonth() + 1,
        day: today.getDate(),
      });
      // 等待期间用户可能已经自己敲了名字：再确认一次，别把他的输入盖掉。
      // 读 **ref** 而不是闭包里的 `nameEdited`——后者还是 `await` 之前的旧值（M8-S5B §6.4）
      if (!nameEditedRef.current) setName(suggested ?? "");
    } catch (err) {
      // 生成建议名失败不是致命错误，但也不能静默填一个假名字——留空让他自己写
      if (!nameEditedRef.current) setName("");
      setError(`没能生成默认名（${(err as Error).message}），请手动填写。`);
    } finally {
      setSuggesting(false);
    }
  }

  return (
    <section>

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
          <CapButton
            allowed={caps?.createKey ?? false}
            reason={capReason(caps, "该站点类型不支持在站点侧建密钥")}
            className="btn btn-primary"
            onClick={openCreateDialog}
          >
            <Plus size={14} aria-hidden /> 新建密钥
          </CapButton>
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
                      {/* 轮换是「建 / 读 / 回收」三连，缺一不可（M7-S2 §3.3） */}
                      <CapButton
                        allowed={rotationAllowed(capsFor(due.siteId))}
                        reason={capReason(
                          capsFor(due.siteId),
                          "轮换需要建 / 读 / 回收三连，该类型缺其中一步",
                        )}
                        busy={rotationPreview.isPending || rotationExecute.isPending}
                        className="btn btn-ghost"
                        onClick={() => rotationPreview.mutate(due.keyId)}
                      >
                        <RotateCw size={13} aria-hidden /> 轮换…
                      </CapButton>
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
          {/* 对齐站点密钥 = 列举站点令牌 + 读回明文，两者缺一不可（M7-S2 §3.3） */}
          <CapButton
            allowed={syncAllowed(caps)}
            reason={
              caps && !caps.listKeys
                ? "该站点类型没有密钥列表端点"
                : capReason(caps, "站点不提供明文回读")
            }
            busy={syncing}
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
          </CapButton>
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
        {/* 两种空不能混成一句：「本地一把都没有」与「这个站下没有」处理方式不同 */}
        {keys.data?.length && siteKeys.length === 0 ? (
          <p className="muted">
            这个站点下还没有本地密钥（其他站点共 {keys.data.length} 把，切换上面的站点查看）。
          </p>
        ) : null}

        {siteKeys.length ? (
          <table className="table">
            <thead>
              <tr>
                <th>本地 id</th>
                <th>名称</th>
                <th>分组</th>
                <th>远端 id</th>
                <th>状态</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {siteKeys.map((key) => {
                const site = (sites.data ?? []).find((s) => s.id === key.siteId);
                const gate = revokeGate(site, key);
                return (
                  <tr key={key.id}>
                    <td className="mono">{key.id}</td>
                    <td>
                      <KeyRound size={13} aria-hidden /> {key.name}
                    </td>
                    <td className="mono">{key.group ?? "—"}</td>
                    <td className="mono">{key.remoteId ?? "—"}</td>
                    <td>
                      {/* `revoked`（我回收的·本地）与 `disabled`（站点禁的）**必须能分开**：
                          恢复方式不同，混成一个词会让用户不知道去哪处理（M7-S4）。 */}
                      <span
                        className={`badge badge-${statusTone(key.status)}`}
                        title={statusHint(key.status)}
                      >
                        {statusLabel(key.status)}
                      </span>
                    </td>
                    <td>
                      <CapButton
                        allowed={gate.allowed}
                        reason={gate.reason}
                        busy={revoke.isPending}
                        className="btn btn-ghost"
                        onClick={() => {
                          setError(null);
                          setNotice(null);
                          setRevokeAgreed(false);
                          setRevoking(key);
                        }}
                      >
                        <Trash2 size={13} aria-hidden /> 回收
                      </CapButton>
                    </td>
                  </tr>
                );
              })}
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
        {!(caps?.listKeys ?? false) ? (
          <p className="muted">
            该站点类型没有密钥列表端点，无法对照站点侧令牌（判断来自能力集）。
          </p>
        ) : null}
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
                    <span
                      className={`badge badge-${statusTone(key.status)}`}
                      title={statusHint(key.status)}
                    >
                      {statusLabel(key.status)}
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
        // `suggesting` 期间也禁用：否则可能在建议名到达之前就提交一个空名字
        confirmDisabled={!name || suggesting || create.isPending}
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
            onChange={(e) => {
              setName(e.target.value);
              // 用户动过这个名字之后，就再也不用建议名覆盖他（§6.4）
              nameEditedRef.current = true;
            }}
            placeholder={suggesting ? "正在生成默认名…" : "keyrelay/agent/yyyymmdd"}
            spellCheck={false}
          />
        </label>
        <p className="muted">
          默认名按 <span className="mono">app-id/agent-id/yyyymmdd</span> 生成，
          日期用你本机的今天。它只是标签：可以改成任何你认得出的名字。
        </p>
        <label className="field">
          <span>分组（可选）</span>
          <select
            className="input"
            value={group}
            onChange={(e) => setGroup(e.target.value)}
            disabled={groups.isLoading || !(caps?.groups ?? false)}
          >
            <option value="">不指定（跟随站点默认）</option>
            {(groups.data ?? []).map((option) => (
              <option key={option.name} value={option.name}>
                {option.name} · {formatGroupRate(option.rate)}
              </option>
            ))}
          </select>
        </label>
        {!(caps?.groups ?? false) ? (
          <p className="muted">
            该站点类型没有分组概念，将按站点默认分组创建（这个判断来自能力集，
            不是按站点类型名硬编码的）。
          </p>
        ) : null}
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
        confirmDisabled={
          rotationExecute.isPending ||
          rotationSuggesting ||
          !rotationName ||
          (rotating?.unmappedTargets.length ?? 0) > 0
        }
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

      {/*
        回收站点侧密钥（B-82）。破坏性且**不可逆**：站点上那把 key 真的没了。
        所以 `confirm=true` 只能来自这里的**明确勾选**——默认 false，不勾就点不动
        （后端也会拒绝 `confirm=false`，两处都不给「无参数即执行」的形态）。
      */}
      <ConfirmDialog
        open={revoking !== null}
        title="回收站点上的密钥"
        danger
        confirmLabel={revoke.isPending ? "回收中…" : "确认回收"}
        confirmDisabled={!revokeAgreed || revoke.isPending}
        onCancel={() => {
          setRevokeAgreed(false);
          setRevoking(null);
        }}
        onConfirm={() => revoke.mutate()}
      >
        <p>
          将在<strong>站点上</strong>回收「{revoking?.name ?? ""}」（远端 id{" "}
          <span className="mono">{revoking?.remoteId ?? "—"}</span>）。
          这把 key 在站点侧会<strong>立即失效</strong>，任何正在用它的人都将被拒。
        </p>
        <p className="muted">
          本地记录<strong>不会</strong>被删除，只会被标成「已回收」——`bindings` 与漂移追溯靠它存活。
          已经投递到 agent 配置里的旧值需要你自己重新投递覆盖。
        </p>
        <label className="checkline">
          <input
            type="checkbox"
            checked={revokeAgreed}
            onChange={(e) => setRevokeAgreed(e.target.checked)}
          />
          <span>
            我确认要在站点上回收这把密钥，并明白它<strong>不可逆</strong>（站点侧无法恢复）
          </span>
        </label>
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

/**
 * 状态文案。**两套词表必须能区分**（M7-S4 / 冻结契约 7）：
 *
 * - `"revoked"` 是**本地**状态：用户在本产品里把它在站点侧回收了（`store::KEY_STATUS_REVOKED`）；
 * - `"disabled"` 是**站点**状态：站点自己把它禁用了。
 *
 * 用同一个词显示这两件事，用户就不知道该去哪里恢复——一个是「我干的、不可逆」，
 * 另一个是「站点干的、可能能解禁」。
 */
const STATUS_LABELS: Record<string, string> = {
  enabled: "启用",
  disabled: "站点禁用",
  exhausted: "额度耗尽",
  revoked: "已回收",
  unknown: "未知",
};

function statusLabel(status: string): string {
  // 认不出的取值原样显示，不猜——猜错会让用户按错误的状态处理。
  return STATUS_LABELS[status] ?? status;
}

function statusHint(status: string): string {
  if (status === "revoked") {
    return "本地状态：你已在站点侧回收它（不可逆）。本地记录保留，供溯源与漂移追溯。";
  }
  if (status === "disabled") {
    return "站点状态：站点自己禁用了这把令牌——与本产品无关。";
  }
  return `站点返回的原始状态：${status}`;
}

function statusTone(status: string): string {
  if (status === "enabled") return "ok";
  if (status === "disabled") return "warn";
  if (status === "exhausted") return "danger";
  // 已回收 = 站点侧真的没了，不能看着像「未知」那样无害
  if (status === "revoked") return "danger";
  return "muted";
}

/** 轮换的三连门槛：建 / 读 / 回收**缺一不可**（M7-S2 §3.3）。 */
function rotationAllowed(caps: SiteRow["capabilities"] | undefined): boolean {
  if (!caps) return false;
  return caps.createKey && caps.revealKey && caps.revokeKey;
}

/** 「对齐站点密钥」= 列举站点令牌 + 读回明文，两者缺一不可。 */
function syncAllowed(caps: SiteRow["capabilities"] | undefined): boolean {
  if (!caps) return false;
  return caps.listKeys && caps.revealKey;
}

/**
 * 灰显的原因文案。
 *
 * 「能力集为 false」与「还没有站点」是**两个不同的原因**，不能都写成
 * 「该站点类型不支持…」——那会把「你还没接入站点」说成产品缺陷。
 */
function capReason(
  caps: SiteRow["capabilities"] | undefined,
  unsupported: string,
): string {
  return caps ? unsupported : "先接入一个站点（或站点列表还没加载出来）";
}

/**
 * 单把密钥能不能回收。三个条件各自有各自的**原因文案**——灰显必须说明原因，
 * 否则用户只会觉得按钮坏了（`capabilities.revokeKey` 是站点类型问题，
 * 缺 `remoteId` / 已回收是这把 key 自己的状态问题，处理方式完全不同）。
 */
function revokeGate(
  site: SiteRow | undefined,
  key: StoredKeyRow,
): { allowed: boolean; reason: string } {
  if (!site) return { allowed: false, reason: "找不到这把密钥所属的站点记录" };
  if (!site.capabilities.revokeKey) {
    return { allowed: false, reason: "该站点类型不支持回收" };
  }
  if (!key.remoteId) {
    return { allowed: false, reason: "这把密钥没有站点侧 id，站点上定位不到它" };
  }
  if (key.status === "revoked") {
    return { allowed: false, reason: "已经在站点侧回收过了（本地记录保留）" };
  }
  return { allowed: true, reason: "" };
}

function formatTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}
