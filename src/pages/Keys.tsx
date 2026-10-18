import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, KeyRound, Plus, RefreshCw, RotateCw, Trash2 } from "lucide-react";
import {
  availableGroups,
  createKey,
  formatGroupRate,
  groupKeyOf,
  listKeys,
  listSites,
  listStoredKeys,
  recentKeyUsage,
  revokeKey,
  rotateKey,
  rotationDue,
  rotationPlan,
  suggestKeyName,
  syncSiteKeys,
  type KeyUsageSample,
  type RotationPlan,
  type RotationRun,
  type SiteRow,
  type StoredKeyRow,
} from "../lib/api";
import ConfirmDialog from "../components/ConfirmDialog";
import Skeleton from "../components/Skeleton";
import CapButton from "../components/CapButton";
import { useTranslation, translate, getCurrentDict } from "../i18n";

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
  const { t } = useTranslation();
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

  /**
   * 当前选中的分组（M19-S1）。
   *
   * 下拉的 `value` 是**站点原生标识**（Sub2API 上是 `"2"`），而落库要存**显示名**
   * （`"gpt plus"`）——否则密钥表显示一个数字、按分组名查倍率也会落空。
   * 这里按同一个映射把标识找回来，两个值一起交给后端。
   */
  const selectedGroup = (groups.data ?? []).find((option) => groupKeyOf(option) === group);

  /**
   * 该站点的分组是否带**原生 id**（M19-S1 / 独立复审 P2-3）。
   *
   * 带原生 id ⇒ 站点是按 id 绑定密钥的（Sub2API），不绑分组可能被站点拒绝（403）；
   * 不带 ⇒ 站点以分组名为标识（NewAPI），不传分组等于「跟随用户自己的分组」，是安全默认。
   * 「未选分组」的提示只在前一种情况下出现，否则就是误报。
   */
  const hasNativeGroupIds = (groups.data ?? []).some(
    (option) => (option.id ?? "").trim() !== "",
  );

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
        t("keys.notice.revokedPre", { name: revoking?.name ?? "" }) +
          (report.localStatusUpdated ? "" : t("keys.notice.revokedLocalFail")) +
          (report.note ? t("keys.notice.revokedNote", { note: report.note }) : ""),
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
        // M19-S1：`group` 是**站点原生标识**（发给站点），`groupLabel` 是显示名（落本地）。
        // 下拉的 value 是标识，用户看到的是名字，两者都要带过去。
        group: group || undefined,
        groupLabel: selectedGroup?.name,
      }),
    onSuccess: async (key) => {
      setError(null);
      // 只显示掩码，明文从不出现在界面上
      setNotice(t("keys.notice.created", { name: key.name, masked: key.masked }));
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
      setError(t("keys.createDialog.nameError", { error: (err as Error).message }));
    } finally {
      setSuggesting(false);
    }
  }

  return (
    <section>

      {sites.data?.length === 0 ? (
        <p className="muted">{t("keys.empty")}</p>
      ) : null}

      <div className="card">
        <div className="row row-between">
          <div className="row">
            <label className="field-inline">
              <span>{t("keys.siteSelect")}</span>
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
              <RefreshCw size={14} aria-hidden /> {t("keys.btn.refresh")}
            </button>
          </div>
          <CapButton
            allowed={caps?.createKey ?? false}
            reason={capReason(caps, t("keys.capReason.unsupportedCreate"))}
            className="btn btn-primary"
            onClick={openCreateDialog}
          >
            <Plus size={14} aria-hidden /> {t("keys.btn.create")}
          </CapButton>
        </div>

        {notice ? <p className="ok" role="status">{notice}</p> : null}
        {error ? <p className="error" role="alert">{error}</p> : null}

        {rotation.data && rotation.data.length > 0 ? (
          <div className="warnbox" role="status">
            <p className="warnline">
              <AlertTriangle size={14} aria-hidden />
              {t("keys.rotation.warnPre", { count: rotation.data.length })}
              <strong>{t("keys.rotation.warnStrong")}</strong>
              {t("keys.rotation.warnPost")}
            </p>
            <table className="table">
              <thead>
                <tr>
                  <th>{t("keys.table.name")}</th>
                  <th>{t("keys.table.dueAt")}</th>
                  <th>{t("keys.table.action")}</th>
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
                          t("keys.capReason.rotationMissing"),
                        )}
                        busy={rotationPreview.isPending || rotationExecute.isPending}
                        className="btn btn-ghost"
                        onClick={() => rotationPreview.mutate(due.keyId)}
                      >
                        <RotateCw size={13} aria-hidden /> {t("keys.btn.rotate")}
                      </CapButton>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="muted">{t("keys.rotation.hint")}</p>
          </div>
        ) : null}

        {rotationResult ? <div className="warnbox" role="status">{renderRun(rotationResult)}</div> : null}

        <div className="row">
          {/* 对齐站点密钥 = 列举站点令牌 + 读回明文，两者缺一不可（M7-S2 §3.3） */}
          <CapButton
            allowed={syncAllowed(caps)}
            reason={
              caps && !caps.listKeys
                ? t("keys.capReason.noListEndpoint")
                : capReason(caps, t("keys.capReason.noReveal"))
            }
            busy={syncing}
            onClick={async () => {
              if (activeSite === null) return;
              setError(null);
              setNotice(null);
              setSyncing(true);
              try {
                const s = await syncSiteKeys(activeSite);
                setNotice(
                  t("keys.sync.done", {
                    siteTotal: s.siteTotal,
                    alreadyLocal: s.alreadyLocal,
                    imported: s.imported,
                    unreadable:
                      s.unreadable.length > 0
                        ? t("keys.sync.unreadable", {
                            count: s.unreadable.length,
                            list: s.unreadable.join(", "),
                          })
                        : "",
                  }),
                );
                await qc.invalidateQueries({ queryKey: ["stored-keys"] });
              } catch (err) {
                setError((err as Error).message);
              } finally {
                setSyncing(false);
              }
            }}
          >
            <RefreshCw size={14} aria-hidden /> {syncing ? t("keys.btn.syncing") : t("keys.btn.sync")}
          </CapButton>
          <span className="muted">
            {t("keys.sync.hintPre")}
            <strong>{t("keys.sync.hintStrong")}</strong>
            {t("keys.sync.hintPost")}
          </span>
        </div>

        {keys.isLoading ? <Skeleton rows={3} /> : null}
        {keys.isError ? (
          <p className="muted">{t("keys.emptyStates.keysError", { error: (keys.error as Error).message })}</p>
        ) : null}
        {keys.data?.length === 0 ? (
          <p className="muted">{t("keys.emptyStates.noKeys")}</p>
        ) : null}
        {/* 两种空不能混成一句：「本地一把都没有」与「这个站下没有」处理方式不同 */}
        {keys.data?.length && siteKeys.length === 0 ? (
          <p className="muted">{t("keys.emptyStates.noSiteKeys", { count: keys.data.length })}</p>
        ) : null}

        {siteKeys.length ? (
          <table className="table">
            <thead>
              <tr>
                <th>{t("keys.table.localId")}</th>
                <th>{t("keys.table.name")}</th>
                <th>{t("keys.table.group")}</th>
                <th>{t("keys.table.remoteId")}</th>
                <th>{t("keys.table.status")}</th>
                {/* M14-S3：用量列仅 keyUsage=true 时显示（spec §9）。数据来自 StoredKeyRow.quotaUsed/quotaLimit。 */}
                {caps?.keyUsage && <th>{t("keys.table.usage")}</th>}
                <th>{t("keys.table.action")}</th>
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
                    {/* M14-S3：用量列数据接入（spec §9）。caps?.keyUsage 决定显隐；近 30 天 tokens 仅 Sub2API 有数据。 */}
                    {caps?.keyUsage && (
                      <td>
                        {formatKeyUsage(key.quotaUsed, key.quotaLimit, key.currency)}
                        <KeyUsageCell keyId={key.id} />
                      </td>
                    )}
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
                        <Trash2 size={13} aria-hidden /> {t("keys.btn.revoke")}
                      </CapButton>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : null}

        <p className="muted">{t("keys.footnote")}</p>
      </div>

      <div className="card">
        <h3>{t("keys.remote.title")}</h3>
        {!(caps?.listKeys ?? false) ? (
          <p className="muted">{t("keys.remote.noListCap")}</p>
        ) : null}
        {remote.isLoading ? <p className="muted">{t("common.loading")}</p> : null}
        {remote.isError ? (
          <p className="muted">{t("keys.remote.error", { error: (remote.error as Error).message })}</p>
        ) : null}
        {remote.data?.length ? (
          <table className="table">
            <thead>
              <tr>
                <th>{t("keys.table.name")}</th>
                <th>{t("keys.table.group")}</th>
                <th>{t("keys.table.remoteId")}</th>
                <th>{t("keys.table.status")}</th>
                {caps?.keyUsage && <th>{t("keys.table.usage")}</th>}
                <th>{t("keys.table.createdAt")}</th>
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
                  {caps?.keyUsage && (
                    <td>{formatKeyUsage(key.quotaUsed, key.quotaLimit, key.currency)}</td>
                  )}
                  <td className="mono">{formatTs(key.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </div>

      <ConfirmDialog
        open={creating}
        title={t("keys.createDialog.title")}
        confirmLabel={create.isPending ? t("keys.createDialog.confirming") : t("keys.createDialog.confirm")}
        // `suggesting` 期间也禁用：否则可能在建议名到达之前就提交一个空名字
        confirmDisabled={!name || suggesting || create.isPending}
        onCancel={() => setCreating(false)}
        onConfirm={() => create.mutate()}
      >
        <p className="muted">{t("keys.createDialog.body")}</p>
        <label className="field">
          <span>{t("keys.createDialog.nameLabel")}</span>
          <input
            className="input"
            value={name}
            onChange={(e) => {
              setName(e.target.value);
              // 用户动过这个名字之后，就再也不用建议名覆盖他（§6.4）
              nameEditedRef.current = true;
            }}
            placeholder={suggesting ? t("keys.createDialog.namePlaceholderSuggesting") : t("keys.createDialog.namePlaceholder")}
            spellCheck={false}
          />
        </label>
        <p className="muted">
          {t("keys.createDialog.nameHintPre")}<span className="mono">app-id/agent-id/yyyymmdd</span>{t("keys.createDialog.nameHintMid")}
        </p>
        <label className="field">
          <span>{t("keys.createDialog.groupLabel")}</span>
          <select
            className="input"
            value={group}
            onChange={(e) => setGroup(e.target.value)}
            disabled={groups.isLoading || !(caps?.groups ?? false)}
          >
            <option value="">{t("keys.createDialog.groupDefault")}</option>
            {(groups.data ?? []).map((option) => (
              // M19-S1 / B-161：`value` 必须是**站点原生标识**。有 id 用 id（Sub2API 的
              // 建密钥接口只认数字主键），没有才回落到名字（NewAPI 以名字为标识）。
              // 此前一律用名字 ⇒ Sub2API 把名字解析成整数失败、静默丢弃用户选的分组。
              <option key={groupKeyOf(option)} value={groupKeyOf(option)}>
                {option.name} · {formatGroupRate(option.rate)}
              </option>
            ))}
          </select>
        </label>
        {!(caps?.groups ?? false) ? (
          <p className="muted">{t("keys.createDialog.groupNoCap")}</p>
        ) : null}
        {groups.isError ? (
          <p className="muted">{t("keys.createDialog.groupError", { error: (groups.error as Error).message })}</p>
        ) : null}
        {/*
          有可选分组却没选：不阻断（能不能不绑分组取决于站点部署），但要把后果说清楚。

          **只在「该站点按分组 id 绑定」时才提示**（独立复审 P2-3）：NewAPI 不传分组
          等于「跟随用户自己的分组」，是安全默认，弹这条会把用户推向 spec §2 明确
          不做的「随便选一个」。判据用「分组带不带原生 id」而不是站点类型名——
          与 `groupNoCap` 同一口径：能力/数据说了算，不按类型名硬编码。
        */}
        {(caps?.groups ?? false) && hasNativeGroupIds && !group ? (
          <p className="muted">{t("keys.createDialog.groupUnboundWarn")}</p>
        ) : null}
        {(groups.data ?? []).some(
          (option) => option.rate === null || !Number.isFinite(option.rate) || option.rate <= 0,
        ) ? (
          <p className="muted">{t("keys.createDialog.groupRateWarn")}</p>
        ) : null}
      </ConfirmDialog>

      <ConfirmDialog
        open={rotating !== null}
        title={t("keys.rotationDialog.title")}
        confirmLabel={rotationExecute.isPending ? t("keys.rotationDialog.confirming") : t("keys.rotationDialog.confirm")}
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
              {t("keys.rotationDialog.introPre", { name: rotating.keyName, id: rotating.keyId })}
            </p>
            <ol>
              <li>{t("keys.rotationDialog.step1")}</li>
              <li>
                {rotating.channels.length === 0
                  ? t("keys.rotationDialog.step2All")
                  : t("keys.rotationDialog.step2Some", {
                      count: rotating.channels.length,
                      channels: rotating.channels.join("、"),
                    })}
              </li>
              <li>
                {rotating.oldRemoteId
                  ? t("keys.rotationDialog.step3Revoke", { id: rotating.oldRemoteId })
                  : t("keys.rotationDialog.step3Skip")}
              </li>
            </ol>
            {/*
              M20-S1 / B-166：分组继承要说在**动手之前**。

              旧 key 绑过分组时，新 key 必须继续待在同一个分组里，否则第三步回收旧 key
              之后，站点上两把都不能用（未分组 key 一律 403 的站点）。显示名能否解析回
              站点原生值要看站点当前的分组列表——那需要一次请求，而预览是**纯本地**的，
              所以这里只承诺「会继承」+「站点上没这个分组时会拒绝」。
            */}
            {/*
              与后端同判据：`.trim()` 后为空当作「没有分组」。

              不 trim 的话，一个纯空格的名字会在预览里渲染成「会绑定分组『   』」，
              而后端把它当无分组静默跳过——用户看到的信息与真实行为相反
              （M20-S1 独立复审 P3-2）。
            */}
            {rotating.oldGroupName?.trim() ? (
              <p className="muted">
                {t("keys.rotationDialog.groupInherit", {
                  group: rotating.oldGroupName.trim(),
                })}
              </p>
            ) : null}
            {rotating.unmappedTargets.length > 0 ? (
              <p className="error" role="alert">
                {t("keys.rotationDialog.unmappedError", { targets: rotating.unmappedTargets.join("、") })}
              </p>
            ) : null}
            <label className="field">
              <span>{t("keys.rotationDialog.newNameLabel")}</span>
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
        title={t("keys.revokeDialog.title")}
        danger
        confirmLabel={revoke.isPending ? t("keys.revokeDialog.confirming") : t("keys.revokeDialog.confirm")}
        confirmDisabled={!revokeAgreed || revoke.isPending}
        onCancel={() => {
          setRevokeAgreed(false);
          setRevoking(null);
        }}
        onConfirm={() => revoke.mutate()}
      >
        <p>
          {t("keys.revokeDialog.bodyPre", { name: revoking?.name ?? "" })}
          <span className="mono">{revoking?.remoteId ?? "—"}</span>
          {t("keys.revokeDialog.bodyMid")}
          <strong>{t("keys.revokeDialog.bodyStrong")}</strong>
          {t("keys.revokeDialog.bodyPost")}
        </p>
        <p className="muted">
          {t("keys.revokeDialog.localKeepPre")}
          <strong>{t("keys.revokeDialog.localKeepStrong")}</strong>
          {t("keys.revokeDialog.localKeepPost")}
        </p>
        <label className="checkline">
          <input
            type="checkbox"
            checked={revokeAgreed}
            onChange={(e) => setRevokeAgreed(e.target.checked)}
          />
          <span>{t("keys.revokeDialog.agree")}</span>
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
      ? translate(getCurrentDict(), "keys.rotationResult.revokeRevoked")
      : run.revoke === "skippedNoRemoteId"
        ? translate(getCurrentDict(), "keys.rotationResult.revokeSkipped")
        : run.revoke === "failed"
          ? translate(getCurrentDict(), "keys.rotationResult.revokeFailed", {
              reason: run.revokeReason ?? translate(getCurrentDict(), "keys.rotationResult.stoppedPost"),
            })
          : translate(getCurrentDict(), "keys.rotationResult.revokeNotAttempted");

  if (run.completed) {
    return (
      <>
        <p className="warnline">
          <AlertTriangle size={14} aria-hidden />
          {translate(getCurrentDict(), "keys.rotationResult.completedPre", { masked: run.newKeyMasked })}
          {run.reinjected.length === 0
            ? translate(getCurrentDict(), "keys.rotationResult.completedNoTargets")
            : translate(getCurrentDict(), "keys.rotationResult.completedTargets", { targets: run.reinjected.join("、") })}
        </p>
        <p className="muted">{revokeText}</p>
      </>
    );
  }

  return (
    <>
      <p className="warnline">
        <AlertTriangle size={14} aria-hidden />
        <strong>{translate(getCurrentDict(), "keys.rotationResult.stoppedPre")}</strong>
        {translate(getCurrentDict(), "keys.rotationResult.stoppedMid", { step: rotationStepLabel(run.stoppedAt ?? "") })}
        {run.stopReason ?? translate(getCurrentDict(), "keys.rotationResult.stoppedPost")}。
      </p>
      <p className="muted">
        {translate(getCurrentDict(), "keys.rotationResult.aftermathPre", { masked: run.newKeyMasked })}
        {run.reinjected.length === 0
          ? translate(getCurrentDict(), "keys.rotationResult.aftermathNoTargets")
          : translate(getCurrentDict(), "keys.rotationResult.aftermathTargets", { targets: run.reinjected.join("、") })}
        {revokeText}
      </p>
      <p className="muted">{translate(getCurrentDict(), "keys.rotationResult.fixHint")}</p>
    </>
  );
}

/** 轮换步骤标识 → 显示文案（取值来自后端 `RotationRun.stoppedAt`，未知值原样返回）。 */
function rotationStepLabel(step: string): string {
  switch (step) {
    case "create_new":
      return translate(getCurrentDict(), "keys.rotationStep.create_new");
    case "reinject_all":
      return translate(getCurrentDict(), "keys.rotationStep.reinject_all");
    case "revoke_old":
      return translate(getCurrentDict(), "keys.rotationStep.revoke_old");
    default:
      return step;
  }
}

/**
 * 状态文案。**两套词表必须能区分**（M7-S4 / 冻结契约 7）：
 *
 * - `"revoked"` 是**本地**状态：用户在本产品里把它在站点侧回收了（`store::KEY_STATUS_REVOKED`）；
 * - `"disabled"` 是**站点**状态：站点自己把它禁用了。
 *
 * 用同一个词显示这两件事，用户就不知道该去哪里恢复——一个是「我干的、不可逆」，
 * 另一个是「站点干的、可能能解禁」。
 */
function statusLabel(status: string): string {
  // 认不出的取值原样显示，不猜——猜错会让用户按错误的状态处理。
  switch (status) {
    case "enabled":
      return translate(getCurrentDict(), "keys.status.enabled");
    case "disabled":
      return translate(getCurrentDict(), "keys.status.disabled");
    case "exhausted":
      return translate(getCurrentDict(), "keys.status.exhausted");
    case "revoked":
      return translate(getCurrentDict(), "keys.status.revoked");
    case "unknown":
      return translate(getCurrentDict(), "keys.status.unknown");
    default:
      return status;
  }
}

function statusHint(status: string): string {
  if (status === "revoked") {
    return translate(getCurrentDict(), "keys.statusHint.revoked");
  }
  if (status === "disabled") {
    return translate(getCurrentDict(), "keys.statusHint.disabled");
  }
  return translate(getCurrentDict(), "keys.statusHint.other", { status });
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
  return caps ? unsupported : translate(getCurrentDict(), "keys.capReason.noSite");
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
  if (!site) return { allowed: false, reason: translate(getCurrentDict(), "keys.capReason.siteNotFound") };
  if (!site.capabilities.revokeKey) {
    return { allowed: false, reason: translate(getCurrentDict(), "keys.capReason.unsupportedRevoke") };
  }
  if (!key.remoteId) {
    return { allowed: false, reason: translate(getCurrentDict(), "keys.capReason.noRemoteId") };
  }
  if (key.status === "revoked") {
    return { allowed: false, reason: translate(getCurrentDict(), "keys.capReason.alreadyRevoked") };
  }
  return { allowed: true, reason: "" };
}

function formatTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

/**
 * 格式化一把 key 的当前累计用量（M14-S3 / spec §9）。
 *
 * - `quotaUsed == null` ⇒ `—`（「不知道」不当成 0，与 `Balance.known` 同纪律）；
 * - `quotaLimit == null` ⇒ 「已用 X（不限）」（NewAPI `unlimited_quota` / Sub2API 无限额）；
 * - 两者都有 ⇒ 「已用 X / 限额 Y」。
 *
 * 文案走 i18n（`keys.usage.*`），不硬编码中文。
 */
function formatKeyUsage(
  quotaUsed: number | null | undefined,
  quotaLimit: number | null | undefined,
  currency: string | null | undefined,
): string {
  const dict = getCurrentDict();
  if (quotaUsed == null) return translate(dict, "keys.usage.unknown");
  const cur = currency ?? "";
  if (quotaLimit == null) {
    return translate(dict, "keys.usage.usedUnlimited", { used: quotaUsed, currency: cur });
  }
  return translate(dict, "keys.usage.usedOverLimit", { used: quotaUsed, limit: quotaLimit, currency: cur });
}

/**
 * 近 30 天 tokens（M14-S3 / spec §9）：仅 Sub2API 站点有 `usage_samples` 数据。
 *
 * 独立组件（`useQuery` 不能在 `.map` 回调里调）——每行一个实例，按本地 `keyId` 查询。
 * NewAPI 站点 `recentKeyUsage` 返回空数组 ⇒ 渲染 `null`（不显示 tokens 行）。
 */
function KeyUsageCell({ keyId }: { keyId: number }) {
  const usage = useQuery({
    queryKey: ["key-usage", keyId],
    queryFn: () => recentKeyUsage(keyId),
    staleTime: 30 * 60 * 1000,
  });
  const samples: KeyUsageSample[] = usage.data ?? [];
  if (samples.length === 0) return null;
  const sum = samples.reduce((acc, s) => acc + s.totalTokens, 0);
  return <div className="muted">{translate(getCurrentDict(), "keys.usage.tokens30d", { tokens: sum })}</div>;
}
