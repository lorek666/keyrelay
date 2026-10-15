import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Save } from "lucide-react";
import { ShieldCheck } from "lucide-react";
import {
  auditRedaction,
  autostartStatus,
  exportBundle,
  exportDiagnostics,
  getSettings,
  pruneBackups,
  purgeKeychain,
  setAutostart,
  updateSettings,
  type KeychainPurgeReport,
  type Settings,
} from "../lib/api";
import GatewayCard from "../components/GatewayCard";
import UpdateChecker from "../components/UpdateChecker";
import ConfirmDialog from "../components/ConfirmDialog";

/** 「系统里的实际状态」的显示文案。`unknown` 是「读不出来」，不是「没开」——两者不能混。 */
const AUTOSTART_LABELS: Record<string, string> = {
  enabled: "已安装并生效",
  disabled: "未安装",
  unknown: "无法判定（读不到自启项，可能是权限或路径问题）",
};

/**
 * 数值字段的提交前校验（M8-S5B §6.6）。
 *
 * 为什么必须在前端拦：这些字段最终落进 Rust 的 `u32` / `u16`。`type="number"` 的
 * `min` / `max` 只是 HTML 属性——用户可以键入越界值，也可以提交（属性不阻止提交），
 * 于是后端反序列化失败，用户看到一句难懂的序列化错误，而界面刚刚还显示他填的值。
 *
 * 返回 `null` = 不合法；调用方据此**不发请求**并给出中文文案。
 */
function intInRange(raw: number, min: number, max: number): number | null {
  if (!Number.isInteger(raw) || raw < min || raw > max) return null;
  return raw;
}

/** 允许小数的字段（目前只有余额阈值）：有限数 + 落在区间内 + 非负。 */
function finiteNonNegative(raw: number, max: number): number | null {
  if (!Number.isFinite(raw) || raw < 0 || raw > max) return null;
  return raw;
}

const PRESETS = [
  { label: "关闭", value: 0 },
  { label: "5 分钟", value: 300 },
  { label: "15 分钟", value: 900 },
  { label: "1 小时", value: 3600 },
];

function ExportCard() {
  const [password, setPassword] = useState("");
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = useMutation({
    mutationFn: () => exportBundle(password || undefined),
    onSuccess: (r) => {
      setError(null);
      setResult(
        `已导出到 ${r.path}（${r.encrypted ? "已加密" : "明文"}，${r.bytes} 字节）` +
          (r.registered
            ? ""
            : "。注意：这个文件没能登记进「已知导出物」表，脱敏审计不会扫描它——请自行确认它里面没有明文凭证。"),
      );
    },
    onError: (err: Error) => {
      setResult(null);
      setError(err.message);
    },
  });

  const prune = useMutation({
    mutationFn: () => pruneBackups(10),
    onSuccess: (r) => setResult(`已清理 ${r.removed} 个历史备份（保留最近 10 个）`),
    onError: (err: Error) => setError(err.message),
  });

  // FR-9:196 诊断包。在此之前 `service::export_diagnostics` 只有测试在调，
  // 命令层与界面都没有入口——PRD 里算已交付，用户手里不存在。
  const diagnostics = useMutation({
    mutationFn: () => exportDiagnostics(),
    onSuccess: (r) => {
      setError(null);
      setResult(
        `已导出诊断包到 ${r.path}（${r.events} 条事件，${r.bytes} 字节）` +
          (r.registered
            ? ""
            : "。注意：这个文件没能登记进「已知导出物」表，脱敏审计不会扫描它。"),
      );
    },
    onError: (err: Error) => {
      setResult(null);
      setError(err.message);
    },
  });

  return (
    <div className="card">
      <h3>导出与备份</h3>
      <p className="muted">
        导出的是站点、密钥**元数据**、同意记录与设置。
        <strong>密钥本体不在导出物里</strong>——它只存在于系统钥匙串。
        因此加密保护的是元数据（站点地址、密钥名称），不是密钥。
      </p>
      <p className="muted">
        「导出诊断包」是给<strong>报障</strong>用的另一份产物：最近的事件（已脱敏）+
        设置快照（<strong>不含</strong>代理与 Webhook 的值，只标「配没配」）+ 版本与库结构。
        它<strong>不含密钥本体</strong>，所以没有加密形态。
      </p>
      <label className="field">
        <span>导出密码（留空 = 明文导出）</span>
        <input
          className="input"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="off"
        />
      </label>
      <div className="row">
        <button
          type="button"
          className="btn btn-primary"
          disabled={run.isPending}
          onClick={() => run.mutate()}
        >
          {run.isPending ? "导出中…" : "导出配置"}
        </button>
        <button
          type="button"
          className="btn"
          disabled={prune.isPending}
          onClick={() => prune.mutate()}
        >
          {prune.isPending ? "清理中…" : "清理历史备份（保留最近 10 个）"}
        </button>
        <button
          type="button"
          className="btn"
          disabled={diagnostics.isPending}
          onClick={() => diagnostics.mutate()}
        >
          {diagnostics.isPending ? "导出中…" : "导出诊断包"}
        </button>
      </div>
      {result ? <p className="ok" role="status">{result}</p> : null}
      {error ? <p className="error" role="alert">{error}</p> : null}
    </div>
  );
}

/**
 * 钥匙串条目一键清理（FR-8:191）。
 *
 * 清理的是**系统钥匙串里的秘密**：删了就没了（站点侧那把 key 还在，但本地再也取不回明文）。
 * 本地 SQLite 记录**保留**——清理的是秘密，不是历史（`bindings` / 漂移追溯靠它存活）。
 *
 * `confirm=true` 只能来自下面的**明确勾选**：默认 false，不勾就点不动。
 * 后端同样会拒绝 `confirm=false`，两处都不提供「无参数即全删」的形态。
 */
function KeychainCard() {
  const [confirming, setConfirming] = useState(false);
  const [agreed, setAgreed] = useState(false);
  const [report, setReport] = useState<KeychainPurgeReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const purge = useMutation({
    mutationFn: () => purgeKeychain(true),
    onSuccess: (r) => {
      setError(null);
      setReport(r);
      setAgreed(false);
      setConfirming(false);
    },
    onError: (err: Error) => {
      setReport(null);
      setError(err.message);
      setAgreed(false);
      setConfirming(false);
    },
  });

  return (
    <div className="card">
      <h3>钥匙串条目清理</h3>
      <p className="muted">
        删除本产品写进<strong>系统钥匙串</strong>的全部条目（按本地数据库里的引用逐条删，
        不去枚举钥匙串——macOS 上枚举会弹授权）。秘密删掉之后<strong>取不回来</strong>：
        站点侧那把 key 还在，但本地再也没有它的明文。
      </p>
      <p className="muted">
        <strong>本地记录不会被删</strong>：站点、密钥元数据、同意记录与变更历史都保留，
        只是它们指向的钥匙串条目不存在了（重新取一次密钥即可恢复）。
      </p>
      <button
        type="button"
        className="btn btn-danger"
        disabled={purge.isPending}
        onClick={() => {
          setError(null);
          setAgreed(false);
          setConfirming(true);
        }}
      >
        {purge.isPending ? "清理中…" : "清理钥匙串条目"}
      </button>

      {report ? (
        <>
          <p
            className={report.failed > 0 ? "error" : "ok"}
            role="status"
          >
            清理完成：尝试 {report.attempted} 条 / 删除 {report.removed} 条 /
            失败 {report.failed} 条。
          </p>
          {report.firstError ? (
            <p className="muted">第一条失败：{report.firstError}</p>
          ) : null}
          {report.failed > 0 ? (
            <p className="muted">
              失败的条目仍然留在钥匙串里（单条失败不会中断其余清理）。可以再点一次重试；
              反复失败通常意味着系统钥匙串的访问权限被拒绝了。
            </p>
          ) : null}
        </>
      ) : null}
      {error ? (
        <p className="error" role="alert">
          <AlertTriangle size={14} aria-hidden /> {error}
        </p>
      ) : null}

      <p className="muted">
        卸载说明：macOS <strong>没有</strong>卸载钩子，所以顺序是「先在这里跑一次清理，
        再删掉 App」——本产品<strong>不会</strong>（也无法）在你删除 App 时自动清理。
      </p>

      <ConfirmDialog
        open={confirming}
        title="清理钥匙串条目"
        danger
        confirmLabel={purge.isPending ? "清理中…" : "确认清理"}
        confirmDisabled={!agreed || purge.isPending}
        onCancel={() => {
          setAgreed(false);
          setConfirming(false);
        }}
        onConfirm={() => purge.mutate()}
      >
        <p>
          会逐条删除本产品在系统钥匙串里的条目。<strong>不可逆</strong>：删掉之后本地再也取不回
          那些密钥的明文，已投递到 agent 配置里的旧值不受影响（它们还在文件里，
          需要你自己重新投递覆盖）。
        </p>
        <p className="muted">本地数据库记录不会被删除。</p>
        <label className="checkline">
          <input
            type="checkbox"
            checked={agreed}
            onChange={(e) => setAgreed(e.target.checked)}
          />
          <span>
            我确认要删除钥匙串里的密钥条目，并明白它们<strong>不可恢复</strong>
          </span>
        </label>
      </ConfirmDialog>
    </div>
  );
}

function AuditCard() {
  const report = useQuery({
    queryKey: ["audit"],
    queryFn: auditRedaction,
    enabled: false,
  });

  return (
    <div className="card">
      <h3>
        <ShieldCheck size={15} aria-hidden /> 脱敏审计
      </h3>
      <p className="muted">
        扫描本产品的全部落盘产物（数据库、WAL、备份目录、事件表），确认没有明文凭证。
        只扫自己的产物，不做全盘扫描。
      </p>
      <button
        type="button"
        className="btn"
        disabled={report.isFetching}
        onClick={() => report.refetch()}
      >
        {report.isFetching ? "扫描中…" : "开始扫描"}
      </button>
      {report.data ? (
        <>
          <p className={report.data.clean ? "ok" : "error"}>
            {report.data.summary}
          </p>
          {report.data.findings.length ? (
            <ul className="list">
              {report.data.findings.map((f, i) => (
                <li key={`${f.kind}-${i}`}>
                  <span className="badge badge-warn">{f.kind}</span>{" "}
                  <span className="mono ellipsis">{f.path ?? "事件表"}</span>{" "}
                  {f.detail}
                </li>
              ))}
            </ul>
          ) : null}
        </>
      ) : null}
      {report.isError ? (
        <p className="error">{(report.error as Error).message}</p>
      ) : null}
    </div>
  );
}

export default function SettingsPage() {
  const qc = useQueryClient();
  const current = useQuery({ queryKey: ["settings"], queryFn: getSettings });
  // 系统里自启的**实际**状态（不是设置里那个意愿）。见下方 AUTOSTART_LABELS 处的说明。
  const autostart = useQuery({
    queryKey: ["autostart-status"],
    queryFn: autostartStatus,
    retry: false,
  });
  const [draft, setDraft] = useState<Settings | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (current.data && draft === null) setDraft(current.data);
  }, [current.data, draft]);

  /**
   * 开关与系统实际状态不一致时的说明。`null` = 一致、或读不到、或用户还没动过草稿。
   *
   * 只在**两者都能确定**时才报：「unknown」是「读不出来」，把它当不一致会制造假警报。
   */
  const autostartMismatch = (() => {
    if (!autostart.data || !draft) return null;
    if (autostart.data.state === "unknown") return null;
    const wanted = draft.autostartEnabled ? "enabled" : "disabled";
    if (autostart.data.state === wanted) return null;
    return autostart.data.state === "enabled"
      ? "系统里已经装了自启项，但开关是关的（关掉开关并保存即可移除）"
      : "系统里没有生效的自启项，但开关是开的（打开开关并保存即可写入）";
  })();

  /**
   * 提交前的数值校验（M8-S5B §6.6）。
   *
   * 逐字段给出「不合法时说什么」。区间取的是**业务界，比后端类型更严**
   * （独立复审 P3-2：`refresh_interval_secs` / `notify_timeout_secs` 在 Rust 侧是
   * `u64`，这里限 0..86400 / 1..60；`rotation_*_days` 是 `u32`，这里限 0..36500）。
   * 方向是安全的：更严只会挡住越界值，不会漏放——`u32` / `u16` 反序列化失败那条
   * 风险已经闭合。
   *
   * **已知副作用**：若某个字段的存量值超出这些业务界（例如手工改过配置文件），
   * 用户会被挡住**任何**保存，直到把它改回界内。这是有意的——真放过去也是后端报错。
   * 任一字段不合法 ⇒ 直接 return，**不发请求**。
   */
  function validateDraft(draft: Settings): string | null {
    const refresh = intInRange(draft.refreshIntervalSecs, 0, 86_400);
    if (refresh === null) return "定时刷新间隔必须是 0 到 86400 之间的整数秒（0 = 关闭）。";
    const threshold = finiteNonNegative(draft.balanceAlertThreshold, 1_000_000);
    if (threshold === null) return "余额告警阈值必须是不超过 1000000 的非负数（0 = 不告警）。";
    const port = intInRange(draft.gatewayPort, 1, 65_535);
    if (port === null) return "网关端口必须是 1 到 65535 之间的整数。";
    const timeout = intInRange(draft.notifyTimeoutSecs, 1, 60);
    if (timeout === null) return "Webhook 超时必须是 1 到 60 之间的整数秒。";
    const maxAge = intInRange(draft.rotationMaxAgeDays, 0, 36_500);
    if (maxAge === null) return "轮换周期必须是 0 到 36500 之间的整数天（0 = 关闭提醒）。";
    const warn = intInRange(draft.rotationWarnBeforeDays, 0, 36_500);
    if (warn === null) return "提前提醒天数必须是 0 到 36500 之间的整数。";
    if (warn > maxAge && maxAge !== 0) {
      return "提前提醒天数不能大于轮换周期（要提醒的事得先在那个周期内发生）。";
    }
    return null;
  }

  const save = useMutation({
    mutationFn: async (settings: Settings) => {
      const saved = await updateSettings(settings);
      // 自启不是「存一个布尔值」就完事的：它要在磁盘上真写 / 真删一个 LaunchAgent，
      // 或者在 Windows 上动注册表。所以保存设置之后立刻把它同步成实际状态，
      // 并把实际状态带回来——否则界面显示「已开启」而系统里什么都没有。
      //
      // 自启失败**不**让整笔保存算失败（M8-S5B §6.10）：设置已经存进去了，
      // 把两件事的结果分别带回，界面分开说——否则用户以为设置没存，会重复保存。
      try {
        const autostart = await setAutostart(saved.autostartEnabled);
        return { saved, autostart, autostartError: null as string | null };
      } catch (err) {
        return { saved, autostart: null, autostartError: (err as Error).message };
      }
    },
    onSuccess: async ({ saved, autostart, autostartError }) => {
      setError(null);
      // 两件事分开说（M8-S5B §6.10）：设置**已保存**（这是事实，先讲清楚），
      // 自启的同步结果是另一件事——失败或状态不一致都单独说一句。
      if (autostartError !== null) {
        setNotice(`设置已保存，但登录自启没能同步：${autostartError}`);
      } else if (autostart) {
        const wanted = saved.autostartEnabled ? "enabled" : "disabled";
        if (autostart.state !== wanted && autostart.state !== "unknown") {
          // 真实状态与用户意愿不一致时**必须说出来**，不能只显示「已保存」。
          setNotice(
            `设置已保存，但登录自启的实际状态是「${autostart.state}」，与设置不一致。`,
          );
        } else {
          setNotice("已保存。定时刷新间隔的变更在**下次启动**生效。");
        }
      } else {
        setNotice("已保存。定时刷新间隔的变更在**下次启动**生效。");
      }
      setDraft(saved);
      await qc.invalidateQueries({ queryKey: ["settings"] });
      // 重读系统里的实际状态，让上面那句「系统里的实际状态」立刻跟上
      await qc.invalidateQueries({ queryKey: ["autostart-status"] });
    },
    onError: (err: Error) => {
      setNotice(null);
      setError(err.message);
    },
  });

  const dirty =
    draft !== null &&
    current.data !== undefined &&
    JSON.stringify(draft) !== JSON.stringify(current.data);

  return (
    <section>
      <p className="muted">
        所有设置都存在本地数据库里，不上传任何地方。
      </p>

      {notice ? <p className="ok" role="status">{notice}</p> : null}
      {error ? (
        <p className="error" role="alert">
          <AlertTriangle size={14} aria-hidden /> {error}
        </p>
      ) : null}

      {draft === null ? (
        <p className="muted">加载中…</p>
      ) : (
        <>
          <div className="card">
            <h3>自动刷新</h3>
            <p className="muted">
              默认关闭：KeyRelay 不会替你做任何定时联网。
              开启后会在后台按间隔刷新已登录站点的余额与密钥列表，失败只记事件、不打断循环。
            </p>
            <div className="row">
              {PRESETS.map((preset) => (
                <button
                  key={preset.value}
                  type="button"
                  className={
                    draft.refreshIntervalSecs === preset.value
                      ? "btn btn-primary"
                      : "btn"
                  }
                  onClick={() =>
                    setDraft({ ...draft, refreshIntervalSecs: preset.value })
                  }
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </div>

          <div className="card">
            <h3>余额告警</h3>
            <label className="field">
              <span>余额低于该值时告警（USD，0 = 不告警）</span>
              <input
                className="input"
                type="number"
                min={0}
                step="0.5"
                value={draft.balanceAlertThreshold}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    balanceAlertThreshold: Number(e.target.value),
                  })
                }
              />
            </label>
          </div>

          <div className="card">
            <h3>启动检查</h3>
            <label className="checkline">
              <input
                type="checkbox"
                checked={draft.driftCheckOnStart}
                onChange={(e) =>
                  setDraft({ ...draft, driftCheckOnStart: e.target.checked })
                }
              />
              <span>
                启动时检查投递目标是否被外部改动（只读本地文件，不联网）
              </span>
            </label>
          </div>

          <div className="card">
            <h3>界面</h3>
            <label className="field">
              <span>主题</span>
              <select
                className="input"
                value={draft.theme}
                onChange={(e) => setDraft({ ...draft, theme: e.target.value })}
              >
                <option value="system">跟随系统</option>
                <option value="light">浅色</option>
                <option value="dark">深色</option>
              </select>
            </label>
            <label className="field">
              <span>语言</span>
              <select
                className="input"
                value={draft.language}
                onChange={(e) => setDraft({ ...draft, language: e.target.value })}
              >
                <option value="zh-CN">简体中文</option>
                <option value="en-US">English</option>
              </select>
            </label>
            {/* 与遥测 / 自动更新开关同口径：做不到的如实说（M9-S4 / F，B-128） */}
            <p className="muted">
              界面目前只有简体中文：选 English 只会记下这个偏好，界面不会切换。
            </p>
            <label className="field">
              <span>代理（HTTP / SOCKS5，留空 = 直连）</span>
              <input
                className="input"
                type="text"
                placeholder="socks5://127.0.0.1:1080"
                value={draft.proxyUrl}
                onChange={(e) => setDraft({ ...draft, proxyUrl: e.target.value })}
              />
            </label>
            <p className="muted">
              代理串的合法性在真正发起请求时校验：写法不合法会直接报错，不会静默降级成直连。
            </p>
          </div>

          <div className="card">
            <h3>通知</h3>
            <p className="muted">
              余额低于阈值、会话失效、密钥到期与配置漂移会走这里的渠道。通知正文不含密钥，
              也不含站点返回的原始文案。
            </p>
            <label className="checkline">
              <input
                type="checkbox"
                checked={draft.notifySystemEnabled}
                onChange={(e) =>
                  setDraft({ ...draft, notifySystemEnabled: e.target.checked })
                }
              />
              <span>系统通知（macOS 通知中心 / Windows Toast）</span>
            </label>
            <label className="field">
              <span>Webhook 地址（留空 = 不启用）</span>
              <input
                className="input"
                type="text"
                placeholder="https://hooks.example.com/keyrelay"
                value={draft.notifyWebhookUrl}
                onChange={(e) =>
                  setDraft({ ...draft, notifyWebhookUrl: e.target.value })
                }
              />
            </label>
            <label className="field">
              <span>Webhook 超时（秒，上限 60）</span>
              <input
                className="input"
                type="number"
                min={1}
                max={60}
                value={draft.notifyTimeoutSecs}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    notifyTimeoutSecs: Number(e.target.value),
                  })
                }
              />
            </label>
            <p className="muted">
              地址里如果内嵌了凭证（<code>https://user:pass@…</code>），
              写进事件表与导出包之前会被剥掉。
            </p>
          </div>

          <div className="card">
            <h3>密钥轮换</h3>
            <p className="muted">
              到期前提醒你换一把新的。轮换是一次三连操作：新建 key → 全量重注入 → 回收旧 key；
              中间任何一步失败都会停下，不会留下「旧 key 已回收但新 key 没注入」的状态。
            </p>
            <label className="field">
              <span>轮换周期（天，0 = 关闭提醒）</span>
              <input
                className="input"
                type="number"
                min={0}
                value={draft.rotationMaxAgeDays}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    rotationMaxAgeDays: Number(e.target.value),
                  })
                }
              />
            </label>
            <label className="field">
              <span>提前提醒（天）</span>
              <input
                className="input"
                type="number"
                min={0}
                value={draft.rotationWarnBeforeDays}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    rotationWarnBeforeDays: Number(e.target.value),
                  })
                }
              />
            </label>
            {draft.rotationMaxAgeDays > 0 &&
            draft.rotationWarnBeforeDays > draft.rotationMaxAgeDays ? (
              <p className="error" role="alert">
                <AlertTriangle size={14} aria-hidden /> 提前提醒天数不能大于轮换周期。
              </p>
            ) : null}
          </div>

          <div className="card">
            <h3>常驻与自启</h3>
            <label className="checkline">
              <input
                type="checkbox"
                checked={draft.closeToTray}
                onChange={(e) =>
                  setDraft({ ...draft, closeToTray: e.target.checked })
                }
              />
              <span>关窗时隐藏到托盘而不是退出（关掉后关窗即退出，后台刷新也随之停止）</span>
            </label>
            <label className="checkline">
              <input
                type="checkbox"
                checked={draft.startHidden}
                onChange={(e) =>
                  setDraft({ ...draft, startHidden: e.target.checked })
                }
              />
              <span>启动时不显示主窗口（等价于命令行加 --hidden）</span>
            </label>
            <label className="checkline">
              <input
                type="checkbox"
                checked={draft.autostartEnabled}
                onChange={(e) =>
                  setDraft({ ...draft, autostartEnabled: e.target.checked })
                }
              />
              <span>
                登录时自动启动（macOS 写入 LaunchAgent，Windows 写入用户级启动项）。
                点「保存」时才会真正写盘；自启启动时一律带 <code>--hidden</code>
                ——自启的用途是后台刷新，弹窗会破坏它。托盘不可用时窗口仍会显示，
                否则你没有任何入口能把它调回来。
              </span>
            </label>
            {/*
              开关只是一个「意愿」，磁盘上的自启项才是事实（M6-S7 审计 §4-3）。
              只写不读会让界面长期显示一个已经不成立的结论——用户手工删掉 plist、
              系统清理了自启项、或写在别的用户目录下，界面都看不出来。
            */}
            <p className="muted">
              系统里的实际状态：
              {autostart.isLoading
                ? " 读取中…"
                : autostart.isError
                  ? ` 读不到（${(autostart.error as Error).message}）`
                  : ` ${AUTOSTART_LABELS[autostart.data!.state]}`}
            </p>
            {autostartMismatch ? (
              <p className="warnline" role="alert">
                <AlertTriangle size={14} aria-hidden />
                与上面的开关不一致：{autostartMismatch}。
                点一次「保存」会按开关重写系统里的自启项。
              </p>
            ) : null}
          </div>

          <div className="card">
            <h3>隐私</h3>
            <label className="checkline">
              <input
                type="checkbox"
                checked={draft.telemetryEnabled}
                onChange={(e) =>
                  setDraft({ ...draft, telemetryEnabled: e.target.checked })
                }
              />
              <span>
                匿名遥测（默认关）。**当前版本只记录这个开关，不发送任何数据**——
                没有服务端，也没有埋点代码。
              </span>
            </label>
            <label className="checkline">
              <input
                type="checkbox"
                checked={draft.autoUpdateEnabled}
                onChange={(e) =>
                  setDraft({ ...draft, autoUpdateEnabled: e.target.checked })
                }
              />
              <span>
                自动更新（默认关）。打开后启动时自动检查一次，安装仍需手动确认。
              </span>
            </label>
          </div>
          <div className="row">
            <label style={{ fontWeight: 600, marginBottom: 4 }}>应用更新</label>
            <UpdateChecker autoCheckOnMount={draft?.autoUpdateEnabled ?? false} />
          </div>

          <div className="row">
            <button
              type="button"
              className="btn btn-primary"
              disabled={!dirty || save.isPending}
              onClick={() => {
                if (!draft) return;
                // 提交前校验（M8-S5B §6.6）：不合法就不发请求，并说清是哪一字段
                const problem = validateDraft(draft);
                if (problem !== null) {
                  setNotice(null);
                  setError(problem);
                  return;
                }
                setError(null);
                save.mutate(draft);
              }}
            >
              <Save size={14} aria-hidden /> 保存
            </button>
            {dirty ? <span className="muted">有未保存的修改</span> : null}
          </div>

          <GatewayCard
            enabled={draft.gatewayEnabled}
            port={draft.gatewayPort}
            onToggle={(enabled) => setDraft({ ...draft, gatewayEnabled: enabled })}
            onPortChange={(port) => setDraft({ ...draft, gatewayPort: port })}
            settingsDirty={dirty}
          />

          <ExportCard />

          <KeychainCard />

          <AuditCard />
        </>
      )}
    </section>
  );
}
