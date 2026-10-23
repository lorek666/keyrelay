import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, LogOut, Plus, RefreshCw } from "lucide-react";
import {
  addSite,
  captchaBegin,
  onCaptchaAutoFinished,
  captchaCancel,
  captchaComplete,
  detectSite,
  isAuthError,
  isCaptchaRequired,
  listSites,
  loginSite,
  logoutSite,
  siteBalance,
  type Balance,
  type SiteRow,
} from "../lib/api";
import ConfirmDialog from "../components/ConfirmDialog";
import Skeleton from "../components/Skeleton";
import { captchaPanelMode } from "../lib/captchaMode";
import CapButton from "../components/CapButton";
import { useTranslation, translate, getCurrentDict } from "../i18n";

export default function Sites() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [baseUrl, setBaseUrl] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loginTarget, setLoginTarget] = useState<SiteRow | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [secondFactor, setSecondFactor] = useState("");
  /** 处于人工验证兜底流程的站点（M8-S2）：登录被要求人机验证时置上。 */
  const [captchaSite, setCaptchaSite] = useState<SiteRow | null>(null);
  /** 官方页面窗口是否已打开（打开后才能提交「我已过完」）。 */
  const [captchaOpened, setCaptchaOpened] = useState(false);
  /** M38-S1：待确认「退出登录」的站点。 */
  const [logoutTarget, setLogoutTarget] = useState<SiteRow | null>(null);

  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });
  // M28-S2 / B-191 B 路：面板三态只来自能力表（不按 kind 硬编码）。
  const captchaMode = captchaSite ? captchaPanelMode(captchaSite.capabilities) : null;

  const detect = useMutation({
    mutationFn: detectSite,
    onSuccess: (fp) => {
      setError(null);
      setNotice(t("sites.notice.detected", {
        name: fp.displayName,
        kind: fp.kind,
        version: fp.version ?? t("sites.notice.unknownVersion"),
      }));
    },
    onError: (err: Error) => {
      setNotice(null);
      setError(err.message);
    },
  });

  const add = useMutation({
    mutationFn: addSite,
    onSuccess: async (site) => {
      setError(null);
      setNotice(t("sites.notice.added", { name: site.displayName }));
      setBaseUrl("");
      await qc.invalidateQueries({ queryKey: ["sites"] });
      await qc.invalidateQueries({ queryKey: ["app-info"] });
    },
    onError: (err: Error) => {
      setNotice(null);
      setError(err.message);
    },
  });

  // 打开站点官方页面（内嵌窗口由后端创建；用户自己在窗口里过验证码）。
  const beginCaptcha = useMutation({
    mutationFn: (siteId: number) => captchaBegin(siteId),
    onSuccess: () => {
      setError(null);
      setCaptchaOpened(true);
      setNotice(t("sites.notice.captchaAutoOpening"));
    },
    onError: (err: Error) => setError(err.message),
  });

  const login = useMutation({
    mutationFn: () =>
      loginSite({
        siteId: loginTarget!.id,
        username,
        password,
        secondFactor: secondFactor || undefined,
      }),
    onSuccess: async () => {
      setError(null);
      setNotice(t("sites.notice.loggedIn", { name: loginTarget?.displayName ?? "" }));
      // 密码只在这一刻存在于内存里，用完立刻清掉
      setPassword("");
      setSecondFactor("");
      setLoginTarget(null);
      // 登录改变的是「会话状态」与「远端密钥的可见性」。
      // 此处早先失效的是 `["keys"]`——**那个 key 从来不存在**（实际叫 `["stored-keys"]`，
      // 见 Keys.tsx / Overview.tsx），于是这条失效一直在空转（M8-S5A §3.6-6 的同一条，
      // 本次随人工验证批次一并订正）。
      await qc.invalidateQueries({ queryKey: ["sites"] });
      await qc.invalidateQueries({ queryKey: ["stored-keys"] });
      await qc.invalidateQueries({ queryKey: ["remote-keys"] });
      await qc.invalidateQueries({ queryKey: ["balance"] });
    },
    onError: (err: Error) => {
      // 失败时也要清密码：错误文案由后端给，前端不留副本
      setPassword("");
      if (isCaptchaRequired(err)) {
        // 人工兜底通道（M8-S2 / FR-1:102）：站点要求人机验证。
        // 按红线**不绕过**——收起登录框，切到「已自动打开验证窗口」面板，让用户自己过。
        const target = loginTarget;
        setError(null);
        setLoginTarget(null);
        setCaptchaSite(target);
        setCaptchaOpened(false);
        // M36-S1：自动打开**一次**（同一轮登录只一次；失败时面板上还有「重新打开」）。
        // `unsupported`（两种 WebView 能力位都 false）不自动打开，保留既有「不适用」面板。
        if (target && captchaPanelMode(target.capabilities) !== "unsupported") {
          beginCaptcha.mutate(target.id);
        }
        return;
      }
      setError(err.message);
    },
  });

  // 「我已过完」：后端去窗口里抓会话 cookie（值不经过前端）并接上会话。
  const finishCaptcha = useMutation({
    mutationFn: (siteId: number) => captchaComplete(siteId),
    onSuccess: async () => {
      setError(null);
      setNotice(t("sites.notice.captchaDone", { name: captchaSite?.displayName ?? "" }));
      setCaptchaSite(null);
      setCaptchaOpened(false);
      // 与「登录成功」同一组失效：会话状态、远端/本地密钥、余额。
      await qc.invalidateQueries({ queryKey: ["sites"] });
      await qc.invalidateQueries({ queryKey: ["stored-keys"] });
      await qc.invalidateQueries({ queryKey: ["remote-keys"] });
      await qc.invalidateQueries({ queryKey: ["balance"] });
    },
    onError: (err: Error) => setError(err.message),
  });

  const cancelCaptcha = useMutation({
    mutationFn: (siteId: number) => captchaCancel(siteId),
    onSuccess: () => {
      setNotice(t("sites.notice.cancelled"));
      setCaptchaSite(null);
      setCaptchaOpened(false);
    },
    onError: (err: Error) => setError(err.message),
  });

  // M38-S1：退出登录——清内存会话 + 删本地保险库条目（站点侧不受影响）。
  // 失败时关闭确认框并在页面顶部给出可读错误（spec §4.3「或关闭后显示错误」）。
  const logout = useMutation({
    mutationFn: (siteId: number) => logoutSite(siteId),
    onSuccess: async () => {
      setError(null);
      setNotice(t("sites.notice.loggedOut", { name: logoutTarget?.displayName ?? "" }));
      setLogoutTarget(null);
      // 与「登录成功」「验证码完成」同一组失效：会话状态、远端/本地密钥、余额。
      await qc.invalidateQueries({ queryKey: ["sites"] });
      await qc.invalidateQueries({ queryKey: ["stored-keys"] });
      await qc.invalidateQueries({ queryKey: ["remote-keys"] });
      await qc.invalidateQueries({ queryKey: ["balance"] });
    },
    onError: (err: Error) => {
      setLogoutTarget(null);
      setError(err.message);
    },
  });

  // M36-S1：订阅后端的「自动完成」事件。事件只是通知——会话已由后端接上（completed）
  // 或接入失败（failed，窗口仍开着）。只处理**当前面板那个站点**的事件：
  // 他站/面板已关 ⇒ 忽略；`completed` 之后迟到的重复事件因为面板已清空而幂等忽略。
  const captchaSiteRef = useRef<SiteRow | null>(null);
  useEffect(() => {
    captchaSiteRef.current = captchaSite;
  }, [captchaSite]);
  // `t` 只用来取文案：放进 ref，避免语言变化以外任何身份变化导致监听反复重订阅。
  const tRef = useRef(t);
  tRef.current = t;
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    let disposed = false;
    void (async () => {
      const stop = await onCaptchaAutoFinished((event) => {
        const current = captchaSiteRef.current;
        if (!current || current.id !== event.siteId) return;
        if (event.status === "completed") {
          setError(null);
          setCaptchaSite(null);
          setCaptchaOpened(false);
          setNotice(tRef.current("sites.notice.captchaAutoDone", { name: current.displayName }));
          void qc.invalidateQueries({ queryKey: ["sites"] });
          void qc.invalidateQueries({ queryKey: ["stored-keys"] });
          void qc.invalidateQueries({ queryKey: ["remote-keys"] });
          void qc.invalidateQueries({ queryKey: ["balance"] });
        } else {
          // 失败：面板保留，展示后端给的可读原因（不含凭据）；窗口仍开着。
          setError(event.message ?? tRef.current("sites.notice.captchaAutoFailed"));
        }
      });
      if (disposed) {
        stop();
        return;
      }
      unlisten = stop;
    })();
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [qc]);

  // 登录账号栏的文案（M9-S2 / B-120）：跟随**当前要登录的那个站点**的约定，
  // 与后端预检同一出处（`SiteRow.loginField`）。
  const fieldHint = loginFieldHint(loginTarget?.loginField ?? null);

  return (
    <section className="page">

      <div className="card site-add-card">
        <h3>{t("sites.title")}</h3>
        <div className="row site-add-form">
          <input
            className="input grow"
            placeholder="https://relay.example.com"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            spellCheck={false}
          />
          <button
            type="button"
            className="btn"
            disabled={!baseUrl || detect.isPending}
            onClick={() => detect.mutate(baseUrl)}
          >
            {t("sites.btn.test")}
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!baseUrl || add.isPending}
            onClick={() => add.mutate(baseUrl)}
          >
            <Plus size={14} aria-hidden /> {t("sites.btn.add")}
          </button>
        </div>
        <p className="muted">{t("sites.hint.fingerprint")}</p>
      </div>

      {notice ? <p className="ok" role="status">{notice}</p> : null}
      {error ? (
        <p className="error" role="alert">
          <AlertTriangle size={14} aria-hidden /> {error}
        </p>
      ) : null}

      {captchaSite ? (
        <div className="card">
          <h3>{t("sites.hint.captchaTitle", { name: captchaSite.displayName })}</h3>
          {captchaMode === "cookie" ? (
            <>
              <p className="muted">{t("sites.hint.captchaAutoBody")}</p>
              <div className="row">
                <button
                  type="button"
                  className="btn"
                  disabled={beginCaptcha.isPending}
                  onClick={() => beginCaptcha.mutate(captchaSite.id)}
                >
                  {t("sites.btn.reopenCaptcha")}
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={!captchaOpened || finishCaptcha.isPending}
                  onClick={() => finishCaptcha.mutate(captchaSite.id)}
                >
                  {finishCaptcha.isPending
                    ? t("sites.btn.connecting")
                    : t("sites.btn.manualFinish")}
                </button>
                <button
                  type="button"
                  className="btn btn-ghost"
                  disabled={cancelCaptcha.isPending}
                  onClick={() => cancelCaptcha.mutate(captchaSite.id)}
                >
                  {t("common.cancel")}
                </button>
              </div>
            </>
          ) : captchaMode === "bearer" ? (
            // M28-S2 / B-191 B 路：会话在响应体里（Bearer），登录页脚本把站点自己写入
            // localStorage 的 access token 经 `tianshu-relay-creds://` 回传；用户**自己**完成
            // 登录与验证码，Tianshu Relay 不替点、不读页面正文/输入框、不绕过验证码。
            <>
              <p className="muted">{t("sites.hint.captchaAutoBody")}</p>
              <div className="row">
                <button
                  type="button"
                  className="btn"
                  disabled={beginCaptcha.isPending}
                  onClick={() => beginCaptcha.mutate(captchaSite.id)}
                >
                  {t("sites.btn.reopenCaptcha")}
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={!captchaOpened || finishCaptcha.isPending}
                  onClick={() => finishCaptcha.mutate(captchaSite.id)}
                >
                  {finishCaptcha.isPending
                    ? t("sites.btn.connecting")
                    : t("sites.btn.manualFinish")}
                </button>
                <button
                  type="button"
                  className="btn btn-ghost"
                  disabled={cancelCaptcha.isPending}
                  onClick={() => cancelCaptcha.mutate(captchaSite.id)}
                >
                  {t("common.cancel")}
                </button>
              </div>
            </>
          ) : (
            // M26-S1 / B-191：该站点类型没有任何 WebView 兜底（两种能力位都 false）。
            // 替换面板：解释原因 + 仅「取消」按钮——不渲染「打开官方页面过一次」「我已过完」，
            // 避免用户撞墙后才看到误导文案。判据只来自能力表，**不按 kind 硬编码**（M7-S2 §3.3）。
            <>
              <p className="muted">{t("sites.hint.captchaUnsupportedBody")}</p>
              <div className="row">
                <button
                  type="button"
                  className="btn btn-ghost"
                  disabled={cancelCaptcha.isPending}
                  onClick={() => cancelCaptcha.mutate(captchaSite.id)}
                >
                  {t("common.cancel")}
                </button>
              </div>
            </>
          )}
        </div>
      ) : null}

      <div className="card">
        <div className="row row-between">
          <h3>{t("sites.list.title", { count: sites.data?.length ?? 0 })}</h3>
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => sites.refetch()}
            disabled={sites.isFetching}
          >
            <RefreshCw size={14} aria-hidden /> {t("common.refresh")}
          </button>
        </div>

        {sites.isLoading ? <Skeleton rows={3} /> : null}
        {sites.data?.length === 0 ? (
          <p className="muted empty">{t("sites.list.empty")}</p>
        ) : null}

        {sites.data?.length ? (
          <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>{t("sites.table.name")}</th>
                <th>{t("sites.table.kind")}</th>
                <th>{t("sites.table.url")}</th>
                <th>{t("sites.table.status")}</th>
                <th>{t("sites.table.balance")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {sites.data.map((site) => (
                <SiteRowView
                  key={site.id}
                  site={site}
                  onLogout={() => {
                    setError(null);
                    setNotice(null);
                    setLogoutTarget(site);
                  }}
                  onLogin={() => {
                    setError(null);
                    setNotice(null);
                    setUsername("");
                    setPassword("");
                    setSecondFactor("");
                    setLoginTarget(site);
                  }}
                />
              ))}
            </tbody>
          </table>
          </div>
        ) : null}
      </div>

      <ConfirmDialog
        open={loginTarget !== null}
        title={t("sites.loginDialog.title", { name: loginTarget?.displayName ?? "" })}
        confirmLabel={login.isPending ? t("sites.loginDialog.confirming") : t("sites.loginDialog.confirm")}
        confirmDisabled={!username || !password || login.isPending}
        onCancel={() => {
          setPassword("");
          setSecondFactor("");
          setLoginTarget(null);
        }}
        onConfirm={() => login.mutate()}
      >
        <p className="muted">{t("sites.loginDialog.body")}</p>
        <label className="field">
          <span>{fieldHint.label}</span>
          <input
            className="input"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="off"
            placeholder={fieldHint.placeholder}
            spellCheck={false}
          />
        </label>
        <label className="field">
          <span>{t("sites.loginDialog.password")}</span>
          <input
            className="input"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="off"
          />
        </label>
        <label className="field">
          <span>{t("sites.loginDialog.secondFactor")}</span>
          <input
            className="input"
            value={secondFactor}
            onChange={(e) => setSecondFactor(e.target.value)}
            autoComplete="off"
          />
        </label>
      </ConfirmDialog>

      <ConfirmDialog
        open={logoutTarget !== null}
        title={t("sites.logout.title", { name: logoutTarget?.displayName ?? "" })}
        confirmLabel={
          logout.isPending ? t("sites.logout.confirming") : t("sites.logout.confirm")
        }
        confirmDisabled={logout.isPending}
        onCancel={() => setLogoutTarget(null)}
        onConfirm={() => {
          if (logoutTarget) logout.mutate(logoutTarget.id);
        }}
      >
        <p className="muted">{t("sites.logout.body")}</p>
      </ConfirmDialog>
    </section>
  );
}

/** 会话状态 → 显示文案。取值由服务层维护（`store::set_site_health`）。 */
function healthLabel(health: string): string {
  switch (health) {
    case "ok":
      return translate(getCurrentDict(), "common.health.ok");
    case "needs_login":
      return translate(getCurrentDict(), "common.health.needsLogin");
    default:
      // `unknown` 或将来新增的取值：不谎报「已登录」
      return translate(getCurrentDict(), "common.health.unknown");
  }
}

/**
 * 登录账号栏的**文案**（M9-S2 / B-120）：标签 + placeholder。
 *
 * 判据来自后端（`SiteRow.loginField`，唯一出处 `site::login_field`）——
 * 这里**只**负责把稳定取值翻成中文，页面里不得出现「哪个 `kind` 该填邮箱」。
 *
 * 未知取值（后端将来新增）回落到中性词「账号」：**不猜**是用户名，也不谎称是邮箱。
 * 猜错的代价与 B-120 一样——用户按标签填，站点直接拒。
 */
function loginFieldHint(field: SiteRow["loginField"]): {
  label: string;
  placeholder?: string;
} {
  if (field === "email") {
    return { label: translate(getCurrentDict(), "sites.loginField.email"), placeholder: "name@example.com" };
  }
  if (field === "username") {
    return { label: translate(getCurrentDict(), "sites.loginField.username") };
  }
  return { label: translate(getCurrentDict(), "sites.loginField.account") };
}

/** 会话状态 → CSS 类名。未知取值落到 `unknown` 的样式，不伪装成正常。 */
function healthClass(health: string): string {
  switch (health) {
    case "ok":
      return "enabled";
    case "needs_login":
      return "needs-login";
    default:
      return "unknown";
  }
}

function SiteRowView({
  site,
  onLogin,
  onLogout,
}: {
  site: SiteRow;
  onLogin: () => void;
  onLogout: () => void;
}) {
  const { t } = useTranslation();
  // 能力集为 false 的站点**连请求都不发**：后端也会提前拒绝（`Error::Unsupported`），
  // 但先发一次注定失败的请求只会让余额列闪一下「（需登录）」这种错的原因。
  const balance = useQuery({
    queryKey: ["balance", site.id],
    queryFn: () => siteBalance(site.id),
    enabled: site.capabilities.balance,
    retry: false,
  });

  const balanceText = !site.capabilities.balance
    ? t("sites.balanceText.unobservable")
    : balance.isLoading
      ? "…"
      : balance.isError
        ? // 只有**确实是凭证问题**才说「（需登录）」（M8-S5B §6.9）。
          // 超时 / 5xx / 断网都说成「需登录」，用户会去重新登录一个根本不需要登录的站点。
          isAuthError(balance.error)
          ? t("sites.balanceText.needLogin")
          : t("sites.balanceText.queryFailed")
        : balance.data
          ? formatBalance(balance.data)
          : "—";

  return (
    <tr>
      <td>{site.displayName}</td>
      <td className="mono">
        <span className="kind-badge">{site.kind}</span>
      </td>
      <td className="mono ellipsis" title={site.baseUrl}>
        {site.baseUrl}
      </td>
      <td>
        {/* 会话状态由服务层维护（B-61）：needs_login 表示「这个站需要重新登录」，
            它在刷新汇总里既不算成功也不算失败，所以必须在这里单独可见。 */}
        <span className={`health-${healthClass(site.health)}`}>
          <span className="status-dot" aria-hidden />
          {healthLabel(site.health)}
        </span>
        {/* M38-S1：会话已落本地加密保险库（重启可免登）。判据只来自后端字段，
            不按 kind / capabilities 猜。`!== true` ⇒ 不显示（旧夹具/未知状态都不显示）。 */}
        {site.sessionPersisted === true ? (
          <span className="session-badge" title={t("sites.session.persistedHint")}>
            {t("sites.session.persisted")}
          </span>
        ) : null}
      </td>
      <td
        className="mono"
        title={balanceReason(site, balance.data, balance.error)}
      >
        {balanceText}
      </td>
      <td>
        <div className="row">
          {/* 能力驱动的灰显（W5）：站点类型不支持登录时，这个按钮点了只会报
              「不需要登录」之类的别的原因。文案与判断都来自 `capabilities`。 */}
          <CapButton
            allowed={site.capabilities.login}
            reason={t("sites.capReason.noLogin")}
            className="btn btn-ghost"
            onClick={onLogin}
          >
            {t("sites.btn.login")}
          </CapButton>
          {/* M38-S1：「退出登录」**不依赖** `capabilities.login`（spec §4.3）——
              会话已经存在时，清除本地状态总是允许的。只在有持久化会话时出现。 */}
          {site.sessionPersisted === true ? (
            <button type="button" className="btn btn-ghost" onClick={onLogout}>
              <LogOut size={14} aria-hidden /> {t("sites.btn.logout")}
            </button>
          ) : null}
        </div>
      </td>
    </tr>
  );
}

/**
 * 余额单元格的文案（W2）。
 *
 * **`known === false` 或后端给了 `null` ⇒ 「不可观测」，绝不 `toFixed(2)`。**
 * 「余额为零」与「余额不可观测」是两个不同的事实，后者渲染成 `0.00` 会让用户
 * 以为这个站没钱了，也会让阈值告警看起来「已经触发过」（M7-S2 §6.5 硬要求 (a)）。
 */
function formatBalance(balance: Balance): string {
  if (!balance.known || balance.remaining === null) return translate(getCurrentDict(), "sites.balanceText.unobservable");
  return `${balance.remaining.toFixed(2)} ${balance.currency}`;
}

/** 余额列为什么显示成这样——挂在 `title` 上，避免「不可观测」被当成一个 bug。 */
function balanceReason(
  site: SiteRow,
  balance?: Balance,
  error?: unknown,
): string | undefined {
  if (!site.capabilities.balance) return translate(getCurrentDict(), "sites.balanceReason.noCapability");
  if (balance && !balance.known) return translate(getCurrentDict(), "sites.balanceReason.noUsable");
  // 查询失败时把**真实原因**放进 title（M8-S5B §6.9）：此前这里不处理错误，
  // 于是用户既看到错的文案（「需登录」），也看不到真正的原因。
  if (error instanceof Error) return error.message;
  return undefined;
}
