import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Plus, RefreshCw } from "lucide-react";
import {
  addSite,
  detectSite,
  listSites,
  loginSite,
  siteBalance,
  type Balance,
  type SiteRow,
} from "../lib/api";
import ConfirmDialog from "../components/ConfirmDialog";
import CapButton from "../components/CapButton";

export default function Sites() {
  const qc = useQueryClient();
  const [baseUrl, setBaseUrl] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loginTarget, setLoginTarget] = useState<SiteRow | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [secondFactor, setSecondFactor] = useState("");

  const sites = useQuery({ queryKey: ["sites"], queryFn: listSites });

  const detect = useMutation({
    mutationFn: detectSite,
    onSuccess: (fp) => {
      setError(null);
      setNotice(`识别成功：${fp.displayName}（${fp.kind} ${fp.version ?? "未知版本"}）`);
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
      setNotice(`已加入站点：${site.displayName}`);
      setBaseUrl("");
      await qc.invalidateQueries({ queryKey: ["sites"] });
      await qc.invalidateQueries({ queryKey: ["app-info"] });
    },
    onError: (err: Error) => {
      setNotice(null);
      setError(err.message);
    },
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
      setNotice(`已登录：${loginTarget?.displayName ?? ""}`);
      // 密码只在这一刻存在于内存里，用完立刻清掉
      setPassword("");
      setSecondFactor("");
      setLoginTarget(null);
      await qc.invalidateQueries({ queryKey: ["keys"] });
    },
    onError: (err: Error) => {
      // 失败时也要清密码：错误文案由后端给，前端不留副本
      setPassword("");
      setError(err.message);
    },
  });

  return (
    <section>
      <h2>站点</h2>

      <div className="card">
        <h3>接入新站点</h3>
        <div className="row">
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
            测试连接
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!baseUrl || add.isPending}
            onClick={() => add.mutate(baseUrl)}
          >
            <Plus size={14} aria-hidden /> 加入
          </button>
        </div>
        <p className="muted">
          只会调用站点的公开状态接口做指纹识别；登录凭证不落库，只进系统钥匙串。
        </p>
      </div>

      {notice ? <p className="ok" role="status">{notice}</p> : null}
      {error ? (
        <p className="error" role="alert">
          <AlertTriangle size={14} aria-hidden /> {error}
        </p>
      ) : null}

      <div className="card">
        <div className="row row-between">
          <h3>已接入（{sites.data?.length ?? 0}）</h3>
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => sites.refetch()}
            disabled={sites.isFetching}
          >
            <RefreshCw size={14} aria-hidden /> 刷新
          </button>
        </div>

        {sites.isLoading ? <p className="muted">加载中…</p> : null}
        {sites.data?.length === 0 ? (
          <p className="muted">还没有站点。填一个中转站地址，点「测试连接」开始。</p>
        ) : null}

        {sites.data?.length ? (
          <table className="table">
            <thead>
              <tr>
                <th>名称</th>
                <th>类型</th>
                <th>地址</th>
                <th>状态</th>
                <th>余额</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {sites.data.map((site) => (
                <SiteRowView
                  key={site.id}
                  site={site}
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
        ) : null}
      </div>

      <ConfirmDialog
        open={loginTarget !== null}
        title={`登录 ${loginTarget?.displayName ?? ""}`}
        confirmLabel={login.isPending ? "登录中…" : "登录"}
        confirmDisabled={!username || !password || login.isPending}
        onCancel={() => {
          setPassword("");
          setSecondFactor("");
          setLoginTarget(null);
        }}
        onConfirm={() => login.mutate()}
      >
        <p className="muted">
          密码只用于本次登录请求；若站点启用了登录加密，会在本机完成加密后再发送。
          凭证不会写入本地数据库。
        </p>
        <label className="field">
          <span>用户名</span>
          <input
            className="input"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="off"
          />
        </label>
        <label className="field">
          <span>密码</span>
          <input
            className="input"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="off"
          />
        </label>
        <label className="field">
          <span>二次验证码（可选）</span>
          <input
            className="input"
            value={secondFactor}
            onChange={(e) => setSecondFactor(e.target.value)}
            autoComplete="off"
          />
        </label>
      </ConfirmDialog>
    </section>
  );
}

/** 会话状态 → 显示文案。取值由服务层维护（`store::set_site_health`）。 */
function healthLabel(health: string): string {
  switch (health) {
    case "ok":
      return "已登录";
    case "needs_login":
      return "需要重新登录";
    default:
      // `unknown` 或将来新增的取值：不谎报「已登录」
      return "未登录";
  }
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

function SiteRowView({ site, onLogin }: { site: SiteRow; onLogin: () => void }) {
  // 能力集为 false 的站点**连请求都不发**：后端也会提前拒绝（`Error::Unsupported`），
  // 但先发一次注定失败的请求只会让余额列闪一下「（需登录）」这种错的原因。
  const balance = useQuery({
    queryKey: ["balance", site.id],
    queryFn: () => siteBalance(site.id),
    enabled: site.capabilities.balance,
    retry: false,
  });

  const balanceText = !site.capabilities.balance
    ? "不可观测"
    : balance.isLoading
      ? "…"
      : balance.isError
        ? "（需登录）"
        : balance.data
          ? formatBalance(balance.data)
          : "—";

  return (
    <tr>
      <td>{site.displayName}</td>
      <td className="mono">{site.kind}</td>
      <td className="mono ellipsis" title={site.baseUrl}>
        {site.baseUrl}
      </td>
      <td>
        {/* 会话状态由服务层维护（B-61）：needs_login 表示「这个站需要重新登录」，
            它在刷新汇总里既不算成功也不算失败，所以必须在这里单独可见。 */}
        <span className={`health-${healthClass(site.health)}`}>
          {healthLabel(site.health)}
        </span>
      </td>
      <td className="mono" title={balanceReason(site, balance.data)}>
        {balanceText}
      </td>
      <td>
        {/* 能力驱动的灰显（W5）：站点类型不支持登录时，这个按钮点了只会报
            「不需要登录」之类的别的原因。文案与判断都来自 `capabilities`。 */}
        <CapButton
          allowed={site.capabilities.login}
          reason="该站点类型不需要登录"
          className="btn btn-ghost"
          onClick={onLogin}
        >
          登录
        </CapButton>
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
  if (!balance.known || balance.remaining === null) return "不可观测";
  return `${balance.remaining.toFixed(2)} ${balance.currency}`;
}

/** 余额列为什么显示成这样——挂在 `title` 上，避免「不可观测」被当成一个 bug。 */
function balanceReason(site: SiteRow, balance?: Balance): string | undefined {
  if (!site.capabilities.balance) return "该站点类型不提供余额";
  if (balance && !balance.known) return "站点这次没有返回可用的余额";
  return undefined;
}
