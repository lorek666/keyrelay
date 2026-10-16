/**
 * 与 Tauri 后端通信的**唯一**入口。
 *
 * 约定：
 * - 所有命令名与 `src-tauri/src/commands_list.rs` 的 `COMMANDS` 一一对应
 *   （由 `scripts/check-commands.mjs` 在 `pnpm test` 里做集合比对）；
 * - 页面组件**不得**直接 `import("@tauri-apps/api")`，只能经过本文件；
 * - 浏览器（无 Tauri）环境下退回 mock，保证 `pnpm build` 与页面预览可用；
 * - 本文件不缓存、不持久化任何密钥；后端返回的 `secret` 只做一次性透传。
 */

import { translate, getCurrentDict } from "../i18n";

/**
 * 站点类型的**设计能力**（M7-S2 的 `site/capability.rs`，IPC 上是 `SiteSummary.capabilities`）。
 *
 * 界面用它灰显按钮，**不得**按 `kind` 硬编码判断：新增站点类型时，硬编码的页面会给出一个
 * 「点了才报错」的按钮，而报的错还是别的原因（例如「未登录」）。认不出的站点类型
 * ⇒ 后端给**全部 `false`**（fail-closed）。
 *
 * 灰显 = `disabled` + `title` 写明原因，**不是**隐藏——用户要能看见「这个功能存在，
 * 但这个站点类型不支持」，否则会以为是产品缺陷（M7-S2 spec §3.3）。
 */
export type SiteCapabilities = {
  /** 有会话/登录端点（需要账号密码换会话） */
  login: boolean;
  /** 能列出站点侧已有的令牌 */
  listKeys: boolean;
  /** 能在站点侧新建令牌 */
  createKey: boolean;
  /** 能读回令牌明文 */
  revealKey: boolean;
  /** 能回收（删除）站点侧令牌 */
  revokeKey: boolean;
  /** 能查询余额 */
  balance: boolean;
  /** 能拉取可用分组（含倍率） */
  groups: boolean;
  /**
   * 能取到**每把** key 的用量。
   *
   * 定义是「本产品**今天**能不能取到」而不是「站点端有没有该字段」：当前三行全 `false`
   * （`keys.quota_used` 没有写入器），所以界面**不显示**用量列（M7-S0 §3.2 裁决 / B-96）。
   */
  keyUsage: boolean;
};

export type SiteRow = {
  id: number;
  kind: string;
  baseUrl: string;
  displayName: string;
  /**
   * 站点健康状态，服务层自动维护，界面只读。
   * `"unknown"`（从没登录过）| `"ok"`（登录过且会话有效）| `"needs_login"`（会话已失效，需要重新登录）
   */
  health: string;
  /**
   * 登录账号栏的**输入约定**（M9-S2 / B-120）：`"username"` | `"email"` | `null`。
   *
   * 判据**只**来自后端那张表（`site::login_field`）——页面里不得出现
   * 「`kind === "sub2api"` 就该填邮箱」这类硬编码：新增站点类型时，硬编码的那处会给出一个
   * **错的标签**，而错标签让用户填一个注定被站点拒的值（B-120 的原始症状：
   * Sub2API 的账号栏被标成「用户名」，用户按标签填用户名 → 站点 400）。
   *
   * `null` = 该站点类型没有登录流程（`capabilities.login === false`，登录按钮本来就是灰的）。
   */
  loginField: "username" | "email" | null;
  /** 该站点类型支持什么（唯一出处，页面不得自己判断 `kind`） */
  capabilities: SiteCapabilities;
};

export type AppInfo = {
  name: string;
  version: string;
  dbPath: string;
  siteCount: number;
  /** 数据库降级原因；非空表示当前跑在内存库上 */
  dbError?: string | null;
  /** 钥匙串后端。`"memory"` 表示密钥没进系统钥匙串（真实运行里即为缺陷）。 */
  vaultBackend: string;
};

export type SiteFingerprint = {
  kind: string;
  displayName: string;
  version?: string | null;
};

export type KeyRow = {
  remoteId: string;
  name: string;
  group?: string | null;
  status: string;
  createdAt?: number | null;
  lastUsedAt?: number | null;
  /** M14-S3：当前累计已用（USD）。`null` = 站点未给 / 未采集。**不得**渲染成 `0.00`。 */
  quotaUsed?: number | null;
  /** M14-S3：限额（USD）。`null` = 不限 / 未采集。 */
  quotaLimit?: number | null;
  /** M14-S3：币种（`"USD"`）。 */
  currency?: string | null;
};

/** 新建密钥的返回值。`secret` 是**明文**，只允许一次性透传给投递流程，不渲染、不落任何存储。 */
export type StoredKey = {
  id: number;
  remoteId: string;
  name: string;
  /** 掩码后的密钥（`…末4位`）。**明文永远不从后端返回给前端。** */
  masked: string;
};

export type StoredKeyRow = {
  id: number;
  siteId: number;
  remoteId?: string | null;
  name: string;
  group?: string | null;
  /**
   * 生命周期状态。**两个来源、两套词表**，界面上必须能区分：
   *
   * - 站点侧（`site::KeyStatus`）：`"enabled"` / `"disabled"`（站点把它禁了）/ `"exhausted"` / `"unknown"`；
   * - 本地侧（`store::KEY_STATUS_REVOKED`）：`"revoked"` —— **我**在站点上回收了它（B-82）。
   *
   * `"revoked"` 是本地生命周期标记：本地行**保留**（`bindings` 与漂移追溯靠 `keys.id` 存活），
   * 站点侧那把 key 已经没了。用 `disabled` 冒充会让界面分不清「站点禁的」与「我回收的」。
   */
  status: string;
  /** M14-S3：当前累计已用（USD）。`null` = 未采集。**不得**渲染成 `0.00`。 */
  quotaUsed?: number | null;
  /** M14-S3：限额（USD）。`null` = 不限 / 未采集。 */
  quotaLimit?: number | null;
  /** M14-S3：币种（`"USD"`）。 */
  currency?: string | null;
};

/**
 * 站点余额。
 *
 * **`known === false` ⇒ `remaining` / `used` 是 `null`** —— 这是**结构性**保证：
 * 后端在未知态下不给出任何可渲染的数字，界面也就不可能把「不知道」渲染成 `0.00`。
 * 这两件事必须能分开：余额为零是一个事实，余额不可观测是另一个事实
 * （`custom-openai-compatible` 站点拿不到余额）。阈值告警同理，见 M7-S2 §6.5 硬要求 (b)。
 */
export type Balance = {
  currency: string;
  /** 该站点的余额是否可观测。`false` ⇒ 下面两个数值字段为 `null`。 */
  known: boolean;
  /** 未知时为 `null`。**未知绝不当成 0。** */
  remaining: number | null;
  /** 未知时为 `null`。 */
  used: number | null;
  rawQuota?: number | null;
  quotaPerUnit?: number | null;
};

export type DeliveryField = {
  key: string;
  /** 已掩码的值（密钥只暴露末 4 位） */
  masked: string;
};

export type ConsentState = "missing" | "granted" | "revoked";

/**
 * 投递后该 agent 是否需要重启才读到新配置（PRD FR-4:137 / M7-S3）。
 *
 * 取值**只能**来自后端 `delivery::restart_hint(channel)`——界面**不得**按通道硬编码判断，
 * 否则新增一条通道时又会漏一处，而漏掉的那处会给出一个错的生效预期。
 */
export type RestartHint = "notNeeded" | "needed" | "dependsOnNewSession";

export type DeliveryPlan = {
  agentId: string;
  channel: string;
  targetPath: string;
  targetExists: boolean;
  /**
   * `"site"` | `"gateway"`（M8-S4 §6.6）。
   *
   * 网关模式下写进去的是**本地网关令牌**，不是站点密钥——两种模式的字段名一模一样
   * （`apiKey` / `apiBase`）⇒ 界面不把模式说出来，用户就分不清。
   */
  mode: DeliveryMode;
  fields: DeliveryField[];
  /** 已脱敏的 diff 预览 */
  preview: string;
  consent: ConsentState;
  consentGrantedAt?: number | null;
  consentRevokedAt?: number | null;
  /**
   * 提示项（**不是错误**，投递照常可做）。
   *
   * 当前唯一来源：同目录下存在「同主名、不同扩展名」的兄弟文件
   * （例如 `opencode.jsonc` 与 `opencode.json` 并存），agent 可能优先读另一个，
   * 于是本次投递**静默不生效**（BACKLOG B-76）。
   */
  warnings: string[];
  /** 生效策略。文案由这个取值派生，**不得**在页面里按通道判断。 */
  restartHint: RestartHint;
};

/** 投递模式（M8-S4 §6.2）。缺省 = `"site"`：既有调用点的行为一字不变。 */
export type DeliveryMode = "site" | "gateway";

export type ConsentRow = {
  agentId: string;
  channel: string;
  targetPath: string;
  /** JSON 数组文本，只有键名 */
  fields: string;
  grantedAt: number;
  revokedAt?: number | null;
};

export type DeliveryOutcome = {
  channel: string;
  targetPath: string;
  journalId: string;
  backupPath?: string | null;
};

export type EventRow = {
  id: number;
  ts: number;
  level: string;
  source: string;
  /** 已脱敏 */
  message: string;
  /** 已脱敏 */
  payload?: string | null;
};

export type DriftState =
  | "intact"
  | "modified"
  | "missing"
  // 文件**存在但读不到**（权限/路径类型）：与「被删了」不同，处理方式也不同
  | "unreadable"
  | "unknown";

export type DriftReport = {
  targetPath: string;
  agentId: string;
  channel: string;
  state: DriftState;
  journalId: string;
  currentSha256?: string | null;
  expectedSha256?: string | null;
};

export type Settings = {
  /** 秒；0 = 关闭定时刷新 */
  refreshIntervalSecs: number;
  /** USD；0 = 不告警 */
  balanceAlertThreshold: number;
  driftCheckOnStart: boolean;
  /** 本地网关开关。默认关闭。 */
  gatewayEnabled: boolean;
  /** 网关端口（只绑 127.0.0.1） */
  gatewayPort: number;
  /** M14-S1：多站路由开关（默认关，保住换站语义）。 */
  gatewayMultiSite: boolean;
  /** M14-S1：模型清单采集开关（默认关）。 */
  collectModels: boolean;
  /** M14-S1：模型采集最小间隔秒（默认 1800 = 30min）。 */
  modelsMinIntervalSecs: number;
  // ---- M6-S5：FR-9 界面与隐私 ----
  /** "system" | "light" | "dark" */
  theme: string;
  /** "zh-CN" | "en-US" */
  language: string;
  /** 空 = 直连（manual 模式下）；auto 模式下被忽略。合法性由传输层判定，这里只存。 */
  proxyUrl: string;
  /** 代理模式（M10-S2）："auto" | "manual" | "direct"。默认 auto。 */
  proxyMode: string;
  /** 默认关（PRD §5「默认零遥测」）。当前只记录意愿，不发送任何数据。 */
  telemetryEnabled: boolean;
  /** 默认关。当前只记录意愿，未接更新服务器。 */
  autoUpdateEnabled: boolean;
  // ---- M6-S5：FR-3 通知 ----
  /** 系统通知。默认开。 */
  notifySystemEnabled: boolean;
  /** 空 = 不启用 Webhook。 */
  notifyWebhookUrl: string;
  /** Webhook 超时（秒），上限 60。 */
  notifyTimeoutSecs: number;
  // ---- M6-S5：FR-7 轮换与常驻 ----
  /** 轮换周期（天）；0 = 关闭轮换提醒。 */
  rotationMaxAgeDays: number;
  /** 到期前多少天开始提醒；不得超过 rotationMaxAgeDays。 */
  rotationWarnBeforeDays: number;
  /** 登录自启。默认关。 */
  autostartEnabled: boolean;
  /** 关窗时隐藏到托盘。默认开。 */
  closeToTray: boolean;
  /** 启动时不显示主窗口。默认关。 */
  startHidden: boolean;
};

export type RefreshSummary = {
  sitesTotal: number;
  sitesOk: number;
  sitesFailed: number;
  keysTotal: number;
  balanceAlerts: number[];
  /**
   * 需要重新登录的站点 id（升序去重）。
   *
   * 当轮认证失败的站点**同时**出现在 `sitesFailed` 与这里；
   * 上一轮就已失效、本轮被跳过的站点**只在这里**——那正是这个字段存在的理由。
   */
  needsLogin: number[];
};

export type AuditFinding = {
  /** `"plaintext-in-file"` | `"unreadable"` | `"plaintext-in-events"` */
  kind: string;
  path?: string | null;
  detail: string;
};

export type AuditReport = {
  filesScanned: number;
  bytesScanned: number;
  clean: boolean;
  findings: AuditFinding[];
  summary: string;
};

export type GatewayStatus = {
  running: boolean;
  url?: string | null;
  /** 本地令牌：只在界面上显示给用户，用于配置 agent 连本地网关 */
  token?: string | null;
  site?: string | null;
  /**
   * 令牌是否已持久化（M8-S4 §6.4 第 5 条）。
   *
   * `false` = 临时令牌（钥匙串不可用），**重启后会变** ⇒ 指向网关的通道需要重新投递。
   * 这是**降级**，必须显示出来——不说的话用户会以为「换站零改动」成立了，直到 agent 开始 401。
   */
  tokenPersistent: boolean;
};

/** 一次回收（站点侧删除）的回报（B-100）。 */
export type RevokeReport = {
  siteId: number;
  remoteId?: string | null;
  /** 站点侧确认删除（不可逆） */
  revoked: boolean;
  /** 本地 `keys.status` 是否写上 */
  localStatusUpdated: boolean;
  note?: string | null;
};

/** 一次解绑的结果（M8-S4 §5.4）。三者互相独立，界面要分别说。 */
export type UnbindOutcome = {
  /** 本次新标记的行数（幂等：二次调用为 0） */
  unbound: number;
  /** 本次看到但早已解绑的行数 */
  alreadyUnbound: number;
  revoked: RevokeReport[];
  note?: string | null;
};

/** 一次「等待人工验证」的挑战（M8-S2 §2.1）。 */
export type CaptchaChallenge = {
  siteId: number;
  /** 站点自己的官方页面地址（永不带 userinfo、永不指向第三方域名）。 */
  url: string;
};

export type ExportResult = {
  path: string;
  encrypted: boolean;
  bytes: number;
  /**
   * 是否登记进「已知导出物」表（审计据此扫描用户自选路径）。
   * `false` = 文件写成了，但**审计看不到它** —— 界面必须说出来。
   */
  registered: boolean;
};

export type PruneResult = { removed: number };

/** 诊断包落盘结果（FR-9:196）。与 `ExportResult` 分开：诊断包**没有加密形态**。 */
export type DiagnosticsResult = {
  path: string;
  bytes: number;
  /** 实际写进去的事件条数。 */
  events: number;
  /** 语义同 `ExportResult.registered`：`false` = 审计看不到这个文件。 */
  registered: boolean;
};

export type LoginArgs = {
  siteId: number;
  username: string;
  password: string;
  secondFactor?: string;
};

export type CreateKeyArgs = {
  siteId: number;
  name: string;
  group?: string;
};

export type DeliveryArgs = {
  keyId: number;
  channel: string;
  /** 模型名（可缺）。OpenCode 通道可填；其余通道不读它。 */
  model?: string;
  /**
   * 投递模式（M8-S4 §6.2）。缺省 = `"site"`（既有行为一字不变）。
   *
   * `"gateway"` 时后端要求网关**正在运行**：此时才有一个可信的本地地址可写。
   */
  mode?: DeliveryMode;
};

const hasTauri =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export const runtimeMode: "tauri" | "browser" = hasTauri ? "tauri" : "browser";

/** 后端错误统一是字符串（`Error::Display`）。 */
function asMessage(err: unknown): string {
  if (typeof err === "string") return err;
  if (err instanceof Error) return err.message;
  return String(err);
}

async function invokeCommand<T>(
  cmd: string,
  args?: Record<string, unknown>,
): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core");
  try {
    return await invoke<T>(cmd, args);
  } catch (err) {
    throw new Error(asMessage(err));
  }
}

// ============================================================ mock（浏览器预览）

/** mock 用的能力集：与 `site/capability.rs` 的两行**逐格一致**（NewAPI/Sub2Api 同表）。 */
const MOCK_CAPS_LOGINABLE: SiteCapabilities = {
  login: true,
  listKeys: true,
  createKey: true,
  revealKey: true,
  revokeKey: true,
  balance: true,
  groups: true,
  // M14-S3：NewAPI/Sub2API 的 key_usage 从 false 改 true（list_keys 带用量）。
  keyUsage: true,
};

/**
 * mock 里放**三个**站点是有意的：
 *
 * - `newapi`：全能力 + 账号栏是**用户名**；
 * - `sub2api`：全能力 + 账号栏是**邮箱**（M9-S2 / B-120）——`pnpm dev` 里点它的「登录」
 *   就能肉眼核标签与 placeholder 是否跟着 `loginField` 变（本机没有 GUI 会话，
 *   浏览器预览是唯一能肉眼核界面文案的路径）；
 * - `custom-openai-compatible`：全能力 `false`，用来看「灰显 + 不可观测」长什么样。
 */
const MOCK_SITES: SiteRow[] = [
  {
    id: 1,
    kind: "newapi",
    baseUrl: "https://relay.example.com",
    displayName: "示例中转站（mock·用户名登录）",  // i18n:skip
    health: "unknown",
    loginField: "username",
    capabilities: MOCK_CAPS_LOGINABLE,
  },
  {
    id: 2,
    kind: "sub2api",
    baseUrl: "https://api.example.com",
    displayName: "示例 Sub2API（mock·邮箱登录）",  // i18n:skip
    health: "unknown",
    loginField: "email",
    capabilities: MOCK_CAPS_LOGINABLE,
  },
  {
    id: 3,
    kind: "custom-openai-compatible",
    baseUrl: "https://compatible.example.com",
    displayName: "只读兼容端点（mock·无令牌管理）",  // i18n:skip
    health: "unknown",
    loginField: null,
    capabilities: {
      login: false,
      listKeys: false,
      createKey: false,
      revealKey: false,
      revokeKey: false,
      balance: false,
      groups: false,
      keyUsage: false,
    },
  },
];

const MOCK_INFO: AppInfo = {
  name: "KeyRelay",
  version: "0.1.0-dev",
  dbPath: "（浏览器预览模式，无本地数据库）",  // i18n:skip
  siteCount: MOCK_SITES.length,
  dbError: null,
  vaultBackend: "memory",
};

const MOCK_KEYS: KeyRow[] = [
  {
    remoteId: "12",
    // 示例数据用 FR-2 的规范形态（`<app-id>/<agent-id>/<yyyymmdd>`），
    // 免得预览里又出现一个「看着像规范、其实是占位」的旧名字（B-87）
    name: "keyrelay/codex/20251009",
    group: "default",
    status: "enabled",
    createdAt: 1_760_000_000,
    lastUsedAt: null,
    // M14-S3：mock 用量数据（让浏览器预览能看到用量列）。
    quotaUsed: 1.23,
    quotaLimit: 10.0,
    currency: "USD",
  },
];

const MOCK_PLAN: DeliveryPlan = {
  agentId: "codex",
  channel: "codex-auth-json",
  targetPath: "/Users/you/.codex/auth.json",
  targetExists: true,
  mode: "site",
  fields: [
    { key: "auth_mode", masked: "apikey" },
    { key: "OPENAI_API_KEY", masked: "…cdef" },
  ],
  preview: '- "OPENAI_API_KEY": "…0000"\n+ "OPENAI_API_KEY": "…cdef"\n',
  consent: "missing",
  consentGrantedAt: null,
  consentRevokedAt: null,
  warnings: [],
  // codex 只在进程启动时读 auth.json（M7-S3 的 `restart_hint` 表）
  restartHint: "needed",
};

const MOCK_EVENTS: EventRow[] = [
  {
    id: 3,
    ts: 1_760_000_300,
    level: "info",
    source: "delivery",
    message: "投递完成: codex-auth-json",  // i18n:skip
    payload: '{"journal_id":"j1-0","target_path":"/Users/you/.codex/auth.json"}',
  },
  {
    id: 2,
    ts: 1_760_000_200,
    level: "info",
    source: "delivery",
    message: "已授予投递同意",  // i18n:skip
    payload: '{"agent_id":"codex","channel":"codex-auth-json"}',
  },
  {
    id: 1,
    ts: 1_760_000_100,
    level: "info",
    source: "site",
    message: "站点已识别: newapi 示例中转站（mock）",  // i18n:skip
    payload: '{"site_id":1,"version":"v0.0.0-mock"}',
  },
];

function mock<T>(value: T): Promise<T> {
  return Promise.resolve(value);
}

// ============================================================ 命令封装

export async function appInfo(): Promise<AppInfo> {
  return hasTauri ? invokeCommand<AppInfo>("app_info") : mock(MOCK_INFO);
}

export async function listSites(): Promise<SiteRow[]> {
  return hasTauri ? invokeCommand<SiteRow[]>("list_sites") : mock(MOCK_SITES);
}

export async function detectSite(baseUrl: string): Promise<SiteFingerprint> {
  if (!hasTauri) {
    return mock({ kind: "newapi", displayName: "示例中转站（mock）", version: "v0.0.0-mock" });  // i18n:skip
  }
  return invokeCommand<SiteFingerprint>("detect_site", { baseUrl });
}

export async function addSite(baseUrl: string): Promise<SiteRow> {
  if (!hasTauri) return mock(MOCK_SITES[0]);
  return invokeCommand<SiteRow>("add_site", { baseUrl });
}

export async function loginSite(args: LoginArgs): Promise<void> {
  if (!hasTauri) return mock(undefined);
  return invokeCommand<void>("login_site", { args });
}

/**
 * 人工过验证码：打开站点官方页面（内嵌窗口），**用户自己**过一次（FR-1:102 / M8-S2）。
 *
 * 红线：不绕过验证码——窗口里只有官方页面本身，不注入脚本、不读 DOM、不自动点击。
 * 窗口的创建与 cookie 抓取都在后端（`src-tauri`）；本函数只负责发起与收结果。
 */
export async function captchaBegin(siteId: number): Promise<CaptchaChallenge> {
  if (!hasTauri) {
    return mock({ siteId, url: "https://relay.example.com/login" });
  }
  return invokeCommand<CaptchaChallenge>("captcha_begin", { siteId });
}

/**
 * 「我已过完」：后端去窗口里抓会话 cookie 并接上会话。
 *
 * cookie 值**不经过前端**（从 WebView 直接进核心层）；提交前后端会先比对页面 origin，
 * 页面离开了站点域名就拒绝提交（防止把别处的 cookie 存成本站会话）。
 */
export async function captchaComplete(siteId: number): Promise<void> {
  if (!hasTauri) {
    return mock(undefined);
  }
  return invokeCommand<void>("captcha_complete", { siteId });
}

/** 取消人工验证（关窗）：相位回空闲态，不保存任何东西。幂等。 */
export async function captchaCancel(siteId: number): Promise<void> {
  if (!hasTauri) {
    return mock(undefined);
  }
  return invokeCommand<void>("captcha_cancel", { siteId });
}

/**
 * 「这个登录错误是不是站点要求人机验证」——界面据此切到人工兜底面板（M8-S2 §9）。
 *
 * 匹配的是 `Error::CaptchaRequired` 的 Display 原文（`invokeCommand` 已把后端错误
 * 转成 `Error(message)`，这里只看 message）。
 */
export function isCaptchaRequired(err: unknown): boolean {
  return err instanceof Error && err.message.includes("需要人工完成验证码");  // i18n:skip
}

/**
 * 「这个错误是不是认证失败」——界面据此把原因说成「（需登录）」（M8-S5B §6.9）。
 *
 * 为什么需要它：余额查询失败有**很多种**原因（超时 / 5xx / 断网 / 认证失效），
 * 此前一律显示「（需登录）」，用户会去重新登录一个根本不需要登录的站点。
 * 这里只认两种「确实是凭证问题」的形态，其余一律按普通查询失败显示真实原因。
 *
 * 匹配的是后端 Display 原文（`invokeCommand` 已把错误转成 `Error(message)`）：
 * - `Error::AuthFailed` ⇒ `"认证失败: …"`；
 * - `Error::CaptchaRequired` ⇒ `"需要人工完成验证码"`。
 */
export function isAuthError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  return err.message.includes("认证失败") || isCaptchaRequired(err);  // i18n:skip
}

export async function listKeys(siteId: number): Promise<KeyRow[]> {
  if (!hasTauri) return mock(MOCK_KEYS);
  return invokeCommand<KeyRow[]>("list_keys", { siteId });
}

export async function createKey(args: CreateKeyArgs): Promise<StoredKey> {
  if (!hasTauri) {
    return mock({ id: 2, remoteId: "13", name: args.name, masked: "…cdef" });
  }
  return invokeCommand<StoredKey>("create_key", { args });
}

/** 本地已存的密钥（**不含密钥本体**）。投递需要的是这里的 `id`。 */
export async function listStoredKeys(): Promise<StoredKeyRow[]> {
  if (!hasTauri) {
    return mock([
      {
        id: 1,
        siteId: 1,
        remoteId: "12",
        name: "keyrelay/codex/20251009",
        group: "default",
        status: "enabled",
      },
      // 站点 2 上的一把（M9-S4 C/D）：只有一把密钥时，「密钥下拉 / 密钥表跟随所选站点」
      // 在预览里根本看不出来——过滤写反了也一样显示这一把。
      {
        id: 2,
        siteId: 2,
        remoteId: "7",
        name: "keyrelay/claude-code/20251010",
        group: null,
        status: "enabled",
      },
    ]);
  }
  return invokeCommand<StoredKeyRow[]>("list_stored_keys");
}

export async function siteBalance(siteId: number): Promise<Balance> {
  if (!hasTauri) {
    // 站点 2 是 `custom-openai-compatible`：余额**不可观测**。mock 必须照着真实契约返回
    // `known: false` + `null`，否则预览里看不到「不可观测」那条路径。
    const site = MOCK_SITES.find((s) => s.id === siteId);
    if (site && !site.capabilities.balance) {
      return mock({
        currency: "USD",
        known: false,
        remaining: null,
        used: null,
        rawQuota: null,
        quotaPerUnit: null,
      });
    }
    return mock({
      currency: "USD",
      known: true,
      remaining: 12.5,
      used: 3.25,
      rawQuota: 6_250_000,
      quotaPerUnit: 500_000,
    });
  }
  return invokeCommand<Balance>("site_balance", { siteId });
}

export async function deliveryPlan(args: DeliveryArgs): Promise<DeliveryPlan> {
  if (!hasTauri) return mock(MOCK_PLAN);
  return invokeCommand<DeliveryPlan>("delivery_plan", { args });
}

export async function grantConsent(args: DeliveryArgs): Promise<void> {
  if (!hasTauri) return mock(undefined);
  return invokeCommand<void>("grant_consent", { args });
}

export async function revokeConsent(args: DeliveryArgs): Promise<void> {
  if (!hasTauri) return mock(undefined);
  return invokeCommand<void>("revoke_consent", { args });
}

export async function listConsents(): Promise<ConsentRow[]> {
  if (!hasTauri) return mock([]);
  return invokeCommand<ConsentRow[]>("list_consents");
}

/**
 * 已投递且**未解绑**的「通道 → key」绑定（M8-S7 / B-116）。
 *
 * 批量改指网关用它决定「有哪些通道要改、每条该用哪把 key 重投」。
 * 只读 `bindings`，不写任何东西。
 *
 * **没有 `channel` 字段，这是有意的**：`bindings` 表没有 channel 列。后端
 * `relative_target()` 按当前 home 解析，而绑定里的 `targetPath` 可能是当年另一个 home
 * 下写的 ⇒ 后端猜会猜错。前端用 `CHANNELS` 的 `agent` 字段匹配 `agentId`，
 * 再用 `targetPath` 的文件名二分（`opencode.json` vs `opencode.jsonc`）。
 */
export type ChannelBinding = {
  /**
   * 绑定行 id（M8-S7 P2-4）。做 React key 与勾选键用——`bindings` 没有 UNIQUE 约束，
   * 同一文件上可能有多条未解绑的行，用 `${channel}::${targetPath}` 会让它们共用复选框。
   */
  bindingId: number;
  agentId: string;
  keyId: number;
  targetPath: string;
  siteId: number;
};

export async function listChannelBindings(): Promise<ChannelBinding[]> {
  if (!hasTauri) return mock([]);
  return invokeCommand<ChannelBinding[]>("list_channel_bindings");
}

/**
 * 前端侧的「agent ⇒ 通道」表（M8-S7 / B-116）。
 *
 * 与 `Agents.tsx` 的 `CHANNELS` **同源不同处**：那张表驱动投递页的下拉，
 * 这张只服务「从一条 binding 反查它属于哪条通道」。两边都由
 * `scripts/check-commands.mjs` 的通道名对账守着 id 集合一致（B-101），
 * 所以不会静默分叉。
 *
 * `file` 是**文件名**（不是整条路径）：一个 agent 可能对应多条通道
 * （`opencode` 同时有 `opencode.json` 与 `opencode.jsonc` 两条），靠它二分。
 */
/**
 * agent ⇒ 通道（M8-S7 / B-116），一对一。
 *
 * **为什么不需要按文件名二分**（定稿时按独立复审 P3-1 简化）：后端
 * `DeliveryChannel::agent_id()` 是**注入的**（7 条通道 → 7 个不同 agent 名，
 * `delivery/mod.rs` 有测试专门钉「agent_id 不重复」），而 `bindings.agent_id`
 > 写的就是 `channel.agent_id()`。所以本产品写下的行里，  // i18n:skip
 * `agent_id == "opencode"` 时目标一定是 `opencode.json`——给它配第二条
 * `opencode-jsonc` 候选是死逻辑（M8-S7 第一版那么写了，评审抓出）。
 *
 * 真正的多通道场景由 `opencode-jsonc` 这个**独立的 agent 名** 承载，它自己一行。
 * 将来若真出现「一个 agent 名下多条通道」，后端会先有重复的 `agent_id`
 * ⇒ 那条测试会红 ⇒ 那时再改回带文件名的结构。
 */
const AGENT_CHANNELS: Record<string, string> = {
  codex: "codex-auth-json",
  "claude-code": "claude-code-settings",
  opencode: "opencode",
  "opencode-jsonc": "opencode-jsonc",
  "gemini-cli": "gemini-cli",
  "claude-desktop": "claude-desktop",
  "grok-build": "grok-build",
  openclaw: "openclaw",
  hermes: "hermes",
  mcode: "mcode",
  pi: "pi",
  cursor: "cursor",
  cline: "cline",
  "qwen-code": "qwen-code",
  deepseek: "deepseek",
  trae: "trae",
  "mimo-code": "mimo-code",
  "cline-desktop": "cline-desktop",
  "dsh": "dsh",
};

/**
 * 一条 binding 属于哪条通道。猜不出来 ⇒ `null`（**不猜**）。
 *
 * 猜不出来的真实原因：`targetPath` 是当年**另一个 home** 下写的
 * （用户改过 `KEYRELAY_HOME`），文件名对不上表里任何一条。
 * 这时界面显示「无法识别通道」并让用户手工去投递页处理，比猜一个错通道好。
 */
export function channelOfBinding(agentId: string): string | null {
  return AGENT_CHANNELS[agentId] ?? null;
}

export async function applyDelivery(
  args: DeliveryArgs,
): Promise<DeliveryOutcome> {
  if (!hasTauri) {
    return mock({
      channel: args.channel,
      targetPath: MOCK_PLAN.targetPath,
      journalId: "j-mock-0",
      backupPath: "/Users/you/.keyrelay/backups/j-mock-0/0-auth.json",
    });
  }
  return invokeCommand<DeliveryOutcome>("apply_delivery", { args });
}

/**
 * 投递历史的一行（M9-S4）：「变更历史」页的回滚入口。字段语义见 `store::DeliveryHistoryRow`。
 *
 * 能不能回滚由三个标志位决定（`rolledBack` / `superseded` / `hasJournal`），
 * 判据在后端；真正的安全闸是回滚时的哈希校验——这里只负责灰显并说明原因。
 */
export type DeliveryRecord = {
  bindingId: number;
  journalId: string;
  agentId: string;
  keyId: number;
  siteId: number;
  targetPath: string;
  appliedAt: number;
  /** `null` = 仍然绑定。已解绑的投递**仍可回滚**（M8-S4 §5.4） */
  unboundAt: number | null;
  /** `null` 且 `hasJournal`：投递前文件不存在，回滚会删掉它 */
  backupPath: string | null;
  hasJournal: boolean;
  rolledBack: boolean;
  /**
   * 同一文件之后又投递过（且那次没回滚）：这次的回滚通常会被拒，界面据此灰显。
   * 例外（文件已被删 / 之后写下的字节恰好相同）见 `store::DeliveryHistoryRow::superseded`。
   */
  superseded: boolean;
};

export async function listDeliveries(limit = 100): Promise<DeliveryRecord[]> {
  if (!hasTauri) {
    // 每种状态各一行，预览里四种灰显原因都能看到
    return mock([
      {
        bindingId: 4,
        journalId: "j-mock-3",
        agentId: "shell",
        keyId: 1,
        siteId: 1,
        targetPath: "/Users/you/.zshrc",
        appliedAt: 1_760_000_500,
        unboundAt: 1_760_000_600,
        backupPath: "/Users/you/.keyrelay/backups/j-mock-3/0-.zshrc",
        hasJournal: true,
        rolledBack: false,
        superseded: false,
      },
      {
        bindingId: 3,
        journalId: "j-mock-2",
        agentId: "codex",
        keyId: 2,
        siteId: 2,
        targetPath: MOCK_PLAN.targetPath,
        appliedAt: 1_760_000_400,
        unboundAt: null,
        backupPath: null,
        hasJournal: true,
        rolledBack: false,
        superseded: false,
      },
      {
        bindingId: 2,
        journalId: "j-mock-1",
        agentId: "codex",
        keyId: 1,
        siteId: 1,
        targetPath: MOCK_PLAN.targetPath,
        appliedAt: 1_760_000_300,
        unboundAt: null,
        backupPath: "/Users/you/.keyrelay/backups/j-mock-1/0-auth.json",
        hasJournal: true,
        rolledBack: false,
        superseded: true,
      },
      {
        bindingId: 1,
        journalId: "j-mock-0",
        agentId: "claude-code",
        keyId: 1,
        siteId: 1,
        targetPath: "/Users/you/.claude/settings.json",
        appliedAt: 1_760_000_200,
        unboundAt: null,
        backupPath: "/Users/you/.keyrelay/backups/j-mock-0/0-settings.json",
        hasJournal: true,
        rolledBack: true,
        superseded: false,
      },
    ]);
  }
  return invokeCommand<DeliveryRecord[]>("list_deliveries", { limit });
}

export async function rollbackDelivery(journalId: string): Promise<void> {
  if (!hasTauri) return mock(undefined);
  return invokeCommand<void>("rollback_delivery", { journalId });
}

export type GatewayUsageRow = {
  id: number;
  ts: number;
  siteId: number;
  model: string;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
};

export type UsageSnapshotRow = {
  id: number;
  ts: number;
  siteId: number;
  used: number;
  remaining: number;
  currency: string;
  known: boolean;
};

export async function recentGatewayUsage(hours = 24): Promise<GatewayUsageRow[]> {
  if (!hasTauri) return mock([]);
  return invokeCommand<GatewayUsageRow[]>("recent_gateway_usage", { hours });
}

export async function recentUsageSnapshots(hours = 168): Promise<UsageSnapshotRow[]> {
  if (!hasTauri) return mock([]);
  return invokeCommand<UsageSnapshotRow[]>("recent_usage_snapshots", { hours });
}

/**
 * 一把 key 一天的用量采样（M14-S3，Sub2API `usage/daily`）。**不含密钥**。
 *
 * 字段名与后端 `KeyUsageSampleDto`（camelCase）一致：`inputTokens` / `outputTokens`
 *（非 `tokensIn` / `tokensOut`——见 spec §11 差异②）。
 */
export type KeyUsageSample = {
  date: string;
  requests: number;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  cost: number;
};

/**
 * 查一把 key 近 `days`（默认 30）天的 per-key 用量采样（M14-S3 / PRD FR-3）。
 *
 * NewAPI 站点无日趋势端点 ⇒ 返回空数组（NewAPI 只取当前累计 `quotaUsed`，不写 `usage_samples`）。
 * Sub2API 站点返回 `usage/daily` 的 30 天每日采样。
 */
export async function recentKeyUsage(
  keyId: number,
  days = 30,
): Promise<KeyUsageSample[]> {
  if (!hasTauri) return mock([]);
  return invokeCommand<KeyUsageSample[]>("recent_key_usage", { keyId, days });
}

/** M14-S1：模型别名映射（B-110）—— agent 侧模型名 → 真实模型名。 */
export type AliasEntry = { alias: string; realModel: string };

export async function listAliasMap(): Promise<AliasEntry[]> {
  if (!hasTauri) return mock([]);
  return invokeCommand<AliasEntry[]>("list_alias_map");
}

export async function upsertAlias(alias: string, realModel: string): Promise<void> {
  if (!hasTauri) return;
  return invokeCommand<void>("upsert_alias", { alias, realModel });
}

export async function deleteAlias(alias: string): Promise<void> {
  if (!hasTauri) return;
  return invokeCommand<void>("delete_alias", { alias });
}

export async function recentEvents(limit = 100): Promise<EventRow[]> {
  if (!hasTauri) return mock(MOCK_EVENTS);
  return invokeCommand<EventRow[]>("recent_events", { limit });
}

export async function gatewayStatus(): Promise<GatewayStatus> {
  if (!hasTauri) {
    return mock({
      running: false,
      url: null,
      token: null,
      site: null,
      tokenPersistent: false,
    });
  }
  return invokeCommand<GatewayStatus>("gateway_status");
}

export async function gatewayStart(
  siteId: number,
  keyId: number,
): Promise<GatewayStatus> {
  if (!hasTauri) {
    return mock({
      running: true,
      url: "http://127.0.0.1:8787",
      token: "kr-gw-mock0000000000000000000000000",
      site: "示例中转站（mock）",  // i18n:skip
      tokenPersistent: true,
    });
  }
  return invokeCommand<GatewayStatus>("gateway_start", {
    args: { siteId, keyId },
  });
}

export async function gatewayStop(): Promise<GatewayStatus> {
  if (!hasTauri) {
    return mock({
      running: false,
      url: null,
      token: null,
      site: null,
      tokenPersistent: false,
    });
  }
  return invokeCommand<GatewayStatus>("gateway_stop");
}

export async function exportBundle(
  password?: string,
): Promise<ExportResult> {
  if (!hasTauri) {
    return mock({
      path: "/Users/you/.keyrelay/exports/keyrelay-export-mock.json",
      encrypted: Boolean(password),
      bytes: 2048,
      registered: true,
    });
  }
  return invokeCommand<ExportResult>("export_bundle", {
    args: { password: password ?? null },
  });
}

export async function pruneBackups(keep: number): Promise<PruneResult> {
  if (!hasTauri) return mock({ removed: 0 });
  return invokeCommand<PruneResult>("prune_backups", { args: { keep } });
}

/**
 * 导出诊断包（FR-9:196）。**脱敏后的**事件表 + 白名单设置快照 + 版本信息。
 *
 * 与「导出配置」的区别：配置导出是给**迁移**用的（站点与密钥元数据），
 * 诊断包是给**报障**用的（最近发生了什么 + 你装的哪个版本）。
 * 两者都不含密钥本体，但只有配置导出有加密形态。
 */
export async function exportDiagnostics(limit?: number): Promise<DiagnosticsResult> {
  if (!hasTauri) {
    return mock({
      path: "/Users/you/.keyrelay/exports/keyrelay-diagnostics-mock.json",
      bytes: 4096,
      events: 200,
      registered: true,
    });
  }
  return invokeCommand<DiagnosticsResult>("export_diagnostics", {
    args: { limit: limit ?? null },
  });
}

export async function auditRedaction(): Promise<AuditReport> {
  if (!hasTauri) {
    return mock({
      filesScanned: 3,
      bytesScanned: 123456,
      clean: true,
      findings: [],
      summary: "已扫描 3 个文件 / 123456 字节，未发现明文凭证",  // i18n:skip
    });
  }
  return invokeCommand<AuditReport>("audit_redaction");
}

export async function driftReport(): Promise<DriftReport[]> {
  if (!hasTauri) {
    return mock([
      {
        targetPath: "/Users/you/.codex/auth.json",
        agentId: "codex",
        channel: "codex-auth-json",
        state: "intact",
        journalId: "j-mock-0",
        currentSha256: "deadbeef",
        expectedSha256: "deadbeef",
      },
    ]);
  }
  return invokeCommand<DriftReport[]>("drift_report");
}

export async function getSettings(): Promise<Settings> {
  if (!hasTauri) return mock(mockSettings);
  return invokeCommand<Settings>("get_settings");
}

/**
 * 预览模式下的设置「库」（M9-S4）。`updateSettings` 写回这里：主题保存后 `["settings"]`
 * 会被重读，读到的若还是写死的初始值，界面就会立刻弹回「跟随系统」——预览里核不了主题。
 */
let mockSettings: Settings = {
  refreshIntervalSecs: 0,
  balanceAlertThreshold: 0,
  driftCheckOnStart: true,
  gatewayEnabled: false,
  gatewayPort: 8787,
  gatewayMultiSite: false,
  collectModels: false,
  modelsMinIntervalSecs: 1800,
  theme: "system",
  language: "zh-CN",
  proxyUrl: "",
  proxyMode: "auto",
  telemetryEnabled: false,
  autoUpdateEnabled: false,
  notifySystemEnabled: true,
  notifyWebhookUrl: "",
  notifyTimeoutSecs: 10,
  rotationMaxAgeDays: 30,
  rotationWarnBeforeDays: 7,
  autostartEnabled: false,
  closeToTray: true,
  startHidden: false,
};

export async function updateSettings(settings: Settings): Promise<Settings> {
  if (!hasTauri) {
    mockSettings = { ...settings };
    return mock(mockSettings);
  }
  return invokeCommand<Settings>("update_settings", { args: { settings } });
}

/** `detect_system_proxy` 的返回（M10-S2）：auto 模式下探测到的系统代理（已脱敏）。 */
export type DetectedSystemProxy = {
  /** 来源：`macos-system` / `windows-registry` / 环境变量名 / `manual`；`null` = 未检测到 */
  source: string | null;
  /** 脱敏后的 URL（含 userinfo 时完全丢弃，只显示 `scheme://host:port`）；`null` = 未检测到 */
  maskedUrl: string | null;
};

/**
 * 探测系统代理（M10-S2）：只读，不改设置。供设置页「自动」模式展示检测结果。
 * 无 Tauri 环境（mock）返回未检测到。
 */
export async function detectSystemProxy(): Promise<DetectedSystemProxy> {
  if (!hasTauri) {
    return mock({ source: null, maskedUrl: null });
  }
  return invokeCommand<DetectedSystemProxy>("detect_system_proxy");
}

export async function refreshAll(): Promise<RefreshSummary> {
  if (!hasTauri) {
    return mock({
      sitesTotal: 1,
      sitesOk: 1,
      sitesFailed: 0,
      keysTotal: 1,
      balanceAlerts: [],
      needsLogin: [],
    });
  }
  return invokeCommand<RefreshSummary>("refresh_all");
}

// ============================================ M6-S5：FR-2 / FR-7

export type Group = {
  name: string;
  /** 分组倍率。`null` = 站点没给（**不是 0**，0 表示免费分组）。 */
  rate: number | null;
  description: string | null;
};

export async function availableGroups(siteId: number): Promise<Group[]> {
  if (!hasTauri) {
    return mock([
      { name: "default", rate: 1, description: null },
      { name: "vip", rate: 0.5, description: "折扣分组" },  // i18n:skip
    ]);
  }
  return invokeCommand<Group[]>("available_groups", { siteId });
}

export type KeySyncSummary = {
  siteId: number;
  siteTotal: number;
  alreadyLocal: number;
  /**
   * 本次**恢复**了多少条：本地记录还在、但钥匙串条目被清过（「清理钥匙串条目」），
   * 于是把明文取回**原来那一行**。与 `imported` 分开：恢复 = 你清过钥匙串，
   * 现在按提示取回来了；导入 = 本机第一次见到这把 key。
   */
  restored: number;
  imported: number;
  /** 站点没给明文的 key。界面据此引导「新建一把」而不是以为对齐成功了。 */
  unreadable: string[];
};

/**
 * 把站点侧已有密钥的明文一次性对齐到本地钥匙串。
 *
 * **不返回任何明文**——这是刻意的：命令层至今没有任何一条命令返回过密钥明文，
 * 批量明文一旦过 IPC 就会进入 WebView 的内存与开发者工具。
 */
export async function syncSiteKeys(siteId: number): Promise<KeySyncSummary> {
  if (!hasTauri) {
    return mock({
      siteId,
      siteTotal: 2,
      alreadyLocal: 1,
      restored: 0,
      imported: 1,
      unreadable: [],
    });
  }
  return invokeCommand<KeySyncSummary>("sync_site_keys", { siteId });
}

export type RotationDue = {
  keyId: number;
  siteId: number;
  name: string;
  createdAt: number;
  dueAt: number;
};

/** 该轮换的密钥。纯本地判定，不联网、不读密钥。 */
export async function rotationDue(): Promise<RotationDue[]> {
  if (!hasTauri) return mock([]);
  return invokeCommand<RotationDue[]>("rotation_due");
}

export type RotationPlan = {
  keyId: number;
  siteId: number;
  keyName: string;
  /** 固定三步的稳定标识 */
  steps: string[];
  /** 会被重注入的通道 */
  channels: string[];
  /** 认不出通道的目标。非空 = 必须禁用「开始轮换」。 */
  unmappedTargets: string[];
  oldRemoteId: string | null;
};

/**
 * 轮换预览（FR-7）。只读，一个请求都不发。
 *
 * 「回收旧钥匙」不可逆，所以 PRD §7 的二次确认必须建立在这份预览上——
 * 没有预览的二次确认只是「真的要删吗」，用户看不到真正需要他判断的东西：
 * **会波及哪些投递目标**。
 */
export async function rotationPlan(keyId: number): Promise<RotationPlan> {
  if (!hasTauri) {
    return mock({
      keyId,
      siteId: 1,
      keyName: "keyrelay/codex/20251009",
      steps: ["create_new", "reinject_all", "revoke_old"],
      channels: ["codex-auth-json"],
      unmappedTargets: [],
      oldRemoteId: "1",
    });
  }
  return invokeCommand<RotationPlan>("rotation_plan", { keyId });
}

export type RotationRun = {
  newKeyId: number;
  /** 新密钥的掩码形态。明文只在钥匙串里，绝不过 IPC。 */
  newKeyMasked: string;
  reinjected: string[];
  revoke: "revoked" | "skippedNoRemoteId" | "notAttempted" | "failed";
  revokeReason: string | null;
  /** `null` = 没中途失败 */
  stoppedAt: string | null;
  stopReason: string | null;
  /** 三步是否都没中途失败。**不得只看它**：`skippedNoRemoteId` 也算完成。 */
  completed: boolean;
};

/** 执行轮换（FR-7「一键三连」）。破坏性操作，调用前必须走过 `rotationPlan` + 二次确认。 */
export async function rotateKey(keyId: number, name: string): Promise<RotationRun> {
  if (!hasTauri) {
    return mock({
      newKeyId: 2,
      newKeyMasked: "…6789",
      reinjected: ["codex-auth-json"],
      revoke: "revoked" as const,
      revokeReason: null,
      stoppedAt: null,
      stopReason: null,
      completed: true,
    });
  }
  return invokeCommand<RotationRun>("rotate_key", { keyId, name });
}

/**
 * 回收站点上的某把令牌（B-82 的独立路径）。
 *
 * **不是**「删除本地记录」：本地行会被标成 `revoked` 并保留——`bindings` 与漂移追溯
 * 靠 `keys.id` 存活，删行会把它们一起带走。
 *
 * 破坏性且不可逆（站点侧那把 key 真的没了），所以 `confirm` 必须显式为 `true`；
 * 核心层会拒绝 `false`，界面上也必须先问过一次。
 */
export async function revokeKey(
  siteId: number,
  remoteId: string,
  confirm: boolean,
): Promise<RevokeReport> {
  if (!hasTauri) {
    return mock({
      siteId,
      remoteId,
      revoked: true,
      localStatusUpdated: true,
      note: null,
    });
  }
  return invokeCommand<RevokeReport>("revoke_key", { siteId, remoteId, confirm });
}

/**
 * 解绑一个 agent 与它的密钥（FR-2:115 / M8-S4 §5.4）。
 *
 * `alsoRevoke` 是**另一件事**：`false`（默认）纯本地、一个站点请求都不发；
 * `true` 顺带把站点侧那把 key 删掉（不可逆）⇒ 后端强制 `confirm === true`。
 */
export async function unbindAgent(
  agentId: string,
  alsoRevoke: boolean,
  confirm: boolean,
): Promise<UnbindOutcome> {
  if (!hasTauri) {
    return mock({
      unbound: 1,
      alreadyUnbound: 0,
      revoked: alsoRevoke
        ? [
            {
              siteId: 1,
              remoteId: "mock-remote-1",
              revoked: true,
              localStatusUpdated: true,
              note: null,
            },
          ]
        : [],
      note: null,
    });
  }
  return invokeCommand<UnbindOutcome>("unbind_agent", {
    agentId,
    alsoRevoke,
    confirm,
  });
}

/**
 * 显式轮换网关本地令牌（M8-S4 §6.4）。
 *
 * 后端把「换令牌 + 重启网关」合成一个动作：只换钥匙串会让运行中的网关与 agent 配置不一致，
 * 只重启等于没轮换。轮换后旧令牌立即失效 ⇒ **指向网关的通道需要重新投递**。
 *
 * 网关没在跑时只换钥匙串里那一份（`args` 可以不给）。
 */
export async function gatewayRotateToken(
  args?: { siteId: number; keyId: number },
): Promise<GatewayStatus> {
  if (!hasTauri) {
    return mock({
      running: false,
      url: null,
      token: null,
      site: null,
      tokenPersistent: true,
    });
  }
  return invokeCommand<GatewayStatus>("gateway_rotate_token", { args: args ?? null });
}

export type KeychainPurgeReport = {
  attempted: number;
  removed: number;
  failed: number;
  /** 第一条失败的文案（已脱敏）。没有失败时为 `null`。 */
  firstError: string | null;
};

/**
 * 清空钥匙串里属于本产品的条目（FR-8「卸载后钥匙串条目可一键清理」）。
 *
 * 不可逆：秘密删了就没了（站点侧那把 key 还在，但本地再也取不回明文）。
 * 本地 SQLite 记录**保留**——清理的是秘密，不是历史。
 */
export async function purgeKeychain(confirm: boolean): Promise<KeychainPurgeReport> {
  if (!hasTauri) return mock({ attempted: 3, removed: 3, failed: 0, firstError: null });
  return invokeCommand<KeychainPurgeReport>("purge_keychain", { confirm });
}

/**
 * 探测「已知但本版本**不托管**」的 agent 落点（Cline / Roo Code）。
 *
 * 只读：核心层永不创建目录、永不写盘。它存在的理由是**不静默**——用户在 Cline / Roo Code
 * 里配了中转站，本产品既不能帮他注入，也不该假装没这回事。
 *
 * `note` 是给用户看的原文（为什么不写），界面**不得**改写它。
 */
export type UnmanagedTarget = {
  label: string;
  path: string;
  exists: boolean;
  note: string;
};

export async function detectUnmanagedTargets(): Promise<UnmanagedTarget[]> {
  if (!hasTauri) {
    return mock([
      {
        label: "Cline",
        path: "/Users/u/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev",
        exists: false,
        note: "本版本不向 Cline 写入：它的配置落点尚未核实，写错文件会让你以为投递成功。",  // i18n:skip
      },
    ]);
  }
  return invokeCommand<UnmanagedTarget[]>("detect_unmanaged_targets");
}

/**
 * 按 FR-2:113 的命名规范给一个默认名：`<app-id>/<agent-id>/<yyyymmdd>`。
 *
 * **日期由界面给**（M7-S5 决策 D-5）：Rust 侧不读时钟、不做时区——用户看到的「今天」
 * 应当是他所在时区的今天。调用方用本地日期算 `(year, month, day)` 传进去
 * （注意 `getMonth()` 从 0 开始，要 `+1`）。
 *
 * 返回 `null` 表示入参不合法。**此时不要回退到硬编码的名字**——那正是这条规范要消灭的
 * 东西（这里原本写死的 `"codex/daily"` 看着像规范、其实是个占位）。
 */
export async function suggestKeyName(
  agentId: string,
  date: { year: number; month: number; day: number },
): Promise<string | null> {
  if (!hasTauri) {
    // 浏览器预览用的 mock（M8-S5B §7.4 / B-102）。
    //
    // **形态与权威实现同形，但不复刻其校验**：年份补足 4 位、月日各 2 位，
    // 与 `crates/keyrelay-core/src/naming.rs` 的 `{year:04}{month:02}{day:02}` 一致
    // （此前这里写 `date.year` 不补零，与后端差一位——B-102 报的就是这个）。
    //
    // 段规则（非空 / `[A-Za-z0-9._-]` / ≤64 字节）**不在这里校验**：前端不编译 Rust，
    // 复刻一份校验规则只会多一个漂移源。要校验就走 IPC（`hasTauri` 为真时正是如此）。
    const pad = (n: number) => String(n).padStart(2, "0");
    const year = String(date.year).padStart(4, "0");
    return `keyrelay/${agentId}/${year}${pad(date.month)}${pad(date.day)}`;
  }
  return invokeCommand<string | null>("suggest_key_name", {
    agentId,
    year: date.year,
    month: date.month,
    day: date.day,
  });
}

/**
 * 分组倍率的展示口径（M6-S4 复审 P2-4 / P2-5 的裁决）。
 *
 * 只在**展示层**收紧，核心层不加校验：我们没有站点事实支撑「倍率 0 是不是合法值」
 * （有的部署可能用它表示免费分组），所以在核心层拒绝会改掉冻结接口的语义；
 * 而直接显示 `0` 或 `-1` 又会让用户以为「这个分组不要钱」。
 *
 * 因此只渲染能确定是倍率的取值，其余一律显示为「倍率未知」——**绝不用 1.0 兜底**：
 * 那会让用户按错误的成本预期选分组，而选错分组的代价是真实的钱。
 */
export function formatGroupRate(rate: number | null): string {
  if (rate === null || !Number.isFinite(rate) || rate <= 0) return translate(getCurrentDict(), "common.rateUnknown");
  return `${rate}×`;
}

export type AutostartState = "enabled" | "disabled" | "unknown";

export type Autostart = {
  state: AutostartState;
  /** 计划的人类可读摘要（不含任何值）。仅 `setAutostart` 返回时有内容。 */
  plan: string | null;
  manualAction: string | null;
};

export async function autostartStatus(): Promise<Autostart> {
  if (!hasTauri) {
    return mock({ state: "disabled" as AutostartState, plan: null, manualAction: null });
  }
  return invokeCommand<Autostart>("autostart_status");
}

export async function setAutostart(enabled: boolean): Promise<Autostart> {
  if (!hasTauri) {
    return mock({
      state: (enabled ? "enabled" : "disabled") as AutostartState,
      plan: enabled ? "新建 ~/Library/LaunchAgents/keyrelay-autostart.plist" : "删除自启项",  // i18n:skip
      manualAction: null,
    });
  }
  return invokeCommand<Autostart>("autostart_set", { enabled });
}

// ============================================================ 自动更新（M10-S1）

export interface UpdateInfo {
  version: string;
  currentVersion: string;
  date?: string;
  body?: string;
}

/**
 * 检查更新。返回 `null` = 当前已是最新版本。
 *
 * 网络错误、签名校验失败等会抛异常——调用方应 catch 并显示错误，
 * 而不是当成「无更新」。
 *
 * 在浏览器（无 Tauri）环境下，mock 返回 `null`。
 */
export async function checkForUpdates(): Promise<UpdateInfo | null> {
  if (!hasTauri) {
    return mock(null);
  }
  const { check } = await import("@tauri-apps/plugin-updater");
  const result = await check();
  if (!result) return null;
  return {
    version: result.version,
    currentVersion: result.currentVersion,
    date: result.date,
    body: result.body,
  };
}

/**
 * 下载并安装已检查到的更新。**不重启**——安装完成后由调用方在用户确认后调
 * [`relaunchApp`]，避免立即重启丢失用户未保存的修改（U4）。
 *
 * 必须先调用 `checkForUpdates()` 并拿到非 null 的结果——但本函数不持有那个
 * 对象（JS 侧 `Update` 对象不可序列化），所以在 Tauri 环境下重新检查一次再下载。
 * 两次检查之间的时间窗口很小（用户刚点了按钮），版本不会变。
 */
export async function downloadAndInstallUpdate(): Promise<void> {
  if (!hasTauri) {
    await mock(undefined);
    return;
  }
  const { check } = await import("@tauri-apps/plugin-updater");
  const result = await check();
  if (!result) {
    throw new Error(translate(getCurrentDict(), "common.noUpdate"));
  }
  await result.downloadAndInstall();
}

/**
 * 重启应用。在 [`downloadAndInstallUpdate`] 完成、用户确认后调用。
 */
export async function relaunchApp(): Promise<void> {
  if (!hasTauri) {
    await mock(undefined);
    return;
  }
  await import("@tauri-apps/plugin-process").then(({ relaunch }) => relaunch());
}

// ============================================================ M15-S1：模型检测（bazaarlink probe）

/** probe 检测结果（只含身份判定摘要，不含 items[].response 等敏感字段）。 */
export type ProbeRun = {
  runId: string;
  status: string;
  identityStatus?: string | null;
  verdictStatus?: string | null;
  trueFamily?: string | null;
  trueModel?: string | null;
  spoofMethod?: string | null;
  confidence?: string | null;
  warningsCount: number;
  reportUrl?: string | null;
  createdAt?: number | null;
  completedAt?: number | null;
};

export type ProbeArgs = {
  keyId: number;
  modelId: string;
  claimedModel?: string | null;
  baseUrlOverride?: string | null;
  confirm: boolean;
};

/**
 * 模型检测（M15-S1）：把站点 key 发给 bazaarlink.ai 检测模型真伪。
 *
 * **apiKey 发给第三方 bazaarlink.ai**——`confirm` 必须为 true。UI 必须明示这一点。
 */
export async function probeRun(args: ProbeArgs): Promise<ProbeRun> {
  if (!hasTauri) {
    return mock({
      runId: "mock-run-1",
      status: "completed",
      identityStatus: "match",
      verdictStatus: "clean_match",
      trueFamily: "openai",
      trueModel: "gpt-4o",
      spoofMethod: null,
      confidence: "high",
      warningsCount: 0,
      reportUrl: "/api/probe/report/mock-1",
      createdAt: 1700000000,
      completedAt: 1700000060,
    });
  }
  return invokeCommand<ProbeRun>("probe_run", { args });
}

export type ProbeRunRow = {
  id: number;
  runId: string;
  siteId: number;
  keyId: number;
  modelId: string;
  claimedModel?: string | null;
  identityStatus?: string | null;
  verdictStatus?: string | null;
  trueFamily?: string | null;
  trueModel?: string | null;
  spoofMethod?: string | null;
  confidence?: string | null;
  warningsCount: number;
  reportUrl?: string | null;
  bazaarlinkCreatedAt?: number | null;
  bazaarlinkCompletedAt?: number | null;
  recordedAt: number;
};

export async function listProbeRuns(limit?: number): Promise<ProbeRunRow[]> {
  if (!hasTauri) return mock([]);
  return invokeCommand<ProbeRunRow[]>("list_probe_runs", { limit: limit ?? null });
}

export async function getProbeRun(id: number): Promise<ProbeRunRow | null> {
  if (!hasTauri) return mock(null);
  return invokeCommand<ProbeRunRow | null>("get_probe_run", { id });
}
