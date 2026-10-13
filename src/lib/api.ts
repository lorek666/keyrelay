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
  // ---- M6-S5：FR-9 界面与隐私 ----
  /** "system" | "light" | "dark" */
  theme: string;
  /** "zh-CN" | "en-US" */
  language: string;
  /** 空 = 直连。合法性由传输层判定，这里只存。 */
  proxyUrl: string;
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
const MOCK_CAPS_NEWAPI: SiteCapabilities = {
  login: true,
  listKeys: true,
  createKey: true,
  revealKey: true,
  revokeKey: true,
  balance: true,
  groups: true,
  keyUsage: false,
};

/**
 * mock 里放**两个**站点是有意的：第二个 `custom-openai-compatible` 站点全能力为 `false`，
 * 于是浏览器预览（`pnpm dev`）里能直接看到「灰显 + 不可观测」长什么样——
 * 本机没有 GUI 会话，预览是唯一能肉眼核 W2/W5 的路径。
 */
const MOCK_SITES: SiteRow[] = [
  {
    id: 1,
    kind: "newapi",
    baseUrl: "https://relay.example.com",
    displayName: "示例中转站（mock）",
    health: "unknown",
    capabilities: MOCK_CAPS_NEWAPI,
  },
  {
    id: 2,
    kind: "custom-openai-compatible",
    baseUrl: "https://compatible.example.com",
    displayName: "只读兼容端点（mock·无令牌管理）",
    health: "unknown",
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
  dbPath: "（浏览器预览模式，无本地数据库）",
  siteCount: MOCK_SITES.length,
  dbError: null,
  vaultBackend: "memory",
};

const MOCK_KEYS: KeyRow[] = [
  {
    remoteId: "12",
    name: "codex/daily",
    group: "default",
    status: "enabled",
    createdAt: 1_760_000_000,
    lastUsedAt: null,
  },
];

const MOCK_PLAN: DeliveryPlan = {
  agentId: "codex",
  channel: "codex-auth-json",
  targetPath: "/Users/you/.codex/auth.json",
  targetExists: true,
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
    message: "投递完成: codex-auth-json",
    payload: '{"journal_id":"j1-0","target_path":"/Users/you/.codex/auth.json"}',
  },
  {
    id: 2,
    ts: 1_760_000_200,
    level: "info",
    source: "delivery",
    message: "已授予投递同意",
    payload: '{"agent_id":"codex","channel":"codex-auth-json"}',
  },
  {
    id: 1,
    ts: 1_760_000_100,
    level: "info",
    source: "site",
    message: "站点已识别: newapi 示例中转站（mock）",
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
    return mock({ kind: "newapi", displayName: "示例中转站（mock）", version: "v0.0.0-mock" });
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
        name: "codex/daily",
        group: "default",
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

export async function rollbackDelivery(journalId: string): Promise<void> {
  if (!hasTauri) return mock(undefined);
  return invokeCommand<void>("rollback_delivery", { journalId });
}

export async function recentEvents(limit = 100): Promise<EventRow[]> {
  if (!hasTauri) return mock(MOCK_EVENTS);
  return invokeCommand<EventRow[]>("recent_events", { limit });
}

export async function gatewayStatus(): Promise<GatewayStatus> {
  if (!hasTauri) {
    return mock({ running: false, url: null, token: null, site: null });
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
      site: "示例中转站（mock）",
    });
  }
  return invokeCommand<GatewayStatus>("gateway_start", {
    args: { siteId, keyId },
  });
}

export async function gatewayStop(): Promise<GatewayStatus> {
  if (!hasTauri) {
    return mock({ running: false, url: null, token: null, site: null });
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

export async function auditRedaction(): Promise<AuditReport> {
  if (!hasTauri) {
    return mock({
      filesScanned: 3,
      bytesScanned: 123456,
      clean: true,
      findings: [],
      summary: "已扫描 3 个文件 / 123456 字节，未发现明文凭证",
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
  if (!hasTauri) {
    return mock({
      refreshIntervalSecs: 0,
      balanceAlertThreshold: 0,
      driftCheckOnStart: true,
      gatewayEnabled: false,
      gatewayPort: 8787,
      theme: "system",
      language: "zh-CN",
      proxyUrl: "",
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
    });
  }
  return invokeCommand<Settings>("get_settings");
}

export async function updateSettings(settings: Settings): Promise<Settings> {
  if (!hasTauri) return mock(settings);
  return invokeCommand<Settings>("update_settings", { args: { settings } });
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
      { name: "vip", rate: 0.5, description: "折扣分组" },
    ]);
  }
  return invokeCommand<Group[]>("available_groups", { siteId });
}

export type KeySyncSummary = {
  siteId: number;
  siteTotal: number;
  alreadyLocal: number;
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
      keyName: "codex/daily",
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
): Promise<void> {
  if (!hasTauri) return mock(undefined);
  return invokeCommand<void>("revoke_key", { siteId, remoteId, confirm });
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
        note: "本版本不向 Cline 写入：它的配置落点尚未核实，写错文件会让你以为投递成功。",
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
    const pad = (n: number) => String(n).padStart(2, "0");
    return `keyrelay/${agentId}/${date.year}${pad(date.month)}${pad(date.day)}`;
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
  if (rate === null || !Number.isFinite(rate) || rate <= 0) return "倍率未知";
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
      plan: enabled ? "新建 ~/Library/LaunchAgents/keyrelay-autostart.plist" : "删除自启项",
      manualAction: null,
    });
  }
  return invokeCommand<Autostart>("autostart_set", { enabled });
}
