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
  status: string;
};

export type Balance = {
  currency: string;
  remaining: number;
  used: number;
  rawQuota?: number | null;
  quotaPerUnit?: number | null;
};

export type DeliveryField = {
  key: string;
  /** 已掩码的值（密钥只暴露末 4 位） */
  masked: string;
};

export type ConsentState = "missing" | "granted" | "revoked";

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

const MOCK_SITES: SiteRow[] = [
  {
    id: 1,
    kind: "newapi",
    baseUrl: "https://relay.example.com",
    displayName: "示例中转站（mock）",
    health: "unknown",
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
    return mock({
      currency: "USD",
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
