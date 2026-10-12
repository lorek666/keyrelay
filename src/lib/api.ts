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
  health: string;
};

export type AppInfo = {
  name: string;
  version: string;
  dbPath: string;
  siteCount: number;
  /** 数据库降级原因；非空表示当前跑在内存库上 */
  dbError?: string | null;
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

/** 本文件覆盖的命令名集合（供 `scripts/check-commands.mjs` 与后端比对）。 */
export const INVOKED_COMMANDS: string[] = [
  "app_info",
  "list_sites",
  "detect_site",
  "add_site",
  "login_site",
  "list_keys",
  "create_key",
  "site_balance",
  "delivery_plan",
  "grant_consent",
  "revoke_consent",
  "list_consents",
  "apply_delivery",
  "rollback_delivery",
  "recent_events",
  "list_stored_keys",
];
