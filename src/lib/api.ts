/**
 * 与 Tauri 后端通信的唯一入口。
 *
 * 约定：
 * - 浏览器（无 Tauri）环境下退回 mock 数据，保证 `pnpm build` 与页面预览可用；
 * - 所有命令名与 `src-tauri/src/commands.rs` 一一对应；
 * - 不在此处拼接或缓存任何密钥。
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
};

const hasTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

const MOCK_SITES: SiteRow[] = [
  {
    id: 1,
    kind: "newapi",
    baseUrl: "https://newapi.example.com",
    displayName: "爱中转（示例数据）",
    health: "unknown",
  },
];

const MOCK_INFO: AppInfo = {
  name: "KeyRelay",
  version: "0.1.0-dev",
  dbPath: "（浏览器预览模式，无本地数据库）",
  siteCount: MOCK_SITES.length,
};

async function invokeCommand<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

export async function listSites(): Promise<SiteRow[]> {
  if (!hasTauri) return MOCK_SITES;
  return invokeCommand<SiteRow[]>("list_sites");
}

export async function appInfo(): Promise<AppInfo> {
  if (!hasTauri) return MOCK_INFO;
  return invokeCommand<AppInfo>("app_info");
}

export const runtimeMode = hasTauri ? "tauri" : "browser";
