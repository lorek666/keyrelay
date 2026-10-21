/**
 * 每行 Agent 偏好的本地持久化（M31-S1 §4.3）。
 *
 * 只存**本地 `keys.id` 与模型名**，不存任何密钥明文——这两样都不是秘密：
 * key id 是本地行号，模型名是用户自己敲的字符串。
 *
 * 读取时**忽略一切非法输入**（非法 JSON、非对象、非法 keyId）：偏好不是关键路径，
 * 坏数据只该让那一行回到默认，不该让整个页面起不来。写入失败同样静默。
 */

export type AgentPref = { keyId: number | null; model: string };

const PREFIX = "keyrelay.agentPrefs.v1.";
const keyFor = (siteId: number): string => `${PREFIX}${siteId}`;

const EMPTY: AgentPref = { keyId: null, model: "" };

/** 单条偏好的净化：任何字段不合法就回落默认，不抛。 */
function sanitize(raw: unknown): AgentPref {
  if (typeof raw !== "object" || raw === null) return { ...EMPTY };
  const obj = raw as Record<string, unknown>;
  const keyId =
    typeof obj.keyId === "number" && Number.isInteger(obj.keyId) && obj.keyId > 0
      ? obj.keyId
      : null;
  const model = typeof obj.model === "string" ? obj.model : "";
  return { keyId, model };
}

/** 读某站点的全部每行偏好。任何异常都回空对象。 */
export function loadAgentPrefs(siteId: number): Record<string, AgentPref> {
  try {
    const raw = globalThis.localStorage?.getItem(keyFor(siteId));
    if (!raw) return {};
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return {};
    const out: Record<string, AgentPref> = {};
    for (const [channel, value] of Object.entries(parsed as Record<string, unknown>)) {
      out[channel] = sanitize(value);
    }
    return out;
  } catch {
    return {};
  }
}

/** 写某站点的全部每行偏好。失败静默（隐私模式 / 配额满都不该影响投递）。 */
export function saveAgentPrefs(siteId: number, prefs: Record<string, AgentPref>): void {
  try {
    globalThis.localStorage?.setItem(keyFor(siteId), JSON.stringify(prefs));
  } catch {
    /* 偏好不是关键路径 */
  }
}
