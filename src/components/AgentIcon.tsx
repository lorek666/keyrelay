import { useState } from "react";

/**
 * Agent 图标（M31-S1）。
 *
 * 图标资产在 `public/agent-icons/<icon>.svg`（18 个）。**图标缺失或加载失败一律兜底**成
 * 名称首字母色块——一个 404 的 `<img>` 会在行首留一块空白，比没有图标更难看，
 * 而「少一个图标」绝不该让整行信息读不出来。
 *
 * `icon` 是通道的稳定 agent id，不是显示名：所以 `codex-config` / `opencode-jsonc`
 * 这类「同一 agent 的第二落点」共用主图标（见 `ICON_ALIAS`）。
 */
const ICON_ALIAS: Record<string, string> = {
  "codex-config": "codex",
  "opencode-jsonc": "opencode",
};

/** 兜底色块：从字符串稳定地挑一个色相，同一 agent 每次刷新颜色一致。 */
function hueOf(text: string): number {
  let h = 0;
  for (let i = 0; i < text.length; i += 1) h = (h * 31 + text.charCodeAt(i)) % 360;
  return h;
}

export type AgentIconProps = {
  /** 稳定 agent id（`CHANNELS[].agent`） */
  icon: string;
  /** 显示名，用于兜底时的首字母与色相 */
  name: string;
  size?: number;
};

export default function AgentIcon({ icon, name, size = 22 }: AgentIconProps) {
  const [failed, setFailed] = useState(false);
  const file = ICON_ALIAS[icon] ?? icon;
  const initial = (name.trim()[0] ?? "?").toUpperCase();

  if (failed) {
    return (
      <span
        className="agent-icon agent-icon-fallback"
        aria-hidden
        data-agent-icon={file}
        style={{
          width: size,
          height: size,
          lineHeight: `${size}px`,
          fontSize: Math.round(size * 0.5),
          background: `hsl(${hueOf(icon)} 55% 88%)`,
          color: `hsl(${hueOf(icon)} 45% 30%)`,
        }}
      >
        {initial}
      </span>
    );
  }

  return (
    <img
      className="agent-icon"
      src={`/agent-icons/${file}.svg`}
      alt=""
      aria-hidden
      width={size}
      height={size}
      data-agent-icon={file}
      loading="lazy"
      onError={() => setFailed(true)}
    />
  );
}
