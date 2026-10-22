# Agent 图标来源

这些 SVG 是各 Agent / 厂商的品牌图标，取自 [LobeHub Icons](https://lobehub.com/icons) 的静态图标包
（`@lobehub/icons-static-svg`，MIT License），仅用于在天枢 Relay 的 Agent 列表里标识对应产品。

- 图标只做识别用途，不改变任何投递行为。
- 新增 Agent 时把对应 `<id>.svg` 放在本目录，并让 `src/pages/Agents.tsx` 的 `CHANNELS[].agent` 与文件名一致；同一 agent 的第二个落点（`codex-config` / `opencode-jsonc`）由 `AgentIcon` 的 `ICON_ALIAS` 复用主图标。
- 图标缺失或加载失败时，`AgentIcon` 会退回名称首字母色块，不会留下破图。
