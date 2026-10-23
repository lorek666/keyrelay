#!/usr/bin/env node
/**
 * M40-S1：网关用量 flush 调用点 canary。
 *
 * 背景：`drain_gateway_usage()` 只在 `refresh_all` 里被调用时，「网关刚产生用量、
 * 用户随即停网关 / 轮换令牌 / 换站重启 / 退出应用」都会让那批账目永远进不了库——
 * 而它们正是用量看板的唯一数据源。M40-S1 要求在四个边界各 drain 一次。
 *
 * 这个脚本**只做结构断言**：四个边界里必须出现 `drain_gateway_usage()`。
 * 它拦不住「调用顺序写错」（那由 `gateway_stop` 的 IPC 测试与复审读码覆盖），
 * 但能拦住「有人顺手删掉一处调用」这种最常见的静默回归。
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// 仓库路径可能含中文/空格；`URL.pathname` 会保留百分号编码，必须解码后再拼路径。
const root = fileURLToPath(new URL("..", import.meta.url));
const commands = readFileSync(join(root, "src-tauri/src/commands.rs"), "utf8");
const lib = readFileSync(join(root, "src-tauri/src/lib.rs"), "utf8");

/** 从 `startMarker` 之后的第一个 `{` 起做括号配对，返回块内文本。 */
function blockAfter(source, startMarker, label) {
  const at = source.indexOf(startMarker);
  if (at < 0) {
    throw new Error(`找不到锚点「${label}」（${startMarker}）——脚本需要跟着代码更新`);
  }
  const open = source.indexOf("{", at + startMarker.length);
  if (open < 0) throw new Error(`锚点「${label}」后没有代码块`);
  let depth = 0;
  for (let i = open; i < source.length; i += 1) {
    if (source[i] === "{") depth += 1;
    else if (source[i] === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(open, i + 1);
    }
  }
  throw new Error(`锚点「${label}」的代码块没有闭合`);
}

const checks = [
  {
    label: "gateway_stop",
    body: blockAfter(commands, "pub async fn gateway_stop", "gateway_stop"),
    // M41-S1 把「停网关 + drain」收敛到 stop_gateway_locked；这里只要求命令走到该出口。
    token: "stop_gateway_locked",
  },
  {
    label: "gateway_rotate_token",
    body: blockAfter(
      commands,
      "pub async fn gateway_rotate_token",
      "gateway_rotate_token",
    ),
    token: "drain_gateway_usage()",
  },
  {
    // `gateway_start` 的「替换已运行实例」分支：M41-S1 后统一走 stop_gateway_locked(false)。
    label: "gateway_start(replace previous)",
    body: blockAfter(commands, "pub async fn gateway_start", "gateway_start"),
    token: "stop_gateway_locked(&state, false)",
  },
  {
    // 公共停止出口：真正落库的地方。四个边界都必须经过它。
    label: "stop_gateway_locked",
    body: blockAfter(commands, "async fn stop_gateway_locked", "stop_gateway_locked"),
    token: "drain_gateway_usage()",
  },
  {
    // 应用退出：`RunEvent::Exit` 处理块。
    label: "lib.rs RunEvent::Exit",
    body: blockAfter(lib, "if let tauri::RunEvent::Exit = event", "RunEvent::Exit"),
    token: "drain_gateway_usage()",
  },
];

const missing = checks.filter((c) => !c.body.includes(c.token));

if (missing.length > 0) {
  console.error("✗ 网关用量 flush 调用点缺失（M40-S1 / M41-S1）：");
  for (const c of missing) {
    console.error(`  - ${c.label}：缺少 ${c.token}`);
  }
  console.error(
    "  停止/轮换/换网关/退出都必须 drain；停止类统一走 stop_gateway_locked。",
  );
  process.exit(1);
}

console.log(
  `✓ 网关用量 flush 调用点齐全（${checks.length}/${checks.length}：${checks.map((c) => c.label).join(" / ")}）`,
);
