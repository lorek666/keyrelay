#!/usr/bin/env node
/**
 * 前端 ↔ 后端命令一致性守护（M1-S4 spec §7 / §8.2）。
 *
 * 三件事：
 * 1. `src-tauri/src/commands_list.rs` 的 `COMMANDS` 与 `src/lib/api.ts` 的
 *    `INVOKED_COMMANDS` 必须是**同一个集合**（少一个 = 有命令没人调，多一个 = 调了不存在的命令）；
 * 2. `src-tauri/capabilities/default.json` 必须为每条命令声明 `allow-<kebab-case>`；
 * 3. **只有** `src/lib/api.ts` 允许 `import("@tauri-apps/api")`，页面组件必须走 api 层。
 *
 * 退出码非 0 即失败，供 `pnpm test` 使用。
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));

function fail(message) {
  console.error(`✗ ${message}`);
  process.exitCode = 1;
}

function ok(message) {
  console.log(`✓ ${message}`);
}

/** 去掉行注释，避免把被注释掉的命令也算进来（否则「删一条命令」抓不到） */
function stripLineComments(text) {
  return text.replace(/\/\/[^\n]*/g, "");
}

/** 从 `pub const COMMANDS: &[&str] = &[ "a", "b" ];` 里取出字符串字面量 */
function parseRustCommands() {
  const source = readFileSync(
    join(root, "src-tauri/src/commands_list.rs"),
    "utf8",
  );
  const block = source.match(/pub const COMMANDS[^=]*=\s*&\[([\s\S]*?)\];/);
  if (!block) throw new Error("在 commands_list.rs 里找不到 COMMANDS 数组");
  return [...stripLineComments(block[1]).matchAll(/"([^"]+)"/g)].map(
    (m) => m[1],
  );
}

/** 从 `export const INVOKED_COMMANDS: string[] = [ "a", "b" ];` 里取出字符串字面量 */
function parseTsCommands() {
  const source = readFileSync(join(root, "src/lib/api.ts"), "utf8");
  const block = source.match(
    /export const INVOKED_COMMANDS[^=]*=\s*\[([\s\S]*?)\];/,
  );
  if (!block) throw new Error("在 api.ts 里找不到 INVOKED_COMMANDS 数组");
  return [...stripLineComments(block[1]).matchAll(/"([^"]+)"/g)].map(
    (m) => m[1],
  );
}

function parseCapabilities() {
  const raw = readFileSync(
    join(root, "src-tauri/capabilities/default.json"),
    "utf8",
  );
  return JSON.parse(raw).permissions ?? [];
}

/** `list_sites` → `allow-list-sites`（Tauri 的权限名映射规则） */
function permissionFor(command) {
  return `allow-${command.replace(/_/g, "-")}`;
}

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (/\.(ts|tsx)$/.test(entry)) out.push(full);
  }
  return out;
}

// ---------------------------------------------------------------- 1. 集合一致性

const rust = parseRustCommands();
const ts = parseTsCommands();

const onlyRust = rust.filter((c) => !ts.includes(c));
const onlyTs = ts.filter((c) => !rust.includes(c));

if (onlyRust.length) {
  fail(`后端有、前端未覆盖的命令：${onlyRust.join(", ")}`);
} else if (onlyTs.length) {
  fail(`前端调用了不存在的命令：${onlyTs.join(", ")}`);
} else {
  ok(`命令集合一致（${rust.length} 条）`);
}

// ---------------------------------------------------------------- 2. capabilities

const permissions = parseCapabilities();
const missing = rust
  .map(permissionFor)
  .filter((p) => !permissions.includes(p));

if (missing.length) {
  fail(`capabilities 缺少权限声明：${missing.join(", ")}`);
} else {
  ok(`capabilities 覆盖全部 ${rust.length} 条命令`);
}

// ---------------------------------------------------------------- 3. 唯一入口

const srcFiles = walk(join(root, "src"));
const offenders = srcFiles
  .filter((file) => relative(root, file) !== "src/lib/api.ts")
  .filter((file) => readFileSync(file, "utf8").includes("@tauri-apps/api"));

if (offenders.length) {
  fail(
    `只有 src/lib/api.ts 可以直接引用 @tauri-apps/api，违规文件：\n  ${offenders
      .map((f) => relative(root, f))
      .join("\n  ")}`,
  );
} else {
  ok("只有 src/lib/api.ts 直接引用 @tauri-apps/api");
}

if (process.exitCode) {
  console.error("\n命令一致性检查未通过。");
} else {
  console.log("\n命令一致性检查通过。");
}
