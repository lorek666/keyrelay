#!/usr/bin/env node
/**
 * 门禁取数的**唯一入口**（M24-S2 / B-73）。
 *
 * 为什么需要它：`check-clean-gate.mjs`（B-43）与 `check-mut-isolation.mjs`（B-38）以前只有
 * **手动**路径 —— 脚本能拒能拦，但没有任何日常动作会**自动**跑到它们。B-73 要的就是这条
 * 「自动执行路径」。本脚本把「先断言干净、再取数」固化成一条命令：
 *
 *   node scripts/gate.mjs                     # 干净树 → 五门禁 → 汇总表
 *   node scripts/gate.mjs --only fmt          # 只跑一门（干净树断言仍先跑）
 *   node scripts/gate.mjs --allow-dirty       # 逃生阀：诊断用，第一行会声明「不代表提交内容」
 *
 * **退出码是真的**：全程 `spawnSync(cmd, args, …)`，不经 shell、不用管道 ——
 * `cmd | tail` 会把 `$?` 变成 tail 的，这是仓库记过的坑（M5-S6 复审 P2-3）。
 *
 * 退出码：0 = 五门禁全绿；1 = 脏树被拒 / 用法错误；2 = 有门禁未过。
 *
 * 不做的事（明确边界）：
 * - **不早停**：某门红了也继续跑完其余门，让一次取数看全（汇总表 + 失败门清单）。
 * - **不写日志文件**：输出实时继承（`stdio: "inherit"`），失败门的原文就在终端上，
 *   不另存一份会过期的副本。
 * - **不跑 `m16-integration-gate.mjs`**：那是发布/合并工具（建临时 worktree + 依次 merge），
 *   不是每次提交该跑的东西（spec §6.2 的 X1）。
 */

import { spawnSync } from "node:child_process";

const USAGE = `用法: node scripts/gate.mjs [--allow-dirty] [--only <门名>] [--help]

门名：
  fmt          cargo fmt --all -- --check
  clippy       cargo clippy --workspace --all-targets -- -D warnings
  test         cargo test --workspace --no-fail-fast
  pnpm-test    CI=true pnpm test
  pnpm-build   CI=true pnpm build

退出码：0 = 全绿；1 = 脏树被拒 / 用法错误；2 = 有门禁未过`;

/** 五门禁。`env` 只放该门额外的环境（`CI=true` 全局注入，见 runGate）。 */
const GATES = [
  {
    name: "fmt",
    cmd: "cargo",
    args: ["fmt", "--all", "--", "--check"],
    label: "cargo fmt --all -- --check",
  },
  {
    name: "clippy",
    cmd: "cargo",
    args: ["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"],
    label: "cargo clippy --workspace --all-targets -- -D warnings",
  },
  {
    name: "test",
    cmd: "cargo",
    args: ["test", "--workspace", "--no-fail-fast"],
    label: "cargo test --workspace --no-fail-fast",
  },
  {
    name: "pnpm-test",
    cmd: "pnpm",
    args: ["test"],
    label: "CI=true pnpm test",
  },
  {
    name: "pnpm-build",
    cmd: "pnpm",
    args: ["build"],
    label: "CI=true pnpm build",
  },
];

const GATE_NAMES = GATES.map((gate) => gate.name);

// ------------------------------------------------------------------ 参数

const argv = process.argv.slice(2);
let allowDirty = false;
let only = null;

for (let i = 0; i < argv.length; i += 1) {
  const arg = argv[i];
  if (arg === "--help" || arg === "-h") {
    console.log(USAGE);
    process.exit(0);
  } else if (arg === "--allow-dirty") {
    allowDirty = true;
  } else if (arg === "--only") {
    only = argv[i + 1] ?? "";
    i += 1;
    if (!only) {
      console.error(`✗ --only 后面没有门名\n${USAGE}`);
      process.exit(1);
    }
  } else {
    console.error(`✗ 无法识别的参数：${arg}\n${USAGE}`);
    process.exit(1);
  }
}

if (only !== null && !GATE_NAMES.includes(only)) {
  console.error(`✗ 不认识的门名：${only}`);
  console.error(`  合法取值：${GATE_NAMES.join(" / ")}`);
  process.exit(1);
}

/** 真退出码：`status` 为 null 时（被信号杀掉）如实报成 128+，不冒充 0。 */
function exitCodeOf(result) {
  if (result.error) return 127;
  if (result.status === null) return 128 + (result.signal ? 1 : 0);
  return result.status;
}

function ms(n) {
  return n >= 1000 ? `${(n / 1000).toFixed(1)}s` : `${n}ms`;
}

// ------------------------------------------------------------------ ① 干净树断言

// 逃生阀的警告必须是**整条输出的第一行**（B-43 口径）：它要盖住后面所有取数结果。
// 两路都写：只存 stdout 的日志里也要能看到。`check-clean-gate.mjs` 内部还会再打一次
// （那是它自己的契约）；这里提前打一次，是为了让「第一行」在这条命令里也成立。
if (allowDirty) {
  const warning = "⚠️  --allow-dirty：本次门禁取数不代表提交内容（工作区有未提交改动）⚠️";
  console.log(warning);
  console.error(warning);
}

// 这一步是 B-43 的**拦截**语义：脏树上的取数不代表提交内容。
// 直接复用既有守护（不在这里重写一遍 git 解析），并把它的输出原样透传。
console.log("=== 门禁取数（M24-S2 / B-73）===");
console.log("① 干净树断言：node scripts/check-clean-gate.mjs" + (allowDirty ? " --allow-dirty" : ""));
const cleanArgs = ["scripts/check-clean-gate.mjs"];
if (allowDirty) cleanArgs.push("--allow-dirty");
const clean = spawnSync(process.execPath, cleanArgs, { stdio: "inherit", env: process.env });
const cleanCode = exitCodeOf(clean);
if (cleanCode !== 0) {
  console.error("");
  console.error(
    `✗ 干净树断言未过（exit=${cleanCode}）：**一个门禁都没有跑**。` +
      "门禁必须在干净树上取数（B-43）；确实只是诊断就加 --allow-dirty，但结论不得写进闭环记录。",
  );
  process.exit(1);
}

// ------------------------------------------------------------------ ② 依次跑门禁

const selected = only === null ? GATES : GATES.filter((gate) => gate.name === only);
console.log("");
console.log(`② 门禁：${selected.length} 道（${selected.map((gate) => gate.name).join(" → ")}）`);
console.log("");

const results = [];
for (const gate of selected) {
  const startedAt = Date.now();
  console.log(`$ ${gate.label}`);
  const result = spawnSync(gate.cmd, gate.args, {
    stdio: "inherit",
    // `CI=true` 对本步的所有门都注入（`pnpm test` / `pnpm build` 依赖它走非交互路径；
    // cargo 侧忽略这个变量，无害）。
    env: { ...process.env, CI: "true" },
  });
  const code = exitCodeOf(result);
  const elapsed = Date.now() - startedAt;
  results.push({ ...gate, code, elapsed });
  if (result.error) {
    console.error(`✗ ${gate.name} 无法执行：${result.error.message}（记 exit=127）`);
  }
  console.log(`  ${code === 0 ? "✓" : "✗"} ${gate.name.padEnd(11)} exit=${code}  ${ms(elapsed)}`);
  console.log("");
}

// ------------------------------------------------------------------ ③ 汇总

const failed = results.filter((result) => result.code !== 0);
const width = Math.max(...results.map((result) => result.name.length), 4);
console.log("=== 汇总 ===");
console.log(`| ${"门".padEnd(width)} | exit | 耗时 |`);
console.log(`|${"-".repeat(width + 2)}|------|------|`);
for (const result of results) {
  console.log(
    `| ${result.name.padEnd(width)} | ${String(result.code).padStart(4)} | ${ms(result.elapsed).padStart(6)} |`,
  );
}
console.log("");
if (allowDirty) {
  // 两路都写：只存 stdout 的日志里也要能看到（与 check-clean-gate 同口径）。
  const warning = "⚠️  --allow-dirty：本次门禁取数不代表提交内容 ⚠️";
  console.log(warning);
  console.error(warning);
}
if (failed.length > 0) {
  console.error(`✗ ${failed.length} 道门禁未过：${failed.map((result) => `${result.name}(exit=${result.code})`).join("、")}`);
  console.error("  失败门的完整输出就在上面（stdio 继承，未截断）。");
  process.exit(2);
}
console.log(`✓ ${results.length} 道门禁全绿。`);
