#!/usr/bin/env node
/**
 * 门禁取数前置守护（B-43 / 第三轮复核 P1-1）。
 *
 * 为什么需要它：`aacfaea` 是带着 5 处 `cargo fmt --check` diff 入库的——取数是在含
 * 未提交在制品的副本上跑的，结论**不代表提交内容**，闭环记录因此自报失真。
 * 这个脚本把「先断言干净、再取数」变成不可绕过的一步：
 * `git status --porcelain` 为空 ⇒ 工作区内容 == HEAD ⇒ 门禁结论可以归因到提交。
 *
 * 用法：
 *   node scripts/check-clean-gate.mjs
 *   node scripts/check-clean-gate.mjs --run -- cargo fmt --all -- --check
 *   node scripts/check-clean-gate.mjs --allow-dirty            # 逃生阀，仅用于诊断
 *
 * 退出码：0 = 干净（或 `--allow-dirty` 下继续）；1 = 脏树被拒 / 子命令非 0 / 用法错误
 *
 * 被检查的仓库 = **cwd** 所属仓库（不是脚本所在仓库），这样同一个脚本可以在
 * 独立 worktree 里复跑（本波次四包共用主工作副本，主副本必然是脏的）。
 */

import { spawnSync } from "node:child_process";
import { relative } from "node:path";

const USAGE =
  "用法: node scripts/check-clean-gate.mjs [--allow-dirty] [--run -- <命令> [参数...]]";

const argv = process.argv.slice(2);
const separator = argv.indexOf("--");
const flags = separator >= 0 ? argv.slice(0, separator) : argv;
const child = separator >= 0 ? argv.slice(separator + 1) : [];

const unknown = flags.filter((f) => f !== "--allow-dirty" && f !== "--run");
if (unknown.length) {
  console.error(`✗ 无法识别的参数：${unknown.join(" ")}`);
  console.error(USAGE);
  process.exit(1);
}
if (separator >= 0 && child.length === 0) {
  console.error("✗ `--` 后面没有命令");
  console.error(USAGE);
  process.exit(1);
}
const allowDirty = flags.includes("--allow-dirty");

/** 跑一条 git 命令，失败即抛（不静默） */
function git(args) {
  const result = spawnSync("git", args, { encoding: "utf8" });
  if (result.error) throw new Error(`无法执行 git：${result.error.message}`);
  if (result.status !== 0) {
    throw new Error(
      `git ${args.join(" ")} 失败（退出码 ${result.status}）：${(result.stderr ?? "").trim()}`,
    );
  }
  return result.stdout ?? "";
}

let root;
let head;
let porcelain;
try {
  root = git(["rev-parse", "--show-toplevel"]).trim();
  head = git(["log", "-1", "--format=%h %s"]).trim();
  porcelain = git(["status", "--porcelain"]);
} catch (error) {
  console.error(`✗ ${error.message}`);
  console.error("  这个守护必须在 git 仓库里跑；不在仓库里时它**不会**静默通过。");
  process.exit(1);
}

const dirtyLines = porcelain.split("\n").filter((line) => line.length > 0);
const untracked = dirtyLines.filter((line) => line.startsWith("??")).length;

// --allow-dirty 的警告必须是**第一行**：它要盖住后面所有取数结果。
//
// 而且**两路都写**（M5-S6 复审 P2-2）：只在 stderr 上时，只保存 stdout 的日志里
// 一个字都看不到这个警告，`rg "不代表提交内容"` 返回 0 命中 —— 一份被过滤过的日志
// 会看起来像一次干净通过。取数结论是给人看的，警告就必须在给人看的那一路里也在。
if (dirtyLines.length > 0 && allowDirty) {
  const warning =
    `⚠️  --allow-dirty：本次门禁取数不代表提交内容（工作区有 ${dirtyLines.length} 处未提交改动，` +
    `其中未跟踪 ${untracked} 处）⚠️`;
  console.error(warning);
  console.log(warning);
  const detail =
    "    这个开关只用于**诊断**：结论不能写进闭环记录，也不能当成提交前的门禁。";
  console.error(detail);
  console.log(detail);
}

console.log(`仓库根: ${root}`);
console.log(`HEAD:   ${head}`);

if (dirtyLines.length === 0) {
  console.log("✓ 工作区干净（git status --porcelain 为空）——本次取数可归因到 HEAD");
} else {
  console.error(`✗ 工作区不干净：${dirtyLines.length} 处未提交改动（未跟踪 ${untracked} 处）`);
  for (const line of dirtyLines) console.error(`    ${line}`);
  console.error("  取数来自这份工作区，结果**不能代表提交内容**（B-43）。");
  console.error(
    "  本波次多个包共用同一个工作副本，主副本必然是脏的：请在独立 worktree（或提交后）复跑门禁。",
  );
  if (!allowDirty) {
    console.error("  （确实只是诊断，可以加 --allow-dirty，但结论不得写进闭环记录。）");
    process.exit(1);
  }
}

if (child.length === 0) {
  process.exit(0);
}

const [cmd, ...args] = child;
console.log(`\n$ ${child.join(" ")}`);
const result = spawnSync(cmd, args, { stdio: "inherit", env: process.env });
if (result.error) {
  console.error(`✗ 子命令无法执行：${result.error.message}`);
  process.exit(1);
}
if (result.status !== 0) {
  console.error(
    `\n✗ 门禁未通过：\`${child.join(" ")}\` 退出码 ${result.status}（cwd: ${relative(root, process.cwd()) || "."}）`,
  );
  process.exit(result.status ?? 1);
}
console.log(`\n✓ 门禁通过：\`${child.join(" ")}\``);
