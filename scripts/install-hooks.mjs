#!/usr/bin/env node
/**
 * 启用仓库自带的 git hooks（M24-S2 / B-73）。
 *
 * 背景：`.githooks/pre-commit` 只有把 `core.hooksPath` 指过去才会生效，而**改用户 git 配置
 * 必须是显式动作** —— 本脚本就是那个显式动作（`pnpm hooks:install`）。它只写**本仓库**的
 * 配置（`--local`），不动全局；并且**回读校验**，不假装成功。
 *
 * 用法：node scripts/install-hooks.mjs   （或 pnpm hooks:install）
 * 退出码：0 = 已生效；1 = 设置失败 / 回读不一致 / 不在 git 仓库里。
 */

import { spawnSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { join } from "node:path";

const HOOKS_PATH = ".githooks";
const PRE_COMMIT = "pre-commit";

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
try {
  root = git(["rev-parse", "--show-toplevel"]).trim();
} catch (error) {
  console.error(`✗ ${error.message}`);
  console.error("  这个脚本必须在 git 仓库里跑；不在仓库里时它**不会**静默成功。");
  process.exit(1);
}

console.log(`仓库根: ${root}`);

// 1) 设本仓库的 core.hooksPath（--local：只写 .git/config，不动全局）
try {
  git(["config", "--local", "core.hooksPath", HOOKS_PATH]);
} catch (error) {
  console.error(`✗ 设置 core.hooksPath 失败：${error.message}`);
  process.exit(1);
}

// 2) 回读校验（不采信「设置命令没报错」）
let readBack;
try {
  readBack = git(["config", "--local", "--get", "core.hooksPath"]).trim();
} catch (error) {
  console.error(`✗ 回读 core.hooksPath 失败：${error.message}`);
  process.exit(1);
}
if (readBack !== HOOKS_PATH) {
  console.error(`✗ 回读不一致：期望 ${HOOKS_PATH}，实际 ${readBack || "（空）"}`);
  process.exit(1);
}
console.log(`✓ core.hooksPath = ${readBack}（本仓库，--local）`);

// 3) 顺带体检：hook 文件在不在、是不是可执行（git 对不可执行的 hook 会静默跳过 —— 那会变成假守护）
const hookPath = join(root, HOOKS_PATH, PRE_COMMIT);
if (!existsSync(hookPath)) {
  console.error(`✗ 找不到 ${HOOKS_PATH}/${PRE_COMMIT} —— hooksPath 指向了一个没有 hook 的目录`);
  process.exit(1);
}
const mode = statSync(hookPath).mode;
if ((mode & 0o111) === 0) {
  console.error(
    `✗ ${HOOKS_PATH}/${PRE_COMMIT} 不可执行（mode=${(mode & 0o777).toString(8)}）——` +
      "git 会静默跳过不可执行的 hook，那就成了假守护。",
  );
  console.error(`  修复：chmod +x ${HOOKS_PATH}/${PRE_COMMIT}`);
  process.exit(1);
}
console.log(`✓ ${HOOKS_PATH}/${PRE_COMMIT} 存在且可执行`);

// 4) 说清「现在起会发生什么」与「怎么绕过」
console.log("");
console.log("从现在起，每次 git commit 都会先跑：");
console.log("  - node scripts/check-no-real-credentials.mjs（索引语义，恒跑）");
console.log("  - node scripts/check-charter-steps.mjs（仅当暂存区含 docs/specs/ 或 docs/reviews/）");
console.log("绕过：git commit --no-verify（git 自带；CI 侧的 pnpm test 仍会跑同样的守护）。");
