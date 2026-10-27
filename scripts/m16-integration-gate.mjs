#!/usr/bin/env node
/**
 * M16 集成门禁（M16-S9 / B-136 的环境收口）。
 *
 * 把「各道分支 → 干净集成 → 五门禁取数」做成**一条可复跑的命令**：
 *
 *   node scripts/m16-integration-gate.mjs                       # 自动列出所有 m16/* 分支
 *   node scripts/m16-integration-gate.mjs --branches m16/a,m16/b
 *   node scripts/m16-integration-gate.mjs --branches ''          # 空列表：只对 --base 跑门禁
 *   node scripts/m16-integration-gate.mjs --base main --keep     # 保留临时 worktree 与 target
 *
 * 为什么要有它（B-136）：**本副本陈旧的 `target/` 会让网络类用例误红**，于是门禁数字不可信。
 * 这个脚本每次都在**全新的临时 worktree** + **全新的 `CARGO_TARGET_DIR`** 上取数，
 * 既避开了陈旧产物，也让「这次的门禁数字」与「上次」互不污染。
 *
 * **它不做入库**：所有 merge 都发生在临时 worktree 的 **detached HEAD** 上，
 * 不移动任何分支、不碰 `main`。合并入库由 Lead 决定（见 内部文档库 docs/specs/M16-S9-integration-and-gate-environment.md）。
 *
 * 退出码：0 = 全部 merge 成功且五门禁全绿；1 = 用法/环境错误；2 = merge 冲突；
 *         3 = 有门禁红了（打印汇总表后退出）；4 = **共享 node_modules 被污染**。
 *
 * 依赖：node（无第三方依赖）。**前端门禁不调用 `pnpm` 本体**——临时 worktree 的
 * `node_modules` 是软链，pnpm 的依赖检查会把临时目录当成项目根、**改写主工作区
 * `node_modules` 的顶层链接**，而那些链接随后指向被清理的临时目录 ⇒ 全队前端工具链全断
 * （M16-S9 真实事故，见 内部文档库 docs/evidence/m16s9-integration-gate.md §7）。所以这里直接调
 * `node_modules/.bin/*`，并在跑前/跑后各做一次「共享 node_modules 是否被改动」的自检。
 */

import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";

const USAGE = `用法: node scripts/m16-integration-gate.mjs [--branches a,b,c] [--base main] [--keep] [--node-modules <路径>]`;

// ---------------------------------------------------------------- 参数

const argv = process.argv.slice(2);
let branchesFlag = null;
let base = "main";
let keep = false;
let nodeModulesFlag = null;

for (let i = 0; i < argv.length; i += 1) {
  const arg = argv[i];
  if (arg === "--branches") {
    branchesFlag = argv[i + 1] ?? "";
    i += 1;
  } else if (arg === "--base") {
    base = argv[i + 1] ?? "";
    i += 1;
    if (!base) fail(`--base 后面没有分支名\n${USAGE}`);
  } else if (arg === "--keep") {
    keep = true;
  } else if (arg === "--node-modules") {
    nodeModulesFlag = argv[i + 1] ?? "";
    i += 1;
  } else if (arg === "--help" || arg === "-h") {
    console.log(USAGE);
    process.exit(0);
  } else {
    fail(`无法识别的参数：${arg}\n${USAGE}`);
  }
}

function fail(message, code = 1) {
  console.error(`✗ ${message}`);
  process.exit(code);
}

/** 跑一条命令，拿**真退出码**（不经任何管道）。返回 { code, out }。 */
function run(cmd, args, options = {}) {
  const result = spawnSync(cmd, args, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) {
    return { code: 127, out: `（无法执行 ${cmd}: ${result.error.message}）` };
  }
  const out = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  // 被信号杀掉时 status 是 null：如实报成 128+signal，不冒充 0
  const code = result.status === null ? 128 + (result.signal ? 1 : 0) : result.status;
  return { code, out };
}

function git(args, cwd) {
  return run("git", args, { cwd });
}

function nowStamp() {
  const d = new Date();
  const pad = (n, w = 2) => String(n).padStart(w, "0");
  return (
    `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}` +
    `-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`
  );
}

function ms(n) {
  return n >= 1000 ? `${(n / 1000).toFixed(1)}s` : `${n}ms`;
}

function tail(text, lines = 12) {
  const all = text.trimEnd().split("\n");
  return all.slice(Math.max(0, all.length - lines)).join("\n");
}

// ---------------------------------------------------------------- 环境

/**
 * 共享 `node_modules` 的污染检测：主工作区里那几个顶层包**必须仍解析回主工作区自己**。
 *
 * 为什么需要它：临时 worktree 的 `node_modules` 是**软链**到主工作区那份的。如果在这里调用
 * `pnpm` 本体，pnpm 的依赖检查会把临时目录当成项目根，**改写主工作区 `node_modules` 的顶层链接**
 * 指向临时目录；临时目录随后被清理 ⇒ 全队前端工具链（tsc/vite/vitest）全断。
 * 这条自检就是那次事故的常驻守卫（M16-S9 真实事故，见证据文档 §7）。
 *
 * 判据用 `realpathSync`（等价 `readlink -f`）：它会把整条符号链接链解到底，
 * 所以「链接指向临时目录」这种污染一定会被抓到。
 */
function sharedNodeModulesState(mainWorktreePath) {
  if (!mainWorktreePath) {
    return { checked: false, ok: true, detail: "（拿不到主工作区路径，跳过自检）" };
  }
  const probes = ["typescript", "vite", "vitest"];
  const lines = [];
  let ok = true;
  for (const name of probes) {
    const probePath = join(mainWorktreePath, "node_modules", name);
    let resolved;
    try {
      resolved = realpathSync(probePath);
    } catch (err) {
      ok = false;
      lines.push(`${name}: ✗ 无法解析（${err.message}）`);
      continue;
    }
    const inside = resolved.startsWith(mainWorktreePath);
    if (!inside) ok = false;
    lines.push(`${name} → ${resolved}${inside ? "" : "   ✗ 不在主工作区内"}`);
  }
  return { checked: true, ok, detail: lines.join("\n      ") };
}

const repoRoot = (() => {
  const r = git(["rev-parse", "--show-toplevel"], process.cwd());
  if (r.code !== 0) fail(`当前目录不是 git 仓库：${r.out.trim()}`);
  return r.out.trim();
})();

/** 主工作区路径（`git worktree list --porcelain` 的第一条）——pnpm 的 node_modules 在那儿。 */
const mainWorktree = (() => {
  const r = git(["worktree", "list", "--porcelain"], repoRoot);
  if (r.code !== 0) return null;
  const first = r.out.split("\n").find((line) => line.startsWith("worktree "));
  return first ? first.slice("worktree ".length).trim() : null;
})();

const stamp = nowStamp();
const tempRoot = process.env.TIANSHU_INTEGRATION_TMPDIR || tmpdir();
const worktreePath = join(tempRoot, `kr-m16-int-${stamp}`);
const targetDir = join(tempRoot, `kr-t-int-${stamp}`);
const logsDir = join(worktreePath, ".m16-gate-logs");

// 分支列表：显式给就用给的（允许空串 = 只跑 base），否则自动列 m16/*
const branches = (() => {
  if (branchesFlag !== null) {
    return branchesFlag
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }
  const r = git(["branch", "--list", "m16/*", "--format=%(refname:short)"], repoRoot);
  if (r.code !== 0) fail(`列出分支失败：${r.out.trim()}`);
  return r.out
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)
    .sort();
})();

const baseSha = (() => {
  const r = git(["rev-parse", "--short", base], repoRoot);
  if (r.code !== 0) fail(`找不到基线 ${base}：${r.out.trim()}`);
  return r.out.trim();
})();

console.log("=== M16 集成门禁（M16-S9） ===");
console.log(`仓库:            ${repoRoot}`);
console.log(`主工作区:        ${mainWorktree ?? "（未知）"}`);
console.log(`基线:            ${base} @ ${baseSha}`);
console.log(`待合并分支:      ${branches.length ? branches.join(", ") : "（空列表，只跑门禁）"}`);
console.log(`临时 worktree:   ${worktreePath}`);
console.log(`CARGO_TARGET_DIR:${targetDir}`);
console.log("");

const startedAt = Date.now();
let createdWorktree = false;

/** 清理：只删**本脚本自己创建**的路径（前缀校验）。 */
function cleanup() {
  if (keep) {
    console.log(`\n（--keep）保留临时 worktree: ${worktreePath}`);
    console.log(`（--keep）保留 target:       ${targetDir}`);
    return;
  }
  if (createdWorktree) {
    const r = git(["worktree", "remove", "--force", worktreePath], repoRoot);
    console.log(
      r.code === 0
        ? `\n已清理临时 worktree: ${worktreePath}`
        : `\n清理 worktree 失败（可手动 git worktree remove --force ${worktreePath}）：${r.out.trim()}`,
    );
  }
  if (targetDir.startsWith(join(tempRoot, "kr-t-int-"))) {
    rmSync(targetDir, { recursive: true, force: true });
    console.log(`已清理 target: ${targetDir}`);
  }
}

try {
  // ------------------------------------------------------------ ① 建临时 worktree
  console.log(`[1/4] 建临时 worktree（detached，从 ${base} 起）…`);
  const add = git(["worktree", "add", "--detach", worktreePath, base], repoRoot);
  if (add.code !== 0) fail(`建 worktree 失败：${add.out.trim()}`, 1);
  createdWorktree = true;
  mkdirSync(logsDir, { recursive: true });
  console.log(`      ok（HEAD = ${git(["rev-parse", "--short", "HEAD"], worktreePath).out.trim()}）\n`);

  // ------------------------------------------------------------ ② 依次 merge
  console.log(`[2/4] 依次合并 ${branches.length} 个分支（冲突即停）…`);
  for (const branch of branches) {
    const t0 = Date.now();
    const merge = git(["merge", "--no-edit", branch], worktreePath);
    if (merge.code !== 0) {
      console.error(`      ✗ ${branch} 合并失败（${ms(Date.now() - t0)}）`);
      const conflicts = git(["diff", "--name-only", "--diff-filter=U"], worktreePath);
      const status = git(["status", "--short"], worktreePath);
      console.error("\n--- 冲突文件（原样输出） ---");
      console.error(conflicts.out.trim() || "（git 没报未合并路径，下面是原始 git 输出）");
      console.error("\n--- git status --short ---");
      console.error(status.out.trim());
      console.error("\n--- git merge 原始输出 ---");
      console.error(merge.out.trim());
      console.error(
        `\n停下。用 --keep 重跑可保留现场（${worktreePath}）；` +
          `或在临时 worktree 里手工解决后继续。`,
      );
      process.exit(2);
    }
    const head = git(["rev-parse", "--short", "HEAD"], worktreePath).out.trim();
    console.log(`      ✓ ${branch} → HEAD ${head}（${ms(Date.now() - t0)}）`);
  }
  console.log("");

  // ------------------------------------------------------------ ③ 五门禁
  console.log("[3/4] 五门禁（真退出码，每个都不带管道）…");
  const env = {
    ...process.env,
    CARGO_TARGET_DIR: targetDir,
    CARGO_BUILD_JOBS: process.env.CARGO_BUILD_JOBS ?? "4",
    CI: "true",
  };

  // pnpm 需要 node_modules：临时 worktree 里没有 ⇒ 软链主工作区的那份。
  // **软链本身没问题**（依赖由 pnpm-lock.yaml 决定）；出问题的是**调用 pnpm 本体**：
  // 它的依赖检查会把临时目录当项目根、改写主工作区 node_modules 的顶层链接（见文件头）。
  const nm = nodeModulesFlag || (mainWorktree ? join(mainWorktree, "node_modules") : null);
  if (nm && existsSync(nm)) {
    const linkPath = join(worktreePath, "node_modules");
    try {
      symlinkSync(nm, linkPath, "dir");
      console.log(`      node_modules 软链: ${linkPath} -> ${nm}`);
    } catch (err) {
      console.log(`      ⚠ node_modules 软链失败（前端门禁可能因此失败）: ${err.message}`);
    }
  } else {
    console.log("      ⚠ 找不到 node_modules（用 --node-modules <路径> 指定）；前端门禁可能失败");
  }

  // **共享 node_modules 自检（跑前）**：主工作区的顶层链接必须仍指向主工作区自己。
  const nmBefore = sharedNodeModulesState(mainWorktree);
  console.log(
    `      共享 node_modules 自检（跑前）: ${nmBefore.ok ? "✓ 正常" : "⚠ 已异常（不是本次造成的）"}`,
  );
  if (nmBefore.checked) console.log(`      ${nmBefore.detail}`);
  console.log("");

  // 五门禁。**前端两道不调 pnpm 本体**，直接调 node_modules/.bin/*（等价于 package.json
  // 里那两条 `&&` 链，但不会触发 pnpm 的依赖检查）。每道门内部逐步执行，**第一步非 0 即停**，
  // 并把那一步的真退出码作为该门的退出码。
  const bin = (name) => join(worktreePath, "node_modules", ".bin", name);
  const gates = [
    {
      name: "cargo fmt --check",
      steps: [["cargo", ["fmt", "--all", "--", "--check"]]],
    },
    {
      name: "cargo clippy",
      steps: [["cargo", ["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"]]],
    },
    { name: "cargo test", steps: [["cargo", ["test", "--workspace"]]] },
    {
      name: "前端检查（原 pnpm test）",
      steps: [
        ["node", ["scripts/check-commands.mjs"]],
        ["node", ["scripts/check-i18n.mjs"]],
        [bin("vitest"), ["run"]],
      ],
    },
    {
      name: "前端构建（原 pnpm build）",
      steps: [
        [bin("tsc"), ["--noEmit", "--project", "tsconfig.build.json"]],
        [bin("vite"), ["build"]],
      ],
    },
  ];

  const results = [];
  for (const gate of gates) {
    const t0 = Date.now();
    let code = 0;
    let failedStep = null;
    let out = "";
    for (const [cmd, args] of gate.steps) {
      const r = run(cmd, args, { cwd: worktreePath, env });
      out += `\n$ ${cmd} ${args.join(" ")}\n${r.out}`;
      if (r.code !== 0) {
        code = r.code;
        failedStep = `${cmd} ${args.join(" ")}`;
        break;
      }
    }
    const elapsed = Date.now() - t0;
    const logPath = join(logsDir, `${gate.name.replace(/[^a-z0-9]+/gi, "-")}.log`);
    writeFileSync(logPath, out, "utf8");

    // 关键行：优先给**汇总**（cargo test 的逐目标 `test result:` 要加起来才算数，
    // 只看最后一行会抓到一个 0 用例的空目标）；pnpm 的门禁直接取它自己的汇总行。
    const lines = out.split("\n");
    const cargoResults = lines.filter((line) => /^test result:/.test(line));
    let keyLines = "";
    if (cargoResults.length > 0) {
      const sum = (re) =>
        cargoResults.reduce((acc, line) => acc + Number(line.match(re)?.[1] ?? 0), 0);
      const passed = sum(/(\d+) passed/);
      const failed = sum(/(\d+) failed/);
      const ignored = sum(/(\d+) ignored/);
      keyLines =
        `${cargoResults.length} 个目标 / ${passed} passed / ${failed} failed` +
        (ignored ? ` / ${ignored} ignored` : "");
    } else {
      keyLines = lines
        .filter((line) => /Tests:|Test Files|✓ \d+ modules|built in/i.test(line))
        .slice(-3)
        .map((line) => line.trim())
        .join(" | ");
    }

    results.push({ ...gate, code, elapsed, logPath, keyLines, failedStep });
    console.log(
      `      ${code === 0 ? "✓" : "✗"} ${gate.name.padEnd(22)} exit=${code}  ${ms(elapsed)}` +
        (failedStep ? `  ← ${failedStep}` : ""),
    );
  }
  console.log("");

  // **共享 node_modules 自检（跑后）**：主工作区的顶层链接必须仍然指向主工作区自己。
  // 跑前正常、跑后异常 ⇒ 是本脚本的前端门禁干的（历史事故：调用 pnpm 本体）。
  const nmAfter = sharedNodeModulesState(mainWorktree);
  console.log(
    `      共享 node_modules 自检（跑后）: ${nmAfter.ok ? "✓ 未被改动" : "✗ 共享 node_modules 被污染"}`,
  );
  if (nmAfter.checked) console.log(`      ${nmAfter.detail}`);
  console.log("");
  if (nmBefore.ok && !nmAfter.ok) {
    console.error(
      "✗ 共享 node_modules 被污染（跑前正常、跑后异常）：前端门禁改写了主工作区的 node_modules 链接。",
    );
    console.error(
      "  修复：在主工作区跑 `CI=true pnpm install --frozen-lockfile --prefer-offline`；" +
        "并检查本脚本是否退回了调用 `pnpm` 本体（只允许 node_modules/.bin/*）。",
    );
    cleanup();
    process.exit(4);
  }

  // ------------------------------------------------------------ ④ 汇总表
  const total = Date.now() - startedAt;
  console.log("[4/4] 汇总");
  console.log("");
  const width = Math.max(...results.map((r) => r.name.length), 10);
  console.log(`| ${"门禁".padEnd(width)} | exit | 耗时 | 关键行 |`);
  console.log(`|${"-".repeat(width + 2)}|------|------|--------|`);
  for (const r of results) {
    console.log(
      `| ${r.name.padEnd(width)} | ${String(r.code).padStart(4)} | ${ms(r.elapsed).padStart(6)} | ${r.keyLines || "—"} |`,
    );
  }
  console.log("");
  console.log(`总耗时: ${ms(total)}`);
  console.log(`合并分支: ${branches.length ? branches.join(", ") : "（无）"}（基线 ${base}@${baseSha}）`);
  console.log(`日志目录: ${logsDir}`);
  console.log(`共享 node_modules: ${nmAfter.ok ? "✓ 未被改动" : "✗ 被污染"}`);
  console.log("");

  const failed = results.filter((r) => r.code !== 0);
  if (failed.length > 0) {
    console.error(`✗ ${failed.length} 道门禁未过：`);
    for (const r of failed) {
      console.error(`\n--- ${r.name}（exit=${r.code}）最后 12 行 ---`);
      console.error(tail(readFileSync(r.logPath, "utf8"), 12));
    }
    cleanup();
    process.exit(3);
  }

  console.log("✓ 五门禁全绿。");
  console.log(
    "  注意：**本次没有做任何入库**——所有 merge 都在临时 worktree 的 detached HEAD 上，" +
      "不移动任何分支、不碰 main。是否合并入库由 Lead 决定。",
  );
  cleanup();
  process.exit(0);
} catch (err) {
  console.error(`✗ 脚本异常：${err.stack ?? err}`);
  cleanup();
  process.exit(1);
}
