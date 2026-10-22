#!/usr/bin/env node
/**
 * 变异验证的 target 目录隔离守护（B-38 / 第三轮复核 P2-5）。
 *
 * 机制：两个 worktree 共用同一个 target 目录时，cargo 会为两边生成**同名产物**并互相
 * 复用，于是「在旧代码上跑新测试」报「全部通过」——**结论完全相反**（实测假绿）。
 * 所以这个守护比的不是「环境变量设没设」（那是假守护），而是
 * 「这个 target 目录是不是**别的 git worktree** 的 `target/`」。
 *
 * 用法：
 *   node scripts/check-mut-isolation.mjs
 *   node scripts/check-mut-isolation.mjs --run -- cargo test -p tianshu-relay-core --test <目标>
 *   node scripts/check-mut-isolation.mjs --target-dir /tmp/mut-target --run -- cargo test …
 *
 * 退出码：0 = 隔离成立且无残留；1 = target 与别的 worktree 共享 / 有残留 / 子命令非 0 / 用法错误
 *
 * 两种模式都会扫 `crates/`、`src/`、`src-tauri/` 里的 `MUT-` / `M5 变异`；
 * `--run` 额外在子命令跑完**再**扫一次（探针最容易在这里留残留）。
 */

import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
} from "node:fs";
import { basename, join, relative, resolve, sep } from "node:path";

const USAGE =
  "用法: node scripts/check-mut-isolation.mjs [--self-test] [--target-dir <目录>] [--run -- <命令> [参数...]]";

const RESIDUE_DIRS = ["crates", "src", "src-tauri"];
const RESIDUE_PATTERNS = ["MUT-", "M5 变异"];
const SKIP_DIRS = new Set(["target", ".git", "node_modules", ".mut-target"]);
const MAX_FILE_BYTES = 2 * 1024 * 1024;

// ------------------------------------------------------------------ 参数

const argv = process.argv.slice(2);
const separator = argv.indexOf("--");
const flags = separator >= 0 ? argv.slice(0, separator) : argv;
const child = separator >= 0 ? argv.slice(separator + 1) : [];

let targetDirFlag = null;
let selfTest = false;
for (let i = 0; i < flags.length; i += 1) {
  const flag = flags[i];
  if (flag === "--run") continue;
  if (flag === "--self-test") {
    selfTest = true;
    continue;
  }
  if (flag === "--target-dir") {
    targetDirFlag = flags[i + 1] ?? null;
    i += 1;
    if (!targetDirFlag) {
      console.error("✗ --target-dir 后面没有目录");
      console.error(USAGE);
      process.exit(1);
    }
    continue;
  }
  console.error(`✗ 无法识别的参数：${flag}`);
  console.error(USAGE);
  process.exit(1);
}
if (separator >= 0 && child.length === 0) {
  console.error("✗ `--` 后面没有命令");
  console.error(USAGE);
  process.exit(1);
}
const runMode = separator >= 0;

// `--self-test`：只自证**判定逻辑**，不读真实仓库、不跑 cargo、不依赖网络。
// 必须在「现场」那一步之前返回 —— 它不需要在 git 仓库里跑（CI/新克隆都能自检）。
if (selfTest) {
  process.exit(runSelfTest());
}

// ------------------------------------------------------------------ 工具

/** 解析符号链接；路径不存在时退回到「最近存在祖先」的真实路径 + 剩余部分 */
function realpathSoft(path) {
  const tail = [];
  let current = resolve(path);
  for (;;) {
    try {
      const real = realpathSync(current);
      return tail.length ? join(real, ...tail.reverse()) : real;
    } catch {
      const parent = resolve(current, "..");
      if (parent === current) return resolve(path);
      tail.push(basename(current));
      current = parent;
    }
  }
}

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

function fail(message) {
  console.error(`✗ ${message}`);
}

function ok(message) {
  console.log(`✓ ${message}`);
}

/** `target/` 是否与某个 worktree 的 target 目录重合（相等或在其之下） */
function sharesTargetWith(worktreeReal, targetReal) {
  // **两侧都要解析符号链接**（M5-S6 复审 P1-1）。
  //
  // 有效 target 是 `realpathSoft()` 的结果，而 `worktreeReal/target` 只是**拼出来的字符串**：
  // 如果那个 worktree 的 `target/` 本身是一个**指向共享目录的符号链接**，
  // 拼字符串得到的路径与解析后的路径是同一个目录、写法却不同，
  // 于是脚本会打印「✓ 不重合」并 exit 0 —— 静默假通过，
  // 恰好是这个守护唯一要防的形态（PROCESS.md §3 的假绿）。
  const otherTarget = realpathSoft(join(worktreeReal, "target"));
  return targetReal === otherTarget || targetReal.startsWith(otherTarget + sep);
}

/**
 * `--self-test`（M24-S2 / B-73）：用**临时目录造 fixture** 自证判定逻辑没退化。
 *
 * 为什么需要它：这个守护以前只有「手动 `--run`」一条路径，没人知道它是不是还活着。
 * 接进 `pnpm test` 后，每次测试都会问一句「判定逻辑还认得出共享 target 吗」——
 * 一个恒 false 的判定（最容易写出来的退化）会当场红。
 *
 * 四条 fixture（全部在 `os.tmpdir()` 下，跑完删除）：
 *   S1 有效 target 在**别的 worktree 的 target/ 里面**（子目录）⇒ 必须判共享（不隔离）
 *   S2 有效 target 是独立目录 ⇒ 必须判不共享（隔离）
 *   S3 别的 worktree 的 `target/` 是**指向共享目录的符号链接** ⇒ 必须判共享（P1-1 的形态）
 *   S4 与 target/ **前缀相同但同级**的目录（`target-other`）⇒ 必须判不共享（`sep` 边界）
 *
 * 退出码：0 = 四条全符合期望；1 = 有任一条不符合（逐条打印期望/实际，不静默）。
 */
function runSelfTest() {
  let base;
  try {
    base = mkdtempSync(join(tmpdir(), "kr-mut-selftest-"));
  } catch (error) {
    fail(`--self-test 建临时目录失败：${error.message}`);
    return 1;
  }

  const fakeWtA = join(base, "fake-wt-a");
  const fakeWtB = join(base, "fake-wt-b");
  const sharedTarget = join(base, "shared-target");
  const isolated = join(base, "isolated");

  try {
    mkdirSync(join(fakeWtA, "target", "debug"), { recursive: true });
    mkdirSync(fakeWtB, { recursive: true });
    mkdirSync(sharedTarget, { recursive: true });
    mkdirSync(isolated, { recursive: true });
    // B 的 target/ 是指向共享目录的符号链接 —— 拼字符串与真实路径写法不同，是 P1-1 的形态。
    symlinkSync(sharedTarget, join(fakeWtB, "target"), "dir");

    const wtA = realpathSoft(fakeWtA);
    const wtB = realpathSoft(fakeWtB);

    const cases = [
      {
        id: "S1",
        desc: "有效 target 在别的 worktree 的 target/ 之下（子目录）⇒ 判共享（不隔离）",
        expect: true,
        actual: sharesTargetWith(wtA, realpathSoft(join(fakeWtA, "target", "debug"))),
      },
      {
        id: "S2",
        desc: "有效 target 是独立目录 ⇒ 判不共享（隔离）",
        expect: false,
        actual: sharesTargetWith(wtA, realpathSoft(isolated)),
      },
      {
        id: "S3",
        desc: "别的 worktree 的 target/ 是指向共享目录的符号链接 ⇒ 判共享（P1-1 形态）",
        expect: true,
        actual: sharesTargetWith(wtB, realpathSoft(sharedTarget)),
      },
      {
        id: "S4",
        desc: "与 target/ 前缀相同但同级的目录（target-other）⇒ 判不共享（sep 边界）",
        expect: false,
        actual: sharesTargetWith(wtA, realpathSoft(join(fakeWtA, "target-other"))),
      },
    ];

    let bad = 0;
    console.log("=== check-mut-isolation --self-test（fixture 自证，不跑 cargo）===");
    for (const testCase of cases) {
      const pass = testCase.actual === testCase.expect;
      if (!pass) bad += 1;
      console.log(
        `${pass ? "✓" : "✗"} ${testCase.id}  期望=${testCase.expect} 实际=${testCase.actual}  ${testCase.desc}`,
      );
    }
    console.log(`${bad === 0 ? "✓" : "✗"} ${cases.length - bad}/${cases.length} 条符合期望`);
    if (bad > 0) {
      fail("判定逻辑已退化：上面 ✗ 的那条就是退化点（改回后应恢复 ✓）。");
      return 1;
    }
    return 0;
  } catch (error) {
    fail(`--self-test 建 fixture 失败：${error.message}`);
    return 1;
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
}

/** 扫 `crates/ src/ src-tauri/` 的变异残留，返回 `文件:行: 内容` */
function scanResidue(root) {
  const hits = [];
  const walk = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(full);
        continue;
      }
      if (!entry.isFile()) continue;
      let size;
      try {
        size = statSync(full).size;
      } catch {
        continue;
      }
      if (size > MAX_FILE_BYTES) continue;
      let text;
      try {
        text = readFileSync(full, "utf8");
      } catch {
        continue;
      }
      if (text.includes("\0")) continue; // 二进制
      text.split("\n").forEach((line, index) => {
        if (RESIDUE_PATTERNS.some((pattern) => line.includes(pattern))) {
          hits.push(`${relative(root, full)}:${index + 1}: ${line.trim()}`);
        }
      });
    }
  };
  for (const dir of RESIDUE_DIRS) {
    const full = join(root, dir);
    if (existsSync(full)) walk(full);
  }
  return hits;
}

// ------------------------------------------------------------------ 现场

let repoRoot;
let worktreePaths;
try {
  repoRoot = git(["rev-parse", "--show-toplevel"]).trim();
  worktreePaths = git(["worktree", "list", "--porcelain"])
    .split("\n")
    .filter((line) => line.startsWith("worktree "))
    .map((line) => realpathSoft(line.slice("worktree ".length).trim()));
} catch (error) {
  console.error(`✗ ${error.message}`);
  console.error("  这个守护必须在 git 仓库里跑；不在仓库里时它**不会**静默通过。");
  process.exit(1);
}

const repoRootReal = realpathSoft(repoRoot);
const cwdReal = realpathSoft(process.cwd());
const others = worktreePaths.filter((path) => path !== cwdReal);
const envTarget = process.env.CARGO_TARGET_DIR ?? null;
const effectiveTarget = realpathSoft(
  envTarget ? resolve(process.cwd(), envTarget) : join(process.cwd(), "target"),
);

console.log(`仓库根:        ${repoRootReal}`);
console.log(`当前 worktree: ${cwdReal}`);
console.log(
  `worktree 列表: ${worktreePaths.length} 个${worktreePaths.length > 1 ? `（其他：${others.join(", ")}）` : ""}`,
);
console.log(
  `有效 target:   ${effectiveTarget}${envTarget ? "（来自 CARGO_TARGET_DIR）" : "（默认 <cwd>/target）"}`,
);

if (worktreePaths.length === 1 && runMode) {
  console.log(
    "提示: 当前目录不是链接 worktree（worktree 列表只有 1 项）。PROCESS.md §3 要求变异探针在旧 commit 的独立 worktree 里做；" +
      "若这是独立克隆，忽略本提示。",
  );
}

// ------------------------------------------------- 1. 隔离判定（B-38 的核心）

const sharing = others.filter((other) => sharesTargetWith(other, effectiveTarget));
if (sharing.length > 0) {
  fail(`有效 target 目录与别的 worktree 共享：${effectiveTarget}`);
  for (const other of sharing) fail(`    共享对象：${other}（它的 target/ 就是同一个目录）`);
  console.error(
    "  为什么是红线：两个 worktree 共用 target 时 cargo 会复用同名产物，" +
      "「旧代码 + 新测试」会报全部通过——结论反转（B-38）。",
  );
  console.error("  做法：给变异探针一个隔离目录，例如");
  console.error("    CARGO_TARGET_DIR=/tmp/mut-target cargo test -p tianshu-relay-core --test <目标>");
  process.exit(1);
}
ok(`有效 target 与另外 ${others.length} 个 worktree 的 target/ 都不重合`);

// ------------------------------------------------- 2. 残留扫描

function reportResidue(hits, when) {
  if (hits.length === 0) {
    ok(`${when}：crates/ src/ src-tauri/ 里没有 MUT- / M5 变异 残留`);
    return true;
  }
  fail(`${when}：发现变异残留 ${hits.length} 处`);
  for (const hit of hits) console.error(`    ${hit}`);
  console.error("  残留会把「本次门禁取数」污染成不可归因的结果，必须清掉再复跑。");
  return false;
}

let residueClean = reportResidue(scanResidue(repoRootReal), "残留扫描");

// ------------------------------------------------- 3. --run：强制隔离目录后执行

if (!runMode) {
  process.exit(residueClean ? 0 : 1);
}

const isolated = realpathSoft(
  targetDirFlag
    ? resolve(process.cwd(), targetDirFlag)
    : // 默认放在**系统临时目录**，而不是仓库里的 `.mut-target`（M5 变异验证期间发现）：
      // 放在仓库里会让「跑一次变异」本身把工作区弄脏 —— 而 `check-clean-gate.mjs`
      // 与 PROCESS.md §3 又要求门禁只在干净树上取数。两个守护互相打架，
      // 结果是操作者要么手工删目录、要么被迫用 `--allow-dirty` 降低取数可信度。
      join(tmpdir(), `tianshu-relay-mut-target-${process.pid}`),
);
const isolatedSharing = others.filter((other) => sharesTargetWith(other, isolated));
if (isolatedSharing.length > 0) {
  fail(`要注入的隔离目录落在别的 worktree 的 target/ 之下：${isolated}`);
  for (const other of isolatedSharing) fail(`    共享对象：${other}`);
  process.exit(1);
}

console.log(`\n强制注入 CARGO_TARGET_DIR=${isolated}`);
const [cmd, ...args] = child;
console.log(`$ ${child.join(" ")}`);
const result = spawnSync(cmd, args, {
  stdio: "inherit",
  env: { ...process.env, CARGO_TARGET_DIR: isolated },
});
if (result.error) {
  console.error(`✗ 子命令无法执行：${result.error.message}`);
  process.exit(1);
}

residueClean = reportResidue(scanResidue(repoRootReal), "跑完复扫") && residueClean;

if (result.status !== 0) {
  console.error(`\n✗ 子命令退出码 ${result.status}（target dir: ${isolated}）`);
  process.exit(result.status ?? 1);
}
if (!residueClean) process.exit(1);
console.log(`\n✓ 变异探针跑完：target 隔离成立（${isolated}），无残留`);
