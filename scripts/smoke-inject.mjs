#!/usr/bin/env node
/**
 * B-86 冒烟脚本：注入 → agent 冒烟请求 → 回滚 → 字节比对（PRD 第 9 章「三连」）。
 *
 * ## 这个脚本**在本机从未完整跑过**（spec §5.3）
 *
 * 本机**有** codex / claude / continue 三个 agent 可执行文件（实测 `--version` 可用），
 * 但缺两样东西，因此三连走不完：
 *
 * 1. **一把可用的 sk- 密钥**：注入本身不需要它（密钥走钥匙串，配置文件里写的是
 *    产品自己那套占位/引用），但「agent 冒烟请求」那一步要的是一次**真的**带认证
 *    调用 —— 没有真密钥，agent 只会回 401（实测 `codex exec` 在无效 key 下的表现）。
 * 2. **KeyRelay 的 CLI / 可脚本化入口**：投递与回滚是 **core 库函数**
 *    （`KeyRelayService::apply_delivery` / `rollback_delivery`），要走到它们就得
 *    起 Tauri 应用或另写一个二进制 —— 本包（M8-S3）的写域里**没有**这一项，
 *    所以本脚本把这一半留成**明确的前置缺口**，不假装调到了。
 *
 * 因此本文件只声称：
 *
 * - 脚本存在、`node --check` 通过、前置检查缺什么就**明确说出缺什么**；
 * - 退出码 2 = 前置不满足（**没跑**，不是失败）；0 = 三连全过；1 = 断言失败；
 * - 判定口径写在代码里，补齐前置后可以直接跑。
 *
 * ## 为什么密钥从环境变量读
 *
 * 从 `KEYRELAY_SMOKE_KEY` 读：不进命令行参数（`ps` 看得见）、不进临时文件、
 * **不打印**（连长度都不打，只打「已提供 / 未提供」）。
 *
 * ## 与 Rust 侧测试的关系
 *
 * `tests/real_site_smoke.rs` 是 Rust 侧**只读**冒烟（`#[ignore]`，需真实站点）；
 * `tests/acceptance_matrix.rs` 的 A-2 / A-9 已经把「注入 → 回滚 → 字节比对」
 * 在**注入式夹具**上钉死了（含 Continue 传 model）。本脚本多出来的只有一件事：
 * **真的跑一次 agent**。三者互补、不重复。
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const USAGE =
  "用法: node scripts/smoke-inject.mjs [--agent codex|claude-code|opencode|gemini-cli|continue] [--keep]";

const argv = process.argv.slice(2);
// P3-16 / DEBUG-REPORT-v3 §3-16：--agent <name> 的值（紧跟 --agent 的那个）不是
// 未知参数，要跳过——否则 `--agent codex` 里 codex 被当成未知参数 exit 2。
const unknown = argv.filter((a, i) => {
  if (i > 0 && argv[i - 1] === "--agent") return false;
  return !a.startsWith("--");
});
if (unknown.length) {
  console.error(`✗ 无法识别的参数：${unknown.join(" ")}\n${USAGE}`);
  process.exit(2);
}

const agentFlagIndex = argv.indexOf("--agent");
const keep = argv.includes("--keep");
const agent = agentFlagIndex >= 0 ? argv[agentFlagIndex + 1] : "codex";
const AGENTS = ["codex", "claude-code", "opencode", "gemini-cli", "continue"];

/** 每个 agent 的可执行文件名、冒烟用的最小子命令、以及目标配置的相对路径。 */
const TARGETS = {
  codex: { bin: "codex", smoke: ["exec", "echo ok"], config: ".codex/auth.json" },
  "claude-code": { bin: "claude", smoke: ["-p", "echo ok"], config: ".claude/settings.json" },
  opencode: { bin: "opencode", smoke: ["run", "echo ok"], config: ".config/opencode/opencode.json" },
  "gemini-cli": { bin: "gemini", smoke: ["-p", "echo ok"], config: ".gemini/.env" },
  continue: { bin: "continue", smoke: ["-p", "echo ok"], config: ".continue/config.yaml" },
};

/** 前置不满足：说清缺什么，退出码 2（没跑，不是失败）。 */
function missing(message) {
  console.error(`✗ 前置不满足：${message}`);
  console.error("  退出码 2 = 没跑（不是失败）。补齐后重跑即可。");
  cleanup();
  process.exit(2);
}

function fail(message) {
  console.error(`✗ ${message}`);
  // P2-18：运行中失败（投递/回滚没走完）⇒ 保留备份，原配置可能未还原。
  cleanup(true);
  process.exit(1);
}

function info(message) {
  console.log(`  ${message}`);
}

/**
 * 收尾：删掉自己做的备份。
 *
 * 必须挂在**每一条**提前退出的路上：备份是在前置检查里做的，而前置检查可能在第 ⑤ 条
 * 才失败——那时若不删，下一次跑会撞上「`<path>.smoke-backup` 已存在」而永远起不来
 * （实测：第一版就把备份留在 `~/.codex/` 里了）。`--keep` 只影响**跑完之后**的清理。
 *
 * P2-18 / DEBUG-REPORT-v3 §2-18：`preserveBackup = true` 时**保留**备份——用于运行中
 * 失败（回滚没完成、SIGINT 中断）的路径。那时原配置还没还原，删备份 = 把用户真实的
 * agent 配置（含密钥）永久丢失。前置失败（还没投递）仍删（`preserveBackup = false`）。
 */
let backupPathRef = null;
function cleanup(preserveBackup = false) {
  if (backupPathRef && existsSync(backupPathRef)) {
    if (preserveBackup) {
      console.error(`  ⚠ 保留备份 ${backupPathRef}（原配置可能未还原，请手工比对后决定是否删除）`);
    } else {
      rmSync(backupPathRef);
      console.log(`  已清理本次留下的备份 ${backupPathRef}`);
    }
  }
}

if (!AGENTS.includes(agent)) {
  console.error(`✗ 不认识的 agent：${agent}\n${USAGE}`);
  process.exit(2);
}
const target = TARGETS[agent];

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");

// ---------------------------------------------------------------- 前置检查（缺一条就退出码 2）

// ① 产品已构建：`dist/` 在 ⇒ 至少 `pnpm build` 跑过
if (!existsSync(resolve(root, "dist"))) {
  missing("dist/ 不存在 —— 先跑 `CI=true pnpm build`");
}

// ② agent 可执行文件在 PATH 里
const probe = spawnSync(target.bin, ["--version"], { encoding: "utf8" });
if (probe.error || probe.status !== 0) {
  missing(`PATH 里找不到 ${target.bin}（${agent}）—— 冒烟请求那一步需要真的跑一次 agent`);
}
info(`agent: ${agent}（${target.bin} 可用）`);

// ③ 一把可用的 sk- 密钥（环境变量；**不打印、不进参数、不落盘**）
const key = process.env.KEYRELAY_SMOKE_KEY ?? "";
if (!key.startsWith("sk-") || key.length < 12) {
  missing(
    "环境变量 KEYRELAY_SMOKE_KEY 未提供（或不是 sk- 形态）—— 冒烟请求需要一把**真**密钥；" +
      "没有它，agent 只会回 401，这一跑证明不了任何事",
  );
}
info("密钥: 已提供（不打印、不进命令行参数）");

// ④ 目标配置不存在或可写；存在时先备份到 <path>.smoke-backup。
//
// P2-18：默认 home 不再是真实 `$HOME`——冒烟脚本会向 agent 配置写密钥、跑请求，
// 对真实环境是破坏性的。显式 KEYRELAY_SMOKE_HOME 才允许指向真实目录（提示里写明）。
const home =
  process.env.KEYRELAY_SMOKE_HOME ??
  resolve(tmpdir(), `keyrelay-smoke-${Date.now()}`);
if (!existsSync(home)) {
  mkdirSync(home, { recursive: true });
}
info(`home: ${home}${process.env.KEYRELAY_SMOKE_HOME ? "" : "（临时目录，未设 KEYRELAY_SMOKE_HOME）"}`);
const configPath = resolve(home, target.config);
const backupPath = `${configPath}.smoke-backup`;
if (existsSync(backupPath)) {
  missing(`${backupPath} 已存在 —— 上一次冒烟可能没跑完，先手工清理再重跑`);
}
let hadConfig = false;
if (existsSync(configPath)) {
  // P2-18：备份文件权限继承原文件（原配置通常 0600 且含真实密钥）——
  // 不再是默认 0644（同机其他用户可读）。原文件权限读不到时保守用 0600。
  let mode;
  try {
    mode = statSync(configPath).mode & 0o777;
  } catch {
    mode = 0o600;
  }
  writeFileSync(backupPath, readFileSync(configPath), { mode });
  backupPathRef = backupPath;
  hadConfig = true;
  info(`已备份原配置 → ${backupPath}（权限 ${mode.toString(8)}）`);
} else {
  info(`目标配置不存在（将新建）: ${configPath}`);
}

// P2-18：SIGINT（Ctrl-C）时原配置可能已注入未回滚——与 fail() 同一条路：
// 保留备份，让用户能手工还原；直接 exit 会跳过 cleanup。
process.on("SIGINT", () => {
  console.error("\n✗ 收到 SIGINT，中断冒烟");
  cleanup(true);
  process.exit(130);
});
process.on("SIGTERM", () => {
  console.error("\n✗ 收到 SIGTERM，中断冒烟");
  cleanup(true);
  process.exit(143);
});

// ⑤ 投递 / 回滚的入口：本机**没有** KeyRelay 的 CLI（投递是 core 库函数，
//    见文件头「从未完整跑过」的第 2 条）。明确报出来，不静默跳过。
const cli = process.env.KEYRELAY_CLI ?? "";
if (!cli || !existsSync(cli)) {
  missing(
    "找不到 KeyRelay 的可脚本化入口（环境变量 KEYRELAY_CLI 指向一个可执行文件）—— " +
      "投递与回滚是 core 库函数（apply_delivery / rollback_delivery），" +
      "当前仓库没有把它们包成 CLI；补上后再跑三连",
  );
}

// ---------------------------------------------------------------- 三连

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/** 秘密形态：sk- / nap- / 32 位以上 hex。**只扫 agent 的输出**，不扫注入产物。 */
const SECRET_SHAPES = [/\bsk-[A-Za-z0-9_-]{8,}/, /\bnap-[A-Za-z0-9_-]{8,}/, /\b[0-9a-fA-F]{32,}\b/];
function looksLikeSecret(text) {
  return SECRET_SHAPES.some((re) => re.test(text));
}

const results = [];
function check(name, ok, detail) {
  results.push({ name, ok });
  console.log(`${ok ? "✓" : "✗"} ${name}${detail ? ` —— ${detail}` : ""}`);
}

console.log("\n三连：注入 → agent 冒烟请求 → 回滚 → 字节比对\n");

// ① 注入：调产品自己的投递入口写目标文件（**不手拼配置**——手拼一份「看起来对」的
//    配置，冒烟通过只能证明 agent 认那份配置，证明不了产品写得对）。
const inject = spawnSync(cli, ["apply-delivery", "--agent", agent], {
  encoding: "utf8",
  env: { ...process.env, HOME: home },
  timeout: 120_000,
});
if (inject.error || inject.status !== 0) {
  fail(`投递失败（退出码 ${inject.status}）: ${(inject.stderr ?? "").slice(0, 300)}`);
}
if (!existsSync(configPath)) {
  fail(`投递报了成功，但目标文件不存在: ${configPath}`);
}
check("① 注入写出目标文件", true, `${statSync(configPath).size} B`);

// ② 冒烟请求：用注入后的配置跑一次**最小**请求。退出码 0 且输出里不含密钥形态。
const smoke = spawnSync(target.bin, target.smoke, {
  encoding: "utf8",
  timeout: 180_000,
  env: { ...process.env, HOME: home },
});
const smokeOut = `${smoke.stdout ?? ""}${smoke.stderr ?? ""}`;
if (smoke.error) {
  check("② agent 冒烟请求", false, `无法执行 ${target.bin}: ${smoke.error.message}`);
} else {
  check("② agent 冒烟请求", smoke.status === 0, `退出码 ${smoke.status}`);
  check(
    "② 冒烟输出不含密钥形态",
    !looksLikeSecret(smokeOut),
    looksLikeSecret(smokeOut) ? "输出里出现 sk-/nap-/32位hex" : "干净",
  );
}

// ③ 回滚：目标文件必须回到注入前的状态（有备份 ⇒ 逐字节相等；没有 ⇒ 文件消失）。
const rollback = spawnSync(cli, ["rollback-delivery", "--agent", agent], {
  encoding: "utf8",
  env: { ...process.env, HOME: home },
  timeout: 120_000,
});
if (rollback.error || rollback.status !== 0) {
  fail(`回滚失败（退出码 ${rollback.status}）: ${(rollback.stderr ?? "").slice(0, 300)}`);
}
if (hadConfig) {
  const now = sha256(configPath);
  const before = sha256(backupPath);
  check("③ 回滚逐字节还原", now === before, `sha256 ${now.slice(0, 16)}…`);
} else {
  check("③ 回滚删掉自己创建的文件", !existsSync(configPath), configPath);
}

// ---------------------------------------------------------------- 收尾

if (!keep && existsSync(backupPath)) {
  rmSync(backupPath);
  info(`已删除备份 ${backupPath}`);
}

const failed = results.filter((r) => !r.ok);
console.log(`\n${failed.length === 0 ? "三连全过" : `${failed.length} 项未过`}`);
process.exit(failed.length === 0 ? 0 : 1);
