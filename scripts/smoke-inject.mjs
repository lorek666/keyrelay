#!/usr/bin/env node
/**
 * B-86 / B-118 冒烟脚本：注入 → agent 冒烟请求 → 回滚 → 字节比对（PRD 第 9 章「三连」）。
 *
 * ## 这个脚本现在能跑了（M14-S4 起）
 *
 * 投递与回滚走 KeyRelay 的薄 CLI（`KEYRELAY_CLI` 指向 `keyrelay-cli` 二进制），
 * 它包了 `KeyRelayService::apply_delivery` / `rollback_delivery`。两种模式：
 *
 * - **真路径**：`KEYRELAY_REAL_KEY`（真 `sk-`）+ 真 agent 在 PATH ⇒ 用真 key 注入、
 *   跑真 agent（`codex exec` 等）做一次带认证调用，断言首 token 成功且输出不含密钥形态。
 * - **mock 路径**：缺真 key 或缺真 agent ⇒ 用占位 key 注入、跑 CLI 的 `mock-agent`
 *   子命令（只读解析注入产物、校验密钥字段在）。mock 证明「注入产物可解析 + 密钥字段在」，
 *   **不**证明「真 agent 首 token 成功」——后者只走真路径才算。
 *
 * ## 退出码
 *
 * - 0 = 三连全过（真或 mock）；
 * - 1 = 断言失败（投递/回滚/字节比对/密钥形态泄漏）；
 * - 2 = 前置不满足（**没跑**，不是失败）——现在只有 `KEYRELAY_CLI` 缺失才会停在这一档。
 *
 * ## 密钥从环境变量读
 *
 * 从 `KEYRELAY_REAL_KEY` 读：不进命令行参数（`ps` 看得见）、不进临时文件、
 * **不打印**（连长度都不打，只打「已提供 / 未提供」）。mock 路径用脚本内置的占位 key，
 * 不需要用户提供。
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const USAGE =
  "用法: node scripts/smoke-inject.mjs --agent <codex|claude-code|opencode|opencode-jsonc|gemini-cli|claude-desktop|grok-build|openclaw|hermes|mcode|pi> [--mock] [--keep]";

const argv = process.argv.slice(2);
// --agent <name> 的值不是未知参数；--mock / --keep 是 bool。
const unknown = argv.filter((a, i) => {
  if (i > 0 && argv[i - 1] === "--agent") return false;
  if (a === "--mock" || a === "--keep") return false;
  return !a.startsWith("--");
});
if (unknown.length) {
  console.error(`✗ 无法识别的参数：${unknown.join(" ")}\n${USAGE}`);
  process.exit(2);
}

const agentFlagIndex = argv.indexOf("--agent");
if (agentFlagIndex < 0) {
  console.error(`✗ 需要 --agent <name>\n${USAGE}`);
  process.exit(2);
}
const agent = argv[agentFlagIndex + 1];
const keep = argv.includes("--keep");
const forceMock = argv.includes("--mock");
const AGENTS = [
  "codex", "claude-code", "opencode", "opencode-jsonc", "gemini-cli",
  "claude-desktop", "grok-build", "openclaw", "hermes", "mcode", "pi",
];

if (!AGENTS.includes(agent)) {
  console.error(`✗ 不认识的 agent：${agent}\n${USAGE}`);
  process.exit(2);
}

/** agent → 投递通道名（与 DeliveryChannel::as_str() 一致，11 通道）。 */
const CHANNEL = {
  codex: "codex-auth-json",
  "claude-code": "claude-code-settings",
  opencode: "opencode",
  "opencode-jsonc": "opencode-jsonc",
  "gemini-cli": "gemini-cli",
  "claude-desktop": "claude-desktop",
  "grok-build": "grok-build",
  openclaw: "openclaw",
  hermes: "hermes",
  mcode: "mcode",
  pi: "pi",
};
/** M14-S1 起 Continue 已删，11 通道均不要求 model（OpenCode 系列的 model 可选）。
 *  M25-S1 起 codex 真路径要 model：env KEYRELAY_REAL_MODEL 优于空表。 */
const MODEL = {};

/** 每个 agent 的可执行文件名、冒烟用的最小子命令、目标配置的相对路径。
 *  新 6 通道（claude-desktop/grok-build/openclaw/hermes/mcode/pi）多为桌面或配置型 agent，
 *  本机通常无 CLI 二进制 ⇒ realAgentAvailable=false ⇒ 自动落 mock 路径。 */
const TARGETS = {
  codex: { bin: "codex", smoke: ["exec", "say ok"], config: ".codex/auth.json" },
  "claude-code": { bin: "claude", smoke: ["-p", "echo ok"], config: ".claude/settings.json" },
  opencode: { bin: "opencode", smoke: ["run", "echo ok"], config: ".config/opencode/opencode.json" },
  "opencode-jsonc": { bin: "opencode", smoke: ["run", "echo ok"], config: ".config/opencode/opencode.jsonc" },
  "gemini-cli": { bin: "gemini", smoke: ["-p", "echo ok"], config: ".gemini/.env" },
  "claude-desktop": { bin: "claude-desktop", smoke: ["--version"], config: "Library/Application Support/Claude/claude_desktop_config.json" },
  "grok-build": { bin: "grok", smoke: ["--version"], config: ".grok/config.toml" },
  openclaw: { bin: "openclaw", smoke: ["--version"], config: ".openclaw/openclaw.json" },
  hermes: { bin: "hermes", smoke: ["--version"], config: ".hermes/config.yaml" },
  mcode: { bin: "mcode", smoke: ["--version"], config: ".minimax/config.yaml" },
  pi: { bin: "pi", smoke: ["--version"], config: ".pi/agent/models.json" },
};

/** M25-S1：codex 真路径需要写 ~/.codex/config.toml（LoongPort 同形 + wire_api=responses），
 *  让 codex 真用上上游网关的 Responses API（codex 0.162.1 起 chat wire 已被砍）。
 *  在 codex-auth-json 注入完成后追加写 config.toml；回滚时一并删掉。 */
function writeCodexConfigToml(home, base, model) {
  if (!base) return null;
  const dir = resolve(home, ".codex");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const path = resolve(dir, "config.toml");
  let backup = null;
  if (existsSync(path)) {
    backup = readFileSync(path);
  }
  const q = (s) => JSON.stringify(s);
  const body =
    `model_provider = "custom"\n` +
    (model ? `model = ${q(model)}\n` : ``) +
    `disable_response_storage = true\n\n` +
    `[model_providers.custom]\n` +
    `name = "custom"\n` +
    `base_url = ${q(base)}\n` +
    `wire_api = "responses"\n`;
  writeFileSync(path, body, { mode: 0o600 });
  return { path, backup };
}

/** mock 路径用的占位密钥（sk- 形态、长度 ≥ 12；不是任何真实密钥）。 */
const PLACEHOLDER_KEY = "sk-keyrelay-smoke-mock-0123456789abcdef";

function missing(message) {
  console.error(`✗ 前置不满足：${message}`);
  console.error("  退出码 2 = 没跑（不是失败）。补齐后重跑即可。");
  cleanup();
  process.exit(2);
}

function fail(message) {
  console.error(`✗ ${message}`);
  cleanup(true);
  process.exit(1);
}

function info(message) {
  console.log(`  ${message}`);
}

let backupPathRef = null;
let codexConfigRef = null; // M25-S1：codex 真路径写出的 config.toml，回滚时要还原/删
function cleanup(preserveBackup = false) {
  if (backupPathRef && existsSync(backupPathRef)) {
    if (preserveBackup) {
      console.error(`  ⚠ 保留备份 ${backupPathRef}（原配置可能未还原，请手工比对后决定是否删除）`);
    } else {
      rmSync(backupPathRef);
      console.log(`  已清理本次留下的备份 ${backupPathRef}`);
    }
  }
  // M25-S1：codex 真路径写出的 ~/.codex/config.toml
  if (codexConfigRef && existsSync(codexConfigRef.path)) {
    if (preserveBackup) {
      console.error(`  ⚠ 保留 codex config.toml（原配置可能未还原）`);
    } else if (codexConfigRef.backup != null) {
      writeFileSync(codexConfigRef.path, codexConfigRef.backup, { mode: 0o600 });
      console.log(`  已还原 ~/.codex/config.toml 备份`);
    } else {
      rmSync(codexConfigRef.path);
      console.log(`  已删除本次新建的 ~/.codex/config.toml`);
    }
  }
}

const target = TARGETS[agent];
const channel = CHANNEL[agent];
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");

// ---------------------------------------------------------------- 前置检查

// ① KeyRelay CLI 可执行文件在（投递/回滚/mock-agent 都靠它）
const cli = process.env.KEYRELAY_CLI ?? "";
if (!cli || !existsSync(cli)) {
  missing(
    "找不到 KeyRelay 的 CLI（环境变量 KEYRELAY_CLI 指向 keyrelay-cli 二进制）—— " +
      "M14-S4 交付的薄 CLI；先 `cargo build -p keyrelay-cli` 再指向 target/.../keyrelay-cli",
  );
}
info(`CLI: ${cli}`);

// ② 真 agent 可执行文件在 PATH 里（缺失 ⇒ 落 mock 路径，不退出）
const probe = spawnSync(target.bin, ["--version"], { encoding: "utf8" });
const realAgentAvailable = !probe.error && probe.status === 0;

// ③ 一把可用的真 sk- 密钥（缺失 ⇒ 落 mock 路径，不退出）
const realKey = process.env.KEYRELAY_REAL_KEY ?? "";
const realKeyAvailable = realKey.startsWith("sk-") && realKey.length >= 12;

// 模式裁决：真路径需要真 key + 真 agent 且未强制 mock；否则 mock。
const realMode = !forceMock && realKeyAvailable && realAgentAvailable;
const mode = realMode ? "真" : "mock";
info(
  `agent: ${agent}` +
    (realAgentAvailable ? `（${target.bin} 可用）` : `（${target.bin} 不在 PATH）`) +
    `；密钥: ${realKeyAvailable ? "已提供" : "未提供"}；模式: ${mode}`,
);
if (!forceMock && realKeyAvailable && !realAgentAvailable) {
  info(`  真 key 在但真 agent 不在 ⇒ mock 路径（注入用占位 key，冒烟走 mock-agent）`);
}
if (forceMock) info(`  --mock 强制 mock 路径`);

// ④ 目标配置所在的 home（默认临时目录；KEYRELAY_SMOKE_HOME 才允许指向真实目录）
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

// 注入用的密钥：真路径用真 key，mock 路径用占位 key（CLI --smoke 始终从 env 读）
const keyForInject = realMode ? realKey : PLACEHOLDER_KEY;

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

console.log(`\n三连（${mode} 路径）：注入 → agent 冒烟请求 → 回滚 → 字节比对\n`);

// ① 注入：CLI apply-delivery --smoke（store/backup 由 --home 派生）
// CLI 调用不覆盖 HOME：CLI 用 --home flag 解析路径，不读 HOME；让 CLI 看到真实 $HOME，
// --home=<temp> ≠ $HOME ⇒ --smoke 防呆放行（若覆盖 HOME=temp，--home==HOME 会误触发防呆）。
// M25-S1：model 优先级：MODEL 表 > KEYRELAY_REAL_MODEL env；codex 真路径用它写 config.toml。
const realModelFromEnv = process.env.KEYRELAY_REAL_MODEL ?? "";
const modelName = MODEL[agent] ?? (realMode && realModelFromEnv ? realModelFromEnv : "");
const modelArgs = modelName ? ["--model", modelName] : [];
const realBaseUrl = process.env.KEYRELAY_REAL_BASE_URL ?? "";
const inject = spawnSync(
  cli,
  ["apply-delivery", "--channel", channel, "--smoke", "--home", home, ...modelArgs],
  {
    encoding: "utf8",
    env: { ...process.env, KEYRELAY_REAL_KEY: keyForInject },
    timeout: 120_000,
  },
);
if (inject.error || inject.status !== 0) {
  fail(`投递失败（退出码 ${inject.status}）: ${(inject.stderr ?? "").slice(0, 300)}`);
}
const journalId = (inject.stdout ?? "").trim();
if (!journalId) {
  fail(`投递报了成功，但 stdout 没有 journal_id: ${(inject.stderr ?? "").slice(0, 300)}`);
}
if (!existsSync(configPath)) {
  fail(`投递报了成功，但目标文件不存在: ${configPath}`);
}
check("① 注入写出目标文件", true, `${statSync(configPath).size} B；journal=${journalId.slice(0, 12)}…`);

// M25-S1：codex 真路径要追加写 ~/.codex/config.toml（让 codex 用 NewAPI 的 chat completions）
if (realMode && agent === "codex") {
  if (!realBaseUrl.startsWith("http")) {
    fail("codex 真路径需要 KEYRELAY_REAL_BASE_URL（如 https://<relayed-upstream>/v1）");
  }
  codexConfigRef = writeCodexConfigToml(home, realBaseUrl, modelName);
  info(`已写 ~/.codex/config.toml（LoongPort 同形 + wire_api=responses）`);
}

// ② 冒烟请求：真路径跑真 agent；mock 路径跑 CLI mock-agent
let smokeOk = false;
let smokeDetail = "";
if (realMode) {
  const smoke = spawnSync(target.bin, target.smoke, {
    encoding: "utf8",
    timeout: 180_000,
    env: { ...process.env, HOME: home },
  });
  const smokeOut = `${smoke.stdout ?? ""}${smoke.stderr ?? ""}`;
  if (smoke.error) {
    smokeDetail = `无法执行 ${target.bin}: ${smoke.error.message}`;
  } else {
    smokeOk = smoke.status === 0;
    smokeDetail = `退出码 ${smoke.status}`;
  }
  check("② agent 冒烟请求（真）", smokeOk, smokeDetail);
  check(
    "② 冒烟输出不含密钥形态",
    !looksLikeSecret(smokeOut),
    looksLikeSecret(smokeOut) ? "输出里出现 sk-/nap-/32位hex" : "干净",
  );
  // M25-S1：codex 真路径额外断言「真模型返回结果」——输出非空 + 含可识别响应文本
  if (agent === "codex") {
    const trimmedOut = smokeOut.trim();
    const hasNonEmptyBody = trimmedOut.length > 0;
    check(
      "② codex 真路径拿到真模型响应（输出非空）",
      smokeOk && hasNonEmptyBody,
      hasNonEmptyBody ? `输出 ${trimmedOut.length} 字节` : "输出为空",
    );
  }
} else {
  // mock 路径：CLI mock-agent 只读解析注入产物、校验密钥字段在
  const smoke = spawnSync(cli, ["mock-agent", "--channel", channel, "--home", home], {
    encoding: "utf8",
    env: { ...process.env },
    timeout: 60_000,
  });
  if (smoke.error) {
    smokeDetail = `无法执行 mock-agent: ${smoke.error.message}`;
  } else {
    smokeOk = smoke.status === 0;
    smokeDetail = `退出码 ${smoke.status}（${smoke.status === 0 ? "密钥字段在" : (smoke.stderr ?? "").slice(0, 120)}）`;
  }
  check("② mock-agent 校验密钥字段在", smokeOk, smokeDetail);
  // mock 路径不扫密钥形态：mock-agent 只读不产生密钥输出，扫描无意义
}

// ③ 回滚：CLI rollback-delivery --journal（store 由 --home 派生）
const rollback = spawnSync(cli, ["rollback-delivery", "--journal", journalId, "--home", home], {
  encoding: "utf8",
  env: { ...process.env },
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
console.log(`\n${failed.length === 0 ? `三连全过（${mode} 路径）` : `${failed.length} 项未过`}`);
process.exit(failed.length === 0 ? 0 : 1);
