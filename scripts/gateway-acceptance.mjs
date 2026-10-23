#!/usr/bin/env node
/**
 * M44-S1 网关验收矩阵的一条命令入口。
 *
 *   node scripts/gateway-acceptance.mjs                 # A–E 矩阵（默认）
 *   node scripts/gateway-acceptance.mjs --perf          # 追加 F 组（release，#[ignore]）
 *   node scripts/gateway-acceptance.mjs --artifact      # 追加 G 组产物校验
 *   node scripts/gateway-acceptance.mjs --all           # 三段都跑
 *
 * 纪律：
 * - **真退出码**：全部 spawnSync，不经 shell、不用管道（`cmd | tail` 会把 `$?` 变成 tail 的）。
 * - **不早停**：一段红了也继续跑其余段，最后打印汇总表。
 * - **未接线要显式**：缺 release 目录 / 缺 DMG 产物 ⇒ 该段标 `未接线（<原因>）`，退出码 2。
 * - 不做入库、不改 main；只读被测代码与产物。
 */

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";

const USAGE = `用法: node scripts/gateway-acceptance.mjs [--perf] [--artifact] [--all]`;
const argv = process.argv.slice(2);
const want = { perf: false, artifact: false };
for (const a of argv) {
  if (a === "--perf") want.perf = true;
  else if (a === "--artifact") want.artifact = true;
  else if (a === "--all") {
    want.perf = true;
    want.artifact = true;
  } else if (a === "--help" || a === "-h") {
    console.log(USAGE);
    process.exit(0);
  } else {
    console.error(`✗ 无法识别的参数：${a}\n${USAGE}`);
    process.exit(1);
  }
}

function run(cmd, args, extra = {}) {
  const r = spawnSync(cmd, args, {
    stdio: ["ignore", "pipe", "pipe"],
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    env: { ...process.env, ...extra },
  });
  if (r.error) return { code: 127, out: `（无法执行 ${cmd}: ${r.error.message}）` };
  return { code: r.status === null ? 128 : r.status, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

const results = [];
function record(name, code, note) {
  results.push({ name, code, note });
  console.log(`${code === 0 ? "✓" : code === 2 ? "…" : "✗"} ${name.padEnd(34)} exit=${code}  ${note ?? ""}`);
}

// ---------------- A–E 矩阵 ----------------
console.log("[1] A–E 端到端矩阵（多站 mock）");
const t0 = Date.now();
const matrix = run("cargo", ["test", "-p", "tianshu-relay-core", "--test", "gateway_acceptance"]);
const lines = matrix.out.split("\n").filter((l) => /^test result:/.test(l));
const passed = (matrix.out.match(/(\d+) passed/g) ?? []).map((m) => Number(m.split(" ")[0])).reduce((a, b) => a + b, 0);
const failed = (matrix.out.match(/(\d+) failed/g) ?? []).map((m) => Number(m.split(" ")[0])).reduce((a, b) => a + b, 0);
const ignored = (matrix.out.match(/(\d+) ignored/g) ?? []).map((m) => Number(m.split(" ")[0])).reduce((a, b) => a + b, 0);
record("A–E matrix", matrix.code, `${passed} passed / ${failed} failed / ${ignored} ignored（${((Date.now() - t0) / 1000).toFixed(1)}s）`);
if (matrix.code !== 0) console.log(matrix.out.split("\n").slice(-12).join("\n"));

// ---------------- F 组（可选） ----------------
if (want.perf) {
  console.log("\n[2] F 组性能（release，#[ignore]）");
  const t = Date.now();
  const perf = run("cargo", [
    "test",
    "-p",
    "tianshu-relay-core",
    "--release",
    "--test",
    "gateway_perf",
    "--",
    "--ignored",
    "--nocapture",
    "--test-threads=1",
  ]);
  const p = (perf.out.match(/(\d+) passed/g) ?? []).map((m) => Number(m.split(" ")[0])).reduce((a, b) => a + b, 0);
  const f = (perf.out.match(/(\d+) failed/g) ?? []).map((m) => Number(m.split(" ")[0])).reduce((a, b) => a + b, 0);
  record("F perf", perf.code, `${p} passed / ${f} failed（${((Date.now() - t) / 1000).toFixed(1)}s）`);
  if (perf.code !== 0) console.log(perf.out.split("\n").slice(-16).join("\n"));
}

// ---------------- G 组（可选） ----------------
if (want.artifact) {
  console.log("\n[3] G 组打包产物校验");
  const art = run("node", ["scripts/check-gateway-artifact.mjs"]);
  record("G artifact", art.code, art.code === 0 ? "产物合格" : art.code === 2 ? "未接线（缺产物/工具）" : "产物不合格");
  console.log(art.out.trim());
}

// ---------------- 汇总 ----------------
console.log("\n=== 汇总 ===");
const width = Math.max(...results.map((r) => r.name.length), 8);
for (const r of results) {
  console.log(`| ${r.name.padEnd(width)} | ${String(r.code).padStart(2)} | ${r.note ?? ""}`);
}
const hardFail = results.some((r) => r.code !== 0 && r.code !== 2);
const notWired = results.some((r) => r.code === 2);
process.exit(hardFail ? 3 : notWired ? 2 : 0);
