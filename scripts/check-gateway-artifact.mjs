#!/usr/bin/env node
/**
 * M44-S1 G 组：macOS 打包产物校验（spec §7 G1–G3）。
 *
 *   node scripts/check-gateway-artifact.mjs [--dmg <路径>] [--app <路径>]
 *
 * 退出码：0 = 全部合格；2 = **未接线**（缺产物或缺工具，打印缺什么）；3 = 产物不合格。
 *
 * 只读：不构建、不安装、不签章；只做 `stat` / `plutil` / `lipo` / `hdiutil verify` 的读取。
 *
 * 2026-10-26 起分架构：不再要求 Universal（arm64 + x86_64 合并），改为每架构
 * 单独校验——.app 必须是单架构薄二进制，且与所在分架构目录一致；DMG 每张 ≤ 30 MB。
 * 默认在两个分架构产物目录里找全部产物；--dmg/--app 可指定单个产物单测。
 */

import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const USAGE = "用法: node scripts/check-gateway-artifact.mjs [--dmg <路径>] [--app <路径>]";
const argv = process.argv.slice(2);
let dmgArg = null;
let appArg = null;
for (let i = 0; i < argv.length; i += 1) {
  if (argv[i] === "--dmg") dmgArg = argv[++i] ?? null;
  else if (argv[i] === "--app") appArg = argv[++i] ?? null;
  else if (argv[i] === "--help" || argv[i] === "-h") {
    console.log(USAGE);
    process.exit(0);
  } else {
    console.error(`✗ 无法识别的参数：${argv[i]}\n${USAGE}`);
    process.exit(1);
  }
}

function run(cmd, args) {
  const r = spawnSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 32 * 1024 * 1024 });
  if (r.error) return { code: 127, out: String(r.error.message) };
  return { code: r.status === null ? 128 : r.status, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

const MAX_DMG_BYTES = 30 * 1024 * 1024; // spec：每张 DMG ≤ 30 MB
const problems = [];
const notWired = [];

// 分架构产物目录（工作区根 target/ 优先，src-tauri/target/ 回落；与 build-macos.sh 一致）。
const ARCHES = [
  { triple: "aarch64-apple-darwin", lipo: "arm64" },
  { triple: "x86_64-apple-darwin", lipo: "x86_64" },
];
const BUNDLE_ROOTS = ["target", "src-tauri/target"];

function archOfPath(p) {
  for (const a of ARCHES) {
    if (p.includes(a.triple)) return a.lipo;
  }
  return null;
}

function collect(kind) {
  // kind: "dmg" | "macos"；返回全部找到的产物路径。
  const found = [];
  for (const root of BUNDLE_ROOTS) {
    for (const a of ARCHES) {
      const dir = join(root, a.triple, "release", "bundle", kind);
      if (!existsSync(dir)) continue;
      const ext = kind === "dmg" ? ".dmg" : ".app";
      for (const f of readdirSync(dir).filter((x) => x.endsWith(ext))) {
        found.push(join(dir, f));
      }
    }
  }
  return found.sort();
}

// ---- G1 DMG ----
const dmgs = dmgArg ? [dmgArg] : collect("dmg");
if (dmgs.length === 0) {
  notWired.push(
    `缺 DMG 产物（分架构目录 target/<triple>/release/bundle/dmg 与 src-tauri/target/<triple>/release/bundle/dmg 里都没有 .dmg；先跑 scripts/build-macos.sh <aarch64-apple-darwin|x86_64-apple-darwin>）`,
  );
}
for (const dmg of dmgs) {
  if (!existsSync(dmg)) {
    problems.push(`DMG 不存在：${dmg}`);
    continue;
  }
  const size = statSync(dmg).size;
  console.log(`DMG: ${dmg}（${size} 字节 = ${(size / 1024 / 1024).toFixed(2)} MiB）`);
  if (size > MAX_DMG_BYTES) problems.push(`DMG 体积 ${size} > 30 MB 上限`);
  const name = dmg.split("/").pop() ?? "";
  if (!name.startsWith("天枢 Relay_")) problems.push(`DMG 文件名不以「天枢 Relay_」开头：${name}`);
  const verify = run("hdiutil", ["verify", dmg]);
  console.log(`hdiutil verify: exit=${verify.code}`);
  if (verify.code !== 0) problems.push(`hdiutil verify 失败：${verify.out.trim().split("\n").at(-1)}`);
}

// ---- G2/G3 App bundle ----
const apps = appArg ? [appArg] : collect("macos");
if (apps.length === 0) {
  notWired.push(
    `缺 macos 产物（分架构目录 target/<triple>/release/bundle/macos 与 src-tauri/target/<triple>/release/bundle/macos 里都没有 .app）`,
  );
}
for (const app of apps) {
  if (!existsSync(app)) {
    problems.push(`App 不存在：${app}`);
    continue;
  }
  const name = app.split("/").pop() ?? "";
  console.log(`App: ${app}`);
  if (name !== "天枢 Relay.app") problems.push(`App 包名不是「天枢 Relay.app」：${name}`);

  const plist = join(app, "Contents", "Info.plist");
  const plutil = run("plutil", ["-p", plist]);
  if (plutil.code !== 0) {
    problems.push(`plutil 读取失败：${plutil.out.trim()}`);
  } else {
    const hit = (k, v) => new RegExp(`"${k}"\\s*=>\\s*"${v}"`).test(plutil.out);
    if (!hit("CFBundleIdentifier", "com.tianshu.relay")) problems.push("CFBundleIdentifier != com.tianshu.relay");
    if (!/天枢 Relay/.test(plutil.out)) problems.push("Info.plist 里没有「天枢 Relay」字样");
    console.log("Info.plist: CFBundleIdentifier / 名称检查完成");
  }

  const bin = join(app, "Contents", "MacOS", "tianshu-relay");
  if (!existsSync(bin)) {
    problems.push(`可执行文件不存在：${bin}`);
  } else {
    const lipo = run("lipo", ["-archs", bin]);
    const archs = lipo.out.trim();
    console.log(`lipo -archs: ${archs}（exit=${lipo.code}）`);
    const expected = archOfPath(app);
    if (lipo.code !== 0 || (archs !== "arm64" && archs !== "x86_64")) {
      problems.push(`不是单架构薄二进制（分架构产物应恰含一个架构）：${archs}`);
    } else if (expected !== null && archs !== expected) {
      problems.push(`架构与目录不一致（目录要求 ${expected}，实际 ${archs}）`);
    }
  }
}

// ---- 结论 ----
if (notWired.length > 0) {
  console.error("\n未接线（2）：");
  for (const n of notWired) console.error(`  - ${n}`);
}
if (problems.length > 0) {
  console.error("\n产物不合格（3）：");
  for (const p of problems) console.error(`  - ${p}`);
}
if (problems.length > 0) process.exit(3);
if (notWired.length > 0) process.exit(2);
console.log("\n✓ G 组产物校验通过（每架构 DMG ≤ 30 MB / 天枢 Relay.app / CFBundleIdentifier / 单架构与目录一致）。");
