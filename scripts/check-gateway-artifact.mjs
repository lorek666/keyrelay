#!/usr/bin/env node
/**
 * M44-S1 G 组：macOS 打包产物校验（spec §7 G1–G3）。
 *
 *   node scripts/check-gateway-artifact.mjs [--dmg <路径>] [--app <路径>]
 *
 * 退出码：0 = 全部合格；2 = **未接线**（缺产物或缺工具，打印缺什么）；3 = 产物不合格。
 *
 * 只读：不构建、不安装、不签章；只做 `stat` / `plutil` / `lipo` / `hdiutil verify` 的读取。
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

const MAX_DMG_BYTES = 30 * 1024 * 1024; // spec：≤ 30 MB
const problems = [];
const notWired = [];

// ---- G1 DMG ----
const dmgDir = "src-tauri/target/universal-apple-darwin/release/bundle/dmg";
let dmg = dmgArg;
if (!dmg) {
  if (!existsSync(dmgDir)) {
    notWired.push(`缺 DMG 目录 ${dmgDir}（先跑 scripts/build-universal.sh）`);
  } else {
    const found = readdirSync(dmgDir).filter((f) => f.endsWith(".dmg"));
    if (found.length === 0) notWired.push(`目录里没有 .dmg：${dmgDir}`);
    else dmg = join(dmgDir, found.sort().at(-1));
  }
}
if (dmg) {
  if (!existsSync(dmg)) {
    problems.push(`DMG 不存在：${dmg}`);
  } else {
    const size = statSync(dmg).size;
    console.log(`DMG: ${dmg}（${size} 字节 = ${(size / 1024 / 1024).toFixed(2)} MiB）`);
    if (size > MAX_DMG_BYTES) problems.push(`DMG 体积 ${size} > 30 MB 上限`);
    const name = dmg.split("/").pop() ?? "";
    if (!name.startsWith("天枢 Relay_")) problems.push(`DMG 文件名不以「天枢 Relay_」开头：${name}`);
    const verify = run("hdiutil", ["verify", dmg]);
    console.log(`hdiutil verify: exit=${verify.code}`);
    if (verify.code !== 0) problems.push(`hdiutil verify 失败：${verify.out.trim().split("\n").at(-1)}`);
  }
}

// ---- G2/G3 App bundle ----
let app = appArg;
if (!app) {
  const macDir = "src-tauri/target/universal-apple-darwin/release/bundle/macos";
  if (!existsSync(macDir)) {
    notWired.push(`缺 macos 产物目录 ${macDir}`);
  } else {
    const found = readdirSync(macDir).filter((f) => f.endsWith(".app"));
    if (found.length === 0) notWired.push(`macos 目录里没有 .app：${macDir}`);
    else app = join(macDir, found.sort().at(-1));
  }
}
if (app) {
  if (!existsSync(app)) {
    problems.push(`App 不存在：${app}`);
  } else {
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
      console.log(`lipo -archs: ${lipo.out.trim()}（exit=${lipo.code}）`);
      if (lipo.code !== 0 || !/arm64/.test(lipo.out) || !/x86_64/.test(lipo.out)) {
        problems.push(`不是 Universal（需要 arm64 + x86_64）：${lipo.out.trim()}`);
      }
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
console.log("\n✓ G 组产物校验通过（DMG ≤ 30 MB / 天枢 Relay.app / CFBundleIdentifier / Universal）。");
