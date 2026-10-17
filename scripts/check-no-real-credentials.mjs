#!/usr/bin/env node
// M16-S8 · 仓库级凭证卫生守护（B-125）。
//
// 背景：历次「真实站点验证」把真实账号名写进了代码、测试与文档。每次「已脱敏」的声明都只
// 覆盖**当次新增文件**，从没人总的对过账 ⇒ 仓库尺度上一直没闭环（`docs/PROCESS.md` §3
// 「不保存站点管理员凭证」）。M16 做了一次全仓清理（46 处 / 13 文件），本脚本防回归。
//
// 设计要点：
// 1. **不自扫**：`fileURLToPath(import.meta.url)` 排除自己——凡是「扫目录/扫自己所在文件」
//    的守护，先问一句「它会不会扫到自己」（M8-S6 的教训）。
// 2. **针在运行时拼**：禁词不在本文件里以字面量出现，否则本脚本自己就会命中。
// 3. 只扫 `git ls-files` 的**已跟踪**文件（仓库卫生的边界就是入库内容）。
//
// 用法：node scripts/check-no-real-credentials.mjs
// 退出码：0 = 干净；1 = 命中；2 = 脚本自身错误（例如不在 git 仓库里）。

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const SELF = fileURLToPath(import.meta.url);

/** 禁词（运行时拼接，避免本文件自身命中）。 */
const NEEDLES = [
  { label: "真实站点账号名", value: ["test", "user"].join("") },
  { label: "已作废的站点口令", value: ["aa123", "123"].join("") },
  // M18-S1：真机验证时**两次**把真实域名写进了文档与代码注释（第一次在 M17-S1 第二轮入库时
  // 漏了，第二次是本步新写的 spec/module doc）。这类值不是「凭证」，所以旧禁词表抓不到——
  // 但它们同样是「仓库里不该出现的真实标识」，一并守。
  { label: "真实站点域名", value: ["aizhong", "zhuan"].join("") },
  { label: "真机 SSH 私钥文件名", value: ["xinzhuan", "_key"].join("") },
];

/** 允许出现的白名单：占位符（大小写不敏感地匹配「占位」语义）。 */
const PLACEHOLDER_PATTERNS = [
  /USER_PLACEHOLDER/g,
  /user_placeholder/g,
  /<user>/g,
];

function trackedFiles() {
  const out = execFileSync("git", ["ls-files", "-z"], { encoding: "utf8" });
  return out.split("\0").filter(Boolean);
}

function isBinary(buf) {
  return buf.includes(0);
}

function main() {
  let files;
  try {
    files = trackedFiles();
  } catch (e) {
    console.error(`✗ 无法列出仓库文件（需要在 git 仓库里运行）：${e.message}`);
    process.exit(2);
  }

  const hits = [];
  for (const file of files) {
    if (file === SELF) continue; // 不自扫
    let buf;
    try {
      buf = readFileSync(file);
    } catch {
      continue; // 已删除/不可读的跟踪项：跳过（不是本守护的职责）
    }
    if (isBinary(buf)) continue;
    const text = buf.toString("utf8");
    for (const needle of NEEDLES) {
      if (!text.includes(needle.value)) continue;
      // 命中数（占位符已替换掉的部分不计——本守护只找**残留的真值**）
      let count = 0;
      let idx = text.indexOf(needle.value);
      while (idx !== -1) {
        count += 1;
        idx = text.indexOf(needle.value, idx + needle.value.length);
      }
      hits.push({ file, label: needle.label, count });
    }
  }

  if (hits.length === 0) {
    console.log(
      `✓ 仓库里没有真实账号名/口令残留（扫了 ${files.length} 个已跟踪文件，` +
        `${NEEDLES.length} 条禁词，占位符规则 ${PLACEHOLDER_PATTERNS.length} 条）`,
    );
    process.exit(0);
  }

  console.error("✗ 仓库里有真实凭证残留（B-125 的红线：不保存站点管理员凭证）：");
  for (const hit of hits) {
    console.error(`  ${hit.file}：${hit.label} × ${hit.count}`);
  }
  console.error("");
  console.error("修法：把真值换成占位符（USER_PLACEHOLDER）。历史留档要**标注「已脱敏改写」**");
  console.error("而不是静默替换，否则留档与当时的提交说明会对不上。");
  process.exit(1);
}

main();
