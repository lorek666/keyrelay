#!/usr/bin/env node
// M16-S8 · 仓库级凭证卫生守护（B-125）。
//
// 背景：历次「真实站点验证」把真实账号名写进了代码、测试与文档。每次「已脱敏」的声明都只
// 覆盖**当次新增文件**，从没人总的对过账 ⇒ 仓库尺度上一直没闭环（`docs/PROCESS.md` §3
// 「不保存站点管理员凭证」）。M16 做了一次全仓清理（**48 命中行 / 13 文件 / 60 次出现**；
// 复算命令见 `docs/specs/M16-S8-仓库级凭证脱敏闭环.md` §3 的「口径订正」），本脚本防回归。
//
// 设计要点：
// 1. **不自扫**：排除自己——凡是「扫目录/扫自己所在文件」的守护，先问一句「它会不会扫到自己」
//    （M8-S6 的教训）。M22 修正：初版写成 `file === SELF`，而 `git ls-files` 给的是**相对**
//    路径、`SELF` 是**绝对**路径 ⇒ 比较恒假、这条 continue 从不触发（M16-S8 复审 P1-1）。
//    现在两边都解析成绝对路径再比。
// 2. **针在运行时拼**：禁词不在本文件里以字面量出现，否则本脚本自己就会命中。
// 3. 只扫 `git ls-files` 的**已跟踪**文件。读的是工作树内容而非索引 blob（差别见
//    `trackedFiles()` 的注释与 BACKLOG B-170）。
//
// 用法：node scripts/check-no-real-credentials.mjs
// 退出码：0 = 干净；1 = 命中；2 = 脚本自身错误（例如不在 git 仓库里）。

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SELF = fileURLToPath(import.meta.url);

/**
 * 仓库根（惰性求值）。`git ls-files --full-name` 的路径相对于它，读文件与排除自身都按它解析。
 *
 * 不写成模块顶层的 `const ROOT = execFileSync(...)`：不在 git 仓库里时那会在 `main()` 的
 * try/catch 之外抛出，表现为一段堆栈而不是约定的 exit 2。
 */
let REPO_ROOT = null;
function repoRoot() {
  if (REPO_ROOT === null) {
    REPO_ROOT = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      encoding: "utf8",
    }).trim();
  }
  return REPO_ROOT;
}

/** 禁词（运行时拼接，避免本文件自身命中）。 */
const NEEDLES = [
  { label: "真实站点账号名", value: ["test", "user"].join("") },
  { label: "已作废的站点口令", value: ["aa123", "123"].join("") },
  // M18-S1：真机验证时**两次**把真实域名写进了文档与代码注释（第一次在 M17-S1 第二轮入库时
  // 漏了，第二次是本步新写的 spec/module doc）。这类值不是「凭证」，所以旧禁词表抓不到——
  // 但它们同样是「仓库里不该出现的真实标识」，一并守。
  { label: "真实站点域名", value: ["aizhong", "zhuan"].join("") },
  { label: "真机 SSH 私钥文件名", value: ["xinzhuan", "_key"].join("") },
  // M16-S8 复审 P2-1：M17 的真机记录把站点**显示名**写进了证据与 BACKLOG。它同样不是凭证，
  // 但属于「仓库里不该出现的真实标识」（与上面两条同口径）。补针时**必须同时**把出现处换成
  // 占位符——只补针不脱敏会让守护当场红。这正是 spec §9 风险 1 说的「真机收口时补禁词」。
  { label: "真实站点显示名", value: ["天枢", "AI"].join("") },
];

function trackedFiles() {
  // `--full-name` 让路径恒为**仓库根相对**（否则从子目录跑会带上前缀，后面的
  // `resolve(root, file)` 就会拼错）。
  //
  // **`cwd: repoRoot()` 是必须的**：`git ls-files` 的**范围**随 cwd 走，`--full-name` 只改
  // 路径写法、不改范围。实测 `cd scripts && node check-no-real-credentials.mjs` 只扫 14 个
  // 文件、仍打印 ✓ 并 exit 0（仓库根是 531）——一个「跑在子目录就静默缩小扫描面」的守护
  // 比没有守护更糟（M16-S8 复审闭环 P1-3）。
  //
  // 边界：读的是**工作树里**的已跟踪文件，不是索引/HEAD 的 blob。差别见 BACKLOG B-170。
  const out = execFileSync("git", ["ls-files", "-z", "--full-name"], {
    encoding: "utf8",
    cwd: repoRoot(),
  });
  return out.split("\0").filter(Boolean);
}

function isBinary(buf) {
  return buf.includes(0);
}

function main() {
  let files;
  let root;
  try {
    root = repoRoot();
    files = trackedFiles();
  } catch (e) {
    console.error(`✗ 无法列出仓库文件（需要在 git 仓库里运行）：${e.message}`);
    process.exit(2);
  }

  const hits = [];
  for (const file of files) {
    // 不自扫。两边都解析成绝对路径再比：初版写成 `file === SELF` 是**恒假**的
    // （`git ls-files` 给相对路径、`SELF` 是绝对路径），那条 continue 从不触发
    // ⇒ 谁把禁词字面量写进本脚本，守护就会命中自己（M16-S8 复审 P1-1）。
    const abs = resolve(root, file);
    if (abs === SELF) continue;
    let buf;
    try {
      buf = readFileSync(abs);
    } catch {
      continue; // 已删除/不可读的跟踪项：跳过（不是本守护的职责）
    }
    if (isBinary(buf)) continue;
    const text = buf.toString("utf8");
    for (const needle of NEEDLES) {
      if (!text.includes(needle.value)) continue;
      // 命中数（本守护只找**残留的真值**；占位符本身不含信息，不在禁词表里）
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
      `✓ 仓库里没有真实账号名/口令残留（扫了 ${files.length} 个工作树里的已跟踪文件，` +
        `${NEEDLES.length} 条禁词）`,
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
