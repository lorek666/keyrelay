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
// 3. 只扫 `git ls-files` 的**已跟踪**文件。**边界是入库内容（索引），不是工作树**（BACKLOG B-170：
//    旧版读工作树 blob，`git add` 一个含真值的文件再把工作树改回干净 ⇒ 守护 exit 0 —— 实测复现过）。
//    现在读 `git ls-files -s` 的 sha → `git cat-file --batch` 的 blob 内容，
//    即「下一次 `git commit` 会写进去的那份字节」。差别与代价见 `trackedBlobs()` 的注释。
//
// 用法：node scripts/check-no-real-credentials.mjs
// 退出码：0 = 干净；1 = 命中；2 = 脚本自身错误（例如不在 git 仓库里）。

import { execFileSync, spawnSync } from "node:child_process";
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

function trackedBlobs() {
  // `--full-name` 让路径恒为**仓库根相对**（否则从子目录跑会带上前缀）。
  //
  // **`cwd: repoRoot()` 是必须的**：`git ls-files` 的**范围**随 cwd 走，`--full-name` 只改
  // 路径写法、不改范围。实测 `cd scripts && node check-no-real-credentials.mjs` 只扫 14 个
  // 文件、仍打印 ✓ 并 exit 0（仓库根是 531）——一个「跑在子目录就静默缩小扫描面」的守护
  // 比没有守护更糟（M16-S8 复审闭环 P1-3）。
  //
  // **边界是索引，不是工作树**（B-170）：`-s` 让我们拿到每个 stage-0 条目的 blob sha，
  // 内容从 `git cat-file --batch` 读。理由：
  //   ① 「入库内容」才是这条红线要守的东西——`git add` 之后、提交之前的那份字节。
  //      旧版读工作树 ⇒ `git add` 一个含真值的文件、再把工作树改回干净 ⇒ 守护 exit 0
  //      （工单里的原场景，改动前实测复现：exit 0）。
  //   ② 工作树与索引不一致时（半提交状态），读索引的那份是**确定**的；读工作树则要回答
  //      「算哪一份」——而那恰是争议所在。
  // 代价（如实记）：不覆盖「已 `git add` 但 sha 还没落盘」这一种不可能状态（sha 由 add 写入），
  // 也不覆盖工作树里**未跟踪**的新文件（边界之外，与旧版一致）。
  const out = execFileSync("git", ["ls-files", "-s", "-z", "--full-name"], {
    encoding: "utf8",
    cwd: repoRoot(),
  });
  return out
    .split("\0")
    .filter(Boolean)
    .map((line) => {
      // 形态：`<mode> <sha> <stage>\t<path>`
      const tab = line.indexOf("\t");
      const meta = tab === -1 ? line : line.slice(0, tab);
      const path = tab === -1 ? "" : line.slice(tab + 1);
      const sha = meta.split(" ")[1];
      return { path, sha };
    })
    .filter((entry) => entry.sha && entry.path);
}

/**
 * 用**一次** `git cat-file --batch` 把给定 sha 的 blob 内容读出来。
 *
 * `--batch` 就是为这种「几百个已知 sha、逐个取内容」的场景设计的：一次子进程、一条 stdin
 * 流水线，比逐文件 fork 快一个量级（旧版是 500+ 次 `readFileSync`，这次是 1 次 spawn）。
 * 输入格式是 `<sha>\n`（空行结束）；输出是若干个 `<sha> <type> <size>\n<二进制内容>\n` 段。
 *
 * 返回值按 sha 索引；batch 输出解析失败（sha 不存在 / 格式不认识）时该 sha **缺席**，
 * 由调用方按「读不到就跳过」处理（与旧版 `readFileSync` 失败时 continue 同口径）。
 */
function readBlobs(shas) {
  if (shas.length === 0) return new Map();
  const proc = spawnSync("git", ["cat-file", "--batch"], {
    input: `${shas.join("\n")}\n`,
    cwd: repoRoot(),
    maxBuffer: 1024 * 1024 * 1024,
  });
  if (proc.error) throw proc.error;
  if (proc.status !== 0) {
    throw new Error(
      `git cat-file --batch 失败（exit ${proc.status}）：${String(
        proc.stderr,
      ).trim()}`,
    );
  }
  const out = Buffer.isBuffer(proc.stdout) ? proc.stdout : Buffer.from(proc.stdout ?? "");
  const blobs = new Map();
  let offset = 0;
  while (offset < out.length) {
    const headerEnd = out.indexOf("\n", offset);
    if (headerEnd === -1) break;
    const header = out.toString("utf8", offset, headerEnd);
    const parts = header.split(" ");
    const sha = parts[0];
    const size = Number.parseInt(parts[2] ?? "", 10);
    if (parts[1] !== "blob" || Number.isNaN(size)) {
      // 形如 `<sha> missing` 或解析不了 ⇒ 不让整棵守护挂掉，跳过这一条
      offset = headerEnd + 1;
      continue;
    }
    const content = out.subarray(headerEnd + 1, headerEnd + 1 + size);
    blobs.set(sha, content);
    offset = headerEnd + 1 + size + 1; // 内容后还有一个换行
  }
  return blobs;
}

function isBinary(buf) {
  return buf.includes(0);
}

function main() {
  let entries;
  let root;
  try {
    root = repoRoot();
    entries = trackedBlobs();
  } catch (e) {
    console.error(`✗ 无法列出仓库文件（需要在 git 仓库里运行）：${e.message}`);
    process.exit(2);
  }

  let blobs;
  try {
    // 去重：同一个 blob 被多处引用时只读一次（同一 sha 内容必然相同）
    blobs = readBlobs([...new Set(entries.map((e) => e.sha))]);
  } catch (e) {
    console.error(`✗ 读不到索引内容（git cat-file --batch 失败）：${e.message}`);
    process.exit(2);
  }

  const hits = [];
  let scanned = 0;
  let unreadable = 0;
  for (const { path: file, sha } of entries) {
    // 不自扫。两边都解析成绝对路径再比：初版写成 `file === SELF` 是**恒假**的
    // （`git ls-files` 给相对路径、`SELF` 是绝对路径），那条 continue 从不触发
    // ⇒ 谁把禁词字面量写进本脚本，守护就会命中自己（M16-S8 复审 P1-1）。
    const abs = resolve(root, file);
    if (abs === SELF) continue;
    const buf = blobs.get(sha);
    if (buf === undefined) {
      // 索引里指向的 blob 读不到（理论上只有仓库损坏才会发生）。不当作通过——
      // 但也不就此中断：逐条累计，最后在输出里报告数量。
      unreadable += 1;
      continue;
    }
    scanned += 1;
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

  if (unreadable > 0) {
    console.error(
      `✗ 有 ${unreadable} 个索引条目读不到 blob（仓库可能损坏）——不当作干净放行`,
    );
    process.exit(2);
  }

  if (hits.length === 0) {
    console.log(
      `✓ 仓库里没有真实账号名/口令残留（扫了 ${scanned} 个索引里的已跟踪文件` +
        `（共 ${entries.length} 条），${NEEDLES.length} 条禁词）`,
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
