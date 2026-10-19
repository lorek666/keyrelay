#!/usr/bin/env node
/**
 * 章程 ↔ 产物齐全性守护（B-169，M16-S8 复审发现）。
 *
 * 背景：`M16-S0` 章程 §1.1 把 B-125 指派给 **M16-S8**，而 S8 是唯一没落 spec 的步骤；
 * 波次收口时也没人对着「章程列了 S1…S8」逐个数。结果代码在 `919d3b9` 就交付了（含守护脚本），
 * `docs/specs/M16-S8-*` 与 `docs/reviews/M16-S8-*` 直到 2026-10-18 才补（spec 明确标为
 * 「追认定稿」）。本脚本把这条收口检查固化成守护：**章程点名的每个本波 step，都必须同时有
 * spec 与复审两份文件**。
 *
 * 三条与既有守护一致的约定（对齐 `check-commands.mjs` 的写法）：
 * 1. **先自证数量，再下结论**：解析出几个 step、找到几份 spec / 几份 review，三个数先打出来。
 *    只报「缺哪个」不报总数，读者就无从发现解析本身漏了 —— 这正是 B-169 批评的老毛病
 *    （`check-commands.mjs` §8 的调用点计数自证是同一条教训的产物）。
 * 2. **解析不出东西就当坏，不当成通过**：找不到章程文件 / 目录缺失 / 解析出 0 个 step ⇒ exit 2。
 * 3. **日志单调**：所有 ✓ 打在前面，从第一处 ✗ 起只打失败，不穿插 ✓（P3-17 口径）。
 *
 * 范围裁定（**为什么只断言「本里程碑」的 step**）：
 * 章程里会出现两种 `M<n>-S<m>` 引用 —— ① **本波指派的 step**（「**收了** → M16-S8」、
 * 派工表里的包），② **跨里程碑的上下文引用**（依赖的前置 Step、代码基线、上一波的转出项）。
 * 只有 ① 是「章程列出的 step 清单」——B-169 原话是「对着『章程列了 S1…S8』逐个数」，
 * S1…S8 都是**同一里程碑内**的序号。把 ② 也断言会产生一片假红：例如 M16-S0 章程把
 * `M15-S1`（**没有独立 spec 的上一波收尾步**）写进基线行，断言它必须有 spec 毫无意义。
 * 判据因此收窄为：**token 的里程碑号 == 章程文件自己文件名里的里程碑号**。
 * 被排除的跨里程碑 token 数量会打进自证行（见下），不静默丢。
 *
 * 已知边界（如实记，不假装修了）：
 * - **按文件名前缀匹配，不按内容判定**：一份叫 `M8-S5A-调试余项收口.md` 的 spec 就算数，
 *   哪怕它其实没有验收标准；一份叫 `M6-S7-PRD覆盖度审计.md` 的复审文件也算 M6-S7 的复审，
 *   哪怕标题里没有「复审」二字。判「是不是合格的 spec/复审」超出本脚本职责（那是复审者的活）。
 * - **章程里的裸序号引用抓不到**：M16-S0 章程正文写作「S8 是唯一没落 spec 的步骤」
 *   （没有 `M16-` 前缀）。这类引用解析不出来，只能靠带完整 token 的那些行。
 * - **不判定「这一步该不该有产物」**：章程写「留待 M5-S7（下一波）」时，M5-S7 没有 spec 是
 *   **符合章程的**，本脚本仍会报红。所以每条缺失都带 `章程文件:行号 + 原文行**，
 *   读的人当场就能判「这是真缺口还是章程自述不需要」——不替人做这个判断。
 *
 * 用法：node scripts/check-charter-steps.mjs
 * 退出码：0 = 章程点名的本波 step 都有 spec + 复审；1 = 有缺失（逐条给出 文件:行号）；
 *         2 = 脚本自身错误（目录缺失 / 找不到章程 / 解析出 0 个 step）。
 */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// 用 `import.meta.url` 解析仓库根，**不**用 `process.cwd()`：从子目录跑时
// （`cd scripts && node check-charter-steps.mjs`）cwd 会变，`docs/specs` 就找不到了。
// `check-no-real-credentials.mjs` 踩过同类的坑（`git ls-files` 的范围随 cwd 走，
// M16-S8 复审闭环 P1-3），这里一开始就绕开。
const root = fileURLToPath(new URL("..", import.meta.url));
const SPECS_DIR = join(root, "docs", "specs");
const REVIEWS_DIR = join(root, "docs", "reviews");

/**
 * `M<里程碑>-S<序号>[ab]?`。
 *
 * **`i` 标志是必须的，不是装饰**：不带 `i` 时 `M8-S5A` 只会匹配到 `M8-S5`（`[ab]` 字符类
 * 默认只认小写），于是章程里 5 处 `M8-S5A` 会被替换成一个**不存在的 step** `M8-S5`，
 * 而真正的 `M8-S5A` 一条都断言不到 —— 一个「把存在的 step 漏掉、把不存在的 step 报红」的
 * 解析器。实测（Node 24）：`/M(\d+)-S(\d+)([ab]?)/` 对 `M8-S5A` 给 `M8-S5`，
 * 加 `i` 才给 `M8-S5A`。
 */
const STEP_TOKEN = /M(\d+)-S(\d+)([ab]?)/gi;

/** 文件名里的 step 前缀（`M16-S6a-命令层与投递欠账收口.md` → `M16-S6a`）。 */
const FILE_PREFIX = /^(M\d+-S\d+[ab]?)/i;

function fail(message) {
  console.error(`✗ ${message}`);
  process.exitCode = 1;
}

function die(message) {
  console.error(`✗ ${message}`);
  process.exit(2);
}

/** 列出目录里的 `.md` 文件；目录不存在 ⇒ 抛错（由调用方转成 exit 2）。 */
function listMarkdown(dir) {
  return readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".md"))
    .map((entry) => entry.name)
    .sort();
}

/** 取章程自己文件名里的里程碑号（`M16-S0-欠账清零波次章程.md` → 16）。 */
function charterMilestone(fileName) {
  const m = fileName.match(/^M(\d+)-S(\d+)[ab]?-/i);
  return m ? Number(m[1]) : null;
}

// ---------------------------------------------------------------- 1. 读目录与定位章程

let specFiles;
let reviewFiles;
try {
  specFiles = listMarkdown(SPECS_DIR);
  reviewFiles = listMarkdown(REVIEWS_DIR);
} catch (e) {
  die(`读不到 docs/specs 或 docs/reviews（${e.message}）——需要在仓库根跑本脚本`);
}

/**
 * 章程 = `docs/specs/` 下**文件名含「章程」**的 `.md`。
 *
 * 为什么不 grep 全仓：`docs/**` 里有几百处「章程」二字，绝大多数是别的文件**引用**章程
 * （spec 的「上游」行、复审记录的「章程依据」）。把引用方也当章程，等于把实现记录当章程，
 * 断言面会被稀释到没有意义。文件名含「章程」是本仓库既有的命名事实（M5-S0 / M6-S0 /
 * M7-S0 / M8-S0 / M9-S7 / M16-S0 六份）。
 */
const charters = specFiles.filter((name) => name.includes("章程"));
if (charters.length === 0) {
  die(
    `在 docs/specs/ 里找不到文件名含「章程」的文件（现有 ${specFiles.length} 个 md）——` +
      `解析面为空，不能当作通过`,
  );
}

// ------------------------------------------------- 2. 解析章程点名的「本波 step」

/**
 * 每个契约步骤的 token：出现在哪些章程的哪几行（带原文，报缺失时直接给出上下文）。
 * @type {Map<string, {token: string, seen: Array<{charter: string, line: number, text: string}>}>}
 */
const steps = new Map();
/** 被排除的跨里程碑 token（只计数 + 记样本，不纳入断言）。 */
const crossMilestone = new Map();
/** 被排除的「本章程自述不用产物」的 token（只计数 + 记样本，不纳入断言，见下）。 */
const waived = new Map();
/** 被排除的「非派工行」（变更记录表 / 散文提及 / 写域表），逐条可点名。 */
const nonAssignment = [];

/**
 * 章程**自述**「这一步不产生 spec/复审」的三类措辞：
 *
 * 1. `转出给别的波次` —— 「留待 **M5-S7（下一波）**」「后续 M9-S8 / M9-S9 波次」
 *    （把工作推给将来，那一步的产物归将来的波次负责）。
 * 2. `引用别处的现成产物` —— M6-S0 章程 §3 写「M6-S7 审计 | `channel-forge` |
 *    `docs/reviews/M6-S7-PRD覆盖度审计.md`」，产物路径已经直接给出，且不是 `<step>-复审` 前缀。
 * 3. `指认一次已完成的实测轮次` —— M9-S7 章程 §4 写「（M9-S6 §7）」，指的是
 *    `docs/evidence/m9s6-real-site-response-shapes.md`（一份既有的探测记录，不是新的 step 包）。
 *
 * **为什么豁免而不是报红**：B-169 的诉求是「章程列出的 step 必须有 spec+复审」，
 * 这三类都是**章程自己说清了这一步不由本波次出产物**——照报红就是假红，
 * 假红会训练大家绕过守护。豁免的理由必须写在这一行字面里（下面就是），
 * 命中即计数并打进自证行，**不静默丢**：读者能看见「被豁免了几个、为什么」。
 *
 * 反向约束（这条豁免不放宽真缺口）：M16-S0 章程把 B-125 指派给 S8 用的是
 * 「**收了** → M16-S8」，不含豁免措辞 ⇒ 仍然会被断言（B-169 原型场景守住）。
 */
const WAIVER_PATTERNS = [
  // ① 转出给将来 / 别的波次
  /留待/,
  /后续\s*M\d+-S\d+/,
  /下一波/,
  /按严重度分批/,
  // ②③ 引用了现成产物路径（docs/reviews|specs|evidence/<lowercase-token>.md）
  // **`-` 必须在字符类外写成字面量**：`M\d+[Ss]\d+` 漏了连字符，实测对 `M6-S7` 恒 false
  // （`/[Mm]\d+[Ss]\d+/.test("M6-S7")` → false），整条豁免会静默失效。
  /docs\/(reviews|specs|evidence)\/[Mm]\d+-[Ss]\d+/,
  // 措辞指认一次已完成实测轮次（「（M9-S6 §7）」「见 M9-S6 实测」）
  /M\d+-S\d+[ab]?\s*(§|实测|证据)/,
];

/**
 * 行型判别（B-180）：**只有「派工行」里的本波 step 才纳入断言**。
 *
 * 为什么必须判行型：M23-S2 首版按「章程里出现的本波 token」一刀切断言，结果把三类
 * **不是派工**的提及也断言了，制造 4 个假红：
 *
 * 1. **变更记录表**（`| v1.5 | 2026-10-12 | …M6-S7… |`）：记录的是「哪一版章程改了什么」，
 *    里面的 token 是**被提及的既存 step**，不是本波派的工。M6-S7 由此假红
 *    （它的产物 `docs/reviews/M6-S7-PRD覆盖度审计.md` 就在，只是名字不叫 `-复审`）。
 * 2. **散文提及**（「见 M9-S6 §7」「`docs/M8-收口记录.md:6`」）：上下文引用。
 * 3. **写域表 / 冻结接口表 / 裁决表**（`| \`routing.rs\` | **M8-S1** | … |`、
 *    `| 1 | DEBUG §2.1 | … | M8-S1 | … |`）：它们确实与派工有关，但同一 step 的派工
 *    在派工表（首格是 step token、或含「收了/转」的行）里已经断言过，不重复断言。
 *
 * **派工的两种行型**（本仓库 6 份章程都用这两种）：
 * - **首格就是 step token**（M5-S0 §3 / M6-S0 §3 / M7-S0 §5 / M8-S0 §6 的派工表、
 *   M8-S0 §1 的「条目 → 处置」表）：`| M5-S1 | 导出与脱敏纵深防御 | B-60 … | … |`。
 * - **同行含指派动词**（「**收了** → M8-S1」「转 **M7-S6**」）：M8-S0 §1 每行都是。
 *
 * 判据（保守，宁可漏报也要少假红；**漏报的那部分由自证行点名补偿**）：
 * - 必须是 Markdown 表格数据行（`|` 开头）；
 * - 首格**不是**版本号（排除变更记录表）——**先判这一步**，否则
 *   `| v1.1 | … 并入 … M8-S5A … |`（M8-S0:319，首格 `v1.1`、含「转」义）会被当成派工；
 * - 且满足二者之一：① 首格含本行的 step token；② 同行含指派动词
 *   （`收了` / `转 <Mx-Sy>` / `归属` / `待定` / `未参与本波次` / `按同一规则派` /
 *   `停止写入后派` / `与 S1–S4 并行` / `复审者 =`）。
 *
 * **反向约束（为什么不能只按「首格是不是版本号」一刀切）**：M16-S0:53 的
 * `| B-107 \`M7-S6\` 从未产出 \| … \| **收了** → 本波以 M16-S5/S6b/S7 承接 \|`
 * 首格是 `B-107` 不是版本号、且含「收了」⇒ 它是**本波派的工**，必须照常断言
 * （它断言的目标 token 是同里程碑的 M16-S*，这条判据保住了 B-169 的原型场景）。
 */
const TABLE_ROW = /^\s*\|/;
const CHANGELOG_FIRST_CELL = /^v\d+(\.\d+)*$/i;
const ASSIGNMENT_VERB =
  /收了|转\s*\*{0,2}\s*M\d+-S\d+|归属|待定|未参与本波次|按同一规则派|停止写入后派|与 S1[–\-]S\d+\s*\*{0,2}并行|复审者\s*[=＝]/;
/** 去掉 markdown 强调符与反引号，只留给「首格是什么」做字面比较。 */
const stripEmphasis = (cell) => cell.replace(/[`*_~]/g, "").trim();

/**
 * 这一行是不是「派工行」？
 *
 * `token` 是**当前正在判断的那个 step token**——首格判据要用它：派工表的首格
 * 正是 `M5-S1` / `M8-S5A 调试余项收口（§3.6）` 这种「token + 标题」的形态。
 */
function isAssignmentRow(raw, token) {
  if (!TABLE_ROW.test(raw)) return false;
  const firstCell = stripEmphasis(raw.split("|")[1] ?? "");
  // 先排除变更记录表：`| v1.5 | 2026-10-12 | … |`。顺序不可交换（见上面注释）。
  if (CHANGELOG_FIRST_CELL.test(firstCell)) return false;
  // 形态①：首格就是 token（或「token + 标题」）
  if (firstCell.startsWith(token)) return true;
  // 形态②：同行有指派动词
  return ASSIGNMENT_VERB.test(raw);
}

/**
 * 章程**自身**不需要 spec 之外的复审文件：`M5-S0-加固波次章程.md` 这类文件名本身就是
 * `docs/specs/<step>-*.md`，它既是章程也是该 step 的 spec；而「复审本章程」没有意义
 * （M5-S0 / M6-S0 / M7-S0 / M8-S0 / M9-S7 五份都如此）。
 *
 * 判据在下面的主循环里：**章程文件名自己的 token** 出现在该文件的第 1 行（标题行）。
 * 为什么不按「S0 后缀」判：M16-S0 也是 S0，但本仓库有 `M16-S1…S8` 的完整波次，
 * S0 判据在别处可能误伤；按「自己的文件名」判只命中真正的那一份。
 */


for (const charter of charters) {
  const milestone = charterMilestone(charter);
  const text = readFileSync(join(SPECS_DIR, charter), "utf8");
  const lines = text.split("\n");
  // 本章程自身的 step token（如 `M16-S0-欠账清零波次章程.md` → `M16-S0`）
  const selfToken = charter.match(/^(M\d+-S\d+[ab]?)-/i)?.[1] ?? null;
  lines.forEach((raw, index) => {
    // 每行重新 new 一个正则：带 `g` 的正则对象有 lastIndex 状态，跨行复用会漏匹配
    const re = new RegExp(STEP_TOKEN.source, STEP_TOKEN.flags);
    for (const m of raw.matchAll(re)) {
      const token = m[0];
      const record = { charter, line: index + 1, text: raw.trim() };
      if (milestone !== null && Number(m[1]) !== milestone) {
        if (!crossMilestone.has(token)) crossMilestone.set(token, []);
        crossMilestone.get(token).push({ charter, line: index + 1 });
        continue;
      }
      // 章程自己（自身 token，无论出现在标题行还是元信息行）：它本身就是 spec，
      // 不要求独立复审文件。判据用「token == 本章程文件名里的 token」，与出现在第几行无关
      // （M9-S7 的 token 在标题行，M5-S0 的在第 5 行「Step：M5-S0（章程，本身不产出产品代码）」）。
      if (token === selfToken) {
        if (!waived.has(token)) waived.set(token, []);
        waived.get(token).push(record);
        continue;
      }
      // B-180 行型判别：非派工行（变更记录表 / 散文 / 写域表）里的提及不进断言集。
      // 逐条记进 `nonAssignment`（含 文件:行号 + 原文），由自证行点名输出——
      // 漏报不能静默，否则「排除」就成了「放水」的别名。
      if (!isAssignmentRow(raw, token)) {
        nonAssignment.push({ ...record, token });
        continue;
      }
      if (WAIVER_PATTERNS.some((p) => p.test(raw))) {
        if (!waived.has(token)) waived.set(token, []);
        waived.get(token).push(record);
        continue;
      }
      if (!steps.has(token)) steps.set(token, { token, seen: [] });
      steps.get(token).seen.push(record);
    }
  });
}

const asserted = [...steps.keys()].sort();
if (asserted.length === 0) {
  die(
    `从 ${charters.length} 份章程里解析出 0 个待断言的本波 step（` +
      `另有 ${crossMilestone.size} 个跨里程碑引用、${waived.size} 个被豁免 token、` +
      `${nonAssignment.length} 处非派工行提及）——` +
      `解析器坏了，不能当作通过。请检查 STEP_TOKEN 正则与 charterMilestone() 的里程碑号提取`,
  );
}

/**
 * 「非派工行」的自证输出。
 *
 * 设计取舍：**不逐条列 200 多处**。按 token 聚合，每个 token 一行：
 * ① 它有没有在**别处**以派工行进入断言集（有 ⇒ 这次排除无损，只是「同一 step 被多次提及」）；
 * ② 只列**前 3 个**行号，够定位即可。
 *
 * 为什么不能只给个数：B-180 的教训是「排除」很容易变成「放水」的别名。所以每个 token
 * 都必须能被点名核对——尤其是**从未以派工行出现**的那些（`onlyExcluded`），
 * 它们提示「章程只在散文里提过这一步」。
 */
function reportNonAssignment(assertedTokens) {
  if (nonAssignment.length === 0) return;
  const byToken = new Map();
  for (const r of nonAssignment) {
    if (!byToken.has(r.token)) byToken.set(r.token, []);
    byToken.get(r.token).push(r);
  }
  const all = [...byToken.keys()].sort();
  const assertedSet = new Set(assertedTokens);
  const onlyExcluded = all.filter((t) => !assertedSet.has(t));
  console.log(
    `  （自证）未纳入断言的 ${nonAssignment.length} 处非派工行提及，涉及 ${all.length} 个 token` +
      `（其中 ${onlyExcluded.length} 个**从未**以派工行出现）：`,
  );
  for (const token of all) {
    const rs = byToken.get(token);
    const shown = rs.slice(0, 3).map((r) => `${r.charter}:${r.line}`);
    const more = rs.length > 3 ? ` 等 ${rs.length} 处` : "";
    const note = assertedSet.has(token) ? "" : "　← 只在非派工行出现过，未被断言";
    console.log(`    - ${token}（${shown.join("、")}${more}）${note}`);
  }
}


// --------------------------------------------- 3. 给 spec / review 建 step → 文件 索引

/** `Map<token, 文件名[]>`；`TEMPLATE.md` 这类没有 step 前缀的文件自然不会进来。 */
function indexByStep(fileNames) {
  const index = new Map();
  for (const name of fileNames) {
    const m = name.match(FILE_PREFIX);
    if (!m) continue;
    const token = m[1];
    if (!index.has(token)) index.set(token, []);
    index.get(token).push(name);
  }
  return index;
}

const specOf = indexByStep(specFiles);
const reviewOf = indexByStep(reviewFiles);

/**
 * `docs/specs/<step>-*.md` 里**内嵌独立复审记录**的 step。
 *
 * 为什么要有这一层：M8 波次的约定是「复审记录在各包 spec 的『独立复审记录』节」
 * （`docs/M8-收口记录.md:6`），M8-S5B / M8-S6 / M8-S7 三份 spec 确实各有一节
 * `## N. 独立复审记录（<复审者名>，<日期>）`。只认 `docs/reviews/<step>-*` 就会把这三份
 * 判成「缺复审」——**假红**。
 *
 * 判据（保守）：spec 正文里出现形如
 * `独立复审记录` / `## 独立复审` 的**小节标题**，且同行/邻行含一个**外在于作者名的
 * 复审者标识**。这里只做「有内嵌复审节」的存在性判定，**不**判它写得合不合格
 * （那是复审者的活，超出守护职责）。
 */
function embeddedReviewTokens() {
  const tokens = new Set();
  for (const [token, files] of specOf) {
    const hasEmbeddedReview = files.some((file) => {
      const text = readFileSync(join(SPECS_DIR, file), "utf8");
      // 形如 `## 6. 独立复审记录（`adapter-hardening`，2026-10-14）`
      // 或 `### 17.3 复审者清单` + 修订记录里的「独立复审后修三条」
      // **`m` 标志是必须的**：少了它 `^` 只匹配字符串开头，标题在文中 ⇒ 恒 false，
      // 整条内嵌识别会静默失效（实测踩过）。
      return (
        /^#{2,3}\s*\d*\.?\s*独立复审记录/m.test(text) ||
        /^#{2,3}\s*\d*\.?\s*独立复审/m.test(text)
      );
    });
    if (hasEmbeddedReview) tokens.add(token);
  }
  return tokens;
}

const embeddedReview = embeddedReviewTokens();

// ------------------------------------------------------------ 4. 自证数量（先打总数）

const specCovered = asserted.filter((t) => specOf.has(t)).length;
const reviewCovered = asserted.filter((t) => reviewOf.has(t)).length;
const unreferencedSpecs = [...specOf.keys()].filter((t) => !steps.has(t)).sort();
const unreferencedReviews = [...reviewOf.keys()].filter((t) => !steps.has(t)).sort();

console.log(
  `✓ 章程文件 ${charters.length} 份：${charters.join("、")}`,
);
console.log(
  `✓ 解析出 ${asserted.length} 个章程点名的本波 step；另有 ${crossMilestone.size} 个跨里程碑引用未纳入断言`,
);
reportNonAssignment(asserted);
console.log(
  `✓ docs/specs 命中 ${specCovered}/${asserted.length} 个 step、` +
    `docs/reviews 命中 ${reviewCovered}/${asserted.length} 个 step`,
);

// 未被任何章程点名的产物（不是失败，是边界提示：说明「有产物但章程没列」或「章程还没写」）
const sample = (arr) => (arr.length > 6 ? `${arr.slice(0, 6).join("、")}…` : arr.join("、"));
if (unreferencedSpecs.length || unreferencedReviews.length) {
  console.log(
    `  （提示，不算失败）不被任何章程点名：spec ${unreferencedSpecs.length} 份` +
      `${unreferencedSpecs.length ? `（${sample(unreferencedSpecs)}）` : ""}、` +
      `review ${unreferencedReviews.length} 份` +
      `${unreferencedReviews.length ? `（${sample(unreferencedReviews)}）` : ""}`,
  );
}

// -------------------------------------------------------------------- 5. 逐条断言

const missingSpec = [];
const missingReview = [];
for (const token of asserted) {
  if (!specOf.has(token)) missingSpec.push(token);
  // 复审在 `docs/reviews/<step>-*` 或 spec 内嵌的「独立复审记录」节里，二者有一即可
  if (!reviewOf.has(token) && !embeddedReview.has(token)) missingReview.push(token);
}

const describe = (token) => {
  // 同一 step 可能在章程里出现多次；报**第一次**出现的行，足够定位
  const first = steps.get(token).seen[0];
  const text = first.text.length > 90 ? `${first.text.slice(0, 90)}…` : first.text;
  return `${token}（章程 ${first.charter}:${first.line}：「${text}」）`;
};

if (missingSpec.length) {
  fail(
    `章程点名、但 docs/specs/ 里没有对应前缀文件的 step（${missingSpec.length} 个）：\n` +
      missingSpec.map((t) => `  ${describe(t)}`).join("\n"),
  );
}
if (missingReview.length) {
  fail(
    `章程点名、但 docs/reviews/ 里没有对应前缀文件的 step（${missingReview.length} 个）：\n` +
      missingReview.map((t) => `  ${describe(t)}`).join("\n"),
  );
}

if (missingSpec.length === 0 && missingReview.length === 0) {
  console.log(
    `\n✓ 章程点名的 ${asserted.length} 个本波 step 全都有 spec + 复审两份文件。`,
  );
} else {
  console.error(
    "\n章程 step 产物齐全性检查未通过。",
  );
  console.error(
    "处置：缺 spec ⇒ 该 step 按 docs/PROCESS.md §2 补 spec（先写）再动代码；",
  );
  console.error(
    "　　　缺复审 ⇒ 由未参与实现的复审者补 docs/reviews/<step>-复审.md。",
  );
  console.error(
    "　　　若某一条是**章程自述不需要产物**（如「留待下一波」），改章程的措辞或销账，",
  );
  console.error(
    "　　　不要靠把脚本放水来消红——上面每条都带了 章程文件:行号，可当场核对。",
  );
}
