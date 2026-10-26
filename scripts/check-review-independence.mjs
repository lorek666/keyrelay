#!/usr/bin/env node
/**
 * 复审记录的**独立性声明**守护（M24-S3 / B-181③④）。
 *
 * 为什么需要它：B-181 的 ③（门禁取数与复审解耦）与 ④（复审期作者只读）此前只是
 * `内部文档库 docs/PROCESS.md` 里的散文 + 聊天里的约定。散文没有承载物：一份复审记录里
 * **看不出**「复审者是谁、跑没跑门禁、作者当时能不能写文件」——
 * 于是「复审发生了」与「复审被跳过了」在文件层面**不可区分**（B-182 的教训）。
 *
 * 判据是结构性的（不判散文）：
 *   1. 文件里有 `## 0.` 段；
 *   2. 该段里出现三个键：`复审者` / `是否参与本步实现` / `门禁数字来源`；
 *   3. `是否参与本步实现` 的值必须含「否」——写「是」等于自认不独立，直接红。
 *
 * **纳入范围**：波次号 ≥ 24 的 `*-复审.md`（M24 起）。
 * 历史（M0–M23）的复审记录**不纳入**，原因是它们写在新模板之前、且当年的事实多数已查不到；
 * 为了不制造「填空式回填」，这里按**波次号**豁免而不是维护一张会腐烂的白名单。
 * 豁免不是静默的：运行时逐条列出文件名（B-182：任何排除都必须可点名）。
 *
 * 用法：node scripts/check-review-independence.mjs
 * 退出码：0 = 全部合规；1 = 有缺失 / 自认不独立 / 解析到 0 份（解析器坏了不许静默通过）；2 = 脚本自身错误。
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

/** 从 M24 起要求独立性声明。 */
const FIRST_GUARDED_WAVE = 24;
const REVIEWS_DIR = "docs/reviews";
/** 只断言「复审记录」本体；`-复审闭环.md` 是复审者的追加说明，不重复要求 §0。 */
const REVIEW_FILE = /^(M(\d+)-S\d+[ab]?.*)-复审\.md$/;
// 三键是「独立性」的最小集；④（复审期作者只读）是 §6.2 的**唯一书面承载物**，
// 不守护它 ⇒ 一份记录可以声称「作者只读：是」也可以漏写，守护都绿 ⇒ §6.2 形同虚设。
// 所以这里把 ④ 也纳入；它的值必须含「是」或「否」（写「是」不红——只读是合规的，
// 写「否」才需要解释，但本守护不判解释，只判键在）。
const REQUIRED_KEYS = ["复审者", "是否参与本步实现", "门禁数字来源", "复审期作者是否只读"];
const INDEPENDENT_VALUE = "是否参与本步实现";

function fail(message) {
  console.error(`✗ ${message}`);
}

/** 取 `## 0.` 段的正文（到下一个 `## ` 或文件末尾）。 */
function sectionZero(text) {
  const lines = text.split("\n");
  const start = lines.findIndex((line) => /^##\s+0[.\s]/.test(line));
  if (start === -1) return null;
  const body = [];
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^##\s+/.test(lines[i])) break;
    body.push(lines[i]);
  }
  return body.join("\n");
}

function main() {
  let entries;
  try {
    entries = readdirSync(REVIEWS_DIR, { withFileTypes: true });
  } catch (error) {
    fail(`读不到 ${REVIEWS_DIR}：${error.message}`);
    return 2;
  }

  const reviewFiles = entries
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .filter((name) => REVIEW_FILE.test(name))
    .sort();

  if (reviewFiles.length === 0) {
    // 解析器坏了（或目录换了）时**不许静默通过** —— 恒绿的守护等于没有守护。
    fail(`${REVIEWS_DIR} 里一份 *-复审.md 都没解析到：守护不可能在「零输入」下成立。`);
    return 1;
  }

  const guarded = [];
  const legacy = [];
  for (const name of reviewFiles) {
    const wave = Number(REVIEW_FILE.exec(name)[2]);
    if (wave >= FIRST_GUARDED_WAVE) guarded.push(name);
    else legacy.push({ name, wave });
  }

  console.log(
    `=== 复审独立性守护（M${FIRST_GUARDED_WAVE} 起）=== 解析到 ${reviewFiles.length} 份 *-复审.md`,
  );
  console.log(`  纳入断言 ${guarded.length} 份；豁免 ${legacy.length} 份（M0–M${FIRST_GUARDED_WAVE - 1}）`);

  if (legacy.length > 0) {
    // B-182：豁免必须**逐条**可点名，不能只报一个数字。
    const byWave = new Map();
    for (const item of legacy) {
      if (!byWave.has(item.wave)) byWave.set(item.wave, []);
      byWave.get(item.wave).push(item.name);
    }
    for (const wave of [...byWave.keys()].sort((a, b) => a - b)) {
      console.log(`    - M${wave}：${byWave.get(wave).join("、")}`);
    }
  }

  const problems = [];
  for (const name of guarded) {
    const path = join(REVIEWS_DIR, name);
    let text;
    try {
      text = readFileSync(path, "utf8");
    } catch (error) {
      problems.push(`${name}：读不到（${error.message}）`);
      continue;
    }
    const body = sectionZero(text);
    if (body === null) {
      problems.push(`${name}：缺 \`## 0.\` 独立性声明段`);
      continue;
    }
    const missing = REQUIRED_KEYS.filter((key) => !body.includes(key));
    if (missing.length > 0) {
      problems.push(`${name}：\`## 0.\` 里缺键 ${missing.map((k) => `「${k}」`).join("、")}`);
      continue;
    }
    // 「是否参与本步实现」的**值**必须以「否」开头；写「是」= 自认不独立。
    // 只判「行里出现过否」会被 `是（虽然…否…）` 这种句子骗过，所以判冒号后的第一个字符。
    const line = body
      .split("\n")
      .find((candidate) => candidate.includes(INDEPENDENT_VALUE)) ?? "";
    const value = line.split(/[：:]/).slice(1).join("：").trim();
    if (!value.startsWith("否")) {
      problems.push(
        `${name}：\`${INDEPENDENT_VALUE}\` 的值必须以「否」开头（原文：${line.trim()}）`,
      );
    }
  }

  if (problems.length > 0) {
    fail(`复审独立性声明不合规（${problems.length} 份）：`);
    for (const problem of problems) console.error(`    - ${problem}`);
    console.error("");
    console.error("模板见 内部文档库 docs/specs/REVIEW-TEMPLATE.md §2；约束见 内部文档库 docs/PROCESS.md §6。");
    return 1;
  }

  console.log(`✓ ${guarded.length} 份新波次复审记录都有合规的 \`## 0.\` 独立性声明。`);
  return 0;
}

process.exit(main());
