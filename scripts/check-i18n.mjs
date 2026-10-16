#!/usr/bin/env node
/**
 * M14-S2 i18n 守护：扫描 src 下 .tsx/.ts，确保无硬编码中文 UI 文案残留。
 *
 * 规则：
 * - 扫描 src 下所有 .tsx 与 .ts 文件（含 src/lib/api.ts）。
 * - 排除注释：块注释（含 JSX 块注释）与行注释，用逐行 stripLine 维护跨行块状态。
 * - 排除行尾标记 i18n:skip 的行（豁免 mock 后端数据、后端错误匹配串）。
 * - 排除 src/i18n 目录（字典本身含中文）与 src/__tests__（测试断言含中文）。
 *
 * 残留则退出码 1，供 pnpm test 使用。
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));

function listFiles(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (name === "i18n" || name === "__tests__" || name === "node_modules") continue;
      listFiles(p, out);
    } else if (/\.(tsx|ts)$/.test(name)) {
      out.push(p);
    }
  }
  return out;
}

/** 逐行去除注释，维护跨行块注释状态。返回该行的非注释代码部分。 */
function stripLine(line, state) {
  let out = "";
  let i = 0;
  while (i < line.length) {
    if (state.inBlock) {
      const end = line.indexOf("*\/", i);
      if (end === -1) return out;
      state.inBlock = false;
      i = end + 2;
    } else {
      const bc = line.indexOf("/*", i);
      const lc = line.indexOf("//", i);
      if (lc !== -1 && (bc === -1 || lc < bc)) {
        out += line.slice(i, lc);
        return out;
      }
      if (bc !== -1) {
        out += line.slice(i, bc);
        state.inBlock = true;
        i = bc + 2;
      } else {
        out += line.slice(i);
        return out;
      }
    }
  }
  return out;
}

const files = listFiles(join(root, "src"));
let bad = 0;
const HAN = /[\u4e00-\u9fff]/;

for (const f of files) {
  const src = readFileSync(f, "utf8");
  const lines = src.split("\n");
  const state = { inBlock: false };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/\/\/\s*i18n:skip/.test(line)) continue;
    const code = stripLine(line, state);
    if (HAN.test(code)) {
      console.error(`✗ ${relative(root, f)}:${i + 1} 硬编码中文: ${line.trim().slice(0, 80)}`);
      bad++;
    }
  }
}

if (bad > 0) {
  console.error(`✗ ${bad} 处硬编码中文残留（抽成 t()/translate()，或加 // i18n:skip 豁免 mock/后端匹配串）`);
  process.exit(1);
}
console.log(`✓ 无硬编码中文 UI 文案残留（src 下 tsx/ts）`);

// ---------------------------------------------------------------- 两侧字典键集合相等（B-128）
//
// 「抽了键 + 补了英文包」这两件事本身不构成守护：英文包漏一个键时，
// `t("x")` 会**静默回退成键名本身**（i18n/index.tsx 的既定行为），
// 界面上就是一行 `agents.notice.delivered`——没有任何东西会红。
// 所以两侧的**键集合必须相等**，插值占位符也要一致（漏一个插值 = 文案缺一块）。

const dicts = {
  "zh-CN": JSON.parse(readFileSync(join(root, "src/i18n/zh-CN.json"), "utf8")),
  "en-US": JSON.parse(readFileSync(join(root, "src/i18n/en-US.json"), "utf8")),
};

/** 嵌套字典展平成 `a.b.c` → 值。 */
function flatten(obj, prefix = "", out = new Map()) {
  for (const [key, value] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (value && typeof value === "object" && !Array.isArray(value)) {
      flatten(value, path, out);
    } else {
      out.set(path, value);
    }
  }
  return out;
}

/** `{name}` / `{count}` 这类插值占位符。 */
function placeholders(value) {
  if (typeof value !== "string") return [];
  return [...value.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1]).sort();
}

const flatZh = flatten(dicts["zh-CN"]);
const flatEn = flatten(dicts["en-US"]);
const zhKeys = [...flatZh.keys()].sort();
const enKeys = [...flatEn.keys()].sort();
const problems = [];

for (const key of zhKeys.filter((k) => !flatEn.has(k))) {
  problems.push(`  en-US 缺键: ${key}`);
}
for (const key of enKeys.filter((k) => !flatZh.has(k))) {
  problems.push(`  zh-CN 缺键: ${key}`);
}
/** 允许「一侧是空值、另一侧不是」的键（逐条声明，加一行即一次可见改动）。 */
const BLANK_ONE_SIDE_OK = new Set([
  // 靠语序拼句的片段：中文这里是「的目标」三个字，英文靠前后片段 + 一个空格就能成句
  // （见 Overview.tsx 的 hint3Pre/Mid1/Mid2/Post 拼法）。**不是漏译**。
  "overview.drift.hint3Mid1",
]);

for (const key of zhKeys.filter((k) => flatEn.has(k))) {
  const zhValue = flatZh.get(key);
  const enValue = flatEn.get(key);
  // 空值**两侧必须一致**：刻意留空的片段（`sites.table.action` 的空表头）是合法的，
  // 但「中文有字、英文忘了填」不是——那正是这条守护要抓的。
  // 个别靠语序拼句的片段在 BLANK_ONE_SIDE_OK 里逐条豁免。
  const zhBlank = typeof zhValue === "string" && zhValue.trim() === "";
  const enBlank = typeof enValue === "string" && enValue.trim() === "";
  if (zhBlank !== enBlank && !BLANK_ONE_SIDE_OK.has(key)) {
    problems.push(
      `  一侧是空值而另一侧不是: ${key}（zh ${zhBlank ? "空" : "非空"} / en ${enBlank ? "空" : "非空"}）`,
    );
  }
  const zhPh = placeholders(zhValue).join(",");
  const enPh = placeholders(enValue).join(",");
  if (zhPh !== enPh) {
    problems.push(`  插值占位符不一致: ${key}（zh: [${zhPh}] vs en: [${enPh}]）`);
  }
}

if (problems.length) {
  console.error(`✗ 两侧字典不一致（B-128）：\n${problems.join("\n")}`);
  console.error(`  zh-CN ${zhKeys.length} 键 / en-US ${enKeys.length} 键`);
  process.exit(1);
}
console.log(`✓ 中英字典键集合与插值一致（${zhKeys.length} 键）`);
