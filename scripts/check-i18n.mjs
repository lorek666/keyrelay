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
