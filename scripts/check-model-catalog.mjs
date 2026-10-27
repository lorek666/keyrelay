#!/usr/bin/env node
/**
 * 模型名单守护（M47-S2）。
 *
 * 为什么要有这个脚本：`catalog/models.json` 会随 `main` 分支**立刻**下发到所有客户端，
 * 写错一个字（负价格、0 窗口、拼错的协议名）影响的不是 CI，而是所有用户下次同步后的
 * 投递行为。所以把「客户端会宽容跳过的那些条目」在仓库侧变成**红灯**。
 *
 * 三条与仓内其它守护一致的约定：
 * 1. **先自证数量再下结论**：解析出几条、跳过几条都要打出来，不能只说「缺哪个」；
 * 2. **解析不出东西就当坏**（exit 2），不当成通过；
 * 3. 日志单调：先 ✓，第一处 ✗ 之后只打失败，不穿插 ✓。
 *
 * 用法：node scripts/check-model-catalog.mjs
 * 退出码：0 = 通过；1 = 有不合规条目；2 = 文件缺失 / 不是 JSON / 结构不对。
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const root = fileURLToPath(new URL("..", import.meta.url));
const path = join(root, "catalog", "models.json");

/** 客户端支持的 schema 版本（`crates/tianshu-relay-core/src/model_catalog.rs`）。 */
const MAX_SCHEMA_VERSION = 1;
const PROTOCOLS = ["openai_chat", "openai_responses", "anthropic_messages", "gemini"];
const LEVELS = ["off", "low", "medium", "high", "xhigh"];
const CURRENCIES = ["USD", "CNY"];

let text;
try {
  text = readFileSync(path, "utf8");
} catch (err) {
  console.error(`✗ 读不到 ${path}: ${err.message}`);
  process.exit(2);
}

let doc;
try {
  doc = JSON.parse(text);
} catch (err) {
  console.error(`✗ catalog/models.json 不是合法 JSON: ${err.message}`);
  process.exit(2);
}

const failures = [];
function bad(message) {
  failures.push(message);
}

if (!Number.isInteger(doc.schemaVersion)) {
  console.error("✗ 缺少整数 schemaVersion");
  process.exit(2);
}
if (doc.schemaVersion < 1) {
  bad(`schemaVersion=${doc.schemaVersion} 必须 ≥ 1`);
}
if (doc.schemaVersion > MAX_SCHEMA_VERSION) {
  bad(`schemaVersion=${doc.schemaVersion} 高于客户端支持的 ${MAX_SCHEMA_VERSION}`);
}
if (!Array.isArray(doc.models)) {
  console.error("✗ 缺少 models 数组");
  process.exit(2);
}

const total = doc.models.length;
if (total === 0) {
  bad("models 是空的：客户端会一直用内置名单，这份文件等于没发");
}
const seen = new Map();
let withThinking = 0;
let withPrice = 0;
let skipped = 0;

for (const [index, model] of doc.models.entries()) {
  const at = `models[${index}]`;
  const before = failures.length;

  const id = typeof model?.id === "string" ? model.id.trim() : "";
  if (id === "") {
    bad(`${at}: id 为空`);
  } else if (id !== id.toLowerCase()) {
    bad(`${at}: id "${id}" 必须小写（规范化后按小写匹配）`);
  } else if (seen.has(id)) {
    bad(`${at}: id "${id}" 与 models[${seen.get(id)}] 重复`);
  } else {
    seen.set(id, index);
  }

  const ctx = model?.limits?.contextWindow;
  const out = model?.limits?.maxOutputTokens;
  for (const [name, value] of [
    ["limits.contextWindow", ctx],
    ["limits.maxOutputTokens", out],
  ]) {
    if (!Number.isInteger(value) || value <= 0) {
      bad(`${at} (${id || "?"}): ${name} 必须是正整数，实际 ${JSON.stringify(value)}`);
    } else if (value > 4_294_967_295) {
      // Rust 侧是 u32，超了整条会被跳过；这里必须同样红。
      bad(`${at} (${id || "?"}): ${name} 超出 u32 上限，客户端会跳过整条`);
    }
  }

  const protocol = model?.protocol?.upstream;
  if (!PROTOCOLS.includes(protocol)) {
    bad(`${at} (${id || "?"}): protocol.upstream 非法（${JSON.stringify(protocol)}）`);
  }
  if (
    model?.protocol?.anthropicCompatible !== undefined &&
    typeof model.protocol.anthropicCompatible !== "boolean"
  ) {
    bad(`${at} (${id || "?"}): protocol.anthropicCompatible 必须是布尔`);
  }

  if (model?.aliases !== undefined) {
    if (!Array.isArray(model.aliases)) {
      bad(`${at} (${id || "?"}): aliases 必须是数组`);
    } else if (model.aliases.some((a) => typeof a !== "string" || a.trim() === "")) {
      bad(`${at} (${id || "?"}): aliases 里有空值或非字符串`);
    } else {
      // 别名撞车 = 两个模型抢同一个名字，查表结果取决于遍历顺序（等于随机）。
      for (const alias of model.aliases) {
        const key = alias.trim().toLowerCase();
        if (seen.has(key) && seen.get(key) !== index) {
          bad(`${at} (${id || "?"}): 别名 "${alias}" 与 models[${seen.get(key)}] 撞车`);
        } else if (!seen.has(key)) {
          seen.set(key, index);
        }
      }
    }
  }

  // 输出上限大于窗口本身没有意义：Rust 侧会整条跳过（`parse_model`），这里必须同样红，
  // 否则 CI 放过的数据到客户端会静默消失。
  const limits = model?.limits;
  if (
    Number.isInteger(limits?.contextWindow) &&
    Number.isInteger(limits?.maxOutputTokens) &&
    limits.maxOutputTokens > limits.contextWindow
  ) {
    bad(`${at} (${id || "?"}): maxOutputTokens 不能大于 contextWindow`);
  }

  if (model?.thinking) {
    const thinking = model.thinking;
    if (thinking.supported !== true) {
      // `supported: false` 是合法写法（显式声明不支持），只是不计数。
    } else {
      withThinking += 1;
      if (!["thinking", "reasoning_effort"].includes(thinking.param)) {
        bad(`${at} (${id || "?"}): thinking.param 非法（${JSON.stringify(thinking.param)}）`);
      }
      if (!Array.isArray(thinking.levels) || thinking.levels.length === 0) {
        bad(`${at} (${id || "?"}): thinking.levels 必须是非空数组`);
      } else {
        const unknown = thinking.levels.filter((l) => !LEVELS.includes(l));
        if (unknown.length > 0) {
          bad(`${at} (${id || "?"}): thinking.levels 含未知档位 ${unknown.join(", ")}`);
        }
        if (!thinking.levels.some((l) => l !== "off")) {
          bad(`${at} (${id || "?"}): thinking.levels 只有 off，等于不支持——要么删掉 thinking，要么补档位`);
        }
      }
      if (thinking.defaultLevel !== undefined && !LEVELS.includes(thinking.defaultLevel)) {
        bad(`${at} (${id || "?"}): thinking.defaultLevel 非法`);
      }
      // 默认档必须真的在 levels 里、且不能是 off：Rust 侧会把越界的默认档静默 clamp 到
      // max_level，clamp 掉的是「维护者写错了」这件事实，界面却照常显示，属于坏味道。
      if (
        thinking.defaultLevel !== undefined &&
        Array.isArray(thinking.levels) &&
        !thinking.levels.includes(thinking.defaultLevel)
      ) {
        bad(`${at} (${id || "?"}): thinking.defaultLevel 不在 levels 里`);
      }
      if (thinking.defaultLevel === "off") {
        bad(`${at} (${id || "?"}): thinking.defaultLevel 不能是 off（关掉思考就别声明 supported）`);
      }
      if (thinking.budgetTokens !== undefined) {
        if (typeof thinking.budgetTokens !== "object" || thinking.budgetTokens === null) {
          bad(`${at} (${id || "?"}): thinking.budgetTokens 必须是对象`);
        } else {
          for (const [key, value] of Object.entries(thinking.budgetTokens)) {
            if (!LEVELS.includes(key) || !Number.isInteger(value) || value <= 0) {
              bad(`${at} (${id || "?"}): thinking.budgetTokens.${key} 非法（需正整数）`);
            }
          }
          // 两种形态的预算表必须各就各位，写错位置是「静默不生效」而不是报错：
          // - thinking（预算形态）：网关按这张表把 budget_tokens 映射成档位，缺表 ⇒
          //   任何预算都折成 low，等于把用户的预算请求悄悄降级；
          // - reasoning_effort（枚举形态）：网关不读预算表（不替用户猜档位），写了是死数据。
          const hasBudget = Object.keys(thinking.budgetTokens).length > 0;
          if (thinking.param === "thinking") {
            if (!hasBudget) {
              bad(`${at} (${id || "?"}): param=thinking 必须给 budgetTokens（否则预算折算不出来）`);
            }
            if (
              thinking.defaultLevel !== undefined &&
              thinking.budgetTokens[thinking.defaultLevel] === undefined
            ) {
              bad(
                `${at} (${id || "?"}): param=thinking 的 defaultLevel（${thinking.defaultLevel}）缺对应预算`
              );
            }
          } else if (thinking.param === "reasoning_effort" && hasBudget) {
            bad(`${at} (${id || "?"}): param=reasoning_effort 不接受 budgetTokens（网关不按预算猜档位）`);
          }
        }
      } else if (thinking.param === "thinking") {
        bad(`${at} (${id || "?"}): param=thinking 必须给 budgetTokens`);
      }
    }
  }

  if (model?.prices !== undefined) {
    if (!Array.isArray(model.prices)) {
      bad(`${at} (${id || "?"}): prices 必须是数组`);
    } else {
      if (model.prices.length > 0) withPrice += 1;
      for (const [pi, price] of model.prices.entries()) {
        if (!CURRENCIES.includes(price?.currency)) {
          bad(`${at} (${id || "?"}) prices[${pi}]: currency 必须是 USD 或 CNY`);
        }
        for (const field of ["inputPerMTok", "outputPerMTok", "cacheReadPerMTok"]) {
          const value = price?.[field];
          if (value === undefined) continue;
          if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
            bad(`${at} (${id || "?"}) prices[${pi}]: ${field} 必须是有限的非负数`);
          }
        }
        if (typeof price?.inputPerMTok !== "number" || typeof price?.outputPerMTok !== "number") {
          bad(`${at} (${id || "?"}) prices[${pi}]: 必须同时给 inputPerMTok 与 outputPerMTok`);
        }
      }
    }
  }

  if (failures.length > before) skipped += 1;
}

console.log(`· 名单版本 schemaVersion=${doc.schemaVersion}，生成于 ${doc.generatedAt ?? "（未填）"}`);
console.log(`· 解析到 ${total} 条模型：含思考档位 ${withThinking} 条，含价格 ${withPrice} 条`);
console.log(`· 有问题的条目：${skipped} 条`);

if (failures.length === 0) {
  console.log("✓ catalog/models.json 结构与取值全部合规");
  process.exit(0);
}
for (const failure of failures) {
  console.error(`✗ ${failure}`);
}
process.exit(1);
