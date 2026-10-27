# 模型名单（catalog/models.json）

天枢 Relay 的内置模型名单，是这些参数的**优先数据源**：客户端名单页、投递时自动带入的
上下文 / 最大输出 / 思考档位与价格说明，以及成本估算的默认价格。未覆盖模型仍可使用
内置 `model_meta` 表和 models.dev 的窗口/输出兜底；查不到就是未知，不猜。
协议字段描述模型原生能力；本地网关负责把客户端协议转换为 OpenAI Chat，不会把 Responses
客户端配置盲目改写成名单中的另一种协议。

当前（2026-10-27）收录 **20 家厂商的 133 个模型**，覆盖 OpenAI、Anthropic、Google、xAI、
DeepSeek、Qwen、GLM、Kimi、MiniMax、Mistral、Meta、Cohere、Perplexity、Amazon Nova、
豆包、混元、MiMo、StepFun、Nemotron 与 LongCat。窗口 / 最大输出与原生协议按 models.dev 的
公开元数据整理，并对主流模型与各厂商文档做了交叉核对；没有逐项核实的价格与思考能力保持未知，不猜。

OpenAI GPT 系列的窗口统一按中转站常见的 **272K** 封顶（模型文档的 API 窗口更大）；
这是投递保守值，不是模型原生上限。

## 名字怎么匹配（先看这个）

客户端把用户填的模型名规范化后再查表：

```
zcode/GLM-5.3-Flash[1m]  →  glm-5.3-flash
OpenAI/GPT-4o            →  gpt-4o
claude-3-5-sonnet-20241022 → claude-3-5-sonnet（逐段剥尾）
```

规则：`trim → 小写 → 去 vendor/ 前缀 → 去 [..] 后缀 → 精确命中 → 逐段剥尾`。
所以中转站那种「带前缀 + 带方括号」的写法不用写进名单，只要 `id` 或 `aliases` 里有能命中的名字即可。

## 字段

```jsonc
{
  "schemaVersion": 1,              // 客户端只认 <= 自己支持的版本；更高整份忽略
  "generatedAt": "2026-10-27T06:45:00Z",   // 也是「价格生效时间」的兜底
  "minAppVersion": "0.2.1",        // 提示用，不强制
  "notes": "……",
  "models": [
    {
      "id": "glm-5.3-flash",       // 规范名（小写、无前缀、无方括号）——必填
      "displayName": "GLM-5.3-Flash",
      "aliases": ["zcode/GLM-5.3-Flash[1m]"], // 可选，中转站常见写法写这里
      "vendor": "zhipu",
      "protocol": {
        "upstream": "openai_chat", // openai_chat | openai_responses | anthropic_messages | gemini
        "anthropicCompatible": true
      },
      "limits": {
        "contextWindow": 1000000,  // 必填，> 0
        "maxOutputTokens": 128000  // 必填，> 0
      },
      "thinking": {                // 可选；不给 = 未知（**不猜**，投递不写该参数）
        "supported": true,
        "param": "thinking",           // thinking（预算形态，必须给 budgetTokens）
                                       // reasoning_effort（枚举形态，**不要**给 budgetTokens）
        "levels": ["off", "low", "medium", "high"],
        "defaultLevel": "medium",
        "budgetTokens": { "low": 4096, "medium": 16384, "high": 32768 }
      },
      "prices": [                  // 可选；不给 = 未定价（成本估算显示未知，绝不按 0 计）
        { "currency": "USD", "inputPerMTok": 0.5, "outputPerMTok": 2.0,
          "cacheReadPerMTok": 0.1, "effectiveFrom": "2026-10-01" }
      ],
      "deprecated": false
    }
  ]
}
```

### 硬性校验（`node scripts/check-model-catalog.mjs`）

- `schemaVersion` 必须是整数且 ≤ 客户端支持版本；`models` 必须是数组；
- `id` 唯一、非空；`limits.*` 必须是 > 0 的整数；
- `protocol.upstream` 必须是四个枚举值之一；
- `thinking.levels` 只能用那五个档位；只写 `off` 等于「不支持」；
- `thinking.defaultLevel` 必须出现在 `levels` 里、且不能是 `off`；
- `limits.maxOutputTokens` 不得大于 `limits.contextWindow`；两者都不得超过 u32 上限；
- `models` 不能为空；`schemaVersion` 必须 ≥ 1；`id` 与 `aliases` 之间不许撞车；
- 价格：`currency` 只能是 `USD` / `CNY`，单价必须是 ≥ 0 的有限数；
- 任何一条不合格 ⇒ 脚本红（客户端更宽容：**跳过坏条目并计数**，不整份丢弃）。

## 怎么加一个模型

1. 在 `models` 里加一条（上面的模板），`id` 用小写规范名；
2. 中转站用的名字（可能带 `vendor/` 或 `[1m]`）写进 `aliases`；
3. 价格只填**你确认过**的数字——价格写错会直接影响成本估算；
4. 跑 `node scripts/check-model-catalog.mjs`，然后开 PR。

## 客户端怎么用它

- 启动后 20 秒同步一次，之后每 24 小时一次（可在「成本中心 → 内置模型名单」关掉，或点「立即同步」）；
- 拉到 `~/.tianshu-relay/catalog/models.json`（原子写：临时文件 + rename），**失败保留旧缓存**；
- 优先级：**本机覆盖** > GitHub 缓存 > 编译进二进制的这份文件 > models.dev（只补窗口/输出）；
- 投递是同步路径，只读内存快照，**永不在投递途中联网**；
- 名单里的价格只用来「补空缺」：用户手输过的价格永远优先，不会被名单覆盖；本机价格覆盖
  以新生效版本参与成本估算，撤销只清理名单导入价，保留手工价格历史。

## 为什么价格要留空也不要瞎填

成本估算把「没有价格」显示成**未知**。填一个错的数字会让「未知」变成「看起来精确的错数」，
这比承认不知道更糟。所以新条目宁可不写 `prices`。

## 思考档位：只写核对过的事实

同一句「宁可不写」，对 `thinking` 比对 `prices` 更要紧——价格错了只是估算歪，思考能力错了会
**改掉客户端的行为**：

- 名单说支持 ⇒ 投递会往 Claude Code / Codex 的配置里写 `CLAUDE_CODE_EFFORT_LEVEL` /
  `model_reasoning_effort`，网关也会把入站 `thinking` 折算成上游 `reasoning_effort`；
- 名单留空 ⇒ **未知**：不自动写入，也不删除用户手调档位；网关不会擅自开启思考；
- 只有 `supported: false` 或本机覆盖明确选择「关闭」⇒ 才可清理受管客户端的旧档位；
- 名单写错（比如给一个根本没有思考能力的模型写上 `supported: true`）⇒ 客户端开始发一个上游
  不认识的参数，用户看到的是「这个模型 400」，而不是「名单写错了」。

所以：

1. **没核对过官方文档就别写 `thinking`**，留空 = 未知，代价只是「不自动带档位」；
2. `param` 只能二选一，且决定网关怎么折算：
   - `thinking`（Anthropic 的 `budget_tokens` 形态）：**必须**给 `budgetTokens`，网关按这张表把
     预算映射成档位；`defaultLevel` 必须有对应预算；
   - `reasoning_effort`（枚举形态）：**不要**给 `budgetTokens`，网关直接用 `defaultLevel`，
     不按预算猜档位（与投递层同一口径）。
3. `defaultLevel` 必须出现在 `levels` 里，且不能是 `off`。

当前这份内置名单只有 `o1` / `o3` / `o3-mini` 三条声明了思考能力（`reasoning_effort`）。
其它模型不是「不支持」，而是**没核对**——需要时按上面规则补，或用界面上的「本机覆盖」只对
自己那台机器生效。
