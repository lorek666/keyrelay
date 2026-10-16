import type { DeliveryMode } from "./api";

/**
 * 投递预览的展示层派生（M16-S6b）。
 *
 * 两个都是**纯函数**：不碰 React、不碰网络、不读全局状态 ⇒ 能被 vitest 直接测。
 */

/**
 * 网关模式下，是否该提示「本通道**不写 endpoint**」。
 *
 * ## 判据**只来自后端字段**（M16-S6b 复审 P2-1 的闭环）
 *
 * `plan.endpointInChannel` 由后端 `delivery::channel_carries_endpoint(channel)` 给出——
 * **与 writer 装配表同源**。这里不再做任何推导：
 *
 * - 曾经有过一版按「计划里字段名」正则猜的实现（`planWritesEndpoint`），它与后端字段
 *   **两套机制并存**：任一侧改动都会分叉，而症状是「提示错了」而不是报错（正是 P2-1 的顾虑）。
 *   该函数已**删除**（不是降级成兜底——兜底等于把第二套机制留着）。
 * - 后端字段是 DTO 的必填项，且由 `check-commands.mjs` 的 B-122 对账**双向**钉住
 *   （Rust DTO 字段集合 == TS 类型键集合）⇒ 正常情况下它**不可能**缺失。
 * - `undefined`（例如前端配了旧二进制）按「**不提示**」处理：宁可不提示，也不给一条
 *   可能错的提示——错提示会把用户引去改一个本来正确的配置。
 *
 * 通道自身的事实（哪条通道真的写 endpoint）由后端负责；**前端不判特例**
 * （例如 DSH 的 `channel_carries_endpoint` 与事实不符一事，已由后端在 `m16/dsh-fix` 修，
 * 前端在这里再判一次就会又变成两套）。
 */
export function shouldWarnEndpointOutOfScope(
  mode: DeliveryMode,
  endpointInChannel: boolean | undefined,
): boolean {
  return mode === "gateway" && endpointInChannel === false;
}

/**
 * 把 diff 预览里**删除行**的值侧掩掉。
 *
 * 为什么需要：`diff_preview` 只对**已知的**密钥串做替换，再走文本层 `scrub`
 * （只认 `sk-` / `nap-` / ≥32 位 hex）。切到网关模式时，被删掉的那一行是**旧站点密钥**，
 * 形态未必落在 `scrub` 认得的集合里 ⇒ 旧明文会原样出现在预览里（DEBUG-REPORT-v3 P2-5）。
 * 后端修法属别的写域；界面这一侧先做到「不把旧值渲染出来」。
 *
 * 规则（可测）：
 * - 只处理以 `- ` 开头、且不是 `---` 的行；`+ ` 行与其它行**逐字节不变**
 *   （新增行是「将要写进去什么」，掩掉它就等于掩盖改动）；
 * - 保留键名与结构，只把值换成占位（`- "K": <占位>` / `- K=<占位>`）；
 * - 找不到分隔符时整行内容换成占位（宁可少显示，不可多泄露）。
 *
 * 占位文案由调用方传入（i18n 键），这样本函数保持纯净、也不含硬编码文案。
 */
export function maskRemovedValues(preview: string, placeholder: string): string {
  return preview
    .split("\n")
    .map((line) => {
      if (!line.startsWith("- ") || line.startsWith("---")) return line;
      const content = line.slice(2);
      const colon = content.match(/^(.*?):\s*(.*)$/);
      if (colon) return `- ${colon[1]}: ${placeholder}`;
      const eq = content.match(/^(.*?)=(.*)$/);
      if (eq) return `- ${eq[1]}=${placeholder}`;
      return `- ${placeholder}`;
    })
    .join("\n");
}
