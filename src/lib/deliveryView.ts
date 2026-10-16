import type { DeliveryField } from "./api";

/**
 * 投递预览的展示层派生（M16-S6b）。
 *
 * 两个都是**纯函数**：不碰 React、不碰网络、不读全局状态 ⇒ 能被 vitest 直接测。
 */

/**
 * 这份计划里有没有写「agent 该往哪发请求」的字段。
 *
 * 用途：网关模式下，有的通道**只写令牌、不写 endpoint**（例如 `codex-auth-json` 写的是
 * `~/.codex/auth.json` 里的 `auth_mode` + `OPENAI_API_KEY`，没有 base_url 字段；
 * `dsh` 同理）。这种通道里打开「指向本地网关」时，agent 仍会把请求发到**站点**，
 * 拿的是本地网关令牌 ⇒ 站点回 401。用户看不出这一点，因为开关文案对所有通道是同一句。
 *
 * 判据**来自数据**（计划里实际要写的字段名），不是按通道名硬编码——后者在新增通道时
 * 必然漏一处，而漏掉的那处会给出一个错的生效预期。
 *
 * 后端若将来在 DTO 上给出显式字段（例如 `endpointManaged`），应改为读它；
 * 在那之前，字段名是唯一可得的数据（M8-S4 spec §4.3 承诺的
 * `codex_channel_reports_that_the_endpoint_is_out_of_scope` 在仓库里尚不存在）。
 */
export function planWritesEndpoint(fields: DeliveryField[]): boolean {
  return fields.some((f) => /base[_-]?url|endpoint|api[_-]?base/i.test(f.key));
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
