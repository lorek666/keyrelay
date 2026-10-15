import { translate, getCurrentDict } from "../i18n";

/**
 * 回滚成功之后必须告诉用户的事（M9-S4 复审 P2-1 / BACKLOG B-126）。
 *
 * 回滚只还原文件、不动绑定。只要那个 agent 还绑着，漂移检测拿「KeyRelay 最后写下的内容」去比，
 * 回滚后的文件必然对不上：总览会一直把它列为「需要处理」，每打开一次总览还会记一条
 * 「外部改动」告警；轮换这把密钥时它会被重新写入，批量改指网关时它也仍在候选里（逐条勾选，默认不勾）。
 * 更伤人的一条（复审 N-2）：如果回滚把文件还原成了更早一次投递写下的**另一把**密钥，漂移与轮换眼里的
 * 「现状」仍是被回滚的这次——轮换或回收那把更早的密钥时，这个文件不会被重写，agent 会留在一把已被回收的
 * 密钥上。这是 M3-S1 的既定语义（改不改由 B-126 决定）——在那之前，至少要把后果说全。
 *
 * 投递页与历史页两处回滚共用这一句：此前两处说法不一，投递页那处一个字都没提。
 *
 * M14-S2：文案抽成 i18n key `rollback.aftermath`（带 {agent} 插值）。
 */
export function rollbackAftermath(agentId: string): string {
  return translate(getCurrentDict(), "rollback.aftermath", { agent: agentId });
}
