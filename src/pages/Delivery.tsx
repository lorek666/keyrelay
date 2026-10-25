import Agents from "./Agents";
import History from "./History";

/**
 * 投递中心（M45-S6）：Agent 通道表 + 投递记录合流为一个入口，只换入口归属。
 * 与 M45-S4 健康中心渲染 `Probe.tsx`、M45-S5 资产中心渲染 `Sites`/`Keys` 同一模式：
 * 两组件零改动，通道、安装、更新、授权、解绑、投递、回滚逻辑全部保持原样；
 * Agent 入口与历史入口在本步 retire。`Agents.tsx` 内的 `AgentIcon`（19 条可投递通道含
 * DeepSeek Harness，缺失兜底首字母色块；cline-desktop 已下线，检测保留但不在此列）亦未动。
 */
export default function Delivery() {
  return (
    <section className="page">
      <Agents />
      <History />
    </section>
  );
}
