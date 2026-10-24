import Sites from "./Sites";
import Keys from "./Keys";

/**
 * 资产中心（M45-S5）：站点表 + 密钥表合流为资产库，只换入口归属。
 * 与 M45-S4 健康中心渲染 `Probe.tsx` 同一模式：两组件零改动，行为、表单、校验、
 * 能力门控、余额列、轮换、同步逻辑全部保持原样；站点/密钥入口在本步 retire。
 */
export default function Assets() {
  return (
    <section className="page">
      <Sites />
      <Keys />
    </section>
  );
}
