import type { ReactNode } from "react";

type Props = {
  /** 能力集里对应的那一格。`false` ⇒ 灰显（`disabled`）。 */
  allowed: boolean;
  /** `allowed === false` 时告诉用户**为什么**（文案来自 M7-S2 spec §3.3 的映射表）。 */
  reason: string;
  /** 与能力无关的临时禁用（例如「正在执行」）。它**不**改变 `title` 里的原因。 */
  busy?: boolean;
  className?: string;
  onClick?: () => void;
  children: ReactNode;
};

/**
 * 能力驱动的按钮（M7-S5 / W5）。
 *
 * 判断**只**来自 `SiteCapabilities`，页面里不得出现「哪个 `kind` 不支持什么」——
 * 那种硬编码在新增站点类型时必然漏一处，而漏掉的那处会给出一个「点了才报错」的按钮，
 * 报的错还是别的原因（例如「未登录」）。
 *
 * **灰显而不是隐藏**：用户要能看见「这个功能存在，但这个站点类型不支持」，
 * 否则会以为是产品缺陷（M7-S2 §3.3）。
 *
 * 原因挂在外层 `<span title>`：禁用的按钮在部分浏览器里不弹 `title`，
 * 那样灰显就等于没说明原因。（`index.css` 不在本包写域，所以外层只用无样式的 `span`：
 * 它在 `.row` 里是一个普通的 flex 项，不改变既有排版。）
 */
export default function CapButton({
  allowed,
  reason,
  busy = false,
  className = "btn",
  onClick,
  children,
}: Props) {
  return (
    <span title={allowed ? undefined : reason}>
      <button
        type="button"
        className={className}
        disabled={!allowed || busy}
        onClick={onClick}
      >
        {children}
      </button>
    </span>
  );
}
