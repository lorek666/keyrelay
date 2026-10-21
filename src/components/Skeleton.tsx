/**
 * 骨架屏（M16-S6b / B-129 J）。
 *
 * 此前所有加载态都是一行「加载中…」。它的问题是**布局会跳**：文字占一行，数据回来时
 * 表格/卡片一撑开，整页内容往下蹦——用户正在看的按钮会移走。骨架屏把最终尺寸先占住。
 *
 * 纯展示组件，不依赖任何数据；`rows` 决定占位行数，`variant` 决定形状。
 */
export default function Skeleton({
  rows = 3,
  variant = "line",
}: {
  rows?: number;
  variant?: "line" | "card";
}) {
  const count = Math.max(1, rows);
  return (
    <div className="skeleton-wrap" aria-hidden data-skeleton-variant={variant}>
      {Array.from({ length: count }, (_, i) => (
        <div
          key={i}
          className={variant === "card" ? "skeleton skeleton-card" : "skeleton"}
        />
      ))}
    </div>
  );
}
