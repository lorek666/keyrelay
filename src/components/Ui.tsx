import { useId, type ReactNode } from "react";
import { ArrowUpRight, LoaderCircle } from "lucide-react";

export function StatusDot({ tone = "muted" }: { tone?: "ok" | "warn" | "danger" | "muted" | "accent" }) {
  return <span className={`status-dot status-dot-${tone}`} aria-hidden="true" />;
}

export function PageIntro({ children }: { children: ReactNode }) {
  return <p className="page-intro">{children}</p>;
}

export function SectionHeader({
  title,
  description,
  action,
}: {
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="section-header">
      <div className="section-heading">
        <h2>{title}</h2>
        {description ? <p>{description}</p> : null}
      </div>
      {action ? <div className="section-actions">{action}</div> : null}
    </div>
  );
}

export function MetricCard({
  label,
  value,
  detail,
  icon,
  tone = "default",
  onClick,
}: {
  label: ReactNode;
  value: ReactNode;
  detail?: ReactNode;
  icon: ReactNode;
  tone?: "default" | "ok" | "warn" | "danger" | "accent";
  onClick?: () => void;
}) {
  const labelId = useId();
  const valueId = useId();
  const content = (
    <>
      <div className="metric-topline">
        <span className={`metric-icon metric-icon-${tone}`}>{icon}</span>
        {onClick ? <ArrowUpRight className="metric-link" size={16} aria-hidden="true" /> : null}
      </div>
      <div className="metric-value" id={valueId}>{value}</div>
      <div className="metric-label" id={labelId}>{label}</div>
      {detail ? <div className="metric-detail">{detail}</div> : null}
    </>
  );
  const className = `metric-card metric-${tone}`;
  return onClick ? (
    <button type="button" className={className} aria-labelledby={`${valueId} ${labelId}`} onClick={onClick}>
      {content}
    </button>
  ) : (
    <div className={className}>{content}</div>
  );
}

export function InlineNotice({
  tone,
  children,
}: {
  tone: "success" | "warning" | "danger" | "info";
  children: ReactNode;
}) {
  return (
    <div className={`inline-notice notice-${tone}`} role={tone === "danger" ? "alert" : "status"}>
      {children}
    </div>
  );
}

export function BusyLabel({ busy, children }: { busy: boolean; children: ReactNode }) {
  return (
    <>
      {busy ? <LoaderCircle className="spin" size={15} aria-hidden="true" /> : null}
      {children}
    </>
  );
}
