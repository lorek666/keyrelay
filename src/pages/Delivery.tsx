import { useState } from "react";
import { History as HistoryIcon, Send } from "lucide-react";
import Agents from "./Agents";
import History from "./History";
import { useTranslation } from "../i18n";

type DeliveryView = "configure" | "history";

/**
 * 投递中心：主任务与历史回滚分视图，但沿用原有 Agents / History 组件。
 * 已访问的面板保持挂载，往返历史不会丢失未确认的预览与通道筛选。
 * 授权、预览、写入、回滚、解绑和更新逻辑仍由各自组件负责。
 */
export default function Delivery() {
  const { t } = useTranslation();
  const [view, setView] = useState<DeliveryView>("configure");
  const [historyVisited, setHistoryVisited] = useState(false);
  const openView = (next: DeliveryView) => {
    setView(next);
    if (next === "history") setHistoryVisited(true);
  };

  return (
    <section className="page delivery-page" data-delivery-view={view}>
      <div className="delivery-view-tabs" role="tablist" aria-label={t("delivery.navigation")}>
        <button
          type="button"
          role="tab"
          id="delivery-tab-configure"
          aria-selected={view === "configure"}
          aria-label={t("delivery.configure")}
          aria-describedby="delivery-tab-configure-hint"
          aria-controls="delivery-panel-configure"
          tabIndex={view === "configure" ? 0 : -1}
          onClick={() => openView("configure")}
          onKeyDown={(event) => {
            if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
              event.preventDefault();
              openView("history");
              document.getElementById("delivery-tab-history")?.focus();
            }
          }}
        >
          <Send size={16} aria-hidden="true" />
          <span>
            <strong>{t("delivery.configure")}</strong>
            <small id="delivery-tab-configure-hint">{t("delivery.configureHint")}</small>
          </span>
        </button>
        <button
          type="button"
          role="tab"
          id="delivery-tab-history"
          aria-selected={view === "history"}
          aria-label={t("delivery.history")}
          aria-describedby="delivery-tab-history-hint"
          aria-controls="delivery-panel-history"
          tabIndex={view === "history" ? 0 : -1}
          onClick={() => openView("history")}
          onKeyDown={(event) => {
            if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
              event.preventDefault();
              openView("configure");
              document.getElementById("delivery-tab-configure")?.focus();
            }
          }}
        >
          <HistoryIcon size={16} aria-hidden="true" />
          <span>
            <strong>{t("delivery.history")}</strong>
            <small id="delivery-tab-history-hint">{t("delivery.historyHint")}</small>
          </span>
        </button>
      </div>
      <div
        role="tabpanel"
        id="delivery-panel-configure"
        aria-labelledby="delivery-tab-configure"
        className="delivery-view-panel"
        hidden={view !== "configure"}
      >
        <Agents />
      </div>
      {historyVisited ? (
        <div
          role="tabpanel"
          id="delivery-panel-history"
          aria-labelledby="delivery-tab-history"
          className="delivery-view-panel"
          hidden={view !== "history"}
        >
          <History />
        </div>
      ) : null}
    </section>
  );
}
