import { useEffect, useRef, type ReactNode } from "react";
import { useTranslation } from "../i18n";

type Props = {
  open: boolean;
  title: string;
  /** 危险操作会把确认按钮标红 */
  danger?: boolean;
  confirmLabel?: string;
  /** 确认按钮是否可用（例如「必须先勾选同意」） */
  confirmDisabled?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
  children: ReactNode;
};

/**
 * 二次确认 / 同意弹窗。
 *
 * 用原生 `<dialog>` 是为了白拿「焦点陷阱 + Esc 关闭」，避免自己实现出错。
 * 注意：**不做**任何密钥相关的处理，`children` 里的内容由调用方保证已脱敏。
 *
 * M14-S2：`title` / `confirmLabel` 由调用方传 `t(...)`；默认确认文案走 `confirm.confirm`。
 */
export default function ConfirmDialog({
  open,
  title,
  danger = false,
  confirmLabel,
  confirmDisabled = false,
  onCancel,
  onConfirm,
  children,
}: Props) {
  const { t } = useTranslation();
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    const onNativeCancel = (event: Event) => {
      event.preventDefault();
      onCancel();
    };
    dialog.addEventListener("cancel", onNativeCancel);
    return () => dialog.removeEventListener("cancel", onNativeCancel);
  }, [onCancel]);

  return (
    <dialog ref={ref} className="dialog" aria-label={title}>
      <h2>{title}</h2>
      <div className="dialog-body">{children}</div>
      <div className="dialog-actions">
        <button type="button" className="btn" onClick={onCancel}>
          {t("confirm.cancel")}
        </button>
        <button
          type="button"
          className={danger ? "btn btn-danger" : "btn btn-primary"}
          disabled={confirmDisabled}
          onClick={onConfirm}
        >
          {confirmLabel ?? t("confirm.confirm")}
        </button>
      </div>
    </dialog>
  );
}
