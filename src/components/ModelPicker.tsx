import { useQuery } from "@tanstack/react-query";
import { listKeyModels } from "../lib/api";
import { useTranslation } from "../i18n";

/**
 * 行内模型控件（M32-S1）。
 *
 * 抽成组件是为了**在组件内调 `useQuery`**——直接在 `CHANNELS.map` 里调 hook 会违反 hooks 规则
 * （行数随 `CHANNELS` 变化时会崩）。
 *
 * 五种状态（spec §4.3）：
 *   未选密钥 → 禁用 select（只有占位项）
 *   查询中   → 禁用 select（显示「加载模型…」）
 *   成功非空 → select；**已保存但不在清单**的 model 追加为同值 option 并保持选中
 *   失败     → 回退 input + 「模型清单获取失败，可手动输入」
 *   成功但空 → 回退 input + 「该分组没有可用模型，可手动输入」
 *
 * 失败/为空时**回退而不是禁用**：站点不支持 `/v1/models` 很常见，模型名不该因此填不了。
 */
export type ModelPickerProps = {
  /** 该行选中的本地 key id；`null` 表示还没选 */
  keyId: number | null;
  /** 当前已保存的模型名 */
  value: string;
  onChange: (next: string) => void;
  disabled?: boolean;
  /** 无障碍名称（默认「模型名」；调用方会带上通道名以区分同页多个下拉） */
  ariaLabel?: string;
};

export default function ModelPicker({
  keyId,
  value,
  onChange,
  disabled = false,
  ariaLabel,
}: ModelPickerProps) {
  const { t } = useTranslation();
  const label = ariaLabel ?? t("agents.select.model");

  const models = useQuery({
    queryKey: ["keyModels", keyId],
    queryFn: () => listKeyModels(keyId!),
    enabled: keyId !== null,
    staleTime: 5 * 60 * 1000,
    retry: false,
  });

  // 未选密钥：没有查询可发，给一个禁用下拉，与既有「先选密钥」的引导一致
  if (keyId === null) {
    return (
      <select className="input agent-row-model" aria-label={label} disabled>
        <option value="">{t("agents.select.modelPlaceholder")}</option>
      </select>
    );
  }

  if (models.isLoading) {
    return (
      <select className="input agent-row-model" aria-label={label} disabled>
        <option value="">{t("agents.select.modelLoading")}</option>
      </select>
    );
  }

  const failed = models.isError;
  const list = models.data ?? [];

  if (failed || list.length === 0) {
    return (
      <span className="agent-row-model-fallback">
        <input
          className="input agent-row-model"
          aria-label={label}
          value={value}
          placeholder={t("agents.select.modelPlaceholder")}
          spellCheck={false}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
        />
        <span className="muted agent-row-model-hint">
          {failed ? t("agents.select.modelFetchFailed") : t("agents.select.modelEmpty")}
        </span>
      </span>
    );
  }

  // 已保存的模型不在新清单里（换分组 / 站点改了清单）⇒ 追加同值选项并保持选中，
  // **不静默清空**用户之前的选择。
  const missingSaved = value !== "" && !list.includes(value);

  return (
    <select
      className="input agent-row-model"
      aria-label={label}
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value)}
    >
      <option value="">{t("agents.select.modelPlaceholder")}</option>
      {missingSaved ? <option value={value}>{value}</option> : null}
      {list.map((m) => (
        <option key={m} value={m}>
          {m}
        </option>
      ))}
    </select>
  );
}
