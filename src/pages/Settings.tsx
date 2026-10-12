import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Save } from "lucide-react";
import { getSettings, updateSettings, type Settings } from "../lib/api";

const PRESETS = [
  { label: "关闭", value: 0 },
  { label: "5 分钟", value: 300 },
  { label: "15 分钟", value: 900 },
  { label: "1 小时", value: 3600 },
];

export default function SettingsPage() {
  const qc = useQueryClient();
  const current = useQuery({ queryKey: ["settings"], queryFn: getSettings });
  const [draft, setDraft] = useState<Settings | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (current.data && draft === null) setDraft(current.data);
  }, [current.data, draft]);

  const save = useMutation({
    mutationFn: (settings: Settings) => updateSettings(settings),
    onSuccess: async (saved) => {
      setError(null);
      setNotice("已保存。定时刷新间隔的变更在**下次启动**生效。");
      setDraft(saved);
      await qc.invalidateQueries({ queryKey: ["settings"] });
    },
    onError: (err: Error) => {
      setNotice(null);
      setError(err.message);
    },
  });

  const dirty =
    draft !== null &&
    current.data !== undefined &&
    JSON.stringify(draft) !== JSON.stringify(current.data);

  return (
    <section>
      <h2>设置</h2>
      <p className="muted">
        所有设置都存在本地数据库里，不上传任何地方。
      </p>

      {notice ? <p className="ok" role="status">{notice}</p> : null}
      {error ? (
        <p className="error" role="alert">
          <AlertTriangle size={14} aria-hidden /> {error}
        </p>
      ) : null}

      {draft === null ? (
        <p className="muted">加载中…</p>
      ) : (
        <>
          <div className="card">
            <h3>自动刷新</h3>
            <p className="muted">
              默认关闭：KeyRelay 不会替你做任何定时联网。
              开启后会在后台按间隔刷新已登录站点的余额与密钥列表，失败只记事件、不打断循环。
            </p>
            <div className="row">
              {PRESETS.map((preset) => (
                <button
                  key={preset.value}
                  type="button"
                  className={
                    draft.refreshIntervalSecs === preset.value
                      ? "btn btn-primary"
                      : "btn"
                  }
                  onClick={() =>
                    setDraft({ ...draft, refreshIntervalSecs: preset.value })
                  }
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </div>

          <div className="card">
            <h3>余额告警</h3>
            <label className="field">
              <span>余额低于该值时告警（USD，0 = 不告警）</span>
              <input
                className="input"
                type="number"
                min={0}
                step="0.5"
                value={draft.balanceAlertThreshold}
                onChange={(e) =>
                  setDraft({
                    ...draft,
                    balanceAlertThreshold: Number(e.target.value),
                  })
                }
              />
            </label>
          </div>

          <div className="card">
            <h3>启动检查</h3>
            <label className="checkline">
              <input
                type="checkbox"
                checked={draft.driftCheckOnStart}
                onChange={(e) =>
                  setDraft({ ...draft, driftCheckOnStart: e.target.checked })
                }
              />
              <span>
                启动时检查投递目标是否被外部改动（只读本地文件，不联网）
              </span>
            </label>
          </div>

          <div className="row">
            <button
              type="button"
              className="btn btn-primary"
              disabled={!dirty || save.isPending}
              onClick={() => save.mutate(draft)}
            >
              <Save size={14} aria-hidden /> 保存
            </button>
            {dirty ? <span className="muted">有未保存的修改</span> : null}
          </div>
        </>
      )}
    </section>
  );
}
