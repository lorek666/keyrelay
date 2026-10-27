import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";

/**
 * 自研 i18n 运行时（M14-S2）。
 *
 * 不引入 react-i18next——当前主 bundle 余量约 6.8 KB，库本身 10 KB+ 会超线（spec §9.1）。
 * 字典按语言各为独立 JSON chunk，`import()` 动态加载，不内联进主 bundle。
 *
 * 语言取值与 `Settings.language`（M6-S5）对齐：`"zh-CN" | "en-US"`。无 `"system"`——
 * PRD FR-9 即二选一，默认 `zh-CN`。未知值回落 `zh-CN`（不猜，与 `useApplyTheme` 同口径）。
 */

export type Lang = "zh-CN" | "en-US";

/** 字典：嵌套对象，按点号路径取叶子字符串。 */
type Dict = Record<string, unknown>;

type Vars = Record<string, string | number>;

interface I18nValue {
  lang: Lang;
  /** 字典未加载完时为 null（切换语言途中的短暂态）；为 null 时 `t` 回退到 key 本身。 */
  dict: Dict | null;
  t: (key: string, vars?: Vars) => string;
}

const I18nContext = createContext<I18nValue | null>(null);

export const DEFAULT_LANG: Lang = "zh-CN";

/** 把 `settings.language`（可能为未知值 / undefined）规范成两种语言之一。 */
export function normalizeLang(lang: string | undefined): Lang {
  return lang === "en-US" ? "en-US" : "zh-CN";
}

/** 已加载字典缓存：切换来回时不重复 import。 */
const cache = new Map<Lang, Dict>();

/**
 * 模块级当前字典：供非组件场景（`lib/api.ts` 的 `formatGroupRate` / `throw Error`）取用。
 *
 * 由 `I18nProvider` 在加载字典时同步——组件树首次渲染前 `main.tsx` 已预加载 zh-CN 并经
 * `initialDict` 传入，故首次渲染时此处即非 null。后续语言切换由 Provider 的 effect 同步。
 */
let currentDict: Dict | null = null;

/** 非组件代码取当前字典（可能为 null：Provider 未挂载 / 字典未加载完）。 */
export function getCurrentDict(): Dict | null {
  return currentDict;
}

/** 静态映射加载——Vite 据此生成两个独立 JSON chunk，且 TS 能正确推断类型。 */
async function loadDict(lang: Lang): Promise<Dict> {
  const cached = cache.get(lang);
  if (cached) return cached;
  const mod = lang === "en-US" ? await import("./en-US.json") : await import("./zh-CN.json");
  const dict = mod.default as Dict;
  cache.set(lang, dict);
  return dict;
}

/** 按 "a.b.c" 取叶子字符串；取不到返回 undefined。 */
function lookup(dict: Dict | null, key: string): string | undefined {
  if (!dict) return undefined;
  const parts = key.split(".");
  let cur: unknown = dict;
  for (const p of parts) {
    if (cur && typeof cur === "object" && p in (cur as Record<string, unknown>)) {
      cur = (cur as Record<string, unknown>)[p];
    } else {
      return undefined;
    }
  }
  return typeof cur === "string" ? cur : undefined;
}

/** `{var}` 插值：未提供实参的占位符保留原样（不崩，提示漏传参）。 */
function interpolate(s: string, vars?: Vars): string {
  if (!vars) return s;
  return s.replace(/\{(\w+)\}/g, (_, name: string) =>
    name in vars ? String(vars[name]) : `{${name}}`,
  );
}

/**
 * 翻译函数（可脱离 hook 使用，供非组件场景如 `lib/api.ts` 的 `scrubError` 用）。
 *
 * 缺 key：返回 key 本身 + 控制台 warn（生产不崩；**不**返回空串——空串会让按钮变空白，
 * 比显示 key 更难排查）。`dict === null`（加载中）同样回退 key。
 */
export function translate(dict: Dict | null, key: string, vars?: Vars): string {
  const val = lookup(dict, key);
  if (val === undefined) {
    if (dict !== null) console.warn(`[i18n] missing key: ${key}`);
    return key;
  }
  return interpolate(val, vars);
}

export function useTranslation(): I18nValue {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useTranslation must be used within I18nProvider");
  return ctx;
}

/**
 * Provider：持有当前语言与字典。`lang` 变化时动态 import 目标字典，加载完替换 `dict`
 * （加载中保留旧字典，不置 null，避免界面闪烁）。`initialDict` 由 `main.tsx` 预加载传入，
 * 保证默认语言首屏不空。
 */
export function I18nProvider({
  children,
  lang,
  initialDict,
}: {
  children: ReactNode;
  lang: Lang;
  initialDict?: Dict | null;
}) {
  const [dict, setDict] = useState<Dict | null>(() => {
    if (initialDict) currentDict = initialDict;
    return initialDict ?? null;
  });

  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  useEffect(() => {
    let cancelled = false;
    loadDict(lang).then((d) => {
      if (!cancelled) {
        setDict(d);
        currentDict = d;
      }
    });
    return () => {
      cancelled = true;
    };
  }, [lang]);

  const tFn = useCallback(
    (key: string, vars?: Vars) => translate(dict, key, vars),
    [dict],
  );

  const value: I18nValue = { lang, dict, t: tFn };

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}
