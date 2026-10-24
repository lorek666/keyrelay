import React from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import App from "./App";
import "./index.css";
import "./lib/harmony.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

const root = document.getElementById("root");
if (!root) {
  // 开发期挂载点断言，非用户可见 UI 文案——i18n:skip
  throw new Error("找不到 #root 挂载点");  // i18n:skip
}

// 预加载默认语言（zh-CN）字典后再 render，保证首屏不空（M14-S2 §9.2）。
// 顶层 await：ESM + target ES2021 支持，Vite 构建保留；zh-CN.json 作为独立 chunk。
// en-US 字典在 settings.language === "en-US" 时由 I18nProvider 切换加载。
const initialDict = (await import("./i18n/zh-CN.json")).default as Record<string, unknown>;

createRoot(root).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <App initialDict={initialDict} />
    </QueryClientProvider>
  </React.StrictMode>,
);
