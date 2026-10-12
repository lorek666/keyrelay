import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri 期望固定端口与不自动开浏览器；开发期由 `tauri dev` 注入 devUrl。
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 3123,
    strictPort: true,
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2021",
  },
});
