#!/usr/bin/env node
// M16-S7 · macOS GUI 真机走查（**AppleScript 后端**）
//
// 为什么不是 tauri-driver：tauri-driver 官方不支持 macOS（WKWebView 没有 WebDriver 后端），
// 本机也从未安装。所以本脚本用 `osascript`（System Events）+ `screencapture` 做真机走查。
//
// **AppleScript 能证到什么、证不到什么**（这条边界写进 docs/specs/M16-S7-GUI真机走查.md）：
//   能证：窗口存在 / 窗口标题 / 窗口尺寸与位置 / 进程存活 / 截图里有真实渲染内容
//   证不到：WebView 内部的 JS 状态、invoke 往返的字节、DOM 结构
// 因此「首屏渲染完成」只能用**截图里确实有内容**来旁证，不能声称看到了 JS 状态。
//
// 用法：
//   node scripts/gui-walkthrough-macos.mjs [--runs 5] [--binary <path>] [--out <dir>]
//                                          [--dump-ax] [--keep] [--fixture-port 18999]
//
// 安全：**只**在临时目录里建 `KEYRELAY_HOME`（`platform::home_dir` 的显式覆盖，绝对路径），
// 绝不碰用户真实的 `~/.keyrelay`。用完杀进程。

import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdirSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const APP_PROCESS = "keyrelay";

// ---------------------------------------------------------------- 参数

function parseArgs(argv) {
  const opts = {
    runs: 5,
    binary: "/Volumes/Date/kr-t-gui/release/keyrelay",
    out: "docs/evidence",
    fixturePort: 18999,
    dumpAx: false,
    shots: false,
    keep: false,
    timeoutMs: 30000,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--runs") opts.runs = Number(argv[++i]);
    else if (a === "--binary") opts.binary = argv[++i];
    else if (a === "--out") opts.out = argv[++i];
    else if (a === "--fixture-port") opts.fixturePort = Number(argv[++i]);
    else if (a === "--timeout") opts.timeoutMs = Number(argv[++i]);
    else if (a === "--dump-ax") opts.dumpAx = true;
    else if (a === "--shots") opts.shots = true;
    else if (a === "--keep") opts.keep = true;
  }
  return opts;
}

// ---------------------------------------------------------------- osascript 封装

/** 跑一段 AppleScript，返回 { ok, out, err, ms }。 */
function osa(script, timeoutMs = 15000) {
  const t0 = Date.now();
  const r = spawnSync("osascript", ["-e", script], {
    encoding: "utf8",
    timeout: timeoutMs,
  });
  return {
    ok: r.status === 0,
    out: (r.stdout || "").trim(),
    err: (r.stderr || "").trim(),
    ms: Date.now() - t0,
  };
}

/** 一次性拿到窗口的存活/标题/几何。**不**在轮询里用它（osascript 启动开销会淹没测量）。 */
function windowInfo() {
  const script = `
tell application "System Events"
  if not (exists process "${APP_PROCESS}") then return "NOPROC"
  tell process "${APP_PROCESS}"
    if (count of windows) is 0 then return "NOWIN"
    set w to window 1
    set p to position of w
    set s to size of w
    return "WIN|" & (name of w) & "|" & (item 1 of p) & "," & (item 2 of p) & "|" & (item 1 of s) & "x" & (item 2 of s)
  end tell
end tell`;
  const r = osa(script);
  if (!r.ok) return { state: "ERR", err: r.err };
  if (r.out === "NOPROC") return { state: "NOPROC" };
  if (r.out === "NOWIN") return { state: "NOWIN" };
  const [tag, title, pos, size] = r.out.split("|");
  if (tag !== "WIN") return { state: "ERR", err: r.out };
  const [x, y] = pos.split(",").map(Number);
  const [w, h] = size.split("x").map(Number);
  return { state: "WIN", title, x, y, w, h };
}

/** 进程是否存活。 */
function processAlive() {
  const r = spawnSync("pgrep", ["-x", APP_PROCESS], { encoding: "utf8" });
  return r.status === 0;
}

/** 截窗口区域（用 AX 给的几何），返回文件路径。 */
function captureWindow(file, win) {
  // -R x,y,w,h；-x 不播声音；-o 不投影
  const rect = `${win.x},${win.y},${win.w},${win.h}`;
  const r = spawnSync("screencapture", ["-x", "-o", "-R", rect, file], {
    encoding: "utf8",
  });
  return { ok: r.status === 0, file, rect, err: (r.stderr || "").trim() };
}

// ---------------------------------------------------------------- fixture 站点

/**
 * 本地 fixture 登录页（**只为验证码 WebView 兜底路径**服务，不联网、不需要真实账号）。
 * 用 127.0.0.1 的随机/固定端口，进程退出即关闭。
 */
function startFixtureServer(port) {
  const html = `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>KeyRelay Fixture 登录页</title></head>
<body style="font-family:-apple-system;padding:2rem">
<h1 id="t">KEYRELAY-FIXTURE-PAGE</h1>
<p>本页由 scripts/gui-walkthrough-macos.mjs 提供，仅用于真机走查取证。</p>
<form><input name="u" placeholder="user"><input name="p" type="password" placeholder="pass"></form>
</body></html>`;
  const server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(html);
  });
  return new Promise((ok) => {
    server.listen(port, "127.0.0.1", () => ok(server));
  });
}

// ---------------------------------------------------------------- 冷启动测量

/**
 * 测一次「spawn → 窗口出现」。
 *
 * 关键：**先起 AppleScript 轮询器、再 spawn 应用**，这样 osascript 自身的启动开销
 * （约几十毫秒）被吸收在测量窗口**之前**，不叠加到结果里。
 * 轮询粒度 `delay 0.005` = 5ms。
 */
function coldStartOnce(binary, home, timeoutMs) {
  return new Promise((resolveP) => {
    const poller = spawn(
      "osascript",
      [
        "-e",
        `tell application "System Events"
  repeat 6000 times
    try
      if (count of windows of process "${APP_PROCESS}") > 0 then return "APPEARED"
    end try
    delay 0.005
  end repeat
  return "TIMEOUT"`,
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );

    let pollerOut = "";
    poller.stdout.on("data", (d) => (pollerOut += d.toString()));

    // 给轮询器一点时间完成 osascript 启动 + AX 连接，再计时
    setTimeout(() => {
      const env = {
        ...process.env,
        KEYRELAY_HOME: home, // ← platform::home_dir 的显式覆盖（绝对路径）
      };
      const t0 = Date.now();
      const app = spawn(binary, [], { env, stdio: ["ignore", "pipe", "pipe"] });

      let appErr = "";
      app.stderr.on("data", (d) => (appErr += d.toString()));
      app.on("exit", (code) => {
        // 应用自己退了：也算一次失败测量，别让轮询器空转到超时
        if (!poller.killed) poller.kill();
        resolveP({ ok: false, ms: Date.now() - t0, reason: `app exited early code=${code}`, appErr });
      });

      const deadline = setTimeout(() => {
        poller.kill();
        try { app.kill("SIGKILL"); } catch {}
        resolveP({ ok: false, ms: Date.now() - t0, reason: "timeout waiting for window" });
      }, timeoutMs);

      const watch = setInterval(() => {
        if (pollerOut.includes("APPEARED")) {
          clearInterval(watch);
          clearTimeout(deadline);
          const ms = Date.now() - t0;
          // 窗口出现了但**不立刻杀**：调用方要截图，所以只回报时刻
          resolveP({ ok: true, ms, app, poller });
        } else if (pollerOut.includes("TIMEOUT")) {
          clearInterval(watch);
          clearTimeout(deadline);
          try { app.kill("SIGKILL"); } catch {}
          resolveP({ ok: false, ms: Date.now() - t0, reason: "poller timed out" });
        }
      }, 10);
    }, 150);
  });
}

function killApp() {
  spawnSync("pkill", ["-x", APP_PROCESS], { encoding: "utf8" });
}

// ---------------------------------------------------------------- AX 树（诊断：WebView 是否可点）

function dumpAxTree() {
  const script = `
tell application "System Events"
  tell process "${APP_PROCESS}"
    set out to ""
    try
      set ui to entire contents of window 1
      repeat with e in ui
        try
          set out to out & (class of e as text) & tab & (role of e as text) & tab & (description of e as text) & linefeed
        end try
      end repeat
    end try
    return out
  end tell
end tell`;
  return osa(script, 30000);
}

// ---------------------------------------------------------------- main

async function main() {
  const opts = parseArgs(process.argv);
  const lines = [];
  const say = (s) => {
    console.log(s);
    lines.push(s);
  };

  say(`# M16-S7 GUI 真机走查（AppleScript 后端）`);
  say(`时间: ${new Date().toISOString()}`);
  say(`二进制: ${opts.binary}`);
  say(`存在: ${existsSync(opts.binary)}`);

  // 前置条件（本机实测，不采信任何转述）
  const proc = osa('tell application "System Events" to count processes');
  const ax = osa('tell application "System Events" to get UI elements enabled');
  say(`前置: System Events 进程数=${proc.out} UI elements enabled=${ax.out}`);
  say(`前置: tauri-driver=${spawnSync("which", ["tauri-driver"]).status === 0 ? "已装" : "未安装"}`);

  const home = join(tmpdir(), `kr-m16s7-home-${Date.now()}`);
  mkdirSync(join(home, ".keyrelay"), { recursive: true });
  say(`临时 KEYRELAY_HOME=${home}（真实 ~/.keyrelay 不受影响）`);
  mkdirSync(opts.out, { recursive: true });

  const server = await startFixtureServer(opts.fixturePort);
  say(`fixture 站点: http://127.0.0.1:${opts.fixturePort}/login`);

  const results = [];
  let firstWin = null;

  try {
    for (let i = 1; i <= opts.runs; i++) {
      killApp();
      await new Promise((r) => setTimeout(r, 400));
      const r = await coldStartOnce(opts.binary, home, opts.timeoutMs);
      results.push({ ok: r.ok, ms: r.ms, reason: r.reason });
      say(`第 ${i} 次冷启动: ${r.ok ? `${r.ms} ms` : `失败(${r.reason}) ${r.ms} ms`}`);

      if (i === 1 && r.ok) {
        await new Promise((res) => setTimeout(res, 1500)); // 等首屏渲染
        firstWin = windowInfo();
        say(`窗口: ${JSON.stringify(firstWin)}`);
        if (firstWin.state === "WIN" && opts.shots) {
          const shot = resolve(opts.out, "m16s7-01-main.png");
          const cap = captureWindow(shot, firstWin);
          say(`截图: ${shot} (${cap.ok ? "ok" : cap.err}) rect=${cap.rect}`);
        }
        if (opts.dumpAx) {
          const tree = dumpAxTree();
          writeFileSync(resolve(opts.out, "m16s7-ax-tree.txt"), tree.out + "\n" + tree.err);
          const n = tree.out.split("\n").filter(Boolean).length;
          say(`AX 树: ${n} 个元素 → ${resolve(opts.out, "m16s7-ax-tree.txt")}`);
        }
      }
      if (r.ok && r.app) { try { r.app.kill("SIGKILL"); } catch {} }
    }

    const okMs = results.filter((r) => r.ok).map((r) => r.ms);
    const sorted = [...okMs].sort((a, b) => a - b);
    const median = sorted[Math.floor(sorted.length / 2)];
    say(`\n冷启动原始值(ms): [${okMs.join(", ")}]`);
    say(`中位数=${median} 最大=${Math.max(...okMs)} 最小=${Math.min(...okMs)}`);
  } finally {
    killApp();
    server.close();
    if (!opts.keep) rmSync(home, { recursive: true, force: true });
  }

  say(`\n进程残留检查: ${processAlive() ? "**仍在运行**" : "已清理"}`);
  writeFileSync(resolve(opts.out, "m16s7-gui-raw.txt"), lines.join("\n") + "\n");
}

main().catch((e) => {
  killApp();
  console.error(e);
  process.exit(1);
});
