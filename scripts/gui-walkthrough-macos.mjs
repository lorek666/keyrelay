#!/usr/bin/env node
// M16-S7 · macOS GUI 真机走查（**AppleScript 后端**）
// M27-S1 · 启动方式订正（**根因订正见下方「B-154」段**）
//
// 为什么不是 tauri-driver：tauri-driver 官方不支持 macOS（WKWebView 没有 WebDriver 后端），
// 本机也从未安装。
//
// **AppleScript 能证到什么、证不到什么**（详见 docs/specs/M16-S7-GUI真机走查.md）：
//   能证：窗口存在 / 标题 / 尺寸 / 进程存活
//   证不到：WebView 内部的 JS 状态、invoke 往返的字节、DOM 结构
// 并且本机**采不到该窗口的像素**（窗口存在 ≠ 能采到它的像素）——见 spec §4 的坑清单。
//
// **B-154（M27-S1 订正）**：M16-S7 用 `spawn(opts.binary, ...)` 直接 exec 二进制——
// shell-spawned child **未挂到 Aqua GUI 会话**，WebContent 子进程虽然出现，但 main process
// 不在 WindowServer 的进程组里，JS 没真正跑起来（27 次 `ui_ready_at` 零命中、WebContent 12 秒
// 只烧 0.06s CPU 都是这一现象的副作用，不是宿主能力的边界）。**修法**：用 `--app <KeyRelay.app>`
// 走 `open -n` 让 LaunchServices 在用户 GUI 会话里启动新实例，env（含 `KEYRELAY_HOME`）从父
// shell 正常传播。3 次重复：`ui_ready_at` 全部落库（1097 / 1089 / 1099 ms；M27-S1 重测另得
// 689 / 598 / 607 / 1032 ms）。**`--binary` 模式保留**作为对比口径（与 M16-S7 同形）。
//
// 用法（M27-S1 起 `--app` 与 `--binary` 二选一，必填其一）：
//   node scripts/gui-walkthrough-macos.mjs --app <KeyRelay.app> [--runs 10] [--wait 30]
//                                        [--out <dir>] [--keep] [--fixture-port 18999]
//   node scripts/gui-walkthrough-macos.mjs --binary <path>   [同上选项]   # M16-S7 直接 spawn 路径
//
// **退出码语义**（M16-S7 复审 P2-4）：
//   0 = 两条口径**都**拿到了至少一个有效样本
//   1 = 任一口径 0 样本（全失败）/ 前置条件不满足 / 用法错误
//   （旧版全失败仍 exit 0，且统计退化成 中位=undefined / max=-Infinity —— 那是缺陷）
//
// **安全**：只在自己 spawn 的 pid 上操作（不按进程名 `pkill`，避免杀掉用户自己的实例）；
// 只在临时目录里建 `KEYRELAY_HOME`，绝不碰用户真实 `~/.keyrelay`；默认**不截图**。

import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdirSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

function parseArgs(argv) {
  const opts = {
    runs: 10,
    // 默认 null：M27-S1 起 `--app` 与 `--binary` 二选一必填其一。
    // 旧默认 `/Volumes/Date/kr-t-gui/release/keyrelay` 是 M16-S7 的开发机路径，
    // 默默继续沿用会让「照文档复跑」跑到一个不存在的二进制 ⇒ 误判环境。
    app: null,
    binary: null,
    // 默认写到**临时目录**：旧默认 `docs/evidence` 会让「照文档复跑一次」弄脏工作树（P2-6）
    out: join(tmpdir(), "kr-m16s7-walkthrough"),
    fixturePort: 18999,
    waitSec: 30,
    keep: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--runs") opts.runs = Number(argv[++i]);
    else if (a === "--app") opts.app = argv[++i];
    else if (a === "--binary") opts.binary = argv[++i];
    else if (a === "--out") opts.out = argv[++i];
    else if (a === "--wait") opts.waitSec = Number(argv[++i]);
    else if (a === "--fixture-port") opts.fixturePort = Number(argv[++i]);
    else if (a === "--keep") opts.keep = true;
    else if (a === "--help" || a === "-h") {
      console.log(
        "用法: node scripts/gui-walkthrough-macos.mjs (--app <KeyRelay.app> | --binary <path>) [--runs N] [--wait SEC] [--out DIR] [--keep] [--fixture-port PORT]\n" +
          "退出码: 0 = 两条口径都有样本；1 = 任一口径 0 样本 / 前置不满足 / 用法错误",
      );
      process.exit(0);
    } else {
      console.error(`未知参数: ${a}`);
      process.exit(1);
    }
  }
  // M27-S1：二选一必填
  if (opts.app === null && opts.binary === null) {
    console.error("用法错误：必须提供 --app <KeyRelay.app> 或 --binary <path> 之一（M27-S1 起强制）");
    process.exit(1);
  }
  if (opts.app !== null && opts.binary !== null) {
    console.error("用法错误：--app 与 --binary 二选一，不能同时提供");
    process.exit(1);
  }
  return opts;
}

function osa(script, timeoutMs = 15000) {
  const r = spawnSync("osascript", ["-e", script], { encoding: "utf8", timeout: timeoutMs });
  return { ok: r.status === 0, out: (r.stdout || "").trim(), err: (r.stderr || "").trim() };
}

/**
 * **按 pid** 拿窗口信息。
 *
 * 为什么不按进程名：用户自己也开着 KeyRelay 时，按名字查到的是**他的**窗口 ⇒ 数字无效
 * （M16-S7 复审 P2-5）。另外按名字解析 AX 进程本身还有 ~2.7s 的固定开销，
 * 会把「窗口出现」的量级从 ~0.4s 抬到 ~3s（实测）。
 */
function windowInfoForPid(pid) {
  const script = `
tell application "System Events"
  try
    tell (first process whose unix id is ${pid})
      if (count of windows) is 0 then return "NOWIN"
      set w to window 1
      set p to position of w
      set s to size of w
      return "WIN|" & (name of w) & "|" & (item 1 of p) & "," & (item 2 of p) & "|" & (item 1 of s) & "x" & (item 2 of s)
    end tell
  on error
    return "NOPROC"
  end try
end tell`;
  const r = osa(script);
  if (!r.ok || r.out === "NOPROC") return { state: "NOPROC" };
  if (r.out === "NOWIN") return { state: "NOWIN" };
  const [tag, title, pos, size] = r.out.split("|");
  if (tag !== "WIN") return { state: "ERR", err: r.out };
  const [x, y] = pos.split(",").map(Number);
  const [w, h] = size.split("x").map(Number);
  return { state: "WIN", title, x, y, w, h };
}

const nowMs = () => Date.now();

/**
 * **按进程名** pgrep KeyRelay pid 集合（M27-S1 新增）。
 *
 * 用途：`--app` 模式下 `open -n` 不直接返回 pid，需 launch 前后做 pgrep diff 找本实例 pid。
 * 用 `pgrep -f KeyRelay`：能匹配到 .app 包内的可执行（路径含 "KeyRelay.app"）以及裸二进制
 * （名称含 "keyrelay" 大小写敏感下不匹配，但 LaunchServices 启动后的进程名是 "KeyRelay"）。
 * 返回 Set<string>，pgrep 失败返回空 Set（不抛错，让 diff 逻辑自己处理）。
 */
function pgrepKeyRelay() {
  const r = spawnSync("pgrep", ["-f", "KeyRelay"], { encoding: "utf8" });
  if (r.status !== 0) return new Set();
  return new Set(r.stdout.trim().split(/\s+/).filter(Boolean));
}

/**
 * 一次冷启动：并行轮询「窗口出现」与「ui_ready_at 落库」，两条口径并列报。
 *
 * 为什么每次都要**新建临时 HOME**：`ui_ready_at` 是持久化的，复用 HOME 会让第二次之后的
 * 新口径立刻命中旧值 ⇒ 数字无意义。
 *
 * 启动方式（M27-S1 订正）：
 *   `--app <KeyRelay.app>`：用 `open -n` 启动 .app 包，挂到 Aqua 会话；env 透传由父 shell
 *     完成。`open` 不直接给 pid，需 launch 前后 pgrep diff 找本实例 pid（B-154 修法）。
 *   `--binary <path>`：直接 spawn（与 M16-S7 同形）。本模式下若环境不带 Aqua（如非交互
 *     harness），WebContent 不会真正跑 JS —— 这正是 B-154 的现象，保留作为对比口径。
 */
function coldStartOnce(opts, runIndex) {
  const home = join(tmpdir(), `kr-m16s7-run-${runIndex}`);
  rmSync(home, { recursive: true, force: true });
  mkdirSync(join(home, ".keyrelay"), { recursive: true });
  const db = join(home, ".keyrelay", "keyrelay.db");

  const t0 = nowMs();
  let pid = null;
  let appExitedEarly = false;
  let pidMiss = false;
  let child = null;

  if (opts.app !== null) {
    // --- `--app` 模式（M27-S1，B-154 修法）---
    if (!existsSync(opts.app) || !opts.app.endsWith(".app")) {
      console.error(`--app 路径不存在或不是 .app 包: ${opts.app}`);
      process.exit(1);
    }
    const before = pgrepKeyRelay();
    const r = spawnSync("open", ["-n", opts.app], {
      env: { ...process.env, KEYRELAY_HOME: home },
      encoding: "utf8",
    });
    if (r.status !== 0) {
      appExitedEarly = true;
    } else {
      // launch 后逐 tick pgrep，diff 出新 pid（不属于 launch 前基线的）
      const findNewPid = () => {
        const after = pgrepKeyRelay();
        for (const p of after) if (!before.has(p)) return p;
        return null;
      };
      // 先同步扫一次（多数情况 launch 后 50ms 内 pid 已可见）
      pid = findNewPid();
      if (pid === null) {
        // 把「待 tick 内继续找」丢给主轮询；先记一个 sentinel 让上层继续走
        pidMiss = true;
      }
      // 把 findNewPid 暴露给主循环用闭包继续找
      coldStartOnce._findNewPid = findNewPid;
    }
  } else {
    // --- `--binary` 模式（M16-S7 同形）---
    child = spawn(opts.binary, [], {
      env: { ...process.env, KEYRELAY_HOME: home },
      stdio: ["ignore", "ignore", "ignore"],
    });
    pid = child.pid;
    child.on("exit", () => { appExitedEarly = true; });
  }

  return new Promise((done) => {
    let win = null;
    let winInfo = null;
    let ui = null;
    let finished = false;

    const finish = () => {
      if (finished) return;
      finished = true;
      clearInterval(tick);
      clearTimeout(deadline);
      // 只杀**自己识别到的** pid（不按进程名 pkill，避免杀掉用户自己的实例）
      if (pid !== null) {
        try { process.kill(Number(pid), "SIGKILL"); } catch {}
      } else if (child !== null) {
        try { child.kill("SIGKILL"); } catch {}
      }
      done({ win, winInfo, ui, home, pid, appExitedEarly, pidMiss });
    };

    const tick = setInterval(() => {
      // `--app` 模式若 pidMiss，每 tick 继续找新 pid
      if (pid === null && opts.app !== null && typeof coldStartOnce._findNewPid === "function") {
        const p = coldStartOnce._findNewPid();
        if (p !== null) { pid = p; pidMiss = false; }
      }
      if (pid !== null && win === null) {
        const info = windowInfoForPid(pid);
        if (info.state === "WIN") { win = nowMs() - t0; winInfo = info; }
      }
      if (ui === null) {
        const r = spawnSync("sqlite3", [db, "SELECT value FROM settings WHERE key='ui_ready_at';"], {
          encoding: "utf8",
        });
        if (r.status === 0 && (r.stdout || "").trim() !== "") ui = nowMs() - t0;
      }
      if (win !== null && ui !== null) finish();
    }, 20);

    // 早退分支也会走 finish ⇒ 两条路径都清定时器（旧版只在一条分支里清，另一条会空转 30s）
    const deadline = setTimeout(finish, opts.waitSec * 1000);
  });
}

function stats(label, values) {
  if (values.length === 0) return `${label}: **0 个有效样本**`;
  const v = [...values].sort((a, b) => a - b);
  const pct = (p) => {
    const k = (v.length - 1) * p;
    const lo = Math.floor(k);
    const hi = Math.min(lo + 1, v.length - 1);
    return Math.round(v[lo] + (v[hi] - v[lo]) * (k - lo));
  };
  const median =
    v.length % 2 ? v[(v.length - 1) / 2] : Math.round((v[v.length / 2 - 1] + v[v.length / 2]) / 2);
  return `${label}: n=${v.length} 原始=[${v.join(", ")}]\n  中位=${median}ms  p90=${pct(0.9)}ms  最小=${v[0]}ms  最大=${v[v.length - 1]}ms`;
}

async function main() {
  const opts = parseArgs(process.argv);
  const lines = [];
  const say = (s) => { console.log(s); lines.push(s); };

  const mode = opts.app !== null ? "app" : "binary";
  const target = opts.app !== null ? opts.app : opts.binary;
  const targetExists = mode === "app" ? (existsSync(opts.app) && opts.app.endsWith(".app")) : existsSync(opts.binary);

  say(`# M16-S7 GUI 真机走查（AppleScript 后端）`);
  say(`时间: ${new Date().toISOString()}`);
  say(`启动模式: ${mode === "app" ? "--app（open -n .app 包，M27-S1 B-154 修法）" : "--binary（直接 spawn，M16-S7 同形）"}`);
  say(`目标: ${target}（存在: ${targetExists}）`);
  say(`等待上限: ${opts.waitSec}s  runs: ${opts.runs}`);

  const proc = osa('tell application "System Events" to count processes');
  const ax = osa('tell application "System Events" to get UI elements enabled');
  say(`前置: System Events 进程数=${proc.out} UI elements enabled=${ax.out}`);
  say(`前置: tauri-driver=${spawnSync("which", ["tauri-driver"]).status === 0 ? "已装" : "未安装"}`);
  if (!targetExists) { console.error("目标不存在或不是 .app 包"); process.exit(1); }

  mkdirSync(opts.out, { recursive: true });

  const server = await new Promise((ok) => {
    const s = createServer((_q, res) => {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end("<!doctype html><html><body>KEYRELAY-FIXTURE</body></html>");
    });
    s.listen(opts.fixturePort, "127.0.0.1", () => ok(s));
  });
  say(`fixture 站点: http://127.0.0.1:${opts.fixturePort}/login`);

  const wins = [];
  const uis = [];
  try {
    for (let i = 1; i <= opts.runs; i++) {
      const r = await coldStartOnce(opts, i);
      if (r.win !== null) wins.push(r.win);
      if (r.ui !== null) uis.push(r.ui);
      say(
        `第 ${i} 次: 窗口=${r.win ?? "—"}ms  ui_ready=${r.ui ?? "—"}ms  pid=${r.pid ?? "—"}` +
          (r.appExitedEarly ? "  ⚠️ 进程提前退出" : "") +
          (r.pidMiss ? "  ⚠️ pgrep 未找到本实例 pid（在 wait 上限内）" : ""),
      );
      if (i === 1) say(`  窗口元数据（出现时采样）: ${JSON.stringify(r.winInfo)}`);
      if (!opts.keep) rmSync(r.home, { recursive: true, force: true });
    }
  } finally {
    server.close();
  }

  say("");
  say(stats("旧口径 窗口出现", wins));
  say(stats("新口径 ui_ready_at", uis));
  say("");
  say(`退出码语义: 0 = 两条口径都有样本；1 = 任一口径 0 样本`);
  writeFileSync(resolve(opts.out, "m16s7-gui-raw.txt"), lines.join("\n") + "\n");
  say(`原始输出: ${resolve(opts.out, "m16s7-gui-raw.txt")}`);

  if (wins.length === 0 || uis.length === 0) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
