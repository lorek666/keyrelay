#!/usr/bin/env node
// M16-S7 · macOS GUI 真机走查（**AppleScript 后端**）
//
// 为什么不是 tauri-driver：tauri-driver 官方不支持 macOS（WKWebView 没有 WebDriver 后端），
// 本机也从未安装。
//
// **AppleScript 能证到什么、证不到什么**（详见 docs/specs/M16-S7-GUI真机走查.md）：
//   能证：窗口存在 / 标题 / 尺寸 / 进程存活
//   证不到：WebView 内部的 JS 状态、invoke 往返的字节、DOM 结构
// 并且本机**采不到该窗口的像素**（窗口存在 ≠ 能采到它的像素）——见 spec §4 的坑清单。
//
// 用法：
//   node scripts/gui-walkthrough-macos.mjs [--runs 10] [--binary <path>] [--wait 30]
//                                          [--out <dir>] [--keep] [--fixture-port 18999]
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
    binary: "/Volumes/Date/kr-t-gui/release/keyrelay",
    // 默认写到**临时目录**：旧默认 `docs/evidence` 会让「照文档复跑一次」弄脏工作树（P2-6）
    out: join(tmpdir(), "kr-m16s7-walkthrough"),
    fixturePort: 18999,
    waitSec: 30,
    keep: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--runs") opts.runs = Number(argv[++i]);
    else if (a === "--binary") opts.binary = argv[++i];
    else if (a === "--out") opts.out = argv[++i];
    else if (a === "--wait") opts.waitSec = Number(argv[++i]);
    else if (a === "--fixture-port") opts.fixturePort = Number(argv[++i]);
    else if (a === "--keep") opts.keep = true;
    else if (a === "--help" || a === "-h") {
      console.log(
        "用法: node scripts/gui-walkthrough-macos.mjs [--runs N] [--binary PATH] [--wait SEC] [--out DIR] [--keep] [--fixture-port PORT]\n" +
          "退出码: 0 = 两条口径都有样本；1 = 任一口径 0 样本 / 前置不满足",
      );
      process.exit(0);
    } else {
      console.error(`未知参数: ${a}`);
      process.exit(1);
    }
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
 * 一次冷启动：并行轮询「窗口出现」与「ui_ready_at 落库」，两条口径并列报。
 *
 * 为什么每次都要**新建临时 HOME**：`ui_ready_at` 是持久化的，复用 HOME 会让第二次之后的
 * 新口径立刻命中旧值 ⇒ 数字无意义。
 */
function coldStartOnce(opts, runIndex) {
  const home = join(tmpdir(), `kr-m16s7-run-${runIndex}`);
  rmSync(home, { recursive: true, force: true });
  mkdirSync(join(home, ".keyrelay"), { recursive: true });
  const db = join(home, ".keyrelay", "keyrelay.db");

  const t0 = nowMs();
  const app = spawn(opts.binary, [], {
    env: { ...process.env, KEYRELAY_HOME: home },
    stdio: ["ignore", "ignore", "ignore"],
  });
  const pid = app.pid;

  return new Promise((done) => {
    let win = null;
    let winInfo = null;
    let ui = null;
    let finished = false;
    let appExitedEarly = false;
    app.on("exit", () => { appExitedEarly = true; });

    const finish = () => {
      if (finished) return;
      finished = true;
      clearInterval(tick);
      clearTimeout(deadline);
      // 只杀**自己 spawn 的** pid
      try { app.kill("SIGKILL"); } catch {}
      done({ win, winInfo, ui, home, pid, appExitedEarly });
    };

    const tick = setInterval(() => {
      if (win === null) {
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

  say(`# M16-S7 GUI 真机走查（AppleScript 后端）`);
  say(`时间: ${new Date().toISOString()}`);
  say(`二进制: ${opts.binary}（存在: ${existsSync(opts.binary)}）`);
  say(`等待上限: ${opts.waitSec}s  runs: ${opts.runs}`);

  const proc = osa('tell application "System Events" to count processes');
  const ax = osa('tell application "System Events" to get UI elements enabled');
  say(`前置: System Events 进程数=${proc.out} UI elements enabled=${ax.out}`);
  say(`前置: tauri-driver=${spawnSync("which", ["tauri-driver"]).status === 0 ? "已装" : "未安装"}`);
  if (!existsSync(opts.binary)) { console.error("二进制不存在"); process.exit(1); }

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
        `第 ${i} 次: 窗口=${r.win ?? "—"}ms  ui_ready=${r.ui ?? "—"}ms  pid=${r.pid}` +
          (r.appExitedEarly ? "  ⚠️ 进程提前退出" : ""),
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
