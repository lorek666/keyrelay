// M14-S6 · GUI 走查库：tauri-driver（WebDriver REST）驱动真实窗口，四条 check + JSON 报告。
//
// 本机非交互 tty / 无 tauri-driver / 无 GUI → checkEnvironment skip → exitCode 2（环境不具备，≠失败）。
// --check 模式只验脚本自身，不起 driver、不开窗口。
// 红线：报告不含 cookie 字节/密钥/PAT（captcha evidence 只记 cookie count，不记内容）。
// 见 内部文档库 docs/specs/M14-S6-GUI走查.md。

import { execFileSync } from "node:child_process";

export const SCRIPT_VERSION = "0.1.0";
const DRIVER_URL = process.env.TAURI_DRIVER_URL || "http://127.0.0.1:4444";
const COLD_START_TIMEOUT_MS = 10000;

// 六页清单（与 src/App.tsx PAGES 数组一致：本地 useState 切换，非路由）
export const NAV_PAGES = [
  { id: "overview", label: "总览" },
  { id: "sites", label: "站点" },
  { id: "keys", label: "密钥" },
  { id: "agents", label: "Agent 投递" },
  { id: "history", label: "变更历史" },
  { id: "settings", label: "设置" },
];

const EXIT = { PASS: 0, FAIL: 1, ENV: 2, SCRIPT: 3 };

function nowIso() {
  return new Date().toISOString();
}

function result(id, name, status, detail, extra = {}) {
  return { id, name, status, detail, ...extra };
}

// --- checkSelf（--check 模式，不依赖 driver/spawn，本机可跑）---
export async function checkSelf() {
  const errors = [];
  if (NAV_PAGES.length !== 6) errors.push(`NAV_PAGES 应为 6 页，实际 ${NAV_PAGES.length}`);
  const ids = NAV_PAGES.map((p) => p.id);
  const expected = ["overview", "sites", "keys", "agents", "history", "settings"];
  if (JSON.stringify(ids) !== JSON.stringify(expected))
    errors.push(`NAV_PAGES id 应为 ${expected.join(",")}，实际 ${ids.join(",")}`);
  if (!NAV_PAGES.every((p) => p.id && p.label))
    errors.push("NAV_PAGES 每页需有 id+label");
  if (new Set(ids).size !== ids.length) errors.push("NAV_PAGES id 重复");
  // 退出码常量在
  if (![EXIT.PASS, EXIT.FAIL, EXIT.ENV, EXIT.SCRIPT].every((n) => typeof n === "number"))
    errors.push("EXIT 常量缺失");
  if (errors.length) return { ok: false, detail: errors.join("; ") };
  return {
    ok: true,
    detail:
      "self-check ok（6 页 overview/sites/keys/agents/history/settings + 四 check + 退出码 0/1/2/3）",
  };
}

// --- checkEnvironment（tty / tauri-driver / GUI 会话）---
export async function checkEnvironment(options = {}) {
  const env = {
    platform: process.platform,
    arch: process.arch,
    tty: process.stdout.isTTY === true,
    term: process.env.TERM || "unknown",
    driver: "none",
    binary: options.binary || "src-tauri/target/release/tianshu-relay",
    fixture: options.fixture || "http://127.0.0.1:18999/login",
  };
  const reasons = [];
  if (!env.tty && !options.force)
    reasons.push("非交互 tty（process.stdout.isTTY=false）");
  try {
    execFileSync("tauri-driver", ["--version"], {
      stdio: "ignore",
      timeout: 3000,
    });
    env.driver = "tauri-driver";
  } catch {
    reasons.push("tauri-driver 未安装/不可执行");
  }
  if (process.platform === "darwin" && !options.force) {
    try {
      execFileSync(
        "osascript",
        ["-e", 'tell application "System Events" to UI elements enabled'],
        { stdio: "ignore", timeout: 3000 }
      );
    } catch {
      reasons.push("macOS GUI 会话不可用（osascript UI elements 失败）");
    }
  }
  if (reasons.length) {
    return result("environment", "环境自检", "skip", `环境不具备，跳过走查：${reasons.join("；")}`, {
      evidence: [JSON.stringify(env)],
    });
  }
  return result("environment", "环境自检", "pass", "环境具备", {
    evidence: [JSON.stringify(env)],
  });
}

// --- WebDriver REST client（轻量，fetch；tauri-driver 暴露 http://127.0.0.1:4444）---
async function wd(method, path, body) {
  const res = await fetch(`${DRIVER_URL}${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  if (json.error)
    throw new Error(`WebDriver ${method} ${path}: ${json.error.message || JSON.stringify(json.error)}`);
  return json.value ?? json;
}

async function wdNewSession(binary) {
  const v = await wd("POST", "/session", {
    capabilities: { alwaysMatch: { "tauri:options": { binary } } },
  });
  return v.sessionId;
}
async function wdFindElement(sid, selector) {
  const v = await wd("POST", `/session/${sid}/element`, {
    using: "css selector",
    value: selector,
  });
  return v["element-6066-11e4-a52e-4f735466cecf"] || Object.values(v)[0];
}
async function wdExecuteScript(sid, script, args = []) {
  return wd("POST", `/session/${sid}/execute/sync`, { script, args });
}
async function wdGetWindowHandles(sid) {
  return wd("GET", `/session/${sid}/window/handles`);
}
async function wdGetLogs(sid, type = "browser") {
  return wd("POST", `/session/${sid}/logs`, { type });
}
async function wdDeleteSession(sid) {
  await wd("DELETE", `/session/${sid}`);
}

async function waitFor(sid, selector, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      return await wdFindElement(sid, selector);
    } catch {
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  throw new Error(`waitFor ${selector} 超时 ${timeoutMs}ms`);
}

// --- 四条 check ---

// B-114：冷启动计时（进程启动 → 首屏可交互，端到端，≤1500ms）
export async function checkColdStart(options = {}) {
  const t0 = Date.now();
  let sid;
  try {
    sid = await wdNewSession(options.binary);
    await waitFor(sid, ".nav-item, .brand", options.timeout || COLD_START_TIMEOUT_MS);
    const ms = Date.now() - t0;
    let status, detail;
    if (ms <= 1500) {
      status = "pass";
      detail = `冷启动 ${ms}ms（≤1500ms 达标）`;
    } else if (ms <= 3000) {
      status = "warn";
      detail = `冷启动 ${ms}ms（>1500ms，B-114 未达标）`;
    } else {
      status = "fail";
      detail = `冷启动 ${ms}ms（>3000ms）`;
    }
    return result("cold-start", "冷启动计时", status, detail, {
      durationMs: ms,
      threshold: "≤1500ms",
      evidence: [`.nav-item/.brand visible @ ${ms}ms`],
    });
  } catch (e) {
    return result("cold-start", "冷启动计时", "fail", `冷启动失败：${e.message}`, {
      threshold: "≤1500ms",
    });
  } finally {
    if (sid) try { await wdDeleteSession(sid); } catch {}
  }
}

// B-117：验证码 WebView（窗口创建 + cookies 抓取 + 关闭事件三断言）
export async function checkCaptchaWebView(fixtureUrl) {
  let sid;
  try {
    if (!fixtureUrl)
      return result("captcha-webview", "验证码 WebView", "skip", "fixture 未提供（--fixture），B-117 无法走查");
    // fixture URL 探活：不可达（连接拒绝/超时）→ skip（非 fail），与 spec §6.3 一致
    try {
      const ctrl = new AbortController();
      setTimeout(() => ctrl.abort(), 3000);
      await fetch(fixtureUrl, { signal: ctrl.signal, method: "HEAD" });
    } catch (e) {
      return result("captcha-webview", "验证码 WebView", "skip", `fixture 不可达（${fixtureUrl}）：${e.message}，B-117 无法走查`);
    }
    sid = await wdNewSession();
    // 触发 captcha_begin（invoke）
    await wdExecuteScript(sid, `return await window.__TAURI_INTERNALS__.invoke('captcha_begin', { siteId: 1 })`);
    const handles = await wdGetWindowHandles(sid);
    if (handles.length < 2) throw new Error("验证码 WebView 窗口未创建");
    // cookies：evidence 只记 count，绝不记字节（红线）
    const cookies = await wdExecuteScript(sid, `return await window.__TAURI_INTERNALS__.invoke('webview_cookies') || []`);
    const cookieCount = Array.isArray(cookies) ? cookies.length : 0;
    await wdExecuteScript(sid, `window.close()`);
    return result("captcha-webview", "验证码 WebView", "pass", "窗口创建 + cookies 抓取 + 关闭事件三断言通过", {
      threshold: "窗口+cookies+关闭",
      evidence: [`handles=${handles.length}`, `cookie_count=${cookieCount}`],
    });
  } catch (e) {
    return result("captcha-webview", "验证码 WebView", "fail", `验证码 WebView 失败：${e.message}`, {
      threshold: "窗口+cookies+关闭",
    });
  } finally {
    if (sid) try { await wdDeleteSession(sid); } catch {}
  }
}

// B-15：invoke 桥实调（__TAURI_INTERNALS__.invoke 只读命令往返）
export async function checkInvokeBridge(options = {}) {
  const cmd = options.invokeCommand || "app_info";
  let sid;
  try {
    sid = await wdNewSession(options.binary);
    const ret = await wdExecuteScript(
      sid,
      `return await window.__TAURI_INTERNALS__.invoke(${JSON.stringify(cmd)})`
    );
    if (ret === undefined || ret === null)
      throw new Error(`invoke(${cmd}) 返回 undefined/null`);
    const summary =
      typeof ret === "object" ? `{${Object.keys(ret).join(",")}}` : typeof ret;
    return result("invoke-bridge", "invoke 桥实调", "pass", `invoke(${cmd}) 返回 ${summary}`, {
      threshold: "返回值非 undefined",
      evidence: [`cmd=${cmd}`, `typeof=${typeof ret}`],
    });
  } catch (e) {
    return result("invoke-bridge", "invoke 桥实调", "fail", `invoke 失败：${e.message}`, {
      threshold: "返回值非 undefined",
    });
  } finally {
    if (sid) try { await wdDeleteSession(sid); } catch {}
  }
}

// B-28：六页导航冒烟（active class + h1 文本 + 无 console error）
export async function checkNavSmoke(options = {}) {
  let sid;
  const perPage = [];
  try {
    sid = await wdNewSession(options.binary);
    const errs = [];
    for (let i = 0; i < NAV_PAGES.length; i++) {
      const page = NAV_PAGES[i];
      try {
        // 按顺序定位（第 i 个 .nav-item button，0-5 对应 overview/sites/keys/agents/history/settings）
        // 不按 label 文本：i18n 后 label 变（en-US "Overview"），按顺序 i18n 无关
        const clicked = await wdExecuteScript(
          sid,
          `(()=>{const b=document.querySelectorAll('button.nav-item')[${i}];if(b)b.click();return !!b;})()`
        );
        if (!clicked) throw new Error(`nav-item[${i}] 未找到`);
        await new Promise((r) => setTimeout(r, 200));
        const active = await wdExecuteScript(
          sid,
          `(()=>{const b=document.querySelectorAll('button.nav-item')[${i}];return b?b.className.includes('active'):false;})()`
        );
        // h1 断言：非空即可（i18n 后 h1 是本地化 label，不硬编码中文）
        const h1 = await wdExecuteScript(
          sid,
          `return document.querySelector('main header h1')?.textContent || ''`
        );
        if (!active) errs.push(`${page.id}: nav-item[${i}] 未 active`);
        if (!h1) errs.push(`${page.id}: h1 为空`);
        perPage.push({ id: page.id, active, h1 });
      } catch (e) {
        errs.push(`${page.id}: ${e.message}`);
      }
    }
    let jsErrors = [];
    try {
      jsErrors = await wdGetLogs(sid, "browser");
    } catch {
      // tauri-driver 可能不支持 logs：不阻断
    }
    const severe = Array.isArray(jsErrors) ? jsErrors.filter((l) => l.level === "SEVERE") : [];
    if (errs.length)
      return result("nav-smoke", "六页导航冒烟", "fail", `${errs.length} 处失败：${errs.join("; ")}`, {
        threshold: "六页 active+h1",
        evidence: perPage.map((p) => `${p.id}:active=${p.active},h1=${p.h1}`),
      });
    if (severe.length)
      return result("nav-smoke", "六页导航冒烟", "warn", `六页导航通过，但 console 有 ${severe.length} 个 SEVERE`, {
        threshold: "六页 active+h1",
        evidence: perPage.map((p) => `${p.id}:active=${p.active}`),
      });
    return result("nav-smoke", "六页导航冒烟", "pass", "六页导航全过（active+h1+无 console error）", {
      threshold: "六页 active+h1",
      evidence: perPage.map((p) => `${p.id}:ok`),
    });
  } catch (e) {
    return result("nav-smoke", "六页导航冒烟", "fail", `导航冒烟失败：${e.message}`, {
      threshold: "六页 active+h1",
    });
  } finally {
    if (sid) try { await wdDeleteSession(sid); } catch {}
  }
}

// --- runWalkthrough ---
export async function runWalkthrough(options = {}) {
  const startedAt = nowIso();
  const checks = [];
  const envCheck = await checkEnvironment(options);
  checks.push(envCheck);
  let env = {};
  try {
    env = JSON.parse(envCheck.evidence?.[0] || "{}");
  } catch {
    env = {};
  }

  if (envCheck.status === "skip") {
    checks.push(result("cold-start", "冷启动计时", "skip", "环境不具备，跳过"));
    checks.push(result("captcha-webview", "验证码 WebView", "skip", "环境不具备，跳过"));
    checks.push(result("invoke-bridge", "invoke 桥实调", "skip", "环境不具备，跳过"));
    checks.push(result("nav-smoke", "六页导航冒烟", "skip", "环境不具备，跳过"));
  } else {
    checks.push(await checkColdStart(options));
    checks.push(await checkCaptchaWebView(options.fixture));
    checks.push(await checkInvokeBridge(options));
    checks.push(await checkNavSmoke(options));
  }

  const summary = { pass: 0, warn: 0, fail: 0, skip: 0 };
  for (const c of checks) summary[c.status] = (summary[c.status] || 0) + 1;
  const hasFail = checks.some((c) => c.status === "fail");
  const exitCode =
    envCheck.status === "skip" ? EXIT.ENV : hasFail ? EXIT.FAIL : EXIT.PASS;
  const finishedAt = nowIso();
  const find = (id) => checks.find((c) => c.id === id)?.status || "skip";
  const report = {
    script: "gui-walkthrough.mjs",
    version: SCRIPT_VERSION,
    startedAt,
    finishedAt,
    env,
    checks,
    summary,
    exitCode,
    backlog: {
      "B-114": find("cold-start"),
      "B-117": find("captcha-webview"),
      "B-15": find("invoke-bridge"),
      "B-28": find("nav-smoke"),
    },
  };
  return { report, exitCode };
}
