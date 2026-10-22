#!/usr/bin/env node
/**
 * B 路注入脚本的**行为**测试（M28-S1 / B-191）。
 *
 * 为什么不只做字符串断言：`login_script.js` 是**真的要在站点页面里执行**的代码。
 * 这里用 `node:vm` 造一个最小的 `window / localStorage / location / navigator` 假环境，
 * 把**同一份模板**（与 Rust `include_str!` 的是同一个文件）替换占位符后真实执行一遍，
 * 断言它在四种情况下「发 / 不发」回传 URL，并把 payload 解回来核对。
 *
 * 判据（spec §2.1.6）：
 *   ① 本站 origin 下写 `auth_token` ⇒ 发出 `tianshu-relay-creds://ok?d=…`；
 *   ② 解出的 JSON 含 token 与 UA，且**只有**这两个键；
 *   ③ origin 不匹配 ⇒ 不发；
 *   ④ 子 frame（`window.top !== window.self`）⇒ 不发。
 *
 * 计时器：`setInterval` 用**假实现**（返回 1、不真正定时 —— 否则进程不退出）；
 * `setTimeout` 用真实实现，测试里 await 一小段等回调落地。
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import vm from 'node:vm';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TEMPLATE = resolve(ROOT, 'crates/tianshu-relay-core/src/site/webview_creds/login_script.js');
const CALLBACK_PREFIX = 'tianshu-relay-creds://ok?d=';

/** 与 Rust `webview_creds::login_script` 同序替换：origin **最后**（防二次扫描）。 */
function buildScript(origin) {
  const lit = (s) => JSON.stringify(s);
  let js = readFileSync(TEMPLATE, 'utf8')
    .replaceAll('__CREDS_SCHEME__', lit('tianshu-relay-creds'))
    .replaceAll('__CREDS_HOST__', lit('ok'))
    .replaceAll('__AUTH_TOKEN_KEY__', lit('auth_token'));
  js = js.replaceAll('__ALLOWED_ORIGIN__', lit(origin));
  if (/__[A-Z_]+__/.test(js)) throw new Error(`模板残留占位符：${js.match(/__[A-Z_]+__/)}`);
  return js;
}

/** 在假环境里跑一次模板。`prefilledToken = null` ⇒ 初始没有 token（靠 setItem 劫持触发）。 */
function runTemplate({
  origin = 'https://sub.example.com',
  pageOrigin = origin,
  topFrame = true,
  prefilledToken = 'tok-from-storage',
  userAgent = 'UA/1.0 (WebView)',
} = {}) {
  const emitted = [];
  const storage = new Map();
  if (prefilledToken !== null) storage.set('auth_token', prefilledToken);

  const window = {};
  window.self = window;
  window.top = topFrame ? window : { different: true };

  const location = { origin: pageOrigin, _href: '' };
  Object.defineProperty(location, 'href', {
    get() {
      return this._href;
    },
    set(value) {
      emitted.push(value);
      this._href = value;
    },
  });
  window.location = location;

  const localStorage = {
    getItem: (k) => (storage.has(k) ? storage.get(k) : null),
    setItem: (k, v) => storage.set(k, String(v)),
    removeItem: (k) => storage.delete(k),
  };
  window.localStorage = localStorage;

  let intervalCreated = 0;
  const context = {
    window,
    location,
    localStorage,
    navigator: { userAgent },
    setTimeout: (fn, ms) => setTimeout(fn, ms),
    setInterval: () => {
      intervalCreated += 1;
      return 1;
    },
    clearInterval: () => {},
    TextEncoder,
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    console,
  };
  vm.createContext(context);
  vm.runInContext(buildScript(origin), context, { filename: 'login_script.js' });
  return { emitted, storage, window, intervalCreated };
}

const failures = [];
function check(name, condition, detail = '') {
  if (condition) {
    console.log(`✓ ${name}`);
  } else {
    console.log(`✗ ${name}${detail ? ` — ${detail}` : ''}`);
    failures.push(name);
  }
}

// ① 本站 origin 下**写** auth_token（走 setItem 劫持 + setTimeout）⇒ 发出回传 URL
{
  const env = runTemplate({ prefilledToken: null });
  check('① setInterval 兜底已安装', env.intervalCreated === 1, `intervalCreated=${env.intervalCreated}`);
  check('① 写入前不发', env.emitted.length === 0, JSON.stringify(env.emitted));
  env.window.localStorage.setItem('auth_token', 'tok-after-login');
  await new Promise((r) => setTimeout(r, 20));
  check('① 写 auth_token ⇒ 发出 1 次', env.emitted.length === 1, JSON.stringify(env.emitted));
  check(
    '① 回传 URL 形态 = tianshu-relay-creds://ok?d=…',
    (env.emitted[0] ?? '').startsWith(CALLBACK_PREFIX),
    JSON.stringify(env.emitted),
  );
}

// ② 解出的 JSON 含 token 与 UA，且只有这两个键
{
  const env = runTemplate({ prefilledToken: 'tok-decode-me', userAgent: 'UA/decode 1.0' });
  check('② 打开时已有 token ⇒ 立即发', env.emitted.length === 1, JSON.stringify(env.emitted));
  const url = env.emitted[0] ?? '';
  const d = url.startsWith(CALLBACK_PREFIX) ? url.slice(CALLBACK_PREFIX.length) : '';
  let payload = null;
  try {
    payload = JSON.parse(Buffer.from(d, 'base64url').toString('utf8'));
  } catch (err) {
    payload = { error: String(err) };
  }
  check('② payload 是合法 base64url JSON', payload && !payload.error, JSON.stringify(payload));
  check('② auth_token 正确', payload?.auth_token === 'tok-decode-me', JSON.stringify(payload));
  check('② user_agent 正确', payload?.user_agent === 'UA/decode 1.0', JSON.stringify(payload));
  check(
    '② payload 只有 auth_token / user_agent',
    payload && Object.keys(payload).sort().join(',') === 'auth_token,user_agent',
    JSON.stringify(payload && Object.keys(payload)),
  );
}

// ③ origin 不匹配 ⇒ 不发
{
  const env = runTemplate({ pageOrigin: 'https://evil.example', prefilledToken: 'tok' });
  check('③ origin 不匹配 ⇒ 不发', env.emitted.length === 0, JSON.stringify(env.emitted));
}

// ④ 子 frame ⇒ 不发
{
  const env = runTemplate({ topFrame: false, prefilledToken: 'tok' });
  check('④ 子 frame ⇒ 不发', env.emitted.length === 0, JSON.stringify(env.emitted));
}

// ============================================================ M36-S1：keep_open_notice.js

/**
 * 「请勿关闭」提示脚本（M36-S1）的行为测试。
 *
 * 与 `login_script.js` 同样的规矩：用 `node:vm` 造一个**极简假 DOM**，把同一份模板
 * （与 Rust `include_str!` 的是同一个文件）替换占位符后真实执行，断言：
 *   ⑤ 顶层 + 本站 origin ⇒ 只挂 1 条 banner，文本/固定定位正确；
 *   ⑥ 非本站 origin ⇒ 不挂；
 *   ⑦ 子 frame ⇒ 不挂；
 *   ⑧ 重复执行幂等（同一个文档里只有一条）。
 */
const NOTICE_TEMPLATE = resolve(ROOT, 'crates/tianshu-relay-core/src/site/keep_open_notice.js');
// 与 Rust `captcha::KEEP_OPEN_NOTICE_TEXT` 一致（模板里的 `__NOTICE_TEXT__` 就替换成它）。
const NOTICE_TEXT = '请勿关闭此窗口，验证完成后会自动关闭';

function buildNoticeScript(origin) {
  const lit = (s) => JSON.stringify(s);
  let js = readFileSync(NOTICE_TEMPLATE, 'utf8').replaceAll('__NOTICE_TEXT__', lit(NOTICE_TEXT));
  js = js.replaceAll('__ALLOWED_ORIGIN__', lit(origin));
  if (/__[A-Z_]+__/.test(js)) throw new Error(`banner 模板残留占位符：${js.match(/__[A-Z_]+__/)}`);
  return js;
}

/** 极简假 DOM：只提供脚本用到的 createElement / getElementById / appendChild。 */
function runNotice({ origin = 'https://sub.example.com', pageOrigin = origin, topFrame = true } = {}) {
  const nodes = new Map();
  const appended = [];
  const document = {
    body: null,
    documentElement: {
      appendChild(node) {
        appended.push(node);
        nodes.set(node.id, node);
      },
    },
    createElement() {
      return {
        id: '',
        textContent: '',
        style: {},
        attrs: {},
        setAttribute(name, value) {
          this.attrs[name] = value;
        },
      };
    },
    getElementById(id) {
      return nodes.get(id) ?? null;
    },
  };
  const window = {};
  window.self = window;
  window.top = topFrame ? window : { different: true };
  window.location = { origin: pageOrigin };
  // document-start 兜底用的 API：假实现（不真正定时，进程不会挂着）
  document.addEventListener = () => {};
  const context = {
    window,
    document,
    console,
    setInterval: () => 1,
    clearInterval: () => {},
  };
  vm.createContext(context);
  const run = () =>
    vm.runInContext(buildNoticeScript(origin), context, { filename: 'keep_open_notice.js' });
  run();
  return { appended, nodes, rerun: run };
}

{
  const env = runNotice();
  check('⑤ 顶层 + 本站 origin ⇒ 挂 1 条 banner', env.appended.length === 1, String(env.appended.length));
  check('⑤ banner 文本正确', env.appended[0]?.textContent === NOTICE_TEXT, String(env.appended[0]?.textContent));
  check('⑤ banner 固定顶部', env.appended[0]?.style.position === 'fixed', String(env.appended[0]?.style.position));
  check('⑤ banner 不拦截点击（pointer-events: none）', env.appended[0]?.style.pointerEvents === 'none');
}
{
  const env = runNotice({ pageOrigin: 'https://evil.example' });
  check('⑥ 非本站 origin ⇒ 不挂', env.appended.length === 0, String(env.appended.length));
}
{
  const env = runNotice({ topFrame: false });
  check('⑦ 子 frame ⇒ 不挂', env.appended.length === 0, String(env.appended.length));
}
{
  const env = runNotice();
  env.rerun();
  env.rerun();
  check('⑧ 重复执行幂等：只挂 1 条', env.appended.length === 1, String(env.appended.length));
}

if (failures.length > 0) {
  console.error(`\n✗ ${failures.length} 项失败：${failures.join('、')}`);
  process.exit(1);
}
console.log('\n✓ webview creds 脚本行为测试全部通过');
