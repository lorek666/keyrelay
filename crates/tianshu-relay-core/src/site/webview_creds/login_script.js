(function () {
  'use strict';

  // ── 双重守卫 ──────────────────────────────────────────────────────────────
  // ① 只在**顶层 frame**跑：同源 iframe 会让脚本多执行一份、重复回传。
  if (window.top !== window.self) return;
  // ② 只在**站点自己的 origin** 下跑：站点若把我们重定向到别的 origin（自定义域 → 主域、
  //    http → https、SSO 前置页），整段不执行 —— 凭据绝不从非本站页面回传。
  var ALLOWED_ORIGIN = __ALLOWED_ORIGIN__;
  if (window.location.origin !== ALLOWED_ORIGIN) return;

  var SCHEME = __CREDS_SCHEME__;
  var HOST = __CREDS_HOST__;
  var K_TOKEN = __AUTH_TOKEN_KEY__;

  var sent = false;

  // base64url（RFC 4648 §5）：TextEncoder 处理非 ASCII（UA 里可能有），btoa 只吃 latin1。
  function b64url(s) {
    var bytes = new TextEncoder().encode(s);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function trySend() {
    if (sent) return;
    var token = null;
    try {
      token = window.localStorage.getItem(K_TOKEN);
    } catch (e) {
      return; // 存储不可用（隐私模式等）：下面的轮询还会再试
    }
    if (!token) return;

    sent = true;
    // payload **只**含这两项：不读 refresh_token / token_expires_at（不持久化续期凭据），
    // 也不把 cookie 塞进来（cf_clearance 是 HttpOnly，JS 读不到，由壳层从 window.cookies() 补）。
    var payload = JSON.stringify({
      auth_token: token,
      user_agent: (navigator.userAgent || '')
    });

    // 走**顶层导航**回传：壳层在 on_navigation 里拦下并返回 false，页面不会真的走掉。
    // 不能用 iframe：站点 CSP 的 frame-src 白名单会把它直接卡死。
    window.location.href = SCHEME + '://' + HOST + '?d=' + b64url(payload);
  }

  // 劫持 setItem：站点 SPA 在登录成功那一刻把 auth_token 写进来（sub2api 的 stores/auth.ts）。
  // 用 setTimeout(0) 延到同步段跑完再读，避免抢跑读到半份状态。
  try {
    var orig = window.localStorage.setItem.bind(window.localStorage);
    window.localStorage.setItem = function (k, v) {
      orig(k, v);
      if (k === K_TOKEN) setTimeout(trySend, 0);
    };
  } catch (e) {
    /* 存储不可用：交给下面的轮询兜底 */
  }

  // 兜底轮询：用户可能是「已登录状态」直接打开页面（localStorage 里本来就有 token，
  // 不会再触发 setItem）。500ms 一次，最多 5 分钟。
  var polls = 0;
  var timer = setInterval(function () {
    polls++;
    trySend();
    if (sent || polls > 600) clearInterval(timer);
  }, 500);

  // 立即试一次：页面打开时 token 可能已经在里面了。
  trySend();
})();
