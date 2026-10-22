(function () {
  'use strict';

  // ── 双重守卫（M36-S1）──────────────────────────────────────────────────────
  // ① 只在**顶层 frame** 跑：子 frame 里挂 banner 会重复，也会挡住页面内容。
  if (window.top !== window.self) return;
  // ② 只在**站点自己的 origin** 下跑：站点把我们重定向到别处时，这条提示没有意义，
  //    也不该在第三方页面上留下我们注入的元素。
  var ALLOWED_ORIGIN = __ALLOWED_ORIGIN__;
  if (window.location.origin !== ALLOWED_ORIGIN) return;

  var NOTICE_TEXT = __NOTICE_TEXT__;
  var ID = 'tianshu-relay-keep-open-notice';
  var TRIES = 0;

  // **只创建元素与样式**：不读取页面文本、输入框、cookie、localStorage；
  // 不点击、不提交表单、不识别或绕过验证码。
  function mount() {
    try {
      // document-start 时 `documentElement` 也可能还没就绪 ⇒ 拿不到宿主就先返回，
      // 由下面的 DOMContentLoaded / 短轮询重试（挂不上不能抛错，否则整段脚本中断）。
      var host = document.body || document.documentElement;
      if (!host) return false;
      // 幂等：同一个文档里只留一条（重复注入 / 重试都只更新文本）。
      var existing = document.getElementById(ID);
      if (existing) {
        existing.textContent = NOTICE_TEXT;
        return true;
      }
      var bar = document.createElement('div');
      bar.id = ID;
      bar.textContent = NOTICE_TEXT;
      bar.setAttribute('role', 'status');
      bar.setAttribute('aria-live', 'polite');

      var style = bar.style;
      style.position = 'fixed';
      style.top = '0';
      style.left = '0';
      style.right = '0';
      style.zIndex = '2147483647';
      style.padding = '10px 16px';
      style.background = 'rgba(24, 24, 27, 0.94)';
      style.color = '#fafafa';
      style.font = '600 14px/1.4 -apple-system, "SF Pro Text", "PingFang SC", system-ui, sans-serif';
      style.textAlign = 'center';
      style.letterSpacing = '0.01em';
      // 展示层不拦点击：用户还要在下面正常操作站点页面。
      style.pointerEvents = 'none';
      style.boxShadow = '0 1px 6px rgba(0, 0, 0, 0.35)';

      host.appendChild(bar);
      return true;
    } catch (e) {
      return false;
    }
  }

  if (mount()) return;

  // 兜底一：DOM 就绪后再试一次（只挂一次监听，不用 oncancel 之类会覆盖站点钩子的写法）。
  try {
    document.addEventListener(
      'DOMContentLoaded',
      function () {
        mount();
      },
      { once: true }
    );
  } catch (e) {
    /* 站点沙箱禁止监听：下面的短轮询还会兜底 */
  }
  // 兜底二：短轮询（50ms × 40 ≈ 2s）。成功或超时即停，不会长期占用定时器。
  try {
    var timer = setInterval(function () {
      TRIES += 1;
      if (mount() || TRIES > 40) clearInterval(timer);
    }, 50);
  } catch (e) {
    /* 没有定时器 API：只能靠 DOMContentLoaded */
  }
})();
