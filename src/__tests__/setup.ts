import "@testing-library/jest-dom";

/**
 * jsdom 没有实现 `<dialog>` 的两个方法，而 `ConfirmDialog` 正是靠它们开关的
 * （M19-S1 的用例要打开「新建密钥」对话框才能看到分组下拉）。
 *
 * 这里补的是**宿主能力**，不是产品行为：`showModal` / `close` 在真实浏览器里
 * 由 WebView 提供，测试环境缺这一块只会让「弹窗根本没开」和「弹窗开了但没渲染」
 * 看起来一样。补丁只做属性层面的开关，不模拟焦点陷阱。
 */
if (typeof HTMLDialogElement !== "undefined") {
  HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
    this.setAttribute("open", "");
  };
  HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
    this.removeAttribute("open");
  };
}
