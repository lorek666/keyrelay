//! 站点类型的**设计能力表**（M7-S2 / PRD FR-1）。
//!
//! 这张表只有两个用途，**不要扩散**：
//!
//! 1. **界面灰显**：某项为 `false` ⇒ 对应按钮 `disabled` + 说明文案（映射见
//!    `docs/specs/M7-S2-站点类型与能力集.md` §3.3）。灰显而不是隐藏：用户要能看见
//!    「这个功能存在，但这个站点类型不支持」，否则会以为是产品缺陷。
//! 2. **核心层提前拒绝**：为 `false` 时，调用方应在**调用适配器之前**直接返回
//!    [`crate::error::Error::Unsupported`]，不必发请求、也不必等适配器报错。
//!
//! 纯函数：无 IO、无网络、不读环境变量、不读时钟、不碰钥匙串。
//! 新增站点类型时**只改本文件**（这张表就是「哪个类型支持什么」的唯一出处）。

use super::SiteKind;

/// 某个站点类型支持哪些能力。
///
/// 字段语义一律是「**本产品今天能不能做到**」，不是「站点端有没有这个概念」——
/// 这条定义是 M7-S0 §3.2 的裁决（见 [`Self::key_usage`] 的注释）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SiteCapabilities {
    /// 有会话/登录端点（需要账号密码换取会话）
    pub login: bool,
    /// 能列出站点侧已有的令牌
    pub list_keys: bool,
    /// 能在站点侧新建令牌
    pub create_key: bool,
    /// 能读回令牌明文
    pub reveal_key: bool,
    /// 能回收（删除）站点侧令牌
    pub revoke_key: bool,
    /// 能查询余额
    pub balance: bool,
    /// 能拉取可用分组（含倍率）
    pub groups: bool,
    /// 能取到**每把** key 的用量
    ///
    /// **定义（M7-S0 §3.2 裁决，别改成别的意思）**：本产品**今天**能不能从该站点类型取到
    /// 每把 key 的用量 —— 不是「站点端有没有用量字段」。
    /// - NewAPI / Sub2API：`true`（M14-S3 起：`list_keys` 响应带当前累计用量，Sub2API 另有
    ///   `usage/daily` 日趋势；适配器解析进 `KeyMeta.quota_used`，写 `keys.quota_used`）。
    /// - `CustomOpenAiCompatible`：`false`（只读 `/v1/models`，无令牌管理端点）。
    ///
    /// 界面据本字段决定用量列显示与否（`true` 显示、`false` 隐藏，不按 `kind` 硬编码）。
    pub key_usage: bool,
    /// 该站点的分组有**稳定主键**（适配器返回的 `GroupInfo.id` 为 `Some`）。
    ///
    /// - Sub2API：`true`（`/api/v1/groups/available` 的 `id` 是 `int64` 主键）。
    /// - NewAPI：`false`（分组以**名字**为标识，`id` 恒为 `None`）。
    /// - `CustomOpenAiCompatible`：`false`（没有分组概念）。
    ///
    /// **为什么要有它**（M22-S1 复审 P1-1）：`keys.group_id` 只能存**真正的主键**。
    /// NewAPI 的分组名（`"vip"`）一旦被当成 id 落库，轮换就会按 id 找而永远找不到
    /// （NewAPI 的 `id` 全是 `None`）⇒ 这把 key 从此**每次轮换都被拒**，而站点根本没改名。
    /// 这条是「站点类型的设计能力」，所以放能力表，不在 `create_key` 里按 `kind` 分支。
    pub group_ids: bool,
    /// 该站点类型的会话机制能否被 **WebView cookie 抓取兜底**（M26-S1 / B-191）。
    ///
    /// **定义**：`true` = 会话凭证走 `Set-Cookie`，`window.cookies()` 能抓到；
    /// `false` = 会话走非 Cookie 机制（Bearer / 无登录），抓不到——
    /// 用户在 WebView 里登录成功后点「我已过完」，后端 `window.cookies()` 拿到空集，
    /// 即便非空也只能造 cookie-only 会话，对该站点的 Bearer 鉴权不可用。
    ///
    /// 取值（与 `sub2api::with_auth` / `newapi::login` 的实测形态一致）：
    /// - NewAPI：`true`（`newapi.rs:580-603` 走 `Set-Cookie` 或 `data.access_token`，
    ///   cookie 路径在真实部署上可达；本字段只判「能否被 cookie 兜底」，不判「是否唯一路径」）。
    /// - Sub2API：`false`（`sub2api.rs:82-83` 出 `Authorization: Bearer`，登录响应 JSON 体
    ///   里的 `access_token` 是 JWT，**从不写 `Set-Cookie`**；SPA 把它存进 localStorage，
    ///   `window.cookies()` 结构性拿不到）。
    /// - `CustomOpenAiCompatible`：`false`（`login = false`，根本不进 `CaptchaRequired` 分支；
    ///   fail-closed 同向落点）。
    ///
    /// **为什么放能力表**：与 `group_ids` 同形——这是「站点类型的设计能力」，不在
    /// `captcha_complete` / `Sites.tsx` 里按 `kind` 分支（M7-S2 §3.3 红线）。
    /// 界面据此决定「打开官方页面过一次」面板**渲染与否**；核心层据此在 `window.cookies()`
    /// **之前**直接拒绝，不调 cookies、不进 validate、不关窗。
    ///
    /// **M28-S1 / B-191 B 路起**：本字段只描述 **cookie 抓取**这一种兜底。Sub2API 的
    /// `false` **不再等价于**「UI 必须显示不适用」——还要看 [`Self::webview_bearer_supported`]。
    pub webview_captcha_supported: bool,
    /// 本产品今天是否支持用「WebView 页面 localStorage → `tianshu-relay-creds://`」拿会话（M28-S1 / B-191）。
    ///
    /// - Sub2API：`true`（SPA 把 `auth_token` 写进 localStorage，是唯一需要这条路的类型）。
    /// - NewAPI：`false`（cookie 兜底已覆盖，**不**同时开两条取数路径）。
    /// - `CustomOpenAiCompatible`：`false`（没有登录流程）。
    ///
    /// 与 `webview_captcha_supported` 是**两种不同的取数机制**，不是同一格的两种写法：
    /// 前者抓 `window.cookies()`（HttpOnly，JS 读不到），后者读页面 localStorage（JS 可读）
    /// 并回传 `tianshu-relay-creds://`。两者可以同时为 `false`（= 该类型没有任何 WebView 兜底）。
    pub webview_bearer_supported: bool,
}

/// 站点类型的**设计能力**。纯函数、无 IO、无网络。
///
/// 界面用它灰显按钮；核心层用它决定是否直接返回 `Error::Unsupported`。
pub fn capabilities(kind: SiteKind) -> SiteCapabilities {
    match kind {
        SiteKind::NewApi | SiteKind::Sub2Api => SiteCapabilities {
            login: true,
            list_keys: true,
            create_key: true,
            reveal_key: true,
            revoke_key: true,
            balance: true,
            groups: true,
            // M14-S3：两个站点类型的 `list_keys` 响应都带每把 key 的当前累计用量
            //（NewAPI `used_quota` / Sub2API `quota_used`），Sub2API 另有 `usage/daily` 日趋势。
            // 适配器已解析进 `KeyMeta.quota_used`，`key_usage` 从 `false` 改 `true`。
            key_usage: true,
            // 两个站点在这一格上**不同**：Sub2API 的分组有 `int64` 主键，NewAPI 以名字为标识。
            // 写在同一个臂里会让 `keys.group_id` 存进 NewAPI 的分组名（M22-S1 复审 P1-1）。
            group_ids: matches!(kind, SiteKind::Sub2Api),
            // M26-S1 / B-191：两个站点在「会话机制」这一格上也**不同**。
            // NewAPI 走 `Set-Cookie`（或 access_token），cookie 兜底路径可达 ⇒ `true`。
            // Sub2API 走 `Authorization: Bearer`（JWT 在响应体里，不写 Set-Cookie）⇒ `false`：
            // WebView 兜底抓不到这种会话，UI 必须把「打开官方页面过一次」面板替换成「不适用」。
            webview_captcha_supported: matches!(kind, SiteKind::NewApi),
            // M28-S1 / B-191：B 路（localStorage → tianshu-relay-creds://）只有 Sub2API 需要。
            // NewAPI 的 cookie 兜底已覆盖，不同时开两条取数路径；Custom 没有登录流程。
            webview_bearer_supported: matches!(kind, SiteKind::Sub2Api),
        },
        // 只读的 OpenAI 兼容端点：只有一个 `/v1/models` 可读，没有任何令牌管理端点，
        // 也没有余额/分组概念（M7-S0 §3.2）。
        SiteKind::CustomOpenAiCompatible => SiteCapabilities {
            login: false,
            list_keys: false,
            create_key: false,
            reveal_key: false,
            revoke_key: false,
            balance: false,
            groups: false,
            key_usage: false,
            // 没有分组概念，自然也没有主键。
            group_ids: false,
            // 没有登录流程，根本不进 CaptchaRequired 分支；fail-closed 同向落点。
            webview_captcha_supported: false,
            webview_bearer_supported: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_table_is_frozen() {
        // 逐格写死期望值：不要用 `..Default::default()` 之类的写法，
        // 否则将来给结构体加字段时，这里会静默通过（M7-S2 spec §7 T3）。
        assert_eq!(
            capabilities(SiteKind::NewApi),
            SiteCapabilities {
                login: true,
                list_keys: true,
                create_key: true,
                reveal_key: true,
                revoke_key: true,
                balance: true,
                groups: true,
                key_usage: true,
                group_ids: false,
                webview_captcha_supported: true,
                webview_bearer_supported: false,
            }
        );
        assert_eq!(
            capabilities(SiteKind::Sub2Api),
            SiteCapabilities {
                login: true,
                list_keys: true,
                create_key: true,
                reveal_key: true,
                revoke_key: true,
                balance: true,
                groups: true,
                key_usage: true,
                group_ids: true,
                webview_captcha_supported: false,
                webview_bearer_supported: true,
            }
        );
        assert_eq!(
            capabilities(SiteKind::CustomOpenAiCompatible),
            SiteCapabilities {
                login: false,
                list_keys: false,
                create_key: false,
                reveal_key: false,
                revoke_key: false,
                balance: false,
                groups: false,
                key_usage: false,
                group_ids: false,
                webview_captcha_supported: false,
                webview_bearer_supported: false,
            }
        );
    }

    #[test]
    fn capabilities_is_deterministic_and_total() {
        for kind in [
            SiteKind::NewApi,
            SiteKind::Sub2Api,
            SiteKind::CustomOpenAiCompatible,
        ] {
            assert_eq!(capabilities(kind), capabilities(kind));
        }
    }

    /// M26-S1 / B-191：`webview_captcha_supported` 取值与站点的会话机制逐条对齐。
    ///
    /// 钉死契约理由，不是「按 kind 排出三个布尔」：
    /// - NewAPI：`newapi.rs::login` 走 `Set-Cookie` 或 `data.access_token`，cookie 兜底可达 ⇒ `true`。
    /// - Sub2API：`sub2api.rs::with_auth` 出 `Authorization: Bearer`，`access_token` 是 JWT 在响应体里，
    ///   **从不写 `Set-Cookie`** ⇒ WebView 兜底抓不到 ⇒ `false`。
    /// - Custom：`login = false`，不进 `CaptchaRequired` 分支 ⇒ fail-closed `false`。
    #[test]
    fn webview_captcha_supported_matches_session_mechanism() {
        assert!(
            capabilities(SiteKind::NewApi).webview_captcha_supported,
            "NewAPI 会话可走 Set-Cookie，WebView cookie 兜底可达"
        );
        assert!(
            !capabilities(SiteKind::Sub2Api).webview_captcha_supported,
            "Sub2API 走 Bearer (JWT 在响应体)，不写 Set-Cookie，WebView 兜底架构性抓不到"
        );
        assert!(
            !capabilities(SiteKind::CustomOpenAiCompatible).webview_captcha_supported,
            "无登录流程，fail-closed"
        );
    }

    /// M28-S1 / B-191：`webview_bearer_supported` 的取值与「哪种会话机制需要 B 路」逐条对齐。
    ///
    /// 钉死**契约理由**，不是按 kind 排三个布尔：
    /// - Sub2API：SPA 把 `auth_token` 写进 localStorage（`stores/auth.ts:11`），cookie 抓不到 ⇒ 只有它能走 B 路 ⇒ `true`。
    /// - NewAPI：`Set-Cookie` 已被 cookie 兜底覆盖，不同时开两条取数路径 ⇒ `false`。
    /// - Custom：`login = false`，没有登录流程 ⇒ fail-closed `false`。
    #[test]
    fn webview_bearer_supported_is_only_for_sub2api() {
        assert!(
            capabilities(SiteKind::Sub2Api).webview_bearer_supported,
            "Sub2API 的 auth_token 在 localStorage，B 路是唯一可达路径"
        );
        assert!(
            !capabilities(SiteKind::NewApi).webview_bearer_supported,
            "NewAPI 已有 cookie 兜底，不同时开两条取数路径"
        );
        assert!(
            !capabilities(SiteKind::CustomOpenAiCompatible).webview_bearer_supported,
            "无登录流程，fail-closed"
        );
        // 两种机制可以同时为 false；Sub2API 是「cookie 假 / B 路真」，NewAPI 是「cookie 真 / B 路假」。
        let sub = capabilities(SiteKind::Sub2Api);
        let new = capabilities(SiteKind::NewApi);
        assert!(!sub.webview_captcha_supported && sub.webview_bearer_supported);
        assert!(new.webview_captcha_supported && !new.webview_bearer_supported);
    }
}
