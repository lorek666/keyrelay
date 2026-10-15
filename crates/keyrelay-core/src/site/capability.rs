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
}
