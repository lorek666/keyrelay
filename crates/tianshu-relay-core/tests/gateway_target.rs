//! M8-S4：**指向网关**（FR-5:158 / B-105）。
//!
//! PRD 那句话是「换站只需改网关后端，agent 侧零改动」。而在此之前
//! `delivery/**` 里**没有任何**把 agent 指向网关的落点（全仓零命中），
//! 现实现是手工复制 token 到 agent 配置——换站之后 agent 侧**必然要改**，
//! 这恰好是 PRD 声称要消除的那件事。
//!
//! 本文件钉两件事：
//! ① **落点与站点模式逐字相同**（同一个 `relative_target`），只换值——这不是靠人工比对，
//!    而是靠「两者走同一个 `resolve_for_binding`」保证的；
//! ② 空地址 / 空令牌在**解析时**就拒绝（写一个空 base_url 会把 agent 指向语法错误的目标，
//!    而那种失败要到 agent 启动时才看得见）。

use std::path::Path;

use tianshu_relay_core::delivery::{
    resolve_for_binding, resolve_for_gateway, DeliveryChannel, GatewayEndpoint, PLACEHOLDER_KEY,
};

const SITE_URL: &str = "https://relay.example.com/v1";
const GATEWAY_URL: &str = "http://127.0.0.1:8787/v1";
const TOKEN: &str = "kr-gw-0123456789abcdef";

fn gateway() -> GatewayEndpoint {
    GatewayEndpoint {
        base_url: GATEWAY_URL.to_string(),
        token: TOKEN.to_string(),
    }
}

#[test]
fn the_landing_point_is_byte_identical_to_the_site_mode() {
    // FR-5:158 的实现基础：**同一个文件、同一组键名**，只换两个值。
    // 落点不同的话「换站零改动」立刻变成「换站要改落点」。
    let home = Path::new("/home/u");
    // B-292：ClineDesktop 已下线，站点与网关两路解析同样拒绝——先钉住下线错误本身。
    for (label, r) in [
        (
            "站点模式",
            resolve_for_binding(
                DeliveryChannel::ClineDesktop,
                home,
                SITE_URL,
                "tianshu-relay",
                Some("gpt-5.6"),
            ),
        ),
        (
            "网关模式",
            resolve_for_gateway(
                DeliveryChannel::ClineDesktop,
                home,
                &gateway(),
                "tianshu-relay",
                Some("gpt-5.6"),
            ),
        ),
    ] {
        let err = match r {
            Ok(_) => panic!("ClineDesktop 应已下线，{label}不应解析出 writer"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("cline auth"),
            "ClineDesktop 下线错误必须指明 cline auth CLI 去向：{err}"
        );
    }
    for channel in DeliveryChannel::ALL {
        // B-292：ClineDesktop 已下线，不再投递，跳过。
        if channel == DeliveryChannel::ClineDesktop {
            continue;
        }
        let site = resolve_for_binding(channel, home, SITE_URL, "tianshu-relay", Some("gpt-5.6"))
            .expect("站点模式应能解析");
        let via_gateway =
            resolve_for_gateway(channel, home, &gateway(), "tianshu-relay", Some("gpt-5.6"))
                .expect("指向网关应能解析");

        assert_eq!(
            site.target_path(),
            via_gateway.target_path(),
            "通道 {} 的落点必须逐字相同",
            channel.as_str()
        );
        assert_eq!(
            site.field_names(),
            via_gateway.field_names(),
            "通道 {} 的键名清单必须相同（只换值，不换形状）",
            channel.as_str()
        );
    }
}

#[test]
fn the_plan_carries_the_gateway_address_and_the_local_token() {
    // 「只换值」的另一半：写进去的确实是网关地址与本地令牌，不是站点地址与站点密钥。
    let home = Path::new("/home/u");
    let writer = resolve_for_gateway(
        DeliveryChannel::ClaudeCodeSettings,
        home,
        &gateway(),
        "tianshu-relay",
        None,
    )
    .expect("解析");

    let patch = writer.plan(TOKEN).expect("生成补丁");
    assert!(
        patch.after.contains(GATEWAY_URL),
        "必须写网关地址: {}",
        patch.after
    );
    assert!(patch.after.contains(TOKEN), "必须写本地令牌");
    assert!(
        !patch.after.contains("relay.example.com"),
        "不得残留站点地址: {}",
        patch.after
    );
}

#[test]
fn an_empty_gateway_address_is_refused_at_resolve_time() {
    let home = Path::new("/home/u");
    for bad in ["", "   "] {
        let endpoint = GatewayEndpoint {
            base_url: bad.to_string(),
            token: TOKEN.to_string(),
        };
        let err = resolve_for_gateway(
            DeliveryChannel::ClaudeCodeSettings,
            home,
            &endpoint,
            "k",
            None,
        )
        .err()
        .expect("空地址必须拒绝");
        assert!(
            err.to_string().contains("网关地址为空"),
            "文案要说清原因: {err}"
        );
    }
}

#[test]
fn an_empty_token_is_refused_at_resolve_time() {
    let home = Path::new("/home/u");
    let endpoint = GatewayEndpoint {
        base_url: GATEWAY_URL.to_string(),
        token: "  ".to_string(),
    };
    let err = resolve_for_gateway(
        DeliveryChannel::ClaudeCodeSettings,
        home,
        &endpoint,
        "k",
        None,
    )
    .err()
    .expect("空令牌必须拒绝");
    assert!(
        err.to_string().contains("网关令牌为空"),
        "文案要说清原因: {err}"
    );
}

#[test]
fn the_endpoint_debug_never_prints_the_token() {
    // 拿到令牌 = 拿到「以本机身份经网关转发」的能力。它只对回环地址有效，
    // 但那不构成「可以打印」的理由。
    let printed = format!("{:?}", gateway());
    assert!(!printed.contains(TOKEN), "Debug 泄漏了令牌: {printed}");
    assert!(
        printed.contains(GATEWAY_URL),
        "地址可以打印（它有诊断价值）"
    );
}

#[test]
fn the_placeholder_key_is_not_a_secret_shape() {
    // §9-8：预检用的占位密钥只用于 `writer.plan()` 的空跑。
    // 它**不能**长得像真密钥——否则它会进入任何「按形态识别密钥」的扫描
    // （`redact::contains_secret` / 脱敏审计），把一次空跑变成一条假告警。
    assert!(!PLACEHOLDER_KEY.starts_with("sk-"));
    assert!(!PLACEHOLDER_KEY.starts_with("nap-"));
    assert!(
        !tianshu_relay_core::redact::contains_secret(PLACEHOLDER_KEY),
        "占位密钥被识别成密钥了——它会让脱敏审计产生假告警"
    );
}

#[test]
fn the_placeholder_key_writes_through_every_deliverable_channel() {
    // §9-8 的实质：轮换在 `create_key` **之前**要用它把每个通道空跑一遍。
    // 这条证明「空跑」这件事在每个通道上都成立（写得进、不报错）。
    let dir = tempfile::tempdir().unwrap();
    for channel in DeliveryChannel::ALL {
        // B-292：ClineDesktop 已下线，不再投递，跳过。
        if channel == DeliveryChannel::ClineDesktop {
            continue;
        }
        let writer = resolve_for_binding(
            channel,
            dir.path(),
            SITE_URL,
            "tianshu-relay",
            Some("gpt-5.6"),
        )
        .unwrap_or_else(|e| panic!("通道 {} 解析失败: {e}", channel.as_str()));
        writer
            .plan(PLACEHOLDER_KEY)
            .unwrap_or_else(|e| panic!("通道 {} 空跑失败: {e}", channel.as_str()));
    }
}
