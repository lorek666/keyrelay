//! 投递模式（M8-S4 §6）：站点模式与网关模式只差**两个值**，其余逐字相同。
//!
//! 这一条是 FR-5:158「换站零改动」的落地面：agent 配置里从此写的是网关地址与本地令牌，
//! 换站只要重启网关（令牌稳定，见 `gateway_token.rs`），agent 侧不用改。
//!
//! 覆盖：
//! ① 7 条通道在网关模式下都能出计划，且产物里含 `<url>/v1` 与令牌；
//! ② 落点（`target_path`）与站点模式**逐字相同**——模式不是新通道；
//! ③ 计划的 `mode` 字段如实标注；
//! ④ 网关端点为空 ⇒ 拒绝（写一个空 base_url 会把 agent 指向语法错误的目标）；
//! ⑤ 预览/计划的 `Debug` 不泄露令牌。

use std::fs;
use std::sync::Arc;

use keyrelay_core::delivery::{
    DeliveryChannel, DeliveryMode, DeliverySource, GatewayEndpoint, PLACEHOLDER_KEY,
};
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::transport::{HttpResponse, MockTransport};
use keyrelay_core::site::Credentials;
use keyrelay_core::store::Store;
use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};
use serde_json::json;

const SECRET: &str = "sk-mode-0123456789abcdef";
const BASE: &str = "https://relay.example.com";
const GATEWAY_URL: &str = "http://127.0.0.1:8787/v1";
const GATEWAY_TOKEN: &str = "kr-gw-abcdef0123456789";

struct Fixture {
    _dir: tempfile::TempDir,
    service: KeyRelayService<MockTransport>,
    key_id: i64,
}

fn encryption_disabled() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": {"enabled": false}})).unwrap()
}

fn login_ok() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": {"id": 7}}))
        .unwrap()
        .with_header("Set-Cookie", "session=abc; Path=/")
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let store = Store::open(&dir.path().join("keyrelay.db")).unwrap();
    let site_id = store.upsert_site("newapi", BASE, "测试站").unwrap();
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &reference, Some("1"), None)
        .unwrap();
    let vault = Arc::new(MemoryVault::new());
    vault.put(&reference, SECRET).unwrap();
    let mock = MockTransport::new(vec![]);
    let service = KeyRelayService::new(
        store,
        mock.clone(),
        ServiceConfig {
            vault,
            home,
            backup_dir: dir.path().join("backups"),
        },
    );
    mock.push(encryption_disabled());
    mock.push(login_ok());
    service
        .login(site_id, Credentials::new("me", "pw"))
        .await
        .unwrap();
    Fixture {
        _dir: dir,
        service,
        key_id,
    }
}

fn gateway() -> GatewayEndpoint {
    GatewayEndpoint {
        base_url: GATEWAY_URL.to_string(),
        token: GATEWAY_TOKEN.to_string(),
    }
}

/// 所有通道：**Continue 必须给模型名**（§9-12）——否则它连 `plan()` 都过不去，
/// 而那是 Continue 自己的 schema 要求，不是本文件的夹具问题。
fn model_for(channel: DeliveryChannel) -> Option<&'static str> {
    match channel {
        DeliveryChannel::OpenClaw => Some("gpt-4o"),
        _ => None,
    }
}

#[tokio::test]
async fn every_channel_can_point_at_the_gateway() {
    let f = setup().await;
    let endpoint = gateway();

    for channel in DeliveryChannel::ALL {
        let plan = f
            .service
            .delivery_plan_in(
                f.key_id,
                channel,
                model_for(channel),
                DeliverySource::Gateway(&endpoint),
            )
            .unwrap_or_else(|e| panic!("{}: {e}", channel.as_str()));

        assert_eq!(
            plan.mode,
            DeliveryMode::LocalGateway,
            "{}",
            channel.as_str()
        );
        // **令牌必须换掉**：产物里的密钥值应当是网关令牌（掩码末四位），而不是站点密钥。
        // 这一条是「半个开关」的探测器——`base_url` 换成网关、令牌却还是站点密钥的配置会 401。
        assert!(
            plan.fields.iter().any(|f| f.masked.ends_with("6789")),
            "{} 写进去的应当是网关令牌：{:?}",
            channel.as_str(),
            plan.fields
        );
        assert!(
            !plan.fields.iter().any(|f| f.masked.ends_with("cdef")),
            "{} 不该写站点密钥：{:?}",
            channel.as_str(),
            plan.fields
        );

        if channel == DeliveryChannel::CodexAuthJson || channel == DeliveryChannel::DeepSeekHarness
        {
            // §6.3：CodexAuthJson 的 endpoint 在 `~/.codex/config.toml`，不在 auth.json 里。
            // DeepSeekHarness 只写 `KEYRELAY_API_KEY` 到 `.credentials.yaml` 的 `refs:` 段，
            // 不写 base_url——provider 配置在另一个文件 `cordis.patch.yml` 里（spec §3）。
            assert!(
                !plan.preview.contains("127.0.0.1:8787"),
                "{} 不该含网关地址：{}",
                channel.as_str(),
                plan.preview
            );
        } else {
            assert!(
                plan.preview.contains("127.0.0.1:8787"),
                "{} 的产物应含网关地址：{}",
                channel.as_str(),
                plan.preview
            );
        }
    }
}

#[tokio::test]
async fn gateway_mode_differs_from_site_mode_only_in_values() {
    let f = setup().await;
    let endpoint = gateway();

    for channel in DeliveryChannel::ALL {
        let site = f
            .service
            .delivery_plan_in(f.key_id, channel, model_for(channel), DeliverySource::Site)
            .unwrap();
        let gw = f
            .service
            .delivery_plan_in(
                f.key_id,
                channel,
                model_for(channel),
                DeliverySource::Gateway(&endpoint),
            )
            .unwrap();

        assert_eq!(
            site.target_path,
            gw.target_path,
            "{}：落点必须逐字相同（模式不是新通道）",
            channel.as_str()
        );
        assert_eq!(
            site.fields.iter().map(|f| &f.key).collect::<Vec<_>>(),
            gw.fields.iter().map(|f| &f.key).collect::<Vec<_>>(),
            "{}：字段名相同，只有值不同",
            channel.as_str()
        );
        assert_eq!(site.mode, DeliveryMode::Site);
        assert_eq!(gw.mode, DeliveryMode::LocalGateway);
    }
}

#[tokio::test]
async fn gateway_mode_writes_the_gateway_values_and_the_site_mode_keeps_the_old_ones() {
    let f = setup().await;
    let endpoint = gateway();
    let channel = DeliveryChannel::ClaudeCodeSettings;

    let site = f
        .service
        .delivery_plan_in(f.key_id, channel, None, DeliverySource::Site)
        .unwrap();
    let gw = f
        .service
        .delivery_plan_in(f.key_id, channel, None, DeliverySource::Gateway(&endpoint))
        .unwrap();

    // 站点模式：站点 base_url + 站点密钥的掩码
    assert!(
        site.fields.iter().any(|f| f.masked.contains(BASE)),
        "{:?}",
        site.fields
    );
    // 网关模式：网关地址 + 令牌的掩码（**不是**站点地址、**不是**站点密钥）
    assert!(
        gw.fields
            .iter()
            .any(|f| f.masked.contains("127.0.0.1:8787")),
        "{:?}",
        gw.fields
    );
    assert!(
        gw.fields.iter().any(|f| f.masked.ends_with("6789")),
        "写的是网关令牌：{:?}",
        gw.fields
    );
    assert!(
        !gw.fields.iter().any(|f| f.masked.contains(BASE)),
        "网关模式不该出现站点地址：{:?}",
        gw.fields
    );
    assert!(
        !gw.fields.iter().any(|f| f.masked.ends_with("cdef")),
        "网关模式不该出现站点密钥：{:?}",
        gw.fields
    );
}

#[tokio::test]
async fn an_empty_gateway_endpoint_is_refused_without_writing_anything() {
    let f = setup().await;
    let home = f.service.home().to_path_buf();

    for bad in [
        GatewayEndpoint {
            base_url: String::new(),
            token: GATEWAY_TOKEN.to_string(),
        },
        GatewayEndpoint {
            base_url: GATEWAY_URL.to_string(),
            token: String::new(),
        },
    ] {
        let err = f
            .service
            .delivery_plan_in(
                f.key_id,
                DeliveryChannel::ClaudeCodeSettings,
                None,
                DeliverySource::Gateway(&bad),
            )
            .expect_err("空端点必须拒绝");
        assert!(err.to_string().contains("拒绝写入"), "{err}");
    }

    // 零落盘：连目录都还没建
    assert!(
        !home.join(".claude").exists(),
        "拒绝时不该留下任何文件或目录"
    );
}

#[tokio::test]
async fn the_plan_debug_never_prints_the_gateway_token() {
    let f = setup().await;
    let endpoint = gateway();
    let plan = f
        .service
        .delivery_plan_in(
            f.key_id,
            DeliveryChannel::ClaudeCodeSettings,
            None,
            DeliverySource::Gateway(&endpoint),
        )
        .unwrap();

    let text = format!("{plan:?}");
    assert!(!text.contains(GATEWAY_TOKEN), "{text}");
    assert!(!text.contains(SECRET), "{text}");
    // 端点自己的 `Debug` 也不许打印令牌
    assert!(!format!("{endpoint:?}").contains(GATEWAY_TOKEN));
    // 预览是脱敏后的 diff：令牌原文不该出现在里面
    assert!(!plan.preview.contains(GATEWAY_TOKEN), "{}", plan.preview);
}

#[tokio::test]
async fn gateway_mode_still_requires_consent() {
    let f = setup().await;
    let endpoint = gateway();

    let err = f
        .service
        .apply_delivery_in(
            f.key_id,
            DeliveryChannel::ClaudeCodeSettings,
            None,
            DeliverySource::Gateway(&endpoint),
        )
        .expect_err("没同意就不该写");

    assert!(
        matches!(err, keyrelay_core::error::Error::ConsentRequired { .. }),
        "{err:?}"
    );
}

#[tokio::test]
async fn gateway_mode_writes_the_gateway_values_to_disk() {
    let f = setup().await;
    let endpoint = gateway();
    let channel = DeliveryChannel::ClaudeCodeSettings;
    f.service.grant_consent(f.key_id, channel).unwrap();

    let outcome = f
        .service
        .apply_delivery_in(f.key_id, channel, None, DeliverySource::Gateway(&endpoint))
        .unwrap();

    let text = fs::read_to_string(&outcome.target_path).unwrap();
    assert!(text.contains(GATEWAY_URL), "{text}");
    assert!(text.contains(GATEWAY_TOKEN), "{text}");
    assert!(
        !text.contains(SECRET),
        "站点密钥**不得**出现在网关模式的产物里：{text}"
    );
    assert!(
        !text.contains(BASE),
        "站点地址也不该出现（否则换站时 agent 侧还得改）：{text}"
    );
}

#[tokio::test]
async fn the_placeholder_key_is_not_a_real_key_shape() {
    // 预检用的占位密钥必须**看起来就不是密钥**：没有 `sk-` / `nap-` 前缀，
    // 也不像 32 位 hex。它只用于 `plan()` 空跑，但「像不像真密钥」决定了
    // 万一它出现在某个产物或日志里时会不会被误读。
    assert!(!PLACEHOLDER_KEY.starts_with("sk-"), "{PLACEHOLDER_KEY}");
    assert!(!PLACEHOLDER_KEY.starts_with("nap-"), "{PLACEHOLDER_KEY}");
    assert!(PLACEHOLDER_KEY.contains("placeholder"), "{PLACEHOLDER_KEY}");
    assert!(
        PLACEHOLDER_KEY.len() >= 16,
        "太短的值可能撞上某些通道的最小长度校验：{PLACEHOLDER_KEY}"
    );
}
