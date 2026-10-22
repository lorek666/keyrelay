//! `--smoke` 路径的内联 seeding：读 `TIANSHU_RELAY_REAL_KEY` env → 临时 store + MemoryVault
//! 里建一把 smoke key + 授同意 → 交给 `apply_delivery_with_model`。
//!
//! 与 `tests/acceptance_matrix.rs::setup` 同构，差别仅在：
//! - `secret_ref` 用稳定字面量 `kr/smoke/seed/secret`（不依赖自增 id，差异登记 D-2）；
//! - 真密钥从 env 读，不硬编码；
//! - vault 是 `MemoryVault`（进程内），**真密钥不进真钥匙串、不进用户真实 tianshu-relay.db**。
//!
//! seeding 在构造 `TianshuRelayService` **之前**对 `&Store` + `&dyn Vault` 完成：
//! `TianshuRelayService::new` 会 move 掉 store，之后只能走 service 的 `pub` 方法
//! （`grant_consent` / `apply_delivery_with_model`）。

use tianshu_relay_core::delivery::DeliveryChannel;
use tianshu_relay_core::error::{Error, Result};
use tianshu_relay_core::service::TianshuRelayService;
use tianshu_relay_core::store::Store;
use tianshu_relay_core::vault::Vault;

/// 冒烟用的稳定 `secret_ref`。`kr/smoke/seed/secret`：4 段、首段 `kr`、其余非空
/// ⇒ `is_valid_secret_ref` 通过（差异登记 D-2）。
pub const SMOKE_SECRET_REF: &str = "kr/smoke/seed/secret";

/// 冒烟站点的固定形态：`newapi` + 占位 base_url。
///
/// base_url 写进 Claude Code / shell / OpenCode / Gemini / Continue 的配置；
/// 冒烟/mock 路径不联网，占位值不影响 mock-agent 校验。真路径（真 agent）需要
/// 真实 base_url，由 `TIANSHU_RELAY_REAL_BASE_URL` env 覆盖（缺失则用占位值，真 agent
/// 会连不上——真路径本就需手工配，见 spec §12）。
pub const SMOKE_BASE_URL_DEFAULT: &str = "https://relay.example.com";

/// 读 `TIANSHU_RELAY_REAL_BASE_URL` env，缺失用占位值。
pub fn smoke_base_url() -> String {
    std::env::var("TIANSHU_RELAY_REAL_BASE_URL")
        .unwrap_or_else(|_| SMOKE_BASE_URL_DEFAULT.to_string())
}

/// 校验 `TIANSHU_RELAY_REAL_KEY` 形态：`sk-` 前缀 + 长度 ≥ 12。
///
/// 与 `smoke-inject.mjs` 前置 ③ 同口径。不通过返回 `Err`（调用方按 exit 2 处理）。
pub fn validate_real_key(key: &str) -> Result<()> {
    if !key.starts_with("sk-") || key.len() < 12 {
        return Err(Error::InvalidInput(format!(
            "TIANSHU_RELAY_REAL_KEY 不是 sk- 形态或长度不足（当前长度 {}，不打印实际值）",
            key.len()
        )));
    }
    Ok(())
}

/// 在 `store` + `vault` 里建一把 smoke key，返回 `key_id`。
///
/// 步骤：`upsert_site` → `insert_key`（`secret_ref = kr/smoke/seed/secret`）→
/// `vault.put(secret_ref, real_key)`。**不授同意**——同意要 `TianshuRelayService`
/// 构造后走 `grant_consent`（它要 `self.home` / `self.checked_target`）。
pub fn seed_store(store: &Store, vault: &dyn Vault, base_url: &str, real_key: &str) -> Result<i64> {
    let site_id = store.upsert_site("newapi", base_url, "smoke")?;
    let key_id = store.insert_key(site_id, "smoke/seed", SMOKE_SECRET_REF, Some("smoke"), None)?;
    // 真密钥只进 MemoryVault（进程内），不落盘、不进真钥匙串。
    vault.put(SMOKE_SECRET_REF, real_key)?;
    Ok(key_id)
}

/// 给定已构造的 service + 已 seed 的 `key_id`，授同意并投递，返回 `journal_id`。
///
/// `channel` / `model` 透传给 `apply_delivery_with_model`。
/// Continue 通道必须传 `model`（与 `acceptance_matrix.rs::model_for` 同口径）。
pub fn grant_and_apply(
    service: &TianshuRelayService<tianshu_relay_core::site::transport::MockTransport>,
    key_id: i64,
    channel: DeliveryChannel,
    model: Option<&str>,
) -> Result<String> {
    service.grant_consent(key_id, channel)?;
    let outcome = service.apply_delivery_with_model(key_id, channel, model)?;
    Ok(outcome.journal_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tianshu_relay_core::vault::MemoryVault;

    #[test]
    fn smoke_secret_ref_is_valid() {
        // 4 段、首段 kr、其余非空 —— 与 store::is_valid_secret_ref 同规则
        assert!(tianshu_relay_core::vault::is_valid_secret_ref(
            SMOKE_SECRET_REF
        ));
    }

    #[test]
    fn validate_real_key_accepts_sk_form() {
        assert!(validate_real_key("sk-0123456789abcdef").is_ok());
    }

    #[test]
    fn validate_real_key_rejects_non_sk() {
        assert!(validate_real_key("not-a-key").is_err());
        assert!(validate_real_key("sk-short").is_err()); // 长度 < 12
        assert!(validate_real_key("").is_err());
    }

    #[test]
    fn seed_store_returns_key_id_and_puts_secret_in_vault() {
        // 与 acceptance_matrix::setup 同构，但不构造 service（只验 seeding 半段）
        let dir = tempfile::tempdir().expect("tmp");
        let store = Store::open(&dir.path().join("k.db")).expect("open");
        let vault = MemoryVault::new();
        let key_id =
            seed_store(&store, &vault, "https://x.example", "sk-0123456789abcdef").expect("seed");
        assert!(key_id > 0);
        // 密钥进了 vault（get 返回 Result<Option<String>>，double-unwrap）
        assert_eq!(
            vault.get(SMOKE_SECRET_REF).expect("get").expect("present"),
            "sk-0123456789abcdef"
        );
        // store 里有这一行
        let row = store.get_key(key_id).expect("get_key").expect("present");
        assert_eq!(row.secret_ref, SMOKE_SECRET_REF);
        assert_eq!(row.name, "smoke/seed");
    }
}
