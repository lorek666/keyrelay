// 应用命令清单的**唯一来源**（用 `//` 注释而非 `//!`，因为本文件会被 build.rs `include!`）。
//
// 三处必须一致：
// 1. 本清单 —— `build.rs` 据此生成 `allow-<command>` 权限；
// 2. `lib.rs` 的 `generate_handler!` —— 实际注册；
// 3. `capabilities/default.json` —— 引用 `allow-<command>`。
//
// 漏登记的后果是**运行期**被 ACL 拒绝（`not allowed. Plugin not found`），
// 编译期不报错，因此由 `tests/commands.rs` 的守护测试兜底。

pub const COMMANDS: &[&str] = &[
    "list_sites",
    "app_info",
    "detect_site",
    "add_site",
    "login_site",
    "list_keys",
    "create_key",
    "site_balance",
    "delivery_plan",
    "grant_consent",
    "revoke_consent",
    "list_consents",
    "list_channel_bindings",
    "apply_delivery",
    "rollback_delivery",
    "list_deliveries",
    "recent_events",
    "list_stored_keys",
    "drift_report",
    "get_settings",
    "update_settings",
    "detect_system_proxy",
    "refresh_all",
    "audit_redaction",
    "gateway_status",
    "gateway_start",
    "gateway_stop",
    "export_bundle",
    "prune_backups",
    // M8-S5A：FR-9:196 诊断包（此前 `service::export_diagnostics` 零生产调用点）
    "export_diagnostics",
    // M6-S5：FR-2 / FR-7 接线
    "available_groups",
    "sync_site_keys",
    "rotation_due",
    "rotation_plan",
    "rotate_key",
    "autostart_status",
    "autostart_set",
    // M7-S5：FR-2 回收（B-82）、FR-8 钥匙串清理、FR-4 未托管落点探测（R-7）
    "revoke_key",
    "purge_keychain",
    "detect_unmanaged_targets",
    "suggest_key_name",
    // M8-S4：解绑（FR-2:115）、网关令牌轮换（§6.4）
    "unbind_agent",
    "gateway_rotate_token",
    // M8-S2：人工过验证码（FR-1:102）
    "captcha_begin",
    "captcha_complete",
    "captcha_cancel",
];
