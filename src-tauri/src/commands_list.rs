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
    "logout_site",
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
    "report_ui_ready",
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
    // M31-S1：Agent 安装/版本发现（只读）
    "detect_agents",
    // DEBUG-G7 P2-C3：Cline CLI 探针（只读；与 detect_agents 同批只读命令）
    "cline_cli_probe",
    // M43-S1：Agent 网关令牌
    "gateway_token_create",
    "gateway_token_list",
    "gateway_token_revoke",
    // M38-S2：钥匙串迁移（状态 / 显式重试 / 放弃）
    "vault_migration_status",
    "vault_migration_retry",
    "vault_migration_abandon",
    "check_agent_updates",
    "update_agent",
    // M32-S1：Agent 模型下拉（只读，密钥不落日志）
    "list_key_models",
    "suggest_key_name",
    // M8-S4：解绑（FR-2:115）、网关令牌轮换（§6.4）
    "unbind_agent",
    "gateway_rotate_token",
    // M8-S2：人工过验证码（FR-1:102）
    "captcha_begin",
    "captcha_complete",
    "captcha_cancel",
    // M13-S1：Token 消耗统计
    "recent_gateway_usage",
    "recent_usage_snapshots",
    // M14-S3：per-key 用量采样（Sub2API usage/daily）
    "recent_key_usage",
    // M34-S1：用量看板（站点 / 模型 / 天聚合，只读）
    "usage_dashboard",
    "model_price_list",
    "model_price_upsert",
    "model_price_delete",
    // M46-S5：站点 / key 硬预算
    "site_budget_list",
    "site_budget_create",
    "site_budget_delete",
    "site_bill_probe",
    "site_bill_import",
    "site_bills",
    // M46-S6：多源账单对账（只读）
    "bill_reconciliation",
    // M14-S1：模型别名映射（B-110）
    "list_alias_map",
    "upsert_alias",
    "delete_alias",
    // M15-S1：模型检测（bazaarlink probe）
    "probe_run",
    "list_probe_runs",
    "get_probe_run",
    // 投递改进 P1-5：一键重启（Codex / Claude Desktop；其余 CLI 类不进命令表）
    "restart_codex",
    "restart_claude_desktop",
];
