// 应用命令清单的**唯一来源**（用 `//` 注释而非 `//!`，因为本文件会被 build.rs `include!`）。
//
// 三处必须一致：
// 1. 本清单 —— `build.rs` 据此生成 `allow-<command>` 权限；
// 2. `lib.rs` 的 `generate_handler!` —— 实际注册；
// 3. `capabilities/default.json` —— 引用 `allow-<command>`。
//
// 漏登记的后果是**运行期**被 ACL 拒绝（`not allowed. Plugin not found`），
// 编译期不报错，因此由 `tests/commands.rs` 的守护测试兜底。

pub const COMMANDS: &[&str] = &["list_sites", "app_info"];
