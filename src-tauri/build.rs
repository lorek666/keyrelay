// 命令清单与 lib 共享同一份源文件，避免 build.rs 与 generate_handler! 两处硬编码漂移。
include!("src/commands_list.rs");

fn main() {
    // 应用自身的命令在 Tauri 2 里同样受 ACL 管控：必须在这里登记，
    // 否则 build 不会为它们生成 allow-<command> 权限，capabilities 无物可引，
    // 真实运行时与测试运行时都会以「not allowed. Plugin not found」拒绝 IPC 调用。
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));

    tauri_build::try_build(attributes).expect("tauri-build 失败");
}
