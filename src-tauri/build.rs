fn main() {
    // 应用自身的命令在 Tauri 2 里同样受 ACL 管控：必须在这里登记，
    // 否则 build 会为它们生成 allow-<command> 权限，capabilities 才有东西可引用，
    // 真实运行时与测试运行时都会以「not allowed. Plugin not found」拒绝 IPC 调用。
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(&["list_sites", "app_info"]));

    tauri_build::try_build(attributes).expect("tauri-build 失败");
}
