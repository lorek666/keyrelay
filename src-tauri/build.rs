// 命令清单与 lib 共享同一份源文件，避免 build.rs 与 generate_handler! 两处硬编码漂移。
include!("src/commands_list.rs");

fn main() {
    // 应用自身的命令在 Tauri 2 里同样受 ACL 管控：必须在这里登记，
    // 否则 build 不会为它们生成 allow-<command> 权限，capabilities 无物可引，
    // 真实运行时与测试运行时都会以「not allowed. Plugin not found」拒绝 IPC 调用。
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));

    tauri_build::try_build(attributes).expect("tauri-build 失败");

    // Windows 测试 exe 的 Common-Controls v6 清单（diag-commands 第二轮实证）。
    //
    // 背景：commands 集成测试链接的 Tauri 界面栈（tao/muda）从 comctl32 导入
    // TaskDialogIndirect / SetWindowSubclass 等 v6 专属 API；Tauri 正式构建会给
    // 应用二进制嵌入 v6 清单，但 cargo test 产物没有，于是加载器绑到 comctl32 v5、
    // 导入解析失败，测试 exe 启动即死 0xc0000139（Windows CI 实测，一行测试都跑不到）。
    // 给 exe 副本嵌入一份标准 v6 清单后 --list 即能列出测试，理论已证实。
    //
    // 只影响测试目标（rustc-link-arg-tests 不作用于应用二进制与 lib 本身），
    // 正式发版产物不受影响；清单内容仅含 v6 依赖一项，与实证用的文件一致。
    if std::env::var("CARGO_CFG_WINDOWS").is_ok() {
        let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR 未设置");
        let manifest_path = std::path::Path::new(&out_dir).join("v6.manifest");
        std::fs::write(
            &manifest_path,
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
</assembly>
"#,
        )
        .expect("写 v6 清单失败");
        println!(
            "cargo:rustc-link-arg-tests=/MANIFESTINPUT:{}",
            manifest_path.display()
        );
    }
}
