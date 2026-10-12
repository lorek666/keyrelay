//! M6-S2 集成测试 · 登录自启（macOS LaunchAgent plist / Windows `...\Run` 键）。
//!
//! Windows 分支在本机（macOS）**只验证构造**：`RegOp` 字段与 argv 拼装。
//! 真实登录自启 / 注册表写入未验证（spec §13）。

use std::fs;
use std::path::{Path, PathBuf};

use keyrelay_core::autostart::{
    plan_disable, plan_disable_on, plan_enable, plan_enable_on, state, state_on, AutostartState,
    AutostartTarget, AUTOSTART_SUFFIX,
};
use keyrelay_core::platform_env::{EnvPlan, RegHive};

const APP: &str = "keyrelay";
/// 绝对路径 + 空格（本机是 macOS，`Path::is_absolute()` 是宿主语义，见 spec §13）。
const EXE: &str = "/Applications/KeyRelay App.app/Contents/MacOS/keyrelay";

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().expect("临时目录")
}

fn plist_path(home: &Path, app_id: &str) -> PathBuf {
    home.join("Library/LaunchAgents")
        .join(format!("{app_id}{AUTOSTART_SUFFIX}.plist"))
}

fn files(plan: &EnvPlan) -> &Vec<keyrelay_core::inject::Patch> {
    match plan {
        EnvPlan::Files(patches) => patches,
        other => panic!("应为 Files 计划，实际是 {other:?}"),
    }
}

fn registry(plan: &EnvPlan) -> &Vec<keyrelay_core::platform_env::RegOp> {
    match plan {
        EnvPlan::Registry(ops) => ops,
        other => panic!("应为 Registry 计划，实际是 {other:?}"),
    }
}

// ============================================================ macOS

#[test]
fn mac_enable_writes_plist_with_hidden_flag() {
    let dir = tmp();
    let plan = plan_enable(dir.path(), APP, Path::new(EXE), true).unwrap();
    let patches = files(&plan);
    assert_eq!(patches.len(), 1);
    let patch = &patches[0];

    assert_eq!(patch.path, plist_path(dir.path(), APP));
    assert!(patch.path.is_absolute());
    assert_eq!(patch.before, "");
    assert_eq!(
        patch.new_file_mode, None,
        "自启 plist 不含密钥 → 普通权限（0644）"
    );
    assert!(patch.after.contains(&format!(
        "<key>Label</key>\n\t<string>{APP}{AUTOSTART_SUFFIX}</string>"
    )));
    assert!(patch.after.contains("<key>ProgramArguments</key>"));
    assert!(
        patch.after.contains(&format!("<string>{EXE}</string>")),
        "{}",
        patch.after
    );
    assert!(patch.after.contains("<string>--hidden</string>"));
    assert!(patch.after.contains("<key>RunAtLoad</key>\n\t<true/>"));
}

#[test]
fn mac_fresh_file_is_byte_exact() {
    // 黄金产物：新建自启 plist 的**逐字**形态
    let dir = tmp();
    let plan = plan_enable(dir.path(), APP, Path::new("/x/keyrelay"), true).unwrap();
    let after = &files(&plan)[0].after;

    let expected = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
        <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
        <plist version=\"1.0\">\n\
        <dict>\n\
        \t<key>Label</key>\n\
        \t<string>keyrelay-autostart</string>\n\
        \t<key>ProgramArguments</key>\n\
        \t<array>\n\
        \t\t<string>/x/keyrelay</string>\n\
        \t\t<string>--hidden</string>\n\
        \t</array>\n\
        \t<key>RunAtLoad</key>\n\
        \t<true/>\n\
        </dict>\n\
        </plist>\n";
    assert_eq!(after, expected);
}

#[test]
fn mac_enable_without_hidden_has_no_flag() {
    let dir = tmp();
    let plan = plan_enable(dir.path(), APP, Path::new(EXE), false).unwrap();
    let after = &files(&plan)[0].after;
    assert!(!after.contains("--hidden"), "{after}");
    assert!(after.contains("<key>RunAtLoad</key>\n\t<true/>"));
}

#[test]
fn mac_state_covers_enabled_disabled_unknown() {
    let dir = tmp();
    let path = plist_path(dir.path(), APP);

    // 文件不存在 → Disabled
    assert_eq!(state(dir.path(), APP).unwrap(), AutostartState::Disabled);

    let write = |text: &str| {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, text).unwrap();
    };

    write(
        "<plist version=\"1.0\">\n<dict>\n\t<key>RunAtLoad</key>\n\t<true/>\n</dict>\n</plist>\n",
    );
    assert_eq!(state(dir.path(), APP).unwrap(), AutostartState::Enabled);

    write(
        "<plist version=\"1.0\">\n<dict>\n\t<key>RunAtLoad</key>\n\t<false/>\n</dict>\n</plist>\n",
    );
    assert_eq!(state(dir.path(), APP).unwrap(), AutostartState::Disabled);

    // **验收项**：文件存在但缺 RunAtLoad → Unknown（不得报 Enabled）
    write("<plist version=\"1.0\">\n<dict>\n\t<key>Label</key>\n\t<string>x</string>\n</dict>\n</plist>\n");
    assert_eq!(state(dir.path(), APP).unwrap(), AutostartState::Unknown);

    // 非布尔取值 → Unknown（保守）
    write("<plist version=\"1.0\">\n<dict>\n\t<key>RunAtLoad</key>\n\t<string>true</string>\n</dict>\n</plist>\n");
    assert_eq!(state(dir.path(), APP).unwrap(), AutostartState::Unknown);

    // 内容不是 plist → Unknown
    write("这不是 plist");
    assert_eq!(state(dir.path(), APP).unwrap(), AutostartState::Unknown);

    // 嵌套 dict 里的 RunAtLoad 不算顶层键 → Unknown
    write("<plist><dict><key>Other</key><dict><key>RunAtLoad</key><true/></dict></dict></plist>");
    assert_eq!(state(dir.path(), APP).unwrap(), AutostartState::Unknown);

    // 重复的 RunAtLoad（取舍由解析器决定）→ Unknown，绝不报 Enabled
    write("<plist><dict><key>RunAtLoad</key><true/><key>RunAtLoad</key><false/></dict></plist>");
    assert_eq!(state(dir.path(), APP).unwrap(), AutostartState::Unknown);
}

#[test]
fn mac_refuses_duplicate_managed_keys() {
    let dir = tmp();
    let path = plist_path(dir.path(), APP);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let text = "<plist version=\"1.0\">\n<dict>\n\
                \t<key>RunAtLoad</key>\n\t<true/>\n\
                \t<key>RunAtLoad</key>\n\t<false/>\n\
                </dict>\n</plist>\n";
    fs::write(&path, text).unwrap();

    let err = plan_enable(dir.path(), APP, Path::new(EXE), false).unwrap_err();
    assert!(err.to_string().contains("歧义"), "{err}");
    assert!(plan_disable(dir.path(), APP).is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), text, "拒绝时磁盘零改动");
}

#[test]
fn mac_disable_flips_run_at_load_and_keeps_the_rest() {
    let dir = tmp();
    let backups = dir.path().join("backups");

    let enable = plan_enable(dir.path(), APP, Path::new(EXE), true).unwrap();
    enable.apply_files(&backups).unwrap().unwrap();
    assert_eq!(state(dir.path(), APP).unwrap(), AutostartState::Enabled);

    let disable = plan_disable(dir.path(), APP).unwrap();
    let patches = files(&disable);
    assert_eq!(patches.len(), 1);
    assert!(patches[0]
        .after
        .contains("<key>RunAtLoad</key>\n\t<false/>"));
    assert!(
        patches[0].after.contains("<key>Label</key>"),
        "不得删掉受管的其它键"
    );
    assert!(patches[0].after.contains("<key>ProgramArguments</key>"));
    disable.apply_files(&backups).unwrap();

    assert_eq!(state(dir.path(), APP).unwrap(), AutostartState::Disabled);
    assert!(plist_path(dir.path(), APP).exists(), "禁用不删文件");
}

#[test]
fn mac_disable_on_missing_file_creates_nothing() {
    let dir = tmp();
    let plan = plan_disable(dir.path(), APP).unwrap();
    assert!(files(&plan).is_empty(), "文件不存在时禁用是空计划");
    assert!(plan
        .apply_files(&dir.path().join("backups"))
        .unwrap()
        .is_none());
    assert!(!plist_path(dir.path(), APP).exists());
}

#[test]
fn mac_enable_preserves_extra_keys_and_repairs_unknown_state() {
    let dir = tmp();
    let path = plist_path(dir.path(), APP);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let user = "<plist version=\"1.0\">\n<dict>\n\
                \t<key>KeepAlive</key>\n\t<true/>\n\
                \t<key>StandardOutPath</key>\n\t<string>/tmp/keyrelay.log</string>\n\
                \t<key>RunAtLoad</key>\n\t<string>maybe</string>\n\
                </dict>\n</plist>\n";
    fs::write(&path, user).unwrap();
    assert_eq!(state(dir.path(), APP).unwrap(), AutostartState::Unknown);

    let plan = plan_enable(dir.path(), APP, Path::new(EXE), false).unwrap();
    let after = &files(&plan)[0].after;
    for needle in [
        "<key>KeepAlive</key>\n\t<true/>",
        "<key>StandardOutPath</key>\n\t<string>/tmp/keyrelay.log</string>",
    ] {
        assert!(
            after.contains(needle),
            "非受管键必须逐字保留：{needle}\n{after}"
        );
    }
    plan.apply_files(&dir.path().join("backups"))
        .unwrap()
        .unwrap();

    assert_eq!(state(dir.path(), APP).unwrap(), AutostartState::Enabled);
    // 幂等：再启用一次不应产生改动
    let again = plan_enable(dir.path(), APP, Path::new(EXE), false).unwrap();
    assert!(files(&again).is_empty(), "已启用时必须是空计划");
}

#[test]
fn mac_escapes_the_executable_path() {
    let dir = tmp();
    let weird = "/Applications/A&B <x>.app/Contents/MacOS/keyrelay";
    let plan = plan_enable(dir.path(), APP, Path::new(weird), true).unwrap();
    let after = &files(&plan)[0].after;
    assert!(
        after.contains(
            "<string>/Applications/A&amp;B &lt;x&gt;.app/Contents/MacOS/keyrelay</string>"
        ),
        "{after}"
    );
    plan.apply_files(&dir.path().join("backups"))
        .unwrap()
        .unwrap();
    assert_eq!(
        state(dir.path(), APP).unwrap(),
        AutostartState::Enabled,
        "转义后仍应是合法 plist"
    );
}

#[test]
fn mac_inputs_are_validated() {
    let dir = tmp();
    let exe = Path::new(EXE);

    assert!(
        plan_enable(Path::new("rel"), APP, exe, false).is_err(),
        "home 必须绝对"
    );
    assert!(state(Path::new("rel"), APP).is_err());
    assert!(
        plan_enable(dir.path(), "../evil", exe, false).is_err(),
        "app_id 不得穿越"
    );
    assert!(plan_enable(dir.path(), "", exe, false).is_err());
    assert!(
        plan_enable(dir.path(), APP, Path::new("keyrelay"), false).is_err(),
        "exe 必须绝对"
    );
    assert!(
        plan_enable(dir.path(), APP, Path::new("/x/a\"b"), false).is_err(),
        "exe 不得含引号"
    );
    assert!(plan_enable(dir.path(), APP, Path::new(""), false).is_err());
}

#[test]
fn frozen_wrappers_dispatch_to_the_host_branch() {
    let dir = tmp();
    let exe = Path::new(EXE);
    assert_eq!(
        plan_enable(dir.path(), APP, exe, true).unwrap(),
        plan_enable_on(AutostartTarget::MacLaunchAgent, dir.path(), APP, exe, true).unwrap()
    );
    assert_eq!(
        plan_disable(dir.path(), APP).unwrap(),
        plan_disable_on(AutostartTarget::MacLaunchAgent, dir.path(), APP).unwrap()
    );
    assert_eq!(
        state(dir.path(), APP).unwrap(),
        state_on(AutostartTarget::MacLaunchAgent, dir.path(), APP).unwrap()
    );
}

// ============================================================ Windows 分支（只验构造）

#[test]
fn windows_run_key_ops_are_constructed_and_argv_is_literal() {
    let dir = tmp();
    let exe = Path::new("/Program Files/KeyRelay App/keyrelay.exe");

    let plan = plan_enable_on(AutostartTarget::WindowsRunKey, dir.path(), APP, exe, true).unwrap();
    let ops = registry(&plan);
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].hive, RegHive::CurrentUser);
    assert_eq!(ops[0].key, r"Software\Microsoft\Windows\CurrentVersion\Run");
    assert_eq!(ops[0].name, APP);
    assert_eq!(
        ops[0].value.as_deref(),
        Some("\"/Program Files/KeyRelay App/keyrelay.exe\" --hidden")
    );
    assert_eq!(
        ops[0].to_argv(),
        vec![
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "keyrelay",
            "/t",
            "REG_SZ",
            "/d",
            "\"/Program Files/KeyRelay App/keyrelay.exe\" --hidden",
            "/f",
        ]
    );

    let without =
        plan_enable_on(AutostartTarget::WindowsRunKey, dir.path(), APP, exe, false).unwrap();
    assert_eq!(
        registry(&without)[0].value.as_deref(),
        Some("\"/Program Files/KeyRelay App/keyrelay.exe\"")
    );

    let off = plan_disable_on(AutostartTarget::WindowsRunKey, dir.path(), APP).unwrap();
    assert_eq!(registry(&off)[0].value, None, "空值 = 删除");
    assert_eq!(
        registry(&off)[0].to_argv(),
        vec![
            "delete",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "keyrelay",
            "/f",
        ]
    );

    // 注册表形态无法在本机查询 → Unknown（不是 Disabled，也不是 Err）
    assert_eq!(
        state_on(AutostartTarget::WindowsRunKey, dir.path(), APP).unwrap(),
        AutostartState::Unknown
    );
    assert!(plan
        .apply_files(&dir.path().join("backups"))
        .unwrap()
        .is_none());
}
