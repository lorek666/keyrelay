//! M6-S2 集成测试 · 环境变量落点（macOS LaunchAgent plist / Windows `HKCU\Environment`）。
//!
//! 全部走公开 API（`keyrelay_core::platform_env`），不经命令层——本波次不接线（章程 §5.2）。
//! Windows 分支在本机（macOS）**只验证构造**：`RegOp` 字段与 `reg.exe` argv 的字面量传递。
//!
//! 文件末尾的 `every_entry_point_rejects_traversal_and_leaves_no_trace` 刻意**跨两个模块**
//! （把 `autostart` 的三个入口也列进来）：它守的是「M6-S2 每一个公开入口都拦住路径穿越」这个
//! **不变量**，而不是某个模块的行为——将来加第 8 个入口时，只有这张清单会拦住漏调校验。

use std::fs;
use std::path::{Path, PathBuf};

use keyrelay_core::autostart::{plan_disable, plan_enable, state};
use keyrelay_core::error::Error;
use keyrelay_core::inject;
use keyrelay_core::platform_env::{
    plan_set, plan_unset, plan_unset_named, read_managed, EnvPlan, EnvScope, EnvVar, RegHive,
    BLOCK_BEGIN, BLOCK_END,
};

const APP: &str = "keyrelay";
const SECRET: &str = "sk-platform-env-LEAKY-0123456789";
const BASE: &str = "https://relay.example.com/v1";

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().expect("临时目录")
}

fn var(name: &str, value: &str) -> EnvVar {
    EnvVar {
        name: name.to_string(),
        value: value.to_string(),
    }
}

fn plist_path(home: &Path, app_id: &str) -> PathBuf {
    home.join("Library/LaunchAgents")
        .join(format!("{app_id}.plist"))
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_string()).collect()
}

/// 用户手写的 plist：既有非受管顶层键，也有段内非受管键（对抗性探针的夹具）。
fn user_plist() -> String {
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
     <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
     <plist version=\"1.0\">\n\
     <dict>\n\
     \t<key>Label</key>\n\
     \t<string>my-own-agent</string>\n\
     \t<key>KeepAlive</key>\n\
     \t<true/>\n\
     \t<key>EnvironmentVariables</key>\n\
     \t<dict>\n\
     \t\t<key>MY_OWN_VAR</key>\n\
     \t\t<string>keep-me-please</string>\n\
     \t</dict>\n\
     </dict>\n\
     </plist>\n"
        .to_string()
}

fn write_user_plist(dir: &Path) -> PathBuf {
    let path = plist_path(dir, APP);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, user_plist()).unwrap();
    path
}

fn files_plan(plan: &EnvPlan) -> &Vec<keyrelay_core::inject::Patch> {
    match plan {
        EnvPlan::Files(patches) => patches,
        other => panic!("应为 Files 计划，实际是 {other:?}"),
    }
}

fn registry_plan(plan: &EnvPlan) -> &Vec<keyrelay_core::platform_env::RegOp> {
    match plan {
        EnvPlan::Registry(ops) => ops,
        other => panic!("应为 Registry 计划，实际是 {other:?}"),
    }
}

// ============================================================ macOS：新建 / 更新

#[test]
fn mac_fresh_file_writes_managed_block_with_0600() {
    let dir = tmp();
    let plan = plan_set(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &[var("OPENAI_API_KEY", SECRET), var("OPENAI_BASE_URL", BASE)],
    )
    .unwrap();

    let patches = files_plan(&plan);
    assert_eq!(patches.len(), 1);
    let patch = &patches[0];
    assert_eq!(
        patch.path,
        plist_path(dir.path(), APP),
        "落点必须是 home 下的绝对路径"
    );
    assert!(patch.path.is_absolute());
    assert_eq!(patch.before, "");
    assert_eq!(patch.new_file_mode, Some(0o600), "含密钥的新文件必须 0600");
    assert!(patch.after.contains(BLOCK_BEGIN) && patch.after.contains(BLOCK_END));
    assert!(
        patch.after.contains(&format!(
            "<key>OPENAI_API_KEY</key>\n\t\t<string>{SECRET}</string>"
        )),
        "{}",
        patch.after
    );
    assert!(patch.after.contains(&format!("<string>{BASE}</string>")));
    assert!(patch.after.starts_with("<?xml version=\"1.0\""));
}

#[test]
fn mac_fresh_file_is_byte_exact() {
    // 黄金产物：新建 plist 的**逐字**形态（plist 会被别的工具解析，格式不能随手漂）
    let dir = tmp();
    let plan = plan_set(EnvScope::MacLaunchAgent, dir.path(), APP, &[var("A", "1")]).unwrap();
    let after = &files_plan(&plan)[0].after;

    let expected = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
        <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
        <plist version=\"1.0\">\n\
        <dict>\n\
        \t<key>Label</key>\n\
        \t<string>keyrelay</string>\n\
        \t<key>EnvironmentVariables</key>\n\
        \t<dict>\n\
        \t\t<!-- keyrelay:managed -->\n\
        \t\t<!-- 由 KeyRelay 管理；手工修改会在下次写入时被覆盖 -->\n\
        \t\t<key>A</key>\n\
        \t\t<string>1</string>\n\
        \t\t<!-- /keyrelay:managed -->\n\
        \t</dict>\n\
        </dict>\n\
        </plist>\n";
    assert_eq!(after, expected);
}

#[test]
fn mac_update_preserves_unmanaged_keys_verbatim() {
    // 对抗性探针：用户手写的非受管键（顶层 + 段内）必须逐字保留
    let dir = tmp();
    let path = write_user_plist(dir.path());
    let before = fs::read_to_string(&path).unwrap();

    let plan = plan_set(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &[var("OPENAI_API_KEY", SECRET)],
    )
    .unwrap();
    let patches = files_plan(&plan);
    let patch = &patches[0];

    assert_eq!(patch.before, before, "before 必须是磁盘原文");
    for needle in [
        "<key>Label</key>\n\t<string>my-own-agent</string>",
        "<key>KeepAlive</key>\n\t<true/>",
        "<key>MY_OWN_VAR</key>\n\t\t<string>keep-me-please</string>",
        "<!DOCTYPE plist PUBLIC",
    ] {
        assert!(
            patch.after.contains(needle),
            "非受管内容必须逐字保留：{needle}\n{}",
            patch.after
        );
    }
    assert!(patch.after.contains(SECRET), "受管块必须写进去");
    assert_eq!(patch.after.matches(BLOCK_BEGIN).count(), 1);
    // 段内既有条目与新块并存：`MY_OWN_VAR` 不被改写
    let my_var_at = patch.after.find("MY_OWN_VAR").unwrap();
    let block_at = patch.after.find(BLOCK_BEGIN).unwrap();
    assert!(my_var_at < block_at, "新块追加在既有条目之后");
}

#[test]
fn mac_plan_is_idempotent() {
    let dir = tmp();
    let path = write_user_plist(dir.path());
    let vars = [var("OPENAI_API_KEY", SECRET)];

    let first = plan_set(EnvScope::MacLaunchAgent, dir.path(), APP, &vars).unwrap();
    let after = files_plan(&first)[0].after.clone();
    fs::write(&path, &after).unwrap();

    let second = plan_set(EnvScope::MacLaunchAgent, dir.path(), APP, &vars).unwrap();
    assert!(
        files_plan(&second).is_empty(),
        "同一输入再来一次必须是空计划（幂等，不产生无意义的写入与备份）"
    );

    // 反例保护：换一组变量时必须重新产生补丁（证明「空计划」不是无条件返回的）
    let changed = plan_set(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &[var("OPENAI_API_KEY", SECRET), var("OPENAI_BASE_URL", BASE)],
    )
    .unwrap();
    assert_eq!(files_plan(&changed).len(), 1);
    assert!(files_plan(&changed)[0].after.contains("OPENAI_BASE_URL"));
}

#[test]
fn mac_inserts_env_section_when_absent() {
    let dir = tmp();
    let path = plist_path(dir.path(), APP);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let user = "<plist version=\"1.0\">\n<dict>\n\t<key>Label</key>\n\t<string>x</string>\n</dict>\n</plist>\n";
    fs::write(&path, user).unwrap();

    let plan = plan_set(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &[var("OPENAI_API_KEY", SECRET)],
    )
    .unwrap();
    let after = &files_plan(&plan)[0].after;
    assert!(
        after.contains("<key>Label</key>\n\t<string>x</string>"),
        "{after}"
    );
    assert!(after.contains("<key>EnvironmentVariables</key>"));
    assert!(after.contains(SECRET));
    // 顶层结构没被破坏
    assert!(after.starts_with("<plist version=\"1.0\">\n<dict>\n"));
    assert!(after.ends_with("</dict>\n</plist>\n"));
}

#[test]
fn mac_refuses_same_name_conflict_instead_of_overwriting() {
    // PRD FR-4：「重名冲突时先报冲突让用户确认」；这里必须拒绝，且文件零改动
    let dir = tmp();
    let path = write_user_plist(dir.path());
    let mut text = fs::read_to_string(&path).unwrap();
    text = text.replace("\t\t<key>MY_OWN_VAR</key>", "\t\t<key>OPENAI_API_KEY</key>");
    fs::write(&path, &text).unwrap();

    let err = plan_set(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &[var("OPENAI_API_KEY", SECRET)],
    )
    .unwrap_err();

    assert!(matches!(err, Error::Inject { .. }), "{err:?}");
    let message = err.to_string();
    assert!(message.contains("OPENAI_API_KEY"), "{message}");
    assert!(message.contains("冲突"), "{message}");
    assert_eq!(fs::read_to_string(&path).unwrap(), text, "拒绝时磁盘零改动");
}

#[test]
fn mac_values_with_xml_specials_round_trip() {
    let dir = tmp();
    let raw = "a<b&c>d\"e'f";
    let plan = plan_set(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &[var("WEIRD", raw)],
    )
    .unwrap();
    let patches = files_plan(&plan);
    assert!(
        patches[0]
            .after
            .contains("<string>a&lt;b&amp;c&gt;d\"e'f</string>"),
        "{}",
        patches[0].after
    );

    let journal = plan.apply_files(&dir.path().join("backups")).unwrap();
    assert!(journal.is_some());
    assert_eq!(
        read_managed(EnvScope::MacLaunchAgent, dir.path(), APP).unwrap(),
        vec![var("WEIRD", raw)],
        "读回来必须与写入前逐字一致"
    );
}

// ============================================================ macOS：卸载

#[test]
fn mac_unset_removes_only_managed_block_and_keeps_file() {
    let dir = tmp();
    let path = write_user_plist(dir.path());
    let backups = dir.path().join("backups");

    let plan = plan_set(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &[var("OPENAI_API_KEY", SECRET), var("OPENAI_BASE_URL", BASE)],
    )
    .unwrap();
    plan.apply_files(&backups).unwrap().unwrap();

    let unset = plan_unset(EnvScope::MacLaunchAgent, dir.path(), APP).unwrap();
    unset.apply_files(&backups).unwrap();

    let after = fs::read_to_string(&path).unwrap();
    assert!(path.exists(), "卸载不得删除文件");
    assert!(
        !after.contains(BLOCK_BEGIN) && !after.contains(BLOCK_END),
        "{after}"
    );
    assert!(!after.contains(SECRET), "受管值必须消失：{after}");
    assert!(!after.contains("OPENAI_API_KEY"), "{after}");
    assert!(after.contains("<key>MY_OWN_VAR</key>\n\t\t<string>keep-me-please</string>"));
    assert!(after.contains("<key>KeepAlive</key>\n\t<true/>"));
    assert!(read_managed(EnvScope::MacLaunchAgent, dir.path(), APP)
        .unwrap()
        .is_empty());
}

#[test]
fn mac_unset_named_removes_only_the_named_entries() {
    let dir = tmp();
    let path = plist_path(dir.path(), APP);
    let backups = dir.path().join("backups");

    let plan = plan_set(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &[var("OPENAI_API_KEY", SECRET), var("OPENAI_BASE_URL", BASE)],
    )
    .unwrap();
    plan.apply_files(&backups).unwrap().unwrap();

    let partial = plan_unset_named(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &names(&["OPENAI_API_KEY"]),
    )
    .unwrap();
    partial.apply_files(&backups).unwrap();

    let after = fs::read_to_string(&path).unwrap();
    assert!(!after.contains(SECRET), "被点名的键必须删掉：{after}");
    assert!(after.contains("OPENAI_BASE_URL"), "{after}");
    assert!(
        after.contains(BLOCK_BEGIN) && after.contains(BLOCK_END),
        "块还在"
    );
    assert_eq!(
        read_managed(EnvScope::MacLaunchAgent, dir.path(), APP).unwrap(),
        vec![var("OPENAI_BASE_URL", BASE)]
    );

    // 点名一个不存在的键 → 文件不变（幂等）
    let again = plan_unset_named(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &names(&["NOT_THERE"]),
    )
    .unwrap();
    assert!(files_plan(&again).is_empty(), "点名不存在的键 → 空计划");
    assert_eq!(fs::read_to_string(&path).unwrap(), after);
}

#[test]
fn mac_missing_file_is_an_empty_plan_not_an_error() {
    let dir = tmp();
    let plan = plan_unset(EnvScope::MacLaunchAgent, dir.path(), APP).unwrap();
    assert!(files_plan(&plan).is_empty());
    assert!(plan
        .apply_files(&dir.path().join("backups"))
        .unwrap()
        .is_none());
    assert!(read_managed(EnvScope::MacLaunchAgent, dir.path(), APP)
        .unwrap()
        .is_empty());
    assert!(
        !plist_path(dir.path(), APP).exists(),
        "卸载不得凭空创建文件"
    );
}

// ============================================================ 落盘 / 回滚 / 脱敏

#[test]
fn apply_files_writes_through_inject_and_rolls_back() {
    let dir = tmp();
    let path = write_user_plist(dir.path());
    let before = fs::read_to_string(&path).unwrap();
    let backups = dir.path().join("backups");

    let plan = plan_set(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &[var("OPENAI_API_KEY", SECRET)],
    )
    .unwrap();
    let expected = files_plan(&plan)[0].after.clone();
    let journal = plan.apply_files(&backups).unwrap().expect("应有 journal");

    assert_eq!(fs::read_to_string(&path).unwrap(), expected);
    assert!(path.exists());

    inject::rollback(&journal).unwrap();
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        before,
        "回滚必须字节一致"
    );
}

#[test]
fn rollback_removes_a_file_that_did_not_exist_before() {
    let dir = tmp();
    let path = plist_path(dir.path(), APP);
    let backups = dir.path().join("backups");

    let plan = plan_set(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &[var("OPENAI_API_KEY", SECRET)],
    )
    .unwrap();
    let journal = plan.apply_files(&backups).unwrap().expect("应有 journal");
    assert!(path.exists());
    assert!(
        journal.entries[0].backup.is_none(),
        "新建文件在 journal 里没有备份"
    );

    inject::rollback(&journal).unwrap();
    assert!(!path.exists(), "回滚必须删掉原本不存在的文件");
}

#[cfg(unix)]
#[test]
fn applied_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp();
    let path = plist_path(dir.path(), APP);
    let plan = plan_set(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &[var("OPENAI_API_KEY", SECRET)],
    )
    .unwrap();
    plan.apply_files(&dir.path().join("backups")).unwrap();

    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600,
        "plist 里有明文密钥，权限必须是 0600"
    );
}

#[test]
fn describe_and_debug_never_contain_values() {
    let dir = tmp();
    let mac = plan_set(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &[var("OPENAI_API_KEY", SECRET)],
    )
    .unwrap();
    let mac_text = mac.describe();
    assert!(!mac_text.contains(SECRET), "{mac_text}");
    assert!(!mac_text.contains("LEAKY"), "{mac_text}");
    assert!(!format!("{mac:?}").contains("LEAKY"), "{mac:?}");
    assert!(
        mac_text.contains("OPENAI_API_KEY"),
        "键名要保留：{mac_text}"
    );
    assert!(mac_text.contains("Library/LaunchAgents"), "{mac_text}");

    let win = plan_set(
        EnvScope::WindowsUserEnv,
        dir.path(),
        APP,
        &[var("ANTHROPIC_AUTH_TOKEN", SECRET)],
    )
    .unwrap();
    let win_text = win.describe();
    assert!(!win_text.contains(SECRET), "{win_text}");
    assert!(!format!("{win:?}").contains("LEAKY"), "{win:?}");
    assert!(win_text.contains("ANTHROPIC_AUTH_TOKEN"), "{win_text}");
    assert!(win_text.contains("HKCU\\Environment"), "{win_text}");
    assert!(win_text.contains("设置"), "{win_text}");

    let deletes = plan_unset_named(
        EnvScope::WindowsUserEnv,
        dir.path(),
        APP,
        &names(&["OPENAI_API_KEY"]),
    )
    .unwrap();
    assert!(
        deletes.describe().contains("删除"),
        "{}",
        deletes.describe()
    );
}

// ============================================================ 拒绝路径

#[test]
fn mac_refuses_malformed_targets_without_touching_them() {
    let cases: [(&str, &str); 4] = [
        ("完全不是 plist 的内容", "找不到顶层 <dict>"),
        (
            "<plist><dict><key>EnvironmentVariables</key><string>oops</string></dict></plist>",
            "不是 <dict>",
        ),
        (
            "<plist><dict><key>EnvironmentVariables</key><dict>\n\t\t<!-- keyrelay:managed -->\n\t\t<key>A</key>\n\t\t<string>1</string>\n\t</dict></dict></plist>",
            "结束标记",
        ),
        (
            "<plist><dict><key>EnvironmentVariables</key><dict>\n\t\t<!-- keyrelay:managed -->\n\t\t<!-- /keyrelay:managed -->\n\t\t<!-- keyrelay:managed -->\n\t\t<!-- /keyrelay:managed -->\n\t</dict></dict></plist>",
            "歧义",
        ),
    ];

    for (text, needle) in cases {
        let dir = tmp();
        let path = plist_path(dir.path(), APP);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, text).unwrap();

        let err = plan_set(
            EnvScope::MacLaunchAgent,
            dir.path(),
            APP,
            &[var("OPENAI_API_KEY", SECRET)],
        )
        .unwrap_err();
        assert!(matches!(err, Error::Inject { .. }), "{err:?}");
        assert!(err.to_string().contains(needle), "{} / {needle}", err);
        assert_eq!(fs::read_to_string(&path).unwrap(), text, "拒绝时磁盘零改动");
    }
}

#[test]
fn mac_refuses_duplicate_managed_keys() {
    // 重复键的取舍由解析器决定（多数「后者胜」）：改第一个会让写入静默不生效，
    // 所以宁可拒绝。三个入口（set / unset / read）都必须拒绝。
    let dir = tmp();
    let path = plist_path(dir.path(), APP);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let text = "<plist version=\"1.0\">\n<dict>\n\
                \t<key>EnvironmentVariables</key>\n\t<dict>\n\t\t<key>A</key>\n\t\t<string>1</string>\n\t</dict>\n\
                \t<key>EnvironmentVariables</key>\n\t<dict>\n\t\t<key>B</key>\n\t\t<string>2</string>\n\t</dict>\n\
                </dict>\n</plist>\n";
    fs::write(&path, text).unwrap();

    let err = plan_set(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &[var("OPENAI_API_KEY", SECRET)],
    )
    .unwrap_err();
    assert!(err.to_string().contains("歧义"), "{err}");
    assert!(plan_unset(EnvScope::MacLaunchAgent, dir.path(), APP).is_err());
    assert!(read_managed(EnvScope::MacLaunchAgent, dir.path(), APP).is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), text, "拒绝时磁盘零改动");
}

#[test]
fn inputs_are_validated() {
    let dir = tmp();
    let vars = [var("OPENAI_API_KEY", SECRET)];

    // home 必须是绝对路径
    for err in [
        plan_set(EnvScope::MacLaunchAgent, Path::new("rel"), APP, &vars).unwrap_err(),
        plan_unset(EnvScope::MacLaunchAgent, Path::new("rel"), APP).unwrap_err(),
        read_managed(EnvScope::MacLaunchAgent, Path::new("rel"), APP).unwrap_err(),
    ] {
        assert!(err.to_string().contains("绝对路径"), "{err}");
    }

    // app_id 会被拼进文件名 → 路径穿越必须被拒
    for app_id in ["", ".", "..", "../evil", "a/b", "a\\b", "a b"] {
        let err = plan_set(EnvScope::MacLaunchAgent, dir.path(), app_id, &vars).unwrap_err();
        assert!(err.to_string().contains("app_id"), "{app_id}: {err}");
        assert!(!dir.path().join("Library").exists(), "被拒时不得创建目录");
    }

    // vars 校验
    assert!(plan_set(EnvScope::MacLaunchAgent, dir.path(), APP, &[]).is_err());
    assert!(plan_set(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &[var("A", "1"), var("A", "2")]
    )
    .is_err());
    assert!(plan_set(EnvScope::MacLaunchAgent, dir.path(), APP, &[var("", "1")]).is_err());
    assert!(plan_set(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &[var("A B", "1")]
    )
    .is_err());
    assert!(plan_set(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &[var("A=B", "1")]
    )
    .is_err());
    assert!(plan_set(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &[var("A", "x\0y")]
    )
    .is_err());
    // 制表符 / 换行是允许的
    assert!(plan_set(
        EnvScope::MacLaunchAgent,
        dir.path(),
        APP,
        &[var("A", "x\ty\n")]
    )
    .is_ok());
}

// ============================================================ Windows 分支（只验构造）

#[test]
fn windows_set_produces_registry_ops() {
    let dir = tmp();
    let weird = "v with space \"quote\" and 100% and 中文";
    let plan = plan_set(
        EnvScope::WindowsUserEnv,
        dir.path(),
        APP,
        &[var("OPENAI_API_KEY", weird), var("OPENAI_BASE_URL", BASE)],
    )
    .unwrap();

    let ops = registry_plan(&plan);
    assert_eq!(ops.len(), 2);
    assert_eq!(ops[0].hive, RegHive::CurrentUser);
    assert_eq!(ops[0].key, "Environment");
    assert_eq!(ops[0].name, "OPENAI_API_KEY");
    assert_eq!(ops[0].value.as_deref(), Some(weird));
    assert_eq!(ops[0].full_key(), "HKCU\\Environment");
    assert_eq!(
        ops[0].to_argv(),
        vec![
            "add",
            "HKCU\\Environment",
            "/v",
            "OPENAI_API_KEY",
            "/t",
            "REG_SZ",
            "/d",
            weird,
            "/f",
        ],
        "argv 必须原样传递（不经 shell，不做转义）"
    );
    assert_eq!(ops[1].value.as_deref(), Some(BASE));
}

#[test]
fn windows_delete_ops_and_display_line() {
    let dir = tmp();
    let plan = plan_unset_named(
        EnvScope::WindowsUserEnv,
        dir.path(),
        APP,
        &names(&["OPENAI_API_KEY", "OPENAI_BASE_URL"]),
    )
    .unwrap();
    let ops = registry_plan(&plan);
    assert_eq!(ops.len(), 2);
    assert!(ops.iter().all(|op| op.value.is_none()), "空值 = 删除");
    assert_eq!(
        ops[0].to_argv(),
        vec!["delete", "HKCU\\Environment", "/v", "OPENAI_API_KEY", "/f"]
    );

    // 展示串：空格被引号包裹、引号被双写；真实执行走 to_argv
    let op = keyrelay_core::platform_env::RegOp {
        hive: RegHive::CurrentUser,
        key: "Environment".to_string(),
        name: "K".to_string(),
        value: Some("a b\"c".to_string()),
    };
    assert_eq!(
        op.to_command_line(),
        "reg.exe add HKCU\\Environment /v K /t REG_SZ /d \"a b\"\"c\" /f"
    );
}

#[test]
fn windows_enumeration_gap_is_loud() {
    // spec §14 O-1：注册表无法枚举键名 → 必须报错（不能静默返回空计划），并指向 plan_unset_named
    let dir = tmp();
    let err = plan_unset(EnvScope::WindowsUserEnv, dir.path(), APP).unwrap_err();
    assert!(err.to_string().contains("plan_unset_named"), "{err}");
    let err = read_managed(EnvScope::WindowsUserEnv, dir.path(), APP).unwrap_err();
    assert!(err.to_string().contains("reg.exe"), "{err}");

    // Registry 计划不落盘
    let plan = plan_set(
        EnvScope::WindowsUserEnv,
        dir.path(),
        APP,
        &[var("OPENAI_API_KEY", SECRET)],
    )
    .unwrap();
    assert!(plan
        .apply_files(&dir.path().join("backups"))
        .unwrap()
        .is_none());
    assert!(!dir.path().join("backups").exists(), "不该建备份目录");
}

// ============================================================ 纯函数性

#[test]
fn plans_do_not_read_the_process_environment() {
    let dir = tmp();
    let path = write_user_plist(dir.path());
    let vars = [var("OPENAI_API_KEY", SECRET)];

    let first = plan_set(EnvScope::MacLaunchAgent, dir.path(), APP, &vars).unwrap();

    // 把 HOME / KEYRELAY_HOME 指到别处：计划必须逐字不变（home 只由参数决定）
    let saved_home = std::env::var("HOME").ok();
    let saved_override = std::env::var("KEYRELAY_HOME").ok();
    std::env::set_var("HOME", "/tmp/keyrelay-not-this-home");
    std::env::set_var("KEYRELAY_HOME", "/tmp/keyrelay-not-this-home");
    let second = plan_set(EnvScope::MacLaunchAgent, dir.path(), APP, &vars).unwrap();
    let third = plan_set(EnvScope::MacLaunchAgent, dir.path(), APP, &vars).unwrap();
    match saved_home {
        Some(value) => std::env::set_var("HOME", value),
        None => std::env::remove_var("HOME"),
    }
    match saved_override {
        Some(value) => std::env::set_var("KEYRELAY_HOME", value),
        None => std::env::remove_var("KEYRELAY_HOME"),
    }

    assert_eq!(first, second, "计划不得依赖进程环境变量");
    assert_eq!(second, third, "同一输入必须同输出");
    assert_eq!(files_plan(&first)[0].path, plist_path(dir.path(), APP));
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        user_plist(),
        "计划阶段不得落盘"
    );
}

// ============================================================ 防线守卫（跨两个模块）

/// 递归列出 `root` 下的所有路径（含目录），用于「被拒时磁盘零副作用」的比对。
fn tree_snapshot(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path.clone());
            }
            out.push(path);
        }
    }
    out.sort();
    out
}

/// 一个入口的「非法输入」自检：必须 `Err`，且**磁盘零副作用**。
///
/// 断言只要 `Err`（不钉文案——文案是实现细节）；但必须同时钉住「没有文件被写出去」，
/// 否则「报了错但已经动了文件」这种形态抓不到。
fn assert_rejects_without_trace(label: &str, call: impl Fn(&Path, &str) -> Result<(), Error>) {
    let dir = tmp();
    let before = tree_snapshot(dir.path());

    // ① 路径穿越的 app_id（它会被拼进文件名）
    assert!(
        call(dir.path(), "../evil").is_err(),
        "{label}: 穿越 app_id 必须被拒"
    );
    assert_eq!(
        tree_snapshot(dir.path()),
        before,
        "{label}: 被拒时不得产生任何磁盘副作用"
    );

    // ② 相对 home（会随 CWD 漂移）
    assert!(
        call(
            Path::new("keyrelay-m6s2-relative-home-should-never-exist"),
            APP
        )
        .is_err(),
        "{label}: 相对 home 必须被拒"
    );
    assert_eq!(
        tree_snapshot(dir.path()),
        before,
        "{label}: 被拒时不得产生任何磁盘副作用"
    );
}

/// 防假绿：`tree_snapshot` 必须真的能观测到文件变化——否则上面那条「零副作用」断言是空跑。
#[test]
fn tree_snapshot_detects_changes() {
    let dir = tmp();
    let empty = tree_snapshot(dir.path());
    assert!(empty.is_empty());
    fs::create_dir_all(dir.path().join("a/b")).unwrap();
    fs::write(dir.path().join("a/b/c"), "x").unwrap();
    let after = tree_snapshot(dir.path());
    assert_ne!(after, empty, "快照函数必须能观测到新增的目录与文件");
    assert_eq!(after.len(), 3, "应含 a、a/b、a/b/c：{after:?}");
}

/// **每一个**公开入口都必须拦住路径穿越 / 相对 home。
///
/// 存在的理由（Lead 的裁决，2026-10-12）：这不是覆盖率问题，而是「守卫自己会不会腐化」——
/// 将来有人加第 8 个入口时，只有这张清单会拦住他漏掉 `validate_app_id` / `validate_home`。
/// 新增入口必须在这里补一行。
#[test]
fn every_entry_point_rejects_traversal_and_leaves_no_trace() {
    let vars = [var("OPENAI_API_KEY", SECRET)];
    let names = names(&["OPENAI_API_KEY"]);
    let exe = Path::new("/Applications/KeyRelay.app/Contents/MacOS/keyrelay");

    assert_rejects_without_trace("plan_set(Mac)", |home, app_id| {
        plan_set(EnvScope::MacLaunchAgent, home, app_id, &vars).map(|_| ())
    });
    assert_rejects_without_trace("plan_set(Windows)", |home, app_id| {
        plan_set(EnvScope::WindowsUserEnv, home, app_id, &vars).map(|_| ())
    });
    assert_rejects_without_trace("plan_unset(Mac)", |home, app_id| {
        plan_unset(EnvScope::MacLaunchAgent, home, app_id).map(|_| ())
    });
    assert_rejects_without_trace("plan_unset_named(Mac)", |home, app_id| {
        plan_unset_named(EnvScope::MacLaunchAgent, home, app_id, &names).map(|_| ())
    });
    assert_rejects_without_trace("plan_unset_named(Windows)", |home, app_id| {
        plan_unset_named(EnvScope::WindowsUserEnv, home, app_id, &names).map(|_| ())
    });
    assert_rejects_without_trace("read_managed(Mac)", |home, app_id| {
        read_managed(EnvScope::MacLaunchAgent, home, app_id).map(|_| ())
    });
    // 冻结包装（按平台分派），覆盖 autostart 的三个入口
    assert_rejects_without_trace("plan_enable", |home, app_id| {
        plan_enable(home, app_id, exe, true).map(|_| ())
    });
    assert_rejects_without_trace("plan_disable", |home, app_id| {
        plan_disable(home, app_id).map(|_| ())
    });
    assert_rejects_without_trace("state", |home, app_id| state(home, app_id).map(|_| ()));
}
