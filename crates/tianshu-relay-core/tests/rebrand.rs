//! M35-S1 §7：旧数据迁移的 9 个场景。
//!
//! 所有用例都在临时目录里造夹具，**不碰真实 `~/.keyrelay`**。

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use tianshu_relay_core::rebrand::{
    resolve_app_home, RebrandStatus, APP_DIR_NAME, DB_FILE_NAME, LEGACY_APP_DIR_NAME,
    LEGACY_DB_FILE_NAME,
};

fn home() -> tempfile::TempDir {
    tempfile::tempdir().expect("临时 home")
}

fn write(p: &Path, bytes: &[u8]) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, bytes).unwrap();
}

/// 目录内容的稳定哈希（文件名 → 字节），用于断言「旧目录一个字节都没改」。
fn tree_hash(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for e in fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            if p.is_dir() {
                walk(root, &p, out);
            } else {
                let rel = p.strip_prefix(root).unwrap().to_string_lossy().to_string();
                out.insert(rel, fs::read(&p).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    if root.exists() {
        walk(root, root, &mut out);
    }
    out
}

/// 造一个「合法的旧库」：用真正的 SQLite 写一行，保证 quick_check 能过。
fn make_valid_db(path: &Path) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch("CREATE TABLE t(x INTEGER); INSERT INTO t VALUES (42);")
        .unwrap();
}

fn add_legacy(home: &Path) {
    make_valid_db(&home.join(LEGACY_APP_DIR_NAME).join(LEGACY_DB_FILE_NAME));
}

#[test]
fn no_legacy_dir_returns_new_path() {
    let h = home();
    let (dir, report) = resolve_app_home(h.path());
    assert_eq!(report.status, RebrandStatus::NoLegacy);
    assert_eq!(dir, h.path().join(APP_DIR_NAME));
    assert!(report.from.is_none());
}

#[test]
fn migrates_and_leaves_legacy_untouched() {
    let h = home();
    add_legacy(h.path());
    make_valid_db(&h.path().join(LEGACY_APP_DIR_NAME).join("vault.db"));
    let before = tree_hash(&h.path().join(LEGACY_APP_DIR_NAME));

    let (dir, report) = resolve_app_home(h.path());

    assert_eq!(report.status, RebrandStatus::Migrated, "{report:?}");
    assert_eq!(dir, h.path().join(APP_DIR_NAME));
    assert_eq!(report.files, 2);
    let new_db = h.path().join(APP_DIR_NAME).join(DB_FILE_NAME);
    assert!(new_db.exists());
    assert_eq!(
        fs::read(&new_db).unwrap(),
        fs::read(h.path().join(LEGACY_APP_DIR_NAME).join(LEGACY_DB_FILE_NAME)).unwrap()
    );
    // 旧目录一个字节都没改
    assert_eq!(before, tree_hash(&h.path().join(LEGACY_APP_DIR_NAME)));
}

#[test]
fn second_call_is_idempotent() {
    let h = home();
    add_legacy(h.path());
    assert_eq!(resolve_app_home(h.path()).1.status, RebrandStatus::Migrated);
    let (_, report) = resolve_app_home(h.path());
    assert_eq!(report.status, RebrandStatus::NoLegacy);
    assert_eq!(report.files, 0, "第二次不该再复制");
}

#[test]
fn new_db_present_means_no_legacy_even_if_old_exists() {
    let h = home();
    add_legacy(h.path());
    write(&h.path().join(APP_DIR_NAME).join(DB_FILE_NAME), b"mine");
    let before = tree_hash(&h.path().join(LEGACY_APP_DIR_NAME));

    let (dir, report) = resolve_app_home(h.path());

    assert_eq!(report.status, RebrandStatus::NoLegacy);
    assert_eq!(dir, h.path().join(APP_DIR_NAME));
    assert_eq!(
        fs::read(h.path().join(APP_DIR_NAME).join(DB_FILE_NAME)).unwrap(),
        b"mine"
    );
    assert_eq!(
        before,
        tree_hash(&h.path().join(LEGACY_APP_DIR_NAME)),
        "旧目录不该动"
    );
}

#[test]
fn non_empty_target_without_db_is_not_overwritten() {
    let h = home();
    add_legacy(h.path());
    write(&h.path().join(APP_DIR_NAME).join("keep.txt"), b"keep me");

    let (_, report) = resolve_app_home(h.path());

    assert_eq!(report.status, RebrandStatus::TargetExists);
    assert_eq!(
        fs::read(h.path().join(APP_DIR_NAME).join("keep.txt")).unwrap(),
        b"keep me"
    );
    assert!(!h.path().join(APP_DIR_NAME).join(DB_FILE_NAME).exists());
}

#[test]
fn corrupt_legacy_db_fails_and_falls_back() {
    let h = home();
    write(
        &h.path().join(LEGACY_APP_DIR_NAME).join(LEGACY_DB_FILE_NAME),
        b"not a sqlite file at all",
    );

    let (dir, report) = resolve_app_home(h.path());

    assert_eq!(report.status, RebrandStatus::Failed, "{report:?}");
    assert_eq!(dir, h.path().join(LEGACY_APP_DIR_NAME), "必须回退旧目录");
    assert!(report.error.is_some());
    // 临时目录已清理
    let leftovers: Vec<_> = fs::read_dir(h.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.contains(".migrating-"))
        .collect();
    assert!(leftovers.is_empty(), "临时目录应已清理: {leftovers:?}");
}

#[test]
fn symlinks_are_skipped_and_reported() {
    let h = home();
    let legacy = h.path().join(LEGACY_APP_DIR_NAME);
    add_legacy(h.path());
    let outside = h.path().join("outside-secret.txt");
    fs::write(&outside, b"must not be copied").unwrap();

    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, legacy.join("link.txt")).unwrap();

    let (_, report) = resolve_app_home(h.path());

    assert_eq!(report.status, RebrandStatus::Migrated, "{report:?}");
    assert!(
        report.warnings.iter().any(|w| w.contains("link.txt")),
        "必须记录被跳过的符号链接: {:?}",
        report.warnings
    );
    assert!(
        !h.path().join(APP_DIR_NAME).join("link.txt").exists(),
        "链接目标不该被复制"
    );
}

#[test]
fn wal_content_is_carried_over() {
    let h = home();
    let legacy_db = h.path().join(LEGACY_APP_DIR_NAME).join(LEGACY_DB_FILE_NAME);
    fs::create_dir_all(legacy_db.parent().unwrap()).unwrap();
    {
        // 保持连接存活到迁移之后：已提交但未 checkpoint 的行还在 -wal 里
        let conn = rusqlite::Connection::open(&legacy_db).unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.execute_batch("CREATE TABLE t(x INTEGER);").unwrap();
        conn.execute("INSERT INTO t VALUES (7)", []).unwrap();

        let (dir, report) = resolve_app_home(h.path());
        assert_eq!(report.status, RebrandStatus::Migrated, "{:?}", report.error);

        let new_db = dir.join(DB_FILE_NAME);
        let c2 = rusqlite::Connection::open(&new_db).unwrap();
        let got: i64 = c2.query_row("SELECT x FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(got, 7, "WAL 里已提交的行必须能读到");
    }
}

#[cfg(unix)]
#[test]
fn new_dir_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let h = home();
    add_legacy(h.path());
    let (dir, _) = resolve_app_home(h.path());
    let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "数据目录必须是 0700，实际 {mode:o}");
}

#[test]
fn retire_legacy_autostart_is_a_noop_without_old_plist() {
    let h = home();
    assert_eq!(
        tianshu_relay_core::rebrand::retire_legacy_autostart(
            h.path(),
            &h.path().join(".tianshu-relay")
        )
        .unwrap(),
        None
    );
}

#[cfg(target_os = "macos")]
#[test]
fn retire_legacy_autostart_flips_run_at_load_and_keeps_file() {
    let h = home();
    let plist: PathBuf = h
        .path()
        .join("Library")
        .join("LaunchAgents")
        .join("keyrelay-autostart.plist");
    fs::create_dir_all(plist.parent().unwrap()).unwrap();
    fs::write(
        &plist,
        "<?xml version=\"1.0\"?>\n<plist><dict><key>RunAtLoad</key>\n\t<true/></dict></plist>\n",
    )
    .unwrap();

    let warning = tianshu_relay_core::rebrand::retire_legacy_autostart(
        h.path(),
        &h.path().join(".tianshu-relay"),
    )
    .unwrap();
    assert!(warning.is_some(), "应给出提示");
    assert!(plist.exists(), "文件必须保留");
    let text = fs::read_to_string(&plist).unwrap();
    assert!(
        text.contains("<false/>"),
        "RunAtLoad 必须被置 false: {text}"
    );
    assert!(!text.contains("<true/>"), "不该残留 true: {text}");
}

#[cfg(target_os = "macos")]
#[test]
fn retire_handles_space_indented_and_explicit_false_element() {
    let h = home();
    let data = h.path().join(".tianshu-relay");
    let plist = h
        .path()
        .join("Library")
        .join("LaunchAgents")
        .join("keyrelay-autostart.plist");
    fs::create_dir_all(plist.parent().unwrap()).unwrap();
    // 合法但**不是**旧实现认的那两种字节形态：空格缩进 + `<true></true>` 闭合写法
    fs::write(
        &plist,
        "<?xml version=\"1.0\"?>\n<plist version=\"1.0\">\n<dict>\n  <key>RunAtLoad</key>\n  <true></true>\n</dict>\n</plist>\n",
    )
    .unwrap();

    let warning = tianshu_relay_core::rebrand::retire_legacy_autostart(h.path(), &data).unwrap();
    assert!(warning.is_some(), "必须识别并停用");
    let text = fs::read_to_string(&plist).unwrap();
    assert!(
        !text.contains("<true></true>") && !text.contains("<true/>"),
        "RunAtLoad 必须变成 false: {text}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn retire_is_idempotent_when_already_false() {
    let h = home();
    let data = h.path().join(".tianshu-relay");
    let plist = h
        .path()
        .join("Library")
        .join("LaunchAgents")
        .join("keyrelay-autostart.plist");
    fs::create_dir_all(plist.parent().unwrap()).unwrap();
    fs::write(
        &plist,
        "<?xml version=\"1.0\"?>\n<plist><dict><key>RunAtLoad</key>\n\t<false/></dict></plist>\n",
    )
    .unwrap();
    let before = fs::read(&plist).unwrap();

    let warning = tianshu_relay_core::rebrand::retire_legacy_autostart(h.path(), &data).unwrap();

    assert!(warning.is_some(), "已知旧项存在时应给出提示");
    assert_eq!(fs::read(&plist).unwrap(), before, "已 false 时不得重写");
}
