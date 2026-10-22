//! M33-S1：本地加密保险库的集成测试（真文件、真 SQLite、真 AES-GCM）。
//!
//! 这些用例只写临时目录，绝不碰 `~/.tianshu-relay`，也绝不碰真实钥匙串。

use std::path::{Path, PathBuf};

use tianshu_relay_core::vault::keyfile::StaticMachineId;
use tianshu_relay_core::vault::{LocalVault, Vault};
use tianshu_relay_core::Error;

/// `tempfile::TempDir`：并行测试不撞名（复审 P2-2）。
fn temp_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("建临时目录")
}

fn paths(dir: &Path) -> (PathBuf, PathBuf) {
    (dir.join("vault.db"), dir.join("vault.key"))
}

#[test]
fn secrets_survive_a_restart_with_the_same_key_file() {
    let dir = temp_dir();
    let (db, key) = paths(dir.path());
    let machine = StaticMachineId(Some("machine-a".into()));

    {
        let vault = LocalVault::open_with_machine(&db, &key, &machine).unwrap();
        vault.put("kr/key/1/secret", "sk-first-value").unwrap();
        vault.put("kr/site/2/session", "cookie-value").unwrap();
        assert_eq!(vault.count().unwrap(), 2);
    }

    let reopened = LocalVault::open_with_machine(&db, &key, &machine).unwrap();
    assert_eq!(
        reopened.get("kr/key/1/secret").unwrap().as_deref(),
        Some("sk-first-value")
    );
    assert_eq!(
        reopened.get("kr/site/2/session").unwrap().as_deref(),
        Some("cookie-value")
    );
}

#[test]
fn moving_the_folder_to_another_machine_cannot_decrypt() {
    let dir = temp_dir();
    let (db, key) = paths(dir.path());
    let here = StaticMachineId(Some("machine-a".into()));
    let elsewhere = StaticMachineId(Some("machine-b".into()));

    {
        let vault = LocalVault::open_with_machine(&db, &key, &here).unwrap();
        vault.put("kr/key/1/secret", "sk-secret").unwrap();
    }

    let err = match LocalVault::open_with_machine(&db, &key, &elsewhere) {
        Ok(_) => panic!("换一台机器不该解得开"),
        Err(err) => err,
    };
    assert!(
        matches!(err, Error::Vault(_)),
        "应该是 Vault 错误，实际: {err:?}"
    );
}

#[test]
fn losing_the_key_file_must_fail_and_not_create_a_fresh_one() {
    // 复审 P1-1：删掉 vault.key 后重开，必须报错，且**不能**生成新的空密钥文件
    // （否则旧密文会被一把新 DEK 永久锁死，而启动看起来一切正常）。
    let dir = temp_dir();
    let (db, key) = paths(dir.path());
    let machine = StaticMachineId(Some("machine-a".into()));

    {
        let vault = LocalVault::open_with_machine(&db, &key, &machine).unwrap();
        vault.put("kr/key/1/secret", "sk-must-survive").unwrap();
    }
    std::fs::remove_file(&key).unwrap();
    assert!(!key.exists());

    let err = match LocalVault::open_with_machine(&db, &key, &machine) {
        Ok(_) => panic!("密钥文件缺失时必须拒绝打开"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("密钥文件"), "{err}");
    assert!(!key.exists(), "不得凭空生成新的密钥文件覆盖现场");

    // 换一个同样不存在的密钥路径也一样：库里已有密文，绝不能悄悄生成新 DEK。
    let other_key = dir.path().join("another.key");
    assert!(
        LocalVault::open_with_machine(&db, &other_key, &machine).is_err(),
        "库里已有密文时，任何新密钥文件都必须被拒绝"
    );
    assert!(!other_key.exists());
}

#[test]
fn database_files_contain_no_plaintext() {
    let dir = temp_dir();
    let (db, key) = paths(dir.path());
    let machine = StaticMachineId(Some("machine-a".into()));
    {
        let vault = LocalVault::open_with_machine(&db, &key, &machine).unwrap();
        vault
            .put("kr/key/9/secret", "sk-plaintext-marker-1234567890")
            .unwrap();
        // 触发一次 checkpoint，让密文落到主库文件而不只是 WAL。
        drop(vault);
    }

    let mut blobs = Vec::new();
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with("vault.db"))
            .unwrap_or(false)
        {
            blobs.extend(std::fs::read(&path).unwrap());
        }
    }
    let text = String::from_utf8_lossy(&blobs);
    assert!(
        !text.contains("sk-plaintext-marker"),
        "库文件里出现了明文密钥"
    );
    assert!(text.contains("krseal1."), "库文件里应该有密文封套");
}

#[test]
fn a_row_cannot_be_reused_under_another_reference() {
    let dir = temp_dir();
    let (db, key) = paths(dir.path());
    let machine = StaticMachineId(Some("machine-a".into()));
    let vault = LocalVault::open_with_machine(&db, &key, &machine).unwrap();
    vault.put("kr/key/1/secret", "sk-one").unwrap();

    // 直接把 A 行的 seal 抄到 B 行（模拟「换行攻击」）。
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute(
        "INSERT INTO vault_secrets(ref, seal, created_at, updated_at)
         SELECT 'kr/key/2/secret', seal, created_at, updated_at FROM vault_secrets WHERE ref = 'kr/key/1/secret'",
        [],
    )
    .unwrap();
    drop(conn);

    let err = vault.get("kr/key/2/secret").unwrap_err();
    assert!(err.to_string().contains("密文校验失败"), "{err}");
}

#[test]
fn probe_rejects_a_key_file_from_another_vault() {
    // 复审 P2-5：密钥文件有效、但和库里的密文不是一对时，probe 必须报不可用。
    let dir_a = temp_dir();
    let dir_b = temp_dir();
    let machine = StaticMachineId(Some("machine-a".into()));

    let a = LocalVault::open_with_machine(&paths(dir_a.path()).0, &paths(dir_a.path()).1, &machine)
        .unwrap();
    a.put("kr/key/1/secret", "sk-a").unwrap();

    let b = LocalVault::open_with_machine(&paths(dir_b.path()).0, &paths(dir_b.path()).1, &machine)
        .unwrap();

    // 用 B 的密钥文件去开 A 的库
    let mismatched =
        LocalVault::open_with_machine(&paths(dir_a.path()).0, &paths(dir_b.path()).1, &machine)
            .unwrap();
    assert!(
        mismatched.probe().is_err(),
        "密钥文件与保险库不匹配时 probe 必须失败: {:?}",
        mismatched.probe()
    );
    // 正常的那个仍然可用
    assert!(b.probe().is_ok());
}
