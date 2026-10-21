//! M33-S1：本地加密保险库的集成测试（真文件、真 SQLite、真 AES-GCM）。
//!
//! 这些用例只写临时目录，绝不碰 `~/.keyrelay`，也绝不碰真实钥匙串。

use std::path::{Path, PathBuf};

use keyrelay_core::vault::keyfile::StaticMachineId;
use keyrelay_core::vault::{LocalVault, Vault};
use keyrelay_core::Error;

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "keyrelay-vault-it-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn paths(dir: &Path) -> (PathBuf, PathBuf) {
    (dir.join("vault.db"), dir.join("vault.key"))
}

#[test]
fn secrets_survive_a_restart_with_the_same_key_file() {
    let dir = temp_dir();
    let (db, key) = paths(&dir);
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
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn moving_the_folder_to_another_machine_cannot_decrypt() {
    let dir = temp_dir();
    let (db, key) = paths(&dir);
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
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn database_files_contain_no_plaintext() {
    let dir = temp_dir();
    let (db, key) = paths(&dir);
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
    for entry in std::fs::read_dir(&dir).unwrap() {
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
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_row_cannot_be_reused_under_another_reference() {
    let dir = temp_dir();
    let (db, key) = paths(&dir);
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
    std::fs::remove_dir_all(&dir).ok();
}
