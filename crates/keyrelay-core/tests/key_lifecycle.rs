//! M7-S4 集成测试：**密钥生命周期状态**（`keys.status` 的写入与读取）。
//!
//! 对应 `docs/specs/M7-S4-密钥生命周期与命名.md` §8.3 的 T-K1…T-K10。
//!
//! 红线（章程 §4.3）：夹具里**不出现任何真实密钥**——`secret_ref` 用钥匙串引用形态
//! （`kr/key/1/secret`），非法值探针用掩码形态（`sk-***`）。

use std::path::PathBuf;

use keyrelay_core::error::Error;
use keyrelay_core::site::KeyStatus;
use keyrelay_core::store::{Store, KEY_STATUS_REVOKED};
use keyrelay_core::vault::secret_ref;

struct Fixture {
    _dir: tempfile::TempDir,
    db_path: PathBuf,
    store: Store,
    site_id: i64,
    key_id: i64,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let db_path = dir.path().join("keyrelay.db");
    let store = Store::open(&db_path).expect("打开文件库");
    let site_id = store
        .upsert_site("newapi", "https://relay.example.com", "测试站")
        .expect("写站点");
    let key_id = store
        .insert_key(
            site_id,
            "keyrelay/codex/20261013",
            &secret_ref("key", 1, "secret"),
            Some("42"),
        )
        .expect("写密钥记录");
    Fixture {
        _dir: dir,
        db_path,
        store,
        site_id,
        key_id,
    }
}

/// 穷举 `match`（**无 `_` 分支**）：`site::KeyStatus` 新增变体时这里**编译失败**，
/// 逼人回来确认 `store::legal_key_statuses()` 是否要跟着改。
fn site_status_label(status: KeyStatus) -> &'static str {
    match status {
        KeyStatus::Enabled => "enabled",
        KeyStatus::Disabled => "disabled",
        KeyStatus::Exhausted => "exhausted",
        KeyStatus::Unknown => "unknown",
    }
}

#[test]
fn set_key_status_accepts_every_legal_value() {
    let f = setup();

    // 站点侧词表：四个变体逐个写入并读回
    for status in [
        KeyStatus::Enabled,
        KeyStatus::Disabled,
        KeyStatus::Exhausted,
        KeyStatus::Unknown,
    ] {
        assert_eq!(
            site_status_label(status),
            status.as_str(),
            "穷举 match 与 as_str 必须一致（新增变体时本测试会编译失败）"
        );
        f.store
            .set_key_status(f.key_id, status.as_str())
            .unwrap_or_else(|e| panic!("{} 应合法: {e}", status.as_str()));
        assert_eq!(
            f.store.key_status(f.key_id).unwrap(),
            Some(status.as_str().to_string())
        );
    }

    // 本地词表：已回收
    f.store
        .set_key_status(f.key_id, KEY_STATUS_REVOKED)
        .expect("revoked 应合法");
    assert_eq!(
        f.store.key_status(f.key_id).unwrap(),
        Some("revoked".to_string())
    );
}

/// 两个命名空间的区别（章程 §3.4 v1.1 裁决）：`revoked` 可写可读回，
/// 但它**不在** `site::KeyStatus` 的四个值里——它是**本地**状态。
#[test]
fn revoked_is_a_local_status_outside_the_site_enum() {
    let f = setup();

    let site_values = [
        KeyStatus::Enabled.as_str(),
        KeyStatus::Disabled.as_str(),
        KeyStatus::Exhausted.as_str(),
        KeyStatus::Unknown.as_str(),
    ];
    assert!(
        !site_values.contains(&KEY_STATUS_REVOKED),
        "revoked 不该出现在站点侧词表里（否则这个常量就没有存在意义）"
    );

    f.store
        .set_key_status(f.key_id, KEY_STATUS_REVOKED)
        .expect("本地状态必须可写");
    assert_eq!(
        f.store.key_status(f.key_id).unwrap().as_deref(),
        Some(KEY_STATUS_REVOKED)
    );
    // 与站点侧的 disabled **必须可区分**（这就是不用 disabled 冒充的理由）
    assert_ne!(KEY_STATUS_REVOKED, KeyStatus::Disabled.as_str());
}

#[test]
fn set_key_status_rejects_illegal_values_without_writing() {
    let f = setup();
    f.store
        .set_key_status(f.key_id, KeyStatus::Enabled.as_str())
        .expect("先写一个已知值");

    for bad in [
        "",
        "REVOKED",  // 大小写敏感
        "Enabled",  // 同上
        " revoked", // 前后空格
        "revoked ", //
        "sk-***",   // 掩码形态也不是合法状态
        "unknown2",
        "disabled; DROP TABLE keys",
    ] {
        let err = f
            .store
            .set_key_status(f.key_id, bad)
            .expect_err(&format!("「{bad}」应被拒绝"));
        assert!(matches!(err, Error::Store(_)), "「{bad}」→ {err:?}");
        assert!(
            err.to_string().contains("keys.status 非法值"),
            "错误文案应说明是哪一列: {err}"
        );
    }

    // 库零改动：非法值之后读回仍是先前那个合法值
    assert_eq!(
        f.store.key_status(f.key_id).unwrap(),
        Some(KeyStatus::Enabled.as_str().to_string()),
        "非法值不得产生任何 UPDATE"
    );
}

#[test]
fn set_key_status_on_a_missing_key_is_an_error() {
    let f = setup();
    let err = f
        .store
        .set_key_status(9_999_999, KeyStatus::Disabled.as_str())
        .expect_err("不存在的 key 必须报错");
    assert!(matches!(err, Error::Store(_)), "{err:?}");
    assert!(err.to_string().contains("密钥不存在"), "{err}");
}

#[test]
fn key_status_returns_none_for_a_missing_key() {
    let f = setup();
    assert_eq!(
        f.store.key_status(9_999_999).expect("读不存在的行不是错误"),
        None
    );
}

#[test]
fn key_status_defaults_to_unknown_for_a_fresh_key() {
    let f = setup();
    assert_eq!(
        f.store.key_status(f.key_id).unwrap(),
        Some("unknown".to_string()),
        "列默认值必须真的在生效（INSERT 不写 status）"
    );
}

#[test]
fn set_key_status_is_idempotent_and_last_write_wins() {
    let f = setup();
    for _ in 0..2 {
        f.store
            .set_key_status(f.key_id, KEY_STATUS_REVOKED)
            .expect("重复写同一个值应成功");
    }
    assert_eq!(
        f.store.key_status(f.key_id).unwrap().as_deref(),
        Some(KEY_STATUS_REVOKED)
    );

    f.store
        .set_key_status(f.key_id, KeyStatus::Disabled.as_str())
        .expect("改写成别的合法值");
    assert_eq!(
        f.store.key_status(f.key_id).unwrap().as_deref(),
        Some(KeyStatus::Disabled.as_str())
    );
}

/// **反证探针**（spec §6.1）：直接删 `keys` 行会经 `ON DELETE CASCADE` 带走该 key 的
/// 全部 `bindings`，漂移追溯随之消失。这条测试断言的是**代价**，所以它红了才说明论证成立。
#[test]
fn deleting_a_key_row_cascades_away_its_binding_traceability() {
    let f = setup();
    f.store
        .record_binding("codex", f.key_id, "/tmp/auth.json", "j1")
        .expect("写绑定");
    assert_eq!(
        f.store.binding_drift_rows().unwrap().len(),
        1,
        "绑定应可被漂移查询看到"
    );

    // 没有 store API 能删 keys 行（本包刻意不提供）→ 用原生 SQL 模拟「有人顺手加了一个 delete_key」
    {
        let conn = rusqlite::Connection::open(&f.db_path).expect("第二个连接");
        let affected = conn
            .execute(
                "DELETE FROM keys WHERE id = ?1",
                rusqlite::params![f.key_id],
            )
            .expect("删 keys 行");
        assert_eq!(affected, 1);
    }

    assert!(
        f.store.binding_drift_rows().unwrap().is_empty(),
        "删 keys 行必须**确实**会带走绑定（`foreign_keys = ON` + `ON DELETE CASCADE`）"
    );
}

/// 与上一条成对：**改状态**不丢追溯（这就是回收用状态而不是删行的理由）。
#[test]
fn marking_a_key_disabled_keeps_its_bindings() {
    let f = setup();
    f.store
        .record_binding("codex", f.key_id, "/tmp/auth.json", "j1")
        .expect("写绑定");

    f.store
        .set_key_status(f.key_id, KEY_STATUS_REVOKED)
        .expect("回收 = 改状态");
    assert_eq!(
        f.store.binding_drift_rows().unwrap().len(),
        1,
        "改状态后绑定必须还在（对照上一条：删行会变 0）"
    );
    assert_eq!(
        f.store.key_status(f.key_id).unwrap().as_deref(),
        Some(KEY_STATUS_REVOKED),
        "状态确实落库了"
    );
    // 站点侧信息与站点归属都还在，追溯链完整
    let row = f.store.get_key(f.key_id).unwrap().expect("行还在");
    assert_eq!(row.site_id, f.site_id);
    assert_eq!(row.remote_id.as_deref(), Some("42"));
}

#[test]
fn key_status_paths_never_carry_a_secret() {
    let f = setup();
    let secret = "sk-0123456789abcdefSECRET";

    // 写路径：把密钥当状态传进来 → 错误文案必须脱敏
    let err = f.store.set_key_status(f.key_id, secret).unwrap_err();
    let text = err.to_string();
    assert!(!text.contains(secret), "错误文案泄漏密钥: {text}");
    assert!(
        !keyrelay_core::redact::contains_secret(&text),
        "错误文案仍含未脱敏凭证: {text}"
    );
    assert!(text.contains("sk-***"), "应留下脱敏痕迹: {text}");

    // 读路径：状态是闭集，读回的值不可能含密钥
    f.store
        .set_key_status(f.key_id, KEY_STATUS_REVOKED)
        .unwrap();
    let status = f.store.key_status(f.key_id).unwrap().expect("有值");
    assert!(!keyrelay_core::redact::contains_secret(&status), "{status}");
}
