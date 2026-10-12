//! 注入器端到端：plan → apply → rollback，要求字节级还原与受管键隔离。

use std::fs;

use keyrelay_core::inject::codex::CodexInjector;
use keyrelay_core::inject::{apply, rollback, sha256_hex, Binding, Injector};
use keyrelay_core::Error;

const FIXTURE: &str = r#"# 用户自己的注释
model = "gpt-6-astra"
model_reasoning_effort = "xhigh"

notify = [
    "/Users/me/notify.sh",
    "turn-ended",
]

[marketplaces.karpathy-skills]
source_type = "git"
source = "https://github.com/forrestchang/andrej-karpathy-skills.git"

[model_providers.my-own]
name = "my-own"
base_url = "https://my.example.com/v1"
wire_api = "chat"
"#;

fn binding() -> Binding {
    Binding {
        base_url: "https://newapi.example.com".into(),
        api_key: "sk-must-not-be-written".into(),
        model: Some("gpt-5.6".into()),
        provider_id: "keyrelay".into(),
    }
}

#[test]
fn roundtrip_restores_original_bytes_and_keeps_user_content() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    fs::write(&config, FIXTURE).unwrap();
    let original_sha = sha256_hex(FIXTURE.as_bytes());

    let injector = CodexInjector::new(&config);
    let patches = injector.plan(&binding()).unwrap();
    assert_eq!(patches.len(), 1);

    // 计划里必须包含受管键，且不含用户原有 provider 的破坏
    assert!(patches[0].after.contains("model_provider = \"keyrelay\""));
    assert!(patches[0].after.contains("[model_providers.my-own]"));
    assert!(patches[0].after.contains("notify = ["));
    assert!(patches[0].after.contains("# 用户自己的注释"));

    let journal = apply(&patches, &dir.path().join("backups")).unwrap();
    let applied = fs::read_to_string(&config).unwrap();
    assert!(applied.contains("[model_providers.keyrelay]"));
    assert!(applied.contains("base_url = \"https://newapi.example.com/v1\""));
    assert!(
        !applied.contains("sk-must-not-be-written"),
        "密钥不得写入配置"
    );
    assert_eq!(journal.entries.len(), 1);
    assert!(journal.entries[0].backup.is_some());

    // 备份内容 = 注入前内容
    let backup = journal.entries[0].backup.clone().unwrap();
    assert_eq!(fs::read_to_string(backup).unwrap(), FIXTURE);

    rollback(&journal).unwrap();
    assert_eq!(sha256_hex(&fs::read(&config).unwrap()), original_sha);
    assert_eq!(fs::read_to_string(&config).unwrap(), FIXTURE);
}

#[test]
fn second_injection_is_idempotent_on_managed_keys() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    fs::write(&config, FIXTURE).unwrap();
    let injector = CodexInjector::new(&config);

    let first = injector.plan(&binding()).unwrap();
    let journal = apply(&first, &dir.path().join("backups")).unwrap();
    let after_first = fs::read_to_string(&config).unwrap();

    // 再次注入：内容应稳定（除 provider 块重复覆盖外无新增）
    let second = injector.plan(&binding()).unwrap();
    assert_eq!(second[0].before, after_first);
    let journal2 = apply(&second, &dir.path().join("backups")).unwrap();
    let after_second = fs::read_to_string(&config).unwrap();
    assert_eq!(after_first, after_second, "重复注入不应改变文件内容");

    rollback(&journal2).unwrap();
    assert_eq!(fs::read_to_string(&config).unwrap(), after_first);
    rollback(&journal).unwrap();
    assert_eq!(fs::read_to_string(&config).unwrap(), FIXTURE);
}

#[test]
fn refuses_to_apply_when_file_changed_behind_our_back() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    fs::write(&config, FIXTURE).unwrap();

    let injector = CodexInjector::new(&config);
    let patches = injector.plan(&binding()).unwrap();

    // 模拟并发修改
    fs::write(&config, format!("{FIXTURE}\n# 别人加的一行\n")).unwrap();

    let err = apply(&patches, &dir.path().join("backups")).unwrap_err();
    assert!(matches!(err, Error::Inject { .. }));
    assert!(fs::read_to_string(&config)
        .unwrap()
        .contains("别人加的一行"));
}

#[test]
fn refuses_rollback_after_external_edit() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    fs::write(&config, FIXTURE).unwrap();

    let injector = CodexInjector::new(&config);
    let patches = injector.plan(&binding()).unwrap();
    let journal = apply(&patches, &dir.path().join("backups")).unwrap();

    fs::write(&config, "手工改坏了").unwrap();
    let err = rollback(&journal).unwrap_err();
    assert!(matches!(err, Error::Inject { .. }));
    assert_eq!(fs::read_to_string(&config).unwrap(), "手工改坏了");
}
