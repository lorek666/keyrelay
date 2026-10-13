//! `Zeroizing` 落地（M8-S5A §2，关闭 DEBUG 报告 §1.10）。
//!
//! `M7-S5` spec §2.1 要求「`service.rs` 里从钥匙串取出、交给投递 / 轮换 / 网关的明文
//! 都用 `Zeroizing` 包住，并有一条清零断言」，复审 §6-4 写的却是「核了」——
//! 实际全仓没有一处 `Zeroizing`，也没有任何 `.zeroize()` 断言。
//!
//! 这里的三条断言各自可证伪，且**不读已释放内存**（第一版设计想读 `Vec` drop 之后的
//! 缓冲来断言清零，那是未定义行为：可能碰巧是 0、可能不是，而且随时可能被复用）。
//!
//! 三条加起来是完整的两半：
//! - 类型系统管**覆盖**（`key_secret` 的返回值类型就是 `Zeroizing`，调用方拿不到裸 `String`）；
//! - 这三条管**契约**（`Zeroizing` 的 drop 真的调 `Zeroize`，`Zeroize` 真的写零）。

use std::fs;
use std::sync::Arc;

use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::transport::{HttpResponse, MockTransport};
use keyrelay_core::site::Credentials;
use keyrelay_core::store::Store;
use keyrelay_core::vault::{secret_ref, MemoryVault, Vault};
use serde_json::json;
use zeroize::{Zeroize, Zeroizing};

const SECRET: &str = "sk-zeroize-0123456789abcdef";
const BASE: &str = "https://relay.example.com";

/// 计数型内层类型：`Zeroize` 被调用了几次。
///
/// 用它而不是观察缓冲，是因为「`Zeroizing` 的 `Drop` 会不会调 `Zeroize`」
/// 是**我们整套设计依赖的那条契约**，而它是可以被证伪的：把 `Zeroizing` 换成裸值，
/// 计数就是 0。
#[derive(Default)]
struct Counter {
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl Zeroize for Counter {
    fn zeroize(&mut self) {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[test]
fn zeroizing_calls_zeroize_on_drop() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let _guard = Zeroizing::new(Counter {
            calls: Arc::clone(&calls),
        });
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "活着的时候不该清零"
        );
    }
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "Zeroizing 的 Drop 必须调用内层 Zeroize——这是整套设计依赖的契约"
    );
}

#[test]
fn zeroize_really_wipes_a_real_buffer() {
    // 定长数组在栈上：`zeroize()` 之后缓冲**还活着**，断言读的是活内存。
    // 这一条证明的是「`zeroize` 在本项目的真实缓冲上会写零」，
    // 而不是「依赖出现在 Cargo.toml 里」。
    let mut buf = *b"sk-live-buffer-0123456789ab";
    assert!(
        buf.iter().any(|b| *b != 0),
        "对照组：清零前必须真的有内容（否则这条测的是「本来就是 0」）"
    );
    buf.zeroize();
    assert!(buf.iter().all(|b| *b == 0), "zeroize 没有把缓冲写零");
}

#[test]
fn zeroizing_does_not_protect_against_debug() {
    // **这条纠正了我写 spec 时的想当然**：`zeroize::Zeroizing` 的 `Debug` 是**透传**的
    // （打印成 `Zeroizing("sk-…")`）。它保护的是「drop 时擦内存」，**不是**「不会被打印」。
    //
    // 后果值得说清：任何持有 `Zeroizing` 的结构体只要 `#[derive(Debug)]`，
    // 密钥就会随一次 `{:?}` 外流——在这里 `Zeroizing` 给的是一种**虚假的安全感**。
    // 本仓的处置是让持有者**手写** `Debug`（`GatewayConfig` 就是：它刻意不把
    // `keys_by_ref` 放进 field 列表，见 `gateway.rs` 的同名测试）。
    //
    // 这条断言把「透传」这个事实钉住：将来有人以为它会被掩成 `***` 时，这里会红。
    let wrapped = Zeroizing::new(SECRET.to_string());
    let printed = format!("{wrapped:?}");
    assert!(
        printed.contains("sk-zeroize"),
        "Zeroizing 的 Debug 应当是透传的。这条红了说明 zeroize 改了语义——\
         那要重新评估 `GatewayConfig` 手写 Debug 的必要性，而不是把这条改绿: {printed}"
    );
    // 顺带钉住「包了一层不等于改了值」：deref 之后内容照旧可读。
    assert_eq!(wrapped.as_str(), SECRET);
}

#[test]
fn the_zeroizing_holder_has_a_hand_written_debug() {
    // 上一条说的是「`Zeroizing` 自己不管 Debug」。那么**持有者**必须管。
    // 本仓目前唯一持有 `Zeroizing<String>` 的生产结构体是 `GatewayConfig`；
    // 它必须是手写 `Debug`，而且 `keys_by_ref` 不得出现在 field 列表里。
    let gateway = include_str!("../src/gateway.rs");
    assert!(
        gateway.contains("impl std::fmt::Debug for GatewayConfig"),
        "GatewayConfig 必须手写 Debug"
    );
    let derive_line = gateway
        .lines()
        .find(|line| line.contains("pub struct GatewayConfig"))
        .unwrap_or_default();
    // `#[derive(…)]` 在 struct 行的上一行；往回找三行足够。
    let idx = gateway
        .lines()
        .position(|line| line.contains("pub struct GatewayConfig"))
        .unwrap_or(0);
    let window: Vec<&str> = gateway
        .lines()
        .skip(idx.saturating_sub(3))
        .take(4)
        .collect();
    let derives = window.join(" ");
    assert!(
        !derives.contains("Debug"),
        "GatewayConfig 不得 derive Debug（Zeroizing 的 Debug 是透传的，会打印密钥）: {derive_line}"
    );
}

async fn service_with_one_key() -> (tempfile::TempDir, KeyRelayService<MockTransport>, i64) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let store = Store::open(&dir.path().join("keyrelay.db")).unwrap();
    let site_id = store.upsert_site("newapi", BASE, "测试站").unwrap();
    let reference = secret_ref("key", 1, "secret");
    let key_id = store
        .insert_key(site_id, "codex/daily", &reference, Some("1"), None)
        .unwrap();
    let vault = Arc::new(MemoryVault::new());
    vault.put(&reference, SECRET).unwrap();
    let mock = MockTransport::new(vec![]);
    let service = KeyRelayService::new(
        store,
        mock.clone(),
        ServiceConfig {
            vault,
            home,
            backup_dir: dir.path().join("backups"),
        },
    );
    mock.push(
        HttpResponse::json(200, json!({"success": true, "data": {"enabled": false}})).unwrap(),
    );
    mock.push(
        HttpResponse::json(200, json!({"success": true, "data": {"id": 7}}))
            .unwrap()
            .with_header("Set-Cookie", "session=abc; Path=/"),
    );
    service
        .login(site_id, Credentials::new("me", "pw"))
        .await
        .unwrap();
    (dir, service, key_id)
}

#[tokio::test]
async fn key_secret_returns_a_zeroizing_wrapper() {
    // **这一条是这次修复的全部内容**：`Zeroizing<String>` 的 deref 让所有调用点
    // 照旧编译，所以「返回类型被改回裸 `String`」没有任何别的测试会红。
    let (_dir, service, key_id) = service_with_one_key().await;
    let secret: Zeroizing<String> = service.key_secret_for_test(key_id).expect("取密钥");
    assert_eq!(secret.as_str(), SECRET);
}

#[test]
fn the_vault_is_read_through_exactly_one_choke_point() {
    // `gateway_config` 原来自己抄了一遍 `vault.get` + `ensure_not_revoked`（DEBUG 报告
    // §1.10 的现场）。两处同义代码的后果是：`Zeroizing` 只能包住其中一处，
    // 而另一处是不是包住了要看有没有人记得改。
    //
    // 断言的是**源码里 `vault.get` 的出现次数为 1**——这是一条脆弱的文本断言，
    // 所以它只钉「不要长出第二个明文出口」这一件事，不试图证明更多。
    //
    // **实测过的教训**：加上 §5 的 `sync_site_keys` 之后这条**当场红了**（2 处）——
    // 而那一处是「查一下在不在」不是「把明文取出来用」。处置不是放宽这条断言，
    // 是给 `Vault` 加 `has()`（名字上分开意图），于是这条守卫的前提重新成立。
    let source = include_str!("../src/service.rs");
    let reads = source
        .lines()
        .filter(|line| line.contains("vault.get("))
        .filter(|line| !line.trim_start().starts_with("//"))
        .count();
    assert_eq!(
        reads, 1,
        "明文出口应当只有 `key_secret` 一处；新增读取点请走 `key_secret`（当前 {reads} 处）"
    );
}

#[test]
fn the_gateway_config_copy_is_wrapped_too() {
    // 这条守卫的**前身**断言的是「必须留着那句未接线声明」：M8-S5A 时期
    // `GatewayConfig::api_key` 还是裸 `String`，于是 `service.rs` 里那次 `.to_string()`
    // 产生了一个未清零的副本，代码里必须写明去向（M8-S1 章程 §3.5 第 13 行）。
    // M8-S4 把类型换成 `Zeroizing<String>` 之后那句声明消失——守卫随之换向：
    // 从「声明未接线」变成「**接线不许回退**」。
    //
    // 为什么非要有这条守卫：把类型改回裸 `String` 不会让任何**行为**测试变红
    // （`Zeroizing` 的 `Deref` 让所有调用点照旧编译，`key_secret_returns_a_zeroizing_wrapper`
    // 也只看返回类型），所以只有文本断言拦得住它。
    let gateway = include_str!("../src/gateway.rs");
    assert!(
        gateway.contains("pub api_key: Zeroizing<String>"),
        "`GatewayConfig::api_key` 必须是 `Zeroizing<String>`：\
         它每请求被 clone，裸 `String` 会留下一份永不擦除的站点密钥"
    );

    let service = include_str!("../src/service.rs");
    let bare_copies = service
        .lines()
        .filter(|line| line.contains("key_secret(") && line.contains("to_string()"))
        .filter(|line| !line.trim_start().starts_with("//"))
        .count();
    assert_eq!(
        bare_copies, 0,
        "`key_secret` 的返回值不得被复制成裸 `String`（当前 {bare_copies} 处）"
    );
}
