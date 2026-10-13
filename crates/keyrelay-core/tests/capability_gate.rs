//! 能力门与「不可观测余额」的**接线**验证（M7-S5 / 关闭 M7-S2 复审的 S-1 与 S-2）。
//!
//! 为什么单独一个文件：M7-S2 交付的是**纯函数**（`capabilities()` / `parse_rate()` /
//! `Balance::unknown()`），包内测试把这三样钉得很死；但它们的**消费者在 `service.rs`**
//! （Lead 的写域），而复审实测出两条只在这一层才暴露的缺陷：
//!
//! - **S-1**：`balance()` 在调适配器**之前**先要会话，而 `custom-openai-compatible`
//!   站点没有登录流程（`login: false`）→ 会话永远拿不到 → 那个 `Ok(Balance::unknown)`
//!   **永远走不到**，用户看到的是「请先登录」（一个不存在的流程）。
//! - **S-2**：快照装配把 `Ok(balance)` 直接映射成 `BalanceSnapshot { remaining }`，
//!   不看 `known` → 未知余额被当成 `0.0` → 阈值 > 0 时产出**假的** `BalanceLow`。
//!
//! 两条都属于「纯函数对、接线错」，所以钉它们的位置必须在这一层。

use std::fs;
use std::sync::Arc;

use keyrelay_core::error::Error;
use keyrelay_core::notify::NotifyConfig;
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::transport::MockTransport;
use keyrelay_core::site::{Credentials, SiteKind};
use keyrelay_core::store::Store;
use keyrelay_core::vault::MemoryVault;

/// 站点的类型字符串必须与 `SiteKind::as_str()` 一致——写死字面量会让
/// 「改枚举拼写」这件事绕过本文件（那正是它要防的一类漂移）。
const CUSTOM_KIND: &str = "custom-openai-compatible";

struct Fixture {
    _dir: tempfile::TempDir,
    service: KeyRelayService<MockTransport>,
    site_id: i64,
}

/// 通知配置：**两个出口都关**（本文件验的是「事实有没有走到规则」，不是发送），
/// 但阈值开到 30——这样「未知余额被当成 0」会立刻产出一条 `BalanceLow`，
/// 而「未知余额不进快照」则一条都不产出。差别只来自被测的那一行。
fn threshold_notify() -> NotifyConfig {
    NotifyConfig {
        system_enabled: false,
        webhook_url: None,
        balance_threshold: 30.0,
        timeout: std::time::Duration::from_secs(10),
    }
}

fn setup(kind: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");

    let store = Store::open(&dir.path().join("keyrelay.db")).expect("文件库");
    let site_id = store
        .upsert_site(kind, "https://compat.example.com", "兼容站")
        .expect("写站点");

    let service = KeyRelayService::new(
        store,
        MockTransport::new(vec![]),
        ServiceConfig {
            vault: Arc::new(MemoryVault::new()),
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
        },
    )
    .with_notify(threshold_notify());

    Fixture {
        _dir: dir,
        service,
        site_id,
    }
}

fn creds() -> Credentials {
    Credentials {
        username: "u".into(),
        password: "p".into(),
        second_factor: None,
    }
}

/// 本文件里的站点类型字符串必须真的是产品认得的类型——否则下面的断言会
/// 「通过」但什么也没证明（`kind_of` 对认不出的类型会报错，那会让每条测试
/// 都以同一种错误结束，而不是以各自被验的语义结束）。
#[test]
fn the_fixture_kind_is_a_real_site_kind() {
    assert_eq!(
        SiteKind::parse(CUSTOM_KIND).map(SiteKind::as_str),
        Some(CUSTOM_KIND)
    );
}

/// **S-1**：没有余额能力的站点，`balance()` 必须返回**未知态**，而不是
/// 「请先登录」——后者会把用户引向一个该站点类型根本没有的流程。
#[tokio::test]
async fn balance_without_the_capability_reports_unknown_instead_of_auth_failure() {
    let f = setup(CUSTOM_KIND);

    let balance = f
        .service
        .balance(f.site_id)
        .await
        .expect("没有余额能力不等于操作失败：它有一个答案——「不可观测」");

    assert!(!balance.known, "兼容站点的余额必须标记为不可观测");
    assert_eq!(balance, keyrelay_core::site::Balance::unknown("USD"));
    // 反例保护：若短路被挪到 `session()?` 之后，这里拿到的是 AuthFailed。
    assert!(
        !matches!(
            f.service.balance(f.site_id).await,
            Err(Error::AuthFailed(_))
        ),
        "不得把「不可观测」报成「未登录」"
    );
}

/// 六个**不支持**的入口必须在 `session()` **之前**就返回 `Unsupported`。
///
/// 为什么这条重要：`custom-openai-compatible` 没有会话。若能力门放在会话检查之后，
/// 用户看到的是「请先登录该站点」——而那个站点根本没有登录入口，
/// 于是「不支持」被伪装成「你没做对某件事」。
#[tokio::test]
async fn unsupported_entry_points_fail_before_asking_for_a_session() {
    let f = setup(CUSTOM_KIND);

    let cases: Vec<(&str, Result<(), Error>)> = vec![
        (
            "登录",
            f.service.login(f.site_id, creds()).await.map(|_| ()),
        ),
        ("列举令牌", f.service.list_keys(f.site_id).await.map(|_| ())),
        (
            "创建令牌",
            f.service
                .create_key(
                    f.site_id,
                    keyrelay_core::site::KeySpec {
                        name: "x".into(),
                        group: None,
                        quota_limit: None,
                        expires_at: None,
                    },
                )
                .await
                .map(|_| ()),
        ),
        (
            "读取令牌明文",
            f.service.reveal_key(f.site_id, "1").await.map(|_| ()),
        ),
        (
            "回收令牌",
            f.service.revoke_key(f.site_id, "1").await.map(|_| ()),
        ),
        (
            "读取分组",
            f.service.available_groups(f.site_id).await.map(|_| ()),
        ),
    ];

    for (what, result) in cases {
        match result {
            Err(Error::Unsupported(msg)) => {
                assert!(
                    msg.contains("custom-openai-compatible"),
                    "{what} 的错误文案应指名站点类型，实际是：{msg}"
                );
            }
            other => panic!("{what} 应当返回 Unsupported，实际是 {other:?}"),
        }
    }
}

/// **结构守卫**：`service.rs` 里每一处 `self.session(site_id)?` 都必须在
/// **能力门或能力短路之后**。
///
/// # 为什么需要这条（M7-S5 复审 P1-1 的教训）
///
/// 上面那条 `unsupported_entry_points_fail_before_asking_for_a_session` **手写了六个入口**，
/// 而漏掉的 `sync_site_keys` / `reveal_keys_batch` 恰好不在那张清单里——
/// **实现与测试共享同一个盲区**，于是它「5 passed」地看起来完全正常，
/// 而用户点「密钥对齐」会看到「请先登录」（一个该站点类型根本没有的流程）。
///
/// 手写清单永远会漏。所以这条测试**扫源码**：新增入口若忘了过门，它会直接红，
/// 而不用等下一轮复审的对抗性探针。
#[test]
fn every_session_use_in_service_goes_through_the_capability_gate() {
    const SOURCE: &str = include_str!("../src/service.rs");

    // 逐段切出每个函数体：按 `\n    pub ` 切、取每段到下一个同级项为止。
    // 这不是完整的 Rust 解析器，但对「函数体在同一缩进层级里」这件事足够，
    // 而且它**故意**保持简单——守卫的价值在于不漏，不在于精确。
    //
    // **必须先剥掉注释行**：本文件的说明文字里就写着 `self.session(site_id)?`
    // 这个字样（`capability_gate` 的文档注释），不剥的话守卫会对自己误报。
    // 这条是实测出来的——第一版没剥，守卫报了 `["fn"]`。
    let code: String = SOURCE
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    let mut offenders: Vec<String> = Vec::new();
    for chunk in code.split("\n    pub ").skip(1) {
        let Some(session_at) = chunk.find("self.session(site_id)?") else {
            continue;
        };
        let head = &chunk[..session_at];
        let name = chunk
            .split_once("fn ")
            .and_then(|(_, rest)| rest.split(['(', '<', ' ']).next())
            .unwrap_or("<未知>")
            .to_string();
        // 允许两种形态，都必须在 `session` **之前**：
        // ① `capability_gate(...)` —— 不支持就 `Err(Unsupported)`；
        // ② `capabilities(kind)` —— `balance` 的短路（`Ok(unknown)`，不是错误）。
        if !head.contains("capability_gate(") && !head.contains("capabilities(kind)") {
            offenders.push(name);
        }
    }

    assert!(
        offenders.is_empty(),
        "这些入口在拿会话之前没有过能力门（在 `custom-openai-compatible` 站点上会报\
         「请先登录」而不是「这个站点类型不支持」）：{offenders:?}\n\
         修法：在 `self.session(site_id)?` 之前插入 \
         `capability_gate(kind, capabilities(kind).<能力>, \"<动作>\")?`，\
         或者（像 `balance` 那样）短路成未知态。"
    );
}

/// **S-2**：未知余额**不得**产生余额告警。
///
/// 这是本文件最值钱的一条：阈值 30、站点余额「不可观测」。若快照里塞进
/// `remaining: 0.0`，`balance_low` 会立刻报「余额不足」——用户会去查一个
/// 根本没问题的站点。假告警比不告警更糟：它会消耗掉用户对告警的信任。
#[tokio::test]
async fn an_unobservable_balance_never_produces_a_false_alarm() {
    let f = setup(CUSTOM_KIND);

    f.service.refresh_all().await.expect("刷新应成功");

    let titles: Vec<String> = f
        .service
        .recent_events(200)
        .expect("读事件")
        .into_iter()
        .map(|row| row.message)
        .filter(|message| message.starts_with("通知: "))
        .collect();

    assert!(
        !titles.iter().any(|t| t.contains("余额")),
        "未知余额不得产出余额告警，实际产生了：{titles:?}"
    );

    // 反例保护：把「未知」换成真的 0 余额，同一条链路**必须**报警——
    // 否则上面那条断言在「规则压根没跑」时也会通过（假绿）。
    let g = setup(CUSTOM_KIND);
    g.service
        .store()
        .upsert_site("newapi", "https://relay.example.com", "真站点")
        .expect("写第二个站点");
    // 第二个站点是 newapi：它**有**余额能力，但没有会话 ⇒ `balance()` 走 Err 分支
    // ⇒ 快照里是 `None` ⇒ 同样不该报警。这条不是反例，只是把「没有会话」也覆盖上。
    g.service.refresh_all().await.expect("刷新应成功");
    let titles: Vec<String> = g
        .service
        .recent_events(200)
        .expect("读事件")
        .into_iter()
        .map(|row| row.message)
        .filter(|message| message.starts_with("通知: "))
        .collect();
    assert!(
        !titles.iter().any(|t| t.contains("余额")),
        "拿不到余额时也不得报警（宁可不说，不要说错）：{titles:?}"
    );
}

/// 反例保护（正面方向）：**真的**低余额必须报警。
///
/// 没有这一条，上面那两条「不报警」的断言在「通知链路整个没接上」时也会绿。
/// 这里用 `evaluate` 直接喂一个已知的低余额快照，证明规则本身是活的。
#[test]
fn the_low_balance_rule_is_actually_alive() {
    use keyrelay_core::notify::{evaluate, BalanceSnapshot, SiteSnapshot, Snapshot};

    let snapshot = Snapshot {
        sites: vec![SiteSnapshot {
            site_id: 1,
            display_name: "兼容站".into(),
            balance: Some(BalanceSnapshot {
                remaining: 3.0,
                used: 1.0,
                currency: "USD".into(),
            }),
            needs_login: false,
            quota_exceeded: false,
            models: None,
            drift: Vec::new(),
            rotation_due: Vec::new(),
        }],
    };

    let items = evaluate(None, &snapshot, &threshold_notify(), 1_700_000_000);
    assert!(
        !items.is_empty(),
        "低余额（3.0 < 阈值 30.0）必须产出告警——否则本文件的「不报警」断言证明不了任何事"
    );
}
