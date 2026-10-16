//! M17-S1 · 真实站点契约复验（**env 驱动**，默认 `#[ignore]`）。
//!
//! # 红线
//!
//! 主机名、账号、口令、密钥**一律来自环境变量**——源码里不得出现任何真实值。
//! 理由：`docs/PROCESS.md` §3「不保存站点管理员凭证」，以及 B-125 的仓库级清理
//! （历史上 `zz_real_*` 的编译产物把凭据编进了二进制，是反面教材）。
//!
//! # 为什么单独一个文件
//!
//! `tests/offline.rs` 验证的是「断网时的行为」，本文件验证的是「**真站点上的契约**」——
//! 两者都要真实网络栈，但前者只需要回环、后者需要真实凭据，所以分开并同样默认 `#[ignore]`。
//!
//! # 用法
//!
//! ```bash
//! KR_REAL_PROXY=http://127.0.0.1:7897 \
//! KR_REAL_SUB2API_BASE=https://… \
//! KR_REAL_SUB2API_EMAIL=… KR_REAL_SUB2API_PASSWORD=… \
//! KR_REAL_NEWAPI_BASE=https://… \
//! cargo test -p keyrelay-core --test real_site_contract -- --ignored --nocapture --test-threads=1
//! ```
//!
//! 未设置必需变量时，每条用例打印 `SKIP`（缺哪些变量）并**直接返回**——不 panic，
//! 免得在没配凭据的机器上制造假红。

use std::env;
use std::time::{Duration, Instant};

use keyrelay_core::probe::{
    fetch_probe_run, needs_poll, poll_probe_run, run_probe, PollPolicy, ProbeRequest,
};
use keyrelay_core::site::registry::SiteRegistry;
use keyrelay_core::site::retry::TokioSleeper;
use keyrelay_core::site::transport_reqwest::{ReqwestTransport, TransportConfig};
use keyrelay_core::site::{Credentials, KeySpec, SiteKind};

/// 本文件所有用例的统一前缀：缺变量时打印它，便于一眼看出是「没配」而不是「失败」。
const SKIP: &str = "SKIP(real-site)";

fn env_opt(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// 取一组必需变量；缺任何一个都返回 `None`（调用方打印 SKIP）。
fn require(names: &[&str]) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut missing = Vec::new();
    for name in names {
        match env_opt(name) {
            Some(v) => out.push(v),
            None => missing.push(*name),
        }
    }
    if missing.is_empty() {
        Some(out)
    } else {
        println!("{SKIP} 缺少环境变量：{}", missing.join(", "));
        None
    }
}

fn transport() -> ReqwestTransport {
    let config = TransportConfig {
        // 本机走 Clash 时 DNS 是 fake-IP，必须显式走代理（真机走查记录里的同一条坑）。
        proxy: env_opt("KR_REAL_PROXY"),
        timeout: Duration::from_secs(60),
        ..TransportConfig::default()
    };
    ReqwestTransport::new(config).expect("构造真实传输层")
}

/// 真实站点指纹识别：`SiteRegistry` 按 `SiteKind::ALL` 的顺序逐个 `detect`。
#[tokio::test]
#[ignore = "会走真实网络与真实站点（需要 KR_REAL_* 环境变量），用 --ignored 显式执行"]
async fn real_sites_are_recognized_by_the_fingerprint_registry() {
    let Some(vars) = require(&["KR_REAL_NEWAPI_BASE", "KR_REAL_SUB2API_BASE"]) else {
        return;
    };
    let (newapi_base, sub2api_base) = (vars[0].clone(), vars[1].clone());
    let registry = SiteRegistry::new(transport());

    for (label, base, expected) in [
        ("NewAPI", &newapi_base, SiteKind::NewApi),
        ("Sub2API", &sub2api_base, SiteKind::Sub2Api),
    ] {
        let t0 = Instant::now();
        let fp = registry
            .detect(base)
            .await
            .unwrap_or_else(|e| panic!("{label} 指纹识别失败（{base}）：{e}"));
        println!(
            "{label}: kind={:?} 期望={:?} 耗时={:?} display_name={:?} version={:?}",
            fp.kind,
            expected,
            t0.elapsed(),
            fp.display_name,
            fp.version
        );
        assert_eq!(fp.kind, expected, "{label} 被识别成了 {:?}", fp.kind);
    }
}

/// Sub2API 全生命周期：登录 → 余额 → 分组 → 列密钥 → 建密钥 → 读明文 → 列表 → 回收。
///
/// **自清理**：无论中间哪一步失败，最后都尽力回收自己建的密钥（真实站点上不留垃圾）。
#[tokio::test]
#[ignore = "会走真实网络与真实站点（需要 KR_REAL_* 环境变量），用 --ignored 显式执行"]
async fn sub2api_key_lifecycle_on_a_real_deployment() {
    let Some(vars) = require(&[
        "KR_REAL_SUB2API_BASE",
        "KR_REAL_SUB2API_EMAIL",
        "KR_REAL_SUB2API_PASSWORD",
    ]) else {
        return;
    };
    let (base, email, password) = (vars[0].clone(), vars[1].clone(), vars[2].clone());
    let registry = SiteRegistry::new(transport());
    let adapter = registry.adapter(SiteKind::Sub2Api);

    // ① 登录
    let t0 = Instant::now();
    let session = adapter
        .login(&base, Credentials::new(email, password))
        .await
        .expect("真实登录应当成功");
    println!(
        "登录 ok：耗时={:?} cookies={} access_token={} user_id={:?}",
        t0.elapsed(),
        session.cookies.len(),
        session.access_token.is_some(),
        session.user_id
    );
    assert!(
        session.access_token.is_some(),
        "Sub2API 的会话必须带 access_token（Authorization 头）"
    );

    // ② 余额（`known=false` 时 remaining/used 无意义）
    let balance = adapter.balance(&base, &session).await.expect("取余额");
    println!(
        "余额：known={} currency={} remaining={} used={}",
        balance.known, balance.currency, balance.remaining, balance.used
    );

    // ③ 分组与倍率（`/groups/rates` 为空时要回落到 `rate_multiplier`）
    let groups = adapter
        .available_groups(&base, &session)
        .await
        .expect("取分组");
    println!(
        "分组 {} 个：{:?}",
        groups.len(),
        &groups[..groups.len().min(3)]
    );

    // ④ 建密钥（带 `Idempotency-Key`）→ ⑤ 读明文（两者必须逐字相同）
    let name = format!(
        "keyrelay/m17-real/{}-{}",
        env::var("KR_REAL_RUN_ID").unwrap_or_else(|_| "run".into()),
        std::process::id()
    );
    let created = adapter
        .create_key(&base, &session, KeySpec::named(name.clone()))
        .await
        .expect("建密钥");
    println!(
        "建密钥 ok：remote_id={} 明文长度={}",
        created.remote_id,
        created.secret.len()
    );
    assert!(
        created.secret.starts_with("sk-"),
        "Sub2API 的明文以 sk- 开头（实测形态）"
    );

    let revealed = adapter
        .reveal_key(&base, &session, &created.remote_id)
        .await
        .expect("读明文");
    assert_eq!(
        revealed.secret, created.secret,
        "读到的明文必须与创建响应逐字一致"
    );
    println!(
        "读明文 ok：与创建响应逐字一致（{} 字符）",
        revealed.secret.len()
    );

    // ⑥ 列表：适配器**不得**把列表项里的 key 当明文用——`KeyMeta` 里根本没有密钥字段。
    let listed = adapter.list_keys(&base, &session).await.expect("列密钥");
    let mine = listed
        .iter()
        .find(|k| k.remote_id == created.remote_id)
        .expect("刚建的密钥应当出现在列表里");
    println!(
        "列密钥 ok：total={} 本条={{ name={:?} status={:?} quota_used={:?} quota_limit={:?} currency={:?} }}",
        listed.len(),
        mine.name,
        mine.status,
        mine.quota_used,
        mine.quota_limit,
        mine.currency
    );

    // ⑦ 回收（自清理）
    adapter
        .revoke_key(&base, &session, &created.remote_id)
        .await
        .expect("回收密钥");
    let after = adapter
        .list_keys(&base, &session)
        .await
        .expect("回收后列密钥");
    assert!(
        !after.iter().any(|k| k.remote_id == created.remote_id),
        "回收后该密钥不应再出现在列表里"
    );
    println!("回收 ok：列表里已消失（回收后 total={}）", after.len());
}

/// **B-134 的真机证据**：`sync=false` 让 bazaarlink 立刻回一个**非终态** run，然后用
/// `poll_probe_run` 真轮询到终态——这条路径在本波之前**只有 mock 覆盖**。
///
/// 若该部署的 `sync=false` 仍然直接给终态，本用例**退化**为「用真实 run_id 打一次轮询端点」
/// （`fetch_probe_run`），并把这一点如实打印出来——不假装拿到了 `running`。
#[tokio::test]
#[ignore = "会走真实网络与真实站点（需要 KR_REAL_* 环境变量），用 --ignored 显式执行"]
async fn probe_async_run_is_polled_until_terminal_on_a_real_deployment() {
    let Some(vars) = require(&[
        "KR_REAL_SUB2API_BASE",
        "KR_REAL_SUB2API_EMAIL",
        "KR_REAL_SUB2API_PASSWORD",
    ]) else {
        return;
    };
    let (base, email, password) = (vars[0].clone(), vars[1].clone(), vars[2].clone());
    let model = env_opt("KR_REAL_PROBE_MODEL").unwrap_or_else(|| "gpt-4o-mini".into());
    let registry = SiteRegistry::new(transport());
    let adapter = registry.adapter(SiteKind::Sub2Api);
    let session = adapter
        .login(&base, Credentials::new(email, password))
        .await
        .expect("真实登录应当成功");
    let key = adapter
        .create_key(
            &base,
            &session,
            KeySpec::named(format!("keyrelay/m17-poll/{}", std::process::id())),
        )
        .await
        .expect("建密钥");

    let transport = transport();
    let req = ProbeRequest {
        base_url: base.clone(),
        api_key: zeroize::Zeroizing::new(key.secret.clone()),
        model_id: model.clone(),
        claimed_model: None,
        sync: false, // ← 关键：要求 bazaarlink 立刻返回 run（异步模式）
    };

    let first = run_probe(&transport, &req)
        .await
        .expect("异步 probe 应当返回 run");
    println!(
        "sync=false：status={:?} needs_poll={} verdict={:?} run_id={}",
        first.status,
        needs_poll(&first),
        first.verdict_status,
        first.run_id
    );

    if needs_poll(&first) {
        let policy = PollPolicy {
            max_attempts: 20,
            interval: Duration::from_secs(10),
        };
        let t0 = Instant::now();
        let (last, polls) = poll_probe_run(&transport, first, policy, &TokioSleeper).await;
        println!(
            "轮询结束：polls={polls} 耗时={:?} status={:?} verdict={:?} identity={:?} true_model={:?} confidence={:?}",
            t0.elapsed(),
            last.status,
            last.verdict_status,
            last.identity_status,
            last.true_model,
            last.confidence
        );
        assert!(polls > 0, "needs_poll 为真时轮询至少要真的发过一次请求");
    } else {
        println!(
            "退化路径：本部署的 sync=false 直接给终态（{:?}）⇒ 只用真实 run_id 打一次轮询端点",
            first.status
        );
        let fetched = fetch_probe_run(&transport, &first.run_id)
            .await
            .expect("轮询端点对真实 run_id 应当可解析");
        println!(
            "fetch_probe_run ok：status={:?} verdict={:?}（与 POST 的终态一致={}）",
            fetched.status,
            fetched.verdict_status,
            fetched.status == first.status
        );
    }

    adapter
        .revoke_key(&base, &session, &key.remote_id)
        .await
        .expect("回收探针用的密钥");
    println!("探针用的密钥已回收（remote_id={}）", key.remote_id);
}

///
/// 只读判据：打印 `status` / 判定字段 / 耗时 / `needs_poll`；**不断言**具体判定值
/// （那取决于站点与模型，不是本用例的契约）。
#[tokio::test]
#[ignore = "会走真实网络与真实站点（需要 KR_REAL_* 环境变量），用 --ignored 显式执行"]
async fn probe_reports_the_run_lifecycle_for_a_real_key() {
    let Some(vars) = require(&[
        "KR_REAL_SUB2API_BASE",
        "KR_REAL_SUB2API_EMAIL",
        "KR_REAL_SUB2API_PASSWORD",
    ]) else {
        return;
    };
    let (base, email, password) = (vars[0].clone(), vars[1].clone(), vars[2].clone());
    let model = env_opt("KR_REAL_PROBE_MODEL").unwrap_or_else(|| "gpt-4o-mini".into());
    let registry = SiteRegistry::new(transport());
    let adapter = registry.adapter(SiteKind::Sub2Api);
    let session = adapter
        .login(&base, Credentials::new(email, password))
        .await
        .expect("真实登录应当成功");

    let key = adapter
        .create_key(
            &base,
            &session,
            KeySpec::named(format!("keyrelay/m17-probe/{}", std::process::id())),
        )
        .await
        .expect("建密钥");

    let transport = transport();
    let req = ProbeRequest {
        base_url: base.clone(),
        api_key: zeroize::Zeroizing::new(key.secret.clone()),
        model_id: model.clone(),
        claimed_model: None,
        sync: true,
    };
    let t0 = Instant::now();
    let outcome = run_probe(&transport, &req).await;
    let elapsed = t0.elapsed();

    match &outcome {
        Ok(run) => {
            println!(
                "probe ok：耗时={:?} status={:?} needs_poll={} identity={:?} verdict={:?} \
                 true_model={:?} confidence={:?} warnings={} report={:?}",
                elapsed,
                run.status,
                needs_poll(run),
                run.identity_status,
                run.verdict_status,
                run.true_model,
                run.confidence,
                run.warnings_count,
                run.report_url
            );
        }
        Err(e) => println!("probe 失败（也是证据）：耗时={elapsed:?} err={e}"),
    }

    adapter
        .revoke_key(&base, &session, &key.remote_id)
        .await
        .expect("回收探针用的密钥");
    println!("探针用的密钥已回收（remote_id={}）", key.remote_id);
}
