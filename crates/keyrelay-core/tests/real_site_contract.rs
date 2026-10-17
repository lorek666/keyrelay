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
    needs_poll, poll_probe_run, run_probe, PollPolicy, PollStop, ProbeRequest,
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

/// **与生产 `build_probe_transport` 同形**的传输层：120s 单请求超时、不套 retry。
///
/// B-160 的复现要点就在这里——120s 是**单次请求**的上界，而旧实现把它当成「整轮检测的
/// 总时长」在用。用例必须用这条传输层，否则「>120s 也拿得到判定」就不成立。
fn probe_transport() -> ReqwestTransport {
    let config = TransportConfig {
        proxy: env_opt("KR_REAL_PROXY"),
        timeout: Duration::from_secs(120),
        ..TransportConfig::default()
    };
    ReqwestTransport::new(config).expect("构造真实 probe 传输层")
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

/// 真机 probe 的入口：**key 驱动**，不是登录驱动。
///
/// 返回 `(base_url, api_key, model_id)`，三者任一缺失就打印 `SKIP` 并返回 `None`。
///
/// # 为什么不用 `KR_REAL_SUB2API_*` 走登录 + 建密钥
///
/// 2026-10-17 复验时该部署的**登录端点要求 Cloudflare Turnstile**
/// （`turnstile_enabled=true` 且 secret 已配置，本地无法产出 token），也就是
/// 「B-160 能不能复验」会取决于一件与 B-160 完全无关的事。probe 路径本身只需要
/// **一把可用的 key**，所以把凭据入口收敛成 key。
///
/// # 代价（如实写在文档里，不藏）
///
/// 用例**不回收**这把 key——回收需要管理权限。运营者应当给一把**一次性** key，
/// 跑完自行吊销。这比「用例自己建、自己删」少一段覆盖，换来的是「不依赖管理端点」。
fn probe_target() -> Option<(String, String, String)> {
    let vars = require(&["KR_REAL_PROBE_BASE", "KR_REAL_PROBE_KEY"])?;
    let model = env_opt("KR_REAL_PROBE_MODEL").unwrap_or_else(|| "gpt-4o-mini".into());
    Some((vars[0].clone(), vars[1].clone(), model))
}

/// **B-160 的真机验收**：走**与生产同形**的路径——`sync=false` 提交 + `poll_probe_run`
/// 用 `PollPolicy::default()` 轮询到终态，并且**用生产那条 120s 超时的传输层**。
///
/// 断言的核心不是「拿到了判定」（那取决于站点与模型，不是本用例的契约），而是：
/// - 提交响应的形状就是异步形状（`needs_poll(run, true) == true`）——这是 B-160 的触发条件；
/// - 轮询确实收敛到 `Settled`（不是把预算等完、也不是连续失败）；
/// - **`run_id` 一定带得回来**，即使没拿到判定。
///
/// 耗时只**打印**不断言：它取决于站点当时的负载与模型，把它写死成断言会变成偶发红。
/// 但打印出来正好是证据——真机实测同一模型 `sync=true` 单条连接要 360.53s，
/// 而这条传输层 120s 就掐断；`sync=false` 那条路在 187s 时仍然拿回了判定。
#[tokio::test]
#[ignore = "会走真实网络与真实站点（需要 KR_REAL_* 环境变量），用 --ignored 显式执行"]
async fn probe_async_submit_plus_poll_survives_a_run_longer_than_the_http_timeout() {
    let Some((base, key_secret, model)) = probe_target() else {
        return;
    };

    // 生产同形：120s 单请求超时、不套 retry。
    let probe_transport = probe_transport();
    let req = ProbeRequest {
        base_url: base.clone(),
        api_key: zeroize::Zeroizing::new(key_secret),
        model_id: model.clone(),
        claimed_model: None,
        sync: false, // B-160：主路径
    };

    let t0 = Instant::now();
    let first = run_probe(&probe_transport, &req)
        .await
        .expect("异步 probe 提交应当返回 run");
    let submit = t0.elapsed();
    println!(
        "[B-160] 提交 ok：耗时={submit:?} status={:?} verdict={:?} run_id={} report={:?}",
        first.status, first.verdict_status, first.run_id, first.report_url
    );
    // 真机形状：`sync=false` 的响应只有 runId + claimToken，没有 status ⇒ 解析成 unknown。
    assert_eq!(
        first.status, "unknown",
        "真机形状变了：异步提交响应现在带了 status={:?}",
        first.status
    );
    assert!(
        needs_poll(&first, true),
        "异步提交响应必须被判为「要轮询」，否则 B-160 的结论会在提交后立刻丢掉"
    );
    assert!(
        !needs_poll(&first, false),
        "同一个响应在同步语义下不轮询——两种语义不能混"
    );

    let policy = PollPolicy::default();
    let outcome = poll_probe_run(&probe_transport, first, true, policy, &TokioSleeper).await;
    let total = t0.elapsed();
    println!(
        "[B-160] 轮询结束：stop={:?} polled={} errors={} 总耗时={total:?} status={:?} \
         identity={:?} verdict={:?} true_family={:?} true_model={:?} confidence={:?} \
         warnings={} bazaarlink_wall={:?} report={:?} run_id={}",
        outcome.stop,
        outcome.polled,
        outcome.errors,
        outcome.run.status,
        outcome.run.identity_status,
        outcome.run.verdict_status,
        outcome.run.true_family,
        outcome.run.true_model,
        outcome.run.confidence,
        outcome.run.warnings_count,
        match (outcome.run.created_at, outcome.run.completed_at) {
            (Some(a), Some(b)) => Some(Duration::from_millis((b - a).max(0) as u64)),
            _ => None,
        },
        outcome.run.report_url,
        outcome.run.run_id
    );
    if total >= Duration::from_secs(120) {
        println!(
            "[B-160] ✅ 复现：本次从提交到收尾 {total:?} > 120s。旧实现把整轮检测压在一条连接上、\
             120s 掐断 ⇒ 这一条判定在旧实现下必然丢失。"
        );
    } else {
        println!(
            "[B-160] ⚠️ 本次 {total:?} < 120s，未复现超时形态（站点/模型这次跑得快）——\
             不假装复现，如实记录。"
        );
    }

    assert_eq!(
        outcome.stop,
        PollStop::Settled,
        "轮询必须收敛到终态（不是预算用尽、也不是连续失败）：{outcome:?}"
    );
    assert!(!outcome.run.run_id.is_empty(), "run_id 必须带回来");
    assert_eq!(
        outcome.run.status, "completed",
        "真机异步 run 的终态是 completed"
    );

    println!(
        "探针结束：全程用过的 run_id={}（这把 key 是一次性的，请运营者自行吊销）",
        outcome.run.run_id
    );
}

/// **B-160 的对照组**：旧路径（`sync=true` 一次性 POST）在生产那条 120s 的传输层上跑，
/// 只读打印耗时与结果；**不断言**具体判定值（那取决于站点与模型，不是本用例的契约）。
///
/// 重模型下这里应当打印 `Err(Transport(... timed out ...))`——那正是 B-160 的复现。
/// 轻模型下它可能正常返回，所以**不能**把「必然超时」写成断言（会变成偶发红）。
#[tokio::test]
#[ignore = "会走真实网络与真实站点（需要 KR_REAL_* 环境变量），用 --ignored 显式执行"]
async fn probe_reports_the_run_lifecycle_for_a_real_key() {
    let Some((base, key_secret, model)) = probe_target() else {
        return;
    };

    // 对照组必须用**生产那条 120s 传输层**：B-160 要证明的正是「这条路径在 120s 掐断、
    // 而服务端的判定还在后面」。用 60s 的 `transport()` 会把变量搞混。
    let transport = probe_transport();
    let req = ProbeRequest {
        base_url: base.clone(),
        api_key: zeroize::Zeroizing::new(key_secret),
        model_id: model.clone(),
        claimed_model: None,
        sync: true, // ← 对照组：B-160 之前的**唯一**路径
    };
    let t0 = Instant::now();
    let outcome = run_probe(&transport, &req).await;
    let elapsed = t0.elapsed();

    match &outcome {
        Ok(run) => {
            println!(
                "[对照组 sync=true] probe ok：耗时={:?} status={:?} needs_poll={} identity={:?} \
                 verdict={:?} true_model={:?} confidence={:?} warnings={} report={:?}",
                elapsed,
                run.status,
                needs_poll(run, false),
                run.identity_status,
                run.verdict_status,
                run.true_model,
                run.confidence,
                run.warnings_count,
                run.report_url
            );
        }
        Err(e) => println!(
            "[对照组 sync=true] probe 失败（**这条就是 B-160 的复现**）：耗时={elapsed:?} err={e}"
        ),
    }
}
