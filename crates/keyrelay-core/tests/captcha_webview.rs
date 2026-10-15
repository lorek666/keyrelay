//! 人工过验证码的**红线层**（M8-S2 §5）与复核 N-2 的文案断言（§6.5）。
//!
//! §5 的红线思路：**cookie 与密钥同级**——除内存（`SessionCache`）之外，它不得出现在
//! 任何持久化 / 事件 / 导出 / 审计结论里。这些断言全部读**真实产物**（库文件字节 /
//! 事件行 / 导出文本 / 审计结论），不是「看代码里没写」：谁把 `complete_captcha`
//! 改成把 cookie 写进事件表，T12 必然变红。
//!
//! N-2（§6.5）：探测失败文案不得回显录入地址里的 userinfo。四个用例里三条是
//! 「必须掩掉」（有 scheme / 纯字母数字 / 无 scheme），一条是**对照组**
//! （无 userinfo 的地址文案**逐字不变**）——防止「顺手改文案」把既有断言打红。
//!
//! 未验证边界（不得声称已验证）：WebView 的**创建与抓取**本身（窗口、`cookies()`、
//! 关窗事件）在本机无 GUI 会话，见 spec §10-1。本文件覆盖的是它在核心层的契约：
//! 相位流转（T1–T8 的单测在 `site/captcha.rs`）、cookie 校验、红线产物。

use std::fs;
use std::path::{Path, PathBuf};

use keyrelay_core::error::Error;
use keyrelay_core::service::{KeyRelayService, ServiceConfig, HEALTH_NEEDS_LOGIN};
use keyrelay_core::site::captcha::CaptchaPhase;
use keyrelay_core::site::registry::SiteRegistry;
use keyrelay_core::site::transport::{HttpResponse, MockTransport};
use keyrelay_core::site::{Credentials, SiteKind};
use keyrelay_core::store::Store;
use serde_json::json;

/// 会话 cookie 的值：只要它出现在任何持久化产物里，红线就破了。
const COOKIE_VALUE: &str = "SESSKR9x2F7q1Zx8mP0vT";
const BASE: &str = "https://relay.example.com";

struct Fixture {
    dir: tempfile::TempDir,
    service: KeyRelayService<MockTransport>,
    mock: MockTransport,
    site_id: i64,
    db_path: PathBuf,
}

fn encryption_disabled() -> HttpResponse {
    HttpResponse::json(200, json!({"success": true, "data": {"enabled": false}})).expect("构造响应")
}

/// 站点在登录响应里要求人机验证（`classify_login_message` 据此判 `CaptchaRequired`）。
fn login_rejected_by_captcha() -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"success": false, "message": "Turnstile 验证失败，请重试"}),
    )
    .expect("构造响应")
}

fn keys_ok() -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"success": true, "data": {"items": [], "total": 0}}),
    )
    .expect("构造响应")
}

fn not_found() -> HttpResponse {
    HttpResponse::new(404, b"{}".to_vec())
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let db_path = dir.path().join("keyrelay.db");
    let store = Store::open(&db_path).expect("文件库");
    let mock = MockTransport::new(vec![]);
    let service = KeyRelayService::new(store, mock.clone(), ServiceConfig::in_memory(home));
    // 站点直接写库：探测路径由 T15 单独钉（这里关心的是人工态与红线产物）。
    let site_id = service
        .store()
        .upsert_site("newapi", BASE, "测试站")
        .expect("写站点");
    Fixture {
        dir,
        service,
        mock,
        site_id,
        db_path,
    }
}

/// 一次完整的人工过验证码流程的产物与事件条数快照。
struct Flow {
    /// 进流程前的事件条数（基线）。
    events_before: usize,
    /// 登录被拒 + 拿到挑战之后（人工态挂着时）的条数。
    events_in_human_state: usize,
    /// 成功提交之后的条数。
    events_after: usize,
}

/// 跑一遍完整流程：登录被拒 ⇒ 人工态 ⇒ 拿官方页面地址 ⇒ 提交 WebView 抓到的 cookie。
///
/// 三段事件条数**分开**返回，供 T12 断言「人工态不写事件、成功提交恰好一条」。
async fn run_captcha_flow(f: &Fixture) -> Flow {
    let events_before = f.service.store().list_events(500).unwrap().len();

    // ① 登录：站点要求人机验证 ⇒ 转人工态（错误类型不变，前端据此弹入口）。
    f.mock.push(encryption_disabled());
    f.mock.push(login_rejected_by_captcha());
    let err = f
        .service
        .login(f.site_id, Credentials::new("me", "pw"))
        .await
        .expect_err("必须被要求人机验证");
    assert_eq!(err, Error::CaptchaRequired);
    assert!(
        matches!(
            f.service.captcha_phase(f.site_id),
            CaptchaPhase::AwaitingHuman { site_id, .. } if site_id == f.site_id
        ),
        "登录被拒之后必须处在人工态"
    );

    // ② 拿「官方页面」地址：纯内存读相位，不联网。
    let challenge = f.service.begin_captcha(f.site_id).expect("等待中的挑战");
    assert_eq!(challenge.site_id, f.site_id);
    assert_eq!(challenge.url, "https://relay.example.com/login");
    assert!(!challenge.url.contains('@'), "页面地址不得带 userinfo");

    let events_in_human_state = f.service.store().list_events(500).unwrap().len();

    // ③ 用户在 WebView 里**自己**过完验证码，App 抓到的 cookie 交回来（版本模拟）。
    let cookies = vec![
        ("session".to_string(), COOKIE_VALUE.to_string()),
        ("cf_clearance".to_string(), "1.2-3_4.5~6".to_string()),
    ];
    f.service
        .complete_captcha(f.site_id, cookies)
        .expect("提交必须成功");
    assert_eq!(
        f.service.captcha_phase(f.site_id),
        CaptchaPhase::Idle,
        "完成之后回空闲态"
    );

    let events_after = f.service.store().list_events(500).unwrap().len();
    Flow {
        events_before,
        events_in_human_state,
        events_after,
    }
}

/// 目录下的全部文件（递归；目录本身不算）。
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

// ============================================================ T11–T14：红线（读真实产物）

#[tokio::test]
async fn captcha_cookies_never_reach_sqlite_bytes() {
    let f = setup();
    run_captcha_flow(&f).await;

    // 扫描**整棵临时目录**：数据库（含 `-wal` / `-shm`）+ home / backups / exports。
    let files = files_under(f.dir.path());
    assert!(
        files.iter().any(|p| p == &f.db_path),
        "至少要扫到主库文件: {files:?}"
    );
    for path in &files {
        let bytes = fs::read(path).expect("读产物");
        assert!(
            !contains_bytes(&bytes, COOKIE_VALUE.as_bytes()),
            "{} 含 cookie 值",
            path.display()
        );
        // 片段同样按泄漏处理（值可能被截断存储）
        assert!(
            !contains_bytes(&bytes, &COOKIE_VALUE.as_bytes()[..8]),
            "{} 含 cookie 值片段",
            path.display()
        );
    }
}

#[tokio::test]
async fn captcha_cookies_never_reach_events() {
    let f = setup();
    let flow = run_captcha_flow(&f).await;

    // 「人工态不写事件」（T1/T6）：登录被拒、拿到挑战都不留痕。
    assert_eq!(
        flow.events_in_human_state, flow.events_before,
        "人工态不得写事件（进入 / 取消 / 校验失败都不写）"
    );
    // 只有**成功提交**那一条才留痕。
    assert_eq!(
        flow.events_after,
        flow.events_before + 1,
        "成功提交应恰好留一条痕（多了或少了都说明有路径在事件表里说话）"
    );

    let rows = f.service.store().list_events(500).unwrap();
    assert_eq!(rows.len(), flow.events_after);
    // 最新一条就是完成事件（`ORDER BY id DESC`）。
    assert_eq!(
        rows[0].message,
        "人机验证已通过：cookie 已更新，需重新登录获取访问令牌"
    );
    assert!(
        rows[0].payload.as_deref().unwrap_or("").contains("site_id"),
        "完成事件应只带站点号: {:?}",
        rows[0]
    );

    for row in &rows {
        for text in [Some(row.message.as_str()), row.payload.as_deref()]
            .into_iter()
            .flatten()
        {
            assert!(!text.contains(COOKIE_VALUE), "事件行含 cookie 值: {text}");
            assert!(
                !text.contains(&COOKIE_VALUE[..8]),
                "事件行含 cookie 值片段: {text}"
            );
        }
    }
}

#[tokio::test]
async fn captcha_cookies_never_reach_diagnostics() {
    let f = setup();
    run_captcha_flow(&f).await;

    let text = f.service.export_diagnostics(200).expect("导出诊断");
    assert!(!text.contains(COOKIE_VALUE), "诊断导出含 cookie 值");
    assert!(!text.contains(&COOKIE_VALUE[..8]), "诊断导出含 cookie 片段");
    // 反倒是那条**不含 cookie** 的完成事件应当能在诊断里看到（证明导出不是空的）。
    assert!(text.contains("人机验证已通过"), "诊断里应能看到完成事件");
}

#[tokio::test]
async fn captcha_cookies_never_reach_audit() {
    let f = setup();
    run_captcha_flow(&f).await;

    let report = f.service.audit_redaction().expect("脱敏审计");
    let text = format!("{report:?}");
    assert!(!text.contains(COOKIE_VALUE), "审计结论含 cookie 值: {text}");
    assert!(
        !text.contains(&COOKIE_VALUE[..8]),
        "审计结论含 cookie 片段: {text}"
    );
    assert!(report.is_clean(), "这套流程不该产生任何明文发现: {text}");
}

// ============================================================ 会话真的接上了（§1 目标）

#[tokio::test]
async fn captcha_completion_leaves_session_cookie_only_needs_relogin() {
    // P1-8：cookie-only 会话在 Sub2API（要 Authorization 头）上不可用。
    // captcha 兜底后 health = needs_login（不谎报 ok），但 cookie 仍进 SessionCache
    //（mock 不验 Authorization，list_keys 仍能调通；真实站点会 401）。
    let f = setup();
    run_captcha_flow(&f).await;

    // `list_keys` 需要会话；mock 里仍能调通（cookie 进了 SessionCache）。
    f.mock.push(keys_ok());
    let keys = f
        .service
        .list_keys(f.site_id)
        .await
        .expect("mock 不验 auth，list_keys 应调通");
    assert!(keys.is_empty());

    // 而且请求里确实带上了 WebView 抓到的 cookie（不是别处凑出来的会话）。
    let req = f
        .mock
        .nth_request(2)
        .expect("第 3 个请求（0/1 是登录流程）");
    let cookie = req
        .headers
        .iter()
        .find(|(name, _)| name == "Cookie")
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    assert!(
        cookie.contains(COOKIE_VALUE),
        "会话 cookie 应进 `Cookie:` 头: {cookie}"
    );
    // P1-8：健康状态是 needs_login（cookie-only 不可用），不谎报 ok。
    let site = f
        .service
        .store()
        .get_site(f.site_id)
        .unwrap()
        .expect("站点");
    assert_eq!(site.health, HEALTH_NEEDS_LOGIN);
}

// ============================================================ T15：复核 N-2（§6.5）

/// 三个适配器各自的文案 + 汇总文案：**都不**回显录入地址，但都保留 host。
async fn assert_detect_failure_masks(base: &str, userinfo: &str, host: &str) {
    for kind in [
        SiteKind::NewApi,
        SiteKind::Sub2Api,
        SiteKind::CustomOpenAiCompatible,
    ] {
        let mock = MockTransport::new(vec![]);
        mock.push(not_found());
        let registry = SiteRegistry::new(mock).with_probe_order(vec![kind]);
        let text = registry
            .detect(base)
            .await
            .expect_err("404 ⇒ 不匹配")
            .to_string();
        assert!(!text.contains(base), "{kind:?} 原样回显了录入地址: {text}");
        assert!(!text.contains(userinfo), "{kind:?} 回显了 userinfo: {text}");
        assert!(text.contains(host), "{kind:?} 文案丢了 host: {text}");
        assert!(text.contains("***@"), "{kind:?} 缺少掩蔽痕迹: {text}");
    }

    // 汇总文案：三个原因拼在一起，是用户实际看到的那一条。
    let mock = MockTransport::new(vec![]);
    for _ in 0..3 {
        mock.push(not_found());
    }
    let text = SiteRegistry::new(mock)
        .detect(base)
        .await
        .expect_err("三个适配器都不匹配")
        .to_string();
    assert!(!text.contains(base), "汇总文案原样回显了录入地址: {text}");
    assert!(!text.contains(userinfo), "汇总文案回显了 userinfo: {text}");
    assert!(text.contains(host), "汇总文案丢了 host: {text}");
    assert!(text.contains("***@"), "汇总文案缺少掩蔽痕迹: {text}");
}

#[tokio::test]
async fn detect_failure_never_echoes_userinfo() {
    assert_detect_failure_masks(
        "https://alice:supersecret123@host.example",
        "alice:supersecret123",
        "host.example",
    )
    .await;
}

#[tokio::test]
async fn detect_failure_never_echoes_an_alphanumeric_password() {
    // 纯字母数字的密码不匹配 `scrub` 的任何规则——「靠下游脱敏」这条路走不通，
    // 必须在拼进文案之前就掩掉。
    assert_detect_failure_masks(
        "https://bob:pw123456@host.example",
        "bob:pw123456",
        "host.example",
    )
    .await;
}

#[tokio::test]
async fn detect_failure_never_echoes_a_schemeless_userinfo() {
    // `strip_url_userinfo` 对没有 `://` 的形态明确「不猜」，`display_url` 必须补上这一步。
    assert_detect_failure_masks(
        "carol:pw654321@host.example",
        "carol:pw654321",
        "host.example",
    )
    .await;
}

#[tokio::test]
async fn detect_failure_text_is_unchanged_for_a_plain_url() {
    // 对照组：无 userinfo 的地址，文案必须**逐字不变**——否则「顺手改文案」
    // 会把依赖它排障的用户体验偷偷改掉。
    let mock = MockTransport::new(vec![]);
    for _ in 0..3 {
        mock.push(not_found());
    }
    let text = SiteRegistry::new(mock)
        .detect("https://plain.example.com")
        .await
        .expect_err("三个适配器都不匹配")
        .to_string();
    assert_eq!(
        text,
        "站点指纹不匹配: https://plain.example.com 未被识别（newapi: 站点指纹不匹配: https://plain.example.com/api/status 返回 404; sub2api: 站点指纹不匹配: https://plain.example.com/api/v1/settings/public 返回 404; custom-openai-compatible: 站点指纹不匹配: https://plain.example.com/v1/models 返回 404）"
    );
    assert!(!text.contains("***"), "对照组不得出现掩蔽痕迹: {text}");
}
