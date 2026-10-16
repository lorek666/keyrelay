//! M9-S2 / B-120 的**接线**验证：登录账号形态的本地预检。
//!
//! 为什么单独一个文件：`site/login_field.rs` 的单测把纯函数钉得很死，但「**请求有没有真的
//! 被拦下来**」只有在这一层才看得见——纯函数返回 `Err` 不等于 `service.login` 用了它，
//! 也不等于它发生在发请求**之前**。
//!
//! 所以本文件里最值钱的两条是**反向**断言：
//!
//! 1. 该拦的：账号不是邮箱形态时 **HTTP 请求数 = 0**（不是「返回了错误」——站点也会返回错误，
//!    那是 400 + Go validator 英文原文，正是 B-120 要消灭的体验）；
//! 2. 不该拦的：邮箱形态的账号、以及 NewAPI 站点的用户名，请求**必须真的发出去**
//!    （判据若写严了，用户就再也登不进去了，而且没有任何绕过手段）。

use std::sync::Arc;

use keyrelay_core::error::Error;
use keyrelay_core::service::{KeyRelayService, ServiceConfig};
use keyrelay_core::site::transport::{HttpResponse, MockTransport};
use keyrelay_core::site::Credentials;
use keyrelay_core::store::Store;
use keyrelay_core::vault::MemoryVault;
use serde_json::{json, Value};

const SUB2API: &str = "sub2api";
const NEWAPI: &str = "newapi";
const CUSTOM: &str = "custom-openai-compatible";

struct Fixture {
    _dir: tempfile::TempDir,
    mock: MockTransport,
    service: KeyRelayService<MockTransport>,
    site_id: i64,
}

/// 建一个**指定类型**的站点。
///
/// 用 `upsert_site` 直接落库、绕开 `add_site`：后者会跑指纹探测，而探测会消耗 mock 队列里
/// 的响应并产生请求——那会让「零请求」这条断言失去意义（它会把探测的请求也数进去）。
fn setup(kind: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("home");

    let store = Store::open(&dir.path().join("keyrelay.db")).expect("文件库");
    let site_id = store
        .upsert_site(kind, "https://sub.example.com", "测试站")
        .expect("写站点");

    let mock = MockTransport::new(vec![]);
    let service = KeyRelayService::new(
        store,
        mock.clone(),
        ServiceConfig {
            vault: Arc::new(MemoryVault::new()),
            home: home.clone(),
            backup_dir: dir.path().join("backups"),
        },
    );

    Fixture {
        _dir: dir,
        mock,
        service,
        site_id,
    }
}

fn creds(username: &str) -> Credentials {
    Credentials::new(username, "pw-12345678")
}

/// Sub2API 登录成功的响应形态（真实站点实测，见 M9-S1 证据 §3）。
fn sub2api_login_ok() -> HttpResponse {
    HttpResponse::json(
        200,
        json!({"code": 0, "message": "success",
               "data": {"access_token": "tok-e2e", "user": {"id": 73}}}),
    )
    .expect("构造响应")
}

/// NewAPI 登录成功的响应形态（旧版无加密端点 ⇒ 先 404，再登录 200）。
fn newapi_login_ok() -> Vec<HttpResponse> {
    vec![
        HttpResponse::new(404, b"404 page not found".to_vec()),
        HttpResponse::json(
            200,
            json!({"success": true, "message": "",
                   "data": {"id": 207, "access_token": "tok-newapi",
                            "user": {"id": 207, "username": "USER_PLACEHOLDER"}}}),
        )
        .expect("构造响应"),
    ]
}

fn body_of(req: &keyrelay_core::site::transport::HttpRequest) -> Value {
    serde_json::from_slice(req.body.as_ref().expect("有请求体")).expect("请求体是 JSON")
}

/// **B-120 的判据**：账号不是邮箱形态时，本机拦下、**一个请求都不发**，文案指向邮箱。
#[tokio::test]
async fn a_non_email_account_is_rejected_before_any_request_is_sent() {
    for bad in [
        "USER_PLACEHOLDER",     // 真实站点实测被拒的那个值（B-120 的原始症状）
        "  USER_PLACEHOLDER  ", // trim 之后仍不是邮箱
        "USER_PLACEHOLDER@qq",  // 域名没有点
        "USER_PLACEHOLDER@",    // 域名为空
        "@qq.com",      // 本地部为空
    ] {
        let f = setup(SUB2API);
        let err = f
            .service
            .login(f.site_id, creds(bad))
            .await
            .expect_err("这个账号不可能是邮箱，必须本地拦下");

        assert!(
            matches!(err, Error::InvalidInput(_)),
            "{bad:?} 的错误类型必须是「输入不符合站点要求」（不是认证失败/传输错误），实际: {err:?}"
        );
        assert!(
            err.to_string().contains("邮箱"),
            "{bad:?} 的文案要直接告诉用户填邮箱：{err}"
        );
        assert_eq!(
            f.mock.request_count(),
            0,
            "{bad:?}：预检必须在发请求**之前**拦下（站点那边也会报错，但那正是 B-120 要消灭的体验）"
        );
    }
}

/// **反向断言**：邮箱形态的账号必须真的发出去，且字段名仍是 `email`。
///
/// 没有这一条，「判据写严了」这个最危险的失效模式（用户再也登不进去）不会有人发现。
#[tokio::test]
async fn an_email_shaped_account_reaches_the_adapter() {
    let f = setup(SUB2API);
    f.mock.push(sub2api_login_ok());

    f.service
        .login(f.site_id, creds("me@example.com"))
        .await
        .expect("邮箱形态必须放行");

    assert_eq!(f.mock.request_count(), 1, "应当正好发一次登录请求");
    let body = body_of(&f.mock.requests()[0]);
    assert_eq!(body["email"], "me@example.com");
    assert!(
        body.get("username").is_none(),
        "Sub2API 的字段名是 email，不能是 username: {body}"
    );
}

/// **反向断言**：NewAPI 就是用户名登录——同一个 `USER_PLACEHOLDER` 在这里**必须**放行。
///
/// 这条证明预检是**按站点类型**走的，不是「凡不是邮箱就拦」。真实站点
/// `newapi.example.com` 就是用 `USER_PLACEHOLDER` 登录成功的（M9-S1 证据 §2）。
#[tokio::test]
async fn a_username_still_reaches_a_newapi_site() {
    let f = setup(NEWAPI);
    for response in newapi_login_ok() {
        f.mock.push(response);
    }

    f.service
        .login(f.site_id, creds("USER_PLACEHOLDER"))
        .await
        .expect("NewAPI 的账号栏不限形态，不得被邮箱判据拦住");

    // 两次请求：① 探测登录加密端点（404）② 登录
    assert_eq!(f.mock.request_count(), 2, "探测 + 登录各一次");
    assert_eq!(
        f.mock.requests()[1].url,
        "https://sub.example.com/api/user/login"
    );
}

/// 没有登录流程的站点：能力门先拒（`Unsupported`），预检**不会**抢在它前面改变错误类型。
///
/// 顺序是硬要求：先「这个站点类型不做登录」，再谈「账号该填什么」——反过来的话，
/// 用户会收到一句关于输入形态的建议，而那个站点**根本没有登录入口**。
#[tokio::test]
async fn a_site_without_login_still_reports_unsupported() {
    let f = setup(CUSTOM);
    let err = f
        .service
        .login(f.site_id, creds("USER_PLACEHOLDER"))
        .await
        .expect_err("没有登录流程的站点类型必须被能力门拒掉");

    assert!(
        matches!(err, Error::Unsupported(_)),
        "必须是「站点类型不支持」，不能是输入形态问题，实际: {err:?}"
    );
    assert_eq!(f.mock.request_count(), 0);
}
