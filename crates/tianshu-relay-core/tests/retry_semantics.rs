//! M21-S3 / B-165：**站点侧非幂等写只重试「可证明未送达」**。
//!
//! 判据与网关 B-138、probe M19-S2 同源，但这条走的是**适配器 + 重试层**的真实装配：
//! 用 `RetryingTransport<MockTransport>` 包住真适配器，数站点侧到底收到了几次请求。
//!
//! 为什么值得单独一个文件：`site/retry.rs` 的单测只能证明判据本身，`contract_*.rs`
//! 又不套重试层。只有把两者拼起来，才能证明「NewAPI 建令牌读超时后站点上不会多出
//! 第二把 key」这件**用户可感知**的事。

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tianshu_relay_core::error::Error;
use tianshu_relay_core::site::newapi::NewApi;
use tianshu_relay_core::site::retry::{RetryPolicy, RetryingTransport, Sleeper};
use tianshu_relay_core::site::sub2api::Sub2Api;
use tianshu_relay_core::site::transport::{HttpRequest, HttpResponse, MockTransport};
use tianshu_relay_core::site::{Credentials, KeySpec, Session, SiteAdapter};

const NEWAPI_BASE: &str = "https://newapi.example.com/";
const SUB2API_BASE: &str = "https://sub.example.com/";

/// 记录每次 sleep 的假计时器：既能观测退避，也**不真的等**。
#[derive(Default)]
struct RecordingSleeper {
    calls: std::sync::Mutex<Vec<Duration>>,
}

impl RecordingSleeper {
    fn calls(&self) -> Vec<Duration> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

#[async_trait::async_trait]
impl Sleeper for RecordingSleeper {
    async fn sleep(&self, duration: Duration) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(duration);
        }
    }
}

fn json_resp(status: u16, value: Value) -> HttpResponse {
    HttpResponse::json(status, value).expect("构造响应")
}

/// NewAPI 成功信封：`{success, message, data}`
fn newapi_ok(data: Value) -> HttpResponse {
    json_resp(200, json!({"success": true, "message": "", "data": data}))
}

/// Sub2API 成功信封：`{code, message, data}`
fn sub2api_ok(data: Value) -> HttpResponse {
    json_resp(200, json!({"code": 0, "message": "success", "data": data}))
}

fn cookie_session() -> Session {
    Session {
        cookies: vec![("session".to_string(), "abc".to_string())],
        access_token: None,
        user_id: Some("7".to_string()),
        user_agent: None,
    }
}

// ============================================================ NewAPI 建令牌

/// NewAPI 建令牌：读超时 ⇒ 站点侧**只有一次** `POST /api/token/`。
///
/// 这是 B-165 立项的那件事。NewAPI 的 `POST /api/token` **没有幂等键**：
/// 读超时意味着这次可能已经建成功了，重试就在站点上多留一把产品不知道的令牌
/// （用户随后用它，账记在产品根本没见过的那把 key 上）。
#[tokio::test]
async fn newapi_create_key_is_not_retried_on_an_ambiguous_failure() {
    let mock = MockTransport::new(vec![]);
    mock.push_error(Error::Transport("请求超时".into()));

    let sleeper = Arc::new(RecordingSleeper::default());
    let transport =
        RetryingTransport::with_sleeper(mock.clone(), RetryPolicy::default(), sleeper.clone());
    let adapter = NewApi::new(transport);

    let err = adapter
        .create_key(
            NEWAPI_BASE,
            &cookie_session(),
            KeySpec::named("codex/daily"),
        )
        .await
        .expect_err("读超时必须失败");

    assert_eq!(
        mock.request_count(),
        1,
        "读超时不得重试建令牌，否则站点上会多出一把 key"
    );
    assert!(sleeper.calls().is_empty(), "不重试就不该退避等待");
    let message = err.to_string();
    assert!(
        message.contains("无法确认服务端是否已处理"),
        "必须把「可能已建好令牌」说清楚: {message}"
    );
}

/// 对照：连接被拒（`NotDelivered`）时**仍然**重试——那类失败对端根本没看到请求。
///
/// 收窄不能收过头：砍掉它等于把站点侧瞬时连接故障从「重试 3 次」降级成「一次就放弃」。
#[tokio::test]
async fn newapi_create_key_is_still_retried_when_not_delivered() {
    let mock = MockTransport::new(vec![]);
    for _ in 0..3 {
        mock.push_error(Error::NotDelivered("连接被拒".into()));
    }

    let sleeper = Arc::new(RecordingSleeper::default());
    let transport =
        RetryingTransport::with_sleeper(mock.clone(), RetryPolicy::default(), sleeper.clone());
    let adapter = NewApi::new(transport);

    let err = adapter
        .create_key(
            NEWAPI_BASE,
            &cookie_session(),
            KeySpec::named("codex/daily"),
        )
        .await
        .expect_err("连不上必须失败");

    assert_eq!(
        mock.request_count(),
        3,
        "NotDelivered 可证明未送达，应重试到 max_attempts"
    );
    assert_eq!(sleeper.calls().len(), 2, "两次重试各等一次退避");
    assert!(matches!(err, Error::NotDelivered(_)), "{err:?}");
}

// ============================================================ Sub2API 建令牌

/// Sub2API 建令牌：**故意与 NewAPI 不同**。
///
/// Sub2API 的 `POST /api/v1/keys` 带 `Idempotency-Key`，而 `RetryingTransport` 重试时发的
/// 是 `req.clone()`——**同一个键**——服务端据此去重。所以读超时后重试不会多出一把密钥，
/// `retry_safe` 保持 `true`。
///
/// 这条用例钉住这个**差异**：将来若有人「统一」两个适配器的标记，这条会红，
/// 逼他先想清楚 Sub2API 的幂等键是哪来的。
#[tokio::test]
async fn sub2api_create_key_keeps_retrying_because_of_the_idempotency_key() {
    let mock = MockTransport::new(vec![]);
    mock.push_error(Error::Transport("请求超时".into()));
    mock.push(sub2api_ok(json!({"id": 21, "key": "sk-abc"})));

    let sleeper = Arc::new(RecordingSleeper::default());
    let transport =
        RetryingTransport::with_sleeper(mock.clone(), RetryPolicy::default(), sleeper.clone());
    let adapter = Sub2Api::new(transport);

    let material = adapter
        .create_key(
            SUB2API_BASE,
            &Session {
                cookies: Vec::new(),
                access_token: Some("tok".to_string()),
                user_id: Some("7".to_string()),
                user_agent: None,
            },
            KeySpec::named("codex/daily"),
        )
        .await
        .expect("幂等键在，重试应当成功");

    assert_eq!(mock.request_count(), 2, "读超时后重试了一次");
    assert_eq!(material.remote_id, "21");

    // 两次请求必须是**逐字相同**的同一个 Idempotency-Key——这正是它能重试的理由。
    // 键若在两次之间变了，服务端就会当成两笔创建，站点上照样多出一把 key。
    let keys: Vec<String> = mock
        .requests()
        .into_iter()
        .map(|req| {
            let HttpRequest { headers, .. } = req;
            headers
                .into_iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("idempotency-key"))
                .map(|(_, value)| value)
                .unwrap_or_default()
        })
        .collect();
    assert_eq!(keys.len(), 2, "应有两次请求");
    assert!(!keys[0].is_empty(), "必须带 Idempotency-Key: {:?}", keys);
    assert_eq!(keys[0], keys[1], "重试必须复用同一个幂等键，否则去重不成立");
}

// ============================================================ 回收令牌

/// 回收（DELETE）读超时 ⇒ 只发一次，且**不**把 404 之类后续状态暴露给用户。
///
/// DELETE 的终态是幂等的，但重试仍然危险：读超时时那次删除可能已经成功，
/// 重试会拿到 404，用户于是被告知「令牌不存在」——而他刚刚还在用它。
#[tokio::test]
async fn revoke_is_not_retried_on_an_ambiguous_failure() {
    let mock = MockTransport::new(vec![]);
    mock.push_error(Error::Transport("请求超时".into()));

    let sleeper = Arc::new(RecordingSleeper::default());
    let transport =
        RetryingTransport::with_sleeper(mock.clone(), RetryPolicy::default(), sleeper.clone());
    let adapter = NewApi::new(transport);

    adapter
        .revoke_key(NEWAPI_BASE, &cookie_session(), "567")
        .await
        .expect_err("读超时必须失败");

    assert_eq!(mock.request_count(), 1, "回收读超时时不得重试");
    assert!(sleeper.calls().is_empty(), "不重试就不该退避等待");
}

// ============================================================ 回归：读取类

/// 读取类请求的重试行为**逐字不变**（`retry_safe` 默认 `true`）。
///
/// 这条是 B-165 的回归防线：判据收紧时最怕顺手把 GET 也砍了，那会让
/// 「站点抖一下」从「自动重试成功」变成「用户看到一次失败」。
#[tokio::test]
async fn reads_still_retry_exactly_as_before() {
    let mock = MockTransport::new(vec![]);
    // `login` 先探测 `GET /api/user/login/encryption-key`（404 = 站点未启用加密登录），
    // 那之后才发 `POST /api/user/login`。第一次登录读超时、第二次成功。
    mock.push(HttpResponse::new(404, b"not found".to_vec()));
    mock.push_error(Error::Transport("请求超时".into()));
    // 会话要能建起来：`access_token` 或 `Set-Cookie` 至少有一个
    // （M16-S3：空 access_token 且无 cookie ⇒ 响亮失败，而不是留一个空会话）。
    let login = newapi_ok(json!({"access_token": "tok-abc", "user": {"id": 7}}));
    mock.push(login);

    let sleeper = Arc::new(RecordingSleeper::default());
    let transport =
        RetryingTransport::with_sleeper(mock.clone(), RetryPolicy::default(), sleeper.clone());
    let adapter = NewApi::new(transport);

    let session = adapter
        .login(NEWAPI_BASE, Credentials::new("me", "pw"))
        .await
        .expect("读路径应重试后成功");

    // 3 次请求 = 加密探测 1 + 登录 2（第一次超时、第二次成功）
    assert_eq!(
        mock.request_count(),
        3,
        "读超时后读路径仍重试（外加一次加密探测）"
    );
    assert_eq!(sleeper.calls().len(), 1, "只重试了登录那一次");
    assert_eq!(session.user_id.as_deref(), Some("7"));
}

/// 认证失败**绝不**因为 `retry_safe = true` 就被重试。
///
/// 第一版把 `retry_safe` 写在判据最前面，于是默认 `true` 的请求连 `AuthFailed` 都会被
/// 重试 3 次——正是 `retry.rs` 模块注释里「避免把风控撞成封号」要防的那件事。
/// 这条用例钉住「`is_retryable()` 是第一道门」。
#[tokio::test]
async fn auth_failure_is_never_retried_even_on_a_read() {
    let mock = MockTransport::new(vec![]);
    mock.push(HttpResponse::new(404, b"not found".to_vec()));
    mock.push_error(Error::AuthFailed("密码错误".into()));

    let sleeper = Arc::new(RecordingSleeper::default());
    let transport =
        RetryingTransport::with_sleeper(mock.clone(), RetryPolicy::default(), sleeper.clone());
    let adapter = NewApi::new(transport);

    let err = adapter
        .login(NEWAPI_BASE, Credentials::new("me", "wrong"))
        .await
        .expect_err("密码错误必须失败");

    // 2 次请求 = 加密探测 1 + 登录 1（认证失败，绝不重试）
    assert_eq!(mock.request_count(), 2, "认证失败不得重试");
    assert!(sleeper.calls().is_empty());
    assert!(matches!(err, Error::AuthFailed(_)), "{err:?}");
}
