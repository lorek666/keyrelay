//! M6-S4 契约测试：**分组与倍率**。
//!
//! - NewAPI：`GET /api/token/auto-groups`（真实形态见 `crates/keyrelay-core/src/site/newapi.rs`
//!   的 `parse_auto_groups` 文档与 `docs/specs/M6-S4-站点能力.md` §5.1）。
//! - Sub2API：`GET /api/v1/groups/available` + `GET /api/v1/groups/rates` 两次调用合并。
//!
//! 本文件用的是**假 transport**，不代表真实站点已验证（M6-S4 spec §9）。

use keyrelay_core::error::Error;
use keyrelay_core::site::newapi::NewApi;
use keyrelay_core::site::sub2api::Sub2Api;
use keyrelay_core::site::transport::{HttpResponse, MockTransport};
use keyrelay_core::site::{GroupInfo, Session, SiteAdapter};
use serde_json::{json, Value};

const NEWAPI_BASE: &str = "https://newapi.example.com/";
const SUB2API_BASE: &str = "https://sub.example.com/";
const SECRET: &str = "sk-LEAK0000000000000000000000000000";

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
    }
}

fn bearer_session() -> Session {
    Session {
        cookies: Vec::new(),
        access_token: Some("tok-abc".to_string()),
        user_id: Some("7".to_string()),
    }
}

fn group(name: &str, rate: Option<f64>, description: Option<&str>) -> GroupInfo {
    GroupInfo {
        name: name.to_string(),
        rate,
        description: description.map(str::to_string),
    }
}

// ============================================================ NewAPI

#[tokio::test]
async fn newapi_available_groups_hits_auto_groups_endpoint() {
    let transport = MockTransport::new(vec![newapi_ok(json!({
        "groups": ["default", "vip"],
        "max_count": 3,
    }))]);
    let adapter = NewApi::new(transport);

    let groups = adapter
        .available_groups(NEWAPI_BASE, &cookie_session())
        .await
        .expect("拉取分组");

    assert_eq!(
        groups,
        vec![group("default", None, None), group("vip", None, None)],
        "顺序与站点一致，站点不给倍率时 rate = None"
    );

    let requests = adapter.transport().requests();
    assert_eq!(requests.len(), 1, "只发一次请求");
    assert_eq!(
        requests[0].url,
        "https://newapi.example.com/api/token/auto-groups"
    );
    assert_eq!(
        requests[0].method,
        keyrelay_core::site::transport::Method::Get
    );
    assert!(
        requests[0]
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("cookie") && v.contains("session=abc")),
        "必须带会话: {:?}",
        requests[0].headers
    );
}

#[tokio::test]
async fn newapi_available_groups_rate_is_none_when_site_has_no_rate_field() {
    // 真实形态：站点只回分组名（`service.GetUserAutoGroup` → []string），没有倍率字段。
    // 章程 §4.4：「rate 取站点字段，缺省 None」——不得凭空补一个 1.0。
    let transport = MockTransport::new(vec![newapi_ok(json!({
        "groups": ["a", "b", "c"],
        "max_count": 5,
    }))]);
    let adapter = NewApi::new(transport);

    let groups = adapter
        .available_groups(NEWAPI_BASE, &cookie_session())
        .await
        .unwrap();
    assert_eq!(groups.len(), 3);
    assert!(groups.iter().all(|g| g.rate.is_none()), "{groups:?}");
    assert!(groups.iter().all(|g| g.description.is_none()), "{groups:?}");
}

#[tokio::test]
async fn newapi_available_groups_accepts_object_entries() {
    // 兼容形态（真实站点未观察到，spec D-6）：对象条目才可能带倍率字段。
    let transport = MockTransport::new(vec![newapi_ok(json!({
        "groups": [
            {"name": "vip", "rate": 0.8, "description": "高级"},
            {"name": "std", "ratio": 1.5},
            {"name": ""},
            42,
            "basic",
        ],
        "max_count": 9,
    }))]);
    let adapter = NewApi::new(transport);

    let groups = adapter
        .available_groups(NEWAPI_BASE, &cookie_session())
        .await
        .unwrap();
    assert_eq!(
        groups,
        vec![
            group("vip", Some(0.8), Some("高级")),
            group("std", Some(1.5), None),
            group("basic", None, None),
        ]
    );
}

#[tokio::test]
async fn newapi_available_groups_empty_list_is_ok() {
    let transport = MockTransport::new(vec![newapi_ok(json!({"groups": [], "max_count": 3}))]);
    let adapter = NewApi::new(transport);
    assert!(adapter
        .available_groups(NEWAPI_BASE, &cookie_session())
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn newapi_available_groups_missing_field_is_an_error() {
    // 静默返回空列表等于告诉用户「站点没有可选分组」——必须报错。
    for data in [
        json!({"max_count": 3}),
        json!({"groups": "oops"}),
        Value::Null,
    ] {
        let transport = MockTransport::new(vec![newapi_ok(data.clone())]);
        let adapter = NewApi::new(transport);
        let err = adapter
            .available_groups(NEWAPI_BASE, &cookie_session())
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Transport(ref m) if m.contains("groups")),
            "{data} → {err:?}"
        );
    }
}

#[tokio::test]
async fn newapi_available_groups_unrecognized_entries_error() {
    let transport = MockTransport::new(vec![newapi_ok(json!({"groups": [1, true, null]}))]);
    let adapter = NewApi::new(transport);
    let err = adapter
        .available_groups(NEWAPI_BASE, &cookie_session())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Transport(ref m) if m.contains("分组名")),
        "{err:?}"
    );
}

#[tokio::test]
async fn newapi_available_groups_maps_http_and_envelope_failures() {
    let transport = MockTransport::new(vec![json_resp(401, json!({"message": "会话已失效"}))]);
    let adapter = NewApi::new(transport);
    let err = adapter
        .available_groups(NEWAPI_BASE, &cookie_session())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::AuthFailed(_)), "{err:?}");

    let transport = MockTransport::new(vec![newapi_ok(Value::Null)]);
    let adapter = NewApi::new(transport);
    // data = null → 缺少 groups 数组
    let err = adapter
        .available_groups(NEWAPI_BASE, &cookie_session())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Transport(_)), "{err:?}");

    let transport = MockTransport::new(vec![json_resp(
        200,
        json!({"success": false, "message": "未授权"}),
    )]);
    let adapter = NewApi::new(transport);
    let err = adapter
        .available_groups(NEWAPI_BASE, &cookie_session())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::AuthFailed(_)), "{err:?}");
}

// ============================================================ Sub2API

#[tokio::test]
async fn sub2api_available_groups_merges_two_calls_in_order() {
    let transport = MockTransport::new(vec![
        sub2api_ok(json!([
            {"id": 1, "name": "default", "description": "默认分组", "rate_multiplier": 1.0},
            {"id": 2, "name": "vip", "description": "高级", "rate_multiplier": 1.2},
        ])),
        sub2api_ok(json!({"1": 0.9, "2": 1.1})),
    ]);
    let adapter = Sub2Api::new(transport);

    let groups = adapter
        .available_groups(SUB2API_BASE, &bearer_session())
        .await
        .unwrap();

    assert_eq!(
        groups,
        vec![
            group("default", Some(0.9), Some("默认分组")),
            group("vip", Some(1.1), Some("高级")),
        ],
        "按 id 合并，顺序 = available 的顺序"
    );

    let requests = adapter.transport().requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].url,
        "https://sub.example.com/api/v1/groups/available"
    );
    assert_eq!(
        requests[1].url,
        "https://sub.example.com/api/v1/groups/rates"
    );
    assert!(
        requests[0]
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("authorization") && v == "Bearer tok-abc"),
        "{:?}",
        requests[0].headers
    );
}

#[tokio::test]
async fn sub2api_available_groups_rates_null_yields_none() {
    // 源码：`userGroupRateRepo == nil` 时 `GetUserGroupRates` 返回 `nil, nil` → `data: null`。
    let transport = MockTransport::new(vec![
        sub2api_ok(json!([
            {"id": 1, "name": "default", "description": "", "rate_multiplier": 1.0},
            {"id": 2, "name": "vip", "description": "高级", "rate_multiplier": 1.2},
        ])),
        sub2api_ok(Value::Null),
    ]);
    let adapter = Sub2Api::new(transport);

    let groups = adapter
        .available_groups(SUB2API_BASE, &bearer_session())
        .await
        .unwrap();
    assert_eq!(
        groups,
        vec![
            group("default", None, None),
            group("vip", None, Some("高级")),
        ],
        "rates 缺失 → rate = None（章程冻结语义）"
    );
}

#[tokio::test]
async fn sub2api_available_groups_missing_id_in_rates_yields_none() {
    // rates 里没有该分组 → None；**不**回落到 available 的 `rate_multiplier`（spec D-3：
    // 那是分组基准倍率，不是该用户的专属覆盖倍率）。
    let transport = MockTransport::new(vec![
        sub2api_ok(json!([
            {"id": 1, "name": "default", "description": "", "rate_multiplier": 1.0},
            {"id": 2, "name": "vip", "description": "", "rate_multiplier": 1.2},
        ])),
        sub2api_ok(json!({"1": 0.5})),
    ]);
    let adapter = Sub2Api::new(transport);

    let groups = adapter
        .available_groups(SUB2API_BASE, &bearer_session())
        .await
        .unwrap();
    assert_eq!(groups[0].rate, Some(0.5));
    assert_eq!(
        groups[1].rate, None,
        "没有专属倍率时必须留空，不得回落到基准倍率 1.2"
    );
}

#[tokio::test]
async fn sub2api_available_groups_empty_description_is_none() {
    let transport = MockTransport::new(vec![
        sub2api_ok(json!([
            {"id": 1, "name": "a", "description": ""},
            {"id": 2, "name": "b"},
            {"id": 3, "name": "c", "description": "有说明"},
        ])),
        sub2api_ok(json!({})),
    ]);
    let adapter = Sub2Api::new(transport);
    let groups = adapter
        .available_groups(SUB2API_BASE, &bearer_session())
        .await
        .unwrap();
    assert_eq!(
        groups,
        vec![
            group("a", None, None),
            group("b", None, None),
            group("c", None, Some("有说明")),
        ]
    );
}

#[tokio::test]
async fn sub2api_available_groups_accepts_items_envelope() {
    // 兼容形态（真实站点是裸数组；与既有 extract_keys_page 同口径，spec D-6 之外的单列登记）
    let transport = MockTransport::new(vec![
        sub2api_ok(json!({"items": [{"id": 1, "name": "a"}], "total": 1})),
        sub2api_ok(json!({"1": 2.0})),
    ]);
    let adapter = Sub2Api::new(transport);
    let groups = adapter
        .available_groups(SUB2API_BASE, &bearer_session())
        .await
        .unwrap();
    assert_eq!(groups, vec![group("a", Some(2.0), None)]);
}

#[tokio::test]
async fn sub2api_available_groups_rejects_unrecognized_shape() {
    // available 形态不认识
    let transport = MockTransport::new(vec![sub2api_ok(json!("oops"))]);
    let adapter = Sub2Api::new(transport);
    let err = adapter
        .available_groups(SUB2API_BASE, &bearer_session())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Transport(ref m) if m.contains("形态无法识别")),
        "{err:?}"
    );

    // rates 形态不认识（既不是对象也不是 null）
    let transport = MockTransport::new(vec![
        sub2api_ok(json!([{"id": 1, "name": "a"}])),
        sub2api_ok(json!([1.0, 2.0])),
    ]);
    let adapter = Sub2Api::new(transport);
    let err = adapter
        .available_groups(SUB2API_BASE, &bearer_session())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Transport(ref m) if m.contains("形态无法识别")),
        "{err:?}"
    );

    // 条目都取不出名字
    let transport = MockTransport::new(vec![sub2api_ok(json!([{"id": 1, "name": ""}, 7]))]);
    let adapter = Sub2Api::new(transport);
    let err = adapter
        .available_groups(SUB2API_BASE, &bearer_session())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Transport(ref m) if m.contains("分组名")),
        "{err:?}"
    );
}

#[tokio::test]
async fn sub2api_available_groups_propagates_rates_call_failure() {
    // 会话失效必须可见（M5-S2 红线）：不得把 401 静默降级成「倍率未知」。
    let transport = MockTransport::new(vec![
        sub2api_ok(json!([{"id": 1, "name": "a"}])),
        json_resp(401, json!({"code": 401, "message": "invalid token"})),
    ]);
    let adapter = Sub2Api::new(transport);
    let err = adapter
        .available_groups(SUB2API_BASE, &bearer_session())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::AuthFailed(_)), "{err:?}");
}

// ============================================================ 红线：错误文案

#[tokio::test]
async fn groups_errors_never_carry_site_echoed_secret() {
    // 站点把密钥回显在错误文案里：错误全文不得出现密钥（章程 §4.4）。
    let transport = MockTransport::new(vec![json_resp(
        401,
        json!({"message": format!("token {SECRET} rejected")}),
    )]);
    let adapter = NewApi::new(transport);
    let err = adapter
        .available_groups(NEWAPI_BASE, &cookie_session())
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(!text.contains(SECRET), "错误文案泄漏密钥: {text}");
    assert!(!text.contains("LEAK0000"), "错误文案残留密钥片段: {text}");
    assert!(text.contains("sk-***"), "应留下脱敏痕迹: {text}");

    let transport = MockTransport::new(vec![json_resp(
        403,
        json!({"code": 403, "message": format!("key {SECRET} forbidden")}),
    )]);
    let adapter = Sub2Api::new(transport);
    let err = adapter
        .available_groups(SUB2API_BASE, &bearer_session())
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(!text.contains(SECRET), "错误文案泄漏密钥: {text}");
    assert!(!text.contains("LEAK0000"), "错误文案残留密钥片段: {text}");
    assert!(text.contains("sk-***"), "应留下脱敏痕迹: {text}");
}

// ============================================================ M7-S2 D-1：倍率统一走 parse_rate

/// D-1 订正：NewAPI 的倍率**不再**直接 `as_f64()`，而是走 `parse_rate`（B-91 的语义定稿）。
///
/// 关键三格：`0` **保留**（免费分组）、负数 **丢弃**（`None`，不报错）、字符串数字按边界表处理。
#[tokio::test]
async fn newapi_available_groups_rates_follow_parse_rate_semantics() {
    let transport = MockTransport::new(vec![newapi_ok(json!({
        "groups": [
            {"name": "free", "rate": 0},
            {"name": "neg", "rate": -1},
            {"name": "str", "rate": "2"},
            {"name": "bad", "rate": "abc"},
            {"name": "nul", "rate": null},
            {"name": "ratio", "ratio": 0.5},
            {"name": "inf", "rate": "inf"},
        ],
        "max_count": 9,
    }))]);
    let adapter = NewApi::new(transport);

    let groups = adapter
        .available_groups(NEWAPI_BASE, &cookie_session())
        .await
        .expect("倍率不可用不是传输错误，不得整条失败");

    assert_eq!(
        groups,
        vec![
            group("free", Some(0.0), None), // 0 = 免费分组，必须保留
            group("neg", None, None),       // 负数 ⇒ None（B-91）
            group("str", Some(2.0), None),  // 字符串数字按边界表
            group("bad", None, None),       // 非数字 ⇒ None
            group("nul", None, None),       // null ⇒ None
            group("ratio", Some(0.5), None),
            group("inf", None, None), // ±inf / NaN 形态 ⇒ None
        ]
    );
}

/// D-1 订正：Sub2API 的 `/groups/rates` 映射同样走 `parse_rate`。
///
/// 语义差异（与 NewAPI 的差别是**结构性的**）：这里的倍率是 `map<group_id, f64>` 的一项，
/// 解析不出 ⇒ **忽略该条目** ⇒ 该分组回落成 `rate = None`（而不是报错）。
#[tokio::test]
async fn sub2api_available_groups_rates_follow_parse_rate_semantics() {
    let transport = MockTransport::new(vec![
        sub2api_ok(json!([
            {"id": 1, "name": "free", "description": ""},
            {"id": 2, "name": "neg", "description": ""},
            {"id": 3, "name": "str", "description": ""},
            {"id": 4, "name": "bad", "description": ""},
            {"id": 5, "name": "ok", "description": ""},
            {"id": 6, "name": "missing", "description": ""},
        ])),
        sub2api_ok(json!({
            "1": 0,
            "2": -1,
            "3": "2",
            "4": "abc",
            "5": 1.5,
            "not-an-id": 1.0,
        })),
    ]);
    let adapter = Sub2Api::new(transport);

    let groups = adapter
        .available_groups(SUB2API_BASE, &bearer_session())
        .await
        .expect("倍率不可用不是传输错误，不得整条失败");

    assert_eq!(
        groups,
        vec![
            group("free", Some(0.0), None), // 0 = 免费分组，必须保留（不能丢条目）
            group("neg", None, None),       // 负数 ⇒ 条目被忽略 ⇒ 回落 None
            group("str", Some(2.0), None),  // 字符串数字按边界表
            group("bad", None, None),       // 非数字 ⇒ 忽略
            group("ok", Some(1.5), None),
            group("missing", None, None), // rates 里没有 ⇒ None（既有口径）
        ]
    );
}
