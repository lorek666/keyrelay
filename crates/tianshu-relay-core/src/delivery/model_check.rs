//! 投递前模型验证（P2-8）。
//!
//! 两层，职责分开：
//!
//! 1. **静态配对校验**（[`check_static`]，纯函数、不联网）：
//!    只拦**有把握**的错配。仓库里**没有** provider↔模型的映射表可以依据——
//!    - `model_meta` 的内置表是「模型名 → 上下文/输出参数」，按厂商分组写注释，
//!      但它不约束哪个通道能写哪个模型；
//!    - 各通道写入器把模型名**原样**写进落点文件，不做厂商校验；
//!    - 中转端点本身会转译模型名：仓库内就有反例——`claude_code` 的模块文档
//!      以 `ANTHROPIC_MODEL = "gpt-4o"` 为例，即 Claude Code 通道经中转投递 GPT 模型
//!      是**正常用法**；按「通道厂商 = 模型厂商」硬拦会把这种合法投递拦掉；
//!    - 站点行只有 `kind`（网关类型，如 newapi）与 `base_url`，不声明它提供哪些模型；
//!      OpenCode 的 provider 名恒为 `keyrelay`（中转 provider，不是上游厂商）。
//!      因此静态层**不判定厂商配对**：格式合格的模型一律记 `unchecked`
//!      （不是通过、不是失败——是「无依据，不作判定」，以探针为准）；只拦两种
//!      格式上不可能是模型 id 的输入（空白/控制字符、URL 形态、provider 前缀后无模型名）。
//!      没有模型、或通道根本不写模型字段时记 `not_applicable`，不拦也不警告。
//!
//! 2. **真实 `/v1/models` 探针**（[`probe_models`]，只读）：
//!    用待投递的端点 + 密钥发一次 `GET /v1/models`，验证端点可达、密钥有效、
//!    目标模型在目录中。探针**只读**：GET、无 body、不写盘、不记账、不写绑定、
//!    不进任何持久化表；结果只随本次计划返回，调用方不得把它存下来。
//!    超时由调用方传入（生产取 [`MODEL_PROBE_TIMEOUT`]）；失败分层见
//!    [`ProbeCheck::code`] 的取值说明；密钥只出现在 `Authorization` 请求头里，
//!    任何返回结构、错误文案、日志里都不含它（本模块根本不 log）。
//!
//! # 失败是否硬拦投递（fail-closed 定夺）
//!
//! - **硬拦**（`blocks_delivery = true`）：
//!   - 静态格式无效：写进去的模型名在任何端点上都不可能是合法 id，投递必错；
//!   - 探针 401：密钥与端点不匹配或旧登录残留——这是**肯定性证据**，投递必拿 401；
//!   - 探针 200 但目录非空且模型不在其中：端点已证实密钥有效，目录是它亲口给的，
//!     模型不在其中是**肯定性证据**，投递后 agent 必报模型不存在。
//!     注意：这条只对「被探端点 = 目标站点」成立。网关模式下被探的是本地网关
//!     的聚合/透传目录（见 `TianshuRelayService::validate_delivery_model` 的分流），
//!     那里的 `not_in_catalog` 不是肯定性证据，故在验证层被降级为警告
//!     `not_in_gateway_catalog`，通过也被改写为口径限定的
//!     `passed_gateway_catalog`；`probe_models` 本身不分来源，仍按端点口径出码。
//! - **警告放行**（`blocks_delivery = false`，由用户在计划视图看到后决定）：
//!   - 网络不可达 / 超时 / 非 401 的异常状态 / 非 OpenAI 目录形态 / 空目录：
//!     这些都是「**没有证据**」，不是「有反证据」。探针失败可能是端点一时不可达、
//!     目录接口被单独限流、或中转站不公开完整目录；硬拦会把「端点暂时查不到」
//!     变成「用户永远投不出去」。警告里必须给出去向（检查端点地址、代理、重试），
//!     用户看过警告仍确认投递时，责任在用户一侧——这与「计划展示、apply 复核」的
//!     两层结构一致（plan 只展示，apply 再探一次并执行硬拦）。
//! - 403 单独处理：目录接口的权限可能与推理接口分开设（有的中转站只给管理员 key
//!   开目录），403 不能证明推理会失败 ⇒ 警告，不硬拦；401 则不同，401 是
//!   「这把密钥在这个端点上根本认不出来」，推理同样认不出来 ⇒ 硬拦。
//!
//! # 被动指纹比对（不在本项）
//!
//! 响应指纹、模型身份指纹等被动比对是后续项，本模块**不做**：探针只核对
//! 「目录里有没有这个 id」，不推断端点背后到底是哪个模型。

use std::time::Duration;

use crate::site::transport::{HttpRequest, HttpResponse, HttpTransport, Method};

/// 生产探针总预算：一次 `GET /v1/models` 连重试在内不得超过此时长。
/// 10s 是计划视图可接受的等待上限；中转站目录接口正常在 1s 内返回，
/// 超过即视为端点侧有问题，走超时警告分支，不继续拖住界面。
pub const MODEL_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

// ============================================================ 静态校验

/// 静态校验结果。`outcome` 取值：
///
/// - `"fail"`：格式上不可能是模型 id，硬拦；
/// - `"not_applicable"`：没有模型、或通道不写模型字段，不拦不警告；
/// - `"unchecked"`：格式合格，但仓库无依据判定厂商配对——不拦，以探针为准。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticCheck {
    pub outcome: &'static str,
    pub code: &'static str,
}

/// 通道是否写模型字段。依据与 `delivery::expected_fields` 的装配表同源：
/// 只有四条通道从不写模型——Codex 的 auth.json（只有令牌）、Claude Desktop、
/// Cursor（两者只写令牌与端点）、DSH（只有 `KEYRELAY_API_KEY`）；其余通道在
/// 有模型输入时都写模型字段（CodexConfig 的 `model` 同样只在有输入时出现，
/// 但它属于「写模型字段」的通道）。
pub fn channel_writes_model(channel: crate::delivery::DeliveryChannel) -> bool {
    use crate::delivery::DeliveryChannel::*;
    !matches!(
        channel,
        CodexAuthJson | ClaudeDesktop | Cursor | DeepSeekHarness
    )
}

/// 静态配对校验（纯函数）。
///
/// - `model` 为 `None` 或 trim 后为空 ⇒ `not_applicable` / `no_model`：
///   模型是可选输入，没填时投递只写密钥与端点，无配对可言；
/// - 通道不写模型字段 ⇒ `not_applicable` / `channel_no_model`：
///   模型输入根本不会落盘，拦它等于拦一个不存在的写入；
/// - 模型含空白/控制字符、含 `://`（把 URL 贴进了模型栏）、或 provider 前缀
///   （`xxx/` 形态，见 opencode 文档的 `keyrelay/gpt-4o`）后无模型名
///   ⇒ `fail` / `malformed`：这些串在任何 OpenAI 兼容端点上都不可能是模型 id；
/// - 其余 ⇒ `unchecked` / `unchecked`：见模块文档，厂商配对无依据，不判定。
pub fn check_static(channel: crate::delivery::DeliveryChannel, model: Option<&str>) -> StaticCheck {
    let Some(raw) = model.map(str::trim).filter(|m| !m.is_empty()) else {
        return StaticCheck {
            outcome: "not_applicable",
            code: "no_model",
        };
    };
    if !channel_writes_model(channel) {
        return StaticCheck {
            outcome: "not_applicable",
            code: "channel_no_model",
        };
    }
    if !is_plausible_model_id(raw) {
        return StaticCheck {
            outcome: "fail",
            code: "malformed",
        };
    }
    StaticCheck {
        outcome: "unchecked",
        code: "unchecked",
    }
}

/// 模型 id 的最低形态要求（宁缺不拦：只排除**肯定不是**的串）。
///
/// 允许 `/`（`provider/model` 形态是 opencode 文档里的既有用例）与常见标点；
/// 排除空白与控制字符（id 里不可能出现）、`://`（URL 形态）、以及 `/` 后
/// 无内容（前缀后没有模型名）。
fn is_plausible_model_id(raw: &str) -> bool {
    if raw.contains("://") {
        return false;
    }
    if raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    if let Some((_, last)) = raw.rsplit_once('/') {
        if last.is_empty() {
            return false;
        }
    }
    true
}

// ============================================================ 探针

/// 探针结果。`outcome` 取值：
///
/// - `"passed"`：端点可达、密钥有效、模型在目录中；
/// - `"failed"`：有肯定性证据证明投递必错（401、模型不在非空目录），硬拦；
/// - `"warning"`：无证据（不可达、超时、目录形态异常、空目录、403 与其他状态），
///   不拦，用户看警告后决定；
/// - `"skipped"`：没做探针（无模型、通道不写模型、端点/密钥解析失败），不拦。
///
/// `code` 是前端文案的稳定键（中英成对见 `agents.plan.modelValidation`）；
/// `status` 只记 HTTP 状态码，**绝不**带响应正文（正文可能回显凭据或极长）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeCheck {
    pub outcome: &'static str,
    pub code: &'static str,
    pub status: Option<u16>,
    pub blocks_delivery: bool,
}

fn probe_failed(code: &'static str, status: Option<u16>) -> ProbeCheck {
    ProbeCheck {
        outcome: "failed",
        code,
        status,
        blocks_delivery: true,
    }
}

fn probe_warning(code: &'static str, status: Option<u16>) -> ProbeCheck {
    ProbeCheck {
        outcome: "warning",
        code,
        status,
        blocks_delivery: false,
    }
}

/// 静态校验 + 探针的合体。`model` 为 trim 后的模型名（无模型时为 `None`）；
/// `blocks_delivery` 为任一层硬拦的合取——调用方（plan 展示、apply 门禁）只看它。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelValidation {
    pub model: Option<String>,
    pub static_check: StaticCheck,
    pub probe: ProbeCheck,
    pub blocks_delivery: bool,
}

impl ModelValidation {
    /// 探针未做时的结果（静态层已判定不适用，或端点/密钥解析失败）。
    pub fn skipped(static_check: StaticCheck, code: &'static str) -> Self {
        Self {
            model: None,
            static_check,
            probe: ProbeCheck {
                outcome: "skipped",
                code,
                status: None,
                blocks_delivery: false,
            },
            blocks_delivery: false,
        }
    }

    pub fn with_probe(model: String, static_check: StaticCheck, probe: ProbeCheck) -> Self {
        let blocks_delivery = static_check.outcome == "fail" || probe.blocks_delivery;
        Self {
            model: Some(model),
            static_check,
            probe,
            blocks_delivery,
        }
    }
}

/// 拼 `/v1/models` 探针地址。站点 base_url 按既有惯例（`site::fetch_models`）
/// 是不带 `/v1` 的；但网关模式的 base_url 按通道可能已带 `/v1`
/// （`delivery::gateway_base_url_for`），直接拼会出 `/v1/v1/models` ⇒
/// 已带 `/v1` 时只补 `/models`，其余补 `/v1/models`；尾部斜杠先去掉。
pub fn models_url(base_url: &str) -> String {
    let base = base_url.trim().trim_end_matches('/');
    if base.ends_with("/v1") {
        format!("{base}/models")
    } else {
        format!("{base}/v1/models")
    }
}

/// 向待投递端点发一次真实 `/v1/models` 探针（只读 GET、无 body）。
///
/// - `tok` 是待投递密钥明文：只进 `Authorization` 请求头，不进任何返回结构；
///   参数名刻意不用 `token`（见仓库既定约束）。
/// - `timeout` 是本次探针的总预算（含传输层内部重试）；超时 ⇒ `timeout` 警告，
///   不硬拦（超时证明不了「密钥错」或「模型无」，只证明「这次没问到」）。
/// - 传输层错误（连接拒绝、DNS 失败等）⇒ `unreachable` 警告：去向是检查端点
///   地址与代理，不是「密钥错」。
/// - 401 ⇒ `unauthorized` 硬拦：文案必须译成「密钥与端点不匹配或旧登录残留」，
///   不得只报裸 401（前端按 code 取成对文案，见 `agents.plan.modelValidation`）。
/// - 403 ⇒ `forbidden` 警告：目录接口权限可能与推理接口分开，不证明推理会失败。
/// - 2xx：`data` 不是数组 ⇒ `bad_response` 警告（端点回的不是 OpenAI 目录形态，
///   无法判定）；`data` 为空 ⇒ `empty_catalog` 警告（空目录证明不了「模型不在」，
///   有的中转站不公开完整目录）；目录非空且宽松匹配不到 ⇒ `not_in_catalog` 硬拦。
/// - 其他状态 ⇒ `unexpected_status` 警告，只记状态码（404 常是 base_url 路径不对，
///   429 是限流稍后重试，5xx 是端点侧问题——前端按状态码给去向）。
pub async fn probe_models<T: HttpTransport + ?Sized>(
    transport: &T,
    base_url: &str,
    tok: &str,
    model: &str,
    timeout: Duration,
) -> ProbeCheck {
    let req = HttpRequest::new(Method::Get, models_url(base_url))
        .header("Authorization", format!("Bearer {tok}"));
    let resp = match tokio::time::timeout(timeout, transport.request(req)).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(_)) => return probe_warning("unreachable", None),
        Err(_) => return probe_warning("timeout", None),
    };
    match resp.status {
        401 => return probe_failed("unauthorized", Some(401)),
        403 => return probe_warning("forbidden", Some(403)),
        200..=299 => {}
        other => return probe_warning("unexpected_status", Some(other)),
    }
    let value = match resp.json_value() {
        Ok(v) => v,
        Err(_) => return probe_warning("bad_response", Some(resp.status)),
    };
    let Some(data) = value.get("data").and_then(|d| d.as_array()) else {
        return probe_warning("bad_response", Some(resp.status));
    };
    if data.is_empty() {
        return probe_warning("empty_catalog", Some(resp.status));
    }
    let ids: Vec<&str> = data
        .iter()
        .filter_map(|item| item.get("id").and_then(|i| i.as_str()))
        .collect();
    if ids.iter().any(|id| model_matches(model, id)) {
        ProbeCheck {
            outcome: "passed",
            code: "passed",
            status: Some(resp.status),
            blocks_delivery: false,
        }
    } else {
        probe_failed("not_in_catalog", Some(resp.status))
    }
}

/// 目录匹配（刻意宽松：只为避免**误拦**，误拦比漏拦代价大——漏拦时用户
/// 仍能在计划视图看到警告之外的信息，而误拦会把合法投递挡在门外）。
///
/// 依次试：精确相等 → 大小写不敏感 → 去 provider 前缀（`keyrelay/gpt-4o`
/// 对 `gpt-4o`）→ 去版本后缀（`gpt-4o-2024-08-06` 对 `gpt-4o`，与
/// `model_meta::lookup` 的去后缀口径同源，但后缀段只认版本形态——纯数字、
/// `v` + 数字、数字加点，避免 `gpt-4` 被误认成 `gpt-4o` 的去后缀结果）。
fn model_matches(model: &str, catalog_id: &str) -> bool {
    let model = model.trim();
    let catalog_id = catalog_id.trim();
    if model == catalog_id {
        return true;
    }
    if model.eq_ignore_ascii_case(catalog_id) {
        return true;
    }
    let model_base = strip_provider_prefix(model);
    let catalog_base = strip_provider_prefix(catalog_id);
    if model_base.eq_ignore_ascii_case(catalog_base) {
        return true;
    }
    let model_low = model_base.to_lowercase();
    let catalog_low = catalog_base.to_lowercase();
    strip_version_suffix(&model_low) == catalog_low
        || model_low == strip_version_suffix(&catalog_low)
}

/// 去掉 `provider/` 前缀（只去第一段；没有 `/` 时原样返回）。
fn strip_provider_prefix(id: &str) -> &str {
    match id.split_once('/') {
        Some((_, rest)) if !rest.is_empty() => rest,
        _ => id,
    }
}

/// 去掉尾部版本形态段：段为纯数字、或 `v`/`V` + 数字开头且其余只含数字与点时
/// 才去掉，并继续向前试；一旦遇到非版本段即停。
fn strip_version_suffix(id: &str) -> &str {
    let mut cur = id;
    while let Some(pos) = cur.rfind('-') {
        let seg = &cur[pos + 1..];
        let version_like = !seg.is_empty()
            && (seg.bytes().all(|b| b.is_ascii_digit())
                || (seg.len() > 1
                    && (seg.starts_with('v') || seg.starts_with('V'))
                    && seg[1..].bytes().all(|b| b.is_ascii_digit() || b == b'.')));
        if !version_like {
            break;
        }
        cur = &cur[..pos];
    }
    cur
}

/// 供测试断言：响应体解析口径与探针一致（`data[].id` 列表）。
#[allow(dead_code)]
fn catalog_ids(resp: &HttpResponse) -> Option<Vec<String>> {
    let value = resp.json_value().ok()?;
    let data = value.get("data")?.as_array()?;
    Some(
        data.iter()
            .filter_map(|item| item.get("id").and_then(|i| i.as_str()))
            .map(|s| s.to_string())
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::DeliveryChannel;
    use crate::site::transport::MockTransport;
    use serde_json::json;

    fn resp(status: u16, value: serde_json::Value) -> HttpResponse {
        HttpResponse::json(status, value).expect("测试响应可序列化")
    }

    fn catalog_response(ids: &[&str]) -> HttpResponse {
        resp(
            200,
            json!({ "data": ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>() }),
        )
    }

    // ---------- 静态层 ----------

    #[test]
    fn static_no_model_is_not_applicable() {
        for model in [None, Some(""), Some("   ")] {
            let c = check_static(DeliveryChannel::OpenCode, model);
            assert_eq!(c.outcome, "not_applicable");
            assert_eq!(c.code, "no_model");
        }
    }

    #[test]
    fn static_channel_without_model_field_is_not_applicable() {
        // 装配表同源：这四条通道从不写模型字段，模型输入不会落盘。
        for ch in [
            DeliveryChannel::CodexAuthJson,
            DeliveryChannel::ClaudeDesktop,
            DeliveryChannel::Cursor,
            DeliveryChannel::DeepSeekHarness,
        ] {
            let c = check_static(ch, Some("gpt-4o"));
            assert_eq!(c.outcome, "not_applicable", "{ch:?}");
            assert_eq!(c.code, "channel_no_model", "{ch:?}");
        }
    }

    #[test]
    fn static_malformed_ids_fail() {
        for bad in [
            "gpt 4o",
            "gpt\n4o",
            "gpt\t4o",
            "https://relay.example.com/v1",
            "keyrelay/",
        ] {
            // 注：首尾空白由 check_static 先 trim（与计划层口径一致），
            // 这里只测「trim 后仍残留」的内部空白与 URL/空前缀形态。
            let c = check_static(DeliveryChannel::OpenCode, Some(bad));
            assert_eq!(c.outcome, "fail", "{bad:?}");
            assert_eq!(c.code, "malformed", "{bad:?}");
        }
    }

    #[test]
    fn static_cross_family_is_unchecked_not_blocked() {
        // 仓库反例：claude_code 文档以 ANTHROPIC_MODEL=gpt-4o 为例——
        // 经中转投递时跨厂商是正常用法，静态层不得以厂商名硬拦。
        let c = check_static(DeliveryChannel::ClaudeCodeSettings, Some("gpt-4o"));
        assert_eq!(c.outcome, "unchecked");
        assert_eq!(c.code, "unchecked");
        // provider 前缀形态（opencode 文档的 keyrelay/gpt-4o）同样不拦。
        let c = check_static(DeliveryChannel::OpenCode, Some("keyrelay/gpt-4o"));
        assert_eq!(c.outcome, "unchecked");
    }

    #[test]
    fn static_well_formed_unknown_model_is_unchecked() {
        let c = check_static(DeliveryChannel::DeepSeek, Some("acme-future-1"));
        assert_eq!(c.outcome, "unchecked");
    }

    // ---------- 探针 URL ----------

    #[test]
    fn models_url_handles_v1_suffix_and_trailing_slash() {
        assert_eq!(
            models_url("https://relay.example.com"),
            "https://relay.example.com/v1/models"
        );
        assert_eq!(
            models_url("https://relay.example.com/"),
            "https://relay.example.com/v1/models"
        );
        // 网关模式 base 已带 /v1 时不得拼出 /v1/v1/models。
        assert_eq!(
            models_url("http://127.0.0.1:8080/v1"),
            "http://127.0.0.1:8080/v1/models"
        );
        assert_eq!(
            models_url("http://127.0.0.1:8080/v1/"),
            "http://127.0.0.1:8080/v1/models"
        );
    }

    // ---------- 探针（MockTransport） ----------

    fn probe_req_assertions(mock: &MockTransport, expected_url: &str) {
        let reqs = mock.requests();
        assert_eq!(reqs.len(), 1);
        let req = &reqs[0];
        assert_eq!(req.method, Method::Get);
        assert_eq!(req.url, expected_url);
        assert!(req.body.is_none(), "探针是只读 GET，不得带 body");
        let auth = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Authorization"))
            .map(|(_, v)| v.as_str())
            .expect("探针必须带 Authorization 头");
        assert!(
            auth.starts_with("Bearer "),
            "Authorization 须为 Bearer 形态"
        );
    }

    #[tokio::test]
    async fn probe_success_when_model_in_catalog() {
        let mock = MockTransport::new(vec![catalog_response(&["gpt-4o", "gpt-4o-mini"])]);
        let out = probe_models(
            &mock,
            "https://relay.example.com",
            "sk-test-placeholder",
            "gpt-4o",
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(out.outcome, "passed");
        assert_eq!(out.code, "passed");
        assert_eq!(out.status, Some(200));
        assert!(!out.blocks_delivery);
        probe_req_assertions(&mock, "https://relay.example.com/v1/models");
    }

    #[tokio::test]
    async fn probe_unauthorized_blocks() {
        let mock = MockTransport::new(vec![resp(401, json!({ "error": "bad key" }))]);
        let out = probe_models(
            &mock,
            "https://relay.example.com",
            "sk-test-placeholder",
            "gpt-4o",
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(out.outcome, "failed");
        assert_eq!(out.code, "unauthorized");
        assert_eq!(out.status, Some(401));
        assert!(out.blocks_delivery);
    }

    #[tokio::test]
    async fn probe_not_in_nonempty_catalog_blocks() {
        let mock = MockTransport::new(vec![catalog_response(&["gpt-4o"])]);
        let out = probe_models(
            &mock,
            "https://relay.example.com",
            "sk-test-placeholder",
            "claude-3-5-sonnet",
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(out.outcome, "failed");
        assert_eq!(out.code, "not_in_catalog");
        assert!(out.blocks_delivery);
    }

    #[tokio::test]
    async fn probe_empty_catalog_is_warning_not_block() {
        let mock = MockTransport::new(vec![catalog_response(&[])]);
        let out = probe_models(
            &mock,
            "https://relay.example.com",
            "sk-test-placeholder",
            "gpt-4o",
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(out.outcome, "warning");
        assert_eq!(out.code, "empty_catalog");
        assert!(!out.blocks_delivery);
    }

    #[tokio::test]
    async fn probe_bad_shape_and_other_status_are_warnings() {
        let mock = MockTransport::new(vec![resp(200, json!({ "object": "list" }))]);
        let out = probe_models(
            &mock,
            "https://relay.example.com",
            "sk-test-placeholder",
            "gpt-4o",
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(out.code, "bad_response");
        assert!(!out.blocks_delivery);

        let mock = MockTransport::new(vec![resp(404, json!({ "error": "not found" }))]);
        let out = probe_models(
            &mock,
            "https://relay.example.com",
            "sk-test-placeholder",
            "gpt-4o",
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(out.code, "unexpected_status");
        assert_eq!(out.status, Some(404));
        assert!(!out.blocks_delivery);

        // 403 不证明推理会失败（目录权限可能与推理权限分开）⇒ 警告，不硬拦。
        let mock = MockTransport::new(vec![resp(403, json!({ "error": "forbidden" }))]);
        let out = probe_models(
            &mock,
            "https://relay.example.com",
            "sk-test-placeholder",
            "gpt-4o",
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(out.code, "forbidden");
        assert!(!out.blocks_delivery);
    }

    #[tokio::test]
    async fn probe_transport_error_is_unreachable_warning() {
        let mock = MockTransport::default();
        mock.push_error(crate::error::Error::Transport("连接被拒绝".to_string()));
        let out = probe_models(
            &mock,
            "https://relay.example.com",
            "sk-test-placeholder",
            "gpt-4o",
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(out.outcome, "warning");
        assert_eq!(out.code, "unreachable");
        assert!(!out.blocks_delivery);
    }

    #[tokio::test]
    async fn probe_lenient_matching_avoids_false_blocks() {
        // provider 前缀与版本后缀都不应造成误拦。
        for (model, catalog) in [
            ("keyrelay/gpt-4o", "gpt-4o"),
            ("gpt-4o", "keyrelay/gpt-4o"),
            ("gpt-4o-2024-08-06", "gpt-4o"),
            ("gpt-4o", "gpt-4o-2024-08-06"),
            ("GPT-4O", "gpt-4o"),
        ] {
            let mock = MockTransport::new(vec![catalog_response(&[catalog])]);
            let out = probe_models(
                &mock,
                "https://relay.example.com",
                "sk-test-placeholder",
                model,
                Duration::from_secs(5),
            )
            .await;
            assert_eq!(out.outcome, "passed", "{model} 对 {catalog}");
        }
        // 反例：gpt-4 不得被误认成 gpt-4o（去后缀只认版本形态段）。
        let mock = MockTransport::new(vec![catalog_response(&["gpt-4o"])]);
        let out = probe_models(
            &mock,
            "https://relay.example.com",
            "sk-test-placeholder",
            "gpt-4",
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(out.code, "not_in_catalog");
    }

    /// 慢传输层：请求永不返回，探针预算耗尽 ⇒ 超时警告，不硬拦。
    struct SlowTransport;

    #[async_trait::async_trait]
    impl HttpTransport for SlowTransport {
        async fn request(&self, _req: HttpRequest) -> crate::error::Result<HttpResponse> {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(HttpResponse::new(200, b"{}".to_vec()))
        }
    }

    #[tokio::test]
    async fn probe_timeout_is_warning_not_block() {
        let out = probe_models(
            &SlowTransport,
            "https://relay.example.com",
            "sk-test-placeholder",
            "gpt-4o",
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(out.outcome, "warning");
        assert_eq!(out.code, "timeout");
        assert!(!out.blocks_delivery);
    }

    #[test]
    fn validation_blocks_only_on_hard_evidence() {
        let static_ok = StaticCheck {
            outcome: "unchecked",
            code: "unchecked",
        };
        let v = ModelValidation::with_probe(
            "gpt-4o".to_string(),
            static_ok.clone(),
            probe_failed("unauthorized", Some(401)),
        );
        assert!(v.blocks_delivery);
        let v = ModelValidation::with_probe(
            "gpt-4o".to_string(),
            static_ok.clone(),
            probe_warning("timeout", None),
        );
        assert!(!v.blocks_delivery);
        let v = ModelValidation::with_probe(
            "gpt-4o".to_string(),
            StaticCheck {
                outcome: "fail",
                code: "malformed",
            },
            ProbeCheck {
                outcome: "passed",
                code: "passed",
                status: Some(200),
                blocks_delivery: false,
            },
        );
        assert!(v.blocks_delivery, "静态格式失败本身即硬拦，与探针无关");
        let v = ModelValidation::skipped(
            StaticCheck {
                outcome: "not_applicable",
                code: "no_model",
            },
            "skipped",
        );
        assert!(!v.blocks_delivery);
        assert_eq!(v.model, None);
    }

    // ---------- 本地桩端点（真实 ReqwestTransport + 本机 TCP 桩） ----------
    //
    // MockTransport 只能证明「探针函数按约定处理响应」；下面四组证明
    // 「真实传输层 + 真实 URL 拼法」下探针同样成立，且绝不用真实用户密钥
    // 与真实站点（桩密钥为测试串、桩地址为 127.0.0.1）。

    /// 起一个只回一次的桩：返回 (base_url, 捕获到的请求原文)。
    /// `delay` 为真延迟响应（用于超时组）；请求原文只用于断言方法/路径/
    /// Authorization 形态，断言时不打印密钥值。
    async fn stub_server(
        status: u16,
        body: &str,
        delay: Duration,
    ) -> (String, std::sync::Arc<std::sync::Mutex<String>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("桩端口可绑定");
        let base = format!("http://{}", listener.local_addr().expect("桩地址可读"));
        let captured = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let captured_clone = std::sync::Arc::clone(&captured);
        let body = body.to_string();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 8192];
                if let Ok(n) = stream.read(&mut buf).await {
                    if let Ok(text) = std::str::from_utf8(&buf[..n]) {
                        if let Ok(mut guard) = captured_clone.lock() {
                            *guard = text.to_string();
                        }
                    }
                }
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });
        (base, captured)
    }

    fn stub_transport() -> crate::site::transport_reqwest::ReqwestTransport {
        let config = crate::site::transport_reqwest::TransportConfig {
            timeout: Duration::from_secs(5),
            proxy: None,
            ..Default::default()
        };
        crate::site::transport_reqwest::ReqwestTransport::new(config).expect("桩传输层可构造")
    }

    #[tokio::test]
    async fn stub_probe_success_and_request_shape() {
        let (base, captured) = stub_server(
            200,
            r#"{"data":[{"id":"gpt-4o"},{"id":"gpt-4o-mini"}]}"#,
            Duration::ZERO,
        )
        .await;
        let out = probe_models(
            &stub_transport(),
            &base,
            "sk-stub-placeholder",
            "gpt-4o",
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(out.outcome, "passed");
        assert!(!out.blocks_delivery);
        let text = captured.lock().expect("桩请求可读").clone();
        assert!(
            text.starts_with("GET /v1/models "),
            "桩收到的请求行: 首行须为 GET /v1/models"
        );
        // 头名大小写不敏感：reqwest 落 HeaderMap 后会小写化头名。
        assert!(
            text.to_lowercase().contains("authorization: bearer "),
            "探针须带 Bearer 头"
        );
    }

    #[tokio::test]
    async fn stub_probe_gateway_v1_base_does_not_double_v1() {
        let (base, captured) =
            stub_server(200, r#"{"data":[{"id":"gpt-4o"}]}"#, Duration::ZERO).await;
        let out = probe_models(
            &stub_transport(),
            &format!("{base}/v1"),
            "sk-stub-placeholder",
            "gpt-4o",
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(out.outcome, "passed");
        let text = captured.lock().expect("桩请求可读").clone();
        assert!(
            text.starts_with("GET /v1/models "),
            "网关 base 已带 /v1 时不得请求 /v1/v1/models"
        );
    }

    #[tokio::test]
    async fn stub_probe_unauthorized_blocks() {
        let (base, _) = stub_server(401, r#"{"error":"bad key"}"#, Duration::ZERO).await;
        let out = probe_models(
            &stub_transport(),
            &base,
            "sk-stub-placeholder",
            "gpt-4o",
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(out.code, "unauthorized");
        assert!(out.blocks_delivery);
    }

    #[tokio::test]
    async fn stub_probe_not_in_catalog_blocks() {
        let (base, _) = stub_server(
            200,
            r#"{"data":[{"id":"some-other-model"}]}"#,
            Duration::ZERO,
        )
        .await;
        let out = probe_models(
            &stub_transport(),
            &base,
            "sk-stub-placeholder",
            "gpt-4o",
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(out.code, "not_in_catalog");
        assert!(out.blocks_delivery);
    }

    #[tokio::test]
    async fn stub_probe_timeout_and_unreachable_are_warnings() {
        // 超时：桩 3s 后才回，探针预算 300ms ⇒ 超时警告，不硬拦。
        let (base, _) =
            stub_server(200, r#"{"data":[{"id":"gpt-4o"}]}"#, Duration::from_secs(3)).await;
        let out = probe_models(
            &stub_transport(),
            &base,
            "sk-stub-placeholder",
            "gpt-4o",
            Duration::from_millis(300),
        )
        .await;
        assert_eq!(out.code, "timeout");
        assert!(!out.blocks_delivery);
        // 不可达：127.0.0.1:1 上没有任何监听 ⇒ 连接拒绝 ⇒ 警告，不硬拦。
        let out = probe_models(
            &stub_transport(),
            "http://127.0.0.1:1",
            "sk-stub-placeholder",
            "gpt-4o",
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(out.code, "unreachable");
        assert!(!out.blocks_delivery);
    }
}
