//! bazaarlink 模型检测（probe API，M15-S1）。
//!
//! 向 bazaarlink 发 probe 请求，检测目标模型端点是否真的是它声称的模型（防套壳/spoof）。
//! 复用 `site::HttpTransport` 调 bazaarlink.ai——不新加 transport trait、不新加依赖。
//!
//! # 安全边界
//!
//! - `apiKey` 来自 `Service::key_secret`（唯一明文出口 `vault_secret`，M8-S1 守卫），不新开 `vault.get`；
//! - `ProbeRequest` 手写 `Debug`，`api_key` 打印 `<已设置>`，不泄漏明文；
//! - 调用只 log 元数据（site_id / key_id / modelId），**不 log apiKey**；
//! - 响应里 `items[].response` / `responseHeaders` / `startedByIp` / `userKey` 视为敏感，
//!   `ProbeRun` 只取身份判定摘要，**不持久化**这些敏感字段。

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::site::transport::{HttpRequest, HttpResponse, HttpTransport, Method};

/// bazaarlink probe 端点（POST 启动 / GET 轮询）。M15-S1 只用同步 POST。
const PROBE_ENDPOINT: &str = "https://bazaarlink.ai/api/probe/run";

/// probe 请求。`api_key` 是明文，手写 `Debug` 不泄漏。
///
/// `api_key` 用 `Zeroizing<String>` 包裹：drop 时清零堆上明文，与 `key_secret` 出口口径一致。
#[derive(Clone)]
pub struct ProbeRequest {
    pub base_url: String,
    pub api_key: Zeroizing<String>,
    pub model_id: String,
    /// 身份声明。`None` 时由调用方默认填 `model_id`（M15-S1 决策：claimedModel = modelId）。
    pub claimed_model: Option<String>,
    pub sync: bool,
}

impl std::fmt::Debug for ProbeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 手写 Debug：api_key 永不回显明文（证伪守卫：改 derive Debug ⇒ 测试断言红）。
        f.debug_struct("ProbeRequest")
            .field("base_url", &self.base_url)
            .field("api_key", &"<已设置>")
            .field("model_id", &self.model_id)
            .field("claimed_model", &self.claimed_model)
            .field("sync", &self.sync)
            .finish()
    }
}

impl ProbeRequest {
    /// 构造发往 bazaarlink 的 JSON 请求体。`apiKey` 在体里是设计要求（发给 bazaarlink）。
    fn to_json(&self) -> Value {
        let mut v = json!({
            "baseUrl": self.base_url,
            "apiKey": self.api_key.as_str(),
            "modelId": self.model_id,
            "sync": self.sync,
        });
        if let Some(cm) = &self.claimed_model {
            v["claimedModel"] = json!(cm);
        }
        v
    }
}

/// probe 结果摘要。
///
/// **只取身份判定摘要**——`items[].response` / `responseHeaders` / `startedByIp` / `userKey`
/// 等敏感字段不进本结构（M15-S1 安全边界）。持久化与 IPC 都只走本结构。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProbeRun {
    /// bazaarlink runId（轮询用；也作为本地历史的主键之一）。
    pub run_id: String,
    /// run 生命周期：running / completed / failed / aborted。
    pub status: String,
    /// `identityAssessment.status`：match / mismatch / uncertain / insufficient_data。
    pub identity_status: Option<String>,
    /// `identityAssessment.verdict.status`：clean_match / spoof_behavior_induced / plain_mismatch / ...
    pub verdict_status: Option<String>,
    pub true_family: Option<String>,
    pub true_model: Option<String>,
    pub spoof_method: Option<String>,
    pub confidence: Option<String>,
    pub warnings_count: u32,
    /// bazaarlink 报告路径（`/api/probe/report/<id>`）。半敏感：含 runId。
    pub report_url: Option<String>,
    pub created_at: Option<i64>,
    pub completed_at: Option<i64>,
}

/// 发 probe 请求（POST bazaarlink，`sync=true` 等完成）。
///
/// 复用传入的 `HttpTransport`——生产用 `ReqwestTransport`，测试用 `MockTransport`。
/// 限流（429）读 `Retry-After` 头；502/503/400/403 映射成可读错误。
pub async fn run_probe<T: HttpTransport + Clone + 'static>(
    transport: &T,
    req: &ProbeRequest,
) -> Result<ProbeRun> {
    let http = HttpRequest::new(Method::Post, PROBE_ENDPOINT).json_body(&req.to_json())?;
    let resp = transport.request(http).await?;
    parse_probe_response(resp)
}

fn parse_probe_response(resp: HttpResponse) -> Result<ProbeRun> {
    if resp.status == 429 {
        let retry = resp.retry_after_secs().unwrap_or(60);
        return Err(Error::RateLimited {
            retry_after_secs: retry,
        });
    }
    if resp.status == 502 {
        return Err(Error::Transport("目标站点无法访问（DNS 解析失败）".into()));
    }
    if resp.status == 503 {
        return Err(Error::Transport("检测服务正在维护，请稍后重试".into()));
    }
    if resp.status == 400 {
        let body = resp.text_lossy();
        return Err(Error::Transport(format!(
            "检测请求被拒（目标 URL 无效或私有 / 参数不合法）: {body}"
        )));
    }
    if resp.status == 403 {
        return Err(Error::Transport(
            "请求的检测功能（推理强度校验）未启用".into(),
        ));
    }
    if resp.status < 200 || resp.status >= 300 {
        return Err(Error::Transport(format!(
            "检测服务返回 HTTP {}",
            resp.status
        )));
    }
    let v: Value = resp.json_value()?;
    parse_probe_run(&v)
}

/// 从 bazaarlink 响应 JSON 取身份判定摘要。宽松反序列化：只强依赖 `runId`，
/// 其余字段缺失返回 `None`/默认（schema 可能演变，文档明说 "may evolve"）。
fn parse_probe_run(v: &Value) -> Result<ProbeRun> {
    let run_id = v
        .get("runId")
        .and_then(|x| x.as_str())
        .ok_or_else(|| Error::Transport("probe 响应缺 runId".into()))?
        .to_string();
    let status = v
        .get("status")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown")
        .to_string();
    let assessment = v.get("identityAssessment");
    let identity_status = assessment
        .and_then(|a| a.get("status"))
        .and_then(|x| x.as_str())
        .map(String::from);
    let verdict = assessment.and_then(|a| a.get("verdict"));
    let verdict_status = verdict
        .and_then(|v| v.get("status"))
        .and_then(|x| x.as_str())
        .map(String::from);
    let true_family = verdict
        .and_then(|v| v.get("trueFamily"))
        .and_then(|x| x.as_str())
        .map(String::from);
    let true_model = verdict
        .and_then(|v| v.get("trueModel"))
        .and_then(|x| x.as_str())
        .map(String::from);
    let spoof_method = verdict
        .and_then(|v| v.get("spoofMethod"))
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty() && *s != "null")
        .map(String::from);
    let confidence = verdict
        .and_then(|v| v.get("confidence"))
        .and_then(|x| x.as_str())
        .map(String::from);
    let warnings_count = v
        .get("warnings")
        .and_then(|w| w.as_array())
        .map(|a| a.len() as u32)
        .unwrap_or(0);
    let report_url = v
        .get("reportUrl")
        .and_then(|x| x.as_str())
        .map(String::from);
    let created_at = v.get("createdAt").and_then(|x| x.as_i64());
    let completed_at = v.get("completedAt").and_then(|x| x.as_i64());
    Ok(ProbeRun {
        run_id,
        status,
        identity_status,
        verdict_status,
        true_family,
        true_model,
        spoof_method,
        confidence,
        warnings_count,
        report_url,
        created_at,
        completed_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::transport::MockTransport;

    fn probe_req() -> ProbeRequest {
        ProbeRequest {
            base_url: "https://api.example.com/v1".into(),
            api_key: Zeroizing::new("sk-test-secret".into()),
            model_id: "vendor/model".into(),
            claimed_model: Some("vendor/model".into()),
            sync: true,
        }
    }

    #[tokio::test]
    async fn run_probe_parses_completed_clean_match() {
        let mock = MockTransport::new(vec![HttpResponse::json(
            200,
            json!({
                "runId": "r1",
                "status": "completed",
                "identityAssessment": {
                    "status": "match",
                    "verdict": {
                        "status": "clean_match",
                        "trueFamily": "openai",
                        "trueModel": "gpt-4o",
                        "spoofMethod": null,
                        "confidence": "high"
                    }
                },
                "warnings": [],
                "reportUrl": "/api/probe/report/r1",
                "createdAt": 1700000000,
                "completedAt": 1700000060
            }),
        )
        .unwrap()]);
        let run = run_probe(&mock, &probe_req()).await.unwrap();
        assert_eq!(run.run_id, "r1");
        assert_eq!(run.status, "completed");
        assert_eq!(run.identity_status.as_deref(), Some("match"));
        assert_eq!(run.verdict_status.as_deref(), Some("clean_match"));
        assert_eq!(run.true_family.as_deref(), Some("openai"));
        assert_eq!(run.true_model.as_deref(), Some("gpt-4o"));
        assert_eq!(run.spoof_method, None);
        assert_eq!(run.confidence.as_deref(), Some("high"));
        assert_eq!(run.warnings_count, 0);
        assert_eq!(run.report_url.as_deref(), Some("/api/probe/report/r1"));
        assert_eq!(run.created_at, Some(1700000000));
        assert_eq!(run.completed_at, Some(1700000060));
    }

    #[tokio::test]
    async fn run_probe_parses_spoof_verdict() {
        let mock = MockTransport::new(vec![HttpResponse::json(
            200,
            json!({
                "runId": "r2",
                "status": "completed",
                "identityAssessment": {
                    "status": "mismatch",
                    "verdict": {
                        "status": "spoof_behavior_induced",
                        "trueFamily": "other",
                        "trueModel": null,
                        "spoofMethod": "behavior_induced",
                        "confidence": "medium"
                    }
                },
                "warnings": [{"id":"w1"},{"id":"w2"}]
            }),
        )
        .unwrap()]);
        let run = run_probe(&mock, &probe_req()).await.unwrap();
        assert_eq!(
            run.verdict_status.as_deref(),
            Some("spoof_behavior_induced")
        );
        assert_eq!(run.true_family.as_deref(), Some("other"));
        assert_eq!(run.true_model, None);
        assert_eq!(run.spoof_method.as_deref(), Some("behavior_induced"));
        assert_eq!(run.warnings_count, 2);
    }

    #[tokio::test]
    async fn run_probe_429_maps_to_rate_limited_with_retry_after() {
        let mock = MockTransport::new(vec![
            HttpResponse::new(429, b"rate limited".to_vec()).with_header("Retry-After", "120")
        ]);
        let err = run_probe(&mock, &probe_req()).await.unwrap_err();
        assert!(matches!(
            err,
            Error::RateLimited {
                retry_after_secs: 120
            }
        ));
    }

    #[tokio::test]
    async fn run_probe_502_reports_dns_failure() {
        let mock = MockTransport::new(vec![HttpResponse::new(502, b"bad gateway".to_vec())]);
        let err = run_probe(&mock, &probe_req()).await.unwrap_err();
        assert!(err.to_string().contains("DNS"));
    }

    #[tokio::test]
    async fn run_probe_400_reports_invalid_url() {
        let mock = MockTransport::new(vec![HttpResponse::new(400, b"invalid url".to_vec())]);
        let err = run_probe(&mock, &probe_req()).await.unwrap_err();
        assert!(err.to_string().contains("无效"));
    }

    #[tokio::test]
    async fn run_probe_503_reports_maintenance() {
        let mock = MockTransport::new(vec![HttpResponse::new(503, b"maintenance".to_vec())]);
        let err = run_probe(&mock, &probe_req()).await.unwrap_err();
        assert!(err.to_string().contains("维护"));
    }

    #[tokio::test]
    async fn run_probe_403_reports_feature_disabled() {
        let mock = MockTransport::new(vec![HttpResponse::new(403, b"disabled".to_vec())]);
        let err = run_probe(&mock, &probe_req()).await.unwrap_err();
        assert!(err.to_string().contains("未启用"));
    }

    #[tokio::test]
    async fn run_probe_incomplete_status_still_parses() {
        // running 状态（sync=false 场景，或未完成）——无 identityAssessment
        let mock = MockTransport::new(vec![HttpResponse::json(
            200,
            json!({ "runId": "r4", "status": "running" }),
        )
        .unwrap()]);
        let run = run_probe(&mock, &probe_req()).await.unwrap();
        assert_eq!(run.status, "running");
        assert_eq!(run.identity_status, None);
        assert_eq!(run.verdict_status, None);
    }

    #[tokio::test]
    async fn run_probe_missing_run_id_is_error() {
        let mock = MockTransport::new(vec![HttpResponse::json(
            200,
            json!({ "status": "completed" }),
        )
        .unwrap()]);
        let err = run_probe(&mock, &probe_req()).await.unwrap_err();
        assert!(err.to_string().contains("runId"));
    }

    #[tokio::test]
    async fn probe_request_debug_does_not_leak_api_key() {
        // 证伪守卫：Debug 输出不含 apiKey 明文。
        let req = probe_req();
        let dbg = format!("{:?}", req);
        assert!(!dbg.contains("sk-test-secret"));
        assert!(dbg.contains("<已设置>"));
    }

    #[tokio::test]
    async fn run_probe_sends_api_key_in_body_to_bazaarlink() {
        // 请求体含 apiKey（发给 bazaarlink，设计要求）；不是泄漏——是协议要求。
        let mock = MockTransport::new(vec![HttpResponse::json(
            200,
            json!({
                "runId": "r3", "status": "completed",
                "identityAssessment": {"status": "uncertain", "verdict": {"status": "ambiguous"}}
            }),
        )
        .unwrap()]);
        run_probe(&mock, &probe_req()).await.unwrap();
        let sent = mock.nth_request(0).unwrap();
        assert_eq!(sent.method, Method::Post);
        assert_eq!(sent.url, PROBE_ENDPOINT);
        let body: Value = serde_json::from_slice(&sent.body.unwrap()).unwrap();
        assert_eq!(body["apiKey"], "sk-test-secret");
        assert_eq!(body["baseUrl"], "https://api.example.com/v1");
        assert_eq!(body["modelId"], "vendor/model");
        assert_eq!(body["claimedModel"], "vendor/model");
        assert_eq!(body["sync"], true);
    }

    #[tokio::test]
    async fn run_probe_omits_claimed_model_when_none() {
        let mock = MockTransport::new(vec![HttpResponse::json(
            200,
            json!({ "runId": "r5", "status": "completed" }),
        )
        .unwrap()]);
        let mut req = probe_req();
        req.claimed_model = None;
        run_probe(&mock, &req).await.unwrap();
        let body: Value =
            serde_json::from_slice(&mock.nth_request(0).unwrap().body.unwrap()).unwrap();
        assert!(body.get("claimedModel").is_none() || body["claimedModel"].is_null());
    }
}
