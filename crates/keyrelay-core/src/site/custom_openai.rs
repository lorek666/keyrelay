//! `custom-openai-compatible` 适配器（M7-S2 / PRD FR-1，审计 §3-5 / B-85）。
//!
//! 定位：一个**只读**的 OpenAI 兼容端点（自建中转、第三方 relay、本地 vLLM/Ollama 之类）。
//! 它只有 `/v1/models` 可读——**没有**令牌管理端点、**没有**余额与分组概念。
//! 因此本适配器：
//!
//! - 只实现 `detect()`（读 `/v1/models` 判形态）与 `login()`（无凭证语义，返回空会话）；
//! - 五个写/管方法一律 `Err(Error::Unsupported(...))`，**不猜端点、不发请求**；
//! - `balance()` 返回 [`Balance::unknown`]（不可观测），**不编造数字**（章程 §4.2 第 4 条）。
//!
//! **红线**（章程 §3.2）：
//!
//! 1. 探测**不带任何凭证**：`detect()` 的请求头集合为空（不带 `Authorization` / `Cookie` /
//!    `X-Api-Key` / `X-Goog-Api-Key`）；本适配器**从不**把任何站点密钥发往 `/v1/models` 之外的端点。
//! 2. **不碰计费端点**：不探 `/v1/chat/completions`、`/v1/completions`、`/v1/embeddings`
//!    —— 那些会产生真实计费请求。
//! 3. 探测**不落盘、不建目录**：`detect()` 只发一次 GET。

use async_trait::async_trait;
use serde_json::Value;

use super::transport::{HttpRequest, HttpTransport, Method};
use super::{
    json_str, normalize_base_url, Balance, Credentials, GroupInfo, KeyMaterial, KeyMeta, KeySpec,
    Session, SiteAdapter, SiteFingerprint, SiteKind,
};
use crate::error::{Error, Result};

/// 五个写/管方法的统一错误文案（章程 §3.2 冻结，逐字）。
pub const UNSUPPORTED_MESSAGE: &str = "custom-openai-compatible 站点没有令牌管理端点";

/// 兜底站点名（`display_name` 三档兜底链的最后一档）。
const FALLBACK_DISPLAY_NAME: &str = "OpenAI 兼容端点";

pub struct CustomOpenAi<T: HttpTransport> {
    transport: T,
}

impl<T: HttpTransport> CustomOpenAi<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// 暴露传输层，便于契约测试断言请求内容。
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

/// 三档兜底：`data[0].owned_by`（非空）→ `base_url` 的 host → 字面量。
///
/// **不用** `data[0].id`：那是模型名，会把站点显示成 `gpt-4o`（M7-S2 spec §5）。
fn display_name(items: &[Value], url: &str) -> String {
    if let Some(owner) = items
        .first()
        .and_then(|item| json_str(item, "/owned_by"))
        .filter(|owner| !owner.is_empty())
    {
        return owner.to_string();
    }
    if let Some(host) = host_of(url) {
        return host.to_string();
    }
    FALLBACK_DISPLAY_NAME.to_string()
}

/// 从 URL 里取 host（含端口）。不引入 URL 解析库：本函数只服务于一个显示名。
fn host_of(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let host = rest.split(['/', '?', '#']).next()?;
    (!host.is_empty()).then_some(host)
}

fn unsupported() -> Error {
    Error::Unsupported(UNSUPPORTED_MESSAGE.to_string())
}

#[async_trait]
impl<T: HttpTransport + 'static> SiteAdapter for CustomOpenAi<T> {
    fn kind(&self) -> SiteKind {
        SiteKind::CustomOpenAiCompatible
    }

    /// `GET {base}/v1/models`，**不带任何凭证**。
    ///
    /// 命中判据（全部满足）：2xx + body 是 JSON **对象** + 有 `data` 字段且 `data` 是**数组**
    /// （空数组也算命中：「一个模型都没有」仍是合法的兼容端点）。
    /// 其余一律 `FingerprintMismatch`（**不猜**，M7-S2 spec §5）。
    async fn detect(&self, base_url: &str) -> Result<SiteFingerprint> {
        let url = format!("{}/v1/models", normalize_base_url(base_url));
        // 头集合保持为空：不携带 Authorization / Cookie / X-Api-Key。
        let resp = self
            .transport
            .request(HttpRequest::new(Method::Get, url.clone()))
            .await?;

        if !(200..300).contains(&resp.status) {
            return Err(Error::FingerprintMismatch(format!(
                "{url} 返回 {}",
                resp.status
            )));
        }

        let value = resp.json_value().map_err(|_| {
            Error::FingerprintMismatch(format!("{url} 不是 JSON，可能不是 OpenAI 兼容端点"))
        })?;

        let Some(object) = value.as_object() else {
            return Err(Error::FingerprintMismatch(
                "响应不是对象，不符合 OpenAI /v1/models 形态".into(),
            ));
        };
        let Some(data) = object.get("data") else {
            return Err(Error::FingerprintMismatch("响应缺少 data 字段".into()));
        };
        let Some(items) = data.as_array() else {
            return Err(Error::FingerprintMismatch(
                "data 不是数组，不符合 OpenAI /v1/models 形态".into(),
            ));
        };

        Ok(SiteFingerprint {
            kind: SiteKind::CustomOpenAiCompatible,
            display_name: display_name(items, &url),
            // 兼容端点不声明版本；编一个版本号就是编造。
            version: None,
        })
    }

    /// 无凭证语义：返回空会话，**不发任何请求**。
    async fn login(&self, _base_url: &str, _cred: Credentials) -> Result<Session> {
        Ok(Session::default())
    }

    async fn list_keys(&self, _base_url: &str, _session: &Session) -> Result<Vec<KeyMeta>> {
        Err(unsupported())
    }

    async fn create_key(
        &self,
        _base_url: &str,
        _session: &Session,
        _spec: KeySpec,
    ) -> Result<KeyMaterial> {
        Err(unsupported())
    }

    async fn reveal_key(
        &self,
        _base_url: &str,
        _session: &Session,
        _remote_id: &str,
    ) -> Result<KeyMaterial> {
        Err(unsupported())
    }

    async fn revoke_key(
        &self,
        _base_url: &str,
        _session: &Session,
        _remote_id: &str,
    ) -> Result<()> {
        Err(unsupported())
    }

    /// 不可观测的余额（M7-S2 spec §6）：`known == false`，**不发请求、不编造数字**。
    ///
    /// 为什么不返回 `Err(Unsupported)`：`refresh_all` 会把任何错误计入 `sites_failed`，
    /// 那会让一个健康的兼容端点在每轮刷新里显示成「站点失败」——用假故障换假数字。
    /// 「该类型不提供余额」由能力集（`capabilities(kind).balance == false`）表达。
    async fn balance(&self, _base_url: &str, _session: &Session) -> Result<Balance> {
        Ok(Balance::unknown("USD"))
    }

    async fn available_groups(
        &self,
        _base_url: &str,
        _session: &Session,
    ) -> Result<Vec<GroupInfo>> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::transport::{HttpResponse, MockTransport};
    use serde_json::json;

    const BASE: &str = "https://relay.example.com";

    fn ok(value: Value) -> HttpResponse {
        HttpResponse::json(200, value).expect("构造响应")
    }

    #[tokio::test]
    async fn detect_accepts_empty_data_array_and_uses_host_fallback() {
        let transport = MockTransport::new(vec![ok(json!({"object": "list", "data": []}))]);
        let adapter = CustomOpenAi::new(transport);

        let fingerprint = adapter.detect(BASE).await.expect("应命中");
        assert_eq!(fingerprint.kind, SiteKind::CustomOpenAiCompatible);
        assert_eq!(fingerprint.display_name, "relay.example.com");
        assert!(fingerprint.version.is_none());
    }

    #[tokio::test]
    async fn detect_prefers_owned_by_over_host() {
        let transport = MockTransport::new(vec![ok(json!({
            "object": "list",
            "data": [{"id": "gpt-4o", "owned_by": "自建中转"}],
        }))]);
        let adapter = CustomOpenAi::new(transport);
        assert_eq!(adapter.detect(BASE).await.unwrap().display_name, "自建中转");
    }

    #[test]
    fn host_of_handles_ports_and_paths() {
        assert_eq!(
            host_of("https://a.example.com:8443/v1/models"),
            Some("a.example.com:8443")
        );
        assert_eq!(host_of("http://127.0.0.1/v1/models"), Some("127.0.0.1"));
        assert_eq!(host_of("not-a-url"), None);
    }
}
