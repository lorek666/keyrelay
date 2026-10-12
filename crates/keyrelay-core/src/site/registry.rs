//! 适配器注册表：按顺序探测站点类型，并按类型取出适配器。
//!
//! 新增一个站点适配器只需要：实现 [`SiteAdapter`] → 在 [`SiteRegistry::adapter`] 加一个分支
//! → 在 [`SiteRegistry::new`] 的探测顺序里插入。核心逻辑不用动。

use super::newapi::NewApi;
use super::sub2api::Sub2Api;
use super::transport::HttpTransport;
use super::{SiteAdapter, SiteFingerprint, SiteKind};
use crate::error::{Error, Result};

#[derive(Clone)]
pub struct SiteRegistry<T: HttpTransport + Clone + 'static> {
    transport: T,
    probe_order: Vec<SiteKind>,
}

impl<T: HttpTransport + Clone + 'static> SiteRegistry<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            probe_order: vec![SiteKind::NewApi, SiteKind::Sub2Api],
        }
    }

    /// 覆盖探测顺序（测试用）
    pub fn with_probe_order(mut self, order: Vec<SiteKind>) -> Self {
        self.probe_order = order;
        self
    }

    pub fn adapter(&self, kind: SiteKind) -> Box<dyn SiteAdapter> {
        match kind {
            SiteKind::NewApi => Box::new(NewApi::new(self.transport.clone())),
            SiteKind::Sub2Api => Box::new(Sub2Api::new(self.transport.clone())),
        }
    }

    /// 依次探测，返回第一个匹配的指纹。
    ///
    /// `Unimplemented` 的适配器（占位实现）直接跳过；其余失败原因会被汇总进最终错误，
    /// 便于用户判断「是站点类型不支持，还是网络/站点改版」。
    pub async fn detect(&self, base_url: &str) -> Result<SiteFingerprint> {
        let mut reasons: Vec<String> = Vec::new();

        for kind in self.probe_order.clone() {
            let adapter = self.adapter(kind);
            match adapter.detect(base_url).await {
                Ok(fingerprint) => return Ok(fingerprint),
                Err(Error::Unimplemented(_)) => continue,
                Err(err) => reasons.push(format!("{}: {err}", kind.as_str())),
            }
        }

        detection_failure(base_url, reasons)
    }
}

/// 组装「探测全失败」的错误：无原因（全是占位适配器）与多原因两种形态。
fn detection_failure(base_url: &str, reasons: Vec<String>) -> Result<SiteFingerprint> {
    if reasons.is_empty() {
        return Err(Error::FingerprintMismatch(format!(
            "没有可用适配器能识别 {base_url}"
        )));
    }
    Err(Error::FingerprintMismatch(format!(
        "{base_url} 未被识别（{}）",
        reasons.join("; ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::transport::{HttpResponse, MockTransport};
    use serde_json::json;

    fn newapi_status_response() -> HttpResponse {
        HttpResponse::json(
            200,
            json!({"success": true, "data": {"version": "v0.9.1", "quota_per_unit": 500000}}),
        )
        .expect("构造测试响应")
    }

    #[tokio::test]
    async fn detect_returns_newapi_fingerprint() {
        let mock = MockTransport::new(vec![newapi_status_response()]);
        let registry = SiteRegistry::new(mock.clone());

        let fingerprint = registry.detect("https://relay.example.com").await.unwrap();
        assert_eq!(fingerprint.kind, SiteKind::NewApi);
        // 只探测一次就命中：Sub2API 分支（占位）不应被调用
        assert_eq!(mock.request_count(), 1);
    }

    #[tokio::test]
    async fn detect_skips_unimplemented_adapters() {
        // Sub2API 目前是 Unimplemented 占位：探测顺序把它放前面，应被跳过
        let mock = MockTransport::new(vec![newapi_status_response()]);
        let registry = SiteRegistry::new(mock.clone())
            .with_probe_order(vec![SiteKind::Sub2Api, SiteKind::NewApi]);

        let fingerprint = registry.detect("https://relay.example.com").await.unwrap();
        assert_eq!(fingerprint.kind, SiteKind::NewApi);
        assert_eq!(mock.request_count(), 1, "占位适配器不发请求");
    }

    #[tokio::test]
    async fn detect_reports_each_adapter_reason() {
        let mock = MockTransport::new(vec![HttpResponse::new(404, "nope".as_bytes().to_vec())]);
        let registry = SiteRegistry::new(mock);

        let err = registry
            .detect("https://unknown.example.com")
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(matches!(err, Error::FingerprintMismatch(_)));
        assert!(
            message.contains("newapi"),
            "错误信息应包含 newapi 分支原因: {message}"
        );
    }

    #[tokio::test]
    async fn detect_with_only_unimplemented_adapters_reports_no_adapter() {
        // 全部适配器都是占位实现时，不能把 Unimplemented 当成「站点不匹配」
        let mock = MockTransport::new(vec![]);
        let registry = SiteRegistry::new(mock.clone()).with_probe_order(vec![SiteKind::Sub2Api]);

        let err = registry
            .detect("https://sub.example.com")
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("没有可用适配器"),
            "应给出「没有可用适配器」而不是分支原因: {message}"
        );
        assert_eq!(mock.request_count(), 0);
    }

    #[test]
    fn detection_failure_aggregates_reasons() {
        // 多分支汇总（复审 P2-5）：错误串包含每条原因并以 "; " 连接
        let err = detection_failure(
            "https://x.example.com",
            vec!["newapi: 指纹不匹配".into(), "sub2api: 连接超时".into()],
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("newapi: 指纹不匹配"), "{message}");
        assert!(message.contains("sub2api: 连接超时"), "{message}");
        assert!(
            message.contains("; "),
            "多条原因应以 \"; \" 连接: {message}"
        );

        // 无原因分支
        let err = detection_failure("https://y.example.com", vec![]).unwrap_err();
        assert!(err.to_string().contains("没有可用适配器能识别"));
    }

    #[tokio::test]
    async fn adapter_returns_expected_kind() {
        let mock = MockTransport::new(vec![]);
        let registry = SiteRegistry::new(mock);
        assert_eq!(registry.adapter(SiteKind::NewApi).kind(), SiteKind::NewApi);
        assert_eq!(
            registry.adapter(SiteKind::Sub2Api).kind(),
            SiteKind::Sub2Api
        );
    }
}
