//! 适配器注册表：按顺序探测站点类型，并按类型取出适配器。
//!
//! 新增一个站点适配器只需要：实现 [`SiteAdapter`] → 在 [`SiteRegistry::adapter`] 加一个分支
//! → 在 [`SiteRegistry::new`] 的探测顺序里插入。核心逻辑不用动。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::newapi::NewApi;
use super::sub2api::Sub2Api;
use super::transport::HttpTransport;
use super::{SiteAdapter, SiteFingerprint, SiteKind};
use crate::error::{Error, Result};

#[derive(Clone)]
pub struct SiteRegistry<T: HttpTransport + Clone + 'static> {
    transport: T,
    probe_order: Vec<SiteKind>,
    /// **适配器实例缓存**。
    ///
    /// 不能每次调用都新建：Sub2API 的适配器内部持有「等待二次验证的 temp_token」，
    /// 每次新建会让那份状态在两次 `login` 之间丢失，导致每次都要多发一次密码登录请求
    /// （M2-S2 的 e2e 实测到 3 次登录请求而不是 2 次）。
    cache: Arc<Mutex<HashMap<SiteKind, Arc<dyn SiteAdapter>>>>,
}

impl<T: HttpTransport + Clone + 'static> SiteRegistry<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            probe_order: vec![SiteKind::NewApi, SiteKind::Sub2Api],
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 覆盖探测顺序（测试用）
    pub fn with_probe_order(mut self, order: Vec<SiteKind>) -> Self {
        self.probe_order = order;
        self
    }

    /// 取该类型的适配器实例（同一个 registry 内复用）。
    pub fn adapter(&self, kind: SiteKind) -> Arc<dyn SiteAdapter> {
        if let Ok(cache) = self.cache.lock() {
            if let Some(existing) = cache.get(&kind) {
                return Arc::clone(existing);
            }
        }
        let created: Arc<dyn SiteAdapter> = match kind {
            SiteKind::NewApi => Arc::new(NewApi::new(self.transport.clone())),
            SiteKind::Sub2Api => Arc::new(Sub2Api::new(self.transport.clone())),
        };
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(kind, Arc::clone(&created));
        }
        created
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
        // NewAPI 排在探测顺序第一位，一次命中
        assert_eq!(mock.request_count(), 1);
    }

    #[tokio::test]
    async fn detect_falls_through_to_the_second_adapter() {
        // Sub2API 放前面：它对 NewAPI 站点会失败（404），随后 NewAPI 命中。
        // 这条同时证明「探测顺序真的会依次尝试」而不是只试第一个。
        let mock = MockTransport::new(vec![
            HttpResponse::new(404, b"nope".to_vec()),
            newapi_status_response(),
        ]);
        let registry = SiteRegistry::new(mock.clone())
            .with_probe_order(vec![SiteKind::Sub2Api, SiteKind::NewApi]);

        let fingerprint = registry.detect("https://relay.example.com").await.unwrap();
        assert_eq!(fingerprint.kind, SiteKind::NewApi);
        assert_eq!(mock.request_count(), 2, "两个适配器都应真的发过请求");
    }

    #[tokio::test]
    async fn detect_identifies_sub2api_and_does_not_misjudge_newapi() {
        // Sub2API 的公开设置（信封是 code/data，没有 success 字段）
        let sub2api = HttpResponse::json(
            200,
            json!({"code": 0, "message": "success", "data": {"site_name": "示例 Sub2API", "totp_enabled": true}}),
        )
        .expect("构造测试响应");

        // 默认顺序是 [NewAPI, Sub2API]：NewAPI 的探测会先打 `/api/status` 并失败，
        // 再轮到 Sub2API。这里给两个响应，验证「第二个适配器被真的调用且命中」。
        let mock = MockTransport::new(vec![HttpResponse::new(404, b"nope".to_vec()), sub2api]);
        let registry = SiteRegistry::new(mock.clone());
        let fingerprint = registry.detect("https://sub.example.com").await.unwrap();
        assert_eq!(fingerprint.kind, SiteKind::Sub2Api);
        assert_eq!(fingerprint.display_name, "示例 Sub2API");
        assert_eq!(mock.request_count(), 2);

        // 反向：把 NewAPI 的 `/api/status` 响应同时喂给两个适配器，
        // Sub2API 必须**拒绝**它，随后 NewAPI 认领。
        let mock = MockTransport::new(vec![newapi_status_response(), newapi_status_response()]);
        let registry = SiteRegistry::new(mock.clone())
            .with_probe_order(vec![SiteKind::Sub2Api, SiteKind::NewApi]);
        let fingerprint = registry.detect("https://relay.example.com").await.unwrap();
        assert_eq!(
            fingerprint.kind,
            SiteKind::NewApi,
            "NewAPI 的响应被 Sub2API 误判了"
        );
        assert_eq!(mock.request_count(), 2, "两个适配器各发一次");
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
    async fn detect_aggregates_every_adapter_reason() {
        // 两个适配器都失败时，错误串要同时给出两条原因（便于判断是网络问题还是站点改版）
        let mock = MockTransport::new(vec![
            HttpResponse::new(404, b"nope".to_vec()),
            HttpResponse::new(404, b"nope".to_vec()),
        ]);
        let registry = SiteRegistry::new(mock);

        let err = registry
            .detect("https://unknown.example.com")
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(matches!(err, Error::FingerprintMismatch(_)));
        assert!(message.contains("newapi"), "{message}");
        assert!(message.contains("sub2api"), "{message}");
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
