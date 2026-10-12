//! 真实 NewAPI 站点**只读**冒烟（BACKLOG B-30 的主体）。
//!
//! 默认 `#[ignore]`：本文件依赖外网与第三方站点的可用性，**不进**常规门禁。
//! 显式执行：
//!
//! ```bash
//! cargo test -p keyrelay-core --test real_site_smoke -- --ignored --nocapture
//! ```
//!
//! 安全约定（由本文件自身的断言守护）：
//! - **只发 GET**，不发起任何写请求；
//! - 不使用任何账号密码；
//! - 只探测公开端点 `/api/status` 与 `/api/user/login/encryption-key`。

use std::sync::{Arc, Mutex};

use keyrelay_core::site::newapi::NewApi;
use keyrelay_core::site::transport::{HttpRequest, HttpResponse, HttpTransport, Method};
use keyrelay_core::site::transport_reqwest::{ReqwestTransport, TransportConfig};
use keyrelay_core::site::{SiteAdapter, SiteKind};
use keyrelay_core::Result;

/// 真实站点（2026-10-12 探测留档见 `docs/evidence/real-site-probe-2026-10-12.md`）。
const REAL_SITE: &str = "https://newapi.example.com";

/// 记录每一次请求的方法与 URL，并**拒绝**任何非 GET 请求。
struct ReadOnlyTransport {
    inner: ReqwestTransport,
    seen: Arc<Mutex<Vec<(Method, String)>>>,
}

impl ReadOnlyTransport {
    fn new() -> Self {
        Self {
            inner: ReqwestTransport::new(TransportConfig::default()).expect("构造传输层"),
            seen: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn methods(&self) -> Vec<Method> {
        self.seen
            .lock()
            .expect("锁")
            .iter()
            .map(|(m, _)| *m)
            .collect()
    }

    fn urls(&self) -> Vec<String> {
        self.seen
            .lock()
            .expect("锁")
            .iter()
            .map(|(_, u)| u.clone())
            .collect()
    }
}

#[async_trait::async_trait]
impl HttpTransport for ReadOnlyTransport {
    async fn request(&self, req: HttpRequest) -> Result<HttpResponse> {
        assert_eq!(
            req.method,
            Method::Get,
            "本测试只允许 GET，实际发出了 {:?} {}",
            req.method,
            req.url
        );
        self.seen
            .lock()
            .expect("锁")
            .push((req.method, req.url.clone()));
        self.inner.request(req).await
    }
}

#[tokio::test]
#[ignore = "依赖外网与第三方站点可用性；用 --ignored 显式执行"]
async fn detect_identifies_real_newapi_site() {
    let transport = ReadOnlyTransport::new();
    let adapter = NewApi::new(transport);

    let fingerprint = adapter.detect(REAL_SITE).await.expect("真实站点应能识别");

    assert_eq!(fingerprint.kind, SiteKind::NewApi);
    assert!(
        !fingerprint.display_name.trim().is_empty(),
        "display_name 不应为空"
    );
    let version = fingerprint.version.expect("真实站点应带 version");
    assert!(!version.trim().is_empty(), "version 不应为空");

    println!(
        "[real-site] kind={:?} display_name={} version={}",
        fingerprint.kind, fingerprint.display_name, version
    );
    assert_eq!(
        adapter.transport().methods(),
        vec![Method::Get],
        "指纹识别只应发 GET"
    );
}

#[tokio::test]
#[ignore = "依赖外网与第三方站点可用性；用 --ignored 显式执行"]
async fn encryption_probe_parses_real_response_shape() {
    // 直接打公开端点，验证真实响应形态可被现有解析路径读懂。
    // `login` 会先探测加密端点——但我们不能真登录（需要账号），
    // 因此这里只发探测请求并断言状态码与 JSON 形态。
    let transport = ReadOnlyTransport::new();
    let url = format!("{REAL_SITE}/api/user/login/encryption-key");
    let resp = transport
        .request(HttpRequest::new(Method::Get, url))
        .await
        .expect("探测请求应完成");

    println!("[real-site] encryption-key status={}", resp.status);
    assert_eq!(resp.status, 200, "真实站点该端点应返回 200");

    let value = resp.json_value().expect("应是 JSON");
    assert_eq!(
        value.get("success").and_then(|v| v.as_bool()),
        Some(true),
        "信封应是 success=true: {value}"
    );
    let enabled = value
        .pointer("/data/enabled")
        .expect("真实响应应带 data.enabled");
    assert!(
        enabled.is_boolean(),
        "data.enabled 应是布尔（真实形态），实际: {enabled}"
    );

    println!("[real-site] data.enabled={enabled}");
    assert_eq!(transport.methods(), vec![Method::Get], "只应发 GET");
}

#[tokio::test]
#[ignore = "依赖外网与第三方站点可用性；用 --ignored 显式执行"]
async fn status_endpoint_exposes_the_fields_detect_relies_on() {
    let transport = ReadOnlyTransport::new();
    let url = format!("{REAL_SITE}/api/status");
    let resp = transport
        .request(HttpRequest::new(Method::Get, url))
        .await
        .expect("status 请求应完成");

    let value = resp.json_value().expect("应是 JSON");
    let data = value.get("data").expect("应有 data");

    // `detect` 的特征判定是「多字段任一命中」，这里逐个记录真实存在性
    for field in ["quota_per_unit", "version", "system_name", "start_time"] {
        println!(
            "[real-site] {field} present={} value={}",
            data.get(field).is_some(),
            data.get(field).cloned().unwrap_or_default()
        );
    }
    assert!(
        data.get("quota_per_unit").is_some() || data.get("version").is_some(),
        "至少应命中一个特征字段"
    );

    // 余额换算依赖这个字段；真实站点若缺失，`quota_per_unit` 会退化为 None（不致命）
    if let Some(qpu) = data.get("quota_per_unit").and_then(|v| v.as_i64()) {
        assert!(qpu > 0, "quota_per_unit 应为正数");
        println!("[real-site] quota_per_unit={qpu}");
    }

    assert_eq!(transport.methods(), vec![Method::Get], "只应发 GET");
    assert!(
        transport.urls().iter().all(|u| u.contains("/api/status")),
        "只应访问 /api/status: {:?}",
        transport.urls()
    );
}

#[tokio::test]
#[ignore = "依赖外网；用 --ignored 显式执行"]
async fn unreachable_host_reports_a_clear_error() {
    // 不依赖外网的负例：指向必然拒绝连接的本地端口
    let transport = ReadOnlyTransport::new();
    let adapter = NewApi::new(transport);

    let err = adapter
        .detect("http://127.0.0.1:1")
        .await
        .expect_err("不可达地址必须报错，不得静默成功");
    println!("[real-site] unreachable → {err}");
    assert!(!err.to_string().is_empty());
}
