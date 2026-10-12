//! Sub2API 适配器占位。
//!
//! M0 只固定接口形态；真实实现（`/api/v1/auth/login`、`/api/v1/keys`、`/api/v1/user/platform-quotas`，
//! 含 TOTP / step-up 处理）在 **M2-S1** 落地，spec 见 `docs/specs/`。
//!
//! 现在所有方法都返回 [`Error::Unimplemented`]，以便上层在 UI 上明确显示「暂不支持」而不是静默失败。

use async_trait::async_trait;

use super::transport::HttpTransport;
use super::{
    Balance, Credentials, KeyMaterial, KeyMeta, KeySpec, Session, SiteAdapter, SiteFingerprint,
    SiteKind,
};
use crate::error::{Error, Result};

const NOT_YET: &str = "Sub2API 适配器将在 M2-S1 实现";

pub struct Sub2Api<T: HttpTransport> {
    transport: T,
}

impl<T: HttpTransport> Sub2Api<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
}

#[async_trait]
impl<T: HttpTransport + 'static> SiteAdapter for Sub2Api<T> {
    fn kind(&self) -> SiteKind {
        SiteKind::Sub2Api
    }

    async fn detect(&self, _base_url: &str) -> Result<SiteFingerprint> {
        Err(Error::Unimplemented(NOT_YET.into()))
    }

    async fn login(&self, _base_url: &str, _cred: Credentials) -> Result<Session> {
        Err(Error::Unimplemented(NOT_YET.into()))
    }

    async fn list_keys(&self, _base_url: &str, _session: &Session) -> Result<Vec<KeyMeta>> {
        Err(Error::Unimplemented(NOT_YET.into()))
    }

    async fn create_key(
        &self,
        _base_url: &str,
        _session: &Session,
        _spec: KeySpec,
    ) -> Result<KeyMaterial> {
        Err(Error::Unimplemented(NOT_YET.into()))
    }

    async fn reveal_key(
        &self,
        _base_url: &str,
        _session: &Session,
        _remote_id: &str,
    ) -> Result<KeyMaterial> {
        Err(Error::Unimplemented(NOT_YET.into()))
    }

    async fn revoke_key(
        &self,
        _base_url: &str,
        _session: &Session,
        _remote_id: &str,
    ) -> Result<()> {
        Err(Error::Unimplemented(NOT_YET.into()))
    }

    async fn balance(&self, _base_url: &str, _session: &Session) -> Result<Balance> {
        Err(Error::Unimplemented(NOT_YET.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::transport::MockTransport;

    #[tokio::test]
    async fn stub_returns_unimplemented() {
        let adapter = Sub2Api::new(MockTransport::default());
        let err = adapter.detect("https://sub.example.com").await.unwrap_err();
        assert!(matches!(err, Error::Unimplemented(_)));
    }
}
