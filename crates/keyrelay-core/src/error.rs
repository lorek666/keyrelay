//! 统一错误类型。所有对外错误都必须有明确变体，库内不得 `unwrap()` / `panic!`。

/// 二次验证方式。定义在错误模块中，供 `site` 适配器与上层复用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondFactorKind {
    /// 6 位动态口令
    Totp,
    /// 邮件/短信验证码
    EmailCode,
    /// 通行密钥（本产品不做自动处理，仅提示用户走 WebView）
    Passkey,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// 站点指纹与适配器不匹配（站点改版或类型判断错误）
    #[error("站点指纹不匹配: {0}")]
    FingerprintMismatch(String),

    /// 账号密码错误或会话失效
    #[error("登录失败: {0}")]
    AuthFailed(String),

    /// 站点要求人机验证，本产品不绕过，需转 WebView 人工完成
    #[error("需要人工完成验证码")]
    CaptchaRequired,

    /// 站点要求二次验证
    #[error("需要二次验证({kind:?})")]
    SecondFactorRequired { kind: SecondFactorKind },

    /// 触发站点限流
    #[error("触发限流, 建议 {retry_after_secs}s 后重试")]
    RateLimited { retry_after_secs: u64 },

    /// 额度不足（HTTP 403 + insufficient_user_quota / pre_consume_token_quota_failed）
    #[error("额度不足")]
    QuotaExhausted,

    /// 远端资源不存在（key 被删除等）
    #[error("远端资源不存在: {0}")]
    NotFound(String),

    /// 网络层错误
    #[error("传输错误: {0}")]
    Transport(String),

    /// 钥匙串读写失败
    #[error("钥匙串错误: {0}")]
    Vault(String),

    /// 系统钥匙串不可用（无后端 / 未授权 / 平台不支持）。禁止降级为内存实现。
    #[error("系统钥匙串不可用: {0}")]
    VaultUnavailable(String),

    /// 需要用户先在界面上明确同意
    #[error("需要用户同意后才能写入：{agent_id} 的 {channel} 通道将写入 {target_path}")]
    ConsentRequired {
        agent_id: String,
        channel: String,
        target_path: String,
    },

    /// 目标文件正被另一个 KeyRelay 实例（或线程）占用
    #[error("目标文件正被占用，请稍后重试: {0}")]
    FileBusy(String),

    /// 本地存储失败
    #[error("存储错误: {0}")]
    Store(String),

    /// 配置文件写入失败
    #[error("写入失败 {path}: {reason}")]
    Inject { path: String, reason: String },

    /// 尚未实现的能力（占位，禁止在发布路径上出现）
    #[error("尚未实现: {0}")]
    Unimplemented(String),
}

impl Error {
    /// 便于构造 `Error::Inject`
    pub fn inject(path: impl AsRef<std::path::Path>, reason: impl Into<String>) -> Self {
        Error::Inject {
            path: path.as_ref().display().to_string(),
            reason: reason.into(),
        }
    }

    /// 该错误是否值得重试（用于调度器退避策略）
    pub fn is_retryable(&self) -> bool {
        matches!(self, Error::Transport(_) | Error::RateLimited { .. })
    }
}

pub type Result<T> = std::result::Result<T, Error>;
