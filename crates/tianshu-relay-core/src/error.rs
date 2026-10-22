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

    /// 账号密码错误、会话失效，或站点拒绝了某个需要认证的操作。
    ///
    /// 消息里由调用方带上**操作名**（「登录」/「列举令牌」/「创建令牌」），
    /// 否则用户在列举令牌时看到「登录失败」会误判为会话问题（第三轮复核 P2-4）。
    #[error("认证失败: {0}")]
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

    /// 连接层失败：DNS / TCP / TLS 在**握手阶段**就失败了，请求体一个字节都没进对端
    /// 的处理流程（M19-S2 / B-162）。
    ///
    /// 这个变体存在的唯一理由是**计费安全**：它回答的是「这次失败能不能把同一个请求
    /// 再发一次而不产生重复扣费」。答案是可以——对端根本没看到这个请求。
    ///
    /// 与 [`Error::Transport`] 的分界：`Transport` 包含**可能已送达**的失败
    /// （读超时、连接建立后中断、响应体读到一半 EOF），那些**不能**重放。
    /// 判据只有一处：`reqwest::Error::is_connect()`（见 `site::transport_reqwest::describe`），
    /// 与网关侧 B-138 的重放口径同源。别在别处凭文案猜——`"连接失败: …"` 这个前缀是
    /// 给人看的，不是契约。
    ///
    /// **边界（实测）**：`is_connect()` **不**覆盖「连接挂起直到 `connect_timeout`」，
    /// 那类失败在 reqwest 里表现为 `is_timeout()` ⇒ 仍落在 `Transport`（不可重放）。
    #[error("连接未建立（请求未送达）: {0}")]
    NotDelivered(String),

    /// 输入形态不符合该站点类型的约定（M9-S2 / B-120）。**请求未发出**。
    ///
    /// 为什么单开一个变体，而不是复用现成的两个：
    ///
    /// - **不是** [`Error::AuthFailed`]：那会命中 `is_auth_failure` 与前端的
    ///   `isAuthError()`，把「改一下输入」说成「请重新登录」（M9-S1 D-1 的同一条推理）；
    /// - **不是** [`Error::Transport`]：一个字节都没发出去，说「传输错误」是假话；
    ///   而且 `Transport` 会被 `is_retryable()` 判为可重试——同一个值重试多少次也不会成功。
    #[error("输入不符合站点要求: {0}")]
    InvalidInput(String),

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

    /// 目标文件正被另一个天枢 Relay 实例（或线程）占用
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

    /// 该站点类型**设计上**不支持此能力。
    ///
    /// 与 [`Error::Unimplemented`] 的区别是语义而非措辞：后者表示「还没做」（发布路径上不该出现），
    /// 本条表示「不做」——例如 `custom-openai-compatible` 站点没有令牌管理端点，
    /// 它永远不会有 `list_keys`。界面上因此应当**灰显**而不是提示「即将支持」。
    #[error("站点类型不支持: {0}")]
    Unsupported(String),
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
        // `NotDelivered` 必须在这里：它此前是 `Transport` 的一个分支，站点侧的
        // `RetryingTransport` 一直会重试它（连接失败重试是安全的）。加变体而漏掉这一条，
        // 等于把站点侧的瞬时连接故障从「重试 3 次」悄悄降级成「一次就放弃」。
        matches!(
            self,
            Error::Transport(_) | Error::NotDelivered(_) | Error::RateLimited { .. }
        )
    }

    /// 这次失败**可证明**请求没有送达对端（M19-S2）。
    ///
    /// 只用于「能不能把同一个请求再发一次」这一个判断，不要拿它当错误分类用。
    pub fn is_not_delivered(&self) -> bool {
        matches!(self, Error::NotDelivered(_))
    }

    /// 把一个「可能已送达」的传输失败说清楚（M21-S3 / B-165）。
    ///
    /// 全仓只有这一个地方生成这类话：probe 的提交失败（M19-S2）与站点侧非幂等写
    /// 放弃重试（本步）共用。**别在别处拼同义句**——两处措辞一旦漂移，用户会以为
    /// 那是两种不同的故障。
    ///
    /// 只包装 [`Error::Transport`]：其余变体（限流、额度、认证…）都带着自己准确的语义，
    /// 套上「无法确认是否已处理」反而把它们的意思搅浑了。
    pub fn note_maybe_delivered(self, op: &str) -> Error {
        match self {
            Error::Transport(message) => Error::Transport(format!(
                "{op}时连接中断，无法确认服务端是否已处理（可能已成功、也可能没有）：{message}"
            )),
            other => other,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
