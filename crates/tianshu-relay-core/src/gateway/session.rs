//! M2：显式会话粘性（纯内存、无 IO、无 async）。
//!
//! 只接受客户端明确给出的稳定会话标识：`X-Tianshu-Session` 优先，其次
//! JSON body 顶层的 `prompt_cache_key`。原始标识只在本函数栈上短暂存在，
//! 存储里只有带本机随机盐、token scope 与上游协议派生的 SHA-256 key。
//!
//! 这里**不做** prompt 猜测、不解析 `metadata.user_id`、不看 IP / User-Agent。
//! pin 的语义只是“下次优先尝试上次成功的候选”，不是独占，也绝不会越过
//! 网关的规则、预算、熔断、撤销与协议能力约束；这些约束由调用方在查找 pin
//! 之后仍照常执行。

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// 方案默认值：30 分钟、512 个会话。TTL 只表示本地 pin 的有效期，不代表
/// 上游 prompt cache 的 TTL。
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(30 * 60);
pub const DEFAULT_SESSION_CAPACITY: usize = 512;
pub const MAX_SESSION_ID_BYTES: usize = 256;
pub const MAX_SESSION_MODEL_BYTES: usize = 256;

/// 会话与上游协议绑定，避免同名的跨协议会话共享 pin。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UpstreamProtocol {
    OpenAiChat,
    OpenAiResponses,
    AnthropicMessages,
    GeminiGenerateContent,
}

impl UpstreamProtocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiChat => "openai_chat",
            Self::OpenAiResponses => "openai_responses",
            Self::AnthropicMessages => "anthropic_messages",
            Self::GeminiGenerateContent => "gemini_generate_content",
        }
    }
}

/// 派生前的作用域。token id 使用本地数据库 id，不用 token 明文；`None`
/// 代表 legacy 单令牌作用域。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionScope {
    pub token_id: Option<i64>,
    pub upstream_protocol: UpstreamProtocol,
}

impl SessionScope {
    pub fn new(token_id: Option<i64>, upstream_protocol: UpstreamProtocol) -> Self {
        Self {
            token_id,
            upstream_protocol,
        }
    }
}

/// 不可逆的会话键。字段私有，且 `Debug` 不打印摘要；Drop 时清零。
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SessionIdentity([u8; 32]);

impl fmt::Debug for SessionIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionIdentity(<redacted>)")
    }
}

impl Drop for SessionIdentity {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// 成功请求后记录的上游目标。模型名必须来自已解析的路由事实，不能是原始
/// 请求里的任意自由文本。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionPin {
    pub site_id: i64,
    pub key_id: Option<i64>,
    pub model: String,
    pub upstream_protocol: UpstreamProtocol,
    /// 路由快照 generation；热更新后旧 pin 不再匹配。
    pub generation: u64,
}

impl SessionPin {
    /// 构造并校验 pin。模型名接受常见的模型标识字符；空、过长、URL 或
    /// 带空白的自由文本一律拒绝。
    pub fn new(
        site_id: i64,
        key_id: Option<i64>,
        model: impl Into<String>,
        upstream_protocol: UpstreamProtocol,
    ) -> Option<Self> {
        let model = model.into();
        if !safe_model_text(&model) {
            return None;
        }
        Some(Self {
            site_id,
            key_id,
            model,
            upstream_protocol,
            generation: 0,
        })
    }

    pub fn at_generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }
}

#[derive(Clone)]
struct Entry {
    pin: SessionPin,
    expires_at: Instant,
    last_used: u64,
}

#[derive(Default)]
struct State {
    entries: HashMap<SessionIdentity, Entry>,
    sequence: u64,
}

/// 线程安全的内存 pin 存储。`enabled=false` 时不解析身份、不存 pin。
pub struct SessionAffinityStore {
    enabled: bool,
    capacity: usize,
    ttl: Duration,
    salt: [u8; 32],
    state: Mutex<State>,
}

impl fmt::Debug for SessionAffinityStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionAffinityStore")
            .field("enabled", &self.enabled)
            .field("capacity", &self.capacity)
            .field("ttl", &self.ttl)
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl SessionAffinityStore {
    /// 生产构造器。随机盐来自操作系统 CSPRNG；失败必须显式返回，绝不降级为
    /// 可预测盐。调用方通常用默认 capacity / ttl。
    pub fn new(enabled: bool, capacity: usize, ttl: Duration) -> Result<Self, String> {
        // 默认关闭时连 CSPRNG 都不碰，保证既有启动路径不因新实验功能新增失败点。
        if !enabled {
            return Ok(Self::with_salt_inner(false, capacity, ttl, [0; 32]));
        }
        let mut salt = [0u8; 32];
        getrandom::fill(&mut salt).map_err(|e| format!("生成会话亲和盐失败: {e}"))?;
        Ok(Self::with_salt_inner(true, capacity, ttl, salt))
    }

    /// 确定性测试构造器。
    ///
    /// **不要在生产装配中使用固定盐**：固定盐会让相同会话 id 在不同安装间
    /// 派生出相同 key，破坏本地隔离。生产必须走 [`Self::new`] 的随机盐。
    #[doc(hidden)]
    pub fn with_salt(enabled: bool, capacity: usize, ttl: Duration, salt: [u8; 32]) -> Self {
        Self::with_salt_inner(enabled, capacity, ttl, salt)
    }

    fn with_salt_inner(enabled: bool, capacity: usize, ttl: Duration, salt: [u8; 32]) -> Self {
        Self {
            enabled,
            capacity,
            ttl,
            salt,
            state: Mutex::new(State::default()),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// 从明确来源提取身份并派生不可逆 key。Header 存在但非法时直接返回
    /// `None`，不会静默回退到 body；只有 Header 完全缺失才看 body。
    pub fn identity_from_header_or_body(
        &self,
        header: Option<&str>,
        body: Option<&[u8]>,
        scope: SessionScope,
    ) -> Option<SessionIdentity> {
        if !self.enabled {
            return None;
        }

        let raw = match header {
            Some(value) => normalize_session_id(value),
            None => {
                let body = body?;
                let value: serde_json::Value = serde_json::from_slice(body).ok()?;
                normalize_session_id(value.get("prompt_cache_key")?.as_str()?)
            }
        }?;

        let mut hasher = Sha256::new();
        hasher.update(b"tianshu-relay/session-affinity/v1\0");
        hasher.update(self.salt);
        match scope.token_id {
            Some(id) => {
                hasher.update([1u8]);
                hasher.update(id.to_le_bytes());
            }
            None => hasher.update([0u8]),
        }
        let protocol = scope.upstream_protocol.as_str().as_bytes();
        hasher.update((protocol.len() as u64).to_le_bytes());
        hasher.update(protocol);
        hasher.update((raw.len() as u64).to_le_bytes());
        hasher.update(raw.as_bytes());
        let digest = hasher.finalize();
        drop(raw);

        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        let identity = SessionIdentity(key);
        key.zeroize();
        Some(identity)
    }

    /// 查找仍有效的 pin，并把它更新为最近使用。过期项立即删除。
    pub fn lookup(&self, identity: &SessionIdentity, now: Instant) -> Option<SessionPin> {
        if !self.enabled {
            return None;
        }
        let Ok(mut state) = self.state.lock() else {
            return None;
        };
        let expired = state
            .entries
            .get(identity)
            .is_some_and(|entry| now >= entry.expires_at);
        if expired {
            state.entries.remove(identity);
            return None;
        }
        state.sequence = state.sequence.wrapping_add(1);
        let sequence = state.sequence;
        let entry = state.entries.get_mut(identity)?;
        entry.last_used = sequence;
        Some(entry.pin.clone())
    }

    /// 成功响应后写入 / 刷新 pin。容量满时淘汰最久未使用的会话。
    /// 返回 `false` 表示关闭、容量为 0 或时间溢出，调用方可据此记录原因。
    pub fn pin(&self, identity: SessionIdentity, pin: SessionPin, now: Instant) -> bool {
        if !self.enabled || self.capacity == 0 {
            return false;
        }
        let Some(expires_at) = now.checked_add(self.ttl) else {
            return false;
        };
        let Ok(mut state) = self.state.lock() else {
            return false;
        };

        if !state.entries.contains_key(&identity) && state.entries.len() >= self.capacity {
            if let Some(oldest) = state
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            {
                state.entries.remove(&oldest);
            }
        }

        state.sequence = state.sequence.wrapping_add(1);
        let sequence = state.sequence;
        state.entries.insert(
            identity,
            Entry {
                pin,
                expires_at,
                last_used: sequence,
            },
        );
        true
    }

    /// 清理过期 pin，返回删除数。
    pub fn retain_live(&self, now: Instant) -> usize {
        let Ok(mut state) = self.state.lock() else {
            return 0;
        };
        let before = state.entries.len();
        state.entries.retain(|_, entry| now < entry.expires_at);
        before - state.entries.len()
    }

    /// 按 pin 条件失效（撤销 key、切换模型、热更新等由调用方提供条件）。
    pub fn remove_if(&self, predicate: impl Fn(&SessionPin) -> bool) -> usize {
        let Ok(mut state) = self.state.lock() else {
            return 0;
        };
        let before = state.entries.len();
        state.entries.retain(|_, entry| !predicate(&entry.pin));
        before - state.entries.len()
    }

    pub fn clear(&self) -> usize {
        let Ok(mut state) = self.state.lock() else {
            return 0;
        };
        let removed = state.entries.len();
        state.entries.clear();
        removed
    }

    /// 包含可能已过期、尚未清理的条目。
    pub fn len(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.entries.len())
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for SessionAffinityStore {
    fn drop(&mut self) {
        self.salt.zeroize();
        if let Ok(mut state) = self.state.lock() {
            state.entries.clear();
        }
    }
}

fn normalize_session_id(raw: &str) -> Option<Zeroizing<String>> {
    if raw.is_empty()
        || raw.len() > MAX_SESSION_ID_BYTES
        || !raw.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        })
    {
        return None;
    }
    Some(Zeroizing::new(raw.to_owned()))
}

fn safe_model_text(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= MAX_SESSION_MODEL_BYTES
        && !model.contains("://")
        && !model.contains("sk-")
        && model.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@' | b'+')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const SALT_A: [u8; 32] = [7; 32];
    const SALT_B: [u8; 32] = [9; 32];

    fn store(capacity: usize, ttl: Duration) -> SessionAffinityStore {
        SessionAffinityStore::with_salt(true, capacity, ttl, SALT_A)
    }

    fn scope(token_id: Option<i64>, protocol: UpstreamProtocol) -> SessionScope {
        SessionScope::new(token_id, protocol)
    }

    fn pin(site_id: i64, key_id: i64, model: &str) -> SessionPin {
        SessionPin::new(site_id, Some(key_id), model, UpstreamProtocol::OpenAiChat)
            .expect("合法 pin")
    }

    fn identity(
        store: &SessionAffinityStore,
        header: Option<&str>,
        body: Option<&[u8]>,
        scope: SessionScope,
    ) -> SessionIdentity {
        store
            .identity_from_header_or_body(header, body, scope)
            .expect("应有明确身份")
    }

    #[test]
    fn disabled_store_never_extracts_or_pins() {
        let store = SessionAffinityStore::with_salt(
            false,
            DEFAULT_SESSION_CAPACITY,
            DEFAULT_SESSION_TTL,
            SALT_A,
        );
        let scope = scope(Some(1), UpstreamProtocol::OpenAiChat);
        assert!(store
            .identity_from_header_or_body(Some("session-a"), None, scope)
            .is_none());
        // Even an identity derived by an enabled store cannot pin while disabled.
        let enabled = self::store(1, DEFAULT_SESSION_TTL);
        let id = identity(&enabled, Some("session-a"), None, scope);
        assert!(!store.pin(id, pin(1, 2, "gpt-x"), Instant::now()));
        assert!(store.is_empty());
    }

    #[test]
    fn only_explicit_header_or_prompt_cache_key_is_accepted() {
        let store = self::store(8, DEFAULT_SESSION_TTL);
        let scope = scope(Some(1), UpstreamProtocol::OpenAiChat);
        assert_eq!(
            store.identity_from_header_or_body(Some("session-a"), None, scope),
            store.identity_from_header_or_body(Some("session-a"), None, scope)
        );
        assert!(store
            .identity_from_header_or_body(Some("session with spaces"), None, scope)
            .is_none());
        assert!(store
            .identity_from_header_or_body(Some(&"a".repeat(257)), None, scope)
            .is_none());
        assert!(store
            .identity_from_header_or_body(Some("会话"), None, scope)
            .is_none());
        assert!(store
            .identity_from_header_or_body(None, Some(b"not-json"), scope)
            .is_none());
        assert!(store
            .identity_from_header_or_body(
                None,
                Some(br#"{"metadata":{"user_id":"user-1"}}"#),
                scope
            )
            .is_none());
        assert_eq!(
            store.identity_from_header_or_body(
                None,
                Some(br#"{"prompt_cache_key":"session-b"}"#),
                scope
            ),
            store.identity_from_header_or_body(Some("session-b"), None, scope)
        );
        // Header wins and a malformed explicit header does not fall back to body.
        assert!(store
            .identity_from_header_or_body(
                Some("bad id"),
                Some(br#"{"prompt_cache_key":"session-b"}"#),
                scope
            )
            .is_none());
    }

    #[test]
    fn token_and_protocol_scopes_are_isolated() {
        let store = self::store(16, DEFAULT_SESSION_TTL);
        let now = Instant::now();
        let s1 = scope(Some(1), UpstreamProtocol::OpenAiChat);
        let s2 = scope(Some(2), UpstreamProtocol::OpenAiChat);
        let s3 = scope(Some(1), UpstreamProtocol::AnthropicMessages);
        let i1 = identity(&store, Some("same"), None, s1);
        let i2 = identity(&store, Some("same"), None, s2);
        let i3 = identity(&store, Some("same"), None, s3);
        assert_ne!(i1, i2);
        assert_ne!(i1, i3);
        assert!(store.pin(i1.clone(), pin(10, 11, "gpt-x"), now));
        assert!(store.pin(i2, pin(20, 21, "gpt-x"), now));
        assert!(store.pin(i3, pin(30, 31, "claude-x"), now));
        assert_eq!(store.lookup(&i1, now).unwrap().site_id, 10);
        assert_eq!(store.len(), 3);
    }

    #[test]
    fn salt_changes_the_derived_identity() {
        let one = self::store(2, DEFAULT_SESSION_TTL);
        let other = SessionAffinityStore::with_salt(true, 2, DEFAULT_SESSION_TTL, SALT_B);
        let scope = scope(Some(1), UpstreamProtocol::OpenAiChat);
        let a = identity(&one, Some("same-session"), None, scope);
        let b = identity(&other, Some("same-session"), None, scope);
        assert_ne!(a, b);
    }

    #[test]
    fn ttl_expires_and_lookup_refreshes_lru() {
        let store = self::store(2, Duration::from_secs(10));
        let start = Instant::now();
        let a = identity(
            &store,
            Some("session-a"),
            None,
            scope(Some(1), UpstreamProtocol::OpenAiChat),
        );
        let b = identity(
            &store,
            Some("session-b"),
            None,
            scope(Some(1), UpstreamProtocol::OpenAiChat),
        );
        assert!(store.pin(a.clone(), pin(1, 1, "m"), start));
        assert!(store.pin(b.clone(), pin(2, 2, "m"), start));
        assert_eq!(
            store
                .lookup(&a, start + Duration::from_secs(5))
                .unwrap()
                .site_id,
            1
        );
        let c = identity(
            &store,
            Some("session-c"),
            None,
            scope(Some(1), UpstreamProtocol::OpenAiChat),
        );
        assert!(store.pin(c, pin(3, 3, "m"), start + Duration::from_secs(5)));
        assert_eq!(
            store
                .lookup(&a, start + Duration::from_secs(5))
                .unwrap()
                .site_id,
            1
        );
        assert!(
            store.lookup(&b, start + Duration::from_secs(5)).is_none(),
            "B 应被 LRU 淘汰"
        );
        assert_eq!(
            store.lookup(&a, start + Duration::from_secs(10)),
            None,
            "TTL 到点应过期"
        );
        assert_eq!(store.len(), 1, "过期项在下一次 lookup 时清除");
        assert_eq!(
            store.retain_live(start + Duration::from_secs(16)),
            1,
            "主动清理也应删除过期 pin"
        );
        assert!(store.is_empty());
    }

    #[test]
    fn zero_capacity_never_pins() {
        let store = self::store(0, DEFAULT_SESSION_TTL);
        let id = identity(
            &store,
            Some("session-a"),
            None,
            scope(Some(1), UpstreamProtocol::OpenAiChat),
        );
        assert!(!store.pin(id, pin(1, 1, "model-x"), Instant::now()));
        assert!(store.is_empty());
    }

    #[test]
    fn refresh_pin_replaces_value_and_moves_to_recent() {
        let store = self::store(1, DEFAULT_SESSION_TTL);
        let now = Instant::now();
        let a = identity(
            &store,
            Some("session-a"),
            None,
            scope(Some(1), UpstreamProtocol::OpenAiChat),
        );
        assert!(store.pin(a.clone(), pin(1, 1, "model-a"), now));
        assert!(store.pin(
            a.clone(),
            pin(2, 2, "model-b"),
            now + Duration::from_secs(1)
        ));
        assert_eq!(store.len(), 1);
        assert_eq!(
            store
                .lookup(&a, now + Duration::from_secs(1))
                .unwrap()
                .site_id,
            2
        );
    }

    #[test]
    fn clear_and_remove_if_are_safe() {
        let store = self::store(8, DEFAULT_SESSION_TTL);
        let now = Instant::now();
        let scope = scope(Some(1), UpstreamProtocol::OpenAiChat);
        for (id, site) in [("a", 1), ("b", 2), ("c", 3)] {
            let key = identity(&store, Some(id), None, scope);
            assert!(store.pin(key, pin(site, site, "m"), now));
        }
        assert_eq!(store.remove_if(|pin| pin.key_id == Some(2)), 1);
        assert_eq!(store.len(), 2);
        assert_eq!(store.clear(), 2);
        assert!(store.is_empty());
    }

    #[test]
    fn pin_model_validation_rejects_free_text_and_urls() {
        for model in ["gpt-5.1", "claude-opus-4.6", "openrouter/anthropic/claude"] {
            assert!(SessionPin::new(1, None, model, UpstreamProtocol::OpenAiChat).is_some());
        }
        for model in [
            "",
            "please summarize this prompt",
            "https://secret.example/x",
        ] {
            assert!(SessionPin::new(1, None, model, UpstreamProtocol::OpenAiChat).is_none());
        }
    }

    #[test]
    fn lru_is_bounded_and_thread_safe() {
        let store = Arc::new(self::store(64, DEFAULT_SESSION_TTL));
        let mut handles = Vec::new();
        for worker in 0..8 {
            let store = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                let now = Instant::now();
                for i in 0..100 {
                    let header = format!("worker-{worker}-session-{i}");
                    let scope = scope(Some(worker), UpstreamProtocol::OpenAiChat);
                    let id = store
                        .identity_from_header_or_body(Some(&header), None, scope)
                        .unwrap();
                    assert!(store.pin(id, pin(worker, i, "model-x"), now));
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(store.len(), 64);
    }

    #[test]
    fn debug_output_never_contains_raw_identity() {
        let store = self::store(2, DEFAULT_SESSION_TTL);
        let raw = "session-canary-0123456789";
        let id = identity(
            &store,
            Some(raw),
            None,
            scope(Some(1), UpstreamProtocol::OpenAiChat),
        );
        assert!(!format!("{:?}", id).contains(raw));
        assert!(!format!("{:?}", store).contains(raw));
        assert_eq!(format!("{:?}", id), "SessionIdentity(<redacted>)");
    }
}
