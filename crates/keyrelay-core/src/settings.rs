//! 运行时设置：刷新间隔、余额阈值、启动时是否跑漂移检测、通知、轮换、界面与常驻。
//!
//! 存储是 `settings` 键值表；**读不到就用默认值**（老库没有这些键是正常状态，
//! 不该因此报错）。写入前一律 `validate()`。
//!
//! M6-S5 把 PRD FR-9 要求但一直缺的项补齐：主题、语言、代理、遥测开关、自动更新开关，
//! 以及 FR-3 / FR-7 的通知、轮换、自启与常驻配置。

use crate::error::{Error, Result};

/// 刷新间隔上限：24 小时。再长就没有「定时」的意义了。
pub const MAX_REFRESH_INTERVAL_SECS: u64 = 24 * 60 * 60;

/// Webhook 超时上限。再长会让后台刷新任务被一个挂死的端点拖住。
pub const MAX_NOTIFY_TIMEOUT_SECS: u64 = 60;

/// 轮换周期的上限（天）。10 年足够表达「实际上不想轮换」。
pub const MAX_ROTATION_AGE_DAYS: u32 = 3650;

/// 允许的主题取值。第一个是默认值。
pub const THEMES: [&str; 3] = ["system", "light", "dark"];
/// 允许的语言取值。第一个是默认值。
pub const LANGUAGES: [&str; 2] = ["zh-CN", "en-US"];

const KEY_REFRESH_INTERVAL: &str = "refresh_interval_secs";
const KEY_BALANCE_THRESHOLD: &str = "balance_alert_threshold";
const KEY_DRIFT_ON_START: &str = "drift_check_on_start";
const KEY_GATEWAY_ENABLED: &str = "gateway_enabled";
const KEY_GATEWAY_PORT: &str = "gateway_port";
const KEY_THEME: &str = "theme";
const KEY_LANGUAGE: &str = "language";
const KEY_PROXY_URL: &str = "proxy_url";
const KEY_PROXY_MODE: &str = "proxy_mode";
const KEY_TELEMETRY: &str = "telemetry_enabled";
const KEY_AUTO_UPDATE: &str = "auto_update_enabled";
const KEY_NOTIFY_SYSTEM: &str = "notify_system_enabled";
const KEY_NOTIFY_WEBHOOK: &str = "notify_webhook_url";
const KEY_NOTIFY_TIMEOUT: &str = "notify_timeout_secs";
const KEY_ROTATION_MAX_AGE: &str = "rotation_max_age_days";
const KEY_ROTATION_WARN: &str = "rotation_warn_before_days";
const KEY_AUTOSTART: &str = "autostart_enabled";
const KEY_CLOSE_TO_TRAY: &str = "close_to_tray";
const KEY_START_HIDDEN: &str = "start_hidden";

#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    /// 自动刷新间隔（秒）。`0` = 关闭。
    pub refresh_interval_secs: u64,
    /// 余额低于该值时告警（USD）。`0` = 不告警。
    pub balance_alert_threshold: f64,
    /// 是否在启动时跑一次漂移检测（只读本地文件）。
    pub drift_check_on_start: bool,
    /// 本地网关开关。默认关闭。
    pub gateway_enabled: bool,
    /// 网关端口。只绑 `127.0.0.1`。
    pub gateway_port: u16,

    // ---- M6-S5：FR-9 界面与隐私 ----
    /// 主题：`system` / `light` / `dark`。
    pub theme: String,
    /// 界面语言：`zh-CN` / `en-US`。
    pub language: String,
    /// HTTP/SOCKS5 代理。空 = 直连（manual 模式下）；auto 模式下仅作手填兜底被忽略。
    ///
    /// **注意**：本模块不校验代理串的合法性（那会引入对 `site::transport` 的依赖）。
    /// 非法代理串在真正构造传输层时报错——见 spec §2.2 第 4 条。
    pub proxy_url: String,
    /// 代理模式（M10-S2）：`auto` / `manual` / `direct`。默认 `auto`。
    ///
    /// 字符串而非 `ProxyMode` 枚举：与 `theme`/`language` 同形态，KV 往返简单，
    /// 解析在 `proxy::ProxyMode::parse`（校验集中在一处）。未知值退回 `auto`。
    pub proxy_mode: String,
    /// 匿名遥测开关。**默认关**（PRD §5「默认零遥测」）。
    pub telemetry_enabled: bool,
    /// 自动更新开关。默认关。
    pub auto_update_enabled: bool,

    // ---- M6-S5：FR-3 通知 ----
    /// 系统通知开关。默认开（PRD FR-3「系统通知（默认）」）。
    pub notify_system_enabled: bool,
    /// Webhook 地址。空 = 不启用。
    pub notify_webhook_url: String,
    /// Webhook 超时（秒）。
    pub notify_timeout_secs: u64,

    // ---- M6-S5：FR-7 密钥轮换 ----
    /// 轮换周期（天）。`0` = 关闭轮换提醒。
    pub rotation_max_age_days: u32,
    /// 到期前多少天开始提醒。
    pub rotation_warn_before_days: u32,

    // ---- M6-S5：FR-7 常驻与自启 ----
    /// 登录自启。默认关：不替用户决定。
    pub autostart_enabled: bool,
    /// 关窗时隐藏到托盘而不是退出。默认开（托盘常驻是 PRD FR-7 的默认形态）。
    pub close_to_tray: bool,
    /// 启动时不显示主窗口（`--hidden` 的设置侧对应项）。
    pub start_hidden: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            // 默认**关闭**定时刷新：不替用户决定要不要定时联网
            refresh_interval_secs: 0,
            balance_alert_threshold: 0.0,
            // 漂移检测只读本地文件，默认开
            drift_check_on_start: true,
            // 网关会监听端口，默认关闭
            gateway_enabled: false,
            gateway_port: 8787,

            theme: "system".to_string(),
            language: "zh-CN".to_string(),
            proxy_url: String::new(),
            // M10-S2：默认 auto——听系统已有的代理，不让用户填第二遍。
            proxy_mode: "auto".to_string(),
            // PRD §5：默认零遥测
            telemetry_enabled: false,
            auto_update_enabled: false,

            // PRD FR-3：系统通知是默认渠道
            notify_system_enabled: true,
            notify_webhook_url: String::new(),
            notify_timeout_secs: 10,

            rotation_max_age_days: 30,
            rotation_warn_before_days: 7,

            // 不替用户决定登录自启
            autostart_enabled: false,
            close_to_tray: true,
            start_hidden: false,
        }
    }
}

impl Settings {
    pub fn validate(&self) -> Result<()> {
        if self.refresh_interval_secs > MAX_REFRESH_INTERVAL_SECS {
            return Err(Error::Store(format!(
                "刷新间隔不能超过 {MAX_REFRESH_INTERVAL_SECS} 秒（24 小时）"
            )));
        }
        if !self.balance_alert_threshold.is_finite() || self.balance_alert_threshold < 0.0 {
            return Err(Error::Store("余额告警阈值必须是非负有限数".to_string()));
        }
        // 1024 以下是特权端口，普通用户绑不上；0 也不是合法端口
        if self.gateway_port < 1024 {
            return Err(Error::Store(
                "网关端口必须在 1024..=65535 之间（1024 以下需要管理员权限）".to_string(),
            ));
        }
        if !THEMES.contains(&self.theme.as_str()) {
            return Err(Error::Store(format!(
                "未知主题「{}」（可选：{}）",
                self.theme,
                THEMES.join(" / ")
            )));
        }
        if !LANGUAGES.contains(&self.language.as_str()) {
            return Err(Error::Store(format!(
                "未知语言「{}」（可选：{}）",
                self.language,
                LANGUAGES.join(" / ")
            )));
        }
        // M10-S2：proxy_mode 必须是合法值之一。from_pairs 已过滤，但保存路径要走 validate。
        if crate::proxy::ProxyMode::parse(&self.proxy_mode).is_none() {
            return Err(Error::Store(format!(
                "未知代理模式「{}」（可选：auto / manual / direct）",
                self.proxy_mode
            )));
        }
        if self.notify_timeout_secs > MAX_NOTIFY_TIMEOUT_SECS {
            return Err(Error::Store(format!(
                "Webhook 超时不能超过 {MAX_NOTIFY_TIMEOUT_SECS} 秒"
            )));
        }
        // `0` 不是「不超时」，而是一个**竞态**：M6-S3 实测同一个二进制里
        // `Ok(())`（547µs）与 `Err(超时)`（4.9ms）都出现过——取决于请求发出去之后
        // 还有没有剩余时间片。用户设 0 会得到「时灵时不灵」的 webhook，而现象完全无法归因。
        // 这里直接拒绝，让它变成一个明确的输入错误。
        if self.notify_timeout_secs == 0 {
            return Err(Error::Store(
                "Webhook 超时至少 1 秒（0 会让请求时成时败，没有可用的语义）".to_string(),
            ));
        }
        if self.rotation_max_age_days > MAX_ROTATION_AGE_DAYS {
            return Err(Error::Store(format!(
                "轮换周期不能超过 {MAX_ROTATION_AGE_DAYS} 天"
            )));
        }
        // 只有「轮换开着」时才谈得上提醒窗口。`max_age_days == 0` 表示关闭轮换，
        // 此时 `warn_before_days` 是多少都无所谓——不让一个不生效的字段把保存卡死。
        if self.rotation_max_age_days > 0
            && self.rotation_warn_before_days > self.rotation_max_age_days
        {
            return Err(Error::Store(format!(
                "提前提醒天数（{}）不能大于轮换周期（{}）",
                self.rotation_warn_before_days, self.rotation_max_age_days
            )));
        }
        Ok(())
    }

    /// 是否真的需要起后台刷新任务。
    pub fn scheduler_enabled(&self) -> bool {
        self.refresh_interval_secs > 0
    }

    /// 轮换提醒是否启用。
    pub fn rotation_enabled(&self) -> bool {
        self.rotation_max_age_days > 0
    }

    /// Webhook 是否配置了地址。
    pub fn webhook_enabled(&self) -> bool {
        !self.notify_webhook_url.trim().is_empty()
    }

    /// 诊断包里的设置快照（PRD FR-9:196「脱敏后的配置快照」）。
    ///
    /// **白名单，不是黑名单**：只列明确无秘密的字段。`proxy_url` 与 `notify_webhook_url`
    /// **只回报「配没配」**——它们的值可能带 userinfo 或 `?token=…`，而本模块没有脱敏能力
    /// （那是 `redact` 的职责）。
    ///
    /// 为什么在这里**不**顺手写一段掩码：M5-S1 已经踩过一次「两条出口各抄一段组合、
    /// 结果悄悄分叉」（见 `service.rs::export_diagnostics` 的注释），所以宁可少给一个字段，
    /// 也不在这里长出一条平行的脱敏路径。诊断包是**要发给别人**的东西，少一个字段的代价
    /// 远小于多一条会分叉的掩码逻辑。
    pub fn diagnostic_snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "refresh_interval_secs": self.refresh_interval_secs,
            "balance_alert_threshold": self.balance_alert_threshold,
            "drift_check_on_start": self.drift_check_on_start,
            "gateway_enabled": self.gateway_enabled,
            "gateway_port": self.gateway_port,
            "theme": self.theme,
            "language": self.language,
            "telemetry_enabled": self.telemetry_enabled,
            "auto_update_enabled": self.auto_update_enabled,
            "notify_system_enabled": self.notify_system_enabled,
            "notify_timeout_secs": self.notify_timeout_secs,
            "rotation_max_age_days": self.rotation_max_age_days,
            "rotation_warn_before_days": self.rotation_warn_before_days,
            "autostart_enabled": self.autostart_enabled,
            "close_to_tray": self.close_to_tray,
            "start_hidden": self.start_hidden,
            // 只回报「配没配」，不回报值：
            "proxy_configured": !self.proxy_url.trim().is_empty(),
            "proxy_mode": self.proxy_mode,
            "webhook_configured": self.webhook_enabled(),
        })
    }

    /// 关窗时该隐藏到托盘吗？
    ///
    /// # 为什么需要 `tray_available`
    ///
    /// 直接返回 `close_to_tray` 是个恒等式，没有信息量。真正的规则是：
    /// **托盘不可用时一律不隐藏**。没有菜单栏图标的话，隐藏窗口等于把应用变成
    /// 用户碰不到的后台进程——窗口没了，也没有任何入口能把它调回来，
    /// 只能去活动监视器里杀进程。
    ///
    /// 托盘创建失败在无 GUI 会话（CI、SSH、headless）下是**正常**结果，
    /// 所以这不是假想分支。
    ///
    /// 抽成纯函数的另一个理由：真正的关窗回调只在 GUI 会话里跑得起来（本机没有），
    /// 但这条规则本身应当被单测钉住。
    pub fn should_hide_on_close(&self, tray_available: bool) -> bool {
        self.close_to_tray && tray_available
    }

    /// 启动时是否隐藏主窗口。
    ///
    /// `hidden_flag` 是命令行的 `--hidden`。它与设置项 `start_hidden` 是**或**的关系：
    /// 任一路径要求隐藏就隐藏。同样受 `tray_available` 约束，理由见
    /// [`Self::should_hide_on_close`]——启动即隐藏而托盘又没建起来，用户会以为
    /// 应用根本没启动。
    pub fn should_start_hidden(&self, hidden_flag: bool, tray_available: bool) -> bool {
        (hidden_flag || self.start_hidden) && tray_available
    }

    /// 从键值对还原；缺失或非法的项**各自**退回默认值，不影响其它项。
    pub fn from_pairs<'a, I>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut settings = Self::default();
        let mut proxy_mode_seen = false;
        for (key, value) in pairs {
            match key {
                KEY_REFRESH_INTERVAL => {
                    if let Ok(secs) = value.parse::<u64>() {
                        if secs <= MAX_REFRESH_INTERVAL_SECS {
                            settings.refresh_interval_secs = secs;
                        }
                    }
                }
                KEY_BALANCE_THRESHOLD => {
                    if let Ok(threshold) = value.parse::<f64>() {
                        if threshold.is_finite() && threshold >= 0.0 {
                            settings.balance_alert_threshold = threshold;
                        }
                    }
                }
                KEY_DRIFT_ON_START => {
                    if let Some(flag) = parse_bool(value) {
                        settings.drift_check_on_start = flag;
                    }
                }
                KEY_GATEWAY_ENABLED => {
                    if let Some(flag) = parse_bool(value) {
                        settings.gateway_enabled = flag;
                    }
                }
                KEY_GATEWAY_PORT => {
                    if let Ok(port) = value.parse::<u16>() {
                        if port >= 1024 {
                            settings.gateway_port = port;
                        }
                    }
                }
                KEY_THEME => {
                    if THEMES.contains(&value) {
                        settings.theme = value.to_string();
                    }
                }
                KEY_LANGUAGE => {
                    if LANGUAGES.contains(&value) {
                        settings.language = value.to_string();
                    }
                }
                // 代理串**原样收下**：合法性由传输层判定（spec §2.2 第 4 条）。
                // 这里做长度上限，避免一个病态的巨型串被反复搬来搬去。
                KEY_PROXY_URL => {
                    if value.len() <= MAX_PROXY_URL_LEN {
                        settings.proxy_url = value.to_string();
                    }
                }
                KEY_PROXY_MODE => {
                    // 未知值不收，保留默认 auto。合法值见 `ProxyMode::as_str`。
                    if crate::proxy::ProxyMode::parse(value).is_some() {
                        settings.proxy_mode = value.trim().to_ascii_lowercase();
                        proxy_mode_seen = true;
                    }
                }
                KEY_TELEMETRY => {
                    if let Some(flag) = parse_bool(value) {
                        settings.telemetry_enabled = flag;
                    }
                }
                KEY_AUTO_UPDATE => {
                    if let Some(flag) = parse_bool(value) {
                        settings.auto_update_enabled = flag;
                    }
                }
                KEY_NOTIFY_SYSTEM => {
                    if let Some(flag) = parse_bool(value) {
                        settings.notify_system_enabled = flag;
                    }
                }
                KEY_NOTIFY_WEBHOOK => {
                    if value.len() <= MAX_WEBHOOK_URL_LEN {
                        settings.notify_webhook_url = value.to_string();
                    }
                }
                KEY_NOTIFY_TIMEOUT => {
                    if let Ok(secs) = value.parse::<u64>() {
                        // 下界也是 1：`0` 是竞态（见 `validate`），读到一个历史遗留的 0
                        // 必须退回默认值，而不是让应用带着一个「时灵时不灵」的超时跑起来。
                        if (1..=MAX_NOTIFY_TIMEOUT_SECS).contains(&secs) {
                            settings.notify_timeout_secs = secs;
                        }
                    }
                }
                KEY_ROTATION_MAX_AGE => {
                    if let Ok(days) = value.parse::<u32>() {
                        if days <= MAX_ROTATION_AGE_DAYS {
                            settings.rotation_max_age_days = days;
                        }
                    }
                }
                KEY_ROTATION_WARN => {
                    if let Ok(days) = value.parse::<u32>() {
                        if days <= MAX_ROTATION_AGE_DAYS {
                            settings.rotation_warn_before_days = days;
                        }
                    }
                }
                KEY_AUTOSTART => {
                    if let Some(flag) = parse_bool(value) {
                        settings.autostart_enabled = flag;
                    }
                }
                KEY_CLOSE_TO_TRAY => {
                    if let Some(flag) = parse_bool(value) {
                        settings.close_to_tray = flag;
                    }
                }
                KEY_START_HIDDEN => {
                    if let Some(flag) = parse_bool(value) {
                        settings.start_hidden = flag;
                    }
                }
                _ => {}
            }
        }
        // 升级迁移（M10-S2）：旧库没有 `proxy_mode` 键。若用户之前手填了 `proxy_url`
        // （非空），保留其手填语义 ⇒ manual；否则用默认 auto（听系统）。
        // 不做这条的话，升级后所有手填过代理的用户会突然变成 auto，代理被忽略。
        if !proxy_mode_seen && !settings.proxy_url.trim().is_empty() {
            settings.proxy_mode = "manual".to_string();
        }
        settings
    }

    /// 序列化成待落库的键值对。
    pub fn to_pairs(&self) -> Vec<(&'static str, String)> {
        vec![
            (KEY_REFRESH_INTERVAL, self.refresh_interval_secs.to_string()),
            (
                KEY_BALANCE_THRESHOLD,
                format!("{}", self.balance_alert_threshold),
            ),
            (KEY_DRIFT_ON_START, self.drift_check_on_start.to_string()),
            (KEY_GATEWAY_ENABLED, self.gateway_enabled.to_string()),
            (KEY_GATEWAY_PORT, self.gateway_port.to_string()),
            (KEY_THEME, self.theme.clone()),
            (KEY_LANGUAGE, self.language.clone()),
            (KEY_PROXY_URL, self.proxy_url.clone()),
            (KEY_PROXY_MODE, self.proxy_mode.clone()),
            (KEY_TELEMETRY, self.telemetry_enabled.to_string()),
            (KEY_AUTO_UPDATE, self.auto_update_enabled.to_string()),
            (KEY_NOTIFY_SYSTEM, self.notify_system_enabled.to_string()),
            (KEY_NOTIFY_WEBHOOK, self.notify_webhook_url.clone()),
            (KEY_NOTIFY_TIMEOUT, self.notify_timeout_secs.to_string()),
            (KEY_ROTATION_MAX_AGE, self.rotation_max_age_days.to_string()),
            (
                KEY_ROTATION_WARN,
                self.rotation_warn_before_days.to_string(),
            ),
            (KEY_AUTOSTART, self.autostart_enabled.to_string()),
            (KEY_CLOSE_TO_TRAY, self.close_to_tray.to_string()),
            (KEY_START_HIDDEN, self.start_hidden.to_string()),
        ]
    }

    /// 从存储层一次性读全部键，缺失键退回默认值（走 `from_pairs` 的迁移与容错）。
    ///
    /// 与 `KeyRelayService::settings` 同一份逻辑；抽到本模块是为了让壳层（`src-tauri`）
    /// 在构造 service 之前就能读 settings 解析代理（M10-S2：`build_transport` 要用）。
    pub fn load_from_store(store: &crate::store::Store) -> Result<Self> {
        let mut pairs: Vec<(String, String)> = Vec::new();
        for key in Self::KEYS {
            if let Some(value) = store.get_setting(key)? {
                pairs.push((key.to_string(), value));
            }
        }
        let borrowed: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        Ok(Self::from_pairs(borrowed))
    }

    pub const KEYS: [&'static str; 19] = [
        KEY_REFRESH_INTERVAL,
        KEY_BALANCE_THRESHOLD,
        KEY_DRIFT_ON_START,
        KEY_GATEWAY_ENABLED,
        KEY_GATEWAY_PORT,
        KEY_THEME,
        KEY_LANGUAGE,
        KEY_PROXY_URL,
        KEY_PROXY_MODE,
        KEY_TELEMETRY,
        KEY_AUTO_UPDATE,
        KEY_NOTIFY_SYSTEM,
        KEY_NOTIFY_WEBHOOK,
        KEY_NOTIFY_TIMEOUT,
        KEY_ROTATION_MAX_AGE,
        KEY_ROTATION_WARN,
        KEY_AUTOSTART,
        KEY_CLOSE_TO_TRAY,
        KEY_START_HIDDEN,
    ];
}

/// 代理串长度上限。真实代理串只有几十字节，超过这个长度一定是别的东西。
pub const MAX_PROXY_URL_LEN: usize = 2048;
/// Webhook 地址长度上限。
pub const MAX_WEBHOOK_URL_LEN: usize = 2048;

/// 宽松解析布尔值：大小写不敏感，并接受 `1` / `0`。
///
/// 为什么不用 `str::parse::<bool>()`（复审 P2-9）：它只认小写 `true` / `false`。
/// 用户手工把库里的值改成 `"False"` 时，解析失败会**静默退回默认值**，
/// 而 `drift_check_on_start` 的默认是 `true` —— 结果与用户写的正好相反。
fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_conservative() {
        let s = Settings::default();
        assert_eq!(s.refresh_interval_secs, 0, "定时刷新必须默认关闭");
        assert!(!s.scheduler_enabled());
        assert_eq!(s.balance_alert_threshold, 0.0);
        assert!(s.drift_check_on_start, "漂移检测只读本地，默认开");
        assert!(!s.gateway_enabled, "网关会监听端口，必须默认关闭");
        assert_eq!(s.gateway_port, 8787);
        assert!(s.validate().is_ok());
    }

    #[test]
    fn m6_defaults_match_the_spec_table() {
        let s = Settings::default();
        assert_eq!(s.theme, "system");
        assert_eq!(s.language, "zh-CN");
        assert!(s.proxy_url.is_empty(), "默认直连");
        assert!(!s.telemetry_enabled, "PRD §5：默认零遥测");
        assert!(!s.auto_update_enabled, "自动更新默认关");
        assert!(s.notify_system_enabled, "PRD FR-3：系统通知是默认渠道");
        assert!(!s.webhook_enabled(), "没填地址就不启用 Webhook");
        assert_eq!(s.notify_timeout_secs, 10);
        assert_eq!(s.rotation_max_age_days, 30);
        assert_eq!(s.rotation_warn_before_days, 7);
        assert!(s.rotation_enabled());
        assert!(!s.autostart_enabled, "不替用户决定登录自启");
        assert!(s.close_to_tray, "托盘常驻是默认形态");
        assert!(!s.start_hidden, "默认要显示窗口");
        assert!(!s.should_start_hidden(false, true));
    }

    #[test]
    fn hiding_requires_a_working_tray() {
        // 这条规则是本模块里唯一不平凡的判定：托盘没建起来时隐藏窗口 =
        // 应用变成用户碰不到的后台进程（没窗口、没菜单栏图标、没入口调回来）。
        let hide_on_close = Settings {
            close_to_tray: true,
            ..Settings::default()
        };
        assert!(hide_on_close.should_hide_on_close(true), "有托盘才隐藏");
        assert!(
            !hide_on_close.should_hide_on_close(false),
            "没有托盘时必须放行关闭，否则窗口关掉就再也打不开了"
        );

        let keep_open = Settings {
            close_to_tray: false,
            ..Settings::default()
        };
        assert!(!keep_open.should_hide_on_close(true), "用户关掉了常驻");
        assert!(!keep_open.should_hide_on_close(false));

        // 启动隐藏：命令行 flag 与设置项是「或」，但都受托盘约束
        let s = Settings {
            start_hidden: false,
            ..Settings::default()
        };
        assert!(!s.should_start_hidden(false, true));
        assert!(s.should_start_hidden(true, true), "--hidden 生效");
        assert!(
            !s.should_start_hidden(true, false),
            "没有托盘时 --hidden 必须降级，否则用户以为应用没启动"
        );

        let by_setting = Settings {
            start_hidden: true,
            ..Settings::default()
        };
        assert!(by_setting.should_start_hidden(false, true), "设置项生效");
        assert!(!by_setting.should_start_hidden(false, false));
        assert!(by_setting.should_start_hidden(true, true));
    }

    #[test]
    fn validate_rejects_bad_values() {
        let bad_interval = Settings {
            refresh_interval_secs: MAX_REFRESH_INTERVAL_SECS + 1,
            ..Settings::default()
        };
        assert!(matches!(bad_interval.validate(), Err(Error::Store(_))));

        for threshold in [-1.0, f64::NAN, f64::INFINITY] {
            let bad = Settings {
                balance_alert_threshold: threshold,
                ..Settings::default()
            };
            assert!(
                matches!(bad.validate(), Err(Error::Store(_))),
                "{threshold} 应被拒绝"
            );
        }

        // 上限本身是合法的
        let at_limit = Settings {
            refresh_interval_secs: MAX_REFRESH_INTERVAL_SECS,
            ..Settings::default()
        };
        assert!(at_limit.validate().is_ok());

        // 特权端口被拒
        for port in [0u16, 80, 1023] {
            let bad = Settings {
                gateway_port: port,
                ..Settings::default()
            };
            assert!(bad.validate().is_err(), "端口 {port} 应被拒绝");
        }
        let ok_port = Settings {
            gateway_port: 1024,
            ..Settings::default()
        };
        assert!(ok_port.validate().is_ok());
    }

    #[test]
    fn validate_rejects_unknown_theme_and_language() {
        let bad_theme = Settings {
            theme: "neon".to_string(),
            ..Settings::default()
        };
        let err = bad_theme.validate().unwrap_err().to_string();
        assert!(err.contains("主题"), "{err}");
        assert!(err.contains("neon"), "{err}");

        let bad_lang = Settings {
            language: "fr-FR".to_string(),
            ..Settings::default()
        };
        let err = bad_lang.validate().unwrap_err().to_string();
        assert!(err.contains("语言"), "{err}");

        for theme in THEMES {
            let ok = Settings {
                theme: theme.to_string(),
                ..Settings::default()
            };
            assert!(ok.validate().is_ok(), "{theme} 应被接受");
        }
        for lang in LANGUAGES {
            let ok = Settings {
                language: lang.to_string(),
                ..Settings::default()
            };
            assert!(ok.validate().is_ok(), "{lang} 应被接受");
        }
    }

    #[test]
    fn validate_bounds_notify_timeout() {
        let at_limit = Settings {
            notify_timeout_secs: MAX_NOTIFY_TIMEOUT_SECS,
            ..Settings::default()
        };
        assert!(at_limit.validate().is_ok());

        let over = Settings {
            notify_timeout_secs: MAX_NOTIFY_TIMEOUT_SECS + 1,
            ..Settings::default()
        };
        let err = over.validate().unwrap_err().to_string();
        assert!(err.contains("超时"), "{err}");
    }

    #[test]
    fn zero_notify_timeout_is_rejected_as_a_race_not_treated_as_unlimited() {
        // M6-S3 实测：`timeout = 0` 时同一个二进制里 `Ok(())`（547µs）与
        // `Err(超时)`（4.9ms）都出现过。它不是「不超时」，是一个竞态——
        // 必须变成明确的输入错误，而不是让用户面对「时灵时不灵」的 webhook。
        let zero = Settings {
            notify_timeout_secs: 0,
            ..Settings::default()
        };
        let err = zero.validate().unwrap_err().to_string();
        assert!(err.contains("至少 1 秒"), "{err}");

        // 1 秒是允许的（下界）
        let one = Settings {
            notify_timeout_secs: 1,
            ..Settings::default()
        };
        assert!(one.validate().is_ok());
    }

    #[test]
    fn validate_rejects_warn_window_wider_than_the_rotation_period() {
        let bad = Settings {
            rotation_max_age_days: 30,
            rotation_warn_before_days: 31,
            ..Settings::default()
        };
        let err = bad.validate().unwrap_err().to_string();
        assert!(err.contains("提前提醒"), "{err}");

        // 恰好相等是允许的：整段周期都在提醒窗口里
        let equal = Settings {
            rotation_max_age_days: 30,
            rotation_warn_before_days: 30,
            ..Settings::default()
        };
        assert!(equal.validate().is_ok());
    }

    #[test]
    fn rotation_disabled_makes_the_warn_window_irrelevant() {
        // `max_age_days == 0` = 关闭轮换。此时 `warn_before_days` 不生效，
        // 不该让一个不生效的字段把保存卡死。
        let s = Settings {
            rotation_max_age_days: 0,
            rotation_warn_before_days: 365,
            ..Settings::default()
        };
        assert!(s.validate().is_ok(), "关闭轮换时提醒窗口不参与校验");
        assert!(!s.rotation_enabled());
    }

    #[test]
    fn a_stored_zero_timeout_falls_back_instead_of_loading_a_race() {
        // 老库里可能已经存了 0（那时还没有这条校验）。读回来必须退默认，
        // 而不是让应用带着竞态超时跑起来——`validate` 管不到读路径。
        let s = Settings::from_pairs(vec![(KEY_NOTIFY_TIMEOUT, "0")]);
        assert_eq!(s.notify_timeout_secs, 10, "历史遗留的 0 应退回默认");
        assert!(s.validate().is_ok());

        let s = Settings::from_pairs(vec![(KEY_NOTIFY_TIMEOUT, "1")]);
        assert_eq!(s.notify_timeout_secs, 1, "1 是合法下界");
    }

    #[test]
    fn pairs_round_trip() {
        let s = Settings {
            refresh_interval_secs: 900,
            balance_alert_threshold: 3.5,
            drift_check_on_start: false,
            gateway_enabled: true,
            gateway_port: 9999,
            theme: "dark".to_string(),
            language: "en-US".to_string(),
            proxy_url: "socks5://127.0.0.1:1080".to_string(),
            proxy_mode: "manual".to_string(),
            telemetry_enabled: true,
            auto_update_enabled: true,
            notify_system_enabled: false,
            notify_webhook_url: "https://hooks.example.com/kr".to_string(),
            notify_timeout_secs: 25,
            rotation_max_age_days: 45,
            rotation_warn_before_days: 10,
            autostart_enabled: true,
            close_to_tray: false,
            start_hidden: true,
        };
        let pairs = s.to_pairs();
        let borrowed: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(Settings::from_pairs(borrowed), s);
        // 每一个字段都要有对应的键，漏一个就会在往返里静默丢失
        assert_eq!(pairs.len(), Settings::KEYS.len());
    }

    #[test]
    fn every_key_is_emitted_and_consumed() {
        // 反例保护：`KEYS` 里的每一项都必须出现在 `to_pairs()` 的输出里。
        // 新增字段时忘了加进 `to_pairs` 是很容易犯的错，而后果是**静默不落库**。
        let emitted: Vec<&str> = Settings::default()
            .to_pairs()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        for key in Settings::KEYS {
            assert!(emitted.contains(&key), "`{key}` 没有出现在 to_pairs() 里");
        }
        // 反向：to_pairs 不得吐出 KEYS 之外的键（否则 from_pairs 会当未知键丢掉）
        for key in emitted {
            assert!(Settings::KEYS.contains(&key), "`{key}` 不在 KEYS 里");
        }
    }

    #[test]
    fn missing_or_invalid_values_fall_back_per_key() {
        // 完全空 → 全默认
        assert_eq!(
            Settings::from_pairs(std::iter::empty()),
            Settings::default()
        );

        // 只有一项非法 → 该项默认，其余保留
        let s = Settings::from_pairs(vec![
            (KEY_REFRESH_INTERVAL, "not-a-number"),
            (KEY_BALANCE_THRESHOLD, "2.5"),
        ]);
        assert_eq!(s.refresh_interval_secs, 0);
        assert_eq!(s.balance_alert_threshold, 2.5);

        // 超出上限的间隔也回退
        let s = Settings::from_pairs(vec![(KEY_REFRESH_INTERVAL, "99999999")]);
        assert_eq!(s.refresh_interval_secs, 0);

        // 负数阈值回退
        let s = Settings::from_pairs(vec![(KEY_BALANCE_THRESHOLD, "-3")]);
        assert_eq!(s.balance_alert_threshold, 0.0);

        // 未知键忽略
        let s = Settings::from_pairs(vec![("unknown", "1")]);
        assert_eq!(s, Settings::default());
    }

    #[test]
    fn m6_invalid_values_fall_back_per_key_without_touching_neighbours() {
        let s = Settings::from_pairs(vec![
            (KEY_THEME, "neon"),
            (KEY_LANGUAGE, "fr-FR"),
            (KEY_NOTIFY_TIMEOUT, "9999"),
            (KEY_ROTATION_MAX_AGE, "999999"),
            // 邻居：合法值必须活下来
            (KEY_PROXY_URL, "http://127.0.0.1:8080"),
            (KEY_ROTATION_WARN, "3"),
        ]);
        assert_eq!(s.theme, "system", "未知主题退回默认");
        assert_eq!(s.language, "zh-CN", "未知语言退回默认");
        assert_eq!(s.notify_timeout_secs, 10, "超上限的超时退回默认");
        assert_eq!(s.rotation_max_age_days, 30, "超上限的周期退回默认");
        assert_eq!(s.proxy_url, "http://127.0.0.1:8080", "邻居不受影响");
        assert_eq!(s.rotation_warn_before_days, 3, "邻居不受影响");
    }

    #[test]
    fn oversized_urls_are_dropped_not_truncated() {
        // 截断一个 URL 会产生一个「看起来合法但指向别处」的值，比直接丢弃更危险。
        let huge = "h".repeat(MAX_PROXY_URL_LEN + 1);
        let s = Settings::from_pairs(vec![(KEY_PROXY_URL, huge.as_str())]);
        assert!(s.proxy_url.is_empty(), "超长代理串应被丢弃而不是截断");

        let huge_hook = "h".repeat(MAX_WEBHOOK_URL_LEN + 1);
        let s = Settings::from_pairs(vec![(KEY_NOTIFY_WEBHOOK, huge_hook.as_str())]);
        assert!(s.notify_webhook_url.is_empty());
        assert!(!s.webhook_enabled());

        // 恰好等于上限是允许的
        let at_limit = "h".repeat(MAX_PROXY_URL_LEN);
        let s = Settings::from_pairs(vec![(KEY_PROXY_URL, at_limit.as_str())]);
        assert_eq!(s.proxy_url.len(), MAX_PROXY_URL_LEN);
    }

    #[test]
    fn booleans_are_parsed_case_insensitively() {
        // 复审 P2-9：`"False"` 以前解析失败 → 静默退回默认 `true`，与用户写的**正好相反**
        for text in ["false", "False", "FALSE", " false ", "0", "no", "off"] {
            let s = Settings::from_pairs(vec![
                (KEY_DRIFT_ON_START, text),
                (KEY_GATEWAY_ENABLED, text),
            ]);
            assert!(!s.drift_check_on_start, "「{text}」应解析成 false");
            assert!(!s.gateway_enabled, "「{text}」应解析成 false");
        }

        for text in ["true", "True", "TRUE", " true ", "1", "yes", "on"] {
            let s = Settings::from_pairs(vec![
                (KEY_DRIFT_ON_START, text),
                (KEY_GATEWAY_ENABLED, text),
            ]);
            assert!(s.drift_check_on_start, "「{text}」应解析成 true");
            assert!(s.gateway_enabled, "「{text}」应解析成 true");
        }
    }

    #[test]
    fn m6_booleans_are_parsed_case_insensitively_too() {
        // 新字段走同一套解析；默认值不一致的字段要单独钉：
        // `notify_system_enabled` / `close_to_tray` 默认 true，其余默认 false。
        let falsy = Settings::from_pairs(vec![
            (KEY_NOTIFY_SYSTEM, "OFF"),
            (KEY_CLOSE_TO_TRAY, "off"),
            (KEY_TELEMETRY, "Off"),
            (KEY_AUTOSTART, "OFF"),
            (KEY_START_HIDDEN, "OFF"),
            (KEY_AUTO_UPDATE, "OFF"),
        ]);
        assert!(!falsy.notify_system_enabled);
        assert!(!falsy.close_to_tray);
        assert!(!falsy.should_hide_on_close(true));
        assert!(!falsy.telemetry_enabled);
        assert!(!falsy.autostart_enabled);
        assert!(!falsy.start_hidden);
        assert!(!falsy.auto_update_enabled);

        let truthy = Settings::from_pairs(vec![
            (KEY_NOTIFY_SYSTEM, "On"),
            (KEY_CLOSE_TO_TRAY, "On"),
            (KEY_TELEMETRY, "On"),
            (KEY_AUTOSTART, "On"),
            (KEY_START_HIDDEN, "On"),
            (KEY_AUTO_UPDATE, "On"),
        ]);
        assert!(truthy.notify_system_enabled);
        assert!(truthy.close_to_tray);
        assert!(truthy.should_hide_on_close(true));
        assert!(truthy.telemetry_enabled);
        assert!(truthy.autostart_enabled);
        assert!(truthy.start_hidden);
        assert!(truthy.auto_update_enabled);
    }

    #[test]
    fn an_unparseable_boolean_falls_back_to_the_default_not_to_the_opposite() {
        // 认不出来的值仍然退回默认（`drift_check_on_start` 默认 true）——
        // 但至少「认不出来的值」不会伪装成用户显式写下的相反值
        let s = Settings::from_pairs(vec![(KEY_DRIFT_ON_START, "maybe")]);
        assert_eq!(s, Settings::default());
    }

    #[test]
    fn false_survives_a_round_trip() {
        // 端到端：写进库的 `false` 读回来必须还是 `false`
        let wanted = Settings {
            drift_check_on_start: false,
            gateway_enabled: false,
            ..Settings::default()
        };
        let pairs = wanted.to_pairs();
        let borrowed: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(Settings::from_pairs(borrowed), wanted);
    }
}
