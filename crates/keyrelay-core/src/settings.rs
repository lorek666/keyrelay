//! 运行时设置：刷新间隔、余额阈值、启动时是否跑漂移检测。
//!
//! 存储是 `settings` 键值表；**读不到就用默认值**（老库没有这些键是正常状态，
//! 不该因此报错）。写入前一律 `validate()`。

use crate::error::{Error, Result};

/// 刷新间隔上限：24 小时。再长就没有「定时」的意义了。
pub const MAX_REFRESH_INTERVAL_SECS: u64 = 24 * 60 * 60;

const KEY_REFRESH_INTERVAL: &str = "refresh_interval_secs";
const KEY_BALANCE_THRESHOLD: &str = "balance_alert_threshold";
const KEY_DRIFT_ON_START: &str = "drift_check_on_start";
const KEY_GATEWAY_ENABLED: &str = "gateway_enabled";
const KEY_GATEWAY_PORT: &str = "gateway_port";

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
        Ok(())
    }

    /// 是否真的需要起后台刷新任务。
    pub fn scheduler_enabled(&self) -> bool {
        self.refresh_interval_secs > 0
    }

    /// 从键值对还原；缺失或非法的项**各自**退回默认值，不影响其它项。
    pub fn from_pairs<'a, I>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut settings = Self::default();
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
                _ => {}
            }
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
        ]
    }

    pub const KEYS: [&'static str; 5] = [
        KEY_REFRESH_INTERVAL,
        KEY_BALANCE_THRESHOLD,
        KEY_DRIFT_ON_START,
        KEY_GATEWAY_ENABLED,
        KEY_GATEWAY_PORT,
    ];
}

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
    fn pairs_round_trip() {
        let s = Settings {
            refresh_interval_secs: 900,
            balance_alert_threshold: 3.5,
            drift_check_on_start: false,
            gateway_enabled: true,
            gateway_port: 9999,
        };
        let pairs = s.to_pairs();
        let borrowed: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(Settings::from_pairs(borrowed), s);
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
