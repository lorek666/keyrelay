//! M3：key 级 429 冷却与 Retry-After 解析。
//!
//! 与站点/模型熔断分开：一把 key 被限流不应让同站其他 key 一起停摆。
//! 没有合法 Retry-After 时不发明冷却时长，继续沿用现有熔断语义。
//! 冷却只把候选排到队尾，不硬删除；所有候选都在冷却时仍按原顺序尝试。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

pub const MAX_RETRY_AFTER_SECS: u64 = 3600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cooldown {
    pub until: Instant,
    pub source: &'static str,
}

#[derive(Default)]
pub struct KeyCooldownTable {
    entries: Mutex<HashMap<(i64, Option<i64>), Cooldown>>,
}

impl std::fmt::Debug for KeyCooldownTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyCooldownTable")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl KeyCooldownTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// 只接受 1..=3600 秒的 `Retry-After`。0 表示可立即重试，不建立冷却。
    pub fn record_retry_after(
        &self,
        site_id: i64,
        key_id: Option<i64>,
        value: Option<&str>,
        now: Instant,
    ) -> Option<Cooldown> {
        let key_id = key_id?;
        let duration = parse_retry_after(value?, SystemTime::now())?;
        let until = now.checked_add(duration)?;
        let entry = Cooldown {
            until,
            source: "retry_after",
        };
        let Ok(mut entries) = self.entries.lock() else {
            return None;
        };
        entries.retain(|_, cooldown| cooldown.until > now);
        entries.insert((site_id, Some(key_id)), entry);
        Some(entry)
    }

    pub fn is_cooling(&self, site_id: i64, key_id: Option<i64>, now: Instant) -> bool {
        let Some(key_id) = key_id else {
            return false;
        };
        self.entries
            .lock()
            .ok()
            .and_then(|entries| entries.get(&(site_id, Some(key_id))).copied())
            .is_some_and(|cooldown| cooldown.until > now)
    }

    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .map(|entries| entries.len())
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
    }
}

/// 解析 Retry-After：delta-seconds 或 HTTP-date。过去的日期 / 非法值 / 0 都返回 None。
pub fn parse_retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(seconds) = value.parse::<u64>() {
        if seconds == 0 || seconds > MAX_RETRY_AFTER_SECS {
            return None;
        }
        return Some(Duration::from_secs(seconds));
    }
    let at = httpdate::parse_http_date(value).ok()?;
    let duration = at.duration_since(now).ok()?;
    if duration.is_zero() || duration > Duration::from_secs(MAX_RETRY_AFTER_SECS) {
        return None;
    }
    Some(duration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_accepts_seconds_and_http_dates_only_in_bounds() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(parse_retry_after("30", now), Some(Duration::from_secs(30)));
        assert_eq!(
            parse_retry_after("Tue, 14 Nov 2023 22:13:50 GMT", now),
            Some(Duration::from_secs(30))
        );
        assert_eq!(parse_retry_after("0", now), None);
        assert_eq!(parse_retry_after("3601", now), None);
        assert_eq!(parse_retry_after("not-a-date", now), None);
        assert_eq!(
            parse_retry_after("Tue, 14 Nov 2023 22:13:00 GMT", now),
            None,
            "past HTTP date must not create a cooldown"
        );
    }

    #[test]
    fn cooldown_is_key_scoped_and_does_not_invent_missing_headers() {
        let table = KeyCooldownTable::new();
        let now = Instant::now();
        assert!(table.record_retry_after(1, Some(10), None, now).is_none());
        assert!(table
            .record_retry_after(1, Some(10), Some("bad"), now)
            .is_none());
        assert!(table.is_empty());
        assert!(table
            .record_retry_after(1, Some(10), Some("30"), now)
            .is_some());
        assert!(table.is_cooling(1, Some(10), now));
        assert!(!table.is_cooling(1, Some(11), now));
        assert!(!table.is_cooling(2, Some(10), now));
        assert!(!table.is_cooling(1, Some(10), now + Duration::from_secs(31)));
        assert!(table
            .record_retry_after(1, Some(10), Some("5"), now)
            .is_some());
        assert!(table.is_cooling(1, Some(10), now + Duration::from_secs(4)));
        table.clear();
        assert!(table.is_empty());
    }

    #[test]
    fn cooldown_is_thread_safe() {
        let table = std::sync::Arc::new(KeyCooldownTable::new());
        let now = Instant::now();
        let threads: Vec<_> = (0..8)
            .map(|worker| {
                let table = std::sync::Arc::clone(&table);
                std::thread::spawn(move || {
                    for key in 0..50 {
                        table.record_retry_after(worker, Some(key), Some("60"), now);
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(table.len(), 8 * 50);
    }
}
