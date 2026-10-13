//! 通知基线的跨重启持久化（B-81）。
//!
//! # 现状与目标
//!
//! [`crate::notify::evaluate`] 的**边沿型**规则（用量跳变 / 登录态失效 / 额度耗尽 /
//! 漂移）拿上一轮快照当基线；而 `NotifyState::last` 是**内存态**——进程重启后首轮
//! 用中性基线，处于坏状态的项会各再报一次。
//!
//! 本模块把基线**落库**（`settings` KV 表），让通知更像「边沿」而不是「现状播报」。
//!
//! # 不含密钥（fail-closed，**不静默改写**）
//!
//! [`Snapshot`] 的字段里没有任何密钥（M6-S3 §6.3 的结构性保证：快照类型里
//! **没有**承载上游自由文本的字段，`site_snapshot_field_set_is_pinned` 编译期钉着）。
//! 但 `display_name` / `currency` / `drift[].target_path` / `models[]` /
//! `rotation_due[].name` 仍是**用户可控文本**，可能长得像密钥。
//!
//! 处置是 [`encode_snapshot`] **拒绝编码**（返回 `None`），不是把数据改坏后写库：
//! 后者会让 `Drift` 的去重键（含 `target_path`）在基线与当前快照之间永久失配，
//! 于是那条漂移**每轮都重报**——正是 B-81 要消灭的噪声（M8-S3 独立复审 P2-1）。
//! 拒绝编码的代价只是「这一轮没有基线」，下一轮照常收集。
//!
//! # 落库形态（逐字，勿改）
//!
//! ```json
//! {"v":1,"observed_at":1760000000,"sites":[
//!   {"site_id":1,"display_name":"测试站点","balance":{"remaining":3.5,"used":20.0,"currency":"USD"},
//!    "needs_login":false,"quota_exceeded":false,"models":["gpt-4"],"drift":[],"rotation_due":[]}]}
//! ```
//!
//! `v` 是格式版本：**加字段就升版本**，老版本解析失败 ⇒ `None`（退回首轮语义），不猜。
//!
//! # 本模块不接线
//!
//! 只交付**编解码 + 过期策略**（纯函数）；读写调用点在 `service.rs`（Lead 的写域），
//! 去向 M8-S5，见 spec §7.4 的未接线声明。

use serde::{Deserialize, Serialize};

use crate::drift::DriftState;
use crate::notify::{BalanceSnapshot, DriftFact, RotationDueFact, SiteSnapshot, Snapshot};
use crate::redact::contains_secret;

/// 落库键（`settings` KV 表；复用既有公开 API `Store::get_setting` / `set_setting`，
/// **不需要**新的存储层接口）。
///
/// 改键名 = 丢掉全部历史基线（所有站点退回首轮语义）⇒ 必须显式（N-13 钉住）。
pub const BASELINE_SETTING_KEY: &str = "notify.baseline.v1";

/// 过期策略：基线超过该时长即视为无效（当轮按「没有基线」处理 ⇒ 首轮语义）。
///
/// 7 天。理由：基线太旧时「与上一轮比较」已经没有意义（用户可能一周没开机），
/// 此时按首轮处理（事实型规则照发、边沿型不报）比拿一周前的状态去比更诚实。
pub const BASELINE_MAX_AGE_SECS: i64 = 7 * 86_400;

/// 当前落库格式版本。`decode_snapshot` 只认这一个值。
const FORMAT_VERSION: u32 = 1;

/// 快照 → JSON 文本。
///
/// # 命中密钥形态 ⇒ 拒绝编码（**不静默改写**）
///
/// `Snapshot` 的结构里没有任何密钥字段（M6-S3 §6.3 的结构性保证），但
/// `display_name` / `drift[].target_path` / `models[]` / `rotation_due[].name`
/// 仍是**用户可控文本**，可能长得像密钥。
///
/// 第一版在这里对整串 JSON 过 [`scrub`]，被独立复审（M8-S3 P2-1）抓出两个后果：
///
/// 1. **N-9 与 N-12 自相矛盾**：「干净往返」与「必须掩掉密钥形态」不可能同时成立；
/// 2. **边沿去重永久失配**（更严重）：`Drift` 的去重键含 `target_path`
///    （`rules.rs` 的 `same_fact`），基线里被掩成 `***`、当前快照里是原文
///    ⇒ 永不匹配 ⇒ **那条漂移每轮都重报**——正是 B-81 要消灭的噪声。
///
/// 因此改成 fail-closed：命中就返回 `None`，让调用方**不写这一轮**的基线
/// （下一轮照常收集；`prev` 缺一轮只是少一次去重，比把数据改坏安全得多）。
/// 落库文本因此与内存快照**逐字节同构**。
///
/// 序列化不可达失败时同样返回 `None`。**绝不**返回改过的或未定稿的中间态。
pub fn encode_snapshot(snapshot: &Snapshot, observed_at: i64) -> Option<String> {
    let persisted = Persisted {
        v: FORMAT_VERSION,
        observed_at,
        sites: snapshot.sites.iter().map(PersistedSite::from).collect(),
    };
    let text = serde_json::to_string(&persisted).ok()?;
    // fail-closed：宁可丢一轮基线，也不把用户数据改坏
    if contains_secret(&text) {
        return None;
    }
    Some(text)
}

/// JSON 文本 → 快照。
///
/// 解析失败 / 版本不认识 / 超过 [`BASELINE_MAX_AGE_SECS`] ⇒ `None`
/// （**不报错**：基线坏了不该阻断通知，退回「首轮语义」即可）。
///
/// 过期边界是**含**的：`now - observed_at == BASELINE_MAX_AGE_SECS` 仍算有效（N-10）。
pub fn decode_snapshot(text: &str, now: i64) -> Option<Snapshot> {
    let persisted: Persisted = serde_json::from_str(text).ok()?;
    if persisted.v != FORMAT_VERSION {
        return None;
    }
    // `observed_at` 在未来（时钟被往回拨过）不算过期：它是比较基线，不是「发生时间」。
    let age = now.saturating_sub(persisted.observed_at);
    if age > BASELINE_MAX_AGE_SECS {
        return None;
    }
    Some(Snapshot {
        sites: persisted.sites.iter().map(SiteSnapshot::from).collect(),
    })
}

/// 落库镜像。**刻意与 [`Snapshot`] 分开**：磁盘格式是独立契约，内部结构改名
/// （或加字段）不该静默改变它——改格式要显式升 [`FORMAT_VERSION`]。
#[derive(Serialize, Deserialize)]
struct Persisted {
    v: u32,
    observed_at: i64,
    sites: Vec<PersistedSite>,
}

/// 单站点的落库记录。**刻意与 [`SiteSnapshot`] 分开**：磁盘格式是独立契约，
/// 内部结构改名（或加字段）不该静默改变它——改格式要显式升 [`FORMAT_VERSION`]。
///
/// 容器级 `#[serde(default)]`：单条站点记录缺键时**按缺省补齐**，不因为少了某个键
/// 就把整份基线作废（与坏基线「安静退回首轮语义」同一取向）。
/// 缺 `site_id` ⇒ `0`，匹配不到任何真实站点 ⇒ 那条记录对判定没有影响。
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct PersistedSite {
    site_id: i64,
    display_name: String,
    balance: Option<PersistedBalance>,
    needs_login: bool,
    quota_exceeded: bool,
    /// `None` = 没取到，`[]` = 站点返回空列表（两者在规则里含义不同，必须区分）。
    models: Option<Vec<String>>,
    drift: Vec<PersistedDrift>,
    rotation_due: Vec<PersistedRotation>,
}

#[derive(Serialize, Deserialize)]
struct PersistedBalance {
    remaining: f64,
    used: f64,
    currency: String,
}

#[derive(Serialize, Deserialize)]
struct PersistedDrift {
    target_path: String,
    agent_id: String,
    channel: String,
    /// [`DriftState`] 的 `as_str()` 取值（snake_case）。认不出来的字符串 ⇒
    /// [`DriftState::Unknown`]——**不猜**成「被改过」（那会让用户白跑一趟）。
    state: String,
}

#[derive(Serialize, Deserialize)]
struct PersistedRotation {
    key_id: i64,
    name: String,
    due_at: i64,
}

impl From<&SiteSnapshot> for PersistedSite {
    fn from(site: &SiteSnapshot) -> Self {
        Self {
            site_id: site.site_id,
            display_name: site.display_name.clone(),
            balance: site.balance.as_ref().map(PersistedBalance::from),
            needs_login: site.needs_login,
            quota_exceeded: site.quota_exceeded,
            models: site.models.clone(),
            drift: site.drift.iter().map(PersistedDrift::from).collect(),
            rotation_due: site
                .rotation_due
                .iter()
                .map(PersistedRotation::from)
                .collect(),
        }
    }
}

impl From<&BalanceSnapshot> for PersistedBalance {
    fn from(balance: &BalanceSnapshot) -> Self {
        Self {
            remaining: balance.remaining,
            used: balance.used,
            currency: balance.currency.clone(),
        }
    }
}

impl From<&DriftFact> for PersistedDrift {
    fn from(fact: &DriftFact) -> Self {
        Self {
            target_path: fact.target_path.clone(),
            agent_id: fact.agent_id.clone(),
            channel: fact.channel.clone(),
            state: fact.state.as_str().to_string(),
        }
    }
}

impl From<&RotationDueFact> for PersistedRotation {
    fn from(fact: &RotationDueFact) -> Self {
        Self {
            key_id: fact.key_id,
            name: fact.name.clone(),
            due_at: fact.due_at,
        }
    }
}

/// [`DriftState`] 的字符串 → 枚举。认不出来 ⇒ [`DriftState::Unknown`]。
///
/// 与 [`crate::drift::classify`] 的「没有哈希 ⇒ `Unknown`」同向：**宁可不知道，
/// 不可猜**——把不认识的状态猜成 `Modified` 会让用户去查一个没被改过的文件。
fn drift_state_from_str(state: &str) -> DriftState {
    match state {
        "intact" => DriftState::Intact,
        "modified" => DriftState::Modified,
        "missing" => DriftState::Missing,
        "unreadable" => DriftState::Unreadable,
        _ => DriftState::Unknown,
    }
}

impl From<&PersistedSite> for SiteSnapshot {
    fn from(site: &PersistedSite) -> Self {
        Self {
            site_id: site.site_id,
            display_name: site.display_name.clone(),
            balance: site.balance.as_ref().map(BalanceSnapshot::from),
            needs_login: site.needs_login,
            quota_exceeded: site.quota_exceeded,
            models: site.models.clone(),
            drift: site.drift.iter().map(DriftFact::from).collect(),
            rotation_due: site
                .rotation_due
                .iter()
                .map(RotationDueFact::from)
                .collect(),
        }
    }
}

impl From<&PersistedBalance> for BalanceSnapshot {
    fn from(balance: &PersistedBalance) -> Self {
        Self {
            remaining: balance.remaining,
            used: balance.used,
            currency: balance.currency.clone(),
        }
    }
}

impl From<&PersistedDrift> for DriftFact {
    fn from(fact: &PersistedDrift) -> Self {
        Self {
            target_path: fact.target_path.clone(),
            agent_id: fact.agent_id.clone(),
            channel: fact.channel.clone(),
            state: drift_state_from_str(&fact.state),
        }
    }
}

impl From<&PersistedRotation> for RotationDueFact {
    fn from(fact: &PersistedRotation) -> Self {
        Self {
            key_id: fact.key_id,
            name: fact.name.clone(),
            due_at: fact.due_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drift::DriftState;

    const NOW: i64 = 1_760_000_000;

    fn snapshot() -> Snapshot {
        Snapshot {
            sites: vec![
                SiteSnapshot {
                    site_id: 1,
                    display_name: "测试站点".to_string(),
                    balance: Some(BalanceSnapshot {
                        remaining: 3.5,
                        used: 20.0,
                        currency: "USD".to_string(),
                    }),
                    needs_login: false,
                    quota_exceeded: false,
                    models: Some(vec!["gpt-4".to_string()]),
                    drift: vec![DriftFact {
                        target_path: "/Users/me/.codex/auth.json".to_string(),
                        agent_id: "codex".to_string(),
                        channel: "codex_auth_json".to_string(),
                        state: DriftState::Modified,
                    }],
                    rotation_due: vec![RotationDueFact {
                        key_id: 9,
                        name: "主力".to_string(),
                        due_at: 1_760_000_100,
                    }],
                },
                SiteSnapshot {
                    site_id: 2,
                    display_name: "赤霄API".to_string(),
                    balance: None,
                    needs_login: true,
                    quota_exceeded: true,
                    // `None`（没取到）与 `Some(vec![])`（空列表）必须都能往返
                    models: Some(Vec::new()),
                    drift: Vec::new(),
                    rotation_due: Vec::new(),
                },
                // 第三个站点：`models == None`
                SiteSnapshot {
                    site_id: 3,
                    display_name: "空模型站".to_string(),
                    balance: None,
                    needs_login: false,
                    quota_exceeded: false,
                    models: None,
                    drift: Vec::new(),
                    rotation_due: Vec::new(),
                },
            ],
        }
    }

    #[test]
    fn snapshot_round_trips_verbatim() {
        let original = snapshot();
        let text = encode_snapshot(&original, NOW).expect("干净快照必须能编码");
        assert_eq!(
            decode_snapshot(&text, NOW),
            Some(original),
            "编解码必须逐字段往返（含 None / 空列表的区分）\n{text}"
        );
    }

    #[test]
    fn encoded_form_is_the_pinned_shape() {
        // spec §7.2 的「落库形态（逐字）」：键名、顺序、紧凑分隔都不许漂移
        assert_eq!(
            encode_snapshot(&snapshot(), NOW).expect("干净快照必须能编码"),
            concat!(
                r#"{"v":1,"observed_at":1760000000,"sites":["#,
                r#"{"site_id":1,"display_name":"测试站点","balance":{"remaining":3.5,"used":20.0,"currency":"USD"},"needs_login":false,"quota_exceeded":false,"models":["gpt-4"],"#,
                r#""drift":[{"target_path":"/Users/me/.codex/auth.json","agent_id":"codex","channel":"codex_auth_json","state":"modified"}],"#,
                r#""rotation_due":[{"key_id":9,"name":"主力","due_at":1760000100}]},"#,
                r#"{"site_id":2,"display_name":"赤霄API","balance":null,"needs_login":true,"quota_exceeded":true,"models":[],"drift":[],"rotation_due":[]},"#,
                r#"{"site_id":3,"display_name":"空模型站","balance":null,"needs_login":false,"quota_exceeded":false,"models":null,"drift":[],"rotation_due":[]}]}"#
            )
        );
    }

    #[test]
    fn expired_baseline_decodes_to_none() {
        let text = encode_snapshot(&snapshot(), NOW).expect("干净快照必须能编码");
        // 恰好等于上限 ⇒ 仍有效（边界含）
        assert!(decode_snapshot(&text, NOW + BASELINE_MAX_AGE_SECS).is_some());
        // 超一秒 ⇒ 无效（退回首轮语义）
        assert!(decode_snapshot(&text, NOW + BASELINE_MAX_AGE_SECS + 1).is_none());
        // 基线「来自未来」（本机时钟被往回拨过）不算过期
        assert!(decode_snapshot(&text, NOW - 86_400).is_some());
    }

    #[test]
    fn malformed_baseline_decodes_to_none() {
        for text in [
            "",
            "   ",
            "{}",
            "null",
            "[]",
            "not json at all",
            r#"{"v":2,"observed_at":1760000000,"sites":[]}"#, // 版本不认识
            r#"{"v":1,"observed_at":1760000000}"#,            // 缺 sites
            r#"{"v":1,"observed_at":"1760000000","sites":[]}"#, // 类型不对
        ] {
            assert!(
                decode_snapshot(text, NOW).is_none(),
                "坏基线必须安静地退回首轮语义，而不是 panic / 报错: {text}"
            );
        }
    }

    #[test]
    fn unknown_drift_state_decodes_to_unknown_not_modified() {
        let text = r#"{"v":1,"observed_at":1760000000,"sites":[{"site_id":1,"display_name":"甲",
            "balance":null,"needs_login":false,"quota_exceeded":false,"models":null,
            "drift":[{"target_path":"/x","agent_id":"codex","channel":"codex_auth_json","state":"wat"}],
            "rotation_due":[]}]}"#;
        let snapshot = decode_snapshot(text, NOW).expect("合法 JSON");
        assert_eq!(
            snapshot.sites[0].drift[0].state,
            DriftState::Unknown,
            "认不出来的状态必须落 Unknown：猜成 Modified 会让用户白跑一趟"
        );
    }

    #[test]
    fn missing_optional_fields_still_decode() {
        // 老版本 / 手写基线可能没有这些键：缺省补齐，不因为缺键就整体作废
        let text =
            r#"{"v":1,"observed_at":1760000000,"sites":[{"site_id":1,"display_name":"甲"}]}"#;
        let snapshot = decode_snapshot(text, NOW).expect("可缺省字段的基线仍应可用");
        assert_eq!(snapshot.sites.len(), 1);
        assert_eq!(snapshot.sites[0].display_name, "甲");
        assert_eq!(snapshot.sites[0].balance, None);
        assert_eq!(snapshot.sites[0].models, None);
        assert!(snapshot.sites[0].drift.is_empty());
    }

    #[test]
    fn encoded_baseline_refuses_a_secret_shaped_snapshot() {
        // 显示名 / 货币 / 路径 / 名字都是**用户可控文本**：塞了密钥形态时
        // **拒绝编码**（fail-closed），而不是把数据改坏后写进库。
        let mut dirty = Snapshot::default();
        dirty.sites.push(SiteSnapshot {
            site_id: 1,
            display_name: "sk-0123456789abcdef".to_string(),
            balance: Some(BalanceSnapshot {
                remaining: 1.0,
                used: 2.0,
                currency: "nap-0123456789abcdef".to_string(),
            }),
            needs_login: false,
            quota_exceeded: false,
            models: None,
            drift: vec![DriftFact {
                target_path: "/x".to_string(),
                agent_id: "0123456789abcdef0123456789abcdef".to_string(),
                channel: "c".to_string(),
                state: DriftState::Missing,
            }],
            rotation_due: vec![RotationDueFact {
                key_id: 1,
                name: "0123456789abcdef0123456789abcdef".to_string(),
                due_at: 1,
            }],
        });
        assert_eq!(
            encode_snapshot(&dirty, NOW),
            None,
            "命中密钥形态必须拒绝编码：静默 scrub 会让边沿去重永久失配（P2-1）"
        );

        // 每一种字段单独命中都要被拒（不是只有显示名那条路）
        for mutate in [
            |s: &mut SiteSnapshot| s.display_name = "sk-0123456789abcdef".to_string(),
            |s: &mut SiteSnapshot| {
                s.balance = Some(BalanceSnapshot {
                    remaining: 1.0,
                    used: 2.0,
                    currency: "nap-0123456789abcdef".to_string(),
                })
            },
            |s: &mut SiteSnapshot| {
                s.models = Some(vec!["0123456789abcdef0123456789abcdef".to_string()])
            },
            |s: &mut SiteSnapshot| {
                s.drift = vec![DriftFact {
                    target_path: "0123456789abcdef0123456789abcdef".to_string(),
                    agent_id: "a".to_string(),
                    channel: "c".to_string(),
                    state: DriftState::Missing,
                }]
            },
            |s: &mut SiteSnapshot| {
                s.rotation_due = vec![RotationDueFact {
                    key_id: 1,
                    name: "0123456789abcdef0123456789abcdef".to_string(),
                    due_at: 1,
                }]
            },
        ] {
            let mut one = SiteSnapshot {
                site_id: 1,
                ..SiteSnapshot::default()
            };
            mutate(&mut one);
            let snapshot = Snapshot { sites: vec![one] };
            assert_eq!(
                encode_snapshot(&snapshot, NOW),
                None,
                "换一个字段塞密钥形态也必须被拒"
            );
        }

        // 干净快照不受影响（fail-closed 不等于「永远编不出来」）
        assert!(encode_snapshot(&snapshot(), NOW).is_some());
    }

    #[test]
    fn encoded_baseline_is_byte_identical_to_the_memory_snapshot() {
        // P2-1 的另一半：落库文本必须与内存快照**同构**。第一版在这里过 `scrub`，
        // 把 `target_path` 里的 32 位 hex 改成 `***` ⇒ 下一轮 `same_fact` 比不到
        // 同一条事实 ⇒ 漂移每轮重报。现在改成拒绝编码，这条就是回归防线。
        let mut with_hash_path = Snapshot::default();
        with_hash_path.sites.push(SiteSnapshot {
            site_id: 1,
            display_name: "测试站点".to_string(),
            balance: None,
            needs_login: false,
            quota_exceeded: false,
            models: None,
            drift: vec![DriftFact {
                // 真实场景：home 下的哈希目录名（64 位 hex）
                target_path: "/Users/me/Library/Caches/0123456789abcdef0123456789abcdef/x.toml"
                    .to_string(),
                agent_id: "codex".to_string(),
                channel: "codex_auth_json".to_string(),
                state: DriftState::Modified,
            }],
            rotation_due: Vec::new(),
        });
        // 这种快照**编不出来**（哈希路径命中 ≥32 位 hex）⇒ 调用方跳过这一轮，
        // 而不是存一份被改坏的基线。
        assert_eq!(encode_snapshot(&with_hash_path, NOW), None);

        // 能编出来的那些，编出来必须逐字节等于内存快照的字段值
        let clean = snapshot();
        let text = encode_snapshot(&clean, NOW).expect("干净快照");
        let decoded = decode_snapshot(&text, NOW).expect("自己编的必须能解");
        assert_eq!(decoded, clean);
        assert_eq!(
            decoded.sites[0].drift[0].target_path, "/Users/me/.codex/auth.json",
            "路径必须逐字节往返（不得被掩成 ***）"
        );
    }

    #[test]
    fn baseline_setting_key_is_pinned() {
        assert_eq!(BASELINE_SETTING_KEY, "notify.baseline.v1");
        assert_eq!(BASELINE_MAX_AGE_SECS, 604_800);
    }
}
