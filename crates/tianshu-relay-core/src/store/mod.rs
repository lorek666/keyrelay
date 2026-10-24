//! 本地元数据存储（SQLite / WAL）。
//!
//! 红线：本模块**不存密钥**。`keys.secret_ref` 只是钥匙串引用（见 `vault::secret_ref`）。

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension as _};

use crate::error::{Error, Result};
use crate::inject::Journal;
use crate::site::KeyStatus;

/// 当前 schema 版本（M39-S1：6 → 7，新增 `site_model_catalog` / `site_model_sync`）。
///
/// 版本号只是「将来需要非幂等迁移」的锚点：新表由每次打开的幂等 `DDL` 建出。
/// M39-S1 之后下一个用版本号的是 M40-S1（顺延为 8）。
const SCHEMA_VERSION: i64 = 10;

/// 「已回收」——**本地**密钥生命周期状态（M7-S4 / FR-2）。
///
/// **这一列的词表是本地词表**：`keys.status` 今天**没有任何站点侧写入者**——
/// `INSERT INTO keys` 不写它（`store/mod.rs:395`）、也没有把站点侧 `KeyMeta.status` 映射进来的代码，
/// 所以它记的是**本产品对这把钥匙做过什么**，而不是站点怎么报。
///
/// `site::KeyStatus` 只有 `enabled` / `disabled` / `exhausted` / `unknown`，**装不下「已回收」**
/// ——键在站点上已经不存在了，站点永远不会报这个状态。用 `"disabled"` 冒充会让界面无法区分
/// 「站点把它禁了」与「我自己把它回收了」，而后者正是本包存在的理由（章程 §3.4 v1.1 裁决）。
pub const KEY_STATUS_REVOKED: &str = "revoked";

/// `keys.status` 的合法值 = 站点侧词表 ∪ 本地词表。
///
/// 站点侧四个值**从枚举派生**（不抄字面量）：章程 §3.4 的原文就是「只接受 `site::KeyStatus::as_str()`
/// 的合法值」，派生比抄写少一个漂移源。新增站点侧变体时，`tests/key_lifecycle.rs` 里那条
/// 穷举 `match` 会编译失败，逼人回来确认本集合。
fn legal_key_statuses() -> [&'static str; 5] {
    [
        KeyStatus::Enabled.as_str(),
        KeyStatus::Disabled.as_str(),
        KeyStatus::Exhausted.as_str(),
        KeyStatus::Unknown.as_str(),
        KEY_STATUS_REVOKED,
    ]
}

fn is_legal_key_status(status: &str) -> bool {
    legal_key_statuses().contains(&status)
}

const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sites(
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,
  base_url TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL DEFAULT '',
  fingerprint_json TEXT,
  health TEXT NOT NULL DEFAULT 'unknown',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts(
  id INTEGER PRIMARY KEY,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  credential_ref TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'unknown',
  plan TEXT,
  last_login_at INTEGER
);
CREATE TABLE IF NOT EXISTS keys(
  id INTEGER PRIMARY KEY,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  account_id INTEGER REFERENCES accounts(id) ON DELETE SET NULL,
  remote_id TEXT,
  name TEXT NOT NULL,
  group_id TEXT,
  group_name TEXT,
  secret_ref TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'unknown',
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  quota_used REAL,
  quota_limit REAL,
  currency TEXT
);
CREATE TABLE IF NOT EXISTS bindings(
  id INTEGER PRIMARY KEY,
  agent_id TEXT NOT NULL,
  key_id INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
  target_path TEXT NOT NULL,
  managed_json TEXT,
  applied_at INTEGER NOT NULL,
  journal_id TEXT,
  -- M8-S4：解绑标记（FR-2:115）。**不删行**——漂移追溯与 journals 的溯源靠它存活。
  -- NULL = 仍然绑定。老库靠 `add_column_if_missing` 补上（见 `migrate()`）。
  unbound_at INTEGER,
  -- P1-2：投递模式（"site" / "gateway"）。轮换按它走，不把网关模式改成站点模式。
  -- 老库靠 `add_column_if_missing` 补，默认 "site"（既有行为）。
  delivery_mode TEXT NOT NULL DEFAULT 'site'
);
CREATE TABLE IF NOT EXISTS journals(
  id TEXT PRIMARY KEY,
  ts INTEGER NOT NULL,
  op TEXT NOT NULL,
  target_path TEXT NOT NULL,
  before_sha256 TEXT,
  after_sha256 TEXT,
  backup_path TEXT,
  status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  level TEXT NOT NULL,
  source TEXT NOT NULL,
  message TEXT NOT NULL,
  payload_redacted_json TEXT
);
-- 密钥投递的用户授权（M1-S2）。**只存键名**，任何情况下不得出现密钥明文或掩码值。
CREATE TABLE IF NOT EXISTS consents(
  id INTEGER PRIMARY KEY,
  agent_id TEXT NOT NULL,
  channel TEXT NOT NULL,
  target_path TEXT NOT NULL,
  fields TEXT NOT NULL,
  granted_at INTEGER NOT NULL,
  revoked_at INTEGER,
  UNIQUE(agent_id, channel, target_path)
);
CREATE INDEX IF NOT EXISTS idx_consents_agent ON consents(agent_id, channel);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
-- 运行时设置（M3-S1）。键值都是文本，读不到就用默认值。
CREATE TABLE IF NOT EXISTS settings(
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
-- 已知导出物（M5-S1 / 关闭 B-60）。审计按这张表扫，用户自选路径才算进了覆盖范围。
-- 只记路径与统计，不记内容。
CREATE TABLE IF NOT EXISTS exports(
  path        TEXT PRIMARY KEY,
  encrypted   INTEGER NOT NULL,
  bytes       INTEGER NOT NULL,
  exported_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bindings_target ON bindings(target_path);
-- M13-S1：网关 token 用量日志（逐请求）。
CREATE TABLE IF NOT EXISTS gateway_usage_log(
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,                 -- 插入时刻（审计；M40 起不再是账目日期口径）
  at INTEGER NOT NULL DEFAULT 0,       -- M40-S1：请求完成时刻
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  model TEXT NOT NULL DEFAULT '',
  prompt_tokens INTEGER NOT NULL DEFAULT 0,
  completion_tokens INTEGER NOT NULL DEFAULT 0,
  total_tokens INTEGER NOT NULL DEFAULT 0,
  key_id INTEGER,                      -- M40-S1：实际命中的 key（可空：legacy/未知）
  status INTEGER NOT NULL DEFAULT 0,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  attempts INTEGER NOT NULL DEFAULT 1,
  stream INTEGER NOT NULL DEFAULT 0,
  token_id INTEGER REFERENCES gateway_tokens(id) ON DELETE SET NULL,
  agent_label TEXT NOT NULL DEFAULT ''
);
-- M43-S1：Agent 级网关令牌。**只存 hash**；明文只在创建时返回一次，永不落库。
CREATE TABLE IF NOT EXISTS gateway_tokens(
  id           INTEGER PRIMARY KEY,
  token_hash   TEXT    NOT NULL UNIQUE,   -- sha256(明文) 的 64 位小写 hex
  label        TEXT    NOT NULL,          -- agent 标签（用户输入，展示前过 scrub）
  created_at   INTEGER NOT NULL,          -- unix 秒
  revoked_at   INTEGER,                   -- NULL = 有效
  last_used_at INTEGER,                   -- NULL = 从没用过
  is_default   INTEGER NOT NULL DEFAULT 0 -- 1 = 钥匙串那把默认令牌对应的行（**身份事实，不看 label**）
);
-- 非吊销的 label 唯一：归因按标签聚合，重名会混账。
CREATE UNIQUE INDEX IF NOT EXISTS idx_gateway_tokens_label_live
  ON gateway_tokens(label) WHERE revoked_at IS NULL;
-- 最多一个默认行（部分唯一索引）：默认令牌是身份事实，不允许两份。
CREATE UNIQUE INDEX IF NOT EXISTS idx_gateway_tokens_one_default
  ON gateway_tokens(is_default) WHERE is_default = 1;
CREATE INDEX IF NOT EXISTS idx_gateway_tokens_created ON gateway_tokens(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_usage_ts ON gateway_usage_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_usage_site ON gateway_usage_log(site_id, ts DESC);
-- M13-S1：站点余额快照（每轮刷新时写一条）。
CREATE TABLE IF NOT EXISTS usage_snapshots(
  id INTEGER PRIMARY KEY,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  used REAL NOT NULL,
  remaining REAL NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  known INTEGER NOT NULL DEFAULT 1,
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_usage_snapshots_site ON usage_snapshots(site_id, ts DESC);
-- M14-S1：模型别名映射（B-110 / FR-6）。alias 为主键：重复 alias 后者胜，
-- 与 routing::alias_map 的 BTreeMap::insert 语义一致。只存映射，不存密钥。
CREATE TABLE IF NOT EXISTS model_aliases(
  alias TEXT PRIMARY KEY,
  real_model TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
-- M14-S3：每把 key 的每日用量采样（Sub2API `usage/daily` 的 items）。NewAPI 不写本表（无日趋势）。
-- 字段名与 Sub2API 源码 `APIKeyDailyUsagePoint` 一致（input_tokens / output_tokens，非 tokens_in/out）。
CREATE TABLE IF NOT EXISTS usage_samples(
  id INTEGER PRIMARY KEY,
  key_id INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  date TEXT NOT NULL,
  requests INTEGER NOT NULL DEFAULT 0,
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  total_tokens INTEGER NOT NULL DEFAULT 0,
  cost REAL NOT NULL DEFAULT 0,
  sampled_at INTEGER NOT NULL,
  UNIQUE(key_id, date)
);
CREATE INDEX IF NOT EXISTS idx_usage_samples_key ON usage_samples(key_id, date DESC);
-- M15-S1：模型检测历史（bazaarlink probe）。只存身份判定摘要，
-- **不存** items[].response / responseHeaders / startedByIp / userKey（敏感，见 probe/mod.rs）。
CREATE TABLE IF NOT EXISTS probe_runs(
  id INTEGER PRIMARY KEY,
  run_id TEXT NOT NULL,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  key_id INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
  model_id TEXT NOT NULL,
  claimed_model TEXT,
  identity_status TEXT,
  verdict_status TEXT,
  true_family TEXT,
  true_model TEXT,
  spoof_method TEXT,
  confidence TEXT,
  warnings_count INTEGER NOT NULL DEFAULT 0,
  report_url TEXT,
  bazaarlink_created_at INTEGER,
  bazaarlink_completed_at INTEGER,
  recorded_at INTEGER NOT NULL,
  -- B-135：bazaarlink run 生命周期状态（running/completed/failed/aborted）。
  -- 放在**末尾**是刻意的：老库只能靠 `add_column_if_missing` 追加到末尾，
  -- 写在中部会让「新建库」与「迁移库」的物理列序不一致。本项目所有读写都带显式列名，
  -- 列序不影响行为——但不一致本身就是将来踩坑的种子。
  status TEXT
);
CREATE INDEX IF NOT EXISTS idx_probe_runs_recorded ON probe_runs(recorded_at DESC);
-- M39-S1：站点模型目录（持久化的「该站点当前服务哪些模型」）。
-- 与 sites 级联删除：站点没了，它的目录行也不该留着。
-- 主键 (site_id, model) 以 site_id 为前导列 ⇒ `WHERE site_id = ?` 与 `ORDER BY model`
-- 都走同一条索引，不需要额外的二级索引。
CREATE TABLE IF NOT EXISTS site_model_catalog(
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  model TEXT NOT NULL,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  PRIMARY KEY(site_id, model)
);
-- M39-S1：采集同步状态（每站一行）：节流锚点 + 连续空计数 + 最近错误（已脱敏、截断）。
CREATE TABLE IF NOT EXISTS site_model_sync(
  site_id INTEGER PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
  last_success_at INTEGER,
  last_attempt_at INTEGER,
  empty_streak INTEGER NOT NULL DEFAULT 0,
  last_error TEXT
);
-- M43-S2：模型单价表。同一 (model, currency, effective_from) 唯一（= 一个价格版本）。
CREATE TABLE IF NOT EXISTS model_prices(
  id               INTEGER PRIMARY KEY,
  model            TEXT    NOT NULL,
  input_per_mtok   REAL    NOT NULL,
  output_per_mtok  REAL    NOT NULL,
  currency         TEXT    NOT NULL,
  effective_from   INTEGER NOT NULL,
  created_at       INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_model_prices_version
  ON model_prices(model, currency, effective_from);
CREATE INDEX IF NOT EXISTS idx_model_prices_model
  ON model_prices(model, currency, effective_from DESC);
-- M43-S2：站点自报账单（只读导入结果；**不含任何原始日志正文**）。
CREATE TABLE IF NOT EXISTS site_bills(
  id         INTEGER PRIMARY KEY,
  site_id    INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  day        TEXT    NOT NULL,
  amount     REAL,
  currency   TEXT,
  requests   INTEGER,
  source     TEXT    NOT NULL,
  fetched_at INTEGER NOT NULL,
  UNIQUE(site_id, day, source)
);
CREATE INDEX IF NOT EXISTS idx_site_bills_site_day ON site_bills(site_id, day DESC);
-- M46-S5：站点 / key 硬预算（一行 = 一个预算）。
-- key_id 为空 = 该站全部 key 合计；有值 = 该 key 单独的预算。
-- period 只认 'day' | 'month'（写路径 validate，不靠 CHECK 约束兜底）。
-- 站级与 key 级各一条部分唯一索引：SQLite 里 NULL 互不相等，一条
-- UNIQUE(site_id, key_id, period) 拦不住站级重复行，必须分开写。
CREATE TABLE IF NOT EXISTS site_budgets(
  id INTEGER PRIMARY KEY,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  key_id INTEGER REFERENCES keys(id) ON DELETE CASCADE,
  period TEXT NOT NULL,
  limit_usd REAL NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_site_budgets_site_period
  ON site_budgets(site_id, period) WHERE key_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_site_budgets_key_period
  ON site_budgets(site_id, key_id, period) WHERE key_id IS NOT NULL;
-- M46-S5：预算已花 SUM 的范围扫描索引不在这里（见 migrate）：预算查询按
-- (site_id, at) / (key_id, at) 过滤，而老库在 DDL 阶段还没有 at / key_id 列
-- （M40-S1 才补），放进 DDL 批会在老库上报 no such column（与 idx_gateway_usage_at
-- 同一个坑），故与它并排、在补列之后建。
"#;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 用量看板查询窗口上限（天，M34-S1）。
///
/// 与 `prune_gateway_usage_log` / `prune_usage_snapshots` / `prune_usage_samples` 的 90 天
/// 裁剪窗口一致：更早的数据已经不在库里，界面不提供更宽的窗口（否则是空承诺）。
pub const USAGE_MAX_DAYS: i64 = 90;

/// 把调用方给的窗口天数夹到 `1..=USAGE_MAX_DAYS`。命令层与 store 层共用这一条，
/// 避免「命令回显 90、实际查了 30」这种两处夹取不一致。
pub fn clamp_usage_days(days: i64) -> i64 {
    days.clamp(1, USAGE_MAX_DAYS)
}

// ---- M39-S1：站点模型目录的返回类型与阈值 ----

/// 连续多少次「成功但空」才清空该站目录（M39-S1 §5.2）。
///
/// 取 2 的理由：一次空响应可能是站点瞬时的上游抖动/超时半开；连续两次才当作「真的没有模型」。
pub const EMPTY_STREAK_TO_CLEAR: i64 = 2;

/// `site_model_sync.last_error` 的入库长度上限（字符，不是字节；M39-S1 §4.4 / §12）。
///
/// 截断是红线的一部分：一条异常（例如带上整段 HTML 错误页）不该把这行撑爆。
pub const MODEL_SYNC_ERROR_MAX_CHARS: usize = 500;

/// 一次「成功但空」的结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmptyOutcome {
    /// 自增后的连续空计数。
    pub streak: i64,
    /// 本次是否清空了该站目录（`streak >= EMPTY_STREAK_TO_CLEAR`）。
    pub cleared: bool,
}

/// 单站的采集同步状态（诊断 / 测试 / 节流读取）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteModelSync {
    pub site_id: i64,
    pub last_success_at: Option<i64>,
    pub last_attempt_at: Option<i64>,
    pub empty_streak: i64,
    pub last_error: Option<String>,
}

/// 本地时区「今天往前 `days_ago` 天」的日零点 epoch（秒）。
///
/// **`'utc'` 修饰符不能省**：`date(...)` 给出的是本地日期字符串，SQLite 默认把它当 UTC
/// 解释；`'utc'` 告诉它「这个时间值在本地时区」，于是换算出的 epoch 才是本地日零点。
/// 省掉后，在 UTC+8 上窗口起点会晚 8 小时（前一天的 08:00）。
fn local_day_start(conn: &Connection, days_ago: i64) -> Result<i64> {
    conn.query_row(
        "SELECT CAST(strftime('%s', date('now','localtime','-' || ?1 || ' days'), 'utc') AS INTEGER)",
        params![days_ago.max(0)],
        |row| row.get(0),
    )
    .map_err(|e| Error::Store(format!("计算本地日零点失败: {e}")))
}

/// 本地时区「今天往前 `days_ago` 天」的 `YYYY-MM-DD`。
fn local_day_ago(conn: &Connection, days_ago: i64) -> Result<String> {
    conn.query_row(
        "SELECT date('now','localtime','-' || ?1 || ' days')",
        params![days_ago.max(0)],
        |row| row.get(0),
    )
    .map_err(|e| Error::Store(format!("计算本地日期失败: {e}")))
}

/// 钥匙串引用形状：`kr/<scope>/<id>/<field>`（与 `vault::secret_ref` 一致）。
///
/// 采用白名单而非黑名单：只拦 `sk-` / `nap-` 前缀会放过 32 位 hex 之类的明文
/// （复审 P2-4 的探针即用该形状入库成功）。
fn is_valid_secret_ref(value: &str) -> bool {
    let parts: Vec<&str> = value.split('/').collect();
    parts.len() == 4 && parts[0] == "kr" && parts[1..].iter().all(|p| !p.is_empty())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteRow {
    pub id: i64,
    pub kind: String,
    pub base_url: String,
    pub display_name: String,
    pub health: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct KeyRow {
    pub id: i64,
    pub site_id: i64,
    pub remote_id: Option<String>,
    pub name: String,
    pub group_name: Option<String>,
    /// 站点原生分组主键（Sub2API 的数字 id）。`None` = 不知道 / 站点没有 id 概念（NewAPI）。
    ///
    /// `keys.group_id` 列从 M0 就在 DDL 里，但一直没人写；M22-S1 起由 `create_key` 写入。
    /// **旧行仍是 `NULL`，不做回填**：回填只能按名字反查，而名字正是「改名后失效」的那个依据，
    /// 回填等于把猜出来的值写进库（`rotation_inherit_group` 的 id 优先判据因此必须兼容 `None`）。
    pub group_id: Option<String>,
    pub secret_ref: String,
    pub status: String,
    /// 本地记账的创建时间（unix 秒）。M6-S5 起用于密钥轮换判定
    /// （`rotation::due_keys`）；列一直是 `NOT NULL`，只是先前没进 `SELECT`。
    pub created_at: i64,
    /// M14-S3：该 key 的当前累计已用（USD）。`None` = 未采集 / 站点未给。
    pub quota_used: Option<f64>,
    /// M14-S3：该 key 的限额（USD）。`None` = 不限 / 未采集。
    pub quota_limit: Option<f64>,
    /// M14-S3：币种（`"USD"`）。
    pub currency: Option<String>,
}

/// 事件行。`message` / `payload` 在写入时已脱敏。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRow {
    pub id: i64,
    pub ts: i64,
    pub level: String,
    pub source: String,
    pub message: String,
    pub payload: Option<String>,
}

/// 一次投递的漂移检测输入：绑定 + 投递时记录的哈希。
///
/// M6-S5（W-1）新增 `site_id`：漂移本身是**投递目标**的属性，但通知快照
/// （章程 §4.3 的 `SiteSnapshot`）是按站点装配的，装配时必须知道归属。
/// 归属取自 `bindings.key_id → keys.site_id`（`keys.id` 有 `ON DELETE CASCADE`，
/// 所以不存在「绑定还在、密钥已删」的悬挂行，用 INNER JOIN 不会丢行）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingDriftRow {
    pub agent_id: String,
    pub target_path: String,
    pub journal_id: String,
    /// 投递时该文件的 sha256；老库可能没有
    pub expected_sha256: Option<String>,
    /// 该绑定所用密钥所属的站点（用于把漂移事实归到站点快照上）
    pub site_id: i64,
    /// 该绑定所用的密钥 id（用于「这把 key 现在服务哪些投递目标」）
    pub key_id: i64,
}

/// 一条投递绑定（M8-S4 的解绑与「同时回收」都要按它走）。
///
/// 含**已解绑**的行：`also_revoke` 要按「这次解绑之前有哪些绑定」去回收站点侧，
/// 而解绑本身不删行（§5.1），所以读的时候必须能把两者分开——判据是 `unbound_at`。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingRow {
    pub id: i64,
    pub agent_id: String,
    pub key_id: i64,
    pub target_path: String,
    pub applied_at: i64,
    /// `None` = 仍然绑定。
    pub unbound_at: Option<i64>,
    /// 该绑定所用密钥所属的站点。
    pub site_id: i64,
    /// 站点侧的令牌 id（回收要用它）。
    pub remote_id: Option<String>,
    /// P1-2：投递模式（"site" / "gateway"）。轮换按它走。
    pub delivery_mode: String,
}

/// 投递历史的一行（M9-S4）：一次投递 = 一条 `bindings` 行 + 它的 `journals` 行。
///
/// 从 `bindings` 出发而不是从 `journals` 出发：`journals` 只有路径与哈希，
/// 「是哪个 agent、用的哪把 key」只在 `bindings` 上。解绑不删行（M8-S4 §5.1），
/// 所以已解绑的投递也在这里——它们仍然可以回滚（M8-S4 §5.4）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryHistoryRow {
    pub binding_id: i64,
    /// 老库行可能为 NULL ⇒ 空串（与 `binding_drift_rows` 同口径）。
    pub journal_id: String,
    pub agent_id: String,
    pub key_id: i64,
    pub site_id: i64,
    pub target_path: String,
    pub applied_at: i64,
    /// `None` = 仍然绑定。
    pub unbound_at: Option<i64>,
    /// `None`：投递前文件不存在（回滚 = 删掉它），或者没有 journal 行。
    pub backup_path: Option<String>,
    /// 没有 journal 行就无从回滚（`rollback_delivery` 会报「变更记录不存在」）。
    pub has_journal: bool,
    pub rolled_back: bool,
    /// 同一目标上有**更新的、未回滚的**投递。为真时回滚**通常**会被哈希校验拒绝：
    /// 文件里是之后那次写下的内容，不是这次。两种例外下真回滚会成功——文件已被删除
    /// （`restore_entry` 对不存在的文件不做哈希校验）、或之后那次写下的字节恰好相同。
    /// 界面据此灰显，在这两种例外里比实际更保守；真正的闸是哈希校验（M9-S4 复审 P2-2）。
    pub superseded: bool,
}

/// 解绑的返回语义（**逐条**，因为它们都会被 UI 直接念给用户听）：
/// - `unbound`：本次**新标记**的行数（已解绑过的行不计 ⇒ 幂等，二次调用返回 0）
/// - `already_unbound`：本次看到但**早已解绑**的行数（用于「本来就是解绑状态」的文案）
///
/// 两者之和 = 这次调用**匹配到**的绑定总数。这是一条可断言的恒等式。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnbindReport {
    pub unbound: usize,
    pub already_unbound: usize,
}

/// 投递授权行。`fields` 是 JSON 数组，**只有键名**。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentRow {
    pub agent_id: String,
    pub channel: String,
    pub target_path: String,
    pub fields: String,
    pub granted_at: i64,
    pub revoked_at: Option<i64>,
}

/// 一次导出的登记行（M5-S1 / 关闭 B-60）。**不含文件内容**。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportRecord {
    pub path: String,
    pub encrypted: bool,
    pub bytes: i64,
    pub exported_at: i64,
}

/// 一次网关请求的 token 用量行（M13-S1）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayUsageRow {
    pub id: i64,
    pub ts: i64,
    pub site_id: i64,
    pub model: String,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
}

/// 一个站点的余额快照行（M13-S1）。
#[derive(Clone, Debug, PartialEq)]
pub struct UsageSnapshotRow {
    pub id: i64,
    pub ts: i64,
    pub site_id: i64,
    pub used: f64,
    pub remaining: f64,
    pub currency: String,
    pub known: bool,
}

/// 一把 key 一天的用量采样行（M14-S3，Sub2API `usage/daily`）。**不含密钥**。
#[derive(Clone, Debug, PartialEq)]
pub struct UsageSampleRow {
    pub id: i64,
    pub key_id: i64,
    pub site_id: i64,
    pub date: String,
    pub requests: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub cost: f64,
    pub sampled_at: i64,
}

/// M34-S1：网关 token 用量按（本地日, 站点, 模型）聚合的一行。
///
/// `date` 是**本地时区**的 `YYYY-MM-DD`（`date(ts,'unixepoch','localtime')`）；
/// `model` 保留空串作为独立分组（网关没解析出模型名时），前端显示「未知模型」。
// 注意：`estimated_cost: Option<f64>` ⇒ 不能 derive `Eq`（浮点没有全序等式）。
#[derive(Clone, Debug, PartialEq)]
pub struct UsageDailyRow {
    pub date: String,
    pub site_id: i64,
    pub model: String,
    pub requests: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
    /// M43-S1：命中的令牌行；`None` = 未归因（旧数据）
    pub token_id: Option<i64>,
    /// M43-S1：认证当时的标签快照；`''` = 未归因（旧数据）
    pub agent_label: String,
    /// M43-S2：本组命中的**价格币种**（同一模型若在不同时段命中不同币种的价格，
    /// 会按币种**拆成多行**）。行级合计按 `ROUND(单条成本, 6)` 再求和（§4.6）。
    pub currency: Option<String>,
    /// M43-S2：本组里**能定价**的用量合计；`None` = 整组都没有价格（未知，不是 0）。
    pub estimated_cost: Option<f64>,
    /// M43-S2：本组里**没有价格**的请求数与 token 数（>0 ⇒ 界面标「部分未定价」）。
    pub unpriced_requests: i64,
    pub unpriced_tokens: i64,
}

/// M43-S1：一条 Agent 网关令牌。**只有 hash，没有明文**。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayTokenRow {
    pub id: i64,
    pub token_hash: String,
    pub label: String,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub is_default: bool,
}

impl GatewayTokenRow {
    /// 是否有效（未吊销）。
    pub fn active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

/// M34-S1：站点余额快照按（本地日, 站点）聚合的一行。
///
/// `used` / `remaining` / `currency` 取**当日最后一条**快照（`ts DESC, id DESC`），
/// `samples` 是当日快照条数（>1 表示当天刷新过多次）。
#[derive(Clone, Debug, PartialEq)]
pub struct UsageSnapshotDailyRow {
    pub date: String,
    pub site_id: i64,
    pub used: f64,
    pub remaining: f64,
    pub currency: String,
    pub samples: i64,
}

/// M43-S2：一个价格版本（`model_prices` 的一行）。**纯数据**，供 `usage_cost` 纯函数消费。
#[derive(Clone, Debug, PartialEq)]
pub struct ModelPriceRow {
    pub id: i64,
    pub model: String,
    pub input_per_mtok: f64,
    pub output_per_mtok: f64,
    /// `"USD"` | `"CNY"`
    pub currency: String,
    pub effective_from: i64,
    pub created_at: i64,
}

/// M46-S5：一行站点 / key 硬预算（`site_budgets` 表的一行）。
/// `key_id` 为 `None` = 该站全部 key 合计；有值 = 该 key 单独的预算。
/// `period` 只认 `"day"` | `"month"`（写路径 validate，见 `budget_create`）。
#[derive(Clone, Debug, PartialEq)]
pub struct SiteBudgetRow {
    pub id: i64,
    pub site_id: i64,
    pub key_id: Option<i64>,
    pub period: String,
    pub limit_usd: f64,
    pub created_at: i64,
}

/// M43-S2：一行站点自报账单。`amount` / `currency` 为 `None` = 站点没给（**不是 0**）。
#[derive(Clone, Debug, PartialEq)]
pub struct SiteBillRow {
    pub id: i64,
    pub site_id: i64,
    pub day: String,
    pub amount: Option<f64>,
    pub currency: Option<String>,
    pub requests: Option<i64>,
    /// `"newapi-log-self"` | `"sub2api-usage-daily"`
    pub source: String,
    pub fetched_at: i64,
}

/// M43-S2：按 agent（`agent_label` 快照）× 币种的成本聚合。
#[derive(Clone, Debug, PartialEq)]
pub struct AgentUsageRow {
    pub agent_label: String,
    pub currency: Option<String>,
    pub requests: i64,
    pub total_tokens: i64,
    /// `None` = 该组全部行都没有价格。
    pub estimated_cost: Option<f64>,
    pub unpriced_requests: i64,
}

/// M34-S1：`usage_samples` 按 key 汇总的一行（join `keys` 取名字与币种）。
#[derive(Clone, Debug, PartialEq)]
pub struct KeyUsageTotalRow {
    pub key_id: i64,
    pub site_id: i64,
    pub key_name: String,
    pub requests: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    /// M43-S2：站点自报成本的合计；**`None` = 所有行都没上报**（不是 0——`cost_reported = 0`
    /// 表示站点没给这个字段，与「真的是 0」不可分，见 spec §6.1）。
    pub cost: Option<f64>,
    /// `keys.currency`；未记录时为 `None`（不猜币种，与 `Balance.known` 同纪律）。
    pub currency: Option<String>,
}

/// M15-S1：一次 probe 检测的本地记录（`probe_runs` 表的一行）。
///
/// **不含敏感字段**——`items[].response` / `responseHeaders` / `startedByIp` / `userKey`
/// 在写入时就被丢弃（`insert_probe_run` 只接 `ProbeRun` 摘要）。
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeRunRow {
    pub id: i64,
    pub run_id: String,
    pub site_id: i64,
    pub key_id: i64,
    pub model_id: String,
    pub claimed_model: Option<String>,
    pub identity_status: Option<String>,
    pub verdict_status: Option<String>,
    pub true_family: Option<String>,
    pub true_model: Option<String>,
    pub spoof_method: Option<String>,
    pub confidence: Option<String>,
    pub warnings_count: u32,
    pub report_url: Option<String>,
    pub bazaarlink_created_at: Option<i64>,
    pub bazaarlink_completed_at: Option<i64>,
    pub recorded_at: i64,
    /// B-135：bazaarlink run 生命周期状态。**老库的行是 `None`**——那一列是 v6 才加的，
    /// 历史行没记过状态，不猜（`Some("running")` 与 `None` 是两个不同的信息）。
    pub status: Option<String>,
}

impl ProbeRunRow {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            run_id: row.get(1)?,
            site_id: row.get(2)?,
            key_id: row.get(3)?,
            model_id: row.get(4)?,
            claimed_model: row.get(5)?,
            identity_status: row.get(6)?,
            verdict_status: row.get(7)?,
            true_family: row.get(8)?,
            true_model: row.get(9)?,
            spoof_method: row.get(10)?,
            confidence: row.get(11)?,
            warnings_count: row.get::<_, i64>(12)? as u32,
            report_url: row.get(13)?,
            bazaarlink_created_at: row.get(14)?,
            bazaarlink_completed_at: row.get(15)?,
            recorded_at: row.get(16)?,
            // 17 = 追加列（见 DDL 注释：新增列一律排在末尾，索引与 SELECT 同步）
            status: row.get(17)?,
        })
    }
}

pub struct Store {
    conn: Mutex<Connection>,
    /// 文件库的路径；内存库为 `None`。审计要用它定位 `*.db` / `-wal` / `-shm`。
    path: Option<std::path::PathBuf>,
    /// 仅测试用：下一次 `update_gateway_token_hash` 强制失败（M41-S2 F-2 失败路径用例）。
    /// 生产代码永不 arm；一次性，用后自动清零。
    fail_next_token_hash_update: std::sync::atomic::AtomicBool,
}

/// `scheme://user:pass@host/...` 里的 `user:pass@host` 部分（**不含**路径 / query / fragment）。
///
/// 返回的是带 userinfo 的整个 authority，而不是只返回 userinfo：被修的历史数据形态是
/// `display_name == "alice:pw@host.example"`（当时的 `host_of` 把整个 authority 当成了 host）。
/// 逐字比对整段 ⇒ 零误伤。
fn authority_of(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    Some(authority.to_string())
}

/// 从 URL 里取 host[:port]（不含 userinfo、不含路径）。取不到时原样返回。
fn host_of_url(url: &str) -> String {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    if host.is_empty() {
        url.to_string()
    } else {
        host.to_string()
    }
}

/// SQLite 的「忙 / 锁」错误判定——按**错误码**而不是错误串。
///
/// 只给 [`Store::open`] 的 WAL 重试循环用：那个循环只该吞掉「别人正拿着锁」这一类，
/// 磁盘满 / 权限 / 语法错必须原样冒泡。
fn is_sqlite_busy(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(
                inner.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            )
    )
}

/// 表里有没有这一列。
fn column_exists(conn: &rusqlite::Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| Error::Store(format!("读取表结构失败: {e}")))?;
    let existing: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| Error::Store(format!("读取表结构失败: {e}")))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Store(format!("读取表结构失败: {e}")))?;
    Ok(existing.iter().any(|name| name == column))
}

/// 直接 `ALTER TABLE ... ADD COLUMN`，**不做存在性判断**。
///
/// 只给 [`add_column_if_missing`] 与竞态测试用：把「判存在」与「加列」拆开，
/// 竞态测试才能**确定性地**复现「判完存在之后、加列之前，别人先加上了」这个窗口。
fn add_column_unchecked(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
    decl: &str,
) -> Result<()> {
    conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"))
        .map_err(|e| Error::Store(format!("为 {table} 增加 {column} 列失败: {e}")))
}

/// 表里没有这一列时才 `ALTER TABLE` 加上它。
///
/// 为什么不能直接 `ALTER TABLE ... ADD COLUMN`：`migrate()` 每次打开都跑，
/// 第二次会因 `duplicate column name` 失败。为什么也不能只靠 DDL：
/// `CREATE TABLE IF NOT EXISTS` 对已存在的表是空操作，加列不会生效（M8-S4 §5.2）。
///
/// **并发安全**（M16-S1 / P3-1）：进程内由 `migrate()` 持有的 `Mutex` 串行化 ✓；
/// 跨**进程**（或跨连接）首次打开同一个老库时，两个连接可能都判「不存在」，
/// 其中一个先加完 ⇒ 另一个的 `ALTER` 撞 `duplicate column name`。
/// 处置：**失败后复验**——列确实在了 ⇒ 视为成功（幂等）；仍不在 ⇒ 原样冒泡
/// （表不存在、语法错这类真错误**不许**被吞）。
/// 注意判据是**复验结果**而不是错误串匹配：错误串是 SQLite 的实现细节，
/// 而「列在不在」是我们要的事实。
fn add_column_if_missing(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
    decl: &str,
) -> Result<()> {
    add_column_if_missing_with(conn, table, column, decl, || {})
}

/// 与 [`add_column_if_missing`] 相同，但在**「查列」与「ALTER」之间**留一个窗口回调。
///
/// 存在的唯一理由：那条竞态（另一个连接在这个窗口里把列加上）**必须能被确定性复现**——
/// 否则测试只能靠概率碰（报告实测 18/400），而概率型用例的「绿」不代表修复有效
/// （实测：不留这个窗口时，把修复退回旧实现，用例照样绿 ⇒ 假绿）。
/// 生产路径传空闭包，编译后无开销。
fn add_column_if_missing_with(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
    decl: &str,
    window: impl FnOnce(),
) -> Result<()> {
    if column_exists(conn, table, column)? {
        return Ok(());
    }
    window();
    match add_column_unchecked(conn, table, column, decl) {
        Ok(()) => Ok(()),
        Err(err) => {
            if column_exists(conn, table, column)? {
                Ok(())
            } else {
                Err(err)
            }
        }
    }
}

/// WAL 切换的等待预算（B-156 / M24-S1）。
///
/// 取 10s 的理由：它必须**大于** `tests/store_wal_lock_retry.rs` 那条确定性用例的持锁时长
/// （6s，判据是「熬过忙等超时」），留约 1.7× 余量；同时把旧的 ≈206s 上界压到 ~10s（低一个数量级）。
const WAL_LOCK_BUDGET: Duration = Duration::from_secs(10);

/// 预算内的轮询间隔。关掉忙等之后，每次尝试都是**立即**返回的 `SQLITE_BUSY`。
const WAL_RETRY_INTERVAL: Duration = Duration::from_millis(25);

/// `busy_timeout` 的**通用**取值：服务建表 / `migrate` 等普通语句，**不是** WAL 那条 pragma
/// （那条由 [`WAL_LOCK_BUDGET`] 单独管，见 `open_with_budget` 的注释）。
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

fn map_gateway_token_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<GatewayTokenRow> {
    Ok(GatewayTokenRow {
        id: row.get(0)?,
        token_hash: row.get(1)?,
        label: row.get(2)?,
        created_at: row.get(3)?,
        revoked_at: row.get(4)?,
        last_used_at: row.get(5)?,
        is_default: row.get::<_, i64>(6)? != 0,
    })
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_budget(path, WAL_LOCK_BUDGET)
    }

    /// `budget` 可注入**只为测试**：B-140 的教训是不可注入的预算只能靠「等 3.5 分钟」来验。
    fn open_with_budget(path: &Path, budget: Duration) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Store(format!("创建数据目录失败: {e}")))?;
        }
        let conn =
            Connection::open(path).map_err(|e| Error::Store(format!("打开数据库失败: {e}")))?;
        // **忙等超时**（M16-S1 / P3-1 的另一半）：并发首次打开同一个库时
        // （多进程 / 多线程），建表与其它语句都要拿写锁——不设忙等的话，
        // 另一个连接正在建表就会立刻 `database is locked`，`Store::open` 失败。
        // 5s 覆盖「另一个进程正在跑 migrate」这段窗口，又不会让真死锁挂太久。
        conn.busy_timeout(BUSY_TIMEOUT)
            .map_err(|e| Error::Store(format!("设置忙等超时失败: {e}")))?;
        // 文件库必须真的跑在 WAL 上（并发读+写）。内存库不支持 WAL，只在 open_in_memory 分支跳过。
        //
        // **这一步单独处理，并且刻意关掉忙等**（B-156 / M24-S1）：
        // `PRAGMA journal_mode = WAL` 需要**独占锁**，而忙等在这条路径上**确实生效**——
        // 证据是 B-140 那条确定性用例：另一个连接 `BEGIN EXCLUSIVE` 持锁 6s 时，
        // `busy_timeout(5s)` 会先等满 5s 才拿到 `SQLITE_BUSY`（短于 5s 的争用光靠忙等就扛过去了）。
        // 旧实现留着忙等、再用 40 次盲重试兜底 ⇒ 最坏 41 × (5s + 25ms) ≈ **206s**
        // （M16-S10 实测 213.6s）；而旧注释写的是「这条路径不调用忙等处理器 ⇒ `busy_timeout`
        // 对它无效、预算 ≈1s」——**那句话与实测不符**，正是 B-156 要修的东西。
        //
        // **为什么还要重试**：并发首次打开同一个老库时，多个进程都要把日志模式从
        // rollback journal 切到 WAL，而这一步要独占锁 ⇒ 撞锁是**常态**而不是异常
        // （`concurrent_first_upgrade_of_an_old_database_all_succeed` 实测 20%~28% 命中
        // `database is locked`）。没有重试，正常启动就会随机失败。
        //
        // 现在的口径：**关掉忙等，等待只由 `budget` 控制**。每次尝试都是立即返回的
        // `SQLITE_BUSY`，按 `WAL_RETRY_INTERVAL` 轮询，直到锁释放或预算耗尽。
        // 判据用**错误码**（`DatabaseBusy` / `DatabaseLocked`）而不是错误串：
        // 错误串是实现细节，别的错误（磁盘满、权限）**不许**被这个循环吞掉。
        conn.busy_timeout(Duration::ZERO)
            .map_err(|e| Error::Store(format!("关闭忙等失败: {e}")))?;
        let started = Instant::now();
        let mut wal_attempts = 0u32;
        loop {
            match conn.pragma_update(None, "journal_mode", "WAL") {
                Ok(()) => break,
                Err(err) if is_sqlite_busy(&err) && started.elapsed() < budget => {
                    wal_attempts += 1;
                    std::thread::sleep(WAL_RETRY_INTERVAL);
                }
                Err(err) => {
                    return Err(Error::Store(format!(
                        "切换 WAL 模式失败（重试 {wal_attempts} 次 / 预算 {}s 后）: {err}",
                        budget.as_secs()
                    )))
                }
            }
        }
        // 恢复忙等：`migrate()` 与后续普通语句要它（P3-1 的另一半就在这里）。
        // 恢复失败不许静默——否则「打开成功、之后所有并发写都不再等待」，比失败更糟。
        conn.busy_timeout(BUSY_TIMEOUT)
            .map_err(|e| Error::Store(format!("恢复忙等超时失败: {e}")))?;
        let store = Self::from_conn(conn)?;
        // 记下路径（`from_conn` 不关心路径）
        Ok(Self {
            conn: store.conn,
            path: Some(path.to_path_buf()),
            fail_next_token_hash_update: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| Error::Store(format!("打开内存库失败: {e}")))?;
        Self::from_conn(conn)
    }

    fn from_conn(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| Error::Store(format!("开启外键失败: {e}")))?;
        let store = Self {
            conn: Mutex::new(conn),
            path: None,
            fail_next_token_hash_update: std::sync::atomic::AtomicBool::new(false),
        };
        store.migrate()?;
        // P2-1：接线显示名 userinfo 剥离迁移（DEBUG-REPORT-v3 P2 #1）。
        // M7 老库里 display_name 仍带 `user:pw@host`，拼进通知后 webhook 两层
        // 脱敏都掩不掉。迁移函数写对了但只在测试里调用——open 时自动跑（幂等）。
        store.migrate_display_names_stripping_userinfo()?;
        Ok(store)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| Error::Store("数据库锁已中毒".into()))
    }

    fn migrate(&self) -> Result<()> {
        let conn = self.lock()?;
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|e| Error::Store(format!("读取 schema 版本失败: {e}")))?;

        // **每次都跑 DDL**，而不是只在版本变化时跑。
        //
        // DDL 里全是 `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`，天然幂等。
        // 只在 `version < SCHEMA_VERSION` 时跑会有一个隐蔽后果：往 DDL 里**新增**表
        // 却不改版本号时，已经存在的库永远建不出那张新表——
        // 实测：加了 `consents` 之后，跑过旧版的 `~/.tianshu-relay/tianshu-relay.db` 里依然没有该表，
        // `grant_consent` 会直接报 `no such table`（M1-S4 真实启动时发现）。
        conn.execute_batch(DDL)
            .map_err(|e| Error::Store(format!("建表失败: {e}")))?;

        // **加列必须显式迁移**（M8-S4 §5.2）。DDL 里全是 `CREATE TABLE IF NOT EXISTS`——
        // 对**已存在**的表它是空操作，所以往建表语句里加一列，老库永远不会有那一列。
        // 这正是 `keys.status` 那个形态：列在 DDL 里、老库里没有。
        //
        // **必须先判存在**：不判的话第二次打开会因 `duplicate column name` 直接失败——
        // 而 `migrate()` 是每次打开都跑的。
        add_column_if_missing(&conn, "bindings", "unbound_at", "INTEGER")?;
        // P1-2：投递模式（轮换按它走）。老库默认 "site"（既有行为）。
        add_column_if_missing(
            &conn,
            "bindings",
            "delivery_mode",
            "TEXT NOT NULL DEFAULT 'site'",
        )?;
        // B-135：probe_runs.status（bazaarlink run 生命周期，SCHEMA_VERSION 5 → 6）。
        // 老行留 NULL 而**不回填**：「有 verdict ⇒ completed」是推断不是观测，
        // 历史行当时到底跑没跑完没人知道——NULL 就是「没记过」，界面显示 "—"。
        add_column_if_missing(&conn, "probe_runs", "status", "TEXT")?;
        // M40-S1（SCHEMA_VERSION 7 → 8）：网关用量账本六列。
        add_column_if_missing(
            &conn,
            "gateway_usage_log",
            "at",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        add_column_if_missing(&conn, "gateway_usage_log", "key_id", "INTEGER")?;
        add_column_if_missing(
            &conn,
            "gateway_usage_log",
            "status",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        add_column_if_missing(
            &conn,
            "gateway_usage_log",
            "latency_ms",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        add_column_if_missing(
            &conn,
            "gateway_usage_log",
            "attempts",
            "INTEGER NOT NULL DEFAULT 1",
        )?;
        add_column_if_missing(
            &conn,
            "gateway_usage_log",
            "stream",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        // 索引必须在 `at` 列补齐**之后**建：老库的 DDL 阶段还没有 at 列，
        // 把 CREATE INDEX 放进 DDL 批会报 `no such column: at`（新库/老库都得走这里）。
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_gateway_usage_at ON gateway_usage_log(at DESC)",
            [],
        )
        .map_err(|e| Error::Store(format!("建 gateway_usage_at 索引失败: {e}")))?;
        // M46-S5：预算已花 SUM 的范围扫描索引。必须在 at / key_id 列补齐之后建
        // （见 DDL 末尾注释）：老库的 DDL 阶段还没有这两列，放进 DDL 批会直接
        // 让 migrate 在老库上失败（schema_v8 迁移测试即为此回归的哨兵）。
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_gateway_usage_budget_site ON gateway_usage_log(site_id, at)",
            [],
        )
        .map_err(|e| Error::Store(format!("建 gateway_usage_budget_site 索引失败: {e}")))?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_gateway_usage_budget_key ON gateway_usage_log(key_id, at)",
            [],
        )
        .map_err(|e| Error::Store(format!("建 gateway_usage_budget_key 索引失败: {e}")))?;
        if version < 8 {
            // 一次性回填：旧行的 at 取 ts（**近似，不是观测**——当时没记完成时刻）。
            // 不回填成 0：否则看板会把旧账显示成 1970。
            conn.execute("UPDATE gateway_usage_log SET at = ts WHERE at = 0", [])
                .map_err(|e| Error::Store(format!("回填 gateway_usage_log.at 失败: {e}")))?;
        }
        // M43-S1（SCHEMA_VERSION 8 → 9）：令牌表与 usage 归因两列。
        // `gateway_tokens` 由 DDL 一次建全（新库）；预发布构建可能建过没有 is_default 的旧表 ⇒ 补列。
        add_column_if_missing(
            &conn,
            "gateway_tokens",
            "is_default",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        add_column_if_missing(
            &conn,
            "gateway_usage_log",
            "token_id",
            "INTEGER REFERENCES gateway_tokens(id) ON DELETE SET NULL",
        )?;
        add_column_if_missing(
            &conn,
            "gateway_usage_log",
            "agent_label",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_gateway_usage_token ON gateway_usage_log(token_id, ts DESC)",
            [],
        )
        .map_err(|e| Error::Store(format!("建 gateway_usage_token 索引失败: {e}")))?;
        // M43-S2（SCHEMA_VERSION 9 → 10）：站点自报 cost 的「有没有上报」标记。
        // 老行取 0 = **未上报**（不是「真的 0」）；读侧据此显示「未知」，**不回填**
        //（回填是推断不是观测，与 probe_runs.status 同一条纪律）。
        add_column_if_missing(
            &conn,
            "usage_samples",
            "cost_reported",
            "INTEGER NOT NULL DEFAULT 0",
        )?;

        // 版本号仍然只在升级时写，保留它作为「将来需要非幂等迁移」的锚点。
        if version < SCHEMA_VERSION {
            conn.pragma_update(None, "user_version", SCHEMA_VERSION)
                .map_err(|e| Error::Store(format!("写入 schema 版本失败: {e}")))?;
        }
        Ok(())
    }

    /// 文件库的路径；内存库返回 `None`。
    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }

    pub fn schema_version(&self) -> Result<i64> {
        let conn = self.lock()?;
        conn.pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|e| Error::Store(format!("读取 schema 版本失败: {e}")))
    }

    /// 按 `base_url` 去重写入，返回站点 id
    pub fn upsert_site(&self, kind: &str, base_url: &str, display_name: &str) -> Result<i64> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO sites(kind, base_url, display_name, created_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(base_url) DO UPDATE SET kind = ?1, display_name = ?3",
            params![kind, base_url, display_name, now_secs()],
        )
        .map_err(|e| Error::Store(format!("写入站点失败: {e}")))?;
        conn.query_row(
            "SELECT id FROM sites WHERE base_url = ?1",
            params![base_url],
            |row| row.get(0),
        )
        .map_err(|e| Error::Store(format!("读取站点 id 失败: {e}")))
    }

    pub fn list_sites(&self) -> Result<Vec<SiteRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT id, kind, base_url, display_name, health FROM sites ORDER BY id")
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(SiteRow {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    base_url: row.get(2)?,
                    display_name: row.get(3)?,
                    health: row.get(4)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询站点失败: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取站点行失败: {e}")))
    }

    /// 迁移用：枚举所有「密钥落点引用」。
    ///
    /// 钥匙串没有枚举接口（ADR-0002 §2），所以迁移只能从**索引侧**反查：
    /// `keys.secret_ref` ∪ `accounts.credential_ref` ∪ 每个站点的会话引用
    /// （站点会话不在任何列里，是按 `kr/site/<id>/session` 约定拼出来的）。
    ///
    /// 去重后按字典序返回，保证迁移日志与测试可复现。
    pub fn all_secret_refs(&self) -> Result<Vec<String>> {
        let conn = self.lock()?;
        let mut refs = std::collections::BTreeSet::new();

        let mut stmt = conn
            .prepare("SELECT secret_ref FROM keys")
            .map_err(|e| Error::Store(format!("准备查询密钥引用失败: {e}")))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| Error::Store(format!("查询密钥引用失败: {e}")))?;
        for row in rows {
            let value = row.map_err(|e| Error::Store(format!("读取密钥引用失败: {e}")))?;
            // 只收合法引用：历史库里可能有非 `kr/...` 的脏值，带进迁移会让它每次都失败。
            if crate::vault::is_valid_secret_ref(&value) {
                refs.insert(value);
            }
        }

        let mut stmt = conn
            .prepare("SELECT credential_ref FROM accounts")
            .map_err(|e| Error::Store(format!("准备查询账号引用失败: {e}")))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| Error::Store(format!("查询账号引用失败: {e}")))?;
        for row in rows {
            let value = row.map_err(|e| Error::Store(format!("读取账号引用失败: {e}")))?;
            if crate::vault::is_valid_secret_ref(&value) {
                refs.insert(value);
            }
        }

        let mut stmt = conn
            .prepare("SELECT id FROM sites")
            .map_err(|e| Error::Store(format!("准备查询站点 id 失败: {e}")))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, i64>(0))
            .map_err(|e| Error::Store(format!("查询站点 id 失败: {e}")))?;
        for row in rows {
            let id = row.map_err(|e| Error::Store(format!("读取站点 id 失败: {e}")))?;
            refs.insert(crate::vault::secret_ref("site", id, "session"));
        }

        Ok(refs.into_iter().collect())
    }

    pub fn get_site(&self, id: i64) -> Result<Option<SiteRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT id, kind, base_url, display_name, health FROM sites WHERE id = ?1")
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let mut rows = stmt
            .query_map(params![id], |row| {
                Ok(SiteRow {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    base_url: row.get(2)?,
                    display_name: row.get(3)?,
                    health: row.get(4)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询站点失败: {e}")))?;

        match rows.next() {
            Some(Ok(row)) => Ok(Some(row)),
            Some(Err(e)) => Err(Error::Store(format!("读取站点行失败: {e}"))),
            None => Ok(None),
        }
    }

    pub fn delete_site(&self, id: i64) -> Result<()> {
        let conn = self.lock()?;
        conn.execute("DELETE FROM sites WHERE id = ?1", params![id])
            .map_err(|e| Error::Store(format!("删除站点失败: {e}")))?;
        Ok(())
    }

    /// `secret_ref` 必须是钥匙串引用（`kr/<scope>/<id>/<field>`），禁止传明文
    ///
    /// `group_name` 是**调用方给的权威值**（新建密钥时用户刚填的那个分组）。
    /// 传 `None` 表示「不知道」⇒ 落 `NULL`，界面显示空——**绝不猜**：
    /// `sync_site_keys` 的导入路径就传 `None`，那条路的名字都是从 `KeyMeta` 反查的，
    /// 分组同样没有权威来源。
    ///
    /// `status` **刻意不写**：它是本地词表（见本模块顶部 `KEY_STATUS_REVOKED` 的说明），
    /// `DEFAULT 'unknown'` 的正确含义是「本产品没对这把钥匙做过任何事」。
    /// 新建时写一个站点侧状态会把两套语义混成一列（M8-S5B §6.5）。
    pub fn insert_key(
        &self,
        site_id: i64,
        name: &str,
        secret_ref: &str,
        remote_id: Option<&str>,
        group_name: Option<&str>,
    ) -> Result<i64> {
        // 签名一个参数都不加（调用点从 65 降到 62：4 处改用 `insert_key_with_group`、
        // 1 处新增内联测试；其余 61 处逐字未动）。委托给带分组 id 的那一版，
        // 传 `None` ⇒ `keys.group_id` 落 `NULL`，与 M22-S1 之前的落库形态逐字一致。
        self.insert_key_with_group(site_id, name, secret_ref, remote_id, group_name, None)
    }

    /// 与 [`Self::insert_key`] 同一条语句，但**同时**写分组标识（M22-S2 / B-172）。
    ///
    /// 为什么是**新方法**而不是给 `insert_key` 加参数：它的 65 处调用点里绝大多数是测试
    /// （生产只有 3 处），加参数会让改动淹在机械修改里，且每一处都要重新判断「这里该传什么」。
    ///
    /// 为什么不再保留 M22-S1 的 `set_key_group`（"先插行、再补 id"）：那条路径
    /// **两写不原子**，第二写失败只能吞成 Warn 事件 ⇒ 库里留下「行在、id 缺」的中间态，
    /// 而这条形态没有任何非测试消费者，留着它等于留第二个写入口径。现在两列在
    /// **同一条 INSERT** 里，要么都落、要么整行不写。
    ///
    /// `group_id` 是站点原生主键（Sub2API 的数字 id）；`group_name` 是给人看的名字。
    /// 两者都可以是 `None`（NewAPI 没有 id 概念 / 调用方不知道名字）。
    pub fn insert_key_with_group(
        &self,
        site_id: i64,
        name: &str,
        secret_ref: &str,
        remote_id: Option<&str>,
        group_name: Option<&str>,
        group_id: Option<&str>,
    ) -> Result<i64> {
        if !is_valid_secret_ref(secret_ref) {
            return Err(Error::Store(format!(
                "secret_ref 必须是钥匙串引用（kr/<scope>/<id>/<field>），拒绝写入疑似明文: {}",
                crate::redact::scrub(secret_ref)
            )));
        }
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO keys(site_id, remote_id, name, secret_ref, created_at, group_name, group_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                site_id,
                remote_id,
                name,
                secret_ref,
                now_secs(),
                group_name,
                group_id
            ],
        )
        .map_err(|e| Error::Store(format!("写入密钥记录失败: {e}")))?;
        Ok(conn.last_insert_rowid())
    }

    /// 按 id 取单条密钥记录（投递时用它拿 `secret_ref`）。
    pub fn get_key(&self, id: i64) -> Result<Option<KeyRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, site_id, remote_id, name, group_name, secret_ref, status, created_at,
                        quota_used, quota_limit, currency, group_id
                 FROM keys WHERE id = ?1",
            )
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let mut rows = stmt
            .query_map(params![id], |row| {
                Ok(KeyRow {
                    id: row.get(0)?,
                    site_id: row.get(1)?,
                    remote_id: row.get(2)?,
                    name: row.get(3)?,
                    group_name: row.get(4)?,
                    secret_ref: row.get(5)?,
                    status: row.get(6)?,
                    created_at: row.get(7)?,
                    quota_used: row.get(8)?,
                    quota_limit: row.get(9)?,
                    currency: row.get(10)?,
                    group_id: row.get(11)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询密钥失败: {e}")))?;
        match rows.next() {
            Some(row) => {
                Ok(Some(row.map_err(|e| {
                    Error::Store(format!("读取密钥行失败: {e}"))
                })?))
            }
            None => Ok(None),
        }
    }

    /// 记录一次投递绑定（agent ← key → 目标文件）。
    pub fn record_binding(
        &self,
        agent_id: &str,
        key_id: i64,
        target_path: &str,
        journal_id: &str,
        delivery_mode: &str,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO bindings(agent_id, key_id, target_path, applied_at, journal_id, delivery_mode)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![agent_id, key_id, target_path, now_secs(), journal_id, delivery_mode],
        )
        .map_err(|e| Error::Store(format!("写入投递绑定失败: {e}")))?;
        Ok(())
    }

    /// 解绑一个 agent 与它的密钥（FR-2:115）。**默认只解绑不回收**（可恢复）。
    ///
    /// **解绑不是删除**：`bindings` 行**保留**，只写 `unbound_at`。
    /// 删行会连带丢掉 `managed_json` / `journal_id`（回滚要靠它），
    /// 而 `keys.id` 是漂移追溯链的起点——与 B-82 同一条纪律（M7-S4 spec §6.1 有实测）。
    ///
    /// **幂等**：命中已解绑的行时**不刷新时间戳**，只计入 `already_unbound`。
    /// 刷新时间戳会让「什么时候解绑的」随着重复点击漂移。
    pub fn unbind_agent(&self, agent_id: &str) -> Result<UnbindReport> {
        self.unbind_where("agent_id = ?1", &[&agent_id])
    }

    /// 只解绑**某一个目标文件**上的绑定（同一 agent 可能有多个落点）。
    pub fn unbind_target(&self, target_path: &str) -> Result<UnbindReport> {
        self.unbind_where("target_path = ?1", &[&target_path])
    }

    fn unbind_where(
        &self,
        predicate: &str,
        params: &[&dyn rusqlite::ToSql],
    ) -> Result<UnbindReport> {
        let conn = self.lock()?;
        // 先数「早已解绑」的：`UPDATE` 的 `changes()` 只报**真的改了**的行数，
        // 而用户需要知道「本来就是解绑状态」与「这次才解开」的区别（UI 两种文案）。
        let already_unbound: usize = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM bindings WHERE {predicate} AND unbound_at IS NOT NULL"
                ),
                params,
                |row| row.get::<_, i64>(0),
            )
            .map_err(|e| Error::Store(format!("统计解绑记录失败: {e}")))?
            .max(0) as usize;
        // 时间戳**内联**成一个整数字面量而不是占位符：谓词里的占位符编号由调用方给，
        // 再塞一个 `?2` 会让「谓词有几个参数」与「这条语句要几个参数」耦合成一个陷阱
        // （第一版就是这么写的，实测 `Wrong number of parameters`）。
        // 值是 `i64`，不来自任何外部输入，拼接是安全的。
        let unbound = conn
            .execute(
                &format!(
                    "UPDATE bindings SET unbound_at = {} WHERE {predicate} AND unbound_at IS NULL",
                    now_secs()
                ),
                params,
            )
            .map_err(|e| Error::Store(format!("写入解绑标记失败: {e}")))?;
        Ok(UnbindReport {
            unbound,
            already_unbound,
        })
    }

    /// 一个 agent 的绑定（含已解绑的行——`also_revoke` 要按**当时的**绑定去回收）。
    pub fn bindings_of_agent(&self, agent_id: &str) -> Result<Vec<BindingRow>> {
        self.bindings_where("b.agent_id = ?1", &[&agent_id])
    }

    /// 某一个目标文件上的绑定。
    pub fn bindings_of_target(&self, target_path: &str) -> Result<Vec<BindingRow>> {
        self.bindings_where("b.target_path = ?1", &[&target_path])
    }

    /// 全部绑定（含已解绑的行）。
    ///
    /// 给**批量**动作用（M8-S7 / B-116：「把已投递的通道批量改指网关」要拿到全部候选）。
    /// 单 agent 的场景请用 [`Self::bindings_of_agent`]——那个有 predicate，不会把
    /// 无关 agent 的行也拉回来。
    pub fn all_bindings(&self) -> Result<Vec<BindingRow>> {
        self.bindings_where("1 = 1", &[])
    }

    /// **当前生效**的通道绑定（P2-16 / DEBUG-REPORT-v3 §2-16）：给 `channel_bindings`
    /// （批量改指候选、UI 现状）用。
    ///
    /// 与 [`Self::all_bindings`] 的区别：同一个 `(agent_id, key_id, target_path)` 上
    /// 多次重投时，只保留**最新一行**——被同 key 的更新投递取代的旧行不再作为候选列出。
    /// 否则每重投一次批量候选就多一条重复行（2→4→…），用户对着同一个「文件 × key」
    /// 看到多个复选框，选了旧的那条等于白写一次（P1-1 误删的根因正是这些旧行）。
    ///
    /// 口径与 [`Self::delivery_history`] 的 `superseded` 一致：**同 key 的更新投递**
    /// 取代旧的；但**换 key 重投**（同 target 不同 key）不算取代——两条都是独立绑定、
    /// 各自成行（M8-S7 P2-4，`list_channel_bindings_filters_out_unbound_rows` 钉住）。
    /// 已解绑（`unbound_at IS NOT NULL`）的行也不返回。
    ///
    /// 旧行不删（溯源靠它），只是不进候选；看历史走 [`Self::delivery_history`]。
    pub fn current_bindings(&self) -> Result<Vec<BindingRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT b.id, b.agent_id, b.key_id, b.target_path, b.applied_at, b.unbound_at,
                        k.site_id, k.remote_id, b.delivery_mode
                 FROM bindings b JOIN keys k ON k.id = b.key_id
                 WHERE b.unbound_at IS NULL
                   AND b.id = (SELECT MAX(b2.id) FROM bindings b2
                               WHERE b2.agent_id = b.agent_id
                                 AND b2.key_id = b.key_id
                                 AND b2.target_path = b.target_path)
                 ORDER BY b.id",
            )
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(BindingRow {
                    id: row.get(0)?,
                    agent_id: row.get(1)?,
                    key_id: row.get(2)?,
                    target_path: row.get(3)?,
                    applied_at: row.get(4)?,
                    unbound_at: row.get(5)?,
                    site_id: row.get(6)?,
                    remote_id: row.get(7)?,
                    delivery_mode: row.get(8)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询绑定失败: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取绑定行失败: {e}")))
    }

    /// 投递历史，最新的在前（M9-S4）。只读。
    ///
    /// **`limit` 只截历史，不截现状**（复审 P2-4）：返回最近 `limit` 行，**外加**所有
    /// `superseded = false` 的行——每个目标的「现状」（当前生效、可以回滚的那次，以及在它之后
    /// 被回滚掉的那几次）不管多早都在。否则一个早就投递、一直生效的目标会被之后别的投递挤出
    /// 历史页，「当前生效的投递都能在这里回滚」就不成立；「最后一次是被你回滚掉的」也得看得见——
    /// 总览把这种目标报成需要处理时（B-126），用户要能在历史页找到原因。
    /// 被截掉的只有更早、已被覆盖的记录——界面本来就不让回滚它们（真回滚通常也会被拒，例外见 `superseded`）。
    ///
    /// `superseded` 的两条口径（M9-S4 spec §5）：
    /// - **已解绑**的更新投递也算覆盖：解绑不改文件，文件里仍是那次写下的内容；
    /// - **已回滚**的更新投递不算覆盖：回滚把文件还原成它之前的样子，也就是更早那次写下的样子。
    ///
    /// 这只是界面上的预判；真正的安全闸仍是 `inject::rollback` 的哈希校验。
    pub fn delivery_history(&self, limit: usize) -> Result<Vec<DeliveryHistoryRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "WITH h AS (
                   SELECT b.id AS id, COALESCE(b.journal_id, '') AS journal_id,
                          b.agent_id AS agent_id, b.key_id AS key_id, k.site_id AS site_id,
                          b.target_path AS target_path, b.applied_at AS applied_at,
                          b.unbound_at AS unbound_at, j.backup_path AS backup_path,
                          j.id IS NOT NULL AS has_journal,
                          COALESCE(j.status, '') = 'rolled_back' AS rolled_back,
                          EXISTS (SELECT 1 FROM bindings n
                                  LEFT JOIN journals nj ON nj.id = n.journal_id || ':' || n.target_path
                                  WHERE n.target_path = b.target_path
                                    AND n.id > b.id
                                    AND COALESCE(nj.status, 'applied') <> 'rolled_back') AS superseded,
                          ROW_NUMBER() OVER (ORDER BY b.id DESC) AS rn
                   FROM bindings b
                   JOIN keys k ON k.id = b.key_id
                   LEFT JOIN journals j ON j.id = b.journal_id || ':' || b.target_path
                 )
                 SELECT id, journal_id, agent_id, key_id, site_id, target_path, applied_at,
                        unbound_at, backup_path, has_journal, rolled_back, superseded
                 FROM h
                 WHERE rn <= ?1 OR NOT superseded
                 ORDER BY id DESC",
            )
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let rows = stmt
            .query_map(params![i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
                Ok(DeliveryHistoryRow {
                    binding_id: row.get(0)?,
                    journal_id: row.get(1)?,
                    agent_id: row.get(2)?,
                    key_id: row.get(3)?,
                    site_id: row.get(4)?,
                    target_path: row.get(5)?,
                    applied_at: row.get(6)?,
                    unbound_at: row.get(7)?,
                    backup_path: row.get(8)?,
                    has_journal: row.get(9)?,
                    rolled_back: row.get(10)?,
                    superseded: row.get(11)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询投递历史失败: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取投递历史行失败: {e}")))
    }

    /// 把一个 journal 的全部行记为已回滚，返回改动行数（M9-S4）。
    ///
    /// 前缀匹配与 [`Self::journal_entries`] 同一写法：`LIKE` 的通配符会让含 `%` / `_` 的 id 误中。
    pub fn mark_journal_rolled_back(&self, journal_id: &str) -> Result<usize> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE journals SET status = 'rolled_back' WHERE instr(id, ?1 || ':') = 1",
            params![journal_id],
        )
        .map_err(|e| Error::Store(format!("记录回滚状态失败: {e}")))
    }

    fn bindings_where(
        &self,
        predicate: &str,
        params: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<BindingRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT b.id, b.agent_id, b.key_id, b.target_path, b.applied_at, b.unbound_at,
                        k.site_id, k.remote_id, b.delivery_mode
                 FROM bindings b JOIN keys k ON k.id = b.key_id
                 WHERE {predicate}
                 ORDER BY b.id"
            ))
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let rows = stmt
            .query_map(params, |row| {
                Ok(BindingRow {
                    id: row.get(0)?,
                    agent_id: row.get(1)?,
                    key_id: row.get(2)?,
                    target_path: row.get(3)?,
                    applied_at: row.get(4)?,
                    unbound_at: row.get(5)?,
                    site_id: row.get(6)?,
                    remote_id: row.get(7)?,
                    delivery_mode: row.get(8)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询绑定失败: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取绑定行失败: {e}")))
    }

    /// 把 `sites.display_name` 里**逐字等于该站点 `base_url` 的 userinfo** 的行改写成 host。
    ///
    /// M7 版本录入 `https://alice:pw@host` 时，`display_name` 被写成了 `alice:pw@host`
    /// （`custom_openai::host_of` 当时的形态）。那条数据**已经入库**，而文本级脱敏
    /// 没有 `://` 抓不到它——所以通知与 webhook 正文会持续带出密码（DEBUG 报告 §1.3 / 复审 P2-4）。
    ///
    /// **判据是「逐字等于」而不是「看起来像 URL」**：只有 `display_name` 与从 `base_url`
    /// 里剥出来的 userinfo 完全一致时才改写，所以**零误伤**——一个用户真的想把显示名
    /// 取成 `alice:pw@host` 的情形，与这条迁移想修的形态在字节上无法区分，
    /// 但那种命名本身没有意义，代价可接受。
    pub fn migrate_display_names_stripping_userinfo(&self) -> Result<usize> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT id, base_url, display_name FROM sites")
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let rows: Vec<(i64, String, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|e| Error::Store(format!("查询站点失败: {e}")))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取站点行失败: {e}")))?;
        drop(stmt);

        let mut changed = 0usize;
        for (id, base_url, display_name) in rows {
            // **判据是「逐字等于带 userinfo 的 authority」**，不是「看起来像 userinfo」。
            //
            // 被修的那种形态是 `custom_openai::host_of` 当时产出的：它把整个 authority
            // 当成了 host，所以 `display_name` 是 `alice:pw@host.example`
            // （含 `@` 与 host），不是 `alice:pw`。逐字相等 ⇒ 零误伤。
            let Some(authority) = authority_of(&base_url) else {
                continue;
            };
            if display_name != authority || !authority.contains('@') {
                continue;
            }
            let stripped = crate::redact::strip_url_userinfo(&base_url);
            let host = host_of_url(&stripped);
            conn.execute(
                "UPDATE sites SET display_name = ?1 WHERE id = ?2",
                rusqlite::params![host, id],
            )
            .map_err(|e| Error::Store(format!("改写显示名失败: {e}")))?;
            changed += 1;
        }
        Ok(changed)
    }

    /// 还原一个 journal 的条目，供 `rollback_delivery` 重建 `Journal`。
    ///
    /// 用 `instr(...) = 1` 做前缀匹配而不是 `LIKE`：`LIKE` 的通配符会让
    /// 含 `%` / `_` 的 id 匹配到别的 journal。
    pub fn journal_entries(&self, journal_id: &str) -> Result<Vec<crate::inject::JournalEntry>> {
        use crate::inject::JournalEntry;
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT target_path, backup_path, before_sha256, after_sha256
                 FROM journals WHERE instr(id, ?1 || ':') = 1 ORDER BY rowid",
            )
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let rows = stmt
            .query_map(params![journal_id], |row| {
                Ok(JournalEntry {
                    path: std::path::PathBuf::from(row.get::<_, String>(0)?),
                    backup: row
                        .get::<_, Option<String>>(1)?
                        .map(std::path::PathBuf::from),
                    before_sha256: row.get(2)?,
                    after_sha256: row.get(3)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询变更记录失败: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取变更记录行失败: {e}")))
    }

    pub fn list_keys(&self) -> Result<Vec<KeyRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, site_id, remote_id, name, group_name, secret_ref, status, created_at,
                        quota_used, quota_limit, currency, group_id
                 FROM keys ORDER BY id",
            )
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(KeyRow {
                    id: row.get(0)?,
                    site_id: row.get(1)?,
                    remote_id: row.get(2)?,
                    name: row.get(3)?,
                    group_name: row.get(4)?,
                    secret_ref: row.get(5)?,
                    status: row.get(6)?,
                    created_at: row.get(7)?,
                    quota_used: row.get(8)?,
                    quota_limit: row.get(9)?,
                    currency: row.get(10)?,
                    group_id: row.get(11)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询密钥失败: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取密钥行失败: {e}")))
    }

    pub fn record_journal(&self, journal: &Journal) -> Result<()> {
        let conn = self.lock()?;
        for entry in &journal.entries {
            conn.execute(
                "INSERT OR REPLACE INTO journals
                 (id, ts, op, target_path, before_sha256, after_sha256, backup_path, status)
                 VALUES (?1, ?2, 'inject', ?3, ?4, ?5, ?6, 'applied')",
                params![
                    format!("{}:{}", journal.id, entry.path.display()),
                    now_secs(),
                    entry.path.display().to_string(),
                    entry.before_sha256,
                    entry.after_sha256,
                    entry.backup.as_ref().map(|p| p.display().to_string()),
                ],
            )
            .map_err(|e| Error::Store(format!("写入变更记录失败: {e}")))?;
        }
        Ok(())
    }

    pub fn journal_count(&self) -> Result<i64> {
        let conn = self.lock()?;
        conn.query_row("SELECT COUNT(*) FROM journals", [], |row| row.get(0))
            .map_err(|e| Error::Store(format!("统计变更记录失败: {e}")))
    }

    // ======================================================== 投递授权（M1-S2）

    /// 授予/刷新同意。同一 `(agent_id, channel, target_path)` 幂等：
    /// 重复同意只刷新 `granted_at` 并清空 `revoked_at`。
    pub fn grant_consent(
        &self,
        agent_id: &str,
        channel: &str,
        target_path: &str,
        fields: &[String],
    ) -> Result<()> {
        let fields_json = serde_json::to_string(fields)
            .map_err(|e| Error::Store(format!("序列化字段名失败: {e}")))?;
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO consents(agent_id, channel, target_path, fields, granted_at, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL)
             ON CONFLICT(agent_id, channel, target_path)
             DO UPDATE SET fields = excluded.fields,
                           granted_at = excluded.granted_at,
                           revoked_at = NULL",
            params![agent_id, channel, target_path, fields_json, now_secs()],
        )
        .map_err(|e| Error::Store(format!("写入投递授权失败: {e}")))?;
        Ok(())
    }

    /// 撤销同意。**不**回滚已写入的文件（回滚是独立动作）。
    pub fn revoke_consent(&self, agent_id: &str, channel: &str, target_path: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE consents SET revoked_at = ?4
             WHERE agent_id = ?1 AND channel = ?2 AND target_path = ?3 AND revoked_at IS NULL",
            params![agent_id, channel, target_path, now_secs()],
        )
        .map_err(|e| Error::Store(format!("撤销投递授权失败: {e}")))?;
        Ok(())
    }

    /// 查有效同意（`revoked_at IS NULL`）。返回 `granted_at`。
    pub fn active_consent(
        &self,
        agent_id: &str,
        channel: &str,
        target_path: &str,
    ) -> Result<Option<i64>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT granted_at FROM consents
                 WHERE agent_id = ?1 AND channel = ?2 AND target_path = ?3 AND revoked_at IS NULL",
            )
            .map_err(|e| Error::Store(format!("查询投递授权失败: {e}")))?;
        let mut rows = stmt
            .query_map(params![agent_id, channel, target_path], |row| row.get(0))
            .map_err(|e| Error::Store(format!("查询投递授权失败: {e}")))?;
        match rows.next() {
            Some(row) => {
                Ok(Some(row.map_err(|e| {
                    Error::Store(format!("读取投递授权失败: {e}"))
                })?))
            }
            None => Ok(None),
        }
    }

    /// 列出全部同意记录（含已撤销），供 UI 展示。
    pub fn list_consents(&self) -> Result<Vec<ConsentRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT agent_id, channel, target_path, fields, granted_at, revoked_at
                 FROM consents ORDER BY agent_id, channel, target_path",
            )
            .map_err(|e| Error::Store(format!("列举投递授权失败: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(ConsentRow {
                    agent_id: row.get(0)?,
                    channel: row.get(1)?,
                    target_path: row.get(2)?,
                    fields: row.get(3)?,
                    granted_at: row.get(4)?,
                    revoked_at: row.get(5)?,
                })
            })
            .map_err(|e| Error::Store(format!("列举投递授权失败: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取投递授权行失败: {e}")))
    }

    // ======================================================== 设置与绑定（M3-S1）

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT value FROM settings WHERE key = ?1")
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let mut rows = stmt
            .query_map(params![key], |row| row.get::<_, String>(0))
            .map_err(|e| Error::Store(format!("查询设置失败: {e}")))?;
        match rows.next() {
            Some(row) => Ok(Some(
                row.map_err(|e| Error::Store(format!("读取设置失败: {e}")))?,
            )),
            None => Ok(None),
        }
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO settings(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )
        .map_err(|e| Error::Store(format!("写入设置失败: {e}")))?;
        Ok(())
    }

    /// 每个投递目标只取**最近一次**投递的绑定，并 LEFT JOIN 出当时的 `after_sha256`。
    ///
    /// 用 LEFT JOIN（journals）而不是 INNER JOIN：老库里可能没有对应的 journal 行，
    /// 那种情况要能被识别成「无法判定」而不是从报告里消失。
    /// `keys` 那一跳反过来必须是 INNER JOIN：那一跳是「这行属于哪个站点」，
    /// 少了它这行就成了无法归组的孤儿数据（而 `keys` 的删除会级联带走 `bindings`，
    /// 所以 INNER JOIN 不会把正常行丢掉）。
    ///
    /// `journal_id` 过 `COALESCE`：列在 schema 里可空（`journal_id TEXT`），而 Rust 侧是
    /// `String`——一行 NULL 会让 `row.get::<String>` 报「Invalid column type Null」，
    /// 于是**整张表**读不出来（一次手工写的/迁移来的绑定行就能让漂移报告与轮换预览
    /// 一起变成 `Err`）。空串的语义与 NULL 在下面那个 `j.id = …` 拼接里完全一致
    /// （都匹配不到 journal 行 → `expected_sha256` 为 NULL → `Unknown`），
    /// 所以这里不需要改类型、也不会把「无法判定」说成「完好」。
    pub fn binding_drift_rows(&self) -> Result<Vec<BindingDriftRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT b.agent_id, b.target_path, COALESCE(b.journal_id, '') AS journal_id,
                        j.after_sha256, k.site_id, b.key_id
                 FROM bindings b
                 -- M8-S4：**已解绑的目标不再出现在漂移报告里**。文件已经不属于我们，
                 -- 继续报「配置已漂移」等于指挥用户去修一个我们不该管的文件。
                 --
                 -- M16-S1（B-126 选项①）：**已回滚的那次投递也不再算数**——回滚把文件还原了，
                 -- 那次投递不再是现状；继续拿它的 `after_sha256` 当期望值，会让一个已回滚的目标
                 -- 永远显示漂移，并让 `rotation_targets` 把一把已经不在服务的 key 当成服务者。
                 -- 「合格」的判定与 `delivery_history` 的 `superseded` **同源**：
                 -- `COALESCE(status,'applied') <> 'rolled_back'`（没有 journal 行 = applied；
                 -- 老库 `journal_id` 为空串时 join 出 NULL ⇒ 同样视为合格）。
                 JOIN (SELECT b2.target_path, MAX(b2.id) AS mid
                         FROM bindings b2
                         LEFT JOIN journals j2
                                ON j2.id = b2.journal_id || ':' || b2.target_path
                        WHERE b2.unbound_at IS NULL
                          AND COALESCE(j2.status, 'applied') <> 'rolled_back'
                        GROUP BY b2.target_path) latest
                   ON b.id = latest.mid
                 JOIN keys k ON k.id = b.key_id
                 LEFT JOIN journals j ON j.id = b.journal_id || ':' || b.target_path
                 ORDER BY b.target_path",
            )
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(BindingDriftRow {
                    agent_id: row.get(0)?,
                    target_path: row.get(1)?,
                    journal_id: row.get(2)?,
                    expected_sha256: row.get(3)?,
                    site_id: row.get(4)?,
                    key_id: row.get(5)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询投递绑定失败: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取投递绑定行失败: {e}")))
    }

    // ============================================================ 事件（M1-S3）

    /// 写入一条**已脱敏**的事件。
    ///
    /// 只接受 [`crate::observability::Event`]（其构造器已过 `scrub`），
    /// 从类型上挡住「直接塞原文」这条路径。
    pub fn insert_event(&self, event: &crate::observability::Event) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO events(ts, level, source, message, payload_redacted_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                event.ts,
                event.level.as_str(),
                event.source,
                event.message,
                event.payload,
            ],
        )
        .map_err(|e| Error::Store(format!("写入事件失败: {e}")))?;
        Ok(())
    }

    pub fn list_events(&self, limit: usize) -> Result<Vec<EventRow>> {
        let limit = i64::try_from(limit)
            .map_err(|_| Error::Store(format!("事件条数上限超出范围: {limit}")))?;
        self.query_events(limit)
    }

    /// 读**全部**事件，不限条数（事件表守护用）。
    ///
    /// 单独一个方法，而不是 `list_events(usize::MAX)`（复审 P2-13）：后者能「不限制」
    /// 纯粹是因为 `usize::MAX as i64 == -1`，而 SQLite 恰好把负 `LIMIT` 解释成不限制。
    /// 一旦有人给 `list_events` 加上限（`recent_events` 就有 `min(1000)`），
    /// 事件表守护会**静默只扫最近 N 条**，红线守护变成空跑。
    pub fn list_all_events(&self) -> Result<Vec<EventRow>> {
        // `LIMIT -1` 是 SQLite 明文的「不限制」，不是巧合
        self.query_events(-1)
    }

    fn query_events(&self, limit: i64) -> Result<Vec<EventRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, ts, level, source, message, payload_redacted_json
                 FROM events ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let rows = stmt
            .query_map(params![limit], |row| {
                Ok(EventRow {
                    id: row.get(0)?,
                    ts: row.get(1)?,
                    level: row.get(2)?,
                    source: row.get(3)?,
                    message: row.get(4)?,
                    payload: row.get(5)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询事件失败: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取事件行失败: {e}")))
    }

    /// 扫描整表，返回**疑似**含未脱敏凭证的行数（正常应为 0）。
    ///
    /// 用 `redact::scrub` 做判定，而不是硬编码正则：脱敏规则只有一处定义，
    /// 规则升级后本方法自动跟随。
    pub fn count_events_with_secrets(&self) -> Result<i64> {
        let events = self.list_all_events()?;
        let hits = events
            .iter()
            .filter(|row| {
                crate::redact::contains_secret(&row.message)
                    || row
                        .payload
                        .as_deref()
                        .is_some_and(crate::redact::contains_secret)
            })
            .count();
        Ok(hits as i64)
    }

    /// **一次性数据修复**：把 `events` 表里所有老行的 `message` / `payload` 按**当前**
    /// 脱敏规则改写一遍，返回改写的行数。
    ///
    /// 为什么需要（M8-S5B §7.2）：`observability::event_with_payload` 是后来才加上
    /// 结构化脱敏的（M5-S0），在那之前写进行表的老行可能带着密钥明文，而事件表会被
    /// 导出与审计 ⇒ 那些行是真实的泄漏面。
    ///
    /// **未接线（章程 §4 增量）**：本仓库唯一的调用点是
    /// `tests/events_redaction.rs::scrub_legacy_event_rows`（`#[ignore]`）——
    /// 生产代码里没有调用点，命令层也没有入口。去向：需要「在界面上修历史行」时
    /// 再加一条命令（跑前自动备份 `<db>` / `-wal` / `<db>-shm`）；在那之前它是
    /// **可复跑的一次性工具**，不是产品功能。
    ///
    /// **不进门禁、不自动执行**：它是数据修复，由人显式跑
    /// （`cargo test -p tianshu-relay-core --test events_redaction scrub_legacy_event_rows -- --ignored`）。
    /// 跑之前先备份数据库。
    ///
    /// 用真规则而不是 SQL：脱敏规则在 Rust 侧（`scrub_event_message` /
    /// `scrub_event_payload`），SQL 复刻必然漏（猜不出 authority 边界、也不知道哪些
    /// payload 键是敏感键）。
    ///
    /// 幂等：规则本身幂等，跑第二遍改写行数为 0。
    pub fn scrub_legacy_events(&self) -> Result<usize> {
        let rows = self.list_all_events()?;
        let mut repaired = 0usize;
        for row in &rows {
            let new_message = crate::redact::scrub_event_message(&row.message);
            let new_payload = crate::redact::scrub_event_payload(row.payload.as_deref());
            let message_changed = new_message != row.message;
            let payload_changed = new_payload.as_deref() != row.payload.as_deref();
            if !message_changed && !payload_changed {
                continue;
            }
            let conn = self.lock()?;
            conn.execute(
                "UPDATE events SET message = ?2, payload_redacted_json = ?3 WHERE id = ?1",
                params![row.id, new_message, new_payload],
            )
            .map_err(|e| Error::Store(format!("改写事件行 {} 失败: {e}", row.id)))?;
            repaired += 1;
        }
        Ok(repaired)
    }

    /// 更新站点的健康状态。取值由调用方约定：`"unknown"` / `"ok"` / `"needs_login"`。
    ///
    /// 站点不存在时**报错**而不是静默成功：静默成功会让调用方以为状态已落库，
    /// 而 `needs_login` 正是「用户看不到就永远修不好」的那类状态（B-61）。
    pub fn set_site_health(&self, site_id: i64, health: &str) -> Result<()> {
        let conn = self.lock()?;
        let affected = conn
            .execute(
                "UPDATE sites SET health = ?2 WHERE id = ?1",
                params![site_id, health],
            )
            .map_err(|e| Error::Store(format!("更新站点状态失败: {e}")))?;
        if affected == 0 {
            return Err(Error::Store(format!("站点不存在: {site_id}")));
        }
        Ok(())
    }

    /// 写 `keys.status`（M7-S4 / FR-2「回收站点侧 key」的落点）。
    ///
    /// 合法值 = [`legal_key_statuses`]（站点侧 `site::KeyStatus::as_str()` 四个值
    /// ∪ [`KEY_STATUS_REVOKED`]）。其余值 ⇒ [`Error::Store`]，且**不执行 UPDATE**：
    /// 先校验后写，调用方的入参 bug 不该在库里留下半成品。
    ///
    /// 行不存在时**报错**而不是静默成功（与 [`Store::set_site_health`] 同口径）：
    /// 静默成功会让调用方以为状态已落库，而界面会显示一个**不存在**的 key「已回收」。
    ///
    /// **不删行**：回收语义只改状态。删 `keys` 行会经 `ON DELETE CASCADE` 带走该 key 的
    /// 全部 `bindings`（漂移检测的输入），而 `journals` 没有 `key_id` 列——溯源链的起点就是
    /// `keys.id`，删了它再也答不上「这次投递是哪把 key 造成的」（M7-S4 spec §6.1）。
    pub fn set_key_status(&self, key_id: i64, status: &str) -> Result<()> {
        if !is_legal_key_status(status) {
            // 值本身也过 `scrub`：调用方可能把密钥误传进来，错误文案里不能出现它
            return Err(Error::Store(format!(
                "keys.status 非法值: {}（合法值: {}）",
                crate::redact::scrub(status),
                legal_key_statuses().join("/")
            )));
        }
        let conn = self.lock()?;
        let affected = conn
            .execute(
                "UPDATE keys SET status = ?2 WHERE id = ?1",
                params![key_id, status],
            )
            .map_err(|e| Error::Store(format!("更新密钥状态失败: {e}")))?;
        if affected == 0 {
            return Err(Error::Store(format!("密钥不存在: {key_id}")));
        }
        Ok(())
    }

    /// 读 `keys.status`。行不存在 ⇒ `Ok(None)`。
    ///
    /// 读是查询语义：「没有这行」是正常状态而不是错误——与写的口径**刻意不同**
    /// （写不存在的行是调用方的 bug，见 [`Store::set_key_status`]）。两条都有测试。
    pub fn key_status(&self, key_id: i64) -> Result<Option<String>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT status FROM keys WHERE id = ?1")
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let mut rows = stmt
            .query_map(params![key_id], |row| row.get::<_, String>(0))
            .map_err(|e| Error::Store(format!("查询密钥状态失败: {e}")))?;
        match rows.next() {
            Some(row) => {
                Ok(Some(row.map_err(|e| {
                    Error::Store(format!("读取密钥状态失败: {e}"))
                })?))
            }
            None => Ok(None),
        }
    }

    /// 登记一次导出（同一路径重复导出则覆盖）。**只记路径与统计，不记内容。**
    pub fn record_export(&self, path: &Path, encrypted: bool, bytes: usize) -> Result<()> {
        let bytes = i64::try_from(bytes)
            .map_err(|_| Error::Store(format!("导出字节数超出范围: {bytes}")))?;
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO exports(path, encrypted, bytes, exported_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(path) DO UPDATE SET
               encrypted   = excluded.encrypted,
               bytes       = excluded.bytes,
               exported_at = excluded.exported_at",
            params![
                path.to_string_lossy(),
                i64::from(encrypted),
                bytes,
                now_secs(),
            ],
        )
        .map_err(|e| Error::Store(format!("登记导出失败: {e}")))?;
        Ok(())
    }

    /// 列出已知导出物，最新的在前。同 `exported_at` 时按路径升序，保证顺序确定。
    pub fn list_exports(&self) -> Result<Vec<ExportRecord>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT path, encrypted, bytes, exported_at FROM exports
                 ORDER BY exported_at DESC, path ASC",
            )
            .map_err(|e| Error::Store(format!("准备查询失败: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(ExportRecord {
                    path: row.get(0)?,
                    encrypted: row.get::<_, i64>(1)? != 0,
                    bytes: row.get(2)?,
                    exported_at: row.get(3)?,
                })
            })
            .map_err(|e| Error::Store(format!("查询导出记录失败: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取导出行失败: {e}")))
    }

    // ============================================================ M43-S1：Agent 网关令牌

    /// 插入一行令牌（**只收 hash**）。返回新行 id。
    ///
    /// 唯一约束：`token_hash` 全表唯一；`label` 非吊销内唯一；`is_default=1` 全局最多一行。
    pub fn insert_gateway_token(
        &self,
        token_hash: &str,
        label: &str,
        is_default: bool,
    ) -> Result<i64> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO gateway_tokens(token_hash, label, created_at, is_default) VALUES(?1, ?2, ?3, ?4)",
            params![token_hash, label, now_secs(), i64::from(is_default)],
        )
        .map_err(|e| Error::Store(format!("插入网关令牌失败: {e}")))?;
        Ok(conn.last_insert_rowid())
    }

    /// 全部令牌，按 `created_at DESC, id DESC`（列表口径）。
    pub fn list_gateway_tokens(&self) -> Result<Vec<GatewayTokenRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, token_hash, label, created_at, revoked_at, last_used_at, is_default
                 FROM gateway_tokens ORDER BY created_at DESC, id DESC",
            )
            .map_err(|e| Error::Store(format!("准备令牌列表失败: {e}")))?;
        let rows = stmt
            .query_map([], map_gateway_token_row)
            .map_err(|e| Error::Store(format!("查询令牌列表失败: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("读取令牌行失败: {e}")))
    }

    pub fn gateway_token_by_id(&self, id: i64) -> Result<Option<GatewayTokenRow>> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, token_hash, label, created_at, revoked_at, last_used_at, is_default
             FROM gateway_tokens WHERE id = ?1",
            params![id],
            map_gateway_token_row,
        )
        .optional()
        .map_err(|e| Error::Store(format!("查询令牌 #{id} 失败: {e}")))
    }

    /// 默认行（`is_default = 1`）——**不看 label、不看 revoked_at**（身份事实）。
    pub fn default_gateway_token(&self) -> Result<Option<GatewayTokenRow>> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT id, token_hash, label, created_at, revoked_at, last_used_at, is_default
             FROM gateway_tokens WHERE is_default = 1",
            [],
            map_gateway_token_row,
        )
        .optional()
        .map_err(|e| Error::Store(format!("查询默认令牌失败: {e}")))
    }

    /// 吊销（幂等：已吊销不动 `revoked_at`）。
    pub fn revoke_gateway_token(&self, id: i64) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE gateway_tokens SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
            params![id, now_secs()],
        )
        .map_err(|e| Error::Store(format!("吊销令牌 #{id} 失败: {e}")))?;
        Ok(())
    }

    /// M43-S1：记录一次使用，**按「每分钟最多一次」节流**（SQL 原子判定，多进程安全）。
    ///
    /// 返回是否真的写入了（供测试断言节流生效）。
    pub fn touch_gateway_token_throttled(&self, id: i64, now: i64) -> Result<bool> {
        let conn = self.lock()?;
        let changed = conn
            .execute(
                "UPDATE gateway_tokens SET last_used_at = ?2
                 WHERE id = ?1
                   AND (last_used_at IS NULL OR last_used_at <= ?2 - 60)",
                params![id, now],
            )
            .map_err(|e| Error::Store(format!("更新令牌 #{id} 使用时间失败: {e}")))?;
        Ok(changed > 0)
    }

    /// 记录一次使用（调用方负责节流；见 service 的 `touch_gateway_token`）。
    pub fn touch_gateway_token(&self, id: i64) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE gateway_tokens SET last_used_at = ?2 WHERE id = ?1",
            params![id, now_secs()],
        )
        .map_err(|e| Error::Store(format!("更新令牌 #{id} 使用时间失败: {e}")))?;
        Ok(())
    }

    /// M41-S2 复审 P2：对账时复位默认行的 `revoked_at`（只用于手工吊销后的自愈）。
    pub fn restore_gateway_token(&self, id: i64) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE gateway_tokens SET revoked_at = NULL WHERE id = ?1",
            params![id],
        )
        .map_err(|e| Error::Store(format!("恢复令牌 #{id} 失败: {e}")))?;
        Ok(())
    }

    /// M41-S2 的轮换接口：**原地**改默认行的 hash（保留 id/label/created_at/is_default）。
    /// 仅测试用：让下一次 `update_gateway_token_hash` 强制失败（M41-S2 F-2）。
    /// 生产代码永不调用；一次性，用后自动清零。
    pub fn fail_next_gateway_token_hash_update_for_test(&self) {
        self.fail_next_token_hash_update
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn update_gateway_token_hash(&self, id: i64, token_hash: &str) -> Result<()> {
        if self
            .fail_next_token_hash_update
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(Error::Store("测试注入：令牌 hash 更新失败".to_string()));
        }
        let conn = self.lock()?;
        conn.execute(
            "UPDATE gateway_tokens SET token_hash = ?2 WHERE id = ?1",
            params![id, token_hash],
        )
        .map_err(|e| Error::Store(format!("更新令牌 #{id} hash 失败: {e}")))?;
        Ok(())
    }

    /// 一条网关用量账目（M40-S1）。
    ///
    /// `ts` 由本方法取 `now_secs()`（**插入时刻**，审计用）；其余 11 列全部来自 `usage`
    /// （`at` 是请求完成时刻）。直接吃 `GatewayUsage` 而不是 11 个标量参数：账目只有一个
    /// 结构，参数化只能靠位置对齐，`model` 写进 `key_id` 这种错位编译器抓不到。
    pub fn insert_gateway_usage(&self, usage: &crate::gateway::GatewayUsage) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO gateway_usage_log(ts, at, site_id, key_id, model, prompt_tokens, completion_tokens, total_tokens, status, latency_ms, attempts, stream, token_id, agent_label) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                now_secs(),
                usage.at,
                usage.site_id,
                usage.key_id,
                usage.model,
                usage.prompt_tokens,
                usage.completion_tokens,
                usage.total_tokens,
                i64::from(usage.status),
                usage.latency_ms as i64,
                i64::from(usage.attempts),
                i64::from(usage.stream),
                usage.token_id,
                usage.agent_label,
            ],
        ).map_err(|e| Error::Store(format!("gateway usage insert: {e}")))?;
        Ok(())
    }

    /// M13-S1: query recent gateway usage
    pub fn recent_gateway_usage(&self, hours: i64) -> Result<Vec<GatewayUsageRow>> {
        let hours = hours.max(1);
        let cutoff = now_secs() - hours * 3600;
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT id, ts, site_id, model, prompt_tokens, completion_tokens, total_tokens FROM gateway_usage_log WHERE at >= ?1 ORDER BY at DESC LIMIT 1000").map_err(|e| Error::Store(format!("prepare: {e}")))?;
        let rows = stmt
            .query_map(params![cutoff], |row| {
                Ok(GatewayUsageRow {
                    id: row.get(0)?,
                    ts: row.get(1)?,
                    site_id: row.get(2)?,
                    model: row.get(3)?,
                    prompt_tokens: row.get(4)?,
                    completion_tokens: row.get(5)?,
                    total_tokens: row.get(6)?,
                })
            })
            .map_err(|e| Error::Store(format!("query: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("collect: {e}")))
    }

    /// M13-S1: insert usage snapshot
    pub fn insert_usage_snapshot(
        &self,
        site_id: i64,
        used: f64,
        remaining: f64,
        currency: &str,
        known: bool,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO usage_snapshots(site_id, used, remaining, currency, known, ts) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![site_id, used, remaining, currency, i64::from(known), now_secs()],
        ).map_err(|e| Error::Store(format!("snapshot insert: {e}")))?;
        Ok(())
    }

    /// M13-S1: query recent usage snapshots
    pub fn recent_usage_snapshots(&self, hours: i64) -> Result<Vec<UsageSnapshotRow>> {
        let hours = hours.max(1);
        let cutoff = now_secs() - hours * 3600;
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT id, ts, site_id, used, remaining, currency, known FROM usage_snapshots WHERE ts >= ?1 ORDER BY site_id ASC, ts DESC LIMIT 500").map_err(|e| Error::Store(format!("prepare: {e}")))?;
        let rows = stmt
            .query_map(params![cutoff], |row| {
                Ok(UsageSnapshotRow {
                    id: row.get(0)?,
                    ts: row.get(1)?,
                    site_id: row.get(2)?,
                    used: row.get(3)?,
                    remaining: row.get(4)?,
                    currency: row.get(5)?,
                    known: row.get::<_, i64>(6)? != 0,
                })
            })
            .map_err(|e| Error::Store(format!("query: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("collect: {e}")))
    }

    /// M13-S1: 裁剪网关用量日志，只保留最近 N 天。在 `refresh_all` 里调用。
    pub fn prune_gateway_usage_log(&self, days: i64) -> Result<usize> {
        let cutoff = now_secs() - days * 86400;
        let conn = self.lock()?;
        let n = conn
            .execute(
                "DELETE FROM gateway_usage_log WHERE at < ?1",
                params![cutoff],
            )
            .map_err(|e| Error::Store(format!("prune gateway usage: {e}")))?;
        Ok(n)
    }

    /// M13-S1: 裁剪余额快照，只保留最近 N 天。
    pub fn prune_usage_snapshots(&self, days: i64) -> Result<usize> {
        let cutoff = now_secs() - days * 86400;
        let conn = self.lock()?;
        let n = conn
            .execute("DELETE FROM usage_snapshots WHERE ts < ?1", params![cutoff])
            .map_err(|e| Error::Store(format!("prune usage snapshots: {e}")))?;
        Ok(n)
    }

    // ============================================================ M34-S1：用量看板聚合
    //
    // 三张表都是**只读聚合**：不写库、不改采集口径。日界一律按系统本地时区
    // （`date(ts,'unixepoch','localtime')`），窗口含今天（`days=7` ⇒ 6 天前零点起）。
    // `days` 与 `site_id` 的夹取/筛选语义见 spec §4.1 与 §6。

    /// M34-S1：近 `days` 天（含今天）网关 token 用量，按（本地日, 站点, 模型）聚合。
    ///
    /// `model` 空串是独立分组（网关没解析出模型名），**不归并**成「未知」以外的名字。
    pub fn usage_daily(&self, days: i64, site_id: Option<i64>) -> Result<Vec<UsageDailyRow>> {
        let days = clamp_usage_days(days);
        let conn = self.lock()?;
        let cutoff = local_day_start(&conn, days - 1)?;
        let mut stmt = conn
            .prepare(
                // M43-S2：按**行级**关联「不晚于该行 at 的最新价格版本」，再按币种分组。
                // `p.currency` 为 NULL = 该行没有可用价格（旧行 / 未配价 / 币种不符）。
                "SELECT date(u.at, 'unixepoch', 'localtime') AS d, u.site_id, u.model,
                        COUNT(*),
                        COALESCE(SUM(u.prompt_tokens), 0),
                        COALESCE(SUM(u.completion_tokens), 0),
                        COALESCE(SUM(u.total_tokens), 0),
                        u.token_id, u.agent_label,
                        p.currency,
                        CASE WHEN p.currency IS NULL THEN NULL ELSE
                          ROUND(SUM(ROUND(u.prompt_tokens / 1000000.0 * p.input_per_mtok
                                       + u.completion_tokens / 1000000.0 * p.output_per_mtok, 6)), 6)
                        END,
                        SUM(CASE WHEN p.currency IS NULL THEN 1 ELSE 0 END),
                        SUM(CASE WHEN p.currency IS NULL THEN u.total_tokens ELSE 0 END)
                 FROM gateway_usage_log u
                 LEFT JOIN model_prices p
                   ON p.model = u.model
                  AND p.effective_from = (
                        SELECT MAX(q.effective_from) FROM model_prices q
                         WHERE q.model = u.model AND q.effective_from <= u.at
                      )
                 WHERE u.at >= ?1 AND (?2 IS NULL OR u.site_id = ?2)
                 GROUP BY d, u.site_id, u.model, u.token_id, u.agent_label, p.currency
                 ORDER BY d ASC, u.site_id ASC, u.model ASC, u.agent_label ASC, p.currency ASC",
            )
            .map_err(|e| Error::Store(format!("prepare usage daily: {e}")))?;
        let rows = stmt
            .query_map(params![cutoff, site_id], |row| {
                Ok(UsageDailyRow {
                    date: row.get(0)?,
                    site_id: row.get(1)?,
                    model: row.get(2)?,
                    requests: row.get(3)?,
                    prompt_tokens: row.get(4)?,
                    completion_tokens: row.get(5)?,
                    total_tokens: row.get(6)?,
                    token_id: row.get(7)?,
                    agent_label: row.get(8)?,
                    currency: row.get(9)?,
                    estimated_cost: row.get(10)?,
                    unpriced_requests: row.get(11)?,
                    unpriced_tokens: row.get(12)?,
                })
            })
            .map_err(|e| Error::Store(format!("query usage daily: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("collect usage daily: {e}")))
    }

    /// M43-S2：按 agent（认证时的 label 快照）× 币种聚合成本。
    ///
    /// 与 [`Self::usage_daily`] 同一套价格关联口径（行级 `effective_from <= at` 取最大，按币种拆行）。
    pub fn usage_by_agent(&self, days: i64) -> Result<Vec<AgentUsageRow>> {
        let days = clamp_usage_days(days);
        let conn = self.lock()?;
        let cutoff = local_day_start(&conn, days - 1)?;
        let mut stmt = conn
            .prepare(
                "SELECT u.agent_label, p.currency,
                        COUNT(*),
                        COALESCE(SUM(u.total_tokens), 0),
                        CASE WHEN p.currency IS NULL THEN NULL ELSE
                          ROUND(SUM(ROUND(u.prompt_tokens / 1000000.0 * p.input_per_mtok
                                       + u.completion_tokens / 1000000.0 * p.output_per_mtok, 6)), 6)
                        END,
                        SUM(CASE WHEN p.currency IS NULL THEN 1 ELSE 0 END)
                 FROM gateway_usage_log u
                 LEFT JOIN model_prices p
                   ON p.model = u.model
                  AND p.effective_from = (
                        SELECT MAX(q.effective_from) FROM model_prices q
                         WHERE q.model = u.model AND q.effective_from <= u.at
                      )
                 WHERE u.at >= ?1
                 GROUP BY u.agent_label, p.currency
                 ORDER BY u.agent_label ASC, p.currency ASC",
            )
            .map_err(|e| Error::Store(format!("prepare usage by agent: {e}")))?;
        let rows = stmt
            .query_map(params![cutoff], |row| {
                Ok(AgentUsageRow {
                    agent_label: row.get(0)?,
                    currency: row.get(1)?,
                    requests: row.get(2)?,
                    total_tokens: row.get(3)?,
                    estimated_cost: row.get(4)?,
                    unpriced_requests: row.get(5)?,
                })
            })
            .map_err(|e| Error::Store(format!("query usage by agent: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("collect usage by agent: {e}")))
    }

    // ======================================================== M43-S2：模型单价

    /// 全部价格版本（按 model / currency / effective_from 降序）。
    pub fn model_price_list(&self) -> Result<Vec<ModelPriceRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, model, input_per_mtok, output_per_mtok, currency, effective_from, created_at
                 FROM model_prices ORDER BY model ASC, currency ASC, effective_from DESC",
            )
            .map_err(|e| Error::Store(format!("prepare model price list: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(ModelPriceRow {
                    id: row.get(0)?,
                    model: row.get(1)?,
                    input_per_mtok: row.get(2)?,
                    output_per_mtok: row.get(3)?,
                    currency: row.get(4)?,
                    effective_from: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })
            .map_err(|e| Error::Store(format!("query model price list: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("collect model price list: {e}")))
    }

    /// 写入一个价格版本：同一 `(model, currency, effective_from)` 已存在时**覆盖**价格。
    ///
    /// 校验在这一层再做一遍（命令层也校验）：模型名非空且 ≤128；两个单价**有限且 > 0**
    /// （`0` 不是「免费」的合法表达——免费就不配价格）；币种只接受 `USD` / `CNY`。
    pub fn model_price_upsert(
        &self,
        model: &str,
        input_per_mtok: f64,
        output_per_mtok: f64,
        currency: &str,
        effective_from: i64,
    ) -> Result<i64> {
        let model = model.trim();
        if model.is_empty() || model.chars().count() > 128 {
            return Err(Error::Store("模型名不能为空且不超过 128 字符".into()));
        }
        for (name, v) in [("input", input_per_mtok), ("output", output_per_mtok)] {
            if !v.is_finite() || v <= 0.0 {
                return Err(Error::Store(format!(
                    "{name} 单价必须是有限的正数（每 1M token，单位与币种一致）"
                )));
            }
        }
        let currency = currency.trim().to_ascii_uppercase();
        if currency != "USD" && currency != "CNY" {
            return Err(Error::Store("币种只支持 USD / CNY（不做汇率换算）".into()));
        }
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO model_prices(model, input_per_mtok, output_per_mtok, currency, effective_from, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(model, currency, effective_from)
             DO UPDATE SET input_per_mtok = excluded.input_per_mtok,
                           output_per_mtok = excluded.output_per_mtok,
                           created_at = excluded.created_at",
            params![model, input_per_mtok, output_per_mtok, currency, effective_from, now_secs()],
        )
        .map_err(|e| Error::Store(format!("写入模型单价失败: {e}")))?;
        let id: i64 = conn
            .query_row(
                "SELECT id FROM model_prices WHERE model = ?1 AND currency = ?2 AND effective_from = ?3",
                params![model, currency, effective_from],
                |row| row.get(0),
            )
            .map_err(|e| Error::Store(format!("读回模型单价 id 失败: {e}")))?;
        Ok(id)
    }

    /// 删除一个价格版本。**允许删除**（估算是展示层：删掉后该时段的成本变回「未知」）。
    pub fn model_price_delete(&self, id: i64) -> Result<bool> {
        let conn = self.lock()?;
        let affected = conn
            .execute("DELETE FROM model_prices WHERE id = ?1", params![id])
            .map_err(|e| Error::Store(format!("删除模型单价失败: {e}")))?;
        Ok(affected > 0)
    }

    // ======================================================== M46-S5：站点 / key 硬预算
    //
    // 花销口径（spec §2）：主口径 = gateway_usage_log token 数 × model_prices
    // USD 价格行，SQL 表达式与 usage_daily 的 USD 分组逐字同构（行级最新价版本、
    // 每百万 token 单价、每行 ROUND 6 位后求和再 ROUND 6 位）。usage_samples
    // 不用：只有 Sub2API 系写、cost 有「上报与否」问题、无币种列、日粒度快照。

    /// 校验预算 period（store 层只认这两个值；网关侧枚举见 gateway::BudgetPeriod）。
    fn validate_budget_period(period: &str) -> Result<()> {
        if period != "day" && period != "month" {
            return Err(Error::Store(format!(
                "预算周期非法: {period}（只认 day / month）"
            )));
        }
        Ok(())
    }

    /// 建预算（validate 先行：周期枚举、上限有限且 > 0、站点存在、key 存在且属该站、
    /// 重复 (site, key, period) 拒绝——唯一索引兜底，错误文案友好化，不抛 SQLite 原文）。
    pub fn budget_create(
        &self,
        site_id: i64,
        key_id: Option<i64>,
        period: &str,
        limit_usd: f64,
    ) -> Result<i64> {
        Self::validate_budget_period(period)?;
        if !limit_usd.is_finite() || limit_usd <= 0.0 {
            return Err(Error::Store(format!(
                "预算上限非法: {limit_usd}（必须为有限正数）"
            )));
        }
        if !self.list_sites()?.iter().any(|s| s.id == site_id) {
            return Err(Error::Store(format!("预算站点不存在: {site_id}")));
        }
        if let Some(kid) = key_id {
            match self.list_keys()?.iter().find(|k| k.id == kid) {
                None => return Err(Error::Store(format!("预算密钥不存在: {kid}"))),
                Some(row) if row.site_id != site_id => {
                    return Err(Error::Store(format!("预算密钥 {kid} 不属于站点 {site_id}")));
                }
                _ => {}
            }
        }
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO site_budgets(site_id, key_id, period, limit_usd, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![site_id, key_id, period, limit_usd, now_secs()],
        )
        .map_err(|e| {
            Error::Store(format!(
                "该站点/密钥该周期已有预算（同一站同一周期只能有一行站级预算、同一 key 只能有一行 key 级预算）: {e}"
            ))
        })?;
        Ok(conn.last_insert_rowid())
    }

    /// 全部预算行（按 id 升序；展示层按需再排）。
    pub fn budget_list(&self) -> Result<Vec<SiteBudgetRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, site_id, key_id, period, limit_usd, created_at
                 FROM site_budgets ORDER BY id ASC",
            )
            .map_err(|e| Error::Store(format!("prepare budget list: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(SiteBudgetRow {
                    id: row.get(0)?,
                    site_id: row.get(1)?,
                    key_id: row.get(2)?,
                    period: row.get(3)?,
                    limit_usd: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })
            .map_err(|e| Error::Store(format!("query budget list: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("collect budget list: {e}")))
    }

    /// 删除预算行。不存在 -> Ok(false)，与 model_price_delete 同口径。
    pub fn budget_delete(&self, id: i64) -> Result<bool> {
        let conn = self.lock()?;
        let affected = conn
            .execute("DELETE FROM site_budgets WHERE id = ?1", params![id])
            .map_err(|e| Error::Store(format!("删除预算失败: {e}")))?;
        Ok(affected > 0)
    }

    /// 周期窗口（本地时区，unix 秒，左闭右开）。
    ///
    /// 与 `local_day_start` 同一条纪律：`date(...)` 给出本地日期串，SQLite 默认按
    /// UTC 解释，`'utc'` 修饰符不能省；month 用 `'start of month','+1 month'`，
    /// 不用起点 + 86400（夏令时切换日不是 86400 秒）。
    pub fn budget_period_bounds(&self, period: &str) -> Result<(i64, i64)> {
        Self::validate_budget_period(period)?;
        let conn = self.lock()?;
        let (start_sql, end_sql) = match period {
            "day" => (
                "strftime('%s', date('now','localtime'), 'utc')",
                "strftime('%s', date('now','localtime','+1 day'), 'utc')",
            ),
            _ => (
                "strftime('%s', date('now','localtime','start of month'), 'utc')",
                "strftime('%s', date('now','localtime','start of month','+1 month'), 'utc')",
            ),
        };
        conn.query_row(
            &format!("SELECT CAST({start_sql} AS INTEGER), CAST({end_sql} AS INTEGER)"),
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|e| Error::Store(format!("计算预算周期窗口失败: {e}")))
    }

    /// 当期已花（USD）。
    ///
    /// SQL 与 `usage_daily` 的 USD 分组逐字同构：行级关联「不晚于该行 at 的最新
    /// USD 价格版本」，无价行 / CNY 价行因 INNER JOIN + currency='USD' 自然不计入
    /// （已知漏口，见 spec §2.4，不静默换算）。`key_id` 为空的 legacy 行计入站级
    /// 已花（属于该站），key 级查询因 `u.key_id = ?` 自然排除它们（无法归因）。
    pub fn budget_spent_usd(&self, site_id: i64, key_id: Option<i64>, period: &str) -> Result<f64> {
        let (start, end) = self.budget_period_bounds(period)?;
        let conn = self.lock()?;
        let mut sql = "SELECT COALESCE(ROUND(SUM(ROUND(
                u.prompt_tokens / 1000000.0 * p.input_per_mtok
              + u.completion_tokens / 1000000.0 * p.output_per_mtok, 6)), 6), 0)
             FROM gateway_usage_log u
             JOIN model_prices p
               ON p.model = u.model AND p.currency = 'USD'
              AND p.effective_from = (
                    SELECT MAX(q.effective_from) FROM model_prices q
                     WHERE q.model = u.model AND q.currency = 'USD'
                       AND q.effective_from <= u.at
                  )
             WHERE u.at >= ?1 AND u.at < ?2 AND u.site_id = ?3"
            .to_string();
        if key_id.is_some() {
            sql.push_str(" AND u.key_id = ?4");
        }
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| Error::Store(format!("prepare budget spent: {e}")))?;
        let spent: f64 = match key_id {
            Some(kid) => stmt
                .query_row(params![start, end, site_id, kid], |row| row.get(0))
                .map_err(|e| Error::Store(format!("query budget spent: {e}")))?,
            None => stmt
                .query_row(params![start, end, site_id], |row| row.get(0))
                .map_err(|e| Error::Store(format!("query budget spent: {e}")))?,
        };
        Ok(spent)
    }

    // ======================================================== M43-S2：站点账单

    /// 覆盖写入一天的站点账单（`UNIQUE(site_id, day, source)` 后者胜，不做历史快照）。
    pub fn site_bill_upsert(
        &self,
        site_id: i64,
        day: &str,
        amount: Option<f64>,
        currency: Option<&str>,
        requests: Option<i64>,
        source: &str,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO site_bills(site_id, day, amount, currency, requests, source, fetched_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(site_id, day, source)
             DO UPDATE SET amount = excluded.amount,
                           currency = excluded.currency,
                           requests = excluded.requests,
                           fetched_at = excluded.fetched_at",
            params![site_id, day, amount, currency, requests, source, now_secs()],
        )
        .map_err(|e| Error::Store(format!("写入站点账单失败: {e}")))?;
        Ok(())
    }

    /// 站点账单（近 `days` 天，按日倒序）。
    pub fn site_bills(&self, days: i64) -> Result<Vec<SiteBillRow>> {
        let days = clamp_usage_days(days);
        let conn = self.lock()?;
        let cutoff = local_day_ago(&conn, days - 1)?;
        let mut stmt = conn
            .prepare(
                "SELECT id, site_id, day, amount, currency, requests, source, fetched_at
                 FROM site_bills WHERE day >= ?1 ORDER BY day DESC, site_id ASC",
            )
            .map_err(|e| Error::Store(format!("prepare site bills: {e}")))?;
        let rows = stmt
            .query_map(params![cutoff], |row| {
                Ok(SiteBillRow {
                    id: row.get(0)?,
                    site_id: row.get(1)?,
                    day: row.get(2)?,
                    amount: row.get(3)?,
                    currency: row.get(4)?,
                    requests: row.get(5)?,
                    source: row.get(6)?,
                    fetched_at: row.get(7)?,
                })
            })
            .map_err(|e| Error::Store(format!("query site bills: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("collect site bills: {e}")))
    }

    /// M34-S1：近 `days` 天余额快照，按（本地日, 站点）聚合，每天取**最后一条**。
    ///
    /// 用 `ROW_NUMBER() OVER (PARTITION BY 日, 站点 ORDER BY ts DESC, id DESC)` 而不是
    /// `MAX(id)`：`MAX(id)` 只在「id 与 ts 单调同序」时成立，而快照的 ts 是写入时刻，
    /// 排序口径要按**时间**而不是按自增号（同秒多条时再用 id 兜底）。
    pub fn usage_snapshot_daily(
        &self,
        days: i64,
        site_id: Option<i64>,
    ) -> Result<Vec<UsageSnapshotDailyRow>> {
        let days = clamp_usage_days(days);
        let conn = self.lock()?;
        let cutoff = local_day_start(&conn, days - 1)?;
        let mut stmt = conn
            .prepare(
                "SELECT d, site_id, used, remaining, currency, samples FROM (
                   SELECT date(ts, 'unixepoch', 'localtime') AS d,
                          site_id, used, remaining, currency,
                          COUNT(*) OVER (
                            PARTITION BY date(ts, 'unixepoch', 'localtime'), site_id
                          ) AS samples,
                          ROW_NUMBER() OVER (
                            PARTITION BY date(ts, 'unixepoch', 'localtime'), site_id
                            ORDER BY ts DESC, id DESC
                          ) AS rn
                   FROM usage_snapshots
                   -- `known = 0`（余额不可观测）的快照不画进趋势：它的 used/remaining
                   -- 没有意义，混进去会把「不知道」显示成一条 0 余额的线（复审 P3-9）。
                   WHERE known = 1 AND ts >= ?1 AND (?2 IS NULL OR site_id = ?2)
                 )
                 WHERE rn = 1
                 ORDER BY d ASC, site_id ASC",
            )
            .map_err(|e| Error::Store(format!("prepare usage snapshot daily: {e}")))?;
        let rows = stmt
            .query_map(params![cutoff, site_id], |row| {
                Ok(UsageSnapshotDailyRow {
                    date: row.get(0)?,
                    site_id: row.get(1)?,
                    used: row.get(2)?,
                    remaining: row.get(3)?,
                    currency: row.get(4)?,
                    samples: row.get(5)?,
                })
            })
            .map_err(|e| Error::Store(format!("query usage snapshot daily: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("collect usage snapshot daily: {e}")))
    }

    /// M34-S1：近 `days` 天 `usage_samples` 按 key 汇总（join `keys` 取名字与币种）。
    ///
    /// 窗口按 `usage_samples.date`（站点给的 `YYYY-MM-DD`）比较，不按 `sampled_at`：
    /// 每轮刷新会覆盖同日全部采样，`sampled_at` 总是「最近一轮」，用它过滤会把
    /// 30 天前采集到的历史日也算进「近 7 天」。`date` 的时区归属站点，本产品不改写。
    pub fn key_usage_totals(
        &self,
        days: i64,
        site_id: Option<i64>,
    ) -> Result<Vec<KeyUsageTotalRow>> {
        let days = clamp_usage_days(days);
        let conn = self.lock()?;
        let cutoff_date = local_day_ago(&conn, days - 1)?;
        let mut stmt = conn
            .prepare(
                "SELECT us.key_id, us.site_id, k.name,
                        COALESCE(SUM(us.requests), 0),
                        COALESCE(SUM(us.input_tokens), 0),
                        COALESCE(SUM(us.output_tokens), 0),
                        COALESCE(SUM(us.total_tokens), 0) AS total,
                        SUM(CASE WHEN us.cost_reported = 1 THEN us.cost END),
                        k.currency
                 FROM usage_samples us
                 JOIN keys k ON k.id = us.key_id
                 WHERE us.date >= ?1 AND (?2 IS NULL OR us.site_id = ?2)
                 GROUP BY us.key_id, us.site_id, k.name, k.currency
                 ORDER BY total DESC, us.key_id ASC",
            )
            .map_err(|e| Error::Store(format!("prepare key usage totals: {e}")))?;
        let rows = stmt
            .query_map(params![cutoff_date, site_id], |row| {
                Ok(KeyUsageTotalRow {
                    key_id: row.get(0)?,
                    site_id: row.get(1)?,
                    key_name: row.get(2)?,
                    requests: row.get(3)?,
                    input_tokens: row.get(4)?,
                    output_tokens: row.get(5)?,
                    total_tokens: row.get(6)?,
                    cost: row.get(7)?, // Option<f64>：全部未上报 ⇒ NULL
                    currency: row.get(8)?,
                })
            })
            .map_err(|e| Error::Store(format!("query key usage totals: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("collect key usage totals: {e}")))
    }

    // ============================================================ M14-S1：模型别名映射（B-110）

    /// 列出全部别名映射（B-110）。按 `alias` 升序——确定顺序，与
    /// [`routing::alias_map`] 的 `BTreeMap` 遍历序一致。
    ///
    /// 只读，不持有任何锁之外的状态。返回 `Vec<(alias, real_model)>`。
    pub fn list_alias_map(&self) -> Result<Vec<(String, String)>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT alias, real_model FROM model_aliases ORDER BY alias ASC")
            .map_err(|e| Error::Store(format!("prepare alias map: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| Error::Store(format!("query alias map: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("collect alias map: {e}")))
    }

    /// 插入或覆盖一条别名映射（B-110）。`alias` 为主键 ⇒ 重复后者胜，
    /// 与 [`routing::alias_map`] 的 `BTreeMap::insert` 语义一致。
    ///
    /// **纵深防御**：空 / 空白 / 超长（>128）入参在这里就拒绝——命令层也校验，
    /// 两层都校验不冲突；store 层是最后一道（防绕过命令层直接写库的路径）。
    /// 入参先 `trim`：用户前后空格不构成 alias 的一部分。
    pub fn upsert_alias(&self, alias: &str, real_model: &str) -> Result<()> {
        let alias = alias.trim();
        let real_model = real_model.trim();
        if alias.is_empty() || real_model.is_empty() {
            return Err(Error::Store("alias 与 real_model 都不能为空或空白".into()));
        }
        if alias.len() > 128 || real_model.len() > 128 {
            return Err(Error::Store("alias 与 real_model 长度上限 128".into()));
        }
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO model_aliases(alias, real_model, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(alias) DO UPDATE SET real_model = ?2, updated_at = ?3",
            params![alias, real_model, now_secs()],
        )
        .map_err(|e| Error::Store(format!("upsert alias: {e}")))?;
        Ok(())
    }

    /// 删除一条别名映射（B-110）。不存在的 `alias` ⇒ 幂等返回 `Ok(())`
    /// （解绑是收尾动作，二次调用不该报错，与 `unbind_*` 同口径）。
    /// 入参先 `trim`：与 `upsert` 同口径，防止「存的是 trimmed、删的是带空格」导致删不掉。
    pub fn delete_alias(&self, alias: &str) -> Result<()> {
        let alias = alias.trim();
        let conn = self.lock()?;
        conn.execute("DELETE FROM model_aliases WHERE alias = ?1", params![alias])
            .map_err(|e| Error::Store(format!("delete alias: {e}")))?;
        Ok(())
    }

    // ---- M15-S1：模型检测历史（probe_runs）----

    /// M15-S1：写入一次 probe 检测结果摘要。只存身份判定字段，
    /// **不存** items[].response / responseHeaders / startedByIp / userKey（敏感）。
    ///
    /// B-135：`status`（run 生命周期）也写进去——历史表靠它区分
    /// 「跑完但没判定」与「没跑完」（两者 verdict 都是 NULL，只靠 verdict 分不开）。
    pub fn insert_probe_run(
        &self,
        site_id: i64,
        key_id: i64,
        model_id: &str,
        claimed_model: Option<&str>,
        run: &crate::probe::ProbeRun,
    ) -> Result<i64> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO probe_runs
             (run_id, site_id, key_id, model_id, claimed_model, identity_status, verdict_status,
              true_family, true_model, spoof_method, confidence, warnings_count, report_url,
              bazaarlink_created_at, bazaarlink_completed_at, recorded_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                run.run_id,
                site_id,
                key_id,
                model_id,
                claimed_model,
                run.identity_status,
                run.verdict_status,
                run.true_family,
                run.true_model,
                run.spoof_method,
                run.confidence,
                run.warnings_count,
                run.report_url,
                run.created_at,
                run.completed_at,
                now_secs(),
                run.status
            ],
        )
        .map_err(|e| Error::Store(format!("insert probe run: {e}")))?;
        Ok(conn.last_insert_rowid())
    }

    /// M15-S1：最近 `limit` 条检测历史，按 `recorded_at` 降序（最新在前）。上限 200。
    pub fn list_probe_runs(&self, limit: usize) -> Result<Vec<ProbeRunRow>> {
        let limit = limit.min(200) as i64;
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, run_id, site_id, key_id, model_id, claimed_model, identity_status,
                        verdict_status, true_family, true_model, spoof_method, confidence,
                        warnings_count, report_url, bazaarlink_created_at,
                        bazaarlink_completed_at, recorded_at, status
                 FROM probe_runs ORDER BY recorded_at DESC LIMIT ?1",
            )
            .map_err(|e| Error::Store(format!("prepare list probe runs: {e}")))?;
        let rows = stmt
            .query_map(params![limit], ProbeRunRow::from_row)
            .map_err(|e| Error::Store(format!("query probe runs: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("collect probe runs: {e}")))
    }

    /// M15-S1：按本地 id 取单条检测记录。
    pub fn get_probe_run(&self, id: i64) -> Result<Option<ProbeRunRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, run_id, site_id, key_id, model_id, claimed_model, identity_status,
                        verdict_status, true_family, true_model, spoof_method, confidence,
                        warnings_count, report_url, bazaarlink_created_at,
                        bazaarlink_completed_at, recorded_at, status
                 FROM probe_runs WHERE id = ?1",
            )
            .map_err(|e| Error::Store(format!("prepare get probe run: {e}")))?;
        let mut rows = stmt
            .query_map(params![id], ProbeRunRow::from_row)
            .map_err(|e| Error::Store(format!("query probe run: {e}")))?;
        rows.next()
            .transpose()
            .map_err(|e| Error::Store(format!("probe run row: {e}")))
    }

    /// M14-S3：写入 / 覆盖一把 key 一天的用量采样（Sub2API `usage/daily`）。
    /// `UNIQUE(key_id, date)` + `INSERT OR REPLACE`：每轮覆盖同日，不堆积。
    pub fn upsert_usage_sample(
        &self,
        key_id: i64,
        site_id: i64,
        sample: &crate::site::KeyDailyUsage,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR REPLACE INTO usage_samples
             (key_id, site_id, date, requests, input_tokens, output_tokens, total_tokens, cost, sampled_at, cost_reported)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                key_id,
                site_id,
                sample.date,
                sample.requests,
                sample.input_tokens,
                sample.output_tokens,
                sample.total_tokens,
                sample.cost,
                now_secs(),
                if sample.cost_reported { 1 } else { 0 }
            ],
        )
        .map_err(|e| Error::Store(format!("upsert usage sample: {e}")))?;
        Ok(())
    }

    /// M14-S3：查一把 key 近 `days` 天内采集的用量采样，按 `date` 升序（前端趋势用）。
    ///
    /// 过滤用 `sampled_at`（采集时间）而非 `date`（站点侧日期）：每轮覆盖同日，
    /// `sampled_at` 总是最近一轮；`days=30` 覆盖最近一轮的全部 30 天 `date`。
    /// 前端若要更窄的 date 窗口，在返回数据上自行截断。
    pub fn recent_key_usage(&self, key_id: i64, days: i64) -> Result<Vec<UsageSampleRow>> {
        let days = days.max(1);
        let cutoff = now_secs() - days * 86400;
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, key_id, site_id, date, requests, input_tokens, output_tokens,
                        total_tokens, cost, sampled_at
                 FROM usage_samples
                 WHERE key_id = ?1 AND sampled_at >= ?2
                 ORDER BY date ASC LIMIT 90",
            )
            .map_err(|e| Error::Store(format!("prepare: {e}")))?;
        let rows = stmt
            .query_map(params![key_id, cutoff], |row| {
                Ok(UsageSampleRow {
                    id: row.get(0)?,
                    key_id: row.get(1)?,
                    site_id: row.get(2)?,
                    date: row.get(3)?,
                    requests: row.get(4)?,
                    input_tokens: row.get(5)?,
                    output_tokens: row.get(6)?,
                    total_tokens: row.get(7)?,
                    cost: row.get(8)?,
                    sampled_at: row.get(9)?,
                })
            })
            .map_err(|e| Error::Store(format!("query: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("collect: {e}")))
    }

    /// M14-S3：更新本地 key 行的当前累计用量（NewAPI / Sub2API 都用）。
    /// `None` 写 `NULL`（不是 0——「不知道」与「用 0」必须分开，与 `Balance::known` 同纪律）。
    pub fn update_key_usage(
        &self,
        key_id: i64,
        quota_used: Option<f64>,
        quota_limit: Option<f64>,
        currency: Option<&str>,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE keys SET quota_used = ?2, quota_limit = ?3, currency = ?4 WHERE id = ?1",
            params![key_id, quota_used, quota_limit, currency],
        )
        .map_err(|e| Error::Store(format!("update key usage: {e}")))?;
        Ok(())
    }

    /// M14-S3：裁剪用量采样，只保留最近 N 天。在 `refresh_all` 里调用。
    pub fn prune_usage_samples(&self, days: i64) -> Result<usize> {
        let cutoff = now_secs() - days * 86400;
        let conn = self.lock()?;
        let n = conn
            .execute(
                "DELETE FROM usage_samples WHERE sampled_at < ?1",
                params![cutoff],
            )
            .map_err(|e| Error::Store(format!("prune usage samples: {e}")))?;
        Ok(n)
    }

    // ---- M39-S1：站点模型目录 ----

    /// 成功且**非空**：替换该站集合（删掉不在 `models` 里的行；保留行的 `first_seen_at` 不动、
    /// `last_seen_at = now`；新行 `first_seen_at = last_seen_at = now`），并把 sync 行置为
    /// `(last_attempt_at = now, last_success_at = now, empty_streak = 0, last_error = NULL)`。
    ///
    /// **单事务**：中途失败不会留下「删了一半」的目录（那会让路由少一半上游）。
    /// 空列表**必须**走 [`Self::record_site_models_empty`]——静默清空正是 M39-S1 要消灭的
    /// 「瞬时空响应删目录」入口。
    pub fn replace_site_models(&self, site_id: i64, models: &[String], now: i64) -> Result<usize> {
        let mut normalized: Vec<String> = Vec::new();
        for raw in models {
            let model = raw.trim();
            if model.is_empty() {
                continue;
            }
            if !normalized.iter().any(|kept| kept == model) {
                normalized.push(model.to_string());
            }
        }
        if normalized.is_empty() {
            return Err(Error::Store(
                "replace_site_models 被空列表调用：空结果必须走 record_site_models_empty".into(),
            ));
        }

        let mut conn = self.lock()?;
        let tx = conn
            .transaction()
            .map_err(|e| Error::Store(format!("begin: {e}")))?;

        let existing: Vec<String> = {
            let mut stmt = tx
                .prepare("SELECT model FROM site_model_catalog WHERE site_id = ?1")
                .map_err(|e| Error::Store(format!("prepare catalog: {e}")))?;
            let rows = stmt
                .query_map(params![site_id], |row| row.get::<_, String>(0))
                .map_err(|e| Error::Store(format!("query catalog: {e}")))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| Error::Store(format!("collect catalog: {e}")))?
        };
        for stale in existing
            .iter()
            .filter(|old| !normalized.iter().any(|new| new == *old))
        {
            tx.execute(
                "DELETE FROM site_model_catalog WHERE site_id = ?1 AND model = ?2",
                params![site_id, stale],
            )
            .map_err(|e| Error::Store(format!("delete catalog row: {e}")))?;
        }
        for model in &normalized {
            // `DO UPDATE` 只刷 `last_seen_at`：`first_seen_at` 是「这个模型第一次在这站出现」，
            // 替换语义下它不该被重置（那等于把目录当重建）。
            tx.execute(
                "INSERT INTO site_model_catalog(site_id, model, first_seen_at, last_seen_at)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(site_id, model) DO UPDATE SET last_seen_at = excluded.last_seen_at",
                params![site_id, model, now],
            )
            .map_err(|e| Error::Store(format!("upsert catalog row: {e}")))?;
        }
        tx.execute(
            "INSERT INTO site_model_sync(
                 site_id, last_success_at, last_attempt_at, empty_streak, last_error)
             VALUES (?1, ?2, ?2, 0, NULL)
             ON CONFLICT(site_id) DO UPDATE SET
                 last_success_at = excluded.last_success_at,
                 last_attempt_at = excluded.last_attempt_at,
                 empty_streak = 0,
                 last_error = NULL",
            params![site_id, now],
        )
        .map_err(|e| Error::Store(format!("upsert model sync: {e}")))?;
        tx.commit()
            .map_err(|e| Error::Store(format!("commit: {e}")))?;
        Ok(normalized.len())
    }

    /// 成功但**空**：`empty_streak += 1`，同步 `last_attempt_at` / `last_success_at = now`；
    /// 达到 [`EMPTY_STREAK_TO_CLEAR`] 时**在同一事务里**清空该站目录。
    pub fn record_site_models_empty(&self, site_id: i64, now: i64) -> Result<EmptyOutcome> {
        let mut conn = self.lock()?;
        let tx = conn
            .transaction()
            .map_err(|e| Error::Store(format!("begin: {e}")))?;
        tx.execute(
            "INSERT INTO site_model_sync(
                 site_id, last_success_at, last_attempt_at, empty_streak, last_error)
             VALUES (?1, ?2, ?2, 1, NULL)
             ON CONFLICT(site_id) DO UPDATE SET
                 last_success_at = excluded.last_success_at,
                 last_attempt_at = excluded.last_attempt_at,
                 empty_streak = site_model_sync.empty_streak + 1",
            params![site_id, now],
        )
        .map_err(|e| Error::Store(format!("bump empty streak: {e}")))?;
        let streak: i64 = tx
            .query_row(
                "SELECT empty_streak FROM site_model_sync WHERE site_id = ?1",
                params![site_id],
                |row| row.get(0),
            )
            .map_err(|e| Error::Store(format!("read empty streak: {e}")))?;
        let cleared = streak >= EMPTY_STREAK_TO_CLEAR;
        if cleared {
            tx.execute(
                "DELETE FROM site_model_catalog WHERE site_id = ?1",
                params![site_id],
            )
            .map_err(|e| Error::Store(format!("clear catalog: {e}")))?;
        }
        tx.commit()
            .map_err(|e| Error::Store(format!("commit: {e}")))?;
        Ok(EmptyOutcome { streak, cleared })
    }

    /// 失败：只写 `last_attempt_at = now` 与 `last_error`；**不动**目录、**不动**
    /// `empty_streak`、**不动** `last_success_at`（失败不是「站点说没有模型」的证据）。
    ///
    /// **红线（M39-S1 §12）**：错误文本在这里**再**脱敏 + 截断到
    /// [`MODEL_SYNC_ERROR_MAX_CHARS`]——调用方已 scrub 也幂等；store 是最后一道。
    pub fn record_site_models_failure(&self, site_id: i64, now: i64, error: &str) -> Result<()> {
        let scrubbed = crate::redact::scrub(error);
        let text: String = scrubbed.chars().take(MODEL_SYNC_ERROR_MAX_CHARS).collect();
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO site_model_sync(
                 site_id, last_success_at, last_attempt_at, empty_streak, last_error)
             VALUES (?1, NULL, ?2, 0, ?3)
             ON CONFLICT(site_id) DO UPDATE SET
                 last_attempt_at = excluded.last_attempt_at,
                 last_error = excluded.last_error",
            params![site_id, now, text],
        )
        .map_err(|e| Error::Store(format!("record model sync failure: {e}")))?;
        Ok(())
    }

    /// 全量目录：`site_id → 模型名（按字节序升序）`。只有**有行**的站点出现在结果里。
    ///
    /// 这是路由构建的唯一模型来源（M39-S1 §5.3）：每次建路由/发布快照都现读，
    /// 因此不存在「内存缓存与表不一致」，也不需要「启动时加载」这一步。
    pub fn site_model_catalog(&self) -> Result<std::collections::BTreeMap<i64, Vec<String>>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT site_id, model FROM site_model_catalog ORDER BY site_id ASC, model ASC",
            )
            .map_err(|e| Error::Store(format!("prepare catalog: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| Error::Store(format!("query catalog: {e}")))?;
        let mut out: std::collections::BTreeMap<i64, Vec<String>> =
            std::collections::BTreeMap::new();
        for row in rows {
            let (site_id, model) =
                row.map_err(|e| Error::Store(format!("collect catalog: {e}")))?;
            out.entry(site_id).or_default().push(model);
        }
        Ok(out)
    }

    /// 单站目录（升序）。没有行 ⇒ 空 vec（**不是** `None`：空与「没有这个站」在路由层同义）。
    pub fn site_models(&self, site_id: i64) -> Result<Vec<String>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT model FROM site_model_catalog WHERE site_id = ?1 ORDER BY model ASC")
            .map_err(|e| Error::Store(format!("prepare site models: {e}")))?;
        let rows = stmt
            .query_map(params![site_id], |row| row.get::<_, String>(0))
            .map_err(|e| Error::Store(format!("query site models: {e}")))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Store(format!("collect site models: {e}")))
    }

    /// 单站同步状态。没有行 ⇒ `Ok(None)`。
    pub fn site_model_sync(&self, site_id: i64) -> Result<Option<SiteModelSync>> {
        use rusqlite::OptionalExtension;
        let conn = self.lock()?;
        conn.query_row(
            "SELECT site_id, last_success_at, last_attempt_at, empty_streak, last_error
             FROM site_model_sync WHERE site_id = ?1",
            params![site_id],
            |row| {
                Ok(SiteModelSync {
                    site_id: row.get(0)?,
                    last_success_at: row.get(1)?,
                    last_attempt_at: row.get(2)?,
                    empty_streak: row.get(3)?,
                    last_error: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|e| Error::Store(format!("read model sync: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inject::JournalEntry;
    use std::path::PathBuf;

    #[test]
    fn migrate_adds_new_tables_to_an_existing_database() {
        // M1-S4 实测回归：往 DDL 里新增表后，**已经存在的库**也必须补建。
        // 旧实现只在 `user_version < SCHEMA_VERSION` 时跑 DDL，
        // 于是「加了 consents 却不改版本号」会让旧库永远缺这张表。
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("tianshu-relay.db");

        {
            let store = Store::open(&path).expect("首次建库");
            assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        }

        // 模拟「旧版库」：把新表与新索引删掉，版本号保持不变
        {
            let conn = rusqlite::Connection::open(&path).expect("直连库");
            conn.execute_batch("DROP TABLE consents; DROP INDEX idx_events_ts;")
                .expect("删表");
        }

        let store = Store::open(&path).expect("重新打开");
        let conn = rusqlite::Connection::open(&path).expect("直连库");
        let consents: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='consents'",
                [],
                |row| row.get(0),
            )
            .expect("查表");
        let index: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_events_ts'",
                [],
                |row| row.get(0),
            )
            .expect("查索引");
        assert_eq!(consents, 1, "已存在的库必须补建 consents 表");
        assert_eq!(index, 1, "已存在的库必须补建 idx_events_ts 索引");

        // 补建后功能可用（不是只有表壳）
        store
            .grant_consent("codex", "codex-auth-json", "/tmp/auth.json", &["k".into()])
            .expect("写入同意");
        assert_eq!(store.list_consents().unwrap().len(), 1);
    }

    #[test]
    fn record_binding_persists_delivery_mode() {
        // P1-2：delivery_mode 写入 bindings，BindingRow 读回。
        let dir = tempfile::tempdir().expect("临时目录");
        let store = Store::open(&dir.path().join("tianshu-relay.db")).expect("建库");
        let site_id = store
            .upsert_site("newapi", "https://relay.example.com", "测试")
            .unwrap();
        let reference = crate::vault::secret_ref("key", 1, "secret");
        let key_id = store
            .insert_key(site_id, "codex/daily", &reference, Some("1"), None)
            .unwrap();
        store
            .record_binding("codex", key_id, "/t", "j1", "gateway")
            .unwrap();
        store
            .record_binding("codex", key_id, "/t", "j2", "site")
            .unwrap();
        let bindings = store.bindings_of_agent("codex").unwrap();
        let modes: Vec<&str> = bindings.iter().map(|b| b.delivery_mode.as_str()).collect();
        assert!(modes.contains(&"gateway"), "gateway 模式应记: {modes:?}");
        assert!(modes.contains(&"site"), "site 模式应记: {modes:?}");
    }

    #[test]
    fn delivery_mode_column_survives_reopen() {
        // P1-2：migrate 的 add_column_if_missing 幂等——重新打开后 delivery_mode 列仍在，原值保留。
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("tianshu-relay.db");
        {
            let store = Store::open(&path).expect("建库");
            let site_id = store.upsert_site("newapi", "https://x", "t").unwrap();
            let reference = crate::vault::secret_ref("key", 1, "s");
            let key_id = store
                .insert_key(site_id, "n", &reference, Some("1"), None)
                .unwrap();
            store
                .record_binding("codex", key_id, "/t", "j", "gateway")
                .unwrap();
        }
        let store = Store::open(&path).expect("重新打开（migrate 幂等）");
        let bindings = store.bindings_of_agent("codex").unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].delivery_mode, "gateway", "delivery_mode 应保留");
    }

    /// B-135 的 fixture：只填轮询/落库关心的三个字段，其余留空。
    fn probe_run_fixture(run_id: &str, status: &str) -> crate::probe::ProbeRun {
        crate::probe::ProbeRun {
            run_id: run_id.into(),
            status: status.into(),
            identity_status: None,
            verdict_status: None,
            true_family: None,
            true_model: None,
            spoof_method: None,
            confidence: None,
            warnings_count: 0,
            report_url: None,
            created_at: None,
            completed_at: None,
        }
    }

    #[test]
    fn probe_runs_status_column_is_added_to_an_existing_database() {
        // B-135（SCHEMA_VERSION 5 → 6）：**加列必须显式迁移**——DDL 里全是
        // `CREATE TABLE IF NOT EXISTS`，对已存在的表是空操作，往建表语句里加列，
        // 老库永远不会有那一列（这正是 `keys.status` / `bindings.delivery_mode` 那个形态）。
        //
        // 造一个 v5 老库：建库 → 写一行 → 去掉 status 列 → 版本号写回 5。
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("tianshu-relay.db");
        let store = Store::open(&path).expect("建库");
        let site_id = store
            .upsert_site("newapi", "https://relay.example.com", "测试")
            .expect("upsert_site");
        let reference = crate::vault::secret_ref("key", 1, "secret");
        let key_id = store
            .insert_key(site_id, "probe-key", &reference, Some("1"), None)
            .expect("insert_key");
        store
            .insert_probe_run(
                site_id,
                key_id,
                "vendor/model",
                None,
                &probe_run_fixture("r-legacy", "completed"),
            )
            .expect("写入一行（v6 形态）");
        drop(store);

        {
            let conn = rusqlite::Connection::open(&path).expect("直连库");
            conn.execute_batch("ALTER TABLE probe_runs DROP COLUMN status;")
                .expect("模拟 v5 老库（没有 status 列）");
            conn.pragma_update(None, "user_version", 5)
                .expect("版本号写回 5");
        }

        let store = Store::open(&path).expect("重新打开旧库");
        assert_eq!(
            store.schema_version().unwrap(),
            SCHEMA_VERSION,
            "版本号必须被抬到当前值"
        );
        {
            let conn = rusqlite::Connection::open(&path).expect("直连库");
            let has_status: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('probe_runs') WHERE name = 'status'",
                    [],
                    |row| row.get(0),
                )
                .expect("查列");
            assert_eq!(has_status, 1, "老库必须补出 status 列");
        }

        // 老行**不回填**：status 是 NULL（那一列是后加的，历史行没记过状态，不猜）。
        let rows = store.list_probe_runs(10).expect("list_probe_runs");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].run_id, "r-legacy");
        assert_eq!(rows[0].status, None, "历史行不得被推断成 completed");

        // 补列后功能可用（不是只有列壳）：新写入能带状态读回
        store
            .insert_probe_run(
                site_id,
                key_id,
                "vendor/model",
                None,
                &probe_run_fixture("r-new", "running"),
            )
            .expect("旧库补列后必须能写");
        let rows = store.list_probe_runs(10).expect("list_probe_runs");
        // 按 run_id 找，不看 rows[0]：两行 recorded_at 同秒，DESC 排序不保证先后。
        let fresh = rows
            .iter()
            .find(|r| r.run_id == "r-new")
            .expect("刚写入的行");
        assert_eq!(fresh.status.as_deref(), Some("running"));
    }

    #[test]
    fn probe_run_row_roundtrips_lifecycle_status() {
        // B-135：`list` 与 `get` 都必须带回 status（两条 SELECT 的列序要一致）。
        let store = Store::open_in_memory().unwrap();
        let site_id = store
            .upsert_site("newapi", "https://relay.example.com", "测试")
            .unwrap();
        let reference = crate::vault::secret_ref("key", 1, "secret");
        let key_id = store
            .insert_key(site_id, "probe-key", &reference, Some("1"), None)
            .unwrap();
        let id = store
            .insert_probe_run(
                site_id,
                key_id,
                "vendor/model",
                Some("vendor/model"),
                &probe_run_fixture("r-running", "running"),
            )
            .unwrap();

        let row = store.get_probe_run(id).unwrap().expect("按 id 取回");
        assert_eq!(row.status.as_deref(), Some("running"));
        assert_eq!(row.verdict_status, None, "没跑完 ⇒ 无判定");
        assert!(row.recorded_at > 0, "落库时间仍在");

        let listed = store.list_probe_runs(10).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].status.as_deref(), Some("running"));
    }

    #[test]
    fn migrate_is_idempotent() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        store.migrate().unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn add_column_is_race_safe_when_the_column_appears_concurrently() {
        // **M16-S1 / P3-1 的确定性复现**（不靠概率）：
        // 把「另一个连接在窗口里把列加上」钉死在「查列」与「ALTER」之间——
        // 这正是两个进程首次打开同一个老库时必现的窗口。旧实现在最后一步
        // 直接 `Err(duplicate column name)` ⇒ `Store::open` 失败（报告实测 18/400）。
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("race.db");

        let conn_a = rusqlite::Connection::open(&path).expect("连接 A");
        conn_a
            .execute_batch("CREATE TABLE t(id INTEGER PRIMARY KEY)")
            .expect("建表");
        let conn_b = rusqlite::Connection::open(&path).expect("连接 B");

        let mut raced = false;
        let result = add_column_if_missing_with(&conn_a, "t", "extra", "INTEGER", || {
            // 窗口：B（另一个连接）抢先把列加上并提交。A 的「查列」已经过去、还没 ALTER。
            add_column_unchecked(&conn_b, "t", "extra", "INTEGER").expect("B 先加列");
            raced = true;
        });
        assert!(
            raced,
            "夹具：窗口必须被走到（若没走到，说明「查列」那步就早返回了，这条用例没在测竞态）"
        );
        result.expect("并发下应视为成功（复验列已存在），而不是报 duplicate column");
        assert!(column_exists(&conn_a, "t", "extra").unwrap());

        // 幂等：再调一次仍然 Ok（这次走「列已存在」的早返回）
        add_column_if_missing(&conn_a, "t", "extra", "INTEGER").expect("重复调用应幂等");
    }

    #[test]
    fn add_column_still_reports_real_errors() {
        // 反例保护：复验机制**不许**把真错误吞掉——表不存在时必须照旧 `Err`。
        let store = Store::open_in_memory().unwrap();
        let conn = store.lock().unwrap();
        let err = add_column_if_missing(&conn, "no_such_table", "extra", "INTEGER")
            .expect_err("表不存在应报错");
        let text = err.to_string();
        assert!(text.contains("no_such_table"), "错误里应带上表名: {text}");
    }

    #[test]
    fn concurrent_first_upgrade_of_an_old_database_all_succeed() {
        // 老库形态：`bindings` 表存在但缺 M8-S4 / P1-2 之后加的两列
        // （`unbound_at` / `delivery_mode`）⇒ 每个打开者都会走一次 `add_column_if_missing`。
        // N 个线程同时首次打开：全部应成功，列只加一次。
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("old.db");
        {
            let conn = rusqlite::Connection::open(&path).expect("造老库");
            conn.execute_batch(
                "CREATE TABLE bindings(
                   id INTEGER PRIMARY KEY,
                   agent_id TEXT NOT NULL,
                   key_id INTEGER NOT NULL,
                   target_path TEXT NOT NULL,
                   managed_json TEXT,
                   applied_at INTEGER NOT NULL,
                   journal_id TEXT
                 );",
            )
            .expect("建老表");
        }

        const THREADS: usize = 4;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let path = path.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    Store::open(&path).map(|_| ())
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let failures: Vec<String> = results
            .iter()
            .filter_map(|r| r.as_ref().err().map(|e| e.to_string()))
            .collect();
        assert!(failures.is_empty(), "并发首次升级不得失败: {failures:?}");

        let store = Store::open(&path).expect("再开一次");
        let conn = store.lock().unwrap();
        assert!(column_exists(&conn, "bindings", "unbound_at").unwrap());
        assert!(column_exists(&conn, "bindings", "delivery_mode").unwrap());
    }

    /// B-156 / M24-S1：`budget = 0` 时**零重试、立即放弃**。
    ///
    /// 这条同时是「忙等真的被关掉了」的判据：旧实现会在第一次尝试里等满
    /// `busy_timeout(5s)` 才拿到 `SQLITE_BUSY`，所以 2s 的上界能把它区分出来。
    #[test]
    fn open_gives_up_immediately_when_the_budget_is_zero() {
        let (dir, path) = make_rollback_journal_db_for_test();
        let blocker = hold_exclusive_lock_for_test(&path);

        let started = Instant::now();
        let err = match Store::open_with_budget(&path, Duration::ZERO) {
            Ok(_) => panic!("预算为 0 且锁被持有 ⇒ 必须立即放弃"),
            Err(err) => err,
        };
        let elapsed = started.elapsed();
        drop(blocker);

        let text = err.to_string();
        assert!(
            text.contains("切换 WAL 模式失败"),
            "文案应说清是切 WAL 失败: {text}"
        );
        assert!(
            text.contains("重试 0 次"),
            "预算为 0 必须零重试（旧实现是 40 次）: {text}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "预算为 0 时必须立刻返回（实测 {elapsed:?}）；>2s 说明忙等没关掉（旧实现会等满 5s）"
        );
        drop(dir);
    }

    /// B-156 / M24-S1：预算**真的**是等待的唯一来源——100ms 预算就该在 ~100ms 放弃。
    ///
    /// 上界 900ms 是刻意的：旧实现（40 次 × 25ms = 1000ms 的**次数**预算）会越过它 ⇒ 变红。
    /// 只断言「有界」而不钉住量级，就抓不到「把预算偷偷改回次数」这种回退。
    #[test]
    fn open_gives_up_after_the_budget_and_says_how_many_retries() {
        let (dir, path) = make_rollback_journal_db_for_test();
        let blocker = hold_exclusive_lock_for_test(&path);

        let started = Instant::now();
        let err = match Store::open_with_budget(&path, Duration::from_millis(100)) {
            Ok(_) => panic!("锁一直不放时必须按预算放弃，而不是无限等"),
            Err(err) => err,
        };
        let elapsed = started.elapsed();
        drop(blocker);

        let text = err.to_string();
        assert!(
            text.contains("切换 WAL 模式失败"),
            "文案应说清是切 WAL 失败: {text}"
        );
        assert!(
            text.contains("预算 0s"),
            "预算 100ms 被 as_secs() 截成 0s，文案里应能看到预算: {text}"
        );
        let retries: u32 = text
            .split("重试 ")
            .nth(1)
            .and_then(|s| s.split(" 次").next())
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("文案里应报出真实重试次数: {text}"));
        assert!(retries > 0, "预算 100ms 内必须真的重试过: {text}");
        assert!(
            elapsed >= Duration::from_millis(90),
            "至少要等掉整个预算（实测 {elapsed:?}，预算 100ms）"
        );
        assert!(
            elapsed < Duration::from_millis(900),
            "必须按预算放弃而不是按次数（实测 {elapsed:?}）；>900ms 说明预算被改成了 40 次盲重试"
        );
        drop(dir);
    }

    /// B-156 / M24-S1 / 复审 P2-1：**默认预算本身**必须被钉住。
    ///
    /// 为什么需要这条：本步的标题级成果是「206s → 10s」，但其它用例都走**注入预算**
    /// （0 / 100ms / 300ms），默认预算只剩「> 6s」这条隐式下界。把 `WAL_LOCK_BUDGET`
    /// 悄悄改成 200s，全部测试仍然绿 ⇒ 回退是静默的。这里直接把数字钉死：
    /// 改它就必须同时改这条断言，评审时逃不掉。
    ///
    /// 刻意**不**给 6s 那条用例加上界（复审建议的 `< 8s`）：B-163 的教训是墙上时钟上界
    /// 会被满载误伤（6s 的持锁窗口 + 机器 I/O 停顿时很容易越过 8s），而「能静默回退的东西」
    /// 是这个常量，不是那条用例的耗时。
    #[test]
    fn wal_budget_is_pinned_so_the_206s_regression_cannot_sneak_back() {
        assert_eq!(
            WAL_LOCK_BUDGET,
            Duration::from_secs(10),
            "默认预算变了就重跑 B-156 的标定：旧实现是 ≈206s，本步把它压到 10s"
        );
        assert_eq!(
            WAL_RETRY_INTERVAL,
            Duration::from_millis(25),
            "轮询间隔变了要重新评估「预算内会试几次」"
        );
        assert!(
            WAL_LOCK_BUDGET > Duration::from_secs(6),
            "预算必须大于 6s 持锁用例的窗口，否则那条用例会变成必然失败"
        );
    }

    /// B-156 / M24-S1 / 复审 P3-4：**非 busy 类错误一次都不重试**，直接冒泡。
    ///
    /// 判据是错误码（`is_sqlite_busy`），所以「文件不是数据库」这种错必须**立即**报出来，
    /// 不能被当成「别人拿着锁」去轮询 —— 那会把一个永久性错误拖成 10s 的假等待。
    /// 这条同时给 `is_sqlite_busy` 加了回归钉：将来把它放宽成「任何 `SqliteFailure`」就红。
    #[test]
    fn open_does_not_retry_non_busy_errors() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("not-a-database.db");
        // 一个**能打开、但不是数据库**的文件：`Connection::open` 是惰性的（成功），
        // 第一条要读文件头的语句才报 `SQLITE_NOTADB`。
        std::fs::write(&path, b"this is definitely not a sqlite database file")
            .expect("写垃圾文件");

        let started = Instant::now();
        let err = match Store::open_with_budget(&path, Duration::from_secs(10)) {
            Ok(_) => panic!("垃圾文件不可能打开成功"),
            Err(err) => err,
        };
        let elapsed = started.elapsed();

        let text = err.to_string();
        assert!(
            text.contains("重试 0 次"),
            "非 busy 错误不许进重试循环（文案里应是重试 0 次）: {text}"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "非 busy 错误必须立即冒泡（实测 {elapsed:?}）；>1s 说明被当成锁争用去轮询了"
        );
        drop(dir);
    }

    /// B-156 / M24-S1：WAL 切换成功后必须**恢复**忙等，否则之后所有并发写都不再等待。
    ///
    /// 判据是行为而不是内部状态（`busy_timeout` 不可查询）：另一连接持写锁 1.2s，
    /// 从 `Store` 做一次写必须**等过去**；若恢复那行被删掉，这次写会立刻
    /// `database is locked`（或直接失败）。
    #[test]
    fn open_restores_the_busy_timeout_for_later_writes() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("tianshu-relay.db");
        let store = Store::open(&path).expect("首次建库");

        let blocker = hold_exclusive_lock_for_test(&path);
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1_200));
            // 连接关闭 ⇒ 未提交事务回滚 ⇒ 锁释放
            drop(blocker);
        });

        let started = Instant::now();
        store
            .set_setting("m24s1.probe", "ok")
            .expect("恢复忙等后这次写必须等到锁释放，而不是立刻报 database is locked");
        let elapsed = started.elapsed();
        releaser.join().expect("放锁线程");

        assert!(
            elapsed >= Duration::from_millis(900),
            "必须等过持锁窗口（实测 {elapsed:?}）；没等就说明 busy_timeout 没恢复"
        );
    }

    /// 造一个**非 WAL** 的库文件：只有「从 rollback journal 切到 WAL」才需要独占锁。
    /// 夹具自断言初始模式是 `delete`，否则用例会变成空跑（B-140 的教训）。
    fn make_rollback_journal_db_for_test() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("tianshu-relay.db");
        let conn = Connection::open(&path).expect("建库");
        conn.execute_batch("CREATE TABLE probe(id INTEGER PRIMARY KEY, note TEXT);")
            .expect("建表");
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("读 journal_mode");
        assert_eq!(
            mode, "delete",
            "夹具必须是非 WAL 库（否则切 WAL 不需要独占锁，用例会空跑）"
        );
        (dir, path)
    }

    /// 拿一把排他锁：`BEGIN EXCLUSIVE` 立刻拿锁，不依赖线程调度。
    fn hold_exclusive_lock_for_test(path: &Path) -> Connection {
        let conn = Connection::open(path).expect("锁连接");
        conn.execute_batch("BEGIN EXCLUSIVE").expect("拿排他锁");
        conn
    }

    #[test]
    fn exports_table_is_added_to_an_existing_database() {
        // 与 `migrate_adds_new_tables_to_an_existing_database` 同一条回归：
        // M5-S1 新增了 `exports` 表并把 SCHEMA_VERSION 提到 2，
        // 老库（版本号 1、没有 exports）打开后必须补建，否则 `record_export` 直接 no such table。
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("tianshu-relay.db");

        {
            let conn = rusqlite::Connection::open(&path).expect("直连库");
            conn.execute_batch(
                "CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);",
            )
            .expect("造一个最小旧库");
            conn.pragma_update(None, "user_version", 1)
                .expect("写成旧版本号");
        }

        let store = Store::open(&path).expect("打开旧库");
        assert_eq!(
            store.schema_version().unwrap(),
            SCHEMA_VERSION,
            "版本号必须被抬到当前值"
        );
        store
            .record_export(Path::new("/tmp/old-db-export.json"), false, 12)
            .expect("旧库补建 exports 表后必须能登记");
        assert_eq!(store.list_exports().unwrap().len(), 1);
    }

    #[test]
    fn record_export_upserts_by_path_and_lists_newest_first() {
        let store = Store::open_in_memory().unwrap();
        store
            .record_export(Path::new("/tmp/a.json"), false, 10)
            .unwrap();
        store
            .record_export(Path::new("/tmp/b.krbackup"), false, 20)
            .unwrap();
        // 同一路径再导出一次：覆盖，不新增行
        store
            .record_export(Path::new("/tmp/a.json"), true, 33)
            .unwrap();

        let rows = store.list_exports().unwrap();
        assert_eq!(rows.len(), 2, "同一路径必须覆盖而不是追加");
        // 覆盖后的 a.json 更新，排最前
        assert_eq!(rows[0].path, "/tmp/a.json");
        assert!(rows[0].encrypted);
        assert_eq!(rows[0].bytes, 33);
        assert_eq!(rows[1].path, "/tmp/b.krbackup");
        assert!(!rows[1].encrypted);
    }

    #[test]
    fn set_site_health_persists_and_rejects_an_unknown_site() {
        let store = Store::open_in_memory().unwrap();
        let site = store
            .upsert_site("newapi", "https://h.example.com", "H")
            .unwrap();
        assert_eq!(store.get_site(site).unwrap().unwrap().health, "unknown");

        store.set_site_health(site, "needs_login").unwrap();
        assert_eq!(store.get_site(site).unwrap().unwrap().health, "needs_login");

        let err = store.set_site_health(9999, "ok").unwrap_err();
        assert!(
            err.to_string().contains("站点不存在"),
            "未知站点必须报错而不是静默成功：{}",
            err
        );
    }

    #[test]
    fn upsert_site_dedupes_by_base_url() {
        let store = Store::open_in_memory().unwrap();
        let a = store
            .upsert_site("newapi", "https://a.example.com", "A")
            .unwrap();
        let b = store
            .upsert_site("newapi", "https://a.example.com", "A 改名")
            .unwrap();
        assert_eq!(a, b);
        let sites = store.list_sites().unwrap();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].display_name, "A 改名");
    }

    #[test]
    fn keys_cascade_when_site_deleted() {
        let store = Store::open_in_memory().unwrap();
        let site = store
            .upsert_site("newapi", "https://b.example.com", "B")
            .unwrap();
        store
            .insert_key(site, "codex/daily", "kr/key/1/secret", Some("12"), None)
            .unwrap();
        assert_eq!(store.list_keys().unwrap().len(), 1);

        store.delete_site(site).unwrap();
        assert!(store.list_keys().unwrap().is_empty());
    }

    #[test]
    fn refuses_plaintext_secret_ref() {
        let store = Store::open_in_memory().unwrap();
        let site = store
            .upsert_site("newapi", "https://c.example.com", "C")
            .unwrap();
        let err = store
            .insert_key(site, "bad", "sk-abcdefgh12345678", None, None)
            .unwrap_err();
        assert!(matches!(err, Error::Store(_)));
    }

    #[test]
    fn refuses_non_keychain_shaped_refs() {
        let store = Store::open_in_memory().unwrap();
        let site = store
            .upsert_site("newapi", "https://d.example.com", "D")
            .unwrap();

        // 32 位 hex 明文（复审 P2-4 探针形状）：黑名单时代会被放过
        assert!(matches!(
            store.insert_key(site, "hex", "9f3c1a7b2e5d8046c1b9f4a7d2e83b15", None, None),
            Err(Error::Store(_))
        ));
        // 段数不对的引用
        assert!(matches!(
            store.insert_key(site, "short", "kr/key/1", None, None),
            Err(Error::Store(_))
        ));
        // 合法引用
        assert!(store
            .insert_key(site, "ok", "kr/key/9/secret", None, None)
            .is_ok());
    }

    #[test]
    fn records_journal_entries() {
        let store = Store::open_in_memory().unwrap();
        let journal = Journal {
            id: "j1".into(),
            entries: vec![JournalEntry {
                path: PathBuf::from("/tmp/config.toml"),
                backup: Some(PathBuf::from("/tmp/backups/0-config.toml")),
                before_sha256: Some("aa".into()),
                after_sha256: "bb".into(),
            }],
        };
        store.record_journal(&journal).unwrap();
        assert_eq!(store.journal_count().unwrap(), 1);
    }

    /// 合法值集合必须是「站点侧词表 ∪ 本地词表」，且**从枚举派生**（不是抄字面量）。
    ///
    /// 站点侧新增变体时，`tests/key_lifecycle.rs` 里那条穷举 `match` 会先编译失败；
    /// 这里再钉住集合大小与派生关系，两道一起挡。
    #[test]
    fn legal_key_statuses_are_derived_from_the_site_enum_plus_the_local_revoked() {
        let legal = legal_key_statuses();
        for status in [
            KeyStatus::Enabled,
            KeyStatus::Disabled,
            KeyStatus::Exhausted,
            KeyStatus::Unknown,
        ] {
            assert!(
                legal.contains(&status.as_str()),
                "站点侧 {} 必须是合法值",
                status.as_str()
            );
        }
        assert!(
            legal.contains(&KEY_STATUS_REVOKED),
            "本地 revoked 必须是合法值"
        );
        assert_eq!(
            legal.len(),
            5,
            "集合大小变了要回来确认（4 站点侧 + 1 本地）"
        );

        assert!(!is_legal_key_status("REVOKED"), "大小写敏感");
        assert!(!is_legal_key_status(""));
        assert!(!is_legal_key_status(" revoked"));
    }

    // ---- M13-S1：token 用量 store CRUD ----

    #[test]
    fn gateway_usage_insert_and_query_roundtrip() {
        let store = Store::open_in_memory().unwrap();
        let site_id = store.upsert_site("newapi", "https://a", "A").unwrap();
        // 用直接 SQL 写入不同时间戳，保证排序确定（now_secs 精度是秒，同秒内顺序不定）
        let conn = store.lock().unwrap();
        let now = now_secs();
        conn.execute(
            "INSERT INTO gateway_usage_log(ts, at, site_id, model, prompt_tokens, completion_tokens, total_tokens) VALUES (?1, ?1, ?2, ?3, 100, 50, 150)",
            params![now - 60, site_id, "gpt-4"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gateway_usage_log(ts, at, site_id, model, prompt_tokens, completion_tokens, total_tokens) VALUES (?1, ?1, ?2, ?3, 200, 100, 300)",
            params![now, site_id, "gpt-4"],
        )
        .unwrap();
        drop(conn);
        let rows = store.recent_gateway_usage(24).unwrap();
        assert_eq!(rows.len(), 2);
        // 按 ts 降序 ⇒ 最新的在前
        assert_eq!(rows[0].prompt_tokens, 200);
        assert_eq!(rows[0].completion_tokens, 100);
        assert_eq!(rows[0].total_tokens, 300);
        assert_eq!(rows[1].prompt_tokens, 100);
        assert_eq!(rows[1].model, "gpt-4");
        assert_eq!(rows[1].site_id, site_id);
    }

    #[test]
    fn gateway_usage_time_filter_excludes_old_rows() {
        let store = Store::open_in_memory().unwrap();
        let site_id = store.upsert_site("newapi", "https://a", "A").unwrap();
        // 直接写一条「2 小时前」的记录
        let conn = store.lock().unwrap();
        let old_ts = now_secs() - 7200;
        conn.execute(
            "INSERT INTO gateway_usage_log(ts, at, site_id, model, prompt_tokens, completion_tokens, total_tokens) VALUES (?1, ?1, ?2, ?3, 1, 1, 2)",
            params![old_ts, site_id, "gpt-4"],
        )
        .unwrap();
        drop(conn);
        // 查最近 1 小时 ⇒ 不应包含
        let rows = store.recent_gateway_usage(1).unwrap();
        assert!(rows.is_empty(), "2 小时前的记录不该出现在 1h 查询里");
        // 查最近 3 小时 ⇒ 包含
        let rows = store.recent_gateway_usage(3).unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn usage_snapshot_insert_and_query_roundtrip() {
        let store = Store::open_in_memory().unwrap();
        let site_id = store.upsert_site("newapi", "https://a", "A").unwrap();
        let conn = store.lock().unwrap();
        let now = now_secs();
        conn.execute(
            "INSERT INTO usage_snapshots(site_id, used, remaining, currency, known, ts) VALUES (?1, 10.5, 89.5, 'USD', 1, ?2)",
            params![site_id, now - 60],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO usage_snapshots(site_id, used, remaining, currency, known, ts) VALUES (?1, 15.0, 85.0, 'USD', 1, ?2)",
            params![site_id, now],
        )
        .unwrap();
        drop(conn);
        let rows = store.recent_usage_snapshots(168).unwrap();
        assert_eq!(rows.len(), 2);
        // 按 site_id ASC, ts DESC ⇒ 两条同站点，最新的在前
        assert_eq!(rows[0].used, 15.0);
        assert_eq!(rows[0].remaining, 85.0);
        assert_eq!(rows[1].used, 10.5);
    }

    #[test]
    fn prune_gateway_usage_log_deletes_old_rows() {
        let store = Store::open_in_memory().unwrap();
        let site_id = store.upsert_site("newapi", "https://a", "A").unwrap();
        let conn = store.lock().unwrap();
        let old_ts = now_secs() - 86400 * 100; // 100 天前
        conn.execute(
            "INSERT INTO gateway_usage_log(ts, at, site_id, model, prompt_tokens, completion_tokens, total_tokens) VALUES (?1, ?1, ?2, ?, 1, 1, 2)",
            params![old_ts, site_id, "old"],
        )
        .unwrap();
        drop(conn);
        store
            .insert_gateway_usage(&crate::gateway::GatewayUsage {
                token_id: None,
                agent_label: String::new(),
                at: now_secs(),
                site_id,
                key_id: None,
                model: "new".into(),
                prompt_tokens: 1,
                completion_tokens: 1,
                total_tokens: 2,
                status: 200,
                latency_ms: 5,
                attempts: 1,
                stream: false,
            })
            .unwrap();
        let deleted = store.prune_gateway_usage_log(90).unwrap();
        assert_eq!(deleted, 1, "应删除 1 条 90 天前的记录");
        let rows = store.recent_gateway_usage(24).unwrap();
        assert_eq!(rows.len(), 1, "应只剩 1 条新记录");
        assert_eq!(rows[0].model, "new");
    }
    // ---- M34-S1：用量看板聚合 ----

    /// 与 store 查询同一口径的本地日标签（测试只用来算期望值）。
    fn day_label(store: &Store, ts: i64) -> String {
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT date(?1, 'unixepoch', 'localtime')",
                params![ts],
                |row| row.get(0),
            )
            .unwrap()
    }

    /// 本地时区「今天往前 `days_ago` 天」。
    fn day_ago_label(store: &Store, days_ago: i64) -> String {
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT date('now', 'localtime', '-' || ?1 || ' days')",
                params![days_ago],
                |row| row.get(0),
            )
            .unwrap()
    }

    /// 本地今天零点的 epoch（秒）。
    ///
    /// 夹具用它 + 固定偏移构造「今天之内」的时间戳，避免 `now - 30s` 这类写法在
    /// 本地 00:00:00–00:00:29 运行时跨日（复审 P3-10）。
    fn local_midnight(store: &Store) -> i64 {
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT CAST(strftime('%s', date('now','localtime'), 'utc') AS INTEGER)",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn usage_daily_groups_by_local_day_site_and_model() {
        let store = Store::open_in_memory().unwrap();
        let site_a = store.upsert_site("newapi", "https://a", "A").unwrap();
        let site_b = store.upsert_site("newapi", "https://b", "B").unwrap();
        // 固定取「本地今天 00:01」起的时间戳：不用 `now - 30s`，避免本地零点后
        // 半分钟内运行时两条记录跨日（复审 P3-10）。
        let base = local_midnight(&store) + 600;
        {
            let conn = store.lock().unwrap();
            let insert = |site: i64, model: &str, ts: i64, prompt: i64, completion: i64| {
                conn.execute(
                    "INSERT INTO gateway_usage_log(ts, at, site_id, model, prompt_tokens, completion_tokens, total_tokens) VALUES (?1, ?1, ?2, ?3, ?4, ?5, ?6)",
                    params![ts, site, model, prompt, completion, prompt + completion],
                )
                .unwrap();
            };
            insert(site_a, "gpt-4", base - 30, 10, 5);
            insert(site_a, "gpt-4", base, 20, 10);
            // 空模型名是**独立分组**，不并进 "gpt-4"
            insert(site_a, "", base, 1, 1);
            // 不同站点独立成行
            insert(site_b, "gpt-4", base, 100, 50);
        }
        let rows = store.usage_daily(7, None).unwrap();
        assert_eq!(rows.len(), 3, "两个站点 + 空模型名 ⇒ 三行");
        let today = day_label(&store, base);
        for row in &rows {
            assert_eq!(row.date, today, "同一本地日应聚到一起");
        }
        // 排序：date ASC, site_id ASC, model ASC（空串排在 "gpt-4" 前）
        assert_eq!(rows[0].site_id, site_a);
        assert_eq!(rows[0].model, "");
        assert_eq!(rows[0].requests, 1);
        assert_eq!(rows[0].total_tokens, 2);
        assert_eq!(rows[1].site_id, site_a);
        assert_eq!(rows[1].model, "gpt-4");
        assert_eq!(rows[1].requests, 2, "同站同模型同日两条应合并");
        assert_eq!(rows[1].prompt_tokens, 30);
        assert_eq!(rows[1].completion_tokens, 15);
        assert_eq!(rows[1].total_tokens, 45);
        assert_eq!(rows[2].site_id, site_b);
        assert_eq!(rows[2].total_tokens, 150);
    }

    #[test]
    fn usage_daily_window_and_site_filter() {
        let store = Store::open_in_memory().unwrap();
        let site_a = store.upsert_site("newapi", "https://a", "A").unwrap();
        let site_b = store.upsert_site("newapi", "https://b", "B").unwrap();
        // 同上：夹具锚在「本地今天 00:01」，不用 `now`（避免跨日假红）。
        let base = local_midnight(&store) + 600;
        {
            let conn = store.lock().unwrap();
            for (site, ts) in [(site_a, base), (site_b, base), (site_a, base - 3 * 86400)] {
                conn.execute(
                    "INSERT INTO gateway_usage_log(ts, at, site_id, model, prompt_tokens, completion_tokens, total_tokens) VALUES (?1, ?1, ?2, 'm', 1, 1, 2)",
                    params![ts, site],
                )
                .unwrap();
            }
        }
        assert_eq!(store.usage_daily(7, None).unwrap().len(), 3);
        let recent = store.usage_daily(2, None).unwrap();
        assert_eq!(recent.len(), 2, "3 天前的记录不在近 2 天窗口");
        let only_a = store.usage_daily(7, Some(site_a)).unwrap();
        assert_eq!(only_a.len(), 2);
        assert!(only_a.iter().all(|row| row.site_id == site_a));
        assert!(
            store.usage_daily(7, Some(9999)).unwrap().is_empty(),
            "不存在的站点 ⇒ 空数组，不报错"
        );
        // 窗口夹取：0 ⇒ 1 天（今天）；91 ⇒ 90 天（这里只断言不 panic 且语义等价）
        assert_eq!(store.usage_daily(0, None).unwrap().len(), 2);
        assert_eq!(store.usage_daily(91, None).unwrap().len(), 3);
        assert_eq!(clamp_usage_days(0), 1);
        assert_eq!(clamp_usage_days(91), USAGE_MAX_DAYS);
    }

    #[test]
    fn usage_snapshot_daily_takes_last_snapshot_of_the_day() {
        let store = Store::open_in_memory().unwrap();
        let site_a = store.upsert_site("newapi", "https://a", "A").unwrap();
        let site_b = store.upsert_site("sub2api", "https://b", "B").unwrap();
        // 锚在「本地今天 00:01」，避免 `now - 120s` 在零点后两分钟内跨日（P3-10）。
        let base = local_midnight(&store) + 600;
        {
            let conn = store.lock().unwrap();
            let insert = |site: i64, used: f64, remaining: f64, currency: &str, ts: i64| {
                conn.execute(
                    "INSERT INTO usage_snapshots(site_id, used, remaining, currency, known, ts) VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                    params![site, used, remaining, currency, ts],
                )
                .unwrap();
            };
            insert(site_a, 10.0, 90.0, "USD", base - 120);
            insert(site_a, 12.0, 88.0, "USD", base - 60);
            insert(site_a, 15.0, 85.0, "USD", base);
            // **id 与 ts 逆序**：这条 id 最大、ts 更早。`MAX(id)` / `ORDER BY id DESC`
            // 会取到 99.0；正确实现（ts DESC, id DESC）仍取 base 那条的 15.0。
            // 没有这一行，两种实现给出同一结果，用例就是假绿（复审 P2-1）。
            insert(site_a, 99.0, 1.0, "USD", base - 30);
            insert(site_b, 1.0, 9.0, "CNY", base);
            insert(site_a, 5.0, 95.0, "USD", base - 86400);
            // `known = 0`（余额未知）的快照不得进图（P3-9）
            conn.execute(
                "INSERT INTO usage_snapshots(site_id, used, remaining, currency, known, ts) VALUES (?1, 0.0, 0.0, 'CNY', 0, ?2)",
                params![site_b, base],
            )
            .unwrap();
        }
        let rows = store.usage_snapshot_daily(7, None).unwrap();
        assert_eq!(rows.len(), 3, "昨天 A 一条 + 今天 A/B 各一条");
        assert_eq!(rows[0].date, day_ago_label(&store, 1));
        assert_eq!(rows[0].site_id, site_a);
        assert_eq!(rows[0].used, 5.0);
        assert_eq!(rows[1].date, day_label(&store, base));
        assert_eq!(rows[1].site_id, site_a);
        assert_eq!(
            rows[1].used, 15.0,
            "取当日最后一条（按 ts），不是第一条、也不是 id 最大那条（99.0）"
        );
        assert_eq!(rows[1].remaining, 85.0);
        assert_eq!(rows[1].samples, 4);
        assert_eq!(rows[2].site_id, site_b);
        assert_eq!(rows[2].currency, "CNY");
        assert_eq!(rows[2].samples, 1, "known=0 的行不计入 samples");
        // days=1 ⇒ 只今天
        assert_eq!(store.usage_snapshot_daily(1, None).unwrap().len(), 2);
        // 站点过滤
        let only_b = store.usage_snapshot_daily(7, Some(site_b)).unwrap();
        assert_eq!(only_b.len(), 1);
        assert_eq!(only_b[0].site_id, site_b);
    }

    #[test]
    fn key_usage_totals_sums_samples_and_joins_key_metadata() {
        let store = Store::open_in_memory().unwrap();
        let site = store.upsert_site("sub2api", "https://s", "S").unwrap();
        let key = store
            .insert_key_with_group(site, "key-a", "kr/key/1/secret", Some("r1"), None, None)
            .unwrap();
        store
            .update_key_usage(key, Some(3.0), Some(10.0), Some("USD"))
            .unwrap();
        let today = day_ago_label(&store, 0);
        let yesterday = day_ago_label(&store, 1);
        let old = day_ago_label(&store, 10);
        {
            let conn = store.lock().unwrap();
            for (date, requests, input, output, cost) in [
                (today.as_str(), 2_i64, 100_i64, 50_i64, 0.5_f64),
                (yesterday.as_str(), 1, 10, 5, 0.1),
                (old.as_str(), 9, 900, 900, 9.0),
            ] {
                conn.execute(
                    "INSERT INTO usage_samples(key_id, site_id, date, requests, input_tokens, output_tokens, total_tokens, cost, sampled_at, cost_reported) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1)",
                    params![key, site, date, requests, input, output, input + output, cost, now_secs()],
                )
                .unwrap();
            }
        }
        let rows = store.key_usage_totals(7, None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].key_id, key);
        assert_eq!(rows[0].site_id, site);
        assert_eq!(rows[0].key_name, "key-a");
        assert_eq!(rows[0].requests, 3);
        assert_eq!(rows[0].input_tokens, 110);
        assert_eq!(rows[0].output_tokens, 55);
        assert_eq!(rows[0].total_tokens, 165);
        // M43-S2：`cost` 是 `Option<f64>`（`None` = 站点没上报）。该夹具**上报了** cost。
        assert!((rows[0].cost.expect("已上报") - 0.6).abs() < 1e-9);
        assert_eq!(rows[0].currency.as_deref(), Some("USD"));
        // days=1 ⇒ 10 天前的采样按 `date` 被排除，只剩今天
        let today_rows = store.key_usage_totals(1, None).unwrap();
        assert_eq!(today_rows.len(), 1);
        assert_eq!(today_rows[0].total_tokens, 150);
        // 不存在的站点 ⇒ 空
        assert!(store.key_usage_totals(7, Some(9999)).unwrap().is_empty());
    }

    #[test]
    fn usage_daily_window_starts_at_local_midnight() {
        let store = Store::open_in_memory().unwrap();
        let site = store.upsert_site("newapi", "https://a", "A").unwrap();
        // 期望口径：本地今天零点 = `strftime('%s', date('now','localtime'), 'utc')`。
        // 生产实现若漏掉 `'utc'`（把本地日期当 UTC 解释），在 UTC+8 上窗口起点会晚 8 小时，
        // 零点整那条会被排除 ⇒ 本用例红。
        let midnight = local_midnight(&store);
        {
            let conn = store.lock().unwrap();
            for ts in [midnight, midnight - 1] {
                conn.execute(
                    "INSERT INTO gateway_usage_log(ts, at, site_id, model, prompt_tokens, completion_tokens, total_tokens) VALUES (?1, ?1, ?2, 'm', 1, 1, 2)",
                    params![ts, site],
                )
                .unwrap();
            }
        }
        let rows = store.usage_daily(1, None).unwrap();
        assert_eq!(
            rows.len(),
            1,
            "days=1 的窗口从本地零点开始：含零点整，不含前一秒"
        );
        // 分组日必须是**本地日**。只断行数挡不住「生产 SQL 改成 UTC 日」的变异
        // （UTC 分组下零点行与前一行都归到昨天，仍是 1 组）——复审 P2-2。
        assert_eq!(
            rows[0].date,
            day_label(&store, midnight),
            "零点整那行的分组日必须是本地日（不是 UTC 日）"
        );
    }

    #[test]
    fn usage_queries_return_empty_on_empty_database() {
        let store = Store::open_in_memory().unwrap();
        assert!(store.usage_daily(7, None).unwrap().is_empty());
        assert!(store.usage_snapshot_daily(7, None).unwrap().is_empty());
        assert!(store.key_usage_totals(7, None).unwrap().is_empty());
    }

    /// `group_id` 与 `group_name` 必须与密钥行**同一次**写入、且都能读回（M22-S2 / B-172）。
    ///
    /// 这条替换了 M22-S1 的 `set_key_group` 往返测试：那种「先插行、再 UPDATE 两列」
    /// 的形态已不存在，留着旧测试就等于保住一条本步要消掉的写入口径。
    #[test]
    fn insert_key_with_group_writes_both_group_columns() {
        let dir = tempfile::tempdir().expect("临时目录");
        let store = Store::open(&dir.path().join("tianshu-relay.db")).expect("建库");
        let site = store
            .upsert_site("sub2api", "https://sub.example.com", "站")
            .expect("写站点");

        let id = store
            .insert_key_with_group(
                site,
                "codex/daily",
                "kr/key/1/secret",
                Some("9"),
                Some("gpt plus"),
                Some("2"),
            )
            .expect("写密钥");

        let row = store.get_key(id).expect("取行").expect("应存在");
        assert_eq!(row.group_id.as_deref(), Some("2"));
        assert_eq!(row.group_name.as_deref(), Some("gpt plus"));
        // 其余列逐字不变：这条写入不夹带任何别的字段
        assert_eq!(row.name, "codex/daily");
        assert_eq!(row.remote_id.as_deref(), Some("9"));
        assert_eq!(row.secret_ref, "kr/key/1/secret");
    }

    /// 两个分组列都可以是「不知道」⇒ `NULL`；且 `insert_key` 与它的落库形态**逐字一致**。
    ///
    /// 后半句是给 65 处旧调用点的保证：本步只是把委托插进中间，不许顺手改变它们的语义
    /// （例如把 `None` 写成空串，或给 `group_id` 编一个值）。
    #[test]
    fn insert_key_leaves_both_group_columns_null() {
        let dir = tempfile::tempdir().expect("临时目录");
        let store = Store::open(&dir.path().join("tianshu-relay.db")).expect("建库");
        let site = store
            .upsert_site("sub2api", "https://sub.example.com", "站")
            .expect("写站点");

        let plain = store
            .insert_key(site, "a", "kr/key/1/secret", None, None)
            .expect("旧入口");
        let grouped_none = store
            .insert_key_with_group(site, "b", "kr/key/2/secret", None, None, None)
            .expect("新入口");

        for id in [plain, grouped_none] {
            let row = store.get_key(id).expect("取行").expect("应存在");
            assert_eq!(row.group_name, None, "不知道就落 NULL，不许猜：{row:?}");
            assert_eq!(row.group_id, None, "没有站点主键就落 NULL：{row:?}");
        }
    }

    // ---- M39-S1：站点模型目录 ----

    fn model_store() -> (tempfile::TempDir, Store, i64) {
        let dir = tempfile::tempdir().expect("临时目录");
        let store = Store::open(&dir.path().join("tianshu-relay.db")).expect("建库");
        let site = store
            .upsert_site("newapi", "https://relay.example.com", "目录站")
            .expect("写站点");
        (dir, store, site)
    }

    fn models(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// M39-S1 §5.4：**真的旧库**（`user_version = 6`、没有这两张表）打开后必须补建，
    /// 版本走到 7，既有数据不受影响。
    #[test]
    fn migrate_creates_site_model_tables_on_an_existing_database() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("tianshu-relay.db");
        {
            let store = Store::open(&path).expect("首次建库");
            let _ = store
                .upsert_site("newapi", "https://old.example.com", "旧站")
                .expect("旧数据");
        }
        {
            // 造「v6 旧库」：删掉两张新表 + 把版本退回 6
            let conn = rusqlite::Connection::open(&path).expect("直连");
            conn.execute_batch(
                "DROP TABLE site_model_catalog; DROP TABLE site_model_sync;
                 PRAGMA user_version = 6;",
            )
            .expect("造旧库");
        }
        let store = Store::open(&path).expect("重新打开");
        assert_eq!(store.schema_version().unwrap(), 10, "M43-S2 之后是 v10");
        let conn = rusqlite::Connection::open(&path).expect("直连");
        for table in ["site_model_catalog", "site_model_sync"] {
            let n: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    params![table],
                    |row| row.get(0),
                )
                .expect("查表");
            assert_eq!(n, 1, "旧库必须补建 {table}");
        }
        assert_eq!(
            store.list_sites().expect("旧数据还在").len(),
            1,
            "迁移不得动既有数据"
        );
    }

    #[test]
    fn replace_site_models_deletes_removed_and_keeps_first_seen() {
        let (_dir, store, site) = model_store();
        store
            .replace_site_models(site, &models(&["a", "b"]), 100)
            .expect("首次替换");
        assert_eq!(store.site_models(site).unwrap(), models(&["a", "b"]));

        let n = store
            .replace_site_models(site, &models(&["b", "c"]), 200)
            .expect("二次替换");
        assert_eq!(n, 2);
        assert_eq!(
            store.site_models(site).unwrap(),
            models(&["b", "c"]),
            "**替换**语义：下架的 a 必须消失（不是只增不删）"
        );

        // first_seen_at 不被刷新：b 的第一见是 100，c 的是 200
        let conn = rusqlite::Connection::open(store.path().expect("文件库")).expect("直连");
        let b_first: i64 = conn
            .query_row(
                "SELECT first_seen_at FROM site_model_catalog WHERE site_id=?1 AND model='b'",
                params![site],
                |r| r.get(0),
            )
            .expect("b 的行");
        let c_first: i64 = conn
            .query_row(
                "SELECT first_seen_at FROM site_model_catalog WHERE site_id=?1 AND model='c'",
                params![site],
                |r| r.get(0),
            )
            .expect("c 的行");
        assert_eq!(
            b_first, 100,
            "b 是第一次就在的：first_seen_at 不得被替换刷新"
        );
        assert_eq!(c_first, 200);
        let b_last: i64 = conn
            .query_row(
                "SELECT last_seen_at FROM site_model_catalog WHERE site_id=?1 AND model='b'",
                params![site],
                |r| r.get(0),
            )
            .expect("b 的行");
        assert_eq!(b_last, 200, "last_seen_at 要刷新");
    }

    #[test]
    fn replace_site_models_rejects_an_empty_list() {
        let (_dir, store, site) = model_store();
        let err = store
            .replace_site_models(site, &[], 1)
            .expect_err("空列表必须被拒（走 record_site_models_empty）");
        assert!(
            format!("{err}").contains("record_site_models_empty"),
            "{err}"
        );
        assert_eq!(store.site_models(site).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn one_empty_pass_does_not_clear_the_catalog() {
        let (_dir, store, site) = model_store();
        store
            .replace_site_models(site, &models(&["a"]), 10)
            .expect("首次替换");
        let outcome = store.record_site_models_empty(site, 20).expect("记空");
        assert_eq!(outcome.streak, 1);
        assert!(!outcome.cleared, "一次空不得清空");
        assert_eq!(
            store.site_models(site).unwrap(),
            models(&["a"]),
            "目录必须还在"
        );
    }

    #[test]
    fn two_consecutive_empty_passes_clear_the_catalog() {
        let (_dir, store, site) = model_store();
        store
            .replace_site_models(site, &models(&["a", "b"]), 10)
            .expect("首次替换");
        store.record_site_models_empty(site, 20).expect("第一次空");
        let outcome = store.record_site_models_empty(site, 30).expect("第二次空");
        assert_eq!(outcome.streak, 2);
        assert!(outcome.cleared, "连续两次空必须清空");
        assert_eq!(store.site_models(site).unwrap(), Vec::<String>::new());
        // 再空一次不 panic、streak 继续涨、仍为空
        let again = store.record_site_models_empty(site, 40).expect("第三次空");
        assert_eq!(again.streak, 3);
        assert!(again.cleared);
    }

    #[test]
    fn a_non_empty_success_resets_the_empty_streak() {
        let (_dir, store, site) = model_store();
        store.record_site_models_empty(site, 10).expect("空一次");
        store
            .replace_site_models(site, &models(&["a"]), 20)
            .expect("成功");
        let sync = store.site_model_sync(site).unwrap().expect("有行");
        assert_eq!(sync.empty_streak, 0, "非空成功必须把连续空计数清零");
        assert_eq!(sync.last_error, None);
    }

    #[test]
    fn a_failed_collection_leaves_catalog_and_streak_untouched() {
        let (_dir, store, site) = model_store();
        store
            .replace_site_models(site, &models(&["a"]), 10)
            .expect("首次替换");
        store.record_site_models_empty(site, 20).expect("空一次");

        // 密钥形状的文本必须被脱敏；超长必须截断（红线）
        let long = format!("boom {} {}", "sk-0123456789abcdef", "x".repeat(2000));
        store
            .record_site_models_failure(site, 30, &long)
            .expect("记失败");

        assert_eq!(
            store.site_models(site).unwrap(),
            models(&["a"]),
            "失败不得动目录"
        );
        let sync = store.site_model_sync(site).unwrap().expect("有行");
        assert_eq!(sync.empty_streak, 1, "失败不得动连续空计数");
        assert_eq!(sync.last_attempt_at, Some(30));
        // 20 那次「成功但空」也算一次成功（站点回了 200 + 空列表）⇒ last_success_at = 20；
        // 失败（30）不得把它往后推。
        assert_eq!(sync.last_success_at, Some(20), "失败不是一次成功");
        let err = sync.last_error.expect("有错误文本");
        assert!(
            !err.contains("sk-0123456789abcdef"),
            "错误文本必须脱敏: {err}"
        );
        assert!(
            err.chars().count() <= MODEL_SYNC_ERROR_MAX_CHARS,
            "错误文本必须截断到 {} 字符，实际 {}",
            MODEL_SYNC_ERROR_MAX_CHARS,
            err.chars().count()
        );
    }

    #[test]
    fn deleting_a_site_cascades_its_catalog_and_sync_rows() {
        let (_dir, store, site) = model_store();
        store
            .replace_site_models(site, &models(&["a"]), 10)
            .expect("替换");
        store.delete_site(site).expect("删站点");
        assert_eq!(store.site_models(site).unwrap(), Vec::<String>::new());
        assert_eq!(
            store.site_model_sync(site).unwrap(),
            None,
            "sync 行也要级联删"
        );
    }

    #[test]
    fn site_model_catalog_returns_models_sorted_by_bytes() {
        let (_dir, store, site) = model_store();
        // 入参顺序打乱；存的是集合，读出来必须升序
        store
            .replace_site_models(site, &models(&["zeta", "alpha", "mike"]), 10)
            .expect("替换");
        assert_eq!(
            store.site_models(site).unwrap(),
            models(&["alpha", "mike", "zeta"]),
            "读取必须按字节序升序（确定性）"
        );
        let all = store.site_model_catalog().unwrap();
        assert_eq!(all.get(&site), Some(&models(&["alpha", "mike", "zeta"])));
    }

    // ---------- M40-S1：网关用量账本（schema v8 + `at` 口径） ----------

    fn usage_fixture(site_id: i64, at: i64, total: i64) -> crate::gateway::GatewayUsage {
        crate::gateway::GatewayUsage {
            at,
            site_id,
            key_id: Some(9),
            model: "m40".to_string(),
            prompt_tokens: 1,
            completion_tokens: 2,
            total_tokens: total,
            status: 200,
            latency_ms: 33,
            attempts: 1,
            stream: false,
            token_id: None,
            agent_label: String::new(),
        }
    }

    fn usage_columns(store: &Store) -> Vec<String> {
        let conn = store.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT name FROM pragma_table_info('gateway_usage_log') ORDER BY name")
            .unwrap();
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        rows
    }

    #[test]
    fn schema_v8_migrates_v7_db_and_backfills_at() {
        // 造一个 v7 老库：先按当前 DDL 建库，再把 M40 的六列与索引去掉、版本号写回 7。
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("tianshu-relay.db");
        let store = Store::open(&path).expect("建库");
        let site_id = store
            .upsert_site("newapi", "https://m40.example.com", "测试")
            .expect("upsert_site");
        {
            let conn = store.lock().unwrap();
            conn.execute_batch(
                "DROP INDEX IF EXISTS idx_gateway_usage_at;
                 DROP INDEX IF EXISTS idx_gateway_usage_budget_site;
                 DROP INDEX IF EXISTS idx_gateway_usage_budget_key;
                 ALTER TABLE gateway_usage_log DROP COLUMN at;
                 ALTER TABLE gateway_usage_log DROP COLUMN key_id;
                 ALTER TABLE gateway_usage_log DROP COLUMN status;
                 ALTER TABLE gateway_usage_log DROP COLUMN latency_ms;
                 ALTER TABLE gateway_usage_log DROP COLUMN attempts;
                 ALTER TABLE gateway_usage_log DROP COLUMN stream;
                 PRAGMA user_version = 7;",
            )
            .expect("模拟 v7 老库");
            conn.execute(
                "INSERT INTO gateway_usage_log(ts, site_id, model, prompt_tokens, completion_tokens, total_tokens) \
                 VALUES (1700000000, ?1, 'legacy', 3, 4, 7)",
                params![site_id],
            )
            .expect("写一行旧数据");
        }
        drop(store);

        let store = Store::open(&path).expect("重新打开 v7 旧库");
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(
            SCHEMA_VERSION, 10,
            "M43-S2 占用 v10（M43-S1 占 v9、M40-S1 占 v8）"
        );
        let columns = usage_columns(&store);
        for expected in ["at", "key_id", "status", "latency_ms", "attempts", "stream"] {
            assert!(
                columns.iter().any(|c| c == expected),
                "老库必须补出 {expected} 列"
            );
        }

        // 旧行语义：at = ts（近似，非观测），其余新列取默认值（未记录）。
        {
            let conn = store.lock().unwrap();
            let row: (i64, Option<i64>, i64, i64, i64, i64) = conn
                .query_row(
                    "SELECT at, key_id, status, latency_ms, attempts, stream FROM gateway_usage_log",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
                )
                .expect("读旧行");
            assert_eq!(row, (1_700_000_000, None, 0, 0, 1, 0));
        }

        // 重复打开幂等（不 duplicate column）。
        drop(store);
        let store = Store::open(&path).expect("再次打开");
        assert_eq!(store.schema_version().unwrap(), 10);
        assert_eq!(usage_columns(&store).len(), 15);
    }

    #[test]
    // M43-S1 T4b（B-224 长尾）：**真 v8 夹具**——含 M40 六列、无令牌表、
    // 无归因列、无 cost 标记，user_version = 8 ⇒ 打开后走 8→9→10。
    // 区别于上面的 v7 夹具（v7 连 M40 六列都没有）和下面的 v10 新库用例。
    fn schema_v9_migrates_v8_db_and_adds_token_tables() {
        let dir = tempfile::tempdir().expect("临时目录");
        let path = dir.path().join("tianshu-relay.db");
        let store = Store::open(&path).expect("建库");
        let site_id = store
            .upsert_site("newapi", "https://m40.example.com", "测试")
            .expect("upsert_site");
        {
            let conn = store.lock().unwrap();
            conn.execute_batch(
                "DROP INDEX IF EXISTS idx_gateway_usage_token;
                 ALTER TABLE gateway_usage_log DROP COLUMN token_id;
                 ALTER TABLE gateway_usage_log DROP COLUMN agent_label;
                 DROP TABLE IF EXISTS gateway_tokens;
                 ALTER TABLE usage_samples DROP COLUMN cost_reported;
                 PRAGMA user_version = 8;",
            )
            .expect("模拟 v8 老库");
            conn.execute(
                "INSERT INTO gateway_usage_log(ts, site_id, model, prompt_tokens, completion_tokens, total_tokens, at, key_id, status, latency_ms, attempts, stream) \
                 VALUES (1700000000, ?1, 'legacy-v8', 3, 4, 7, 1700000000, NULL, 200, 33, 1, 0)",
                params![site_id],
            )
            .expect("写一行 v8 旧数据");
        }
        drop(store);

        let store = Store::open(&path).expect("重新打开 v8 旧库");
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(SCHEMA_VERSION, 10, "当前 schema 应为 v10");
        // v9 产物：令牌表 + 归因两列。
        let columns = usage_columns(&store);
        for expected in ["token_id", "agent_label"] {
            assert!(
                columns.iter().any(|c| c == expected),
                "老库必须补出 {expected} 列"
            );
        }
        {
            let conn = store.lock().unwrap();
            let table: String = conn
                .query_row(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='gateway_tokens'",
                    [],
                    |r| r.get(0),
                )
                .expect("令牌表必须存在");
            assert_eq!(table, "gateway_tokens");
            let cost_col: String = conn
                .query_row(
                    "SELECT name FROM pragma_table_info('usage_samples') WHERE name='cost_reported'",
                    [],
                    |r| r.get(0),
                )
                .expect("v10 的 cost_reported 列必须存在");
            assert_eq!(cost_col, "cost_reported");
            // 旧行保留：归因列取默认值（token_id NULL、agent_label ''），不丢账。
            let row: (String, Option<i64>, String) = conn
                .query_row(
                    "SELECT model, token_id, agent_label FROM gateway_usage_log",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .expect("读旧行");
            assert_eq!(row, ("legacy-v8".to_string(), None, String::new()));
        }
    }

    #[test]
    // B-224 P3（M43-S1 T4b 名实不符）：旧名写 v8、实际断言的是当前
    // schema v10 的 15 列（其中 6 列是 M40 新增的），改名以免后人按
    // 名去找一个不存在的 v8 夹具。
    fn schema_v10_fresh_db_has_all_fifteen_columns() {
        let store = Store::open_in_memory().expect("内存库");
        assert_eq!(store.schema_version().unwrap(), 10);
        let columns = usage_columns(&store);
        assert_eq!(
            columns.len(),
            15,
            "15 列：id/ts/at/site_id/model/3 tokens/key_id/status/latency_ms/attempts/stream/token_id/agent_label（cost_reported 在 usage_samples 上，不在本表）"
        );
        for expected in ["at", "key_id", "status", "latency_ms", "attempts", "stream"] {
            assert!(
                columns.iter().any(|c| c == expected),
                "新库必须直接带 {expected} 列"
            );
        }
    }

    #[test]
    fn insert_gateway_usage_round_trips_new_columns() {
        let store = Store::open_in_memory().expect("内存库");
        let site_id = store
            .upsert_site("newapi", "https://m40.example.com", "测试")
            .expect("upsert_site");
        store
            .insert_gateway_usage(&usage_fixture(site_id, 1_700_000_123, 42))
            .expect("insert");
        let conn = store.lock().unwrap();
        let row: (i64, Option<i64>, String, i64, i64, i64, i64, i64) = conn
            .query_row(
                "SELECT at, key_id, model, total_tokens, status, latency_ms, attempts, stream FROM gateway_usage_log",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)),
            )
            .expect("读回");
        assert_eq!(
            row,
            (1_700_000_123, Some(9), "m40".into(), 42, 200, 33, 1, 0)
        );
    }

    #[test]
    fn usage_daily_groups_by_at_not_ts() {
        let store = Store::open_in_memory().expect("内存库");
        let site_id = store
            .upsert_site("newapi", "https://m40.example.com", "测试")
            .expect("upsert_site");
        let now = now_secs();
        // 故意让 ts 与 at 的「日期」相反：分组若还看 ts，两条会被归到错误的日。
        let day_of = |at: i64| -> String {
            let conn = store.lock().unwrap();
            conn.query_row(
                "SELECT date(?1, 'unixepoch', 'localtime')",
                params![at],
                |r| r.get(0),
            )
            .unwrap()
        };
        let today = day_of(now);
        let yesterday = day_of(now - 86_400);
        {
            let conn = store.lock().unwrap();
            // A：ts 今天、at 昨天；B：ts 昨天、at 今天。
            conn.execute(
                "INSERT INTO gateway_usage_log(ts, at, site_id, model, total_tokens) VALUES (?1, ?2, ?3, 'a', 1)",
                params![now, now - 86_400, site_id],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO gateway_usage_log(ts, at, site_id, model, total_tokens) VALUES (?1, ?2, ?3, 'b', 2)",
                params![now - 86_400, now, site_id],
            )
            .unwrap();
        }
        let rows = store.usage_daily(2, Some(site_id)).expect("usage_daily");
        assert_eq!(rows.len(), 2, "两个不同 at 日期 ⇒ 两行");
        let a = rows.iter().find(|r| r.model == "a").expect("a");
        assert_eq!(a.date, yesterday, "a 必须按 at 归到昨天（不是 ts 的今天）");
        let b = rows.iter().find(|r| r.model == "b").expect("b");
        assert_eq!(b.date, today, "b 必须按 at 归到今天（不是 ts 的昨天）");
    }

    #[test]
    fn prune_gateway_usage_log_uses_at() {
        let store = Store::open_in_memory().expect("内存库");
        let site_id = store
            .upsert_site("newapi", "https://m40.example.com", "测试")
            .expect("upsert_site");
        let now = now_secs();
        {
            let conn = store.lock().unwrap();
            // 旧账：at 100 天前，但 ts 是现在 ⇒ 必须按 at 裁掉。
            conn.execute(
                "INSERT INTO gateway_usage_log(ts, at, site_id, model) VALUES (?1, ?2, ?3, 'old')",
                params![now, now - 100 * 86_400, site_id],
            )
            .unwrap();
            // 新账：at 现在，但 ts 100 天前 ⇒ 必须保留（按 at）。
            conn.execute(
                "INSERT INTO gateway_usage_log(ts, at, site_id, model) VALUES (?1, ?2, ?3, 'fresh')",
                params![now - 100 * 86_400, now, site_id],
            )
            .unwrap();
        }
        let removed = store.prune_gateway_usage_log(90).expect("prune");
        assert_eq!(removed, 1, "只裁 at 超窗的那条");
        let conn = store.lock().unwrap();
        let models: Vec<String> = conn
            .prepare("SELECT model FROM gateway_usage_log")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(models, vec!["fresh".to_string()]);
    }
}
