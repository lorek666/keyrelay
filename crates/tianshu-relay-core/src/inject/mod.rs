//! agent 配置注入：计划（plan）→ 应用（apply）→ 回滚（rollback）。
//!
//! 安全约定：
//! - `apply` 前必须备份，写入必须原子（同目录临时文件 + rename）
//! - `apply` 会校验目标文件当前内容与计划中的 `before` 一致，防止覆盖并发修改
//! - `rollback` 会校验文件未被外部改动，拒绝静默覆盖
//! - 本模块**不**负责密钥投递：受管文件里只出现 base_url / provider / env 变量名

pub mod claude_code;
pub mod codex;
pub mod lock;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// 一次文件改写：`before` / `after` 用于生成 diff 与校验
#[derive(Clone, PartialEq, Eq)]
pub struct Patch {
    pub path: PathBuf,
    pub before: String,
    pub after: String,
    /// 新建文件时使用的权限位（Unix）。`None` = 0644。
    /// 已存在的文件**一律保留原权限**（沿用 M0 的行为）。
    pub new_file_mode: Option<u32>,
}

impl Patch {
    /// 常规配置补丁（不含密钥；新建时 0644）。
    pub fn new(
        path: impl Into<PathBuf>,
        before: impl Into<String>,
        after: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            before: before.into(),
            after: after.into(),
            new_file_mode: None,
        }
    }

    /// 含密钥的文件（新建时 0600）。
    pub fn secret_bearing(
        path: impl Into<PathBuf>,
        before: impl Into<String>,
        after: impl Into<String>,
    ) -> Self {
        Self {
            new_file_mode: Some(0o600),
            ..Self::new(path, before, after)
        }
    }
}

/// 手写 `Debug`：只打印路径、长度与内容摘要，**绝不打印 `before` / `after` 正文**。
///
/// BACKLOG B-12：`Patch::after` 会包含密钥本体（投递场景），
/// 而用户的 `config.toml` 里也可能本就有明文密钥。任何 `{:?}` 都不得把它们写进日志。
impl std::fmt::Debug for Patch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Patch")
            .field("path", &self.path)
            .field("before_len", &self.before.len())
            .field("after_len", &self.after.len())
            .field("before_sha8", &&sha256_hex(self.before.as_bytes())[..8])
            .field("after_sha8", &&sha256_hex(self.after.as_bytes())[..8])
            .field(
                "new_file_mode",
                &self.new_file_mode.map(|m| format!("{m:o}")),
            )
            .finish()
    }
}

/// 回滚凭据。`backup` 为 `None` 表示该文件在应用前不存在（回滚时应删除）。
/// `before_mode`（Unix）= 应用前目标文件的权限位：备份文件自 DEBUG-G5 P1-10
/// 起被强制成 0600 后，不能再拿备份文件当回滚的权限模板（否则一个 0644
/// 的原文件回滚后会被收紧成 0600）；回滚时按本字段还原原始位，`None`（例如
/// 从老库 journals 行重建、或非 Unix）时回落到既有模板行为。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalEntry {
    pub path: PathBuf,
    pub backup: Option<PathBuf>,
    pub before_sha256: Option<String>,
    pub after_sha256: String,
    pub before_mode: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Journal {
    pub id: String,
    pub entries: Vec<JournalEntry>,
}

/// 注入上下文：agent 需要知道「连哪里、用哪个 provider、模型叫什么」。
///
/// 注意 `api_key` 字段在本阶段**不会**写入受管文件（密钥投递见 M1-S2 的授权流程）。
#[derive(Clone, PartialEq, Eq)]
pub struct Binding {
    pub base_url: String,
    pub api_key: String,
    pub model: Option<String>,
    pub provider_id: String,
}

impl std::fmt::Debug for Binding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Binding")
            .field("base_url", &self.base_url)
            .field("api_key", &"<已脱敏>")
            .field("model", &self.model)
            .field("provider_id", &self.provider_id)
            .finish()
    }
}

pub trait Injector: Send + Sync {
    /// 注入器标识，与 `bindings.agent_id` 对应
    fn id(&self) -> &'static str;

    /// 只计算、不落盘。要求是纯函数：同样的输入产出同样的补丁。
    fn plan(&self, binding: &Binding) -> Result<Vec<Patch>>;
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn read_or_empty(path: &Path) -> Result<String> {
    match fs::read(path) {
        Ok(bytes) => String::from_utf8(bytes)
            .map_err(|_| Error::inject(path, "文件不是合法 UTF-8，拒绝改写")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(Error::inject(path, format!("读取失败: {e}"))),
    }
}

/// 决定临时文件应当使用的权限位（Unix）。
///
/// 优先级：① 目标文件现存权限 → ② `mode_from` 模板文件（回滚时的备份文件，
/// `fs::copy` 会带上原权限位）→ ③ 调用方指定值（含密钥的文件必须 0600）→ ④ 0644。
#[cfg(unix)]
fn resolve_mode(path: &Path, new_file_mode: Option<u32>, mode_from: Option<&Path>) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    // `mode_from`（回滚时的备份文件）优先：回滚的语义是「还原到投递之前」，
    // 包括权限位。若让它排在目标文件之后，就会把 apply 阶段收紧过的 0600
    // 当成「原权限」再写回去，0644 永远还原不了。
    if let Some(template) = mode_from {
        if let Ok(meta) = fs::metadata(template) {
            return meta.permissions().mode() & 0o7777;
        }
    }
    if let Ok(meta) = fs::metadata(path) {
        return clamp_secret_mode(meta.permissions().mode() & 0o7777, new_file_mode);
    }
    new_file_mode.unwrap_or(0o644)
}

/// 含密钥的文件**不允许比 0600 更宽**。
///
/// 只「保留原权限」是不够的：用户（或某个 CLI 的历史版本）把 `~/.codex/auth.json`
/// 留成 0644 时，我们往里写密钥会让同机其它用户直接读到它。
/// 这里只收紧、不放宽：`0o644 → 0o600`、`0o400 → 0o400`、`0o777 → 0o600`。
#[cfg(unix)]
fn clamp_secret_mode(existing: u32, new_file_mode: Option<u32>) -> u32 {
    if new_file_mode == Some(0o600) {
        existing & 0o600
    } else {
        existing
    }
}

/// 临时文件名：随机后缀 + `create_new`，同时解决两个问题：
/// - **可预测路径**：固定名字（`.<name>.tianshu-relay.tmp`）可以被预先放一个符号链接劫持，
///   让密钥写到攻击者指定的文件上（复核 P2）；
/// - **并发覆盖**：同目录两次写入若用同一个临时名会互相踩。
fn temp_path(parent: &Path, file_name: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    parent.join(format!(
        ".{file_name}.tianshu-relay.{:x}{:x}.tmp",
        nanos, seq
    ))
}

fn write_atomic(
    path: &Path,
    contents: &str,
    new_file_mode: Option<u32>,
    mode_from: Option<&Path>,
) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::inject(path, "没有父目录"))?;
    fs::create_dir_all(parent).map_err(|e| Error::inject(parent, format!("创建目录失败: {e}")))?;

    // 目标是符号链接时**拒绝写入**：`rename` 会把符号链接换成普通文件，
    // 用户精心搭的软链（例如 `~/.codex` 指向另一块盘）就被静默拆掉了，
    // 而且回滚也还原不了那层链接（备份复制的是**被指向文件**的内容）。
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(Error::inject(
                path,
                "目标是符号链接；写入会把它替换成普通文件，且回滚无法还原链接。\
                 请手工改成普通文件，或直接对链接指向的真实路径操作",
            ));
        }
    }

    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "config".to_string());
    let tmp = temp_path(parent, &file_name);

    // **权限必须在创建时就正确**：先用 `fs::write`（umask 022 → 0644）创建再 chmod，
    // 会在磁盘上留下一个「内容是密钥、权限却是 0644」的窗口（M1-S2 复审 P1-1，实测
    // 权限序列 [0644, 0600]）。这里用 `OpenOptions::mode()` 一次到位，
    // 并加 `create_new` 防止跟随已存在的符号链接。
    #[cfg(unix)]
    let write_result = {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mode = resolve_mode(path, new_file_mode, mode_from);
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .and_then(|mut file| {
                // `OpenOptions::mode` 会被 **umask 剥位**（0664 在 umask 022 下变成 0644、
                // 0777 变成 0755），因此必须再 `fchmod` 一次把请求的权限位钉死。
                // `File::set_permissions` 走的是 fd，不受 umask 影响。
                file.set_permissions(fs::Permissions::from_mode(mode))?;
                std::io::Write::write_all(&mut file, contents.as_bytes())
            })
    };

    #[cfg(not(unix))]
    let write_result = {
        let _ = (new_file_mode, mode_from);
        fs::write(&tmp, contents)
    };

    write_result.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        Error::inject(&tmp, format!("写临时文件失败: {e}"))
    })?;

    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        Error::inject(path, format!("原子替换失败: {e}"))
    })
}

/// 写入并回读校验，返回**磁盘上实际内容**的 sha256。
///
/// 对应 spec §6「注入后回读失败 → 自动回滚并报错」：若落盘内容与预期不符，
/// journal 记录的哈希就会与磁盘不一致，后续 `rollback` 会误判为「外部改动」而拒绝，
/// 因此必须在写入当步发现并补偿。
fn write_verified(path: &Path, contents: &str, new_file_mode: Option<u32>) -> Result<String> {
    write_atomic(path, contents, new_file_mode, None)?;
    let read_back =
        fs::read(path).map_err(|e| Error::inject(path, format!("写入后回读失败: {e}")))?;
    let text = String::from_utf8(read_back)
        .map_err(|_| Error::inject(path, "写入后回读不是合法 UTF-8"))?;
    if text != contents {
        return Err(Error::inject(path, "写入后回读内容与预期不一致"));
    }
    Ok(sha256_hex(text.as_bytes()))
}

fn new_journal_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};

    // 毫秒级时间戳会在同一毫秒内的连续调用上碰撞，故追加进程内自增序号。
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("j{nanos}-{seq}")
}

/// 锁目录：**与调用方参数无关**的进程级常量。
///
/// 早先的版本从 `backup_dir` 参数派生锁目录，结果是「换个 `backup_dir` 就换一个锁文件」，
/// 互斥形同虚设（M1-S2 复审 P1-3，真子进程实测可绕过）。
/// 现在固定用 `<系统临时目录>/tianshu-relay-locks`：
/// - 同一用户的任意进程都算出同一个目录 → 跨进程互斥成立；
/// - 不依赖任何入参，调用方无法「不小心」绕开。
pub fn default_lock_dir() -> PathBuf {
    std::env::temp_dir().join("tianshu-relay-locks")
}

/// 注入备份的保留期（DEBUG-G5 P1-10）：每次成功 apply 后，把 `backup_dir` 下
/// 超过此时限的 journal 目录删掉——备份里是含旧密钥明文的完整旧配置，不能
/// 无限期留存。代价是过期 journal 的回滚随之失效（备份文件已不在，回滚会
/// 报「读取备份失败」），这是「过期」的本意，不是 bug：回滚窗口 = 保留期。
/// 只删名字以 `j` 开头的子目录（journal id 形如 `j<纳秒>-<序号>`），不碰
/// 其它文件、不递归、不跟随符号链接；删不掉的单目录静默跳过（不因此让
/// 本次 apply 失败——过期清理是善后，不是本次写入的前提）。
pub const BACKUP_RETENTION: std::time::Duration = std::time::Duration::from_secs(30 * 24 * 3600);

/// 删掉 `backup_dir` 下超过 `retention` 的 journal 目录，返回删掉的个数。
/// mtime 取不到的目录不删（无法证明它已过期，宁可留着）。
pub fn prune_expired_backups(backup_dir: &Path, retention: std::time::Duration) -> usize {
    let Ok(entries) = std::fs::read_dir(backup_dir) else {
        return 0;
    };
    let now = SystemTime::now();
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        // 只删真实目录：符号链接指向目录时 file_type().is_dir() 为 false，
        // 不跟随，避免删到用户别处的数据。
        if !file_type.is_dir() {
            continue;
        }
        if !entry.file_name().to_string_lossy().starts_with('j') {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let Ok(mtime) = meta.modified() else {
            continue;
        };
        let expired = now
            .duration_since(mtime)
            .map(|age| age > retention)
            .unwrap_or(false);
        if expired && std::fs::remove_dir_all(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}
///
/// 三处保证：
/// 1. **先加锁**：所有目标文件在预检之前就取到排他锁（进程内 + 跨进程），
///    封住「读 → 校验 → 写」之间被其它实例插入改写的窗口（BACKLOG B-16）。
/// 2. **先全量预检再写入**：任一目标文件的当前内容与计划的 `before` 不一致时，
///    在动任何文件之前就失败，不会留下「改了一半」的中间态。
/// 3. **写入失败即补偿**：若第 N 个补丁写入或回读失败，已写入的条目与当前条目
///    会按逆序用备份还原，磁盘回到调用前状态。
///
/// 备份落在 `backup_dir/<journal_id>/` 下：每次 apply 一个独立目录，
/// 避免同一目标文件被多次注入时后一次覆盖前一次的备份（那样会导致回滚链断裂）。
pub fn apply(patches: &[Patch], backup_dir: &Path) -> Result<Journal> {
    // BACKLOG B-46：同批次重复路径在**取锁之前**就拒绝。
    // 放到这里而不是只放进 `apply_holding_lock`，是为了让「等价但字面不同」的路径
    // （`a/config.toml` 与 `./a/config.toml`）也拿到「同一批次重复」的专用文案，
    // 而不是先撞出 `FileBusy`（同一个归一化目标取第二把锁必然失败）。
    reject_duplicate_targets(patches)?;

    // 每个目标路径到这里都是唯一的，因此一条补丁一把锁即可（无需去重）。
    let lock_dir = default_lock_dir();
    let mut locks: Vec<lock::FileLock> = Vec::with_capacity(patches.len());
    for patch in patches {
        locks.push(lock::FileLock::acquire(&patch.path, &lock_dir)?);
    }
    apply_holding_lock(patches, backup_dir, &locks)
}

/// 同批次里同一个目标文件出现两次 → 直接拒绝（BACKLOG B-46）。
///
/// 为什么必须前置拒绝，而不是让预检去报错：
/// - 两条补丁的 `before` 串联（`v0→v1`、`v1→v2`）时，第二条预检读到的是 `v0`，
///   于是报出「文件内容与计划不一致（可能被外部修改）」——把调用方的**计划错误**
///   说成外部改动，用户会去找一个根本不存在的外部修改者；
/// - 两条补丁的 `before` 相同（`v0→v1`、`v0→v2`）时更糟：静默「后者胜」，
///   调用方以为两次改写都生效了，而备份链只留了一条 `v0`。
///
/// 比较用 `lock::normalize_target`（补全绝对路径 + 解析父目录符号链接 + 拼回文件名），
/// 因此 `a/config.toml` 与 `./a/config.toml`、软链目录别名都算同一个目标。
fn reject_duplicate_targets(patches: &[Patch]) -> Result<()> {
    let mut seen: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(patches.len());
    for patch in patches {
        let key = lock::normalize_target(&patch.path);
        if let Some((_, first)) = seen.iter().find(|(seen_key, _)| *seen_key == key) {
            return Err(Error::inject(
                &patch.path,
                format!(
                    "同一批次里有重复的目标路径（重复出现：{}，首次出现：{}）；\
                     同一个文件在一次注入中只能出现一条补丁，请合并后重试",
                    patch.path.display(),
                    first.display()
                ),
            ));
        }
        seen.push((key, patch.path.clone()));
    }
    Ok(())
}

/// 调用方**已经持有** `patches` 里全部目标路径的锁时使用。
///
/// 存在这个入口的原因：服务层需要在「取锁 → 重新确认用户同意 → 写入」之间保持互斥。
/// 如果先查同意再进 `apply` 取锁，用户完全可能在我们等锁的时候撤销同意，
/// 结果「撤销后仍然写入」（M1-S2 复审 P1-2）。
///
/// `held` 是调用方持有的锁的借用凭证；本函数**不会**自己加锁。
pub(crate) fn apply_holding_lock(
    patches: &[Patch],
    backup_dir: &Path,
    held: &[lock::FileLock],
) -> Result<Journal> {
    // 服务层会直接调本函数（已自持锁），因此重复路径校验必须在这里也做一遍（B-46）。
    reject_duplicate_targets(patches)?;

    debug_assert!(
        patches.iter().all(|p| {
            let normalized = lock::normalize_target(&p.path);
            held.iter().any(|l| l.target() == normalized)
        }),
        "apply_holding_lock 要求调用方已锁住所有目标路径"
    );

    let mut current_contents = Vec::with_capacity(patches.len());
    for patch in patches {
        let current = read_or_empty(&patch.path)?;
        if current != patch.before {
            return Err(Error::inject(
                &patch.path,
                "文件内容与计划不一致（可能被外部修改），请重新生成计划",
            ));
        }
        current_contents.push(current);
    }

    let journal_id = new_journal_id();
    let journal_backup_dir = backup_dir.join(&journal_id);
    fs::create_dir_all(&journal_backup_dir)
        .map_err(|e| Error::inject(&journal_backup_dir, format!("创建备份目录失败: {e}")))?;
    // DEBUG-G5 P1-10：备份目录本身先收紧到 0700（纵深防御：即使单个备份
    // 文件的权限被旁路改宽，同机其它用户也进不来目录）；失败即报错——备份
    // 目录还没写任何文件，此时失败不丢数据。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&journal_backup_dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::inject(&journal_backup_dir, format!("收紧备份目录失败: {e}")))?;
    }

    let mut entries: Vec<JournalEntry> = Vec::with_capacity(patches.len());
    for (index, (patch, current)) in patches.iter().zip(current_contents).enumerate() {
        let existed = !current.is_empty() || patch.path.exists();
        // 应用前目标文件的原始权限位（Unix）：回滚时按它还原，见 JournalEntry
        // 的 before_mode 注释——备份文件被强制 0600 后不能再当权限模板。
        #[cfg(unix)]
        let before_mode = {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(&patch.path)
                .ok()
                .map(|meta| meta.permissions().mode() & 0o7777)
        };
        #[cfg(not(unix))]
        let before_mode = None;
        let backup = if existed {
            let file_name = patch
                .path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "config".to_string());
            let backup_path = journal_backup_dir.join(format!("{index}-{file_name}"));
            fs::copy(&patch.path, &backup_path)
                .map_err(|e| Error::inject(&backup_path, format!("备份失败: {e}")))?;
            // DEBUG-G5 P1-10：备份文件强制 0600，不再继承源文件权限。
            // `fs::copy` 会把源权限（例如 0644）带过来，而备份里是含旧密钥
            // 明文的完整旧配置——0644 下同机其它用户可直接读。chmod 失败时
            // 删掉刚拷的备份再报错：目标文件此时还没动，不留一份宽权限的
            // 明文副本在磁盘上。
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Err(e) = fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600))
                {
                    let _ = fs::remove_file(&backup_path);
                    return Err(Error::inject(
                        &backup_path,
                        format!("收紧备份权限失败: {e}"),
                    ));
                }
            }
            Some(backup_path)
        } else {
            None
        };

        match write_verified(&patch.path, &patch.after, patch.new_file_mode) {
            Ok(after_sha256) => entries.push(JournalEntry {
                path: patch.path.clone(),
                backup,
                before_sha256: existed.then(|| sha256_hex(current.as_bytes())),
                after_sha256,
                before_mode,
            }),
            Err(err) => {
                // 2) 补偿：把当前文件（若已被改写）与之前所有已写入的文件还原，
                //    保证 apply 失败后磁盘回到调用前状态。
                //    注意：当前文件未被改写时不加入补偿列表——否则会在「目录不可写」
                //    这类失败场景里，对一个本就无需还原的文件做无谓写入而拖垮整轮补偿。
                let mut compensation = entries.clone();
                let disk_now = read_or_empty(&patch.path)?;
                if disk_now != current {
                    compensation.push(JournalEntry {
                        path: patch.path.clone(),
                        backup: backup.clone(),
                        before_sha256: existed.then(|| sha256_hex(current.as_bytes())),
                        // 用磁盘现状计算，保证补偿回滚的校验必然通过
                        after_sha256: sha256_hex(disk_now.as_bytes()),
                        before_mode,
                    });
                }
                return match rollback(&Journal {
                    id: journal_id.clone(),
                    entries: compensation,
                }) {
                    Ok(()) => Err(err),
                    Err(rollback_err) => Err(Error::inject(
                        &patch.path,
                        format!("写入失败且自动补偿失败（需人工介入）: {err} / {rollback_err}"),
                    )),
                };
            }
        }
    }

    // 成功后顺带清过期备份（DEBUG-G5 P1-10，尽力而为）：本轮刚建的 journal
    // 远未过期，不会被误删；清理失败不影响本次 apply 的成功回报。
    let _ = prune_expired_backups(backup_dir, BACKUP_RETENTION);
    Ok(Journal {
        id: journal_id,
        entries,
    })
}

/// 回滚：校验文件未被外部改动后还原（或删除原本不存在的文件）。
///
/// **尽力而为**：逐个条目尝试还原，单个失败（例如该文件被外部改过、或目录不可写）
/// 不会中断其余条目的还原；只要有一条失败，整体返回 `Err` 并列出全部失败原因。
/// 这样一次失败不会把其他文件永久留在「已注入」状态。
pub fn rollback(journal: &Journal) -> Result<()> {
    let mut failures: Vec<String> = Vec::new();
    for entry in journal.entries.iter().rev() {
        if let Err(err) = restore_entry(entry) {
            failures.push(err.to_string());
        }
    }

    if failures.is_empty() {
        return Ok(());
    }
    Err(Error::Inject {
        path: format!("journal {}", journal.id),
        reason: format!(
            "{} 个文件未能还原: {}",
            failures.len(),
            failures.join(" | ")
        ),
    })
}

fn restore_entry(entry: &JournalEntry) -> Result<()> {
    if entry.path.exists() {
        let current = fs::read(&entry.path)
            .map_err(|e| Error::inject(&entry.path, format!("读取失败: {e}")))?;
        if sha256_hex(&current) != entry.after_sha256 {
            return Err(Error::inject(
                &entry.path,
                "文件已被外部修改，拒绝覆盖（请手工处理后重试）",
            ));
        }
    }

    match &entry.backup {
        Some(backup) => {
            let bytes = fs::read(backup)
                .map_err(|e| Error::inject(backup, format!("读取备份失败: {e}")))?;
            let contents = String::from_utf8(bytes)
                .map_err(|_| Error::inject(backup, "备份不是合法 UTF-8"))?;
            write_atomic(&entry.path, &contents, None, Some(backup))?;
            // DEBUG-G5 P1-10：备份文件已被强制成 0600，`write_atomic` 的模板
            // 优先规则会把 0600 带到目标上——回滚语义是「还原到投递之前」，
            // 包括原始权限位，故按 entry.before_mode 再钉一次（方向是还原，
            // 不是放宽：0600 的原文件仍是 0600，0644 的原文件回到 0644）。
            // before_mode 为 None（老库重建行）时跳过，保留模板行为。
            #[cfg(unix)]
            if let Some(mode) = entry.before_mode {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&entry.path, fs::Permissions::from_mode(mode))
                    .map_err(|e| Error::inject(&entry.path, format!("还原权限失败: {e}")))?;
            }
        }
        None => {
            if entry.path.exists() {
                fs::remove_file(&entry.path)
                    .map_err(|e| Error::inject(&entry.path, format!("删除失败: {e}")))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn patch_for(dir: &Path, before: &str, after: &str) -> Patch {
        Patch::new(dir.join("config.toml"), before, after)
    }

    #[test]
    fn apply_then_rollback_restores_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let original = "# 注释保留\nmodel = \"old\"\n";
        let target = dir.path().join("config.toml");
        fs::write(&target, original).unwrap();

        let patch = patch_for(dir.path(), original, "model = \"new\"\n");
        let journal = apply(&[patch], &dir.path().join("backups")).unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "model = \"new\"\n");
        assert!(journal.entries[0].backup.is_some());

        rollback(&journal).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), original);
        assert_eq!(
            sha256_hex(original.as_bytes()),
            journal.entries[0].before_sha256.clone().unwrap()
        );
    }

    #[test]
    fn apply_rejects_concurrent_change() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        fs::write(&target, "changed by user").unwrap();

        let patch = patch_for(dir.path(), "expected content", "new");
        let err = apply(&[patch], &dir.path().join("backups")).unwrap_err();
        assert!(matches!(err, Error::Inject { .. }));
        // 未通过校验时不得改写文件
        assert_eq!(fs::read_to_string(&target).unwrap(), "changed by user");
    }

    #[test]
    fn rollback_refuses_when_file_modified_after_apply() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        fs::write(&target, "before").unwrap();

        let patch = patch_for(dir.path(), "before", "after");
        let journal = apply(&[patch], &dir.path().join("backups")).unwrap();

        fs::write(&target, "after but edited by user").unwrap();
        let err = rollback(&journal).unwrap_err();
        assert!(matches!(err, Error::Inject { .. }));
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "after but edited by user"
        );
    }

    #[test]
    fn rollback_deletes_file_that_did_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("brand-new.toml");
        let patch = Patch::new(target.clone(), String::new(), "created".to_string());
        let journal = apply(&[patch], &dir.path().join("backups")).unwrap();
        assert!(target.exists());
        assert!(journal.entries[0].backup.is_none());

        rollback(&journal).unwrap();
        assert!(!target.exists());
    }

    #[test]
    fn consecutive_applies_use_separate_backups_and_roll_back_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        fs::write(&target, "v0").unwrap();

        let j1 = apply(
            &[patch_for(dir.path(), "v0", "v1")],
            &dir.path().join("backups"),
        )
        .unwrap();
        let j2 = apply(
            &[patch_for(dir.path(), "v1", "v2")],
            &dir.path().join("backups"),
        )
        .unwrap();

        assert_ne!(j1.id, j2.id, "journal id 必须唯一");
        assert_ne!(
            j1.entries[0].backup, j2.entries[0].backup,
            "两次注入的备份必须落在不同文件，否则回滚链会断裂"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "v2");

        rollback(&j2).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "v1");
        rollback(&j1).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "v0");
    }

    #[test]
    fn multi_patch_preflight_failure_touches_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.toml");
        fs::write(&a, "A0").unwrap();
        let b = dir.path().join("b.toml");
        fs::write(&b, "B0").unwrap();

        let patches = vec![
            Patch::new(a.clone(), "A0", "A1"),
            Patch::new(b.clone(), "与磁盘不符的前置内容", "B1"),
        ];

        let err = apply(&patches, &dir.path().join("backups")).unwrap_err();
        assert!(matches!(err, Error::Inject { .. }));
        // 预检失败必须在动任何文件之前发生
        assert_eq!(fs::read_to_string(&a).unwrap(), "A0");
        assert_eq!(fs::read_to_string(&b).unwrap(), "B0");
    }

    #[cfg(unix)]
    #[test]
    fn multi_patch_write_failure_compensates_written_files() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.toml");
        fs::write(&a, "A0").unwrap();

        let readonly = dir.path().join("ro");
        fs::create_dir(&readonly).unwrap();
        let b = readonly.join("b.toml");
        fs::write(&b, "B0").unwrap();

        // 目录只读 → 第 2 个补丁写临时文件必然失败，触发补偿路径
        let mut perm = fs::metadata(&readonly).unwrap().permissions();
        perm.set_mode(0o500);
        fs::set_permissions(&readonly, perm).unwrap();

        let patches = vec![
            Patch::new(a.clone(), "A0", "A1"),
            Patch::new(b.clone(), "B0", "B1"),
        ];

        let err = apply(&patches, &dir.path().join("backups")).unwrap_err();
        assert!(matches!(err, Error::Inject { .. }));
        // 已写入的第 1 个文件必须被补偿还原
        assert_eq!(fs::read_to_string(&a).unwrap(), "A0");
        assert_eq!(fs::read_to_string(&b).unwrap(), "B0");

        let mut perm = fs::metadata(&readonly).unwrap().permissions();
        perm.set_mode(0o700);
        fs::set_permissions(&readonly, perm).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn apply_and_rollback_preserve_file_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        fs::write(&target, "v0").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();

        let journal = apply(
            &[patch_for(dir.path(), "v0", "v1")],
            &dir.path().join("backups"),
        )
        .unwrap();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600,
            "注入后权限位不得被放宽"
        );

        rollback(&journal).unwrap();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600,
            "回滚后权限位必须保持"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "v0");
    }

    #[test]
    fn write_is_atomic_no_temp_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        fs::write(&target, "a").unwrap();
        let patch = patch_for(dir.path(), "a", "b");
        apply(&[patch], &dir.path().join("backups")).unwrap();

        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tianshu-relay.tmp"))
            .collect();
        assert!(leftovers.is_empty(), "临时文件未清理: {leftovers:?}");
    }

    // ==================================================== M1-S2：B-12 / 0600 / 文件锁

    #[test]
    fn patch_debug_never_prints_contents() {
        // BACKLOG B-12：投递场景下 `after` 含密钥本体，用户 config.toml 里也可能有明文密钥
        let patch = Patch::secret_bearing(
            "/home/u/.codex/auth.json",
            r#"{"auth_mode":"apikey","OPENAI_API_KEY":"sk-OLD-LEAKY-VALUE"}"#,
            r#"{"auth_mode":"apikey","OPENAI_API_KEY":"sk-NEW-LEAKY-VALUE"}"#,
        );
        let text = format!("{patch:?}");

        assert!(!text.contains("LEAKY"), "{text}");
        assert!(!text.contains("sk-"), "{text}");
        assert!(!text.contains("OPENAI_API_KEY"), "{text}");
        // 有用的诊断信息仍要在
        assert!(text.contains("auth.json"), "{text}");
        assert!(text.contains("after_len"), "{text}");
        assert!(text.contains("after_sha8"), "{text}");
    }

    #[test]
    fn journal_debug_never_prints_contents() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("auth.json");
        fs::write(&target, "{}").unwrap();
        let patch = Patch::secret_bearing(&target, "{}", r#"{"OPENAI_API_KEY":"sk-LEAKY"}"#);
        let journal = apply(&[patch], &dir.path().join("backups")).unwrap();

        let text = format!("{journal:?}");
        assert!(!text.contains("LEAKY"), "{text}");
        assert!(!text.contains("sk-"), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn secret_bearing_new_file_is_created_with_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("auth.json");
        assert!(!target.exists());

        let patch = Patch::secret_bearing(&target, "", r#"{"OPENAI_API_KEY":"sk-x"}"#);
        apply(&[patch], &dir.path().join("backups")).unwrap();

        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600,
            "含密钥的新文件必须是 0600，不能是 umask 决定的 0644"
        );
    }

    #[cfg(unix)]
    #[test]
    fn secret_patch_tightens_a_world_readable_existing_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("auth.json");
        fs::write(&target, "{}").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();

        let patch = Patch::secret_bearing(&target, "{}", r#"{"OPENAI_API_KEY":"sk-x"}"#);
        let journal = apply(&[patch], &dir.path().join("backups")).unwrap();

        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600,
            "含密钥的文件不得保持 0644"
        );

        // 回滚要按**原始**权限还原（0644），而不是把收紧后的 0600 也带回去
        rollback(&journal).unwrap();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644,
            "回滚必须还原原始权限位"
        );
    }

    #[cfg(unix)]
    #[test]
    fn secret_patch_never_widens_a_stricter_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("auth.json");
        fs::write(&target, "{}").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o400)).unwrap();

        let patch = Patch::secret_bearing(&target, "{}", r#"{"OPENAI_API_KEY":"sk-x"}"#);
        apply(&[patch], &dir.path().join("backups")).unwrap();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o400,
            "不得把只读文件放宽成 0600"
        );
    }

    #[cfg(unix)]
    #[test]
    fn plain_patch_new_file_still_uses_0644() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");

        let patch = Patch::new(&target, "", "model = \"gpt\"\n");
        apply(&[patch], &dir.path().join("backups")).unwrap();

        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[cfg(unix)]
    #[test]
    fn rollback_restores_0600_when_file_was_deleted_in_between() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("auth.json");
        fs::write(&target, "{}").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();

        let patch = Patch::secret_bearing(&target, "{}", r#"{"OPENAI_API_KEY":"sk-x"}"#);
        let journal = apply(&[patch], &dir.path().join("backups")).unwrap();

        // 模拟「注入后目标被外部删除」，回滚时必须从备份重建而不是留下 0644
        fs::remove_file(&target).unwrap();
        rollback(&journal).unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "{}");
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600,
            "回滚重建的文件必须继承备份的权限位"
        );
    }

    #[test]
    fn apply_takes_the_lock_so_a_second_apply_is_busy() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        fs::write(&target, "v0").unwrap();
        let backup_dir = dir.path().join("backups");

        // 手工持有锁 → apply 必须报 FileBusy 而不是继续写
        let lock_dir = default_lock_dir();
        let held = lock::FileLock::acquire(&target, &lock_dir).unwrap();

        let err = apply(&[Patch::new(&target, "v0", "v1")], &backup_dir).unwrap_err();
        assert!(matches!(err, Error::FileBusy(_)), "{err:?}");
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "v0",
            "被锁住时不得写入"
        );

        drop(held);
        apply(&[Patch::new(&target, "v0", "v1")], &backup_dir).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "v1");
    }

    #[test]
    fn duplicate_paths_in_one_batch_are_rejected() {
        // BACKLOG B-46（改写自 `duplicate_paths_in_one_batch_do_not_self_deadlock`，
        // 差异登记见 `docs/specs/M5-S3-适配器与注入加固.md` §11 D-1）。
        //
        // 旧行为：重复路径被静默接受（后者胜、回滚链串起来）或报出
        // 「文件内容与计划不一致（可能被外部修改）」——两种都把调用方的计划错误
        // 说成外部改动。新行为：预检之前直接拒绝。
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        fs::write(&target, "v0").unwrap();

        let err = apply(
            &[
                Patch::new(&target, "v0", "v1"),
                // 第二条的 before 与第一条的 after 串联：这正是旧实现报「可能被外部修改」的形态
                Patch::new(&target, "v1", "v2"),
            ],
            &dir.path().join("backups"),
        )
        .unwrap_err();

        assert!(matches!(err, Error::Inject { .. }), "{err:?}");
        let message = err.to_string();
        assert!(message.contains("同一批次"), "{message}");
        assert!(message.contains("重复"), "{message}");
        assert!(
            message.contains("config.toml"),
            "文案必须带路径原文: {message}"
        );
        assert!(
            !message.contains("可能被外部修改"),
            "不得再落到误导性的外部改动文案: {message}"
        );
        // 前置校验：磁盘一个字节都没动
        assert_eq!(fs::read_to_string(&target).unwrap(), "v0");
    }

    #[test]
    fn duplicate_paths_are_rejected_before_any_read() {
        // 同一个目标用两种字面写法（相对 + 归一化后相同），并且磁盘内容与 before 不符：
        // 必须拿到「同一批次重复」而不是「可能被外部修改」——证明校验发生在预检之前。
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        fs::write(&target, "实际内容").unwrap();

        let aliased = dir.path().join(".").join("config.toml");
        let err = apply(
            &[
                Patch::new(&target, "与磁盘不符", "a"),
                Patch::new(&aliased, "与磁盘不符", "b"),
            ],
            &dir.path().join("backups"),
        )
        .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("同一批次"), "{message}");
        assert!(message.contains("重复"), "{message}");
        assert!(!message.contains("可能被外部修改"), "{message}");
        assert_eq!(fs::read_to_string(&target).unwrap(), "实际内容");
    }

    #[test]
    fn distinct_paths_in_one_batch_still_apply() {
        // 反例保护：不同路径的多条补丁不得被重复校验误伤
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.toml");
        let b = dir.path().join("b.toml");
        fs::write(&a, "A0").unwrap();
        fs::write(&b, "B0").unwrap();

        let journal = apply(
            &[Patch::new(&a, "A0", "A1"), Patch::new(&b, "B0", "B1")],
            &dir.path().join("backups"),
        )
        .unwrap();

        assert_eq!(journal.entries.len(), 2);
        assert_eq!(fs::read_to_string(&a).unwrap(), "A1");
        assert_eq!(fs::read_to_string(&b).unwrap(), "B1");
    }

    #[cfg(unix)]
    #[test]
    fn temp_file_never_exists_with_a_wider_mode_than_the_target() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        // 复审 P1-1 的回归：旧实现用 `fs::write`（umask 022 → 0644）建临时文件、
        // 写入密钥正文、**再** chmod 0600，留下一个「内容是密钥、权限 0644」的窗口。
        // 这里用一个观察线程在整个写入过程中轮询临时文件的权限位。
        //
        // 为什么带重试（复审 P2-12）：采样是竞态的——写入太快时观察线程可能**一个
        // 样本都没采到**（实测 1/19 次），于是门禁在负载高时无缘无故变红。
        // 单次采不到样本 ≠ 实现有问题，所以改成最多 `ATTEMPTS` 轮、累加所有样本：
        // 只要**任意一轮**采到样本就足以判定；轮数多了之后「全都采不到」几乎不可能，
        // 而「临时文件权限真的宽了」这种回归在每一轮都会被采到。
        const ATTEMPTS: usize = 12;
        let mut observed: Vec<u32> = Vec::new();
        let mut last_target = None;

        for _ in 0..ATTEMPTS {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("auth.json");
            let stop = Arc::new(AtomicBool::new(false));

            let watcher = {
                let dir = dir.path().to_path_buf();
                let stop = stop.clone();
                std::thread::spawn(move || {
                    let mut seen: Vec<u32> = Vec::new();
                    while !stop.load(Ordering::Relaxed) {
                        if let Ok(entries) = fs::read_dir(&dir) {
                            for entry in entries.flatten() {
                                let name = entry.file_name().to_string_lossy().to_string();
                                if name.ends_with(".tmp") {
                                    if let Ok(meta) = entry.metadata() {
                                        seen.push(meta.permissions().mode() & 0o777);
                                    }
                                }
                            }
                        }
                    }
                    seen
                })
            };

            // 内容足够大，让写入过程持续可观测
            let big = "x".repeat(16 * 1024 * 1024);
            let patch = Patch::secret_bearing(&target, "", big.clone());
            apply(&[patch], &dir.path().join("backups")).unwrap();

            stop.store(true, Ordering::Relaxed);
            observed.extend(watcher.join().expect("观察线程"));

            // 终态每轮都要对：临时文件已改名成目标文件，权限必须是 0600
            assert_eq!(
                fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o600
            );
            last_target = Some(target);
        }

        assert!(
            !observed.is_empty(),
            "连续 {ATTEMPTS} 轮、每轮 16 MiB 写入都没采到任何样本 → 该门禁是空跑"
        );
        assert!(
            observed.iter().all(|m| *m == 0o600),
            "临时文件出现过非 0600 的权限位: {observed:?}"
        );
        assert!(last_target.is_some());
    }

    #[test]
    fn apply_uses_a_lock_dir_independent_of_backup_dir() {
        // 复审 P1-3 的回归：换个 backup_dir 不得换锁文件
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("auth.json");
        fs::write(&target, "v0").unwrap();

        let held = lock::FileLock::acquire(&target, &default_lock_dir()).unwrap();

        // 故意用一个与持锁者完全无关的 backup_dir
        let err = apply(
            &[Patch::new(&target, "v0", "v1")],
            &dir.path().join("totally/other/backups"),
        )
        .unwrap_err();
        assert!(matches!(err, Error::FileBusy(_)), "{err:?}");
        assert_eq!(fs::read_to_string(&target).unwrap(), "v0");
        drop(held);
    }

    #[cfg(unix)]
    #[test]
    fn requested_mode_is_not_masked_by_umask() {
        use std::os::unix::fs::PermissionsExt;

        // 回归：`OpenOptions::mode(0o664)` 在 umask 022 下会变成 0644。
        // 现在创建后再 `fchmod` 一次，请求什么就是什么。
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("auth.json");
        fs::write(&target, "{}").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o664)).unwrap();

        let patch = Patch::secret_bearing(&target, "{}", r#"{"k":"v"}"#);
        let journal = apply(&[patch], &dir.path().join("backups")).unwrap();

        // 含密钥的文件会被收紧到 0600（`clamp_secret_mode`）
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        rollback(&journal).unwrap();
        // 回滚必须还原成**原始**的 0664，而不是被 umask 剥成 0644
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o664,
            "回滚必须还原原始权限位（0664），不能被 umask 剥成 0644"
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_write_through_a_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.json");
        fs::write(&real, "{}").unwrap();
        let link = dir.path().join("link.json");
        symlink(&real, &link).unwrap();

        let patch = Patch::secret_bearing(&link, "{}", r#"{"k":"v"}"#);
        let err = apply(&[patch], &dir.path().join("backups")).unwrap_err();
        assert!(matches!(err, Error::Inject { .. }), "{err:?}");
        assert!(err.to_string().contains("符号链接"), "{err}");

        // 链接还在、指向的文件一个字节没动
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_to_string(&real).unwrap(), "{}");
    }

    #[test]
    fn lock_dir_does_not_depend_on_caller_arguments() {
        // 复审 P1-3 的回归：换 backup_dir 不得换锁文件
        let a = Patch::new("/tmp/x/auth.json", "", "a");
        let b = Patch::new("/tmp/x/auth.json", "", "a");
        assert_eq!(
            lock::FileLock::lock_path(&a.path, &default_lock_dir()),
            lock::FileLock::lock_path(&b.path, &default_lock_dir())
        );
        assert!(default_lock_dir().is_absolute(), "锁目录必须是绝对路径");
    }

    #[test]
    fn temp_path_is_unpredictable_and_unique() {
        let dir = Path::new("/tmp/x");
        let a = temp_path(dir, "auth.json");
        let b = temp_path(dir, "auth.json");
        assert_ne!(a, b, "两次写入不得用同一个临时名");
        assert!(a.to_string_lossy().ends_with(".tmp"));
        assert!(a.to_string_lossy().contains("auth.json"));
    }

    #[cfg(unix)]
    #[test]
    fn backup_is_forced_0600_and_rollback_restores_original_mode() {
        // DEBUG-G5 P1-10：源文件 0644 时备份文件不得继承 0644（含旧密钥明文
        // 的完整旧配置），必须强制 0600；journal 目录 0700；回滚时内容与
        // 原始权限位（0644）都要回来——备份文件本身不再是权限模板。
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("config.toml");
        fs::write(&target, "old-secret").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();

        let journal = apply(
            &[Patch::new(&target, "old-secret", "new-secret")],
            &dir.path().join("backups"),
        )
        .unwrap();
        let backup = journal.entries[0].backup.clone().expect("应有备份");
        assert_eq!(
            fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o600,
            "备份文件必须强制 0600，不得继承源文件 0644"
        );
        let journal_dir = backup.parent().unwrap();
        assert_eq!(
            fs::metadata(journal_dir).unwrap().permissions().mode() & 0o777,
            0o700,
            "备份目录必须 0700"
        );
        assert_eq!(journal.entries[0].before_mode, Some(0o644));

        rollback(&journal).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "old-secret");
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o644,
            "回滚必须还原原始权限位，而不是备份的 0600"
        );
    }

    #[test]
    fn prune_expired_backups_only_touches_old_journal_dirs() {
        // DEBUG-G5 P1-10：只删 j* 真实目录中超过保留期的；非 j* 目录、
        // 普通文件、未过期目录一律不动。
        let dir = tempfile::tempdir().unwrap();
        let backup_dir = dir.path().join("backups");
        let old_journal = backup_dir.join("j1000-0");
        let fresh_journal = backup_dir.join("j2000-0");
        let other_dir = backup_dir.join("exports");
        fs::create_dir_all(&old_journal).unwrap();
        fs::create_dir_all(&fresh_journal).unwrap();
        fs::create_dir_all(&other_dir).unwrap();
        fs::write(backup_dir.join("notes.txt"), "keep").unwrap();

        // 保留期 0：全部 j* 目录都已过期（mtime 早于 now）。
        let removed = prune_expired_backups(&backup_dir, std::time::Duration::from_secs(0));
        assert_eq!(removed, 2, "两个 j* 目录都应被删");
        assert!(!old_journal.exists());
        assert!(!fresh_journal.exists());
        assert!(other_dir.exists(), "非 j* 目录不得动");
        assert!(backup_dir.join("notes.txt").exists(), "普通文件不得动");

        // 保留期极大：新建的 j* 目录未过期，保留。
        let kept = backup_dir.join("j3000-0");
        fs::create_dir_all(&kept).unwrap();
        let removed =
            prune_expired_backups(&backup_dir, std::time::Duration::from_secs(365 * 24 * 3600));
        assert_eq!(removed, 0, "未过期目录不得删");
        assert!(kept.exists());
    }
}
