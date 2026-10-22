//! 品牌改名的旧数据迁移（M35-S1 §4.2）。
//!
//! 设计约束（逐条对应 spec 的 10 步算法）：
//!
//! - **旧目录只读**：迁移只复制，绝不修改/删除 `~/.keyrelay` 里的任何字节。
//! - **失败必须回退**：任何一步失败都用**旧目录**继续跑（数据比新名字重要）。
//! - **不覆盖已有新目录**：目标非空就不动它（`TargetExists`）。
//! - **不跟符号链接**：链接目标可能是用户主目录之外的任意位置，跟随会把无关文件复制进来。
//! - **上限 2 GiB**：防止误把超大目录（例如用户塞进去的备份）复制一份。
//! - **临时目录清理**：成功 rename 后自然消失；失败/已存在都必须删干净。
//! - **`PRAGMA quick_check`**：复制后先确认库不是坏页，再落位。空文件/坏库直接失败。

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// 旧目录相对用户 home 的名字。
pub const LEGACY_APP_DIR_NAME: &str = ".keyrelay";
/// 新目录相对用户 home 的名字。
pub const APP_DIR_NAME: &str = ".tianshu-relay";
/// 新主库文件名。
pub const DB_FILE_NAME: &str = "tianshu-relay.db";
/// 旧主库文件名（迁移源）。
pub const LEGACY_DB_FILE_NAME: &str = "keyrelay.db";

/// 复制上限：2 GiB。
const MAX_COPY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RebrandStatus {
    /// 没有旧目录，或新目录已有主库：无需迁移。
    NoLegacy,
    /// 本次成功复制旧目录 → 新目录。
    Migrated,
    /// 新目录已存在非空内容但还没有主库：不覆盖，保持原样。
    TargetExists,
    /// 复制/校验失败；调用方必须继续使用旧目录。
    Failed,
}

impl RebrandStatus {
    /// 给 IPC / 前端用的稳定字符串（spec §4.3）。
    pub fn as_str(self) -> &'static str {
        match self {
            RebrandStatus::NoLegacy => "noLegacy",
            RebrandStatus::Migrated => "migrated",
            RebrandStatus::TargetExists => "targetExists",
            RebrandStatus::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebrandReport {
    pub status: RebrandStatus,
    pub from: Option<PathBuf>,
    pub to: PathBuf,
    pub files: usize,
    pub bytes: u64,
    /// 迁移过程中的非致命提示（例如旧自启项已停用）。不含任何密钥材料。
    pub warnings: Vec<String>,
    /// `Failed` 时的脱敏原因；其它状态为 `None`。
    pub error: Option<String>,
}

impl RebrandReport {
    fn simple(status: RebrandStatus, to: PathBuf) -> Self {
        Self {
            status,
            from: None,
            to,
            files: 0,
            bytes: 0,
            warnings: Vec::new(),
            error: None,
        }
    }
}

/// 解析本次启动使用的数据目录。
pub fn resolve_app_home(home: &Path) -> (PathBuf, RebrandReport) {
    let new = home.join(APP_DIR_NAME);
    let old = home.join(LEGACY_APP_DIR_NAME);

    // 2. 新库已在 ⇒ 无需迁移（旧目录留着也不动）。
    if new.join(DB_FILE_NAME).exists() {
        return (
            new.clone(),
            RebrandReport::simple(RebrandStatus::NoLegacy, new),
        );
    }
    // 3. 旧目录不存在 ⇒ 用新目录（由调用方创建）。
    if !old.is_dir() {
        return (
            new.clone(),
            RebrandReport::simple(RebrandStatus::NoLegacy, new),
        );
    }
    // 4. 新目录存在且非空 ⇒ 不覆盖。
    if is_non_empty_dir(&new) {
        return (
            new.clone(),
            RebrandReport::simple(RebrandStatus::TargetExists, new),
        );
    }

    match try_migrate(home, &old, &new) {
        Ok(report) => {
            let to = report.to.clone();
            (to, report)
        }
        Err(err) => {
            // 9. 失败 ⇒ 用**旧目录**继续跑，错误脱敏。
            let report = RebrandReport {
                status: RebrandStatus::Failed,
                from: Some(old.clone()),
                to: new,
                files: 0,
                bytes: 0,
                warnings: Vec::new(),
                error: Some(crate::redact::scrub(&err.to_string())),
            };
            (old, report)
        }
    }
}

fn is_non_empty_dir(p: &Path) -> bool {
    fs::read_dir(p)
        .map(|mut it| it.next().is_some())
        .unwrap_or(false)
}

/// 第 5–8 步：临时目录 → 复制 → quick_check → rename 落位。
fn try_migrate(home: &Path, old: &Path, new: &Path) -> Result<RebrandReport> {
    let stamp = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let temp = home.join(format!("{APP_DIR_NAME}.migrating-{stamp}"));

    // 临时目录 0700（里面有密钥库副本）
    create_private_dir(&temp)?;

    let outcome = (|| -> Result<(usize, u64, Vec<String>)> {
        let mut warnings = Vec::new();
        let (files, bytes) = copy_tree(old, &temp, &mut warnings, 0, 0)?;
        // 6. 副本的库完整性
        quick_check(&temp.join(DB_FILE_NAME))?;
        quick_check(&temp.join("vault.db"))?;
        Ok((files, bytes, warnings))
    })();

    let (files, bytes, warnings) = match outcome {
        Ok(v) => v,
        Err(e) => {
            let _ = fs::remove_dir_all(&temp);
            return Err(e);
        }
    };

    // 7. 原子落位；目标在此期间出现 ⇒ 不覆盖。
    match fs::rename(&temp, new) {
        Ok(()) => {}
        Err(e) => {
            let _ = fs::remove_dir_all(&temp);
            if new.exists() {
                return Ok(RebrandReport::simple(
                    RebrandStatus::TargetExists,
                    new.to_path_buf(),
                ));
            }
            return Err(Error::Store(format!("迁移落位失败: {e}")));
        }
    }

    Ok(RebrandReport {
        status: RebrandStatus::Migrated,
        from: Some(old.to_path_buf()),
        to: new.to_path_buf(),
        files,
        bytes,
        warnings,
        error: None,
    })
}

fn create_private_dir(p: &Path) -> Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    #[cfg(not(unix))]
    {
        // Windows 没有 POSIX mode；目录继承用户目录 ACL。这里显式留一个非 unix 分支，
        // 让 platform_parity 的「unix 代码必须有非 unix 对应实现」守护能看见。
    }
    b.create(p)
        .map_err(|e| Error::Store(format!("创建临时目录失败: {e}")))
}

/// 递归复制。跳过符号链接（记 warning）、跳过 `*-shm`、保留 `*-wal`。
fn copy_tree(
    src: &Path,
    dst: &Path,
    warnings: &mut Vec<String>,
    mut files: usize,
    mut bytes: u64,
) -> Result<(usize, u64)> {
    let entries = fs::read_dir(src).map_err(|e| Error::Store(format!("读取目录失败: {e}")))?;
    for entry in entries {
        let entry = entry.map_err(|e| Error::Store(format!("读取目录项失败: {e}")))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_string();
        let from = entry.path();
        // **主库要改名**：`keyrelay.db` → `tianshu-relay.db`。
        // 只复制不改名的话，新目录里躺着一个 `keyrelay.db`，而应用打开的是
        // `tianshu-relay.db` ⇒ 会新建一个空库，用户看到「数据全没了」。
        // WAL 也要跟着改名：SQLite 按「主库文件名 + `-wal`」找旁路日志，
        // 主库改名而 WAL 不改名 ⇒ 已提交但未 checkpoint 的行**静默丢失**。
        let out_name = if name_str == LEGACY_DB_FILE_NAME {
            std::ffi::OsString::from(DB_FILE_NAME)
        } else if name_str == "keyrelay.db-wal" {
            std::ffi::OsString::from(format!("{DB_FILE_NAME}-wal"))
        } else if name_str == "keyrelay.db-journal" {
            // 旧库若在 rollback journal 模式下异常退出，热日志也要跟着主库改名，
            // 否则 SQLite 会在新目录里找不到它，可能丢掉未提交/正在回滚的事务。
            std::ffi::OsString::from(format!("{DB_FILE_NAME}-journal"))
        } else {
            name.clone()
        };
        let to = dst.join(&out_name);
        let meta = fs::symlink_metadata(&from)
            .map_err(|e| Error::Store(format!("读取元数据失败: {e}")))?;

        // 不跟随符号链接：链接目标可能在 home 之外。
        if meta.file_type().is_symlink() {
            warnings.push(format!("跳过符号链接: {name_str}"));
            continue;
        }
        if meta.is_dir() {
            create_private_dir(&to)?;
            let (f, b) = copy_tree(&from, &to, warnings, files, bytes)?;
            files = f;
            bytes = b;
            continue;
        }
        // `-shm` 是 WAL 的共享内存索引，**不能**跨进程复制（内容指向另一个进程的映射）；
        // `-wal` 必须复制，否则已提交但未 checkpoint 的行会丢。
        if name_str.ends_with("-shm") {
            continue;
        }
        // 目录里其它非普通文件（socket/device）跳过
        if !meta.is_file() {
            warnings.push(format!("跳过非普通文件: {name_str}"));
            continue;
        }

        let len = meta.len();
        bytes = bytes.saturating_add(len);
        if bytes > MAX_COPY_BYTES {
            return Err(Error::Store(format!(
                "待迁移数据超过上限（{} GiB）",
                MAX_COPY_BYTES / 1024 / 1024 / 1024
            )));
        }
        copy_file_private(&from, &to)?;
        files += 1;
    }
    Ok((files, bytes))
}

fn copy_file_private(from: &Path, to: &Path) -> Result<()> {
    let mut src = fs::File::open(from).map_err(|e| Error::Store(format!("打开源文件失败: {e}")))?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(not(unix))]
    {
        // Windows 没有 POSIX mode；文件继承目录 ACL。与 `create_private_dir` 同理。
    }
    let mut dst = opts
        .open(to)
        .map_err(|e| Error::Store(format!("创建目标文件失败: {e}")))?;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = src
            .read(&mut buf)
            .map_err(|e| Error::Store(format!("读取源文件失败: {e}")))?;
        if n == 0 {
            break;
        }
        use std::io::Write;
        dst.write_all(&buf[..n])
            .map_err(|e| Error::Store(format!("写入目标文件失败: {e}")))?;
    }
    Ok(())
}

/// 对副本里的库跑 `PRAGMA quick_check`。文件不存在 ⇒ 无需检查。
fn quick_check(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    // `PRAGMA quick_check` 对一个**短于页头**的垃圾文件会返回 `ok`（SQLite 把它当空库）。
    // 先验 16 字节魔数，避免把「根本不是数据库」的东西搬进新目录。
    // 只读前 16 字节：2 GiB 的库不该为了看一眼魔数就整份读进内存。
    let mut header = [0u8; 16];
    {
        use std::io::Read as _;
        let mut f = fs::File::open(path).map_err(|e| Error::Store(format!("读取副本失败: {e}")))?;
        f.read_exact(&mut header)
            .map_err(|_| Error::Store("迁移副本不是 SQLite 数据库（文件过短）".to_string()))?;
    }
    if &header != b"SQLite format 3\0" {
        return Err(Error::Store("迁移副本不是 SQLite 数据库".to_string()));
    }
    let conn = rusqlite::Connection::open(path)
        .map_err(|e| Error::Store(format!("打开副本数据库失败: {e}")))?;
    let result: String = conn
        .query_row("PRAGMA quick_check", [], |r| r.get(0))
        .map_err(|e| Error::Store(format!("quick_check 失败: {e}")))?;
    if result != "ok" {
        return Err(Error::Store(format!("迁移副本未通过完整性检查: {result}")));
    }
    Ok(())
}

/// 旧版登录自启项：只把 `RunAtLoad` 置 false，**保留文件**。
///
/// 走 [`crate::autostart::plan_disable`] 而不是自己拼字符串：
/// plist 的合法写法很多（空格缩进、`<true></true>`、CRLF），手写 `replacen` 只认两种字节形态，
/// 其余会**静默返回 None**——上层以为「没有旧自启项」，而机器仍然开机启动。
/// `plan_disable` 走真正的 plist 解析，并且产生可备份/可回滚的 `Patch`。
///
/// 四态：
/// - 无旧文件 ⇒ `Ok(None)`；
/// - 已是 `false` ⇒ `Ok(Some(提示))`，**不写盘**（plan 为空 ⇒ `apply_files` 返回 `None`）；
/// - 成功置 false ⇒ `Ok(Some(提示))`；
/// - plist 解析失败 / 写入失败 ⇒ `Err`（调用方只记 warning，不阻断启动）。
///
/// `data_dir` 必须是**本次解析出的**数据目录：迁移失败时会回退旧目录，
/// 这里若按 `home + 新目录名` 硬拼，就会凭空创建新目录，把下次重试挡成 `targetExists`。
pub fn retire_legacy_autostart(home: &Path, data_dir: &Path) -> Result<Option<String>> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (home, data_dir);
        Ok(None)
    }
    #[cfg(target_os = "macos")]
    {
        /// 旧版写进 LaunchAgent 文件名与 `Label` 的 app id。
        const LEGACY_APP_ID: &str = "keyrelay";

        let plist = home
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{LEGACY_APP_ID}-autostart.plist"));
        if !plist.exists() {
            return Ok(None);
        }

        let plan = crate::autostart::plan_disable(home, LEGACY_APP_ID)?;
        // 备份落在**本次实际使用的**数据目录下（旧目录或新目录，取决于迁移结果）。
        plan.apply_files(&data_dir.join("backups"))?;
        Ok(Some(
            "旧版登录自启项已停用（文件保留，可手动删除）".to_string(),
        ))
    }
}
