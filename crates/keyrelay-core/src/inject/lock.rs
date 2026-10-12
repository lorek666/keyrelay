//! 目标文件的排他写锁（进程内 + 跨进程两道），用于封住 `apply` 的
//! 「读 → 校验 → 写」窗口（BACKLOG B-16）。
//!
//! 两道锁**缺一不可**，理由来自实测（见 `docs/ADR/0002`）：
//! - `flock` 在**同一进程的不同 fd** 上不互斥：同进程第二次 `try_lock` 会成功。
//!   因此进程内多线程必须另用一把 `Mutex<HashSet<PathBuf>>`。
//! - 不同进程之间 `try_lock` 返回 `TryLockError::WouldBlock`，跨进程互斥成立。

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use crate::error::{Error, Result};

fn in_process_registry() -> &'static Mutex<HashSet<PathBuf>> {
    static REGISTRY: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashSet::new()))
}

/// 把目标路径归一成稳定 key：相对路径按当前工作目录补全，其余原样。
///
/// **刻意不做 `canonicalize`**：目标文件常常还不存在（`canonicalize` 会失败），
/// 而且按是否存在切换算法会让同一个文件在不同时刻算出不同 key。
/// 调用方负责传入规范化后的绝对路径（本产品的调用方一律由 `home_dir()` 拼出）。
fn normalize(target: &Path) -> PathBuf {
    if target.is_absolute() {
        return target.to_path_buf();
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(target),
        Err(_) => target.to_path_buf(),
    }
}

/// 目标文件的排他写锁。Drop 时释放两道锁。
pub struct FileLock {
    target: PathBuf,
    _file: fs::File,
}

impl FileLock {
    /// 锁文件路径：`<lock_dir>/<sha256(目标绝对路径) 前 16 hex>.lock`。
    ///
    /// 用哈希而不是文件名，避免把用户目录结构暴露在锁目录里，也避免路径里的分隔符出问题。
    pub fn lock_path(target: &Path, lock_dir: &Path) -> PathBuf {
        let digest = super::sha256_hex(normalize(target).to_string_lossy().as_bytes());
        lock_dir.join(format!("{}.lock", &digest[..16]))
    }

    /// 非阻塞获取。已被其它线程/进程占用 → [`Error::FileBusy`]。
    pub fn acquire(target: &Path, lock_dir: &Path) -> Result<Self> {
        let target = normalize(target);

        // 第一道：进程内登记
        {
            let mut registry = in_process_registry()
                .lock()
                .map_err(|_| Error::FileBusy("进程内锁表已中毒".into()))?;
            if registry.contains(&target) {
                return Err(Error::FileBusy(target.display().to_string()));
            }
            registry.insert(target.clone());
        }

        // 第二道：跨进程 flock
        let lock_path = Self::lock_path(&target, lock_dir);
        let acquired = (|| -> Result<fs::File> {
            fs::create_dir_all(lock_dir)
                .map_err(|e| Error::inject(lock_dir, format!("创建锁目录失败: {e}")))?;
            let file = fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(&lock_path)
                .map_err(|e| Error::inject(&lock_path, format!("打开锁文件失败: {e}")))?;
            match file.try_lock() {
                Ok(()) => Ok(file),
                Err(std::fs::TryLockError::WouldBlock) => {
                    Err(Error::FileBusy(target.display().to_string()))
                }
                Err(std::fs::TryLockError::Error(e)) => {
                    Err(Error::inject(&lock_path, format!("加锁失败: {e}")))
                }
            }
        })();

        match acquired {
            Ok(file) => {
                // 锁文件内容写目标路径，便于人工排查「谁锁着谁」。失败不影响加锁结果。
                let _ = fs::write(&lock_path, target.to_string_lossy().as_bytes());
                Ok(Self {
                    target,
                    _file: file,
                })
            }
            Err(err) => {
                // 跨进程加锁失败必须撤回进程内登记，否则一次失败会把这个路径永久锁死。
                if let Ok(mut registry) = in_process_registry().lock() {
                    registry.remove(&target);
                }
                Err(err)
            }
        }
    }

    pub fn target(&self) -> &Path {
        &self.target
    }
}

/// 手写 `Debug`：只暴露目标路径（锁本身不携带密钥）。
impl std::fmt::Debug for FileLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileLock")
            .field("target", &self.target)
            .finish()
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        if let Ok(mut registry) = in_process_registry().lock() {
            registry.remove(&self.target);
        }
        // `_file` 随后被 drop，flock 自动释放。
        // **不删除** `.lock` 文件：删除与其它进程的 open 之间存在竞态，
        // 会出现「A 删掉文件、B 在已删除 inode 上加锁、C 新建同名文件也加锁成功」的双持锁。
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_acquire_in_same_process_is_busy() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("auth.json");
        fs::write(&target, "{}").unwrap();
        let lock_dir = dir.path().join("locks");

        let first = FileLock::acquire(&target, &lock_dir).unwrap();
        let err = FileLock::acquire(&target, &lock_dir).unwrap_err();
        assert!(matches!(err, Error::FileBusy(_)), "{err:?}");

        drop(first);
        // 释放后可再次获取
        let again = FileLock::acquire(&target, &lock_dir).unwrap();
        assert_eq!(again.target(), target);
    }

    #[test]
    fn failed_acquire_does_not_wedge_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("auth.json");
        fs::write(&target, "{}").unwrap();
        let lock_dir = dir.path().join("locks");

        let held = FileLock::acquire(&target, &lock_dir).unwrap();
        assert!(FileLock::acquire(&target, &lock_dir).is_err());
        drop(held);

        // 关键：失败的尝试不能把进程内登记留在表里
        assert!(FileLock::acquire(&target, &lock_dir).is_ok());
    }

    #[test]
    fn different_targets_do_not_block_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let lock_dir = dir.path().join("locks");
        let a = dir.path().join("a.json");
        let b = dir.path().join("b.json");
        fs::write(&a, "{}").unwrap();
        fs::write(&b, "{}").unwrap();

        let _la = FileLock::acquire(&a, &lock_dir).unwrap();
        let _lb = FileLock::acquire(&b, &lock_dir).expect("不同目标不应互相阻塞");
    }

    #[test]
    fn lock_path_is_stable_and_hides_target_name() {
        let target = Path::new("/home/u/.codex/auth.json");
        let dir = Path::new("/tmp/locks");
        let p1 = FileLock::lock_path(target, dir);
        assert_eq!(p1, FileLock::lock_path(target, dir));
        assert_eq!(p1.parent(), Some(dir));
        assert!(p1.to_string_lossy().ends_with(".lock"));
        assert!(!p1.to_string_lossy().contains("auth.json"), "{p1:?}");
    }

    #[test]
    fn lock_file_records_target_path_for_debugging() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("auth.json");
        fs::write(&target, "{}").unwrap();
        let lock_dir = dir.path().join("locks");
        let _lock = FileLock::acquire(&target, &lock_dir).unwrap();

        let written = fs::read_to_string(FileLock::lock_path(&target, &lock_dir)).unwrap();
        assert_eq!(written, target.to_string_lossy());
    }
}
