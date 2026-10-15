//! 跨进程文件锁的真实互斥验证（BACKLOG B-16）。
//!
//! `flock` 在**同一进程的不同 fd** 上不互斥（实测同进程二次 `try_lock` 会成功），
//! 因此「同进程二次获取 → FileBusy」只能证明进程内那道锁有效。
//! 本文件用**真的起一个子进程**来证明跨进程那道锁也有效。

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use keyrelay_core::error::Error;
use keyrelay_core::inject::lock::FileLock;

const ENV_HOLDER: &str = "KEYRELAY_LOCK_TEST_HOLDER";
const ENV_TARGET: &str = "KEYRELAY_LOCK_TEST_TARGET";
const ENV_READY: &str = "KEYRELAY_LOCK_TEST_READY";
const ENV_DONE: &str = "KEYRELAY_LOCK_TEST_DONE";
const ENV_LOCK_DIR: &str = "KEYRELAY_LOCK_TEST_LOCK_DIR";

fn wait_for(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// 子进程模式：持锁 → 通知父进程 → 等父进程写 `done.flag` 再释放（B-123 修法）。
///
/// 用同一个测试二进制 + 环境变量来扮演「另一个 KeyRelay 实例」，
/// 避免为了这个测试再引入一个辅助 bin。
///
/// **B-123**：旧实现固定 `sleep(5s)` 持锁，父进程看到 `ready` 后若被调度挂起 ≥5s
/// （门禁满载、内存紧张时出现），子进程已释放、父进程拿到锁 ⇒ 误红。改成握手：
/// 子进程持锁直到父进程写出 `done.flag`（60s 兜底防父进程崩溃后子进程永久持锁），
/// 父进程 `acquire` 并记下结果后再写 `done`。
fn run_as_holder() {
    let target = PathBuf::from(std::env::var(ENV_TARGET).expect("子进程需要目标路径"));
    let ready = PathBuf::from(std::env::var(ENV_READY).expect("子进程需要 ready 文件"));
    let done = PathBuf::from(std::env::var(ENV_DONE).expect("子进程需要 done 文件"));
    let lock_dir = PathBuf::from(std::env::var(ENV_LOCK_DIR).expect("子进程需要锁目录"));

    let _guard = FileLock::acquire(&target, &lock_dir).expect("子进程应能拿到锁");
    fs::write(&ready, b"locked").expect("写 ready 文件");
    // 持锁直到父进程写出 done.flag（60s 兜底）
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if done.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn cross_process_lock_excludes_another_process() {
    if std::env::var(ENV_HOLDER).is_ok() {
        run_as_holder();
        return;
    }

    let dir = tempfile::tempdir().expect("临时目录");
    let target = dir.path().join("auth.json");
    let lock_dir = dir.path().join("locks");
    let ready = dir.path().join("ready.flag");
    let done = dir.path().join("done.flag");
    fs::write(&target, "{}").expect("预置目标文件");

    let exe = std::env::current_exe().expect("当前测试二进制路径");
    let mut child = std::process::Command::new(exe)
        .args([
            "--exact",
            "cross_process_lock_excludes_another_process",
            "--nocapture",
        ])
        .env(ENV_HOLDER, "1")
        .env(ENV_TARGET, &target)
        .env(ENV_READY, &ready)
        .env(ENV_DONE, &done)
        .env(ENV_LOCK_DIR, &lock_dir)
        .spawn()
        .expect("启动子进程");

    let locked = wait_for(&ready, Duration::from_secs(20));
    if !locked {
        let _ = child.kill();
        panic!("子进程未在 20s 内拿到锁（无法验证跨进程互斥）");
    }

    // 父进程此刻尝试加锁：必须失败，且错误是 FileBusy 而不是「文件不存在」之类。
    // 先记下结果，再写 done.flag 通知子进程释放 —— 顺序不能反，否则子进程可能在
    // 父进程 acquire 之前就释放锁（B-123 根因：旧实现固定 sleep 5s 持锁）。
    let err = match FileLock::acquire(&target, &lock_dir) {
        Ok(_) => panic!("另一进程持锁时本进程不得拿到锁"),
        Err(err) => err,
    };
    fs::write(&done, b"done").expect("写 done 通知子进程释放锁");
    assert!(matches!(err, Error::FileBusy(_)), "{err:?}");

    let status = child.wait().expect("等待子进程");
    assert!(status.success(), "子进程异常退出: {status:?}");

    // 子进程退出后锁必须释放
    let _again = FileLock::acquire(&target, &lock_dir).expect("子进程退出后应能重新加锁");
}

#[test]
fn same_process_second_acquire_is_busy() {
    // 与上一条互补：这道锁由进程内登记保证，不是 flock
    let dir = tempfile::tempdir().expect("临时目录");
    let target = dir.path().join("config.toml");
    let lock_dir = dir.path().join("locks");
    fs::write(&target, "x").expect("预置");

    let first = FileLock::acquire(&target, &lock_dir).expect("首次加锁");
    let err = match FileLock::acquire(&target, &lock_dir) {
        Ok(_) => panic!("同一进程二次加锁必须失败"),
        Err(err) => err,
    };
    assert!(matches!(err, Error::FileBusy(_)), "{err:?}");
    drop(first);

    FileLock::acquire(&target, &lock_dir).expect("释放后可再加锁");
}

#[test]
fn lock_is_released_when_guard_is_dropped_on_panic_path() {
    let dir = tempfile::tempdir().expect("临时目录");
    let target = dir.path().join("config.toml");
    let lock_dir = dir.path().join("locks");
    fs::write(&target, "x").expect("预置");

    let result = std::panic::catch_unwind({
        let target = target.clone();
        let lock_dir = lock_dir.clone();
        move || {
            let _guard = FileLock::acquire(&target, &lock_dir).expect("加锁");
            panic!("模拟业务逻辑 panic");
        }
    });
    assert!(result.is_err(), "应当捕获到 panic");

    // panic 展开会跑 Drop：锁必须已经释放，否则应用会永久卡死
    FileLock::acquire(&target, &lock_dir).expect("panic 后锁必须已释放");
}
