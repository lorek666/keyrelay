//! 跨进程文件锁的真实互斥验证（BACKLOG B-16）。
//!
//! `flock` 在**同一进程的不同 fd** 上不互斥（实测同进程二次 `try_lock` 会成功），
//! 因此「同进程二次获取 → FileBusy」只能证明进程内那道锁有效。
//! 本文件用**真的起一个子进程**来证明跨进程那道锁也有效。
//!
//! # B-150：为什么三条用例要**串行**
//!
//! 本文件三条用例共享一个**进程级**资源：fd 表（`flock` 的载体）与 `FileLock` 的进程内登记。
//! `cross_process_lock_excludes_another_process` 会 `fork` 一个子进程，而 fork 出来的子进程
//! 在 `exec` 之前**短暂共享**父进程所有打开文件的 open file description —— 那期间**别的用例
//! 刚 `drop` 掉的 flock 仍然有效**（`O_CLOEXEC` 只在 `exec` 那一刻才关 fd）。于是那两条
//! 「释放后立刻重取」的用例会拿到 `FileBusy` ⇒ 满载下偶发红。
//!
//! 实测（6 实例并发 × 20 轮 = 120 次运行，负载 = 20 个 CPU 抢占进程 + 一路并行编译）：
//! 三条并行 **5/120 红**、`--test-threads=1` **0/120**、单跑任一用例 **0/120**、
//! 只跑两条进程内用例（没有 fork）**0/120**、跨进程 + panic 两条并行 **11/120 红**。
//! 详见 `docs/specs/M16-S10-跨进程锁用例的满载偶发.md` 与 `docs/evidence/m16s10-lock.md`。
//!
//! 串行化是这条依赖的正确表达（同一时刻只允许一条用例碰这套共享资源），**不是**放松断言：
//! 三条用例的断言逐字未变。

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use keyrelay_core::error::Error;
use keyrelay_core::inject::lock::FileLock;

const ENV_HOLDER: &str = "KEYRELAY_LOCK_TEST_HOLDER";
const ENV_TARGET: &str = "KEYRELAY_LOCK_TEST_TARGET";
const ENV_READY: &str = "KEYRELAY_LOCK_TEST_READY";
const ENV_DONE: &str = "KEYRELAY_LOCK_TEST_DONE";
const ENV_LOCK_DIR: &str = "KEYRELAY_LOCK_TEST_LOCK_DIR";

/// 本文件三条用例的串行闸门（B-150，理由见文件头）。
static SERIAL: Mutex<()> = Mutex::new(());

/// 取串行闸门。中毒也要继续跑：本文件唯一的 panic 被 `catch_unwind` 捕获、不穿过这把锁，
/// 真中毒时也该让用例报出自己的失败，而不是被别人带崩。
fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// 等 `ready.flag`，同时**感知子进程退出**：子进程没写 ready 就退出 ⇒ 立刻报事实（状态），
/// 而不是等满超时再报「未在 Ns 内拿到锁」。超时只是兜底，不参与正确性判断。
fn wait_for_ready(
    child: &mut std::process::Child,
    ready: &Path,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if ready.exists() {
            return Ok(());
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(format!("子进程在写 ready 之前就退出了（{status:?}）"));
            }
            Ok(None) => {}
            Err(e) => return Err(format!("查询子进程状态失败: {e}")),
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "子进程未在 {}s 内拿到锁（无法验证跨进程互斥）",
                timeout.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// 子进程模式：持锁 → 通知父进程 → 等父进程写 `done.flag` 再释放（B-123 修法）。
///
/// 用同一个测试二进制 + 环境变量来扮演「另一个 KeyRelay 实例」，
/// 避免为了这个测试再引入一个辅助 bin。
///
/// **B-123**：旧实现固定 `sleep(5s)` 持锁，父进程看到 `ready` 后若被调度挂起 ≥5s
/// （门禁满载、内存紧张时出现），子进程已释放、父进程拿到锁 ⇒ 误红。改成握手：
/// 子进程持锁直到父进程写出 `done.flag`，父进程 `acquire` 并记下结果后再写 `done`。
///
/// **B-150**：握手本身是确定性的，但持锁窗口的上界原先写成「60s 墙钟兜底」——那是
/// **猜时间**：父进程若在 60s 内没写 `done`（极端满载），子进程会自己释放 ⇒ 父进程的
/// 「必须失败」变成成功 ⇒ 假红，且文案指向完全错误的方向。现在改成由**父进程存活**界定：
/// 父进程把 stdin 管道交给子进程（见调用点 `Stdio::piped()`），子进程读到 EOF 即知父进程
/// 已不在 ⇒ 释放。EOF 是事实，不是猜测；父进程活着就一直持锁（不管它多慢）。
fn run_as_holder() {
    let target = PathBuf::from(std::env::var(ENV_TARGET).expect("子进程需要目标路径"));
    let ready = PathBuf::from(std::env::var(ENV_READY).expect("子进程需要 ready 文件"));
    let done = PathBuf::from(std::env::var(ENV_DONE).expect("子进程需要 done 文件"));
    let lock_dir = PathBuf::from(std::env::var(ENV_LOCK_DIR).expect("子进程需要锁目录"));

    let _guard = FileLock::acquire(&target, &lock_dir).expect("子进程应能拿到锁");
    fs::write(&ready, b"locked").expect("写 ready 文件");

    // 父进程消失的判据：stdin 读到 EOF（父进程那端的管道关闭）。
    let parent_gone = Arc::new(AtomicBool::new(false));
    {
        let flag = Arc::clone(&parent_gone);
        std::thread::spawn(move || {
            let mut buf = [0u8; 1];
            let mut stdin = std::io::stdin();
            while matches!(stdin.read(&mut buf), Ok(n) if n > 0) {}
            flag.store(true, Ordering::SeqCst);
        });
    }

    // 两个判据都是**事实**：① 父进程写了 `done`；② 父进程已经不在了（EOF）。
    while !done.exists() && !parent_gone.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn cross_process_lock_excludes_another_process() {
    let _serial = serial_guard();

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
        // B-150：子进程的 stdin 是父进程给的管道 ⇒ 父进程一消失（或主动关闭）就 EOF，
        // 子进程据此释放锁。持锁窗口由**父进程存活**界定，不依赖墙钟。
        .stdin(Stdio::piped())
        .spawn()
        .expect("启动子进程");

    if let Err(why) = wait_for_ready(&mut child, &ready, Duration::from_secs(20)) {
        let _ = child.kill();
        panic!("{why}");
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
    let _serial = serial_guard();

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
    let _serial = serial_guard();

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
