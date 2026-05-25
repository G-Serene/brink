//! Orchestrates a complete sandboxed execution from the Tokio side.
//!
//! Responsibilities:
//!   - Build and write cgroup limits (via CgroupGuard)
//!   - Open PTY pair
//!   - Request spawn from fork server (via spawn_blocking)
//!   - Read child error pipe (confirms execve succeeded)
//!   - Drive TTL timer + pidfd readiness concurrently with PTY I/O
//!   - Assemble ExecutionReport after child exits
//!   - Clean up cgroup (guaranteed even on future cancellation via Drop)

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::Instant;

use nix::errno::Errno;

use crate::cgroup::CgroupGuard;
use crate::config::SandboxConfig;
use crate::error::{ChildStage, SandboxError};
use crate::fork_server::ForkServer;
use crate::ipc::SpawnRequest;
use crate::pty::open_pty;
use crate::report::{ExecutionReport, TerminationReason};

/// Top-level async entry point; called by `Runtime::run`.
pub(crate) async fn run(
    fork_server: &ForkServer,
    config: SandboxConfig,
) -> Result<ExecutionReport, SandboxError> {
    // Step 3: verify delegation before touching cgroup.
    let cgroup = CgroupGuard::create(&config)?;

    // Step 5: open PTY pair.
    let pty = open_pty()?;
    let master_raw = pty.master.as_raw_fd();
    let slave_raw  = pty.slave.as_raw_fd();

    // Build the IPC request.
    let cgroup_path = cgroup.path().to_path_buf();
    let host_uid = unsafe { libc::getuid() };
    let host_gid = unsafe { libc::getgid() };

    let req = SpawnRequest {
        workspace_path:      config.workspace_path.clone(),
        extra_ro_mounts:     config.extra_ro_mounts.clone(),
        memory_max_bytes:    config.memory_max_bytes,
        cpu_quota_us:        config.cpu_quota_us,
        cpu_period_us:       config.cpu_period_us,
        pids_max:            config.pids_max,
        ttl_secs:            config.ttl.as_secs(),
        ttl_nanos:           config.ttl.subsec_nanos(),
        argv:                build_argv(&config)?,
        env:                 build_env(&config)?,
        max_open_files:      config.resource_limits.max_open_files,
        max_file_size_bytes: config.resource_limits.max_file_size_bytes,
        stack_size_bytes:    config.resource_limits.stack_size_bytes,
        cgroup_path:         cgroup_path.clone(),
        host_uid,
        host_gid,
    };

    // Step 6: request spawn. block_in_place avoids the 'static requirement of
    // spawn_blocking while still allowing the Tokio scheduler to run other tasks.
    let spawn_result = tokio::task::block_in_place(|| {
        fork_server.request_spawn(req, master_raw, slave_raw)
    })?;

    // Drop the slave fd in the parent. The child holds its own copy after clone3.
    // Keeping it open here would prevent EIO on the PTY master when the child exits.
    drop(pty.slave);

    let wall_start = Instant::now();

    // ── Confirm execve via error pipe ─────────────────────────────────────
    // The write end has O_CLOEXEC — if exec succeeded, the read end gets EOF.
    // If setup failed, we receive 5 bytes: stage + errno (LE i32).
    let err_pipe_rd_raw = spawn_result.err_pipe_rd.as_raw_fd();
    let mut err_buf = [0u8; 5];
    // SAFETY: err_pipe_rd is a valid open fd.
    let n = unsafe {
        libc::read(err_pipe_rd_raw, err_buf.as_mut_ptr() as *mut _, 5)
    };
    if n > 0 {
        // Child reported a setup error.
        let stage = ChildStage::from_u8(err_buf[0])
            .unwrap_or(ChildStage::Exec);
        let errno = i32::from_le_bytes(err_buf[1..5].try_into().unwrap_or([0; 4]));
        return Err(SandboxError::ChildSetupFailed { stage, errno });
    }
    // n == 0 → EOF → execve succeeded.

    // ── Wrap pidfd for async polling ─────────────────────────────────────
    let pidfd_raw = spawn_result.pidfd.as_raw_fd();

    // ── Set stderr pipe read end non-blocking before handing to AsyncFd ──
    // SAFETY: F_SETFL with O_NONBLOCK on a valid fd is always safe.
    unsafe {
        let flags = libc::fcntl(spawn_result.stderr_pipe_rd.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(spawn_result.stderr_pipe_rd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    // ── Async I/O: PTY master + stderr pipe + TTL ─────────────────────────
    let ttl = config.ttl;
    let (stdout_bytes, stderr_bytes, timed_out) =
        collect_output(pty.master, spawn_result.stderr_pipe_rd, ttl).await?;

    let wall_time = wall_start.elapsed();

    // ── TTL path: kill cgroup ─────────────────────────────────────────────
    let termination_reason;
    let exit_code;

    if timed_out {
        cgroup.kill_all()?;
        // Wait for the pidfd to become readable (confirms all processes dead).
        wait_pidfd(pidfd_raw).await;
        termination_reason = TerminationReason::TimedOut;
        exit_code = -1;
    } else {
        // ── Normal exit path ──────────────────────────────────────────────
        // waitid(P_PIDFD) — race-free, no PID reuse risk.
        let (code, reason) = reap_child(spawn_result.child_pid, &cgroup)?;
        exit_code          = code;
        termination_reason = reason;
    }

    // ── Collect cgroup metrics (before rmdir) ─────────────────────────────
    let peak_memory_bytes = cgroup.peak_memory_bytes();
    let cpu_time_us       = cgroup.cpu_time_us();

    // CgroupGuard::drop() cleans up the directory.

    let seccomp_violation = match &termination_reason {
        TerminationReason::SeccompViolation(n) => Some(*n),
        _ => None,
    };

    Ok(ExecutionReport {
        exit_status: exit_code,
        termination_reason,
        stdout_bytes,
        stderr_bytes,
        wall_time,
        peak_memory_bytes,
        cpu_time_us,
        seccomp_violation,
    })
}

// ─── I/O collection ─────────────────────────────────────────────────────────

/// Read from the PTY master (stdout) and stderr pipe concurrently until both
/// reach EOF or the TTL expires. Returns (stdout_bytes, stderr_bytes, timed_out).
///
/// The PTY master must already be owned (and will be closed on return).
/// `stderr_rd` is the read end of the child's stderr pipe, already set O_NONBLOCK.
async fn collect_output(
    master: OwnedFd,
    stderr_rd: OwnedFd,
    ttl: std::time::Duration,
) -> Result<(Vec<u8>, Vec<u8>, bool), SandboxError> {
    use tokio::io::unix::AsyncFd;
    use tokio::time::timeout;

    let async_master = AsyncFd::new(master)
        .map_err(SandboxError::IpcError)?;
    let async_stderr = AsyncFd::new(stderr_rd)
        .map_err(SandboxError::IpcError)?;

    let mut stdout_buf  = Vec::new();
    let mut stderr_buf  = Vec::new();
    // Separate read buffers: select! compiles both arms into scope simultaneously,
    // so sharing a single &mut buf would be a borrow conflict.
    let mut out_tmp = [0u8; 4096];
    let mut err_tmp = [0u8; 4096];

    let mut stdout_done = false;
    let mut stderr_done = false;

    let result = timeout(ttl, async {
        loop {
            if stdout_done && stderr_done {
                break Ok::<(), SandboxError>(());
            }

            tokio::select! {
                biased;

                guard = async_master.readable(), if !stdout_done => {
                    let mut guard = guard.map_err(SandboxError::IpcError)?;
                    match guard.try_io(|fd| {
                        let n = unsafe {
                            libc::read(fd.as_raw_fd(), out_tmp.as_mut_ptr() as *mut _, out_tmp.len())
                        };
                        if n < 0 {
                            let e = Errno::last();
                            // EIO on PTY master: slave side closed (child exited).
                            if e == Errno::EIO {
                                return Ok(0usize);
                            }
                            return Err(std::io::Error::from_raw_os_error(e as i32));
                        }
                        Ok(n as usize)
                    }) {
                        Ok(Ok(0)) => { stdout_done = true; }
                        Ok(Ok(n)) => { stdout_buf.extend_from_slice(&out_tmp[..n]); }
                        Ok(Err(e)) => { return Err(SandboxError::IpcError(e)); }
                        Err(_would_block) => {}
                    }
                }

                guard = async_stderr.readable(), if !stderr_done => {
                    let mut guard = guard.map_err(SandboxError::IpcError)?;
                    match guard.try_io(|fd| {
                        let n = unsafe {
                            libc::read(fd.as_raw_fd(), err_tmp.as_mut_ptr() as *mut _, err_tmp.len())
                        };
                        if n < 0 {
                            let e = Errno::last();
                            if e == Errno::EWOULDBLOCK || e == Errno::EAGAIN {
                                return Err(std::io::Error::from_raw_os_error(libc::EWOULDBLOCK));
                            }
                            return Err(std::io::Error::from_raw_os_error(e as i32));
                        }
                        Ok(n as usize)
                    }) {
                        Ok(Ok(0)) => { stderr_done = true; }
                        Ok(Ok(n)) => { stderr_buf.extend_from_slice(&err_tmp[..n]); }
                        Ok(Err(e)) => { return Err(SandboxError::IpcError(e)); }
                        Err(_would_block) => {}
                    }
                }
            }
        }
    })
    .await;

    let timed_out = result.is_err();
    Ok((stdout_buf, stderr_buf, timed_out))
}

// ─── Child reaping ──────────────────────────────────────────────────────────

fn reap_child(
    pid: libc::pid_t,
    cgroup: &CgroupGuard,
) -> Result<(i32, TerminationReason), SandboxError> {
    // Poll/wait for the status file to be written. The pidfd becoming readable
    // means the process has exited, but we give the fork server signal handler
    // up to 1 second to write the status file.
    let status_path = format!("/tmp/sandbox-status-{}", pid);
    let mut status_str = None;
    for _ in 0..100 {
        if let Ok(s) = std::fs::read_to_string(&status_path) {
            status_str = Some(s);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let status: i32 = match status_str {
        Some(s) => s.trim().parse().map_err(|_| SandboxError::WaitFailed(Errno::last()))?,
        None => return Err(SandboxError::WaitFailed(Errno::last())),
    };

    let _ = std::fs::remove_file(&status_path);

    // Check OOM first (authoritative; may accompany a signal).
    if cgroup.oom_kill_count() > 0 {
        return Ok((-1, TerminationReason::OomKilled));
    }

    let is_exited = (status & 0x7f) == 0;
    let (code, reason) = if is_exited {
        let exit_code = (status >> 8) & 0xff;
        (exit_code, TerminationReason::Exited(exit_code))
    } else {
        let sig = status & 0x7f;
        if sig == libc::SIGSYS {
            (sig, TerminationReason::SeccompViolation(0))
        } else {
            (sig, TerminationReason::SignalKilled(sig))
        }
    };

    Ok((code, reason))
}

/// Wait for a pidfd to become readable (blocking poll).
/// Used after cgroup.kill to confirm all processes are dead.
async fn wait_pidfd(pidfd: RawFd) {
    use tokio::io::unix::AsyncFd;
    use std::os::fd::BorrowedFd;

    // SAFETY: pidfd is a valid open file descriptor that outlives this function.
    // BorrowedFd does not close the fd when dropped; ownership stays with the caller.
    let borrowed = unsafe { BorrowedFd::borrow_raw(pidfd) };
    if let Ok(async_fd) = AsyncFd::new(borrowed) {
        let _ = async_fd.readable().await;
    }
}


// ─── Argv / env builders ────────────────────────────────────────────────────

fn build_argv(config: &SandboxConfig) -> Result<Vec<std::ffi::CString>, SandboxError> {
    config
        .argv
        .iter()
        .map(|s| {
            std::ffi::CString::new(s.as_bytes())
                .map_err(|_| SandboxError::ConfigInvalid("argv contains null byte"))
        })
        .collect()
}

fn build_env(config: &SandboxConfig) -> Result<Vec<std::ffi::CString>, SandboxError> {
    config
        .env
        .iter()
        .map(|(k, v)| {
            std::ffi::CString::new(format!("{k}={v}").as_bytes())
                .map_err(|_| SandboxError::ConfigInvalid("env key or value contains null byte"))
        })
        .collect()
}
