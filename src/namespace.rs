//! Namespace creation (clone3) and child-side setup orchestration.
//!
//! `clone3_sandbox` is called from the fork server. It uses the raw clone3(2)
//! syscall because nix ≤ 0.29 does not wrap clone3, and we need CLONE_PIDFD
//! to get a race-free handle on the child.
//!
//! After clone3 returns in the child, `child_run` executes every sandboxing
//! step in sequence and then calls execve. It never returns normally.

use std::os::fd::{OwnedFd, RawFd, FromRawFd};
use std::path::Path;

use nix::errno::Errno;
use nix::sys::resource::{setrlimit, Resource};
use nix::unistd::dup2;

use crate::error::{ChildStage, SandboxError};
use crate::ipc::SpawnRequest;
use crate::mount::{MountContext, create_scratch_root};

/// clone3 flags combining all required namespaces.
const CLONE_FLAGS: u64 =
    libc::CLONE_NEWUSER  as u64 |
    libc::CLONE_NEWPID   as u64 |
    libc::CLONE_NEWNS    as u64 |
    libc::CLONE_NEWNET   as u64 |
    libc::CLONE_NEWUTS   as u64 |
    libc::CLONE_NEWIPC   as u64 |
    libc::CLONE_NEWCGROUP as u64 |
    libc::CLONE_PIDFD    as u64;

/// Kernel-ABI struct for clone3(2).
#[repr(C)]
struct CloneArgs {
    flags:        u64,
    pidfd:        u64,   // pointer to i32 storage for the pidfd
    child_tid:    u64,
    parent_tid:   u64,
    exit_signal:  u64,
    stack:        u64,
    stack_size:   u64,
    tls:          u64,
    set_tid:      u64,
    set_tid_size: u64,
    cgroup:       u64,
}

/// Result of a successful clone3 call (parent side only).
pub(crate) struct CloneResult {
    /// The child PID.
    pub child_pid: libc::pid_t,
    /// A pidfd for the child; closed when the OwnedFd is dropped.
    pub pidfd: OwnedFd,
}

/// Invoke clone3 with all namespace flags.
///
/// Returns `Ok(Some(result))` in the parent, `Ok(None)` in the child.
/// The child must call `child_run` immediately after this returns.
///
/// # Safety
/// The parent side is safe. The child side executes in a forked address
/// space; the caller must not use any Tokio handles or mutexes after this —
/// the fork server is single-threaded so there are no live locks to worry about.
pub(crate) unsafe fn clone3_sandbox() -> Result<Option<CloneResult>, Errno> {
    let mut pidfd_storage: i32 = -1;

    let args = CloneArgs {
        flags:        CLONE_FLAGS,
        pidfd:        &mut pidfd_storage as *mut i32 as u64,
        child_tid:    0,
        parent_tid:   0,
        exit_signal:  libc::SIGCHLD as u64,
        stack:        0,   // 0 = kernel allocates child stack (CoW of parent stack)
        stack_size:   0,
        tls:          0,
        set_tid:      0,
        set_tid_size: 0,
        cgroup:       0,
    };

    // SAFETY: args is correctly initialised; SYS_clone3 is valid on x86_64.
    let ret = libc::syscall(
        libc::SYS_clone3,
        &args as *const CloneArgs as libc::c_long,
        std::mem::size_of::<CloneArgs>() as libc::c_long,
    );

    if ret < 0 {
        return Err(Errno::last());
    }

    if ret == 0 {
        // We are in the child.
        return Ok(None);
    }

    // We are in the parent.
    let child_pid = ret as libc::pid_t;
    // SAFETY: pidfd_storage was written by the kernel on successful clone3.
    let pidfd = OwnedFd::from_raw_fd(pidfd_storage);
    Ok(Some(CloneResult { child_pid, pidfd }))
}

/// All data the child needs after clone3. Lives on the fork server stack;
/// the child inherits it via CoW after clone3.
pub(crate) struct ChildContext {
    pub req:            SpawnRequest,
    /// Read end of the eventfd; child blocks here until parent writes UID/GID maps.
    pub sync_read_fd:   RawFd,
    /// PTY slave fd (inherited, not opened by path inside the new namespace).
    pub slave_fd:       RawFd,
    /// Stderr pipe write end.
    pub stderr_write_fd: RawFd,
    /// Error pipe write end (O_CLOEXEC). Written on setup failure; closed on execve.
    pub err_pipe_write: RawFd,
}

/// Execute every sandboxing step and then execve. Never returns on success.
/// On failure, writes (stage, errno) to the error pipe and exits with code 1.
pub(crate) fn child_run(ctx: ChildContext) -> ! {
    if let Err((stage, errno)) = child_setup(&ctx) {
        report_child_error(ctx.err_pipe_write, stage, errno);
    }
    // Unreachable after execve or report_child_error.
    unsafe { libc::_exit(1) }
}

fn child_setup(ctx: &ChildContext) -> Result<(), (ChildStage, Errno)> {
    // Wait for fork server to finish writing uid_map and gid_map.
    wait_for_mapping(ctx.sync_read_fd)?;

    // Die if the fork server process dies.
    // SAFETY: PR_SET_PDEATHSIG is a harmless prctl; SIGKILL is a valid signal number.
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) };

    // Mount namespace setup.
    let new_root = match create_scratch_root() {
        Ok(p) => p,
        Err(_) => return Err((ChildStage::BuildRootfs, Errno::last())),
    };

    let mctx = MountContext {
        workspace_path:  &ctx.req.workspace_path,
        extra_ro_mounts: &ctx.req.extra_ro_mounts,
        new_root:        &new_root,
    };
    crate::mount::setup(&mctx)?;

    // Landlock (runs after pivot_root; paths are now relative to new root).
    crate::landlock::apply_ruleset(
        Path::new("/workspace"),
        &ctx.req.extra_ro_mounts,
    )
    .map_err(|_| (ChildStage::Landlock, Errno::last()))?;

    // Apply RLIMIT_ supplementary limits.
    apply_rlimits(&ctx.req).map_err(|e| (ChildStage::Exec, e))?;

    // Drop all capabilities.
    drop_capabilities().map_err(|e| (ChildStage::CapabilityDrop, e))?;

    // Attach PTY slave as stdin (0) and stdout (1).
    // stderr (2) is the anonymous pipe write end.
    dup2(ctx.slave_fd, 0)
        .map_err(|e| (ChildStage::PtySlaveSetup, e))?;
    dup2(ctx.slave_fd, 1)
        .map_err(|e| (ChildStage::PtySlaveSetup, e))?;
    dup2(ctx.stderr_write_fd, 2)
        .map_err(|e| (ChildStage::PtySlaveSetup, e))?;

    // Close all fds that are no longer needed. The error pipe write fd has
    // O_CLOEXEC and will be closed automatically on successful execve.
    // We manually close fds we explicitly opened.
    unsafe {
        libc::close(ctx.slave_fd);
        libc::close(ctx.stderr_write_fd);
        libc::close(ctx.sync_read_fd);
    }

    // PR_SET_NO_NEW_PRIVS — must precede seccomp load.
    // SAFETY: this prctl call only restricts privileges, never escalates.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err((ChildStage::NoNewPrivs, Errno::last()));
    }

    // PR_SET_DUMPABLE — prevent /proc/<pid>/mem reads by other processes.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };

    // Load seccomp-BPF filter.
    crate::seccomp::load_filter().map_err(|e| {
        // Preserve the errno captured at the point of failure inside load_filter().
        if let crate::error::SandboxError::SeccompLoadFailed(errno) = e {
            (ChildStage::Seccomp, errno)
        } else {
            (ChildStage::Seccomp, Errno::last())
        }
    })?;

    // execve — point of no return.
    exec_target(ctx)?;

    unreachable!("execve returned")
}

fn wait_for_mapping(eventfd: RawFd) -> Result<(), (ChildStage, Errno)> {
    let mut buf = [0u8; 8];
    // SAFETY: eventfd is valid; buf is large enough for the 8-byte counter.
    let n = unsafe { libc::read(eventfd, buf.as_mut_ptr() as *mut _, 8) };
    if n != 8 {
        return Err((ChildStage::WaitForMapping, Errno::last()));
    }
    Ok(())
}

fn apply_rlimits(req: &SpawnRequest) -> Result<(), Errno> {
    setrlimit(Resource::RLIMIT_NOFILE, req.max_open_files, req.max_open_files)?;
    setrlimit(Resource::RLIMIT_FSIZE, req.max_file_size_bytes, req.max_file_size_bytes)?;
    setrlimit(Resource::RLIMIT_STACK, req.stack_size_bytes, req.stack_size_bytes)?;
    Ok(())
}

fn drop_capabilities() -> Result<(), Errno> {
    // _LINUX_CAPABILITY_VERSION_3 — handles 64-bit capability sets.
    const _LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    #[repr(C)]
    struct CapHeader { version: u32, pid: i32 }
    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    struct CapData   { effective: u32, permitted: u32, inheritable: u32 }

    // Set SECBIT_NOROOT so setuid/setgid binaries cannot re-acquire caps.
    const SECBIT_NOROOT:         u64 = 1 << 2;
    const SECBIT_NOROOT_LOCKED:  u64 = 1 << 3;
    const SECBIT_NO_SETUID_FIXUP: u64 = 1 << 4;
    const SECBIT_NO_SETUID_FIXUP_LOCKED: u64 = 1 << 5;
    const SECBIT_KEEP_CAPS_LOCKED: u64 = 1 << 1;
    let secbits = SECBIT_NOROOT | SECBIT_NOROOT_LOCKED |
                  SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED |
                  SECBIT_KEEP_CAPS_LOCKED;

    // SAFETY: prctl with PR_SET_SECUREBITS and a valid secbits value.
    let ret = unsafe { libc::prctl(libc::PR_SET_SECUREBITS, secbits, 0, 0, 0) };
    if ret != 0 { return Err(Errno::last()); }

    // Drop all capability sets to zero.
    let header = CapHeader { version: _LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let data   = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2];

    // SAFETY: SYS_capset with a valid header and zeroed data array drops all caps.
    let ret = unsafe {
        libc::syscall(libc::SYS_capset, &header, data.as_ptr())
    };
    if ret != 0 { return Err(Errno::last()); }

    Ok(())
}

fn exec_target(ctx: &ChildContext) -> Result<(), (ChildStage, Errno)> {
    use nix::unistd::execve;

    let prog = ctx.req.argv[0].as_c_str();
    let argv: Vec<_> = ctx.req.argv.iter().map(|s| s.as_c_str()).collect();
    let env:  Vec<_> = ctx.req.env.iter().map(|s| s.as_c_str()).collect();

    execve(prog, &argv, &env).map_err(|e| (ChildStage::Exec, e))?;
    unreachable!()
}

/// Write (stage, errno) to the error pipe and exit. This function is called
/// before execve, so the write end still has O_CLOEXEC — it will be closed
/// if execve somehow succeeds after this path (it won't).
fn report_child_error(pipe_fd: RawFd, stage: ChildStage, errno: Errno) -> ! {
    let mut buf = [0u8; 5];
    buf[0] = stage as u8;
    buf[1..5].copy_from_slice(&(errno as i32).to_le_bytes());
    // SAFETY: pipe_fd is valid at this point; we exit immediately after.
    unsafe { libc::write(pipe_fd, buf.as_ptr() as *const _, 5) };
    unsafe { libc::_exit(1) }
}

/// Write UID and GID maps for the child user namespace.
/// Called from the fork server (parent) after clone3 returns.
/// Steps must happen in exact order: setgroups deny → uid_map → gid_map.
pub(crate) fn write_uid_gid_maps(
    child_pid: libc::pid_t,
    host_uid: u32,
    host_gid: u32,
) -> Result<(), SandboxError> {
    use std::fs;
    let proc_dir = format!("/proc/{child_pid}");

    // Step 1: deny setgroups so gid_map can be written without CAP_SETGID.
    let setgroups_path = format!("{proc_dir}/setgroups");
    fs::write(&setgroups_path, "deny")
        .map_err(|_| SandboxError::UserNamespaceSetupFailed(Errno::last()))?;

    // Step 2: uid_map — map uid 0 inside the ns to host_uid outside.
    let uid_map_path = format!("{proc_dir}/uid_map");
    fs::write(&uid_map_path, format!("0 {host_uid} 1\n"))
        .map_err(|_| SandboxError::UserNamespaceSetupFailed(Errno::last()))?;

    // Step 3: gid_map — map gid 0 inside the ns to host_gid outside.
    let gid_map_path = format!("{proc_dir}/gid_map");
    fs::write(&gid_map_path, format!("0 {host_gid} 1\n"))
        .map_err(|_| SandboxError::UserNamespaceSetupFailed(Errno::last()))?;

    Ok(())
}

