//! Seccomp-BPF filter construction using raw kernel interfaces.
//!
//! Policy:
//!   Default action  → SECCOMP_RET_ERRNO(EPERM)   (deny, observable in report)
//!   Danger list     → SECCOMP_RET_KILL_PROCESS    (hard kill, no recovery)
//!   socket(non-UNIX)→ SECCOMP_RET_ERRNO(EACCES)   (argument-level filter)
//!   clone(NEWUSER)  → SECCOMP_RET_ERRNO(EPERM)    (argument-level filter)
//!   ~115 allow-listed syscalls → SECCOMP_RET_ALLOW
//!
//! Written using raw sock_filter BPF instructions to avoid libseccomp's
//! incompatibilities in constrained environments (new user + pid namespaces
//! after pivot_root).
//!
//! PR_SET_NO_NEW_PRIVS must be called BEFORE this function; it is a
//! precondition for unprivileged seccomp(2) and is enforced in namespace.rs.

use nix::errno::Errno;
use crate::error::SandboxError;

// ─── BPF instruction constants ───────────────────────────────────────────────

const BPF_LD:  u16 = 0x00;
const BPF_W:   u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;
const BPF_K:   u16 = 0x00;
const BPF_RET: u16 = 0x06;

// ─── seccomp return values ────────────────────────────────────────────────────

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO:        u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW:        u32 = 0x7fff_0000;

// ─── seccomp_data field offsets (x86-64) ─────────────────────────────────────

const OFF_NR:   u32 = 0;   // int nr (syscall number)
const OFF_ARCH: u32 = 4;   // __u32 arch
const OFF_ARG0: u32 = 16;  // __u64 args[0] low 32 bits

// ─── Architecture audit value ─────────────────────────────────────────────────

// AUDIT_ARCH_X86_64 = 0xC000003E  (EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

// ─── BPF instruction builders ─────────────────────────────────────────────────

#[repr(C)]
struct SockFilter {
    code: u16,
    jt:   u8,
    jf:   u8,
    k:    u32,
}

#[repr(C)]
struct SockFprog {
    len:    u16,
    filter: *const SockFilter,
}

#[inline]
fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter { code, jt: 0, jf: 0, k }
}

#[inline]
fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

// ─── Syscall number helpers ───────────────────────────────────────────────────

fn syscall_nr(name: &str) -> Option<u32> {
    // Map syscall names to x86-64 numbers for the syscalls we need to handle
    // explicitly (kill list + argument-filtered syscalls).
    // The allow list is resolved via libc::SYS_* constants at compile time.
    match name {
        "ptrace"           => Some(libc::SYS_ptrace as u32),
        "process_vm_readv" => Some(libc::SYS_process_vm_readv as u32),
        "process_vm_writev"=> Some(libc::SYS_process_vm_writev as u32),
        "kexec_load"       => Some(libc::SYS_kexec_load as u32),
        "kexec_file_load"  => Some(libc::SYS_kexec_file_load as u32),
        _                  => None,
    }
}

// ─── Filter construction ──────────────────────────────────────────────────────

pub(crate) fn load_filter() -> Result<(), SandboxError> {
    let mut insns: Vec<SockFilter> = Vec::with_capacity(512);

    // Validate architecture to prevent cross-architecture exploits.
    // If arch != AUDIT_ARCH_X86_64, kill the process.
    insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH));
    insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    insns.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // Load syscall number into accumulator (remains loaded for all equality checks).
    insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR));

    // ── Kill list (SECCOMP_RET_KILL_PROCESS) ──────────────────────────────────
    for name in KILL_SYSCALLS {
        if let Some(nr) = syscall_nr(name) {
            // If equal: jump 0 (execute KILL_PROCESS), else jump 1 (skip KILL_PROCESS)
            insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
            insns.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
        }
    }

    // ── socket(): allow AF_UNIX (1) only, deny all other domains ──────────────
    // Structure:
    //   JEQ socket_nr → fall_through (it IS socket)
    //   JMP skip_socket_filter (it is NOT socket)
    //   load arg0 (domain)
    //   JEQ AF_UNIX → allow_socket
    //   RET ERRNO(EACCES)  ← non-AF_UNIX: denied
    //   allow_socket: reload syscall nr (clobbered by arg0 load)
    //   JMP to_allow_list
    {
        let socket_nr = libc::SYS_socket as u32;
        // Instructions at offsets relative to this JEQ:
        // +0: JEQ socket_nr → +1 (is socket), else +skip_count
        // +1 (is socket): load arg0
        // +2: JEQ AF_UNIX → +2 (allow), else +0 (EACCES)
        // +3: EACCES
        // +4 (allow): reload syscall nr
        // +5: fall through to allow list (socket IS in ALLOWED_SYSCALLS so it gets allowed there)
        // skip_count for "not socket": must skip instructions 1..5 = 5 instructions
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, socket_nr, 0, 4));
        // Is socket — check arg0
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0));
        // AF_UNIX = 1
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, libc::AF_UNIX as u32, 1, 0));
        // Not AF_UNIX
        insns.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (libc::EACCES as u32 & 0xFFFF)));
        // Is AF_UNIX: reload syscall number and fall through to allow list
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR));
    }

    // ── clone(): block CLONE_NEWUSER flag ──────────────────────────────────────
    // Allow clone() without CLONE_NEWUSER; block with CLONE_NEWUSER.
    {
        const CLONE_NEWUSER: u32 = 0x1000_0000;
        let clone_nr = libc::SYS_clone as u32;
        // +0: JEQ clone_nr → +1 (is clone), else +5 (skip)
        // +1 (is clone): load arg0 (flags)
        // +2: JSET CLONE_NEWUSER → +0 (deny), else +1 (allow fall-through)
        // +3: EPERM (has CLONE_NEWUSER)
        // +4: reload syscall nr, fall through to allow list
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, clone_nr, 0, 4));
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0));
        // JSET: if (arg0 & CLONE_NEWUSER) != 0, jump 0 (deny), else jump 1 (skip deny)
        insns.push(jump(BPF_JMP | BPF_JSET | BPF_K, CLONE_NEWUSER, 0, 1));
        // CLONE_NEWUSER present — deny
        insns.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32 & 0xFFFF)));
        // No CLONE_NEWUSER — reload syscall nr and fall through to allow list
        insns.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR));
    }

    // ── clone3(): block entirely and return ENOSYS ──────────────────────────────
    // This forces dynamic linkers and standard libraries to fall back to the
    // classic clone() call, where our flag-level checks actually work.
    {
        let clone3_nr = libc::SYS_clone3 as u32;
        // +0: JEQ clone3_nr → +1 (is clone3), else +1 (skip)
        // +1 (is clone3): return ENOSYS
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, clone3_nr, 0, 1));
        insns.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (libc::ENOSYS as u32 & 0xFFFF)));
    }

    // ── Allow list (~115 syscalls) ─────────────────────────────────────────────
    // For each allowed syscall: check equality, if match ALLOW, else continue.
    for &nr in ALLOWED_SYSCALL_NRS {
        insns.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
        insns.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }

    // ── Default deny ──────────────────────────────────────────────────────────
    insns.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32 & 0xFFFF)));

    // ── Load into kernel ──────────────────────────────────────────────────────
    let prog = SockFprog {
        len:    insns.len() as u16,
        filter: insns.as_ptr(),
    };

    // SAFETY: SYS_seccomp with SECCOMP_SET_MODE_FILTER=1 and a valid prog pointer.
    // PR_SET_NO_NEW_PRIVS has already been set; this call only restricts the process.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            1u64,  // SECCOMP_SET_MODE_FILTER
            0u64,  // no flags
            &prog as *const SockFprog as *const libc::c_void,
        )
    };

    if ret != 0 {
        return Err(SandboxError::SeccompLoadFailed(Errno::last()));
    }

    Ok(())
}

// ─── Syscall lists ──────────────────────────────────────────────────────────

const KILL_SYSCALLS: &[&str] = &[
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "kexec_load",
    "kexec_file_load",
];

/// Allow-listed syscall numbers for x86-64.
/// Covers Python 3, Node.js 20, Go, Rust, C/C++ programs.
const ALLOWED_SYSCALL_NRS: &[u32] = &[
    // Process lifecycle
    libc::SYS_execve       as u32,
    libc::SYS_execveat     as u32,
    libc::SYS_exit         as u32,
    libc::SYS_exit_group   as u32,
    libc::SYS_getpid       as u32,
    libc::SYS_getppid      as u32,
    libc::SYS_gettid       as u32,
    libc::SYS_set_tid_address as u32,
    libc::SYS_arch_prctl   as u32,

    // Memory management
    libc::SYS_brk          as u32,
    libc::SYS_mmap         as u32,
    libc::SYS_munmap       as u32,
    libc::SYS_mprotect     as u32,
    libc::SYS_mremap       as u32,
    libc::SYS_madvise      as u32,
    libc::SYS_msync        as u32,
    libc::SYS_mincore      as u32,
    libc::SYS_mlock        as u32,
    libc::SYS_munlock      as u32,

    // Basic file I/O
    libc::SYS_read         as u32,
    libc::SYS_write        as u32,
    libc::SYS_readv        as u32,
    libc::SYS_writev       as u32,
    libc::SYS_pread64      as u32,
    libc::SYS_pwrite64     as u32,
    libc::SYS_open         as u32,
    libc::SYS_openat       as u32,
    libc::SYS_creat        as u32,
    libc::SYS_close        as u32,
    libc::SYS_close_range  as u32,
    libc::SYS_lseek        as u32,

    // File metadata
    libc::SYS_stat         as u32,
    libc::SYS_fstat        as u32,
    libc::SYS_lstat        as u32,
    libc::SYS_newfstatat   as u32,
    libc::SYS_statx        as u32,
    libc::SYS_access       as u32,
    libc::SYS_faccessat    as u32,
    libc::SYS_faccessat2   as u32,
    libc::SYS_readlink     as u32,
    libc::SYS_readlinkat   as u32,
    libc::SYS_statfs       as u32,
    libc::SYS_fstatfs      as u32,

    // File descriptors
    libc::SYS_dup          as u32,
    libc::SYS_dup2         as u32,
    libc::SYS_dup3         as u32,
    libc::SYS_pipe         as u32,
    libc::SYS_pipe2        as u32,
    libc::SYS_fcntl        as u32,
    libc::SYS_ioctl        as u32,

    // Directory & filesystem ops
    libc::SYS_getdents     as u32,
    libc::SYS_getdents64   as u32,
    libc::SYS_chdir        as u32,
    libc::SYS_fchdir       as u32,
    libc::SYS_getcwd       as u32,
    libc::SYS_mkdir        as u32,
    libc::SYS_mkdirat      as u32,
    libc::SYS_rmdir        as u32,
    libc::SYS_rename       as u32,
    libc::SYS_renameat     as u32,
    libc::SYS_renameat2    as u32,
    libc::SYS_unlink       as u32,
    libc::SYS_unlinkat     as u32,
    libc::SYS_symlink      as u32,
    libc::SYS_symlinkat    as u32,
    libc::SYS_link         as u32,
    libc::SYS_linkat       as u32,
    libc::SYS_chmod        as u32,
    libc::SYS_fchmod       as u32,
    libc::SYS_fchmodat     as u32,
    libc::SYS_chown        as u32,
    libc::SYS_fchown       as u32,
    libc::SYS_lchown       as u32,
    libc::SYS_fchownat     as u32,
    libc::SYS_utime        as u32,
    libc::SYS_utimes       as u32,
    libc::SYS_futimesat    as u32,
    libc::SYS_utimensat    as u32,
    libc::SYS_truncate     as u32,
    libc::SYS_ftruncate    as u32,
    libc::SYS_sendfile     as u32,
    libc::SYS_fallocate    as u32,
    libc::SYS_flock        as u32,
    libc::SYS_fsync        as u32,
    libc::SYS_fdatasync    as u32,

    // Signals
    libc::SYS_rt_sigaction    as u32,
    libc::SYS_rt_sigprocmask  as u32,
    libc::SYS_rt_sigreturn    as u32,
    libc::SYS_rt_sigtimedwait as u32,
    libc::SYS_rt_sigpending   as u32,
    libc::SYS_sigaltstack     as u32,
    libc::SYS_kill            as u32,
    libc::SYS_tgkill          as u32,
    libc::SYS_tkill           as u32,

    // Threading & sync
    libc::SYS_clone           as u32,
    libc::SYS_futex           as u32,
    libc::SYS_futex_waitv     as u32,
    libc::SYS_get_robust_list as u32,
    libc::SYS_set_robust_list as u32,

    // Time
    libc::SYS_nanosleep        as u32,
    libc::SYS_clock_nanosleep  as u32,
    libc::SYS_clock_gettime    as u32,
    libc::SYS_clock_getres     as u32,
    libc::SYS_gettimeofday     as u32,
    libc::SYS_time             as u32,
    libc::SYS_times            as u32,
    libc::SYS_setitimer        as u32,
    libc::SYS_getitimer        as u32,
    libc::SYS_alarm            as u32,

    // I/O multiplexing
    libc::SYS_select           as u32,
    libc::SYS_pselect6         as u32,
    libc::SYS_poll             as u32,
    libc::SYS_ppoll            as u32,
    libc::SYS_epoll_create     as u32,
    libc::SYS_epoll_create1    as u32,
    libc::SYS_epoll_ctl        as u32,
    libc::SYS_epoll_wait       as u32,
    libc::SYS_epoll_pwait      as u32,
    libc::SYS_epoll_pwait2     as u32,

    // Wait
    libc::SYS_wait4            as u32,
    libc::SYS_waitid           as u32,

    // Networking (socket arg-filtered above; these work on AF_UNIX fds)
    libc::SYS_socket           as u32,
    libc::SYS_bind             as u32,
    libc::SYS_connect          as u32,
    libc::SYS_listen           as u32,
    libc::SYS_accept           as u32,
    libc::SYS_accept4          as u32,
    // send/recv don't exist as syscalls on x86-64; use sendto/recvfrom with NULL addr.
    libc::SYS_sendto           as u32,
    libc::SYS_recvfrom         as u32,
    libc::SYS_sendmsg          as u32,
    libc::SYS_recvmsg          as u32,
    libc::SYS_sendmmsg         as u32,
    libc::SYS_recvmmsg         as u32,
    libc::SYS_shutdown         as u32,
    libc::SYS_getsockname      as u32,
    libc::SYS_getpeername      as u32,
    libc::SYS_getsockopt       as u32,
    libc::SYS_setsockopt       as u32,
    libc::SYS_socketpair       as u32,

    // Identity (read-only)
    libc::SYS_getuid           as u32,
    libc::SYS_getgid           as u32,
    libc::SYS_geteuid          as u32,
    libc::SYS_getegid          as u32,
    libc::SYS_getgroups        as u32,
    libc::SYS_getpgrp          as u32,
    libc::SYS_getpgid          as u32,
    libc::SYS_getsid           as u32,

    // Resource limits
    libc::SYS_getrlimit        as u32,
    libc::SYS_prlimit64        as u32,
    libc::SYS_setrlimit        as u32,
    libc::SYS_getrusage        as u32,

    // Scheduling
    libc::SYS_sched_yield              as u32,
    libc::SYS_sched_getaffinity        as u32,
    libc::SYS_sched_getscheduler       as u32,
    libc::SYS_sched_get_priority_max   as u32,
    libc::SYS_sched_get_priority_min   as u32,
    libc::SYS_getpriority              as u32,

    // Misc
    libc::SYS_uname            as u32,
    libc::SYS_getrandom        as u32,
    libc::SYS_memfd_create     as u32,
    libc::SYS_eventfd          as u32,
    libc::SYS_eventfd2         as u32,
    libc::SYS_timerfd_create   as u32,
    libc::SYS_timerfd_settime  as u32,
    libc::SYS_timerfd_gettime  as u32,
    libc::SYS_inotify_init1    as u32,
    libc::SYS_inotify_add_watch as u32,
    libc::SYS_inotify_rm_watch as u32,
    libc::SYS_sysinfo          as u32,
    libc::SYS_prctl            as u32,
    libc::SYS_seccomp          as u32,  // allow self-restriction (more restrictive filters)
];
