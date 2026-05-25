use std::time::Duration;

/// Complete report returned after a sandboxed process finishes or is terminated.
#[derive(Debug)]
pub struct ExecutionReport {
    /// Raw exit code (meaningful only when `termination_reason` is `Exited`).
    pub exit_status: i32,

    /// The authoritative reason the process stopped.
    pub termination_reason: TerminationReason,

    /// All output from the PTY master (stdin echo + stdout of the process).
    /// Stderr is captured separately via the anonymous pipe.
    pub stdout_bytes: Vec<u8>,

    /// Stderr captured from the anonymous pipe (independent stream from stdout).
    pub stderr_bytes: Vec<u8>,

    /// Elapsed wall time from spawn request to pidfd becoming readable.
    pub wall_time: Duration,

    /// Peak RSS in bytes, read from `memory.peak` in the cgroup after exit.
    pub peak_memory_bytes: u64,

    /// Total CPU time in microseconds, read from `cpu.stat` (usage_usec) after exit.
    pub cpu_time_us: u64,

    /// Syscall number that triggered a `SCMP_ACT_KILL_PROCESS` seccomp action,
    /// extracted from `si_syscall` in the SIGSYS siginfo. None if not killed by seccomp.
    pub seccomp_violation: Option<u32>,
}

/// Authoritative reason a sandboxed process stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminationReason {
    /// Process called exit(2) or _exit(2) with the given code.
    Exited(i32),
    /// TTL expired; cgroup.kill was written to terminate all processes atomically.
    TimedOut,
    /// The kernel OOM killer fired; `memory.events` reported `oom_kill > 0`.
    OomKilled,
    /// Killed by a `SCMP_ACT_KILL_PROCESS` seccomp rule; field is the syscall number.
    SeccompViolation(u32),
    /// Killed by an unexpected signal (e.g. SIGSEGV, SIGBUS); field is the signal number.
    SignalKilled(i32),
    /// TTL expired and cgroup.kill was used as the termination mechanism.
    /// Distinct from TimedOut only for diagnostic purposes (same cause, confirmed path).
    CgroupKillFallback,
}
