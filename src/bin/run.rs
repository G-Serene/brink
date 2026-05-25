//! `brink-run` — JSON-over-stdio wrapper for the brink sandbox library.
//!
//! Reads a JSON job spec from stdin, runs it in the sandbox, and writes a
//! JSON result to stdout. Errors are written to stderr and exit code is 1.
//!
//! This binary is the bridge between the Python agent and the Rust library.

use std::io::{self, Read};
use std::path::PathBuf;
use std::time::Duration;

use brink::{ExecutionReport, ResourceLimits, Runtime, SandboxConfig, TerminationReason};
use serde::{Deserialize, Serialize};

// ── Input ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Job {
    /// Command + args to run inside the sandbox. argv[0] must be absolute.
    argv: Vec<String>,

    /// Environment variables for the child. Host env is NOT inherited.
    #[serde(default)]
    env: Vec<(String, String)>,

    /// Absolute path to the host directory mounted as /workspace (read-write).
    workspace: String,

    /// Writable cgroup v2 parent (must have cpu/memory/pids delegated).
    cgroup_parent: String,

    /// Memory limit in MiB (e.g. 128 for 128 MiB).
    #[serde(default = "default_memory_mb")]
    memory_mb: u64,

    /// CPU percentage of one core to allow (1–100).
    #[serde(default = "default_cpu_pct")]
    cpu_pct: u64,

    /// Wall-clock timeout in seconds.
    #[serde(default = "default_timeout_secs")]
    timeout_secs: u64,

    /// Max PIDs in the cgroup (fork-bomb guard).
    #[serde(default = "default_pids_max")]
    pids_max: u32,

    /// Extra read-only bind mounts: [[host_path, sandbox_path], ...].
    #[serde(default)]
    extra_ro_mounts: Vec<(String, String)>,
}

fn default_memory_mb() -> u64 { 128 }
fn default_cpu_pct() -> u64 { 50 }
fn default_timeout_secs() -> u64 { 10 }
fn default_pids_max() -> u32 { 64 }

// ── Output ───────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct JobResult {
    exit_status: i32,
    stdout: String,
    stderr: String,
    wall_time_ms: u64,
    peak_memory_bytes: u64,
    cpu_time_us: u64,
    /// Human-readable termination reason: "exited(0)", "timed_out", etc.
    termination: String,
    /// Seccomp-blocked syscall number, if that was the kill reason.
    seccomp_violation: Option<u32>,
    ok: bool,
}

#[derive(Serialize)]
struct ErrorResult {
    ok: bool,
    error: String,
}

// ── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let mut raw = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut raw) {
        die(&format!("failed to read stdin: {e}"));
    }

    let job: Job = match serde_json::from_str(&raw) {
        Ok(j) => j,
        Err(e) => die(&format!("invalid JSON job: {e}")),
    };

    // Runtime::init() must be called before any Tokio runtime starts.
    let runtime = match Runtime::init() {
        Ok(r) => r,
        Err(e) => die(&format!("Runtime::init failed: {e}")),
    };

    let period_us = 100_000u64;
    let quota_us = (job.cpu_pct.clamp(1, 100) * period_us) / 100;

    let config = SandboxConfig {
        workspace_path:   PathBuf::from(&job.workspace),
        memory_max_bytes: job.memory_mb * 1024 * 1024,
        cpu_quota_us:     quota_us,
        cpu_period_us:    period_us,
        pids_max:         job.pids_max,
        ttl:              Duration::from_secs(job.timeout_secs),
        argv:             job.argv,
        env:              job.env,
        resource_limits:  ResourceLimits {
            max_open_files:      256,
            max_file_size_bytes: 64 * 1024 * 1024,
            stack_size_bytes:    8 * 1024 * 1024,
        },
        cgroup_parent:    PathBuf::from(&job.cgroup_parent),
        extra_ro_mounts:  job.extra_ro_mounts
            .into_iter()
            .map(|(h, s)| (PathBuf::from(h), PathBuf::from(s)))
            .collect(),
    };

    let tok = match tokio::runtime::Runtime::new() {
        Ok(t) => t,
        Err(e) => die(&format!("tokio runtime failed: {e}")),
    };

    let report: ExecutionReport = match tok.block_on(runtime.run(config)) {
        Ok(r) => r,
        Err(e) => die(&format!("sandbox run failed: {e}")),
    };

    let termination = termination_string(&report.termination_reason);
    let result = JobResult {
        exit_status:       report.exit_status,
        stdout:            String::from_utf8_lossy(&report.stdout_bytes).into_owned(),
        stderr:            String::from_utf8_lossy(&report.stderr_bytes).into_owned(),
        wall_time_ms:      report.wall_time.as_millis() as u64,
        peak_memory_bytes: report.peak_memory_bytes,
        cpu_time_us:       report.cpu_time_us,
        termination,
        seccomp_violation: report.seccomp_violation,
        ok:                true,
    };

    println!("{}", serde_json::to_string(&result).expect("serialize"));
}

fn termination_string(reason: &TerminationReason) -> String {
    match reason {
        TerminationReason::Exited(code)          => format!("exited({code})"),
        TerminationReason::TimedOut              => "timed_out".into(),
        TerminationReason::OomKilled             => "oom_killed".into(),
        TerminationReason::SeccompViolation(n)   => format!("seccomp_violation({n})"),
        TerminationReason::SignalKilled(sig)     => format!("signal_killed({sig})"),
        TerminationReason::CgroupKillFallback    => "cgroup_kill_fallback".into(),
    }
}

fn die(msg: &str) -> ! {
    let err = ErrorResult { ok: false, error: msg.to_string() };
    eprintln!("{}", serde_json::to_string(&err).unwrap_or_default());
    std::process::exit(1);
}
