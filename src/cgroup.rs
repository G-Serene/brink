//! cgroup v2 lifecycle management.
//!
//! Creates an ephemeral child directory under `cgroup_parent`, writes all
//! resource limits before the child process is spawned, and removes the
//! directory on drop — even if the containing future is cancelled.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use crate::config::SandboxConfig;
use crate::error::SandboxError;

/// RAII guard for an ephemeral cgroup v2 directory.
/// Dropping this removes the directory (after the cgroup is empty).
pub(crate) struct CgroupGuard {
    path: PathBuf,
}

impl CgroupGuard {
    /// Verify delegation and create the ephemeral cgroup slice.
    /// Writes all resource limits before returning.
    pub(crate) fn create(config: &SandboxConfig) -> Result<Self, SandboxError> {
        // Validate delegation: the parent directory must be writable.
        check_delegation(&config.cgroup_parent)?;

        // The parent's subtree_control must enable memory, cpu, pids before we
        // can create a child that uses them.  Write it here; a second identical
        // write is a no-op, so this is idempotent.
        write_cgroup_file(
            &config.cgroup_parent.join("cgroup.subtree_control"),
            "+memory +cpu +pids",
        )
        .map_err(|source| SandboxError::CgroupWriteFailed {
            path: "cgroup.subtree_control",
            source,
        })?;

        // Create a uniquely named child directory.
        let id = unique_id();
        let path = config.cgroup_parent.join(format!("sandbox-{id}"));
        fs::create_dir(&path).map_err(SandboxError::CgroupCreateFailed)?;

        let guard = Self { path };

        // Write limits.  All writes happen before clone() is called.
        guard.write("memory.max",      &config.memory_max_bytes.to_string())?;
        guard.write("memory.swap.max", "0")?;
        guard.write(
            "cpu.max",
            &format!("{} {}", config.cpu_quota_us, config.cpu_period_us),
        )?;
        guard.write("pids.max", &config.pids_max.to_string())?;

        Ok(guard)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Atomically kill every process in the cgroup hierarchy.
    pub(crate) fn kill_all(&self) -> Result<(), SandboxError> {
        self.write("cgroup.kill", "1")
    }

    /// Read `memory.peak` after the child has exited.
    pub(crate) fn peak_memory_bytes(&self) -> u64 {
        read_u64_file(self.path.join("memory.peak"))
    }

    /// Read `usage_usec` from `cpu.stat` after the child has exited.
    pub(crate) fn cpu_time_us(&self) -> u64 {
        let content = fs::read_to_string(self.path.join("cpu.stat")).unwrap_or_default();
        parse_cpu_stat(&content)
    }

    /// Read `oom_kill` counter from `memory.events`.
    pub(crate) fn oom_kill_count(&self) -> u64 {
        let content = fs::read_to_string(self.path.join("memory.events")).unwrap_or_default();
        parse_named_u64(&content, "oom_kill")
    }

    /// Read current PID count. Used to poll until the cgroup is empty before rmdir.
    pub(crate) fn current_pids(&self) -> u64 {
        read_u64_file(self.path.join("pids.current"))
    }

    fn write(&self, filename: &'static str, value: &str) -> Result<(), SandboxError> {
        let p = self.path.join(filename);
        write_cgroup_file(&p, value).map_err(|source| SandboxError::CgroupWriteFailed {
            path: filename,
            source,
        })
    }
}

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        // Poll until pids.current == 0; the kernel rejects rmdir on a non-empty cgroup.
        // We give it up to 5 seconds in 10ms steps. In practice the cgroup is already
        // empty because cgroup.kill has been written before this drop runs.
        for _ in 0..500 {
            if self.current_pids() == 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let _ = fs::remove_dir(&self.path);
    }
}

// ─── Delegation check ───────────────────────────────────────────────────────

fn check_delegation(parent: &Path) -> Result<(), SandboxError> {
    // The cgroup_parent directory must exist and be writable.
    // Attempting to create a file is the most reliable cross-kernel check.
    let probe = parent.join("cgroup.subtree_control");
    if !probe.exists() {
        return Err(SandboxError::CgroupDelegationMissing);
    }
    // Try opening for write to confirm we have permission.
    match fs::OpenOptions::new().write(true).open(&probe) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            Err(SandboxError::CgroupDelegationMissing)
        }
        Err(e) => Err(SandboxError::CgroupCreateFailed(e)),
    }
}

// ─── Low-level helpers ──────────────────────────────────────────────────────

fn write_cgroup_file(path: &Path, value: &str) -> Result<(), io::Error> {
    let mut f = fs::OpenOptions::new().write(true).open(path)?;
    f.write_all(value.as_bytes())?;
    Ok(())
}

fn read_u64_file(path: PathBuf) -> u64 {
    fs::read_to_string(path)
        .unwrap_or_default()
        .trim()
        .parse()
        .unwrap_or(0)
}

fn parse_named_u64(content: &str, key: &str) -> u64 {
    content
        .lines()
        .find_map(|line| {
            let mut parts = line.split_ascii_whitespace();
            if parts.next() == Some(key) {
                parts.next()?.parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

fn parse_cpu_stat(content: &str) -> u64 {
    parse_named_u64(content, "usage_usec")
}

fn unique_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Combine timestamp with PID for uniqueness within a process across rapid calls.
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    ts ^ (pid << 48)
}
