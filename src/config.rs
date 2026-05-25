use std::path::PathBuf;
use std::time::Duration;
use crate::error::SandboxError;

/// Complete configuration for one sandboxed execution.
pub struct SandboxConfig {
    /// The one directory mapped read-write inside the sandbox at `/workspace`.
    pub workspace_path: PathBuf,

    /// Hard memory ceiling (e.g. 512 * 1024 * 1024 for 512 MiB).
    pub memory_max_bytes: u64,

    /// CPU quota per period in microseconds.
    pub cpu_quota_us: u64,

    /// CPU period in microseconds (e.g. 100_000 = 100 ms).
    pub cpu_period_us: u64,

    /// Maximum number of PIDs in the cgroup (fork-bomb prevention).
    pub pids_max: u32,

    /// Wall-clock timeout; the cgroup is killed if the process runs longer.
    pub ttl: Duration,

    /// Command and arguments passed to execve inside the sandbox.
    /// argv[0] must be an absolute path accessible inside the sandbox rootfs.
    pub argv: Vec<String>,

    /// Explicit environment for the child. The host environment is NOT inherited.
    pub env: Vec<(String, String)>,

    /// Supplementary RLIMIT_ layer applied on top of cgroup limits.
    pub resource_limits: ResourceLimits,

    /// Writable path under /sys/fs/cgroup/ that this process owns via
    /// cgroup v2 delegation (e.g. from systemd `Delegate=yes`).
    /// The library creates and destroys an ephemeral child directory here.
    ///
    /// Example: `/sys/fs/cgroup/user.slice/user-1000.slice/app.slice`
    pub cgroup_parent: PathBuf,

    /// Additional read-only bind mounts: `(host_absolute_path, sandbox_absolute_path)`.
    ///
    /// Use to supply language runtimes or shared libraries without embedding them
    /// in the workspace. Each sandbox_path is created as a directory in the rootfs
    /// before `pivot_root`. Landlock grants `READ_FILE | READ_DIR` for each path.
    pub extra_ro_mounts: Vec<(PathBuf, PathBuf)>,
}

/// Supplementary per-process resource limits (RLIMIT_ layer).
pub struct ResourceLimits {
    pub max_open_files: u64,
    pub max_file_size_bytes: u64,
    pub stack_size_bytes: u64,
}

impl SandboxConfig {
    pub(crate) fn validate(&self) -> Result<(), SandboxError> {
        if self.argv.is_empty() {
            return Err(SandboxError::ConfigInvalid("argv must not be empty"));
        }
        if self.cpu_period_us == 0 {
            return Err(SandboxError::ConfigInvalid("cpu_period_us must be non-zero"));
        }
        if self.cpu_quota_us == 0 {
            return Err(SandboxError::ConfigInvalid("cpu_quota_us must be non-zero"));
        }
        if self.cpu_quota_us > self.cpu_period_us {
            return Err(SandboxError::ConfigInvalid(
                "cpu_quota_us must not exceed cpu_period_us (that would mean >100% of one CPU)",
            ));
        }
        if self.memory_max_bytes == 0 {
            return Err(SandboxError::ConfigInvalid("memory_max_bytes must be non-zero"));
        }
        if self.pids_max == 0 {
            return Err(SandboxError::ConfigInvalid("pids_max must be non-zero"));
        }
        if self.ttl.is_zero() {
            return Err(SandboxError::ConfigInvalid("ttl must be non-zero"));
        }
        if !self.workspace_path.is_absolute() {
            return Err(SandboxError::ConfigInvalid("workspace_path must be absolute"));
        }
        if !self.cgroup_parent.is_absolute() {
            return Err(SandboxError::ConfigInvalid("cgroup_parent must be absolute"));
        }
        for (host, sandbox) in &self.extra_ro_mounts {
            if !host.is_absolute() {
                return Err(SandboxError::ConfigInvalid(
                    "extra_ro_mounts: host path must be absolute",
                ));
            }
            if !sandbox.is_absolute() {
                return Err(SandboxError::ConfigInvalid(
                    "extra_ro_mounts: sandbox path must be absolute",
                ));
            }
        }
        if self.resource_limits.stack_size_bytes == 0 {
            return Err(SandboxError::ConfigInvalid("stack_size_bytes must be non-zero"));
        }
        Ok(())
    }
}
