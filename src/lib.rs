#![cfg_attr(
    not(target_os = "linux"),
    compile_error!("brink only supports Linux (x86_64-unknown-linux-gnu)")
)]

//! `brink` — defense-in-depth Linux process sandbox.
//!
//! # Security layers (outermost → innermost)
//!
//! | Layer | Mechanism |
//! |---|---|
//! | 0 | cgroup v2 — memory, CPU, PID limits |
//! | 1 | User namespace + UID/GID mapping |
//! | 2 | Mount namespace + pivot_root |
//! | 3 | Landlock LSM (filesystem allow-list) |
//! | 4 | Capability drop |
//! | 5 | Seccomp-BPF (~115-syscall allow-list + hard-kill list) |
//!
//! # Usage
//!
//! ```rust,no_run
//! use brink::{Runtime, SandboxConfig, ResourceLimits};
//! use std::path::PathBuf;
//! use std::time::Duration;
//!
//! fn main() {
//!     // Must be called BEFORE tokio::main; forking inside a running Tokio
//!     // runtime is undefined behaviour.
//!     let runtime = Runtime::init().expect("sandbox runtime init failed");
//!
//!     tokio::runtime::Runtime::new().unwrap().block_on(async move {
//!         let config = SandboxConfig {
//!             workspace_path:      PathBuf::from("/tmp/my-workspace"),
//!             memory_max_bytes:    512 * 1024 * 1024,
//!             cpu_quota_us:        50_000,
//!             cpu_period_us:       100_000,
//!             pids_max:            64,
//!             ttl:                 Duration::from_secs(10),
//!             argv:                vec!["/workspace/my-binary".to_string()],
//!             env:                 vec![("PATH".to_string(), "/workspace/bin".to_string())],
//!             resource_limits:     ResourceLimits {
//!                 max_open_files:      256,
//!                 max_file_size_bytes: 64 * 1024 * 1024,
//!                 stack_size_bytes:    8  * 1024 * 1024,
//!             },
//!             cgroup_parent:       PathBuf::from("/sys/fs/cgroup/user.slice/user-1000.slice"),
//!             extra_ro_mounts:     vec![],
//!         };
//!
//!         let report = runtime.run(config).await.unwrap();
//!         println!("exit: {:?}", report.termination_reason);
//!     });
//! }
//! ```

mod cgroup;
mod config;
mod error;
mod fork_server;
mod ipc;
mod landlock;
mod mount;
mod namespace;
mod pty;
mod report;
mod seccomp;
mod supervisor;

pub use config::{ResourceLimits, SandboxConfig};
pub use error::SandboxError;
pub use report::{ExecutionReport, TerminationReason};

use fork_server::ForkServer;

/// Handle to the sandbox runtime. Owns the fork server subprocess for its lifetime.
///
/// **Must be created before starting the Tokio runtime** — call `Runtime::init()`
/// at the top of `fn main()`, before `#[tokio::main]` or `tokio::runtime::Runtime::new()`.
///
/// Forking inside a live Tokio multi-threaded runtime is undefined behaviour:
/// the child inherits Tokio's internal state (thread pool mutexes, epoll fd,
/// timers) which may be in a locked or inconsistent state.
pub struct Runtime {
    fork_server: ForkServer,
}

impl Runtime {
    /// Spawn the fork server process and return a handle.
    ///
    /// Errors if the fork fails or the socket pair cannot be created.
    pub fn init() -> Result<Self, SandboxError> {
        let fork_server = ForkServer::spawn()?;
        Ok(Self { fork_server })
    }

    /// Execute a sandboxed process and return a complete report.
    ///
    /// Concurrent calls are serialised through the fork server queue.
    /// The future is cancel-safe: if dropped, the cgroup kill guard
    /// ensures the child is terminated on the next GC cycle.
    pub async fn run(&self, config: SandboxConfig) -> Result<ExecutionReport, SandboxError> {
        config.validate()?;
        supervisor::run(&self.fork_server, config).await
    }
}
