# brink

**Defense-in-depth Linux process sandbox** — isolate untrusted code with cgroup v2, Linux namespaces, Landlock LSM, and seccomp-BPF. Written in Rust, targeting x86_64 Ubuntu 24.04 (kernel 6.8+).

---

## Security layers

Every sandboxed process is enclosed by six independent layers, applied outermost-first:

| # | Layer | Mechanism |
|---|-------|-----------|
| 0 | Resource limits | cgroup v2 — hard caps on memory, CPU time, and PID count |
| 1 | Identity isolation | User namespace + UID/GID mapping (runs as nobody inside) |
| 2 | Filesystem isolation | Mount namespace + `pivot_root` — only `/workspace` is writable |
| 3 | Filesystem allow-list | Landlock LSM — explicit allow-list of readable paths |
| 4 | Privilege removal | All Linux capabilities dropped after setup |
| 5 | Syscall filter | Seccomp-BPF — default-deny + ~115-syscall allow-list, hard-kill on violation |

A process must break all six layers simultaneously to affect the host. In practice seccomp and Landlock stop lateral movement before capabilities or namespaces are even relevant.

---

## Features

- **Memory ceiling** — `memory.max` cgroup control; OOM kills are detected and reported.
- **CPU throttle** — `cpu.max` quota/period pair; configurable per-job.
- **PID limit** — `pids.max` prevents fork bombs.
- **Wall-clock TTL** — `cgroup.kill` writes terminate all processes in the cgroup atomically when the deadline expires.
- **Separate stdout/stderr** — PTY for fd 0+1; anonymous pipe for fd 2. Both captured and returned in the report.
- **Extra read-only mounts** — supply language runtimes (`/usr`, `/lib`, etc.) without embedding them in the workspace; each path gets `READ_FILE | READ_DIR` in Landlock.
- **Execution report** — exit status, termination reason (exited / timed out / OOM killed / seccomp violation / signal), peak RSS, CPU time, stdout, stderr.
- **`brink-run` binary** — JSON-over-stdio bridge so any language can drive the sandbox without FFI.
- **Python agent SDK** — `BrinkRunner` integrates directly with the OpenAI Agents SDK.

---

## Requirements

| Requirement | Detail |
|---|---|
| OS | Linux only (`x86_64-unknown-linux-gnu`) |
| Kernel | 6.8+ (cgroup v2, Landlock ABI 3) |
| Distro | Ubuntu 24.04 recommended |
| cgroup v2 | cgroup v2 unified hierarchy must be active |
| Delegation | The calling process must own a writable cgroup subtree with `cpu`, `memory`, and `pids` controllers delegated (e.g. via systemd `Delegate=yes`) |
| Build | Rust 1.77+, `libseccomp-dev` installed |

---

## Installation

```bash
# Install libseccomp (Ubuntu)
sudo apt install libseccomp-dev

# Build
cargo build --release

# The sandbox library is linked into your binary; brink-run is a standalone bridge
ls target/release/brink-run
```

---

## Quick start (Rust)

`Runtime::init()` **must** be called before the Tokio runtime starts. Forking inside a live async runtime is undefined behaviour.

```rust
use brink::{Runtime, SandboxConfig, ResourceLimits};
use std::path::PathBuf;
use std::time::Duration;

fn main() {
    // Fork the internal fork server BEFORE starting Tokio.
    let runtime = Runtime::init().expect("sandbox init failed");

    tokio::runtime::Runtime::new().unwrap().block_on(async move {
        let config = SandboxConfig {
            workspace_path:      PathBuf::from("/tmp/my-workspace"),
            memory_max_bytes:    256 * 1024 * 1024,   // 256 MiB
            cpu_quota_us:        50_000,               // 50% of one CPU
            cpu_period_us:       100_000,
            pids_max:            64,
            ttl:                 Duration::from_secs(10),
            argv:                vec!["/workspace/my-binary".to_string()],
            env:                 vec![("PATH".to_string(), "/workspace/bin".to_string())],
            resource_limits:     ResourceLimits {
                max_open_files:      256,
                max_file_size_bytes: 64 * 1024 * 1024,
                stack_size_bytes:    8  * 1024 * 1024,
            },
            cgroup_parent:       PathBuf::from("/sys/fs/cgroup/user.slice/user-1000.slice"),
            extra_ro_mounts:     vec![
                (PathBuf::from("/usr"), PathBuf::from("/usr")),
                (PathBuf::from("/lib"), PathBuf::from("/lib")),
            ],
        };

        let report = runtime.run(config).await.unwrap();
        println!("exit: {:?}", report.termination_reason);
        println!("peak RSS: {} bytes", report.peak_memory_bytes);
        println!("stdout:\n{}", String::from_utf8_lossy(&report.stdout_bytes));
    });
}
```

---

## Quick start (`brink-run` JSON bridge)

`brink-run` reads a JSON job from stdin and writes a JSON result to stdout — no Rust required in the caller.

```bash
echo '{
  "argv": ["/usr/bin/python3", "-c", "print(\"hello\")"],
  "workspace": "/tmp/ws",
  "cgroup_parent": "/sys/fs/cgroup/user.slice/user-0.slice",
  "memory_mb": 128,
  "cpu_pct": 50,
  "timeout_secs": 10,
  "extra_ro_mounts": [["/usr", "/usr"], ["/lib", "/lib"], ["/lib64", "/lib64"]]
}' | ./target/release/brink-run
```

**Response:**
```json
{
  "ok": true,
  "exit_status": 0,
  "stdout": "hello\n",
  "stderr": "",
  "wall_time_ms": 42,
  "peak_memory_bytes": 8519680,
  "cpu_time_us": 18000,
  "termination": "exited(0)",
  "seccomp_violation": null
}
```

### Job spec fields

| Field | Type | Default | Description |
|---|---|---|---|
| `argv` | `[string]` | required | Command + arguments. `argv[0]` must be an absolute path inside the sandbox. |
| `workspace` | `string` | required | Absolute host path mounted read-write at `/workspace`. |
| `cgroup_parent` | `string` | required | Writable cgroup v2 parent directory. |
| `memory_mb` | `int` | 128 | Memory ceiling in MiB. |
| `cpu_pct` | `int` | 50 | CPU percentage of one core (1–100). |
| `timeout_secs` | `int` | 10 | Wall-clock timeout in seconds. |
| `pids_max` | `int` | 64 | Maximum PIDs in the cgroup. |
| `env` | `[[k, v]]` | `[]` | Environment variables; host env is **not** inherited. |
| `extra_ro_mounts` | `[[host, sandbox]]` | `[]` | Additional read-only bind mounts. |

---

## Python agent integration

`brink` ships a `BrinkRunner` that wraps `brink-run` and integrates with the [OpenAI Agents SDK](https://github.com/openai/openai-agents-python).

```python
from brink_agent import BrinkRunner
from brink_agent.agent import make_agent
from agents import Runner

runner = BrinkRunner(
    cgroup_parent="/sys/fs/cgroup/user.slice/user-0.slice",
    memory_mb=128,
    cpu_pct=50,
    timeout_secs=15,
    extra_ro_mounts=[
        ("/bin",   "/bin"),
        ("/lib",   "/lib"),
        ("/lib64", "/lib64"),
        ("/usr",   "/usr"),
    ],
)

agent = make_agent(runner)
result = await Runner.run(agent, "Write Python that prints the first 10 Fibonacci numbers")
print(result.final_output)
```

See [`examples/agent_demo.py`](examples/agent_demo.py) for a complete multi-language demo covering Python, Bash, Ruby, file context, and seccomp violation handling.

### Environment variables

| Variable | Description |
|---|---|
| `OPENAI_API_KEY` | Your OpenAI API key |
| `BRINK_BIN` | Path to `brink-run` binary (default: auto-detected) |
| `BRINK_CGROUP_PARENT` | cgroup v2 parent path |

---

## ExecutionReport

Every `runtime.run()` call returns an `ExecutionReport`:

| Field | Type | Description |
|---|---|---|
| `termination_reason` | `TerminationReason` | Authoritative stop reason (see below) |
| `exit_status` | `i32` | Raw exit code (meaningful on `Exited`) |
| `stdout_bytes` | `Vec<u8>` | PTY output (stdout) |
| `stderr_bytes` | `Vec<u8>` | Pipe output (stderr) |
| `wall_time` | `Duration` | Elapsed time from spawn to exit |
| `peak_memory_bytes` | `u64` | Peak RSS from `memory.peak` |
| `cpu_time_us` | `u64` | Total CPU time from `cpu.stat` |
| `seccomp_violation` | `Option<u32>` | Blocked syscall number, if applicable |

**TerminationReason variants:**

| Variant | Meaning |
|---|---|
| `Exited(i32)` | Process called `exit(2)` normally |
| `TimedOut` | Wall-clock TTL expired; cgroup killed |
| `OomKilled` | Kernel OOM killer fired |
| `SeccompViolation(u32)` | Blocked syscall — `SCMP_ACT_KILL_PROCESS` |
| `SignalKilled(i32)` | Unexpected signal (SIGSEGV, SIGBUS, etc.) |
| `CgroupKillFallback` | TTL expired; confirmed via `cgroup.kill` path |

---

## Architecture notes

- **Fork server** — a single subprocess handles all `clone3()` calls, keeping the Tokio thread pool free of fork-unsafe state. `prctl(PR_SET_PDEATHSIG, SIGKILL)` ensures the child dies if the fork server crashes.
- **PTY + pipe** — the child's stdin/stdout share a PTY master (for interactive-compatible output); stderr uses a separate anonymous pipe so the two streams are never interleaved.
- **`pivot_root` sequence** — `pivot_root` → `chdir("/")` → `umount2(MNT_DETACH)` → `rmdir`. The `chdir` before `umount2` is required to avoid `EBUSY`.
- **cgroup delegation** — `cgroup.subtree_control` is written to the *parent* directory, not the child; this is a kernel requirement. The library creates an ephemeral child cgroup per job and destroys it after cleanup.
- **Seccomp allow-list** — ~115 syscalls covering Python, Node.js, Go, and Rust runtimes. `clone(CLONE_NEWUSER)` and `socket(non-AF_UNIX)` use argument-level filtering. All other syscalls return `EPERM`; a hard-kill list (`kill`, `ptrace`, etc.) uses `SCMP_ACT_KILL_PROCESS`.

---

## License

MIT
