use brink::{Runtime, SandboxConfig, ResourceLimits};
use std::path::PathBuf;
use std::time::Duration;

fn make_workspace() -> PathBuf {
    let p = PathBuf::from(format!("/tmp/sandbox-ws-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn base_config(workspace: PathBuf) -> SandboxConfig {
    SandboxConfig {
        workspace_path:      workspace,
        memory_max_bytes:    128 * 1024 * 1024,
        cpu_quota_us:        50_000,
        cpu_period_us:       100_000,
        pids_max:            32,
        ttl:                 Duration::from_secs(5),
        argv:                vec!["/bin/true".to_string()],
        env:                 vec![],
        resource_limits:     ResourceLimits {
            max_open_files:      64,
            max_file_size_bytes: 16 * 1024 * 1024,
            stack_size_bytes:    8 * 1024 * 1024,
        },
        cgroup_parent:       PathBuf::from("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice"),
        extra_ro_mounts:     vec![
            (PathBuf::from("/bin"), PathBuf::from("/bin")),
            (PathBuf::from("/lib"), PathBuf::from("/lib")),
            (PathBuf::from("/lib64"), PathBuf::from("/lib64")),
        ],
    }
}

#[test]
fn smoke_bin_true_exits_zero() {
    let runtime = Runtime::init().expect("Runtime::init failed");
    let ws = make_workspace();

    let tok = tokio::runtime::Runtime::new().unwrap();
    let report = tok
        .block_on(runtime.run(base_config(ws.clone())))
        .expect("run failed");

    std::fs::remove_dir_all(&ws).ok();

    assert_eq!(
        report.exit_status,
        0,
        "expected exit 0 for /bin/true, got {:?}",
        report.termination_reason,
    );
}
