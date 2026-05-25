//! Mount namespace setup inside the child process.
//!
//! All functions run synchronously in the child after clone(), before execve.
//! Returns an errno-carrying error code written to the error pipe on failure.

use std::path::{Path, PathBuf};
use std::fs;
use std::os::unix::fs::DirBuilderExt;

use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::unistd::{chdir, pivot_root};

use crate::error::{ChildStage, SandboxError};

/// Context passed to child mount setup.
pub(crate) struct MountContext<'a> {
    pub workspace_path:  &'a Path,
    pub extra_ro_mounts: &'a [(PathBuf, PathBuf)],
    /// Randomly-named tmpfs root assembled in /tmp on the host before pivot_root.
    pub new_root:        &'a Path,
}

/// Execute the full mount namespace setup sequence inside the child.
/// On error returns `(stage, errno)` for the error pipe.
pub(crate) fn setup(ctx: &MountContext<'_>) -> Result<(), (ChildStage, nix::errno::Errno)> {
    // Step 1: Break shared mount propagation so nothing leaks to the host.
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| (ChildStage::BreakPropagation, e))?;

    // Step 2: Create a private tmpfs as the new rootfs.
    mount(
        Some("tmpfs"),
        ctx.new_root,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=0755"),
    )
    .map_err(|e| (ChildStage::BuildRootfs, e))?;

    // Create required directories in the new root.
    for dir in &["/proc", "/tmp", "/dev", "/dev/pts", "/dev/shm", "/workspace"] {
        let target = ctx.new_root.join(dir.trim_start_matches('/'));
        fs::DirBuilder::new()
            .mode(0o755)
            .create(&target)
            .map_err(|_| (ChildStage::BuildRootfs, nix::errno::Errno::last()))?;
    }

    // Create mount points for extra read-only mounts.
    for (_, sandbox_path) in ctx.extra_ro_mounts {
        let target = ctx.new_root.join(sandbox_path.to_string_lossy().trim_start_matches('/'));
        fs::create_dir_all(&target)
            .map_err(|_| (ChildStage::BuildRootfs, nix::errno::Errno::last()))?;
    }

    // Step 3: Mount devpts with newinstance (isolated from host's pts).
    let devpts_target = ctx.new_root.join("dev/pts");
    mount(
        Some("devpts"),
        &devpts_target,
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=0620"),
    )
    .map_err(|e| (ChildStage::MountDevpts, e))?;

    // Bind /dev/null, /dev/zero, /dev/urandom from host into new /dev.
    for dev in &["null", "zero", "urandom"] {
        let host_dev  = PathBuf::from("/dev").join(dev);
        let guest_dev = ctx.new_root.join("dev").join(dev);
        // Create the file as a bind-mount target (must be a regular file for device bind).
        fs::File::create(&guest_dev)
            .map_err(|_| (ChildStage::MountDevpts, nix::errno::Errno::last()))?;
        mount(
            Some(&host_dev),
            &guest_dev,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| (ChildStage::MountDevpts, e))?;
        // Make the bind read-only for /dev/urandom is already R-only in practice,
        // but explicit is better than implicit.
    }

    // Step 5: Bind workspace read-write.
    let ws_target = ctx.new_root.join("workspace");
    mount(
        Some(ctx.workspace_path),
        &ws_target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| (ChildStage::MountWorkspace, e))?;

    // Bind extra read-only mounts.
    for (host_path, sandbox_path) in ctx.extra_ro_mounts {
        let target = ctx.new_root.join(sandbox_path.to_string_lossy().trim_start_matches('/'));
        mount(
            Some(host_path.as_path()),
            &target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| (ChildStage::MountWorkspace, e))?;
        // Re-mount read-only.
        mount(
            Some(host_path.as_path()),
            &target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| (ChildStage::MountWorkspace, e))?;
    }

    // Step 4: Mount procfs.
    let proc_target = ctx.new_root.join("proc");
    mount(
        Some("proc"),
        &proc_target,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(|e| (ChildStage::MountProc, e))?;

    // Mask dangerous /proc interfaces by bind-mounting empty tmpfs dirs over them.
    mask_proc_paths(ctx.new_root)?;

    // Step 6: pivot_root.
    // The `put_old` directory must be inside `new_root`.
    let put_old = ctx.new_root.join(".put_old");
    fs::create_dir(&put_old)
        .map_err(|_| (ChildStage::PivotRoot, nix::errno::Errno::last()))?;

    pivot_root(ctx.new_root, &put_old).map_err(|e| (ChildStage::PivotRoot, e))?;

    // After pivot_root, chdir("/") MUST precede umount2 or it fails EBUSY.
    chdir("/").map_err(|e| (ChildStage::PivotRoot, e))?;

    // Remove the scratch-root directory from the old root before detaching it.
    // After pivot_root the host's /tmp/sandbox-root-* is at /.put_old/…; removing
    // it here prevents stale empty directories from accumulating on the host /tmp.
    if let Ok(rel) = ctx.new_root.strip_prefix("/") {
        let _ = fs::remove_dir(PathBuf::from("/.put_old").join(rel));
    }

    umount2("/.put_old", MntFlags::MNT_DETACH).map_err(|e| (ChildStage::PivotRoot, e))?;

    fs::remove_dir("/.put_old")
        .map_err(|_| (ChildStage::PivotRoot, nix::errno::Errno::last()))?;

    Ok(())
}

/// Mask dangerous /proc paths by bind-mounting empty stubs over them.
/// Directories are masked with an empty directory; files with an empty file.
fn mask_proc_paths(new_root: &Path) -> Result<(), (ChildStage, nix::errno::Errno)> {
    let mask_dir = new_root.join("tmp/.proc-mask-dir");
    fs::create_dir_all(&mask_dir)
        .map_err(|_| (ChildStage::MaskProc, nix::errno::Errno::last()))?;

    // Empty file stub for file targets (e.g. proc/sysrq-trigger).
    let mask_file = new_root.join("tmp/.proc-mask-file");
    fs::File::create(&mask_file)
        .map_err(|_| (ChildStage::MaskProc, nix::errno::Errno::last()))?;

    let masks = [
        "proc/sys",
        "proc/sysrq-trigger",
        "proc/irq",
        "proc/acpi",
    ];

    for rel in &masks {
        let target = new_root.join(rel);
        if !target.exists() {
            continue;
        }
        let src = if target.is_dir() { &mask_dir } else { &mask_file };
        mount(
            Some(src),
            &target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(|e| (ChildStage::MaskProc, e))?;
    }
    Ok(())
}

/// Build a unique path for the tmpfs scratch root directory.
///
/// Cannot use getpid() because inside CLONE_NEWPID the child always sees PID 1.
/// CLOCK_MONOTONIC_RAW gives nanosecond precision; the fork server is single-threaded
/// so sequential children cannot call this simultaneously.
pub(crate) fn scratch_root_path() -> PathBuf {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime with a valid output pointer is always safe.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut ts) };
    let ns = (ts.tv_sec as u64)
        .wrapping_mul(1_000_000_000)
        .wrapping_add(ts.tv_nsec as u64);
    PathBuf::from(format!("/tmp/sandbox-root-{ns}"))
}

/// Create the scratch root directory and return its path.
pub(crate) fn create_scratch_root() -> Result<PathBuf, SandboxError> {
    use std::os::unix::fs::DirBuilderExt as _;
    let path = scratch_root_path();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(SandboxError::CgroupCreateFailed)?;
    Ok(path)
}
