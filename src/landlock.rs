//! Landlock LSM ruleset construction and application.
//!
//! Requires Landlock ABI ≥ 2 (Linux 5.19). The ruleset uses an allow-list
//! model: all filesystem access is denied by default; only the paths and
//! rights listed here are granted.

use landlock::{
    AccessFs, BitFlags, Compatible, CompatLevel, PathBeneath, PathFd,
    Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr,
};
use std::path::Path;

use crate::error::SandboxError;

/// Check the kernel's Landlock ABI version and apply a strict allow-list ruleset.
/// Must be called inside the child process after mount setup and before execve.
pub(crate) fn apply_ruleset(workspace: &Path, extra_ro: &[(std::path::PathBuf, std::path::PathBuf)]) -> Result<(), SandboxError> {
    // Determine runtime ABI version via the raw syscall so we can return the
    // exact version in LandlockUnsupported rather than a generic error.
    let abi_version = probe_abi_version()?;
    if abi_version < 2 {
        return Err(SandboxError::LandlockUnsupported(abi_version));
    }

    // Rights available in ABI v2.
    let rw_file_rights: BitFlags<AccessFs> =
        AccessFs::ReadFile
        | AccessFs::WriteFile
        | AccessFs::ReadDir
        | AccessFs::MakeReg
        | AccessFs::RemoveFile
        | AccessFs::Truncate;

    let ro_dir_rights: BitFlags<AccessFs> =
        AccessFs::ReadFile | AccessFs::ReadDir;

    let dev_rw_rights: BitFlags<AccessFs> =
        AccessFs::ReadFile | AccessFs::WriteFile;

    // Build ruleset. HardRequirement means the call fails (and we return an
    // error) if the kernel cannot enforce every requested right — no silent
    // degradation on a security boundary.
    let ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(
            AccessFs::ReadFile
            | AccessFs::WriteFile
            | AccessFs::ReadDir
            | AccessFs::MakeReg
            | AccessFs::RemoveFile
            | AccessFs::Truncate
            | AccessFs::MakeDir
            | AccessFs::MakeSym,
        )
        .map_err(|_| SandboxError::LandlockRulesetFailed(nix::errno::Errno::last()))?
        .create()
        .map_err(|_| SandboxError::LandlockRulesetFailed(nix::errno::Errno::last()))?;

    let ruleset = add_path_rule(ruleset, workspace, rw_file_rights)?;
    let ruleset = add_path_rule(ruleset, "/tmp",       rw_file_rights)?;

    // /dev/null and /dev/urandom — read+write (write to /dev/null is common).
    let ruleset = add_path_rule(ruleset, "/dev/null",    dev_rw_rights)?;
    let ruleset = add_path_rule(ruleset, "/dev/urandom", AccessFs::ReadFile.into())?;

    // /dev/pts — allow slave PTY read/write.
    let ruleset = add_path_rule(ruleset, "/dev/pts",     dev_rw_rights)?;

    // /proc/self — minimal read access needed by dynamic linker and runtime.
    let ruleset = add_path_rule(ruleset, "/proc/self",   ro_dir_rights)?;

    // Extra read-only mounts.
    let mut ruleset = ruleset;
    for (_, sandbox_path) in extra_ro {
        ruleset = add_path_rule(ruleset, sandbox_path, ro_dir_rights)?;
    }

    ruleset
        .restrict_self()
        .map_err(|_| SandboxError::LandlockRulesetFailed(nix::errno::Errno::last()))?;

    Ok(())
}

fn add_path_rule<P: AsRef<Path>>(
    ruleset: RulesetCreated,
    path: P,
    rights: BitFlags<AccessFs>,
) -> Result<RulesetCreated, SandboxError> {
    let fd = PathFd::new(path.as_ref())
        .map_err(|_| SandboxError::LandlockRulesetFailed(nix::errno::Errno::last()))?;
    ruleset
        .add_rule(PathBeneath::new(fd, rights))
        .map_err(|_| SandboxError::LandlockRulesetFailed(nix::errno::Errno::last()))
}

/// Probe the kernel's Landlock ABI version via the raw syscall.
/// Returns 0 if Landlock is not supported at all.
fn probe_abi_version() -> Result<u32, SandboxError> {
    // landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
    // syscall number on x86_64 = 444
    const SYS_LANDLOCK_CREATE_RULESET: i64 = 444;
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

    // SAFETY: We pass null pointer and size 0 with the VERSION flag, which is
    // the documented way to query the ABI version without side effects.
    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };

    if ret < 0 {
        // ENOSYS → Landlock not compiled into this kernel.
        // EOPNOTSUPP → Landlock disabled at boot.
        return Err(SandboxError::LandlockUnsupported(0));
    }

    Ok(ret as u32)
}
