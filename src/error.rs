use std::io;
use nix::errno::Errno;

#[derive(Debug)]
pub enum SandboxError {
    // --- spec-defined errors ---
    CgroupCreateFailed(io::Error),
    /// cgroup_parent path is not writable; delegation not configured.
    CgroupDelegationMissing,
    NamespaceCloneFailed(Errno),
    UserNamespaceSetupFailed(Errno),
    MountFailed { step: &'static str, source: Errno },
    PivotRootFailed(Errno),
    /// Kernel Landlock ABI version (first field) is below required minimum (2).
    LandlockUnsupported(u32),
    LandlockRulesetFailed(Errno),
    SeccompLoadFailed(Errno),
    PtyOpenFailed(Errno),
    ForkServerUnavailable,
    ExecFailed(Errno),
    IoTimeout,
    WaitFailed(Errno),

    // --- implementation-required errors not in spec ---
    ConfigInvalid(&'static str),
    IpcError(io::Error),
    CgroupWriteFailed { path: &'static str, source: io::Error },
    /// Child process reported a setup failure before execve via the error pipe.
    ChildSetupFailed { stage: ChildStage, errno: i32 },
    CapabilityDropFailed(Errno),
}

/// Identifies which child setup stage failed; carried in the error pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChildStage {
    WaitForMapping  = 1,
    BreakPropagation = 2,
    BuildRootfs     = 3,
    MountDevpts     = 4,
    MountProc       = 5,
    MountWorkspace  = 6,
    MaskProc        = 7,
    PivotRoot       = 8,
    Landlock        = 9,
    CapabilityDrop  = 10,
    PtySlaveSetup   = 11,
    NoNewPrivs      = 12,
    Seccomp         = 13,
    Exec            = 14,
}

impl ChildStage {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1  => Some(Self::WaitForMapping),
            2  => Some(Self::BreakPropagation),
            3  => Some(Self::BuildRootfs),
            4  => Some(Self::MountDevpts),
            5  => Some(Self::MountProc),
            6  => Some(Self::MountWorkspace),
            7  => Some(Self::MaskProc),
            8  => Some(Self::PivotRoot),
            9  => Some(Self::Landlock),
            10 => Some(Self::CapabilityDrop),
            11 => Some(Self::PtySlaveSetup),
            12 => Some(Self::NoNewPrivs),
            13 => Some(Self::Seccomp),
            14 => Some(Self::Exec),
            _  => None,
        }
    }
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CgroupCreateFailed(e) =>
                write!(f, "cgroup create failed: {e}"),
            Self::CgroupDelegationMissing =>
                write!(f, "cgroup v2 delegation missing: cgroup_parent path is not writable; \
                           configure systemd Delegate=yes or grant write access to the subtree"),
            Self::NamespaceCloneFailed(e) =>
                write!(f, "clone3(CLONE_NEWUSER|…) failed: {e}"),
            Self::UserNamespaceSetupFailed(e) =>
                write!(f, "uid/gid mapping write failed: {e}"),
            Self::MountFailed { step, source } =>
                write!(f, "mount failed at '{step}': {source}"),
            Self::PivotRootFailed(e) =>
                write!(f, "pivot_root failed: {e}"),
            Self::LandlockUnsupported(v) =>
                write!(f, "Landlock ABI version {v} is below required minimum 2 (needs Linux 5.19+)"),
            Self::LandlockRulesetFailed(e) =>
                write!(f, "Landlock ruleset operation failed: {e}"),
            Self::SeccompLoadFailed(e) =>
                write!(f, "seccomp filter load failed: {e}"),
            Self::PtyOpenFailed(e) =>
                write!(f, "PTY open failed: {e}"),
            Self::ForkServerUnavailable =>
                write!(f, "fork server is unavailable or crashed; was Runtime::init() called?"),
            Self::ExecFailed(e) =>
                write!(f, "execve failed: {e}"),
            Self::IoTimeout =>
                write!(f, "I/O timeout reading from PTY master"),
            Self::WaitFailed(e) =>
                write!(f, "waitid(P_PIDFD) failed: {e}"),
            Self::ConfigInvalid(msg) =>
                write!(f, "invalid SandboxConfig: {msg}"),
            Self::IpcError(e) =>
                write!(f, "IPC error with fork server: {e}"),
            Self::CgroupWriteFailed { path, source } =>
                write!(f, "cgroup write to '{path}' failed: {source}"),
            Self::ChildSetupFailed { stage, errno } =>
                write!(f, "child setup failed at stage {stage:?} (errno {errno})"),
            Self::CapabilityDropFailed(e) =>
                write!(f, "capability drop failed: {e}"),
        }
    }
}

impl std::error::Error for SandboxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CgroupCreateFailed(e)          => Some(e),
            Self::IpcError(e)                    => Some(e),
            Self::CgroupWriteFailed { source, .. } => Some(source),
            _ => None,
        }
    }
}
