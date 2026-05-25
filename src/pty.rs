//! PTY master/slave allocation.
//!
//! Both master and slave are opened in the parent (fork server) before clone(),
//! so the child inherits the slave fd directly — no path-based reopen inside
//! the new devpts namespace is needed. This sidesteps the newinstance devpts
//! slave-path problem described in requirements §5.

use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};

use nix::pty::{grantpt, posix_openpt, ptsname, unlockpt};
use nix::fcntl::OFlag;
use nix::libc;

use crate::error::SandboxError;

/// Allocated PTY pair ready to be passed to the fork server.
pub(crate) struct PtyPair {
    /// The async-readable master fd; retained by the Tokio parent.
    pub master: OwnedFd,
    /// The slave fd; passed to the fork server → child via SCM_RIGHTS.
    pub slave: OwnedFd,
}

/// Open /dev/ptmx, run grantpt+unlockpt, open the slave, configure window size.
pub(crate) fn open_pty() -> Result<PtyPair, SandboxError> {
    // Open master.
    // O_NONBLOCK is required: AsyncFd::try_io relies on non-blocking reads to
    // detect WouldBlock rather than blocking the executor thread.
    let master = posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
        .map_err(SandboxError::PtyOpenFailed)?;

    grantpt(&master).map_err(SandboxError::PtyOpenFailed)?;
    unlockpt(&master).map_err(SandboxError::PtyOpenFailed)?;

    // Get slave path while we still have access to the host /dev/pts.
    // SAFETY: ptsname returns a pointer to static/thread-local storage; we
    // copy it immediately into a CString before any other ptsname call.
    let slave_name = unsafe { ptsname(&master) }.map_err(SandboxError::PtyOpenFailed)?;

    // Open slave with O_CLOEXEC so it is closed in the fork-server process
    // after being passed to the child.  The child removes CLOEXEC after dup2.
    let slave_fd = nix::fcntl::open(
        slave_name.as_str(),
        OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(SandboxError::PtyOpenFailed)?;

    // Set a reasonable initial window size so programs that query it on startup
    // (e.g. Python's readline, ncurses) see a sane value.
    let winsize = libc::winsize {
        ws_col: 220,
        ws_row: 50,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: master_fd is valid and the winsize struct is correctly sized.
    let ret = unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &winsize) };
    if ret != 0 {
        return Err(SandboxError::PtyOpenFailed(nix::errno::Errno::last()));
    }

    // SAFETY: slave_fd is a valid open fd returned from nix::fcntl::open above.
    let slave = unsafe { OwnedFd::from_raw_fd(slave_fd) };

    // Transfer ownership of master out of PtyMaster without closing it.
    // PtyMaster wraps RawFd; into_raw_fd gives us ownership.
    let master_raw = master.into_raw_fd();
    // SAFETY: master_raw is the fd we just opened; we are taking ownership.
    let master = unsafe { OwnedFd::from_raw_fd(master_raw) };

    Ok(PtyPair { master, slave })
}
