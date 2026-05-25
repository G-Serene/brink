//! Fork server process.
//!
//! Spawned once before the Tokio runtime starts. Runs as a dedicated
//! single-threaded process. The Tokio parent communicates with it over
//! an AF_UNIX SOCK_STREAM socket pair. Each spawn request carries
//! SCM_RIGHTS for (master_fd, slave_fd); the response carries SCM_RIGHTS
//! for (pidfd, err_pipe_rd, stderr_pipe_rd).
//!
//! The fork server is the ONLY process that calls clone3(). This avoids
//! fork-inside-async-runtime UB.
//!
//! On success the response carries SCM_RIGHTS for (pidfd, err_pipe_rd, stderr_pipe_rd).

use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use nix::errno::Errno;
use nix::sys::socket::{
    recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags,
};
use nix::sys::eventfd::{EventFd, EfdFlags};

use crate::error::SandboxError;
use crate::ipc::{SpawnRequest, decode_response, encode_ok_response, encode_err_response};
use crate::namespace::{ChildContext, child_run, write_uid_gid_maps};

/// Parent-side handle to the fork server process.
pub(crate) struct ForkServer {
    /// Mutex-protected socket; one `run()` call at a time uses it.
    socket: Arc<Mutex<UnixStream>>,
}

impl ForkServer {
    /// Spawn the fork server and return the parent-side handle.
    /// Must be called before `tokio::main` starts.
    pub(crate) fn spawn() -> Result<Self, SandboxError> {
        let (parent_sock, child_sock) =
            UnixStream::pair().map_err(SandboxError::IpcError)?;

        // SAFETY: We fork before Tokio starts — no live thread pool, no epoll,
        // no mutexes held by other threads. The child does only async-signal-safe
        // work from this point; the parent returns immediately.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(SandboxError::NamespaceCloneFailed(Errno::last()));
        }

        if pid == 0 {
            // ── Fork server child ──────────────────────────────────────────
            drop(parent_sock);
            fork_server_main(child_sock); // never returns
        }

        // ── Parent ─────────────────────────────────────────────────────────
        drop(child_sock);
        Ok(Self {
            socket: Arc::new(Mutex::new(parent_sock)),
        })
    }

    /// Send a spawn request and receive (pidfd, err_pipe_rd, stderr_pipe_rd) back.
    /// Blocks the calling thread; use `tokio::task::block_in_place` from async code.
    pub(crate) fn request_spawn(
        &self,
        req: SpawnRequest,
        master_fd: RawFd,
        slave_fd: RawFd,
    ) -> Result<SpawnResponse, SandboxError> {
        let mut sock = self.socket.lock().map_err(|_| SandboxError::ForkServerUnavailable)?;
        // DerefMut through MutexGuard gives us &mut UnixStream.
        let stream: &mut UnixStream = &mut *sock;

        // ── Send length prefix ────────────────────────────────────────────
        let payload = req.serialize();
        let len_prefix = (payload.len() as u32).to_le_bytes();
        stream.write_all(&len_prefix).map_err(SandboxError::IpcError)?;

        // ── Send payload + master_fd, slave_fd via SCM_RIGHTS ─────────────
        let fds  = [master_fd, slave_fd];
        let cmsg = [ControlMessage::ScmRights(&fds)];
        sendmsg::<()>(
            stream.as_raw_fd(),
            &[io::IoSlice::new(&payload)],
            &cmsg,
            MsgFlags::empty(),
            None,
        )
        .map_err(|e| SandboxError::IpcError(io::Error::from_raw_os_error(e as i32)))?;

        // ── Read response length ──────────────────────────────────────────
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).map_err(SandboxError::IpcError)?;
        let resp_len = u32::from_le_bytes(len_buf) as usize;

        // ── Receive response payload + pidfd, err_pipe via SCM_RIGHTS ─────
        let mut resp_payload = vec![0u8; resp_len];
        let mut cmsg_space   = nix::cmsg_space!([RawFd; 3]);

        let mut iov = [io::IoSliceMut::new(&mut resp_payload)];
        let msg = recvmsg::<()>(
            stream.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_space),
            MsgFlags::empty(),
        )
        .map_err(|e| SandboxError::IpcError(io::Error::from_raw_os_error(e as i32)))?;

        let mut received_fds: Vec<RawFd> = Vec::new();
        for cmsg in msg
            .cmsgs()
            .map_err(|e| SandboxError::IpcError(io::Error::from_raw_os_error(e as i32)))?
        {
            if let ControlMessageOwned::ScmRights(fds) = cmsg {
                received_fds.extend_from_slice(&fds);
            }
        }

        match decode_response(&resp_payload) {
            Some(Ok(child_pid)) => {
                if received_fds.len() < 3 {
                    return Err(SandboxError::ForkServerUnavailable);
                }
                // SAFETY: kernel delivers these as valid open fds via SCM_RIGHTS.
                let pidfd          = unsafe { OwnedFd::from_raw_fd(received_fds[0]) };
                let err_pipe_rd    = unsafe { OwnedFd::from_raw_fd(received_fds[1]) };
                let stderr_pipe_rd = unsafe { OwnedFd::from_raw_fd(received_fds[2]) };
                Ok(SpawnResponse { pidfd, err_pipe_rd, stderr_pipe_rd, child_pid })
            }
            Some(Err(errno)) => Err(SandboxError::NamespaceCloneFailed(errno)),
            None              => Err(SandboxError::ForkServerUnavailable),
        }
    }
}

/// Successful spawn response from the fork server.
pub(crate) struct SpawnResponse {
    /// Race-free handle for the child; usable with waitid(P_PIDFD).
    pub pidfd:          OwnedFd,
    /// Read end of the child setup error pipe.
    /// EOF means execve succeeded. 5 bytes means setup failed.
    pub err_pipe_rd:    OwnedFd,
    /// Read end of the child's stderr pipe. The child's fd 2 writes here.
    pub stderr_pipe_rd: OwnedFd,
    /// The PID of the sandboxed process in the host namespace.
    pub child_pid:      libc::pid_t,
}

// ─── Fork server main loop ───────────────────────────────────────────────────

fn fork_server_main(sock: UnixStream) -> ! {
    let sock_fd = sock.as_raw_fd();

    // Mark all fds ≥ 3 as close-on-exec so they are closed in any child the
    // fork server spawns (sandboxed children inherit only what we explicitly keep).
    // SAFETY: close_range(3, UINT_MAX, CLOSE_RANGE_CLOEXEC) is a documented
    // kernel interface; we restore the socket fd's flags immediately after.
    // Register SIGCHLD handler to automatically reap children and write their exit status
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGCHLD);
        libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());

        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigchld_handler as *const () as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigaction(libc::SIGCHLD, &sa, std::ptr::null_mut());
    }

    unsafe {
        libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 1u32 /* CLOSE_RANGE_CLOEXEC */);
        let flags = libc::fcntl(sock_fd, libc::F_GETFD);
        libc::fcntl(sock_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
    }

    loop {
        if handle_one_request(&sock).is_err() {
            // Socket closed or unrecoverable protocol error — parent died.
            unsafe { libc::_exit(0) };
        }
    }
}

fn handle_one_request(mut sock: &UnixStream) -> Result<(), ()> {
    // ── Read length-prefixed payload ──────────────────────────────────────
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf).map_err(|_| ())?;
    let payload_len = u32::from_le_bytes(len_buf) as usize;

    let mut payload    = vec![0u8; payload_len];
    let mut cmsg_space = nix::cmsg_space!([RawFd; 2]);

    let mut iov = [io::IoSliceMut::new(&mut payload)];
    let msg = recvmsg::<()>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_space),
        MsgFlags::empty(),
    )
    .map_err(|_| ())?;

    // ── Extract master_fd and slave_fd from SCM_RIGHTS ────────────────────
    let mut received: Vec<RawFd> = Vec::new();
    for cmsg in msg.cmsgs().map_err(|_| ())? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            received.extend_from_slice(&fds);
        }
    }
    if received.len() < 2 {
        return Err(());
    }
    // SAFETY: SCM_RIGHTS delivers valid open fds.
    let master_fd = unsafe { OwnedFd::from_raw_fd(received[0]) };
    let slave_fd  = unsafe { OwnedFd::from_raw_fd(received[1]) };

    let req = match SpawnRequest::deserialize(&payload) {
        Some(r) => r,
        None    => { send_error(sock, libc::EINVAL); return Ok(()); }
    };

    // ── Eventfd for child synchronisation ─────────────────────────────────
    let efd = match EventFd::from_value_and_flags(0, EfdFlags::EFD_CLOEXEC) {
        Ok(fd) => fd,
        Err(e) => { send_error(sock, e as i32); return Ok(()); }
    };
    let efd_raw = efd.as_raw_fd();

    // ── Error pipe (write-end is O_CLOEXEC → auto-closed on execve) ───────
    // This pipe carries at most 5 bytes on setup failure; EOF means execve succeeded.
    let mut pipe_fds = [0i32; 2];
    // SAFETY: pipe2 with valid storage and O_CLOEXEC flag.
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        send_error(sock, Errno::last() as i32);
        return Ok(());
    }
    // SAFETY: pipe2 successfully initialised both fds.
    let err_pipe_rd = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
    let err_pipe_wr = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };

    // ── Stderr pipe (child's fd 2 → parent reads actual stderr output) ────
    // Write-end does NOT have O_CLOEXEC — it must survive execve.
    let mut stderr_pipe_fds = [0i32; 2];
    // SAFETY: pipe2 with valid storage; flags = 0 so write-end stays open after execve.
    if unsafe { libc::pipe2(stderr_pipe_fds.as_mut_ptr(), 0) } != 0 {
        send_error(sock, Errno::last() as i32);
        return Ok(());
    }
    // SAFETY: pipe2 successfully initialised both fds.
    let stderr_pipe_rd = unsafe { OwnedFd::from_raw_fd(stderr_pipe_fds[0]) };
    let stderr_pipe_wr = unsafe { OwnedFd::from_raw_fd(stderr_pipe_fds[1]) };

    let host_uid    = req.host_uid;
    let host_gid    = req.host_gid;
    let cgroup_path = req.cgroup_path.clone();

    let ctx = ChildContext {
        req,
        sync_read_fd:    efd_raw,
        slave_fd:        slave_fd.as_raw_fd(),
        stderr_write_fd: stderr_pipe_wr.as_raw_fd(),
        err_pipe_write:  err_pipe_wr.as_raw_fd(),
    };

    // SAFETY: fork server is single-threaded with no Tokio runtime — safe to clone3.
    let result = unsafe { crate::namespace::clone3_sandbox() };

    match result {
        Err(errno) => {
            send_error(sock, errno as i32);
        }

        Ok(None) => {
            // ── Child process ──────────────────────────────────────────────
            drop(master_fd);
            drop(err_pipe_rd);
            drop(stderr_pipe_rd);
            child_run(ctx); // never returns
        }

        Ok(Some(clone_result)) => {
            // ── Fork server parent side ────────────────────────────────────
            let child_pid = clone_result.child_pid;

            // 1. Assign child to cgroup before signalling it to proceed.
            if let Err(e) = write_cgroup_procs(&cgroup_path, child_pid) {
                send_error(sock, e as i32);
                return Ok(());
            }

            // 2. Write setgroups=deny, uid_map, gid_map (must be in this order).
            if write_uid_gid_maps(child_pid, host_uid, host_gid).is_err() {
                send_error(sock, Errno::last() as i32);
                return Ok(());
            }

            // 3. Signal child to proceed past its eventfd barrier.
            let one: u64 = 1;
            // SAFETY: efd_raw is a valid eventfd; &one is a correctly typed pointer.
            unsafe { libc::write(efd_raw, &one as *const u64 as *const _, 8) };

            // 4. Send response: length prefix + payload + SCM_RIGHTS (pidfd, err_pipe_rd, stderr_pipe_rd).
            let resp_payload = encode_ok_response(child_pid);
            let len_prefix   = (resp_payload.len() as u32).to_le_bytes();
            if sock.write_all(&len_prefix).is_err() {
                return Err(());
            }
            let resp_fds = [
                clone_result.pidfd.as_raw_fd(),
                err_pipe_rd.as_raw_fd(),
                stderr_pipe_rd.as_raw_fd(),
            ];
            let resp_cmsg = [ControlMessage::ScmRights(&resp_fds)];
            let _ = sendmsg::<()>(
                sock.as_raw_fd(),
                &[io::IoSlice::new(&resp_payload)],
                &resp_cmsg,
                MsgFlags::empty(),
                None,
            );
        }
    }

    Ok(())
}

fn send_error(mut sock: &UnixStream, errno_val: i32) {
    let payload    = encode_err_response(errno_val);
    let len_prefix = (payload.len() as u32).to_le_bytes();
    let _ = sock.write_all(&len_prefix);
    let _ = sock.write_all(&payload);
}

fn write_cgroup_procs(path: &std::path::Path, pid: libc::pid_t) -> Result<(), Errno> {
    std::fs::write(path.join("cgroup.procs"), pid.to_string()).map_err(|_| Errno::last())
}

extern "C" fn sigchld_handler(_sig: libc::c_int) {
    let saved_errno = unsafe { *libc::__errno_location() };
    loop {
        let mut status: libc::c_int = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid <= 0 {
            break;
        }
        
        let mut path_buf = [0u8; 64];
        let mut len = 0;
        let prefix = b"/tmp/sandbox-status-";
        path_buf[..prefix.len()].copy_from_slice(prefix);
        len += prefix.len();
        
        let mut temp_pid = pid;
        let mut digits = [0u8; 16];
        let mut d_len = 0;
        if temp_pid == 0 {
            digits[0] = b'0';
            d_len = 1;
        } else {
            while temp_pid > 0 {
                digits[d_len] = b'0' + (temp_pid % 10) as u8;
                temp_pid /= 10;
                d_len += 1;
            }
        }
        for i in 0..d_len {
            path_buf[len] = digits[d_len - 1 - i];
            len += 1;
        }
        path_buf[len] = 0;
        
        unsafe {
            let fd = libc::open(
                path_buf.as_ptr() as *const libc::c_char,
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
                0o644
            );
            if fd >= 0 {
                let mut status_buf = [0u8; 16];
                let mut s_len = 0;
                let mut temp_status = status;
                if temp_status == 0 {
                    status_buf[0] = b'0';
                    s_len = 1;
                } else {
                    let mut is_neg = false;
                    if temp_status < 0 {
                        is_neg = true;
                        temp_status = -temp_status;
                    }
                    while temp_status > 0 {
                        status_buf[s_len] = b'0' + (temp_status % 10) as u8;
                        temp_status /= 10;
                        s_len += 1;
                    }
                    if is_neg {
                        status_buf[s_len] = b'-';
                        s_len += 1;
                    }
                }
                for i in 0..(s_len / 2) {
                    status_buf.swap(i, s_len - 1 - i);
                }
                status_buf[s_len] = b'\n';
                s_len += 1;
                
                libc::write(fd, status_buf.as_ptr() as *const libc::c_void, s_len);
                libc::close(fd);
            }
        }
    }
    unsafe { *libc::__errno_location() = saved_errno; }
}
