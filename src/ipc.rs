//! Wire protocol between the Tokio parent and the fork server process.
//!
//! Format: all integers little-endian. Every variable-length field is prefixed
//! with a u32 byte-length. No external serialization library is used — the
//! dependency allow-list excludes serde/bincode, and a hand-rolled format keeps
//! the parser surface minimal.
//!
//! The socket carries two message kinds:
//!   SpawnRequest  — Tokio parent → fork server (with SCM_RIGHTS for master_fd + slave_fd)
//!   SpawnResponse — fork server → Tokio parent (with SCM_RIGHTS for pidfd + err_pipe_read_fd)

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::ffi::OsStr;


// ─── Request ────────────────────────────────────────────────────────────────

/// All data the fork server needs to spawn a child. File descriptors
/// (master_fd, slave_fd) are sent separately via SCM_RIGHTS.
pub(crate) struct SpawnRequest {
    pub workspace_path:     PathBuf,
    pub extra_ro_mounts:    Vec<(PathBuf, PathBuf)>,
    pub memory_max_bytes:   u64,
    pub cpu_quota_us:       u64,
    pub cpu_period_us:      u64,
    pub pids_max:           u32,
    pub ttl_secs:           u64,
    pub ttl_nanos:          u32,
    pub argv:               Vec<CString>,
    /// Each element is a `KEY=VALUE` CString.
    pub env:                Vec<CString>,
    pub max_open_files:     u64,
    pub max_file_size_bytes: u64,
    pub stack_size_bytes:   u64,
    /// Absolute path of the already-created ephemeral cgroup directory.
    pub cgroup_path:        PathBuf,
    /// uid that the fork server process is running as (for uid_map write).
    pub host_uid:           u32,
    /// gid that the fork server process is running as (for gid_map write).
    pub host_gid:           u32,
}

impl SpawnRequest {
    pub(crate) fn serialize(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(512);
        push_path(&mut b, &self.workspace_path);
        push_u32(&mut b, self.extra_ro_mounts.len() as u32);
        for (host, sandbox) in &self.extra_ro_mounts {
            push_path(&mut b, host);
            push_path(&mut b, sandbox);
        }
        push_u64(&mut b, self.memory_max_bytes);
        push_u64(&mut b, self.cpu_quota_us);
        push_u64(&mut b, self.cpu_period_us);
        push_u32(&mut b, self.pids_max);
        push_u64(&mut b, self.ttl_secs);
        push_u32(&mut b, self.ttl_nanos);
        push_u32(&mut b, self.argv.len() as u32);
        for a in &self.argv {
            push_bytes(&mut b, a.as_bytes());
        }
        push_u32(&mut b, self.env.len() as u32);
        for e in &self.env {
            push_bytes(&mut b, e.as_bytes());
        }
        push_u64(&mut b, self.max_open_files);
        push_u64(&mut b, self.max_file_size_bytes);
        push_u64(&mut b, self.stack_size_bytes);
        push_path(&mut b, &self.cgroup_path);
        push_u32(&mut b, self.host_uid);
        push_u32(&mut b, self.host_gid);
        b
    }

    pub(crate) fn deserialize(buf: &[u8]) -> Option<Self> {
        let mut p = 0usize;
        let workspace_path     = pull_path(buf, &mut p)?;
        let n_extra            = pull_u32(buf, &mut p)? as usize;
        let mut extra_ro_mounts = Vec::with_capacity(n_extra);
        for _ in 0..n_extra {
            extra_ro_mounts.push((pull_path(buf, &mut p)?, pull_path(buf, &mut p)?));
        }
        let memory_max_bytes   = pull_u64(buf, &mut p)?;
        let cpu_quota_us       = pull_u64(buf, &mut p)?;
        let cpu_period_us      = pull_u64(buf, &mut p)?;
        let pids_max           = pull_u32(buf, &mut p)?;
        let ttl_secs           = pull_u64(buf, &mut p)?;
        let ttl_nanos          = pull_u32(buf, &mut p)?;
        let n_argv             = pull_u32(buf, &mut p)? as usize;
        let mut argv           = Vec::with_capacity(n_argv);
        for _ in 0..n_argv {
            argv.push(pull_cstring(buf, &mut p)?);
        }
        let n_env              = pull_u32(buf, &mut p)? as usize;
        let mut env            = Vec::with_capacity(n_env);
        for _ in 0..n_env {
            env.push(pull_cstring(buf, &mut p)?);
        }
        let max_open_files     = pull_u64(buf, &mut p)?;
        let max_file_size_bytes = pull_u64(buf, &mut p)?;
        let stack_size_bytes   = pull_u64(buf, &mut p)?;
        let cgroup_path        = pull_path(buf, &mut p)?;
        let host_uid           = pull_u32(buf, &mut p)?;
        let host_gid           = pull_u32(buf, &mut p)?;

        Some(Self {
            workspace_path, extra_ro_mounts,
            memory_max_bytes, cpu_quota_us, cpu_period_us, pids_max,
            ttl_secs, ttl_nanos,
            argv, env,
            max_open_files, max_file_size_bytes, stack_size_bytes,
            cgroup_path, host_uid, host_gid,
        })
    }
}

// ─── Response ───────────────────────────────────────────────────────────────

/// Tag byte values for the response.
pub(crate) const RESP_OK:  u8 = 0;
pub(crate) const RESP_ERR: u8 = 1;

pub(crate) fn encode_ok_response(child_pid: libc::pid_t) -> Vec<u8> {
    let mut b = vec![RESP_OK];
    b.extend_from_slice(&(child_pid as i32).to_le_bytes());
    b
}

pub(crate) fn encode_err_response(errno_val: i32) -> Vec<u8> {
    let mut b = vec![RESP_ERR];
    b.extend_from_slice(&errno_val.to_le_bytes());
    b
}

pub(crate) fn decode_response(buf: &[u8]) -> Option<Result<libc::pid_t, nix::errno::Errno>> {
    if buf.len() < 5 { return None; }
    match buf[0] {
        RESP_OK  => {
            let pid = i32::from_le_bytes(buf[1..5].try_into().ok()?);
            Some(Ok(pid))
        }
        RESP_ERR => {
            let raw = i32::from_le_bytes(buf[1..5].try_into().ok()?);
            Some(Err(nix::errno::Errno::from_raw(raw)))
        }
        _ => None,
    }
}

// ─── Encode helpers ─────────────────────────────────────────────────────────

fn push_u32(b: &mut Vec<u8>, v: u32)  { b.extend_from_slice(&v.to_le_bytes()); }
fn push_u64(b: &mut Vec<u8>, v: u64)  { b.extend_from_slice(&v.to_le_bytes()); }

fn push_bytes(b: &mut Vec<u8>, data: &[u8]) {
    push_u32(b, data.len() as u32);
    b.extend_from_slice(data);
}

fn push_path(b: &mut Vec<u8>, path: &PathBuf) {
    push_bytes(b, path.as_os_str().as_bytes());
}

// ─── Decode helpers ─────────────────────────────────────────────────────────

fn pull_u32(buf: &[u8], p: &mut usize) -> Option<u32> {
    let end = p.checked_add(4).filter(|&e| e <= buf.len())?;
    let v = u32::from_le_bytes(buf[*p..end].try_into().ok()?);
    *p = end;
    Some(v)
}

fn pull_u64(buf: &[u8], p: &mut usize) -> Option<u64> {
    let end = p.checked_add(8).filter(|&e| e <= buf.len())?;
    let v = u64::from_le_bytes(buf[*p..end].try_into().ok()?);
    *p = end;
    Some(v)
}

fn pull_bytes<'a>(buf: &'a [u8], p: &mut usize) -> Option<&'a [u8]> {
    let len = pull_u32(buf, p)? as usize;
    let end = p.checked_add(len).filter(|&e| e <= buf.len())?;
    let data = &buf[*p..end];
    *p = end;
    Some(data)
}

fn pull_path(buf: &[u8], p: &mut usize) -> Option<PathBuf> {
    let data = pull_bytes(buf, p)?;
    Some(PathBuf::from(OsStr::from_bytes(data)))
}

fn pull_cstring(buf: &[u8], p: &mut usize) -> Option<CString> {
    let data = pull_bytes(buf, p)?;
    CString::new(data).ok()
}
