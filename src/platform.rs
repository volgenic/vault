//! Small operating-system helpers that read no secrets: the socket caller (R22, R23) and
//! process hardening (R3).

use std::path::Path;

use crate::error::VaultError;

/// SHA-256 of a file, as hex.
pub fn sha256_of(path: &Path) -> Result<String, VaultError> {
    use sha2::{Digest, Sha256};
    let data = std::fs::read(path)?;
    Ok(hex::encode(Sha256::digest(&data)))
}

/// Hardening at start (R3): refuse debugger attachment and never write a crash dump.
pub fn harden_process() {
    unsafe {
        let no_core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &no_core);
        #[cfg(target_os = "macos")]
        {
            const PT_DENY_ATTACH: libc::c_int = 31;
            libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
        }
    }
}

/// Who is on the other end of a socket connection.
pub struct Peer {
    pub uid: u32,
    pub pid: Option<i32>,
    pub program: Option<String>,
}

pub fn peer_of(fd: std::os::fd::RawFd) -> Option<Peer> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
        return None;
    }
    let pid = peer_pid(fd);
    let program = pid.and_then(program_path);
    Some(Peer { uid, pid, program })
}

#[cfg(target_os = "macos")]
fn peer_pid(fd: std::os::fd::RawFd) -> Option<i32> {
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERPID: libc::c_int = 0x002;
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let ok = unsafe {
        libc::getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, (&mut pid as *mut libc::pid_t).cast(), &mut len)
    };
    (ok == 0 && pid > 0).then_some(pid)
}

#[cfg(not(target_os = "macos"))]
fn peer_pid(_fd: std::os::fd::RawFd) -> Option<i32> {
    None
}

#[cfg(target_os = "macos")]
fn program_path(pid: i32) -> Option<String> {
    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let len = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    (len > 0).then(|| String::from_utf8_lossy(&buffer[..len as usize]).into_owned())
}

#[cfg(not(target_os = "macos"))]
fn program_path(_pid: i32) -> Option<String> {
    None
}
