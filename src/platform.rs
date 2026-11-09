//! Small operating-system checks that read no secrets: automatic login (R31), FileVault
//! (information only), the vault's own code signature, the socket caller (R22, R23), and
//! process hardening (R3).

use std::path::Path;
use std::process::Command;

/// Whether macOS automatic login is on: an `autoLoginUser` in the login window preferences, or
/// an `/etc/kcpassword` file (R31).
pub fn auto_login_on() -> bool {
    if Path::new("/etc/kcpassword").exists() {
        return true;
    }
    Command::new("/usr/bin/defaults")
        .args(["read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"])
        .output()
        .map(|out| out.status.success() && !String::from_utf8_lossy(&out.stdout).trim().is_empty())
        .unwrap_or(false)
}

/// FileVault's state as `fdesetup status` reports it. Information only (R31).
pub fn filevault_status() -> String {
    Command::new("/usr/bin/fdesetup")
        .arg("status")
        .output()
        .ok()
        .and_then(|out| String::from_utf8_lossy(&out.stdout).lines().next().map(str::to_string))
        .unwrap_or_else(|| "unknown".into())
}

/// The running program's signature, as `codesign --display` reports it (display only; it
/// touches no keychain item or signing identity).
pub fn own_signature() -> String {
    let Ok(exe) = std::env::current_exe() else {
        return "unknown".into();
    };
    let Ok(out) = Command::new("/usr/bin/codesign").arg("--display").arg("--verbose=2").arg(&exe).output() else {
        return "unknown".into();
    };
    let text = String::from_utf8_lossy(&out.stderr);
    let mut identifier = None;
    let mut authority = None;
    let mut runtime = false;
    let mut adhoc = false;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Identifier=") {
            identifier = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("Authority=") {
            authority.get_or_insert_with(|| value.to_string());
        } else if line.starts_with("CodeDirectory") {
            runtime = line.contains("runtime");
            adhoc = line.contains("adhoc");
        } else if line.starts_with("Signature=adhoc") {
            adhoc = true;
        }
    }
    match (identifier, authority) {
        (Some(id), Some(by)) => format!("{id}, signed by \"{by}\"{}", if runtime { ", hardened runtime" } else { ", NO hardened runtime" }),
        (Some(id), None) if adhoc => format!("{id}, ad-hoc signature (not the vault's certificate)"),
        _ => "not signed".into(),
    }
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
