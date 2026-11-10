//! Small operating-system checks that read no secrets: automatic login (R31), FileVault
//! (information only), the vault's own code signature, the socket caller (R22, R23), and
//! process hardening (R3).

use std::path::Path;
use std::process::Command;

use crate::error::VaultError;

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

/// A program's code signature, as `codesign --display` reports it (display only; it touches no
/// keychain item or signing identity).
#[derive(Clone, Debug, Default)]
pub struct SignatureInfo {
    pub identifier: Option<String>,
    /// The first (leaf) authority: the certificate's name.
    pub authority: Option<String>,
    pub runtime: bool,
    pub adhoc: bool,
}

/// The certificate every vault build is signed with (R3).
pub const SIGNING_AUTHORITY: &str = "Volgenic Vault Local Signing";

impl SignatureInfo {
    pub fn describe(&self) -> String {
        match (&self.identifier, &self.authority) {
            (Some(id), Some(by)) => format!(
                "{id}, signed by \"{by}\"{}",
                if self.runtime { ", hardened runtime" } else { ", NO hardened runtime" }
            ),
            (Some(id), None) if self.adhoc => format!("{id}, ad-hoc signature (not the vault's certificate)"),
            _ => "not signed".into(),
        }
    }

    /// Signed with the vault's certificate and the hardened runtime (R3).
    pub fn is_the_vaults(&self) -> bool {
        self.authority.as_deref() == Some(SIGNING_AUTHORITY) && self.runtime && !self.adhoc
    }
}

pub fn signature_of(path: &Path) -> SignatureInfo {
    let mut info = SignatureInfo::default();
    let Ok(out) = Command::new("/usr/bin/codesign").arg("--display").arg("--verbose=2").arg(path).output() else {
        return info;
    };
    let text = String::from_utf8_lossy(&out.stderr);
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Identifier=") {
            info.identifier = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("Authority=") {
            info.authority.get_or_insert_with(|| value.to_string());
        } else if line.starts_with("CodeDirectory") {
            info.runtime = line.contains("runtime");
            info.adhoc = line.contains("adhoc");
        } else if line.starts_with("Signature=adhoc") {
            info.adhoc = true;
        }
    }
    info
}

/// The running program's signature, for display.
pub fn own_signature() -> String {
    match std::env::current_exe() {
        Ok(exe) => signature_of(&exe).describe(),
        Err(_) => "unknown".into(),
    }
}

/// Runs `f` with the effective user ID switched to `uid` (and its primary group), then switches
/// back to root. As root, `install-system` writes into the owner's home only this way, so the
/// kernel applies the owner's permissions and a symbolic link can't redirect root's write (R17).
/// Not root: just runs `f`.
pub fn as_effective_user<T>(uid: u32, f: impl FnOnce() -> Result<T, VaultError>) -> Result<T, VaultError> {
    if unsafe { libc::geteuid() } != 0 {
        return f();
    }
    let gid = crate::store::account_by_uid(uid)
        .map(|account| account.gid)
        .ok_or_else(|| VaultError::Io(format!("no user with ID {uid}")))?;
    unsafe {
        if libc::setegid(gid) != 0 {
            return Err(VaultError::Io("setegid failed".into()));
        }
        if libc::seteuid(uid) != 0 {
            libc::setegid(0);
            return Err(VaultError::Io("seteuid failed".into()));
        }
    }
    let result = f();
    unsafe {
        if libc::seteuid(0) != 0 || libc::setegid(0) != 0 {
            // Never carry on with mixed credentials.
            std::process::abort();
        }
    }
    result
}

/// Drops root for good (R14): supplementary groups, group, then user, and checks root can't be
/// regained.
pub fn drop_privileges(uid: u32, gid: u32) -> Result<(), VaultError> {
    unsafe {
        let groups = [gid as libc::gid_t];
        if libc::setgroups(1, groups.as_ptr()) != 0 {
            return Err(VaultError::Io("setgroups failed".into()));
        }
        if libc::setgid(gid) != 0 {
            return Err(VaultError::Io("setgid failed".into()));
        }
        if libc::setuid(uid) != 0 {
            return Err(VaultError::Io("setuid failed".into()));
        }
        let dropped = libc::getuid() == uid
            && libc::geteuid() == uid
            && libc::getgid() == gid
            && libc::getegid() == gid
            && libc::setuid(0) != 0
            && libc::seteuid(0) != 0;
        if !dropped {
            return Err(VaultError::Io("root could still be regained after dropping privileges".into()));
        }
    }
    Ok(())
}

/// Every sudoers line that lets someone run commands without a password (root only can read
/// them). Any of these that an agent can use gives it root, and root opens the vault.
pub fn passwordless_sudo_rules() -> Vec<String> {
    let mut files = vec![std::path::PathBuf::from("/etc/sudoers")];
    if let Ok(entries) = std::fs::read_dir("/etc/sudoers.d") {
        let mut more: Vec<_> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
        more.sort();
        files.extend(more);
    }
    let mut found = Vec::new();
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else { continue };
        for line in text.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with('#') && trimmed.contains("NOPASSWD") {
                found.push(format!("{}: {trimmed}", file.display()));
            }
        }
    }
    found
}

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
