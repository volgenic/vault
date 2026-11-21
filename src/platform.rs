//! Small operating-system helpers that read no secrets: the socket caller (R22, R23), whether
//! it is Volgenic for Mac's signed app (R37) and process hardening (R3). Everything that differs between macOS and Linux at this level sits
//! here, behind `cfg`, so the rest of the crate stays platform-neutral.

use std::path::Path;

use crate::error::VaultError;

/// What the vault calls the machine it runs on, in messages: "Mac" or "machine".
#[cfg(target_os = "macos")]
pub const MACHINE: &str = "Mac";
#[cfg(not(target_os = "macos"))]
pub const MACHINE: &str = "machine";

/// SHA-256 of a file, as hex.
pub fn sha256_of(path: &Path) -> Result<String, VaultError> {
    use sha2::{Digest, Sha256};
    let data = std::fs::read(path)?;
    Ok(hex::encode(Sha256::digest(&data)))
}

/// Hardening at start (R3): refuse debugger attachment and never write a crash dump.
///
/// On macOS, `PT_DENY_ATTACH`. On Linux, `PR_SET_DUMPABLE` 0: no core dump, and no other
/// process of the same user may `ptrace` it or read its memory through `/proc` (only root can).
pub fn harden_process() {
    unsafe {
        let no_core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &no_core);
        #[cfg(target_os = "macos")]
        {
            const PT_DENY_ATTACH: libc::c_int = 31;
            libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
        }
        #[cfg(target_os = "linux")]
        {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }
}

/// Who is on the other end of a socket connection.
pub struct Peer {
    pub uid: u32,
    pub pid: Option<i32>,
    pub program: Option<String>,
}

/// The connected peer's user ID and, as a hint (R23), its process and program.
pub fn peer_of(fd: std::os::fd::RawFd) -> Option<Peer> {
    let (uid, pid) = peer_credentials(fd)?;
    let program = pid.and_then(program_path);
    Some(Peer { uid, pid, program })
}

/// The connected peer's user ID only: what the command-line tool checks of the daemon (R22).
pub fn peer_uid(fd: std::os::fd::RawFd) -> Option<u32> {
    peer_credentials(fd).map(|(uid, _)| uid)
}

/// macOS: `getpeereid` for the user ID, `LOCAL_PEERPID` for the process.
#[cfg(target_os = "macos")]
fn peer_credentials(fd: std::os::fd::RawFd) -> Option<(u32, Option<i32>)> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
        return None;
    }
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERPID: libc::c_int = 0x002;
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let ok = unsafe {
        libc::getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, (&mut pid as *mut libc::pid_t).cast(), &mut len)
    };
    Some((uid, (ok == 0 && pid > 0).then_some(pid)))
}

/// Linux: `SO_PEERCRED`, the credentials the kernel recorded when the peer connected (glibc has
/// no `getpeereid`).
#[cfg(target_os = "linux")]
fn peer_credentials(fd: std::os::fd::RawFd) -> Option<(u32, Option<i32>)> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ok = unsafe {
        libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut cred as *mut libc::ucred).cast(), &mut len)
    };
    if ok != 0 || len as usize != std::mem::size_of::<libc::ucred>() {
        return None;
    }
    Some((cred.uid, (cred.pid > 0).then_some(cred.pid)))
}

/// Volgenic's Developer ID team, which signs Volgenic for Mac (#7078).
pub const VOLGENIC_TEAM_ID: &str = "69CV53Q479";

/// Volgenic for Mac's bundle id.
pub const VOLGENIC_APP_ID: &str = "com.volgenic.desktop";

/// The dev build's bundle id, accepted only by a debug or `test-stubs` build of the vault, never
/// a release: nobody fills from a dev build.
pub const VOLGENIC_DEV_APP_ID: &str = "com.volgenic.desktop.v2dev";

/// The hardened runtime's exceptions that let another program of the owner's load or run its
/// own code in the app, or attach to it. A caller that has any of them (set to true) isn't
/// trusted to be the app, signed or not.
pub const FORBIDDEN_ENTITLEMENTS: [&str; 5] = [
    "com.apple.security.get-task-allow",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.debugger",
];

/// The bundle ids that may fill as Volgenic for Mac in this build.
pub fn volgenic_app_ids() -> &'static [&'static str] {
    if cfg!(any(debug_assertions, feature = "test-stubs")) { &[VOLGENIC_APP_ID, VOLGENIC_DEV_APP_ID] } else { &[VOLGENIC_APP_ID] }
}

/// The code requirement a caller must meet to fill as Volgenic for Mac (#7689): signed with a
/// Developer ID Application certificate (Apple's anchor, the Developer ID intermediate's and leaf's
/// marker extensions) of Volgenic's team, as the app's bundle id, with none of the
/// `FORBIDDEN_ENTITLEMENTS` (`exists` on a boolean entitlement matches only `true`, so one set
/// to false or absent passes).
pub fn volgenic_app_requirement() -> String {
    let ids = volgenic_app_ids().iter().map(|id| format!("identifier \"{id}\"")).collect::<Vec<_>>().join(" or ");
    let forbidden =
        FORBIDDEN_ENTITLEMENTS.iter().map(|key| format!(" and !(entitlement[\"{key}\"] exists)")).collect::<String>();
    format!(
        "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists \
         and certificate leaf[field.1.2.840.113635.100.6.1.13] exists \
         and certificate leaf[subject.OU] = \"{VOLGENIC_TEAM_ID}\" and ({ids}){forbidden}"
    )
}

/// A socket peer's audit token, read when the connection was accepted (macOS). Its pid and
/// pidversion name the process then.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerToken([u32; 8]);

#[cfg(target_os = "macos")]
impl PeerToken {
    /// `audit_token_to_pid`.
    pub fn pid(&self) -> u32 {
        self.0[5]
    }

    /// `audit_token_to_pidversion`: changes when the process runs a new program (exec), and
    /// differs for a new process that got the same pid.
    pub fn pidversion(&self) -> u32 {
        self.0[7]
    }
}

/// No audit tokens on Linux.
#[cfg(not(target_os = "macos"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerToken;

/// The peer's audit token now (`LOCAL_PEERTOKEN`). XNU (`uipc_ctloutput` in
/// `bsd/kern/uipc_usrreq.c`) works it out when asked, from the pid of the last process that used
/// the peer's socket (`proc_find(peerso->last_pid)`), not when the peer connected: it names
/// whatever process has that pid at the moment, so it is read at accept and again at the check
/// (`peer_meets`), and the two must agree.
#[cfg(target_os = "macos")]
pub fn peer_token(fd: std::os::fd::RawFd) -> Option<PeerToken> {
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERTOKEN: libc::c_int = 0x006;
    let mut token = [0u32; 8]; // audit_token_t
    let mut len = std::mem::size_of_val(&token) as libc::socklen_t;
    let got = unsafe { libc::getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, token.as_mut_ptr().cast(), &mut len) };
    (got == 0 && len as usize == std::mem::size_of_val(&token)).then_some(PeerToken(token))
}

#[cfg(not(target_os = "macos"))]
pub fn peer_token(_fd: std::os::fd::RawFd) -> Option<PeerToken> {
    None
}

/// Whether the process on the other end of `fd` is Volgenic for Mac, signed by Volgenic's team
/// with the hardened runtime, and still valid as it runs (#7689, R37). `at_accept` is the peer's
/// token read when the connection was accepted. `Err` says why not.
pub fn peer_is_volgenic_app(fd: std::os::fd::RawFd, at_accept: Option<PeerToken>) -> Result<(), String> {
    peer_meets(fd, at_accept, &volgenic_app_requirement())
        .map_err(|why| format!("the caller isn't Volgenic for Mac signed with Volgenic's Developer ID ({VOLGENIC_TEAM_ID}): {why}"))
}

/// Whether the process on the other end of `fd` meets the code `requirement`, was signed with
/// the hardened runtime, and is still valid as it runs. `Err` says why not, never a value.
///
/// The process is named by its audit token, read now and compared with the one read at accept
/// (`at_accept`): a different pid or pidversion (the pid now belongs to another process, or the
/// peer ran a new program) is refused, and the signature is checked against the token read now.
/// This narrows, and doesn't close, the race XNU's `LOCAL_PEERTOKEN` leaves (`peer_token`): a peer
/// that runs the app's program in its own process (exec) or hands its pid on before the vault
/// accepts the connection still looks like the app at both reads. The full fix is XPC, whose every
/// message carries the sender's own audit token. The hardened runtime and the forbidden
/// entitlements are what keep another program of the owner's from loading its own code into the
/// app (no `DYLD_INSERT_LIBRARIES`, no unsigned libraries, no debugger).
#[cfg(target_os = "macos")]
pub fn peer_meets(fd: std::os::fd::RawFd, at_accept: Option<PeerToken>, requirement: &str) -> Result<(), String> {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;
    use security_framework::os::macos::code_signing::{Flags, GuestAttributes, SecCode, SecRequirement};

    unsafe extern "C" {
        static kSecCodeInfoFlags: core_foundation::string::CFStringRef;
        fn SecCodeCopySigningInformation(
            code: *const std::ffi::c_void,
            flags: u32,
            information: *mut core_foundation::dictionary::CFDictionaryRef,
        ) -> i32;
    }
    const SIGNING_INFORMATION: u32 = 1 << 1; // kSecCSSigningInformation
    const RUNTIME: u32 = 0x10000; // kSecCodeSignatureRuntime

    let at_accept = at_accept.ok_or("the caller's audit token couldn't be read when it connected")?;
    let now = peer_token(fd).ok_or("the caller's audit token couldn't be read")?;
    if now.pid() != at_accept.pid() || now.pidversion() != at_accept.pidversion() {
        return Err(format!(
            "the caller's process changed while it was connected (pid {} version {} at connect, pid {} version {} now)",
            at_accept.pid(),
            at_accept.pidversion(),
            now.pid(),
            now.pidversion()
        ));
    }
    let bytes: Vec<u8> = now.0.iter().flat_map(|word| word.to_ne_bytes()).collect();
    let token = CFData::from_buffer(&bytes);
    let mut attributes = GuestAttributes::new();
    attributes.set_audit_token(token.as_concrete_TypeRef());
    let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|e| format!("the caller's code couldn't be found ({})", e.code()))?;
    let requirement: SecRequirement =
        requirement.parse().map_err(|e: security_framework::base::Error| format!("requirement: {}", e.code()))?;
    code.check_validity(Flags::NONE, &requirement)
        .map_err(|e| format!("its signature doesn't meet the requirement ({})", e.code()))?;
    let mut info = std::ptr::null();
    let status = unsafe { SecCodeCopySigningInformation(code.as_CFTypeRef(), SIGNING_INFORMATION, &mut info) };
    if status != 0 || info.is_null() {
        return Err(format!("the caller's signature couldn't be read ({status})"));
    }
    let info: CFDictionary<CFString, CFType> = unsafe { CFDictionary::wrap_under_create_rule(info) };
    let flags = info
        .find(unsafe { CFString::wrap_under_get_rule(kSecCodeInfoFlags) })
        .and_then(|value| value.downcast::<CFNumber>())
        .and_then(|number| number.to_i64())
        .unwrap_or(0) as u32;
    if flags & RUNTIME == 0 {
        return Err("it wasn't signed with the hardened runtime".into());
    }
    Ok(())
}

/// No code signatures to check on Linux (and no Volgenic for Mac there).
#[cfg(not(target_os = "macos"))]
pub fn peer_meets(_fd: std::os::fd::RawFd, _at_accept: Option<PeerToken>, _requirement: &str) -> Result<(), String> {
    Err("code signatures are checked only on a Mac".into())
}

#[cfg(target_os = "macos")]
fn program_path(pid: i32) -> Option<String> {
    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let len = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    (len > 0).then(|| String::from_utf8_lossy(&buffer[..len as usize]).into_owned())
}

/// The program behind a process, from `/proc`. A process that made itself non-dumpable (the
/// `vault` command-line tool does, R3) hides it, so this is a hint only (R23).
#[cfg(target_os = "linux")]
fn program_path(pid: i32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok().map(|path| path.display().to_string())
}

/// Whether this Linux machine was booted with systemd as its service manager (what
/// `sd_booted()` checks).
#[cfg(target_os = "linux")]
pub fn systemd_booted() -> bool {
    std::fs::symlink_metadata("/run/systemd/system").is_ok_and(|meta| meta.is_dir())
}

/// What protects this Mac's disk when it is off (#7689): FileVault, and whether it logs in by
/// itself. Read with no prompt and no administrator rights: `fdesetup status` and the login
/// window's `autoLoginUser`. `None` when it couldn't be read.
#[derive(Clone, Debug, Default)]
pub struct DiskProtection {
    pub filevault_on: Option<bool>,
    /// The account that logs in by itself at startup, if any.
    pub auto_login_user: Option<String>,
}

#[cfg(target_os = "macos")]
pub fn disk_protection() -> DiskProtection {
    use std::process::{Command, Stdio};
    let filevault_on = Command::new("/usr/bin/fdesetup")
        .arg("status")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.contains("FileVault is On") {
                Some(true)
            } else if text.contains("FileVault is Off") {
                Some(false)
            } else {
                None
            }
        });
    let auto_login_user = Command::new("/usr/bin/defaults")
        .args(["read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|user| !user.is_empty());
    DiskProtection { filevault_on, auto_login_user }
}

/// Sentences for what leaves a powered-off stolen Mac able to open the vault: FileVault off, or
/// automatic login on. Empty when neither, or not a Mac.
pub fn disk_protection_problems(disk: &DiskProtection) -> Vec<(&'static str, String)> {
    let mut problems = Vec::new();
    if disk.filevault_on == Some(false) {
        problems.push((
            "filevault_off",
            "FileVault is off, so someone who takes this Mac, even powered off, can start it and have the Secure Enclave unwrap the vault key: turn on FileVault in System Settings > Privacy & Security.".to_string(),
        ));
    }
    if let Some(user) = &disk.auto_login_user {
        problems.push((
            "auto_login_on",
            format!("This Mac logs in as {user} by itself at startup, so someone who takes it, even powered off, can start it and have the vault opened: turn off automatic login in System Settings > Users & Groups."),
        ));
    }
    problems
}

/// Keeps `path` (a file or a folder) out of Time Machine backups: the sticky exclusion
/// `tmutil addexclusion` sets, the `com.apple.metadata:com_apple_backup_excludeItem` attribute
/// (a binary property list holding "com.apple.backupd"). No administrator rights, no dialog.
/// Best effort: `Err` says why it wasn't set.
#[cfg(target_os = "macos")]
pub fn exclude_from_backups(path: &Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    const NAME: &[u8] = b"com.apple.metadata:com_apple_backup_excludeItem\0";
    const VALUE: [u8; 61] = [
        0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30, 0x5f, 0x10, 0x11, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c,
        0x65, 0x2e, 0x62, 0x61, 0x63, 0x6b, 0x75, 0x70, 0x64, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x1c,
    ];
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| "the path holds a NUL".to_string())?;
    let set = unsafe {
        libc::setxattr(path.as_ptr(), NAME.as_ptr().cast(), VALUE.as_ptr().cast(), VALUE.len(), 0, libc::XATTR_NOFOLLOW)
    };
    if set == 0 { Ok(()) } else { Err(std::io::Error::last_os_error().to_string()) }
}

/// Linux has no Time Machine; a home-folder backup is the person's own to configure.
#[cfg(not(target_os = "macos"))]
pub fn exclude_from_backups(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn disk_protection() -> DiskProtection {
    DiskProtection::default()
}
