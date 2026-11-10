//! The command-line tool's side of the socket. Every command is a request to the daemon, the
//! only process that can read or change the vault (R13, R26).
//!
//! Before sending anything, the client checks it is talking to the vault (R22, R27):
//! - the socket's folder and the socket itself belong to the vault's account and aren't
//!   symbolic links (only root and that account can put a socket there);
//! - `getpeereid` on the connection reports the vault's account.
//!
//! Only then may a request carry a typed value or the recovery key.

use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::de::DeserializeOwned;
use serde_json::json;
use zeroize::Zeroizing;

use crate::backup;
use crate::error::VaultError;
use crate::model::Kind;
use crate::protocol::{
    AddReply, AuditReply, BackupCheck, BackupReply, ConfirmKitReply, ErrorReply, ListReply, MirrorPlanReply, OkReply,
    ReadBackupReply, ResetReply, RestoreReply, RuleInput, SecretRequest, StatusReply, VerifyBackupReply,
};
use crate::secret::SecretValue;
use crate::store::{self, Paths};

/// Quick requests.
const SHORT_WAIT: Duration = Duration::from_secs(30);
/// Changes and backups: a change writes the vault file and a backup, then reads it back.
const CHANGE_WAIT: Duration = Duration::from_secs(120);

/// Connects to the daemon and checks it is the vault's (R22).
fn connect_verified(paths: &Paths) -> Result<UnixStream, VaultError> {
    let role = store::role_account().ok_or(VaultError::NotInstalled)?;
    store::check_dir(&paths.socket_dir, role.uid, 0o022)
        .map_err(|e| VaultError::DaemonNotVerified(e.to_string()))?;
    let meta = std::fs::symlink_metadata(&paths.socket).map_err(|_| VaultError::DaemonNotRunning)?;
    if !meta.file_type().is_socket() || meta.uid() != role.uid {
        return Err(VaultError::DaemonNotVerified(format!(
            "{} isn't a socket owned by {}",
            paths.socket.display(),
            store::ROLE_USER
        )));
    }
    let stream = UnixStream::connect(&paths.socket).map_err(|_| VaultError::DaemonNotRunning)?;
    let (mut uid, mut gid): (libc::uid_t, libc::gid_t) = (0, 0);
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 || uid != role.uid {
        return Err(VaultError::DaemonNotVerified(format!(
            "the process behind the socket isn't {} (user ID {uid})",
            store::ROLE_USER
        )));
    }
    Ok(stream)
}

fn exchange(paths: &Paths, request: &[u8], wait: Duration) -> Result<Vec<u8>, VaultError> {
    let mut stream = connect_verified(paths)?;
    stream.set_read_timeout(Some(wait))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(request)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let mut line = Vec::new();
    BufReader::new(&stream).read_until(b'\n', &mut line)?;
    if line.is_empty() {
        return Err(VaultError::Daemon("the daemon closed the connection without a reply".into()));
    }
    Ok(line)
}

fn parse<T: DeserializeOwned>(line: &[u8]) -> Result<T, VaultError> {
    if let Ok(error) = serde_json::from_slice::<ErrorReply>(line) {
        if !error.ok {
            return Err(VaultError::Daemon(error.message));
        }
    }
    serde_json::from_slice::<T>(line).map_err(|_| VaultError::Daemon("the daemon sent an unreadable reply".into()))
}

fn call<T: DeserializeOwned>(paths: &Paths, request: serde_json::Value, wait: Duration) -> Result<T, VaultError> {
    let bytes = serde_json::to_vec(&request).map_err(|_| VaultError::Io("request encoding".into()))?;
    parse(&exchange(paths, &bytes, wait)?)
}

/// Sends a request that carries a secret. The buffer is sized up front so it isn't reallocated,
/// and wiped after sending (R1).
fn call_secret<T: DeserializeOwned>(
    paths: &Paths,
    request: &SecretRequest<'_>,
    extra: usize,
    wait: Duration,
) -> Result<T, VaultError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(128 * 1024 + extra));
    serde_json::to_writer(&mut *bytes, request).map_err(|_| VaultError::Io("request encoding".into()))?;
    parse(&exchange(paths, &bytes, wait)?)
}

pub fn status(paths: &Paths) -> Result<StatusReply, VaultError> {
    call(paths, json!({"op": "status"}), SHORT_WAIT)
}

pub fn list(paths: &Paths) -> Result<ListReply, VaultError> {
    call(paths, json!({"op": "list"}), SHORT_WAIT)
}

pub fn audit(paths: &Paths, all: bool) -> Result<AuditReply, VaultError> {
    call(paths, json!({"op": "audit", "all": all}), SHORT_WAIT)
}

pub fn add(
    paths: &Paths,
    name: &str,
    kind: Kind,
    site: &str,
    rule: Option<&RuleInput>,
    username: Option<&str>,
    value: &SecretValue,
) -> Result<AddReply, VaultError> {
    let request = SecretRequest::Add { name, kind, site, rule, username, value };
    call_secret(paths, &request, 0, CHANGE_WAIT)
}

pub fn delete(paths: &Paths, name: &str) -> Result<BackupReply, VaultError> {
    call(paths, json!({"op": "delete", "name": name}), CHANGE_WAIT)
}

pub fn confirm_kit(paths: &Paths, recovery_key: &SecretValue) -> Result<ConfirmKitReply, VaultError> {
    call_secret(paths, &SecretRequest::ConfirmKit { recovery_key }, 0, CHANGE_WAIT)
}

pub fn reset(paths: &Paths, recovery_key: Option<&SecretValue>) -> Result<ResetReply, VaultError> {
    call_secret(paths, &SecretRequest::Reset { recovery_key }, 0, CHANGE_WAIT)
}

/// Restores into an empty vault: from the restore point, or from a backup file's bytes.
pub fn restore(
    paths: &Paths,
    recovery_key: &SecretValue,
    file: Option<(String, Vec<u8>)>,
) -> Result<RestoreReply, VaultError> {
    let (source, backup_base64) = match file {
        Some((source, data)) => (Some(source), Some(BASE64.encode(data))),
        None => (None, None),
    };
    let extra = backup_base64.as_ref().map_or(0, String::len);
    let request = SecretRequest::Restore { recovery_key, backup_base64, source };
    call_secret(paths, &request, extra, CHANGE_WAIT)
}

pub fn backup(paths: &Paths) -> Result<BackupReply, VaultError> {
    call(paths, json!({"op": "backup"}), CHANGE_WAIT)
}

pub fn verify(paths: &Paths) -> Result<BackupCheck, VaultError> {
    call::<VerifyBackupReply>(paths, json!({"op": "verify-backup"}), CHANGE_WAIT).map(|reply| reply.check)
}

/// The newest backup's path and ciphertext.
pub fn read_newest(paths: &Paths) -> Result<(String, Vec<u8>), VaultError> {
    let reply: ReadBackupReply = call(paths, json!({"op": "read-backup"}), SHORT_WAIT)?;
    let data = BASE64
        .decode(reply.data_base64)
        .map_err(|_| VaultError::Daemon("the daemon sent an unreadable backup".into()))?;
    Ok((reply.file, data))
}

pub fn mirror_plan(paths: &Paths) -> Result<MirrorPlanReply, VaultError> {
    call(paths, json!({"op": "mirror-plan"}), SHORT_WAIT)
}

pub fn mirror_report(paths: &Paths, report: serde_json::Value) -> Result<(), VaultError> {
    let mut request = report;
    request["op"] = json!("mirror-report");
    call::<OkReply>(paths, request, SHORT_WAIT).map(|_| ())
}

/// Waits up to `wait` for the daemon to answer.
pub fn wait_for_daemon(paths: &Paths, wait: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < wait {
        if status(paths).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

/// Whether the typed recovery key opens this backup and is the vault's (its fingerprint matches
/// the one the daemon reports). Runs in the command-line tool, so the key never crosses the
/// socket for a check that changes nothing (R27).
pub fn recovery_key_opens(data: &[u8], typed: SecretValue, vault_fingerprint: &str) -> bool {
    let identity = backup::parse_identity(&typed);
    drop(typed);
    match identity {
        Ok(identity) => {
            backup::fingerprint(&backup::public_of(&identity)) == vault_fingerprint
                && backup::open_bytes(data, &identity).is_ok()
        }
        Err(_) => false,
    }
}
