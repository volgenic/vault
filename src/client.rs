//! The command-line tool's side of the socket. Every command is a request to the daemon, the
//! only process that reads or changes the vault (R13, R26).
//!
//! Before sending anything, the client checks the socket's folder and the socket are its own
//! user's and not symbolic links, and that the peer's user ID is its own (`getpeereid` on macOS,
//! `SO_PEERCRED` on Linux; R22, R27).
//!
//! Every request carries `"protocol": 2` and a fresh request id, and every reply must echo that
//! id (protocol 2). A reply without a protocol version comes from an older daemon.

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
use crate::model::{Kind, SecretRef};
use crate::platform;
use crate::protocol::{
    self, AddReply, AuditReply, BackupCheck, BackupReply, ConfirmKitReply, ErrorReply, HealthReply, ListReply, MirrorPlanReply,
    OkReply, Outgoing, ReadBackupReply, RenameReply, ReplyFrame, ResetReply, RestoreReply, RuleInput, SecretRequest,
    StatusReply, VerifyBackupReply, WalletReply,
};
use crate::model::secret_bytes;
use crate::secret::SecretValue;
use crate::store::{self, Paths};

/// Quick requests.
const SHORT_WAIT: Duration = Duration::from_secs(30);
/// Changes and backups: a change writes the vault file and a backup, then reads it back.
const CHANGE_WAIT: Duration = Duration::from_secs(120);

/// Connects to the daemon and checks it runs as this user (R22).
fn connect_verified(paths: &Paths) -> Result<UnixStream, VaultError> {
    let me = unsafe { libc::getuid() };
    store::check_dir(&paths.socket_dir, me, 0o077).map_err(|e| VaultError::DaemonNotVerified(e.to_string()))?;
    let meta = std::fs::symlink_metadata(&paths.socket).map_err(|_| VaultError::DaemonNotRunning)?;
    if !meta.file_type().is_socket() || meta.uid() != me {
        return Err(VaultError::DaemonNotVerified(format!("{} isn't a socket of yours", paths.socket.display())));
    }
    let stream = UnixStream::connect(&paths.socket).map_err(|_| VaultError::DaemonNotRunning)?;
    match platform::peer_uid(stream.as_raw_fd()) {
        Some(uid) if uid == me => Ok(stream),
        Some(uid) => {
            Err(VaultError::DaemonNotVerified(format!("the process behind the socket is user ID {uid}, not you")))
        }
        None => Err(VaultError::DaemonNotVerified("can't tell who is behind the socket".into())),
    }
}

/// A fresh request id: `cli-` and 8 random bytes as hex.
fn new_request_id() -> String {
    let mut bytes = [0u8; 8];
    let _ = getrandom::getrandom(&mut bytes);
    format!("cli-{}", hex::encode(bytes))
}

fn exchange(paths: &Paths, request: &[u8], payload: Option<&[u8]>, wait: Duration) -> Result<Vec<u8>, VaultError> {
    let mut stream = connect_verified(paths)?;
    stream.set_read_timeout(Some(wait))?;
    stream.set_write_timeout(Some(Duration::from_secs(60)))?;
    stream.write_all(request)?;
    stream.write_all(b"\n")?;
    if let Some(payload) = payload {
        stream.write_all(payload)?;
    }
    stream.flush()?;
    // Sized up front so a reply that carries a value (`reveal`) isn't left behind by a reallocation.
    let mut line = Vec::with_capacity(64 * 1024);
    BufReader::new(&stream).read_until(b'\n', &mut line)?;
    if line.is_empty() {
        return Err(VaultError::Daemon("the daemon closed the connection without a reply".into()));
    }
    Ok(line)
}

/// Checks the reply is a protocol-2 reply to this request, then reads it.
fn parse<T: DeserializeOwned>(line: &[u8], request_id: &str) -> Result<T, VaultError> {
    let frame = serde_json::from_slice::<ReplyFrame>(line)
        .map_err(|_| VaultError::Daemon("the daemon sent an unreadable reply".into()))?;
    if frame.protocol.is_none() {
        return Err(VaultError::Daemon(
            "the daemon is an older build (protocol 1); run `vault install` with this build to update it".into(),
        ));
    }
    if frame.request_id.as_ref().and_then(|id| id.as_str()) != Some(request_id) {
        return Err(VaultError::ReplyMismatch(format!("sent request id {request_id}, got {:?}", frame.request_id)));
    }
    if let Ok(error) = serde_json::from_slice::<ErrorReply>(line) {
        if !error.ok {
            return Err(VaultError::Daemon(error.message));
        }
    }
    serde_json::from_slice::<T>(line).map_err(|_| VaultError::Daemon("the daemon sent an unreadable reply".into()))
}

fn call<T: DeserializeOwned>(paths: &Paths, request: serde_json::Value, wait: Duration) -> Result<T, VaultError> {
    let mut request = request;
    let request_id = new_request_id();
    request["protocol"] = json!(protocol::PROTOCOL_VERSION);
    request["request_id"] = json!(request_id);
    let bytes = serde_json::to_vec(&request).map_err(|_| VaultError::Io("request encoding".into()))?;
    parse(&exchange(paths, &bytes, None, wait)?, &request_id)
}

/// The JSON fields that name a secret: `name` or `id`.
fn secret_fields(secret: &SecretRef) -> serde_json::Value {
    match secret {
        SecretRef::Name(name) => json!({"name": name}),
        SecretRef::Id(id) => json!({"id": id}),
    }
}

/// Sends a request that carries a secret. The buffer is sized up front so it isn't reallocated,
/// and wiped after sending (R1).
fn call_secret<T: DeserializeOwned>(
    paths: &Paths,
    request: &SecretRequest<'_>,
    payload: Option<&[u8]>,
    wait: Duration,
) -> Result<T, VaultError> {
    let request_id = new_request_id();
    let outgoing = Outgoing { request, protocol: protocol::PROTOCOL_VERSION, request_id: &request_id };
    let mut bytes = Zeroizing::new(Vec::with_capacity(128 * 1024));
    serde_json::to_writer(&mut *bytes, &outgoing).map_err(|_| VaultError::Io("request encoding".into()))?;
    parse(&exchange(paths, &bytes, payload, wait)?, &request_id)
}

pub fn status(paths: &Paths) -> Result<StatusReply, VaultError> {
    call(paths, json!({"op": "status"}), SHORT_WAIT)
}

pub fn list(paths: &Paths) -> Result<ListReply, VaultError> {
    call(paths, json!({"op": "list"}), SHORT_WAIT)
}

pub fn health(paths: &Paths) -> Result<HealthReply, VaultError> {
    call(paths, json!({"op": "health"}), SHORT_WAIT)
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
    app: Option<&str>,
    leasable: bool,
    value: &SecretValue,
) -> Result<AddReply, VaultError> {
    let request = SecretRequest::Add { name, kind, site, rule, username, app, leasable, value };
    call_secret(paths, &request, None, CHANGE_WAIT)
}

pub fn delete(paths: &Paths, secret: &SecretRef) -> Result<BackupReply, VaultError> {
    let mut request = secret_fields(secret);
    request["op"] = json!("delete");
    call(paths, request, CHANGE_WAIT)
}

pub fn rename(paths: &Paths, secret: &SecretRef, new_name: &str) -> Result<RenameReply, VaultError> {
    let mut request = secret_fields(secret);
    request["op"] = json!("rename");
    request["new_name"] = json!(new_name);
    call(paths, request, CHANGE_WAIT)
}

/// What `reveal` gave the command line (#7666): the login's (or API key's) details and its value,
/// held in a `SecretValue` and written out only by `print_value` or `copy_to_clipboard`.
#[derive(serde::Deserialize)]
pub struct Revealed {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub site: String,
    #[serde(default)]
    pub version: u64,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default, deserialize_with = "secret_bytes::deserialize_opt")]
    value: Option<SecretValue>,
    #[serde(default, deserialize_with = "secret_bytes::deserialize_opt")]
    value_base64: Option<SecretValue>,
}

impl Revealed {
    /// The value's bytes, decoded from base64 when the daemon sent it that way. The reveal call
    /// site of `expose` on the command line (R1): `vault show --password` and `--copy`.
    fn bytes(&self) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        match (&self.value, &self.value_base64) {
            (Some(value), _) => Ok(Zeroizing::new(value.expose().to_vec())),
            (None, Some(encoded)) => BASE64
                .decode(encoded.expose())
                .map(Zeroizing::new)
                .map_err(|_| VaultError::Daemon("the daemon sent an unreadable value".into())),
            (None, None) => Err(VaultError::Daemon("the daemon's reply has no value".into())),
        }
    }

    /// Writes the value, then a line break, to `out`.
    pub fn print_value(&self, out: &mut impl Write) -> Result<(), VaultError> {
        out.write_all(&self.bytes()?)?;
        out.write_all(b"\n")?;
        out.flush()?;
        Ok(())
    }

    /// Puts the value on the clipboard: `pbcopy` on macOS; `wl-copy`, then `xclip`, then `xsel`
    /// on Linux. Returns the program that took it.
    pub fn copy_to_clipboard(&self) -> Result<&'static str, VaultError> {
        let bytes = self.bytes()?;
        let programs: &[(&'static str, &[&str])] = if cfg!(target_os = "macos") {
            &[("pbcopy", &[])]
        } else {
            &[("wl-copy", &[]), ("xclip", &["-selection", "clipboard"]), ("xsel", &["--clipboard", "--input"])]
        };
        for (program, args) in programs {
            let child = std::process::Command::new(program)
                .args(*args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            let Ok(mut child) = child else { continue };
            let wrote = child.stdin.take().map(|mut stdin| stdin.write_all(&bytes));
            let status = child.wait()?;
            if matches!(wrote, Some(Ok(()))) && status.success() {
                return Ok(program);
            }
        }
        Err(VaultError::Io(if cfg!(target_os = "macos") {
            "pbcopy didn't take the value".into()
        } else {
            "no clipboard program worked (install wl-copy, xclip or xsel, or use --password)".into()
        }))
    }
}

/// `reveal` (#7666): a login's password or an API key's value, audited with `reason` and the
/// caller `cli` before the daemon sends it. The reply line is wiped once read.
pub fn reveal(paths: &Paths, secret: &SecretRef, reason: &str) -> Result<Revealed, VaultError> {
    let mut request = secret_fields(secret);
    request["op"] = json!("reveal");
    request["reason"] = json!(reason);
    request["caller"] = json!("cli");
    let request_id = new_request_id();
    request["protocol"] = json!(protocol::PROTOCOL_VERSION);
    request["request_id"] = json!(request_id);
    let bytes = serde_json::to_vec(&request).map_err(|_| VaultError::Io("request encoding".into()))?;
    let line = Zeroizing::new(exchange(paths, &bytes, None, SHORT_WAIT)?);
    parse(&line, &request_id)
}

/// Replaces a login's password (#7666), keeping its id, username and site.
pub fn set_password(paths: &Paths, secret: &SecretRef, value: &SecretValue) -> Result<RenameReply, VaultError> {
    let (name, id) = match secret {
        SecretRef::Name(name) => (Some(name.as_str()), None),
        SecretRef::Id(id) => (None, Some(id.as_str())),
    };
    call_secret(paths, &SecretRequest::SetPassword { name, id, value }, None, CHANGE_WAIT)
}

pub fn confirm_kit(paths: &Paths, recovery_key: &SecretValue) -> Result<ConfirmKitReply, VaultError> {
    call_secret(paths, &SecretRequest::ConfirmKit { recovery_key }, None, CHANGE_WAIT)
}

/// Makes a wallet: the vault makes its key itself (#7440). Needs the recovery key.
pub fn wallet_create(
    paths: &Paths,
    name: &str,
    chain: &str,
    caps: &crate::wallet::Caps,
    recovery_key: &SecretValue,
) -> Result<WalletReply, VaultError> {
    call_secret(paths, &SecretRequest::WalletCreate { name, chain, caps, recovery_key }, None, CHANGE_WAIT)
}

/// Changes a wallet's caps. Needs the recovery key.
pub fn wallet_caps(
    paths: &Paths,
    secret: &SecretRef,
    caps: &crate::wallet::Caps,
    recovery_key: &SecretValue,
) -> Result<WalletReply, VaultError> {
    let (name, id) = match secret {
        SecretRef::Name(name) => (Some(name.as_str()), None),
        SecretRef::Id(id) => (None, Some(id.as_str())),
    };
    call_secret(paths, &SecretRequest::WalletCaps { name, id, caps, recovery_key }, None, CHANGE_WAIT)
}

pub fn reset(paths: &Paths, recovery_key: Option<&SecretValue>) -> Result<ResetReply, VaultError> {
    call_secret(paths, &SecretRequest::Reset { recovery_key }, None, CHANGE_WAIT)
}

/// Restores into an empty vault: from the restore point, or from a backup file's bytes, which
/// follow the request line as they are.
pub fn restore(
    paths: &Paths,
    recovery_key: &SecretValue,
    file: Option<(String, Vec<u8>)>,
) -> Result<RestoreReply, VaultError> {
    let (source, data) = match file {
        Some((source, data)) => (Some(source), Some(data)),
        None => (None, None),
    };
    if data.as_ref().is_some_and(|d| d.len() > backup::MAX_BACKUP_BYTES) {
        return Err(VaultError::BackupFailed(format!(
            "the file is over {} MiB, larger than any backup the vault writes",
            backup::MAX_BACKUP_BYTES / (1024 * 1024)
        )));
    }
    let request = SecretRequest::Restore { recovery_key, backup_len: data.as_ref().map(Vec::len), source };
    call_secret(paths, &request, data.as_deref(), CHANGE_WAIT)
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
