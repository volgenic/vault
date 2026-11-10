//! `vault daemon`: the vault's background part, run by the LaunchDaemon `com.volgenic.vault`.
//!
//! It starts as root, and while still root (R14):
//! 1. reads `system.json` (the owner's user ID) from root's folder;
//! 2. reads the Secure Enclave key's public half;
//! 3. unwraps the vault key with the Secure Enclave. After a restart this fails until someone
//!    logs in (CryptoKit's default protection), so it waits and retries.
//!
//! Then it drops to the vault's own account for good, opens the socket and serves. It is the
//! only process that reads or changes the vault (R13), and the only one that writes the local
//! backups (R32). Callers must be the owner's user ID or root (R22).

use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use zeroize::Zeroizing;

use crate::audit::{self, AuditEvent};
use crate::backup;
use crate::secret::WipingBuf;
use crate::error::VaultError;
use crate::keyprotect::{self, SePublic};
use crate::model::{Kind, MirrorState, VaultDoc};
use crate::platform::{self, Peer};
use crate::protocol::{
    self, AddReply, BackupReply, ConfirmKitReply, ErrorReply, ListReply, MirrorPlanReply, OkReply, ProxyReplyOut,
    ReadBackupReply, Request, ResetReply, RestoreReply, StatusReply, TotpReply, VerifyBackupReply,
};
use crate::proxy::{self, ProxyRequest};
use crate::rules;
use crate::store::{self, OwnerPaths, Paths, SystemConfig};
use crate::vault::{self, NewSecret, Vault};

const MAX_CONNECTIONS: usize = 16;
/// How often to retry the Secure Enclave before the first login after a restart.
const UNWRAP_RETRY: Duration = Duration::from_secs(15);

struct Server {
    paths: Paths,
    config: SystemConfig,
    se_public: SePublic,
    /// The mirror folder a restored-from-file vault gets: the owner's iCloud Drive.
    default_mirror_dir: PathBuf,
    /// The open vault, or none (before a restore). Every change and backup holds this lock, so
    /// changes happen one at a time (R13).
    vault: Mutex<Option<Vault>>,
    /// A read-only copy for agents' requests (list, 2FA, proxy), replaced after every change.
    snapshot: RwLock<Option<Arc<VaultDoc>>>,
    client: reqwest::blocking::Client,
    active: AtomicUsize,
}

fn log(message: &str) {
    eprintln!("{} vault daemon: {message}", crate::now_rfc3339());
}

pub fn run() -> Result<(), VaultError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(VaultError::NotRoot);
    }
    let paths = Paths::system();
    let config = store::read_system_config(&paths)?;
    let role = store::role_account().ok_or(VaultError::NotInstalled)?;
    if role.uid != config.role_uid || role.gid != config.role_gid {
        return Err(VaultError::UnsafeVaultFolder(format!(
            "{} is user {} group {}, but install-system recorded {} and {}",
            store::ROLE_USER,
            role.uid,
            role.gid,
            config.role_uid,
            config.role_gid
        )));
    }
    if platform::auto_login_on() {
        return Err(VaultError::AutoLoginOn); // R31
    }
    store::check_dir(&paths.dir, role.uid, 0o077)?;
    store::check_dir(&paths.local_backups, role.uid, 0o022)?;
    store::check_dir(&paths.socket_dir, role.uid, 0o022)?;

    // Root's part (R14): the Secure Enclave key's public half, and the vault key.
    let se_public = keyprotect::load_public(&paths.root_dir)?;
    let opened = if store::vault_exists(&paths) { Some(open_waiting_for_login(&paths)?) } else { None };
    let default_mirror_dir = OwnerPaths::for_uid(config.owner_uid)?.icloud_backups();

    platform::drop_privileges(role.uid, role.gid)?;
    unsafe {
        libc::umask(0o077);
    }
    log(&format!("dropped root; running as {} (user ID {})", store::ROLE_USER, role.uid));

    let client = proxy::client()?;
    match fs::symlink_metadata(&paths.socket) {
        Ok(meta) if meta.file_type().is_socket() => fs::remove_file(&paths.socket)?,
        Ok(_) => {
            return Err(VaultError::UnsafeVaultFolder(format!(
                "{} exists and isn't a socket",
                paths.socket.display()
            )));
        }
        Err(_) => {}
    }
    let listener = UnixListener::bind(&paths.socket)?;
    // 0666: any local user may connect; the daemon then accepts only the owner and root (R22).
    fs::set_permissions(&paths.socket, fs::Permissions::from_mode(0o666))?;

    let snapshot = match &opened {
        Some(vault) => Some(Arc::new(vault.read_copy()?)),
        None => None,
    };
    let server = Arc::new(Server {
        paths: paths.clone(),
        config,
        se_public,
        default_mirror_dir,
        vault: Mutex::new(opened),
        snapshot: RwLock::new(snapshot),
        client,
        active: AtomicUsize::new(0),
    });
    let mut event = AuditEvent::new("daemon", "started");
    event.detail = Some(format!(
        "pid {}, as {}, vault {}, socket {}",
        std::process::id(),
        store::ROLE_USER,
        if server.snapshot.read().map(|s| s.is_some()).unwrap_or(false) { "open" } else { "absent" },
        paths.socket.display()
    ));
    audit::append(&paths.audit_log, event)?;
    log(&format!("serving on {}", paths.socket.display()));

    // A vault just made by install-system, or one whose last backup failed: back it up now.
    let _ = server.with_vault(|vault| {
        if let Some(status) = vault.backup_if_needed() {
            log(&format!("backup of generation {}: {}", status.generation, if status.ok { "ok" } else { "FAILED" }));
        }
        Ok(())
    });

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let server = Arc::clone(&server);
        if server.active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            server.active.fetch_sub(1, Ordering::SeqCst);
            let mut stream = stream;
            let _ = reply(&mut stream, &ErrorReply::from(&VaultError::Busy));
            continue;
        }
        std::thread::spawn(move || {
            server.handle(stream);
            server.active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

/// Opens the vault as root. Before the first login since a restart the Secure Enclave key can't
/// be used, so this waits and retries rather than exiting (launchd would only restart it).
fn open_waiting_for_login(paths: &Paths) -> Result<Vault, VaultError> {
    let started = Instant::now();
    let mut last_log: Option<Instant> = None;
    loop {
        match Vault::open(paths) {
            Ok(vault) => {
                if last_log.is_some() {
                    log(&format!("the Secure Enclave answered after {}s", started.elapsed().as_secs()));
                }
                return Ok(vault);
            }
            Err(VaultError::SecureEnclave) => {
                if last_log.is_none_or(|at| at.elapsed() >= Duration::from_secs(600)) {
                    log("the Secure Enclave refused to unwrap the vault key; waiting for the first login since the restart, retrying every 15s");
                    last_log = Some(Instant::now());
                }
                std::thread::sleep(UNWRAP_RETRY);
            }
            Err(error) => return Err(error),
        }
    }
}

/// Reads one request line straight into a buffer that is wiped when dropped, through a chunk
/// that is wiped too: no ordinary buffer ever holds a request, which may carry a typed value or
/// the recovery key (R1, R27). Returns the line and any bytes read past it.
fn read_request_line(stream: &mut UnixStream) -> Result<(WipingBuf, Vec<u8>), VaultError> {
    let too_long = || VaultError::BadRequest("unreadable or over 2 MiB".into());
    let mut data = WipingBuf::with_capacity(64 * 1024);
    let mut chunk = Zeroizing::new(vec![0u8; 16 * 1024]);
    loop {
        let n = match stream.read(&mut chunk[..]) {
            Ok(n) => n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(too_long()),
        };
        if n == 0 {
            return Err(VaultError::BadRequest("the request ended without a newline".into()));
        }
        let start = data.len();
        data.extend_from_slice(&chunk[..n]);
        if let Some(index) = memchr::memchr(b'\n', &chunk[..n]) {
            let end = start + index;
            if end > protocol::MAX_REQUEST_LINE {
                return Err(too_long());
            }
            let rest = data.as_slice()[end + 1..].to_vec();
            let mut line = WipingBuf::with_capacity(end);
            line.extend_from_slice(&data.as_slice()[..end]);
            return Ok((line, rest));
        }
        if data.len() > protocol::MAX_REQUEST_LINE {
            return Err(too_long());
        }
    }
}

/// Reads the backup file that follows a `restore` request line: exactly `len` bytes, at most
/// `backup::MAX_BACKUP_BYTES`. Ciphertext, so an ordinary buffer is fine.
fn read_payload(stream: &mut UnixStream, mut data: Vec<u8>, len: usize) -> Result<Vec<u8>, VaultError> {
    if len > backup::MAX_BACKUP_BYTES {
        return Err(VaultError::BadRequest(format!(
            "the backup is over {} MiB, larger than any backup the vault writes",
            backup::MAX_BACKUP_BYTES / (1024 * 1024)
        )));
    }
    if data.len() > len {
        return Err(VaultError::BadRequest("more bytes than backup_len".into()));
    }
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
    let have = data.len();
    data.resize(len, 0);
    stream
        .read_exact(&mut data[have..])
        .map_err(|_| VaultError::BadRequest("the backup ended before backup_len bytes".into()))?;
    Ok(data)
}

fn reply<T: serde::Serialize>(stream: &mut UnixStream, value: &T) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(value).unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"encoding\"}".to_vec());
    line.push(b'\n');
    stream.write_all(&line)?;
    stream.flush()
}

fn with_peer(mut event: AuditEvent, peer: &Peer) -> AuditEvent {
    event.peer_pid = peer.pid;
    event.peer_program = peer.program.clone();
    event
}

fn error_reply(stream: &mut UnixStream, error: &VaultError) -> std::io::Result<()> {
    reply(stream, &ErrorReply::from(error))
}

impl Server {
    fn snapshot(&self) -> Result<Arc<VaultDoc>, VaultError> {
        let snapshot = self.snapshot.read().map_err(|_| VaultError::Busy)?;
        snapshot.as_ref().map(Arc::clone).ok_or(VaultError::NotInitialized)
    }

    /// Runs `f` on the open vault under the change lock, then refreshes the agents' snapshot.
    fn with_vault<T>(&self, f: impl FnOnce(&mut Vault) -> Result<T, VaultError>) -> Result<T, VaultError> {
        let mut guard = self.vault.lock().unwrap_or_else(|e| e.into_inner());
        let vault = guard.as_mut().ok_or(VaultError::NotInitialized)?;
        let result = f(vault);
        self.publish(&guard);
        result
    }

    fn publish(&self, guard: &Option<Vault>) {
        let fresh = guard.as_ref().and_then(|vault| vault.read_copy().ok()).map(Arc::new);
        if let Ok(mut snapshot) = self.snapshot.write() {
            *snapshot = fresh;
        }
    }

    /// Best effort, for refusals and for lines after a use that is already recorded.
    fn audit(&self, event: AuditEvent) {
        if let Err(error) = audit::append(&self.paths.audit_log, event) {
            log(&format!("couldn't write the audit log: {}", error.code()));
        }
    }

    /// Records a use before it happens (R28). If the line can't be written, the use doesn't
    /// happen: the caller gets `audit_unavailable`.
    fn record(&self, event: AuditEvent) -> Result<(), VaultError> {
        audit::append(&self.paths.audit_log, event).map(|_| ()).map_err(|error| {
            log(&format!("couldn't write the audit log ({}); refusing the request", error.code()));
            VaultError::AuditUnavailable
        })
    }

    /// Audits a command's outcome, best effort, and turns it into the reply.
    fn finish<T: serde::Serialize>(
        &self,
        stream: &mut UnixStream,
        peer: &Peer,
        op: &str,
        name: Option<&str>,
        result: Result<T, VaultError>,
    ) -> std::io::Result<()> {
        match result {
            Ok(value) => reply(stream, &value),
            Err(error) => {
                let mut event = AuditEvent::new(op, &format!("denied: {}", error.code()));
                event.name = name.map(str::to_string);
                if let VaultError::BackupFailed(why) | VaultError::InvalidRule(why) | VaultError::InvalidSecret(why) = &error {
                    event.detail = Some(why.clone());
                }
                self.audit(with_peer(event, peer));
                error_reply(stream, &error)
            }
        }
    }

    fn handle(&self, mut stream: UnixStream) {
        // R22: only the owner's user ID, or root. R23: the caller's pid and program are a hint.
        let Some(peer) = platform::peer_of(stream.as_raw_fd()) else { return };
        if peer.uid != self.config.owner_uid && peer.uid != 0 {
            let mut event = AuditEvent::new("connect", "denied: not the owner's user ID");
            event.detail = Some(format!("uid {}", peer.uid));
            self.audit(with_peer(event, &peer));
            return;
        }
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

        let (line, rest) = match read_request_line(&mut stream) {
            Ok(read) => read,
            Err(error) => {
                self.audit(with_peer(AuditEvent::new("request", &format!("denied: {}", error.code())), &peer));
                let _ = error_reply(&mut stream, &error);
                return;
            }
        };
        let request: Request = match protocol::parse_request(line.as_slice()) {
            Ok(request) => request,
            Err(_) => {
                let error = VaultError::BadRequest("not a valid request; see the protocol in the README".into());
                self.audit(with_peer(AuditEvent::new("request", "denied: bad_request"), &peer));
                let _ = error_reply(&mut stream, &error);
                return;
            }
        };
        drop(line);
        // `restore FILE` sends the backup's bytes after the line (ciphertext only).
        let payload = match &request {
            Request::Restore { backup_len: Some(len), .. } => match read_payload(&mut stream, rest, *len) {
                Ok(data) => Some(data),
                Err(error) => {
                    self.audit(with_peer(AuditEvent::new("restore", &format!("denied: {}", error.code())), &peer));
                    let _ = error_reply(&mut stream, &error);
                    return;
                }
            },
            _ => None,
        };
        let _ = self.dispatch(&mut stream, &peer, request, payload);
    }

    fn dispatch(
        &self,
        stream: &mut UnixStream,
        peer: &Peer,
        request: Request,
        payload: Option<Vec<u8>>,
    ) -> std::io::Result<()> {
        match request {
            Request::List => {
                let result = self.snapshot().and_then(|doc| {
                    self.record(with_peer(AuditEvent::new("list", "ok"), peer))?;
                    Ok(ListReply { ok: true, secrets: doc.summaries() })
                });
                self.finish(stream, peer, "list", None, result)
            }
            Request::Totp { name } => {
                let result = self.snapshot().and_then(|doc| {
                    let code = vault::totp_code(&doc, &name)?;
                    self.record(with_peer(AuditEvent::named("totp", &name, "ok"), peer))?;
                    Ok(TotpReply { ok: true, name: name.clone(), code: code.code, seconds_left: code.seconds_left })
                });
                self.finish(stream, peer, "totp", Some(&name), result)
            }
            Request::Proxy { name, method, path, headers, body, body_base64 } => {
                match self.snapshot() {
                    Ok(doc) => match self.proxy(&doc, &name, method, path, headers, body, body_base64, peer) {
                        Ok(out) => reply(stream, &out),
                        Err(error) => error_reply(stream, &error),
                    },
                    Err(error) => self.finish::<OkReply>(stream, peer, "proxy", Some(&name), Err(error)),
                }
            }
            Request::Status => {
                let guard = self.vault.lock().unwrap_or_else(|e| e.into_inner());
                let opened = guard.as_ref().map(Vault::status);
                drop(guard);
                let mirror = fs::read(&self.paths.mirror_state)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<MirrorState>(&bytes).ok());
                self.audit(with_peer(AuditEvent::new("status", "ok"), peer));
                reply(
                    stream,
                    &StatusReply {
                        ok: true,
                        version: crate::VERSION.into(),
                        pid: std::process::id(),
                        uid: unsafe { libc::getuid() },
                        key_protection: keyprotect::DESCRIPTION.into(),
                        local_backups: self.paths.local_backups.display().to_string(),
                        restore_point: vault::has_restore_point(&self.paths),
                        vault: opened,
                        mirror,
                    },
                )
            }
            Request::Audit { all } => {
                let report = vault::audit_report(&self.paths, all);
                self.audit(with_peer(AuditEvent::new("audit", "ok"), peer));
                reply(stream, &report)
            }
            Request::Add { name, kind, site, rule, username, value } => {
                let result = (|| {
                    let rule = match (kind, rule) {
                        (Kind::ApiKey, Some(input)) => Some(rules::parse_rule(
                            &input.host,
                            input.port,
                            &input.methods,
                            &input.path,
                            &input.header,
                        )?),
                        (Kind::ApiKey, None) => return Err(VaultError::InvalidRule("an API key needs a rule".into())),
                        _ => None,
                    };
                    let new = NewSecret { name: name.clone(), kind, site, rule, username, value };
                    self.with_vault(|vault| vault.add(new))
                        .map(|(secret, backup)| AddReply { ok: true, secret, backup })
                })();
                self.finish(stream, peer, "add", Some(&name), result)
            }
            Request::Delete { name } => {
                let result = self.with_vault(|vault| vault.delete(&name)).map(|backup| BackupReply { ok: true, backup });
                self.finish(stream, peer, "delete", Some(&name), result)
            }
            Request::ConfirmKit { recovery_key } => {
                let result = self
                    .with_vault(|vault| vault.confirm_kit(recovery_key))
                    .map(|(backup, kit_path)| ConfirmKitReply { ok: true, kit_path, backup });
                self.finish(stream, peer, "confirm-kit", None, result)
            }
            Request::Reset { recovery_key } => {
                let result = (|| {
                    let mut guard = self.vault.lock().unwrap_or_else(|e| e.into_inner());
                    let vault = guard.as_mut().ok_or(VaultError::NotInitialized)?;
                    let outcome = vault.reset(recovery_key);
                    if outcome.is_ok() {
                        *guard = None;
                    }
                    self.publish(&guard);
                    let outcome = outcome?;
                    Ok(ResetReply {
                        ok: true,
                        unused: outcome.unused,
                        newest_file: outcome.newest_file,
                        kit_path: outcome.kit_path,
                    })
                })();
                self.finish(stream, peer, "reset", None, result)
            }
            Request::Restore { recovery_key, backup_len: _, source } => {
                let result = (|| {
                    let file = payload.map(|data| (source.unwrap_or_else(|| "a file the person named".into()), data));
                    let mut guard = self.vault.lock().unwrap_or_else(|e| e.into_inner());
                    if guard.is_some() {
                        return Err(VaultError::AlreadyInitialized);
                    }
                    let (mut restored, report) =
                        vault::restore(&self.paths, &self.se_public, file, &self.default_mirror_dir, recovery_key)?;
                    // The vault is on disk now: hold it even if its first backup fails, so the
                    // daemon and the disk agree (the failure is the alarm of R19).
                    let backup = restored.backup();
                    *guard = Some(restored);
                    self.publish(&guard);
                    let backup = backup?;
                    Ok(RestoreReply {
                        ok: true,
                        vault_id: report.vault_id,
                        from_vault_id: report.from_vault_id,
                        from_generation: report.from_generation,
                        secrets: report.secrets,
                        backup,
                    })
                })();
                self.finish(stream, peer, "restore", None, result)
            }
            Request::Backup => {
                let result = self.with_vault(Vault::backup).map(|backup| BackupReply { ok: true, backup });
                self.finish(stream, peer, "backup-request", None, result)
            }
            Request::VerifyBackup => {
                let result = self.with_vault(|vault| vault.check_newest());
                if let Ok(check) = &result {
                    let mut event = AuditEvent::new("verify-backup", if check.matches_vault { "ok" } else { "differs from vault" });
                    event.detail = Some(format!("{} (generation {})", check.file, check.generation));
                    self.audit(with_peer(event, peer));
                }
                let result = result.map(|check| VerifyBackupReply { ok: true, check });
                self.finish(stream, peer, "verify-backup", None, result)
            }
            Request::ReadBackup => {
                let result = self.with_vault(|vault| vault.read_newest()).and_then(|(file, data)| {
                    let mut event = AuditEvent::new("read-backup", "ok");
                    event.detail = Some(file.display().to_string());
                    self.record(with_peer(event, peer))?;
                    Ok(ReadBackupReply { ok: true, file: file.display().to_string(), data_base64: BASE64.encode(data) })
                });
                self.finish(stream, peer, "read-backup", None, result)
            }
            Request::MirrorPlan => {
                let result = self.with_vault(|vault| {
                    Ok(MirrorPlanReply {
                        ok: true,
                        local_dir: self.paths.local_backups.display().to_string(),
                        mirror_dir: vault.mirror_dir().to_string(),
                        vault_id: vault.vault_id().to_string(),
                        generation: vault.generation(),
                    })
                });
                self.finish(stream, peer, "mirror-plan", None, result)
            }
            Request::MirrorReport { ok, newest_file, newest_generation, copied, already_there, detail } => {
                let result = self.with_vault(|vault| {
                    let detail: String = detail.chars().filter(|c| !c.is_control()).take(500).collect();
                    let state = MirrorState {
                        at: crate::now_rfc3339(),
                        ok,
                        mirror_dir: vault.mirror_dir().to_string(),
                        newest_file: newest_file.map(|f| f.chars().take(300).collect()),
                        newest_generation,
                        copied,
                        already_there,
                        detail: detail.clone(),
                    };
                    let bytes = serde_json::to_vec(&state).map_err(|_| VaultError::Io("mirror state encoding".into()))?;
                    store::write_atomic(&self.paths.mirror_state, &bytes)?;
                    let mut event = AuditEvent::new("mirror-report", if ok { "ok" } else { "FAILED" });
                    event.detail = Some(format!(
                        "copied {copied}, already there {already_there}, newest generation {}{}",
                        newest_generation.map_or("none".into(), |g| g.to_string()),
                        if detail.is_empty() { String::new() } else { format!(": {detail}") }
                    ));
                    self.audit(with_peer(event, peer));
                    Ok(OkReply { ok: true })
                });
                self.finish(stream, peer, "mirror-report", None, result)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn proxy(
        &self,
        doc: &VaultDoc,
        name: &str,
        method: String,
        path: String,
        headers: std::collections::BTreeMap<String, String>,
        body: Option<String>,
        body_base64: Option<String>,
        peer: &Peer,
    ) -> Result<ProxyReplyOut, VaultError> {
        let logged_path: String = path.split(['?', '#']).next().unwrap_or("").chars().take(200).collect();
        let mut event = AuditEvent::named("proxy", name, "");
        event.method = Some(method.chars().take(16).collect());
        event.path = Some(logged_path);
        let event = with_peer(event, peer);
        let fail = |error: VaultError, mut event: AuditEvent| {
            event.outcome = format!("denied: {}", error.code());
            if let VaultError::RuleMismatch(why) | VaultError::BadRequest(why) = &error {
                event.detail = Some(why.clone());
            }
            self.audit(event);
            error
        };

        let Some(record) = doc.find(name) else {
            return Err(fail(VaultError::UnknownSecret(name.into()), event));
        };
        if record.kind != Kind::ApiKey {
            return Err(fail(VaultError::WrongKind, event)); // R5
        }
        let Some(rule) = &record.rule else {
            return Err(fail(VaultError::InvalidRule("this key has no rule".into()), event));
        };
        let mut event = event;
        event.host = Some(rule.host.clone());
        let body = match (body, body_base64) {
            (Some(_), Some(_)) => {
                return Err(fail(VaultError::BadRequest("send body or body_base64, not both".into()), event));
            }
            (Some(text), None) => text.into_bytes(),
            (None, Some(encoded)) => match BASE64.decode(encoded) {
                Ok(bytes) => bytes,
                Err(_) => return Err(fail(VaultError::BadRequest("body_base64 isn't base64".into()), event)),
            },
            (None, None) => Vec::new(),
        };
        let request = ProxyRequest {
            method,
            path_and_query: path,
            headers: headers.into_iter().collect(),
            body,
        };
        if let Err(error) = proxy::check(rule, &request) {
            return Err(fail(error, event));
        }
        // R28: the use is on disk before the key leaves the vault. No line, no request.
        let mut attempt = event.clone();
        attempt.outcome = "sending".into();
        self.record(attempt)?;
        match proxy::send(&self.client, rule, &record.value, &request) {
            Ok(response) => {
                event.outcome = "ok".into();
                event.status = Some(response.status);
                self.audit(event);
                let (body, body_base64) = match String::from_utf8(response.body) {
                    Ok(text) => (Some(text), None),
                    Err(error) => (None, Some(BASE64.encode(error.into_bytes()))),
                };
                Ok(ProxyReplyOut {
                    ok: true,
                    status: response.status,
                    headers: response.headers.into_iter().map(|(k, v)| [k, v]).collect(),
                    body,
                    body_base64,
                })
            }
            Err(error) => {
                if let VaultError::UpstreamFailed(why) = &error {
                    event.detail = Some(why.clone());
                }
                Err(fail(error, event))
            }
        }
    }
}
